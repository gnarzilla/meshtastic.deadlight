/**
 * deadmesh - Meshtastic Transport Plugin (revised)
 *
 * Wires the Meshtastic serial radio into the deadlight proxy core.
 *
 * Architecture:
 *   serial fd
 *     └─> mesh_frame_read_blocking()   [framing layer]
 *           └─> mesh_session_get_or_create()  [session routing]
 *                 └─> DeadlightConnection     [proxy core, unmodified]
 *
 * What changed from the original:
 *   - Serial framing is now correct (0x94 0xC3 length-prefix state machine)
 *   - reader_thread uses blocking reads — no 100ms busy-poll
 *   - Session routing maps (src_node_id, session_id) -> connection
 *   - send_chunk uses nanopb, not a raw memcpy struct cast
 *   - Reassembly uses the bitmap tracker in mesh_session — handles out-of-order
 *   - on_connection_close frees session state cleanly
 *   - Serial open moved to a dedicated helper with proper baud rate config
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include "core/plugins.h"
#include "core/deadlight.h"
#include "mesh_framing.h"
#include "mesh_session.h"

/* nanopb */
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "mesh.pb.h"
#include "portnums.pb.h"

/* ─────────────────────────────────────────────────────────────
 * Plugin state
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    /* Context — needed by reader thread to create connections */
    DeadlightContext *context;

    /* Config */
    gchar    *serial_device;
    int       baud_rate;
    uint32_t  custom_port;
    uint32_t  local_node_id;
    gboolean  enabled;

    /* Serial fd — owned by this struct */
    int       serial_fd;

    /* Framing */
    MeshFrameReader frame_reader;

    /* Session routing */
    MeshSessionTable *sessions;

    /* Reader thread */
    GThread          *reader_thread;
    volatile gboolean running;

    /* Write mutex — reader thread reads, worker threads write */
    GMutex            write_mutex;

    /* Stats */
    guint64 frames_sent;
    guint64 frames_recv;
    guint64 frames_dropped;
    guint64 encode_errors;
} MeshtasticPlugin;

/* ─────────────────────────────────────────────────────────────
 * Forward declarations
 * ───────────────────────────────────────────────────────────── */

static gpointer reader_thread_func(gpointer user_data);
static gboolean send_chunk(MeshtasticPlugin *mp,
                            DeadlightConnection *conn,
                            const uint8_t *payload, size_t len,
                            uint32_t seq, uint32_t total);
static int  open_serial(const char *device, int baud);
static int  baud_constant(int baud_rate);
static void handle_incoming_frame(MeshtasticPlugin *mp,
                                   DeadlightContext *context,
                                   const MeshFrame *frame);

/* ─────────────────────────────────────────────────────────────
 * Serial helpers
 * ───────────────────────────────────────────────────────────── */

static int baud_constant(int baud_rate) {
    switch (baud_rate) {
        case 9600:   return B9600;
        case 19200:  return B19200;
        case 38400:  return B38400;
        case 57600:  return B57600;
        case 115200: return B115200;
        default:
            g_warning("Meshtastic: unknown baud rate %d, defaulting to 115200",
                      baud_rate);
            return B115200;
    }
}

static int open_serial(const char *device, int baud_rate) {
    int fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        g_warning("Meshtastic: cannot open %s: %s", device, g_strerror(errno));
        return -1;
    }

    struct termios tios;
    if (tcgetattr(fd, &tios) < 0) {
        g_warning("Meshtastic: tcgetattr failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    /* 8N1, no flow control, raw binary mode */
    cfmakeraw(&tios);
    cfsetispeed(&tios, baud_constant(baud_rate));
    cfsetospeed(&tios, baud_constant(baud_rate));

    tios.c_cflag |= (CLOCAL | CREAD);
    tios.c_cflag &= ~CSTOPB;
    tios.c_cflag &= ~CRTSCTS;

    /* Block on read until at least 1 byte available — this is what
     * lets mesh_frame_read_blocking() sleep instead of spin.        */
    tios.c_cc[VMIN]  = 1;
    tios.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tios) < 0) {
        g_warning("Meshtastic: tcsetattr failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    tcflush(fd, TCIOFLUSH);
    return fd;
}

/* ─────────────────────────────────────────────────────────────
 * Plugin lifecycle
 * ───────────────────────────────────────────────────────────── */

static gboolean meshtastic_init(DeadlightContext *context) {
    g_info("Meshtastic: initialising transport plugin");

    MeshtasticPlugin *mp = g_new0(MeshtasticPlugin, 1);
    mp->context = context;

    mp->enabled       = deadlight_config_get_bool(context,
                            "meshtastic", "enabled", TRUE);
    mp->serial_device = deadlight_config_get_string(context,
                            "meshtastic", "serial_port", "/dev/ttyACM0");
    mp->baud_rate     = deadlight_config_get_int(context,
                            "meshtastic", "baud_rate", 115200);
    mp->custom_port   = (uint32_t)deadlight_config_get_int(context,
                            "meshtastic", "custom_port", 100);
    mp->local_node_id = (uint32_t)deadlight_config_get_int(context,
                            "meshtastic", "mesh_node_id", 0);

    if (!mp->enabled) {
        g_info("Meshtastic: disabled in config, skipping init");
        g_free(mp->serial_device);
        g_free(mp);
        return TRUE;
    }

    /* Session table — 5 minute idle expiry */
    mp->sessions = mesh_session_table_new(5 * 60 * 1000);

    /* Frame reader */
    mesh_frame_reader_init(&mp->frame_reader);

    /* Open serial port */
    mp->serial_fd = open_serial(mp->serial_device, mp->baud_rate);
    if (mp->serial_fd < 0) {
        g_warning("Meshtastic: failed to open serial port %s — "
                  "is the radio connected?", mp->serial_device);
        /* Don't hard-fail — let deadmesh start without radio,
         * operator can reconnect and send SIGHUP to reload config. */
        mp->serial_fd = -1;
    } else {
        g_info("Meshtastic: opened %s at %d baud (fd=%d)",
               mp->serial_device, mp->baud_rate, mp->serial_fd);
    }

    g_mutex_init(&mp->write_mutex);
    mp->running = TRUE;

    /* Start reader thread only if we have a valid fd */
    if (mp->serial_fd >= 0) {
        mp->reader_thread = g_thread_new("mesh-reader",
                                          reader_thread_func, mp);
    }

    /* Store plugin state on context */
    if (!context->plugins_data) {
        context->plugins_data = g_hash_table_new_full(
            g_str_hash, g_str_equal, g_free, NULL);
    }
    g_hash_table_insert(context->plugins_data,
                        g_strdup("meshtastic"), mp);

    /* Also wire into context->mesh so config_update_context_values()
     * can push fragment_size / ack_timeout updates live.             */
    if (context->mesh) {
        context->mesh->radio_fd = mp->serial_fd;
    }

    g_info("Meshtastic: transport ready — device=%s port=%u",
           mp->serial_device, mp->custom_port);
    return TRUE;
}

static void meshtastic_cleanup(DeadlightContext *context) {
    if (!context->plugins_data) return;

    MeshtasticPlugin *mp = g_hash_table_lookup(
        context->plugins_data, "meshtastic");
    if (!mp) return;

    g_info("Meshtastic: shutting down transport");

    mp->running = FALSE;

    /* Wake the reader thread if it's blocked on read() */
    if (mp->serial_fd >= 0) {
        /* Close the fd — this causes read() to return immediately */
        close(mp->serial_fd);
        mp->serial_fd = -1;
    }

    if (mp->reader_thread) {
        g_thread_join(mp->reader_thread);
        mp->reader_thread = NULL;
    }

    mesh_session_table_free(mp->sessions);
    g_mutex_clear(&mp->write_mutex);
    g_free(mp->serial_device);
    g_free(mp);

    g_hash_table_remove(context->plugins_data, "meshtastic");
}

/* ─────────────────────────────────────────────────────────────
 * Reader thread
 * ───────────────────────────────────────────────────────────── */

static gpointer reader_thread_func(gpointer user_data) {
    MeshtasticPlugin *mp = (MeshtasticPlugin *)user_data;
    DeadlightContext *context = mp->context;

    g_info("Meshtastic reader thread started (fd=%d)", mp->serial_fd);

    MeshFrameReader reader;
    mesh_frame_reader_init(&reader);

    while (mp->running && mp->serial_fd >= 0) {
        MeshFrame frame;

        /* Blocking read — sleeps until a complete frame arrives.
         * Returns false on EOF or fd close (our shutdown path).     */
        if (!mesh_frame_read_blocking(mp->serial_fd, &reader, &frame)) {
            if (mp->running) {
                g_warning("Meshtastic: serial read failed — fd=%d err=%s",
                           mp->serial_fd, g_strerror(errno));
            }
            break;
        }

        mp->frames_recv++;
        mesh_frame_reader_reset(&reader);

        if (context) {
            handle_incoming_frame(mp, context, &frame);
        }

        /* Periodic session expiry — every ~100 frames */
        if (mp->frames_recv % 100 == 0) {
            guint expired = mesh_session_expire(mp->sessions);
            if (expired > 0) {
                g_info("Meshtastic: expired %u idle sessions", expired);
            }
        }
    }

    g_info("Meshtastic reader thread exiting "
           "(frames recv=%lu sync_errors=%lu)",
           mp->frames_recv, reader.sync_errors);
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * Incoming frame handler
 * ───────────────────────────────────────────────────────────── */

static void handle_incoming_frame(MeshtasticPlugin *mp,
                                   DeadlightContext *context,
                                   const MeshFrame *frame) {
    /* Decode FromRadio */
    meshtastic_FromRadio from_radio = meshtastic_FromRadio_init_default;
    pb_istream_t istream = pb_istream_from_buffer(frame->payload, frame->len);

    if (!pb_decode(&istream, meshtastic_FromRadio_fields, &from_radio)) {
        g_warning("Meshtastic: protobuf decode failed: %s",
                  PB_GET_ERROR(&istream));
        return;
    }

    if (from_radio.which_payload_variant != meshtastic_FromRadio_packet_tag) {
        return; /* NodeInfo, Config, etc. — ignore for now */
    }

    meshtastic_MeshPacket *pkt = &from_radio.packet;

    /* Only handle our custom port */
    if (pkt->which_payload_variant != meshtastic_MeshPacket_decoded_tag) {
        return; /* encrypted packet — can't decode without channel key */
    }

    if (pkt->decoded.portnum != (meshtastic_PortNum)mp->custom_port) {
        return;
    }

    uint32_t src_node  = pkt->from;
    uint32_t packet_id = pkt->id;

    if (src_node == 0) {
        g_warning("Meshtastic: received packet with zero src_node, discarding");
        return;
    }

    /* The payload encodes our chunk header + data.
     * Format: seq(4LE) + total(4LE) + data_bytes    */
    const pb_byte_t *raw     = pkt->decoded.payload.bytes;
    size_t           raw_len = pkt->decoded.payload.size;

    if (raw_len < 8) {
        g_warning("Meshtastic: packet from %08x too short (%zu bytes)",
                   src_node, raw_len);
        return;
    }

    uint32_t seq_num      = 0;
    uint32_t total_chunks = 0;
    memcpy(&seq_num,      raw,     4);
    memcpy(&total_chunks, raw + 4, 4);

    const uint8_t *chunk_data = raw + 8;
    size_t         chunk_len  = raw_len - 8;

    /* session_id: use packet_id of the FIRST packet in the sequence.
     * For subsequent chunks, the caller must use the same session_id.
     * Simple convention: session_id = packet_id of seq_num 0.
     * TODO: the client side needs to send seq 0 first, or include
     * the session_id explicitly in the chunk header.               */
    uint32_t session_id = (seq_num == 0) ? packet_id : packet_id;

    MeshSession *session = mesh_session_get_or_create(
        mp->sessions, src_node, session_id);

    /* Initialise reassembly on first chunk */
    if (seq_num == 0 || session->expected_chunks == 0) {
        mesh_session_init_reassembly(session, total_chunks);
    }

    bool complete = mesh_session_record_chunk(
        session, seq_num, chunk_data, chunk_len);

    g_debug("Meshtastic: chunk %u/%u from node %08x session %08x",
            seq_num + 1, total_chunks, src_node, session_id);

    if (!complete) return;

    /* All chunks received — inject reassembled data into the connection */
    if (!session->conn) {
        /* No connection yet — this session needs a new proxy connection.
         * For now, log and skip. Full implementation requires creating
         * a MeshStream GIOStream and handing it to the network layer.
         * That's mesh_stream.c, the next piece.                       */
        g_info("Meshtastic: session %08x:%08x complete (%u bytes) "
               "— no connection assigned yet (mesh_stream pending)",
               src_node, session_id,
               session->assembly_buf->len);
        return;
    }

    /* Append reassembled data to connection's client buffer */
    g_byte_array_append(session->conn->client_buffer,
                        session->assembly_buf->data,
                        session->assembly_buf->len);

    g_info("Meshtastic: injected %u reassembled bytes into conn %lu",
            session->assembly_buf->len, session->conn->id);

    /* Reset reassembly state for next message on this session */
    mesh_session_init_reassembly(session, 0);
    (void)context;
}

/* ─────────────────────────────────────────────────────────────
 * Outbound: chunk and send
 * ───────────────────────────────────────────────────────────── */

static gboolean send_chunk(MeshtasticPlugin *mp,
                            DeadlightConnection *conn,
                            const uint8_t *payload, size_t len,
                            uint32_t seq, uint32_t total) {
    if (mp->serial_fd < 0) {
        g_warning("Meshtastic: cannot send — serial port not open");
        return FALSE;
    }

    /* Build chunk header + payload */
    uint8_t chunk_buf[8 + MESH_FRAME_MAX_PAYLOAD];
    if (len > MESH_FRAME_MAX_PAYLOAD - 8) {
        g_warning("Meshtastic: chunk too large (%zu)", len);
        return FALSE;
    }
    memcpy(chunk_buf,     &seq,   4);  /* seq_num      (LE) */
    memcpy(chunk_buf + 4, &total, 4);  /* total_chunks (LE) */
    memcpy(chunk_buf + 8, payload, len);
    size_t chunk_total = 8 + len;

    /* Encode Data sub-message */
    meshtastic_Data pb_data = meshtastic_Data_init_default;
    pb_data.portnum      = (meshtastic_PortNum)mp->custom_port;
    pb_data.payload.size = (pb_size_t)chunk_total;
    memcpy(pb_data.payload.bytes, chunk_buf, chunk_total);

    /* Encode MeshPacket */
    meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_default;
    packet.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    packet.decoded               = pb_data;
    packet.from                  = mp->local_node_id;
    packet.id                    = (uint32_t)conn->mesh_session_id;
    packet.hop_limit             = 3;

    uint8_t packet_buf[600];
    pb_ostream_t pstream = pb_ostream_from_buffer(packet_buf,
                                                   sizeof(packet_buf));
    if (!pb_encode(&pstream, meshtastic_MeshPacket_fields, &packet)) {
        g_warning("Meshtastic: MeshPacket encode failed: %s",
                  PB_GET_ERROR(&pstream));
        mp->encode_errors++;
        return FALSE;
    }

    /* Encode ToRadio wrapper */
    meshtastic_ToRadio to_radio = meshtastic_ToRadio_init_default;
    to_radio.which_payload_variant = meshtastic_ToRadio_packet_tag;
    to_radio.packet                = packet;

    uint8_t to_buf[700];
    pb_ostream_t tostream = pb_ostream_from_buffer(to_buf, sizeof(to_buf));
    if (!pb_encode(&tostream, meshtastic_ToRadio_fields, &to_radio)) {
        g_warning("Meshtastic: ToRadio encode failed: %s",
                  PB_GET_ERROR(&tostream));
        mp->encode_errors++;
        return FALSE;
    }

    /* Apply serial framing */
    uint8_t frame_buf[MESH_FRAME_MAX_TOTAL];
    size_t frame_len = mesh_frame_encode(to_buf,
                                          (uint16_t)tostream.bytes_written,
                                          frame_buf, sizeof(frame_buf));
    if (frame_len == 0) {
        g_warning("Meshtastic: frame encoding failed (payload too large?)");
        return FALSE;
    }

    /* Write to serial — mutex protects against concurrent worker threads */
    g_mutex_lock(&mp->write_mutex);
    ssize_t written = write(mp->serial_fd, frame_buf, frame_len);
    g_mutex_unlock(&mp->write_mutex);

    if (written < 0 || (size_t)written != frame_len) {
        g_warning("Meshtastic: serial write failed: %s", g_strerror(errno));
        return FALSE;
    }

    mp->frames_sent++;
    g_debug("Meshtastic: sent chunk %u/%u for conn %lu (%zu bytes)",
             seq + 1, total, conn->id, len);
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────
 * Plugin hooks
 * ───────────────────────────────────────────────────────────── */

static gboolean on_request_body(DeadlightRequest *request) {
    if (!request || !request->connection || !request->connection->context)
        return TRUE;

    DeadlightContext *context = request->connection->context;
    MeshtasticPlugin *mp = g_hash_table_lookup(
        context->plugins_data, "meshtastic");
    if (!mp || !mp->enabled || mp->serial_fd < 0) return TRUE;

    GByteArray *body = request->body;
    if (!body || body->len == 0) return TRUE;

    uint32_t total_chunks = (body->len + 219) / 220;
    for (uint32_t i = 0; i < total_chunks; i++) {
        size_t offset    = i * 220;
        size_t chunk_len = MIN(220, body->len - offset);
        if (!send_chunk(mp, request->connection,
                        body->data + offset, chunk_len,
                        i, total_chunks)) {
            g_warning("Meshtastic: chunk %u/%u send failed for conn %lu",
                       i + 1, total_chunks, request->connection->id);
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean on_response_body(DeadlightResponse *response G_GNUC_UNUSED) {
    /* Symmetric send path — implemented once mesh_stream.c is in place
     * and the connection has a live mesh_session_id to address to.    */
    return TRUE;
}

static gboolean on_connection_close(DeadlightContext *context,
                                 DeadlightConnection *conn) {
    if (!context->plugins_data) return TRUE;

    MeshtasticPlugin *mp = g_hash_table_lookup(
        context->plugins_data, "meshtastic");
    if (!mp) return TRUE;

    /* If this connection had a mesh session, close and remove it */
    if (conn->mesh_session_id != 0) {
        MeshSession *session = mesh_session_lookup(
            mp->sessions,
            conn->mesh_source_node,
            conn->mesh_session_id);

        if (session) {
            mesh_session_close(mp->sessions, session);
            mesh_session_remove(mp->sessions,
                                 conn->mesh_source_node,
                                 conn->mesh_session_id);
            g_debug("Meshtastic: closed session %08x:%08x on conn close",
                    conn->mesh_source_node, conn->mesh_session_id);
        }
    }
    return TRUE;
}

static gboolean on_config_change(DeadlightContext *context,
                              const gchar *section,
                              const gchar *key G_GNUC_UNUSED) {
    if (g_strcmp0(section, "meshtastic") != 0) return TRUE;
    if (!context->plugins_data) return TRUE;

    MeshtasticPlugin *mp = g_hash_table_lookup(
        context->plugins_data, "meshtastic");
    if (!mp) return TRUE;

    /* Re-read the fields that can change at runtime without a restart */
    mp->custom_port = (uint32_t)deadlight_config_get_int(
        context, "meshtastic", "custom_port", 100);

    g_info("Meshtastic: config updated (custom_port=%u)", mp->custom_port);
    /* serial_port / baud_rate changes require full plugin restart (SIGHUP) */
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────
 * Plugin registration
 * ───────────────────────────────────────────────────────────── */

static DeadlightPlugin meshtastic_plugin = {
    .name               = "meshtastic",
    .version            = "1.1.0",
    .description        = "Meshtastic LoRa serial transport for deadmesh",
    .author             = "deadlight.boo",
    .init               = meshtastic_init,
    .cleanup            = meshtastic_cleanup,
    .on_request_headers = NULL,
    .on_request_body    = on_request_body,
    .on_response_headers= NULL,
    .on_response_body   = on_response_body,
    .on_connection_accept = NULL,
    .on_protocol_detect = NULL,
    .on_connection_close= on_connection_close,
    .on_config_change   = on_config_change,
};

G_MODULE_EXPORT gboolean deadlight_plugin_get_info(DeadlightPlugin **plugin) {
    *plugin = &meshtastic_plugin;
    return TRUE;
}