// src/plugins/meshtastic.c
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include "core/plugins.h"
#include "core/logging.h"
#include "meshtastic.h"
#include "meshtastic_framing.h"
#include "meshtastic_transport.h"
#include "meshtastic_http_bridge.h"

// Nanopb includes (after generation)
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

// Max chunk size (Meshtastic payload limit)
#define MAX_CHUNK_SIZE 220

// Custom port (pick unused from portnums.proto, e.g., >256 for private apps)
#define DEFAULT_CUSTOM_PORT 100

// Forward declarations
static gboolean send_chunk(MeshtasticData *data,
                           guint32 to_node_id,
                           guint64 session_id,
                           MeshtasticDirection dir,
                           const uint8_t *payload,
                           size_t len,
                           uint32_t seq,
                           uint32_t total);
static gpointer reader_thread_func(gpointer user_data);
static void handle_complete_message(MeshtasticData *data, MeshtasticCompleteMessage *m);
static gboolean on_request_headers(DeadlightRequest *request);
static void gateway_pool_worker(gpointer work_ptr, gpointer user_data);

typedef struct {
    MeshtasticData *data;
    guint32 from;
    guint64 session;
    GByteArray *req;
} GatewayWork;

// Init: Load config, open serial, start reader
static gboolean meshtastic_init(DeadlightContext *context) {
    g_info("Initializing MeshtasticTunnel plugin...");

    MeshtasticData *data = g_new0(MeshtasticData, 1);
    data->context = context;
    g_mutex_init(&data->mutex);
    data->enabled = deadlight_config_get_bool(context, "plugin.meshtastic", "enabled", TRUE);
    data->serial_device = deadlight_config_get_string(context, "plugin.meshtastic", "serial_device", "/dev/ttyUSB0");
    data->channel_name = deadlight_config_get_string(context, "plugin.meshtastic", "channel", "LongFast");
    data->channel_index = deadlight_config_get_int(context, "plugin.meshtastic", "channel_index", 0);
    data->custom_port = (uint32_t)deadlight_config_get_int(context, "plugin.meshtastic", "custom_port", DEFAULT_CUSTOM_PORT);

    // Mode: client|gateway (default client)
    gchar *mode_str = deadlight_config_get_string(context, "plugin.meshtastic", "mode", "client");
    if (mode_str && g_ascii_strcasecmp(mode_str, "gateway") == 0) {
        data->mode = MESHTASTIC_MODE_GATEWAY;
    } else {
        data->mode = MESHTASTIC_MODE_CLIENT;
    }
    g_free(mode_str);

    // Client-mode destination gateway node id (hex string accepted, default 0)
    gchar *gw_str = deadlight_config_get_string(context, "plugin.meshtastic", "gateway_node_id", "0x0");
    if (gw_str) {
        gchar *endp = NULL;
        guint64 v = g_ascii_strtoull(gw_str, &endp, 0);
        data->gateway_node_id = (guint32)v;
        g_free(gw_str);
    }

    // Reassembly safety knobs (optional config, reasonable defaults)
    guint max_sessions = (guint)deadlight_config_get_int(context, "plugin.meshtastic", "max_sessions", 64);
    guint ttl_seconds = (guint)deadlight_config_get_int(context, "plugin.meshtastic", "session_ttl_seconds", 30);
    guint64 max_bytes = (guint64)deadlight_config_get_size(context, "plugin.meshtastic", "max_session_bytes", 262144);

    // Determine payload capacity based on generated nanopb struct field size.
    // Keep it <= MAX_CHUNK_SIZE (safe Meshtastic limit).
    meshtastic_Data tmp = meshtastic_Data_init_default;
    guint payload_cap = (guint)MIN((guint)MAX_CHUNK_SIZE, (guint)sizeof(tmp.payload.bytes));
    guint header_size = (guint)sizeof(MeshtasticDlHeader);
    guint chunk_data_max = payload_cap > header_size ? (payload_cap - header_size) : 0;
    data->chunk_data_max = chunk_data_max;
    data->reassembly = meshtastic_reassembly_new(max_sessions, max_bytes, ttl_seconds, chunk_data_max);

    data->pending = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, (GDestroyNotify)g_async_queue_unref);
    g_mutex_init(&data->pending_mutex);
    data->next_session_id = 1;

    if (data->mode == MESHTASTIC_MODE_GATEWAY) {
        // Keep gateway work off the serial thread
        data->gateway_pool = g_thread_pool_new(gateway_pool_worker, data, 2, FALSE, NULL);
    }
    data->running = TRUE;

    // Open serial (PROTO mode: 38400 baud typical)
    GError *error = NULL;
    data->serial_channel = g_io_channel_new_file(data->serial_device, "r+", &error);
    if (error) {
        g_warning("Failed to open Meshtastic serial: %s", error->message);
        g_error_free(error);
        g_free(data);
        return FALSE;
    }
    g_io_channel_set_encoding(data->serial_channel, NULL, NULL);  // Binary mode
    g_io_channel_set_buffered(data->serial_channel, FALSE);

    // Start reader thread
    data->reader_thread = g_thread_new("meshtastic_reader", reader_thread_func, data);

    if (!context->plugins_data) {
        context->plugins_data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    }
    g_hash_table_insert(context->plugins_data, g_strdup("meshtastic"), data);

    g_info("MeshtasticTunnel initialized: mode=%s device=%s channel_index=%d channel=%s port=%u gateway_node_id=0x%08x",
           data->mode == MESHTASTIC_MODE_GATEWAY ? "gateway" : "client",
           data->serial_device,
           data->channel_index,
           data->channel_name,
           data->custom_port,
           (unsigned)data->gateway_node_id);

    return TRUE;
}

// Cleanup: Stop thread, close serial
static void meshtastic_cleanup(DeadlightContext *context) {
    MeshtasticData *data = g_hash_table_lookup(context->plugins_data, "meshtastic");
    if (!data) return;

    g_info("Cleaning up MeshtasticTunnel...");

    data->running = FALSE;
    if (data->reader_thread) {
        g_thread_join(data->reader_thread);
    }
    if (data->serial_channel) {
        g_io_channel_shutdown(data->serial_channel, TRUE, NULL);
        g_io_channel_unref(data->serial_channel);
    }
    if (data->gateway_pool) {
        g_thread_pool_free(data->gateway_pool, TRUE, TRUE);
        data->gateway_pool = NULL;
    }
    meshtastic_reassembly_free((MeshtasticReassemblyTable *)data->reassembly);
    if (data->pending) {
        g_hash_table_destroy(data->pending);
        data->pending = NULL;
    }
    g_mutex_clear(&data->pending_mutex);
    g_mutex_clear(&data->mutex);
    g_free(data->serial_device);
    g_free(data->channel_name);
    g_free(data);
}

static gboolean on_request_headers(DeadlightRequest *request) {
    if (!request || !request->connection || !request->connection->context) return TRUE;
    MeshtasticData *data = g_hash_table_lookup(request->connection->context->plugins_data, "meshtastic");
    if (!data || !data->enabled) return TRUE;
    if (request->connection->protocol != DEADLIGHT_PROTOCOL_HTTP) return TRUE;

    // Client-mode: handle HTTP requests over mesh by returning FALSE (meaning \"plugin handled response\").
    if (data->mode == MESHTASTIC_MODE_CLIENT) {
        gboolean handled = meshtastic_client_forward_http(data, request);
        return handled ? FALSE : TRUE;
    }

    return TRUE;
}

// Similar for responses (if tunneling back)
static gboolean on_response_body(DeadlightResponse *response G_GNUC_UNUSED) {
    // Symmetric to on_request_body; implement if needed for bidirectional
    return TRUE;
}

// Send a single chunk as Meshtastic MeshPacket
static gboolean send_chunk(MeshtasticData *data,
                           guint32 to_node_id,
                           guint64 session_id,
                           MeshtasticDirection dir,
                           const uint8_t *payload,
                           size_t len,
                           uint32_t seq,
                           uint32_t total) {
    if (!data || !data->serial_channel) return FALSE;

    GByteArray *wire = meshtastic_transport_build_chunk(session_id, dir, seq, total, payload, (guint16)len);

    // Wrap in Meshtastic Data
    meshtastic_Data pb_data = meshtastic_Data_init_default;
    pb_data.portnum = (meshtastic_PortNum)data->custom_port;
    if (wire->len > sizeof(pb_data.payload.bytes)) {
        g_warning("Meshtastic payload too large for nanopb field (%u > %u)",
                  (unsigned)wire->len, (unsigned)sizeof(pb_data.payload.bytes));
        g_byte_array_free(wire, TRUE);
        return FALSE;
    }
    pb_data.payload.size = (pb_size_t)wire->len;
    memcpy(pb_data.payload.bytes, wire->data, wire->len);
    g_byte_array_free(wire, TRUE);

    // Wrap in MeshPacket
    meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_default;
    packet.decoded = pb_data;
    // Set channel, from/to, etc. (use defaults or config)
    packet.channel = (uint32_t)data->channel_index;
    packet.to = to_node_id;

    // Encode packet
    uint8_t packet_buf[512];
    pb_ostream_t ostream = pb_ostream_from_buffer(packet_buf, sizeof(packet_buf));
    if (!pb_encode(&ostream, meshtastic_MeshPacket_fields, &packet)) {
        g_warning("Meshtastic encode failed");
        return FALSE;
    }

    // Wrap in ToRadio - the union is anonymous, access members directly
    meshtastic_ToRadio to_radio = meshtastic_ToRadio_init_default;
    to_radio.which_payload_variant = meshtastic_ToRadio_packet_tag;
    to_radio.packet = packet;

    // Encode ToRadio
    uint8_t to_buf[512];
    pb_ostream_t to_ostream = pb_ostream_from_buffer(to_buf, sizeof(to_buf));
    if (!pb_encode(&to_ostream, meshtastic_ToRadio_fields, &to_radio)) {
        g_warning("ToRadio encode failed");
        return FALSE;
    }

    // Send to serial (length-delimited framing)
    g_mutex_lock(&data->mutex);
    GError *error = NULL;
    meshtastic_framing_write_delimited(data->serial_channel, to_buf, to_ostream.bytes_written, &error);
    g_mutex_unlock(&data->mutex);

    if (error) {
        g_warning("Meshtastic serial write failed: %s", error->message);
        g_error_free(error);
        return FALSE;
    }

    g_debug("Sent Meshtastic chunk %u/%u session=%" G_GUINT64_FORMAT " dir=%u to=0x%08x",
            seq, total, (guint64)session_id, (unsigned)dir, (unsigned)to_node_id);
    return TRUE;
}

// Reader thread: Poll serial for FromRadio, extract packets, reassemble
static gpointer reader_thread_func(gpointer user_data) {
    MeshtasticData *data = (MeshtasticData *)user_data;
    GByteArray *inbuf = g_byte_array_new();
    gint64 next_cleanup = g_get_monotonic_time() + (5 * G_USEC_PER_SEC);

    while (data->running) {
        guint8 buf[1024];
        gsize read_len = 0;
        GError *error = NULL;
        GIOStatus status = g_io_channel_read_chars(data->serial_channel, (gchar*)buf, sizeof(buf), &read_len, &error);

        if (status == G_IO_STATUS_EOF || error) {
            if (error) g_warning("Meshtastic read error: %s", error->message);
            g_clear_error(&error);
            break;
        }

        if (read_len > 0) {
            g_byte_array_append(inbuf, buf, read_len);
        }

        // Drain all complete frames
        for (;;) {
            guint8 *frame = NULL;
            gsize frame_len = 0;
            if (!meshtastic_framing_try_read_frame(inbuf, &frame, &frame_len)) {
                break;
            }

            meshtastic_FromRadio from_radio = meshtastic_FromRadio_init_default;
            pb_istream_t istream = pb_istream_from_buffer(frame, frame_len);
            if (pb_decode(&istream, meshtastic_FromRadio_fields, &from_radio)) {
                if (from_radio.which_payload_variant == meshtastic_FromRadio_packet_tag) {
                    meshtastic_MeshPacket *packet = &from_radio.packet;
                    if (packet->decoded.portnum == (meshtastic_PortNum)data->custom_port) {
                        guint32 from_id = (guint32)packet->from;
                        MeshtasticCompleteMessage *m = meshtastic_reassembly_ingest(
                            (MeshtasticReassemblyTable *)data->reassembly,
                            from_id,
                            packet->decoded.payload.bytes,
                            packet->decoded.payload.size
                        );
                        if (m) {
                            handle_complete_message(data, m);
                            meshtastic_complete_message_free(m);
                        }
                    }
                }
            }
            g_free(frame);
        }

        // Periodic expiry cleanup (keep table bounded if packets are lost)
        gint64 now = g_get_monotonic_time();
        if (now >= next_cleanup) {
            meshtastic_reassembly_cleanup_expired((MeshtasticReassemblyTable *)data->reassembly);
            next_cleanup = now + (5 * G_USEC_PER_SEC);
        }
    }

    g_byte_array_free(inbuf, TRUE);
    return NULL;
}

static void handle_complete_message(MeshtasticData *data, MeshtasticCompleteMessage *m) {
    if (!data || !m || !m->message) return;

    if (data->mode == MESHTASTIC_MODE_CLIENT && m->direction == MESHTASTIC_DIR_RESPONSE) {
        // Deliver response to waiting local request
        guint64 sid = m->session_id;
        g_mutex_lock(&data->pending_mutex);
        GAsyncQueue *q = data->pending ? g_hash_table_lookup(data->pending, &sid) : NULL;
        if (q) g_async_queue_ref(q);
        g_mutex_unlock(&data->pending_mutex);

        if (q) {
            // Pass ownership to queue item
            GByteArray *copy = g_byte_array_new();
            g_byte_array_append(copy, m->message->data, m->message->len);
            g_async_queue_push(q, copy);
            g_async_queue_unref(q);
        }
        return;
    }

    if (data->mode == MESHTASTIC_MODE_GATEWAY && m->direction == MESHTASTIC_DIR_REQUEST) {
        // Offload upstream fetch and mesh response
        if (data->gateway_pool) {
            GByteArray *req_copy = g_byte_array_new();
            g_byte_array_append(req_copy, m->message->data, m->message->len);
            GatewayWork *w = g_new0(GatewayWork, 1);
            w->data = data;
            w->from = m->from_node_id;
            w->session = m->session_id;
            w->req = req_copy;
            g_thread_pool_push(data->gateway_pool, w, NULL);
        } else {
            GByteArray *req_copy = g_byte_array_new();
            g_byte_array_append(req_copy, m->message->data, m->message->len);
            meshtastic_gateway_handle_http_request(data, m->from_node_id, m->session_id, req_copy);
            g_byte_array_free(req_copy, TRUE);
        }
        return;
    }
}

static void gateway_pool_worker(gpointer work_ptr, gpointer user_data) {
    (void)user_data;
    GatewayWork *w = (GatewayWork *)work_ptr;
    if (!w) return;
    meshtastic_gateway_handle_http_request(w->data, w->from, w->session, w->req);
    g_byte_array_free(w->req, TRUE);
    g_free(w);
}

// Plugin definition (matches RateLimiter pattern)
static DeadlightPlugin meshtastic_plugin = {
    .name = "MeshtasticTunnel",
    .version = "1.0.0",
    .description = "Tunnels data over Meshtastic mesh via chunking",
    .author = "Deadlight Team",
    .init = meshtastic_init,
    .cleanup = meshtastic_cleanup,
    .on_request_headers = on_request_headers,
    .on_request_body = NULL,
    .on_response_headers = NULL,
    .on_response_body = on_response_body,
    .on_connection_accept = NULL,
    .on_protocol_detect = NULL,
    .on_connection_close = NULL,  // Add if needed for cleanup
    .on_config_change = NULL,
};

G_MODULE_EXPORT gboolean deadlight_plugin_get_info(DeadlightPlugin **plugin) {
    *plugin = &meshtastic_plugin;
    return TRUE;
}