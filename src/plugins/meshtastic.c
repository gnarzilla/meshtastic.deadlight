// src/plugins/meshtastic.c
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include "core/plugins.h"
#include "core/logging.h"
#include "meshtastic.h"

// Nanopb includes (after generation)
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

// Max chunk size (Meshtastic payload limit)
#define MAX_CHUNK_SIZE 220

// Custom port (pick unused from portnums.proto, e.g., >256 for private apps)
#define DEFAULT_CUSTOM_PORT 100

// Forward declarations
static gboolean send_chunk(MeshtasticData *data, DeadlightConnection *conn, const uint8_t *payload, size_t len, uint32_t seq, uint32_t total);
static gpointer reader_thread_func(gpointer user_data);
static gboolean reassemble_and_inject(MeshtasticData *data, DeadlightConnection *conn, meshtastic_MeshPacket *packet);

// Helper to free GByteArray
static void free_byte_array(gpointer data) {
    if (data) {
        g_byte_array_free((GByteArray *)data, TRUE);
    }
}

// Init: Load config, open serial, start reader
static gboolean meshtastic_init(DeadlightContext *context) {
    g_info("Initializing MeshtasticTunnel plugin...");

    MeshtasticData *data = g_new0(MeshtasticData, 1);
    g_mutex_init(&data->mutex);
    data->reassembly = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_byte_array);
    data->enabled = deadlight_config_get_bool(context, "plugin.meshtastic", "enabled", TRUE);
    data->serial_device = deadlight_config_get_string(context, "plugin.meshtastic", "serial_device", "/dev/ttyUSB0");
    data->channel_name = deadlight_config_get_string(context, "plugin.meshtastic", "channel", "LongFast");
    data->custom_port = (uint32_t)deadlight_config_get_int(context, "plugin.meshtastic", "custom_port", DEFAULT_CUSTOM_PORT);
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

    g_info("MeshtasticTunnel initialized: device=%s, channel=%s, port=%u", 
           data->serial_device, data->channel_name, data->custom_port);

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
    g_hash_table_destroy(data->reassembly);
    g_mutex_clear(&data->mutex);
    g_free(data->serial_device);
    g_free(data->channel_name);
    g_free(data);
}

// Hook: Chunk and send request body over Meshtastic
static gboolean on_request_body(DeadlightRequest *request) {
    if (!request || !request->connection || !request->connection->context) return TRUE;

    MeshtasticData *data = g_hash_table_lookup(request->connection->context->plugins_data, "meshtastic");
    if (!data || !data->enabled) return TRUE;

    GByteArray *body = request->body;
    if (!body || body->len == 0) return TRUE;

    size_t num_chunks = (body->len + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    for (size_t i = 0; i < num_chunks; i++) {
        size_t offset = i * MAX_CHUNK_SIZE;
        size_t chunk_len = MIN(MAX_CHUNK_SIZE, body->len - offset);
        if (!send_chunk(data, request->connection, body->data + offset, chunk_len, i, num_chunks)) {
            return FALSE;  // Send failed
        }
    }
    return TRUE;
}

// Similar for responses (if tunneling back)
static gboolean on_response_body(DeadlightResponse *response G_GNUC_UNUSED) {
    // Symmetric to on_request_body; implement if needed for bidirectional
    return TRUE;
}

// Send a single chunk as Meshtastic MeshPacket
static gboolean send_chunk(MeshtasticData *data, DeadlightConnection *conn, const uint8_t *payload, size_t len, uint32_t seq, uint32_t total) {
    // Create custom chunk struct
    MeshtasticChunk chunk = { .seq_num = seq, .total_chunks = total, .payload_len = len };
    memcpy(chunk.payload, payload, len);

    // Encode chunk to bytes (use nanopb for your custom PB if defined; here simple memcpy for demo)
    uint8_t chunk_buf[sizeof(MeshtasticChunk)];
    memcpy(chunk_buf, &chunk, sizeof(chunk));

    // Wrap in Meshtastic Data
    meshtastic_Data pb_data = meshtastic_Data_init_default;
    pb_data.portnum = (meshtastic_PortNum)data->custom_port;
    pb_data.payload.size = sizeof(chunk_buf);
    memcpy(pb_data.payload.bytes, chunk_buf, sizeof(chunk_buf));

    // Wrap in MeshPacket
    meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_default;
    packet.decoded = pb_data;
    // Set channel, from/to, etc. (use defaults or config)
    packet.channel = 0; // Default channel

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

    // Send to serial
    g_mutex_lock(&data->mutex);
    GError *error = NULL;
    gsize written;
    g_io_channel_write_chars(data->serial_channel, (gchar*)to_buf, to_ostream.bytes_written, &written, &error);
    g_io_channel_flush(data->serial_channel, NULL);
    g_mutex_unlock(&data->mutex);

    if (error) {
        g_warning("Meshtastic serial write failed: %s", error->message);
        g_error_free(error);
        return FALSE;
    }

    g_debug("Sent Meshtastic chunk %u/%u for conn %lu", seq, total, conn->id);
    return TRUE;
}

// Reader thread: Poll serial for FromRadio, extract packets, reassemble
static gpointer reader_thread_func(gpointer user_data) {
    MeshtasticData *data = (MeshtasticData *)user_data;

    while (data->running) {
        // Read FromRadio (assuming framed; Meshtastic serial uses length-prefix)
        uint8_t buf[512];  // Max packet
        gsize read_len;
        GError *error = NULL;
        GIOStatus status = g_io_channel_read_chars(data->serial_channel, (gchar*)buf, sizeof(buf), &read_len, &error);

        if (status == G_IO_STATUS_EOF || error) {
            if (error) g_warning("Meshtastic read error: %s", error->message);
            g_clear_error(&error);
            break;
        }

        if (read_len > 0) {
            // Decode FromRadio
            meshtastic_FromRadio from_radio = meshtastic_FromRadio_init_default;
            pb_istream_t istream = pb_istream_from_buffer(buf, read_len);
            if (pb_decode(&istream, meshtastic_FromRadio_fields, &from_radio)) {
                // Check which union variant is set - the union is anonymous
                if (from_radio.which_payload_variant == meshtastic_FromRadio_packet_tag) {
                    meshtastic_MeshPacket *packet = &from_radio.packet;
                    if (packet->decoded.portnum == (meshtastic_PortNum)data->custom_port) {
                        // Find conn (assume conn_id in packet or broadcast; here dummy)
                        DeadlightConnection *conn = NULL;  // Lookup or create new conn
                        reassemble_and_inject(data, conn, packet);
                    }
                }
            }
        }

        g_usleep(100000);  // Poll every 100ms
    }
    return NULL;
}

// Reassemble chunks and inject as response
static gboolean reassemble_and_inject(MeshtasticData *data, DeadlightConnection *conn, meshtastic_MeshPacket *packet G_GNUC_UNUSED) {
    if (!conn) return FALSE;  // Need valid connection
    
    // Extract chunk from payload
    MeshtasticChunk chunk;
    // pb_decode packet->decoded.payload into chunk (add actual)
    memcpy(&chunk, packet->decoded.payload.bytes, sizeof(chunk));

    gchar *conn_key = g_strdup_printf("%lu", conn->id);
    GByteArray *assembly = g_hash_table_lookup(data->reassembly, conn_key);
    if (!assembly) {
        assembly = g_byte_array_new();
        g_hash_table_insert(data->reassembly, conn_key, assembly);
    } else {
        g_free(conn_key);
    }

    // Append chunk (at seq position if out-of-order)
    size_t target_size = (chunk.seq_num + 1) * MAX_CHUNK_SIZE;
    if (assembly->len < target_size) {
        g_byte_array_set_size(assembly, target_size);
    }
    memcpy(assembly->data + (chunk.seq_num * MAX_CHUNK_SIZE), chunk.payload, chunk.payload_len);

    // Check complete
    if (assembly->len >= (chunk.total_chunks * MAX_CHUNK_SIZE)) {
        // Inject into response
        if (conn->current_response) {
            g_byte_array_append(conn->current_response->body, assembly->data, assembly->len);
        }
        g_hash_table_remove(data->reassembly, g_strdup_printf("%lu", conn->id));
        g_debug("Reassembled %u bytes for conn %lu", assembly->len, conn->id);
    }

    return TRUE;
}

// Plugin definition (matches RateLimiter pattern)
static DeadlightPlugin meshtastic_plugin = {
    .name = "MeshtasticTunnel",
    .version = "1.0.0",
    .description = "Tunnels data over Meshtastic mesh via chunking",
    .author = "Deadlight Team",
    .init = meshtastic_init,
    .cleanup = meshtastic_cleanup,
    .on_request_headers = NULL,
    .on_request_body = on_request_body,
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