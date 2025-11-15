// in src/protocols/imap.c

#include "imap.h"
#include <ctype.h>

// Forward declarations
static gsize imap_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult imap_handle(DeadlightConnection *conn, GError **error);
static void imap_cleanup(DeadlightConnection *conn);

// The handler object provided to the core system
static const DeadlightProtocolHandler imap_protocol_handler = {
    .name = "IMAP",
    .protocol_id = DEADLIGHT_PROTOCOL_IMAP,
    .detect = imap_detect,
    .handle = imap_handle,
    .cleanup = imap_cleanup
};

void deadlight_register_imap_handler(void) {
    deadlight_protocol_register(&imap_protocol_handler);
}

// --- IMPLEMENTATION ---

/**
 * @brief Detects if the initial data buffer looks like IMAP traffic.
 *
 * @param data The buffer of initial data from the client.
 * @param len The length of the data in the buffer.
 * @return 1 if IMAP is detected, 0 otherwise.
 */
static gsize imap_detect(const guint8 *data, gsize len) {
    // A more robust IMAP detection.
    // We need to handle multi-character tags (e.g., "A001 LOGIN").
    // The key is that the first character is predictable and there's a space after the tag.

    if (len < 2) {
        return 0; // Not enough data to possibly be IMAP
    }

    // Case 1: Server untagged response or continuation request.
    // e.g., "* OK ...", "+ Ready for literal"
    if ((data[0] == '*' || data[0] == '+') && data[1] == ' ') {
        return 1; // This is a strong signal for IMAP.
    }

    // Case 2: Client command. e.g., "A001 LOGIN", "TAG CAPABILITY"
    // The tag must start with an alphanumeric character.
    if (isalnum(data[0])) {
        // Find the first space.
        for (gsize i = 1; i < len; ++i) {
            if (data[i] == ' ') {
                // We found a pattern of [alnum]...[space], which is
                // characteristic of an IMAP client command.
                return 1;
            }
        }
    }

    // If none of the above patterns match, it's not IMAP.
    return 0;
}

/**
 * @brief Handles an IMAP connection by tunneling it to a configured upstream server.
 *
 * @param conn The connection object.
 * @param error A pointer to a GError pointer.
 * @return A DeadlightHandlerResult indicating the outcome.
 */
static DeadlightHandlerResult imap_handle(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("IMAP handler assigned to connection %lu", conn->id);

    const gchar *upstream_host = deadlight_config_get_string(ctx, "imap", "upstream_host", "imap.gmail.com");
    gint upstream_port = deadlight_config_get_int(ctx, "imap", "upstream_port", 143);

    g_info("IMAP handler for conn %lu: connecting to upstream %s:%d", conn->id, upstream_host, upstream_port);

    if (!deadlight_network_connect_upstream(conn, error)) {
        g_warning("IMAP handler failed to connect upstream for conn %lu", conn->id);
        return HANDLER_ERROR;
    }

    // Forward the detection buffer
    if (conn->client_buffer && conn->client_buffer->len > 0) {
        GOutputStream *upstream_os = g_io_stream_get_output_stream(
            G_IO_STREAM(conn->upstream_connection));
        
        if (!g_output_stream_write_all(upstream_os, 
                                    conn->client_buffer->data,
                                    conn->client_buffer->len, 
                                    NULL, NULL, error)) {
            g_warning("IMAP: Failed to forward initial buffer: %s", (*error)->message);
            return HANDLER_ERROR;
        }
    }

    g_info("IMAP handler for conn %lu: upstream connected, starting data tunnel.", conn->id);
    
    // deadlight_network_tunnel_data is a synchronous, blocking call.
    // It will handle all I/O between client and upstream until one side closes.
    if (deadlight_network_tunnel_data(conn, error)) {
        g_info("IMAP tunnel for conn %lu finished successfully.", conn->id);
        // The connection is finished. Tell the core to clean up now.
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        g_warning("IMAP tunnel for conn %lu failed: %s", conn->id, (*error)->message);
        // The tunnel itself failed.
        return HANDLER_ERROR;
    }
}

/**
 * @brief Cleans up any resources specific to the IMAP handler.
 * @param conn The connection object.
 */
static void imap_cleanup(DeadlightConnection *conn) {
    // For this simple tunneling handler, there is no specific state to clean up.
    // The upstream socket is managed by the DeadlightConnection object itself.
    // If we had allocated memory with g_malloc, this is where we would g_free it.
    (void)conn; // Suppress unused parameter warning
    g_debug("IMAP cleanup called for conn %lu", conn->id);
}