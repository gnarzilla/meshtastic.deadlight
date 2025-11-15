// in src/protocols/imaps.c

#include "imaps.h"
#include <ctype.h>

// Forward declarations
static gsize imaps_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult imaps_handle(DeadlightConnection *conn, GError **error);
static void imaps_cleanup(DeadlightConnection *conn);

// The handler object provided to the core system
static const DeadlightProtocolHandler imaps_protocol_handler = {
    .name = "IMAPS",
    .protocol_id = DEADLIGHT_PROTOCOL_IMAPS,
    .detect = imaps_detect,
    .handle = imaps_handle,
    .cleanup = imaps_cleanup
};

void deadlight_register_imaps_handler(void) {
    deadlight_protocol_register(&imaps_protocol_handler);
}

// --- IMPLEMENTATION ---

/**
 * @brief Detects if the initial data buffer looks like IMAPS traffic.
 *
 * @param data The buffer of initial data from the client.
 * @param len The length of the data in the buffer.
 * @return 1 if IMAPS is detected, 0 otherwise.
 */
static gsize imaps_detect(const guint8 *data, gsize len) {
    // A more robust IMAPS detection.
    // We need to handle multi-character tags (e.g., "A001 LOGIN").
    // The key is that the first character is predictable and there's a space after the tag.

    if (len < 2) {
        return 0; // Not enough data to possibly be IMAPS
    }

    // Case 1: Server untagged response or continuation request.
    // e.g., "* OK ...", "+ Ready for literal"
    if ((data[0] == '*' || data[0] == '+') && data[1] == ' ') {
        return 1; // This is a strong signal for IMAPS.
    }

    // Case 2: Client command. e.g., "A001 LOGIN", "TAG CAPABILITY"
    // The tag must start with an alphanumeric character.
    if (isalnum(data[0])) {
        // Find the first space.
        for (gsize i = 1; i < len; ++i) {
            if (data[i] == ' ') {
                // We found a pattern of [alnum]...[space], which is
                // characteristic of an IMAPS client command.
                return 1;
            }
        }
    }

    // If none of the above patterns match, it's not IMAPS.
    return 0;
}

/**
 * @brief Handles an IMAPS connection by tunneling it to a configured upstream server.
 *
 * @param conn The connection object.
 * @param error A pointer to a GError pointer.
 * @return A DeadlightHandlerResult indicating the outcome.
 */

// in src/protocols/imaps.c

static DeadlightHandlerResult imaps_handle(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("IMAPS handler assigned to connection %lu", conn->id);

    const gchar *upstream_host = deadlight_config_get_string(ctx, "imaps", "upstream_host", "imap.gmail.com");
    gint upstream_port = deadlight_config_get_int(ctx, "imaps", "upstream_port", 993);

    g_info("IMAPS handler for conn %lu: connecting to upstream %s:%d", conn->id, upstream_host, upstream_port);

    // Step 1: Establish the plain TCP connection.
    if (!deadlight_network_connect_upstream(conn, error)) {
        g_warning("IMAPS handler failed to connect upstream for conn %lu", conn->id);
        return HANDLER_ERROR;
    }

    // Step 2: Secure the channel. This function performs the handshake.
    g_info("IMAPS handler for conn %lu: performing upstream TLS handshake.", conn->id);
    if (!deadlight_network_establish_upstream_ssl(conn, error)) {
        // The error is already logged by the handshake function.
        return HANDLER_ERROR;
    }
    
    // Step 3: Now that the channel is secure, forward the initial data from the detection buffer.
    if (conn->client_buffer && conn->client_buffer->len > 0) {
        g_info("IMAPS handler for conn %" G_GUINT64_FORMAT ": Forwarding initial %u bytes of data.", 
            conn->id, conn->client_buffer->len);
        
        // Get the output stream of our now-encrypted connection.
        GOutputStream *upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_tls));
        
        if (!g_output_stream_write_all(upstream_os, conn->client_buffer->data, conn->client_buffer->len, NULL, NULL, error)) {
            g_warning("IMAPS handler for conn %" G_GUINT64_FORMAT ": Failed to forward initial buffer: %s", 
                    conn->id, (*error)->message);
            return HANDLER_ERROR;
        }
    }

    // Step 4: Begin tunneling any subsequent data.
    g_info("IMAPS handler for conn %lu: Initial data sent, starting data tunnel.", conn->id);
    if (deadlight_network_tunnel_data(conn, error)) {
        g_info("IMAPS tunnel for conn %lu finished successfully.", conn->id);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        g_warning("IMAPS tunnel for conn %lu failed.", conn->id);
        return HANDLER_ERROR;
    }
}

/**
 * @brief Cleans up any resources specific to the IMAPS handler.
 * @param conn The connection object.
 */
static void imaps_cleanup(DeadlightConnection *conn) {
    // For this simple tunneling handler, there is no specific state to clean up.
    // The upstream socket is managed by the DeadlightConnection object itself.
    // If we had allocated memory with g_malloc, this is where we would g_free it.
    (void)conn; // Suppress unused parameter warning
    g_debug("IMAPS cleanup called for conn %lu", conn->id);
}