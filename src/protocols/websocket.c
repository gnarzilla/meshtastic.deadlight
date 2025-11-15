#include "websocket.h"
#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gchecksum.h>
#include "core/utils.h"

#define WS_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_FRAME_SIZE (1024 * 1024) // 1MB max frame size
#define WS_PING_INTERVAL 30 // seconds

// WebSocket protocol data
typedef struct {
    gboolean compression_enabled;
    GTimer *last_ping_timer;
    gboolean close_received;
    guint16 close_code;
    gchar *close_reason;
    guint64 messages_sent;
    guint64 messages_received;
    GMutex frame_mutex; // Thread safety for frame operations
} WebSocketData;

// Forward declarations
static gsize websocket_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult websocket_handle(DeadlightConnection *conn, GError **error);
static void websocket_cleanup(DeadlightConnection *conn);
static gchar* websocket_calculate_accept_key(const gchar *client_key);
static gboolean websocket_frame_relay_loop(DeadlightConnection *conn, GError **error);
static gboolean read_ws_frame(GInputStream *is, WebSocketFrame *frame, GError **error);
static gboolean write_ws_frame(GOutputStream *os, const WebSocketFrame *frame, GError **error);
static void websocket_frame_free(WebSocketFrame *frame);
static gboolean websocket_send_pong(GOutputStream *os, const guint8 *ping_data, gsize ping_len, GError **error);
static const gchar* websocket_opcode_to_string(guint8 opcode);

// Protocol handler definition
static const DeadlightProtocolHandler websocket_protocol_handler = {
    .name = "WebSocket",
    .protocol_id = DEADLIGHT_PROTOCOL_WEBSOCKET,
    .detect = websocket_detect,
    .handle = websocket_handle,
    .cleanup = websocket_cleanup
};

void deadlight_register_websocket_handler(void) {
    deadlight_protocol_register(&websocket_protocol_handler);
}

static gsize websocket_detect(const guint8 *data, gsize len) {
    // WebSocket starts as HTTP GET request
    if (len < 4 || memcmp(data, "GET ", 4) != 0) {
        return 0;
    }
    
    // Need enough data to analyze headers
    if (len < 100) {
        return 0; // Need more data
    }
    
    // Convert to string for header searching - ensure null termination
    gchar *request = g_strndup((const gchar*)data, MIN(len, 8192));
    gchar *request_lower = g_ascii_strdown(request, -1);
    
    // Check for required WebSocket headers
    gboolean has_upgrade = strstr(request_lower, "upgrade: websocket") != NULL;
    gboolean has_connection = strstr(request_lower, "connection:") && 
                             (strstr(request_lower, "upgrade") != NULL);
    gboolean has_ws_key = strstr(request_lower, "sec-websocket-key:") != NULL;
    gboolean has_ws_version = strstr(request_lower, "sec-websocket-version:") != NULL;
    
    g_free(request);
    g_free(request_lower);
    
    // All headers required for valid WebSocket request
    if (has_upgrade && has_connection && has_ws_key && has_ws_version) {
        return 20; // Higher priority than plain HTTP
    }
    
    return 0;
}

// Improved read_ws_frame function with better error handling
static gboolean read_ws_frame(GInputStream *is, WebSocketFrame *frame, GError **error) {
    guint8 header[2];
    gsize bytes_read = 0;
    
    // Initialize frame
    memset(frame, 0, sizeof(WebSocketFrame));
    
    if (!g_input_stream_read_all(is, header, 2, &bytes_read, NULL, error)) {
        return FALSE;
    }
    
    if (bytes_read != 2) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE, "Incomplete frame header");
        return FALSE;
    }

    frame->fin = (header[0] & 0x80) != 0;
    frame->opcode = header[0] & 0x0F;
    gboolean masked = (header[1] & 0x80) != 0;
    guint64 len = header[1] & 0x7F;

    // Read extended payload length
    if (len == 126) {
        guint16 len16;
        if (!g_input_stream_read_all(is, &len16, 2, &bytes_read, NULL, error)) {
            return FALSE;
        }
        if (bytes_read != 2) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE, "Incomplete extended length");
            return FALSE;
        }
        len = g_ntohs(len16);
    } else if (len == 127) {
        guint64 len64;
        if (!g_input_stream_read_all(is, &len64, 8, &bytes_read, NULL, error)) {
            return FALSE;
        }
        if (bytes_read != 8) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE, "Incomplete extended length");
            return FALSE;
        }
        len = GUINT64_FROM_BE(len64);
    }
    
    // Validate frame size
    if (len > WS_MAX_FRAME_SIZE) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, 
                   "Frame too large: %" G_GUINT64_FORMAT " bytes", len);
        return FALSE;
    }
    
    frame->payload_len = len;

    // Read mask key if present
    guint8 mask_key[4] = {0};
    if (masked) {
        if (!g_input_stream_read_all(is, mask_key, 4, &bytes_read, NULL, error)) {
            return FALSE;
        }
        if (bytes_read != 4) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE, "Incomplete mask key");
            return FALSE;
        }
    }

    // Read payload
    if (frame->payload_len > 0) {
        frame->payload = g_malloc(frame->payload_len);
        if (!g_input_stream_read_all(is, frame->payload, frame->payload_len, &bytes_read, NULL, error)) {
            g_free(frame->payload);
            frame->payload = NULL;
            return FALSE;
        }
        if (bytes_read != frame->payload_len) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE, "Incomplete payload");
            g_free(frame->payload);
            frame->payload = NULL;
            return FALSE;
        }
        
        // Unmask payload if masked
        if (masked) {
            for (guint64 i = 0; i < frame->payload_len; i++) {
                frame->payload[i] ^= mask_key[i % 4];
            }
        }
    }
    
    return TRUE;
}

// New function to write WebSocket frames
static gboolean write_ws_frame(GOutputStream *os, const WebSocketFrame *frame, GError **error) {
    guint8 header[14]; // Max header size
    gsize header_len = 2;
    
    header[0] = (frame->fin ? 0x80 : 0x00) | (frame->opcode & 0x0F);
    
    if (frame->payload_len < 126) {
        header[1] = (guint8)frame->payload_len;
    } else if (frame->payload_len <= 0xFFFF) {
        header[1] = 126;
        guint16 len16 = g_htons((guint16)frame->payload_len);
        memcpy(&header[2], &len16, 2);
        header_len = 4;
    } else {
        header[1] = 127;
        guint64 len64 = GUINT64_TO_BE(frame->payload_len);
        memcpy(&header[2], &len64, 8);
        header_len = 10;
    }
    
    // Write header
    if (!g_output_stream_write_all(os, header, header_len, NULL, NULL, error)) {
        return FALSE;
    }
    
    // Write payload
    if (frame->payload_len > 0 && frame->payload) {
        if (!g_output_stream_write_all(os, frame->payload, frame->payload_len, NULL, NULL, error)) {
            return FALSE;
        }
    }
    
    return g_output_stream_flush(os, NULL, error);
}

// Helper to free WebSocket frame
static void websocket_frame_free(WebSocketFrame *frame) {
    if (frame && frame->payload) {
        g_free(frame->payload);
        frame->payload = NULL;
        frame->payload_len = 0;
    }
}

// Send pong response to ping
static gboolean websocket_send_pong(GOutputStream *os, const guint8 *ping_data, gsize ping_len, GError **error) {
    WebSocketFrame pong_frame = {
        .fin = TRUE,
        .opcode = WS_OPCODE_PONG,
        .payload_len = ping_len,
        .payload = (guint8*)ping_data
    };
    
    return write_ws_frame(os, &pong_frame, error);
}

// Helper function to convert opcode to string for logging
static const gchar* websocket_opcode_to_string(guint8 opcode) {
    switch (opcode) {
        case WS_OPCODE_CONTINUATION: return "CONTINUATION";
        case WS_OPCODE_TEXT: return "TEXT";
        case WS_OPCODE_BINARY: return "BINARY";
        case WS_OPCODE_CLOSE: return "CLOSE";
        case WS_OPCODE_PING: return "PING";
        case WS_OPCODE_PONG: return "PONG";
        default: return "UNKNOWN";
    }
}

static gchar* websocket_calculate_accept_key(const gchar *client_key) {
    if (!client_key || strlen(client_key) == 0) {
        return NULL;
    }
    
    // Concatenate client key with magic string
    gchar *concat = g_strconcat(client_key, WS_MAGIC_STRING, NULL);
    
    // Calculate SHA-1 hash
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA1);
    g_checksum_update(checksum, (guchar*)concat, strlen(concat));
    
    // Get digest
    guint8 digest[20];
    gsize digest_len = 20;
    g_checksum_get_digest(checksum, digest, &digest_len);
    
    // Base64 encode
    gchar *accept_key = g_base64_encode(digest, digest_len);
    
    // Cleanup
    g_checksum_free(checksum);
    g_free(concat);
    
    return accept_key;
}

static gboolean websocket_frame_relay_loop(DeadlightConnection *conn, GError **error) {
    WebSocketData *ws_data = (WebSocketData*)conn->protocol_data;
    if (!ws_data) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "WebSocket data not initialized");
        return FALSE;
    }

    g_info("WebSocket [%lu]: Starting frame relay loop", conn->id);  // Add this

    GInputStream *client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    GInputStream *upstream_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
    GOutputStream *upstream_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));

    // Set up polling for both streams
    GPollFD client_poll = {0};
    GPollFD upstream_poll = {0};
    
    if (G_IS_SOCKET_CONNECTION(conn->client_connection)) {
        GSocket *client_socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->client_connection));
        client_poll.fd = g_socket_get_fd(client_socket);
        client_poll.events = G_IO_IN | G_IO_HUP | G_IO_ERR;
    }
    
    if (G_IS_SOCKET_CONNECTION(conn->upstream_connection)) {
        GSocket *upstream_socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->upstream_connection));
        upstream_poll.fd = g_socket_get_fd(upstream_socket);
        upstream_poll.events = G_IO_IN | G_IO_HUP | G_IO_ERR;
    }

    while (!ws_data->close_received && !conn->context->shutdown_requested) {
        // Poll both connections with timeout
        GPollFD polls[] = {client_poll, upstream_poll};
        gint poll_result = g_poll(polls, 2, 1000); // 1 second timeout
        
        if (poll_result < 0) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Poll failed");
            return FALSE;
        }
        
        if (poll_result == 0) {
            // Timeout - continue loop to check shutdown
            continue;
        }
        // ===== CLIENT -> UPSTREAM SECTION =====
        if (polls[0].revents & G_IO_IN) {
            WebSocketFrame frame = {0};
            GError *local_error = NULL;
            
            if (read_ws_frame(client_is, &frame, &local_error)) {
                g_mutex_lock(&ws_data->frame_mutex);
                
                g_info("WebSocket [%lu] C->S: %s frame, fin=%d, len=%lu", 
                    conn->id, websocket_opcode_to_string(frame.opcode), 
                    frame.fin, frame.payload_len);
                
                switch (frame.opcode) {
                    case WS_OPCODE_TEXT:
                    case WS_OPCODE_BINARY:
                        write_ws_frame(upstream_os, &frame, NULL);
                        ws_data->messages_sent++;
                        conn->bytes_client_to_upstream += frame.payload_len;
                        break;
                        
                    case WS_OPCODE_PING:
                        websocket_send_pong(client_os, frame.payload, frame.payload_len, NULL);
                        write_ws_frame(upstream_os, &frame, NULL);
                        break;
                        
                    case WS_OPCODE_PONG:
                        write_ws_frame(upstream_os, &frame, NULL);
                        break;
                        
                    case WS_OPCODE_CLOSE:
                        ws_data->close_received = TRUE;
                        write_ws_frame(upstream_os, &frame, NULL);
                        break;
                        
                    default:
                        g_warning("WebSocket [%lu] C->S: Unknown opcode %s (0x%02x)", 
                                conn->id, websocket_opcode_to_string(frame.opcode), frame.opcode);
                        break;
                }
                
                g_mutex_unlock(&ws_data->frame_mutex);
                websocket_frame_free(&frame);
            } else {
                if (local_error) {
                    g_debug("WebSocket [%lu] Client read error: %s", conn->id, local_error->message);
                    g_error_free(local_error);
                }
                break;
            }
        }

        // ===== UPSTREAM -> CLIENT SECTION =====
        if (polls[1].revents & G_IO_IN) {
            WebSocketFrame frame = {0};
            GError *local_error = NULL;
            
            if (read_ws_frame(upstream_is, &frame, &local_error)) {
                g_mutex_lock(&ws_data->frame_mutex);
                
                g_info("WebSocket [%lu] S->C: %s frame, fin=%d, len=%lu", 
                    conn->id, websocket_opcode_to_string(frame.opcode),
                    frame.fin, frame.payload_len);
                
                switch (frame.opcode) {
                    case WS_OPCODE_TEXT:
                    case WS_OPCODE_BINARY:
                        write_ws_frame(client_os, &frame, NULL);
                        ws_data->messages_received++;
                        conn->bytes_upstream_to_client += frame.payload_len;
                        break;
                        
                    case WS_OPCODE_PING:
                        websocket_send_pong(upstream_os, frame.payload, frame.payload_len, NULL);
                        write_ws_frame(client_os, &frame, NULL);
                        break;
                        
                    case WS_OPCODE_PONG:
                        write_ws_frame(client_os, &frame, NULL);
                        break;
                        
                    case WS_OPCODE_CLOSE:
                        ws_data->close_received = TRUE;
                        write_ws_frame(client_os, &frame, NULL);
                        break;
                        
                    default:
                        g_warning("WebSocket [%lu] S->C: Unknown opcode %s (0x%02x)", 
                                conn->id, websocket_opcode_to_string(frame.opcode), frame.opcode);
                        break;
                }
                
                g_mutex_unlock(&ws_data->frame_mutex);
                websocket_frame_free(&frame);
            } else {
                if (local_error) {
                    g_debug("WebSocket [%lu] Upstream read error: %s", conn->id, local_error->message);
                    g_error_free(local_error);
                }
                break;
            }
        }
        // Check for connection errors
        if ((polls[0].revents & (G_IO_HUP | G_IO_ERR)) || 
            (polls[1].revents & (G_IO_HUP | G_IO_ERR))) {
            g_debug("Connection error detected");
            break;
        }
    }
    
    g_info("WebSocket relay loop ended for connection %lu. Messages: %lu sent, %lu received", 
           conn->id, ws_data->messages_sent, ws_data->messages_received);
    
    return TRUE;
}

static DeadlightHandlerResult websocket_handle(DeadlightConnection *conn, GError **error) {
    // Parse the WebSocket upgrade request
    conn->current_request = deadlight_request_new(conn);
    if (!deadlight_request_parse_headers(conn->current_request, 
                                       (const gchar *)conn->client_buffer->data, 
                                       conn->client_buffer->len)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Failed to parse WebSocket upgrade request");
        return HANDLER_ERROR;
    }
    
    // Validate required headers
    const gchar *ws_key = deadlight_request_get_header(conn->current_request, "Sec-WebSocket-Key");
    const gchar *ws_version = deadlight_request_get_header(conn->current_request, "Sec-WebSocket-Version");
    const gchar *host_header = deadlight_request_get_header(conn->current_request, "Host");
    
    if (!ws_key) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Missing Sec-WebSocket-Key header");
        return HANDLER_ERROR;
    }
    
    if (!ws_version || g_strcmp0(ws_version, "13") != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Unsupported WebSocket version");
        return HANDLER_ERROR;
    }
    
    if (!host_header) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Missing Host header");
        return HANDLER_ERROR;
    }
    
    // Calculate accept key
    gchar *accept_key = websocket_calculate_accept_key(ws_key);
    if (!accept_key) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Failed to calculate accept key");
        return HANDLER_ERROR;
    }

    // Parse host and port
    gchar *host = NULL;
    guint16 port = 80;
    if (!deadlight_parse_host_port(host_header, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Host header");
        g_free(accept_key);
        return HANDLER_ERROR;
    }

    // Connect to upstream
    if (!deadlight_network_connect_upstream(conn, error)) {
        g_free(host);
        g_free(accept_key);
        return HANDLER_ERROR;
    }
    
    // Create upstream WebSocket upgrade request
    GString *upstream_request = g_string_new("");
    g_string_append_printf(upstream_request, "GET %s HTTP/1.1\r\n", 
                          conn->current_request->path ? conn->current_request->path : "/");
    g_string_append_printf(upstream_request, "Host: %s\r\n", host_header);
    g_string_append(upstream_request, "Upgrade: websocket\r\n");
    g_string_append(upstream_request, "Connection: Upgrade\r\n");
    g_string_append(upstream_request, "Sec-WebSocket-Version: 13\r\n");

    // Generate new key for upstream
    guchar client_key_buf[16];
    for (int i = 0; i < 16; i++) { 
        client_key_buf[i] = g_random_int_range(0, 256); 
    }
    gchar *new_client_key = g_base64_encode(client_key_buf, sizeof(client_key_buf));
    g_string_append_printf(upstream_request, "Sec-WebSocket-Key: %s\r\n\r\n", new_client_key);

    // Send upgrade request to upstream
    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    if (!g_output_stream_write_all(upstream_output, upstream_request->str, upstream_request->len, 
                                  NULL, NULL, error)) {
        g_free(new_client_key);
        g_string_free(upstream_request, TRUE);
        g_free(host);
        g_free(accept_key);
        return HANDLER_ERROR;
    }
    g_string_free(upstream_request, TRUE);

    // Read upstream response
    GInputStream *upstream_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_connection));
    guint8 response_buffer[4096];
    gssize bytes_read = g_input_stream_read(upstream_input, response_buffer, 
                                          sizeof(response_buffer) - 1, NULL, error);
    
    if (bytes_read <= 0) {
        g_free(new_client_key);
        g_free(host);
        g_free(accept_key);
        return HANDLER_ERROR;
    }
    
    response_buffer[bytes_read] = '\0';
    
    // Check if upstream accepted the WebSocket upgrade
    if (!g_str_has_prefix((char*)response_buffer, "HTTP/1.1 101")) {
        g_debug("Upstream rejected WebSocket upgrade: %s", (char*)response_buffer);
        // Forward the rejection to client
        GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_output, response_buffer, bytes_read, NULL, NULL, NULL);
        g_free(new_client_key);
        g_free(host);
        g_free(accept_key);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    // Send successful upgrade response to client
    GString *response = g_string_new("HTTP/1.1 101 Switching Protocols\r\n");
    g_string_append(response, "Upgrade: websocket\r\n");
    g_string_append(response, "Connection: Upgrade\r\n");
    g_string_append_printf(response, "Sec-WebSocket-Accept: %s\r\n\r\n", accept_key);

    GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    if (!g_output_stream_write_all(client_output, response->str, response->len, 
                                  NULL, NULL, error)) {
        g_string_free(response, TRUE);
        g_free(new_client_key);
        g_free(host);
        g_free(accept_key);
        return HANDLER_ERROR;
    }
    g_string_free(response, TRUE);

    g_info("Connection %lu: WebSocket MITM established with %s:%u. Relaying frames.", 
           conn->id, host, port);
    
    // Cleanup
    g_free(new_client_key);
    g_free(host);
    g_free(accept_key);
    
    // Initialize WebSocket protocol data
    WebSocketData *ws_data = g_new0(WebSocketData, 1);
    ws_data->last_ping_timer = g_timer_new();
    g_mutex_init(&ws_data->frame_mutex);
    conn->protocol_data = ws_data;

    // Start frame relay loop
    if (websocket_frame_relay_loop(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

static void websocket_cleanup(DeadlightConnection *conn) {
    if (conn->protocol_data) {
        WebSocketData *ws_data = (WebSocketData*)conn->protocol_data;
        
        if (ws_data->last_ping_timer) {
            g_timer_destroy(ws_data->last_ping_timer);
        }
        
        g_mutex_clear(&ws_data->frame_mutex);
        g_free(ws_data->close_reason);
        g_free(ws_data);
        conn->protocol_data = NULL;
    }
}