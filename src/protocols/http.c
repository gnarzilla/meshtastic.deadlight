#include "http.h"
#include "core/ssl_tunnel.h"
#include "core/deadlight.h"
#include "core/utils.h"
#include <string.h>
#include <glib.h>
#include <gio/gio.h>

static gsize http_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult http_handle(DeadlightConnection *conn, GError **error);
static void http_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult handle_plain_http(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult handle_connect(DeadlightConnection *conn, GError **error);

// The handler object provided to the core
static const DeadlightProtocolHandler http_protocol_handler = {
    .name = "HTTP",
    .protocol_id = DEADLIGHT_PROTOCOL_HTTP,
    .detect = http_detect,
    .handle = http_handle,
    .cleanup = http_cleanup
};

// Public registration function
void deadlight_register_http_handler(void) {
    deadlight_protocol_register(&http_protocol_handler);
}

// --- Protocol Handler Implementation ---

static gsize http_detect(const guint8 *data, gsize len) {
    // --- Check if it's a WebSocket upgrade first ---
    gchar *request_lower = NULL;
    if (len > 20) { // A reasonable length to check headers
        gchar *request = g_strndup((const gchar*)data, len);
        request_lower = g_ascii_strdown(request, -1);
        
        // If it has WebSocket headers, it's NOT for the plain HTTP handler.
        if (strstr(request_lower, "upgrade: websocket") && strstr(request_lower, "sec-websocket-key:")) {
            g_free(request_lower);
            g_free(request);
            return 0; // Yield to the WebSocket handler
        }
    }

    // Free the temp string if we allocated it
    if (request_lower) g_free(request_lower);

    // --- ORIGINAL LOGIC: If it's not WebSocket, check for standard HTTP ---
    const gchar *http_methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "TRACE ", "CONNECT ", "PATCH ", NULL};
    for (int i = 0; http_methods[i]; i++) {
        gsize method_len = strlen(http_methods[i]);
        if (len >= method_len && memcmp(data, http_methods[i], method_len) == 0) {
            // Return a medium priority, lower than WebSocket's 20.
            return 8; 
        }
    }
    return 0;
}

static DeadlightHandlerResult http_handle(DeadlightConnection *conn, GError **error) {
    if (conn->client_buffer->len > 8 && strncmp((char*)conn->client_buffer->data, "CONNECT ", 8) == 0) {
        conn->protocol = DEADLIGHT_PROTOCOL_CONNECT;
        return handle_connect(conn, error); // handle_connect also returns DeadlightHandlerResult
    }
    return handle_plain_http(conn, error); // handle_plain_http also returns DeadlightHandlerResult
}

static void http_cleanup(DeadlightConnection *conn) {
    (void)conn;
}

static DeadlightHandlerResult handle_plain_http(DeadlightConnection *conn, GError **error) {
    conn->current_request = deadlight_request_new(conn);

    // Parse headers first
    if (!deadlight_request_parse_headers(conn->current_request, (const gchar *)conn->client_buffer->data, conn->client_buffer->len)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Failed to parse HTTP request headers");
        return HANDLER_ERROR;
    }

    // ADD THIS DEBUG AND PLUGIN CALL:
    g_debug("Connection %lu: Calling plugin hook for %s %s", 
            conn->id, conn->current_request->method, conn->current_request->uri);
    
    // Call plugin hook for request headers
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: HTTP request blocked by plugin", conn->id);
        return HANDLER_SUCCESS_CLEANUP_NOW; // Plugin handled the response
    }

    // Check if this is an API request BEFORE checking for proxy loops
    if (g_str_has_prefix(conn->current_request->uri, "/api/")) {
        const gchar *host_header = deadlight_request_get_header(conn->current_request, "host");
        if (host_header && (strstr(host_header, "localhost") || strstr(host_header, "127.0.0.1"))) {
            g_info("Connection %lu: API request detected, HTTP handler passing", conn->id);
            // Return error so the connection gets re-evaluated by other handlers
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "API request - wrong handler");
            return HANDLER_ERROR;
        }
    }

    const gchar *host_header = deadlight_request_get_header(conn->current_request, "host");
    if (!host_header) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Missing Host header");
        return HANDLER_ERROR;
    }

    gchar *host = NULL;
    guint16 port = 80;
    if (!deadlight_parse_host_port(host_header, &host, &port)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid Host header");
        return HANDLER_ERROR; 
    }

    // *** DETECT PROXY LOOP ***
    if ((g_strcmp0(host, conn->context->listen_address) == 0 || g_strcmp0(host, "localhost") == 0 || g_strcmp0(host, "127.0.0.1") == 0) && port == conn->context->listen_port) {
        g_warning("Connection %lu: Detected proxy loop to %s:%d. Denying request.", conn->id, host, port);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR;
    }

    g_info("Connection %lu: HTTP request to %s:%d", conn->id, host, port);
    
    if (!deadlight_network_connect_upstream(conn, error)) {
        g_free(host);
        return HANDLER_ERROR;
    }
    g_free(host);

    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_connection));
    if (g_output_stream_write_all(upstream_output, conn->client_buffer->data, conn->client_buffer->len, NULL, NULL, error) == FALSE) {
        return HANDLER_ERROR;
    }
    
    g_info("Connection %lu: Initial request sent, starting bidirectional tunnel.", conn->id);
    
    // deadlight_network_tunnel_data is BLOCKING. When it returns, the connection is finished.
    if (deadlight_network_tunnel_data(conn, error)) {
        return HANDLER_SUCCESS_CLEANUP_NOW;
    } else {
        return HANDLER_ERROR;
    }
}

static DeadlightHandlerResult handle_connect(DeadlightConnection *conn, GError **error) {

    // 1. Get a pointer to the start of the buffer and find the end of the first line.
    const gchar *data = (const gchar *)conn->client_buffer->data;
    const gchar *end_of_line = strstr(data, "\r\n");

    // If we can't even find a newline, the request is malformed.
    if (!end_of_line) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Malformed CONNECT request: missing newline");
        return HANDLER_ERROR;
    }

    // 2. Copy *only* the first line, avoiding a large allocation if the buffer is big.
    gchar *request_line = g_strndup(data, end_of_line - data);
    
    // 3. Split the request line into its three expected parts.
    gchar **req_parts = g_strsplit(request_line, " ", 3);
    g_free(request_line); // The temporary line is no longer needed.

    // 4. Stricter validation: We need exactly 3 parts, and the first must be "CONNECT".
    if (g_strv_length(req_parts) < 3 || g_strcmp0(req_parts[0], "CONNECT") != 0) {
        g_strfreev(req_parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid CONNECT request line format");
        return HANDLER_ERROR;
    }

    gchar *host = NULL;
    guint16 port = 443; // Default port for CONNECT
    if (!deadlight_parse_host_port(req_parts[1], &host, &port)) { // req_parts[1] is the "host:port" string
        g_strfreev(req_parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid host:port in CONNECT request");
        return HANDLER_ERROR;
    }

    // Populate the request object for logging and plugins
    conn->current_request = deadlight_request_new(conn);
    conn->current_request->method = g_strdup("CONNECT");
    conn->current_request->uri = g_strdup(req_parts[1]); // e.g., "example.com:443"
    conn->current_request->host = g_strdup(host); // e.g., "example.com"

    g_strfreev(req_parts); // We're done with the split parts, so free the array.

    g_debug("Connection %lu: Calling plugin hook for CONNECT to %s", conn->id, host);

    // Call plugin hook for CONNECT requests
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: CONNECT request blocked by plugin", conn->id);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }
    
    // Proxy loop prevention
    if ((g_strcmp0(host, conn->context->listen_address) == 0 || g_strcmp0(host, "localhost") == 0 || g_strcmp0(host, "127.0.0.1") == 0) && port == conn->context->listen_port) {
        g_warning("Connection %lu: Detected proxy loop to %s:%d. Denying request.", conn->id, host, port);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR;
    }

    g_info("Connection %lu: CONNECT request to %s:%d", conn->id, host, port);
    conn->target_host = g_strdup(host);
    conn->target_port = port;

    if (!deadlight_network_connect_upstream(conn, error)) {
        g_free(host);
        return HANDLER_ERROR;
    }
    g_free(host); // The host string is no longer needed after this point.

    const gchar *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    if (g_output_stream_write_all(client_output, response, strlen(response), NULL, NULL, error) == FALSE) {
        return HANDLER_ERROR;
    }

    if (conn->context->ssl_intercept_enabled) {
        if (deadlight_ssl_intercept_connection(conn, error)) {
            g_info("Connection %lu: Tunneling with intercepted client TLS.", conn->id);
            g_info("Connection %lu: Tunneling with upstream TLS.", conn->id);
            
            if (start_ssl_tunnel_blocking(conn, error)) {
                return HANDLER_SUCCESS_CLEANUP_NOW;
            } else {
                return HANDLER_ERROR;
            }
        } else {
            return HANDLER_ERROR;
        }
    } else {
        // Non-intercepted CONNECT - plain TCP tunnel
        g_info("Connection %lu: SSL intercept disabled. Starting plain TCP tunnel.", conn->id);
        if (deadlight_network_tunnel_data(conn, error)) {
            return HANDLER_SUCCESS_CLEANUP_NOW;
        } else {
            return HANDLER_ERROR;
        }
    }
}
