#include "http.h"
#include "core/ssl_tunnel.h"
#include "core/deadlight.h"
#include "core/utils.h"
#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include "protocols/api.h"

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

/* ── Response routing helper ─────────────────────────────────────────────────
 * Use this everywhere a response goes back to the client instead of writing
 * to client_connection directly.  Handles both socket and mesh origins.
 * ─────────────────────────────────────────────────────────────────────────── */
static gboolean send_client_response(DeadlightConnection *conn,
                                      const gchar *response)
{
    gsize len = strlen(response);

    /* Mesh origin — fragment and send back over LoRa */
    if (conn->mesh_source_node != 0) {
        return deadlight_mesh_send_response(conn, (const guint8 *)response, len);
    }

    /* Normal socket origin */
    GOutputStream *out;
    if (conn->client_tls) {
        out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_tls));
    } else {
        out = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    }

    GError *err = NULL;
    gboolean ok = g_output_stream_write_all(out, response, len, NULL, NULL, &err);
    if (!ok) {
        g_warning("Connection %lu: write to client failed: %s",
                  conn->id, err ? err->message : "unknown");
        g_clear_error(&err);
    }
    return ok;
}

// --- Protocol Handler Implementation ---

static gsize http_detect(const guint8 *data, gsize len) {
    // --- Check if it's a WebSocket upgrade first ---
    gchar *request_lower = NULL;
    if (len > 20) {
        gchar *request = g_strndup((const gchar*)data, len);
        request_lower = g_ascii_strdown(request, -1);

        if (strstr(request_lower, "upgrade: websocket") && strstr(request_lower, "sec-websocket-key:")) {
            g_free(request_lower);
            g_free(request);
            return 0; // Yield to the WebSocket handler
        }
        g_free(request);
    }

    if (request_lower) g_free(request_lower);

    const gchar *http_methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                                    "OPTIONS ", "TRACE ", "CONNECT ", "PATCH ", NULL};
    for (int i = 0; http_methods[i]; i++) {
        gsize method_len = strlen(http_methods[i]);
        if (len >= method_len && memcmp(data, http_methods[i], method_len) == 0) {
            return 8;
        }
    }
    return 0;
}

static DeadlightHandlerResult http_handle(DeadlightConnection *conn, GError **error) {
    if (conn->client_buffer->len > 8 && strncmp((char*)conn->client_buffer->data, "CONNECT ", 8) == 0) {
        conn->protocol = DEADLIGHT_PROTOCOL_CONNECT;
        return handle_connect(conn, error);
    }
    return handle_plain_http(conn, error);
}

static void http_cleanup(DeadlightConnection *conn) {
    (void)conn;
}

static DeadlightHandlerResult handle_plain_http(DeadlightConnection *conn, GError **error) {
    conn->current_request = deadlight_request_new(conn);

    if (!deadlight_request_parse_headers(conn->current_request,
                                          (const gchar *)conn->client_buffer->data,
                                          conn->client_buffer->len)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "Failed to parse HTTP request headers");
        return HANDLER_ERROR;
    }

    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: HTTP request blocked by plugin", conn->id);
        return HANDLER_SUCCESS_CLEANUP_NOW;
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

    /* ── Local request detection ──────────────────────────────────────────
     * Hard rules: loopback + proxy's own listen address.
     * Soft rule: operator-configured local_hostnames in [proxy].
     * ─────────────────────────────────────────────────────────────────── */
    gboolean is_local = (g_strcmp0(host, "localhost") == 0 ||
                         g_strcmp0(host, "127.0.0.1") == 0 ||
                         g_strcmp0(host, "::1") == 0 ||
                         g_strcmp0(host, "deadlight") == 0 ||
                         (conn->context->listen_address &&
                          g_strcmp0(host, conn->context->listen_address) == 0));

    if (!is_local && conn->context->local_hostnames) {
        for (gchar **lh = conn->context->local_hostnames; *lh && !is_local; lh++) {
            if (g_strcmp0(host, *lh) == 0 || strstr(host, *lh) != NULL)
                is_local = TRUE;
        }
    }

    if (is_local) {
        g_debug("Connection %lu: Local request to %s:%d → handling internally",
                conn->id, host, port);

        if (g_str_equal(conn->current_request->uri, "/metrics") ||
            g_str_equal(conn->current_request->uri, "/metrics/")) {
            g_free(host);
            return api_handle_prometheus_metrics(conn, error);
        }

        if (g_strcmp0(conn->current_request->uri, "/") == 0) {
            const gchar *status_body = "DEADLIGHT PROXY: ONLINE\n";
            gchar *response = g_strdup_printf(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s", strlen(status_body), status_body);
            send_client_response(conn, response);
            g_free(response);
            g_free(host);
            return HANDLER_SUCCESS_CLEANUP_NOW;
        }

        send_client_response(conn,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        g_debug("Connection %lu: Local resource '%s' not found",
                conn->id, conn->current_request->uri);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    /* ── Proxy to upstream ──────────────────────────────────────────────── */
    conn->target_host = g_strdup(host);
    conn->target_port = port;

    if (conn->target_port == conn->context->listen_port &&
        (g_strcmp0(conn->target_host, conn->context->listen_address) == 0 ||
         g_strcmp0(conn->target_host, "localhost") == 0 ||
         g_strcmp0(conn->target_host, "127.0.0.1") == 0)) {
        g_warning("Connection %lu: Detected proxy loop. Denying.", conn->id);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR;
    }

    g_info("Connection %lu: Forwarding HTTP to %s:%d",
           conn->id, conn->target_host, conn->target_port);
    g_free(host);

    if (!deadlight_network_connect_upstream(conn, error)) {
        return HANDLER_ERROR;
    }

    GOutputStream *upstream_output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->upstream_connection));
    if (!g_output_stream_write_all(upstream_output,
                                    conn->client_buffer->data,
                                    conn->client_buffer->len,
                                    NULL, NULL, error)) {
        return HANDLER_ERROR;
    }

    g_info("Connection %lu: Initial request sent, starting bidirectional tunnel.", conn->id);

    return deadlight_network_tunnel_data(conn, error)
        ? HANDLER_SUCCESS_CLEANUP_NOW
        : HANDLER_ERROR;
}

static DeadlightHandlerResult handle_connect(DeadlightConnection *conn, GError **error) {
    const gchar *data = (const gchar *)conn->client_buffer->data;
    const gchar *end_of_line = strstr(data, "\r\n");

    if (!end_of_line) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "Malformed CONNECT request: missing newline");
        return HANDLER_ERROR;
    }

    gchar *request_line = g_strndup(data, end_of_line - data);
    gchar **req_parts = g_strsplit(request_line, " ", 3);
    g_free(request_line);

    if (g_strv_length(req_parts) < 3 || g_strcmp0(req_parts[0], "CONNECT") != 0) {
        g_strfreev(req_parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "Invalid CONNECT request line format");
        return HANDLER_ERROR;
    }

    gchar *host = NULL;
    guint16 port = 443;
    if (!deadlight_parse_host_port(req_parts[1], &host, &port)) {
        g_strfreev(req_parts);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "Invalid host:port in CONNECT request");
        return HANDLER_ERROR;
    }

    conn->current_request = deadlight_request_new(conn);
    conn->current_request->method = g_strdup("CONNECT");
    conn->current_request->uri    = g_strdup(req_parts[1]);
    conn->current_request->host   = g_strdup(host);
    g_strfreev(req_parts);

    g_debug("Connection %lu: Plugin hook for CONNECT to %s", conn->id, host);

    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: CONNECT blocked by plugin", conn->id);
        g_free(host);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    if ((g_strcmp0(host, conn->context->listen_address) == 0 ||
         g_strcmp0(host, "localhost") == 0 ||
         g_strcmp0(host, "127.0.0.1") == 0) &&
        port == conn->context->listen_port) {
        g_warning("Connection %lu: Proxy loop to %s:%d. Denying.", conn->id, host, port);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(host);
        return HANDLER_ERROR;
    }

    g_info("Connection %lu: CONNECT to %s:%d", conn->id, host, port);
    conn->target_host = g_strdup(host);
    conn->target_port = port;

    if (!deadlight_network_connect_upstream(conn, error)) {
        g_free(host);
        return HANDLER_ERROR;
    }
    g_free(host);

    /* ── Send 200 back to client ─────────────────────────────────────────
     * CONNECT over mesh is a future concern — for now mesh clients should
     * only be sending plain HTTP (port 80).  Guard here so we don't assert
     * on client_connection for a mesh origin that somehow sends CONNECT.
     * ─────────────────────────────────────────────────────────────────── */
    if (conn->mesh_source_node != 0) {
        g_warning("Connection %lu (mesh): CONNECT tunnel not supported over LoRa yet", conn->id);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                    "CONNECT tunnel not supported for mesh-origin connections");
        return HANDLER_ERROR;
    }

    const gchar *established = "HTTP/1.1 200 Connection Established\r\n\r\n";
    GOutputStream *client_output = g_io_stream_get_output_stream(
        G_IO_STREAM(conn->client_connection));
    if (!g_output_stream_write_all(client_output, established, strlen(established),
                                    NULL, NULL, error)) {
        return HANDLER_ERROR;
    }

    if (!conn->context->ssl_intercept_enabled) {
        g_info("Connection %lu: SSL intercept disabled — plain TCP tunnel", conn->id);
        return deadlight_network_tunnel_data(conn, error)
            ? HANDLER_SUCCESS_CLEANUP_NOW
            : HANDLER_ERROR;
    }

    GError *intercept_error = NULL;
    if (deadlight_ssl_intercept_connection(conn, &intercept_error)) {
        g_info("Connection %lu: Tunneling with intercepted client TLS.", conn->id);
        g_info("Connection %lu: Tunneling with upstream TLS.", conn->id);

        GError *tunnel_error = NULL;
        gboolean ok = start_ssl_tunnel_blocking(conn, &tunnel_error);
        if (!ok && tunnel_error) {
            g_warning("Connection %lu: TLS tunnel error: %s",
                      conn->id, tunnel_error->message);
            g_error_free(tunnel_error);
        }
        return ok ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
    }

    if (conn->tls_passthrough) {
        g_info("Connection %lu: TLS passthrough for %s (upstream h2 or non-interceptable)",
               conn->id, conn->target_host);
        g_clear_error(&intercept_error);
        deadlight_network_tunnel_socket_connections(
            conn->client_connection,
            conn->upstream_connection);
        return HANDLER_SUCCESS_CLEANUP_NOW;
    }

    if (intercept_error) {
        g_warning("Connection %lu: SSL intercept failed for %s: %s",
                  conn->id, conn->target_host, intercept_error->message);
        g_propagate_error(error, intercept_error);
    }
    return HANDLER_ERROR;
}