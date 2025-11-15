#include "api.h"
#include <string.h>
#include <json-glib/json-glib.h>
#include <time.h>
#include "core/utils.h"

static gsize api_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error);
static void api_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_federation_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_send_404(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, gint status_code, const gchar *status_text, const gchar *json_body, GError **error);
static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, DeadlightRequest *request, GError **error);
static DeadlightHandlerResult api_handle_metrics_endpoint(DeadlightConnection *conn, GError **error);

static const DeadlightProtocolHandler api_protocol_handler = {
    .name = "API",
    .protocol_id = DEADLIGHT_PROTOCOL_API, // Reuse HTTP protocol ID
    .detect = api_detect,
    .handle = api_handle,
    .cleanup = api_cleanup
};

void deadlight_register_api_handler(void) {
    deadlight_protocol_register(&api_protocol_handler);
}

static gsize api_detect(const guint8 *data, gsize len) {
    g_debug("API detect called with %zu bytes: %.20s", len, (char*)data);

    // Need at least "GET /api/" (9 chars)
    if (len < 9) return 0;
    
    // Check for API path in the request line (before headers)
    if ((len >= 9 && memcmp(data, "GET /api/", 9) == 0) ||
        (len >= 10 && memcmp(data, "POST /api/", 10) == 0) ||
        (len >= 9 && memcmp(data, "PUT /api/", 9) == 0) ||
        (len >= 12 && memcmp(data, "DELETE /api/", 12) == 0)) {
        
        // Return high priority
        return 100; // Much higher than HTTP's max of 8
    }
    
    return 0;
}

static DeadlightHandlerResult api_handle(DeadlightConnection *conn, GError **error) {
    g_info("API handler for connection %lu", conn->id);
    
    // Debug: Show the raw request
    gchar *request_preview = g_strndup((gchar*)conn->client_buffer->data, 
                                       MIN(conn->client_buffer->len, 200));
    g_debug("API conn %lu: Raw request preview: %s", conn->id, request_preview);
    g_free(request_preview);

    // Parse HTTP request
    DeadlightRequest *request = deadlight_request_new(conn);
    
    // Convert buffer to string for parsing
    gchar *request_str = g_strndup((gchar*)conn->client_buffer->data, conn->client_buffer->len);
    
    if (!deadlight_request_parse_headers(request, request_str, strlen(request_str))) {
        g_free(request_str);
        deadlight_request_free(request);
        return HANDLER_ERROR;
    }
    
    g_free(request_str);

    DeadlightHandlerResult result = HANDLER_ERROR;

    if (g_str_equal(request->method, "OPTIONS")) {
        // Handle CORS preflight
        const gchar *response = 
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: https://deadlight.boo\r\n"
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, X-API-Key\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        
        GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
        g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error);
        result = HANDLER_SUCCESS_CLEANUP_NOW;
    } else if (g_str_has_prefix(request->uri, "/api/system/")) {
        result = api_handle_system_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/email/")) {
        result = api_handle_email_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/blog/")) {
        result = api_handle_blog_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/federation/")) {
        result = api_handle_federation_endpoint(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/metrics")) {
        result = api_handle_metrics_endpoint(conn, error);
    } else {
        result = api_send_404(conn, error);
    }
    
    deadlight_request_free(request);
    return result;
}

static DeadlightHandlerResult api_handle_system_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    if (g_str_equal(request->uri, "/api/system/ip")) {
        // Return current external IP
        gchar *ip = get_external_ip(); // Can implement this
        gchar *json_response = g_strdup_printf("{\"external_ip\":\"%s\",\"port\":8080}", ip);
        DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_response, error);
        g_free(json_response);
        g_free(ip);
        return result;
    }
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_federation_endpoint(DeadlightConnection *conn, 
                                                           DeadlightRequest *request, 
                                                           GError **error) {
    // This is where the magic happens for decentralized social media!
    // Handle instance-to-instance communication via email protocols
    
    if (g_str_equal(request->uri, "/api/federation/send")) {
        // Send a post/comment to another deadlight instance via email
        return api_federation_send(conn, request, error);
    } else if (g_str_equal(request->uri, "/api/federation/receive")) {
        // Receive and process a post/comment from another instance
        return api_federation_receive(conn, request, error);
    } else if (g_str_has_prefix(request->uri, "/api/federation/test/")) {
        // Domain testing endpoint - extract the domain name
        const gchar *domain = request->uri + strlen("/api/federation/test/");
        g_info("API federation domain test for: %s", domain);
        
        // For now, simulate a successful test
        // TODO: Implement actual domain connectivity testing
        gchar *json_response = g_strdup_printf(
            "{\"domain\":\"%s\",\"status\":\"verified\",\"trust_level\":\"verified\",\"test_time\":\"%ld\",\"active\":true}", 
            domain, time(NULL));
        
        DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_response, error);
        g_free(json_response);
        return result;
    } else if (g_str_equal(request->uri, "/api/federation/status")) {
        // Federation system status
        const gchar *json_response = 
            "{"
            "\"status\":\"online\","
            "\"connected_domains\":1,"
            "\"posts_sent\":0,"
            "\"posts_received\":0,"
            "\"comments_synced\":0"
            "}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
    }
    
    return api_send_404(conn, error);
}

static void api_cleanup(DeadlightConnection *conn) {
    g_debug("API cleanup called for conn %lu", conn->id);
    // Clean up any API-specific resources
    (void)conn; // Suppress unused parameter warning
}

static DeadlightHandlerResult api_send_404(DeadlightConnection *conn, GError **error) {
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    const gchar *response = 
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 34\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"error\":\"API endpoint not found\"}";
    
    if (!g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error)) {
        g_warning("API conn %lu: Failed to send 404 response", conn->id);
        return HANDLER_ERROR;
    }
    
    return HANDLER_SUCCESS_CLEANUP_NOW;
}

static DeadlightHandlerResult api_send_json_response(DeadlightConnection *conn, gint status_code, 
                                                    const gchar *status_text, const gchar *json_body, 
                                                    GError **error) {
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    
    gchar *response = g_strdup_printf(
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: https://deadlight.boo\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, X-API-Key\r\n"
        "Content-Encoding: identity\r\n"  // Explicitly disable compression
        "Cache-Control: no-cache\r\n"     // Prevent caching issues
        "Connection: close\r\n"
        "\r\n"
        "%s", status_code, status_text, strlen(json_body), json_body);

    // Add this debug logging
    g_debug("API conn %lu: Sending response (%zu bytes):\n%s", 
            conn->id, strlen(response), response);
    
    gboolean success = g_output_stream_write_all(client_os, response, strlen(response), NULL, NULL, error);
    if (!success) {
        g_warning("API conn %lu: Failed to write response: %s", 
                  conn->id, error && *error ? (*error)->message : "unknown error");
    }
    
    g_free(response);
    return success ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

static DeadlightHandlerResult api_handle_email_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    g_info("API email endpoint for conn %lu: %s %s", conn->id, request->method, request->uri);
    
    if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/send")) {
        // Handle email sending
        const gchar *json_response = "{\"status\":\"success\",\"message\":\"Email queued for sending\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
        
    } else if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/receive")) {
        // Handle incoming email (from SMTP bridge)
        const gchar *json_response = "{\"status\":\"success\",\"message\":\"Email received and processed\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
        
    } else if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/status")) {
        // Email system status
        const gchar *json_response = "{\"status\":\"running\",\"queue_size\":0,\"last_processed\":null}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
    }
    
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_handle_blog_endpoint(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    g_info("API blog endpoint for conn %lu: %s %s", conn->id, request->method, request->uri);
    
    if (g_str_equal(request->method, "POST") && g_str_has_suffix(request->uri, "/publish")) {
        // Handle blog post publishing
        const gchar *json_response = "{\"status\":\"success\",\"message\":\"Post published successfully\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
        
    } else if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/posts")) {
        // List blog posts
        const gchar *json_response = "{\"posts\":[],\"total\":0}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
        
    } else if (g_str_equal(request->method, "GET") && g_str_has_suffix(request->uri, "/status")) {
        // Blog status
        const gchar *json_response = "{\"status\":\"running\",\"version\":\"4.0.0\"}";
        return api_send_json_response(conn, 200, "OK", json_response, error);
    }
    
    return api_send_404(conn, error);
}

static DeadlightHandlerResult api_federation_send(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    (void)request;
    g_info("API federation send for conn %lu", conn->id);
    
    // TODO: Implement federated post sending via email
    const gchar *json_response = "{\"status\":\"success\",\"message\":\"Federated message sent via email\"}";
    return api_send_json_response(conn, 200, "OK", json_response, error);
}

static DeadlightHandlerResult api_federation_receive(DeadlightConnection *conn, DeadlightRequest *request, GError **error) {
    (void)request;
    g_info("API federation receive for conn %lu", conn->id);
    
    // TODO: Process incoming federated content from email
    const gchar *json_response = "{\"status\":\"success\",\"message\":\"Federated message processed\"}";
    return api_send_json_response(conn, 200, "OK", json_response, error);
}

// Add this new function implementation:
static DeadlightHandlerResult api_handle_metrics_endpoint(DeadlightConnection *conn, GError **error) {
    DeadlightContext *ctx = conn->context;
    g_info("API metrics endpoint for conn %lu", conn->id);
    
    // Build JSON response with actual metrics
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    
    // Basic metrics
    json_builder_set_member_name(builder, "active_connections");
    json_builder_add_int_value(builder, ctx->active_connections);
    
    json_builder_set_member_name(builder, "total_connections");
    json_builder_add_int_value(builder, ctx->total_connections);
    
    json_builder_set_member_name(builder, "bytes_transferred");
    json_builder_add_int_value(builder, ctx->bytes_transferred);
    
    json_builder_set_member_name(builder, "uptime");
    json_builder_add_double_value(builder, g_timer_elapsed(ctx->uptime_timer, NULL));
    
    // Protocol breakdown - count connections by protocol
    json_builder_set_member_name(builder, "protocols");
    json_builder_begin_object(builder);
    
    // Initialize protocol counters
    GHashTable *protocol_stats = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Count active connections by protocol
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, ctx->connections);
    
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        DeadlightConnection *active_conn = (DeadlightConnection*)value;
        const gchar *protocol_name = deadlight_protocol_to_string(active_conn->protocol);
        
        // Get or create stats for this protocol
        gpointer stats_ptr = g_hash_table_lookup(protocol_stats, protocol_name);
        gint active_count = stats_ptr ? GPOINTER_TO_INT(stats_ptr) : 0;
        g_hash_table_insert(protocol_stats, g_strdup(protocol_name), GINT_TO_POINTER(active_count + 1));
    }
    
    // Add protocol stats to JSON
    const gchar *protocols[] = {"HTTP", "HTTPS", "WebSocket", "SOCKS", "SMTP", "IMAP", "FTP", "API"};
    for (size_t i = 0; i < G_N_ELEMENTS(protocols); i++) {
        gpointer active_ptr = g_hash_table_lookup(protocol_stats, protocols[i]);
        gint active = active_ptr ? GPOINTER_TO_INT(active_ptr) : 0;
        
        json_builder_set_member_name(builder, protocols[i]);
        json_builder_begin_object(builder);
        
        json_builder_set_member_name(builder, "active");
        json_builder_add_int_value(builder, active);
        
        // TODO: Add total connections and bytes per protocol
        // This would require tracking in the connection structure
        json_builder_set_member_name(builder, "total");
        json_builder_add_int_value(builder, 0); // Placeholder
        
        json_builder_set_member_name(builder, "bytes");
        json_builder_add_int_value(builder, 0); // Placeholder
        
        json_builder_end_object(builder);
    }
    
    json_builder_end_object(builder); // End protocols
    
    // Server info
    json_builder_set_member_name(builder, "server_info");
    json_builder_begin_object(builder);
    
    json_builder_set_member_name(builder, "version");
    json_builder_add_string_value(builder, DEADLIGHT_VERSION_STRING);
    
    json_builder_set_member_name(builder, "port");
    json_builder_add_int_value(builder, ctx->listen_port);
    
    json_builder_set_member_name(builder, "ssl_intercept");
    json_builder_add_boolean_value(builder, ctx->ssl_intercept_enabled);
    
    json_builder_set_member_name(builder, "max_connections");
    json_builder_add_int_value(builder, ctx->max_connections);
    
    json_builder_end_object(builder); // End server_info
    
    json_builder_end_object(builder); // End root
    
    // Generate JSON string
    JsonGenerator *gen = json_generator_new();
    JsonNode *root = json_builder_get_root(builder);
    json_generator_set_root(gen, root);
    
    gchar *json_str = json_generator_to_data(gen, NULL);
    
    // Send response
    DeadlightHandlerResult result = api_send_json_response(conn, 200, "OK", json_str, error);
    
    // Cleanup
    g_free(json_str);
    g_object_unref(gen);
    json_node_unref(root);
    g_object_unref(builder);
    g_hash_table_destroy(protocol_stats);
    
    return result;
}