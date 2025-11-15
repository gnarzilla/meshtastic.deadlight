#include "socks.h"
#include "core/deadlight.h"
#include <glib.h>
#include <gio/gio.h>
#include <arpa/inet.h>
#include <string.h>

// SOCKS5 Constants
#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERNAME_PASSWORD 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONNECTION_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

// SOCKS4 Constants
#define SOCKS4_VERSION 0x04
#define SOCKS4_CMD_CONNECT 0x01
#define SOCKS4_REP_GRANTED 0x5A
#define SOCKS4_REP_REJECTED 0x5B

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

// Forward declarations
static gsize socks_detect(const guint8 *data, gsize len);
static DeadlightHandlerResult socks_handle(DeadlightConnection *conn, GError **error);
static void socks_cleanup(DeadlightConnection *conn);
static DeadlightHandlerResult handle_socks4(DeadlightConnection *conn, GError **error);
static DeadlightHandlerResult handle_socks5(DeadlightConnection *conn, GError **error);
static gboolean send_socks5_error_reply(GOutputStream *client_os, guint8 error_code, GError **error);
static gboolean call_plugin_hooks(DeadlightConnection *conn, const gchar *method, const gchar *target_host, guint16 target_port);

// Helper function to create and populate request for plugin hooks
static gboolean call_plugin_hooks(DeadlightConnection *conn, const gchar *method, const gchar *target_host, guint16 target_port) {
    // Create request object for plugin system (similar to HTTP handler)
    conn->current_request = deadlight_request_new(conn);
    conn->current_request->method = g_strdup(method);
    conn->current_request->uri = g_strdup_printf("%s:%u", target_host, target_port);
    conn->current_request->host = g_strdup(target_host);
    
    // Store target info for connection tracking
    conn->target_host = g_strdup(target_host);
    conn->target_port = target_port;

    g_debug("Connection %lu: Calling plugin hook for %s %s", 
            conn->id, conn->current_request->method, conn->current_request->uri);
    
    // Call plugin hook - this is where rate limiting and other policies are applied
    if (!deadlight_plugins_call_on_request_headers(conn->context, conn->current_request)) {
        g_info("Connection %lu: %s request blocked by plugin", conn->id, method);
        return FALSE;  // Plugin blocked the request
    }
    
    return TRUE;
}

static gboolean send_socks5_error_reply(GOutputStream *client_os, guint8 error_code, GError **error) {
    guint8 error_reply[10] = {
        SOCKS5_VERSION,     // Version
        error_code,         // Error code  
        0x00,               // Reserved
        SOCKS5_ATYP_IPV4,   // Address type
        0, 0, 0, 0,         // IP address (0.0.0.0)
        0, 0                // Port (0)
    };
    
    return g_output_stream_write_all(client_os, error_reply, 10, NULL, NULL, error);
}

static DeadlightHandlerResult handle_socks4(DeadlightConnection *conn, GError **error) {
    GByteArray *buffer = conn->client_buffer;
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));

    // SOCKS4 request format: [ver=4][cmd=1][port_be][ip_be][userid]\0
    // Minimum length is 9 bytes (1+1+2+4+1 for null terminator)
    if (buffer->len < 9) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Incomplete SOCKS4 request header.");
        return HANDLER_ERROR;
    }
    
    guint8 *data = buffer->data;
    
    // Command code must be 1 for CONNECT
    if (data[1] != SOCKS4_CMD_CONNECT) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "SOCKS4 command %d not supported, only CONNECT.", data[1]);
        // Send SOCKS4 error reply
        guint8 error_reply[8] = {0x00, SOCKS4_REP_REJECTED, data[2], data[3], data[4], data[5], data[6], data[7]};
        g_output_stream_write_all(client_os, error_reply, sizeof(error_reply), NULL, NULL, NULL);
        return HANDLER_ERROR;
    }
    
    // Extract port and IP address (network byte order)
    guint16 target_port = ntohs(*(guint16*)&data[2]);
    struct in_addr target_ip_addr = { .s_addr = *(in_addr_t*)&data[4] };
    
    // Extract userid (null-terminated string starting at byte 8)
    const gchar *userid = (const gchar *)(data + 8);
    gsize userid_len = strlen(userid);
    
    // Check for SOCKS4a (hostname support)
    // SOCKS4a uses IP 0.0.0.x (where x != 0) to indicate hostname follows userid
    gchar *target_host = NULL;
    gboolean is_socks4a = (data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] != 0);
    
    if (is_socks4a) {
        // SOCKS4a: hostname follows userid + null terminator
        if (buffer->len < 9 + userid_len + 1) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Incomplete SOCKS4a request.");
            return HANDLER_ERROR;
        }
        
        const gchar *hostname = userid + userid_len + 1;
        target_host = g_strdup(hostname);
        g_info("Connection %lu: SOCKS4a CONNECT request to %s:%u (userid: %s)", 
               conn->id, target_host, target_port, userid);
    } else {
        // Standard SOCKS4: use IP address
        target_host = g_strdup(inet_ntoa(target_ip_addr));
        g_info("Connection %lu: SOCKS4 CONNECT request to %s:%u (userid: %s)", 
               conn->id, target_host, target_port, userid);
    }

    // Call plugin hooks for policy enforcement (rate limiting, blocking, etc.)
    if (!call_plugin_hooks(conn, "CONNECT", target_host, target_port)) {
        g_info("Connection %lu: SOCKS4 request blocked by plugin", conn->id);
        guint8 error_reply[8] = {0x00, SOCKS4_REP_REJECTED, data[2], data[3], data[4], data[5], data[6], data[7]};
        g_output_stream_write_all(client_os, error_reply, sizeof(error_reply), NULL, NULL, NULL);
        g_free(target_host);
        return HANDLER_SUCCESS_CLEANUP_NOW; // Plugin handled the response
    }

    // Proxy loop prevention (similar to HTTP handler)
    if ((g_strcmp0(target_host, conn->context->listen_address) == 0 || 
         g_strcmp0(target_host, "localhost") == 0 || 
         g_strcmp0(target_host, "127.0.0.1") == 0) && 
         target_port == conn->context->listen_port) {
        g_warning("Connection %lu: Detected SOCKS4 proxy loop to %s:%u. Denying request.", 
                  conn->id, target_host, target_port);
        guint8 error_reply[8] = {0x00, SOCKS4_REP_REJECTED, data[2], data[3], data[4], data[5], data[6], data[7]};
        g_output_stream_write_all(client_os, error_reply, sizeof(error_reply), NULL, NULL, NULL);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(target_host);
        return HANDLER_ERROR;
    }
    
    // Connect to upstream target
    if (!deadlight_network_connect_upstream(conn, error)) {
        g_warning("Connection %lu: SOCKS4 failed to connect upstream to %s:%u: %s", 
                 conn->id, target_host, target_port, (*error)->message);
        
        guint8 error_reply[8] = {0x00, SOCKS4_REP_REJECTED, data[2], data[3], data[4], data[5], data[6], data[7]};
        g_output_stream_write_all(client_os, error_reply, sizeof(error_reply), NULL, NULL, NULL);
        
        g_free(target_host);
        return HANDLER_ERROR;
    }
    g_free(target_host);

    // Send SOCKS4 success reply: [ver=0][status=90][port][ip]
    guint8 success_reply[8] = {0x00, SOCKS4_REP_GRANTED, data[2], data[3], data[4], data[5], data[6], data[7]};
    if (!g_output_stream_write_all(client_os, success_reply, sizeof(success_reply), NULL, NULL, error)) {
        g_warning("Connection %lu: Failed to send SOCKS4 success reply: %s", conn->id, (*error)->message);
        return HANDLER_ERROR;
    }
    
    g_info("Connection %lu: SOCKS4 success reply sent. Starting tunnel.", conn->id);

    // Start tunneling data (blocking operation)
    return deadlight_network_tunnel_data(conn, error) ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

static DeadlightHandlerResult handle_socks5(DeadlightConnection *conn, GError **error) {
    GInputStream *client_is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    GOutputStream *client_os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    DeadlightContext *ctx = conn->context;

    // Load configuration
    gboolean auth_required = deadlight_config_get_bool(ctx, "socks5", "auth_required", FALSE);
    gchar *config_username = deadlight_config_get_string(ctx, "socks5", "username", NULL);
    gchar *config_password = deadlight_config_get_string(ctx, "socks5", "password", NULL);

    // --- Phase 1: Greeting & Method Selection ---
    g_debug("SOCKS5 conn %lu: Starting phase 1 (Greeting).", conn->id);
    guint8 *greeting_data = conn->client_buffer->data;
    guint nmethods = greeting_data[1];

    if (conn->client_buffer->len < 2 + nmethods) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Incomplete SOCKS5 greeting.");
        return HANDLER_ERROR;
    }

    // Check supported authentication methods
    gboolean no_auth_offered = FALSE;
    gboolean user_pass_offered = FALSE;
    for (guint i = 0; i < nmethods; i++) {
        guint8 method = greeting_data[2 + i];
        if (method == SOCKS5_AUTH_NONE) no_auth_offered = TRUE;
        if (method == SOCKS5_AUTH_USERNAME_PASSWORD) user_pass_offered = TRUE;
    }

    // Select authentication method
    guint8 selected_method = SOCKS5_AUTH_NO_ACCEPTABLE;
    if (!auth_required && no_auth_offered) {
        selected_method = SOCKS5_AUTH_NONE;
    } else if (auth_required && user_pass_offered && config_username && config_password) {
        selected_method = SOCKS5_AUTH_USERNAME_PASSWORD;
    }

    // Send method selection reply
    guint8 reply_method[2] = {SOCKS5_VERSION, selected_method};
    if (!g_output_stream_write_all(client_os, reply_method, 2, NULL, NULL, error)) {
        g_warning("SOCKS5 conn %lu: Failed to send method reply: %s", conn->id, (*error)->message);
        return HANDLER_ERROR;
    }

    if (selected_method == SOCKS5_AUTH_NO_ACCEPTABLE) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "No acceptable authentication methods.");
        return HANDLER_ERROR;
    }
    g_info("SOCKS5 conn %lu: Method %02x selected.", conn->id, selected_method);

    // --- Phase 2: Authentication (if required) ---
    if (selected_method == SOCKS5_AUTH_USERNAME_PASSWORD) {
        g_debug("SOCKS5 conn %lu: Starting authentication phase.", conn->id);
        
        guint8 auth_buffer[512];
        gsize bytes_read;
        
        // Read authentication header (version + username length)
        if (!g_input_stream_read_all(client_is, auth_buffer, 2, &bytes_read, NULL, error)) {
            send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
            return HANDLER_ERROR;
        }
        
        if (auth_buffer[0] != 0x01) {  // RFC 1929 subnegotiation version
            guint8 auth_reply[2] = {0x01, 0x01};  // Failure
            g_output_stream_write_all(client_os, auth_reply, 2, NULL, NULL, NULL);
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid auth subnegotiation version.");
            return HANDLER_ERROR;
        }
        
        guint8 ulen = auth_buffer[1];
        
        // Read username + password length
        if (!g_input_stream_read_all(client_is, auth_buffer + 2, ulen + 1, &bytes_read, NULL, error)) {
            return HANDLER_ERROR;
        }
        
        guint8 plen = auth_buffer[2 + ulen];
        
        // Read password
        if (!g_input_stream_read_all(client_is, auth_buffer + 2 + ulen + 1, plen, &bytes_read, NULL, error)) {
            return HANDLER_ERROR;
        }

        // Extract and validate credentials
        gchar *client_username = g_strndup((gchar*)(auth_buffer + 2), ulen);
        gchar *client_password = g_strndup((gchar*)(auth_buffer + 2 + ulen + 1), plen);

        gboolean auth_ok = g_strcmp0(client_username, config_username) == 0 &&
                           g_strcmp0(client_password, config_password) == 0;

        // Send authentication response
        guint8 auth_reply[2] = {0x01, auth_ok ? 0x00 : 0x01};
        g_output_stream_write_all(client_os, auth_reply, 2, NULL, NULL, error);

        g_free(client_username);
        g_free(client_password);

        if (!auth_ok) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "SOCKS5 authentication failed.");
            return HANDLER_ERROR;
        }
        g_info("SOCKS5 conn %lu: Authentication succeeded.", conn->id);
    }

    // --- Phase 3: Connection Request ---
    g_debug("SOCKS5 conn %lu: Starting phase 3 (Request).", conn->id);
    guint8 req_buffer[262]; // Max SOCKS5 request size
    gsize bytes_read;

    // Read request header (VER + CMD + RSV + ATYP)
    if (!g_input_stream_read_all(client_is, req_buffer, 4, &bytes_read, NULL, error)) {
        g_warning("SOCKS5 conn %lu: Failed to read request header: %s", conn->id, (*error)->message);
        send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
        return HANDLER_ERROR;
    }

    // Validate request
    if (req_buffer[0] != SOCKS5_VERSION) {
        g_warning("SOCKS5 conn %lu: Invalid version %d in request", conn->id, req_buffer[0]);
        send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid SOCKS5 version in request.");
        return HANDLER_ERROR;
    }

    if (req_buffer[1] != SOCKS5_CMD_CONNECT) {
        g_warning("SOCKS5 conn %lu: Command %d not supported", conn->id, req_buffer[1]);
        send_socks5_error_reply(client_os, SOCKS5_REP_COMMAND_NOT_SUPPORTED, NULL);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "SOCKS5 command %d not supported.", req_buffer[1]);
        return HANDLER_ERROR;
    }

    // Parse target address based on address type
    guint8 atyp = req_buffer[3];
    gchar *target_host = NULL;
    guint16 target_port = 0;

    switch (atyp) {
        case SOCKS5_ATYP_IPV4:
            if (!g_input_stream_read_all(client_is, &req_buffer[4], 6, &bytes_read, NULL, error)) {  // 4 bytes IP + 2 bytes port
                send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
                return HANDLER_ERROR;
            }
            target_host = g_strdup_printf("%d.%d.%d.%d", req_buffer[4], req_buffer[5], req_buffer[6], req_buffer[7]);
            target_port = ntohs(*(guint16*)&req_buffer[8]);
            break;
            
        case SOCKS5_ATYP_DOMAIN:
            if (!g_input_stream_read_all(client_is, &req_buffer[4], 1, &bytes_read, NULL, error)) {  // Domain length
                send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
                return HANDLER_ERROR;
            }
            guint8 domain_len = req_buffer[4];
            if (!g_input_stream_read_all(client_is, &req_buffer[5], domain_len + 2, &bytes_read, NULL, error)) {  // Domain + port
                send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
                return HANDLER_ERROR;
            }
            target_host = g_strndup((gchar*)&req_buffer[5], domain_len);
            target_port = ntohs(*(guint16*)&req_buffer[5 + domain_len]);
            break;
            
        case SOCKS5_ATYP_IPV6:
            if (!g_input_stream_read_all(client_is, &req_buffer[4], 18, &bytes_read, NULL, error)) {  // 16 bytes IPv6 + 2 bytes port
                send_socks5_error_reply(client_os, SOCKS5_REP_GENERAL_FAILURE, NULL);
                return HANDLER_ERROR;
            }
            
            // Format IPv6 address properly
            char ipv6_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &req_buffer[4], ipv6_str, INET6_ADDRSTRLEN)) {
                target_host = g_strdup(ipv6_str);
            } else {
                target_host = g_strdup("IPv6 Address"); // fallback
            }
            target_port = ntohs(*(guint16*)&req_buffer[20]);
            break;
            
        default:
            g_warning("SOCKS5 conn %lu: Address type %d not supported", conn->id, atyp);
            send_socks5_error_reply(client_os, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED, NULL);
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Unsupported address type %d.", atyp);
            return HANDLER_ERROR;
    }
    
    g_info("SOCKS5 conn %lu: CONNECT request to %s:%u", conn->id, target_host, target_port);

    // Call plugin hooks for policy enforcement (rate limiting, blocking, etc.)
    if (!call_plugin_hooks(conn, "CONNECT", target_host, target_port)) {
        g_info("Connection %lu: SOCKS5 request blocked by plugin", conn->id);
        send_socks5_error_reply(client_os, SOCKS5_REP_CONNECTION_NOT_ALLOWED, NULL);
        g_free(target_host);
        return HANDLER_SUCCESS_CLEANUP_NOW; // Plugin handled the response
    }

    // Proxy loop prevention
    if ((g_strcmp0(target_host, conn->context->listen_address) == 0 || 
         g_strcmp0(target_host, "localhost") == 0 || 
         g_strcmp0(target_host, "127.0.0.1") == 0) && 
         target_port == conn->context->listen_port) {
        g_warning("Connection %lu: Detected SOCKS5 proxy loop to %s:%u. Denying request.", 
                  conn->id, target_host, target_port);
        send_socks5_error_reply(client_os, SOCKS5_REP_CONNECTION_NOT_ALLOWED, NULL);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "Proxy loop detected");
        g_free(target_host);
        return HANDLER_ERROR;
    }

    // --- Phase 4: Upstream Connection ---
    g_debug("SOCKS5 conn %lu: Starting phase 4 (Upstream Connect).", conn->id);
    if (!deadlight_network_connect_upstream(conn, error)) {
        g_warning("SOCKS5 conn %lu: Failed to connect upstream to %s:%u: %s", 
                 conn->id, target_host, target_port, (*error)->message);
        
        // Send appropriate SOCKS5 error based on failure reason
        guint8 socks_error = SOCKS5_REP_GENERAL_FAILURE;
        if (g_error_matches(*error, G_RESOLVER_ERROR, G_RESOLVER_ERROR_NOT_FOUND)) {
            socks_error = SOCKS5_REP_HOST_UNREACHABLE;
        } else if (g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED)) {
            socks_error = SOCKS5_REP_CONNECTION_REFUSED;
        } else if (g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_NETWORK_UNREACHABLE)) {
            socks_error = SOCKS5_REP_NETWORK_UNREACHABLE;
        }
        
        send_socks5_error_reply(client_os, socks_error, NULL);
        g_free(target_host);
        return HANDLER_ERROR;
    }
    g_free(target_host);

    // Send SOCKS5 success reply
    guint8 success_reply[10] = {SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0};
    if (!g_output_stream_write_all(client_os, success_reply, 10, NULL, NULL, error)) {
        g_warning("SOCKS5 conn %lu: Failed to send success reply: %s", conn->id, (*error)->message);
        return HANDLER_ERROR;
    }
    g_info("SOCKS5 conn %lu: Success reply sent. Starting tunnel.", conn->id);

    // Start tunneling data (blocking operation)
    return deadlight_network_tunnel_data(conn, error) ? HANDLER_SUCCESS_CLEANUP_NOW : HANDLER_ERROR;
}

static DeadlightHandlerResult socks_handle(DeadlightConnection *conn, GError **error) {
    g_return_val_if_fail(conn->client_buffer && conn->client_buffer->len > 0, HANDLER_ERROR);

    guint8 version = conn->client_buffer->data[0];

    if (version == SOCKS4_VERSION) {
        g_info("Connection %lu: Detected SOCKS4 protocol.", conn->id);
        conn->protocol = DEADLIGHT_PROTOCOL_SOCKS4;
        return handle_socks4(conn, error);
    } else if (version == SOCKS5_VERSION) {
        g_info("Connection %lu: Detected SOCKS5 protocol.", conn->id);
        conn->protocol = DEADLIGHT_PROTOCOL_SOCKS5;
        return handle_socks5(conn, error);
    }

    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Unknown SOCKS version: %d", version);
    return HANDLER_ERROR;
}

static gsize socks_detect(const guint8 *data, gsize len) {
    if (len > 0 && (data[0] == SOCKS4_VERSION || data[0] == SOCKS5_VERSION)) {
        return 1; // Need at least 1 byte to detect version
    }
    return 0;
}

static void socks_cleanup(DeadlightConnection *conn) {
    g_debug("SOCKS cleanup called for conn %lu", conn->id);
    // Additional SOCKS-specific cleanup if needed
}

// The protocol handler definition
static const DeadlightProtocolHandler socks_protocol_handler = {
    .name = "SOCKS",
    .protocol_id = DEADLIGHT_PROTOCOL_SOCKS,
    .detect = socks_detect,
    .handle = socks_handle,
    .cleanup = socks_cleanup
};

// Public registration function
void deadlight_register_socks_handler(void) {
    g_info("Registering SOCKS protocol handler (SOCKS4/4a/5 support with plugin integration)");
    deadlight_protocol_register(&socks_protocol_handler);
}