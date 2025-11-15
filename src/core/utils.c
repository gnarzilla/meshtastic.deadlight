#include "deadlight.h"
#include "utils.h"
#include <gio/gio.h>
#include <string.h>

gchar *get_external_ip(void) {
    GError *error = NULL;
    GSocketClient *client = g_socket_client_new();
    GSocketConnection *connection = NULL;
    gchar *result = NULL;
    
    // Try to connect to a simple IP checking service
    connection = g_socket_client_connect_to_host(client, 
                                                  "api.ipify.org", 80, 
                                                  NULL, &error);
    
    if (connection) {
        GOutputStream *output = g_io_stream_get_output_stream(G_IO_STREAM(connection));
        GInputStream *input = g_io_stream_get_input_stream(G_IO_STREAM(connection));
        
        const gchar *request = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n";
        
        if (g_output_stream_write_all(output, request, strlen(request), NULL, NULL, &error)) {
            gchar buffer[1024];
            gssize bytes_read = g_input_stream_read(input, buffer, sizeof(buffer) - 1, NULL, &error);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                // Find the IP address after the headers
                gchar *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4; // Skip the \r\n\r\n
                    result = g_strdup(g_strstrip(body));
                }
            }
        }
        
        g_object_unref(connection);
    }
    
    g_object_unref(client);
    
    if (error) {
        g_warning("Failed to get external IP: %s", error->message);
        g_error_free(error);
    }
    
    // Return localhost if we couldn't get external IP
    return result ? result : g_strdup("127.0.0.1");
}

gboolean deadlight_test_module(const gchar *module_name) {
    (void)module_name; // Mark as unused for now
    g_print("Testing module system...\n");
    // ... implementation ...
    return TRUE;
}

gchar *deadlight_format_bytes(guint64 bytes) {
    if (bytes < 1024) {
        return g_strdup_printf("%lu B", bytes);
    } else if (bytes < 1024 * 1024) {
        return g_strdup_printf("%.2f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        return g_strdup_printf("%.2f MB", bytes / (1024.0 * 1024.0));
    } else {
        return g_strdup_printf("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

gchar *deadlight_format_duration(gint64 seconds) {
    // [FIX] Change %f to %ld
    if (seconds < 60) {
        return g_strdup_printf("%.1ld seconds", seconds);
    } else if (seconds < 3600) {
        return g_strdup_printf("%.1f minutes", seconds / 60.0);
    } else if (seconds < 86400) {
        return g_strdup_printf("%.1f hours", seconds / 3600.0);
    } else {
        return g_strdup_printf("%.1f days", seconds / 86400.0);
    }
}

gboolean deadlight_parse_host_port(const gchar *host_port, gchar **host, guint16 *port) {
    if (!host_port || !host || !port) return FALSE;

    // Initialize host to NULL. We will check this at the end to determine success.
    *host = NULL;

    if (host_port[0] == '[') { // IPv6 address like [::1]:8080
        // 'end' is declared here, so it's only visible inside this 'if' block.
        const gchar *end = strchr(host_port, ']');
        if (!end) return FALSE; // Malformed, no closing bracket

        *host = g_strndup(host_port + 1, end - (host_port + 1));

        // Check for a port after the ']'
        if (*(end + 1) == ':') {
            gulong p = strtoul(end + 2, NULL, 10);
            // [FIX] Validate the parsed port is in the valid range
            if (p > 0 && p <= 65535) {
                *port = (guint16)p;
            } else {
                // Invalid port, so we fail parsing.
                g_free(*host);
                *host = NULL;
            }
        }
        // If no port is specified, we just keep the default value that was passed in.

    } else { // IPv4 or hostname like 127.0.0.1:8080 or example.com
        const gchar *colon = strrchr(host_port, ':');
        if (colon) { // A port is specified
            *host = g_strndup(host_port, colon - host_port);

            gulong p = strtoul(colon + 1, NULL, 10);
            // [FIX] Validate the parsed port for this case as well
            if (p > 0 && p <= 65535) {
                *port = (guint16)p;
            } else {
                g_free(*host);
                *host = NULL;
            }
        } else { // No port is specified
            *host = g_strdup(host_port);
        }
    }

    // The function is successful if we managed to allocate a non-empty host string.
    return (*host != NULL && strlen(*host) > 0);
}
