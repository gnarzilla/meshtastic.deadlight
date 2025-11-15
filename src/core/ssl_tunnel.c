// src/core/ssl_tunnel.c

#include "ssl_tunnel.h"
#include "deadlight.h"
#include <glib.h>
#include <gio/gio.h>
#include <errno.h> // Required for errno

/**
 * A synchronous, blocking function that shuttles data over two established GTlsConnection handles.
 * This version uses g_poll() for efficient, event-driven I/O, avoiding CPU spin and reducing latency.
 * It will run in a loop until one side closes the connection or an error occurs.
 */
gboolean start_ssl_tunnel_blocking(DeadlightConnection *conn, GError **error) {
    (void)error;

    g_return_val_if_fail(conn != NULL, FALSE);
    g_return_val_if_fail(conn->client_tls != NULL, FALSE);
    g_return_val_if_fail(conn->upstream_tls != NULL, FALSE);
    // We also need the underlying socket connections to get file descriptors.
    g_return_val_if_fail(G_IS_SOCKET_CONNECTION(conn->client_connection), FALSE);
    g_return_val_if_fail(G_IS_SOCKET_CONNECTION(conn->upstream_connection), FALSE);

    g_info("Connection %lu: Starting TLS tunnel.", conn->id);
    conn->state = DEADLIGHT_STATE_TUNNELING;

    // Get streams from TLS connections (same as before)
    GInputStream *client_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_tls));
    GOutputStream *client_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_tls));
    GInputStream *upstream_input = g_io_stream_get_input_stream(G_IO_STREAM(conn->upstream_tls));
    GOutputStream *upstream_output = g_io_stream_get_output_stream(G_IO_STREAM(conn->upstream_tls));

    // Get the underlying GSocket from the GSocketConnection to get its file descriptor (fd).
    GSocket *client_socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->client_connection));
    GSocket *upstream_socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(conn->upstream_connection));
    
    int client_fd = g_socket_get_fd(client_socket);
    int upstream_fd = g_socket_get_fd(upstream_socket);

    // Create the array of file descriptors to poll.
    GPollFD fds[2];
    fds[0].fd = client_fd;
    fds[0].events = G_IO_IN; // We want to know when the client socket is readable.
    
    fds[1].fd = upstream_fd;
    fds[1].events = G_IO_IN; // We want to know when the upstream socket is readable.

    guchar buffer[16384];
    gboolean running = TRUE;
    
    while (running) {
        // This will block until data is available or the timeout (1000ms) is hit.
        int ret = g_poll(fds, 2, 1000);

        if (ret < 0) {
            // An error occurred in poll() itself.
            if (errno == EINTR) continue; // Interrupted by a signal, just try again.
            g_warning("Connection %lu: g_poll() error: %s", conn->id, g_strerror(errno));
            break;
        }

        if (ret == 0) {
            // Timeout - no data on either socket for 1 second. Loop and wait again.
            continue;
        }

        GError *local_error = NULL;
        gssize bytes_read, bytes_written;

        // Check if the client socket has data to read.
        if (fds[0].revents & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
            
            bytes_read = g_pollable_input_stream_read_nonblocking(
                G_POLLABLE_INPUT_STREAM(client_input),
                buffer, sizeof(buffer), NULL, &local_error
            );
            
            if (bytes_read > 0) {
                bytes_written = g_output_stream_write_all(
                    upstream_output, buffer, bytes_read, NULL, NULL, &local_error
                );
                if (bytes_written) {
                    conn->bytes_client_to_upstream += bytes_read;
                    g_output_stream_flush(upstream_output, NULL, NULL);
                }
            } else if (bytes_read == 0 || (fds[0].revents & G_IO_HUP)) {
                g_debug("Connection %lu: Client closed TLS connection", conn->id);
                running = FALSE;
            } else if (local_error) {
                if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                    g_debug("Connection %lu: Client TLS EOF", conn->id);
                    running = FALSE;
                } else if (!g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    g_debug("Connection %lu: Client read error: %s", conn->id, local_error->message);
                    running = FALSE;
                }
                g_clear_error(&local_error);
            }
        }

        // Check if the upstream socket has data to read.
        if (running && (fds[1].revents & (G_IO_IN | G_IO_HUP | G_IO_ERR))) {
            
            bytes_read = g_pollable_input_stream_read_nonblocking(
                G_POLLABLE_INPUT_STREAM(upstream_input),
                buffer, sizeof(buffer), NULL, &local_error
            );
            
            if (bytes_read > 0) {
                bytes_written = g_output_stream_write_all(
                    client_output, buffer, bytes_read, NULL, NULL, &local_error
                );
                if (bytes_written) {
                    conn->bytes_upstream_to_client += bytes_read;
                    g_output_stream_flush(client_output, NULL, NULL);
                }
            } else if (bytes_read == 0 || (fds[1].revents & G_IO_HUP)) {
                g_debug("Connection %lu: Upstream closed TLS connection", conn->id);
                running = FALSE;
            } else if (local_error) {
                if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                    g_debug("Connection %lu: Upstream TLS EOF", conn->id);
                    running = FALSE;
                } else if (!g_error_matches(local_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                    g_debug("Connection %lu: Upstream read error: %s", conn->id, local_error->message);
                    running = FALSE;
                }
                g_clear_error(&local_error);
            }
        }

    }

    g_info("Connection %lu: TLS tunnel closed (client->upstream: %lu B, upstream->client: %lu B)",
           conn->id, conn->bytes_client_to_upstream, conn->bytes_upstream_to_client);

    conn->state = DEADLIGHT_STATE_CLOSING;
    return TRUE;
}