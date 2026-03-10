/**
 * client_main.c — deadmesh-client
 *
 * A lean HTTP proxy that runs on the client device (phone/laptop) and
 * tunnels requests over a Meshtastic LoRa mesh to a deadmesh gateway.
 *
 * Architecture:
 *
 *   Browser → :8888 → [accept loop]
 *                           │
 *                    conn_worker thread (one per connection)
 *                           │
 *                    MeshStream (GIOStream)
 *                      write → client_send_fn → fragment → ToRadio → radio
 *                      read  ← reader thread pushes reassembled response
 *                           │
 *                    :4403 TCP (Meshtastic app API, default)
 *                    or /dev/rfcomm0 (serial, -DCLIENT_TRANSPORT_SERIAL)
 *                           │
 *                    LoRa mesh
 *                           │
 *                    deadmesh gateway → internet
 *
 * Usage:
 *   deadmesh-client --gateway 14e7cdaf [--port 8888]
 *   export http_proxy=http://localhost:8888
 *   curl http://example.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include "mesh_session.h"
#include "mesh_stream.h"
#include "client_transport.h"

/* ─────────────────────────────────────────────────────────────
 * Config
 * ───────────────────────────────────────────────────────────── */

#define CLIENT_DEFAULT_PROXY_PORT   8888
#define CLIENT_DEFAULT_MESH_PORT    100
#define CLIENT_REQUEST_BUF_SIZE     16384
#define CLIENT_BACKLOG              32

/* ─────────────────────────────────────────────────────────────
 * Globals
 * ───────────────────────────────────────────────────────────── */

static ClientTransport *g_transport = NULL;
static volatile bool    g_running   = true;
static int              g_listen_fd = -1;

/* ─────────────────────────────────────────────────────────────
 * Per-connection worker context
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    int              client_fd;
    ClientTransport *transport;
} ConnCtx;

/* ─────────────────────────────────────────────────────────────
 * Signal handler
 * ───────────────────────────────────────────────────────────── */

static void sig_handler(int sig) {
    (void)sig;
    g_running = false;
    if (g_listen_fd >= 0) {
        shutdown(g_listen_fd, SHUT_RDWR);
        close(g_listen_fd);
        g_listen_fd = -1;
    }
}

/* ─────────────────────────────────────────────────────────────
 * HTTP helpers
 * ───────────────────────────────────────────────────────────── */

static ssize_t read_http_request(int fd, uint8_t *buf, size_t buf_size) {
    ssize_t total = 0;
    ssize_t n;

    while ((size_t)total < buf_size - 1) {
        n = read(fd, buf + total, buf_size - 1 - (size_t)total);
        if (n <= 0) break;
        total += n;
        if (total >= 4 && memmem(buf, (size_t)total, "\r\n\r\n", 4))
            break;
    }

    if (total <= 0) return total;

    /* Read body if Content-Length present */
    buf[total] = '\0';
    const char *cl = strcasestr((char *)buf, "Content-Length:");
    if (cl) {
        long body_len    = strtol(cl + 15, NULL, 10);
        const char *hend = strstr((char *)buf, "\r\n\r\n");
        if (hend) {
            ssize_t headers_len   = (ssize_t)(hend + 4 - (char *)buf);
            ssize_t body_received = total - headers_len;
            ssize_t remaining     = body_len - body_received;
            while (remaining > 0 && (size_t)total < buf_size - 1) {
                n = read(fd, buf + total,
                         MIN((size_t)remaining, buf_size - 1 - (size_t)total));
                if (n <= 0) break;
                total     += n;
                remaining -= n;
            }
        }
    }

    return total;
}

static void send_error(int fd, int code, const char *msg) {
    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d Error\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        code, strlen(msg), msg);
    ssize_t ignored = write(fd, buf, (size_t)len);
    (void)ignored;
}

/* ─────────────────────────────────────────────────────────────
 * Connection worker thread
 *
 * Lifecycle:
 *   1. Read HTTP request from browser fd
 *   2. Allocate mesh session → get MeshSession + ClientSendCtx
 *   3. Create MeshStream wrapping the session
 *   4. Wire session->user_data = stream (reader thread pushes here)
 *   5. Write request bytes into stream (fragments to gateway)
 *   6. Read response bytes from stream (reassembled by reader thread)
 *   7. Forward response to browser fd
 *   8. Clean up
 * ───────────────────────────────────────────────────────────── */

static void *conn_worker(void *arg) {
    ConnCtx *ctx = (ConnCtx *)arg;
    int       cfd = ctx->client_fd;
    ClientTransport *ct = ctx->transport;
    g_free(ctx);

    /* Step 1: read request */
    uint8_t *req_buf = g_malloc(CLIENT_REQUEST_BUF_SIZE);
    ssize_t  req_len = read_http_request(cfd, req_buf, CLIENT_REQUEST_BUF_SIZE);

    if (req_len <= 0) {
        g_free(req_buf);
        close(cfd);
        return NULL;
    }

    /* Reject CONNECT tunnels — mesh bandwidth makes raw HTTPS tunneling
     * impractical. Return a clear error so the browser knows.           */
    if (req_len >= 7 && memcmp(req_buf, "CONNECT", 7) == 0) {
        send_error(cfd, 405,
            "deadmesh-client: HTTPS CONNECT tunneling not supported.\n"
            "Use plain HTTP, or point traffic through a local SOCKS5 proxy.\n");
        g_free(req_buf);
        close(cfd);
        return NULL;
    }

    /* Step 2: allocate mesh session
     * client_transport_new_session returns a send_ctx (session_id embedded)
     * and optionally the underlying MeshSession via out_session.
     * We set session->user_data AFTER creating the stream (step 4).    */
    MeshSession   *session  = NULL;
    ClientSendCtx *send_ctx = client_transport_new_session(ct, &session);

    /* Step 3: create MeshStream */
    GIOStream *mesh_io = mesh_stream_new(session, client_send_fn, send_ctx, 220);
    if (!mesh_io) {
        g_warning("client: mesh_stream_new failed");
        send_error(cfd, 503, "deadmesh: failed to create mesh stream\n");
        g_free(send_ctx);
        g_free(req_buf);
        close(cfd);
        return NULL;
    }

    /* Step 4: wire up the stream so the reader thread can push data in */
    session->user_data = MESH_STREAM(mesh_io);

    g_debug("client: session %08x → gateway %08x",
            send_ctx->session_id, send_ctx->gateway_node_id);

    /* Step 5: write request → MeshOutputStream → fragments → radio */
    GOutputStream *out = g_io_stream_get_output_stream(mesh_io);
    GError *err = NULL;
    gsize written = 0;

    if (!g_output_stream_write_all(out, req_buf, (gsize)req_len,
                                   &written, NULL, &err)) {
        g_warning("client: mesh write failed: %s",
                  err ? err->message : "unknown");
        g_clear_error(&err);
        send_error(cfd, 503, "deadmesh: mesh send failed\n");
        g_object_unref(mesh_io);
        g_free(send_ctx);
        g_free(req_buf);
        close(cfd);
        return NULL;
    }
    g_free(req_buf);

    g_debug("client: sent %zu bytes over mesh (session=%08x)",
            written, send_ctx->session_id);

    /* Step 6 & 7: read response from stream, forward to browser.
     * The reader thread pushes reassembled data via mesh_stream_push_data().
     * We loop until EOF (stream closed by push side) or read error.     */
    GInputStream *in       = g_io_stream_get_input_stream(mesh_io);
    uint8_t      *resp_buf = g_malloc(16384);
    gsize         total_resp = 0;

    while (true) {
        gssize nread = g_input_stream_read(in, resp_buf, 16384, NULL, &err);

        if (nread < 0) {
            g_clear_error(&err);
            break;
        }
        if (nread == 0) break; /* EOF */

        ssize_t fw = write(cfd, resp_buf, (size_t)nread);
        if (fw < 0) break; /* browser closed */

        total_resp += (gsize)nread;
    }

    g_free(resp_buf);

    if (total_resp > 0) {
        g_info("client: session %08x complete — %zu response bytes",
               send_ctx->session_id, total_resp);
    } else {
        g_warning("client: session %08x — no response (mesh timeout?)",
                  send_ctx->session_id);
        send_error(cfd, 504,
            "deadmesh: no response from gateway (mesh timeout)\n"
            "Is the gateway node reachable? Does it have port 100 open?\n");
    }

    /* Step 8: clean up */
    g_object_unref(mesh_io);
    mesh_session_remove(ct->sessions, ct->gateway_node_id, send_ctx->session_id);
    g_free(send_ctx);
    close(cfd);
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * Accept loop
 * ───────────────────────────────────────────────────────────── */

static void accept_loop(int listen_fd, ClientTransport *ct) {
    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int cfd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (cfd < 0) {
            if (g_running)
                g_warning("client: accept failed: %s", g_strerror(errno));
            break;
        }

        g_debug("client: accepted from %s:%d",
                inet_ntoa(client_addr.sin_addr),
                ntohs(client_addr.sin_port));

        ConnCtx *ctx = g_new0(ConnCtx, 1);
        ctx->client_fd = cfd;
        ctx->transport = ct;

        GThread *t = g_thread_try_new("conn-worker", conn_worker, ctx, NULL);
        if (!t) {
            g_warning("client: failed to spawn worker");
            g_free(ctx);
            close(cfd);
        } else {
            g_thread_unref(t); /* detach */
        }
    }
}

/* ─────────────────────────────────────────────────────────────
 * Listen socket
 * ───────────────────────────────────────────────────────────── */

static int create_listener(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        g_critical("client: socket() failed: %s", g_strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        g_critical("client: bind :%u failed: %s", port, g_strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, CLIENT_BACKLOG) < 0) {
        g_critical("client: listen() failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/* ─────────────────────────────────────────────────────────────
 * Entry point
 * ───────────────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "deadmesh-client — LoRa mesh HTTP proxy\n\n"
        "Usage: %s --gateway NODE_ID [OPTIONS]\n\n"
        "Options:\n"
        "  --gateway ID     Gateway node ID in hex (e.g. 14e7cdaf) [required]\n"
        "  --port PORT      Local proxy port (default: %d)\n"
        "  --custom-port N  Meshtastic portnum for mesh traffic (default: 100)\n"
        "  --device PATH    Serial device in serial mode (default: /dev/rfcomm0)\n"
        "  -v               Verbose / debug logging\n"
        "  -h               Show this help\n\n"
        "Example:\n"
        "  %s --gateway 14e7cdaf\n"
        "  export http_proxy=http://localhost:%d\n"
        "  curl http://example.com\n\n",
        prog, CLIENT_DEFAULT_PROXY_PORT,
        prog, CLIENT_DEFAULT_PROXY_PORT);
}

int main(int argc, char *argv[]) {
    uint32_t    gateway_node_id = 0;
    uint16_t    proxy_port      = CLIENT_DEFAULT_PROXY_PORT;
    uint32_t    custom_port     = CLIENT_DEFAULT_MESH_PORT;
    const char *device          = "/dev/rfcomm0";
    bool        verbose         = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--gateway") == 0 && i + 1 < argc) {
            gateway_node_id = (uint32_t)strtoul(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            proxy_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--custom-port") == 0 && i + 1 < argc) {
            custom_port = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            device = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (gateway_node_id == 0) {
        fprintf(stderr, "Error: --gateway NODE_ID is required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if (verbose)
        g_setenv("G_MESSAGES_DEBUG", "all", TRUE);

    g_info("deadmesh-client starting");
    g_info("  gateway : %08x", gateway_node_id);
    g_info("  port    : %u",   proxy_port);
    g_info("  portnum : %u",   custom_port);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Connect to radio */
    g_transport = client_transport_new(gateway_node_id, custom_port);
    if (!client_transport_connect(g_transport, device)) {
        g_critical("client: failed to connect to radio");
        client_transport_free(g_transport);
        return 1;
    }

    /* Wait up to 3s for MyNodeInfo so local_node_id is set */
    g_info("client: waiting for mesh state sync...");
    for (int i = 0; i < 30 && g_transport->local_node_id == 0; i++)
        g_usleep(100 * 1000);

    if (g_transport->local_node_id != 0)
        g_info("client: local node: %08x", g_transport->local_node_id);
    else
        g_warning("client: local node ID not yet known — from= will be 0");

    /* Create proxy listener */
    g_listen_fd = create_listener(proxy_port);
    if (g_listen_fd < 0) {
        client_transport_free(g_transport);
        return 1;
    }

    g_print("\ndeadmesh-client ready!\n");
    g_print("  Proxy:   http://localhost:%u\n", proxy_port);
    g_print("  Gateway: %08x\n", gateway_node_id);
    g_print("  Press Ctrl+C to stop\n\n");

    accept_loop(g_listen_fd, g_transport);

    /* Teardown */
    g_info("client: shutting down");
    if (g_listen_fd >= 0) { close(g_listen_fd); g_listen_fd = -1; }
    client_transport_free(g_transport);
    g_transport = NULL;
    return 0;
}