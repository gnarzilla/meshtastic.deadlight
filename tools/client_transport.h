/**
 * client_transport.h — Meshtastic radio transport for deadmesh-client
 */

#ifndef CLIENT_TRANSPORT_H
#define CLIENT_TRANSPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>

#include "mesh_session.h"
#include "mesh_stream.h"

/* ─────────────────────────────────────────────────────────────
 * Types — defined here so client_main.c can access fields
 * ───────────────────────────────────────────────────────────── */

/* Per-session send context — one per proxy connection.
 * Passed as gpointer to MeshSendFn. Holds everything send_fn
 * needs without requiring access to the full ClientTransport.  */
typedef struct _ClientSendCtx {
    int       radio_fd;
    uint32_t  local_node_id;
    uint32_t  gateway_node_id;
    uint32_t  session_id;       /* packet.id — gateway echoes this in responses */
    uint32_t  custom_port;
    GMutex   *write_mutex;      /* shared with ClientTransport, not owned here  */
} ClientSendCtx;

typedef struct _ClientTransport {
    /* Radio connection */
    int          radio_fd;
    GMutex       write_mutex;

    /* Node identity */
    uint32_t     local_node_id;   /* auto-detected from MyNodeInfo */
    uint32_t     gateway_node_id; /* destination for all outbound packets */
    uint32_t     custom_port;     /* portnum=100 by default */

    /* Session table — keyed by (gateway_node_id, session_id) */
    MeshSessionTable *sessions;

    /* Reader thread */
    GThread     *reader_thread;
    gboolean     running;

    /* Session ID counter */
    uint32_t     next_session_id;
    GMutex       session_id_mutex;

    /* Stats */
    guint64      frames_sent;
    guint64      frames_recv;
    guint64      encode_errors;
} ClientTransport;

/* ─────────────────────────────────────────────────────────────
 * API
 * ───────────────────────────────────────────────────────────── */

/* Create transport — does not connect yet */
ClientTransport *client_transport_new(uint32_t gateway_node_id,
                                       uint32_t custom_port);

/* Connect to radio and start reader thread.
 * TCP mode (default): host_or_device ignored; connects to 127.0.0.1:4403.
 * Serial mode (-DCLIENT_TRANSPORT_SERIAL): device path e.g. /dev/rfcomm0  */
gboolean client_transport_connect(ClientTransport *ct,
                                   const char *host_or_device);

/* Allocate a new session and return its send context.
 * If out_session is non-NULL, the underlying MeshSession is also returned
 * so the caller can set session->user_data = stream after stream creation.
 * Caller must free send_ctx with g_free() and call mesh_session_remove()
 * when the session is done.                                                */
ClientSendCtx *client_transport_new_session(ClientTransport *ct,
                                             MeshSession    **out_session);

/* The MeshSendFn — pass to mesh_stream_new() as send_fn.
 * Returns int (not bool) to match the MeshSendFn typedef.                  */
int client_send_fn(const uint8_t *payload, size_t len,
                   uint32_t seq, uint32_t total,
                   gpointer ctx);

void client_transport_free(ClientTransport *ct);

#endif /* CLIENT_TRANSPORT_H */