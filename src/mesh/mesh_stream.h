/**
 * deadmesh - MeshStream: GIOStream over Meshtastic
 *
 * Wraps a MeshSession in a GIOStream so the proxy core can treat a
 * LoRa mesh session identically to a TCP socket connection.
 *
 * Architecture:
 *
 *   MeshStream (GIOStream)
 *     ├── MeshInputStream  (GInputStream)
 *     │     Backed by a pipe(2). Reader thread pushes reassembled
 *     │     data in via mesh_stream_push_data(). The proxy core
 *     │     calls g_input_stream_read() which blocks on the pipe
 *     │     read end — no polling, no busy-wait.
 *     │
 *     └── MeshOutputStream (GOutputStream)
 *           g_output_stream_write() chunks the data and calls the
 *           send_fn callback (which writes framed packets to serial).
 *           Returns when all chunks have been sent.
 *
 * Usage:
 *
 *   // In the reader thread, once a session is complete:
 *   GIOStream *stream = mesh_stream_new(session, send_fn, send_ctx);
 *   mesh_stream_push_data(MESH_STREAM(stream),
 *                         session->assembly_buf->data,
 *                         session->assembly_buf->len);
 *
 *   // Hand to proxy network layer as if it were a GSocketConnection:
 *   deadlight_network_handle_mesh_connection(context, stream, session);
 *
 *   // From the other side, after proxy writes a response:
 *   // send_fn is called automatically with chunked outbound data.
 *
 *   // Shutdown:
 *   mesh_stream_close(MESH_STREAM(stream));  // closes pipe, unblocks reads
 *   g_object_unref(stream);
 */

#ifndef DEADMESH_STREAM_H
#define DEADMESH_STREAM_H

#include <glib-object.h>
#include <gio/gio.h>
#include "mesh_session.h"

G_BEGIN_DECLS

/* ─────────────────────────────────────────────────────────────
 * Send callback type
 *
 * Called by MeshOutputStream when it has a chunk to transmit.
 * @payload     raw chunk data (does NOT include the seq/total header —
 *              the stream handles that internally)
 * @len         chunk length in bytes (<= fragment_size)
 * @seq         chunk sequence number (0-based)
 * @total       total number of chunks in this write
 * @user_data   opaque pointer passed to mesh_stream_new()
 *
 * Returns TRUE on success, FALSE to abort the write.
 * ───────────────────────────────────────────────────────────── */

typedef gboolean (*MeshSendFn)(const guint8 *payload, gsize len,
                                guint32 seq, guint32 total,
                                gpointer user_data);

/* ─────────────────────────────────────────────────────────────
 * MeshStream type
 * ───────────────────────────────────────────────────────────── */

#define MESH_TYPE_STREAM            (mesh_stream_get_type())
#define MESH_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MESH_TYPE_STREAM, MeshStream))
#define MESH_IS_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MESH_TYPE_STREAM))

typedef struct _MeshStream          MeshStream;
typedef struct _MeshStreamClass     MeshStreamClass;
typedef struct _MeshStreamPrivate   MeshStreamPrivate;

struct _MeshStream {
    GIOStream          parent_instance;
    MeshStreamPrivate *priv;
};

struct _MeshStreamClass {
    GIOStreamClass parent_class;
};

GType mesh_stream_get_type(void) G_GNUC_CONST;

/* ─────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────── */

/**
 * Create a new MeshStream for @session.
 *
 * @session       the mesh session this stream belongs to
 * @send_fn       callback invoked for each outbound chunk
 * @send_ctx      opaque pointer passed to @send_fn
 * @fragment_size max bytes per LoRa payload (typically 220)
 *
 * Returns a new GIOStream. Caller owns the reference (g_object_unref).
 */
GIOStream *mesh_stream_new(MeshSession *session,
                            MeshSendFn   send_fn,
                            gpointer     send_ctx,
                            gsize        fragment_size);

/**
 * Push inbound data into the stream's read pipe.
 *
 * Called from the reader thread when a complete message has been
 * reassembled. Wakes any blocked g_input_stream_read() call.
 *
 * Thread-safe. Returns FALSE if the stream is already closed.
 */
gboolean mesh_stream_push_data(MeshStream    *stream,
                                const guint8  *data,
                                gsize          len);

/**
 * Signal EOF on the read side (e.g. session closed by remote node).
 * Any pending or future g_input_stream_read() will return 0 (EOF).
 */
void mesh_stream_close_read(MeshStream *stream);

/**
 * Return the MeshSession this stream belongs to.
 */
MeshSession *mesh_stream_get_session(MeshStream *stream);

G_END_DECLS

#endif /* DEADMESH_STREAM_H */
