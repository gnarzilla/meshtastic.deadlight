/**
 * deadmesh - Mesh Session Routing Layer Implementation
 */

#include "mesh_session.h"
#include <string.h>
#include <stdlib.h>

/* ─────────────────────────────────────────────────────────────
 * Key helpers
 * ───────────────────────────────────────────────────────────── */

gchar *mesh_session_make_key(uint32_t src_node_id, uint32_t session_id) {
    return g_strdup_printf("%08x:%08x", src_node_id, session_id);
}

static void mesh_session_free(gpointer data) {
    MeshSession *s = (MeshSession *)data;
    if (!s) return;

    g_free(s->key);
    g_free(s->chunk_bitmap);

    if (s->assembly_buf) {
        g_byte_array_free(s->assembly_buf, TRUE);
    }

    g_free(s);
}

/* ─────────────────────────────────────────────────────────────
 * Table lifecycle
 * ───────────────────────────────────────────────────────────── */

MeshSessionTable *mesh_session_table_new(guint session_timeout_ms) {
    MeshSessionTable *t = g_new0(MeshSessionTable, 1);
    t->table = g_hash_table_new_full(g_str_hash, g_str_equal,
                                      NULL,               /* key owned by session */
                                      mesh_session_free);
    g_mutex_init(&t->mutex);
    t->session_timeout_us = (gint64)session_timeout_ms * 1000LL;
    return t;
}

void mesh_session_table_free(MeshSessionTable *table) {
    if (!table) return;
    g_mutex_lock(&table->mutex);
    g_hash_table_destroy(table->table);
    g_mutex_unlock(&table->mutex);
    g_mutex_clear(&table->mutex);
    g_free(table);
}

/* ─────────────────────────────────────────────────────────────
 * Lookup / create
 * ───────────────────────────────────────────────────────────── */

MeshSession *mesh_session_lookup(MeshSessionTable *table,
                                  uint32_t src_node_id,
                                  uint32_t session_id) {
    gchar *key = mesh_session_make_key(src_node_id, session_id);

    g_mutex_lock(&table->mutex);
    MeshSession *s = g_hash_table_lookup(table->table, key);
    g_mutex_unlock(&table->mutex);

    g_free(key);
    return s;
}

MeshSession *mesh_session_get_or_create(MeshSessionTable *table,
                                         uint32_t src_node_id,
                                         uint32_t session_id) {
    gchar *key = mesh_session_make_key(src_node_id, session_id);

    g_mutex_lock(&table->mutex);

    MeshSession *s = g_hash_table_lookup(table->table, key);

    if (!s) {
        s = g_new0(MeshSession, 1);
        s->src_node_id   = src_node_id;
        s->session_id    = session_id;
        s->key           = key;         /* table key points into session */
        s->state         = MESH_SESSION_OPENING;
        s->assembly_buf  = g_byte_array_new();
        s->created_at    = g_get_monotonic_time();
        s->last_activity = s->created_at;

        /* Use session's own key string as hash table key (no copy needed) */
        g_hash_table_insert(table->table, s->key, s);
        table->total_created++;
    } else {
        g_free(key);
    }

    s->last_activity = g_get_monotonic_time();

    g_mutex_unlock(&table->mutex);
    return s;
}

/* ─────────────────────────────────────────────────────────────
 * State transitions
 * ───────────────────────────────────────────────────────────── */

void mesh_session_assign_conn(MeshSessionTable *table,
                               MeshSession *session,
                               DeadlightConnection *conn) {
    g_mutex_lock(&table->mutex);
    session->conn           = conn;
    session->state          = MESH_SESSION_ACTIVE;
    session->last_activity  = g_get_monotonic_time();
    g_mutex_unlock(&table->mutex);
}

void mesh_session_close(MeshSessionTable *table, MeshSession *session) {
    g_mutex_lock(&table->mutex);
    if (session->state != MESH_SESSION_CLOSED) {
        session->state = MESH_SESSION_CLOSING;
    }
    g_mutex_unlock(&table->mutex);
}

void mesh_session_remove(MeshSessionTable *table,
                          uint32_t src_node_id,
                          uint32_t session_id) {
    gchar *key = mesh_session_make_key(src_node_id, session_id);
    g_mutex_lock(&table->mutex);
    g_hash_table_remove(table->table, key);
    g_mutex_unlock(&table->mutex);
    g_free(key);
}

/* ─────────────────────────────────────────────────────────────
 * Expiry
 * ───────────────────────────────────────────────────────────── */

guint mesh_session_expire(MeshSessionTable *table) {
    if (table->session_timeout_us == 0) return 0;

    gint64 now     = g_get_monotonic_time();
    guint  expired = 0;

    g_mutex_lock(&table->mutex);

    GHashTableIter iter;
    gpointer key, value;
    GPtrArray *to_remove = g_ptr_array_new();

    g_hash_table_iter_init(&iter, table->table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        MeshSession *s = (MeshSession *)value;
        gint64 idle = now - s->last_activity;

        if (idle > table->session_timeout_us &&
            s->state != MESH_SESSION_ACTIVE) {
            g_ptr_array_add(to_remove, s->key);
        }
    }

    for (guint i = 0; i < to_remove->len; i++) {
        g_hash_table_remove(table->table, to_remove->pdata[i]);
        expired++;
        table->total_expired++;
    }

    g_ptr_array_free(to_remove, TRUE);
    g_mutex_unlock(&table->mutex);

    return expired;
}

/* ─────────────────────────────────────────────────────────────
 * Reassembly
 * ───────────────────────────────────────────────────────────── */

bool mesh_session_init_reassembly(MeshSession *session, uint32_t total_chunks) {
    if (session->chunk_bitmap) {
        g_free(session->chunk_bitmap);
    }

    session->expected_chunks = total_chunks;
    session->received_chunks = 0;

    if (total_chunks == 0) {
        session->chunk_bitmap = NULL;
        session->bitmap_words = 0;
        return true;
    }

    session->bitmap_words = (total_chunks + 31) / 32;
    session->chunk_bitmap = g_new0(uint32_t, session->bitmap_words);

    /* Pre-size the assembly buffer to avoid repeated reallocations.
     * We don't know individual chunk sizes yet — use max as upper bound. */
    g_byte_array_set_size(session->assembly_buf, 0);

    return true;
}

bool mesh_session_record_chunk(MeshSession *session, uint32_t seq_num,
                                const uint8_t *data, size_t len) {
    if (seq_num >= session->expected_chunks) return false;
    if (!session->chunk_bitmap)             return false;

    /* Mark chunk as received in bitmap */
    uint32_t word = seq_num / 32;
    uint32_t bit  = seq_num % 32;

    bool already_received = (session->chunk_bitmap[word] >> bit) & 1;
    if (!already_received) {
        session->chunk_bitmap[word] |= (1u << bit);
        session->received_chunks++;
        session->bytes_in += len;
        session->last_activity = g_get_monotonic_time();
    }

    /* Write data at the correct offset in the assembly buffer.
     * We keep the buffer sized to fit all received data contiguously
     * at seq_num * MAX_CHUNK_SIZE offsets.                          */
    size_t offset = seq_num * 220; /* DEADMESH_DEFAULT_FRAGMENT_SIZE */
    size_t required = offset + len;

    if (session->assembly_buf->len < required) {
        g_byte_array_set_size(session->assembly_buf, required);
    }
    memcpy(session->assembly_buf->data + offset, data, len);

    /* Return true when all chunks have arrived */
    return (session->received_chunks >= session->expected_chunks);
}

bool mesh_session_has_chunk(const MeshSession *session, uint32_t seq_num) {
    if (seq_num >= session->expected_chunks) return false;
    if (!session->chunk_bitmap)              return false;

    uint32_t word = seq_num / 32;
    uint32_t bit  = seq_num % 32;
    return (session->chunk_bitmap[word] >> bit) & 1;
}
