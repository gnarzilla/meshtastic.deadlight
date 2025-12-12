// src/plugins/meshtastic_transport.c
#include "meshtastic_transport.h"
#include <string.h>

typedef struct {
    guint32 from_node_id;
    guint64 session_id;
    guint8 direction;
} ReassemblyKey;

typedef struct {
    gint64 last_update_us;
    guint32 total_chunks;
    guint32 received_chunks;
    guint chunk_data_max;
    GByteArray *storage;      // sized total_chunks*chunk_data_max
    GArray *chunk_sizes;      // guint16 per chunk (0 means missing)
} ReassemblyState;

struct _MeshtasticReassemblyTable {
    GHashTable *sessions; // ReassemblyKey* -> ReassemblyState*
    GMutex mutex;
    guint max_sessions;
    guint64 max_session_bytes;
    guint session_ttl_seconds;
    guint chunk_data_max;
};

static guint reassembly_key_hash(gconstpointer p) {
    const ReassemblyKey *k = (const ReassemblyKey *)p;
    // simple mixing
    guint h = (guint)k->from_node_id;
    h = (h * 16777619u) ^ (guint)(k->session_id & 0xFFFFFFFFu);
    h = (h * 16777619u) ^ (guint)(k->session_id >> 32);
    h = (h * 16777619u) ^ (guint)k->direction;
    return h;
}

static gboolean reassembly_key_equal(gconstpointer a, gconstpointer b) {
    const ReassemblyKey *ka = (const ReassemblyKey *)a;
    const ReassemblyKey *kb = (const ReassemblyKey *)b;
    return ka->from_node_id == kb->from_node_id &&
           ka->session_id == kb->session_id &&
           ka->direction == kb->direction;
}

static void reassembly_state_free(gpointer p) {
    ReassemblyState *s = (ReassemblyState *)p;
    if (!s) return;
    if (s->storage) g_byte_array_free(s->storage, TRUE);
    if (s->chunk_sizes) g_array_free(s->chunk_sizes, TRUE);
    g_free(s);
}

static void reassembly_key_free(gpointer p) {
    g_free(p);
}

MeshtasticReassemblyTable *meshtastic_reassembly_new(guint max_sessions,
                                                     guint64 max_session_bytes,
                                                     guint session_ttl_seconds,
                                                     guint chunk_data_max) {
    MeshtasticReassemblyTable *t = g_new0(MeshtasticReassemblyTable, 1);
    t->sessions = g_hash_table_new_full(reassembly_key_hash, reassembly_key_equal,
                                        reassembly_key_free, reassembly_state_free);
    g_mutex_init(&t->mutex);
    t->max_sessions = max_sessions ? max_sessions : 64;
    t->max_session_bytes = max_session_bytes ? max_session_bytes : (256 * 1024);
    t->session_ttl_seconds = session_ttl_seconds ? session_ttl_seconds : 30;
    t->chunk_data_max = chunk_data_max ? chunk_data_max : 192;
    return t;
}

void meshtastic_reassembly_free(MeshtasticReassemblyTable *t) {
    if (!t) return;
    if (t->sessions) g_hash_table_destroy(t->sessions);
    g_mutex_clear(&t->mutex);
    g_free(t);
}

void meshtastic_complete_message_free(MeshtasticCompleteMessage *m) {
    if (!m) return;
    if (m->message) g_byte_array_free(m->message, TRUE);
    g_free(m);
}

GByteArray *meshtastic_transport_build_chunk(guint64 session_id,
                                            MeshtasticDirection dir,
                                            guint32 seq,
                                            guint32 total,
                                            const guint8 *chunk_bytes,
                                            guint16 chunk_len) {
    MeshtasticDlHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic_be = GUINT32_TO_BE(MESHTASTIC_DL_MAGIC);
    hdr.version = MESHTASTIC_DL_VERSION;
    hdr.direction = (guint8)dir;
    hdr.session_id_be = GUINT64_TO_BE(session_id);
    hdr.seq_be = GUINT32_TO_BE(seq);
    hdr.total_be = GUINT32_TO_BE(total);
    hdr.payload_len_be = GUINT16_TO_BE(chunk_len);

    GByteArray *out = g_byte_array_sized_new(sizeof(hdr) + chunk_len);
    g_byte_array_append(out, (const guint8 *)&hdr, sizeof(hdr));
    if (chunk_len > 0 && chunk_bytes) {
        g_byte_array_append(out, chunk_bytes, chunk_len);
    }
    return out;
}

static gboolean parse_header(const guint8 *payload, gsize payload_len,
                            MeshtasticDlHeader *out_hdr,
                            const guint8 **out_chunk,
                            gsize *out_chunk_len) {
    if (payload_len < sizeof(MeshtasticDlHeader)) return FALSE;
    memcpy(out_hdr, payload, sizeof(MeshtasticDlHeader));

    guint32 magic = GUINT32_FROM_BE(out_hdr->magic_be);
    if (magic != MESHTASTIC_DL_MAGIC) return FALSE;
    if (out_hdr->version != MESHTASTIC_DL_VERSION) return FALSE;

    guint16 chunk_len = GUINT16_FROM_BE(out_hdr->payload_len_be);
    gsize available = payload_len - sizeof(MeshtasticDlHeader);
    if (chunk_len > available) return FALSE;

    *out_chunk = payload + sizeof(MeshtasticDlHeader);
    *out_chunk_len = chunk_len;
    return TRUE;
}

static gint64 now_us(void) {
    return g_get_monotonic_time();
}

static void drop_oldest_session_locked(MeshtasticReassemblyTable *t) {
    // O(n) scan; acceptable for small max_sessions.
    GHashTableIter iter;
    gpointer key = NULL, value = NULL;
    gint64 oldest = G_MAXINT64;
    gpointer oldest_key = NULL;

    g_hash_table_iter_init(&iter, t->sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        ReassemblyState *s = (ReassemblyState *)value;
        if (s && s->last_update_us < oldest) {
            oldest = s->last_update_us;
            oldest_key = key;
        }
    }

    if (oldest_key) {
        g_hash_table_remove(t->sessions, oldest_key);
    }
}

MeshtasticCompleteMessage *meshtastic_reassembly_ingest(MeshtasticReassemblyTable *t,
                                                       guint32 from_node_id,
                                                       const guint8 *payload,
                                                       gsize payload_len) {
    if (!t || !payload) return NULL;

    MeshtasticDlHeader hdr;
    const guint8 *chunk = NULL;
    gsize chunk_len = 0;
    if (!parse_header(payload, payload_len, &hdr, &chunk, &chunk_len)) {
        return NULL;
    }

    guint64 session_id = GUINT64_FROM_BE(hdr.session_id_be);
    guint32 seq = GUINT32_FROM_BE(hdr.seq_be);
    guint32 total = GUINT32_FROM_BE(hdr.total_be);
    guint8 dir = hdr.direction;

    if (total == 0 || total > 4096) return NULL;
    if (seq >= total) return NULL;
    if (chunk_len > t->chunk_data_max) return NULL;

    MeshtasticCompleteMessage *completed = NULL;

    g_mutex_lock(&t->mutex);
    {
        // Enforce table size
        if (g_hash_table_size(t->sessions) >= t->max_sessions) {
            drop_oldest_session_locked(t);
        }

        ReassemblyKey lookup = { from_node_id, session_id, dir };
        ReassemblyState *state = g_hash_table_lookup(t->sessions, &lookup);
        if (!state) {
            guint64 required = (guint64)total * (guint64)t->chunk_data_max;
            if (required > t->max_session_bytes) {
                g_mutex_unlock(&t->mutex);
                return NULL;
            }

            ReassemblyKey *k = g_new0(ReassemblyKey, 1);
            k->from_node_id = from_node_id;
            k->session_id = session_id;
            k->direction = dir;

            state = g_new0(ReassemblyState, 1);
            state->last_update_us = now_us();
            state->total_chunks = total;
            state->received_chunks = 0;
            state->chunk_data_max = t->chunk_data_max;
            state->storage = g_byte_array_sized_new((guint)required);
            g_byte_array_set_size(state->storage, (guint)required);
            state->chunk_sizes = g_array_sized_new(FALSE, TRUE, sizeof(guint16), total);
            g_array_set_size(state->chunk_sizes, total);
            // init sizes to 0
            for (guint i = 0; i < total; i++) {
                g_array_index(state->chunk_sizes, guint16, i) = 0;
            }

            g_hash_table_insert(t->sessions, k, state);
        }

        // Reject mismatched total on existing session
        if (state->total_chunks != total) {
            // protocol violation; drop session
            ReassemblyKey lookup2 = { from_node_id, session_id, dir };
            g_hash_table_remove(t->sessions, &lookup2);
            g_mutex_unlock(&t->mutex);
            return NULL;
        }

        state->last_update_us = now_us();

        guint16 *slot_size = &g_array_index(state->chunk_sizes, guint16, seq);
        if (*slot_size == 0) {
            // copy bytes
            gsize off = (gsize)seq * (gsize)t->chunk_data_max;
            memcpy(state->storage->data + off, chunk, chunk_len);
            *slot_size = (guint16)chunk_len;
            state->received_chunks++;
        }

        if (state->received_chunks == state->total_chunks) {
            // build exact message
            GByteArray *msg = g_byte_array_new();
            for (guint32 i = 0; i < state->total_chunks; i++) {
                guint16 sz = g_array_index(state->chunk_sizes, guint16, i);
                if (sz == 0) continue;
                gsize off = (gsize)i * (gsize)t->chunk_data_max;
                g_byte_array_append(msg, state->storage->data + off, sz);
            }

            completed = g_new0(MeshtasticCompleteMessage, 1);
            completed->from_node_id = from_node_id;
            completed->session_id = session_id;
            completed->direction = (MeshtasticDirection)dir;
            completed->message = msg;

            ReassemblyKey lookup3 = { from_node_id, session_id, dir };
            g_hash_table_remove(t->sessions, &lookup3);
        }
    }
    g_mutex_unlock(&t->mutex);

    return completed;
}

void meshtastic_reassembly_cleanup_expired(MeshtasticReassemblyTable *t) {
    if (!t) return;
    gint64 now = now_us();
    gint64 cutoff = now - ((gint64)t->session_ttl_seconds * G_USEC_PER_SEC);

    g_mutex_lock(&t->mutex);
    {
        GHashTableIter iter;
        gpointer key = NULL, value = NULL;
        g_hash_table_iter_init(&iter, t->sessions);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            ReassemblyState *s = (ReassemblyState *)value;
            if (s && s->last_update_us < cutoff) {
                g_hash_table_iter_remove(&iter);
            }
        }
    }
    g_mutex_unlock(&t->mutex);
}


