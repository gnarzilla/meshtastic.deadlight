// src/plugins/meshtastic_transport.h
#ifndef MESHTASTIC_TRANSPORT_H
#define MESHTASTIC_TRANSPORT_H

#include <glib.h>
#include <stdint.h>

// Transport header magic: "DLMT"
#define MESHTASTIC_DL_MAGIC 0x444C4D54u
#define MESHTASTIC_DL_VERSION 1

typedef enum {
    MESHTASTIC_DIR_REQUEST = 0,
    MESHTASTIC_DIR_RESPONSE = 1,
} MeshtasticDirection;

// Packed, endian-stable header (big-endian on the wire)
typedef struct {
    guint32 magic_be;
    guint8  version;
    guint8  direction;
    guint16 reserved_be;
    guint64 session_id_be;
    guint32 seq_be;
    guint32 total_be;
    guint16 payload_len_be;
} MeshtasticDlHeader;

typedef struct {
    guint32 from_node_id;
    guint64 session_id;
    MeshtasticDirection direction;
    GByteArray *message; // owned by caller
} MeshtasticCompleteMessage;

typedef struct _MeshtasticReassemblyTable MeshtasticReassemblyTable;

MeshtasticReassemblyTable *meshtastic_reassembly_new(guint max_sessions,
                                                     guint64 max_session_bytes,
                                                     guint session_ttl_seconds,
                                                     guint chunk_data_max);
void meshtastic_reassembly_free(MeshtasticReassemblyTable *t);

/**
 * Ingest a single chunk payload (already extracted from MeshPacket decoded payload).
 *
 * - `from_node_id`: MeshPacket sender node id.
 * - `payload`: raw bytes that start with MeshtasticDlHeader followed by chunk bytes.
 *
 * Returns a newly allocated MeshtasticCompleteMessage* when a full message is assembled.
 * Caller owns and must free via meshtastic_complete_message_free().
 */
MeshtasticCompleteMessage *meshtastic_reassembly_ingest(MeshtasticReassemblyTable *t,
                                                       guint32 from_node_id,
                                                       const guint8 *payload,
                                                       gsize payload_len);

void meshtastic_reassembly_cleanup_expired(MeshtasticReassemblyTable *t);

void meshtastic_complete_message_free(MeshtasticCompleteMessage *m);

/**
 * Builds an on-wire chunk payload (header + chunk bytes).
 * Returns a new GByteArray containing the on-wire payload to place into meshtastic_Data.payload.
 */
GByteArray *meshtastic_transport_build_chunk(guint64 session_id,
                                            MeshtasticDirection dir,
                                            guint32 seq,
                                            guint32 total,
                                            const guint8 *chunk_bytes,
                                            guint16 chunk_len);

#endif // MESHTASTIC_TRANSPORT_H


