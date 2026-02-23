/**
 * deadmesh - Meshtastic Serial Framing Layer
 *
 * Encodes and decodes the Meshtastic serial framing protocol:
 *
 *   Byte 0:   0x94  (magic)
 *   Byte 1:   0xC3  (magic)
 *   Byte 2:   high byte of payload length (big-endian uint16)
 *   Byte 3:   low  byte of payload length
 *   Byte 4+:  protobuf payload (ToRadio or FromRadio)
 *
 * This module has NO dependency on GLib or the proxy core — it is
 * intentionally plain C so it can be used by:
 *   - src/plugins/meshtastic.c  (the real radio path)
 *   - tools/mesh-sim.c          (the PTY simulator)
 *   - test harnesses
 */

#ifndef DEADMESH_FRAMING_H
#define DEADMESH_FRAMING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────── */

#define MESH_FRAME_MAGIC0      0x94
#define MESH_FRAME_MAGIC1      0xC3
#define MESH_FRAME_HEADER_LEN  4        /* 2 magic + 2 length bytes       */
#define MESH_FRAME_MAX_PAYLOAD 512      /* Meshtastic max packet size       */
#define MESH_FRAME_MAX_TOTAL   (MESH_FRAME_HEADER_LEN + MESH_FRAME_MAX_PAYLOAD)

/* ─────────────────────────────────────────────────────────────
 * Frame reader state machine
 * ───────────────────────────────────────────────────────────── */

typedef enum {
    MESH_FRAME_STATE_WAIT_MAGIC0 = 0,
    MESH_FRAME_STATE_WAIT_MAGIC1,
    MESH_FRAME_STATE_READ_LEN_HI,
    MESH_FRAME_STATE_READ_LEN_LO,
    MESH_FRAME_STATE_READ_PAYLOAD,
    MESH_FRAME_STATE_READY          /* full frame available — call mesh_frame_get() */
} MeshFrameState;

/**
 * Incremental frame reader.
 *
 * Feed bytes one chunk at a time with mesh_frame_reader_push().
 * When state == MESH_FRAME_STATE_READY, call mesh_frame_get() to
 * retrieve the payload, then mesh_frame_reader_reset() to resume.
 */
typedef struct {
    MeshFrameState  state;
    uint16_t        payload_len;    /* declared length from header          */
    uint16_t        payload_pos;    /* bytes received so far                */
    uint8_t         payload[MESH_FRAME_MAX_PAYLOAD];
    uint64_t        frames_decoded; /* lifetime counter                     */
    uint64_t        sync_errors;    /* times we had to re-sync on magic     */
} MeshFrameReader;

/* ─────────────────────────────────────────────────────────────
 * Completed frame (output of get)
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  payload[MESH_FRAME_MAX_PAYLOAD];
    uint16_t len;
} MeshFrame;

/* ─────────────────────────────────────────────────────────────
 * Frame reader API
 * ───────────────────────────────────────────────────────────── */

/**
 * Initialise a reader to WAIT_MAGIC0 state.
 */
void mesh_frame_reader_init(MeshFrameReader *reader);

/**
 * Push up to @len bytes into the reader.
 *
 * Returns the number of bytes consumed (<= len).
 * If the reader reaches MESH_FRAME_STATE_READY before all bytes
 * are consumed, it stops — call mesh_frame_get() + mesh_frame_reader_reset(),
 * then push the remainder.
 */
size_t mesh_frame_reader_push(MeshFrameReader *reader,
                               const uint8_t *data, size_t len);

/**
 * Copy the completed frame into @out.
 * Only valid when reader->state == MESH_FRAME_STATE_READY.
 * Returns false if called in wrong state.
 */
bool mesh_frame_get(const MeshFrameReader *reader, MeshFrame *out);

/**
 * Reset reader back to WAIT_MAGIC0 after consuming a frame.
 */
void mesh_frame_reader_reset(MeshFrameReader *reader);

/* ─────────────────────────────────────────────────────────────
 * Frame encoder API
 * ───────────────────────────────────────────────────────────── */

/**
 * Encode @payload_len bytes of @payload into a framed packet.
 *
 * Writes into @out_buf (caller must provide at least
 * MESH_FRAME_HEADER_LEN + payload_len bytes).
 *
 * Returns total bytes written, or 0 on error (payload too large).
 */
size_t mesh_frame_encode(const uint8_t *payload, uint16_t payload_len,
                          uint8_t *out_buf, size_t out_buf_len);

/* ─────────────────────────────────────────────────────────────
 * Convenience: blocking read from a file descriptor
 * ───────────────────────────────────────────────────────────── */

/**
 * Block on @fd until a complete frame is available.
 * Feeds bytes into @reader one read() at a time.
 *
 * Returns true and populates @out on success.
 * Returns false on EOF or unrecoverable read error (errno set).
 *
 * This replaces the 100ms g_usleep poll loop in the original plugin.
 */
bool mesh_frame_read_blocking(int fd, MeshFrameReader *reader, MeshFrame *out);

#ifdef __cplusplus
}
#endif

#endif /* DEADMESH_FRAMING_H */
