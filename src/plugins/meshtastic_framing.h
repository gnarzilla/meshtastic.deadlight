// src/plugins/meshtastic_framing.h
#ifndef MESHTASTIC_FRAMING_H
#define MESHTASTIC_FRAMING_H

#include <glib.h>
#include <gio/gio.h>
#include <stdint.h>

/**
 * Meshtastic serial framing (protobuf delimited messages).
 *
 * Meshtastic serial commonly uses a varint32 length prefix followed by a
 * protobuf-encoded message (ToRadio / FromRadio).
 */

gboolean meshtastic_framing_write_delimited(GIOChannel *ch,
                                            const guint8 *msg,
                                            gsize msg_len,
                                            GError **error);

/**
 * Attempts to extract a single length-delimited frame from `buffer`.
 *
 * - If a full frame is available: returns TRUE and sets (*out_frame, *out_len).
 *   The returned frame is newly allocated with g_malloc() and must be g_free()'d.
 * - If not enough data: returns FALSE and leaves buffer intact.
 */
gboolean meshtastic_framing_try_read_frame(GByteArray *buffer,
                                          guint8 **out_frame,
                                          gsize *out_len);

#endif // MESHTASTIC_FRAMING_H


