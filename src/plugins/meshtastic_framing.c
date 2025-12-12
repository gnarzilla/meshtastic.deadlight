// src/plugins/meshtastic_framing.c
#include "meshtastic_framing.h"
#include <string.h>

static gsize varint32_encode(guint32 value, guint8 out[5]) {
    gsize i = 0;
    while (value >= 0x80) {
        out[i++] = (guint8)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    out[i++] = (guint8)(value & 0x7F);
    return i;
}

static gboolean varint32_try_decode(const guint8 *data,
                                    gsize len,
                                    guint32 *out_value,
                                    gsize *out_consumed) {
    guint32 result = 0;
    guint shift = 0;

    for (gsize i = 0; i < len && i < 5; i++) {
        guint8 byte = data[i];
        result |= (guint32)(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) {
            *out_value = result;
            *out_consumed = i + 1;
            return TRUE;
        }
        shift += 7;
    }

    return FALSE;
}

gboolean meshtastic_framing_write_delimited(GIOChannel *ch,
                                            const guint8 *msg,
                                            gsize msg_len,
                                            GError **error) {
    g_return_val_if_fail(ch != NULL, FALSE);
    g_return_val_if_fail(msg != NULL || msg_len == 0, FALSE);

    guint8 prefix[5];
    gsize prefix_len = varint32_encode((guint32)msg_len, prefix);

    gsize written = 0;
    GIOStatus st = g_io_channel_write_chars(ch, (const gchar *)prefix, prefix_len, &written, error);
    if (st != G_IO_STATUS_NORMAL || written != prefix_len) {
        return FALSE;
    }

    written = 0;
    st = g_io_channel_write_chars(ch, (const gchar *)msg, msg_len, &written, error);
    if (st != G_IO_STATUS_NORMAL || written != msg_len) {
        return FALSE;
    }

    return g_io_channel_flush(ch, error) == G_IO_STATUS_NORMAL;
}

gboolean meshtastic_framing_try_read_frame(GByteArray *buffer,
                                          guint8 **out_frame,
                                          gsize *out_len) {
    g_return_val_if_fail(buffer != NULL, FALSE);
    g_return_val_if_fail(out_frame != NULL, FALSE);
    g_return_val_if_fail(out_len != NULL, FALSE);

    if (buffer->len == 0) return FALSE;

    guint32 msg_len = 0;
    gsize prefix_len = 0;
    if (!varint32_try_decode(buffer->data, buffer->len, &msg_len, &prefix_len)) {
        return FALSE; // need more data
    }

    gsize total_needed = prefix_len + (gsize)msg_len;
    if (buffer->len < total_needed) {
        return FALSE; // need more data
    }

    guint8 *frame = g_malloc((gsize)msg_len);
    if (msg_len > 0) {
        memcpy(frame, buffer->data + prefix_len, (gsize)msg_len);
    }

    // Consume bytes from the buffer
    g_byte_array_remove_range(buffer, 0, total_needed);

    *out_frame = frame;
    *out_len = (gsize)msg_len;
    return TRUE;
}


