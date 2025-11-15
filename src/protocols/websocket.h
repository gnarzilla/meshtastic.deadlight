#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include "../core/deadlight.h"

// WebSocket protocol registration
void deadlight_register_websocket_handler(void);

// WebSocket frame opcodes
typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0x2,
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xA
} WebSocketOpcode;

// WebSocket frame structure (exposed for plugins)
typedef struct {
    gboolean fin;
    gboolean rsv1;
    gboolean rsv2;
    gboolean rsv3;
    WebSocketOpcode opcode;
    gboolean mask;
    guint64 payload_len;
    guint8 masking_key[4];
    guint8 *payload_data;
    guchar *payload;
    gsize total_frame_size;
} WebSocketFrame;

// Plugin API functions
gboolean deadlight_websocket_frame_is_text(WebSocketFrame *frame);
gboolean deadlight_websocket_frame_is_binary(WebSocketFrame *frame);
gboolean deadlight_websocket_frame_is_control(WebSocketFrame *frame);
gchar* deadlight_websocket_frame_get_text_payload(WebSocketFrame *frame);

#endif // WEBSOCKET_H