/**
 * Deadlight Proxy v1.0 - Protocol Manager
 *
 * Manages registration and detection of protocol handlers.
 */
#include "deadlight.h"

// For registering protocol handlers
#include "protocols/api.h"
#include "protocols/websocket.h"
#include "protocols/http.h"
#include "protocols/imap.h" 
#include "protocols/imaps.h"
#include "protocols/socks.h"
#include "protocols/smtp.h"
#include "protocols/ftp.h"

static GList *protocol_handlers = NULL;

// Public function to register a handler
void deadlight_protocol_register(const DeadlightProtocolHandler *handler) {
    protocol_handlers = g_list_append(protocol_handlers, (gpointer)handler);
    g_info("Registered protocol handler: %s", handler->name);
}

/**
 * Initialize and register all built-in protocol handlers.
 * This is called once at startup from main.c.
 */
void deadlight_protocols_init(DeadlightContext *context) {
    (void)context;
    g_info("Initializing protocol handlers...");

    // Register your handlers here
    deadlight_register_api_handler();
    deadlight_register_websocket_handler();
    deadlight_register_http_handler();
    deadlight_register_imap_handler();
    deadlight_register_imaps_handler();
    deadlight_register_socks_handler();
    deadlight_register_smtp_handler();
    deadlight_register_ftp_handler();

    g_info("%d protocol handlers registered.", g_list_length(protocol_handlers));
}

/**
 * Helper function to check if data looks like TLS handshake
 */
static gboolean looks_like_tls_handshake(const guint8 *buf, gsize len) {
    // TLS record header: [type][version_major][version_minor][length_high][length_low]
    // ClientHello: type=0x16, version typically 0x03,0x01-0x03
    if (len < 5) return FALSE;
    
    return (buf[0] == 0x16 &&           // TLS Handshake
            buf[1] == 0x03 &&           // SSL 3.0/TLS 1.x major version
            buf[2] >= 0x01 && buf[2] <= 0x04);  // Minor version range
}

/**
 * Helper function to check if data looks like HTTP
 */
#ifdef FUTURE_USE
static gboolean looks_like_http(const guint8 *buf, gsize len) {
    if (len < 3) return FALSE;
    
    // Check for HTTP methods with more precision
    const struct {
        const gchar *method;
        gsize len;
    } methods[] = {
        {"GET ", 4},
        {"POST ", 5}, 
        {"PUT ", 4},
        {"DELETE ", 7},
        {"HEAD ", 5},
        {"OPTIONS ", 8},
        {"PATCH ", 6},
        {"CONNECT ", 8},
        {"TRACE ", 6},
        {NULL, 0}
    };
    
    for (int i = 0; methods[i].method; i++) {
        if (len >= methods[i].len && 
            memcmp(buf, methods[i].method, methods[i].len) == 0) {
            return TRUE;
        }
    }
    
    return FALSE;
}
#endif

/**
 * Helper function to check if data looks like SOCKS
 */
static gboolean looks_like_socks(const guint8 *buf, gsize len) {
    if (len < 2) return FALSE;
    
    // SOCKS4: first byte is version (0x04)
    if (buf[0] == 0x04) return TRUE;
    
    // SOCKS5: first byte is version (0x05), second is number of auth methods
    if (buf[0] == 0x05 && len > 2 && buf[1] > 0 && buf[1] < 16) return TRUE;
    
    return FALSE;
}

/**
 * Fast-path protocol detection with improved logic
 */

static DeadlightProtocol quick_detect(const guint8 *buf, gsize len) {
    if (len == 0) return DEADLIGHT_PROTOCOL_UNKNOWN;
    
    // 1) TLS handshake detection (highest priority for binary protocols)
    if (looks_like_tls_handshake(buf, len)) {
        return DEADLIGHT_PROTOCOL_IMAPS;
    }
    
    // 2) SOCKS detection (binary protocols before text)
    if (looks_like_socks(buf, len)) {
        return DEADLIGHT_PROTOCOL_SOCKS; 
    }

    // 3) Text-based protocols (check for specific greetings)
    if (g_str_has_prefix((const gchar*)buf, "GET") ||
        g_str_has_prefix((const gchar*)buf, "POST") ||
        g_str_has_prefix((const gchar*)buf, "HEAD") ||
        g_str_has_prefix((const gchar*)buf, "PUT") ||
        g_str_has_prefix((const gchar*)buf, "DELETE") ||
        g_str_has_prefix((const gchar*)buf, "OPTIONS") ||
        g_str_has_prefix((const gchar*)buf, "CONNECT")) {
        return DEADLIGHT_PROTOCOL_HTTP;
    }

    // New: Check for SMTP greetings
    if (g_str_has_prefix((const gchar*)buf, "HELO") ||
        g_str_has_prefix((const gchar*)buf, "EHLO")) {
        return DEADLIGHT_PROTOCOL_SMTP;
    }

    // New: Check for IMAP greeting from client (e.g., "A001")
    if (g_str_has_prefix((const gchar*)buf, "A0")) {
        return DEADLIGHT_PROTOCOL_IMAP;
    }

    // 4) Truly unknown
    return DEADLIGHT_PROTOCOL_UNKNOWN;
}


/**
 * Iterates through registered handlers to find one that can
 * process the incoming data.
 */
const DeadlightProtocolHandler*
deadlight_protocol_detect_and_assign(DeadlightConnection *conn,
                                     const guint8 *data,
                                     gsize length)
{
    // 1) Let each handler detect and return a priority
    const DeadlightProtocolHandler *best_handler = NULL;
    gsize best_priority = 0;
    
    for (GList *l = protocol_handlers; l; l = l->next) {
        const DeadlightProtocolHandler *h = l->data;
        if (h->detect) {
            gsize priority = h->detect(data, length);
            if (priority > best_priority) {
                best_priority = priority;
                best_handler = h;
            }
        }
    }
    
    if (best_handler) {
        conn->protocol = best_handler->protocol_id;
        conn->handler = best_handler;
        g_debug("Best handler match: %s with priority %zu", best_handler->name, best_priority);
        return best_handler;
    }
    
    // 2) Fallback to quick_detect only if no handler claimed it
    DeadlightProtocol detected = quick_detect(data, length);
    
    if (detected != DEADLIGHT_PROTOCOL_UNKNOWN) {
        for (GList *l = protocol_handlers; l; l = l->next) {
            const DeadlightProtocolHandler *h = l->data;
            if (h->protocol_id == detected) {
                conn->protocol = detected;
                conn->handler = h;
                g_debug("Quick detect fallback matched: %s", h->name);
                return h;
            }
        }
        g_warning("Quick detect found protocol %s but no handler registered", 
                  deadlight_protocol_to_string(detected));
    }

    // 3) Nothing matched - default to HTTP for text data, or unknown
    if (length > 0 && g_ascii_isprint(data[0])) {
        // Try to find HTTP handler as last resort for text data
        for (GList *l = protocol_handlers; l; l = l->next) {
            const DeadlightProtocolHandler *h = l->data;
            if (h->protocol_id == DEADLIGHT_PROTOCOL_HTTP) {
                conn->protocol = DEADLIGHT_PROTOCOL_HTTP;
                conn->handler = h;
                g_debug("Defaulting unknown text protocol to HTTP");
                return h;
            }
        }
    }

    // 4) Truly unknown
    conn->protocol = DEADLIGHT_PROTOCOL_UNKNOWN;
    conn->handler = NULL;
    g_debug("No handler found for protocol");
    return NULL;
}

/**
 * Convert protocol enum to string
 */
const gchar *deadlight_protocol_to_string(DeadlightProtocol protocol) {
    switch (protocol) {
        case DEADLIGHT_PROTOCOL_API: return "API"; 
        case DEADLIGHT_PROTOCOL_HTTP: return "HTTP";
        case DEADLIGHT_PROTOCOL_HTTPS: return "HTTPS";
        case DEADLIGHT_PROTOCOL_SOCKS: return "SOCKS";
        case DEADLIGHT_PROTOCOL_SOCKS4: return "SOCKS4";
        case DEADLIGHT_PROTOCOL_SOCKS5: return "SOCKS5";
        case DEADLIGHT_PROTOCOL_CONNECT: return "CONNECT";
        case DEADLIGHT_PROTOCOL_WEBSOCKET: return "WebSocket";
        case DEADLIGHT_PROTOCOL_IMAP: return "IMAP";
        case DEADLIGHT_PROTOCOL_IMAPS: return "IMAPS";
        case DEADLIGHT_PROTOCOL_SMTP: return "SMTP";
        case DEADLIGHT_PROTOCOL_FTP: return "FTP";
        case DEADLIGHT_PROTOCOL_UNKNOWN: return "Unknown";
        default: return "Unknown";
    }
}

/**
 * Cleanup function to free protocol handler list
 */
void deadlight_protocols_cleanup(void) {
    if (protocol_handlers) {
        g_list_free(protocol_handlers);
        protocol_handlers = NULL;
    }
}