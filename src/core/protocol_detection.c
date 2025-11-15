#include "protocol_detection.h"
#include <string.h>

// Custom matchers
static gboolean match_socks5_greeting(const guint8 *data, gsize len, gpointer user_data) {
    (void)user_data;
    if (len < 2) return FALSE;
    // SOCKS5: version=5, nmethods should be reasonable
    return data[0] == 0x05 && data[1] > 0 && data[1] <= 16;
}

static gboolean match_tls_handshake(const guint8 *data, gsize len, gpointer user_data) {
    (void)user_data;
    if (len < 5) return FALSE;
    // TLS handshake: type=0x16, version 3.x
    return data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04;
}

static gboolean match_websocket_headers(const guint8 *data, gsize len, gpointer user_data) {
    (void)user_data;
    gchar *str = g_strndup((const gchar*)data, len);
    gchar *lower = g_ascii_strdown(str, -1);
    
    gboolean has_upgrade = strstr(lower, "upgrade: websocket") != NULL;
    gboolean has_connection = strstr(lower, "connection:") && strstr(lower, "upgrade");
    gboolean has_key = strstr(lower, "sec-websocket-key:") != NULL;
    gboolean has_version = strstr(lower, "sec-websocket-version:") != NULL;
    
    g_free(str);
    g_free(lower);
    
    return has_upgrade && has_connection && has_key && has_version;
}

static gboolean match_imap_command(const guint8 *data, gsize len, gpointer user_data) {
    (void)user_data;
    if (len < 2) return FALSE;
    
    // IMAP commands start with tag (alphanumeric) followed by space
    if (!g_ascii_isalnum(data[0])) return FALSE;
    
    // Look for space after tag
    for (gsize i = 1; i < len && i < 20; i++) {  // Tags shouldn't be too long
        if (data[i] == ' ') return TRUE;
        if (!g_ascii_isalnum(data[i])) return FALSE;
    }
    
    return FALSE;
}

// Protocol Rules Definitions
static ProtocolRule http_rules[] = {
    {
        .type = MATCH_OR,
        .data.compound = {
            .rules = (ProtocolRule[]){
                {.type = MATCH_PREFIX, .data.contains = {.string = "GET ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "POST ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "PUT ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "DELETE ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "HEAD ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "OPTIONS ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "CONNECT ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "PATCH ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "TRACE ", .case_insensitive = FALSE}},
            },
            .count = 9
        }
    }
};

static ProtocolRule websocket_rules[] = {
    {
        .type = MATCH_AND,
        .data.compound = {
            .rules = (ProtocolRule[]){
                {.type = MATCH_PREFIX, .data.contains = {.string = "GET ", .case_insensitive = FALSE}},
                {.type = MATCH_CUSTOM, .data.custom = {.matcher = match_websocket_headers, .user_data = NULL}}
            },
            .count = 2
        }
    }
};

static ProtocolRule socks4_rules[] = {
    {.type = MATCH_EXACT, .data.exact = {.bytes = (const guint8*)"\x04", .length = 1, .offset = 0}}
};

static ProtocolRule socks5_rules[] = {
    {.type = MATCH_CUSTOM, .data.custom = {.matcher = match_socks5_greeting, .user_data = NULL}}
};

static ProtocolRule tls_rules[] = {
    {.type = MATCH_CUSTOM, .data.custom = {.matcher = match_tls_handshake, .user_data = NULL}}
};

static ProtocolRule smtp_rules[] = {
    {
        .type = MATCH_OR,
        .data.compound = {
            .rules = (ProtocolRule[]){
                {.type = MATCH_PREFIX, .data.contains = {.string = "HELO ", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "EHLO ", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "MAIL FROM:", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "RCPT TO:", .case_insensitive = TRUE}},
            },
            .count = 4
        }
    }
};

static ProtocolRule imap_rules[] = {
    {.type = MATCH_CUSTOM, .data.custom = {.matcher = match_imap_command, .user_data = NULL}}
};

static ProtocolRule ftp_rules[] = {
    {
        .type = MATCH_OR,
        .data.compound = {
            .rules = (ProtocolRule[]){
                {.type = MATCH_PREFIX, .data.contains = {.string = "USER ", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "PASS ", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "LIST", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "PASV", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "RETR ", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "STOR ", .case_insensitive = TRUE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "220 ", .case_insensitive = FALSE}},
                {.type = MATCH_PREFIX, .data.contains = {.string = "331 ", .case_insensitive = FALSE}},
            },
            .count = 8
        }
    }
};

static ProtocolRule api_rules[] = {
    {
        .type = MATCH_AND,
        .data.compound = {
            .rules = (ProtocolRule[]){
                {.type = MATCH_PREFIX, .data.contains = {.string = "GET /api/", .case_insensitive = FALSE}},
            },
            .count = 1
        }
    }
};

// Global Protocol Table
ProtocolDefinition protocol_table[] = {
    // API has highest priority for /api/ paths
    {
        .name = "API",
        .protocol_id = DEADLIGHT_PROTOCOL_API,
        .priority = 100,
        .rules = api_rules,
        .rule_count = 1,
        .verify = NULL
    },
    
    // WebSocket has higher priority than HTTP
    {
        .name = "WebSocket",
        .protocol_id = DEADLIGHT_PROTOCOL_WEBSOCKET,
        .priority = 50,
        .rules = websocket_rules,
        .rule_count = 1,
        .verify = NULL
    },
    
    // TLS/IMAPS before other text protocols
    {
        .name = "TLS/IMAPS",
        .protocol_id = DEADLIGHT_PROTOCOL_IMAPS,
        .priority = 40,
        .rules = tls_rules,
        .rule_count = 1,
        .verify = NULL
    },
    
    // SOCKS before HTTP
    {
        .name = "SOCKS5",
        .protocol_id = DEADLIGHT_PROTOCOL_SOCKS,
        .priority = 35,
        .rules = socks5_rules,
        .rule_count = 1,
        .verify = NULL
    },
    
    {
        .name = "SOCKS4",
        .protocol_id = DEADLIGHT_PROTOCOL_SOCKS,
        .priority = 34,
        .rules = socks4_rules,
        .rule_count = 1,
        .verify = NULL
    },
    {
        .name = "FTP",
        .protocol_id = DEADLIGHT_PROTOCOL_FTP,
        .priority = 25,
        .rules = ftp_rules,
        .rule_count = 1,
        .verify = NULL
    },
    
    // Text protocols
    {
        .name = "HTTP",
        .protocol_id = DEADLIGHT_PROTOCOL_HTTP,
        .priority = 20,
        .rules = http_rules,
        .rule_count = 1,
        .verify = NULL
    },
    
    {
        .name = "SMTP",
        .protocol_id = DEADLIGHT_PROTOCOL_SMTP,
        .priority = 15,
        .rules = smtp_rules,
        .rule_count = 1,
        .verify = NULL
    },
    
    {
        .name = "IMAP",
        .protocol_id = DEADLIGHT_PROTOCOL_IMAP,
        .priority = 10,
        .rules = imap_rules,
        .rule_count = 1,
        .verify = NULL
    }
};

gint protocol_table_size = G_N_ELEMENTS(protocol_table);

// Rule matching implementation
gboolean rule_matches(const ProtocolRule *rule, const guint8 *data, gsize len) {
    if (!rule || !data) return FALSE;
    
    switch (rule->type) {
        case MATCH_EXACT:
            if (len < rule->data.exact.offset + rule->data.exact.length) return FALSE;
            return memcmp(data + rule->data.exact.offset, 
                         rule->data.exact.bytes, 
                         rule->data.exact.length) == 0;
            
        case MATCH_PREFIX:
            if (!rule->data.contains.string) return FALSE;
            gsize slen = strlen(rule->data.contains.string);
            if (len < slen) return FALSE;
            
            if (rule->data.contains.case_insensitive) {
                gchar *data_str = g_strndup((const gchar*)data, slen);
                gchar *data_lower = g_ascii_strdown(data_str, -1);
                gchar *pattern_lower = g_ascii_strdown(rule->data.contains.string, -1);
                gboolean match = strcmp(data_lower, pattern_lower) == 0;
                g_free(data_str);
                g_free(data_lower);
                g_free(pattern_lower);
                return match;
            } else {
                return memcmp(data, rule->data.contains.string, slen) == 0;
            }
            
        case MATCH_CONTAINS:
            if (!rule->data.contains.string) return FALSE;
            gchar *haystack = g_strndup((const gchar*)data, len);
            gboolean found;
            
            if (rule->data.contains.case_insensitive) {
                gchar *haystack_lower = g_ascii_strdown(haystack, -1);
                gchar *needle_lower = g_ascii_strdown(rule->data.contains.string, -1);
                found = strstr(haystack_lower, needle_lower) != NULL;
                g_free(haystack_lower);
                g_free(needle_lower);
            } else {
                found = strstr(haystack, rule->data.contains.string) != NULL;
            }
            
            g_free(haystack);
            return found;
            
        case MATCH_REGEX:
            // TODO: Implement regex matching
            return FALSE;
            
        case MATCH_CUSTOM:
            if (!rule->data.custom.matcher) return FALSE;
            return rule->data.custom.matcher(data, len, rule->data.custom.user_data);
            
        case MATCH_AND:
            for (gint i = 0; i < rule->data.compound.count; i++) {
                if (!rule_matches(&rule->data.compound.rules[i], data, len)) {
                    return FALSE;
                }
            }
            return TRUE;
            
        case MATCH_OR:
            for (gint i = 0; i < rule->data.compound.count; i++) {
                if (rule_matches(&rule->data.compound.rules[i], data, len)) {
                    return TRUE;
                }
            }
            return FALSE;
            
        default:
            return FALSE;
    }
}

// Main detection function
const ProtocolDefinition* detect_protocol(const guint8 *data, gsize len) {
    if (!data || len == 0) return NULL;
    
    const ProtocolDefinition *best_match = NULL;
    gint best_priority = -1;
    
    for (gint i = 0; i < protocol_table_size; i++) {
        ProtocolDefinition *proto = &protocol_table[i];
        
        // Check all rules for this protocol
        gboolean matches = TRUE;
        for (gint j = 0; j < proto->rule_count; j++) {
            if (!rule_matches(&proto->rules[j], data, len)) {
                matches = FALSE;
                break;
            }
        }
        
        // If all rules match and priority is higher
        if (matches && proto->priority > best_priority) {
            // Optional: Run verification function
            if (proto->verify && !proto->verify(data, len)) {
                continue;
            }
            
            best_match = proto;
            best_priority = proto->priority;
        }
    }
    
    return best_match;
}

void protocol_detection_init(void) {
    // Initialize any regex patterns or other resources
    g_info("Protocol detection system initialized with %d protocols", protocol_table_size);
}

void protocol_detection_cleanup(void) {
    // Cleanup regex patterns or other allocated resources
}
