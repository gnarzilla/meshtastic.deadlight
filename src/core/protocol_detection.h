#ifndef PROTOCOL_DETECTION_H
#define PROTOCOL_DETECTION_H

#include <glib.h>
#include "deadlight.h"

#define MAX_RULES 10
#define MAX_SIGNATURES 20

typedef enum {
    MATCH_EXACT,      // Exact bytes at offset
    MATCH_PREFIX,     // Prefix match (at start of data)
    MATCH_CONTAINS,   // Contains substring anywhere
    MATCH_REGEX,      // Regex pattern matching
    MATCH_CUSTOM,     // Custom function
    MATCH_AND,        // All sub-rules must match
    MATCH_OR          // Any sub-rule must match
} MatchType;

typedef struct _ProtocolRule ProtocolRule;

struct _ProtocolRule {
    MatchType type;
    union {
        struct {
            const guint8 *bytes;
            gsize length;
            gsize offset;
        } exact;
        
        struct {
            const gchar *string;
            gboolean case_insensitive;
        } contains;
        
        struct {
            GRegex *regex;
            const gchar *pattern;  // For initialization
        } regex;
        
        struct {
            gboolean (*matcher)(const guint8 *data, gsize len, gpointer user_data);
            gpointer user_data;
        } custom;
        
        struct {
            ProtocolRule *rules;
            gint count;
        } compound;  // For AND/OR
    } data;
};

typedef struct {
    const gchar *name;
    DeadlightProtocol protocol_id;
    gint priority;  // Higher number = higher priority
    ProtocolRule *rules;
    gint rule_count;
    
    // Optional: More sophisticated detection after initial match
    gboolean (*verify)(const guint8 *data, gsize len);
} ProtocolDefinition;

// Global protocol table
extern ProtocolDefinition protocol_table[];
extern gint protocol_table_size;

// Functions
void protocol_detection_init(void);
void protocol_detection_cleanup(void);
const ProtocolDefinition* detect_protocol(const guint8 *data, gsize len);
gboolean rule_matches(const ProtocolRule *rule, const guint8 *data, gsize len);

#endif // PROTOCOL_DETECTION_H
