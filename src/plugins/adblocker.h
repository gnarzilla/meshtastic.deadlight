// src/plugins/adblocker.h
#ifndef DEADLIGHT_ADBLOCKER_H
#define DEADLIGHT_ADBLOCKER_H

#include <glib.h>
#include "deadlight.h"

typedef struct {
    GHashTable *blocked_domains;
    GHashTable *blocked_keywords;
    GRegex **blocked_patterns;
    gint pattern_count;
    
    guint64 requests_blocked;
    guint64 requests_allowed;
    guint64 bytes_saved;
    
    gchar **blocklist_urls;
    gchar *local_blocklist_path;
    
    GDateTime *last_update;
    guint update_source_id;
    
    gboolean enabled;  // Add this field
} AdBlockerData;

// Direct integration functions
gboolean deadlight_adblocker_init(DeadlightContext *context);
void deadlight_adblocker_cleanup(DeadlightContext *context);
gboolean is_blocked_domain(AdBlockerData *data, const gchar *domain);
gboolean is_blocked_url(AdBlockerData *data, const gchar *url);

#endif // DEADLIGHT_ADBLOCKER_H
