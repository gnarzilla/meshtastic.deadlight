/**
 * Deadlight Proxy v4.0 - Ad Blocker Plugin
 * 
 * DNS-based and content-based ad blocking
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include "deadlight.h"

typedef struct {
    GHashTable *blocked_domains;      // Exact domain matches
    GHashTable *blocked_keywords;     // Keyword blocking
    GRegex **blocked_patterns;        // Regex patterns for URLs
    gint pattern_count;
    gboolean enabled;
    
    // Statistics
    guint64 requests_blocked;
    guint64 requests_allowed;
    guint64 bytes_saved;
    
    // Blocklist sources
    gchar **blocklist_urls;
    gchar *local_blocklist_path;
    
    // Update tracking
    GDateTime *last_update;
    guint update_source_id;
} AdBlockerData;

// Forward declarations
static gboolean adblocker_init(DeadlightContext *context);
static void adblocker_cleanup(DeadlightContext *context);
static gboolean on_request_headers(DeadlightRequest *request);
static gboolean on_response_headers(DeadlightResponse *response);
static gboolean on_response_body(DeadlightResponse *response);

// Blocklist management
static gboolean load_blocklists(AdBlockerData *data, DeadlightContext *context);
static gboolean update_blocklists(gpointer user_data);
static gboolean is_blocked_domain(AdBlockerData *data, const gchar *domain);
static gboolean is_blocked_url(AdBlockerData *data, const gchar *url);

/**
 * Create the ad blocker plugin
 */
DeadlightPlugin *deadlight_plugin_adblocker_new(void) {
    DeadlightPlugin *plugin = g_new0(DeadlightPlugin, 1);
    
    plugin->name = g_strdup("AdBlocker");
    plugin->version = g_strdup("1.0.0");
    plugin->description = g_strdup("Blocks ads at DNS and content level");
    plugin->author = g_strdup("Deadlight Team");
    
    plugin->init = adblocker_init;
    plugin->cleanup = adblocker_cleanup;
    plugin->on_request_headers = on_request_headers;
    plugin->on_response_headers = on_response_headers;
    plugin->on_response_body = on_response_body;
    
    return plugin;
}

/**
 * Initialize the ad blocker
 */
static gboolean adblocker_init(DeadlightContext *context) {
    g_info("Initializing AdBlocker plugin...");
    
    AdBlockerData *data = g_new0(AdBlockerData, 1);

     // Initialize the enabled field
    data->enabled = deadlight_config_get_bool(context, "adblocker", "enabled", TRUE);
    
    // Create hash tables
    data->blocked_domains = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    data->blocked_keywords = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    
    // Get configuration
    data->local_blocklist_path = deadlight_config_get_string(context, "adblocker", 
                                                            "blocklist_path", 
                                                            "/etc/deadlight/blocklist.txt");
    
    // Default blocklist URLs (like Pi-hole's default lists)
    const gchar *default_lists[] = {
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://someonewhocares.org/hosts/zero/hosts",
        "https://raw.githubusercontent.com/AdguardTeam/AdguardSDNSFilter/master/Filters/filter.txt",
        "https://easylist.to/easylist/easylist.txt",
        NULL
    };
    
    // Load blocklist URLs from config or use defaults
    GList *list_urls = NULL;
    for (int i = 0; default_lists[i]; i++) {
        gchar *key = g_strdup_printf("blocklist_url_%d", i);
        const gchar *url = deadlight_config_get_string(context, "adblocker", key, default_lists[i]);
        if (url && strlen(url) > 0) {
            list_urls = g_list_append(list_urls, g_strdup(url));
        }
        g_free(key);
    }
    
    // Convert to array
    guint list_count = g_list_length(list_urls);
    data->blocklist_urls = g_new0(gchar*, list_count + 1);
    GList *l = list_urls;
    for (int i = 0; l; l = l->next, i++) {
        data->blocklist_urls[i] = (gchar *)l->data;
    }
    g_list_free(list_urls);
    
    // Load blocklists
    if (!load_blocklists(data, context)) {
        g_warning("Failed to load blocklists");
    }
    
    // Schedule periodic updates (every 24 hours)
    data->update_source_id = g_timeout_add_seconds(86400, update_blocklists, data);
    
    // Store in context (will need to add a plugins_data hashtable to context)
    if (!context->plugins_data) {
        context->plugins_data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    }
    g_hash_table_insert(context->plugins_data, g_strdup("adblocker"), data);
    
    g_info("AdBlocker initialized with %d blocked domains", 
           g_hash_table_size(data->blocked_domains));
    
    return TRUE;
}

static gboolean on_response_headers(DeadlightResponse *response) {
    (void)response;
    // For now, just pass through - we mainly block at request stage
    return TRUE;
}

/**
 * Load blocklists from files and URLs
 */
static gboolean load_blocklists(AdBlockerData *data, DeadlightContext *context) {
    (void)context;  // Suppress unused parameter warning
    gint total_entries = 0;
    
    // First, load local blocklist
    if (g_file_test(data->local_blocklist_path, G_FILE_TEST_EXISTS)) {
        g_info("Loading local blocklist from %s", data->local_blocklist_path);
        
        gchar *content = NULL;
        gsize length;
        GError *error = NULL;
        
        if (g_file_get_contents(data->local_blocklist_path, &content, &length, &error)) {
            gchar **lines = g_strsplit(content, "\n", -1);
            
            for (int i = 0; lines[i]; i++) {
                gchar *line = g_strstrip(lines[i]);
                
                // Skip comments and empty lines
                if (line[0] == '#' || line[0] == '\0') continue;
                
                // Parse hosts file format (IP domain)
                gchar **parts = g_strsplit(line, " ", -1);
                if (parts[0] && parts[1]) {
                    // Check if it's a blocked entry (0.0.0.0 or 127.0.0.1)
                    if (strcmp(parts[0], "0.0.0.0") == 0 || 
                        strcmp(parts[0], "127.0.0.1") == 0) {
                        g_hash_table_insert(data->blocked_domains, 
                                          g_strdup(parts[1]), 
                                          GINT_TO_POINTER(1));
                        total_entries++;
                    }
                } else if (parts[0] && strchr(parts[0], '.')) {
                    // Plain domain format
                    g_hash_table_insert(data->blocked_domains, 
                                      g_strdup(parts[0]), 
                                      GINT_TO_POINTER(1));
                    total_entries++;
                }
                g_strfreev(parts);
            }
            
            g_strfreev(lines);
            g_free(content);
        } else {
            g_warning("Failed to load local blocklist: %s", error->message);
            g_error_free(error);
        }
    }
    
    // Add some common ad domains if we don't have many entries
    if (total_entries < 100) {
        const gchar *common_ad_domains[] = {
            "doubleclick.net", "googleadservices.com", "googlesyndication.com",
            "google-analytics.com", "googletagmanager.com", "googletagservices.com",
            "facebook.com/tr", "amazon-adsystem.com", "adsystem.com",
            "adsrvr.org", "adzerk.net", "outbrain.com", "taboola.com",
            "scorecardresearch.com", "quantserve.com", "addthis.com",
            "sharethis.com", "twitter.com/i/adsct", "analytics.twitter.com",
            "ads-twitter.com", "static.ads-twitter.com", NULL
        };
        
        for (int i = 0; common_ad_domains[i]; i++) {
            g_hash_table_insert(data->blocked_domains, 
                              g_strdup(common_ad_domains[i]), 
                              GINT_TO_POINTER(1));
            total_entries++;
        }
    }
    
    // TODO: Download and parse remote blocklists
    // For now, we'll use the local list and hardcoded domains
    
    data->last_update = g_date_time_new_now_local();
    
    return TRUE;
}

/**
 * Check if a domain is blocked
 */
static gboolean is_blocked_domain(AdBlockerData *data, const gchar *domain) {
    if (!domain) return FALSE;
    
    // Direct lookup
    if (g_hash_table_contains(data->blocked_domains, domain)) {
        return TRUE;
    }
    
    // Check parent domains (e.g., block "ads.example.com" if "example.com" is blocked)
    gchar *dot = strchr(domain, '.');
    while (dot) {
        if (g_hash_table_contains(data->blocked_domains, dot + 1)) {
            return TRUE;
        }
        dot = strchr(dot + 1, '.');
    }
    
    // Check if domain contains blocked keywords
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, data->blocked_keywords);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        if (strstr(domain, (gchar *)key)) {
            return TRUE;
        }
    }
    
    return FALSE;
}

/**
 * Handle request headers - main blocking logic
 */
static gboolean on_request_headers(DeadlightRequest *request) {
    if (!request || !request->connection || !request->connection->context) {
        return TRUE;
    }
    
    AdBlockerData *data = g_hash_table_lookup(
        request->connection->context->plugins_data, "adblocker");
    if (!data || !data->enabled) return TRUE;
    
    const gchar *host = request->host;  // Single declaration at the top
    gchar *extracted_host = NULL;       // For CONNECT hostname extraction
    
    // For CONNECT requests, extract hostname from the request
    if (request->method && g_strcmp0(request->method, "CONNECT") == 0) {
        if (request->uri) {
            // Extract hostname from "hostname:port"
            gchar *colon = strrchr(request->uri, ':');
            if (colon) {
                extracted_host = g_strndup(request->uri, colon - request->uri);
                host = extracted_host;  // Use extracted host for checking
            } else {
                host = request->uri;   // No port, use as-is
            }
        }
        
        if (host && is_blocked_domain(data, host)) {
            g_info("AdBlocker: Blocking CONNECT to %s", request->uri);
            data->requests_blocked++;
            
            const gchar *blocked_response = 
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Length: 0\r\n"
                "X-Blocked-By: Deadlight-AdBlocker\r\n"
                "\r\n";
            
            GOutputStream *output = g_io_stream_get_output_stream(
                G_IO_STREAM(request->connection->client_connection));
            g_output_stream_write(output, blocked_response, 
                                strlen(blocked_response), NULL, NULL);
            
            if (extracted_host) g_free(extracted_host);
            return FALSE; // Block it
        }
        
        if (extracted_host) g_free(extracted_host);
        data->requests_allowed++;
        return TRUE;
    }
    
    // Handle regular HTTP requests
    if (!host) {
        host = g_hash_table_lookup(request->headers, "Host");
    }
    
    if (host && is_blocked_domain(data, host)) {
        g_info("AdBlocker: Blocking HTTP request to %s", host);
        
        data->requests_blocked++;
        
        const gchar *blocked_response = 
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "X-Blocked-By: Deadlight-AdBlocker\r\n"
            "\r\n";
        
        GOutputStream *output = g_io_stream_get_output_stream(
            G_IO_STREAM(request->connection->client_connection));
        g_output_stream_write(output, blocked_response, strlen(blocked_response), 
                            NULL, NULL);
        
        return FALSE;
    }
    
    // Check URL patterns for non-HTTPS
    if (request->uri && is_blocked_url(data, request->uri)) {
        g_info("AdBlocker: Blocking URL pattern %s", request->uri);
        
        request->blocked = TRUE;
        request->block_reason = g_strdup("URL pattern blocked by AdBlocker");
        
        data->requests_blocked++;
        
        return FALSE;
    }
    
    data->requests_allowed++;
    return TRUE;
}

/**
 * Handle response body
 */
static gboolean on_response_body(DeadlightResponse *response) {
    if (!response || !response->connection || !response->connection->context) {
        return TRUE;
    }
    
    AdBlockerData *data = g_hash_table_lookup(
        response->connection->context->plugins_data, "adblocker");
    if (!data) return TRUE;
    
    // For HTML content, we could do content filtering here
    // But for performance, we'll skip body inspection for now
    
    return TRUE;
}

/**
 * Update blocklists periodically
 */
static gboolean update_blocklists(gpointer user_data) {
    AdBlockerData *data = (AdBlockerData *)user_data;
    
    g_info("AdBlocker: Updating blocklists...");
    
    // TODO: Download and update blocklists from URLs
    // For now, just reload the local file
    
    data->last_update = g_date_time_new_now_local();
    
    return G_SOURCE_CONTINUE; // Keep the timer running
}

/**
 * Plugin cleanup
 */
static void adblocker_cleanup(DeadlightContext *context) {
    AdBlockerData *data = g_hash_table_lookup(context->plugins_data, "adblocker");
    if (!data) return;
    
    g_info("AdBlocker statistics: %lu blocked, %lu allowed, %lu bytes saved",
           data->requests_blocked, data->requests_allowed, data->bytes_saved);
    
    if (data->update_source_id) {
        g_source_remove(data->update_source_id);
    }
    
    g_hash_table_destroy(data->blocked_domains);
    g_hash_table_destroy(data->blocked_keywords);
    
    if (data->blocked_patterns) {
        for (gint i = 0; i < data->pattern_count; i++) {
            if (data->blocked_patterns[i]) {
                g_regex_unref(data->blocked_patterns[i]);
            }
        }
        g_free(data->blocked_patterns);
    }
    
    g_strfreev(data->blocklist_urls);
    g_free(data->local_blocklist_path);
    
    if (data->last_update) {
        g_date_time_unref(data->last_update);
    }
    
    g_free(data);
}

/**
 * Direct integration functions for non-plugin mode
 */

// Check if a host should be blocked (for direct integration)
gboolean deadlight_adblocker_should_block_host(DeadlightContext *context, const gchar *host) {
    if (!context || !context->plugins_data) return FALSE;
    
    AdBlockerData *data = g_hash_table_lookup(context->plugins_data, "adblocker");
    if (!data) return FALSE;
    
    return is_blocked_domain(data, host);
}

// Check if a URL should be blocked (for direct integration)
gboolean deadlight_adblocker_should_block_url(DeadlightContext *context, const gchar *url) {
    if (!context || !context->plugins_data) return FALSE;
    
    AdBlockerData *data = g_hash_table_lookup(context->plugins_data, "adblocker");
    if (!data) return FALSE;
    
    return is_blocked_url(data, url);
}

// Initialize adblocker directly (non-plugin mode)
gboolean deadlight_adblocker_init(DeadlightContext *context) {
    return adblocker_init(context);
}

// Get statistics
void deadlight_adblocker_get_stats(DeadlightContext *context, 
                                  guint64 *blocked, 
                                  guint64 *allowed, 
                                  guint64 *bytes_saved) {
    if (!context || !context->plugins_data) return;
    
    AdBlockerData *data = g_hash_table_lookup(context->plugins_data, "adblocker");
    if (!data) return;
    
    if (blocked) *blocked = data->requests_blocked;
    if (allowed) *allowed = data->requests_allowed;
    if (bytes_saved) *bytes_saved = data->bytes_saved;
}


static gboolean is_blocked_url(AdBlockerData *data, const gchar *url) {
    if (!url) return FALSE;
    
    // Check against regex patterns
    for (gint i = 0; i < data->pattern_count; i++) {
        if (data->blocked_patterns[i] && 
            g_regex_match(data->blocked_patterns[i], url, 0, NULL)) {
            return TRUE;
        }
    }
    
    // Check for common ad URL patterns
    const gchar *ad_patterns[] = {
        "/doubleclick/",
        "/googleads/",
        "/adsense/",
        "/adserver/",
        "/advertisement/",
        "/analytics/",
        "/tracking/",
        "/beacon/",
        "?utm_",
        NULL
    };
    
    for (int i = 0; ad_patterns[i]; i++) {
        if (strstr(url, ad_patterns[i])) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// Plugin definition structure
static DeadlightPlugin adblocker_plugin = {
    .name = "AdBlocker",
    .version = "1.0.0",
    .description = "Blocks ads at DNS and content level",
    .author = "Deadlight Team",
    .init = adblocker_init,
    .cleanup = adblocker_cleanup,
    .on_request_headers = on_request_headers,
    .on_response_headers = on_response_headers,
    .on_response_body = on_response_body,
    .on_connection_accept = NULL,
    .on_protocol_detect = NULL,
    .on_connection_close = NULL,
    .on_config_change = NULL,
    .private_data = NULL,
    .ref_count = 1
};

// CRITICAL: Export function for plugin loader
G_MODULE_EXPORT gboolean deadlight_plugin_get_info(DeadlightPlugin **plugin) {
    *plugin = &adblocker_plugin;
    return TRUE;
}