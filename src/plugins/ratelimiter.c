// File: src/plugins/ratelimiter.c

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include "deadlight.h"
#include "ratelimiter.h"

// Periodic cleanup of old entries (run every 5 minutes)
static gboolean cleanup_old_entries(gpointer user_data) {
    RateLimiterData *data = (RateLimiterData *)user_data;
    gint64 now = g_get_monotonic_time() / G_USEC_PER_SEC;
    gint64 cutoff = now - 300;  // Remove entries older than 5 minutes
    
    g_mutex_lock(&data->mutex);
    
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, data->ip_limits);
    
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        RateLimitEntry *entry = (RateLimitEntry *)value;
        if (entry->timestamp < cutoff) {
            g_hash_table_iter_remove(&iter);
        }
    }
    
    g_mutex_unlock(&data->mutex);
    
    return G_SOURCE_CONTINUE;
}

static gboolean ratelimiter_init(DeadlightContext *context) {
    g_info("Initializing RateLimiter plugin...");
    
    RateLimiterData *data = g_new0(RateLimiterData, 1);
    g_mutex_init(&data->mutex);
    
    data->enabled = deadlight_config_get_bool(context, "ratelimiter", "enabled", TRUE);
    
    // Create hash tables
    data->ip_limits = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    data->path_limits = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Load configuration
    data->requests_per_minute = deadlight_config_get_int(context, "ratelimiter", 
                                                        "requests_per_minute", 60);
    data->auth_requests_per_minute = deadlight_config_get_int(context, "ratelimiter", 
                                                            "auth_requests_per_minute", 10);
    data->burst_size = deadlight_config_get_int(context, "ratelimiter", 
                                              "burst_size", 10);
    
    // Initialize auth_patterns (add this)
    data->auth_patterns = NULL;  // Or load from config if needed
    
    // Schedule periodic cleanup (add this to actually use the cleanup function)
    data->cleanup_source_id = g_timeout_add_seconds(300, cleanup_old_entries, data);
    
    if (!context->plugins_data) {
        context->plugins_data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    }
    g_hash_table_insert(context->plugins_data, g_strdup("ratelimiter"), data);
    
    g_info("RateLimiter initialized: %u req/min (auth: %u req/min)", 
           data->requests_per_minute, data->auth_requests_per_minute);
    
    return TRUE;
}

static gboolean should_rate_limit(RateLimiterData *data, const gchar *key, 
                                 guint limit, guint window_seconds) {
    g_mutex_lock(&data->mutex);
    
    gint64 now = g_get_monotonic_time() / G_USEC_PER_SEC;
    RateLimitEntry *entry = g_hash_table_lookup(data->ip_limits, key);
    
    if (!entry) {
        // First request from this IP
        entry = g_new0(RateLimitEntry, 1);
        entry->timestamp = now;
        entry->count = 1;
        g_hash_table_insert(data->ip_limits, g_strdup(key), entry);
        g_mutex_unlock(&data->mutex);
        return FALSE;
    }
    
    // Check if we're in a new time window
    if (now - entry->timestamp >= window_seconds) {
        // Reset the window
        entry->timestamp = now;
        entry->count = 1;
        g_mutex_unlock(&data->mutex);
        return FALSE;
    }
    
    // Check if limit exceeded
    if (entry->count >= limit) {
        g_mutex_unlock(&data->mutex);
        return TRUE;  // Rate limit hit!
    }
    
    // Increment counter
    entry->count++;
    g_mutex_unlock(&data->mutex);
    return FALSE;
}

static gboolean on_request_headers(DeadlightRequest *request) {
    if (!request || !request->connection || !request->connection->context) {
        return TRUE;
    }
    
    RateLimiterData *data = g_hash_table_lookup(
        request->connection->context->plugins_data, "ratelimiter");
    if (!data) return TRUE;
    
    // Get client IP
    const gchar *client_ip = request->connection->client_address;
    if (!client_ip) return TRUE;
    
    // Check if this is an auth endpoint (customize these patterns)
    gboolean is_auth_endpoint = FALSE;
    if (request->uri) {
        if (strstr(request->uri, "/auth/") ||
            strstr(request->uri, "/login") ||
            strstr(request->uri, "/signin") ||
            strstr(request->uri, "/api/auth") ||
            strstr(request->uri, "/token")) {
            is_auth_endpoint = TRUE;
        }
    }
    
    // Determine rate limit
    guint limit = is_auth_endpoint ? data->auth_requests_per_minute : 
                                    data->requests_per_minute;
    
    // Create rate limit key (IP + optional path for auth endpoints)
    gchar *key;
    if (is_auth_endpoint && request->uri) {
        key = g_strdup_printf("%s:%s", client_ip, request->uri);
    } else {
        key = g_strdup(client_ip);
    }
    
    // Check rate limit
    if (should_rate_limit(data, key, limit, 60)) {
        g_warning("Rate limit exceeded for %s (endpoint: %s)", 
                  client_ip, request->uri ? request->uri : "unknown");
        
        data->total_limited++;
        
        // Send 429 Too Many Requests
        const gchar *response = 
            "HTTP/1.1 429 Too Many Requests\r\n"
            "Content-Type: text/plain\r\n"
            "Retry-After: 60\r\n"
            "X-RateLimit-Limit: %u\r\n"
            "X-RateLimit-Remaining: 0\r\n"
            "X-RateLimit-Reset: %lld\r\n"
            "Content-Length: 29\r\n"
            "\r\n"
            "Rate limit exceeded. Try again later.";
        
        gchar *formatted_response = g_strdup_printf(response, limit, 
                                                   g_get_monotonic_time() / G_USEC_PER_SEC + 60);
        
        GOutputStream *output = g_io_stream_get_output_stream(
            G_IO_STREAM(request->connection->client_connection));
        g_output_stream_write(output, formatted_response, strlen(formatted_response), 
                            NULL, NULL);
        
        g_free(formatted_response);
        g_free(key);
        
        return FALSE;  // Block request
    }
    
    g_free(key);
    data->total_passed++;
    return TRUE;  // Allow request
}

static void ratelimiter_cleanup(DeadlightContext *context) {
    RateLimiterData *data = g_hash_table_lookup(context->plugins_data, "ratelimiter");
    if (!data) return;
    
    g_info("RateLimiter stats: %lu limited, %lu passed", 
           data->total_limited, data->total_passed);
    
    // Remove the cleanup timer (add this)
    if (data->cleanup_source_id) {
        g_source_remove(data->cleanup_source_id);
    }
    
    // Free auth_patterns if allocated (add this)
    if (data->auth_patterns) {
        g_strfreev(data->auth_patterns);
    }
    
    g_hash_table_destroy(data->ip_limits);
    g_hash_table_destroy(data->path_limits);
    g_mutex_clear(&data->mutex);
    g_free(data);
}

// Plugin definition
static DeadlightPlugin ratelimiter_plugin = {
    .name = "RateLimiter",
    .version = "1.0.0",
    .description = "Rate limiting for API endpoints",
    .author = "Deadlight Team",
    .init = ratelimiter_init,
    .cleanup = ratelimiter_cleanup,
    .on_request_headers = on_request_headers,
    .on_response_headers = NULL,
    .on_response_body = NULL,
    .on_connection_accept = NULL,
    .on_protocol_detect = NULL,
    .on_connection_close = NULL,
    .on_config_change = NULL,
    .private_data = NULL,
    .ref_count = 1
};

G_MODULE_EXPORT gboolean deadlight_plugin_get_info(DeadlightPlugin **plugin) {
    *plugin = &ratelimiter_plugin;
    return TRUE;
}

gboolean deadlight_ratelimiter_init(DeadlightContext *context) {
    return ratelimiter_init(context);
}

void deadlight_ratelimiter_cleanup(DeadlightContext *context) {
    ratelimiter_cleanup(context);
}

gboolean deadlight_ratelimiter_check_request(DeadlightContext *context,
                                            const gchar *client_ip,
                                            const gchar *uri) {
    if (!context || !context->plugins_data) return FALSE;
    
    RateLimiterData *data = g_hash_table_lookup(context->plugins_data, "ratelimiter");
    if (!data || !data->enabled) return FALSE;
    
    gboolean is_auth = deadlight_ratelimiter_is_auth_endpoint(data, uri);
    guint limit = is_auth ? data->auth_requests_per_minute : data->requests_per_minute;
    
    gchar *key = is_auth && uri ? g_strdup_printf("%s:%s", client_ip, uri) : g_strdup(client_ip);
    gboolean should_limit = should_rate_limit(data, key, limit, 60);
    g_free(key);
    
    return should_limit;
}

void deadlight_ratelimiter_get_stats(DeadlightContext *context,
                                    guint64 *limited,
                                    guint64 *passed) {
    if (!context || !context->plugins_data) return;
    
    RateLimiterData *data = g_hash_table_lookup(context->plugins_data, "ratelimiter");
    if (!data) return;
    
    if (limited) *limited = data->total_limited;
    if (passed) *passed = data->total_passed;
}

gboolean deadlight_ratelimiter_is_auth_endpoint(RateLimiterData *data,
                                               const gchar *uri) {
    if (!uri) return FALSE;
    
    // Check against configured patterns
    if (data->auth_patterns) {
        for (int i = 0; data->auth_patterns[i]; i++) {
            if (strstr(uri, data->auth_patterns[i])) {
                return TRUE;
            }
        }
    }
    
    // Default patterns
    return (strstr(uri, "/auth/") ||
            strstr(uri, "/login") ||
            strstr(uri, "/signin") ||
            strstr(uri, "/api/auth") ||
            strstr(uri, "/token"));
}