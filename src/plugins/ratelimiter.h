// src/plugins/ratelimiter.h
#ifndef DEADLIGHT_RATELIMITER_H
#define DEADLIGHT_RATELIMITER_H

#include <glib.h>
#include "deadlight.h"

typedef struct {
    gint64 timestamp;      // When this window started
    guint count;          // Requests in current window
} RateLimitEntry;

typedef struct {
    GHashTable *ip_limits;      // Per-IP rate limits
    GHashTable *path_limits;    // Per-path rate limits
    GMutex mutex;               // Thread safety
    
    // Configuration
    guint requests_per_minute;  // Default rate limit
    guint auth_requests_per_minute; // Stricter limit for auth endpoints
    guint burst_size;          // Allow burst up to this size
    
    // Auth endpoint patterns
    gchar **auth_patterns;     // Patterns to identify auth endpoints
    
    // Stats
    guint64 total_limited;
    guint64 total_passed;
    
    // Cleanup timer
    guint cleanup_source_id;
    
    gboolean enabled;
} RateLimiterData;

// Direct integration functions
gboolean deadlight_ratelimiter_init(DeadlightContext *context);
void deadlight_ratelimiter_cleanup(DeadlightContext *context);

// Check if a request should be rate limited
gboolean deadlight_ratelimiter_check_request(DeadlightContext *context,
                                            const gchar *client_ip,
                                            const gchar *uri);

// Get current stats
void deadlight_ratelimiter_get_stats(DeadlightContext *context,
                                    guint64 *limited,
                                    guint64 *passed);

// Manual rate limit check (for custom scenarios)
gboolean deadlight_ratelimiter_check_limit(DeadlightContext *context,
                                          const gchar *key,
                                          guint limit,
                                          guint window_seconds);

// Add IP to whitelist
void deadlight_ratelimiter_whitelist_ip(DeadlightContext *context,
                                       const gchar *ip);

// Check if endpoint is auth-related
gboolean deadlight_ratelimiter_is_auth_endpoint(RateLimiterData *data,
                                               const gchar *uri);

#endif // DEADLIGHT_RATELIMITER_H
