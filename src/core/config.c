/**
 * Deadlight Proxy v1.0 - Configuration Management
 *
 * GKeyFile-based configuration system with caching, validation,
 * and automatic file monitoring for live reload
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "deadlight.h"

// Forward declarations
static void config_file_changed(GFileMonitor *monitor, GFile *file, GFile *other_file,
                               GFileMonitorEvent event_type, gpointer user_data);
static gboolean validate_config_section(DeadlightConfig *config, const gchar *section, GError **error);
static gboolean create_default_config_file(const gchar *config_path, GError **error);
static void config_cache_clear(DeadlightConfig *config);
static void config_update_context_values(DeadlightContext *context);

// Default configuration values
static const struct {
    const gchar *section;
    const gchar *key;
    const gchar *value;
    const gchar *description;
} default_config[] = {
    // Core settings
    {"core", "port", "8080", "Listen port for proxy connections"},
    {"core", "bind_address", "0.0.0.0", "IP address to bind to"},
    {"core", "max_connections", "500", "Maximum concurrent connections"},
    {"core", "connection_timeout", "30", "Connection timeout in seconds"},
    {"core", "buffer_size", "65536", "Buffer size for data transfer"},
    {"core", "log_level", "info", "Log level: error, warning, info, debug"},
    {"core", "log_file", "", "Log file path (empty for stdout)"},
    {"core", "worker_threads", "4", "Number of worker threads"},
    
    // SSL/TLS settings
    {"ssl", "enabled", "true", "Enable SSL interception"},
    {"ssl", "ca_cert_file", "~/.deadlight/ca/ca.crt", "CA certificate file"},
    {"ssl", "ca_key_file", "~/.deadlight/ca/ca.key", "CA private key file"},
    {"ssl", "cert_cache_dir", "/tmp/deadlight_certs", "Certificate cache directory"},
    {"ssl", "cert_cache_size", "1000", "Maximum cached certificates"},
    {"ssl", "cert_validity_days", "30", "Generated certificate validity period"},
    {"ssl", "cipher_suites", "HIGH:!aNULL:!MD5", "Allowed cipher suites"},
    {"ssl", "protocols", "TLSv1.2,TLSv1.3", "Allowed SSL/TLS protocols"},
    
    // Protocol settings
    {"protocols", "http_enabled", "true", "Enable HTTP support"},
    {"protocols", "https_enabled", "true", "Enable HTTPS support"},
    {"protocols", "socks4_enabled", "true", "Enable SOCKS4 support"},
    {"protocols", "socks5_enabled", "true", "Enable SOCKS5 support"},
    {"protocols", "connect_enabled", "true", "Enable HTTP CONNECT support"},
    {"protocols", "imap_enabled", "true", "Enable IMAP support"},
    {"protocols", "imaps_enabled", "true", "Enable IMAPS support"},
    {"protocols", "smtp_enabled", "true", "Enable SMTP support"},
    {"protocols", "protocol_detection_timeout", "5", "Protocol detection timeout"},
    
    // Network settings
    {"network", "upstream_timeout", "30", "Upstream connection timeout"},
    {"network", "keepalive_timeout", "300", "Keep-alive timeout"},
    {"network", "dns_timeout", "5", "DNS resolution timeout"},
    {"network", "dns_servers", "", "Custom DNS servers (comma-separated)"},
    {"network", "ipv6_enabled", "true", "Enable IPv6 support"},
    {"network", "tcp_nodelay", "true", "Enable TCP_NODELAY"},
    {"network", "tcp_keepalive", "true", "Enable TCP keepalive"},

    // Network/Connection Pool settings
    {"network", "connection_pool_size", "10", "Max connections per upstream host"},
    {"network", "connection_pool_timeout", "300", "Idle connection timeout (seconds)"},
    {"network", "connection_pool_max_total", "500", "Total pool size across all hosts"},
    {"network", "connection_pool_eviction_policy", "lru", "Pool eviction policy: lru, fifo, none"},
    {"network", "connection_pool_health_check_interval", "60", "Connection health check interval (seconds)"},
    {"network", "connection_pool_reuse_ssl", "true", "Reuse SSL connections from pool"},
    
    // Plugin settings
    {"plugins", "enabled", "true", "Enable plugin system"},
    {"plugins", "plugin_dir", "/usr/lib/deadlight/plugins", "Plugin directory"},
    {"plugins", "autoload", "adblocker,logger,stats", "Auto-load plugins"},
    {"plugins", "builtin_enabled", "true", "Enable built-in plugins"},
    
    // Ad blocker plugin
    {"plugin.adblocker", "enabled", "true", "Enable ad blocker"},
    {"plugin.adblocker", "blocklist_url", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "Blocklist URL"},
    {"plugin.adblocker", "blocklist_file", "/var/cache/deadlight/blocklist.txt", "Local blocklist file"},
    {"plugin.adblocker", "update_interval", "86400", "Blocklist update interval (seconds)"},
    {"plugin.adblocker", "custom_rules", "", "Custom blocking rules file"},
    
    // Logger plugin
    {"plugin.logger", "enabled", "true", "Enable request logging"},
    {"plugin.logger", "log_requests", "true", "Log HTTP requests"},
    {"plugin.logger", "log_responses", "false", "Log HTTP responses"},
    {"plugin.logger", "log_format", "combined", "Log format: combined, common, json"},
    {"plugin.logger", "log_file", "/var/log/deadlight/access.log", "Access log file"},
    {"plugin.logger", "max_log_size", "100MB", "Maximum log file size"},
    {"plugin.logger", "log_rotation", "daily", "Log rotation: daily, weekly, size"},
    
    // Stats plugin
    {"plugin.stats", "enabled", "true", "Enable statistics collection"},
    {"plugin.stats", "stats_interval", "60", "Statistics update interval"},
    {"plugin.stats", "history_size", "1440", "Statistics history size (minutes)"},
    {"plugin.stats", "web_interface", "true", "Enable web statistics interface"},
    {"plugin.stats", "web_port", "8081", "Web interface port"},
    
    // Authentication plugin
    {"plugin.auth", "enabled", "false", "Enable authentication"},
    {"plugin.auth", "auth_type", "basic", "Authentication type: basic, digest"},
    {"plugin.auth", "auth_file", "/etc/deadlight/users.txt", "Authentication file"},
    {"plugin.auth", "auth_realm", "Deadlight Proxy", "Authentication realm"},
    {"plugin.auth", "require_auth", "false", "Require authentication for all requests"},
    
    // Cache settings
    {"cache", "enabled", "true", "Enable response caching"},
    {"cache", "cache_dir", "/tmp/deadlight_cache", "Cache directory"},
    {"cache", "max_cache_size", "1GB", "Maximum cache size"},
    {"cache", "default_ttl", "3600", "Default cache TTL (seconds)"},
    {"cache", "cache_methods", "GET,HEAD", "Cacheable HTTP methods"},
    {"cache", "cache_responses", "200,301,302,404", "Cacheable response codes"},
    
    // Security settings
    {"security", "enable_security_headers", "true", "Add security headers"},
    {"security", "block_private_ips", "false", "Block requests to private IPs"},
    {"security", "allowed_domains", "", "Allowed domains (whitelist)"},
    {"security", "blocked_domains", "", "Blocked domains (blacklist)"},
    {"security", "max_request_size", "10MB", "Maximum request size"},
    {"security", "max_header_size", "8KB", "Maximum header size"},
    
    {NULL, NULL, NULL, NULL}
};

/**
 * Load configuration from file
 */
gboolean deadlight_config_load(DeadlightContext *context, const gchar *config_file, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    
    // Clean up existing config
    if (context->config) {
        if (context->config->file_monitor) {
            g_file_monitor_cancel(context->config->file_monitor);
            g_object_unref(context->config->file_monitor);
        }
        if (context->config->keyfile) {
            g_key_file_free(context->config->keyfile);
        }
        config_cache_clear(context->config);
        g_free(context->config->config_path);
        g_free(context->config);
    }
    // [FIX] Address potential memory leak from previous load
    g_free(context->listen_address);
    context->listen_address = NULL;
    
    // Create new config structure
    context->config = g_new0(DeadlightConfig, 1);
    context->config->keyfile = g_key_file_new();
    context->config->string_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    context->config->int_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    context->config->bool_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Determine config file path
    const gchar *config_path = config_file ? config_file : DEADLIGHT_DEFAULT_CONFIG_FILE;
    context->config->config_path = g_strdup(config_path);
    
    // Check if config file exists
    if (!g_file_test(config_path, G_FILE_TEST_EXISTS)) {
        g_info("Configuration file %s not found, creating default", config_path);
        
        if (!create_default_config_file(config_path, error)) {
            return FALSE;
        }
    }
    
    // Load config file
    if (!g_key_file_load_from_file(context->config->keyfile, config_path, 
                                  G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS, 
                                  error)) {
        g_prefix_error(error, "Failed to load configuration file %s: ", config_path);
        return FALSE;
    }
    
    // Validate configuration
    gchar **groups = g_key_file_get_groups(context->config->keyfile, NULL);
    for (gchar **group = groups; *group; group++) {
        if (!validate_config_section(context->config, *group, error)) {
            g_strfreev(groups);
            return FALSE;
        }
    }
    g_strfreev(groups);
    
    // Set up file monitoring for live reload
    GFile *file = g_file_new_for_path(config_path);
    context->config->file_monitor = g_file_monitor_file(file, G_FILE_MONITOR_NONE, NULL, error);
    g_object_unref(file);
    
    if (context->config->file_monitor) {
        g_signal_connect(context->config->file_monitor, "changed", 
                        G_CALLBACK(config_file_changed), context);
        g_info("Configuration file monitoring enabled");
    } else {
        g_warning("Failed to set up configuration file monitoring: %s", 
                 error ? (*error)->message : "Unknown error");
        if (error) {
            g_clear_error(error);
        }
    }

    // Set log level
    gchar *log_level = deadlight_config_get_string(context, "core", "log_level", DEADLIGHT_DEFAULT_LOG_LEVEL);
    if (g_strcmp0(log_level, "error") == 0) {
        context->log_level = DEADLIGHT_LOG_ERROR;
    } else if (g_strcmp0(log_level, "warning") == 0) {
        context->log_level = DEADLIGHT_LOG_WARNING;
    } else if (g_strcmp0(log_level, "info") == 0) {
        context->log_level = DEADLIGHT_LOG_INFO;
    } else if (g_strcmp0(log_level, "debug") == 0) {
        context->log_level = DEADLIGHT_LOG_DEBUG;
    } else {
        context->log_level = DEADLIGHT_LOG_INFO;
    }
    g_free(log_level);
    
    // SSL interception setting
    context->ssl_intercept_enabled = deadlight_config_get_bool(context, "ssl", "enabled", TRUE);
    
    config_update_context_values(context);
    
    g_info("Configuration loaded successfully from %s", config_path);
    return TRUE;
}

/**
 * Save configuration to file
 */
gboolean deadlight_config_save(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->config != NULL, FALSE);
    
    gchar *data = g_key_file_to_data(context->config->keyfile, NULL, error);
    if (!data) {
        return FALSE;
    }
    
    gboolean result = g_file_set_contents(context->config->config_path, data, -1, error);
    g_free(data);
    
    if (result) {
        g_info("Configuration saved to %s", context->config->config_path);
    }
    
    return result;
}

/**
 * Get integer value from configuration
 */
gint deadlight_config_get_int(DeadlightContext *context, const gchar *section, 
                             const gchar *key, gint default_value) {
    g_return_val_if_fail(context != NULL, default_value);
    g_return_val_if_fail(context->config != NULL, default_value);
    
    // Check cache first
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    gpointer cached_value = g_hash_table_lookup(context->config->int_cache, cache_key);
    
    if (cached_value) {
        gint value = GPOINTER_TO_INT(cached_value);
        g_free(cache_key);
        return value;
    }
    
    // Get from keyfile
    GError *error = NULL;
    gint value = g_key_file_get_integer(context->config->keyfile, section, key, &error);
    
    if (error) {
        g_error_free(error);
        value = default_value;
    }
    
    // Cache the value
    g_hash_table_insert(context->config->int_cache, cache_key, GINT_TO_POINTER(value));
    
    return value;
}

/**
 * Get string value from configuration
 */
gchar *deadlight_config_get_string(DeadlightContext *context, const gchar *section, 
                                  const gchar *key, const gchar *default_value) {
    g_return_val_if_fail(context != NULL, g_strdup(default_value));
    g_return_val_if_fail(context->config != NULL, g_strdup(default_value));
    
    // Check cache first
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    const gchar *cached_value = g_hash_table_lookup(context->config->string_cache, cache_key);
    
    if (cached_value) {
        gchar *result = g_strdup(cached_value);
        g_free(cache_key);
        return result;
    }
    
    // Get from keyfile
    GError *error = NULL;
    gchar *value = g_key_file_get_string(context->config->keyfile, section, key, &error);
    
    if (error) {
        g_error_free(error);
        value = g_strdup(default_value);
    }
    
    // Cache the value
    g_hash_table_insert(context->config->string_cache, cache_key, g_strdup(value));
    
    return value;
}

/**
 * Get boolean value from configuration
 */
gboolean deadlight_config_get_bool(DeadlightContext *context, const gchar *section, 
                                  const gchar *key, gboolean default_value) {
    g_return_val_if_fail(context != NULL, default_value);
    g_return_val_if_fail(context->config != NULL, default_value);
    
    // Check cache first
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    gpointer cached_value = g_hash_table_lookup(context->config->bool_cache, cache_key);
    
    if (cached_value) {
        gboolean value = GPOINTER_TO_INT(cached_value);
        g_free(cache_key);
        return value;
    }
    
    // Get from keyfile
    GError *error = NULL;
    gboolean value = g_key_file_get_boolean(context->config->keyfile, section, key, &error);
    
    if (error) {
        g_error_free(error);
        value = default_value;
    }
    
    // Cache the value
    g_hash_table_insert(context->config->bool_cache, cache_key, GINT_TO_POINTER(value));
    
    return value;
}

/**
 * Set integer value in configuration
 */
void deadlight_config_set_int(DeadlightContext *context, const gchar *section, 
                             const gchar *key, gint value) {
    g_return_if_fail(context != NULL);
    g_return_if_fail(context->config != NULL);
    
    g_key_file_set_integer(context->config->keyfile, section, key, value);
    
    // Update cache
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    g_hash_table_insert(context->config->int_cache, cache_key, GINT_TO_POINTER(value));
}

/**
 * Set string value in configuration
 */
void deadlight_config_set_string(DeadlightContext *context, const gchar *section, 
                                const gchar *key, const gchar *value) {
    g_return_if_fail(context != NULL);
    g_return_if_fail(context->config != NULL);
    
    g_key_file_set_string(context->config->keyfile, section, key, value);
    
    // Update cache
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    g_hash_table_insert(context->config->string_cache, cache_key, g_strdup(value));
}

/**
 * Set boolean value in configuration
 */
void deadlight_config_set_bool(DeadlightContext *context, const gchar *section, 
                              const gchar *key, gboolean value) {
    g_return_if_fail(context != NULL);
    g_return_if_fail(context->config != NULL);
    
    g_key_file_set_boolean(context->config->keyfile, section, key, value);
    
    // Update cache
    gchar *cache_key = g_strdup_printf("%s.%s", section, key);
    g_hash_table_insert(context->config->bool_cache, cache_key, GINT_TO_POINTER(value));
}

/**
 * Configuration file change callback
 */
static void config_file_changed(GFileMonitor *monitor, GFile *file, GFile *other_file,
                               GFileMonitorEvent event_type, gpointer user_data) {
    (void)monitor; 
    (void)file;
    (void)other_file;
    
    DeadlightContext *context = (DeadlightContext *)user_data;

    if (event_type == G_FILE_MONITOR_EVENT_CHANGED ||
        event_type == G_FILE_MONITOR_EVENT_CREATED) {

        g_info("Configuration file changed, reloading...");

        // Reload keyfile
        GError *error = NULL;
        if (!g_key_file_load_from_file(context->config->keyfile, context->config->config_path,
                                      G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS,
                                      &error)) {
            g_warning("Failed to reload configuration file: %s", error->message);
            g_error_free(error);
            // Clear caches even on failure to force re-read on next access
            config_cache_clear(context->config);
            return;
        }

        // Clear caches before updating
        config_cache_clear(context->config);

        // [REFACTOR] Update context values using the new helper function
        config_update_context_values(context);

        // Notify plugins of configuration change
        if (context->plugins) {
            // This would call plugin configuration change callbacks
            g_info("Notifying plugins of configuration change");
        }

        g_info("Configuration reloaded successfully");
    }
}

/**
 * Validate configuration section
 */
static gboolean validate_config_section(DeadlightConfig *config, const gchar *section, GError **error) {
    // Basic validation - could be extended with more sophisticated checks
    if (!section || strlen(section) == 0) {
        g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
                   "Invalid section name");
        return FALSE;
    }
    
    // Check for required keys in core section
    if (g_strcmp0(section, "core") == 0) {
        if (!g_key_file_has_key(config->keyfile, section, "port", NULL)) {
            g_key_file_set_integer(config->keyfile, section, "port", DEADLIGHT_DEFAULT_PORT);
            return FALSE;
        }
    }
    
    // Validate network pool settings
    if (g_strcmp0(section, "network") == 0) {
        gint max_per_host = g_key_file_get_integer(config->keyfile, section, 
                                                   "connection_pool_size", NULL);
        if (max_per_host <= 0) {
            g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
                       "connection_pool_size must be > 0");
            return FALSE;
        }
        
        gint idle_timeout = g_key_file_get_integer(config->keyfile, section,
                                                   "connection_pool_timeout", NULL);
        if (idle_timeout < 0) {
            g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
                       "connection_pool_timeout must be >= 0");
            return FALSE;
        }
    }
    return TRUE;
}

/**
 * Create default configuration file
 */
static gboolean create_default_config_file(const gchar *config_path, GError **error) {
    GKeyFile *keyfile = g_key_file_new();
    
    // Create directory if it doesn't exist
    gchar *config_dir = g_path_get_dirname(config_path);
    if (g_mkdir_with_parents(config_dir, 0755) != 0) {
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                   "Failed to create configuration directory %s: %s", 
                   config_dir, g_strerror(errno));
        g_free(config_dir);
        g_key_file_free(keyfile);
        return FALSE;
    }
    g_free(config_dir);
    
    // Add default values
    for (int i = 0; default_config[i].section; i++) {
        g_key_file_set_string(keyfile, default_config[i].section, 
                             default_config[i].key, default_config[i].value);
        g_key_file_set_comment(keyfile, default_config[i].section, 
                              default_config[i].key, default_config[i].description, NULL);
    }
    
    // Save to file
    gchar *data = g_key_file_to_data(keyfile, NULL, error);
    if (!data) {
        g_key_file_free(keyfile);
        return FALSE;
    }
    
    gboolean result = g_file_set_contents(config_path, data, -1, error);
    
    g_free(data);
    g_key_file_free(keyfile);
    
    if (result) {
        g_info("Default configuration file created at %s", config_path);
    }
    
    return result;
}

/**
 * Parse human-readable size strings (e.g., "1GB", "512MB", "64KB")
 * Returns size in bytes, or default_value on error
 */
guint64 deadlight_config_get_size(DeadlightContext *context, const gchar *section,
                                  const gchar *key, guint64 default_value) {
    g_return_val_if_fail(context != NULL, default_value);
    
    gchar *value_str = deadlight_config_get_string(context, section, key, NULL);
    if (!value_str) {
        return default_value;
    }
    
    gchar *endptr;
    guint64 size = g_ascii_strtoull(value_str, &endptr, 10);
    
    if (endptr && *endptr) {
        switch (g_ascii_toupper(*endptr)) {
            case 'K':
                size *= 1024;
                break;
            case 'M':
                size *= 1024 * 1024;
                break;
            case 'G':
                size *= 1024 * 1024 * 1024;
                break;
            default:
                g_warning("Unknown size suffix: %c", *endptr);
                size = default_value;
        }
    }
    
    g_free(value_str);
    return size;
}

/**
 * Updates the 'hot' cached configuration values directly on the context
 * after a load or reload.
 */
static void config_update_context_values(DeadlightContext *context) {
    context->listen_port = deadlight_config_get_int(context, "core", "port", DEADLIGHT_DEFAULT_PORT);
    
    // Free any existing string before assigning the new one
    g_free(context->listen_address);
    context->listen_address = deadlight_config_get_string(context, "core", "bind_address", "0.0.0.0");
    context->max_connections = deadlight_config_get_int(context, "core", "max_connections", DEADLIGHT_DEFAULT_MAX_CONNECTIONS);
    context->pool_max_per_host = deadlight_config_get_int(context, "network", "connection_pool_size", 10);
    context->pool_idle_timeout = deadlight_config_get_int(context, "network", "connection_pool_timeout", 300);
    context->pool_max_total = deadlight_config_get_int(context, "network", "connection_pool_max_total", 500);
    g_free(context->pool_eviction_policy);
    context->pool_eviction_policy = deadlight_config_get_string(context, "network", "connection_pool_eviction_policy", "lru");
    context->pool_health_check_interval = deadlight_config_get_int(context, "network","connection_pool_health_check_interval", 60);
    context->pool_reuse_ssl = deadlight_config_get_bool(context, "network", "connection_pool_reuse_ssl", TRUE);
    // Set log level
    gchar *log_level = deadlight_config_get_string(context, "core", "log_level", DEADLIGHT_DEFAULT_LOG_LEVEL);
    if (g_strcmp0(log_level, "error") == 0) {
        context->log_level = DEADLIGHT_LOG_ERROR;
    } else if (g_strcmp0(log_level, "warning") == 0) {
        context->log_level = DEADLIGHT_LOG_WARNING;
    } else if (g_strcmp0(log_level, "info") == 0) {
        context->log_level = DEADLIGHT_LOG_INFO;
    } else if (g_strcmp0(log_level, "debug") == 0) {
        context->log_level = DEADLIGHT_LOG_DEBUG;
    } else {
        context->log_level = DEADLIGHT_LOG_INFO;
    }
    g_free(log_level);

    // Note: Pool settings aren't stored on context yet, but they should be read
    // each time from config in network.c. For now, just log on change:
    gint pool_size = deadlight_config_get_int(context, "network", 
                                             "connection_pool_size", 10);
    gint pool_timeout = deadlight_config_get_int(context, "network",
                                                "connection_pool_timeout", 300);
    
    g_info("Connection pool config updated: size=%d, timeout=%d",
           pool_size, pool_timeout);
    
    // TODO: Dynamically reconfigure the pool if it's already running
    
    // SSL interception setting
    context->ssl_intercept_enabled =
        deadlight_config_get_bool(context, "ssl", "enabled", TRUE);

    // ─── POOL CONFIG ───────────────────────────────────────────
    context->pool_max_per_host =
        deadlight_config_get_int(context, "network",
                                 "connection_pool_size", 10);
    context->pool_idle_timeout =
        deadlight_config_get_int(context, "network",
                                 "connection_pool_timeout", 300);
    context->pool_max_total =
        deadlight_config_get_int(context, "network",
                                 "connection_pool_max_total", 500);
    g_free(context->pool_eviction_policy);
    context->pool_eviction_policy =
        deadlight_config_get_string(context, "network",
                                    "connection_pool_eviction_policy", "lru");
    context->pool_health_check_interval =
        deadlight_config_get_int(context, "network",
                                 "connection_pool_health_check_interval", 60);
    context->pool_reuse_ssl =
        deadlight_config_get_bool(context, "network",
                                  "connection_pool_reuse_ssl", TRUE);

    g_info("Pool config: per_host=%d idle_t=%d total=%d policy=%s health=%d reuse_ssl=%d",
           context->pool_max_per_host,
           context->pool_idle_timeout,
           context->pool_max_total,
           context->pool_eviction_policy,
           context->pool_health_check_interval,
           context->pool_reuse_ssl);
}

/**
 * Clear configuration cache
 */
static void config_cache_clear(DeadlightConfig *config) {
    g_hash_table_remove_all(config->string_cache);
    g_hash_table_remove_all(config->int_cache);
    g_hash_table_remove_all(config->bool_cache);
}
