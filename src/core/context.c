/**
 * Deadlight Proxy v1.0 - Context Management
 *
 * Core context creation and lifecycle management
 */

#include <glib.h>
#include <stdlib.h>
#include "deadlight.h"

#ifdef ENABLE_UI
#include "ui/ui.h"
#endif
#include "vpn/vpn_gateway.h"

/**
 * Create new Deadlight context
 */
DeadlightContext *deadlight_context_new(void) {
    DeadlightContext *ctx = g_new0(DeadlightContext, 1);
    
    // Initialize hash tables
    ctx->certificates = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Initialize plugin data storage
    ctx->plugins_data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // Initialize statistics
    ctx->total_connections = 0;
    ctx->active_connections = 0;
    ctx->bytes_transferred = 0;
    ctx->uptime_timer = g_timer_new();
    
    g_mutex_init(&ctx->stats_mutex);

    // Set defaults
    ctx->shutdown_requested = FALSE;
    
    // VPN will be allocated when enabled
    ctx->vpn = NULL;
    
    return ctx;
}

/**
 * Free Deadlight context
 */
void deadlight_context_free(DeadlightContext *ctx) {
    if (!ctx) return;
    
    // If we're freeing the context, we're shutting down.
    ctx->shutdown_requested = TRUE;

    // Stop main loop if running
    if (ctx->main_loop) {
        if (g_main_loop_is_running(ctx->main_loop)) {
            g_main_loop_quit(ctx->main_loop);
        }
    }

#ifdef ENABLE_UI
    // Stop UI server first (it holds a pointer to ctx via MHD callbacks)
    stop_ui_server();
#endif

    // VPN must be cleaned up BEFORE network stop: VPN sessions can release pooled connections.
    if (ctx->vpn) {
        deadlight_vpn_gateway_cleanup(ctx);
        g_free(ctx->vpn);
        ctx->vpn = NULL;
    }

    // Stop network (owns connections table, worker pool, connection pool, and network manager)
    if (ctx->network) {
        deadlight_network_stop(ctx);
    } else {
        // Fallback cleanup for partial/legacy states where the module manager wasn't created
        if (ctx->worker_pool) {
            g_thread_pool_free(ctx->worker_pool, TRUE, TRUE);
            ctx->worker_pool = NULL;
        }
        if (ctx->connections) {
            g_hash_table_destroy(ctx->connections);
            ctx->connections = NULL;
        }
        if (ctx->conn_pool) {
            connection_pool_free(ctx->conn_pool);
            ctx->conn_pool = NULL;
        }
    }

    // Plugins must outlive connection cleanup (connection cleanup notifies plugins)
    if (ctx->plugins) {
        deadlight_plugins_cleanup(ctx);
    }

    if (ctx->ssl) {
        deadlight_ssl_cleanup(ctx);
    }
    
    // Clean up certificates
    if (ctx->certificates) {
        g_hash_table_destroy(ctx->certificates);
    }

    // Clean up plugin data
    if (ctx->plugins_data) {
        g_hash_table_destroy(ctx->plugins_data);
    }
    
    // Stop uptime timer
    if (ctx->uptime_timer) {
        g_timer_destroy(ctx->uptime_timer);
    }

    g_free(ctx->pool_eviction_policy);

    g_mutex_clear(&ctx->stats_mutex);
    
    // Free cached strings
    g_free(ctx->listen_address);
    g_free(ctx->auth_endpoint);
    g_free(ctx->auth_secret);
    
    // Logging last so shutdown messages still appear
    deadlight_logging_cleanup(ctx);

    if (ctx->main_loop) {
        g_main_loop_unref(ctx->main_loop);
        ctx->main_loop = NULL;
    }
    
    // Free config
    if (ctx->config) {
        if (ctx->config->file_monitor) {
            g_file_monitor_cancel(ctx->config->file_monitor);
            g_object_unref(ctx->config->file_monitor);
        }
        if (ctx->config->keyfile) {
            g_key_file_free(ctx->config->keyfile);
        }
        if (ctx->config->string_cache) {
            g_hash_table_destroy(ctx->config->string_cache);
        }
        if (ctx->config->int_cache) {
            g_hash_table_destroy(ctx->config->int_cache);
        }
        if (ctx->config->bool_cache) {
            g_hash_table_destroy(ctx->config->bool_cache);
        }
        g_free(ctx->config->config_path);
        g_free(ctx->config);
    }
    
    g_free(ctx);
}