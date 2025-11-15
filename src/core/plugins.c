/**
 * Deadlight Proxy v4.0 - Plugin System
 *
 * Dynamic plugin loading and management
 */

#include <glib.h>
#include <gio/gio.h>
#include <gmodule.h>

#include "deadlight.h"
#include "plugins.h"

// Forward declarations
static gboolean load_plugin_from_file(DeadlightContext *context, const gchar *filepath, GError **error);
static gboolean load_plugins_from_directory(DeadlightContext *context, GError **error);
gboolean deadlight_plugin_register(DeadlightContext *context, DeadlightPlugin *plugin);

/**
 * Load a plugin from file
 */
static gboolean load_plugin_from_file(DeadlightContext *context, const gchar *filepath, GError **error) {
    GModule *module = NULL;
    DeadlightPlugin *plugin = NULL;
    gboolean (*get_plugin_info)(DeadlightPlugin **plugin);
    
    g_info("Loading plugin from %s", filepath);
    
    // Open the module
    module = g_module_open(filepath, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
    if (!module) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to load plugin %s: %s", filepath, g_module_error());
        return FALSE;
    }
    
    // Look for the plugin info function
    if (!g_module_symbol(module, "deadlight_plugin_get_info", (gpointer *)&get_plugin_info)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Plugin %s missing deadlight_plugin_get_info function", filepath);
        g_module_close(module);
        return FALSE;
    }
    
    // Get plugin information
    if (!get_plugin_info(&plugin) || !plugin) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to get plugin info from %s", filepath);
        g_module_close(module);
        return FALSE;
    }
    
    // Make module resident so it doesn't get unloaded
    g_module_make_resident(module);
    
    // Register the plugin
    if (!deadlight_plugin_register(context, plugin)) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to register plugin %s", plugin->name);
        g_module_close(module);
        return FALSE;
    }
    
    g_info("Successfully loaded plugin: %s v%s by %s", 
           plugin->name, plugin->version, plugin->author);
    
    return TRUE;
}

/**
 * Load all plugins from directory
 */
static gboolean load_plugins_from_directory(DeadlightContext *context, GError **error) {
    GDir *dir;
    const gchar *filename;
    gchar *filepath;
    GError *local_error = NULL;
    gint loaded = 0;
    
    (void)error; // Suppress unused parameter warning
    
    g_info("Looking for plugins in: %s", context->plugins->plugin_dir);
    
    // Check if directory exists
    if (!g_file_test(context->plugins->plugin_dir, G_FILE_TEST_IS_DIR)) {
        g_warning("Plugin directory does not exist: %s", context->plugins->plugin_dir);
        return TRUE; // Not a fatal error
    }
    
    // Open directory
    dir = g_dir_open(context->plugins->plugin_dir, 0, &local_error);
    if (!dir) {
        g_warning("Failed to open plugin directory %s: %s",
                 context->plugins->plugin_dir, local_error->message);
        g_error_free(local_error);
        return TRUE; // Not a fatal error
    }
    
    // Iterate through files
    while ((filename = g_dir_read_name(dir)) != NULL) {
        // Only load .so files
        if (!g_str_has_suffix(filename, ".so")) {
            continue;
        }
        
        filepath = g_build_filename(context->plugins->plugin_dir, filename, NULL);
        
        // Load the plugin
        local_error = NULL;
        if (load_plugin_from_file(context, filepath, &local_error)) {
            loaded++;
        } else {
            g_warning("Failed to load plugin %s: %s", 
                     filename, local_error ? local_error->message : "Unknown error");
            if (local_error) {
                g_error_free(local_error);
            }
        }
        
        g_free(filepath);
    }
    
    g_dir_close(dir);
    g_info("Loaded %d plugins from %s", loaded, context->plugins->plugin_dir);
    
    return TRUE;
}

/**
 * Initialize plugin system
 */
gboolean deadlight_plugins_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
    
    g_info("Initializing plugin system...");
    
    // Create plugin manager
    context->plugins = g_new0(DeadlightPluginManager, 1);
    context->plugins->plugins = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                    g_free, NULL);
    
    // Get plugin directory
    context->plugins->plugin_dir = deadlight_config_get_string(context, "plugins",
                                                             "plugin_dir",
                                                             "/usr/lib/deadlight/plugins");
    
    // Check if plugins are enabled
    if (!deadlight_config_get_bool(context, "plugins", "enabled", TRUE)) {
        g_info("Plugin system disabled by configuration");
        context->plugins->initialized = TRUE;
        return TRUE;
    }
    
    // Load plugins from directory
    if (!load_plugins_from_directory(context, error)) {
        return FALSE;
    }
    
    context->plugins->initialized = TRUE;
    g_info("Plugin system initialized with %d plugins", deadlight_plugins_count(context));
    
    return TRUE;
}

/**
 * Cleanup plugin system
 */
void deadlight_plugins_cleanup(DeadlightContext *context) {
    g_return_if_fail(context != NULL);
    
    g_info("Cleaning up plugin system...");
    
    if (context->plugins) {
        if (context->plugins->plugins) {
            // TODO: Unload all plugins
            g_hash_table_destroy(context->plugins->plugins);
        }
        
        g_free(context->plugins->plugin_dir);
        g_free(context->plugins);
        context->plugins = NULL;
    }
}

/**
 * Get plugin count
 */
gint deadlight_plugins_count(DeadlightContext *context) {
    g_return_val_if_fail(context != NULL, 0);
    g_return_val_if_fail(context->plugins != NULL, 0);
    
    return g_hash_table_size(context->plugins->plugins);
}

/**
 * Register a plugin
 */
gboolean deadlight_plugin_register(DeadlightContext *context, DeadlightPlugin *plugin) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->plugins != NULL, FALSE);
    g_return_val_if_fail(plugin != NULL, FALSE);
    g_return_val_if_fail(plugin->name != NULL, FALSE);
    
    // Check if plugin already exists
    if (g_hash_table_contains(context->plugins->plugins, plugin->name)) {
        g_warning("Plugin %s already registered", plugin->name);
        return FALSE;
    }
    
    // Initialize plugin
    if (plugin->init && !plugin->init(context)) {
        g_warning("Plugin %s initialization failed", plugin->name);
        return FALSE;
    }
    
    // Add to plugin table
    g_hash_table_insert(context->plugins->plugins, 
                       g_strdup(plugin->name), plugin);
    
    g_info("Plugin %s registered successfully", plugin->name);
    return TRUE;
}

/**
 * Unregister a plugin
 */
gboolean deadlight_plugin_unregister(DeadlightContext *context, const gchar *name) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->plugins != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    
    DeadlightPlugin *plugin = g_hash_table_lookup(context->plugins->plugins, name);
    if (!plugin) {
        g_warning("Plugin %s not found", name);
        return FALSE;
    }
    
    // Cleanup plugin
    if (plugin->cleanup) {
        plugin->cleanup(context);
    }
    
    // Remove from table
    g_hash_table_remove(context->plugins->plugins, name);
    
    g_info("Plugin %s unregistered", name);
    return TRUE;
}

/**
 * Find a plugin by name
 */
DeadlightPlugin *deadlight_plugin_find(DeadlightContext *context, const gchar *name) {
    g_return_val_if_fail(context != NULL, NULL);
    g_return_val_if_fail(context->plugins != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);
    
    return g_hash_table_lookup(context->plugins->plugins, name);
}

gchar **deadlight_config_get_string_list(DeadlightContext *context, 
                                        const gchar *section, 
                                        const gchar *key, 
                                        gchar **default_value) {
    // Suppress unused parameter warnings
    (void)context;
    (void)section;
    (void)key;
    // Simple implementation - just return default for now
    return default_value;
}


/**
 * Returns a new list containing the names of all loaded plugins.
 * The caller is responsible for freeing the list and its string elements
 * using g_list_free_full(list, g_free).
 */
GList* deadlight_plugins_get_all_names(DeadlightContext *context)
{
    GList *names = NULL;
    if (!context || !context->plugins || !context->plugins->plugins) {
        return NULL;
    }

    GHashTableIter iter;
    gpointer key, value; // 'key' will be the plugin name string

    g_hash_table_iter_init(&iter, context->plugins->plugins);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        names = g_list_prepend(names, g_strdup((gchar *)key));
    }
    
    // g_list_prepend adds to the front, so reverse to get a more natural order
    return g_list_reverse(names);
}

// Helper function to iterate and call a hook, stopping if any plugin returns FALSE
typedef gboolean (*PluginHookCaller)(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data);

static gboolean call_plugin_hook_internal(DeadlightContext *context, PluginHookCaller caller, gpointer user_data) {
    if (!context || !context->plugins || !context->plugins->plugins) {
        return TRUE; // No plugins or plugin system not initialized
    }

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, context->plugins->plugins);

    while (g_hash_table_iter_next(&iter, &key, &value)) {
        DeadlightPlugin *plugin = (DeadlightPlugin *)value;
        if (caller(plugin, context, user_data) == FALSE) {
            return FALSE; // Plugin blocked/stopped processing
        }
    }
    return TRUE; // All plugins allowed
}

// --- on_connection_accept ---
static gboolean on_connection_accept_caller(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data) {
    (void)context; // Suppress unused warning
    if (plugin->on_connection_accept) {
        return plugin->on_connection_accept((DeadlightConnection *)user_data);
    }
    return TRUE;
}

// --- on_protocol_detect ---
static gboolean on_protocol_detect_caller(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data) {
    (void)context; // Suppress unused warning
    if (plugin->on_protocol_detect) {
        DeadlightConnection *conn = (DeadlightConnection *)user_data;
        // We need to pass both connection and protocol
        // The protocol should be available in conn->protocol
        return plugin->on_protocol_detect(conn, conn->protocol);
    }
    return TRUE;
}

// --- on_request_headers ---
static gboolean on_request_headers_caller(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data) {
    (void)context; // Suppress unused warning
    if (plugin->on_request_headers) {
        return plugin->on_request_headers((DeadlightRequest *)user_data);
    }
    return TRUE;
}

// --- on_request_body
static gboolean on_request_body_caller(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data) {
    (void)context; // Suppress unused warning
    if (plugin->on_request_body) {
        return plugin->on_request_body((DeadlightRequest *)user_data);
    }
    return TRUE;
}

// --- on_response_headers ---
static gboolean on_response_headers_caller(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data) {
    (void)context; // Suppress unused warning
    if (plugin->on_response_headers) {
        return plugin->on_response_headers((DeadlightResponse *)user_data);
    }
    return TRUE;
}

// --- on_response_body ---
static gboolean on_response_body_caller(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data) {
    (void)context; // Suppress unused warning
    if (plugin->on_response_body) {
        return plugin->on_response_body((DeadlightResponse *)user_data);
    }
    return TRUE;
}

// --- on_connection_close ---
static gboolean on_connection_close_caller(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data) {
    (void)context; // Suppress unused warning
    if (plugin->on_connection_close) {
        return plugin->on_connection_close((DeadlightConnection *)user_data);
    }
    return TRUE;
}

// --- on_config_change ---
// For this one, we need to pass section and key through user_data
typedef struct {
    const gchar *section;
    const gchar *key;
} ConfigChangeData;

static gboolean on_config_change_caller(DeadlightPlugin *plugin, DeadlightContext *context, gpointer user_data) {
    if (plugin->on_config_change) {
        ConfigChangeData *data = (ConfigChangeData *)user_data;
        return plugin->on_config_change(context, data ? data->section : NULL, data ? data->key : NULL);
    }
    return TRUE;
}

gboolean deadlight_plugins_call_on_connection_accept(DeadlightContext *context, DeadlightConnection *conn) {
    return call_plugin_hook_internal(context, on_connection_accept_caller, conn);
}

gboolean deadlight_plugins_call_on_protocol_detect(DeadlightContext *context, DeadlightConnection *conn) {
    return call_plugin_hook_internal(context, on_protocol_detect_caller, conn);
}

gboolean deadlight_plugins_call_on_request_headers(DeadlightContext *context, DeadlightRequest *request) {
    return call_plugin_hook_internal(context, on_request_headers_caller, request);
}

gboolean deadlight_plugins_call_on_request_body(DeadlightContext *context, DeadlightRequest *request) {
    return call_plugin_hook_internal(context, on_request_body_caller, request);
}

gboolean deadlight_plugins_call_on_response_headers(DeadlightContext *context, DeadlightResponse *response) {
    return call_plugin_hook_internal(context, on_response_headers_caller, response);
}

gboolean deadlight_plugins_call_on_response_body(DeadlightContext *context, DeadlightResponse *response) {
    return call_plugin_hook_internal(context, on_response_body_caller, response);
}

gboolean deadlight_plugins_call_on_connection_close(DeadlightContext *context, DeadlightConnection *conn) {
    return call_plugin_hook_internal(context, on_connection_close_caller, conn);
}

void deadlight_plugins_call_on_config_change(DeadlightContext *context, const gchar *section, const gchar *key) {
    ConfigChangeData data = { section, key };
    call_plugin_hook_internal(context, on_config_change_caller, &data);
}