// File: src/core/plugins.h 
#ifndef PLUGINS_H
#define PLUGINS_H

#include "deadlight.h"
#include <glib.h>

// This function will return a list of plugin names.
// The caller is responsible for freeing the list and its contents.
GList* deadlight_plugins_get_loaded_names(DeadlightContext *context);

// Plugin manager structure
struct _DeadlightPluginManager {
    GHashTable *plugins;        // Loaded plugins
    gchar *plugin_dir;          // Plugin directory
    gboolean initialized;
};

#endif // PLUGINS_H
