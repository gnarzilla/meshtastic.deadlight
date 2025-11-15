// src/core/logging.h

#ifndef LOGGING_H
#define LOGGING_H

#include "deadlight.h" // We need DeadlightContext and GError

// --- Public Function Declarations ---
// These are the functions that other modules are allowed to call.
gboolean deadlight_logging_init(DeadlightContext *context, GError **error);
void deadlight_logging_cleanup(DeadlightContext *context);

// --- Convenience Logging Macros ---
// This is the clean way to provide log_info, log_warn, etc.
// They are wrappers around the standard GLib logging functions,
// which will then be captured by our custom handler in logging.c.
// The "deadlight" domain is used to identify our messages.

#define log_error(...) g_log("deadlight", G_LOG_LEVEL_ERROR, __VA_ARGS__)
#define log_warn(...)  g_log("deadlight", G_LOG_LEVEL_WARNING, __VA_ARGS__)
#define log_info(...)  g_log("deadlight", G_LOG_LEVEL_INFO, __VA_ARGS__)
#define log_debug(...) g_log("deadlight", G_LOG_LEVEL_DEBUG, __VA_ARGS__)

#endif // LOGGING_H
