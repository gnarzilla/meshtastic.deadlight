/**
 * Deadlight Proxy v4.0 - Logging System
 * 
 * Centralized logging with file output and level control
 */
#include "core/logging.h"
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "deadlight.h"

static FILE *log_file = NULL;
static DeadlightLogLevel current_log_level = DEADLIGHT_LOG_INFO;

/**
 * Custom log handler
 */
void deadlight_log_handler(const gchar *log_domain, GLogLevelFlags log_level, 
                          const gchar *message, gpointer user_data) {
    (void)user_data; // Unused parameter
    
    // Check if we should log this level
    DeadlightLogLevel dl_level;
    switch (log_level & G_LOG_LEVEL_MASK) {
        case G_LOG_LEVEL_ERROR:
            dl_level = DEADLIGHT_LOG_ERROR;
            break;
        case G_LOG_LEVEL_CRITICAL:
            dl_level = DEADLIGHT_LOG_ERROR;
            break;
        case G_LOG_LEVEL_WARNING:
            dl_level = DEADLIGHT_LOG_WARNING;
            break;
        case G_LOG_LEVEL_MESSAGE:
            dl_level = DEADLIGHT_LOG_INFO;
            break;
        case G_LOG_LEVEL_INFO:
            dl_level = DEADLIGHT_LOG_INFO;
            break;
        case G_LOG_LEVEL_DEBUG:
            dl_level = DEADLIGHT_LOG_DEBUG;
            break;
        default:
            dl_level = DEADLIGHT_LOG_INFO;
    }
    
    if (dl_level > current_log_level) {
        return;
    }
    
    // Format timestamp
    time_t now;
    struct tm *tm_info;
    char timestamp[26];
    
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Format log level
    const gchar *level_str;
    const gchar *color_code = "";
    const gchar *reset_code = "";
    
    // Add colors for terminal output
    if (isatty(fileno(stderr)) && !log_file) {
        reset_code = "\033[0m";
        switch (dl_level) {
            case DEADLIGHT_LOG_ERROR:
                level_str = "ERROR";
                color_code = "\033[31m"; // Red
                break;
            case DEADLIGHT_LOG_WARNING:
                level_str = "WARN ";
                color_code = "\033[33m"; // Yellow
                break;
            case DEADLIGHT_LOG_INFO:
                level_str = "INFO ";
                color_code = "\033[32m"; // Green
                break;
            case DEADLIGHT_LOG_DEBUG:
                level_str = "DEBUG";
                color_code = "\033[36m"; // Cyan
                break;
            default:
                level_str = "INFO ";
                color_code = "\033[32m";
        }
    } else {
        switch (dl_level) {
            case DEADLIGHT_LOG_ERROR:
                level_str = "ERROR";
                break;
            case DEADLIGHT_LOG_WARNING:
                level_str = "WARN ";
                break;
            case DEADLIGHT_LOG_INFO:
                level_str = "INFO ";
                break;
            case DEADLIGHT_LOG_DEBUG:
                level_str = "DEBUG";
                break;
            default:
                level_str = "INFO ";
        }
    }
    
    // Format domain
    const gchar *domain = log_domain ? log_domain : "deadlight";
    
    // Output to file or stderr
    FILE *output = log_file ? log_file : stderr;
    
    fprintf(output, "%s%s [%s] %s: %s%s\n", 
            color_code, timestamp, level_str, domain, message, reset_code);
    
    // Flush immediately for real-time logging
    fflush(output);
}

/**
 * Initialize logging system
 */
gboolean deadlight_logging_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_debug("deadlight_logging_init() called; default log_file=%p", (void*)log_file);
    
    // Get log level from config
    gchar *log_level_str = deadlight_config_get_string(context, "core", "log_level", "info");
    
    if (g_strcmp0(log_level_str, "error") == 0) {
        current_log_level = DEADLIGHT_LOG_ERROR;
    } else if (g_strcmp0(log_level_str, "warning") == 0) {
        current_log_level = DEADLIGHT_LOG_WARNING;
    } else if (g_strcmp0(log_level_str, "info") == 0) {
        current_log_level = DEADLIGHT_LOG_INFO;
    } else if (g_strcmp0(log_level_str, "debug") == 0) {
        current_log_level = DEADLIGHT_LOG_DEBUG;
    } else {
        current_log_level = DEADLIGHT_LOG_INFO;
    }
    
    g_free(log_level_str);
    
    // Get log file from config
    gchar *log_file_path = deadlight_config_get_string(context, "core", "log_file", "");
    
    if (log_file_path && strlen(log_file_path) > 0) {
        // Create log directory if needed
        gchar *log_dir = g_path_get_dirname(log_file_path);
        if (g_mkdir_with_parents(log_dir, 0755) != 0) {
            g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
                       "Failed to create log directory: %s", log_dir);
            g_free(log_dir);
            g_free(log_file_path);
            return FALSE;
        }
        g_free(log_dir);
        
        // Open log file
        log_file = fopen(log_file_path, "a");
        if (!log_file) {
            g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
                       "Failed to open log file: %s", log_file_path);
            g_free(log_file_path);
            return FALSE;
        }
        
        g_info("Logging to file: %s", log_file_path);
    } else {
        g_info("Logging to stderr");
    }
    
    g_free(log_file_path);
    
    // Set our custom log handler
    g_log_set_default_handler(deadlight_log_handler, context);
    
    g_info("Logging system initialized (level: %d)", current_log_level);
    return TRUE;
}

/**
 * Cleanup logging system
 */
void deadlight_logging_cleanup(DeadlightContext *context) {
    (void)context; // Unused parameter
    
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    
    g_info("Logging system cleaned up");
}
