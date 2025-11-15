/**
 * Deadlight Proxy v1.0 - Main Entry Point
 *
 * A modular, extensible HTTP/HTTPS proxy with SSL interception
 * Built with GNU/GLib ecosystem for robustness and performance
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <glib-unix.h>
#include <glib.h>
#include <gio/gio.h>
#include <locale.h>

#include "deadlight.h"

#ifdef ENABLE_UI
#include "ui/ui.h"
#endif

#include "vpn/vpn_gateway.h"

// Global context - managed carefully
static DeadlightContext *g_context = NULL;

// Command line options
static gboolean opt_daemon = FALSE;
static gboolean opt_verbose = FALSE;
static gboolean opt_test_mode = FALSE;
static gchar *opt_config_file = NULL;
static gchar *opt_test_module = NULL;
static gchar *opt_pid_file = NULL;
static gint opt_port = 0;

static GOptionEntry entries[] = {
    {"daemon", 'd', 0, G_OPTION_ARG_NONE, &opt_daemon,
     "Run as daemon", NULL},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose,
     "Verbose output", NULL},
    {"config", 'c', 0, G_OPTION_ARG_STRING, &opt_config_file,
     "Configuration file", "FILE"},
    {"port", 'p', 0, G_OPTION_ARG_INT, &opt_port,
     "Listen port (overrides config)", "PORT"},
    {"pid-file", 0, 0, G_OPTION_ARG_STRING, &opt_pid_file,
     "PID file for daemon mode", "FILE"},
    {"test", 't', 0, G_OPTION_ARG_STRING, &opt_test_module,
     "Test specific module", "MODULE"},
    {"test-mode", 0, 0, G_OPTION_ARG_NONE, &opt_test_mode,
     "Enable test mode", NULL},
    {NULL}
};

// Forward declarations
static gboolean signal_handler(gpointer user_data);
static void cleanup_and_exit(int exit_code);
static int run_tests(const gchar *module);
static int run_daemon_mode(void);
static int run_interactive_mode(void);
static void print_banner(void);
static void print_usage(void);

/**
 * Signal handler for graceful shutdown
 */
static gboolean signal_handler(gpointer user_data) {
    DeadlightContext *ctx = (DeadlightContext *)user_data;

    g_info("Received shutdown signal, cleaning up...");

    if (ctx && ctx->main_loop) {
        g_main_loop_quit(ctx->main_loop);
    }

    return G_SOURCE_REMOVE;
}

/**
 * Cleanup resources and exit
 */
static void cleanup_and_exit(int exit_code) {
    if (g_context) {
        deadlight_context_free(g_context);
        g_context = NULL;
    }

    if (opt_config_file) {
        g_free(opt_config_file);
    }

    if (opt_test_module) {
        g_free(opt_test_module);
    }

    if (opt_pid_file) {
        g_free(opt_pid_file);
    }

    exit(exit_code);
}

/**
 * Test mode - run specific module tests
 */
static int run_tests(const gchar *module) {
    g_print("Test Mode\n");
    g_print("Testing module: %s\n\n", module);

    if (g_strcmp0(module, "all") == 0) {
        g_print("Running all tests...\n");

        // Test each module
        const gchar *modules[] = {
            "config", "logging", "network", "protocols",
            "ssl", "plugins", NULL
        };

        gboolean all_passed = TRUE;
        for (int i = 0; modules[i]; i++) {
            g_print("Testing %s... ", modules[i]);

            // This would call module-specific test functions
            gboolean result = deadlight_test_module(modules[i]);

            if (result) {
                g_print("PASS\n");
            } else {
                g_print("FAIL\n");
                all_passed = FALSE;
            }
        }

        g_print("\n%s\n", all_passed ? "All tests passed!" : "Some tests failed!");
        return all_passed ? 0 : 1;
    }

    // Test specific module
    g_print("Testing %s... ", module);
    gboolean result = deadlight_test_module(module);
    g_print("%s\n", result ? "PASS" : "FAIL");

    return result ? 0 : 1;
}

/**
 * Write PID file for daemon mode
 */
static gboolean write_pid_file(const gchar *pid_file) {
    if (!pid_file) return TRUE;

    FILE *fp = fopen(pid_file, "w");
    if (!fp) {
        g_error("Failed to create PID file %s: %s", pid_file, strerror(errno));
        return FALSE;
    }

    fprintf(fp, "%d\n", getpid());
    fclose(fp);

    g_info("PID file written to %s", pid_file);
    return TRUE;
}

/**
 * Remove PID file on exit
 */
static void remove_pid_file(void) {
    if (opt_pid_file && g_file_test(opt_pid_file, G_FILE_TEST_EXISTS)) {
        if (unlink(opt_pid_file) == 0) {
            g_info("PID file removed");
        } else {
            g_warning("Failed to remove PID file: %s", strerror(errno));
        }
    }
}


/**
 * Daemon mode - detach from terminal
 */
static int run_daemon_mode(void) {
    g_info("Starting daemon mode...");

    // Fork to background
    pid_t pid = fork();
    if (pid < 0) {
        g_error("Failed to fork: %s", strerror(errno));
        return 1;
    }

    if (pid > 0) {
        // Parent process exits
        g_info("Daemon started with PID %d", pid);
        exit(0);
    }

    // Child process continues
    setsid();  // Create new session

    // Change working directory
    if (chdir("/") < 0) {
        g_error("Failed to change directory: %s", strerror(errno));
        return 1;
    }

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Write PID file
    if (!write_pid_file(opt_pid_file)) {
        return 1;
    }

    // Register cleanup for PID file
    atexit(remove_pid_file);

    return run_interactive_mode();
}

/**
 * Interactive mode - main proxy operation
 */
static int run_interactive_mode(void) {
    GError *error = NULL;

    // Initialize context
    g_context = deadlight_context_new();
    if (!g_context) {
        g_error("Failed to create Deadlight context");
        return 1;
    }

    // Load configuration
    if (!deadlight_config_load(g_context, opt_config_file, &error)) {
        g_error("Failed to load configuration: %s", error->message);
        g_error_free(error);
        return 1;
    }

    // Override port if specified
    if (opt_port > 0) {
        deadlight_config_set_int(g_context, "core", "port", opt_port);
    }

    // Set log level
    if (opt_verbose) {
        deadlight_config_set_string(g_context, "core", "log_level", "debug");
    }

    // Initialize logging
    if (!deadlight_logging_init(g_context, &error)) {
        g_error("Failed to initialize logging: %s", error->message);
        g_error_free(error);
        return 1;
    }

    // Print startup banner
    if (!opt_daemon) {
        print_banner();
    }

    deadlight_protocols_init(g_context);

    // Initialize core systems
    g_info("Initializing Deadlight systems...");

    if (!deadlight_network_init(g_context, &error)) {
        g_error("Failed to initialize network: %s", error->message);
        g_error_free(error);
        return 1;
    }

    if (!deadlight_ssl_init(g_context, &error)) {
        g_error("Failed to initialize SSL: %s", error->message);
        g_error_free(error);
        return 1;
    }

    if (!deadlight_plugins_init(g_context, &error)) {
        g_error("Failed to initialize plugins: %s", error->message);
        g_error_free(error);
        return 1;
    }

    gboolean vpn_enabled = deadlight_config_get_bool(g_context, "vpn", "enabled", FALSE);
    if (vpn_enabled) {
        g_info("VPN gateway is enabled in configuration");
        
        // Allocate VPN manager structure
        g_context->vpn = g_new0(DeadlightVPNManager, 1);
        g_context->vpn->context = g_context;
        g_context->vpn->tun_fd = -1;
        g_context->vpn->total_connections = 0;
        g_context->vpn->active_connections = 0;
        g_context->vpn->bytes_sent = 0;
        g_context->vpn->bytes_received = 0;
        
        if (!deadlight_vpn_gateway_init(g_context, &error)) {
            g_warning("Failed to initialize VPN gateway: %s", error->message);
            g_warning("Continuing without VPN functionality");
            g_clear_error(&error);
            
            g_free(g_context->vpn);
            g_context->vpn = NULL;
        } else {
            g_info("VPN initialized successfully");
        }
    } else {
        g_debug("VPN gateway is disabled (set vpn.enabled=true to enable)");
    }
#ifdef ENABLE_UI
    g_info("Starting UI server...");
    start_ui_server(g_context);
#endif

    // Set up signal handlers
    g_unix_signal_add(SIGINT, signal_handler, g_context);
    g_unix_signal_add(SIGTERM, signal_handler, g_context);

    // Start listening
    gint port = deadlight_config_get_int(g_context, "core", "port", 8080);
    g_info("Starting proxy on port %d", port);

    if (!deadlight_network_start_listener(g_context, port, &error)) {
        g_error("Failed to start listener: %s", error->message);
        g_error_free(error);
        return 1;
    }

    // Print configuration info
    if (!opt_daemon) {
        g_print("\nDeadlight Proxy is ready!\n");
        g_print("Listening on port %d\n", port);
        g_print("Configuration file: %s\n",
                opt_config_file ? opt_config_file : "default");
        g_print("Plugins loaded: %d\n",
                deadlight_plugins_count(g_context));

        /* Test commands for all protocols */
        g_print("\nTest commands:\n");

        // HTTP
        g_print("  # HTTP\n");
        g_print("  curl -x http://localhost:%d http://example.com\n", port);

        // HTTPS (trust the local CA)
        g_print("\n  # HTTPS\n");
        g_print("  curl --cacert ~/.deadlight/ca.crt -x http://localhost:%d https://example.com\n", port);

        // SOCKS4
        g_print("\n  # SOCKS4\n");
        g_print("  curl --socks4 localhost:%d http://example.com\n", port);

        // SOCKS5
        g_print("\n  # SOCKS5\n");
        g_print("  curl --socks5 localhost:%d http://example.com\n", port);

        // SMTP handshake
        g_print("\n  # SMTP\n");
        g_print("  printf \"HELO test.com\\r\\n\" | nc localhost %d\n", port);

        // IMAP NOOP
        g_print("\n  # IMAP (NOOP)\n");
        g_print("  printf \"A001 NOOP\\r\\n\" | nc localhost %d\n", port);

        // IMAP STARTTLS (explicit)
        g_print("\n  # IMAP STARTTLS\n");
        g_print("  openssl s_client -connect localhost:%d -starttls imap -crlf\n", port);

        // IMAPS Secure Tunnel
        g_print("\n  # IMAPS tunnel using telnet\n");
        g_print("  telnet localhost 8080\n");
        g_print("\n  # Once connected, type the following and press Enter:\n");
        g_print("  A001 NOOP\n");

        // Websocket
        g_print("\n  # WebSocket\n");
        g_print("  curl -v --proxy http://localhost:8080 -H \"Upgrade: websocket\" http://ws.ifelse.io/\n\n");

        // FTP
        g_print("  # FTP with netcat:\n");
        g_print("  printf \"USER anonymous\\r\\n\" | nc localhost 8080\n\n");

        // VPN
        if (g_context->vpn) {
            g_print("  # VPN Gateway (requires root/CAP_NET_ADMIN):\n");
            g_print("  # Configure client to use 10.8.0.1 as gateway\n");
            g_print("  sudo ip route add default via 10.8.0.1 dev tun0\n");
            g_print("  curl http://example.com  # Traffic goes through proxy!\n\n");
        }

        g_print("\nPress Ctrl+C to stop\n\n");
    }

    // Run main loop
    g_context->main_loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(g_context->main_loop);

    // Cleanup
    g_info("Shutting down...");
    
    // Cleanup VPN if active
    if (g_context->vpn) {
        deadlight_vpn_gateway_cleanup(g_context);
    }
    
    deadlight_network_stop(g_context);
    deadlight_plugins_cleanup(g_context);
    deadlight_ssl_cleanup(g_context);

#ifdef ENABLE_UI
    g_info("Stopping UI server...");
    stop_ui_server();
#endif

    g_info("Deadlight proxy stopped");
    return 0;
} 
/**
 * Print startup banner
 */
static void print_banner(void) {
    g_print("\n");
    g_print("======================================================\n");
    g_print("                                                      \n");
    g_print("              Deadlight Proxy v1.0                   \n");
    g_print("                                                      \n");
    g_print("     Modular - Extensible - High Performance         \n");
    g_print("                                                      \n");
    g_print("======================================================\n");
    g_print("\n");
}

/**
 * Print usage information
 */
static void print_usage(void) {
    g_print("Deadlight Proxy v1.0 - Modular HTTP/HTTPS Proxy\n\n");
    g_print("Usage: deadlight [OPTIONS]\n\n");
    g_print("Options:\n");
    g_print("  -d, --daemon           Run as daemon\n");
    g_print("  -v, --verbose          Verbose output\n");
    g_print("  -c, --config FILE      Configuration file\n");
    g_print("  -p, --port PORT        Listen port (overrides config)\n");
    g_print("      --pid-file FILE    PID file for daemon mode\n");
    g_print("  -t, --test MODULE      Test specific module\n");
    g_print("      --test-mode        Enable test mode\n");
    g_print("  -h, --help             Show this help\n\n");
    g_print("Test modules:\n");
    g_print("  all, config, logging, network, protocols, ssl, plugins\n\n");
    g_print("Examples:\n");
    g_print("  deadlight -p 8080                    # Start on port 8080\n");
    g_print("  deadlight -d --pid-file /tmp/dl.pid  # Run as daemon\n");
    g_print("  deadlight -t all                     # Run all tests\n");
    g_print("  deadlight -t network                 # Test network module\n");
    g_print("\n");
}

/**
 * Main entry point
 */
int main(int argc, char *argv[]) {
    /* enable Unicode output if LANG is UTF-8 capable */
    setlocale(LC_ALL, "");

    GError *error = NULL;
    GOptionContext *context;

    // Initialize GLib
    g_log_set_default_handler(deadlight_log_handler, NULL);

    // Parse command line arguments
    context = g_option_context_new("- HTTP/HTTPS Proxy");

    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_set_description(context,
        "Deadlight Proxy v1.0 - A modular, extensible proxy server\n"
        "Built with GNU/GLib for robustness and performance");

    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr("Option parsing failed: %s\n", error->message);
        g_error_free(error);
        g_option_context_free(context);
        return 1;
    }
    
    g_option_context_free(context);

    // Handle help separately (GOptionContext doesn't handle it well)
    if (argc > 1 && (g_strcmp0(argv[1], "-h") == 0 ||
                     g_strcmp0(argv[1], "--help") == 0)) {
        print_usage();
        return 0;
    }

    // Test mode
    if (opt_test_module) {
        int result = run_tests(opt_test_module);
        cleanup_and_exit(result);
    }

    // Daemon mode
    if (opt_daemon) {
        return run_daemon_mode();
    }

    // Interactive mode
    return run_interactive_mode();
}