// src/plugins/meshtastic.h
#ifndef DEADLIGHT_MESHTASTIC_H
#define DEADLIGHT_MESHTASTIC_H

#pragma once

#include "core/plugins.h"
#include "core/logging.h"

#include "mesh.pb.h"
#include "channel.pb.h"
#include "portnums.pb.h"

#include <glib.h>
#include <gio/gio.h>

// Nanopb includes
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

typedef enum {
    MESHTASTIC_MODE_CLIENT = 0,
    MESHTASTIC_MODE_GATEWAY = 1,
} MeshtasticMode;

typedef struct {
    DeadlightContext *context;   // Back-pointer for config/logging
    GIOChannel *serial_channel;  // Serial connection to Meshtastic node
    GThread *reader_thread;      // Thread for reading FromRadio packets
    GMutex mutex;                // For thread-safe access
    gpointer reassembly;         // MeshtasticReassemblyTable* (opaque to avoid include cycles)
    guint chunk_data_max;        // max bytes per chunk (payload minus transport header)

    // Client-mode response correlation (session_id -> GAsyncQueue*)
    GHashTable *pending;
    GMutex pending_mutex;
    guint64 next_session_id;

    // Gateway-mode: handle incoming requests off the serial reader thread
    GThreadPool *gateway_pool;
    gchar *serial_device;        // e.g., /dev/ttyUSB0
    gchar *channel_name;         // e.g., "LongFast"
    gint channel_index;          // preferred channel selector (0-based)
    guint32 gateway_node_id;     // client-mode destination node id
    uint32_t custom_port;        // Custom PORTNUM for data (e.g., 100)
    MeshtasticMode mode;
    gboolean enabled;
    volatile gboolean running;   // For thread shutdown
} MeshtasticData;

// Plugin exports
gboolean deadlight_meshtastic_init(DeadlightContext *context);
void deadlight_meshtastic_cleanup(DeadlightContext *context);

#endif // DEADLIGHT_MESHTASTIC_H