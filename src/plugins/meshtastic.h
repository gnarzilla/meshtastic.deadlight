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

typedef struct {
    GIOChannel *serial_channel;  // Serial connection to Meshtastic node
    GThread *reader_thread;      // Thread for reading FromRadio packets
    GMutex mutex;                // For thread-safe access
    GHashTable *reassembly;      // conn_id -> GByteArray* (chunk collector)
    gchar *serial_device;        // e.g., /dev/ttyUSB0
    gchar *channel_name;         // e.g., "LongFast"
    uint32_t custom_port;        // Custom PORTNUM for data (e.g., 100)
    gboolean enabled;
    volatile gboolean running;   // For thread shutdown
} MeshtasticData;

// Chunk header for custom data (simple struct, encode as PB payload)
typedef struct {
    uint32_t seq_num;
    uint32_t total_chunks;
    uint8_t payload[220];        // Max payload
    size_t payload_len;
} MeshtasticChunk;

// Plugin exports
gboolean deadlight_meshtastic_init(DeadlightContext *context);
void deadlight_meshtastic_cleanup(DeadlightContext *context);

#endif // DEADLIGHT_MESHTASTIC_H