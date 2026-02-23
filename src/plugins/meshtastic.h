/**
 * deadmesh - Meshtastic Transport Plugin Header
 *
 * Public surface is intentionally minimal — the plugin registers itself
 * via deadlight_plugin_get_info() and everything else is internal.
 *
 * Types that were previously here have moved:
 *   MeshtasticData   -> internal to meshtastic.c (MeshtasticPlugin)
 *   MeshtasticChunk  -> encoded inline in send_chunk(), not a public struct
 *   MeshSession      -> src/mesh/mesh_session.h
 *   MeshFrame        -> src/mesh/mesh_framing.h
 */

#ifndef DEADMESH_MESHTASTIC_PLUGIN_H
#define DEADMESH_MESHTASTIC_PLUGIN_H

#include <glib.h>
#include "core/plugins.h"
#include "core/deadlight.h"

/* nanopb + Meshtastic protobufs */
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "mesh.pb.h"
#include "channel.pb.h"
#include "portnums.pb.h"

/* Transport layers */
#include "mesh_framing.h"
#include "mesh_session.h"

/**
 * Plugin entry point — called by the plugin loader.
 * Populates *plugin with the static plugin descriptor.
 */
G_MODULE_EXPORT gboolean deadlight_plugin_get_info(DeadlightPlugin **plugin);

#endif /* DEADMESH_MESHTASTIC_PLUGIN_H */