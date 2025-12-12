// src/plugins/meshtastic_http_bridge.h
#ifndef MESHTASTIC_HTTP_BRIDGE_H
#define MESHTASTIC_HTTP_BRIDGE_H

#include <glib.h>
#include "meshtastic.h"
#include "meshtastic_transport.h"

/**
 * Client-mode: forward a local HTTP request over mesh and write the response back to client.
 * Returns TRUE if the plugin handled the request (success or failure response written),
 * FALSE if the caller should fall back to normal proxy behavior.
 */
gboolean meshtastic_client_forward_http(MeshtasticData *data, DeadlightRequest *request);

/**
 * Gateway-mode: handle a reassembled request received from a mesh client.
 * This function is intended to run in a worker thread.
 */
void meshtastic_gateway_handle_http_request(MeshtasticData *data,
                                            guint32 from_node_id,
                                            guint64 session_id,
                                            GByteArray *request_bytes);

#endif // MESHTASTIC_HTTP_BRIDGE_H


