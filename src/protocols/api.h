#ifndef DEADLIGHT_API_H
#define DEADLIGHT_API_H

#include "../core/deadlight.h"

void deadlight_register_api_handler(void);
DeadlightHandlerResult api_handle_prometheus_metrics(DeadlightConnection *conn, GError **error);

#endif
