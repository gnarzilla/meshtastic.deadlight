#ifndef DEADLIGHT_UTILS_H
#define DEADLIGHT_UTILS_H

#include <glib.h>
#include "deadlight.h" 


gboolean deadlight_parse_host_port(const gchar *host_port, gchar **host, guint16 *port);
gchar* get_external_ip(void);
gchar* deadlight_format_bytes(guint64 bytes);
gchar* deadlight_format_duration(gint64 seconds);

#endif // DEADLIGHT_UTILS_H
