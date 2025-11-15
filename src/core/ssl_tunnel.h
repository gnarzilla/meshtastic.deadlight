// src/core/ssl_tunnel.h
#ifndef SSL_TUNNEL_H
#define SSL_TUNNEL_H

#include "deadlight.h" // For DeadlightConnection and GError
gboolean start_ssl_tunnel_blocking(DeadlightConnection *conn, GError **error);

#endif // SSL_TUNNEL_H