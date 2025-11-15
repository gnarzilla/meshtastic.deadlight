#ifndef DEADLIGHT_SOCKS_H
#define DEADLIGHT_SOCKS_H

#include "../core/deadlight.h"

#ifdef __cplusplus
extern "C" {
#endif

// Register the SOCKS protocol handler with the core system
void deadlight_register_socks_handler(void);

#ifdef __cplusplus
}
#endif

#endif // DEADLIGHT_SOCKS_H