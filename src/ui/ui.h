#ifndef UI_H
#define UI_H

#include "core/deadlight.h"
#include <microhttpd.h>

void start_ui_server(DeadlightContext *context); 

void stop_ui_server(void); 

#endif // UI_H