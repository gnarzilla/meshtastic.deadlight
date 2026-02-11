# Deadlight Proxy v1.0 - Makefile
# Build system for the modular proxy server

#=============================================================================
# Project Configuration
#=============================================================================
PROJECT = deadlight
VERSION = 1.0.0
PREFIX = /usr/local

#=============================================================================
# Compiler Configuration
#=============================================================================
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -O2 -g
LDFLAGS = -Wl,--as-needed
LIBS = -lssl -lcrypto -lpthread

# Package config for GLib/GIO
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0 gmodule-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0 gmodule-2.0)

# Combined flags
ALL_CFLAGS = $(CFLAGS) $(GLIB_CFLAGS) -DDEADLIGHT_VERSION=\"$(VERSION)\" -Isrc
ALL_LIBS = $(LIBS) $(GLIB_LIBS)

#=============================================================================
# Directory Structure
#=============================================================================
OBJDIR = obj
PLUGINDIR = src/plugins
TESTDIR = src/tests
BINDIR = bin
PLUGIN_BINDIR = $(BINDIR)/plugins

# IMPORTANT: Added src/plugins to VPATH so make finds ratelimiter.c
VPATH = src/core:src/protocols:src/plugins:src/ui:src/vpn

# Installation directories
LIBDIR = $(PREFIX)/lib
CONFDIR = /etc/deadlight
LOGDIR = /var/log/deadlight
CACHEDIR = /var/cache/deadlight

#=============================================================================
# Source Files
#=============================================================================
CORE_SOURCES = main.c config.c context.c logging.c network.c ssl.c \
               protocols.c protocol_detection.c plugins.c request.c \
               utils.c ssl_tunnel.c connection_pool.c

PROTOCOL_SOURCES = http.c imap.c imaps.c socks.c smtp.c websocket.c ftp.c api.c

# NEW: Plugins that are statically linked because Core/API uses them directly
STATIC_PLUGIN_SOURCES = ratelimiter.c

VPN_SOURCES = vpn_gateway.c

# Combine all sources into one list
ALL_SOURCES = $(CORE_SOURCES) $(PROTOCOL_SOURCES) $(STATIC_PLUGIN_SOURCES) $(VPN_SOURCES)

# ==== UI configuration ====
UI ?= 0
ifeq ($(UI),1)
  ALL_CFLAGS += -DENABLE_UI
  ALL_LIBS += $(shell pkg-config --libs libmicrohttpd)
  ALL_SOURCES += ui.c assets.c
endif

#=============================================================================
# Object Files
#=============================================================================

ALL_OBJECTS = $(addprefix $(OBJDIR)/, $(ALL_SOURCES:.c=.o))

#=============================================================================
# Targets
#=============================================================================
MAIN_TARGET = $(BINDIR)/$(PROJECT)
PLUGIN_TARGETS = $(PLUGIN_BINDIR)/adblocker.so \
                 $(PLUGIN_BINDIR)/ratelimiter.so \
                 $(PLUGIN_BINDIR)/meshtastic.so

#=============================================================================
# Build Rules
#=============================================================================

# Default target
all: dirs $(MAIN_TARGET) plugins

# Create necessary directories
dirs:
	@mkdir -p $(OBJDIR) $(BINDIR) $(PLUGIN_BINDIR)

# Main executable
$(MAIN_TARGET): $(ALL_OBJECTS)
	@echo "Linking $(PROJECT)..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(ALL_LIBS)
	@echo "Built $(PROJECT) v$(VERSION)"

# Generic rule for .o files
# Uses VPATH to find .c files in subdirectories
$(OBJDIR)/%.o: %.c
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	@$(CC) $(ALL_CFLAGS) -c $< -o $@

$(OBJDIR)/assets.o: src/ui/assets.c

src/ui/assets.c: src/ui/index.html
ifeq ($(UI),1)
	@echo "Generating UI assets..."
	@xxd -i $< > $@
else
	@:
endif

# Plugin builds
plugins: $(PLUGIN_TARGETS)

$(PLUGIN_BINDIR)/adblocker.so: $(PLUGINDIR)/adblocker.c $(PLUGINDIR)/adblocker.h | $(PLUGIN_BINDIR)
	@echo "Building AdBlocker plugin..."
	@$(CC) $(CFLAGS) $(GLIB_CFLAGS) -DDEADLIGHT_VERSION=\"$(VERSION)\" -Isrc -Isrc/core -fPIC -shared -o $@ $< $(ALL_LIBS)

$(PLUGIN_BINDIR)/ratelimiter.so: $(PLUGINDIR)/ratelimiter.c $(PLUGINDIR)/ratelimiter.h | $(PLUGIN_BINDIR)
	@echo "Building RateLimiter plugin (Shared)..."
	@$(CC) $(CFLAGS) $(GLIB_CFLAGS) -DDEADLIGHT_VERSION=\"$(VERSION)\" -Isrc -Isrc/core -fPIC -shared -o $@ $< $(ALL_LIBS)

# ───────────────────────────────────────────────────────────
# Meshtastic Plugin + Nanopb
# ───────────────────────────────────────────────────────────

NANOPB_DIR      = src/plugins/nanopb
NANOPB_INC      = src/plugins/include/nanopb
PROTO_BASE_DIR  = src/plugins/protobufs
PROTO_DIR       = $(PROTO_BASE_DIR)/meshtastic
GEN_DIR         = src/plugins/meshtastic

NANOPB_SOURCES  = $(NANOPB_DIR)/pb_common.c \
                  $(NANOPB_DIR)/pb_encode.c \
                  $(NANOPB_DIR)/pb_decode.c

NANOPB_CFLAGS   = -I$(NANOPB_INC) \
                  -I$(GEN_DIR) \
                  -I$(GEN_DIR)/meshtastic \
                  -Isrc \
                  -Isrc/core \
                  -Wno-pedantic

PROTO_FILES = $(filter-out $(PROTO_DIR)/deviceonly.proto,$(wildcard $(PROTO_DIR)/*.proto))
MESHTASTIC_PB_C = $(patsubst $(PROTO_DIR)/%.proto,$(GEN_DIR)/meshtastic/%.pb.c,$(PROTO_FILES))
MESHTASTIC_PB_H = $(patsubst $(PROTO_DIR)/%.proto,$(GEN_DIR)/meshtastic/%.pb.h,$(PROTO_FILES))

$(GEN_DIR) $(GEN_DIR)/meshtastic:
	@mkdir -p $(GEN_DIR)/meshtastic

$(GEN_DIR)/meshtastic/%.pb.c $(GEN_DIR)/meshtastic/%.pb.h: $(PROTO_DIR)/%.proto | $(GEN_DIR)/meshtastic
	@echo "Generating nanopb files from $< ..."
	@python3 $(NANOPB_DIR)/generator/nanopb_generator.py \
		-I $(PROTO_BASE_DIR) \
		-D $(GEN_DIR) $<

$(MESHTASTIC_PB_C) $(MESHTASTIC_PB_H): $(PROTO_FILES)

$(PLUGIN_BINDIR)/meshtastic.so: \
		$(PLUGINDIR)/meshtastic.c \
		$(PLUGINDIR)/meshtastic.h \
		$(MESHTASTIC_PB_C) \
		$(NANOPB_SOURCES) \
		| $(PLUGIN_BINDIR)
	@echo "Building MeshtasticTunnel plugin..."
	@$(CC) $(ALL_CFLAGS) $(NANOPB_CFLAGS) -fPIC -shared -o $@ \
		$(PLUGINDIR)/meshtastic.c $(MESHTASTIC_PB_C) $(NANOPB_SOURCES) $(ALL_LIBS)

PLUGIN_TARGETS += $(PLUGIN_BINDIR)/meshtastic.so

#=============================================================================
# Utility Targets
#=============================================================================

clean:
	@echo "Cleaning build files..."
	@rm -rf $(OBJDIR) $(BINDIR)
	@rm -f src/ui/assets.c
	@rm -f $(GEN_DIR)/*.pb.c $(GEN_DIR)/*.pb.h
	@rm -rf $(GEN_DIR)
	@echo "Clean complete"

run: $(MAIN_TARGET)
	@echo "Running $(PROJECT)..."
	@./$(MAIN_TARGET) -v

run-vpn: $(MAIN_TARGET)
	@echo "Running $(PROJECT) with VPN gateway (requires root)..."
	@sudo ./$(MAIN_TARGET) -v

.PHONY: all dirs clean run run-vpn plugins