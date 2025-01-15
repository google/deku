# Copyright (c) 2024 Google LLC
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include *.mk

SRC_DIR := src
BUILD_DIR := build
LIB_NAME := libelfutils.a

# Compiler and linker defaults
CC ?= gcc
AR ?= ar
LDFLAGS ?=
CFLAGS ?=
GOFLAGS ?=

LDFLAGS += -lbfd -lopcodes -liberty -lelf

# Sources and objects
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

# Phony targets
.PHONY: all debug clean

all: $(BUILD_DIR) $(OBJECTS) $(BUILD_DIR)/$(LIB_NAME) elfutils mklivepatch deku

debug: GOFLAGS += -gcflags=all="-N -l"
debug: CFLAGS += -g
debug: all

# Find toolchain if target is AARCH64
ifeq ($(ARCH),AARCH64)
CROSS_COMPILE := $(shell which aarch64-linux-gnu-gcc 2>/dev/null || \
                  which aarch64-unknown-linux-gnu-gcc 2>/dev/null || \
                  which aarch64-cros-linux-gnu-gcc 2>/dev/null)
ifeq ($(CROSS_COMPILE),)
$(error No AArch64 cross compiler found)
endif

TOOLCHAIN := $(shell echo $(CROSS_COMPILE) | sed 's/-gcc$$//' | xargs basename)
BINUTILS_PATH := $(shell ldconfig -p 2>/dev/null | grep libbfd.so | \
                   grep -e aarch64 -e arm64 | head -1 | awk '{print $$4}' | xargs dirname 2>/dev/null)
ifeq ($(BINUTILS_PATH),)
BINUTILS_PATH := $(shell find /usr/ -name "libbfd*.so" | grep -m 1 $(TOOLCHAIN) | xargs dirname)
endif

CFLAGS += -I$(BINUTILS_PATH)/include -DAARCH64
LDFLAGS += -Wl,-rpath=$(BINUTILS_PATH) -L$(BINUTILS_PATH)
TOOLCHAIN := $(TOOLCHAIN)-
endif

CFLAGS += -DTOOLCHAIN=\"$(TOOLCHAIN)\"
GOFLAGS += -ldflags '-X main.TOOLCHAIN=$(TOOLCHAIN)'

# Create build directory
$(BUILD_DIR):
	@mkdir -p $@

# Build rules
mklivepatch: $(SRC_DIR)/mklivepatch.c
	$(CC) $(CFLAGS) $< -lelf -o $@

DISASSEMBLY_STYLE_SUPPORT := $(shell echo "void t() { init_disassemble_info(NULL, 0, NULL); }" | \
                               $(CC) -DPACKAGE=1 -include dis-asm.h -S -o - -x c - > /dev/null 2>&1 && echo 0 || echo 1)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DUSE_AS_LIB -DDISASSEMBLY_STYLE_SUPPORT=$(DISASSEMBLY_STYLE_SUPPORT) -c $< -o $@
	@go clean -cache
	@rm -f deku

$(BUILD_DIR)/$(LIB_NAME): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

elfutils: $(SRC_DIR)/elfutils.c $(BUILD_DIR)/$(LIB_NAME)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

deku: $(BUILD_DIR)/$(LIB_NAME) $(shell find $(SRC_DIR)/go/ -iname "*.go")
	go build -C $(SRC_DIR)/go $(GOFLAGS) -o ../../$@ $(shell cd $(SRC_DIR)/go && find . -iname "*.go")

# Cleaning up
clean::
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR) mklivepatch elfutils deku
