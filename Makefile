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
CFLAGS ?=
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
GOFLAGS ?=
# BINUTILS_DEV_PATH is used when target kernel is AARCH64
BINUTILS_DEV_PATH ?=
# TOOLCHAIN is for a case when DEKU will be used on x86 host and target kernel is AARCH64.
TOOLCHAIN ?=

# Sources and objects
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

# Phony targets
.PHONY: all debug clean

all: $(BUILD_DIR) $(OBJECTS) $(BUILD_DIR)/$(LIB_NAME) elfutils mklivepatch deku

debug: GOFLAGS += -gcflags=all="-N -l"
debug: CFLAGS += -g
debug: all

# Handle case where target kernel is AARCH64 but host will be x86
ifeq ($(ARCH),AARCH64)
ifeq ($(TOOLCHAIN),)
COMPILER := $(shell which aarch64-linux-gnu-gcc 2>/dev/null || \
                  which aarch64-unknown-linux-gnu-gcc 2>/dev/null || \
                  which aarch64-cros-linux-gnu-gcc 2>/dev/null)
ifeq ($(COMPILER),)
$(error No AArch64 cross compiler found)
endif
TOOLCHAIN := $(shell echo $(COMPILER) | sed 's/gcc$$//' | xargs basename)
$(info Found local toolchain: $(TOOLCHAIN))
endif

ifeq ($(BINUTILS_DEV_PATH),)
BINUTILS_DEV_PATH := $(shell ldconfig -p 2>/dev/null | grep libbfd.so | \
                   grep -e aarch64 -e arm64 | head -1 | awk '{print $$4}' | xargs dirname 2>/dev/null)
ifeq ($(BINUTILS_DEV_PATH),)
TOOLCHAIN_DIR := $(shell echo $(TOOLCHAIN) | sed 's/-$$//' | xargs basename)
BINUTILS_DEV_PATH := $(shell find /usr/ -name "libbfd*.so" | grep -m 1 $(TOOLCHAIN_DIR) | xargs dirname)
endif
$(info Found dev binutils path: $(BINUTILS_DEV_PATH))
endif

CPPFLAGS += -I$(BINUTILS_DEV_PATH)/include -DAARCH64
LDFLAGS += -Wl,-rpath=$(BINUTILS_DEV_PATH) -L$(BINUTILS_DEV_PATH)
endif

CPPFLAGS += -DTOOLCHAIN=\"$(TOOLCHAIN)\"
LDLIBS += -lbfd -lopcodes -liberty -lelf
GOFLAGS += -ldflags '-X main.TOOLCHAIN=$(TOOLCHAIN)'

DISASSEMBLY_STYLE_SUPPORT := $(shell echo "void t() { init_disassemble_info(NULL, 0, NULL); }" | \
                               $(CC) -DPACKAGE=1 -include dis-asm.h -S -o - -x c - > /dev/null 2>&1 && echo 0 || echo 1)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $@

# Build rules
mklivepatch: $(SRC_DIR)/mklivepatch.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DUSE_AS_LIB -DDISASSEMBLY_STYLE_SUPPORT=$(DISASSEMBLY_STYLE_SUPPORT) -c $< -o $@
	@go clean -cache
	@rm -f deku

$(BUILD_DIR)/$(LIB_NAME): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

elfutils: $(SRC_DIR)/elfutils.c $(BUILD_DIR)/$(LIB_NAME)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDFLAGS) $(LDLIBS) -o $@

deku: $(BUILD_DIR)/$(LIB_NAME) $(shell find $(SRC_DIR)/go/ -iname "*.go")
	CGO_LDFLAGS="$(LDFLAGS) $(LDLIBS) ../../$(BUILD_DIR)/$(LIB_NAME)" \
	go build -C $(SRC_DIR)/go $(GOFLAGS) -o ../../$@ $(shell cd $(SRC_DIR)/go && find . -iname "*.go")

# Cleaning up
clean::
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR) mklivepatch elfutils deku
