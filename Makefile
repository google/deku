#!/bin/bash
# Copyright (c) 2024 Google LLC
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include *.mk

SRC_DIR:=src
BUILD_DIR:=build
LIB_NAME:=libelfutils.a

# Find all .c files in src directory
SOURCES:=$(wildcard $(SRC_DIR)/*.c)
# Generate corresponding .o file names in build directory
OBJECTS:=$(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

all: $(BUILD_DIR) $(OBJECTS) $(BUILD_DIR)/$(LIB_NAME) elfutils mklivepatch deku

C_DEBUG_FLAG:=
GO_DEBUG_FLAG:=
ifdef debug
	C_DEBUG_FLAG:=-g
	GO_DEBUG_FLAG:=-gcflags=all="-N -l"
endif

CC?=gcc
CFLAGS:=$(C_DEBUG_FLAG)
LDFLAGS:=-lbfd -lopcodes -liberty -lelf
TOOLCHAIN:=

ifeq ($(ARCH),AARCH64)
	CROSS_COMPILE:=$(shell which aarch64-linux-gnu-gcc 2>/dev/null || which aarch64-unknown-linux-gnu-gcc 2>/dev/null || which aarch64-cros-linux-gnu-gcc 2>/dev/null)
	ifeq ($(CROSS_COMPILE),)
		$(error No AArch64 cross compiler found)
	endif

	TOOLCHAIN:=$(shell echo $(CROSS_COMPILE) | sed 's/-gcc$$//' | xargs basename)
	BINUTILS_PATH:=$(shell ldconfig -p 2>/dev/null | grep libbfd.so | grep -e aarch64 -e arm64 | head -1 | awk '{print $$4}' | xargs dirname 2>/dev/null)
	ifeq ($(BFD_PATH),)
		BINUTILS_PATH:=$(shell find /usr/ -name "libbfd*.so" | grep -m 1 $(TOOLCHAIN) | xargs dirname)
	endif

	CFLAGS:=-I$(BINUTILS_PATH)/include $(CFLAGS) -DAARCH64
	LDFLAGS:=-Wl,-rpath=$(BINUTILS_PATH) -L$(BINUTILS_PATH) $(LDFLAGS)
	TOOLCHAIN:=$(TOOLCHAIN)-
endif

CFLAGS:=$(CFLAGS) -DTOOLCHAIN=\"$(TOOLCHAIN)\"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

mklivepatch: src/mklivepatch.c
	$(CC) $< $(CFLAG) -lelf -o $@

DISASSEMBLY_STYLE_SUPPORT = $(shell echo "void t() { init_disassemble_info(NULL, 0, NULL); }" | \
							$(CC) -DPACKAGE=1 -include dis-asm.h -S -o - -x c - > /dev/null 2>&1 && echo 0 || echo 1)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -DUSE_AS_LIB -DDISASSEMBLY_STYLE_SUPPORT=$(DISASSEMBLY_STYLE_SUPPORT) -c $< $(LDFLAGS) -o $@
	@go clean -cache
	@rm -f deku

$(BUILD_DIR)/$(LIB_NAME): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

elfutils: src/elfutils.c $(BUILD_DIR)/$(LIB_NAME)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

deku: $(BUILD_DIR)/$(LIB_NAME) $(shell find src/go/ -iname "*.go")
	go build -C src/go -ldflags '-X main.TOOLCHAIN=$(TOOLCHAIN)' $(GO_DEBUG_FLAG) -o ../../$@ $(shell cd src/go/ && find . -iname "*.go")

clean::
	rm -rf $(BUILD_DIR) mklivepatch elfutils deku
