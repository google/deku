// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

const (
	// Cache dir
	CACHE_DIR = "$HOME/.cache/deku"

	// Default name for workdir
	DEFAULT_WORKDIR = "workdir"

	// File with path to object file from kernel/module build directory
	FILE_OBJECT_PATH = "obj"

	// File with source file path
	FILE_SRC_PATH = "path"

	// File for note in module
	NOTE_FILE = "note"

	// Dir with kernel's object symbols
	SYMBOLS_DIR = "symbols"

	// Configuration file
	CONFIG_FILE = "$workdir/config"

	// Template for DEKU module suffix
	MODULE_SUFFIX_FILE = "resources/module_suffix_tmpl.c"

	// DEKU script to reload modules
	DEKU_RELOAD_SCRIPT = "deku_reload.sh"

	// Prefix for functions that manages DEKU
	DEKU_FUN_PREFIX = "__deku_fun_"

	// Prefix for symbols to reference to origin patch
	DEKU_PATCH_REF_SYM_PREFIX = "__deku_patch_ref_"

	// Local kernel version
	KERNEL_VERSION = "version"

	// Local kernel release
	KERNEL_RELEASE = "release"

	// Hash from kernel config hash
	KERNEL_CONFIG_HASH = "configHash"

	// Commands script dir
	COMMANDS_DIR = "command"

	// Kernel sources install dir
	KERN_SRC_INSTALL_DIR = ""

	// Current DEKU version hash
	DEKU_HASH = "hash"

	// Remote directory with deku modules
	REMOTE_DIR = "deku"

	// File with modified symbols in patch
	MOD_SYMBOLS_FILE = "sym"

	// Directory with patched sources
	PATCHED_SOURCES_DIR = "patched_sources"

	// File with file paths and their id
	FILES_ID = "files"

	// File list of sources file built-in vmlinux
	VMLINUX_FILES_LIST = "vmlinux.list"

	// File list of sources file built as module
	MODULES_FILES_LIST = "modules.list"
)

const (
	RED    = "\x1b[31m"
	GREEN  = "\x1b[32m"
	ORANGE = "\x1b[33m"
	BLUE   = "\x1b[34m"
	NC     = "\x1b[0m" // No Color
)

type Config struct {
	buildDir          string
	crosBoard         string
	crosPath          string
	deployParams      string
	deployType        string
	filesSrcDir       string
	ignoreCross       bool
	isCros            bool
	isAARCH64		  bool
	kernSrcInstallDir string
	kernelSrcDir      string
	kernelVersion     uint64
	linuxHeadersDir   string
	modulesDir        string
	patches           []string
	sshOptions        string
	systemMap         string
	useLLVM           string
	workdir           string
}
