// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed resources
var resources embed.FS

var USE_EXTERNAL_EXECUTABLE = false
var TOOLCHAIN = ""
var MinKernelVersion = "5.4"

func checkWorkdir() {
	workdirCfgFile, err := os.ReadFile(config.workdir + "config")
	workdirCfg := map[string]string{}

	if err != nil {
		LOG_DEBUG("%s", err)
		goto sync
	}

	json.Unmarshal(workdirCfgFile, &workdirCfg)

	if workdirCfg[KERNEL_VERSION] != getKernelVersion() ||
		workdirCfg[KERNEL_RELEASE] != getKernelReleaseVersion() ||
		workdirCfg[KERNEL_CONFIG_HASH] != getKernelConfigHash() ||
		workdirCfg[KERNEL_BUILD_DIR] != config.buildDir {
		goto sync
	}

	if config.kernSrcInstallDir != "" {
		kernStat, err := os.Stat(config.kernSrcInstallDir)
		if err != nil {
			LOG_ERR(err, "Can't get stats for file: %s", config.kernSrcInstallDir)
			goto sync
		}

		cfgStat, err := os.Stat(config.workdir + "config")
		if err != nil {
			LOG_ERR(err, "Can't get stats for file: %s", config.workdir+"config")
			goto sync
		}

		if !kernStat.ModTime().Equal(cfgStat.ModTime()) {
			goto sync
		}
	}

	if workdirCfg[DEKU_HASH] != generateDEKUHash() {
		goto sync
	}

	return
sync:
	synchronize()
}

func prepareConfig() int {
	var init Init
	cfg, lastArgIndex, err := init.init()
	if err != nil {
		LOG_ERR(err, "Error")
		os.Exit(errorStrToCode(err))
	}

	config = cfg

	ver := strings.Split(getKernelReleaseVersion(), ".")
	minVer := strings.Split(MinKernelVersion, ".")
	verMajor, err := strconv.ParseInt(ver[0], 10, 0)
	if err != nil {
		LOG_ERR(err, "Failed to parse kernel release major version")
		os.Exit(1)
	}

	verMinor, err := strconv.ParseInt(ver[1], 10, 0)
	if err != nil {
		LOG_ERR(err, "Failed to parse kernel release minor version")
		os.Exit(1)
	}

	minVerMajor, err := strconv.ParseInt(minVer[0], 10, 0)
	if err != nil {
		LOG_ERR(err, "Failed to parse minimum supported kernel major version")
		os.Exit(1)
	}

	minVerMinor, err := strconv.ParseInt(minVer[1], 10, 0)
	if err != nil {
		LOG_ERR(err, "Failed to parse minimum supported kernel minor version")
		os.Exit(1)
	}

	config.kernelVersion = versionNum(uint64(verMajor), uint64(verMinor), 0)

	if config.kernelVersion <
		versionNum(uint64(minVerMajor), uint64(minVerMinor), 0) {
		LOG_WARN("Kernel version: %s is not supported\nMinimum supported kernel version: %s",
			getKernelReleaseVersion(), MinKernelVersion)
		os.Exit(1)
	}

	checkWorkdir()

	return lastArgIndex
}

func printUsage() {
	text :=
		`Usage:
./deku -b <PATH_TO_BUILD_DIR> --target <USER@DUT_ADDRESS[:PORT]> [COMMAND]

Commands list:
    deploy [default]                      deploy the changes to the device. This is default command.
    livepatch                             build livepatch module.
    sync                                  synchronize information about kernel source code.
                                          It is recommended after fresh building the kernel to
                                          improve the reliability of DEKU, although it is not
                                          mandatory. However, when using the --src_inst_dir
                                          parameter, running this command after building the kernel
                                          is unnecessary, as DEKU's reliability is already enhanced
                                          by this parameter.

Available parameters:
    -b, --builddir                        path to kernel or out-of-tree module build directory.
    -k, --headersdir                      path to the kernel headers directory for the out-of-tree
                                          module in case the DEKU can't find the kernel headers.
                                          This is the same parameter as the -C parameter for the
                                          "make" command in the Makefile.
    -s, --sourcesdir                      path to the kernel source directory. Use this parameter if
                                          DEKU can't find the kernel sources directory.
    -p, --patch                           patch file from which to generate livepatch module or
                                          apply changes to the device.
    --android_kernel                      path to main android kernel directory. It usually points
                                          to the "android-kernel" directory.
    --target=<USER@DUT_ADDRESS[:PORT]>    SSH connection parameter to the target device. The given
                                          user must be able to load and unload kernel modules. The
                                          SSH must be configured to use key-based authentication.
                                          Below is an example with this parameter.
    --ssh_options=<"-o ...">              options for SSH. Below is an example with this parameter.
    --src_inst_dir=<PATH>                 directory with the kernel sources that were installed
                                          after the kernel was built. Having this directory makes
                                          DEKU working more reliable. As an alternative to this
                                          parameter, the 'deku sync' command can be executed after
                                          the kernel has been built to make DEKU work more reliably.

-v, --verbose                             turn verbose mode.
-h, -?, --help                            print this information.
`
	println(text)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	for _, arg := range os.Args {
		if arg == "-v" || arg == "--verbose" {
			LOG_LEVEL = 1
		} else if arg == "-h" || arg == "--help" || arg == "-?" {
			printUsage()
			os.Exit(0)
		}
	}

	lastArgIndex := prepareConfig()

	os.RemoveAll(config.workdir + PATCHED_SOURCES_DIR)

	var err error
	if len(config.patches) > 0 {
		os.MkdirAll(config.workdir+PATCHED_SOURCES_DIR, 0755)
		err := prepareSourcesForPatch(config.patches)
		if err != nil {
			os.Exit(1)
		}
	}

	action := "deploy"
	if lastArgIndex < len(os.Args)-1 {
		action = os.Args[len(os.Args)-1]
	}

	if action == "deploy" {
		if config.deployParams != "" {
			err = CheckDeviceConnection()
			if err != nil {
				LOG_ERR(nil, "Failed to connect to the device: %s", config.deployParams)
			}
		}

		if err == nil {
			err = deploy()
		}
	} else if action == "livepatch" {
		var module dekuModule
		module, err = build([]dekuModule{})
		if err == nil && isModuleValid(module) {
			outFile := filepath.Base(module.KoFile)
			copyFile(module.KoFile, outFile)
			LOG_INFO("Livepatch module was built: %s", outFile)
		}
	} else if action == "sync" {
		synchronize()
	} else {
		LOG_ERR(nil, "Invalid command: %s.\nUse --help parameter to see valid usage", action)
		os.Exit(1)
	}

	// restore workdir permissions if deku is running from sudo
	if os.Getuid() == 0 && config.workdir != "" {
		uid, uidErr := strconv.Atoi(os.Getenv("SUDO_UID"))
		gid, gitErr := strconv.Atoi(os.Getenv("SUDO_GID"))
		if uidErr == nil && gitErr == nil {
			err := filepath.Walk(config.workdir, func(path string, _ os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				err = os.Chown(path, uid, gid)
				if err != nil {
					LOG_INFO("Failed to restore permissions in workspace for %s. %s", path, err)
				}

				return nil
			})

			if err != nil {
				LOG_INFO("An error has occur during restore permissions in workspace for %s", err)
			}
		}
	}

	if err != nil {
		os.Exit(errorStrToCode(err))
	}
}
