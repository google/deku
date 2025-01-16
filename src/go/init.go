// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
)

type Init struct {
	params map[string]string
	config Config
}

var cacheDir = "."

func (init *Init) getParam(long, short string) string {
	var value string
	if val, ok := init.params[long]; ok {
		value = val
	} else if val, ok := init.params[short]; ok {
		value = val
	}

	var directories = []string{"builddir", "sourcesdir", "src_inst_dir", "workdir", "cros_sdk"}
	if slicesContains(directories, long) && len(value) > 0 {
		if !filepath.IsAbs(value) {
			if strings.HasPrefix(value, "~/") {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					LOG_ERR(err, "Failed to get user home directory path")
				} else {
					value = filepath.Join(homeDir, value[2:])
				}
			} else {
				currentPath, err := os.Getwd()
				if err != nil {
					LOG_ERR(err, "Fail to fetch current directory")
					currentPath = "."
				}

				value = filepath.Join(currentPath, value)
			}
		}

		if !strings.HasSuffix(value, "/") {
			value += "/"
		}
	}

	return value
}

func (init *Init) parseParameters() int {
	var noValueParams = []string{"--ignore_cros", "-v"}
	var multiFilesParam = []string{"patch", "p"}

	init.params = make(map[string]string)
	prevOpt := ""
	i := 1
	for ; i < len(os.Args); i++ {
		opt := os.Args[i]
		value := ""
		if slicesContains(noValueParams, opt) {
			// Handle parameters without values.
			value = "1"
		} else if strings.Contains(opt, "=") {
			// Handle key=value parameters.
			arr := strings.SplitN(opt, "=", 2)
			opt = arr[0]
			value = arr[1]
		} else if i+1 < len(os.Args) {
			// Handle parameters with potential file values.
			if slicesContains(multiFilesParam, prevOpt) && fileExists(os.Args[i]) {
				opt = prevOpt
				value = os.Args[i]
			} else {
				// Handle regular parameters with values.
				value = os.Args[i+1]
				i++
			}
		} else {
			if slicesContains(multiFilesParam, prevOpt) && fileExists(os.Args[i]) {
				// Handle the case where the last argument is a file for a multi-file parameter.
				opt = prevOpt
				value = os.Args[i]
			} else {
				i--
				break
			}
		}

		opt = strings.TrimLeft(opt, "-")
		if slicesContains(multiFilesParam, opt) {
			init.params[opt] += "," + value
			init.params[opt] = strings.TrimLeft(init.params[opt], ",")
		} else {
			init.params[opt] = value
		}

		prevOpt = opt
	}

	return i
}

func (init *Init) getConfig() (Config, int) {
	lastArgIndex := init.parseParameters()

	var config Config
	config.buildDir = init.getParam("builddir", "b")
	config.kernelSrcDir = init.getParam("sourcesdir", "s")
	config.deployType = init.getParam("deploytype", "d")
	config.sshOptions = init.getParam("ssh_options", "")
	config.kernSrcInstallDir = init.getParam("src_inst_dir", "")
	config.crosBoard = init.getParam("board", "")
	config.workdir = init.getParam("workdir", "w")
	config.crosPath = init.getParam("cros_sdk", "c")
	config.deployParams = init.getParam("target", "")
	config.ignoreCross = init.getParam("ignore_cros", "") == "1"

	patches := init.getParam("patch", "p")
	if patches != "" {
		config.patches = strings.Split(patches, ",")
	}

	if config.deployType == "" {
		config.deployType = "ssh"
	}

	return config, lastArgIndex
}

func (init *Init) isKernelSourcesDir(path string) bool {
	var files = []string{"Kbuild", "Kconfig", "Makefile"}
	for _, file := range files {
		if !fileExists(path + file) {
			return false
		}
	}

	return true
}

func (init *Init) isKernelBuildDir(path string) bool {
	var files = []string{"vmlinux", "System.map", "Makefile", ".config", "include/generated/uapi/linux/version.h"}
	for _, file := range files {
		if !fileExists(path + file) {
			return false
		}
	}

	return true
}

func (init *Init) checkConfigEnabled(linuxHeadersDir, flag string) bool {
	config, err := os.ReadFile(linuxHeadersDir + ".config")
	if err != nil {
		LOG_ERR(err, "Failed to read config file: %s", linuxHeadersDir + ".config")
		return false
	}

	return bytes.Contains(config, []byte(flag+"=y"))
}

func (init *Init) isKlpEnabled(linuxHeadersDir string) bool {
	if !init.checkConfigEnabled(linuxHeadersDir, "CONFIG_LIVEPATCH") {
		LOG_DEBUG("CONFIG_LIVEPATCH is not enabled")
		return false
	}

	systemMap, err := os.ReadFile(linuxHeadersDir + "System.map")
	if err != nil {
		LOG_ERR(err, "Failed to read System.map file: %s", linuxHeadersDir + "System.map")
		return false
	}

	return bytes.Contains(systemMap, []byte("klp_enable_patch"))
}

func populateCrosWorkdir(workdir string) {
	if fileExists(workdir + "/testing_rsa") {
		return
	}

	var GCLIENT_ROOT = "~/chromiumos/"
	copyFile(GCLIENT_ROOT+"/src/third_party/chromiumos-overlay/chromeos-base/chromeos-ssh-testkeys/files/testing_rsa",
		workdir+"/testing_rsa")
	os.Chmod(workdir+"/testing_rsa", 0400)
}

func (init *Init) checkConfigForCros(config *Config) error {
	const tempWorkdirName = "workdir_temp"
	var overrideWorkdir = false
	var baseDir = ""
	if config.crosPath != "" {
		baseDir = config.crosPath + "chroot/"
	}

	insideCros := fileExists("/etc/cros_chroot_version")
	if !insideCros {
		LOG_ERR(nil, "Build kernel for Chromebook outside of CrOS SDK is not supported yet")
		return errors.New("ERROR_INVALID_PARAMETERS")
	}

	if config.workdir == "" {
		workdirName := "workdir_" + config.crosBoard + "/"
		if config.crosBoard == "" {
			workdirName = tempWorkdirName + "/"
		}

		config.workdir = cacheDir + workdirName
		overrideWorkdir = true
	}

	os.MkdirAll(config.workdir, 0755)
	populateCrosWorkdir(config.workdir)

	if config.sshOptions == "" {
		config.sshOptions = " -o IdentityFile=" + config.workdir + "/testing_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -q"
	}

	if config.deployParams != "" && !strings.Contains(config.deployParams, "@") {
		config.deployParams = "root@" + config.deployParams
	}
	config.deployType = "ssh"

	if config.crosBoard == "" {
		var board []byte
		var err error
		if config.deployParams != "" {
			board, err = runSSHCommandWithConfig("cat /etc/lsb-release | grep CHROMEOS_RELEASE_BOARD | cut -d= -f2", *config)
		}
		config.crosBoard = strings.TrimSpace(string(board))

		if config.crosBoard == "" || err != nil {
			LOG_ERR(nil, "Failure to connect to Chromebook and retrieve board name")
			return mkError(ERROR_NO_BOARD_PARAM)
		}

		if overrideWorkdir {
			config.workdir = cacheDir + "workdir_" + config.crosBoard + "/"
			populateCrosWorkdir(config.workdir)
		}
	}

	if !insideCros && !fileExists(config.crosPath) {
		LOG_ERR(nil, "Given cros_sdk path is invalid")
		return errors.New("ERROR_INVALID_PARAMETERS")
	}

	if !fileExists(baseDir + "/build/" + config.crosBoard) {
		LOG_ERR(nil, "Please setup the board using \"setup_board\" command")
		return errors.New("ERROR_BOARD_NOT_EXISTS")
	}

	if config.buildDir != "" {
		LOG_ERR(nil, "-b|--builddir parameter can not be used for Chromebook kernel")
		return errors.New("ERROR_INVALID_PARAMETERS")
	}

	kernDir, err := CrosKernelName(baseDir, *config)
	if err != nil {
		return err
	}

	config.buildDir = filepath.Join(baseDir, "/build/", config.crosBoard, "/var/cache/portage/sys-kernel", kernDir) + "/"

	if config.kernSrcInstallDir == "" {
		srcPath := filepath.Join(baseDir, "/build/", config.crosBoard, "/usr/src/"+kernDir+"-9999") + "/"
		if fileExists(srcPath) {
			config.kernSrcInstallDir = srcPath
		}
	}

	if config.kernelSrcDir == "" && !insideCros {
		srcDir, err := os.Readlink(config.buildDir + "source")
		if err != nil  {
			LOG_ERR(err, "Fail to read link to kernel source file from: %s", config.buildDir + "source")
			return errors.New("ERROR_INVALID_KERN_SRC_DIR")
		}

		srcDir = strings.TrimPrefix(srcDir, "/mnt/host/source/")
		config.kernelSrcDir = filepath.Join(config.crosPath, srcDir) + "/"
	}

	return nil
}

func (init *Init) checkConfig(config *Config) error {
	if !config.ignoreCross && fileExists("/etc/cros_chroot_version") ||
		(config.crosBoard != "" && config.crosPath != "") {
		err := init.checkConfigForCros(config)
		if err != nil {
			return err
		}
	}

	if config.buildDir == "" {
		LOG_ERR(os.ErrInvalid, "Please specify the kernel build directory using -b or --builddir parameter")
		return errors.New("ERROR_NO_BUILDDIR")
	}

	if config.workdir == "" {
		path, err := os.Executable()
		if err != nil {
			LOG_ERR(err, "Fail to get current executable path")
			return errors.New("ERROR_UNKNOWN")
		}

		hasher := crc32.NewIEEE()
		hasher.Write([]byte(path))
		sum := hex.EncodeToString(hasher.Sum(nil))
		config.workdir = cacheDir + "/workdir_" + sum + "/"
	}

	if config.kernelSrcDir == "" {
		srcDir := config.buildDir + "source"
		if dir, err := os.Readlink(srcDir); err == nil {
			config.kernelSrcDir = dir + "/"
		} else {
			config.kernelSrcDir = config.buildDir
		}
	} else if !init.isKernelSourcesDir(config.kernelSrcDir) {
		LOG_ERR(nil, `Given source directory is not a valid kernel source directory: "%s"`, config.kernelSrcDir)
		return errors.New("ERROR_INVALID_KERN_SRC_DIR")
	}

	LOG_DEBUG("Kernel source dir: %s", config.kernelSrcDir)
	LOG_DEBUG("Kernel build dir: %s", config.buildDir)
	LOG_DEBUG("Workdir: %s", config.workdir)

	if err := os.MkdirAll(config.workdir, 0755); err != nil {
		LOG_ERR(err, "Failed to create directory %s", config.workdir)
		return err
	}

	if !init.isKernelBuildDir(config.buildDir) {
		LOG_ERR(nil, `Given directory is not a valid kernel build directory: "%s"`, config.buildDir)
		return errors.New("ERROR_INVALID_BUILDDIR")
	}

	if !init.isKlpEnabled(config.buildDir) {
		if config.crosBoard != "" {
			LOG_ERR(nil, `Your kernel must be build with: USE="livepatch kernel_sources" emerge-%s chromeos-kernel-...`, config.crosBoard)
			return errors.New("ERROR_INSUFFICIENT_BUILD_PARAMS")
		} else {
			LOG_ERR(nil, "Kernel livepatching is not enabled. Please enable CONFIG_LIVEPATCH flag and rebuild the kernel")
			return errors.New("ERROR_KLP_IS_NOT_ENABLED")
		}
	}

	if init.checkConfigEnabled(config.buildDir, "CONFIG_CC_IS_CLANG") {
		config.useLLVM = "LLVM=1"
	}

	config.isAARCH64 = init.checkConfigEnabled(config.buildDir, "CONFIG_ARM64")

	if len(config.patches) > 0 {
		config.filesSrcDir = config.workdir + PATCHED_SOURCES_DIR + "/"
	} else {
		config.filesSrcDir = config.kernelSrcDir
	}

	config.linuxHeadersDir = config.buildDir
	config.modulesDir = config.buildDir
	config.systemMap = config.buildDir + "System.map"

	return nil
}

func (init *Init) init() (Config, int, error) {
	var lastArgIndex int
	homeDir, err := os.UserHomeDir()
	if err != nil {
		LOG_ERR(err, "Fail to fetch user home directory")
		return init.config, 0, mkError(ERROR_UNKNOWN)
	}

	cacheDir = homeDir + "/.cache/deku/"
	if !fileExists(cacheDir) {
		err = os.Mkdir(cacheDir, os.ModePerm)
		if err != nil {
			LOG_ERR(err, "Fail to create deku cache directory in %s", cacheDir)
			return init.config, 0, mkError(ERROR_UNKNOWN)
		}
	}

	init.config, lastArgIndex = init.getConfig()
	debugPrintConfig(&init.config)
	err = init.checkConfig(&init.config)
	debugPrintConfig(&init.config)
	return init.config, lastArgIndex, err
}

func debugPrintConfig(config *Config) {
	LOG_DEBUG("-----------CONFIG-----------")
	if config.buildDir != "" {
		LOG_DEBUG("buildDir: %s", config.buildDir)
	}
	if config.crosBoard != "" {
		LOG_DEBUG("crosBoard: %s", config.crosBoard)
	}
	if config.crosPath != "" {
		LOG_DEBUG("crosPath: %s", config.crosPath)
	}
	if config.deployParams != "" {
		LOG_DEBUG("deployParams: %s", config.deployParams)
	}
	if config.deployType != "" {
		LOG_DEBUG("deployType: %s", config.deployType)
	}
	LOG_DEBUG("ignoreCross: %v", config.ignoreCross)
	LOG_DEBUG("isAARCH64: %v", config.isAARCH64)
	LOG_DEBUG("isCros: %v", config.isCros)
	if config.kernSrcInstallDir != "" {
		LOG_DEBUG("kernSrcInstallDir: %s", config.kernSrcInstallDir)
	}
	if config.kernelVersion != 0 {
		LOG_DEBUG("kernelVersion: %d", config.kernelVersion)
	}
	if config.linuxHeadersDir != "" {
		LOG_DEBUG("linuxHeadersDir: %s", config.linuxHeadersDir)
	}
	if config.modulesDir != "" {
		LOG_DEBUG("modulesDir: %s", config.modulesDir)
	}
	if config.kernelSrcDir != "" {
		LOG_DEBUG("kernelSrcDir: %s", config.kernelSrcDir)
	}
	if config.filesSrcDir != "" {
		LOG_DEBUG("filesSrcDir: %s", config.filesSrcDir)
	}
	if config.sshOptions != "" {
		LOG_DEBUG("sshOptions: %s", config.sshOptions)
	}
	if config.systemMap != "" {
		LOG_DEBUG("systemMap: %s", config.systemMap)
	}
	if config.useLLVM != "" {
		LOG_DEBUG("useLLVM: %s", config.useLLVM)
	}
	if config.workdir != "" {
		LOG_DEBUG("workdir: %s", config.workdir)
	}
	LOG_DEBUG("----------------------------")
}
