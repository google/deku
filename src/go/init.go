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
	"os/exec"
	"path/filepath"
	"regexp"
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

	var directories = []string{"builddir", "sourcesdir", "headersdir", "src_inst_dir", "workdir", "cros_sdk"}
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
	config.linuxHeadersDir = init.getParam("headersdir", "k")
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

func (init *Init) filesExist(path string, files []string) bool {
	for _, file := range files {
		if !fileExists(path + file) {
			return false
		}
	}

	return true
}

func (init *Init) isKernelSourcesDir(path string) bool {
	return init.filesExist(path, []string{"Kbuild", "Kconfig", "Makefile"})
}

func (init *Init) isKernelBuildDir(path string) bool {
	return init.isLinuxHeadersDir(path) && init.filesExist(path, []string{"vmlinux", "System.map"})
}

func (init *Init) isModuleBuildDir(path string) bool {
	return init.filesExist(path, []string{"Module.symvers", "modules.order", "Makefile"})
}

func (init *Init) isModuleSourcesDir(path string) bool {
	return init.filesExist(path, []string{"Makefile"})
}

func (init *Init) isLinuxHeadersDir(path string) bool {
	return init.filesExist(path, []string{"Makefile", "Module.symvers", "include/generated/uapi/linux/version.h"})
}

func (init *Init) findKernelHeaders(path string) string {

	// try to find from ".o.cmd" file
	dir := findPathForFileFromCmdFile(path, "arch/x86/include/generated/uapi/asm/types.h")
	if fileExists(dir) {
		return dir
	}

	// try to find in the Makefile
	for _, line := range readLines(path + "Makefile") {
		if (strings.Contains(line, "make") || strings.Contains(line, "$(MAKE)")) && strings.Contains(line, " -C ") && strings.HasSuffix(line, "modules") {
			re := regexp.MustCompile(`(?i)-C\s+("[^"]+"|'[^']+'|(?:[^\s$]+|\$\([^)]*\))+([^\s]*)*)`)
			match := re.FindStringSubmatch(line)
			if match != nil {
				path := strings.Trim(match[1], "\"'")
				if fileExists(path) {
					return path + "/"
				}
				if strings.Contains(path, "$(shell ") {
					path = strings.ReplaceAll(path, "$(shell ", "$(")
				}
				out, _ := exec.Command("bash", "-c", "echo -n "+path).Output()
				path = string(out)
				if fileExists(path) {
					return path + "/"
				}
				break
			} else {
				LOG_DEBUG("Can't parse 'make' command to build the module (%s)", line)
			}
			break
		}
	}

	return ""
}

func (init *Init) checkConfigEnabled(linuxHeadersDir, flag, symbolName string) bool {
	// since 5.15 it can be check with: fileExists("include/config/" + flag)
	config, err := os.ReadFile(linuxHeadersDir + ".config")
	if err != nil {
		if symbolName == "" {
			LOG_ERR(err, "Failed to read config file: %s", linuxHeadersDir+".config")
			return false
		} else {
			LOG_DEBUG("Failed to read config file: %s", linuxHeadersDir+".config")
			modSymVers, err := os.ReadFile(linuxHeadersDir + "Module.symvers")
			if err != nil {
				LOG_ERR(err, "Failed to read Module.symvers file: %s", linuxHeadersDir+"Module.symvers")
				return false
			}

			return bytes.Contains(modSymVers, []byte(symbolName))
		}
	}

	return bytes.Contains(config, []byte(flag+"=y"))
}

func (init *Init) isKlpEnabled(linuxHeadersDir string) bool {
	if !init.checkConfigEnabled(linuxHeadersDir, "CONFIG_LIVEPATCH", "klp_enable_patch") {
		LOG_DEBUG("CONFIG_LIVEPATCH is not enabled")
		return false
	}

	return true
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

func (init *Init) checkBuildDir(config *Config) error {
	if init.isKernelBuildDir(config.buildDir) {
		config.isModule = false
	} else if init.isModuleBuildDir(config.buildDir) {
		config.isModule = true
		modules, err := filepath.Glob(filepath.Join(
			config.buildDir,
			"*.ko"))
		if err != nil || len(modules) == 0 {
			LOG_ERR(nil, "Given module directory does not contain built kernel module: %s", config.buildDir)
			return mkError(ERROR_INVALID_MOD_DIR)
		}

		if config.linuxHeadersDir == "" {
			config.linuxHeadersDir = init.findKernelHeaders(config.buildDir)
			if config.linuxHeadersDir == "" {
				LOG_ERR(nil, "Failed to find kernel headers directory. Please specify it using -k or --headersdir parameter. This is the same parameter as the -C parameter for the `make` command in the Makefile.")
				return mkError(ERROR_INVALID_HEADERS_DIR)
			}
		}
	} else if init.isKernelSourcesDir(config.buildDir) {
		LOG_ERR(nil, "Given build directory is a kernel source directory, not a build directory: %s", config.buildDir)
		return mkError(ERROR_INVALID_BUILDDIR)
	} else if init.isModuleSourcesDir(config.buildDir) {
		LOG_ERR(nil, "Given build directory is a module source directory, not a build directory: %s", config.buildDir)
		return mkError(ERROR_INVALID_MOD_DIR)
	} else if init.isLinuxHeadersDir(config.buildDir) {
		LOG_ERR(nil, "Given build directory is a linux headers directory, not a build directory: %s", config.buildDir)
		return mkError(ERROR_INVALID_BUILDDIR)
	} else {
		LOG_ERR(nil, "Given build directory is not a valid kernel or module build directory: %s", config.buildDir)
		return mkError(ERROR_INVALID_BUILDDIR)
	}

	return nil
}

func (init *Init) checkConfigForCros(config *Config) error {
	const tempWorkdirName = "workdir_temp"
	var overrideWorkdir = false
	var overrideSshOptions = false
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
		overrideSshOptions = true
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
			if overrideSshOptions {
				config.sshOptions = " -o IdentityFile=" + config.workdir + "/testing_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -q"
			}

			os.MkdirAll(config.workdir, 0755)
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

	kernDir, err := CrosKernelName(baseDir, *config)
	if err != nil {
		return err
	}

	if config.buildDir != "" {
		if err := init.checkBuildDir(config); err != nil {
			return err
		}

		if !config.isModule {
			LOG_ERR(nil, "-b|--builddir parameter can not be used for Chromebook kernel")
			return mkError(ERROR_INVALID_PARAMETERS)
		}
	} else {
		config.buildDir = filepath.Join(baseDir, "/build/", config.crosBoard, "/var/cache/portage/sys-kernel", kernDir) + "/"
	}

	if config.kernSrcInstallDir == "" {
		srcPath := filepath.Join(baseDir, "/build/", config.crosBoard, "/usr/src/"+kernDir+"-9999") + "/"
		if fileExists(srcPath) {
			config.kernSrcInstallDir = srcPath
		}
	}

	if config.kernelSrcDir == "" && !insideCros {
		srcDir, err := os.Readlink(config.buildDir + "source")
		if err != nil {
			LOG_ERR(err, "Fail to read link to kernel source file from: %s", config.buildDir+"source")
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
		LOG_ERR(os.ErrInvalid, "Please specify the kernel or module build directory using -b or --builddir parameter")
		return mkError(ERROR_NO_BUILDDIR)
	} else if !fileExists(config.buildDir) {
		LOG_ERR(nil, "Given build directory does not exist: %s", config.buildDir)
		return mkError(ERROR_INVALID_BUILDDIR)
	} else {
		err := init.checkBuildDir(config)
		if err != nil {
			return err
		}
	}

	if config.workdir == "" {
		path, err := os.Executable()
		if err != nil {
			LOG_ERR(err, "Fail to get current executable path")
			return mkError(ERROR_UNKNOWN)
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
		LOG_ERR(nil, "Given source directory is not a valid kernel source directory: %s", config.kernelSrcDir)
		return mkError(ERROR_INVALID_KERN_SRC_DIR)
	}

	if config.linuxHeadersDir != "" {
		if !init.isLinuxHeadersDir(config.linuxHeadersDir) {
			LOG_ERR(nil, "Given headers directory is not a valid linux headers directory: %s", config.linuxHeadersDir)
			return mkError(ERROR_INVALID_HEADERS_DIR)
		}
	} else {
		config.linuxHeadersDir = config.buildDir
	}

	if !init.isKlpEnabled(config.linuxHeadersDir) {
		if config.crosBoard != "" {
			LOG_ERR(nil, `Your kernel must be build with: USE="livepatch kernel_sources" emerge-%s chromeos-kernel-...`, config.crosBoard)
			return mkError(ERROR_INSUFFICIENT_BUILD_PARAMS)
		} else {
			LOG_ERR(nil, "Kernel livepatching is not enabled. Please enable CONFIG_LIVEPATCH flag and rebuild the kernel")
			return mkError(ERROR_KLP_IS_NOT_ENABLED)
		}
	}

	if err := os.MkdirAll(config.workdir, 0755); err != nil {
		LOG_ERR(err, "Failed to create directory %s", config.workdir)
		return err
	}

	if init.checkConfigEnabled(config.linuxHeadersDir, "CONFIG_CC_IS_CLANG", "") {
		config.useLLVM = "LLVM=1"
	}

	config.isAARCH64 = init.checkConfigEnabled(config.linuxHeadersDir, "CONFIG_ARM64", "")

	if len(config.patches) > 0 {
		config.filesSrcDir = config.workdir + PATCHED_SOURCES_DIR + "/"
	} else {
		if config.isModule {
			config.filesSrcDir = config.buildDir
		} else {
			config.filesSrcDir = config.kernelSrcDir
		}
	}

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
	LOG_DEBUG("isModule: %v", config.isModule)
	if config.kernSrcInstallDir != "" {
		LOG_DEBUG("kernSrcInstallDir: %s", config.kernSrcInstallDir)
	}
	if config.kernelVersion != 0 {
		LOG_DEBUG("kernelVersion: %d", config.kernelVersion)
	}
	if config.linuxHeadersDir != "" {
		LOG_DEBUG("linuxHeadersDir: %s", config.linuxHeadersDir)
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
	if config.useLLVM != "" {
		LOG_DEBUG("useLLVM: %s", config.useLLVM)
	}
	if config.workdir != "" {
		LOG_DEBUG("workdir: %s", config.workdir)
	}
	LOG_DEBUG("----------------------------")
}
