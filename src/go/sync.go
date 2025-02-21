// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func regenerateSymbols() error {
	files := []string{}
	symbolsPath := config.workdir + SYMBOLS_DIR + "/"
	symbolsPath = strings.TrimPrefix(symbolsPath, "./")
	filepath.Walk(symbolsPath, func(file string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}
		files = append(files, file)
		return nil
	})

	os.RemoveAll(symbolsPath)
	if !fileExists(symbolsPath) {
		if err := os.Mkdir(symbolsPath, 0755); err != nil {
			return err
		}
	}

	for _, file := range files {
		koFile := strings.TrimPrefix(file, symbolsPath) + ".ko"
		generateSymbols(koFile)
	}

	return nil
}

func generateVmlinuxFilesList() error {
	kernelSrcDirs := []string{"arch/x86", "block", "certs", "crypto", "drivers", "fs", "init",
		"io_uring", "ipc", "kernel", "mm", "net", "security", "sound", "virt"}

	outFile, err := os.Create(filepath.Join(config.workdir, VMLINUX_FILES_LIST))
	if err != nil {
		return err
	}
	defer outFile.Close()

	for _, dir := range kernelSrcDirs {
		builtIn := readLines(filepath.Join(config.buildDir, dir, "built-in.a"))
		found := false
		for _, line := range builtIn {
			if srcFile, ok := strings.CutSuffix(line, ".o/"); ok {
				_, err = outFile.WriteString(filepath.Join(dir, srcFile+".c") + "\n")
				if err != nil {
					return err
				}
				found = true
			} else if found {
				break
			}
		}
	}

	return nil
}

func generateModulesFilesList() error {
	outFile, err := os.Create(filepath.Join(config.workdir, MODULES_FILES_LIST))
	if err != nil {
		return err
	}
	defer outFile.Close()

	modules := readLines(filepath.Join(config.buildDir, "modules.order"))
	for _, koFile := range modules {
		var baseFile string
		var found bool
		if baseFile, found = strings.CutSuffix(koFile, ".ko"); !found {
			baseFile = strings.TrimSuffix(baseFile, ".o")
		}

		contents, err := os.ReadFile(filepath.Join(config.buildDir, baseFile+".mod"))
		if err != nil {
			LOG_DEBUG("Can't read .mod file: %s", err)
			continue
		}

		for _, file := range strings.Fields(string(contents)) {
			srcFile := strings.TrimSuffix(file, ".o") + ".c"
			_, err = outFile.WriteString(srcFile + " " + baseFile + "\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func synchronize() {
	LOG_INFO("Synchronize...")

	filepath.Walk(config.workdir, func(file string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() &&
			(strings.HasPrefix(info.Name(), "deku_") || strings.HasPrefix(info.Name(), "patch_")) {
			LOG_DEBUG("Remove %s", file)
			err := os.RemoveAll(file)
			if err != nil {
				LOG_ERR(err, "Can't remove %s", file)
			}
		}

		return nil
	})

	err := os.RemoveAll(config.workdir + FILES_ID)
	if err != nil {
		LOG_ERR(err, "Can't remove %s", config.workdir+FILES_ID)
	}

	workdirCfg := make(map[string]string)
	workdirCfg[KERNEL_VERSION] = getKernelVersion()
	workdirCfg[KERNEL_RELEASE] = getKernelReleaseVersion()
	workdirCfg[KERNEL_CONFIG_HASH] = getKernelConfigHash()
	workdirCfg[DEKU_HASH] = generateDEKUHash()
	jsonStr, err := json.Marshal(workdirCfg)
	if err != nil {
		LOG_ERR(err, "Fail to generate JSON for config file %s", workdirCfg)
	}

	err = os.WriteFile(config.workdir+"config", []byte(jsonStr), 0644)
	if err != nil {
		LOG_ERR(err, "Can't write config file %s", config.workdir+"config")
	}

	err = generateVmlinuxFilesList()
	if err != nil {
		LOG_ERR(err, "Failed to generate sources file list")
		return
	}

	err = generateModulesFilesList()
	if err != nil {
		LOG_ERR(err, "Failed to generate modules sources file list")
		return
	}

	err = regenerateSymbols()
	if err != nil {
		LOG_ERR(err, "Failed to regenerate symbols")
	}

	if config.kernSrcInstallDir == "" {
		cmd := exec.Command("git", "--work-tree="+config.kernelSrcDir, "--git-dir="+config.workdir+".git", "add", config.kernelSrcDir+"*")
		cmd.Run()
	} else {
		stat, err := os.Stat(config.kernSrcInstallDir)
		if err != nil {
			LOG_ERR(err, "Can't get stats for file: %s", config.kernSrcInstallDir)
			return
		}

		os.Chtimes(config.workdir+"config", time.Time{}, stat.ModTime())
	}
}
