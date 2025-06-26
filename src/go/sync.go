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

func findSourceFileForObjectFile(parentDir, objectFile string) string {
	relOjectFile := strings.TrimPrefix(objectFile, parentDir)
	file := filepath.Base(relOjectFile)
	dir := filepath.Dir(relOjectFile)
	cmdFile := filepath.Join(parentDir, dir, "."+file+".cmd")
	lines := readLines(cmdFile)
	if len(lines) == 0 {
		LOG_WARN("No .cmd file found for %s (%s)", objectFile, cmdFile)
		return ""
	}

	found := false
	kernelDir := ""
	for _, line := range lines {
		if strings.HasSuffix(line, `include/linux/kconfig.h \`) {
			line = strings.TrimSuffix(line, `include/linux/kconfig.h \`)
			kernelDir = strings.TrimSpace(line)
			found = true
			break
		}
	}
	if !found {
		LOG_WARN("No kernel directory found in .cmd file for object file %s in directory %s", objectFile, parentDir)
		return ""
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "source_"+objectFile) {
			srcFile := strings.Split(line, " := ")[1]
			if config.isModule {
				srcFile = strings.TrimPrefix(srcFile, config.buildDir)
			} else {
				srcFile = strings.TrimPrefix(srcFile, kernelDir)
			}
			return srcFile
		}
	}

	LOG_WARN("No source file found for object file %s in directory %s", objectFile, parentDir)
	return ""
}

func generateModulesFilesListFromDir(dir string, outFile *os.File) error {
	modules := readLines(filepath.Join(dir, "modules.order"))
	for _, koFile := range modules {
		var baseFile string
		var found bool
		if baseFile, found = strings.CutSuffix(koFile, ".ko"); !found {
			baseFile = strings.TrimSuffix(baseFile, ".o")
		}
		baseFile = strings.TrimPrefix(baseFile, dir)
		modFile := filepath.Join(dir, baseFile+".mod")
		contents, err := os.ReadFile(modFile)
		if err != nil {
			LOG_DEBUG("Can't read .mod file: %s. Skip", modFile)
			continue
		}

		for _, file := range strings.Fields(string(contents)) {
			srcFile := strings.TrimSuffix(file, ".o")
			srcFile = strings.TrimPrefix(srcFile, "./")
			srcFile = strings.TrimPrefix(srcFile, dir)
			if fileExists(filepath.Join(config.kernelSrcDir, srcFile+".c")) {
				srcFile += ".c"
			} else if fileExists(filepath.Join(config.kernelSrcDir, srcFile+".rs")) {
				srcFile += ".rs"
			} else {
				srcFile = findSourceFileForObjectFile(dir, file)
				if srcFile == "" {
					continue
				}
			}
			_, err = outFile.WriteString(srcFile + " " + file + " " + baseFile + "\n")
			if err != nil {
				return err
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

	if config.isAndroid {
		err := generateModulesFilesListFromDir(config.androidModulesDir, outFile)
		if err != nil {
			return err
		}
	}

	return generateModulesFilesListFromDir(config.buildDir, outFile)
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
	workdirCfg[KERNEL_BUILD_DIR] = config.buildDir
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
