// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Cros struct {
	afdoFiles []string
}

func CrosKernelName(baseDir string, config Config) (string, error) {
	kernelsDir := filepath.Join(baseDir, "/build/", config.board, "/var/db/pkg/sys-kernel")
	kernels, err := filepath.Glob(filepath.Join(
		kernelsDir,
		"chromeos-kernel-*"))
	if err != nil || len(kernels) == 0 {
		LOG_ERR(nil, "Can't find the kernel it must be build with: USE=\"livepatch\" emerge-%s chromeos-kernel-...", config.board)
		return "", errors.New("ERROR_INSUFFICIENT_BUILD_PARAMS")
	}

	return strings.TrimSuffix(filepath.Base(kernels[0]), "-9999"), nil
}

func (cros *Cros) extractAfdo(afdoPath, dstDir, afdoFile string) {
	baseDir := ""
	LOG_DEBUG("Extract afdo profile file (%s)", afdoPath)

	dstFile := fmt.Sprintf("%s/%s.xz", dstDir, afdoFile)
	os.MkdirAll(dstDir, 0755)
	copyFile(afdoPath, dstFile)

	cmd := exec.Command("xz", "--decompress", dstFile)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Run()

	cmd = exec.Command(baseDir+"/usr/bin/llvm-profdata", "merge", "-sample", "-extbinary", "-output="+dstDir+"/"+afdoFile+".extbinary.afdo", dstDir+"/"+afdoFile)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Run()

	cros.afdoFiles = append(cros.afdoFiles, dstFile)
}

func (cros *Cros) preBuild() {
	LOG_DEBUG("Run cros pre build")
	afdoFile := ""
	afdoPath := ""
	dstDir := ""
	baseDir := ""
	kernDir, err := CrosKernelName(baseDir, config)
	if err != nil {
		return
	}
	cros.afdoFiles = []string{}

	dstDir = fmt.Sprintf("%s/build/%s/tmp/portage/sys-kernel/%s-9999/work", baseDir, config.board, kernDir)
	path := filepath.Join(baseDir, "/build/", config.board, "/var/db/pkg/sys-kernel/", kernDir+"-9999", kernDir+"-9999.ebuild")
	ebuild, err := os.ReadFile(path)
	if err != nil {
		LOG_ERR(err, "Failed to read file: %s", path)
		return
	}

	match := regexp.MustCompile(`(\w+\s)?AFDO_PROFILE_VERSION="(.*)"\n`)
	result := match.FindStringSubmatch(string(ebuild))
	if len(result) == 0 {
		LOG_DEBUG("Can't find afdo profile file")
		return
	}

	fileName := result[2]
	if fileName == "" {
		LOG_DEBUG("Afdo profile file is not specified")
		baseDir := "/mnt/host/source/"
		filepath.Walk(baseDir+".cache/distfiles/", func(path string, _ os.FileInfo, _ error) error {
			if strings.HasSuffix(path, ".afdo.xz") || strings.HasSuffix(path, ".gcov.xz") {
				LOG_DEBUG("Found %s", path)
				afdoFile = strings.TrimSuffix(filepath.Base(path), ".xz")
				cros.extractAfdo(path, dstDir, afdoFile)
			}
			return nil
		})
		return
	}

	afdoFile = fmt.Sprintf("%s-%s.afdo", kernDir, fileName)
	afdoPath = fmt.Sprintf("%s/var/cache/chromeos-cache/distfiles/%s.xz", baseDir, afdoFile)
	if fileExists(afdoPath) {
		cros.extractAfdo(afdoPath, dstDir, afdoFile)
		return
	}

	afdoFile = fmt.Sprintf("%s-%s.gcov", kernDir, fileName)
	afdoPath = fmt.Sprintf("%s/var/cache/chromeos-cache/distfiles/%s.xz", baseDir, afdoFile)
	if fileExists(afdoPath) {
		cros.extractAfdo(afdoPath, dstDir, afdoFile)
		return
	}

	afdoPath = fmt.Sprintf("%s/build/%s/tmp/portage/sys-kernel/%s-9999/distdir/%s.xz", baseDir, config.board, kernDir, afdoFile)
	if fileExists(afdoPath) {
		cros.extractAfdo(afdoPath, dstDir, afdoFile)
		return
	}

	afdoPath = fmt.Sprintf("%s/.cache/distfiles/%s.xz", baseDir, afdoFile)
	if fileExists(afdoPath) {
		cros.extractAfdo(afdoPath, dstDir, afdoFile)
		return
	}

	LOG_WARN("Can't find afdo profile file")
}

func (cros Cros) postBuild() {
	LOG_DEBUG("Run cros post build")
	for _, file := range cros.afdoFiles {
		os.Remove(strings.TrimSuffix(file, ".xz"))
	}
}
