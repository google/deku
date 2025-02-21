// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func extractPatch(patchFilePath string) error {
	for _, line := range readLines(patchFilePath) {
		if strings.HasPrefix(line, "--- a/") &&
			!strings.HasSuffix(line, ".config") {
			file := line[6:]
			dir := config.filesSrcDir + filepath.Dir(file)
			if err := os.MkdirAll(dir, 0755); err != nil {
				LOG_ERR(err, "Failed to create directory %s", dir)
				return err
			}

			if err := copyFile(config.kernelSrcDir+file, config.filesSrcDir+file); err != nil {
				LOG_ERR(err, "Failed to copy file %s", config.kernelSrcDir+file)
				return err
			}
		}
	}

	return nil
}

func prepareSourcesForPatch(patches []string) error {
	var resolvedPatchesPath []string
	for _, patch := range patches {
		if !strings.Contains(patch, "*") {
			resolvedPatchesPath = append(resolvedPatchesPath, patch)
		} else {
			files, err := filepath.Glob(patch)
			if err != nil {
				LOG_ERR(err, "Failed to search patches for %s", patch)
				return err
			}

			for _, file := range files {
				content, err := os.ReadFile(file)
				if err != nil {
					LOG_DEBUG("Failed to read potential patch file %s", file)
					continue
				}

				if bytes.Contains(content, []byte("--- a/")) {
					resolvedPatchesPath = append(resolvedPatchesPath, file)
				}

			}
		}
	}

	for _, patch := range resolvedPatchesPath {
		err := extractPatch(patch)
		if err != nil {
			return err
		}

		patchPath := patch
		if strings.HasPrefix(patchPath, "~/") {
			hd, _ := os.UserHomeDir()
			patchPath = filepath.Join(hd, patchPath[1:])
		} else if !strings.HasPrefix(patchPath, "/") {
			wd, _ := os.Getwd()
			patchPath = filepath.Join(wd, patchPath)
		}

		execCmd := exec.Command("patch", "-d", config.filesSrcDir, "-p1", "-i", patchPath)
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
		err = execCmd.Run()

		if err != nil {
			LOG_ERR(err, "Failed to apply patch %s", patch)
			return err
		}
	}

	return nil
}
