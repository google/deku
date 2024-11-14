// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

func copyResourceFile(src, dst string) error {
	LOG_DEBUG("Copy resource file: %s to: %s", src, dst)
	usr, err := user.Current()
	if err != nil {
		LOG_ERR(err, "Fail to fetch current user name to copy resource")
		return err
	}

	if strings.HasPrefix(dst, "~/") {
		dst = usr.HomeDir + "/" + dst[1:]
	}

	destination, err := os.Create(dst)
	if err != nil {
		LOG_ERR(err, "Fail to create destination file to copy: %s", dst)
		return err
	}
	defer destination.Close()

	content, err := resources.ReadFile(src)
	if err != nil {
		LOG_ERR(err, "Fail to copy file: %s to: %s", src, dst)
	}
	err = os.WriteFile(dst, content, 0644)
	if err != nil {
		LOG_ERR(err, "Fail to copy file: %s to: %s", src, dst)
	}

	return err
}

func copyFile(src, dst string) error {
	usr, err := user.Current()
	if err != nil {
		LOG_ERR(err, "Fail to fetch current user name to copy file")
		return err
	}

	if strings.HasPrefix(src, "~/") {
		src = usr.HomeDir + "/" + src[1:]
	}
	if strings.HasPrefix(dst, "~/") {
		dst = usr.HomeDir + "/" + dst[1:]
	}

	sourceFileStat, err := os.Stat(src)
	if err != nil {
		LOG_ERR(err, "Fail to open source file to copy: %s", src)
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		LOG_ERR(err, "Fail to open file to copy: %s", src)
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		LOG_ERR(err, "Fail to create destination file to copy: %s", dst)
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		LOG_ERR(err, "Fail to copy file: %s to: %s", src, dst)
	}
	return err
}

func copyDir(srcDir, destDir string) error {
	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return err
	}

	srcDir = strings.TrimSuffix(srcDir, "/")
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if path == srcDir {
			return nil
		}

		dst := filepath.Join(destDir, info.Name())
		if info.IsDir() {
			err = copyDir(path, dst)
		} else {
			err = copyFile(path, dst)
		}
		return err
	})

	return err
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return []string{}
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return []string{}
	}

	return lines
}
