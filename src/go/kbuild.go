// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func cmdFromMod(modFile string, skipParam []string) ([]string, string, error) {
	var cmd []string
	var extraCmd string
	var line string

	file, err := os.Open(modFile)
	if err != nil {
		return cmd, "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	if scanner.Scan() {
		line = scanner.Text()
	}

	array := strings.SplitN(line, "=", 2)
	if len(array) < 2 {
		return cmd, "", fmt.Errorf("can't find command in %s", modFile)
	}
	line = array[1]
	parts := strings.SplitN(line, ";", 2)
	if len(parts) == 2 {
		line = parts[0]
		extraCmd = strings.TrimSpace(parts[1])
	}

	params := strings.Fields(line)

	for i := 0; i < len(params); i++ {
		opt := params[i]

		if strings.Contains(opt, "=") {
			param := strings.SplitN(opt, "=", 2)[0]
			if !slicesContains(skipParam, param) {
				cmd = append(cmd, opt)
			}
		} else {
			if !slicesContains(skipParam, opt) {
				cmd = append(cmd, opt)
			} else {
				i++
			}
		}
	}
	return cmd, extraCmd, nil
}

func cmdBuildFile(srcFile string) ([]string, string, error) {
	file := filenameNoExt(srcFile)
	dir := filepath.Dir(srcFile)
	modFile := filepath.Join(config.buildDir, dir, fmt.Sprintf(".%s.o.cmd", file))

	if _, err := os.Stat(modFile); err != nil {
		return nil, "", err
	}

	skipParam := []string{"-o", "-Wdeclaration-after-statement"}
	cmd, extraCmd, err := cmdFromMod(modFile, skipParam)
	if err != nil {
		return nil, "", err
	}

	newCmd := []string{cmd[0], "-iquote "+config.filesSrcDir+dir, "-iquote "+config.kernelSrcDir+dir}

	for i := 1; i < len(cmd) - 1 /* skip last param */; i++ {
		if !strings.HasPrefix(cmd[i], "-I") {
			newCmd = append(newCmd, cmd[i])
		} else {
			inc := ""
			if cmd[i] == "-I" {
				inc = cmd[i+1]
				i++
			} else {
				inc = cmd[i][2:]
			}

			originInc := inc
			if inc[0] == '/' {
				var cut bool
				inc, cut = strings.CutPrefix(inc, config.kernelSrcDir)
				if cut {
					inc = config.filesSrcDir + inc
				}
			} else {
				inc = config.filesSrcDir + inc
			}

			if fileExists(inc) {
				newCmd = append(newCmd, "-I" + inc)
			}
			newCmd = append(newCmd, "-I" + originInc)
		}
	}
	cmd = newCmd
	cmd = append(cmd, "-I"+config.filesSrcDir+dir)
	cmd = append(cmd, "-I"+config.kernelSrcDir+dir)

	return cmd, extraCmd, err
}

func cmdPrefixMap(from, to string) []string {
	var cmd []string
	cmd = append(cmd, fmt.Sprintf("-fmacro-prefix-map=%s=%s", from, to))
	cmd = append(cmd, fmt.Sprintf("-ffile-prefix-map=%s=%s", from, to))
	cmd = append(cmd, fmt.Sprintf("-fdebug-prefix-map=%s=%s", from, to))
	return cmd
}

func buildFile(srcFile, compileFile, outFile string) error {
	var cmd []string
	var extraCmd string

	cmd, extraCmd, err := cmdBuildFile(srcFile)
	if err != nil {
		return nil
	}

	currentPath, err := os.Getwd()
	if err != nil {
		LOG_ERR(err, "Fail to fetch current directory")
		return err
	}

	if !filepath.IsAbs(outFile) {
		outFile = filepath.Join(currentPath, outFile)
	}

	if !filepath.IsAbs(compileFile) {
		compileFile = filepath.Join(currentPath, compileFile)
	}

	cmd = append(cmd, cmdPrefixMap(filepath.Dir(compileFile), filepath.Dir(srcFile))...)
	cmd = append(cmd, cmdPrefixMap(config.kernelSrcDir, "")...)
	cmd = append(cmd, cmdPrefixMap(config.kernelSrcDir + "./", "")...)
	cmd = append(cmd, cmdPrefixMap(config.filesSrcDir, "")...)
	cmd = append(cmd, cmdPrefixMap(config.filesSrcDir + "./", "")...)
	cmd = append(cmd, "-o", outFile, compileFile)

	execCmd := exec.Command("bash", "-c", strings.Join(cmd, " ")) // FIXME:Do not use a bash
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Dir = config.linuxHeadersDir
	err = execCmd.Run()

	if err != nil {
		LOG_ERR(err, "Failed to build %s", srcFile)
		return err
	}

	if len(extraCmd) > 0 {
		if strings.HasPrefix(extraCmd, "./tools/objtool/objtool") && strings.HasSuffix(extraCmd, ".o") {
			array := []string{}
			for _, a := range strings.Split(extraCmd, " ") {
				if a != "" {
					array = append(array, a)
				}
			}

			newExtraCmd := array[:len(array)-1]
			newExtraCmd = append(newExtraCmd, outFile)

			LOG_DEBUG("Run extra command to build file: %s", strings.Join(newExtraCmd, " "))

			execCmd := exec.Command(newExtraCmd[0], newExtraCmd[1:]...)
			execCmd.Stdout = os.Stdout
			execCmd.Stderr = os.Stderr
			execCmd.Dir = config.buildDir

			if err := execCmd.Run(); err != nil {
				LOG_INFO("Failed to perform additional action for %s (%s). %s", srcFile, execCmd.Args, err)
			}
		} else {
			LOG_INFO("Can't parse additional command to build file (%s)", extraCmd)
		}
	}

	return nil
}

func buildModules(moduleDir string) error {
	cmd := exec.Command("make")
	cmd.Dir = moduleDir
	if config.isAARCH64 {
		cmd.Args = append(cmd.Args, "ARCH=arm64")
		cmd.Args = append(cmd.Args, "CROSS_COMPILE=" + TOOLCHAIN)
	}

	if config.useLLVM != "" {
		cmd.Args = append(cmd.Args, config.useLLVM)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		LOG_ERR(err, "%s", string(out))
		return err
	}

	fileLog, err := os.Create(filepath.Join(moduleDir, "build.log"))
	if err != nil {
		LOG_ERR(err, "Failed to create logs file: %s", filepath.Join(moduleDir, "build.log"))
	}

	defer fileLog.Close()
	fileLog.Write(out)

	rc := len(out)
	if rc != 0 && err != nil {
		regexErr := `^.+\(\/\w+\.\w+\):\([0-9]\+\):[0-9]\+:.* error: \(.\+\)`
		errorCaught := false
		for _, line := range strings.Split(string(out), "\n") {
			err := regexp.MustCompile(regexErr).FindStringSubmatch(line)
			if err != nil {
				file := err[1]
				no, e := strconv.Atoi(err[2])
				if e != nil {
					LOG_ERR(e, "Failed to parse line number from error after failed build module")
				}

				err := err[3]
				errorCaught = true
				LOG_INFO("%s:%d %serror:%s %s. See more: %s\n", file, no, RED, NC, err, "fileLog")
				break
			}
		}

		if !errorCaught {
			fmt.Println("Error:")
			fmt.Println(string(out))
		}

		// Remove the "_filename.o" file because next build might fails
		// TODO: Remove file directly by name
		filepath.Walk(moduleDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.Name() == "_*.o" {
				err := os.Remove(path)
				if err != nil {
					return err
				}
			}

			return nil
		})

		return errors.New("build failed")
	}

	return nil
}

func buildLivepatchModule(moduleDir string) error {
	fileLog := filepath.Join(moduleDir, "build.log")
	oldFileLog := filepath.Join(moduleDir, "build_modules.log")
	os.Rename(fileLog, oldFileLog)
	return buildModules(moduleDir)
}
