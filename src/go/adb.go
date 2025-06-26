// Copyright (c) 2025 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os/exec"
)

func ADBExecuteCommandWithConfig(command string, config Config) ([]byte, error) {
	cmd := exec.Command("adb")
	if config.deployParams != "" {
		cmd.Args = append(cmd.Args, "-s", config.deployParams)
	}
	cmd.Args = append(cmd.Args, "shell")
	cmd.Args = append(cmd.Args, "su", "0", command)
	out, err := cmd.CombinedOutput()
	LOG_DEBUG("%s\n%s", cmd.String(), string(out))

	if exitErr, e := err.(*exec.ExitError); e {
		LOG_DEBUG("Execute command: %s exited with error: %v", command, exitErr)
		err = mkError(ERROR_EXECUTE_COMMAND_ON_DEVICE)
	}

	return out, err
}

func ADBExecuteCommand(command string) ([]byte, error) {
	return ADBExecuteCommandWithConfig(command, config)
}

func ADBUploadFiles(files []string) ([]byte, error) {
	cmd := exec.Command("adb")
	if config.deployParams != "" {
		cmd.Args = append(cmd.Args, "-s", config.deployParams)
	}
	cmd.Args = append(cmd.Args, "push")
	cmd.Args = append(cmd.Args, files...)
	cmd.Args = append(cmd.Args, config.dstPath)
	out, err := cmd.CombinedOutput()
	LOG_DEBUG("%s", cmd.String())
	LOG_DEBUG("%s", out)

	if exitErr, e := err.(*exec.ExitError); e {
		LOG_DEBUG("Upload files: %v exited with error: %v", files, exitErr)
		err = mkError(ERROR_UPLOAD_FILES)
	}

	return out, err
}

func ADBCheckConnection() error {
	cmd := exec.Command("adb")
	if config.deployParams != "" {
		cmd.Args = append(cmd.Args, "-s", config.deployParams)
	}
	cmd.Args = append(cmd.Args, "get-state")
	out, err := cmd.CombinedOutput()
	LOG_DEBUG("%s\n%s", cmd.String(), string(out))

	if exitErr, e := err.(*exec.ExitError); e {
		LOG_DEBUG("Check connection exited with error: %v", exitErr)
		return mkError(ERROR_CANT_CONNECT_DEVICE)
	}

	if string(out) != "device\n" {
		return mkError(ERROR_CANT_CONNECT_DEVICE)
	}

	return nil
}
