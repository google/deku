// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os/exec"
	"strings"
)

func getRemoteParameters(forSSH bool, config Config) []string {
	host := config.deployParams
	if strings.Contains(host, "@") {
		host = strings.Split(host, "@")[1]
	}
	host = strings.Split(host, ":")[0]

	args := []string{
		"-o", "ControlMaster=auto",
		"-o", "ControlPersist=300",
		"-o", "LogLevel=error"}
	sshOpts := strings.TrimSpace(config.sshOptions)
	if sshOpts != "" {
		args = append(args, strings.Split(sshOpts, " ")...)
	}
	deployParams := config.deployParams
	if strings.Contains(deployParams, " ") {
		deployParams = strings.SplitN(config.deployParams, " ", 2)[0]
	}
	colonPos := strings.Index(deployParams, ":")
	port := ""
	if colonPos != -1 {
		port = deployParams[colonPos+1:]
		deployParams = deployParams[:colonPos]
		if forSSH {
			args = append(args, "-p", port)
		} else {
			args = append(args, "-P", port)
		}
	}
	args = append(args, "-o", "ControlPath=/tmp/ssh-deku-"+host+string(port))
	return append(args, deployParams)
}

func SSHExecuteCommandWithConfig(command string, config Config) ([]byte, error) {
	cmd := exec.Command("ssh")
	cmd.Args = append(cmd.Args, getRemoteParameters(true, config)...)
	cmd.Args = append(cmd.Args, command)
	out, err := cmd.CombinedOutput()
	LOG_DEBUG("%s\n%s", cmd.String(), string(out))

	if exitErr, e := err.(*exec.ExitError); e {
		LOG_DEBUG("Execute command: %s exited with error: %v", command, exitErr)
		err = mkError(exitErr.ExitCode())
	}

	return out, err
}

func SSHExecuteCommand(command string) ([]byte, error) {
	return SSHExecuteCommandWithConfig(command, config)
}

func SSHUploadFiles(files []string) ([]byte, error) {
	cmd := exec.Command("scp")
	params := getRemoteParameters(false, config)
	host := params[len(params)-1]
	params = params[:len(params)-1]
	cmd.Args = append(cmd.Args, params...)
	cmd.Args = append(cmd.Args, files...)
	cmd.Args = append(cmd.Args, host+":"+config.dstPath)
	out, err := cmd.CombinedOutput()
	LOG_DEBUG("%s", cmd.String())
	LOG_DEBUG("%s", out)

	if exitErr, e := err.(*exec.ExitError); e {
		LOG_DEBUG("Upload files: %v exited with error: %v", files, exitErr)
		err = mkError(ERROR_UPLOAD_FILES)
	}

	return out, err
}

func SSHCheckConnection() error {
	cmd := exec.Command("ssh")
	cmd.Args = append(cmd.Args, getRemoteParameters(true, config)...)
	cmd.Args = append(cmd.Args, "true")
	out, err := cmd.CombinedOutput()
	LOG_DEBUG("%s\n%s", cmd.String(), string(out))
	if exitErr, e := err.(*exec.ExitError); e {
		LOG_DEBUG("Check connection exited with error: %v", exitErr)
		return mkError(ERROR_CANT_CONNECT_DEVICE)
	}
	if string(out) != "" {
		LOG_DEBUG("Check connection returned unexpected output: %s", string(out))
		return mkError(ERROR_CANT_CONNECT_DEVICE)
	}
	return nil
}
