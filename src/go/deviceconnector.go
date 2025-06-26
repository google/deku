// Copyright (c) 2025 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

func ExecuteCommandOnTarget(command string) ([]byte, error) {
	if config.isAndroid {
		return ADBExecuteCommand(command)
	} else {
		return SSHExecuteCommand(command)
	}
}

func UploadFilesOnTarget(files []string) ([]byte, error) {
	if config.isAndroid {
		return ADBUploadFiles(files)
	} else {
		return SSHUploadFiles(files)
	}
}

func CheckDeviceConnection() error {
	if config.isAndroid {
		return ADBCheckConnection()
	} else {
		return SSHCheckConnection()
	}
}
