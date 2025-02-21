// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func getKernelReleaseOnTarget() (string, error) {
	out, err := runCommand("uname --kernel-release")
	return out, err
}

func getKernelVersionOnTarget() (string, error) {
	out, err := runCommand("uname --kernel-version")
	return out, err
}

func getLoadedDEKUModules() ([]dekuModule, error) {
	out, err := runCommand(`find /sys/module -name .note.deku -type f -exec grep deku_ {} \;; exit 0`)
	if len(out) == 0 {
		return []dekuModule{}, err
	}

	modules := []dekuModule{}
	for _, line := range strings.Split(out, "\n") {
		module := parseDekuModuleFromNote(line)
		if isModuleValid(module) {
			modules = append(modules, module)
		}
	}

	return modules, nil
}

func checkKernels() (bool, error) {
	kernelRelease, err := getKernelReleaseOnTarget()
	if err != nil {
		LOG_ERR(err, "Fail to fetch the kernel release information from the device")
		return false, err
	}
	kernelVersion, err := getKernelVersionOnTarget()
	if err != nil {
		LOG_ERR(err, "Fail to fetch the kernel version from the device")
		return false, err
	}
	localKernelRelease := getKernelReleaseVersion()
	localKernelVersion := getKernelVersion()

	if strings.Contains(kernelRelease, localKernelRelease) &&
		strings.Contains(kernelVersion, localKernelVersion) {
		return true, nil
	}
	LOG_ERR(nil, "The kernel on the device is outdated!")
	LOG_INFO("Kernel on the device: %s %s", kernelRelease, kernelVersion)
	LOG_INFO("Local built kernel:   %s %s", localKernelRelease, localKernelVersion)
	return false, nil
}

func isRemoteDeploy() bool {
	return config.deployParams != ""
}

func deploy() error {
	if isRemoteDeploy() {
		if config.deployType == "" || config.deployParams == "" {
			LOG_ERR(nil, "Please specify SSH connection parameters to the target device using: --target=<user@host[:port]> parameter")
			return mkError(ERROR_NO_DEPLOY_PARAMS)
		}

		if config.deployType != "ssh" {
			LOG_ERR(nil, "Unknown deploy type '%s'", config.deployType)
			return mkError(ERROR_INVALID_DEPLOY_TYPE)
		}
	}

	isKernelValid, err := checkKernels()
	if err != nil {
		return err
	}

	if !isKernelValid {
		LOG_WARN("Please install the current built kernel on the device")
		return mkError(ERROR_INVALID_DEPLOY_TYPE)
	}

	modulesOnDevice, err := getLoadedDEKUModules()
	if err != nil {
		LOG_WARN("Fail to fetch loaded DEKU modules from the device. %s", err)
	}

	module, err := build(modulesOnDevice)
	if err != nil {
		return err
	}

	LOG_DEBUG("Modules on the device: %s", vv(modulesOnDevice))
	if isModuleValid(module) && module.Cumulative {
		if len(module.Patches) == 0 {
			modulesOnDevice = append(modulesOnDevice, module)
		}
		return loadModules([]dekuModule{module}, modulesOnDevice)
	}

	modulesToLoad := []dekuModule{}
	modulesToUnload := []dekuModule{}
	localModules := getDekuModules(true)

	if len(localModules) == 0 {
		return loadModules([]dekuModule{}, modulesOnDevice)
	}

	for _, localModule := range localModules {
		moduleIsLoaded := false
		for _, remoteModule := range modulesOnDevice {
			if localModule.ModuleId == remoteModule.ModuleId {
				moduleIsLoaded = true
				break
			}
		}

		if !moduleIsLoaded {
			modulesToLoad = append(modulesToLoad, localModule)
		}
	}

	// find if some modules can be unloaded
	patchedSymbols := []string{}
	for _, module := range modulesToLoad {
		for _, patch := range module.Patches {
			for _, modSym := range patch.ModFuncs {
				patchedSymbols = append(patchedSymbols, patch.SrcFile+":"+modSym)
			}
		}
	}

	for _, module := range modulesOnDevice {
		canBeRemoved := true
		for _, patch := range module.Patches {
			for _, modSym := range patch.ModFuncs {
				sym := patch.SrcFile + ":" + modSym
				if !slicesContains(patchedSymbols, sym) {
					canBeRemoved = false
					break
				}
				patchedSymbols = append(patchedSymbols, sym)
			}
		}

		if canBeRemoved {
			modulesToUnload = append(modulesToUnload, module)
		}
	}

	if len(modulesToLoad) == 0 && len(modulesToUnload) == 0 {
		LOG_INFO("No changes need to be made to the device")
		return nil
	}

	return loadModules(modulesToLoad, modulesToUnload)
}

func runCommand(command string) (string, error) {
	var out []byte
	var err error

	if isRemoteDeploy() {
		out, err = runSSHCommand(command)
	} else {
		shell := "sh"
		if os.Getenv("SHELL") != "" {
			shell = os.Getenv("SHELL")
		}
		cmd := exec.Command(shell, "-c", command)
		out, err = cmd.CombinedOutput()
		LOG_DEBUG("%s\n%s", cmd.String(), string(out))

		if exiterr, e := err.(*exec.ExitError); e {
			err = mkError(exiterr.ExitCode())
		}
	}

	return strings.TrimSuffix(string(out), "\n"), err
}

func generateLoadScript(modulesToLoad, modulesToUnload []dekuModule) (string, error) {
	var unload string
	var insmod string
	var reloadScript = ""
	var checkTransition = config.kernelVersion >= versionNum(5, 10, 0) // checking patch transition in not reliable on kernel <5.10

	reloadScript += "cd \"$(dirname \"$0\")\"\n"
	reloadScript += "INSMOD=insmod\n"
	reloadScript += "RMMOD=rmmod\n"
	reloadScript += "TEE=tee\n"
	reloadScript += "if [ ! $(id -u) -eq 0 ]; then\n"
	reloadScript += "	INSMOD=\"sudo insmod\"\n"
	reloadScript += "	RMMOD=\"sudo rmmod\"\n"
	reloadScript += "	TEE=\"sudo tee\"\n"
	reloadScript += "fi\n"

	patchOnlyModules := true
	for _, module := range modulesToLoad {
		for _, patch := range module.Patches {
			if !strings.HasSuffix(string(patch.ObjPath), ".ko") {
				patchOnlyModules = false
			}
		}
	}

	if patchOnlyModules {
		for _, module := range modulesToLoad {
			for _, patch := range module.Patches {
				if strings.HasSuffix(string(patch.ObjPath), ".ko") {
					modDep := filenameNoExt(string(patch.ObjPath))
					modDep = strings.ReplaceAll(modDep, "-", "_")
					reloadScript += "\ngrep -q '\\b" + modDep + "\\b' /proc/modules\n"
					reloadScript += "if [ $? != 0 ]; then\n"
					reloadScript += "	echo \"Can't apply changes for " + string(patch.SrcFile) +
						" because the '" + modDep + "' module is not loaded\"\n"
					reloadScript += "	exit " + fmt.Sprintf("%d", ERROR_DEPEND_MODULE_NOT_LOADED) + "\n"
					reloadScript += "fi\n"
				}
			}
		}
	}

	for _, module := range modulesToUnload {
		moduleName := strings.ReplaceAll(module.Name, "-", "_")
		moduleSys := fmt.Sprintf("/sys/kernel/livepatch/%s", moduleName)

		unload += "if [ -d " + moduleSys + " ]; then\n"
		unload += "	for i in $(seq 1 20); do\n"
		unload += "		out=$(sh -c \"echo 0 | $TEE --append " + moduleSys + "/enabled\" 2>&1) && break\n"
		unload += "		[ -z \"${out##*Permission denied*}\" ] && { exit " + fmt.Sprintf("%d", ERROR_PERMISSION_DENIED) + "; }\n"
		unload += "		[ -z \"${out##*I/O error*}\" ] && sleep 1;\n"
		unload += "	done\n"
		unload += "fi\n"

		unload += "for i in $(seq 1 $(($(nproc)*50))); do\n"
		unload += "	[ ! -d " + moduleSys + " ] && break\n"
		unload += "	[ $(cat " + moduleSys + "/transition) = \"0\" ] && break\n"
		unload += "	[ $(($i%25)) = 0 ] && echo \"Undoing previous changes made to " + module.SrcFiles + " is/are still in progress ...\"\n"
		unload += "	sleep 0.2\n"
		unload += "done\n"

		unload += "[ -d /sys/module/" + moduleName + " ] && $RMMOD " + moduleName + "\n"

		unload += "for i in $(seq 1 250); do\n"
		unload += "	[ ! -d " + moduleSys + " ] && break\n"
		unload += "	[ $(($i%25)) = 0 ] && echo \"Cleaning up after previous changes to " + module.SrcFiles + " is/are still in progress...\"\n"
		unload += "	sleep 0.2\n"
		unload += "done\n"
	}

	for _, module := range modulesToLoad {
		moduleName := strings.ReplaceAll(module.Name, "-", "_")
		moduleSys := fmt.Sprintf("/sys/kernel/livepatch/%s", moduleName)

		var koFile = module.Name + ".ko"
		if !isRemoteDeploy() {
			koFile = module.Name + "/" + koFile
		}

		insmod += "module=" + module.Name + "\n"
		insmod += "res=$($INSMOD " + koFile + " 2>&1)\n"
		insmod += "if [ $? != 0 ]; then\n"
		insmod += "	echo \"Failed to load changes for " + module.SrcFiles + ". Reason: $res\"\n"
		insmod += "	exit " + fmt.Sprintf("%d", ERROR_LOAD_MODULE) + "\n"
		insmod += "fi\n"
		insmod += "for i in $(seq 1 50); do\n"
		insmod += "	grep -q " + moduleName + " /proc/modules && break\n"
		insmod += "	[ $? -ne 0 ] && { echo \"Failed to load module " + moduleName + "\"; exit " + fmt.Sprintf("%d", ERROR_LOAD_MODULE) + "; }\n"
		insmod += "	echo \"" + moduleName + " module is still loading...\"\n"
		insmod += "	sleep 0.2\n"
		insmod += "done\n"
		if checkTransition {
			insmod += "for i in $(seq 1 $(($(nproc)*50))); do\n"
			insmod += "	[ $(cat " + moduleSys + "/transition) = \"0\" ] && break\n"
			insmod += "	[ $(($i%25)) = 0 ] && echo \"Applying changes for " + module.SrcFiles + " is/are still in progress...\"\n"
			insmod += "	sleep 0.2\n"
			insmod += "done\n"
			insmod += "[ $(cat " + moduleSys + "/transition) != \"0\" ] && { echo \"Failed to apply " + moduleName + " $i\"; exit " + fmt.Sprintf("%d", ERROR_APPLY_KLP) + "; }\n"
		} else {
			insmod += "sleep 2\n"
		}
		insmod += "echo \"" + module.SrcFiles + " done\"\n"
	}

	reloadScript += "\n" + insmod + "\n" + unload
	// remove deprecated deku modules
	reloadScript += `find /sys/module -name "deku_*" -type d -exec sh -c '$1 $(basename $2) 2>/dev/null' sh "$RMMOD" {} \;`

	scriptPath := config.workdir + DEKU_RELOAD_SCRIPT
	err := os.WriteFile(scriptPath, []byte(reloadScript), 0644)
	if err != nil {
		LOG_ERR(err, "Failed to write the reload script")
		return "", err
	}
	return scriptPath, err
}

func loadModules(modulesToLoad, modulesToUnload []dekuModule) error {
	LOG_DEBUG("Modules to load: %s", vv(modulesToLoad))
	LOG_DEBUG("Modules to unload: %s", vv(modulesToUnload))

	scriptPath, err := generateLoadScript(modulesToLoad, modulesToUnload)
	if err != nil {
		return err
	}

	if isRemoteDeploy() {
		filesToUpload := []string{}
		for _, module := range modulesToLoad {
			filesToUpload = append(filesToUpload, module.KoFile)
		}
		filesToUpload = append(filesToUpload, scriptPath)

		if out, err := runSSHCommand("mkdir -p " + REMOTE_DIR); err != nil {
			LOG_ERR(nil, "Error during creating remote directory: %s", out)
			return err
		}

		runSSHCommand("rm " + REMOTE_DIR + "/*.ko > /dev/null 2>&1")
		out, err := uploadFiles(filesToUpload)
		if err != nil {
			LOG_ERR(err, "Error during upload files on the device:%s", out)
			return mkError(ERROR_UPLOAD_FILES)
		}
	}

	if len(modulesToLoad) > 0 && len(modulesToLoad[0].Patches) > 0 {
		LOG_INFO("Loading...")
	} else if len(modulesToUnload) > 0 || (len(modulesToLoad) == 1 && len(modulesToLoad[0].Patches) == 0) {
		LOG_INFO("Reverting...")
	} else {
		return nil
	}

	var out string
	if isRemoteDeploy() {
		var byteOut []byte
		byteOut, err = runSSHCommand("sh " + REMOTE_DIR + "/" + DEKU_RELOAD_SCRIPT + " 2>&1")
		out = string(byteOut)
	} else {
		// To deal with the "insmod: ERROR: could not insert module .ko: Text file busy" issue
		for _, module := range modulesToLoad {
			tmpKoFile := module.KoFile + "_"
			os.Rename(module.KoFile, tmpKoFile)
			copyFile(tmpKoFile, module.KoFile)
			os.Remove(tmpKoFile)
		}

		out, err = runCommand("sh " + scriptPath + " 2>&1")
	}

	if err == nil {
		LOG_INFO("%sChanges successfully applied!%s", GREEN, NC)
	} else {
		code := errorStrToCode(err)
		if code == ERROR_PERMISSION_DENIED {
			LOG_INFO("Failed to apply changes due to insufficient permissions.")
			LOG_INFO("Follow the information in the README on how to solve the problem.")
		} else {
			LOG_INFO("----------------------------------------")
			LOG_INFO("%s", out)
			LOG_INFO("----------------------------------------")
			LOG_INFO("Failed to apply changes!")
			LOG_INFO("Check the system logs on the device for more information.")
		}

		return err
	}

	return nil
}
