// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"debug/elf"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

func findFilesUsingHeaders(dir string, headerFiles []string) []string {
	files := []string{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Name() == ".git" {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".o.cmd") {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			relPath := strings.Replace(path[len(dir):], "/.", "/", 1)
			obj := relPath[:len(relPath) - len(".cmd")]
			srcFile := relPath[:len(relPath) - len(".o.cmd")] + ".c"

			if valid, err := buildInKernel(srcFile); !valid || err != nil {
				return nil
			}

			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "deps_"+obj) {
					break
				}
			}

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "$(") {
					continue
				}
				line = strings.TrimSuffix(line, ` \`)
				for _, header := range headerFiles {
					if strings.HasSuffix(filepath.Join(line), header) {
						LOG_DEBUG("Found '%s' that is used in %s", header, srcFile)
						files = append(files, srcFile)
						break
					}
				}
			}

			if err := scanner.Err(); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		LOG_ERR(err, "Error walking the path %s", dir)
	}

	return files
}

func getValidPatches() []dekuPatch {
	patches := []dekuPatch{}
	files, err := os.ReadDir(config.workdir)
	if err != nil {
		return patches
	}

	for _, patchDir := range files {
		if !patchDir.IsDir() || !strings.HasPrefix(patchDir.Name(), "patch_") {
			continue
		}

		patchDirPath := filepath.Join(config.workdir, patchDir.Name())
		patchFile := filepath.Join(patchDirPath, "patch.o")
		patchId, _ := os.ReadFile(filepath.Join(patchDirPath, "id"))
		srcFile, _ := os.ReadFile(filepath.Join(patchDirPath, FILE_SRC_PATH))
		objPath, _ := os.ReadFile(filepath.Join(patchDirPath, FILE_OBJECT_PATH))
		if !fileExists(patchFile) || len(patchId) == 0 || len(srcFile) == 0 || len(objPath) == 0 {
			continue
		}

		if id, _ := generatePatchId(string(srcFile)); string(patchId) != id {
			LOG_DEBUG("Patch %s is outdated", patchDir.Name())
			continue
		}

		patch := dekuPatch{
			SrcFile:	string(srcFile),
			Name:		patchDir.Name(),
			ObjPath:	string(objPath),
			PatchFile:	patchFile,
			Id:			string(patchId),
			ModFuncs: 	readLines(filepath.Join(patchDirPath, MOD_SYMBOLS_FILE)),
		}

		patches = append(patches, patch)
	}

	LOG_DEBUG("Valid patches: %s", vv(patches))
	return patches
}

func cleanupWorkdir(modules []dekuModule) []string {
	removedPatches := []string{}

	files, err := os.ReadDir(config.workdir)
	if err != nil {
		return removedPatches
	}

	// remove outdated files ID from FILES_ID
	newFilesId := ""
	filesId := readLines(filepath.Join(config.workdir, FILES_ID))
	for _, file := range filesId {
		filePath := strings.Split(file, " ")[0]
		fileId := strings.Split(file, " ")[1]
		currentFileId, err := generatePatchId(filePath)
		if err != nil {
			LOG_ERR(err, "Failed to generate file ID")
			return removedPatches
		}
		if currentFileId == fileId {
			newFilesId += file + " " + currentFileId + "\n"
		}
	}

	err = os.WriteFile(filepath.Join(config.workdir, FILES_ID), []byte(newFilesId), 0644)
	if err != nil {
		LOG_ERR(err, "Failure to write files ID to file")
		return removedPatches
	}

	patches := getValidPatches()
	toRemove := []string{}
	for _, entry := range files {
		if !entry.IsDir() {
			continue
		}

		path := filepath.Join(config.workdir, entry.Name())

		if strings.HasPrefix(entry.Name(), "patch_") {
			found := false
			for _, patch := range patches {
				if patch.Name == entry.Name() {
					found = true
					break
				}
			}

			if !found {
				patchId, _ := os.ReadFile(filepath.Join(path, "id"))
				srcFile, _ := os.ReadFile(filepath.Join(path, FILE_SRC_PATH))
				if id, _ := generatePatchId(string(srcFile)); string(patchId) != id {
					toRemove = append(toRemove, path)
					removedPatches = append(removedPatches, string(srcFile))
					LOG_DEBUG("Patch ID for %s is outdated", entry.Name())
				}
			}
		}

		if strings.HasPrefix(entry.Name(), "deku_") {
			modDirPath := filepath.Join(config.workdir, entry.Name())
			note, _ := os.ReadFile(filepath.Join(modDirPath, NOTE_FILE))
			mod := parseDekuModuleFromNote(string(note))
			if !isModuleValid(mod) {
				continue
			}

			for _, module := range modules {
				if module.ModuleId == mod.ModuleId {
					goto checkNextModuleDir
				}
			}

			toRemove = append(toRemove, path)
		checkNextModuleDir:
		}
	}

	for _, dir := range toRemove {
		LOG_DEBUG("Remove %s", dir)
		if err := os.RemoveAll(dir); err != nil {
			LOG_ERR(err, "Failed to remove directory: %s", dir)
		}
	}

	return removedPatches
}

func checkPatchesDependency(patches []dekuPatch) (bool, error) {
	var undefinedSymbols []elf.Symbol
	for _, patch := range patches {
		undefSym, err := getUndefinedSymbols(patch.PatchFile)
		if err != nil {
			LOG_ERR(err, "Failed to fetch undefined symbols for %s", patch.PatchFile)
			return false, err
		}

		for i, sym := range undefSym {
			if strings.HasPrefix(sym.Name, DEKU_PATCH_REF_SYM_PREFIX+patch.Name+"_") {
				sym.Name = sym.Name[len(DEKU_PATCH_REF_SYM_PREFIX+patch.Name+"_"):]
				undefSym[i] = sym
			}
		}

		undefinedSymbols = append(undefinedSymbols, undefSym...)
	}

	for _, patch := range patches {
		for _, sym := range undefinedSymbols {
			exists, err := isSymbolExists(patch.PatchFile, sym.Name, elf.ST_TYPE(sym.Info))
			if err != nil {
				LOG_ERR(err, "Failed to check if symbol %s exists in", sym.Name, patch.PatchFile)
				return false, err
			}

			if exists {
				LOG_DEBUG("Found definition of undefined symbol %s in %s", sym.Name, patch.Name)
				return true, nil
			}
		}
	}

	return false, nil
}

func checkSymbolsSubset(allPatches []dekuPatch, modulesOnDevice []dekuModule) bool {
	localPatchedSymbols := []string{}
	for _, patch := range allPatches {
		for _, modSym := range patch.ModFuncs {
			localPatchedSymbols = append(localPatchedSymbols, patch.Name+":"+modSym)
		}
	}

	for _, module := range modulesOnDevice {
		for _, patch := range module.Patches {
			for _, modSym := range patch.ModFuncs {
				if !slicesContains(localPatchedSymbols, patch.Name+":"+modSym) {
					return false
				}
			}
		}
	}

	return true
}

func anyValidPatchOnDevice(allPatches []dekuPatch, modulesOnDevice []dekuModule) bool {
	for _, module := range modulesOnDevice {
		for _, patch := range module.Patches {
			for _, localPatch := range allPatches {
				if patch.Name == localPatch.Name && patch.Id == localPatch.Id {
					return true
				}
			}
		}
	}

	return false
}

func build(modulesOnDevice []dekuModule) (dekuModule, error) {
	var cros Cros

	prevModules := getDekuModules(false)
	removedPatches := cleanupWorkdir(prevModules)

	modifiedFiles := modifiedFiles()
	if len(modifiedFiles) == 0 {
		LOG_INFO("No change detected in the source code")
		return invalidateModule(dekuModule{}), nil
	}
	files := modifiedFiles

	// remove from the list of modified files those headers that haven't really changed since last time
	for _, file := range readLines(filepath.Join(config.workdir, FILES_ID)) {
		filePath := strings.Split(file, " ")[0]
		if strings.HasSuffix(filePath, ".h") && slicesContains(files, filePath) {
			index := slicesIndex(files, filePath)
			files = slicesDelete(files, index, index + 1)
		}
	}

	// add sources that includes modified header files
	sourcesFiles := []string{}
	headerFiles := []string{}
	for _, file := range files {
		if filepath.Ext(file) == ".h" {
			LOG_WARN("The header file: %s has been modified. The changes in header files are not fully supported yet.", file)
			headerFiles = append(headerFiles, file)
		} else {
			sourcesFiles = append(sourcesFiles, file)
		}
	}

	files = sourcesFiles
	if len(headerFiles) > 0 {
		if len(headerFiles) > 20 { // do not allow for changes with too much changes in header files
			LOG_WARN("Detected too many potentially modified header files. Please build and deploy kernel to the device and try once again.")
			return invalidateModule(dekuModule{}), mkError(ERROR_UNSUPPORTED_CHANGES)
		}
		sourcesUsingHeaders := findFilesUsingHeaders(config.buildDir, headerFiles)
		files = append(files, sourcesUsingHeaders...)
		files = removeDuplicate(files)
	}

	// remove any of these files for which a patch has already been generated
	// or the file has not changed since last check
	sourcesFiles = []string{}
	for _, file := range files {
		addFile := false
		name := generatePatchName(file)
		if fileExists(filepath.Join(config.workdir, name, "id")) {
			addFile = true
			// check if any module contains this patch
			for _, module := range prevModules {
				for _, patch := range module.Patches {
					if patch.Name == name {
						addFile = false
						break
					}
				}
			}
		} else {
			addFile = true
		}

		if addFile {
			sourcesFiles = append(sourcesFiles, file)
		}
	}
	files = sourcesFiles

	for _, file := range files {
		if filepath.Ext(file) == ".S" || filepath.Ext(file) == ".rs" {
			LOG_WARN("Detected changes in %s. Only changes to '.c' and '.h' files are supported.", file)
			if KERN_SRC_INSTALL_DIR != "" {
				LOG_WARN("Undo changes in %s and try again.", file)
				return invalidateModule(dekuModule{}), mkError(ERROR_UNSUPPORTED_CHANGES)
			}
			LOG_WARN("Rebuild the kernel to suppress this warning.")
		}
	}

	if len(modulesOnDevice) == 1 && len(modulesOnDevice[0].Patches) == 0 {
		modulesOnDevice = []dekuModule{}
	}

	// check the synchronization of local and remote modules if no new patches needs to be build
	if len(files) == 0 {
		if len(prevModules) == 0 {
			LOG_INFO("No valid changes detected")
			return invalidateModule(dekuModule{}), nil
		}

		foundAll := true
		for _, localModule := range prevModules {
			found := false
			for _, moduleOnDevice := range modulesOnDevice {
				if localModule.ModuleId == moduleOnDevice.ModuleId {
					found = true
					break
				}
			}
			if !found {
				foundAll = false
				break
			}
		}

		if foundAll {
			LOG_INFO("No valid changes detected since last run")
			return invalidateModule(dekuModule{}), nil
		}
	}

	if config.crosBoard != "" && !config.ignoreCross {
		cros.preBuild()
		defer cros.postBuild()
	}

	var err error
	patches := []dekuPatch{}
	wg := sync.WaitGroup{}
    ch := make(chan int, runtime.NumCPU() * 2)
	for i, file := range files {
		wg.Add(1)
        ch <- 1
		go func(i int, file string) {
			defer func() { wg.Done(); <-ch }()
			explicitModified := slicesContains(modifiedFiles, file)
			prevPatchExisted := slicesContains(removedPatches, file)
			patch, e := generatePatch(file, explicitModified, prevPatchExisted)
			if e != nil {
				err = e
				LOG_ERR(err, "Failed to process %s", file)
				return
			}

			if isPatchValid(patch) {
				patches = append(patches, patch)
			}
		}(i, file)
	}
	wg.Wait()

	if err != nil {
		return invalidateModule(dekuModule{}), err
	}

	// add new files to the FILES_ID file
	filesIdFile, err := os.OpenFile(filepath.Join(config.workdir, FILES_ID), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return invalidateModule(dekuModule{}), err
	}

	defer filesIdFile.Close()

	for _, file := range modifiedFiles {
		fileId, err := generatePatchId(file)
		if err != nil {
			LOG_ERR(err, "Failed to generate module")
			return invalidateModule(dekuModule{}), err
		}

		if _, err = filesIdFile.WriteString(file + " " + fileId + "\n"); err != nil {
			LOG_ERR(err, "Failed write file ID to file for %s", file)
			return invalidateModule(dekuModule{}), err
		}
	}

	if len(patches) == 0 && len(prevModules) == 0 && len(modulesOnDevice) == 0 {
		LOG_INFO("No valid changes detected")
		return invalidateModule(dekuModule{}), nil
	}

	allPatches := []dekuPatch{}
	allPatches = append(allPatches, patches...)
	for _, module := range prevModules {
		allPatches = append(allPatches, module.Patches...)
	}

	// generate a single module with all the patches in the workdir that will
	// replace all previous deku modules with the new one if patches applied on
	// the device are not the subset of patches in the workdir or all patches
	// on the device are obsoleted or there are dependencies between patches.
	cumulativeModule := false

	if len(modulesOnDevice) == 0 {
		cumulativeModule = true
		LOG_DEBUG("Generate cumulative module due to no other DEKU modules are loaded on the device")
	} else if len(prevModules) == 0 && len(modulesOnDevice) > 0 {
		cumulativeModule = true
		LOG_DEBUG("Generate cumulative module due to first run and remove previous DEKU modules")
	} else if !checkSymbolsSubset(allPatches, modulesOnDevice) {
		cumulativeModule = true
		LOG_DEBUG("Generate cumulative module due to some patches needed to be reverted")
	} else if !anyValidPatchOnDevice(allPatches, modulesOnDevice) {
		cumulativeModule = true
		LOG_DEBUG("Generate cumulative module due all patches on the device must be reverted")
	} else {
		patchesAreDepended, err := checkPatchesDependency(allPatches)
		if err != nil {
			return invalidateModule(dekuModule{}), err
		}

		if patchesAreDepended {
			cumulativeModule = true
			LOG_DEBUG("Generate cumulative module due to dependencies between patches")
		}
	}

	if cumulativeModule {
		patches = getValidPatches()
	}

	module, err := generateModule(patches, cumulativeModule)
	if err != nil {
		LOG_ERR(err, "Failed to generate module")
		return invalidateModule(dekuModule{}), err
	}

	return module, nil
}
