// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/md5"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var config Config

// Log level filter
var LOG_LEVEL = 2 // 1 - debug, 2 - info, 3 - warning, 4 - error

func LOG_FATAL(err error, format string, args ...any) {
	LOG_ERR(err, format, args...)
	os.Exit(1)
}

func LOG_ERR(err error, format string, args ...any) {
	if LOG_LEVEL > 4 {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, format+": ", args...)
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func LOG_WARN(format string, args ...any) {
	if LOG_LEVEL > 3 {
		return
	}
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func LOG_INFO(format string, args ...any) {
	if LOG_LEVEL > 2 {
		return
	}
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func LOG_DEBUG(format string, args ...any) {
	if LOG_LEVEL > 1 {
		return
	}
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func slicesContains(sl []string, name string) bool {
	for _, value := range sl {
		if value == name {
			return true
		}
	}
	return false
}

func vv[T any](s T) string {
	if patch, ok := any(s).(dekuPatch); ok {
		return fmt.Sprintf("%s (%s)", patch.Name, patch.ModFuncs)
	} else if patches, ok := any(s).([]dekuPatch); ok {
		if len(patches) == 0 {
			return ""
		}

		str := ""
		for _, patch := range patches {
			str += fmt.Sprintf("%s (%s), ", patch.Name, patch.ModFuncs)
		}
		return str[:len(str)-2]
	} else if module, ok := any(s).(dekuModule); ok {
		return fmt.Sprintf("%s (%s): [%s]", module.Name, module.ModuleId, vv(module.Patches))
	} else if modules, ok := any(s).([]dekuModule); ok {
		if len(modules) == 0 {
			return ""
		}

		str := ""
		for _, module := range modules {
			str += fmt.Sprintf("%s (%s): [%s]\n", module.Name, module.ModuleId, vv(module.Patches))
		}
		return str[:len(str)-1]
	}

	str, _ := json.Marshal(s)
	return string(str)
}

func slicesIndex(s []string, v string) int {
	for i := range s {
		if v == s[i] {
			return i
		}
	}
	return -1
}

func slicesDelete(s []string, i, j int) []string {
	_ = s[i:j:len(s)] // bounds check

	if i == j {
		return s
	}

	s = append(s[:i], s[j:]...)
	return s
}

func removeDuplicate(sl []string) []string {
	list := []string{}
	for _, v := range sl {
		if !slicesContains(list, v) {
			list = append(list, v)
		}
	}
	return list
}

func fileExists(file string) bool {
	if _, err := os.Stat(file); err != nil {
		return !os.IsNotExist(err)
	}
	return true
}

func appendToFile(file, text string) error {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		return err
	}
	return nil
}

func filenameNoExt(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return base[:len(base)-len(ext)]
}

/**
 * Find sources files that were changed after the kernel was built
 */
func modifiedFiles() []string {
	ignoredFilesH := []string{
		"arch/x86/boot/voffset.h",
		"arch/x86/boot/cpustr.h",
		"arch/x86/boot/zoffset.h"}

	// find representative file to get the kernel build time
	// vmlinux might not be the best chose as it's not regenerated on every build
	file, err := os.Stat(config.buildDir + "vmlinux")
	if err != nil {
		LOG_ERR(err, "Can't find vmlinux file")
		return nil
	}
	startBuildTime := file.ModTime()

	file, err = os.Stat(config.buildDir + "Makefile")
	if err != nil {
		LOG_ERR(err, "Can't find Makefile file")
		return nil
	}

	if file.ModTime().After(startBuildTime) {
		startBuildTime = file.ModTime()
	}

	files := []string{}
	err = filepath.Walk(config.filesSrcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		path = path[len(config.filesSrcDir):]

		if startBuildTime.After(info.ModTime()) {
			return nil
		}

		if !strings.Contains(path, "/") {
			return nil
		}

		if strings.HasPrefix(path, ".git/") ||
			strings.HasPrefix(path, "snap/") ||
			strings.HasPrefix(path, "tools/") ||
			strings.HasPrefix(path, "debian/") ||
			strings.HasPrefix(path, "pacman/") ||
			strings.HasPrefix(path, "scripts/") ||
			strings.HasPrefix(path, "rpmbuild/") ||
			strings.HasPrefix(path, "tar-install/") ||
			strings.HasPrefix(path, "usr/include/") ||
			strings.HasPrefix(path, "Documentation/") {
			return nil
		}

		fileStat, err := os.Stat(config.filesSrcDir + path)
		if err != nil {
			LOG_ERR(err, "Can't get stats for file: %s", config.filesSrcDir + path)
			return nil
		}

		if isCFile, _ := filepath.Match("*.c", fileStat.Name()); !isCFile {
			isHFile, _ := filepath.Match("*.h", fileStat.Name());
			if !isHFile || slicesContains(ignoredFilesH, path) {
				return nil
			}
		}

		if config.kernSrcInstallDir == "" {
			files = append(files, path)
		} else {
			// compare file against the origin file from the sources installation dir
			originFileStat, err := os.Stat(config.kernSrcInstallDir + path)
			if err != nil {
				if !fileExists(config.kernSrcInstallDir + path) {
					LOG_ERR(err, "The %s file was added after the kernel was built. It's not supported by DEKU", path)
					return err
				}

				LOG_ERR(err, "Can't get stats for file: %s", config.filesSrcDir + path)
				return nil
			}

			if originFileStat != nil {
				f1, err := os.ReadFile(config.filesSrcDir + path)
				if err != nil {
					LOG_ERR(err, "Failed to read file: %s", config.filesSrcDir + path)
					return nil
				}

				f2, err := os.ReadFile(config.kernSrcInstallDir + path)
				if err != nil {
					LOG_ERR(err, "Failed to read file: %s", config.kernSrcInstallDir + path)
					return nil
				}

				if !bytes.Equal(f1, f2) {
					files = append(files, path)
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil
	}

	LOG_DEBUG("Modified files: %s", files)
	return files
}

func generateSymbols(koFile string) bool {
	path := filepath.Dir(koFile)
	outDir := filepath.Join(config.workdir, SYMBOLS_DIR, path)
	outFile := filepath.Join(outDir, filenameNoExt(filepath.Base(koFile)))

	if fileExists(outFile) {
		return true
	}

	LOG_DEBUG("Generate symbols for: %s", koFile)

	// Check if the module is enabled in the kernel configuration.
	modules, err := os.ReadFile(filepath.Join(config.modulesDir, path, "modules.order"))
	if err != nil {
		LOG_DEBUG("Can't find modules.order file")
		return false
	}
	if !bytes.Contains(modules, []byte(koFile)) {
		LOG_DEBUG(fmt.Sprintf("The module %s file is not enabled in the current kernel configuration", koFile))
		return false
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		LOG_DEBUG("Can't create symbol dir: %s\n%s", outDir, err)
		return false
	}

	path = filepath.Join(config.modulesDir, koFile)
	readelfCmd := exec.Command("readelf",
		"--symbols",
		"--wide",
		path)

	output, err := readelfCmd.Output()
	if err != nil {
		LOG_DEBUG("Fail to read symbols for: %s\n%s", path, err)
		return false
	}

	lines := strings.Split(string(output), "\n")
	var symbols []string

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 8 && (fields[3] == "FUNC" || fields[3] == "OBJECT") {
			symbols = append(symbols, fields[7])
		}
	}

	result := strings.Join(symbols, "\n")
	err = os.WriteFile(outFile, []byte(result), 0644)
	if err != nil {
		LOG_DEBUG("Fail to write symbols to file: %s\n%s", outFile, err)
		return false
	}

	return true
}

type embedObjSymbols struct {
	symbols  []elf.Symbol
	index    int
	offset   uint64
	hitCount int
}

func findSymbolIndex(symName, symType, srcFile, objFilePath string) (int, error) {
	LOG_DEBUG("Finding index for symbol: %s [%s] from source file: %s in: %s", symName, symType, srcFile, objFilePath)
	e, err := Open(objFilePath)
	if err != nil {
		return -1, err
	}
	defer e.Close()

	symbolsInObj := []embedObjSymbols{}
	var fileSyms embedObjSymbols
	var symOffset uint64 = 0
	symCount := 0
	index := 0
	hitCount := 0
	srcFileName := filepath.Base(srcFile)
	currentName := ""
	offsets := []uint64{}
	for _, symbol := range e.Symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FILE {
			currentName = symbol.Name
			if currentName == srcFileName {
				fileSyms.symbols = []elf.Symbol{}
			}
			continue
		} else if (elf.ST_TYPE(symbol.Info) == elf.STT_FUNC ||
			elf.ST_TYPE(symbol.Info) == elf.STT_OBJECT || symType == "") &&
			symbol.Name == symName {
			symCount++
			if symType == "f" &&
				elf.ST_TYPE(symbol.Info) != elf.STT_FUNC {
				continue
			}
			if symType == "v" &&
				elf.ST_TYPE(symbol.Info) != elf.STT_OBJECT {
				continue
			}
			index++
			offsets = append(offsets, symbol.Value)
			if currentName == srcFileName {
				fileSyms.index = index
				fileSyms.offset = symbol.Value
				symbolsInObj = append(symbolsInObj, fileSyms)
			}
		}
		if currentName == srcFileName {
			fileSyms.symbols = append(fileSyms.symbols, symbol)
		}
	}

	if symCount == 0 {
		return -ERROR_CANT_FIND_SYM_INDEX, errors.New(fmt.Sprintln("Can't find any symbol index for", symName))
	} else if symCount == 1 {
		index = 0
		goto out
	} else if len(symbolsInObj) == 1 {
		symOffset = symbolsInObj[0].offset
	} else {
		e, err = Open(config.buildDir + strings.TrimSuffix(srcFile, "c") + "o")
		if err != nil {
			return -1, err
		}
		defer e.Close()

		LOG_DEBUG("Found %d objects file with symbol [%s] %s", len(symbolsInObj), symType, symName)

		for k, symbols := range symbolsInObj {
			for _, sym := range e.Symbols {
				for _, s := range symbols.symbols {
					if sym.Size == s.Size && sym.Name == s.Name &&
						sym.Info == s.Info {
						symbolsInObj[k].hitCount++
						break
					}
				}
			}
			cnt := symbolsInObj[k].hitCount
			LOG_DEBUG("Hit count for %d: %d", k, cnt)
			if cnt > hitCount {
				hitCount = cnt
				symOffset = symbolsInObj[k].offset
			}
		}
		if symOffset == 0 {
			return -1, errors.New("Can't find properly symbol index for " + symName + " because there are multiple symbols with the same name")
		}
	}

	index = 1
	for _, offset := range offsets {
		if offset < symOffset {
			index++
		}
	}

out:
	LOG_DEBUG("Found at index %d", index)
	return index, nil
}

func getKernelInformation(info string) string {
	var result = ""
	re := regexp.MustCompile(`.*` + info + ` "(.+)"\n.*`)
	filepath.Walk(config.buildDir+"/include/generated/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.ReadFile(path)
		if err != nil {
			LOG_ERR(err, "Failed to read file: %s", path)
			return nil
		}

		match := re.FindStringSubmatch(string(file))
		if len(match) > 1 {
			result = match[1]
			return io.EOF
		}

		return nil
	})

	return result
}

func getKernelVersion() string {
	return getKernelInformation("UTS_VERSION")
}

func getKernelReleaseVersion() string {
	return getKernelInformation("UTS_RELEASE")
}

func getKernelConfigHash() string {
	file, err := os.Open(filepath.Join(config.buildDir, ".config"))
	if err != nil {
		LOG_ERR(err, "Can't read .config file")
		return ""
	}
	defer file.Close()

	hasher := crc32.NewIEEE()
	if _, err := io.Copy(hasher, file); err != nil {
		LOG_ERR(err, "Can't generate hash for .config file")
		return "";
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func generatePatchName(file string) string {
	hasher := crc32.NewIEEE()
	hasher.Write([]byte(file))
	sum := hex.EncodeToString(hasher.Sum(nil))
	name := filenameNoExt(file)
	name = strings.Replace(name, "-", "_", -1)

	return "patch_" + sum + "_" + name
}

func generateBaseModuleName(patches []dekuPatch) string {
	hasher := crc32.NewIEEE()
	sort.Slice(patches, func(i, j int) bool {
		return patches[i].Name < patches[j].Name
	})
	for _, patch := range patches {
		hasher.Write([]byte(patch.Id))
	}

	return "deku_" + hex.EncodeToString(hasher.Sum(nil))
}

func parseDekuModuleFromNote(note string) dekuModule {
	arr := strings.Split(note, " ")
	if len(arr) != 3 {
		return invalidateModule(dekuModule{})
	}

	module := dekuModule{
		Name: arr[0],
		ModuleId: arr[1],
	}

	patchesId := strings.Split(module.ModuleId, ",")
	patchesStrArr := strings.Split(arr[2], "|")
	if len(patchesId) != len(patchesStrArr) {
		return invalidateModule(dekuModule{})
	}

	for i, pStr := range patchesStrArr {
		pArr := strings.Split(pStr, ":")
		if len(pArr) != 3 {
			continue
		}
		sArr := strings.Split(pArr[2], ";")
		if len(sArr) == 0 {
			continue
		}

		patch := dekuPatch {
			Name: pArr[0],
			SrcFile: pArr[1],
			ModFuncs: sArr,
			Id: patchesId[i],
		}
		module.Patches = append(module.Patches, patch)
		module.SrcFiles += patch.SrcFile + ","
	}
	module.SrcFiles = strings.TrimRight(module.SrcFiles, ",")

	return module
}

func getDekuModules(includeUnloadModule bool) []dekuModule {
	modules := []dekuModule{}
	patches := []dekuPatch{}
	files, err := os.ReadDir(config.workdir)
	if err != nil {
		return modules
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

	for _, dekuMod := range files {
		if !dekuMod.IsDir() || !strings.HasPrefix(dekuMod.Name(), "deku_") {
			continue
		}

		modDirPath := filepath.Join(config.workdir, dekuMod.Name())
		note, _ := os.ReadFile(filepath.Join(modDirPath, NOTE_FILE))
		module := parseDekuModuleFromNote(string(note))
		if !isModuleValid(module) {
			continue
		}

		module.KoFile = filepath.Join(modDirPath, dekuMod.Name()+".ko")
		if !fileExists(module.KoFile) {
			continue
		}

		module.Patches = []dekuPatch{}
		for _, patch := range patches {
			if strings.Contains(module.ModuleId, patch.Id) &&
				strings.Contains(module.SrcFiles, patch.SrcFile) {
				module.Patches = append(module.Patches, patch)
			}
		}

		if ((includeUnloadModule && len(module.Patches) == 0 && module.ModuleId == "")) ||
			(len(module.Patches) == len(strings.Split(module.ModuleId, ","))) {
			modules = append(modules, module)
		}
	}

	LOG_DEBUG("Local modules: %s", vv(modules))
	return modules
}

func generateDEKUHash() string {
	dekuPath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	data, err := os.ReadFile(dekuPath)
	if err != nil {
		LOG_ERR(err, "Can't read file")
	}
	hash := md5.Sum([]byte(fmt.Sprintf("%x", data)))
	return hex.EncodeToString(hash[:])
}

func versionNum(major, minor, patch uint64) uint64 {
	maxPatch := uint64(99999)
	maxMinor := uint64(9999)
	return major*(maxMinor+1)*(maxPatch+1) + minor*(maxPatch+1) + patch
}
