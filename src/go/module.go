// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type dekuPatch struct {
	SrcFile   string
	Name      string
	ObjPath   string
	PatchFile string
	Id        string
	ModFuncs  []string
}

type dekuModule struct {
	SrcFiles   string
	Name       string
	KoFile     string
	ModuleId   string
	Cumulative bool
	Patches    []dekuPatch
}

func isModuleValid(module dekuModule) bool {
	return len(module.Name) > 0
}

func invalidateModule(module dekuModule) dekuModule {
	module.Name = ""
	return module
}

func isPatchValid(module dekuPatch) bool {
	return len(module.Name) > 0
}

func invalidatePatch(patch dekuPatch) dekuPatch {
	patch.Name = ""
	return patch
}

func generatePatchId(srcFile string) (string, error) {
	path := config.filesSrcDir + srcFile
	if !fileExists(path) {
		path = config.kernelSrcDir + srcFile
	}

	file, err := os.Open(path)
	if err != nil {
		LOG_ERR(err, "Can't read file to generate module ID")
		return "", err
	}
	defer file.Close()

	hasher := crc32.NewIEEE()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	sum := hex.EncodeToString(hasher.Sum(nil))

	return sum, nil
}

func getFileDiff(file string) []byte {
	var cmd *exec.Cmd
	if config.kernSrcInstallDir != "" {
		cmd = exec.Command("diff",
			"--unified",
			fmt.Sprintf("%s/%s", config.kernSrcInstallDir, file),
			"--label", fmt.Sprintf("%s/%s", config.kernSrcInstallDir, file),
			fmt.Sprintf("%s/%s", config.filesSrcDir, file),
			"--label", fmt.Sprintf("%s/%s", config.filesSrcDir, file))
	} else {
		cmd = exec.Command("git",
			"-C", config.workdir,
			"diff",
			"--function-context",
			"--", file)
	}
	out, _ := cmd.CombinedOutput()
	return out
}

func generateLivepatchMakefile(makefile string, module dekuModule) error {
	outFile := filenameNoExt(module.Name)

	f, err := os.Create(makefile)
	if err != nil {
		LOG_ERR(err, "Can't create Makefile file")
		return err
	}

	defer f.Close()

	fmt.Fprintf(f, "KBUILD_MODPOST_WARN = 1\n")
	fmt.Fprintf(f, "obj-m += %s.o\n", outFile)
	fmt.Fprintf(f, "%s-objs := livepatch.o", outFile)
	for _, patch := range module.Patches {
		fmt.Fprintf(f, " ../%s/patch.o", patch.Name)
	}
	fmt.Fprintf(f, "\nall:\n")
	fmt.Fprintf(f, "	make -C %s M=\"%s%s\" modules\n", config.linuxHeadersDir, config.workdir, outFile)

	_, err = os.Create(filepath.Dir(makefile) + "/.patch.o.cmd")
	if err != nil {
		LOG_ERR(err, "Failed to create command file for patch")
		return err
	}

	return err
}

func generateDiffObject(patchName string, file string) ([]string, error) {
	fileName := filenameNoExt(file)
	patchDir := filepath.Join(config.workdir, patchName)
	oFile := patchDir + "/" + fileName + ".o"
	originObjFile := config.buildDir + file[:len(file)-1] + "o"
	var extractSyms []string
	var modSyms []string

	out, err := showDiff(originObjFile, oFile)
	if err != nil {
		LOG_ERR(errors.New(out), "Can't find modified functions for %s", file)
		return nil, err
	}

	LOG_DEBUG("Modified symbols:\n%s", out)

	tmpModFun := regexp.MustCompile(`\bModified function: (.+)\n`).FindAllStringSubmatch(out, -1)
	newFun := regexp.MustCompile(`\bNew function: (.+)\n`).FindAllStringSubmatch(out, -1)
	newVar := regexp.MustCompile(`\bNew variable: (.+)\n`).FindAllStringSubmatch(out, -1)

	for _, f := range tmpModFun {
		fun := f[1]
		if checkIfIsInitOrExit(oFile, fun) {
			continue
		}

		isWeak, err := isWeakSymbol(fun, oFile, "f")
		if err != nil {
			LOG_ERR(err, "Failed to check if the %s function is weak", fun)
			return nil, err
		}

		if isWeak {
			isWeak, err = isWeakSymbol(fun, config.buildDir+"vmlinux", "f")
			if err != nil {
				LOG_ERR(err, "Failed to check if the %s function is weak in vmlinux", fun)
				return nil, err
			}

			if !isWeak {
				LOG_INFO("The '%s' is a weak function and other implementation is provided in the kernel. Skip it.", fun)
				continue
			}
		}

		traceable, traceableCallers, nonTraceableCallers := checkIsTraceable(originObjFile, fun)
		if !traceable && len(traceableCallers) == 0 {
			LOG_ERR(nil, "Can't apply changes to '%s'. The '%s' function is not allowed to modify.", file, fun)
			return nil, errors.New("ERROR_FORBIDDEN_MODIFY")
		}

		if traceable {
			modSyms = append(modSyms, fun)
		} else {
			for _, sym := range nonTraceableCallers {
				extractSyms = append(extractSyms, sym)
			}
			for _, sym := range traceableCallers {
				modSyms = append(modSyms, sym)
				extractSyms = append(extractSyms, sym)
			}
		}
		extractSyms = append(extractSyms, fun)
	}

	if len(extractSyms) == 0 && len(newFun) == 0 && len(newVar) == 0 {
		return extractSyms, nil
	}

	for _, fun := range newFun {
		extractSyms = append(extractSyms, fun[1])
	}

	for _, variable := range newVar {
		extractSyms = append(extractSyms, variable[1])
	}

	err = extractSymbols(oFile, patchDir+"/patch.o", removeDuplicate(extractSyms),
		DEKU_PATCH_REF_SYM_PREFIX+patchName)
	if err != nil {
		LOG_ERR(mkError(ERROR_EXTRACT_SYMBOLS), "Failed to extract modified symbols for %s", file)
		return nil, err
	}

	return removeDuplicate(modSyms), nil
}

func findObjectFile(srcFile string) (string, error) {
	vmlinuxFiles := readLines(filepath.Join(config.workdir, VMLINUX_FILES_LIST))
	for _, file := range vmlinuxFiles {
		if file == srcFile {
			return "vmlinux", nil
		}
	}

	modulesFiles := readLines(filepath.Join(config.workdir, MODULES_FILES_LIST))
	for _, line := range modulesFiles {
		if strings.HasPrefix(line, srcFile) {
			baseFile := strings.Split(line, " ")[1]
			return baseFile + ".ko", nil
		}
	}

	return "", mkError(ERROR_CANT_FIND_OBJ)
}

func generateLivepatchSource(moduleDir string, patches []dekuPatch, cumulativeModule bool) error {
	outFilePath := filepath.Join(moduleDir, "livepatch.c")
	klpObjects := ""
	klpFuncPerObjFile := make(map[string]string)

	os.Remove(outFilePath)
	outFile, err := os.OpenFile(outFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	replaceModule := "false"
	if cumulativeModule {
		replaceModule = "true"
	}

	// Add to module necessary headers.
	_, err = outFile.WriteString(`
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/livepatch.h>
#include <linux/version.h>
`	)
	if err != nil {
		return err
	}

	for _, patch := range patches {
		objName := filenameNoExt(patch.ObjPath)
		objName = strings.ReplaceAll(objName, "-", "_")
		for _, symbol := range patch.ModFuncs {
			plainSymbol := strings.ReplaceAll(symbol, ".", "_")
			_, err = outFile.WriteString("void " + DEKU_FUN_PREFIX + plainSymbol + "(void);\n")
			if err != nil {
				return err
			}

			symPos, err := findSymbolIndex(symbol, "f", patch.SrcFile, config.buildDir+patch.ObjPath)
			if err != nil {
				return err
			}

			// Fill list of a klp_func struct.
			klpFuncPerObjFile[objName] += `
{
.old_name = "` + symbol + `",
.new_func = ` + DEKU_FUN_PREFIX + plainSymbol + `,
.old_sympos = ` + fmt.Sprint(symPos) + `
},`
		}
	}

	for objName, klpFunc := range klpFuncPerObjFile {
		// Add livepatching code.
		_, err = outFile.WriteString(`
static struct klp_func deku_funcs_`+objName+`[] = {`+klpFunc+` { }
};
		`)
		if err != nil {
			return err
		}

		klpObjName := "NULL"
		if objName != "vmlinux" {
			klpObjName = "\"" + objName + "\""
		}
		klpObjects += `
{
	.name = `+klpObjName+`,
	.funcs = deku_funcs_`+objName+`,
},`
	}

	_, err = outFile.WriteString(`
static struct klp_object deku_objs[] = {`+klpObjects+` { }
};

static struct klp_patch deku_patch = {
	.mod = THIS_MODULE,
	.objs = deku_objs,
	.replace = `+replaceModule+`,
};
	`)
	if err != nil {
		return err
	}

	// Append the contents of the MODULE_SUFFIX_FILE file to the end of the output file.
	suffix, err := resources.ReadFile(MODULE_SUFFIX_FILE)
	if err != nil {
		LOG_ERR(err, "Failed to read template file: %s", MODULE_SUFFIX_FILE)
		return err
	}

	_, err = outFile.Write(suffix)
	if err != nil {
		LOG_ERR(err, "Failed to write to file: %s", outFilePath)
		return err
	}

	return nil
}

func buildInKernel(srcFile string) (bool, error) {
	objPath, err := findObjectFile(srcFile)
	if err != nil && errorStrToCode(err) == ERROR_CANT_FIND_OBJ {
		err = nil
	}

	return objPath != "", err
}

func cleanUpPatch(patch dekuPatch) {
	// remove all but id and file with src path
	patchDir := filepath.Join(config.workdir, patch.Name)
	files, err := os.ReadDir(patchDir)
	if err != nil {
		LOG_ERR(err, "Failed to read dir %s", patchDir)
		return
	}

	for _, file := range files {
		if file.Name() != "id" && file.Name() != FILE_SRC_PATH {
			if err = os.Remove(filepath.Join(patchDir, file.Name())); err != nil {
				LOG_ERR(err, "Failed to remove file %s", file.Name())
			}
		}
	}
}

func generatePatch(file string, explicitModified, prevExists bool) (dekuPatch, error) {
	var err error
	patch := dekuPatch{
		SrcFile: file,
	}

	baseName := filepath.Base(file)
	fileName := filenameNoExt(file)
	patch.Name = generatePatchName(file)
	patchDir := filepath.Join(config.workdir, patch.Name)
	patch.PatchFile = filepath.Join(patchDir, "patch.o")
	patch.Id, err = generatePatchId(file)
	if err != nil {
		LOG_ERR(err, "Failed to generate patch ID for %s", file)
		return invalidatePatch(patch), err
	}

	if !fileExists(patchDir) {
		err = os.Mkdir(patchDir, 0755)
		if err != nil {
			LOG_ERR(err, "Failed to create directory for patch for %s", file)
			return invalidatePatch(patch), err
		}
	}

	err = os.WriteFile(patchDir+"/"+FILE_SRC_PATH, []byte(file), 0644)
	if err != nil {
		LOG_ERR(err, "Failed write file path to file for %s", file)
		return invalidatePatch(patch), err
	}

	builtin, err := buildInKernel(file)
	if err != nil {
		LOG_ERR(err, "Error during checking if file: %s is built-in into the kernel", file)
		return invalidatePatch(patch), err
	}

	if !builtin {
		var logFunc func(string, ...any)
		if explicitModified {
			logFunc = LOG_WARN
		} else {
			logFunc = LOG_DEBUG
		}

		logFunc("File '%s' is not used in the kernel or module. Skip", file)
		err = os.WriteFile(patchDir+"/id", []byte(patch.Id), 0644)
		if err != nil {
			LOG_ERR(err, "Failed to write patch ID to file for %s", file)
			return invalidatePatch(patch), err
		}

		cleanUpPatch(patch)
		return invalidatePatch(patch), nil
	}

	LOG_INFO("Processing %s...", file)
	os.Remove(patchDir + "/id")

	// Write diff to file for debug purpose
	diff := getFileDiff(file)
	if len(diff) > 0 {
		err = os.WriteFile(patchDir+"/diff", diff, 0644)
		if err != nil {
			LOG_ERR(err, "Failed to write diff for %s", file)
		}
	}

	// File name with prefix '_' is the origin file
	if config.kernSrcInstallDir != "" {
		err = copyFile(config.kernSrcInstallDir+"/"+file, patchDir+"/_"+baseName)
		if err != nil {
			LOG_ERR(err, "Failed to copy source file for %s", file)
			return invalidatePatch(patch), err
		}
	}

	filePath := config.filesSrcDir + "/" + file
	if !fileExists(filePath) {
		filePath = config.kernelSrcDir + file
	}
	err = copyFile(filePath, patchDir + "/" + baseName)
	if err != nil {
		LOG_ERR(err, "Failed to copy source file for %s", file)
		return invalidatePatch(patch), err
	}

	originObjectFile := config.buildDir+filepath.Dir(file)+"/"+fileName+".o"
	if LOG_LEVEL <= 1 {
		copyFile(originObjectFile, patchDir+"/_"+fileName+".o")
	}

	outFile := patchDir+"/"+fileName+".o"
	err = buildFile(file, patchDir+"/"+baseName, outFile)
	if err != nil {
		LOG_ERR(err, "Error while build %s", file)
		return invalidatePatch(patch), err
	}

	adjustAmbiguousSymbols(originObjectFile, outFile)
	if err != nil {
		LOG_ERR(err, "Error while adjust ambiguous symbols %s", file)
		return invalidatePatch(patch), err
	}

	patch.ModFuncs, err = generateDiffObject(patch.Name, file)
	if err != nil {
		LOG_ERR(err, "Error while finding modified functions in %s", file)
		return invalidatePatch(patch), err
	}

	err = os.WriteFile(filepath.Join(patchDir, MOD_SYMBOLS_FILE), []byte(strings.Join(patch.ModFuncs, "\n")), 0644)
	if err != nil {
		return invalidatePatch(patch), err
	}

	if len(patch.ModFuncs) == 0 {
		var logFunc func(string, ...any)
		if explicitModified {
			logFunc = LOG_INFO
		} else {
			logFunc = LOG_DEBUG
		}

		if prevExists {
			logFunc("Reverting changes from %s", file)
		} else {
			logFunc("No valid changes found in %s", file)
		}

		err = os.WriteFile(patchDir+"/id", []byte(patch.Id), 0644)
		if err != nil {
			LOG_ERR(err, "Failed to write patch ID to file for %s", file)
			return invalidatePatch(patch), err
		}

		cleanUpPatch(patch)
		return invalidatePatch(patch), nil
	}

	patch.ObjPath, err = findObjectFile(file)
	if err != nil {
		return invalidatePatch(patch), err
	}

	// Write the object file path to a file.
	err = os.WriteFile(filepath.Join(patchDir, FILE_OBJECT_PATH), []byte(patch.ObjPath), 0644)
	if err != nil {
		return invalidatePatch(patch), err
	}

	os.OpenFile(patchDir + "/.patch.o.cmd", os.O_RDONLY|os.O_CREATE, 0644)

	err = os.WriteFile(patchDir+"/id", []byte(patch.Id), 0644)
	if err != nil {
		LOG_ERR(err, "Failed to write patch ID for %s", file)
		return invalidatePatch(patch), err
	}

	return patch, nil
}

func generateModule(patches []dekuPatch, cumulativeModule bool) (dekuModule, error) {
	module := dekuModule{
		Name: fmt.Sprintf("%s_%d", generateBaseModuleName(patches), time.Now().Unix()),
		Patches: patches,
		Cumulative: cumulativeModule,
	}

	if len(patches) == 0 {
		LOG_DEBUG("Generate module %s to revert all changes", module.Name)
	} else {
		LOG_DEBUG("Generate module %s for patches: %s", module.Name, vv(patches))
	}

	moduleDir := filepath.Join(config.workdir, module.Name)
	os.MkdirAll(moduleDir, 0755)

	moduleIds := []string{}
	srcFiles := []string{}
	for _, patch := range module.Patches {
		moduleIds = append(moduleIds, patch.Id)
		srcFiles = append(srcFiles, patch.SrcFile)
	}

	module.ModuleId = strings.Join(moduleIds, ",")
	module.SrcFiles = strings.Join(srcFiles, ",")

	err := generateLivepatchSource(moduleDir, patches, cumulativeModule)
	if err != nil {
		LOG_ERR(err, "Failed to generate livepatch source file for %s", module.Name)
		return invalidateModule(module), err
	}

	err = generateLivepatchMakefile(moduleDir+"/Makefile", module)
	if err != nil {
		LOG_ERR(err, "Failed to generate livepatch Makefile file for %s", module.Name)
		return invalidateModule(module), err
	}

	err = buildLivepatchModule(moduleDir)
	if err != nil {
		LOG_ERR(err, "Failed to build livepatch module for %s", module.Name)
		return invalidateModule(module), err
	}
	module.KoFile = filepath.Join(moduleDir, module.Name+".ko")

	// Restore calls to origin func XYZ instead of __deku_fun_XYZ
	for _, patch := range module.Patches {
		for _, symbol := range patch.ModFuncs {
			plainSymbol := strings.ReplaceAll(symbol, ".", "_")
			err = changeCallSymbol(module.KoFile, DEKU_FUN_PREFIX+plainSymbol, plainSymbol)
			if err != nil {
				LOG_ERR(err, "Fail to change calls to %s in %s", plainSymbol, module.KoFile)
				return invalidateModule(module), err
			}

			stripSymbolArg := "--strip-symbol=" + DEKU_FUN_PREFIX + plainSymbol
			cmd := exec.Command(TOOLCHAIN+"objcopy", stripSymbolArg, module.KoFile)
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				LOG_ERR(err, "Fail to restore origin function names")
				return invalidateModule(module), err
			}
		}
	}

	err = adjustRelocations(module)
	if err != nil {
		LOG_DEBUG("Fail to adjust relocations: %s", err)
		return invalidateModule(module), err
	}

	// Add note to module with all relevant module information
	noteFile := filepath.Join(moduleDir, NOTE_FILE)

	text := module.Name + " " + module.ModuleId + " "
	for _, patch := range module.Patches {
		text += patch.Name + ":" + patch.SrcFile + ":"
		for _, symbol := range patch.ModFuncs {
			text += symbol+ ";"
		}
		text = strings.TrimSuffix(text, ";")
		text += "|"
	}

	err = os.WriteFile(noteFile, []byte(strings.TrimSuffix(text, "|")), 0644)
	if err != nil {
		LOG_ERR(err, "Failed to write the note file: %s", noteFile)
		return invalidateModule(module), err
	}

	cmd := exec.Command(TOOLCHAIN + "objcopy", "--add-section", ".note.deku="+noteFile,
	"--set-section-flags", ".note.deku=alloc,readonly", module.KoFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		LOG_ERR(err, "Failed to add note information to module for %s", module.SrcFiles)
		return invalidateModule(module), err
	}

	// write ID at the very end to indicate that the module has been successfully generated
	err = os.WriteFile(moduleDir+"/id", []byte(module.ModuleId), 0644)
	if err != nil {
		LOG_ERR(err, "Failed to write module ID for %s", module.Name)
		return invalidateModule(module), err
	}

	return module, nil
}
