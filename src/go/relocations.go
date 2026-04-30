// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

/*
#include <stdlib.h>

int _mklivepatch(const char *file, const char *relocations);
char* findObjWithSymbol(const char* sym, const char* srcFile, const char* objPath, const char* workdir, const char* kernelSrcDir, const char* buildDir);
*/
import "C"

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"unsafe"
)

//export generateSymbolsC
func generateSymbolsC(objFile *C.char) C.int {
	if generateSymbols(C.GoString(objFile)) {
		return 1
	}
	return 0
}

type relocation struct {
	Name      string
	SymType   elf.SymType
	PatchName string
	Pos       uint16
	SymIndex  uint32
}

// rewrite findObjWithSymbol to the C lang. Place this function in the new "relocations.c" file and use it

// findObjWithSymbol was rewritten to C and is declared in the Cgo block.

func getSymbolsToRelocate(module dekuModule, extraSymVers string) ([]relocation, error) {
	var syms []relocation
	ignoreSymbols := []string{"printk", "_printk", "__this_module"}
	undefinedSymbols, err := getUndefinedSymbols(module.KoFile)
	if err != nil {
		LOG_ERR(err, "Failed to fetch undefined symbols for %s", module.KoFile)
		return []relocation{}, err
	}

	for _, sym := range undefinedSymbols {
		symName := sym.Name
		patchName := ""
		for _, patch := range module.Patches {
			if strings.HasPrefix(symName, DEKU_PATCH_REF_SYM_PREFIX+patch.Name+"_") {
				symName = symName[len(DEKU_PATCH_REF_SYM_PREFIX+patch.Name+"_"):]
				patchName = patch.Name
				break
			}
		}

		if slicesContains(ignoreSymbols, symName) {
			continue
		}

		re := regexp.MustCompile("\\b" + symName + "\\b")
		if fileExists(config.linuxHeadersDir + "vmlinux.symvers") { // vmlinux.symvers in some kernel versions is combined into Module.symvers and not exists since v6.3
			symVers, err := os.ReadFile(config.linuxHeadersDir + "vmlinux.symvers")
			if err != nil {
				LOG_WARN("Failed to read file: %s. %s", config.linuxHeadersDir+"vmlinux.symvers", err)
			}

			if re.FindString(string(symVers)) != "" {
				continue
			}
		}

		symVers, err := os.ReadFile(config.linuxHeadersDir + "Module.symvers")
		if err != nil {
			LOG_WARN("Failed to read file: %s. %s", config.linuxHeadersDir+"Module.symvers", err)
		}

		if re.FindString(string(symVers)) != "" {
			continue
		}

		if extraSymVers != "" {
			symVers, err = os.ReadFile(config.linuxHeadersDir + extraSymVers)
			if err != nil {
				LOG_WARN("Failed to read file: %s. %s", config.linuxHeadersDir+"Module.symvers", err)
			}

			if re.FindString(string(symVers)) != "" {
				continue
			}
		}

		syms = append(syms, relocation{
			Name:      symName,
			SymType:   elf.ST_TYPE(sym.Info),
			Pos:       0,
			PatchName: patchName,
			SymIndex:  uint32(sym.Value),
		})
	}

	LOG_DEBUG("Symbols to relocate: %+v", syms)
	return syms, nil
}

func isContainsSymbol(objFilePath, symName, symType string) bool {
	LOG_DEBUG("Check if %s contains symbol: [%s] %s", objFilePath, symType, symName)
	e, err := Open(objFilePath)
	if err != nil {
		return false
	}
	defer e.Close()

	for _, symbol := range e.Symbols {
		if symbol.Size == 0 {
			continue
		}

		if (elf.ST_TYPE(symbol.Info) == elf.STT_FUNC ||
			elf.ST_TYPE(symbol.Info) == elf.STT_OBJECT || symType == "") &&
			symbol.Name == symName {
			if symType == "f" &&
				elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
				return true
			} else if symType == "v" &&
				elf.ST_TYPE(symbol.Info) == elf.STT_OBJECT {
				return true
			} else if symType == "" {
				return true
			}
		}
	}

	return false
}

func adjustRelocations(module dekuModule) error {
	var mklivepatchArgs = []string{}
	var relSyms = []string{}
	var missSymErr error = nil
	toRelocate, err := getSymbolsToRelocate(module, "")
	if err != nil {
		return err
	}

	for _, patch := range module.Patches {
		removeSymbolNamePrefix(module.KoFile, DEKU_PATCH_REF_SYM_PREFIX+patch.Name+"_")
	}

	if len(toRelocate) == 0 {
		return nil
	}

	mklivepatchArgs = append(mklivepatchArgs, module.KoFile)

	for _, symbol := range toRelocate {
		if symbol.Name == "_GLOBAL_OFFSET_TABLE_" {
			continue
		}

		objPath := ""
		srcFile := ""
		for _, patch := range module.Patches {
			if patch.Name == symbol.PatchName {
				objPath = patch.ObjPath
				srcFile = patch.SrcFile
				break
			}
		}

		csym := C.CString(symbol.Name)
		csrcFile := C.CString(srcFile)
		cobjPath := C.CString(objPath)
		cworkdir := C.CString(config.workdir)
		ckernelSrcDir := C.CString(config.kernelSrcDir)
		cbuildDir := C.CString(config.buildDir)

		cres := C.findObjWithSymbol(csym, csrcFile, cobjPath, cworkdir, ckernelSrcDir, cbuildDir)
		
		C.free(unsafe.Pointer(csym))
		C.free(unsafe.Pointer(csrcFile))
		C.free(unsafe.Pointer(cobjPath))
		C.free(unsafe.Pointer(cworkdir))
		C.free(unsafe.Pointer(ckernelSrcDir))
		C.free(unsafe.Pointer(cbuildDir))

		if cres == nil {
			LOG_ERR(nil, "Can't find symbol: %s", symbol.Name)
			os.Exit(ERROR_CANT_FIND_SYMBOL)
		}
		symObjPath := C.GoString(cres)
		C.free(unsafe.Pointer(cres))

		symType := ""
		if symbol.SymType == elf.STT_FUNC {
			symType = "f"
		} else if symbol.SymType == elf.STT_OBJECT {
			symType = "v"
		}

		index, err := findSymbolIndex(symbol.Name, symType, srcFile,
			config.buildDir+symObjPath)
		if err != nil {
			if index == -ERROR_CANT_FIND_SYM_INDEX {
				// check if defined
				found := isContainsSymbol(module.KoFile, symbol.Name, symType)
				if found {
					LOG_DEBUG("Missing symbol %s found in the own deku module", symbol.Name)
					continue
				}
			}
			return err
		}

		relSym := fmt.Sprintf("%s.%s@%d,%d", filenameNoExt(symObjPath), symbol.Name, symbol.SymIndex, index)
		mklivepatchArgs = append(mklivepatchArgs, "-r", relSym)
		relSyms = append(relSyms, relSym)
	}

	if missSymErr != nil {
		return missSymErr
	}

	if USE_EXTERNAL_EXECUTABLE {
		cmd := exec.Command("./mklivepatch", mklivepatchArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		LOG_DEBUG("%s", cmd.String())
		err = cmd.Run()
	} else {
		file := C.CString(module.KoFile)
		defer C.free(unsafe.Pointer(file))
		relocs := C.CString(strings.Join(relSyms, " "))
		defer C.free(unsafe.Pointer(relocs))
		errCode := C._mklivepatch(file, relocs)
		if errCode != 0 {
			err = errors.New("Making livepatch error: " + string(errCode))
		}
	}

	if err != nil {
		LOG_ERR(err, "Failed to mklivepatch for %s", module.Name)
		return err
	}

	cmd := exec.Command(TOOLCHAIN+"objcopy", "--wildcard", "--strip-symbol="+DEKU_PATCH_REF_SYM_PREFIX+"*", module.KoFile)
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		LOG_ERR(err, "Fail to strip temporary symbols")
		return err
	}

	return nil
}
