// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

/*
#include <stdlib.h>
#include "../relocations.h"

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

// getSymbolsToRelocate was rewritten to C and is declared in the Cgo block.
func getSymbolsToRelocate(module dekuModule, extraSymVers string) ([]relocation, error) {
	var patchNames []*C.char
	for _, p := range module.Patches {
		patchNames = append(patchNames, C.CString(p.Name))
	}
	defer func() {
		for _, p := range patchNames {
			C.free(unsafe.Pointer(p))
		}
	}()

	var cPatchNames **C.char
	if len(patchNames) > 0 {
		cPatchNames = (**C.char)(unsafe.Pointer(&patchNames[0]))
	}

	cKoFile := C.CString(module.KoFile)
	defer C.free(unsafe.Pointer(cKoFile))
	cLinuxHeadersDir := C.CString(config.linuxHeadersDir)
	defer C.free(unsafe.Pointer(cLinuxHeadersDir))
	cExtraSymVers := C.CString(extraSymVers)
	defer C.free(unsafe.Pointer(cExtraSymVers))

	var outCount C.int
	cRelocs := C.getSymbolsToRelocate(cKoFile, C.int(len(patchNames)), cPatchNames, cLinuxHeadersDir, cExtraSymVers, &outCount)
	if cRelocs == nil && outCount < 0 {
		err := errors.New("failed to get symbols to relocate in C")
		LOG_ERR(err, "Failed to fetch undefined symbols for %s", module.KoFile)
		return []relocation{}, err
	}
	defer C.freeRelocations(cRelocs, outCount)

	var syms []relocation
	if outCount > 0 && cRelocs != nil {
		slice := unsafe.Slice(cRelocs, int(outCount))
		for _, r := range slice {
			syms = append(syms, relocation{
				Name:      C.GoString(r.name),
				SymType:   elf.SymType(r.symType),
				PatchName: C.GoString(r.patchName),
				Pos:       uint16(r.pos),
				SymIndex:  uint32(r.symIndex),
			})
		}
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
