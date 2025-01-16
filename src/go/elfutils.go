// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

/*
#include <stdlib.h>
#include "../elfutils.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unsafe"
)

func showDiff(filepathA, filepathB string) (string, error) {
	debug := ""
	if LOG_LEVEL <= 1 {
		C.ShowDebugLog = true
		debug = "-v"
	}

	if USE_EXTERNAL_EXECUTABLE {
		out, err := exec.Command("./elfutils", "--diff", "-a", filepathA, "-b",
			filepathB, debug).CombinedOutput()
		if err != nil {
			LOG_ERR(errors.New(string(out)), "Can't find modified functions for %s", filepathA)
			return "", err
		}
		diff := string(out)
		return diff, nil
	} else {
		fileA := C.CString(filepathA)
		fileB := C.CString(filepathB)
		diff := C.GoString(C.showDiff(fileA, fileB))
		C.free(unsafe.Pointer(fileB))
		C.free(unsafe.Pointer(fileA))

		return diff, nil
	}
}

func extractSymbols(filePath, outFile string, symToCopy []string, patchName string) error {
	debug := ""
	if LOG_LEVEL <= 1 {
		C.ShowDebugLog = true
		debug = "-v"
	}

	if USE_EXTERNAL_EXECUTABLE {
		cmd := exec.Command("./elfutils", "--extract", "-f", filePath, "-o", outFile, "-p", patchName, debug)
		for _, sym := range symToCopy {
			cmd.Args = append(cmd.Args, "-s")
			cmd.Args = append(cmd.Args, sym)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			LOG_ERR(errors.New(string(out)), "Failed to extract modified symbols for %s", filePath)
			return err
		}
	} else {
		path := C.CString(filePath)
		out := C.CString(outFile)
		syms := C.CString(strings.Join(symToCopy, ","))
		prefix := C.CString(patchName)
		res := C.extractSymbols(path, out, syms, prefix)
		C.free(unsafe.Pointer(prefix))
		C.free(unsafe.Pointer(syms))
		C.free(unsafe.Pointer(out))
		C.free(unsafe.Pointer(path))

		if res != 0 {
			return errors.New(fmt.Sprintf("Failed to extract symbols from %s. Error code: %d", filePath, res))
		}
	}
	return nil
}

func changeCallSymbol(filePath, fromRelSym, toRelSym string) error {
	if USE_EXTERNAL_EXECUTABLE {
		args := []string{"--changeCallSymbol", "-s", fromRelSym, "-d", toRelSym}
		if LOG_LEVEL <= 1 {
			args = append(args, "-v")
		}
		args = append(args, filePath)
		cmd := exec.Command("./elfutils", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	} else {
		if LOG_LEVEL <= 1 {
			C.ShowDebugLog = true
		}

		file := C.CString(filePath)
		srcRelSym := C.CString(fromRelSym)
		dstRelSym := C.CString(toRelSym)
		res := C.changeCallSymbol(file, srcRelSym, dstRelSym)
		C.free(unsafe.Pointer(dstRelSym))
		C.free(unsafe.Pointer(srcRelSym))
		C.free(unsafe.Pointer(file))

		if res == -1 {
			return fmt.Errorf("Failed to change symbols call in %s. Error code: %d", filePath, res)
		}

		return nil
	}
}

func referenceFrom(file, funName string) (string, error) {
	debug := ""
	if LOG_LEVEL <= 1 {
		C.ShowDebugLog = true
		debug = "-v"
	}

	if USE_EXTERNAL_EXECUTABLE {
		out, err := exec.Command("./elfutils", "--referenceFrom", "-f", file, "-s", funName, debug).Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSuffix(string(out), "\n"), nil
	} else {
		path := C.CString(file)
		symName := C.CString(funName)
		res := C.symbolReferenceFrom(path, symName)
		C.free(unsafe.Pointer(symName))
		C.free(unsafe.Pointer(path))
		if res == nil {
			return "", errors.New(fmt.Sprintf("Failed to find references for symbol %s.", funName))
		}

		refersFrom := C.GoString(res)
		return strings.TrimSuffix(refersFrom, "\n"), nil
	}
}

func removeSymbolNamePrefix(file, symPrefix string) error {
	if USE_EXTERNAL_EXECUTABLE {
		args := []string{"--removePrefix", "-p", symPrefix}
		if LOG_LEVEL <= 1 {
			args = append(args, "-v")
		}
		args = append(args, file)
		cmd := exec.Command("./elfutils", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	} else {
		if LOG_LEVEL <= 1 {
			C.ShowDebugLog = true
		}

		path := C.CString(file)
		prefix := C.CString(symPrefix)
		res := C.removeSymbolNamePrefix(path, prefix)
		C.free(unsafe.Pointer(prefix))
		C.free(unsafe.Pointer(path))
		if res != 0 {
			return errors.New(fmt.Sprintf("Failed to remove prefix '%s' from symbols name.", symPrefix))
		}
	}

	return nil
}

func adjustAmbiguousSymbols(originFilePath, patchedFilePath string) error {
	debug := ""
	if LOG_LEVEL <= 1 {
		C.ShowDebugLog = true
		debug = "-v"
	}

	if USE_EXTERNAL_EXECUTABLE {
		cmd := exec.Command("./elfutils", "--adjustAmbiguousSymbols", "-o", originFilePath, "-p", patchedFilePath, debug)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	} else {
		originFile := C.CString(originFilePath)
		patchedFile := C.CString(patchedFilePath)
		res := C.adjustAmbiguousSymbols(originFile, patchedFile)
		C.free(unsafe.Pointer(patchedFile))
		C.free(unsafe.Pointer(originFile))

		if res != 0 {
			return errors.New(fmt.Sprintf("Failed to adjust ambiguous symbols in %s. Error code: %d", patchedFilePath, res))
		}
	}
	return nil
}

func removeSection(file, section_name string) error {
	if LOG_LEVEL <= 1 {
		C.ShowDebugLog = true
	}

	path := C.CString(file)
	secName := C.CString(section_name)
	res := C.removeSection(path, secName)
	C.free(unsafe.Pointer(secName))
	C.free(unsafe.Pointer(path))
	if res != 0 {
		return errors.New(fmt.Sprintf("Failed to remove helper section for symbol %s.", section_name))
	}

	return nil
}
