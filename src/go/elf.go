// Copyright (c) 2024 Google LLC
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

type ELF struct {
	file     *elf.File
	Sections []*elf.Section
	Symbols  []elf.Symbol
	Strtab   elf.Section
}

func Open(file string) (*ELF, error) {
	e := ELF{
		file:     nil,
		Sections: nil,
		Symbols:  nil,
	}
	f, err := elf.Open(file)
	if err != nil {
		LOG_ERR(err, "Couldn’t open ELF file %s", file)
		return &e, err
	}

	e.file = f
	e.Sections = f.Sections
	e.Symbols, err = f.Symbols()
	if err != nil {
		LOG_ERR(err, " Failed to get symbols from %s", file)
		return &e, err
	}

	for _, section := range e.Sections {
		if section.Type == elf.SHT_STRTAB {
			e.Strtab = *section
			break
		}
	}
	return &e, nil
}

func (e ELF) Close() {
	err := e.file.Close()
	if err != nil {
		LOG_ERR(err, "Couldn’t close ELF file")
	}
}

func (e ELF) getSectionByName(sectionName string) (*elf.Section, error) {
	for _, section := range e.Sections {
		if section.Name == sectionName {
			return section, nil
		}
	}

	return nil, errors.New(fmt.Sprint("Can't find section %s", sectionName))
}

func (e ELF) getSymbolByName(name string) (elf.Symbol, uint32, error) {
	for i, sym := range e.Symbols {
		if sym.Name == name {
			return sym, uint32(i + 1), nil
		}
	}

	return elf.Symbol{}, 0, errors.New(fmt.Sprintf("Can't find symbol with name: ", name))
}

func (e ELF) getSymbolByNameAndType(name string, symType elf.SymType) elf.Symbol {
	for _, sym := range e.Symbols {
		if sym.Name == name && elf.ST_TYPE(sym.Info) == symType {
			return sym
		}
	}

	return elf.Symbol{}
}

func (e ELF) getRelocsForFunction(funName string) ([]elf.Rela64, error) {
	var result []elf.Rela64
	sym, _, err := e.getSymbolByName(funName)
	if err != nil {
		return nil, err
	}

	for _, section := range e.Sections {
		if section.Type == elf.SHT_RELA && section.Info == uint32(sym.Section) {
			for i := 0; i < int(section.Size); i += elf.Sym64Size {
				bytes := make([]byte, elf.Sym64Size)
				section.ReadAt(bytes, int64(i))
				rela := *(*elf.Rela64)(unsafe.Pointer(&bytes[0]))
				if rela.Off >= sym.Value && rela.Off < sym.Value+sym.Size {
					result = append(result, rela)
				}
			}
		}
	}
	return result, nil
}

func isTraceableAArch64(e *ELF, funName string) bool {
	sym, _, err := e.getSymbolByName(funName)
	if err != nil {
		LOG_ERR(err, "Can't find function symbol %s", funName)
		return false
	}

	symSecIndex := 0
	for i, symbol := range e.Symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_SECTION && symbol.Section == sym.Section {
			symSecIndex = i + 1
			break
		}
	}

	for _, section := range e.Sections {
		if section.Type == elf.SHT_RELA && section.Name == ".rela__patchable_function_entries" {
			for i := 0; i < int(section.Size); i += elf.Sym64Size {
				bytes := make([]byte, elf.Sym64Size)
				section.ReadAt(bytes, int64(i))
				rela := *(*elf.Rela64)(unsafe.Pointer(&bytes[0]))
				if int(elf.R_SYM64(rela.Info)) == symSecIndex && uint64(rela.Addend) == sym.Value {
					return true
				}
			}
		}
	}

	return false
}

func isTraceablex86(e *ELF, funName string) bool {
	_, fentryIdx, err := e.getSymbolByName("__fentry__")
	if err != nil {
		return false
	}

	relocs, err := e.getRelocsForFunction(funName)
	if err == nil && len(relocs) > 0 {
		if elf.R_SYM64(relocs[0].Info) == fentryIdx {
			return true
		}
	}
	return false
}

func findTraceableCallers(file, funName, rootFun string, traceableCallers, nonTraceableCallers []string, e *ELF) ([]string, []string, error) {
	refersFrom, err := referenceFrom(file, funName)
	if err != nil {
		return traceableCallers, nonTraceableCallers, err
	}

	if len(refersFrom) == 0 {
		LOG_DEBUG("Couldn't find traceable (in)direct caller of %s", rootFun)
		return traceableCallers, nonTraceableCallers, mkError(ERROR_NOT_TRACEABLE)
	}

	for _, rSym := range strings.Split(refersFrom, "\n") {
		rSymName := rSym[2:]
		if rSym[:2] == "v:" {
			LOG_DEBUG("The non-traceable function %s is (in)directly referenced from variable %s", rootFun, rSymName)
			return traceableCallers, nonTraceableCallers, mkError(ERROR_NOT_TRACEABLE)
		}

		if funName == rSymName || rootFun == rSymName || slicesContains(traceableCallers, rSymName) || slicesContains(nonTraceableCallers, rSymName) {
			continue
		}

		var isTraceable = false
		if config.isAARCH64 {
			isTraceable = isTraceableAArch64(e, rSymName)
		} else {
			isTraceable = isTraceablex86(e, rSymName)
		}

		if isTraceable {
			LOG_DEBUG("The non-traceable function %s is (in)directly called from traceable function %s", rootFun, rSymName)
			traceableCallers = append(traceableCallers, rSymName)
		} else {
			if elf.ST_BIND(e.getSymbolByNameAndType(rSymName, elf.STT_FUNC).Info) != elf.STB_LOCAL {
				LOG_DEBUG("The non-traceable function %s is (in)directly called from other non-traceable function %s that is not local", rootFun, rSymName)
				return traceableCallers, nonTraceableCallers, mkError(ERROR_NOT_TRACEABLE)
			}

			LOG_DEBUG("The non-traceable function %s is (in)directly called from other non-traceable function %s", rootFun, rSymName)
			nonTraceableCallers = append(nonTraceableCallers, rSymName)
			traceableCallers, nonTraceableCallers, err = findTraceableCallers(file, rSymName, rootFun, traceableCallers, nonTraceableCallers, e)
			if err != nil {
				return traceableCallers, nonTraceableCallers, mkError(ERROR_NOT_TRACEABLE)
			}
		}
	}

	return traceableCallers, nonTraceableCallers, nil
}

func checkIsTraceable(file string, funName string) (bool, []string, []string) {
	e, err := Open(file)
	if err != nil {
		return false, []string{}, []string{}
	}
	defer e.Close()

	var isTraceable = false
	if config.isAARCH64 {
		isTraceable = isTraceableAArch64(e, funName)
	} else {
		isTraceable = isTraceablex86(e, funName)
	}

	if isTraceable {
		return true, []string{}, []string{}
	}

	sym, _, err := e.getSymbolByName(funName)
	if err != nil {
		LOG_WARN("Can't find function %s in the %s", funName, file)
		return false, []string{}, []string{}
	}

	if elf.ST_BIND(sym.Info) != elf.STB_LOCAL {
		LOG_DEBUG("The '%s' function is forbidden to modify. The function is non-local", funName)
		return false, []string{}, []string{}
	}

	traceableCallers, nonTraceableCallers := []string{}, []string{}
	traceableCallers, nonTraceableCallers, err = findTraceableCallers(file, funName, funName, traceableCallers, nonTraceableCallers, e)
	if err != nil || len(traceableCallers) == 0 {
		LOG_DEBUG("The '%s' function has no traceable callers", funName)
		return false, []string{}, []string{}
	}

	return false, traceableCallers, nonTraceableCallers
}

func checkIfIsInitOrExit(file string, funName string) bool {
	e, err := Open(file)
	if err != nil {
		return false
	}
	defer e.Close()

	symbol, _, err := e.getSymbolByName(funName)
	if err != nil {
		return false
	}

	secName := e.Sections[symbol.Section].Name
	if secName == ".init.text" {
		LOG_INFO(fmt.Sprintf("The init function '%s' in the %s.c has been modified. Any changes made to this function will not be applied.", funName, filenameNoExt(file)))
		return true
	}
	if secName == ".exit.text" {
		LOG_INFO(fmt.Sprintf("The exit function '%s' in the %s.c has been modified. Any changes made to this function will not be applied.", funName, filenameNoExt(file)))
		return true
	}

	return false
}

func getFunctionsName(file string) ([]string, error) {
	var funcs []string
	e, err := Open(file)
	if err != nil {
		return nil, err
	}
	defer e.Close()

	for _, symbol := range e.Symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC && symbol.Size > 0 {
			funcs = append(funcs, symbol.Name)
		}
	}

	return funcs, err
}

func getVariablesName(file string) ([]string, error) {
	var funcs []string
	e, err := Open(file)
	if err != nil {
		return nil, err
	}
	defer e.Close()

	for _, symbol := range e.Symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_OBJECT && symbol.Size > 0 {
			funcs = append(funcs, symbol.Name)
		}
	}

	return funcs, nil
}

func isSymbolExists(file, symName string, symType elf.SymType) (bool, error) {
	e, err := Open(file)
	if err != nil {
		return false, err
	}
	defer e.Close()

	for _, symbol := range e.Symbols {
		if symbol.Name == symName && symbol.Size > 0 &&
			(symType == elf.STT_NOTYPE || elf.ST_TYPE(symbol.Info) == symType) {
			return true, nil
		}
	}

	return false, nil
}

func getUndefinedSymbols(objFile string) ([]elf.Symbol, error) {
	var symbols []elf.Symbol

	e, err := Open(objFile)
	if err != nil {
		return nil, err
	}
	defer e.Close()

	for i, symbol := range e.Symbols {
		if symbol.Section == 0 && len(symbol.Name) > 0 &&
			(elf.ST_TYPE(symbol.Info) == elf.STT_OBJECT ||
				elf.ST_TYPE(symbol.Info) == elf.STT_FUNC ||
				elf.ST_TYPE(symbol.Info) == elf.STT_NOTYPE) {
			symbol.Value = uint64(i + 1)
			symbols = append(symbols, symbol)
		}
	}

	return symbols, nil
}

func isWeakSymbol(symbolName, objFile, symType string) (bool, error) {
	e, err := Open(objFile)
	if err != nil {
		return false, err
	}

	defer e.Close()

	stt := elf.STT_FUNC
	if symType == "v" {
		stt = elf.STT_OBJECT
	}

	for _, symbol := range e.Symbols {
		if symbol.Name == symbolName && elf.ST_TYPE(symbol.Info) == stt {
			return elf.ST_BIND(symbol.Info) == elf.STB_WEAK, nil
		}
	}

	return false, mkError(ERROR_CANT_FIND_SYMBOL)
}
