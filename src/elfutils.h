/*
 * Copyright (c) 2024 Google LLC
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdbool.h>

extern bool ShowDebugLog;

char *showDiff(char *firstFile, char *secondFile);
int extractSymbols(char *filePath, char *outFile, char *symToCopy, char *prefix);
int changeCallSymbol(char *filePath, char *fromRelSym, char *toRelSym);
char *disassemble(char *filePath, char *symName, bool convertToReloc);
char *symbolReferenceFrom(char *filePath, char *symName);
int removeSymbolNamePrefix(const char *filePath, const char *prefix);
int adjustAmbiguousSymbols(const char *originFilePath, const char *patchedFilePath);
int removeSection(const char *filePath, const char *section_name);
