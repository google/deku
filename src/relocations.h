/*
 * Copyright (c) 2024 Google LLC
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef RELOCATIONS_H
#define RELOCATIONS_H

typedef struct {
	char *name;
	int symType;
	char *patchName;
	unsigned short pos;
	unsigned int symIndex;
} Relocation;

Relocation* getSymbolsToRelocate(const char *koFile, int patchCount, char **patchNames,
                                 const char *linuxHeadersDir, const char *extraSymVers, int *outCount);
void freeRelocations(Relocation *relocs, int count);

#endif /* RELOCATIONS_H */
