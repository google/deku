/*
 * Copyright (c) 2024 Google LLC
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef DEKU_KBUILD_H
#define DEKU_KBUILD_H

#include <stdbool.h>

typedef struct {
	char *buildDir;
	char *filesSrcDir;
	char *kernelSrcDir;
	char *linuxHeadersDir;
	bool isModule;
	bool isAARCH64;
	char *useLLVM;
	char *workdir;
} Config;

extern Config config;

int buildFile(const char *srcFile, const char *compileFile, const char *outFile);

#endif /* DEKU_KBUILD_H */
