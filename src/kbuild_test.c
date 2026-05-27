/*
 * Copyright (c) 2024 Google LLC
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "kbuild.h"

bool ShowDebugLog = true;

void make_mock_environment() {
	system("rm -rf /tmp/deku_kbuild_test");
	system("mkdir -p /tmp/deku_kbuild_test");
	
	// Write mock compiler config file
	FILE *f = fopen("/tmp/deku_kbuild_test/.test_src.o.cmd", "w");
	if (f) {
		fprintf(f, "savedcmd_/tmp/deku_kbuild_test/test_src.o := gcc -DTEST -I/some/sys/inc -I/some/kernel/src/include -Wdeclaration-after-statement -o test_src.o test_src.c ; ./tools/objtool/objtool someflag test_src.o\n");
		fclose(f);
	}
	
	// Write empty C files
	system("touch /tmp/deku_kbuild_test/test_src.c");
	
	// Write mock objtool
	system("mkdir -p /tmp/deku_kbuild_test/tools/objtool");
	FILE *objtool = fopen("/tmp/deku_kbuild_test/tools/objtool/objtool", "w");
	if (objtool) {
		fprintf(objtool, "#!/bin/sh\necho \"MOCK OBJTOOL ARCHIVING $1 $2 $3\"\n");
		fclose(objtool);
	}
	system("chmod +x /tmp/deku_kbuild_test/tools/objtool/objtool");
}

int main() {
	make_mock_environment();
	
	// Setup Config globals
	config.buildDir = "/tmp/deku_kbuild_test";
	config.filesSrcDir = "/tmp/deku_kbuild_test/";
	config.kernelSrcDir = "/tmp/deku_kbuild_test/";
	config.linuxHeadersDir = "/tmp/deku_kbuild_test/";
	config.isModule = false;
	config.useLLVM = "";
	config.isAARCH64 = false;
	
	printf("=========================================\n");
	printf("Running kbuild test with mock environment\n");
	printf("=========================================\n");
	
	int res = buildFile("test_src.c", "test_src.c", "test_src.o");
	printf("buildFile returned: %d\n", res);
	
	printf("=========================================\n");
	
	// Clean up
	system("rm -rf /tmp/deku_kbuild_test");
	return res == 0 ? 0 : 1;
}
