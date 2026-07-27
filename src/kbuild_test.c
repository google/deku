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
		fprintf(f, "savedcmd_/tmp/deku_kbuild_test/test_src.o := gcc -c -DTEST -I/some/sys/inc -I/some/kernel/src/include -Wdeclaration-after-statement -o test_src.o test_src.c ; ./tools/objtool/objtool someflag test_src.o\n");
		fclose(f);
	}
	
	// Write empty C files
	system("touch /tmp/deku_kbuild_test/test_src.c");

	// Write mock Makefile
	FILE *mk = fopen("/tmp/deku_kbuild_test/Makefile", "w");
	if (mk) {
		fprintf(mk, "all:\n\t@echo 'Building mock module'\n\ttouch test_mod.ko\n");
		fclose(mk);
	}

	// Write mock failing module environment
	system("rm -rf /tmp/deku_kbuild_test_fail");
	system("mkdir -p /tmp/deku_kbuild_test_fail/sub");
	system("touch /tmp/deku_kbuild_test_fail/_test.o");
	system("touch /tmp/deku_kbuild_test_fail/sub/_test_sub.o");
	FILE *mk_fail = fopen("/tmp/deku_kbuild_test_fail/Makefile", "w");
	if (mk_fail) {
		fprintf(mk_fail, "all:\n\t@echo '/tmp/deku_kbuild_test_fail/bad.c:15:4: error: unknown type name'\n\t@exit 1\n");
		fclose(mk_fail);
	}

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

	int res1 = buildFile("test_src.c", "/tmp/deku_kbuild_test/test_src.c", "/tmp/deku_kbuild_test/test_src.o");
	printf("buildFile returned: %d\n", res1);

	int res2 = buildModules("/tmp/deku_kbuild_test");
	printf("buildModules returned: %d\n", res2);

	int res3 = buildLivepatchModule("/tmp/deku_kbuild_test");
	printf("buildLivepatchModule returned: %d\n", res3);

	int res4 = buildModules("/tmp/deku_kbuild_test_fail");
	printf("buildModules (expected fail) returned: %d\n", res4);

	struct stat st;
	if (stat("/tmp/deku_kbuild_test_fail/_test.o", &st) == 0) {
		printf("Error: _test.o was not removed!\n");
		res4 = 0;
	}
	if (stat("/tmp/deku_kbuild_test_fail/sub/_test_sub.o", &st) == 0) {
		printf("Error: sub/_test_sub.o was not removed!\n");
		res4 = 0;
	}

	printf("=========================================\n");

	// Clean up
	system("rm -rf /tmp/deku_kbuild_test /tmp/deku_kbuild_test_fail");
	int res = (res1 == 0 && res2 == 0 && res3 == 0 && res4 != 0) ? 0 : -1;
	return res == 0 ? 0 : 1;
}
