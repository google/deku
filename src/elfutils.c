/*
 * Copyright (c) 2024 Google LLC
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

/*
 * Utility to manipulate object file
 */

#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "elfutils.h"
#include "libelfutils.h"

static void help(const char *execName)
{
	error(EXIT_FAILURE, EINVAL, "Usage: %s [-diff|--callchain|--extract|"
										   "--changeCallSymbol|--disassemble|"
										   "--referenceFrom|--adjustAmbiguousSymbols"
										   "] ...", execName);
}

static int _showDiff(int argc, char *argv[])
{
	char *firstFile = NULL;
	char *secondFile = NULL;
	int ret = 0;
	int opt;
	while ((opt = getopt(argc, argv, "a:b:v")) != -1)
	{
		switch (opt)
		{
		case 'a':
			firstFile = optarg;
			break;
		case 'b':
			secondFile = optarg;
			break;
		}
	}

	if (firstFile == NULL || secondFile == NULL)
	{
		free(secondFile);
		free(firstFile);

		error(EXIT_FAILURE, EINVAL, "Invalid parameters to show difference between objects file. Valid parameters:"
			  "-a <ELF_FILE> -b <ELF_FILE> [-v]");
	}

	const char *result = showDiff(firstFile, secondFile);
	if (result == NULL)
		ret = -1;
	else
		printf("%s", result);

	return ret;
}

static int _extractSymbols(int argc, char *argv[])
{
	char *filePath = NULL;
	char *outFile = NULL;
	char *prefix = NULL;
	int ret = 0;
	char *symToCopy = (char *)calloc(1, sizeof(char));
	if (!CHECK_ALLOC(symToCopy))
		goto err;

	int opt;
	while ((opt = getopt(argc, argv, "f:o:s:p:v")) != -1)
	{
		switch (opt)
		{
		case 'f':
			filePath = optarg;
			break;
		case 'o':
			outFile = optarg;
			break;
		case 's':
			symToCopy = REALLOC(symToCopy, strlen(symToCopy) + strlen(optarg) + 2);
			if (!CHECK_ALLOC(symToCopy))
				goto err;

			strcat(symToCopy, optarg);
			strcat(symToCopy, ",");
			break;
		case 'p':
			prefix = optarg;
			break;
		}
	}

	if (filePath == NULL || outFile == NULL || prefix == NULL || symToCopy[0] == '\0')
	{
		free(symToCopy);
		error(EXIT_FAILURE, EINVAL, "Invalid parameters to extract symbols. Valid parameters:"
			  "-f <ELF_FILE> -o <OUT_FILE> -s <SYMBOL_NAME> -p <KLP_RELOC_SYM_PREFIX> [-n <SKIP_DEP_SYMBOL>] [-v]");
	}

	symToCopy[strlen(symToCopy)-1] = '\0';
	ret = extractSymbols(filePath, outFile, symToCopy, prefix);

out:
	free(symToCopy);
	return ret;

err:
	ret = -1;
	goto out;
}

static int _changeCallSymbol(int argc, char *argv[])
{
	char *filePath = NULL;
	int opt;
	char *fromRelSym = NULL;
	char *toRelSym = NULL;

	while ((opt = getopt(argc, argv, "vhs:d:")) != -1)
	{
		switch (opt)
		{
		case 's':
			fromRelSym = optarg;
			break;
		case 'd':
			toRelSym = optarg;
			break;
		case '?':
		case 'h':
			help(argv[0]);
			break;
		case ':':
			LOG_ERR("Missing arg for %c", optopt);
			break;
		}
	}

	if (optind - 1 < argc)
	{
		filePath = argv[optind++];
		while (optind < argc)
			LOG_ERR("Unknown parameter: %s", argv[optind++]);
	}

	if (filePath == NULL || fromRelSym == NULL || toRelSym== NULL)
	{
		free(fromRelSym);
		free(toRelSym);

		error(EXIT_FAILURE, EINVAL, "Invalid parameters to change calling function. Valid parameters:"
			  "-s <SYMBOL_NAME_SOURCE> -d <SYMBOL_NAME_DEST> [-v] <MODULE.ko>");
	}

	if (changeCallSymbol(filePath, fromRelSym, toRelSym) == 0)
	{
		LOG_ERR("No relocation has been replaced");
		return -1;
	}

	return 0;
}

static int _disassemble(int argc, char *argv[])
{
	char *filePath = NULL;
	char *symName = NULL;
	bool convertToReloc = false;
	int result = 0;
	int opt;
	while ((opt = getopt(argc, argv, "f:s:rv")) != -1)
	{
		switch (opt)
		{
		case 'f':
			filePath = optarg;
			break;
		case 's':
			symName = optarg;
			break;
		case 'r':
			convertToReloc = true;
			break;
		}
	}

	if (filePath == NULL || symName == NULL)
	{
		free(symName);
		free(filePath);

		error(EXIT_FAILURE, 0, "Invalid parameters to disassemble. Valid parameters:"
			  "-f <ELF_FILE> -s <SYMBOL_NAME> [-r] [-v]");
	}

	char *disassembled = disassemble(filePath, symName, convertToReloc);
	if (disassembled == NULL)
	{
		result = -1;
	}
	else
	{
		if (strlen(disassembled) > 0)
			disassembled[strlen(disassembled) - 1] = '\0';

		puts(disassembled);

#ifdef OUTPUT_DISASSEMBLY_TO_FILE
		FILE  *fptr = fopen("disassembly", "w");
		if(fptr == NULL)
		{
			result = -1;
			LOG_ERR("Can't open output file for disassembly");
		}
		else
		{
			fputs(disassembled, fptr);
			fclose(fptr);
		}
#endif
	}

	free(disassembled);

	return result;
}

static int _symbolReferenceFrom(int argc, char *argv[])
{
	char *filePath = NULL;
	char *symName = NULL;
	int result = 0;
	int opt;
	while ((opt = getopt(argc, argv, "f:s:v")) != -1)
	{
		switch (opt)
		{
		case 'f':
			filePath = optarg;
			break;
		case 's':
			symName = optarg;
			break;
		}
	}

	if (filePath == NULL || symName == NULL)
	{
		free(symName);
		free(filePath);

		error(EXIT_FAILURE, 0, "Invalid parameters to find symbols referenced to. Valid parameters:"
			  "-f <ELF_FILE> -s <SYMBOL_NAME> [-v]");
	}

	char *syms = symbolReferenceFrom(filePath, symName);
	if (syms == NULL)
		result = -1;
	else
		printf("%s", syms);

	free(syms);

	return result;
}

static int _removePrefix(int argc, char *argv[])
{
	int opt;
	const char *filePath = NULL;
	const char *prefix = NULL;

	while ((opt = getopt(argc, argv, "p:v")) != -1)
	{
		switch (opt)
		{
		case 'p':
			prefix = optarg;
			break;
		}
	}

	if (optind - 1 < argc)
	{
		filePath = argv[optind++];
		while (optind < argc)
			LOG_ERR("Unknown parameter: %s", argv[optind++]);
	}

	if (filePath == NULL || prefix == NULL)
	{
		error(EXIT_FAILURE, EINVAL, "Invalid parameters to remove prefix from symbols name. Valid parameters:"
			  "-p <SYMBOL_NAME_SOURCE> [-v] <FILE>");
	}

	return removeSymbolNamePrefix(filePath, prefix);
}

static int _adjustAmbiguousSymbols(int argc, char *argv[])
{
	char *firstFile = NULL;
	char *secondFile = NULL;
	int ret = 0;
	int opt;
	while ((opt = getopt(argc, argv, "o:p:v")) != -1)
	{
		switch (opt)
		{
		case 'o':
			firstFile = optarg;
			break;
		case 'p':
			secondFile = optarg;
			break;
		}
	}

	if (firstFile == NULL || secondFile == NULL)
	{
		free(secondFile);
		free(firstFile);

		error(EXIT_FAILURE, EINVAL, "Invalid parameters to adjust ambiguous symbols. Valid parameters:"
			  "-o <ORIGIN_OBJECT_FILE> -p <PATCHED_OBJECT_FILE> [-v]");
	}

	return adjustAmbiguousSymbols(firstFile, secondFile);
}

int main(int argc, char *argv[])
{
	bool showDiffElf = false;
	bool extractSym = false;
	bool changeCallSym = false;
	bool disasm = false;
	bool referenceFrom = false;
	bool removePrefix = false;
	bool matchAmbiguousSymbols = false;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-v") == 0)
			ShowDebugLog = true;
		if (strcmp(argv[i], "--diff") == 0)
			showDiffElf = true;
		if (strcmp(argv[i], "--extract") == 0)
			extractSym = true;
		if (strcmp(argv[i], "--changeCallSymbol") == 0)
			changeCallSym = true;
		if (strcmp(argv[i], "--disassemble") == 0)
			disasm = true;
		if (strcmp(argv[i], "--referenceFrom") == 0)
			referenceFrom = true;
		if (strcmp(argv[i], "--removePrefix") == 0)
			removePrefix = true;
		if (strcmp(argv[i], "--adjustAmbiguousSymbols") == 0)
			matchAmbiguousSymbols = true;
	}

	elf_version(EV_CURRENT);

	if (showDiffElf)
		return _showDiff(argc - 1, argv + 1);
	else if (extractSym)
		return _extractSymbols(argc - 1, argv + 1);
	else if (changeCallSym)
		return _changeCallSymbol(argc - 1, argv + 1);
	else if (disasm)
		return _disassemble(argc - 1, argv + 1);
	else if (referenceFrom)
		return _symbolReferenceFrom(argc - 1, argv + 1);
	else if (removePrefix)
		return _removePrefix(argc - 1, argv + 1);
	else if (matchAmbiguousSymbols)
		return _adjustAmbiguousSymbols(argc - 1, argv + 1);
	else
	{
		help(argv[0]);
		return -1;
	}

	return 0;
}
