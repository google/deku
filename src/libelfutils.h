// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdbool.h>
#include <stdio.h>
#include <gelf.h>

#define LOG_ERR(fmt, ...)												\
	do																	\
	{																	\
		fprintf(stderr, "ERROR (%s:%d): " fmt "\n", __FILE__, __LINE__,	\
				##__VA_ARGS__);											\
	} while (0)
#define LOG_INFO(fmt, ...)												\
	do																	\
	{																	\
		printf(fmt "\n", ##__VA_ARGS__);								\
	} while (0)
#define LOG_DEBUG(fmt, ...)												\
	do																	\
	{																	\
		if (ShowDebugLog)												\
			printf(fmt "\n", ##__VA_ARGS__);							\
	} while (0)

#define CHECK_ALLOC(m)	\
	({if (m == NULL)	\
	LOG_ERR("Failed to alloc memory in %s (%s:%d)", __func__, __FILE__, __LINE__); m != NULL;})

#define REALLOC(ptr, size)	\
	({void *tmp = realloc(ptr, size); if (tmp == NULL) free(ptr); CHECK_ALLOC(tmp); tmp;})

#define REALLOC_ELF_DBUF(ptr, size, add)	\
	({void *tmp = malloc(size + add); CHECK_ALLOC(tmp); memcpy(tmp, ptr, size); tmp;})

#define GOTO_ERR do { LOG_INFO("Error in %s:%d", __func__, __LINE__); goto err; } while (0)

extern GElf_Shdr InvalidShdr;
extern GElf_Sym InvalidSym;
#define invalidSym(sym) (sym.st_name == -1)
#define invalidShdr(shdr) (shdr.sh_name == -1)

typedef struct
{
	char *name;
	size_t index;
	bool isFun;
	bool isVar;
	size_t copiedIndex;
	bool copiedWithSection;
	GElf_Sym sym;
	void *data;
} Symbol;

typedef struct
{
	Symbol **symbols;
	Elf_Scn **copiedScnMap;
	size_t sectionsCount;
	size_t symbolsCount;
	Elf_Scn *symtabScn;
	Elf *elf;
	Elf *secondElf;
	const char *filePath;
	void *data;
} Context;

extern bool ShowDebugLog;

Context initContext(Elf *elf, const char *filePath);
void freeContext(Context *ctx);
Elf *openElf(const char *filePath, bool readOnly, int *fd);
bool isAARCH64(Elf *elf);
Symbol **readSymbols(Elf *elf, size_t *count);
Symbol *getSymbolForRelocation(Context *ctx, const GElf_Rela rela);
char *getSectionName(Elf *elf, Elf64_Section index);
Elf_Scn *getSectionByName(Elf *elf, const char *secName);
GElf_Sym getSymbolByName(Elf *elf, const char *name, size_t *symIndex, bool definedOnly);
GElf_Sym getSymbolByIndex(Elf *elf, size_t index);
int getSymbolByNameAndType(Elf *elf, const char *symName, const int type, GElf_Sym *sym);
GElf_Sym getSymbolByOffset(Elf *elf, Elf64_Section shndx, int offset,bool exactSymbol);
GElf_Sym getSymbolByAbsoluteOffset(Elf *elf, int offset, bool exact);
int getSymbolIndex(Elf *elf, const GElf_Sym *sym);
GElf_Shdr getSectionHeader(Elf *elf, Elf64_Section index);
Elf_Scn *getRelForSectionIndex(Elf *elf, Elf64_Section index);
int moveRelocationToOtherSymbol(Elf *elf, int fromSymIndex, int toSymIndex);
char *appendFormatString(char *buf, const char *format, ...);
