// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions responsible for finding ambiguous symbols in the
 * patched object file and renaming them to the corresponding symbols from the
 * original object file.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libelfutils.h"

#ifndef TOOLCHAIN
	#define TOOLCHAIN ""
#endif

typedef struct
{
	struct AmbiguousSymbolRef
	{
		Symbol *sym;
		uint32_t *offset;
		uint32_t count;
	} *referencedFrom;
	uint32_t count;
} AmbiguousSymbol;

/*
 * Get object symbols with suffix ".<NUM>" that are generated from local symbols
 * with the same name in one file. The number in the suffix might be different
 * after making changes in source code unrelated to the symbol.
 *
 * @return 0 on success, otherwise non-zero
 */
static int getAmbiguousSymbols(Context *ctx)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	GElf_Rela rela;

	while ((scn = elf_nextscn(ctx->elf, scn)) != NULL)
	{
		if (gelf_getshdr(scn, &shdr) == NULL)
			goto err;

		if (shdr.sh_type != SHT_RELA)
			continue;

		size_t index = elf_ndxscn(scn);
		if (index == SHN_UNDEF)
			goto err;

		Elf_Data *data = elf_getdata(scn, NULL);
		if (data == NULL)
			goto err;

		size_t cnt = shdr.sh_size / shdr.sh_entsize;

		Symbol *sym;
		for (size_t i = 0; i < cnt; i++)
		{
			if (gelf_getrela(data, i, &rela) == NULL)
				goto err;

			size_t symIndex = ELF64_R_SYM(rela.r_info);
			if (symIndex == 0)
				continue;

			sym = NULL;
			for (size_t j = 0; j < ctx->symbolsCount; j++)
			{
				Symbol *s = ctx->symbols[j];
				if (s->sym.st_shndx != shdr.sh_info)
					continue;

				if ((size_t)rela.r_offset >= s->sym.st_value &&
					(size_t)rela.r_offset < s->sym.st_value + s->sym.st_size)
				{
					sym = s;
					break;
				}
			}

			if (sym == NULL)
				continue;

			Symbol *relSym = getSymbolForRelocation(ctx, rela);
			const char *dot = NULL;
			if (relSym->isVar && (dot = strchr(relSym->name, '.')) != NULL && isdigit(dot[1]))
			{
				if (relSym->data == NULL)
				{
					relSym->data = (AmbiguousSymbol *)calloc(1, sizeof(AmbiguousSymbol));
					if (!CHECK_ALLOC(relSym->data))
						goto err;
				}

				struct AmbiguousSymbolRef *referencedFrom = NULL;
				AmbiguousSymbol *ambiguousSymbol = (AmbiguousSymbol *)relSym->data;
				for (size_t j = 0; j < ambiguousSymbol->count; j++)
				{
					if (ambiguousSymbol->referencedFrom[j].sym == sym)
					{
						referencedFrom = &ambiguousSymbol->referencedFrom[j];
						break;
					}
				}

				if (referencedFrom == NULL)
				{
					ambiguousSymbol->count++;
					ambiguousSymbol->referencedFrom = REALLOC(ambiguousSymbol->referencedFrom,
															  ambiguousSymbol->count * sizeof(struct AmbiguousSymbolRef));
					referencedFrom = &ambiguousSymbol->referencedFrom[ambiguousSymbol->count - 1];
					memset(referencedFrom, 0, sizeof(*referencedFrom));
					referencedFrom->sym = sym;
				}

				referencedFrom->count++;
				uint32_t count = referencedFrom->count;
				referencedFrom->offset = REALLOC(referencedFrom->offset,
												 count * sizeof(uint32_t));
				if (referencedFrom->offset == NULL)
					goto err;

				referencedFrom->offset[count-1] = rela.r_offset - sym->sym.st_value;
			}
		}
	}

	return 0;

err:
	return -1;
}

/*
 * Check if ambiguous symbol from origin object file is also referenced from the same offset as in
 * ambiguous symbol from patched object file.
 */
static bool checkAmbiguousSymbolOffset(struct AmbiguousSymbolRef *originReferencedFrom, struct AmbiguousSymbolRef *patchedReferencedFrom)
{
	for (uint32_t i = 0; i < originReferencedFrom->count; i++)
	{
		for (uint32_t j = 0; j < patchedReferencedFrom->count; j++)
		{
			if (patchedReferencedFrom->offset[j] == originReferencedFrom->offset[i])
				return true;
		}
	}

	return false;
}

/*
 * Get a score of how much the ambiguous symbol from the original object file is similar to the
 * ambiguous symbol from the patched object file.
 *
 * The score is calculated based on the from which symbols and offset it's referenced.
 */
static int getScoreForAmbiguousSymbols(AmbiguousSymbol *originAmbiguousSymbol, AmbiguousSymbol *patchedAmbiguousSymbols)
{
	int score = 0;
	for (size_t i = 0; i < originAmbiguousSymbol->count; i++)
	{
		bool foundReference = false;
		bool foundReferenceWithOffset = false;
		struct AmbiguousSymbolRef originReferencedFrom = (struct AmbiguousSymbolRef) originAmbiguousSymbol->referencedFrom[i];
		for (size_t j = 0; j < patchedAmbiguousSymbols->count; j++)
		{
			struct AmbiguousSymbolRef patchedReferencedFrom = patchedAmbiguousSymbols->referencedFrom[j];
			if (strcmp(patchedReferencedFrom.sym->name, originReferencedFrom.sym->name) == 0)
			{
				foundReference = true;
				if (checkAmbiguousSymbolOffset(&originReferencedFrom, &patchedReferencedFrom))
				{
					foundReferenceWithOffset = true;
					break;
				}
			}
		}

		if (foundReference)
		{
			score += 2;
			if (foundReferenceWithOffset)
				score += 1;
		}
	}

	return score;
}

static void printAmbiguousSymbolDebugInfo(Context *ctx)
{
	for (size_t i = 0; i < ctx->symbolsCount; i++)
	{
		Symbol *sym = ctx->symbols[i];
		if (sym->data == NULL)
			continue;

		const char *symSecName = getSectionName(ctx->elf, sym->sym.st_shndx);
		AmbiguousSymbol *ambiguousSymbol = (AmbiguousSymbol *) sym->data;
		LOG_DEBUG("Ambiguous symbol %s (%s) referenced from:", sym->name, symSecName);
		for (size_t j = 0; j < ambiguousSymbol->count; j++)
		{
			const struct AmbiguousSymbolRef *referencedFrom = &ambiguousSymbol->referencedFrom[j];
			for (uint32_t k = 0; k < referencedFrom->count; k++)
			{
				LOG_DEBUG("\t%s+0x%x", referencedFrom->sym->name, referencedFrom->offset[k]);
			}
		}
	}
}

/*
 * Match ambiguous symbols with ".<NUM>" suffix in the patched object file
 * against the origin file.
 *
 * @return Number of changed symbols. On error return -1
 */
int adjustAmbiguousSymbols(const char *originFilePath, const char *patchedFilePath)
{
	int originFd;
	int patchedFd;
	Elf *originElf = NULL;
	Elf *patchedElf = NULL;
	Context originFileCtx = {0};
	Context patchedFileCtx = {0};
	int result = 0;

	originElf = openElf(originFilePath, true, &originFd);
	if (originElf == NULL)
		goto err;

	patchedElf = openElf(patchedFilePath, true, &patchedFd);
	if (patchedElf == NULL)
		goto err;

	originFileCtx = initContext(originElf, originFilePath);
	originFileCtx.symbols = readSymbols(originElf, &originFileCtx.symbolsCount);
	if (originFileCtx.symbols == NULL)
		goto err;

	patchedFileCtx = initContext(patchedElf, patchedFilePath);
	patchedFileCtx.symbols = readSymbols(patchedElf, &patchedFileCtx.symbolsCount);
	if (patchedFileCtx.symbols == NULL)
		goto err;

	if (getAmbiguousSymbols(&originFileCtx) != 0)
		goto err;

	if (getAmbiguousSymbols(&patchedFileCtx) != 0)
		goto err;

	LOG_DEBUG("Origin object file:");
	printAmbiguousSymbolDebugInfo(&originFileCtx);
	LOG_DEBUG("Patched object file:");
	printAmbiguousSymbolDebugInfo(&patchedFileCtx);

	for (size_t i = 0; i < originFileCtx.symbolsCount; i++)
	{
		Symbol *sym = originFileCtx.symbols[i];
		if (sym->data == NULL)
			continue;

		AmbiguousSymbol *originAmbiguousSymbol = (AmbiguousSymbol *) sym->data;

		int highestScore = 0;
		Symbol *candidate = NULL;
		const char *originSymSecName = getSectionName(originElf, sym->sym.st_shndx);
		for (size_t j = 0; j < patchedFileCtx.symbolsCount; j++)
		{
			Symbol *patchedSym = patchedFileCtx.symbols[j];
			if (patchedSym->data == NULL)
				continue;

			const char *patchedSymSecName = getSectionName(patchedElf, patchedSym->sym.st_shndx);
			AmbiguousSymbol *patchedAmbiguousSymbols = (AmbiguousSymbol *) patchedSym->data;
			if (strcmp(patchedSymSecName, originSymSecName) == 0)
			{
				int score = getScoreForAmbiguousSymbols(originAmbiguousSymbol, patchedAmbiguousSymbols);
				if (score > highestScore || (score >= highestScore && strcmp(sym->name, patchedSym->name) == 0))
				{
					highestScore = score;
					candidate = patchedSym;
				}
			}
		}

		if (candidate != NULL && strcmp(sym->name, candidate->name) != 0)
		{
			LOG_DEBUG("Swap %s with %s", candidate->name, sym->name);
			const char *tmpSymbolName = "__deku_tmp_symbol_rename";
			const char *objcopy = TOOLCHAIN "objcopy";
			unsigned long len =
				strlen(objcopy) +
				strlen(" --redefine-sym = ") +
				strlen(sym->name) + strlen(candidate->name) +
				strlen(patchedFilePath) +
				strlen(tmpSymbolName) + 1;
			char *cmd = malloc(len);
			if (!CHECK_ALLOC(cmd))
				goto err;

			size_t index;
			if (invalidSym(getSymbolByName(patchedElf, sym->name, &index, false)))
			{
				snprintf(cmd, len, "%s --redefine-sym %s=%s %s", objcopy, candidate->name, sym->name, patchedFilePath);
				system(cmd);
			}
			else
			{
				snprintf(cmd, len, "%s --redefine-sym %s=%s %s", objcopy, sym->name, tmpSymbolName, patchedFilePath);
				system(cmd);
				snprintf(cmd, len, "%s --redefine-sym %s=%s %s", objcopy, candidate->name, sym->name, patchedFilePath);
				system(cmd);
				snprintf(cmd, len, "%s --redefine-sym %s=%s %s", objcopy, tmpSymbolName, candidate->name, patchedFilePath);
				system(cmd);

				// swap names also in Symbols
				for (size_t j = 0; j < patchedFileCtx.symbolsCount; j++)
				{
					Symbol *s = patchedFileCtx.symbols[j];
					if (s->data != NULL && strcmp(s->name, sym->name) == 0)
					{
						char *tmp = candidate->name;
						candidate->name = s->name;
						s->name = tmp;
						break;
					}
				}
			}
			free(cmd);
        }
	}

out:
	for (size_t i = 0; i < originFileCtx.symbolsCount; i++)
	{
		Symbol *sym = originFileCtx.symbols[i];
		if (sym->data == NULL)
			continue;

		AmbiguousSymbol *originAmbiguousSymbol = (AmbiguousSymbol *) sym->data;
		for (size_t j = 0; j < originAmbiguousSymbol->count; j++)
			free(originAmbiguousSymbol->referencedFrom[j].offset);

		free(originAmbiguousSymbol->referencedFrom);
		free(originAmbiguousSymbol);
	}

	for (size_t i = 0; i < patchedFileCtx.symbolsCount; i++)
	{
		Symbol *sym = patchedFileCtx.symbols[i];
		if (sym->data == NULL)
			continue;

		AmbiguousSymbol *patchedAmbiguousSymbols = (AmbiguousSymbol *) sym->data;
		for (size_t j = 0; j < patchedAmbiguousSymbols->count; j++)
			free(patchedAmbiguousSymbols->referencedFrom[j].offset);

		free(patchedAmbiguousSymbols->referencedFrom);
		free(patchedAmbiguousSymbols);
	}

	freeContext(&originFileCtx);
	freeContext(&patchedFileCtx);
	elf_end(originElf);
	elf_end(patchedElf);
	close(originFd);
	close(patchedFd);
	fflush(stdout);
	return result;

err:
	result = -1;
	goto out;
}
