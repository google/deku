// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions that are responsible for creating an intermediate
 * patch file, which is created by extracting symbols that have been changed in
 * the patched file.
 */

#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "disassembler.h"

/*
 * @return 0 on success, otherwise non-zero
 */
static int swapSymbolIndex(Elf *elf, size_t left, size_t right)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return -1;

	while ((scn = elf_nextscn(elf, scn)) != NULL)
	{
		if (gelf_getshdr(scn, &shdr) == NULL)
			return -1;

		if (shdr.sh_type != SHT_RELA)
			continue;

		GElf_Rela rela;
		Elf_Data *data = elf_getdata(scn, NULL);
		if (data == NULL)
			return -1;

		size_t cnt = shdr.sh_size / shdr.sh_entsize;
		for (size_t i = 0; i < cnt; i++)
		{
			if (gelf_getrela(data, i, &rela) == NULL)
				return -1;

			if (ELF64_R_SYM(rela.r_info) == left)
			{
				rela.r_info = ELF64_R_INFO(right, ELF64_R_TYPE(rela.r_info));
				if (gelf_update_rela(data, i, &rela) == 0)
					return -1;
			}
			else if (ELF64_R_SYM(rela.r_info) == right)
			{
				rela.r_info = ELF64_R_INFO(left, ELF64_R_TYPE(rela.r_info));
				if (gelf_update_rela(data, i, &rela) == 0)
					return -1;
			}
		}
	}

	return 0;
}

/*
 * @return 0 on success, otherwise non-zero
 */
static int sortSymtab(Elf *elf)
{
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		return -1;

	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	int firstGlobalIndex = 0;
	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getsym(data, i, &sym) == NULL)
			return -1;

		if (firstGlobalIndex == 0 && ELF64_ST_BIND(sym.st_info) != STB_LOCAL)
			firstGlobalIndex = i;

		if (firstGlobalIndex != 0 && ELF64_ST_BIND(sym.st_info) == STB_LOCAL)
		{
			GElf_Sym firstGlobal;
			if (gelf_getsym(data, firstGlobalIndex, &firstGlobal) == NULL)
				return -1;

			if (gelf_update_sym(data, i, &firstGlobal) == 0)
				return -1;

			if (gelf_update_sym(data, firstGlobalIndex, &sym) == 0)
				return -1;

			if (swapSymbolIndex(elf, i, firstGlobalIndex) == -1)
				return -1;

			firstGlobalIndex = 0;
			i = 0;
		}
	}

	// update section info
	shdr.sh_info = firstGlobalIndex;
	if (gelf_update_shdr(scn, &shdr) == 0)
		return -1;

	return 0;
}

/*
 * @return 0 on success, otherwise non-zero
 */
static int addSymbol(Context *ctx, const GElf_Sym sym)
{
	GElf_Shdr shdr;
	Elf_Scn *scn = getSectionByName(ctx->secondElf, ".symtab");
	if (scn == NULL)
		return -1;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	data->d_buf = REALLOC_ELF_DBUF(data->d_buf, data->d_size, sizeof(GElf_Sym));
	if (data->d_buf == NULL)
		return -1;

	memcpy((uint8_t *)data->d_buf + data->d_size, &sym, sizeof(GElf_Sym));
	data->d_size += sizeof(GElf_Sym);
	shdr.sh_size = data->d_size;
	if (gelf_update_shdr(scn, &shdr) == 0)
		return -1;

	return 0;
}

/*
 * @return New string offset. On error return -1
 */
static size_t appendString(GElf_Shdr *shdr, Elf_Data *data, const char *text)
{
	size_t oldSize = data->d_size;
	size_t newSize = data->d_size + strlen(text) + 1;
	char *buf = (char *)calloc(1, newSize);
	if (!CHECK_ALLOC(buf))
		return -1;

	memcpy(buf, data->d_buf, data->d_size);
	strcpy(&buf[data->d_size], text);
	data->d_buf = buf;
	data->d_size = newSize;
	shdr->sh_size = newSize;

	return oldSize;
}

static Elf_Scn *copySection(Context *ctx, Elf64_Section index, bool copyData)
{
	if (ctx->copiedScnMap[index] != NULL)
		return ctx->copiedScnMap[index];

	if (index >= ctx->sectionsCount)
	{
		LOG_ERR("Try to copy section that is out range (%d/%zu)", index, ctx->sectionsCount);
		return NULL;
	}

	size_t shstrndx;
	GElf_Shdr newShdr;
	GElf_Shdr oldShdr;
	GElf_Shdr strshdr;
	if (elf_getshdrstrndx(ctx->elf, &shstrndx) != 0)
		return NULL;

	Elf_Scn *strtabScn = getSectionByName(ctx->secondElf, ".shstrtab");
	if (strtabScn == NULL)
		return NULL;

	Elf_Data *strData = elf_getdata(strtabScn, NULL);
	if (strData == NULL)
		return NULL;

	if (gelf_getshdr(strtabScn, &strshdr) == NULL)
		return NULL;

	Elf_Scn *oldScn = elf_getscn(ctx->elf, index);
	if (oldScn == NULL)
		return NULL;

	const Elf_Data *oldData = elf_getdata(oldScn, NULL);
	if (oldData == NULL)
		return NULL;

	Elf_Scn *newScn = elf_newscn(ctx->secondElf);
	if (newScn == NULL)
		return NULL;

	Elf_Data *newData = elf_newdata(newScn);
	if (newData == NULL)
		return NULL;

	if (gelf_getshdr(oldScn, &oldShdr) == NULL)
		return NULL;

	if (gelf_getshdr(newScn, &newShdr) == NULL)
		return NULL;

	newShdr.sh_type = oldShdr.sh_type;
	newShdr.sh_flags = oldShdr.sh_flags;
	newShdr.sh_entsize = oldShdr.sh_entsize;
	const char *symName = elf_strptr(ctx->elf, shstrndx, oldShdr.sh_name);
	if (symName == NULL)
		return NULL;

	Elf64_Word name = appendString(&strshdr, strData, symName);
	if (name == -1)
		return NULL;

	newShdr.sh_name = name;
	newData->d_type = oldData->d_type;
	if (copyData && oldData->d_size > 0)
	{
		newShdr.sh_size = oldShdr.sh_size;
		newData->d_buf = calloc(1, oldData->d_size);
		if (!CHECK_ALLOC(newData->d_buf))
			return NULL;

		newData->d_size = oldData->d_size;
		if (oldData->d_buf)
			memcpy(newData->d_buf, oldData->d_buf, oldData->d_size);
	}
	if (gelf_update_shdr(newScn, &newShdr) == 0)
		return NULL;
	if (gelf_update_shdr(strtabScn, &strshdr) == 0)
		return NULL;

	ctx->copiedScnMap[index] = newScn;

	return newScn;
}

/*
 * @return Offset of appended string. Return -1 on error
 */
static Elf64_Word appendStringToScn(Elf *elf, const char *scnName, const char *text)
{
	GElf_Shdr shdr;
	Elf_Scn *scn = getSectionByName(elf, scnName);
	if (scn == NULL)
		return -1;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	Elf64_Word result = appendString(&shdr, data, text);
	if (result == -1)
		return -1;

	if (gelf_update_shdr(scn, &shdr) == 0)
		return -1;

	return result;
}

/*
 * @return Index of copied symbol. Return -1 on error
 */
static size_t copySymbol(Context *ctx, size_t index, bool copySec)
{
	GElf_Sym originSym;
	GElf_Shdr shdr;
	GElf_Shdr outShdr;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Sym newSym;

	if (ctx->symbols[index]->copiedIndex)
	{
		if (!copySec || ctx->symbols[index]->copiedWithSection)
			return ctx->symbols[index]->copiedIndex;
	}

	scn = getSectionByName(ctx->elf, ".symtab");
	if (scn == NULL)
		return -1;

	data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	if (gelf_getsym(data, index, &originSym) == NULL)
		return -1;

	scn = getSectionByName(ctx->secondElf, ".symtab");
	if (scn == NULL)
		return -1;

	if (gelf_getshdr(scn, &outShdr) == NULL)
		return -1;

	size_t newIndex = outShdr.sh_size/outShdr.sh_entsize;
	if (ctx->symbols[index]->copiedIndex)
		newIndex = ctx->symbols[index]->copiedIndex;

	data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	if (!ctx->symbols[index]->copiedIndex)
		data->d_buf = REALLOC_ELF_DBUF(data->d_buf, data->d_size, sizeof(GElf_Sym));

	newSym = originSym;

	char symType = ELF64_ST_TYPE(originSym.st_info);
	if (originSym.st_shndx > 0 && originSym.st_shndx < ctx->sectionsCount &&
		copySec)
	{
		Elf_Scn *scn = copySection(ctx, originSym.st_shndx, true);
		if (scn == NULL)
			return -1;

		newSym.st_shndx = elf_ndxscn(scn);
		if (newSym.st_shndx == SHN_UNDEF)
			return -1;

		if (originSym.st_name != 0)
		{
			// TODO: Avoid modify symbol name for functions
			if (symType == STT_FUNC)
			{
				char *funName = strdup(ctx->symbols[index]->name);
				if (!CHECK_ALLOC(funName))
					return -1;

				char *n;
				while ((n = strchr(funName, '.')) != NULL)
					*n = '_';

				newSym.st_name = appendStringToScn(ctx->secondElf, ".strtab", funName);
				if (newSym.st_name == -1)
				{
					free(funName);
					return -1;
				}

				Elf_Data *data = elf_getdata(scn, NULL);
				if (data == NULL)
				{
					free(funName);
					return -1;
				}

				uint8_t *symData = (uint8_t *)data->d_buf + newSym.st_value;
				DisasmData dissData = { .ctx = ctx, .sym = originSym,
										.shdr = shdr, .symData = symData };
				if (convertToRelocations(&dissData) != 0)
				{
					free(funName);
					return -1;
				}

				free(funName);
			}
			else
			{
				newSym.st_name = appendStringToScn(ctx->secondElf, ".strtab", ctx->symbols[index]->name);
				if (newSym.st_name == -1)
					return -1;
			}
		}
	}
	else // mark symbol as "external"
	{
		newSym.st_shndx = 0;
		newSym.st_size = 0;
		// make it global as LLVM drops the symbol if it will be LOCAL
		newSym.st_info = ELF64_ST_INFO(STB_WEAK, symType);
		if (originSym.st_name != 0)
		{
			const char *prefix = (char *)ctx->data;
			int size = strlen(prefix) + strlen(ctx->symbols[index]->name) + 2;
			char *newName = malloc(size);
			if (!CHECK_ALLOC(newName))
				return -1;

			snprintf(newName, size, "%s_%s", prefix, ctx->symbols[index]->name);
			newSym.st_name = appendStringToScn(ctx->secondElf, ".strtab", newName);
			free(newName);
			if (newSym.st_name < 0)
				return -1;
		}
	}

	memcpy((uint8_t *)data->d_buf + (sizeof(GElf_Sym) * newIndex), &newSym, sizeof(GElf_Sym));
	if (!ctx->symbols[index]->copiedIndex)
	{
		data->d_size += sizeof(GElf_Sym);
		outShdr.sh_size = data->d_size;
		if (gelf_update_shdr(scn, &outShdr) == 0)
			return -1;
	}

	ctx->symbols[index]->copiedIndex = newIndex;
	ctx->symbols[index]->copiedWithSection = copySec;

	return newIndex;
}

typedef int (*RelocFilter)(Context *, Elf_Data *, size_t, const char *);

/*
 * Check if symbol pointed by relocation was copied
 *
 * @return Value > 0 if symbol pointed for relocation was copied. Return 0 if not copied. Return -1 on error
 */
static int copiedSymbolsRelocFilter(Context *ctx, Elf_Data *data, size_t index,
									const char *secName)
{
	GElf_Rela rela;

	if (strcmp("__bug_table", secName) == 0 ||
		strcmp(".altinstructions", secName) == 0 ||
		strcmp(".static_call_sites", secName) == 0)
		index = (index / 2) * 2;

	if (strcmp(".altinstr_aux", secName) == 0)
		index = (index / 3) * 3 + 1;

	if (strcmp("__jump_table", secName) == 0)
		index = (index / 3) * 3;

	if (gelf_getrela(data, index, &rela) == NULL)
		return -1;

	if (strcmp("__jump_table", secName) == 0)
	{
		GElf_Sym sym;
		Symbol *symbol = getSymbolForRelocation(ctx, rela);
		if (!ctx->symbols[symbol->index]->copiedWithSection)
			return 0;

		sym = getSymbolByIndex(ctx->secondElf,
							   ctx->symbols[symbol->index]->copiedIndex);
		if (invalidSym(sym))
			return -1;

		if (sym.st_size == 0)
			return 0;

		// check if key is external symbol
		if (gelf_getrela(data, index + 2, &rela) == NULL)
			return -1;

		symbol = getSymbolForRelocation(ctx, rela);

		return symbol->sym.st_size > 0 ? 1 : 0;
	}

	size_t symIndex = ELF64_R_SYM(rela.r_info);
	size_t secIndex = ctx->symbols[symIndex]->sym.st_shndx;

	if (ctx->copiedScnMap[secIndex] == NULL)
		return 0;

	Elf64_Sxword addend = rela.r_addend;
	switch (ELF64_R_TYPE(rela.r_info))
	{
	case R_X86_64_PC32:
		if (strcmp("__bug_table", secName) == 0)
			break;
	case R_X86_64_PLT32:
		addend += 4;
		break;
	}

	for (size_t i = 0; i < ctx->symbolsCount; i++)
	{
		const Symbol *sym = ctx->symbols[i];
		if (!sym->copiedWithSection ||
			sym->sym.st_shndx != secIndex)
			continue;

		if ((size_t)addend >= sym->sym.st_value &&
			(size_t)addend < sym->sym.st_value + sym->sym.st_size)
			return 1;
	}

	return 0;
}

/*
 * Copy relocation section.
 *
 * Relocations that points to strings are copied with data.
 * Relocations for symbols with prefix __pfx_, __cfi_ and .LC are skipped.
 *
 * @return number of copied entries. On error return negative value
 */
static int copyRelSection(Context *ctx, Elf64_Section relSecIndex, size_t secIndex,
						  const GElf_Sym *fromSym, RelocFilter filter)
{
	Elf_Scn *outScn = copySection(ctx, relSecIndex, false);
	if (outScn == NULL)
		return -1;

	const char *secName = getSectionName(ctx->secondElf, secIndex);
	if (secName == NULL)
		return -1;

	GElf_Shdr shdr;
	if (gelf_getshdr(outScn, &shdr) == NULL)
		return -1;

	Elf_Scn *scn = getSectionByName(ctx->secondElf, ".symtab");
	if (scn == NULL)
		return -1;

	shdr.sh_link = elf_ndxscn(scn);
	if (shdr.sh_link == SHN_UNDEF)
		return -1;

	shdr.sh_info = secIndex;
	if (gelf_update_shdr(outScn, &shdr) == 0)
		return -1;

	GElf_Rela rela;
	size_t count = shdr.sh_size / shdr.sh_entsize;
	scn = elf_getscn(ctx->elf, relSecIndex);
	if (scn == NULL)
		return -1;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	Elf_Data *outData = elf_getdata(outScn, NULL);
	if (outData == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	outData->d_size += shdr.sh_size;
	outData->d_buf = REALLOC(outData->d_buf, outData->d_size);
	if (outData->d_buf == NULL)
		return -1;

	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getrela(data, i, &rela) == NULL)
			return -1;

		if (fromSym != NULL &&
			(rela.r_offset < fromSym->st_value ||
			rela.r_offset > fromSym->st_value + fromSym->st_size))
			continue;

		if (filter != NULL)
		{
			int res = filter(ctx, data, i, secName);
			if (res == -1)
				return -1;

			if (res == 0)
				continue;
		}

		size_t newSymIndex;
		size_t symIndex = ELF64_R_SYM(rela.r_info);
		int rType = ELF64_R_TYPE(rela.r_info);
		GElf_Shdr shdr = getSectionHeader(ctx->elf, ctx->symbols[symIndex]->sym.st_shndx);
		if (invalidShdr(shdr))
			return -1;

		const char *symSecName = getSectionName(ctx->elf, ctx->symbols[symIndex]->sym.st_shndx);
		if (symSecName == NULL)
			return -1;

		if (shdr.sh_flags & SHF_STRINGS ||
			strstr(symSecName, ".rodata.__func__") == symSecName ||
			strstr(symSecName, ".rodata.cst16") == symSecName ||
			strstr(symSecName, "__tracepoint_str") == symSecName ||
			strstr(symSecName, "__trace_printk_fmt") == symSecName ||
			(secName != NULL && strcmp(secName, "__jump_table") == 0))
		{
			newSymIndex = copySymbol(ctx, symIndex, true);
			if ((int)newSymIndex < 0)
				return -1;
		}
		else
		{
			Symbol *sym = fromSym == NULL ? ctx->symbols[symIndex] : getSymbolForRelocation(ctx, rela);

			if (strstr(sym->name, "__pfx_") == sym->name ||
				strstr(sym->name, "__cfi_") == sym->name ||
				strstr(sym->name, ".LC") == sym->name)
				continue;

			bool copySec = ELF64_ST_TYPE(ctx->symbols[sym->index]->sym.st_info) == STT_SECTION ||
						   strstr(sym->name, "__tracepoint_") == sym->name || // __tracepoint_* must be copied as it's needed before relocations
						   strstr(sym->name, ".__already_done.") != NULL ||
						   strstr(sym->name, "__UNIQUE_ID_ddebug") != NULL;
			newSymIndex = copySymbol(ctx, sym->index, copySec);
			if ((int)newSymIndex < 0)
				return -1;

			if (fromSym != NULL &&
				(rType == R_X86_64_PC32 || rType == R_X86_64_PLT32 ||
				 rType == R_X86_64_32S || rType == R_X86_64_64))
			{
				if (ELF64_ST_TYPE(ctx->symbols[symIndex]->sym.st_info) == STT_SECTION && \
					rela.r_addend != -4)
					rela.r_addend -= sym->sym.st_value;
			}
		}

		rela.r_info = ELF64_R_INFO(newSymIndex, rType);
		if (gelf_update_rela(outData, count, &rela) == 0)
			return -1;

		count++;
	}
	if (gelf_getshdr(outScn, &shdr) == NULL)
		return -1;

	shdr.sh_size = count * shdr.sh_entsize;
	outData->d_size = shdr.sh_size;
	if (gelf_update_shdr(outScn, &shdr) == 0)
	{
		LOG_ERR("Failed to update section header");
		return -1;
	}

	return count;
}

static Elf_Scn *copySectionWithRel(Context *ctx, Elf64_Section index,
								   const GElf_Sym *fromSym, RelocFilter filter)
{
	Elf_Scn *newScn = copySection(ctx, index, true);
	if (newScn == NULL)
		return NULL;

	Elf_Scn *relScn = getRelForSectionIndex(ctx->elf, index);
	if (relScn == NULL)
		return newScn;

	size_t indexFrom = elf_ndxscn(relScn);
	if (indexFrom == SHN_UNDEF)
		return NULL;

	size_t indexTo = elf_ndxscn(newScn);
	if (indexTo == SHN_UNDEF)
		return NULL;

	int relaCount = copyRelSection(ctx, indexFrom, indexTo, fromSym, filter);
	if (relaCount < 0)
		return NULL;

	// trim section data if it's contains only zeros to size depends on how many relocations are present for specific sections
	int dataSize = 0;
	const char *secName = getSectionName(ctx->elf, index);
	if (strcmp(secName, "__jump_table") == 0)
		dataSize = /*sizeof(struct jump_entry)*/ 16 * relaCount / 3;
	else if (strcmp(secName, ".return_sites") == 0)
		dataSize = relaCount * 4;
	else if (strcmp(secName, ".static_call_sites") == 0)
		dataSize = relaCount * 4;

	Elf_Data *data = elf_getdata(newScn, NULL);
	if (dataSize > 0 && dataSize != data->d_size)
	{
		bool allZero = true;
		for (int i = 0; i < data->d_size && allZero; i++)
			allZero = ((uint8_t *)data->d_buf)[i] == 0;

		if (allZero)
		{
			GElf_Shdr shdr;
			if (gelf_getshdr(newScn, &shdr) == NULL)
				return NULL;

			data->d_size = shdr.sh_size = dataSize;
			if (gelf_update_shdr(newScn, &shdr) == 0)
				return NULL;

			// update offsets
			GElf_Rela rela;
			index = elf_ndxscn(newScn);
			if (index == SHN_UNDEF)
				return NULL;

			relScn = getRelForSectionIndex(ctx->secondElf, index);
			Elf_Data *relData = elf_getdata(relScn, NULL);
			if (relData == NULL)
				return NULL;

			for (size_t i = 0; i < relaCount; i++)
			{
				if (gelf_getrela(relData, i, &rela) == NULL)
					return NULL;

				if (strcmp(secName, "__jump_table") == 0)
					rela.r_offset = (i / 3 * 4 + i % 3) * 4; // get sequence: 0x0, 0x4, 0x8, 0x10, 0x14, 0x18, 0x20, ...
				else if (strcmp(secName, ".return_sites") == 0)
					rela.r_offset = i * 4;
				else if (strcmp(secName, ".static_call_sites") == 0)
					rela.r_offset = i * 4;
				else
				{
					LOG_ERR("Offset for relocations for %s section is not defined", secName);
					return NULL;
				}

				if (gelf_update_rela(relData, i, &rela) == 0)
					return NULL;
			}
		}
	}

	return newScn;
}

/*
 * @return 0 on success, otherwise non-zero
 */
static int markSymbolsToCopy(Context *ctx, bool *symToCopy, const char *symbols)
{
	GElf_Sym sym;
	size_t symIndex;

	// mark the symbols to be copied from "symbols" text parameter
	while (symbols[0] != '\0')
	{
		char *comma = strchr(symbols, ',');
		if (comma)
			*comma = '\0';
		const char *symbol = symbols;

		sym = getSymbolByName(ctx->elf, symbol, &symIndex, false);
		if (invalidSym(sym))
		{
			LOG_ERR("Can't find symbol: %s", symbol);
			return -1;
		}

		symToCopy[symIndex] = true;
		if (!comma)
			break;

		symbols = comma + 1;
	}

	return 0;
}

/*
 * @return 0 on success, otherwise non-zero
 */
static int copySymbols(Context *ctx, const char *filePath, const char *symbols)
{
	Elf_Scn *scn;
	Elf_Scn *relScn = NULL;
	GElf_Shdr shdr;
	GElf_Sym sym;
	int ret = -1;
	bool *symToCopy = calloc(sizeof(bool), ctx->symbolsCount);
	if (!CHECK_ALLOC(symToCopy))
		goto err;

	int res = markSymbolsToCopy(ctx, symToCopy, symbols);
	if (res != 0)
		goto err;

	// copy symbols
	for (size_t i = 0; i < ctx->symbolsCount; i++)
	{
		if (!symToCopy[i])
			continue;

		if (copySymbol(ctx, i, true) == (size_t)-1)
			goto err;
	}

	for (size_t i = 0; i < ctx->symbolsCount; i++)
	{
		if (!symToCopy[i])
			continue;

		sym = getSymbolByIndex(ctx->elf, i);
		if (invalidSym(sym))
		{
			LOG_ERR("Cant find symbol with index: %zu", i);
			goto err;
		}

		Elf_Scn *relScn = getRelForSectionIndex(ctx->elf, sym.st_shndx);
		if (relScn != NULL)
		{
			size_t indexFrom = elf_ndxscn(relScn);
			if (indexFrom == SHN_UNDEF)
				goto err;

			Elf_Scn *copiedScn = ctx->copiedScnMap[sym.st_shndx];
			if (copiedScn == NULL)
				goto err;

			size_t indexTo = elf_ndxscn(copiedScn);
			if (indexTo == SHN_UNDEF)
				goto err;

			res = copyRelSection(ctx, indexFrom, indexTo, &sym, NULL);
			if (res < 0)
				goto err;
		}
	}

	// Copy missed relocation sections
	while ((relScn = elf_nextscn(ctx->elf, relScn)) != NULL)
	{
		if (gelf_getshdr(relScn, &shdr) == NULL)
			goto err;

		if (shdr.sh_type != SHT_RELA)
			continue;

		Elf_Scn *copiedScn = ctx->copiedScnMap[shdr.sh_info];
		if (!copiedScn)
			continue;

		size_t index = elf_ndxscn(relScn);
		if (index == SHN_UNDEF)
			goto err;

		const Elf_Scn *copiedRelScn = ctx->copiedScnMap[index];
		if (copiedRelScn)
			continue;

		// at this moment copy only relocations for .rodata
		const char *secName = getSectionName(ctx->elf, shdr.sh_info);
		if (secName == NULL)
			goto err;

		if (strstr(secName, ".rodata") != secName)
			continue;

		secName = getSectionName(ctx->elf, index);
		LOG_DEBUG("Copy missed %s section", secName);
		GElf_Sym mockSym = {};
		mockSym.st_size = -1;

		size_t indexTo = elf_ndxscn(copiedScn);
		if (indexTo == SHN_UNDEF)
			goto err;

		if (copyRelSection(ctx, index, indexTo, &mockSym, copiedSymbolsRelocFilter) < 0)
			goto err;
	}

	/**
	* TODO: Consider copy following sections:
	".smp_locks", "__ex_table", ".discard.reachable", ".discard.unreachable",
	".discard.addressable", ".discard.retpoline_safe", ".call_sites",
	".static_call.text", ".retpoline_sites", ".orc_unwind",
	".orc_unwind_ip", ".initcall4.init", ".meminit.text", "__tracepoints"
	*/
	const char *extraSections[] = {".altinstructions",
								   ".altinstr_aux",
								   ".altinstr_replacement",
								   "__bug_table",
								   "__jump_table",
								   ".return_sites",
								   ".static_call_sites",
								  };
	for (size_t i = 0; i < sizeof(extraSections) / sizeof(*extraSections); i++)
	{
		scn = getSectionByName(ctx->elf, extraSections[i]);
		if (scn)
		{
			LOG_DEBUG("Copy %s section", extraSections[i]);
			scn = copySectionWithRel(ctx, elf_ndxscn(scn), NULL, copiedSymbolsRelocFilter);
			if (scn == NULL)
				goto err;

			size_t index = elf_ndxscn(scn);
			if (index == SHN_UNDEF)
				goto err;

			relScn = getRelForSectionIndex(ctx->secondElf, index);
			if (relScn == NULL)
				continue;

			if (gelf_getshdr(relScn, &shdr) == NULL)
				goto err;

			size_t cnt = shdr.sh_size / shdr.sh_entsize;
			if (cnt == 0)
			{
				LOG_DEBUG("The %s section is empty. Remove it.", extraSections[i]);

				// TODO: Remove section instead zeroed it
				Elf_Data *data = elf_getdata(scn, NULL);
				data->d_size = 0;

				if (gelf_getshdr(scn, &shdr) == NULL)
					goto err;

				shdr.sh_size = 0;
				if (gelf_update_shdr(scn, &shdr) == 0)
					goto err;
			}
		}
	}

	scn = getSectionByName(ctx->elf, "__tracepoint_str");
	if (scn)
	{
		LOG_DEBUG("Copy %s section", "__tracepoint_str");
		size_t index = elf_ndxscn(scn);
		if (index == SHN_UNDEF)
			goto err;

		scn = copySectionWithRel(ctx, index, NULL, NULL);
		if (scn == NULL)
			goto err;

		// copy all symbols that points to the __tracepoint_str section
		for (size_t i = 0; i < ctx->symbolsCount; i++)
		{
			if (ctx->symbols[i]->sym.st_shndx != index)
				continue;

			if (copySymbol(ctx, i, true) == (size_t)-1)
				goto err;
		}
	}

	if (sortSymtab(ctx->secondElf) == -1)
		goto err;

	if (elf_update(ctx->secondElf, ELF_C_WRITE) == -1)
	{
		LOG_ERR("Can't update ELF file '%s': %s", filePath, elf_errmsg(-1));
		goto err;
	}

	ret = 0;

out:
	free(symToCopy);

	return ret;

err:
	ret = -1;
	goto out;
}

static Elf *createNewElf(const char *outFile, Elf64_Half arch, int *fd)
{
	*fd = open(outFile, O_RDWR|O_TRUNC|O_CREAT, 0666);
	if (*fd == -1)
		goto err;

	Elf *elf = elf_begin(*fd, ELF_C_WRITE, 0);
	if (elf == NULL)
		goto err;

	Elf64_Ehdr *ehdr = elf64_newehdr(elf);
	if (ehdr == NULL)
		goto err;

	ehdr->e_ident[EI_MAG0] = ELFMAG0;
	ehdr->e_ident[EI_MAG1] = ELFMAG1;
	ehdr->e_ident[EI_MAG2] = ELFMAG2;
	ehdr->e_ident[EI_MAG3] = ELFMAG3;
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_machine = arch;
	ehdr->e_type = ET_REL;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_shstrndx = 1;

	GElf_Shdr shdr;
	Elf_Scn *strtabScn = elf_newscn(elf);
	if (strtabScn == NULL)
		goto err;

	Elf_Data *newData = elf_newdata(strtabScn);
	if (newData == NULL)
		goto err;

	if (gelf_getshdr(strtabScn, &shdr) == NULL)
		goto err;

	static uint8_t blank[1] = {'\0'};
	newData->d_buf = blank;
	newData->d_size = 1;
	Elf64_Word strtabName = appendString(&shdr, newData, ".strtab");
	if (strtabName == -1)
		goto err;

	Elf64_Word symtabName = appendString(&shdr, newData, ".symtab");
	if (symtabName == -1)
		goto err;

	shdr.sh_type = SHT_STRTAB;
	Elf64_Word shstrtabName = appendString(&shdr, newData, ".shstrtab");
	if (shstrtabName == -1)
		goto err;

	shdr.sh_name = shstrtabName;
	if (gelf_update_shdr(strtabScn, &shdr) == 0)
		goto err;

	Elf_Scn *shstrtabScn = elf_newscn(elf);
	if (shstrtabScn == NULL)
		goto err;

	newData = elf_newdata(shstrtabScn);
	if (newData == NULL)
		goto err;

	newData->d_buf = blank;
	newData->d_size = 1;
	if (gelf_getshdr(shstrtabScn, &shdr) == NULL)
		goto err;

	shdr.sh_size = 1;
	shdr.sh_type = SHT_STRTAB;
	shdr.sh_name = strtabName;
	if (gelf_update_shdr(shstrtabScn, &shdr) == 0)
		goto err;

	Elf_Scn *symtabScn = elf_newscn(elf);
	if (symtabScn == NULL)
		goto err;

	newData = elf_newdata(symtabScn);
	if (newData == NULL)
		goto err;

	if (gelf_getshdr(symtabScn, &shdr) == NULL)
		goto err;

	GElf_Sym emptySym = {0};
	newData->d_type = ELF_T_SYM;
	newData->d_buf = malloc(sizeof(GElf_Sym));
	if (!CHECK_ALLOC(newData->d_buf))
		goto err;

	memcpy(newData->d_buf, &emptySym, sizeof(GElf_Sym));
	newData->d_size = sizeof(GElf_Sym);

	Elf_Scn *scn = getSectionByName(elf, ".strtab");
	if (scn == NULL)
		goto err;

	shdr.sh_link = elf_ndxscn(scn);
	if (shdr.sh_link == SHN_UNDEF)
		goto err;

	shdr.sh_size = sizeof(GElf_Sym);
	shdr.sh_type = SHT_SYMTAB;
	shdr.sh_name = symtabName;
	shdr.sh_entsize = sizeof(GElf_Sym);
	if (gelf_update_shdr(symtabScn, &shdr) == 0)
		goto err;

	return elf;

err:
	if (*fd != -1)
	{
		if (elf != NULL)
			elf_end(elf);
		close(*fd);
		*fd = -1;
	}
	return NULL;
}

/*
 * @return 0 on success, otherwise non-zero
 */
int extractSymbols(const char *filePath, const char *outFile, const char *symToCopy,
				   char *prefix)
{
	int res = 0;
	Context ctx = {0};
	int fd = 0;
	int outFd = 0;
	Elf *outElf = NULL;
	Elf *elf = openElf(filePath, true, &fd);
	if (elf == NULL)
		goto err;

	Elf64_Ehdr *ehdr = elf64_getehdr(elf);
	if (ehdr == NULL)
		goto err;

	ctx = initContext(elf, filePath);
	ctx.data = prefix;
	ctx.copiedScnMap = calloc(ctx.sectionsCount, sizeof(Elf_Scn *));
	if (!CHECK_ALLOC(ctx.copiedScnMap))
		goto err;

	outElf = createNewElf(outFile, ehdr->e_machine, &outFd);
	if (outElf == NULL)
		goto err;

	ctx.secondElf = outElf;
	ctx.symbols = readSymbols(elf, &ctx.symbolsCount);
	if (ctx.symbols == NULL)
		goto err;

	res = copySymbols(&ctx, filePath, symToCopy);
	if (res != 0)
		goto err;

	res = 0;

out:
	freeContext(&ctx);
	if (outElf)
	{
		elf_end(outElf);
		close(outFd);
	}

	if (elf)
	{
		elf_end(elf);
		close(fd);
	}

	fflush(stdout);
	return res;

err:
	res = -1;
	goto out;
}
