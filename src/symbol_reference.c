// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions that are responsible for finding references to a
 * given symbol.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "disassembler.h"

#include <dis-asm.h>

static Symbol *getSymbolForSym(const Context *ctx, const GElf_Sym *sym)
{
	for (Symbol **s = ctx->symbols; *s != NULL; s++)
	{
		if (memcmp(&s[0]->sym, sym, sizeof(*sym)) == 0)
			return s[0];
	}
	return NULL;
}

static void checkRelatedSymbols(bfd_vma vma, struct disassemble_info *inf)
{
	uint8_t operandOff = 0;
	uint8_t operandSize = 0;
	uint32_t symOffset;
	DisasmData *data = (DisasmData *)inf->application_data;
	GElf_Sym sym = getTargetSymbolForInstruction(vma, data, &operandOff, &operandSize,
												 &symOffset);

	if (invalidSym(sym))
		return;

	const GElf_Sym *targetSym = (GElf_Sym *)data->data;
	if (memcmp(targetSym, &sym, sizeof(sym)) == 0)
	{
		Symbol *symbol = getSymbolForSym(data->ctx, &data->sym);
		if (symbol == NULL)
		{
			data->result = -1;
			return;
		}

		symbol->data = (void *) true;
	}
}

/*
 * Find all symbols referred to by a specific function
 *
 * @return 0 on success, otherwise non-zero
 */
static int findSymbolsRelatingTo(Context *ctx, GElf_Sym *sym)
{
	GElf_Shdr shdr;
	Elf_Scn *scn = getSectionByName(ctx->elf, ".symtab");
	if (scn == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	bfd *abfd = initBfd(ctx->filePath);
	if (abfd == NULL)
		return -1;

	for (Symbol **s = ctx->symbols; *s != NULL; s++)
	{
		if (!s[0]->isFun)
			continue;

		scn = elf_getscn(ctx->elf, s[0]->sym.st_shndx);
		if (scn == NULL)
			return -1;

		Elf_Data *data = elf_getdata(scn, NULL);
		if (data == NULL)
			return -1;

		uint8_t *symData = (uint8_t *)data->d_buf + s[0]->sym.st_value;

		DisasmData dissData = { .sym = s[0]->sym, .shdr = shdr, .abfd = abfd,
								.symData = symData, .data = sym, .ctx = ctx };

		disassemble_info disasmInfo = { 0 };
#ifdef DISASSEMBLY_STYLE_SUPPORT
		disassembler_ftype disasm = initDisassembler(&dissData, NULL,
													nullDisasmPrintf, &disasmInfo,
													checkRelatedSymbols,
													nullFprintfStyled);
#else
		disassembler_ftype disasm = initDisassembler(&dissData, NULL,
													nullDisasmPrintf, &disasmInfo,
													checkRelatedSymbols);
#endif /* DISASSEMBLY_STYLE_SUPPORT */

		if (disasm == NULL)
		{
			disassemble_free_target(&disasmInfo);
			bfd_close(abfd);
			LOG_ERR("Could not get disassembler");
			return -1;
		}

		dissData.result = 0;
		dissData.pc = 0;
		while (dissData.pc < s[0]->sym.st_size)
		{
			int insnSize = disasm(dissData.pc, &disasmInfo);
			if (insnSize < 0 || dissData.result == -1)
				break;

			dissData.pc += insnSize;
		}

		disassemble_free_target(&disasmInfo);
	}

	bfd_close(abfd);

	return 0;
}

/*
 * @return Number of symbols for relocations. Return -1 on error
 */
static int getSymbolsForRelocations(Elf *elf, Elf64_Section sec,
									GElf_Sym *results, GElf_Rela **relocs)
{
	GElf_Rela rela;
	GElf_Shdr shdr;
	Elf_Scn *scn = getRelForSectionIndex(elf, sec);
	if(scn == NULL)
		return -1;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	GElf_Rela *relas = *relocs = calloc(cnt, sizeof(GElf_Rela));
	if (!CHECK_ALLOC(relas))
		return -1;

	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getrela(data, i, &rela) == NULL)
			return -1;

		GElf_Sym sym = getSymbolByIndex(elf, ELF64_R_SYM(rela.r_info));
		if (invalidSym(sym))
			return -1;

		if (sym.st_name != 0 &&
			(rela.r_addend == 0 || rela.r_addend == -4 || rela.r_addend == -5) &&
			ELF64_ST_TYPE(sym.st_info) != STT_SECTION)
		{
			*results = sym;
			results++;
			memcpy(relas, &rela, sizeof(rela));
			relas++;
			continue;
		}

		if (ELF64_R_TYPE(rela.r_info) == R_X86_64_PC32 ||
			ELF64_R_TYPE(rela.r_info) == R_X86_64_PLT32)
			rela.r_addend += 4;

		sym = getSymbolByOffset(elf, sym.st_shndx, rela.r_addend, true);
		if (!invalidSym(sym))
		{
			*results = sym;
			results++;
			memcpy(relas, &rela, sizeof(rela));
			relas++;
		}
	}

	return relas - *relocs;
}

char *symbolReferenceFrom(const char *filePath, const char *symName)
{
	char *result = NULL;
	int fd = -1;
	Elf *elf = openElf(filePath, true, &fd);
	if (elf == NULL)
		goto err;

	GElf_Sym sym;
	int res = getSymbolByNameAndType(elf, symName, STT_FUNC, &sym);
	if (res == -1)
	{
		LOG_ERR("Error during fetching symbol %s", symName);
		goto err;
	}
	else if (res == 0)
	{
		LOG_ERR("Can't find symbol %s", symName);
		goto err;
	}

	Context ctx = initContext(elf, filePath);
	ctx.symbols = readSymbols(elf, &ctx.symbolsCount);
	if (ctx.symbols == NULL)
		goto err;

	// find functions
	if (findSymbolsRelatingTo(&ctx, &sym) != 0)
		goto err;

	// find variables
	GElf_Shdr shdr;
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		goto err;

	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		goto err;

	if (gelf_getshdr(scn, &shdr) == NULL)
		goto err;

	int symtabLink = shdr.sh_link;

	GElf_Sym *syms = calloc(ctx.symbolsCount, sizeof(GElf_Sym));
	CHECK_ALLOC(syms);
	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL)
	{
		if (gelf_getshdr(scn, &shdr) == NULL)
			goto err;

		if (shdr.sh_type != SHT_RELA)
			continue;

		Elf_Scn *parentScn = elf_getscn(elf, shdr.sh_info);
		if (parentScn == NULL)
			goto err;

		if (gelf_getshdr(parentScn, &shdr) == NULL)
			goto err;

		if (shdr.sh_type != SHT_PROGBITS || (shdr.sh_flags & SHF_ALLOC) == 0 ||
			shdr.sh_flags & SHF_EXECINSTR)
			continue;

		Elf64_Section secIndex = elf_ndxscn(parentScn);
		if (secIndex == SHN_UNDEF)
			goto err;

		const char *secName = getSectionName(elf, secIndex);
		if (secName == NULL)
			goto err;

		if (strstr(secName, ".discard.") == secName ||
			strstr(secName, ".smp_locks") == secName ||
			strstr(secName, "___ksymtab+") == secName ||
			strstr(secName, "__bug_table") == secName ||
			strstr(secName, ".return_sites") == secName ||
			strstr(secName, ".orc_unwind_ip") == secName ||
			strstr(secName, ".initcall2.init") == secName ||
			strstr(secName, ".initcall4.init") == secName ||
			strstr(secName, ".retpoline_sites") == secName ||
			strstr(secName, ".altinstructions") == secName)
			continue;

		GElf_Rela *relocs = NULL;
		int count = getSymbolsForRelocations(elf, secIndex, syms, &relocs);
		if (count == -1)
			goto err;

		for (int i = 0; i < count; i++)
		{
			if (sym.st_name != syms[i].st_name)
				continue;

			GElf_Sym varSym = getSymbolByOffset(elf, secIndex,
												relocs[i].r_offset, false);
			if (invalidSym(varSym))
			{
				free(relocs);
				goto err;
			}
			Symbol *symbol = getSymbolForSym(&ctx, &varSym);
			if (symbol == NULL)
			{
				free(relocs);
				goto err;
			}

			symbol->data = (void *) true;
		}
		free(relocs);
	}

	result = calloc(1, sizeof(char));
	if (result == NULL)
		goto err;

	for (Symbol **s = ctx.symbols; *s != NULL; s++)
	{
		if (s[0]->data)
		{
			result = appendFormatString(result, "%s:%s\n",
										s[0]->isFun ? "f" : "v",
										s[0]->name);
			if (result == NULL)
				goto err;
		}
	}

out:
	if (fd != -1)
	{
		freeContext(&ctx);
		free(syms);

		if (elf != NULL)
			elf_end(elf);

		close(fd);
	}

	fflush(stdout);
	return result;

err:
	result = NULL;
	goto out;
}
