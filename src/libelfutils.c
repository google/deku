/*
 * Copyright (c) 2024 Google LLC
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

 /*
  * This file contains functions that operate on object (elf) file.
  */

#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libelfutils.h"

bool ShowDebugLog = false;

GElf_Shdr InvalidShdr = {-1};
GElf_Sym InvalidSym = {-1};

GElf_Shdr getSectionHeader(Elf *elf, Elf64_Section index)
{
	GElf_Shdr shdr;
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return InvalidShdr;

	Elf_Scn *scn = elf_getscn(elf, index);
	if (scn == NULL)
		return InvalidShdr;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return InvalidShdr;

	return shdr;
}

Elf_Scn *getSectionByName(Elf *elf, const char *secName)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return NULL;

	while ((scn = elf_nextscn(elf, scn)) != NULL)
	{
		if (gelf_getshdr(scn, &shdr) == NULL)
			return NULL;

		const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (name == NULL)
			return NULL;

		if (strcmp(name, secName) == 0)
			return scn;
	}
	return NULL;
}

Elf_Scn *getRelForSectionIndex(Elf *elf, Elf64_Section index)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	while ((scn = elf_nextscn(elf, scn)) != NULL)
	{
		if (gelf_getshdr(scn, &shdr) == NULL)
			return NULL;

		if (shdr.sh_type == SHT_RELA && shdr.sh_info == index)
			return scn;
	}
	return NULL;
}

char *getSectionName(Elf *elf, Elf64_Section index)
{
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return NULL;

	GElf_Shdr shdr = getSectionHeader(elf, index);
	if (invalidShdr(shdr))
		return NULL;

	return elf_strptr(elf, shstrndx, shdr.sh_name);
}

Symbol **readSymbols(Elf *elf, size_t *count)
{
	size_t i;
	Symbol **syms;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		goto err;

	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		goto err;

	if (gelf_getshdr(scn, &shdr) == NULL)
		goto err;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	syms = (Symbol **)calloc(cnt + 1, sizeof(Symbol *));
	if (!CHECK_ALLOC(syms))
		goto err;

	*count = 0;
	for (i = 0; i < cnt; i++)
	{
		if (gelf_getsym(data, i, &sym) == NULL)
			goto err;

		syms[i] = calloc(1, sizeof(Symbol));
		if (!CHECK_ALLOC(syms[i]))
			goto err;

		syms[i]->sym = sym;
		// name
		syms[i]->name = elf_strptr(elf, shdr.sh_link, sym.st_name);
		if (syms[i]->name == NULL)
			goto err;

		// section index
		syms[i]->sym.st_shndx = sym.st_shndx;
		// is function
		if ((sym.st_info == ELF64_ST_INFO(STB_GLOBAL, STT_FUNC) ||
			 (sym.st_info == ELF64_ST_INFO(STB_LOCAL, STT_FUNC)) ||
			 (sym.st_info == ELF64_ST_INFO(STB_WEAK, STT_FUNC))) &&
			strlen(syms[i]->name) > 0 && sym.st_size > 0)
		{
			syms[i]->isFun = true;
		}
		// is variable
		if (sym.st_info == ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT) ||
			(sym.st_info == ELF64_ST_INFO(STB_LOCAL, STT_OBJECT)))
		{
			const char *scnName = getSectionName(elf, sym.st_shndx);
			if (scnName == NULL)
				goto err;

			if (strstr(scnName, ".data.") == scnName ||
				strstr(scnName, ".bss.") == scnName)
				syms[i]->isVar = true;
			if (strstr(scnName, ".rodata.") == scnName ||
				strstr(scnName, ".rodata.str") != scnName)
				syms[i]->isVar = true;
		}
		syms[i]->index = (*count)++;
	}

	return syms;

err:
	while (i)
		free(syms[i--]);

	free(syms);
	return NULL;
}

GElf_Sym getSymbolByName(Elf *elf, const char *name, size_t *symIndex, bool definedOnly)
{
	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		goto err;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		goto err;

	if (gelf_getshdr(scn, &shdr) == NULL)
		goto err;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	*symIndex = 1;
	for (size_t i = 1; i < cnt; i++)
	{
		if (gelf_getsym(data, i, &sym) == NULL)
			goto err;

		const char *symName = elf_strptr(elf, shdr.sh_link, sym.st_name);
		if (symName == NULL)
			goto err;

		if (strcmp(symName, name) == 0 && (!definedOnly || sym.st_size > 0))
			return sym;

		(*symIndex)++;
	}

err:
	*symIndex = 0;
	return InvalidSym;
}

/*
 * @return If found return 1, if not found return 0, on error return value less than 0
 */
int getSymbolByNameAndType(Elf *elf, const char *symName, const int type, GElf_Sym *sym)
{
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		return -1;

	GElf_Shdr shdr;
	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getsym(data, i, sym) == NULL)
			return -1;

		const char *name = elf_strptr(elf, shdr.sh_link, sym->st_name);
		if (name == NULL)
			return -1;

		if ((sym->st_info == ELF64_ST_INFO(STB_WEAK, type) ||
			 sym->st_info == ELF64_ST_INFO(STB_LOCAL, type) ||
			 sym->st_info == ELF64_ST_INFO(STB_GLOBAL, type)) &&
			strcmp(name, symName) == 0)
			return 1;
	}

	return 0;
}

GElf_Sym getSymbolByIndex(Elf *elf, size_t index)
{
	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		return InvalidSym;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return InvalidSym;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return InvalidSym;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	if (index < cnt)
	{
		if (gelf_getsym(data, index, &sym) == NULL)
			return InvalidSym;
		else
			return sym;
	}

	return InvalidSym;
}

Symbol *getSymbolForRelocation(Context *ctx, const GElf_Rela rela)
{
	size_t symIndex = ELF64_R_SYM(rela.r_info);
	if (ctx->symbols[symIndex]->sym.st_shndx == 0)
		return ctx->symbols[symIndex];
	if (ctx->symbols[symIndex]->sym.st_size > 0)
		return ctx->symbols[symIndex];
	if (ELF64_ST_TYPE(ctx->symbols[symIndex]->sym.st_info) == STT_FUNC ||
		ELF64_ST_TYPE(ctx->symbols[symIndex]->sym.st_info) == STT_OBJECT)
		return ctx->symbols[symIndex];

	size_t secIndex = ctx->symbols[symIndex]->sym.st_shndx;
	Elf64_Sxword addend = rela.r_addend;
	switch (ELF64_R_TYPE(rela.r_info))
	{
	case R_X86_64_PC32:
	case R_X86_64_PLT32:
		addend += 4;
		break;
	}

	/*
	 * if the relocation with r_addend X points to a section, find a symbol that also points to the
	 * same section by checking its offset (st_value)
	 */
	for (Symbol **s = ctx->symbols; *s != NULL; s++)
	{
		if (s[0]->index != symIndex && s[0]->sym.st_shndx == secIndex &&
			(size_t)addend >= s[0]->sym.st_value &&
			(size_t)addend < s[0]->sym.st_value + s[0]->sym.st_size)
			return s[0];
	}

	// example: referrer to symbol (st_value == st_size == 0) that points to .rodata.str1.1
	return ctx->symbols[symIndex];
}

GElf_Sym getSymbolByOffset(Elf *elf, Elf64_Section shndx, int offset, bool exact)
{
	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		return InvalidSym;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return InvalidSym;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return InvalidSym;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getsym(data, i, &sym) == NULL)
			return InvalidSym;

		if (sym.st_name != 0 && sym.st_shndx == shndx)
		{
			if (exact && sym.st_value == offset)
				return sym;
			else if (!exact && offset >= sym.st_value &&
					 offset < sym.st_value + sym.st_size)
				return sym;
		}
	}

	return InvalidSym;
}

GElf_Sym getSymbolByAbsoluteOffset(Elf *elf, int offset, bool exact)
{
	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		return InvalidSym;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return InvalidSym;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return InvalidSym;

	scn = NULL;
	Elf64_Section shndx = SHN_UNDEF;
	int i=0;
	while ((scn = elf_nextscn(elf, scn)) != NULL)
	{
		GElf_Shdr shdr;
		if (gelf_getshdr(scn, &shdr) == NULL)
			return InvalidSym;

		if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) &&
			shdr.sh_offset >= offset && shdr.sh_offset + shdr.sh_size > offset)
		{
			shndx = elf_ndxscn(scn);
			offset -= shdr.sh_offset;
			break;
		}
		i++;
	}

	if (shndx == SHN_UNDEF)
		return InvalidSym;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getsym(data, i, &sym) == NULL)
			return InvalidSym;

		if (sym.st_name != 0 && sym.st_shndx == shndx)
		{
			if (exact && sym.st_value == offset)
				return sym;
			else if (!exact && offset >= sym.st_value &&
					 offset < sym.st_value + sym.st_size)
				return sym;
		}
	}

	return InvalidSym;
}

char *appendFormatString(char *buf, const char *format, ...)
{
	char localBuf[512];
	va_list args;
	va_start (args, format);
	int len = vsnprintf(localBuf, sizeof(localBuf), format, args);
	va_end (args);
	if (len < 0)
		return NULL;

	buf = REALLOC(buf, strlen(buf) + len + 1);
	if (buf == NULL)
		return NULL;

	strcat(buf, localBuf);
	return buf;
}

/*
 * @return Non-zero symbol index. 0 on error
 */
int getSymbolIndex(Elf *elf, const GElf_Sym *sym)
{
	GElf_Shdr symShdr;
	GElf_Sym symSymtab;
	Elf_Scn *symScn = getSectionByName(elf, ".symtab");
	if (symScn == NULL)
		goto err;

	Elf_Data *symData = elf_getdata(symScn, NULL);
	if (symData == NULL)
		goto err;

	if (gelf_getshdr(symScn, &symShdr) == NULL)
		goto err;

	for (size_t i = 1; i < symShdr.sh_size / symShdr.sh_entsize; i++)
	{
		if (gelf_getsym(symData, i, &symSymtab) == NULL)
			goto err;

		if (memcmp(sym, &symSymtab, sizeof(*sym)) == 0)
			return i;
	}

err:
	LOG_ERR("Invalid index for symbol %u", sym->st_name);

	return 0;
}

/*
 * @return Number of updated relocations. On error return -1
 */
int moveRelocationToOtherSymbol(Elf *elf, int fromSymIndex, int toSymIndex)
{
	int count = 0;
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
	{
		LOG_ERR("Cannot get section header string index");
		fflush(stdout);
		return -1;
	}

	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	GElf_Rela rela;
	Elf_Data *data;
	while ((scn = elf_nextscn(elf, scn)) != NULL)
	{
		if (gelf_getshdr(scn, &shdr) == NULL)
			goto err;

		if (shdr.sh_type != SHT_RELA)
			continue;

		data = elf_getdata(scn, NULL);
		if (data == NULL)
			goto err;

		Elf64_Xword cnt = shdr.sh_size / shdr.sh_entsize;
		for (Elf64_Xword i = 0; i < cnt; i++)
		{
			if (gelf_getrela(data, i, &rela) == NULL)
				goto err;

			if (ELF64_R_SYM(rela.r_info) == fromSymIndex)
			{
				rela.r_info = ELF64_R_INFO(toSymIndex, ELF64_R_TYPE(rela.r_info));
				if (gelf_update_rela(data, i, &rela) == 0)
					goto err;

				count++;
			}
		}
	}

	fflush(stdout);
	return count;

err:
	fflush(stdout);
	return -1;
}

bool isAARCH64(Elf *elf)
{
	const Elf64_Ehdr *ehdr = elf64_getehdr(elf);
	if (ehdr == NULL)
	{
		LOG_ERR("Cannot get class-dependent object file header. %s", elf_errmsg(-1));
		return false;
	}
	return ehdr->e_machine == EM_AARCH64;
}

Elf *openElf(const char *filePath, bool readOnly, int *fd)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		goto err;

	*fd = open(filePath, readOnly ? O_RDONLY : O_RDWR);
	if (*fd == -1)
	{
		LOG_ERR("Cannot open file '%s'", filePath);
		goto err;
	}

	Elf *elf = elf_begin(*fd, readOnly ? ELF_C_READ : ELF_C_RDWR, NULL);
	if (elf == NULL)
	{
		LOG_ERR("Problems opening '%s' as ELF file: %s", filePath, elf_errmsg(-1));
		goto err;
	}

	const Elf64_Ehdr *ehdr = elf64_getehdr(elf);
	if (ehdr == NULL)
	{
		LOG_ERR("Cannot get class-dependent object file header from %s. %s", filePath, elf_errmsg(-1));
		goto err;
	}

	if (ehdr->e_machine != EM_X86_64 && ehdr->e_machine != EM_AARCH64)
	{
		LOG_ERR("Unsupported architecture: %d in %s. Only x86_64 and ARM64 are supported.", ehdr->e_machine, filePath);
		goto err;
	}

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
	{
		LOG_ERR("Cannot get section header string index in %s", filePath);
		goto err;
	}

	if (getSectionByName(elf, ".strtab") == NULL)
	{
		LOG_ERR("Failed to find .strtab section in %s", filePath);
		goto err;
	}

	if (getSectionByName(elf, ".symtab") == NULL)
	{
		LOG_ERR("Failed to find .symtab section in %s", filePath);
		goto err;
	}

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

// TODO check return
Context initContext(Elf *elf, const char *filePath)
{
	Context ctx = {};
	ctx.elf = elf;
	ctx.filePath = filePath;
	ctx.symtabScn = getSectionByName(elf, ".symtab");
	if (ctx.symtabScn == NULL)
	{
		Context empty = {};
		return empty;
	}

	if (elf_getshdrnum(elf, &ctx.sectionsCount) != 0)
	{
		Context empty = {};
		return empty;
	}

	return ctx;
}

void freeContext(Context *ctx)
{
	if (ctx->symbols)
	{
		for (Symbol **s = ctx->symbols; *s != NULL; s++)
			free(s[0]);
	}

	free(ctx->symbols);
	free(ctx->copiedScnMap);
	ctx->symbols = NULL;
	ctx->copiedScnMap = NULL;
}
