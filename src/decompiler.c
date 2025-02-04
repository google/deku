// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions that are responsible for decompile symbol
 * (function).
 */

#include "disassembler.h"

#include <unistd.h>


static Elf_Data *getSymbolData(Elf *elf, const char *name, char type)
{
	GElf_Shdr shdr;
	GElf_Sym sym;
	size_t secCount;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		return NULL;

	if (elf_getshdrnum(elf, &secCount) != 0)
		return NULL;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return NULL;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return NULL;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getsym(data, i, &sym) == NULL)
			return NULL;

		const char *symName = elf_strptr(elf, shdr.sh_link, sym.st_name);
		if (symName == NULL)
			return NULL;

		if (strcmp(symName, name) == 0)
		{
			if (ELF64_ST_TYPE(sym.st_info) == type &&
				sym.st_size > 0 && sym.st_shndx < secCount)
			{
				scn = elf_getscn(elf, sym.st_shndx);
				if (scn == NULL)
					return NULL;

				return elf_getdata(scn, NULL);
			}
		}
	}

	return NULL;
}

char *disassemble(const char *filePath, const char *symName, bool convertToReloc)
{
	char *disassembled = NULL;
	int fd;
	Context ctx = {0};

	Elf *elf = openElf(filePath, true, &fd);
	if (elf == NULL)
		goto err;

	ctx = initContext(elf, filePath);
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

	GElf_Shdr shdr;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		goto err;

	if (gelf_getshdr(scn, &shdr) == NULL)
		goto err;

	Elf_Data *data = getSymbolData(elf, symName, STT_FUNC);
	if (data == NULL)
		goto err;

	uint8_t *symData = (uint8_t *)data->d_buf + sym.st_value;
	DisasmData dissData = { .ctx = &ctx, .sym = sym, .shdr = shdr, .symData = symData };

	if (convertToReloc)
	{
		if (convertToRelocations(&dissData) != 0)
			goto err;
	}

	if (applyStaticKeys(elf, &sym, data->d_buf) != 0)
		goto err;

	disassembled = disassembleBytes(&dissData);
	if (disassembled == NULL)
		goto err;

out:
	freeContext(&ctx);
	close(fd);
	fflush(stdout);

	return disassembled;

err:
	disassembled = NULL;
	goto out;
}
