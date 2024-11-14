// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions responsible for changing calls from one symbol
 * (function) to the other one.
 */

#include <string.h>
#include <unistd.h>

#include "libelfutils.h"

/*
 * @return Non-zero symbol index. On error returns 0
 */
static uint16_t getSymbolIndexByName(Elf *elf, const char *symName)
{
	GElf_Sym sym;
	GElf_Shdr shdr;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		return 0;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return 0;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return 0;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getsym(data, i, &sym) == NULL)
			return 0;

		const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
		if (name == NULL)
			return 0;

		if (strcmp(name, symName) == 0)
			return i;
	}

	return 0;
}

/*
 * @return Number of changed symbols. On error return -1
 */
int changeCallSymbol(char *filePath, const char *fromRelSym, const char *toRelSym)
{
	int replaced = 0;
	int fd;

	Elf *elf = openElf(filePath, false, &fd);
	if (elf == NULL)
		goto err;


	uint16_t oldSymIndex = getSymbolIndexByName(elf, fromRelSym);
	if (oldSymIndex == 0)
	{
		LOG_ERR("Can't find symbol '%s' in %s\n", fromRelSym, filePath);
		goto err;
	}

	uint16_t newSymIndex = getSymbolIndexByName(elf, toRelSym);
	if (newSymIndex == 0)
	{
		LOG_ERR("Can't find symbol '%s' in %s\n", toRelSym, filePath);
		goto err;
	}

	replaced = moveRelocationToOtherSymbol(elf, oldSymIndex, newSymIndex);
	if (replaced == -1)
		goto err;

	if (replaced && elf_update(elf, ELF_C_WRITE) == -1)
	{
		LOG_ERR("Failed to update elf file: %s", elf_errmsg(-1));
		goto err;
	}

	if (fd != -1)
	{
		if (elf != NULL)
			elf_end(elf);

		close(fd);
	}

out:
	fflush(stdout);
	return replaced;

err:
	replaced = -1;
	goto out;
}