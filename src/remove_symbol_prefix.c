// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions that are responsible for remove given prefix from
 * symbols name.
 */

#include <string.h>
#include <unistd.h>

#include "libelfutils.h"

/*
 * @return Number of changed symbols. On error return -1
 */
int removeSymbolNamePrefix(const char *filePath, const char *prefix)
{
	int res = 0;
	int fd;
	Elf *elf = openElf(filePath, false, &fd);
	if (elf == NULL)
	{
		res = -1;
		goto out;
	}

	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
	{
		LOG_ERR("Could not find .symtab section");
		res = -1;
		goto out;
	}

	GElf_Shdr shdr;
	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
	{
		LOG_ERR("Could not get data for .symtab section");
		res = -1;
		goto out;
	}

	if (gelf_getshdr(scn, &shdr) == NULL)
	{
		LOG_ERR("Could not get header for .symtab section");
		res = -1;
		goto out;
	}

	size_t prefixLen = strlen(prefix);
	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		GElf_Sym sym;
		if (gelf_getsym(data, i, &sym) == NULL)
		{
			LOG_ERR("Could not get symbol at index %zu", i);
			res = -1;
			goto out;
		}

		const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
		if (name == NULL)
		{
			LOG_ERR("Could not get symbol name at index %zu", i);
			res = -1;
			goto out;
		}

		if (strncmp(name, prefix, prefixLen) == 0)
		{
			size_t symIndex;
			GElf_Sym otherSym = getSymbolByName(elf, name+prefixLen, &symIndex, true);
			if (!invalidSym(otherSym))
			{
				if (moveRelocationToOtherSymbol(elf, i, symIndex) == -1)
				{
					LOG_ERR("Could not move relocation to other symbol");
					res = -1;
					goto out;
				}
			}
			else
			{
				sym.st_name += prefixLen;
			}

			if (gelf_update_sym(data, i, &sym) == 0)
			{
				LOG_ERR("Could not update symbol at index %zu", i);
				res = -1;
				goto out;
			}
		}
	}

	if (elf_update(elf, ELF_C_WRITE) == -1)
	{
		LOG_ERR("Failed to update elf file: %s", elf_errmsg(-1));
		res = -1;
		goto out;
	}

out:
	if (fd != -1)
	{
		if (elf != NULL)
			elf_end(elf);

		close(fd);
	}

	fflush(stdout);
	return res;
}
