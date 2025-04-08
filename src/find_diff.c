// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions responsible for finding differences between the
 * origin file and the patched object file.
 */

#include <stdlib.h>
#include <unistd.h>

#include "disassembler.h"

typedef enum
{
	DIFF_NO_DIFF,
	DIFF_NEW_VAR,
	DIFF_MOD_VAR,
	DIFF_NEW_FUN,
	DIFF_MOD_FUN,
} DiffResult;

static const unsigned int crc32Table[] =
{
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
  0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
  0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
  0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
  0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
  0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
  0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
  0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
  0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
  0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
  0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
  0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
  0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
  0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
  0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
  0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
  0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
  0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
  0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
  0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
  0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
  0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
  0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
  0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
  0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
  0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
  0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
  0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
  0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
  0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
  0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
  0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
  0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
  0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
  0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
  0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
  0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
  0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
  0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
  0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
  0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
  0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
  0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

static uint32_t crc32(uint8_t *data, uint32_t len)
{
	unsigned int crc = 0;
	while (len--)
	{
		crc = (crc << 8) ^ crc32Table[((crc >> 24) ^ *data) & 255];
		data++;
	}
	return crc;
}

/*
 * @return Hash of relocation symbol. On error return 0
 */
static uint32_t calcRelSymHash(Elf *elf, const GElf_Sym *sym)
{
	uint32_t crc = 0;
	GElf_Rela rela;
	GElf_Shdr shdr;
	Elf_Scn *scn = getSectionByName(elf, ".symtab");
	if (scn == NULL)
		goto err;

	if (gelf_getshdr(scn, &shdr) == NULL)
		goto err;

	Elf64_Word symtabLink = shdr.sh_link;

	scn = getRelForSectionIndex(elf, sym->st_shndx);
	if (scn == NULL)
		goto err;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		goto err;

	if (gelf_getshdr(scn, &shdr) == NULL)
		goto err;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getrela(data, i, &rela) == NULL)
			goto err;

		if (rela.r_offset < sym->st_value || rela.r_offset > sym->st_value + sym->st_size)
			continue;

		char *name = "";
		GElf_Sym rsym = getSymbolByIndex(elf, ELF64_R_SYM(rela.r_info));
		if (invalidSym(rsym))
			goto err;

		if (ELF64_ST_TYPE(rsym.st_info) != STT_SECTION)
		{
			name = elf_strptr(elf, symtabLink, rsym.st_name);
		}
		else
		{
			shdr = getSectionHeader(elf, rsym.st_shndx);
			if (invalidShdr(shdr))
				goto err;

			const char *secName = getSectionName(elf, rsym.st_shndx);

			if (shdr.sh_flags & (SHF_MERGE | SHF_STRINGS))
			{
				scn = elf_getscn(elf, rsym.st_shndx);
				if (scn == NULL)
					goto err;

				Elf_Data *data = elf_getdata(scn, NULL);
				if (data == NULL)
					goto err;

				if (gelf_getshdr(scn, &shdr) == NULL)
					goto err;

				if (strstr(secName, ".rodata.cst") == secName)
					name = "";
				else if ((Elf64_Sxword)shdr.sh_size > rela.r_addend)
					name = (char *)data->d_buf + rela.r_addend;
			}
			else
			{
				if (strcmp(".altinstr_aux", secName) == 0)
					continue;

				if (ELF64_R_TYPE(rela.r_info) == R_X86_64_PC32 || \
					ELF64_R_TYPE(rela.r_info) == R_X86_64_PLT32)
					rela.r_addend += 4;

				GElf_Sym originRsym = rsym;
				rsym = getSymbolByOffset(elf, rsym.st_shndx, rela.r_addend,
										 true);
				if (invalidSym(rsym)) {
					if (rela.r_addend == -1) {
						rsym = getSymbolByOffset(elf, originRsym.st_shndx, 0, true);
					} else if (ELF64_R_TYPE(rela.r_info) == R_X86_64_32S) {
						rsym = getSymbolByOffset(elf, originRsym.st_shndx, rela.r_addend - 4, true);
					}
				}

				name = elf_strptr(elf, symtabLink, rsym.st_name);
			}
		}
		if (name == NULL)
			continue;

		crc += rela.r_offset - sym->st_value;
		crc += crc32((uint8_t *)name, strlen(name));
	}

	return crc;

err:
	return 0;
}

/**
 * @return: 1 as equals, 0 non equals, -1 error
 */
static int equalFunctions(Context *ctx, const char *funName)
{
	GElf_Sym sym1;
	GElf_Sym sym2;
	char *disassembled1 = NULL;
	char *disassembled2 = NULL;
	Context tmpCtx = {0};
	Elf *firstElf = ctx->elf;
	Elf *secondElf = ctx->secondElf;

	if (getSymbolByNameAndType(firstElf, funName, STT_FUNC, &sym1) != 1)
		goto err;

	if (getSymbolByNameAndType(secondElf, funName, STT_FUNC, &sym2) != 1)
		goto err;

	if (sym1.st_size != sym2.st_size)
		return 0;

	Elf_Scn *scn1 = elf_getscn(firstElf, sym1.st_shndx);
	if (scn1 == NULL)
		goto err;

	Elf_Data *data1 = elf_getdata(scn1, NULL);
	if (data1 == NULL)
		goto err;

	uint8_t *symData1 = (uint8_t *)data1->d_buf + sym1.st_value;
	Elf_Scn *scn2 = elf_getscn(secondElf, sym2.st_shndx);
	if (scn2 == NULL)
		goto err;

	Elf_Data *data2 = elf_getdata(scn2, NULL);
	if (data2 == NULL)
		goto err;

	uint8_t *symData2 = (uint8_t *)data2->d_buf + sym2.st_value;
	if (applyStaticKeys(firstElf, &sym1, (uint8_t *)data1->d_buf) != 0)
		goto err;

	if (applyStaticKeys(secondElf, &sym2, (uint8_t *)data2->d_buf) != 0)
		goto err;

	if (memcmp(symData1, symData2, sym2.st_size) != 0)
	{
		bool isEqual = false;
		GElf_Shdr shdr;
		tmpCtx = initContext(firstElf, ctx->filePath);
		Elf_Scn *scn = getSectionByName(firstElf, ".symtab");
		if (scn == NULL)
			goto err;

		if (gelf_getshdr(scn, &shdr) == NULL)
			goto err;

		DisasmData data1 = { .ctx = &tmpCtx, .sym = sym1, .shdr = shdr, .symData = symData1 };
		disassembled1 = disassembleBytes(&data1);
		if (disassembled1 == NULL)
			goto err;

		tmpCtx.elf = secondElf;
		scn = getSectionByName(secondElf, ".symtab");
		if (scn == NULL)
			goto err;

		if (gelf_getshdr(scn, &shdr) == NULL)
			goto err;

		DisasmData data2 = { .ctx = &tmpCtx, .sym = sym2, .shdr = shdr, .symData = symData2 };
		disassembled2 = disassembleBytes(&data2);
		if (disassembled2 == NULL)
			goto err;

		// skip checking first line if it might be a call to __fentry__ in the runtime
		if (strstr(disassembled1, "nop") == disassembled1 ||
			strstr(disassembled2, "nop") == disassembled2)
			isEqual = strcmp(strchr(disassembled1, '\n'), strchr(disassembled2, '\n')) == 0;
		else
			isEqual = strcmp(disassembled1, disassembled2) == 0;

		free(disassembled1);
		free(disassembled2);
		freeContext(&tmpCtx);
		disassembled1 = NULL;
		disassembled2 = NULL;

		if (!isEqual)
			return 0;
	}

	return calcRelSymHash(firstElf, &sym1) == calcRelSymHash(secondElf, &sym2) ? 1 : 0;

err:
	free(disassembled1);
	free(disassembled2);
	freeContext(&tmpCtx);

	return -1;
}

static void checkNearJmpXReference(bfd_vma vma, struct disassemble_info *inf)
{
	uint8_t operandOff = 0;
	uint8_t operandSize = 0;
	uint32_t symOffset;
	DisasmData *data = (DisasmData *)inf->application_data;
	GElf_Sym sym = getTargetSymbolForInstruction(vma, data, &operandOff, &operandSize,
												 &symOffset);

	if (invalidSym(sym))
		return;

	const uint32_t *operand = (uint32_t *)(data->symData + data->pc + operandOff);
	if (operandSize < 4 && ELF64_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_size > 0)
	{
		if (memcmp(&data->sym, &sym, sizeof(sym)) != 0)
		{
			uint32_t symIndex = getSymbolIndex(data->ctx->elf, &sym);
			if (symIndex == 0)
			{
				data->result = -1;
				return;
			}

			if (data->ctx->symbols[symIndex]->data != (void *) DIFF_NO_DIFF)
				return;

			const char *name = data->ctx->symbols[symIndex]->name;
			if (strstr(name, "__cfi_") == name ||
				strstr(name, "__pfx_") == name )
				return;

			data->ctx->symbols[symIndex]->data = (void *) DIFF_MOD_FUN;
			const char *name1 = elf_strptr(data->ctx->elf, data->shdr.sh_link,
										   data->sym.st_name);
			const char *name2 = elf_strptr(data->ctx->elf, data->shdr.sh_link,
										   sym.st_name);
			LOG_DEBUG("A close jump to a neighboring function with a jump of "
					  "less than 4 bytes was detected (%s -> %s)", name1,
					  name2);
		}
	}
}

// if jump to other functions is not 5-byte instruction (can't be converted to
// relocation) then mark target function as modified
static int findNearJmpXReferences(Context *ctx, GElf_Sym *sym)
{
	GElf_Shdr shdr;
	Elf_Scn *scn = getSectionByName(ctx->elf, ".symtab");
	if (scn == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	scn = elf_getscn(ctx->elf, sym->st_shndx);
	if (scn == NULL)
		return -1;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	uint8_t *symData = (uint8_t *)data->d_buf + sym->st_value;
	DisasmData dissData = { .sym = *sym, .shdr = shdr, .symData = symData,
							.ctx = ctx };

	dissData.abfd = initBfd(ctx->filePath);
	if (dissData.abfd == NULL)
		return -1;

	disassemble_info disasmInfo = { 0 };
#ifdef DISASSEMBLY_STYLE_SUPPORT
	disassembler_ftype disasm = initDisassembler(&dissData, NULL,
												 nullDisasmPrintf, &disasmInfo,
												 checkNearJmpXReference,
												 nullFprintfStyled);
#else
	disassembler_ftype disasm = initDisassembler(&dissData, NULL,
												 nullDisasmPrintf, &disasmInfo,
												 checkNearJmpXReference);
#endif /* DISASSEMBLY_STYLE_SUPPORT */

	if (disasm == NULL)
	{
		disassemble_free_target(&disasmInfo);
		bfd_close(dissData.abfd);
		return -1;
	}

	dissData.result = 0;
	dissData.pc = 0;
	while (dissData.pc < sym->st_size)
	{
        int insnSize = disasm(dissData.pc, &disasmInfo);
        if (insnSize < 0 || dissData.result == -1)
            break;

		dissData.pc += insnSize;
	}

	disassemble_free_target(&disasmInfo);
    bfd_close(dissData.abfd);

	return 0;
}

/*
 * @return Modified symbols as a string. On error return NULL
 */
static char *findModifiedSymbols(Context *ctx)
{
	Elf_Scn *scn = getSectionByName(ctx->elf, ".symtab");
	if (scn == NULL)
		return NULL;

	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return NULL;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return NULL;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;

	for (size_t i = 0; i < ctx->symbolsCount; i++)
		ctx->symbols[i]->data = (void *) DIFF_NO_DIFF;

	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getsym(data, i, &sym) == NULL)
			return NULL;

		if (sym.st_size == 0 || sym.st_shndx == 0 ||
			sym.st_name == 0 || sym.st_shndx >= ctx->sectionsCount)
			continue;

		const char *name = elf_strptr(ctx->elf, shdr.sh_link, sym.st_name);
		if (name == NULL)
			return NULL;

		if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC)
		{
			GElf_Sym secondSym;
			if (strstr(name, "__cfi_") == name ||
				strstr(name, "__pfx_") == name )
				continue;

			int res = getSymbolByNameAndType(ctx->secondElf, name, STT_FUNC, &secondSym);
			if (res == -1)
			{
				return NULL;
			}
			else if (res == 0)
			{
				ctx->symbols[i]->data = (void *) DIFF_NEW_FUN;
			}
			else
			{
				int equals = equalFunctions(ctx, name);
				if (equals == -1)
					return NULL;

				if (!equals)
					ctx->symbols[i]->data = (void *) DIFF_MOD_FUN;
			}
		}
		else if (ELF64_ST_TYPE(sym.st_info) == STT_OBJECT)
		{
			GElf_Sym secondSym;
			int res = getSymbolByNameAndType(ctx->secondElf, name, STT_OBJECT, &secondSym);
			if (res == -1)
				return NULL;

			if (res == 0)
			{
				char *bssName = malloc(strlen(name) + 6);
				if (!CHECK_ALLOC(bssName))
					return NULL;

				char *dataName = malloc(strlen(name) + 7);
				if (!CHECK_ALLOC(dataName))
				{
					free(bssName);
					return NULL;
				}

				char *rodataName = malloc(strlen(name) + 9);
				if (!CHECK_ALLOC(rodataName))
				{
					free(dataName);
					free(bssName);
					return NULL;
				}

				snprintf(bssName, strlen(name) + 6, ".bss.%s", name);
				snprintf(dataName, strlen(name) + 7, ".data.%s", name);
				snprintf(rodataName, strlen(name) + 9, ".rodata.%s", name);

				const char *scnName = getSectionName(ctx->elf, sym.st_shndx);
				if (scnName == NULL)
				{
					free(rodataName);
					free(dataName);
					free(bssName);
					return NULL;
				}

				if (strcmp(scnName, bssName) == 0 ||
					strcmp(scnName, dataName) == 0 ||
					strcmp(scnName, rodataName) == 0 ||
					strcmp(scnName, ".bss") == 0 ||
					strcmp(scnName, ".data") == 0 ||
					strcmp(scnName, ".data..read_mostly") == 0 ||
					strcmp(scnName, ".data..ro_after_init") == 0 ||
					strcmp(scnName, ".data..nosave") == 0 ||
					strcmp(scnName, ".data..cacheline_aligned") == 0 ||
					strcmp(scnName, ".data..page_aligned") == 0 ||
					strcmp(scnName, ".bss..page_aligned") == 0 ||
					strcmp(scnName, ".rodata") == 0)
					ctx->symbols[i]->data = (void *) DIFF_NEW_VAR;
			}
			else if (strstr(name, "__func__") == name)
			{
				ctx->symbols[i]->data = (void *) DIFF_NEW_VAR; // TODO: find other way to force copy .rodata section
			}
		}
	}

	int diffCount;
	do
	{
		diffCount = 0;
		for (size_t i = 0; i < ctx->symbolsCount; i++)
		{
			if (ctx->symbols[i]->data != (void *) DIFF_NO_DIFF)
				diffCount++;
		}
		for (size_t i = 0; i < ctx->symbolsCount; i++)
		{
			if (ctx->symbols[i]->data == (void *) DIFF_NEW_FUN ||
				ctx->symbols[i]->data == (void *) DIFF_MOD_FUN)
			{
				if (findNearJmpXReferences(ctx, &ctx->symbols[i]->sym) == -1)
					return NULL;
			}
		}
		for (size_t i = 0; i < ctx->symbolsCount; i++)
		{
			if (ctx->symbols[i]->data != (void *) DIFF_NO_DIFF)
				diffCount--;
		}
	} while(diffCount);

	char *result = calloc(1, sizeof(char));
	if (!CHECK_ALLOC(result))
		return NULL;

	// if the only changes are a new variables starts with __func__. then skip it.
	// this is need beacause varaibles with __func__. prefix are always marked as
	// DIFF_NEW_VAR, but they are not really new. They are need to copy .rodata
	bool skipDueNotValidChange = true;
	for (size_t i = 0; i < ctx->symbolsCount; i++)
	{
		DiffResult diff = (uint64_t) ctx->symbols[i]->data;
		if (diff != DIFF_NEW_VAR ||
			strstr(ctx->symbols[i]->name, "__func__.") != ctx->symbols[i]->name)
		{
			skipDueNotValidChange = false;
			break;
		}
	}

	if (skipDueNotValidChange)
		return result;

	for (size_t i = 0; i < ctx->symbolsCount; i++)
	{
		DiffResult diff = (uint64_t) ctx->symbols[i]->data;
		switch (diff)
		{
			case DIFF_MOD_VAR:
				result = appendFormatString(result, "Modified variable: %s\n",
											ctx->symbols[i]->name);
				if (result == NULL)
					return NULL;

				break;
			case DIFF_NEW_VAR:
				result = appendFormatString(result, "New variable: %s\n",
											ctx->symbols[i]->name);
				if (result == NULL)
					return NULL;

				break;
			case DIFF_MOD_FUN:
				result = appendFormatString(result, "Modified function: %s\n",
											ctx->symbols[i]->name);
				if (result == NULL)
					return NULL;

				break;
			case DIFF_NEW_FUN:
				result = appendFormatString(result, "New function: %s\n",
											ctx->symbols[i]->name);
				if (result == NULL)
					return NULL;

				break;
			case DIFF_NO_DIFF:
			break;
		}
	}

	return result;
}

char *showDiff(const char *firstFile, const char *secondFile)
{
	int firstFd;
	int secondFd;
	Elf *firstElf = NULL;
	Elf *secondElf = NULL;
	Context ctx = {0};
	char *diff = NULL;

	firstElf = openElf(firstFile, true, &firstFd);
	if (firstElf == NULL)
		goto err;

	secondElf = openElf(secondFile, true, &secondFd);
	if (secondElf == NULL)
		goto err;

	ctx = initContext(secondElf, secondFile);
	ctx.secondElf = firstElf;
	ctx.symbols = readSymbols(secondElf, &ctx.symbolsCount);
	if (ctx.symbols == NULL)
		goto err;

	diff = findModifiedSymbols(&ctx);
	if (diff == NULL)
		goto err;

out:
	freeContext(&ctx);
	elf_end(firstElf);
	elf_end(secondElf);
	close(firstFd);
	close(secondFd);
	fflush(stdout);

	return diff;

err:
	diff = NULL;
	goto out;
}
