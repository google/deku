// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions related to disassembly object file
 */

#define PACKAGE 1	/* required by libbfd */
#include <bfd.h>
#include <dis-asm.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disassembler.h"

static int disasmPrintf(void *buf, const char *format, ...)
{
	char localBuf[MAX_DISASM_LINE_LEN];
	va_list args;
	va_start (args, format);
	int len = vsnprintf(localBuf, sizeof(localBuf), format, args);
	va_end (args);
	if (len < 0)
		return len;

	char **buffer = (char **)buf;
	buffer[0] = REALLOC(buffer[0], strlen(buffer[0]) + len + 1);
	if (buffer[0] == NULL)
		return -1;

	strcat(buffer[0], localBuf);

	return len;
}

int nullDisasmPrintf(void *buf, const char *format, ...)
{
	(void) buf;
	(void) format;
	return 0;
}

#ifdef DISASSEMBLY_STYLE_SUPPORT
static int fprintfStyled(void *buf, enum disassembler_style style,
						  const char *format, ...)
{
	va_list args;
	int r;
	char localBuf[MAX_DISASM_LINE_LEN];
	(void)style;

	va_start(args, format);
	r = vsnprintf(localBuf, sizeof(localBuf), format, args);
	va_end(args);
	if (r < 0)
		return r;

	char **buffer = (char **)buf;
	buffer[0] = REALLOC(buffer[0], strlen(buffer[0]) + strlen(localBuf) + 1);
	if (buffer[0] == NULL)
		return -1;

	strcat(buffer[0], localBuf);

	return r;
}

int nullFprintfStyled(void *buf, enum disassembler_style style, const char *format, ...)
{
	(void)buf;
	(void)style;
	(void)format;
	return 0;
}
#endif /* DISASSEMBLY_STYLE_SUPPORT */

static GElf_Sym getSymbolForRelocAtOffset(Elf *elf, Elf64_Section sec,
										  size_t offset,
										  uint32_t *outSymOffset)
{
	GElf_Rela rela;
	GElf_Shdr shdr;
	Elf_Scn *scn = getRelForSectionIndex(elf, sec);
	if(scn == NULL)
		return InvalidSym;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return InvalidSym;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return InvalidSym;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getrela(data, i, &rela) == NULL)
			return InvalidSym;

		if (rela.r_offset == offset)
		{
			GElf_Sym sym = getSymbolByIndex(elf, ELF64_R_SYM(rela.r_info));
			if (invalidSym(sym))
				return InvalidSym;

			if (sym.st_name != 0 &&
				ELF64_ST_TYPE(sym.st_info) != STT_SECTION)
				return sym;

			if (ELF64_R_TYPE(rela.r_info) == R_X86_64_PC32 ||
				ELF64_R_TYPE(rela.r_info) == R_X86_64_PLT32)
				rela.r_addend += 4;
			sym = getSymbolByOffset(elf, sym.st_shndx, rela.r_addend,
									outSymOffset == NULL);
			if (!invalidSym(sym))
			{
				if (outSymOffset != NULL)
					*outSymOffset = rela.r_addend - sym.st_value;

				return sym;
			}
		}
	}

	return InvalidSym;
}

/*
 * Find the symbol pointed to by the instruction.
 * This function only support control instructions like: call, jump, bl
 */
GElf_Sym getTargetSymbolForInstruction(bfd_vma vma, DisasmData *data,  uint8_t *offset, uint8_t *size,
									   uint32_t *outSymOffset)
{
	GElf_Sym sym;
	const uint8_t *inst = data->symData + data->pc;
	int32_t operand = 0;
	uint8_t operandOff = 0;
	uint8_t operandSize = 4;
	bool isCtrlInstr = false;

	*outSymOffset = 0;

	if (!isAARCH64(data->ctx->elf))
	{
		if (inst[0] == 0xE8) // call
		{
			operandOff = 1;
			isCtrlInstr = true;
		}
		else if (inst[0] == 0xE9) // JMP	Jump
		{
			operandOff = 1;
			isCtrlInstr = true;
		}
		else if (inst[0] == 0xEA) // JMP	Jump
		{
			operandOff = 1;
			operandSize = 2;
			isCtrlInstr = true;
		}
		else if (inst[0] == 0xEB) // JMP	Jump
		{
			operandOff = 1;
			operandSize = 1;
			isCtrlInstr = true;
		}
		else if (inst[0] >= 0x70 && inst[0] <= 0x7F) // Jcc	Jump if condition
		{
			operandOff = 1;
			operandSize = 1;
			isCtrlInstr = true;
		}
		else if (inst[0] == 0x0F && inst[1] >= 0x80 && inst[1] <= 0x8F) // Jcc	Jump if condition
		{
			operandOff = 2;
			isCtrlInstr = true;
		}
	}
	else
	{
		if (inst[3] == 0xb5) // CBNZ
		{
			operandSize = 2;
			sym = getSymbolByOffset(data->ctx->elf, data->sym.st_shndx, vma + data->sym.st_value, false);
			if (sym.st_name == data->sym.st_name)
			{
				*outSymOffset = vma + data->sym.st_value - sym.st_value;
				return sym;
			}
		}
		else
		{
			// LOG_ERR("Unsupported instruction: %x %x %x %x at offset:0x%x (vma:0x%x)", inst[0], inst[1], inst[2], inst[3], (uint32_t)data->pc, (uint32_t)vma);
		}
	}

	if (!isCtrlInstr)
		return InvalidSym;

	memcpy(&operand, inst + operandOff, operandSize);
	if (operand == 0 && operandSize >= 4) // if it's relocation
	{
		uint32_t addr = data->pc + data->sym.st_value + operandOff;
		sym = getSymbolForRelocAtOffset(data->ctx->elf, data->sym.st_shndx, addr, outSymOffset);
	}
	else
	{
		uint32_t addr = data->sym.st_value + vma;
		sym = getSymbolByOffset(data->ctx->elf, data->sym.st_shndx, addr, true);
	}

	*offset = operandOff;
	*size = operandSize;

	return sym;
}

static void printFunAtAddr(bfd_vma vma, struct disassemble_info *inf)
{
	uint8_t operandOff = 0;
	uint8_t operandSize = 0;
	uint32_t symOffset;
	int res = 0;
	DisasmData *data = (DisasmData *)inf->application_data;
	if (isAARCH64(data->ctx->elf))
		vma -= 8;

	GElf_Sym sym = getTargetSymbolForInstruction(vma, data, &operandOff, &operandSize,
												 &symOffset);
	if (invalidSym(sym))
	{
		const char *name = elf_strptr(data->ctx->elf, data->shdr.sh_link,
									  data->sym.st_name);
		if (name == NULL)
		{
			data->result = -1;

			return;
		}

		res = (*inf->fprintf_func)(inf->stream, "<%s+0x%lX>", name, vma);
		if (res < 0)
		{
			data->result = -1;

			return;
		}

		return;
	}

	const char *name = elf_strptr(data->ctx->elf, data->shdr.sh_link, sym.st_name);
	if (name == NULL || strlen(name) == 0)
	{
		LOG_ERR("Can't find function for instruction at offset: 0x%zx on "
				"disassembling %s", data->pc,
				elf_strptr(data->ctx->elf, data->shdr.sh_link, data->sym.st_name));
		data->result = -1;

		return;
	}

	int32_t operand = 0;
	memcpy(&operand, data->symData + data->pc + operandOff, operandSize);
	vma += data->sym.st_value;

	if (symOffset != 0)
		res = (*inf->fprintf_func)(inf->stream, "<%s+0x%X>", name, symOffset);
	else if (operand == 0 || vma == 0 || vma == sym.st_value)
		res = (*inf->fprintf_func)(inf->stream, "%s", name);
	else
		res = (*inf->fprintf_func)(inf->stream, "<%s+0x%lX>", name,
								   vma - data->sym.st_value);
	if (res < 0)
	{
		data->result = -1;

		return;
	}
}

bfd *initBfd(const char *filePath)
{
    bfd_init();

    bfd *abfd = bfd_openr(filePath, NULL);
    if (abfd == NULL)
	{
        LOG_ERR("Could not open file %s\n", filePath);
        return NULL;
    }

    if (!bfd_check_format(abfd, bfd_object))
	{
        LOG_ERR("File is not an object file");
        bfd_close(abfd);
        return NULL;
    }

	return abfd;
}

disassembler_ftype initDisassembler(DisasmData *data, void *stream,
									fprintf_ftype fprintfFunc,
									disassemble_info *disasmInfo,
				  void (*printAddressFunc) (bfd_vma, struct disassemble_info *)
#ifdef DISASSEMBLY_STYLE_SUPPORT
				   					, fprintf_styled_ftype fprintfStyledFunc
#endif /* DISASSEMBLY_STYLE_SUPPORT */
									)
{
#ifdef DISASSEMBLY_STYLE_SUPPORT
	init_disassemble_info(disasmInfo, stream, fprintfFunc, fprintfStyledFunc);
#else
	init_disassemble_info(disasmInfo, stream, fprintfFunc);
#endif /* DISASSEMBLY_STYLE_SUPPORT */
	disasmInfo->arch = bfd_get_arch(data->abfd);
	disasmInfo->mach = bfd_get_mach(data->abfd);
	disasmInfo->buffer = data->symData;
	disasmInfo->buffer_vma = 0;
	disasmInfo->buffer_length = data->sym.st_size;
	disasmInfo->application_data = (void *)data;
	disasmInfo->print_address_func = printAddressFunc;
	disassemble_init_for_target(disasmInfo);

	return disassembler(disasmInfo->arch, disasmInfo->display_endian == BFD_ENDIAN_BIG, disasmInfo->mach, NULL);
}

char *disassembleBytes(DisasmData *data)
{
	char *buf[] = { calloc(0, 1) };
	if (buf[0] == NULL)
		return NULL;

	data->abfd = initBfd(data->ctx->filePath);
	if (data->abfd == NULL)
		return NULL;

	disassemble_info disasmInfo = { 0 };
#ifdef DISASSEMBLY_STYLE_SUPPORT
	disassembler_ftype disasm = initDisassembler(data, buf, disasmPrintf,
				   								 &disasmInfo, printFunAtAddr,
												 fprintfStyled);
#else
	disassembler_ftype disasm = initDisassembler(data, &buf, disasmPrintf,
				   								 &disasmInfo, printFunAtAddr);
#endif /* DISASSEMBLY_STYLE_SUPPORT */

	if (disasm == NULL)
	{
		disassemble_free_target(&disasmInfo);
		bfd_close(data->abfd);
		LOG_ERR("Could not get disassembler");
		return NULL;
	}

	data->result = 0;
	data->pc = 0;
	while (data->pc < data->sym.st_size)
	{
        int insnSize = disasm(data->pc, &disasmInfo);
        if (insnSize < 0 || data->result == -1)
            break;

		data->pc += insnSize;
		disasmInfo.fprintf_func(disasmInfo.stream, "\n");
	}

	disassemble_free_target(&disasmInfo);
    // bfd_close(data->abfd);
	data->abfd = NULL;

	return buf[0];
}

static void convInstrAtAddr(bfd_vma vma, struct disassemble_info *inf)
{
	uint8_t operandOff = 0;
	uint8_t operandSize = 0;
	uint32_t symOffset;
	DisasmData *data = (DisasmData *)inf->application_data;
	GElf_Sym sym = getTargetSymbolForInstruction(vma, data, &operandOff, &operandSize,
												 &symOffset);

	if (invalidSym(sym))
		return;

	if (operandSize < 4)
		return;

	uint32_t *operand = (uint32_t *)(data->symData + data->pc + operandOff);
	if (*operand == 0) // check if it's already a placeholder for relocation
		return;

	*operand = 0;

	GElf_Shdr shdr;
	GElf_Rela rela;
	Elf_Scn *scn = getRelForSectionIndex(data->ctx->elf, data->sym.st_shndx);
	Elf_Data *outData = elf_getdata(scn, NULL);
	if (outData == NULL)
		goto err;

	if (gelf_getshdr(scn, &shdr) == NULL)
		goto err;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	shdr.sh_size += shdr.sh_entsize;
	outData->d_buf = REALLOC_ELF_DBUF(outData->d_buf, outData->d_size, shdr.sh_entsize);
	outData->d_size += shdr.sh_entsize;

	uint32_t symIndex = getSymbolIndex(data->ctx->elf, &sym);
	if (symIndex == 0)
		goto err;

	rela.r_info = ELF64_R_INFO(symIndex, ELF64_R_TYPE(R_X86_64_PC32));
	rela.r_addend = (Elf64_Sxword) symOffset - 4;
	rela.r_offset = data->sym.st_value + data->pc + operandOff;
	if (gelf_update_rela(outData, cnt, &rela) == 0)
		goto err;

	if (gelf_update_shdr(scn, &shdr) == 0)
	{
		LOG_ERR("gelf_update_shdr failed");
		goto err;
	}

	const char *name = elf_strptr(data->ctx->elf, data->shdr.sh_link, sym.st_name);
	if (name == NULL)
		goto err;

	if (strlen(name))
		LOG_DEBUG("Convert to relocation at 0x%zx (%s)", data->pc + operandOff, name);

	return;

err:
	data->result = -1;
}

// convert jump address to other functions to relocations
int convertToRelocations(DisasmData *data)
{
	data->abfd = initBfd(data->ctx->filePath);
	if (data->abfd == NULL)
		return -1;

	disassemble_info disasmInfo = { 0 };
#ifdef DISASSEMBLY_STYLE_SUPPORT
	disassembler_ftype disasm = initDisassembler(data, NULL, nullDisasmPrintf,
				   								 &disasmInfo, convInstrAtAddr,
												 nullFprintfStyled);
#else
	disassembler_ftype disasm = initDisassembler(data, NULL, nullDisasmPrintf,
				   								 &disasmInfo, convInstrAtAddr);
#endif /* DISASSEMBLY_STYLE_SUPPORT */

	if (disasm == NULL)
	{
		disassemble_free_target(&disasmInfo);
		bfd_close(data->abfd);
		data->abfd = NULL;
		LOG_ERR("Could not get disassembler");
		return -1;
	}

	data->result = 0;
	data->pc = 0;
	while (data->pc < data->sym.st_size)
	{
        int insnSize = disasm(data->pc, &disasmInfo);
        if (insnSize < 0 || data->result == -1)
            break;

		data->pc += insnSize;
	}

	disassemble_free_target(&disasmInfo);
    bfd_close(data->abfd);
	data->abfd = NULL;

	return 0;
}

/*
 * @return 0 on success, otherwise non-zero
 */
int applyStaticKeys(Elf *elf, const GElf_Sym *sym, uint8_t *bytes)
{
	GElf_Shdr shdr;
	GElf_Rela rela;
	GElf_Rela jmpRela;
	Elf_Scn *scn = getSectionByName(elf, ".rela__jump_table");

	if (isAARCH64(elf))
		return 0;

	if (!scn)
		return 0;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	size_t cnt = shdr.sh_size / shdr.sh_entsize;
	for (size_t i = 0; i < cnt; i++)
	{
		if (gelf_getrela(data, i, &rela) == NULL)
			return -1;

		GElf_Sym rsym = getSymbolByIndex(elf, ELF64_R_SYM(rela.r_info));
		if (invalidSym(rsym))
			return -1;

		if (rsym.st_shndx != sym->st_shndx)
			continue;

		if (rela.r_offset % 16 != 0)
			continue;

		if (rela.r_addend < (Elf64_Sxword) sym->st_value || rela.r_addend > (Elf64_Sxword) (sym->st_value + sym->st_size))
			continue;

		if (gelf_getrela(data, i + 1, &jmpRela) == NULL)
			return -1;

		uint8_t nop2[] = {0x66, 0x90};
		uint8_t nop4[] = {0x0f, 0x1f, 0x40, 0x00};
		uint8_t nop5[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
		uint8_t nopAARCH64[] = {0x1f, 0x20, 0x3, 0xd5};

		if (memcmp(bytes + rela.r_addend, &nop2, sizeof(nop2)) == 0) // 2-bytes nop
		{
			bytes[rela.r_addend] = 0xEB;
			*(uint8_t *)(bytes + rela.r_addend + 1) = jmpRela.r_addend - rela.r_addend - 2;
		}
		else if (memcmp(bytes + rela.r_addend, &nop4, sizeof(nop4)) == 0) // 4-bytes nop
		{
			// TODO: Validate this case
			bytes[rela.r_addend] = 0xEA;
			*(uint16_t *)(bytes + rela.r_addend + 1) = jmpRela.r_addend - rela.r_addend - 3;
		}
		else if (memcmp(bytes + rela.r_addend, &nop5, sizeof(nop5)) == 0) // 5-bytes nop
		{
			bytes[rela.r_addend] = 0xE9;
			*(uint32_t *)(bytes + rela.r_addend + 1) = jmpRela.r_addend - rela.r_addend - 5;
		}
		else if (memcmp(bytes + rela.r_addend, &nopAARCH64, sizeof(nopAARCH64)) == 0)
		{
			// TODO: AARCH64
			*(uint32_t *)(bytes + rela.r_addend + 1) = jmpRela.r_addend - rela.r_addend - 4;
		}
		else if (bytes[rela.r_addend] != 0xEB && bytes[rela.r_addend] != 0xEA &&
				 bytes[rela.r_addend] != 0xE9)
		{
			const char *name = elf_strptr(elf, shdr.sh_link, sym->st_name);
			LOG_ERR("Unrecognized static_key at index %zu for %s [%zu] "
					"(0x%x 0x%x 0x%x 0x%x)", i, name, sym->st_value,
					bytes[rela.r_addend], bytes[rela.r_addend + 1],
					bytes[rela.r_addend + 2], bytes[rela.r_addend + 3]);

			return -1;
		}
	}

	return 0;
}
