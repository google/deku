// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#define PACKAGE 1	/* required by libbfd */
#include <dis-asm.h>

#include "libelfutils.h"


#if DISASSEMBLY_STYLE_SUPPORT == 0
	#undef DISASSEMBLY_STYLE_SUPPORT
#endif

#define MAX_DISASM_LINE_LEN 512

typedef struct
{
	GElf_Sym sym;
	GElf_Shdr shdr;
	uint8_t *symData;
	void *data;
	Context *ctx;
	bfd *abfd;
	size_t pc;
	int result;
} DisasmData;

disassembler_ftype initDisassembler(DisasmData *data, void *stream,
									fprintf_ftype fprintfFunc,
									disassemble_info *disasmInfo,
				  void (*printAddressFunc) (bfd_vma, struct disassemble_info *)
#ifdef DISASSEMBLY_STYLE_SUPPORT
				   					, fprintf_styled_ftype fprintfStyledFunc
#endif /* DISASSEMBLY_STYLE_SUPPORT */
									);
int nullDisasmPrintf(void *buf, const char *format, ...);
#ifdef DISASSEMBLY_STYLE_SUPPORT
int nullFprintfStyled(void *buf, enum disassembler_style style, const char *format, ...);
#endif /* DISASSEMBLY_STYLE_SUPPORT */
bfd *initBfd(const char *filePath);
GElf_Sym getTargetSymbolForInstruction(bfd_vma vma, DisasmData *data,  uint8_t *offset, uint8_t *size,
									   uint32_t *outSymOffset);
int convertToRelocations(DisasmData *data);
char *disassembleBytes(DisasmData *data);
int applyStaticKeys(Elf *elf, const GElf_Sym *sym, uint8_t *bytes);
