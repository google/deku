/*
 * Copyright (c) 2024 Google LLC
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

/*
 * Convert kernel module to livepatch module
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>

#define SHF_RELA_LIVEPATCH	0x00100000
#define SHN_LIVEPATCH	0xff20

#define MODULE_NAME_LEN (64 - sizeof(unsigned long))
#define KSYM_NAME_LEN 512

typedef struct {
	char objFile[MODULE_NAME_LEN];
	char relSym[KSYM_NAME_LEN];
	int symIndex;
	int pos;
} Symbol;

Symbol *parse_arguments(int argc, const char *argv[], int *sym_to_reloc_count) {
	if (sym_to_reloc_count == NULL)
		return NULL;

	*sym_to_reloc_count = 0;
	Symbol *syms = calloc(argc - 1, sizeof(Symbol));
	if (syms == NULL) {
		fprintf(stderr, "Failed to allocate memory for arguments\n");
		return NULL;
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
			Symbol *sym = &syms[*sym_to_reloc_count];
			if (sscanf(argv[++i], "%[^.].%[^@]@%d,%d", sym->objFile, sym->relSym, &sym->symIndex, &sym->pos) == 4) {
				(*sym_to_reloc_count)++;
			} else {
				fprintf(stderr, "Invalid argument format: %s\n", argv[i]);
				free(syms);
				return NULL;
			}
		}
	}

	return syms;
}

bool symbol_exists(Elf *elf, const char *symbol_name) {
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	Elf_Data *data;
	GElf_Sym sym;
	int symbol_count;
	const char *name;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		gelf_getshdr(scn, &shdr);
		if (shdr.sh_type == SHT_SYMTAB) {
			data = elf_getdata(scn, NULL);
			symbol_count = shdr.sh_size / shdr.sh_entsize;

			for (int i = 0; i < symbol_count; i++) {
				gelf_getsym(data, i, &sym);
				name = elf_strptr(elf, shdr.sh_link, sym.st_name);
				if (name && strcmp(name, symbol_name) == 0) {
					return true;
				}
			}
		}
	}

	return false;
}

Elf_Scn *get_section_by_name(Elf *elf, const char *name)
{
	Elf_Scn *scn = NULL;
	size_t shdrstrndx;
	if (elf_getshdrstrndx(elf, &shdrstrndx) != 0) {
		fprintf(stderr, "Error: Failed to get section header string table index: %s\n", elf_errmsg(-1));
		return NULL;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr;
		gelf_getshdr(scn, &shdr);

		const char *sec_name = elf_strptr(elf, shdrstrndx, shdr.sh_name);
		if (strcmp(sec_name, name) == 0)
			return scn;
	}

	return NULL;
}

Elf_Scn *create_klp_rel_section(Elf *elf, const char *name, Elf64_Word link, Elf64_Word info) {
	Elf_Scn *shstrtab_scn = NULL;
	GElf_Shdr shstrtab_shdr;
	Elf_Data *shstrtab_data = NULL;

	// Find the section header string table
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		fprintf(stderr, "Error: Failed to get section header string table index: %s\n", elf_errmsg(-1));
		return NULL;
	}

	shstrtab_scn = elf_getscn(elf, shstrndx);
	if (shstrtab_scn == NULL) {
		fprintf(stderr, "Failed to get section header string table section: %s\n", elf_errmsg(-1));
		return NULL;
	}

	if (gelf_getshdr(shstrtab_scn, &shstrtab_shdr) == NULL) {
		fprintf(stderr, "gelf_getshdr() failed: %s\n", elf_errmsg(-1));
		return NULL;
	}

	shstrtab_data = elf_getdata(shstrtab_scn, NULL);
	if (shstrtab_data == NULL) {
		fprintf(stderr, "elf_getdata() failed: %s\n", elf_errmsg(-1));
		return NULL;
	}

	size_t name_offset = shstrtab_data->d_size;
	char *new_shstrtab = malloc(name_offset + strlen(name) + 1);
	if (new_shstrtab == NULL) {
		fprintf(stderr, "Failed to reallocate section header string table\n");
		return NULL;
	}

	memcpy(new_shstrtab, shstrtab_data->d_buf, shstrtab_data->d_size);
	strcpy(new_shstrtab + name_offset, name);
	shstrtab_data->d_buf = new_shstrtab;
	shstrtab_data->d_size += strlen(name) + 1;

	Elf_Scn *scn = elf_newscn(elf);
	if (scn == NULL) {
		fprintf(stderr, "elf_newscn() failed: %s\n", elf_errmsg(-1));
		return NULL;
	}

	GElf_Shdr rel_shdr;
	gelf_getshdr(scn, &rel_shdr);
	rel_shdr.sh_name = name_offset;
	rel_shdr.sh_type = SHT_RELA;
	rel_shdr.sh_flags = SHF_ALLOC | SHF_INFO_LINK | SHF_RELA_LIVEPATCH;
	rel_shdr.sh_addralign = 8;
	rel_shdr.sh_entsize = sizeof(Elf64_Rela);
	rel_shdr.sh_link = link;
	rel_shdr.sh_info = info;
	gelf_update_shdr(scn, &rel_shdr);

	const Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		fprintf(stderr, "elf_newdata() failed: %s\n", elf_errmsg(-1));
		return NULL;
	}

	// Update the section header string table section header
	shstrtab_shdr.sh_size = shstrtab_data->d_size;
	if (gelf_update_shdr(shstrtab_scn, &shstrtab_shdr) == 0) {
		fprintf(stderr, "gelf_update_shdr() failed for shstrtab: %s\n", elf_errmsg(-1));
		return NULL;
	}

	if (elf_update(elf, ELF_C_NULL) < 0) {
		fprintf(stderr, "elf_update() failed: %s\n", elf_errmsg(-1));
	}

	return scn;
}

bool rename_symbols_and_update_relocations(Elf *elf, Symbol *syms, int sym_to_reloc_count) {
	Elf_Scn *symtab_scn = NULL;
	Elf_Data *symtab_data = NULL;
	int symbol_count;
	GElf_Shdr symtab_shdr;
	size_t shdrstrndx;
	GElf_Shdr shdr;
	Elf_Scn *ref_scn;
	GElf_Shdr ref_shdr;

	if (elf_getshdrstrndx(elf, &shdrstrndx) != 0) {
		fprintf(stderr, "Error: Failed to get section header string table index: %s\n", elf_errmsg(-1));
		return false;
	}

	// Find symbol table
	while ((symtab_scn = elf_nextscn(elf, symtab_scn)) != NULL) {
		gelf_getshdr(symtab_scn, &symtab_shdr);
		if (symtab_shdr.sh_type == SHT_SYMTAB) {
			symtab_data = elf_getdata(symtab_scn, NULL);
			symbol_count = symtab_shdr.sh_size / symtab_shdr.sh_entsize;
			break;
		}
	}

	if (!symtab_data) {
		fprintf(stderr, "Symbol table not found\n");
		return false;
	}

	// Move relocations
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		gelf_getshdr(scn, &shdr);
		if (shdr.sh_type != SHT_RELA)
			continue;

		Elf_Data *data = elf_getdata(scn, NULL);
		int relocation_count = shdr.sh_size / shdr.sh_entsize;
		Elf_Data *new_data = NULL;
		ref_scn = elf_getscn(elf, shdr.sh_info);
		gelf_getshdr(ref_scn, &ref_shdr);
		const char *ref_sec_name = elf_strptr(elf, shdrstrndx, ref_shdr.sh_name);
		if (strstr(ref_sec_name, ".deku.patch_") == ref_sec_name)
			continue;

		for (int i = 0; i < relocation_count; i++) {
			GElf_Rela rela;
			gelf_getrela(data, i, &rela);

			GElf_Sym sym;
			gelf_getsym(symtab_data, GELF_R_SYM(rela.r_info), &sym);

			for (int j = 0; j < sym_to_reloc_count; j++) {
				if (syms[j].symIndex != GELF_R_SYM(rela.r_info))
					continue;

				// Move relocation to new section
				char target_section_name[KSYM_NAME_LEN + MODULE_NAME_LEN + 12];
				snprintf(target_section_name, sizeof(target_section_name), ".klp.rela.%s.%s", syms[j].objFile, ref_sec_name);
				Elf_Scn *target_scn = get_section_by_name(elf, target_section_name);
				if (target_scn == NULL) {
					target_scn = create_klp_rel_section(elf, target_section_name, shdr.sh_link, shdr.sh_info);
					if (target_scn == NULL)
						return false;
				}

				new_data = elf_getdata(target_scn, NULL);

				// Add relocation to new section
				size_t new_size = new_data->d_size + sizeof(GElf_Rela);
				void *buf = malloc(new_size);
				if (buf == NULL) {
					fprintf(stderr, "Failed to allocate memory for section data\n");
					return false;
				}

				memcpy(buf, new_data->d_buf, new_data->d_size);
				new_data->d_buf = buf;
				memcpy((char *)new_data->d_buf + new_data->d_size, &rela, sizeof(GElf_Rela));
				new_data->d_size = new_size;

				// Remove relocation from old section
				if (i < relocation_count - 1) {
					memmove((char *)data->d_buf + i * sizeof(GElf_Rela),
							(char *)data->d_buf + (i + 1) * sizeof(GElf_Rela),
							(relocation_count - i - 1) * sizeof(GElf_Rela));
				}

				data->d_size -= sizeof(GElf_Rela);
				relocation_count--;
				i--; // Reprocess this index as it now contains the next relocation

				// Update section headers
				GElf_Shdr new_shdr;
				gelf_getshdr(target_scn, &new_shdr);
				shdr.sh_size = data->d_size;
				new_shdr.sh_size = new_data->d_size;
				gelf_update_shdr(scn, &shdr);
				gelf_update_shdr(target_scn, &new_shdr);
				break;
			}
		}
	}

	// Get string table
	Elf_Scn *strtab_scn = elf_getscn(elf, symtab_shdr.sh_link);
	Elf_Data *strtab_data = elf_getdata(strtab_scn, NULL);
	GElf_Shdr strtab_shdr;
	gelf_getshdr(strtab_scn, &strtab_shdr);

	// Rename symbols
	for (int i = 0; i < symbol_count; i++) {
		GElf_Sym sym;
		gelf_getsym(symtab_data, i, &sym);

		for (int j = 0; j < sym_to_reloc_count; j++) {
			if (syms[j].symIndex != i)
				continue;

			char new_name[KSYM_NAME_LEN + MODULE_NAME_LEN + 12];
			snprintf(new_name, sizeof(new_name), ".klp.sym.%s.%s,%d", syms[j].objFile, syms[j].relSym, syms[j].pos);

			// Add new name to string table
			size_t new_name_offset = strtab_data->d_size;
			char *new_strtab = malloc(new_name_offset + strlen(new_name) + 1);
			if (new_strtab == NULL) {
				fprintf(stderr, "Failed to reallocate string table\n");
				return false;
			}

			memcpy(new_strtab, strtab_data->d_buf, strtab_data->d_size);
			strcpy(new_strtab + new_name_offset, new_name);
			strtab_data->d_buf = new_strtab;
			strtab_data->d_size += strlen(new_name) + 1;

			// Update symbol
			sym.st_name = new_name_offset;
			sym.st_shndx = SHN_LIVEPATCH;
			sym.st_info = ELF64_ST_INFO(STB_GLOBAL, ELF64_ST_TYPE(sym.st_info));
			gelf_update_sym(symtab_data, i, &sym);
			break;
		}
	}

	// Update string table section header
	strtab_shdr.sh_size = strtab_data->d_size;
	gelf_update_shdr(strtab_scn, &strtab_shdr);

	return true;
}

int mklivepatch(int argc, const char *argv[])
{
	int sym_to_reloc_count = 0;
	Symbol *syms = parse_arguments(argc, argv, &sym_to_reloc_count);
	if (syms == NULL) {
		return 1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	int fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	Elf *elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (elf == NULL) {
		fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
		close(fd);
		return 1;
	}

	// Check if all relSym exist in the file
	for (int i = 0; i < sym_to_reloc_count; i++) {
		if (!symbol_exists(elf, syms[i].relSym)) {
			fprintf(stderr, "Symbol %s not found in the file\n", syms[i].relSym);
			elf_end(elf);
			close(fd);
			return 1;
		}
	}

	if (!rename_symbols_and_update_relocations(elf, syms, sym_to_reloc_count)) {
		elf_end(elf);
		close(fd);
		return 1;
	}

	if (elf_update(elf, ELF_C_WRITE) < 0) {
		fprintf(stderr, "elf_update() failed: %s\n", elf_errmsg(-1));
	}

	elf_end(elf);
	close(fd);

	return 0;
}

#ifdef USE_AS_LIB

int _mklivepatch(const char *file, const char *relocations)
{
	int count = 2;
	const char **argv = malloc(sizeof(char *) * count);
	if (argv == NULL) {
		fprintf(stderr, "Failed to allocate memory for arguments\n");
		return 1;
	}

	argv[0] = __func__;
	argv[1] = file;
	while (relocations[0] != '\0')
	{
		char *sep = strchr(relocations, ' ');
		if (sep)
			*sep = '\0';

		argv = realloc(argv, sizeof(char *) * (count + 2));
		if (argv == NULL) {
			fprintf(stderr, "Failed to allocate memory for %d argument\n", count);
			return 1;
		}

		const char *arg = relocations;
		argv[count++] = "-r";
		argv[count++] = arg;

		if (!sep)
			break;

		relocations = sep + 1;
	}

	int ret = mklivepatch(count, argv);
	free(argv);
	return ret;
}

#else
int main(int argc, const char *argv[]) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <elf_file> -r \"objFile.relSym@index,pos\" [...]\n", argv[0]);
		return 1;
	}

	return mklivepatch(argc, argv);
}
#endif /* USE_AS_LIB */
