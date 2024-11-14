// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * This file contains functions to remove section from object file.
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libelfutils.h"

int removeSection(const char *filePath, const char *sectionName)
{
	int fd;
	Elf *elf;
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	size_t shstrndx;
	const Elf_Scn *target_scn = NULL;
	size_t target_idx = 0;
	size_t idx = 0;

	// Open the file
	if ((fd = open(filePath, O_RDWR)) < 0) {
		LOG_ERR("Could not open file: %s\n", filePath);
		return 1;
	}

	// Initialize ELF version
	if (elf_version(EV_CURRENT) == EV_NONE) {
		LOG_ERR("ELF library initialization failed");
		close(fd);
		return 1;
	}

	// Get the ELF descriptor
	if ((elf = elf_begin(fd, ELF_C_RDWR, NULL)) == NULL) {
		LOG_ERR("elf_begin() failed");
		close(fd);
		return 1;
	}

	// Get the section header string table index
	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		LOG_ERR("elf_getshdrstrndx() failed");
		elf_end(elf);
		close(fd);
		return 1;
	}

	// Get ELF header
	GElf_Ehdr ehdr;
	if (gelf_getehdr(elf, &ehdr) == NULL) {
		LOG_ERR("gelf_getehdr() failed");
		elf_end(elf);
		close(fd);
		return 1;
	}

	// First pass: find the section to remove
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		idx++;
		if (gelf_getshdr(scn, &shdr) == NULL) {
			LOG_ERR("gelf_getshdr() failed");
			continue;
		}

		const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (name == NULL) {
			LOG_ERR("elf_strptr() failed");
			continue;
		}

		if (strcmp(name, sectionName) == 0) {
			target_scn = scn;
			target_idx = idx;
			break;
		}
	}

	if (!target_scn) {
		LOG_ERR("Section '%s' not found\n", sectionName);
		elf_end(elf);
		close(fd);
		return 1;
	}

	// Create a new ELF file
	int tmp_fd;
	char tmp_filename[256];
	snprintf(tmp_filename, sizeof(tmp_filename), "%s.tmp", filePath);

	if ((tmp_fd = open(tmp_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
		LOG_ERR("Could not create temporary file\n");
		elf_end(elf);
		close(fd);
		return 1;
	}

	Elf *new_elf = elf_begin(tmp_fd, ELF_C_WRITE, NULL);
	if (new_elf == NULL) {
		LOG_ERR("elf_begin() failed for new file");
		close(tmp_fd);
		elf_end(elf);
		close(fd);
		return 1;
	}

	// Create new ELF header
	size_t class = gelf_getclass(elf);
	if (gelf_newehdr(new_elf, class) == 0) {
		LOG_ERR("gelf_newehdr() failed");
		elf_end(new_elf);
		close(tmp_fd);
		elf_end(elf);
		close(fd);
		return 1;
	}

	// Copy and update ELF header
	ehdr.e_shnum--;  // Decrease section count
	if (ehdr.e_shstrndx > target_idx) {
		ehdr.e_shstrndx--;
	}
	if (gelf_update_ehdr(new_elf, &ehdr) == 0) {
		LOG_ERR("gelf_update_ehdr() failed");
		elf_end(new_elf);
		close(tmp_fd);
		elf_end(elf);
		close(fd);
		return 1;
	}

	// Copy program headers if any
	if (ehdr.e_phnum > 0) {
		if (gelf_newphdr(new_elf, ehdr.e_phnum) == 0) {
			LOG_ERR("gelf_newphdr() failed");
		} else {
			for (size_t i = 0; i < ehdr.e_phnum; i++) {
				GElf_Phdr phdr;
				if (gelf_getphdr(elf, i, &phdr) != NULL) {
					if (gelf_update_phdr(new_elf, i, &phdr) == 0) {
						LOG_ERR("gelf_update_phdr() failed");
					}
				}
			}
		}
	}

	// Copy all sections except the one to remove
	scn = NULL;
	idx = 0;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		idx++;
		if (idx == target_idx) {
			continue;  // Skip the section we want to remove
		}

		if (gelf_getshdr(scn, &shdr) == NULL) {
			continue;
		}

		// Create new section
		Elf_Scn *new_scn = elf_newscn(new_elf);
		if (new_scn == NULL) {
			LOG_ERR("elf_newscn() failed");
			continue;
		}

		// Adjust section header fields
		if (idx > target_idx) {
			if (shdr.sh_link > target_idx) {
				shdr.sh_link--;
			}
			if (shdr.sh_info > target_idx && shdr.sh_type != SHT_REL && shdr.sh_type != SHT_RELA) {
				shdr.sh_info--;
			}
		}

		// Copy section data
		Elf_Data *data = NULL;
		while ((data = elf_getdata(scn, data)) != NULL) {
			Elf_Data *new_data = elf_newdata(new_scn);
			if (new_data == NULL) {
				LOG_ERR("elf_newdata() failed");
				continue;
			}

			// Deep copy of section data
			new_data->d_buf = malloc(data->d_size);
			if (new_data->d_buf == NULL) {
				LOG_ERR("malloc failed");
				continue;
			}
			memcpy(new_data->d_buf, data->d_buf, data->d_size);
			new_data->d_type = data->d_type;
			new_data->d_size = data->d_size;
			new_data->d_off = data->d_off;
			new_data->d_align = data->d_align;
			new_data->d_version = data->d_version;
		}

		// Copy section header
		if (gelf_update_shdr(new_scn, &shdr) == 0) {
			LOG_ERR("gelf_update_shdr() failed");
			continue;
		}
	}

	// Write the new file
	if (elf_update(new_elf, ELF_C_WRITE) < 0) {
		LOG_ERR("elf_update() failed");
		elf_end(new_elf);
		close(tmp_fd);
		elf_end(elf);
		close(fd);
		unlink(tmp_filename);
		return 1;
	}

	// Clean up
	elf_end(new_elf);
	close(tmp_fd);
	elf_end(elf);
	close(fd);

	// Replace original file with new file
	if (rename(tmp_filename, filePath) != 0) {
		LOG_ERR("Failed to replace original file\n");
		unlink(tmp_filename);
		return 1;
	}

	LOG_DEBUG("Section '%s' removed successfully\n", sectionName);
	return 0;
}
