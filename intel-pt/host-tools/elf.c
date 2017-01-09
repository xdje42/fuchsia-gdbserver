/*
 * Copyright (c) 2015, Intel Corporation
 * Author: Andi Kleen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <intel-pt.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "symtab.h"
#include "elf.h"

void read_symtab(Elf *elf, uint64_t cr3, uint64_t base, uint64_t offset, char *fn)
{
	Elf_Scn *section = NULL;

	while ((section = elf_nextscn(elf, section)) != 0) {
		GElf_Shdr shdr, *sh;
		sh = gelf_getshdr(section, &shdr);

		if (sh->sh_type == SHT_SYMTAB || sh->sh_type == SHT_DYNSYM) {
			Elf_Data *data = elf_getdata(section, NULL);
			GElf_Sym *sym, symbol;
			int j;

			unsigned numsym = sh->sh_size / sh->sh_entsize;
			// XXX search for debug info
			struct symtab *st = add_symtab(numsym, cr3, base, fn);
			struct sym *s;
			st->end = 0;
			for (j = 0; j < numsym; j++) {
				sym = gelf_getsymshndx(data, NULL, j, &symbol, NULL);
				s = &st->syms[j];
				s->name = strdup(elf_strptr(elf, shdr.sh_link, sym->st_name));
				s->val = sym->st_value + offset;
				s->size = sym->st_size;
				if (st->end < s->val + s->size)
					st->end = s->val + s->size;
			}
			sort_symtab(st);
		}
	}
}

static void find_base_len_fileoff(Elf *elf, uint64_t *base, uint64_t* len,
				  uint64_t* fileoff)
{
	size_t numphdr;
	int i;

	elf_getphdrnum(elf, &numphdr);
	for (i = 0; i < numphdr; i++) {
		GElf_Phdr phdr;
		gelf_getphdr(elf, i, &phdr);
		if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X) != 0) {
			/* The first loadable section in magenta.elf is
			   unusable to us. Plus we want to ignore it here.
			   This test is an attempt to not be too magenta
			   specific. */
			if (phdr.p_vaddr < phdr.p_paddr)
				continue;
			*base = phdr.p_vaddr;
			*len = phdr.p_memsz;
			*fileoff = phdr.p_offset;
			return;
		}
	}
}

static void find_offset(Elf *elf, uint64_t base, uint64_t *offset)
{
	size_t numphdr;
	uint64_t minaddr = UINT64_MAX;
	int i;

	if (!base) {
		*offset = 0;
		return;
	}

	elf_getphdrnum(elf, &numphdr);
	for (i = 0; i < numphdr; i++) {
		GElf_Phdr phdr;
		gelf_getphdr(elf, i, &phdr);
		if (phdr.p_type == PT_LOAD && phdr.p_vaddr < minaddr) {
			/* The first loadable section in magenta.elf is
			   unusable to us. Plus we want to ignore it here.
			   This test is an attempt to not be too magenta
			   specific. */
			if (phdr.p_vaddr < phdr.p_paddr)
				continue;
			minaddr = phdr.p_vaddr;
		}
	}
	*offset = base - minaddr;
}

void add_progbits(Elf *elf, struct pt_image *image, char *fn, uint64_t base,
		 uint64_t cr3, uint64_t offset, uint64_t file_off, uint64_t map_len)
{
	size_t numphdr;
	int i;

	elf_getphdrnum(elf, &numphdr);
	for (i = 0; i < numphdr; i++) {
		GElf_Phdr phdr;
		gelf_getphdr(elf, i, &phdr);

		if ((phdr.p_type == PT_LOAD) && (phdr.p_flags & PF_X) &&
			phdr.p_offset >= file_off &&
			(!map_len || phdr.p_offset + phdr.p_filesz <= file_off + map_len)) {
			struct pt_asid asid;
			int err;

			/* The first loadable section in magenta.elf is
			   unusable to us. Plus we want to ignore it here.
			   This test is an attempt to not be too magenta
			   specific. */
			if (phdr.p_vaddr < phdr.p_paddr)
				continue;

			pt_asid_init(&asid);
			asid.cr3 = cr3;
			errno = 0;

			err = pt_image_add_file(image, fn, phdr.p_offset,
						phdr.p_filesz,
					       &asid, phdr.p_vaddr + offset);
			/* Duplicate. Just ignore. */
			if (err == -pte_bad_image)
				continue;
			if (err < 0) {
				fprintf(stderr, "reading prog code at %lx:%lx from %s: %s (%s): %d\n",
						phdr.p_vaddr,
						phdr.p_filesz,
						fn, pt_errstr(pt_errcode(err)),
						errno ? strerror(errno) : "",
						err);
				return;
			}
		}
	}
}

static Elf *elf_open(char *fn, int *fd)
{
	*fd = open(fn, O_RDONLY);
	if (*fd < 0) {
		perror(fn);
		return NULL;
	}
	Elf *elf = elf_begin(*fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin failed for %s: %s\n",
				fn, elf_errmsg(-1));
		close(*fd);
	}
	return elf;
}

static void elf_close(Elf *elf, int fd)
{
	elf_end(elf);
	close(fd);
}

int read_elf(char *fn, struct pt_image *image, uint64_t base, uint64_t cr3,
	     uint64_t file_off, uint64_t map_len)
{
	elf_version(EV_CURRENT);

	/* XXX add cache to read each file only once */

	char *p = strchr(fn, ':');
	if (p) {
		*p = 0;
		p++;
	} else
		p = fn;

	int fd;
	Elf *elf = elf_open(fn, &fd);
	if (elf == NULL)
		return -1;
	bool pic = false;
	GElf_Ehdr header;
	if (gelf_getehdr(elf, &header))
		pic = header.e_type == ET_DYN;
	if (pic && base == 0) {
		elf_close(elf, fd);
		return -1;
	}
	uint64_t offset = 0;
	if (pic)
		find_offset(elf, base, &offset);
	read_symtab(elf, cr3, base, offset, fn);
	if (p) {
		elf_close(elf, fd);
		elf = elf_open(p, &fd);
		if (!elf)
			return -1;
	}
	add_progbits(elf, image, p, base, cr3, offset, file_off, map_len);
	elf_close(elf, fd);
	return 0;
}

// TODO(dje): cr3 should be an argument, but this is all wip wip wip

int read_static_elf(char *fn, struct pt_image *image)
{
	elf_version(EV_CURRENT);

	/* XXX add cache to read each file only once */

	char *p = strchr(fn, ':');
	if (p) {
		*p = 0;
		p++;
	} else
		p = fn;

	int fd;
	Elf *elf = elf_open(fn, &fd);
	if (elf == NULL)
		return -1;

	/* TODO(dje): I'm seeing kernel pc values in traces
	   with userspace cr3 values. Not sure if this is
	   normal or a bad trace. For now, ignore cr3 for
	   kernel pcs. The original value of zero was odd
	   anyway. */
	uint64_t base = 0, len = 0;
	uint64_t offset = 0, file_off = 0;
	find_base_len_fileoff(elf, &base, &len, &file_off);
	read_symtab(elf, pt_asid_no_cr3, base, offset, fn);

	if (p) {
		elf_close(elf, fd);
		elf = elf_open(p, &fd);
		if (!elf)
			return -1;
	}
	add_progbits(elf, image, p, base, pt_asid_no_cr3, offset, file_off, len);

	elf_close(elf, fd);
	return 0;
}
