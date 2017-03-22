// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Portions of this file are derived from "simplept".
 *
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

#include "decoder.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <intel-pt.h>

#include "lib/ftl/logging.h"

#include "debugger-utils/elf-reader.h"
#include "debugger-utils/memory-file.h"
#include "debugger-utils/util.h"

namespace intel_processor_trace {

using namespace debugserver;

// TODO(dje): For now this is focused on text symbols.
// We assign the full range of the text segment to the symtab so that
// even if a symbol isn't found, we still know the pc came from this file.
// Other segments technically needn't be contiguous, which one would have to
// deal with to handle more than just the (assumed) one text segment.

void DecoderState::ReadSymtab(elf::Reader* elf, uint64_t cr3,
                              uint64_t base, uint64_t len, uint64_t offset,
                              const char* file_name, bool is_kernel)
{
  size_t num_sections = elf->GetNumSections();

  elf::Error rc = elf->ReadSectionHeaders();
  if (rc != elf::Error::OK) {
    FTL_LOG(ERROR) << "Error reading ELF section headers: "
                   << elf::ErrorName(rc);
    return;
  }

  for (size_t i = 0; i < num_sections; ++i) {
    const elf::SectionHeader& shdr = elf->GetSectionHeader(i);
    if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
      continue;

    size_t string_section = shdr.sh_link;
    if (string_section >= num_sections) {
      FTL_LOG(ERROR) << "Bad string section: " << string_section;
      continue;
    }
    const elf::SectionHeader& str_shdr = elf->GetSectionHeader(string_section);

    std::unique_ptr<elf::SectionContents> contents;
    rc = elf->GetSectionContents(shdr, &contents);
    if (rc != elf::Error::OK) {
      FTL_LOG(ERROR) << "Error reading ELF section: "
                     << elf::ErrorName(rc);
      continue;
    }

    std::unique_ptr<elf::SectionContents> string_contents;
    rc = elf->GetSectionContents(str_shdr, &string_contents);
    if (rc != elf::Error::OK) {
      FTL_LOG(ERROR) << "Error reading ELF string section: "
                     << elf::ErrorName(rc);
      continue;
    }
    auto strings = reinterpret_cast<const char*>(string_contents->contents());
    size_t max_string_offset = string_contents->GetSize();

    size_t num_symbols = contents->GetNumEntries(); //shdr.sh_size / shdr.sh_entsize;
    Symtab* st = AddSymtab(num_symbols, cr3, base, file_name, is_kernel);
    for (size_t j = 0; j < num_symbols; j++) {
      const elf::Symbol& sym = contents->GetSymbolEntry(j);
      Sym* s = &st->syms[j];
      if (sym.st_name >= max_string_offset) {
        FTL_LOG(ERROR) << "Bad symbol string name offset: " << sym.st_name;
        continue;
      }
      // TODO(dje): IWBN to have a convenience function for getting symbol
      // names, not sure what it will look like yet.
      s->name = util::xstrdup(strings + sym.st_name);
      s->addr = sym.st_value + offset;
      s->size = sym.st_size;
      if (st->end < s->addr + s->size)
        st->end = s->addr + s->size;
    }
    if (offset + len > st->end)
      st->end = offset + len;
    st->Sort();
  }
}

static void FindBaseLenFileoff(elf::Reader* elf, uint64_t* base,
                               uint64_t* len, uint64_t* fileoff)
{
  size_t num_segments = elf->GetNumSegments();
  for (size_t i = 0; i < num_segments; ++i) {
    const elf::SegmentHeader& phdr = elf->GetSegmentHeader(i);
    if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X) != 0) {
      /* The first loadable section in magenta.elf is
         unusable to us. Plus we want to ignore it here.
         This test is an attempt to not be too magenta specific. */
      if (phdr.p_vaddr < phdr.p_paddr)
        continue;
      *base = phdr.p_vaddr;
      *len = phdr.p_memsz;
      *fileoff = phdr.p_offset;
      return;
    }
  }
}

static void FindOffset(elf::Reader* elf, uint64_t base, uint64_t* offset)
{
  uint64_t minaddr = UINT64_MAX;

  if (!base) {
    *offset = 0;
    return;
  }

  size_t num_segments = elf->GetNumSegments();
  for (size_t i = 0; i < num_segments; ++i) {
    const elf::SegmentHeader& phdr = elf->GetSegmentHeader(i);
    if (phdr.p_type == PT_LOAD && phdr.p_vaddr < minaddr) {
      /* The first loadable section in magenta.elf is
         unusable to us. Plus we want to ignore it here.
         This test is an attempt to not be too magenta specific. */
      if (phdr.p_vaddr < phdr.p_paddr)
        continue;
      minaddr = phdr.p_vaddr;
    }
  }

  *offset = base - minaddr;
}

static void AddProgbits(elf::Reader* elf, struct pt_image* image,
                        const char* file_name, uint64_t base, uint64_t cr3,
                        uint64_t offset, uint64_t file_off, uint64_t map_len)
{
  size_t num_segments = elf->GetNumSegments();
  for (size_t i = 0; i < num_segments; ++i) {
    const elf::SegmentHeader& phdr = elf->GetSegmentHeader(i);

    if ((phdr.p_type == PT_LOAD) && (phdr.p_flags & PF_X) &&
        phdr.p_offset >= file_off &&
        (!map_len || phdr.p_offset + phdr.p_filesz <= file_off + map_len)) {
      struct pt_asid asid;
      int err;

      /* The first loadable section in magenta.elf is
         unusable to us. Plus we want to ignore it here.
         This test is an attempt to not be too magenta specific. */
      if (phdr.p_vaddr < phdr.p_paddr)
        continue;

      pt_asid_init(&asid);
      asid.cr3 = cr3;
      errno = 0;

      err = pt_image_add_file(image, file_name, phdr.p_offset,
                              phdr.p_filesz,
                              &asid, phdr.p_vaddr + offset);
      /* Duplicate. Just ignore. */
      if (err == -pte_bad_image)
        continue;
      if (err < 0) {
        fprintf(stderr, "reading prog code at %lx:%lx from %s: %s (%s): %d\n",
                phdr.p_vaddr,
                phdr.p_filesz,
                file_name, pt_errstr(pt_errcode(err)),
                errno ? strerror(errno) : "",
                err);
        return;
      }
    }
  }
}

static bool ElfOpen(const char* file_name,
                    std::unique_ptr<util::FileMemory>* out_memory,
                    std::unique_ptr<elf::Reader>* out_elf)
{
  int fd = open(file_name, O_RDONLY);
  if (fd < 0) {
    util::LogErrorWithErrno(file_name);
    return false;
  }

  auto memory = std::unique_ptr<util::FileMemory>(new util::FileMemory(fd));

  std::unique_ptr<elf::Reader> elf;
  elf::Error rc = elf::Reader::Create(*memory, 0, 0, &elf);
  if (rc != elf::Error::OK) {
    FTL_LOG(ERROR) << "Error creating ELF reader: "
                   << elf::ErrorName(rc);
    return false;
  }

  rc = elf->ReadSegmentHeaders();
  if (rc != elf::Error::OK) {
    FTL_LOG(ERROR) << "Error reading ELF segment headers: "
                   << elf::ErrorName(rc);
    return false;
  }

  *out_memory = std::move(memory);
  *out_elf = std::move(elf);
  return true;
}

bool DecoderState::ReadElf1(const char* file_name, struct pt_image* image,
                            uint64_t base, uint64_t cr3,
                            uint64_t file_off, uint64_t map_len)
{
  std::unique_ptr<util::FileMemory> memory;
  std::unique_ptr<elf::Reader> elf;
  if (!ElfOpen(file_name, &memory, &elf))
    return false;

  bool pic = false;
  const elf::Header& hdr = elf->header();
  pic = hdr.e_type == ET_DYN;
  if (pic && base == 0) {
    FTL_LOG(ERROR) << "PIC/PIE ELF with base 0 is not supported";
    return false;
  }

  uint64_t offset = 0;
  if (pic)
    FindOffset(elf.get(), base, &offset);

  ReadSymtab(elf.get(), cr3, base, map_len, offset, file_name, false);

  AddProgbits(elf.get(), image, file_name, base, cr3, offset, file_off,
              map_len);

  return true;
}

bool DecoderState::ReadStaticElf(const char* file_name, pt_image* image,
                                 uint64_t cr3, bool is_kernel)
{
  std::unique_ptr<util::FileMemory> memory;
  std::unique_ptr<elf::Reader> elf;
  if (!ElfOpen(file_name, &memory, &elf))
    return false;

  /* TODO(dje): kernel pc values can appear in traces with userspace cr3
     values, e.g., when performing a syscall. For now, ignore cr3 for
     kernel pcs. The original value of zero was odd anyway. */
  uint64_t base = 0, len = 0;
  uint64_t offset = 0, file_off = 0;
  FindBaseLenFileoff(elf.get(), &base, &len, &file_off);

  ReadSymtab(elf.get(), pt_asid_no_cr3, base, len, offset, file_name,
             is_kernel);

  AddProgbits(elf.get(), image, file_name, base, cr3 ? cr3 : pt_asid_no_cr3,
              offset, file_off, len);

  return true;
}

bool DecoderState::ReadElf(const std::string& file_name, uint64_t base,
                              uint64_t cr3, uint64_t file_off,
                              uint64_t map_len)
{
  FTL_DCHECK(image_);

  return ReadElf1(file_name.c_str(), image_, base, cr3, file_off, map_len);
}

bool DecoderState::ReadKernelElf(const std::string& file_name, uint64_t cr3)
{
  FTL_DCHECK(image_);

  return ReadStaticElf(file_name.c_str(), image_, cr3, true);
}

} // intel_processor_trace
