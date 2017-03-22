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

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include <intel-pt.h>

#include "debugger-utils/util.h"

#include "lib/ftl/logging.h"
#include "lib/ftl/files/directory.h"
#include "lib/ftl/files/path.h"
#include "lib/ftl/strings/string_printf.h"

#define round_up(x, y) (((x) + (y) - 1) & ~((y) - 1))

namespace intel_processor_trace {

using namespace debugserver;

static int pagesize;

static void __attribute__((constructor)) InitPs(void)
{
  pagesize = sysconf(_SC_PAGESIZE);
}

static void* Mapfile(const char* fn, size_t* size)
{
  int fd = open(fn, O_RDWR);
  if (fd < 0)
    return nullptr;
  struct stat st;
  void* map = (void*) -1L;
  if (fstat(fd, &st) >= 0) {
    *size = st.st_size;
    map = mmap(nullptr, round_up(st.st_size, pagesize),
               PROT_READ|PROT_WRITE,
               MAP_PRIVATE, fd, 0);
  }
  close(fd);
  return map != (void*) -1L ? map : nullptr;
}

static void Unmapfile(void* map, size_t size)
{
  munmap(map, round_up(size, pagesize));
}

std::unique_ptr<DecoderState> DecoderState::Create(
    const DecoderConfig& config)
{
  auto decoder = std::unique_ptr<DecoderState>(new DecoderState());

  FTL_DCHECK(config.pt_file_name != "" ||
             config.pt_list_file_name != "");
  FTL_DCHECK(config.cpuid_file_name != "");
  FTL_DCHECK(config.ktrace_file_name != "");

  if (!decoder->AllocImage("ipt-dump"))
    return nullptr;

  // Read sideband data before we read anything else.

  if (!decoder->ReadCpuidFile(config.cpuid_file_name))
    return nullptr;

  if (!decoder->ReadKtraceFile(config.ktrace_file_name))
    return nullptr;

  for (auto f : config.map_file_names) {
    if (!decoder->ReadMapFile(f))
      return nullptr;
  }

  for (auto f : config.ids_file_names) {
    if (!decoder->ReadIdsFile(f))
      return nullptr;
  }

  if (config.pt_file_name != "") {
    decoder->AddPtFile(files::GetCurrentDirectory(), PtFile::kIdUnset,
                       config.pt_file_name);
  } else {
    if (!decoder->ReadPtListFile(config.pt_list_file_name))
      return nullptr;
  }

  for (auto f : config.elf_file_names) {
    // TODO(dje): This isn't useful without base addr, etc.
    if (!decoder->ReadElf(f, 0, 0, 0, 0))
      return nullptr;
  }

  if (config.kernel_file_name != "") {
    decoder->SetKernelCr3(config.kernel_cr3);
    if (!decoder->ReadKernelElf(config.kernel_file_name, config.kernel_cr3))
      return nullptr;
  }

  if (config.use_tsc_time)
    decoder->set_tsc_freq(0);

  return decoder;
}

DecoderState::DecoderState()
    : image_(nullptr),
      decoder_(nullptr),
      tsc_freq_(0),
      kernel_cr3_(0)
{
  pt_config_init(&config_);
}

DecoderState::~DecoderState()
{
  if (config_.begin)
    Unmapfile(config_.begin, config_.end - config_.begin);
  if (decoder_)
    pt_insn_free_decoder(decoder_);
  if (image_)
    pt_image_free(image_);
}

Process::Process(uint64_t p, uint64_t c, uint64_t start, uint64_t end)
    : pid(p), cr3(c), start_time(start), end_time(end)
{
  FTL_VLOG(2) <<
    ftl::StringPrintf("pid %" PRIu64 " cr3 0x%" PRIx64 " start %" PRIu64,
                      pid, cr3, start_time);
}

BuildId::BuildId(const std::string& b, const std::string& f)
    : build_id(b), file(f)
{
  FTL_VLOG(2) << ftl::StringPrintf("build_id %s, file %s",
                                   build_id.c_str(), file.c_str());
}

PtFile::PtFile(uint64_t i, const std::string& f)
    : id(i), file(f)
{
  FTL_VLOG(2) << ftl::StringPrintf("pt_file %" PRIu64 ", file %s",
                                   id, file.c_str());
}

const Process* DecoderState::LookupProcessByPid(uint64_t pid)
{
  for (auto& p : processes_) {
    if (p.pid == pid)
      return &p;
  }

  return nullptr;
}

const Process* DecoderState::LookupProcessByCr3(uint64_t cr3)
{
  for (auto& p : processes_) {
    if (p.cr3 == cr3 ||
        // If tracing just userspace, cr3 values in the trace may be this
        cr3 == pt_asid_no_cr3)
      return &p;
  }

  return nullptr;
}

const MapEntry* DecoderState::LookupMapEntry(uint64_t pid, uint64_t addr)
{
  for (auto& m : maps_) {
    if (pid == m.pid && addr >= m.load_addr && addr < m.end_addr)
      return &m;
  }

  return nullptr;
}

const BuildId* DecoderState::LookupBuildId(const std::string& bid)
{
  for (auto& b : build_ids_) {
    if (bid == b.build_id)
      return &b;
  }

  return nullptr;
}

std::string DecoderState::LookupFile(const std::string& file)
{
  // TODO: This function is here in case we need to do fancier lookup later.
  return file;
}

// static
int DecoderState::ReadMemCallback(uint8_t* buffer, size_t size,
                                  const struct pt_asid* asid,
                                  uint64_t addr, void* context)
{
  auto decoder = reinterpret_cast<DecoderState*>(context);
  uint64_t cr3 = asid->cr3;

  auto proc = decoder->LookupProcessByCr3(cr3);
  if (!proc) {
    FTL_VLOG(1) << ftl::StringPrintf("process lookup failed for cr3:"
                                     " 0x%" PRIx64, cr3);
    decoder->unknown_cr3s_.emplace(cr3);
    return -pte_nomap;
  }

  auto map = decoder->LookupMapEntry(proc->pid, addr);
  if (!map) {
    FTL_VLOG(1) << ftl::StringPrintf("map lookup failed for cr3/addr:"
                                     " 0x%" PRIx64 "/0x%" PRIx64,
                                     cr3, addr);
    return -pte_nomap;
  }

  auto bid = decoder->LookupBuildId(map->build_id);
  if (!bid) {
    FTL_VLOG(1) << ftl::StringPrintf("build_id not found: %s, for cr3/addr:"
                                     " 0x%" PRIx64 "/0x%" PRIx64,
                                     map->build_id.c_str(), cr3, addr);
    return -pte_nomap;
  }

  auto file = decoder->LookupFile(bid->file);
  if (!file.size()) {
    FTL_VLOG(1) << ftl::StringPrintf("file not found: %s, for build_id %s, cr3/addr:"
                                     " 0x%" PRIx64 "/0x%" PRIx64,
                                     bid->file.c_str(), map->build_id.c_str(),
                                     cr3, addr);
    return -pte_nomap;
  }

  if (!decoder->ReadElf(file.c_str(), map->base_addr, cr3,
                      0, map->end_addr - map->load_addr)) {
    FTL_VLOG(1) << "Reading ELF file failed: " << file;
    return -pte_nomap;
  }

  return pt_image_read_for_callback(decoder->image_, buffer, size, asid, addr);
}

bool DecoderState::AllocImage(const std::string& name)
{
  FTL_DCHECK(!image_);

  struct pt_image* image = pt_image_alloc(name.c_str());
  FTL_DCHECK(image);

  pt_image_set_callback(image, ReadMemCallback, this);

  image_ = image;

  return true;
}

bool DecoderState::AddProcess(uint64_t pid, uint64_t cr3,
                              uint64_t start_time)
{
  FTL_VLOG(1)
    << ftl::StringPrintf("New process: %" PRIu64 ", cr3 0x%" PRIx64
                         " @%" PRIu64,
                         pid, cr3, start_time);
  processes_.push_back(Process(pid, cr3, start_time, 0));
  return true;
}

bool DecoderState::MarkProcessExited(uint64_t pid, uint64_t end_time)
{
  FTL_VLOG(1)
    << ftl::StringPrintf("Marking process exit: %" PRIu64 " @%" PRIu64,
                         pid, end_time);

  // We don't remove the process as process start/exit records are read in
  // one pass over the ktrace file. Instead just mark when it exited.
  // We assume process ids won't wrap, which is pretty safe for now.
  for (auto i = processes_.begin(); i != processes_.end(); ++i) {
    if (i->pid == pid) {
      i->end_time = end_time;
      break;
    }
  }

  // If we didn't find an entry that's ok. We might have gotten a process-exit
  // notification for a process that we didn't get a start notification for.
  return true;
}

bool DecoderState::AddMapEntry(const MapEntry& entry)
{
  FTL_VLOG(1)
    << ftl::StringPrintf("Adding map entry, pid %" PRIu64 " %s 0x%" PRIx64 "-0x%" PRIx64,
                         entry.pid, entry.name.c_str(), entry.load_addr, entry.end_addr);
  maps_.push_back(entry);
  return true;
}

void DecoderState::ClearMap()
{
  maps_.clear();
}

void DecoderState::AddBuildId(const std::string& file_dir,
                              const std::string& build_id,
                              const std::string& path)
{
  std::string abs_path;

  // Convert relative paths to absolute ones.
  if (path[0] != '/') {
    std::string abs_file_dir = files::AbsolutePath(file_dir);
    abs_path = abs_file_dir + "/" + path;
  } else {
    abs_path = path;
  }
  build_ids_.push_back(BuildId(build_id, abs_path));
}

void DecoderState::AddPtFile(const std::string& file_dir, uint64_t id,
                             const std::string& path)
{
  std::string abs_path;

  // Convert relative paths to absolute ones.
  if (path[0] != '/') {
    std::string abs_file_dir = files::AbsolutePath(file_dir);
    abs_path = abs_file_dir + "/" + path;
  } else {
    abs_path = path;
  }
  pt_files_.push_back(PtFile(id, abs_path));
}

bool DecoderState::AllocDecoder(const std::string& pt_file_name)
{
  unsigned zero = 0;

  FTL_DCHECK(decoder_ == nullptr);

  pt_cpu_errata(&config_.errata, &config_.cpu);
  /* When no bit is set, set all, as libipt does not keep up with newer
   * CPUs otherwise.
   */
  if (!memcmp(&config_.errata, &zero, 4))
    memset(&config_.errata, 0xff, sizeof(config_.errata));

  size_t len;
  unsigned char* map =
    reinterpret_cast<unsigned char*>(Mapfile(pt_file_name.c_str(), &len));
  if (!map) {
    fprintf(stderr, "Cannot open PT file %s: %s\n", pt_file_name.c_str(),
            strerror(errno));
    exit(1);
  }
  config_.begin = map;
  config_.end = map + len;

  decoder_ = pt_insn_alloc_decoder(&config_);
  if (!decoder_) {
    fprintf(stderr, "Cannot create PT decoder\n");
    Unmapfile(map, len);
    return false;
  }

  pt_insn_set_image(decoder_, image_);

  return true;
}

void DecoderState::FreeDecoder()
{
  FTL_DCHECK(decoder_);
  pt_insn_free_decoder(decoder_);
  decoder_ = nullptr;
}

/* caller must fill in st->end */
Symtab* DecoderState::AddSymtab(unsigned num, unsigned long cr3,
                                unsigned long base, const char* file_name,
                                bool is_kernel)
{
  auto st = reinterpret_cast<Symtab*>(malloc(sizeof(Symtab)));
  if (!st)
    exit(ENOMEM);
  st->num = num;
  st->next = symtabs_;
  symtabs_ = st;
  st->cr3 = cr3;
  st->base = base;
  st->syms = reinterpret_cast<Sym*>(calloc(num, sizeof(Sym)));
  if (!st->syms)
    exit(ENOMEM);
  st->end = 0;
  st->file_name = file_name ? util::xstrdup(file_name) : nullptr;
  st->is_kernel = is_kernel;
  return st;
}

const Symtab* DecoderState::FindSymtab(unsigned long cr3, unsigned long pc)
{
  Symtab* st;

  /* add last hit cache here */

  for (st = symtabs_; st; st = st->next) {
    if (st->cr3 && cr3 &&
        st->cr3 != pt_asid_no_cr3 && cr3 != pt_asid_no_cr3 &&
        cr3 != st->cr3)
      continue;
    if (pc < st->base || pc >= st->end)
      continue;
    return st;
  }

  return nullptr;
}

const Sym* DecoderState::FindSym(unsigned long cr3, unsigned long pc)
{
  const Symtab* symtab = FindSymtab(cr3, pc);
  if (!symtab)
    return nullptr;
  return symtab->FindSym(pc);
}

const char* DecoderState::FindPcFileName(unsigned long cr3,
                                         unsigned long pc)
{
  Symtab* st;
  for (st = symtabs_; st; st = st->next) {
    if (st->cr3 && cr3 &&
        st->cr3 != pt_asid_no_cr3 && cr3 != pt_asid_no_cr3 &&
        cr3 != st->cr3)
      continue;
    if (pc < st->base || pc >= st->end)
      continue;
    return st->file_name;
  }
  return nullptr;
}

bool DecoderState::SeenCr3(unsigned long cr3)
{
  Symtab* st;

  for (st = symtabs_; st; st = st->next) {
    if (st->cr3 == cr3)
      return true;
  }
  return false;
}

static int CmpSym(const void* ap, const void* bp)
{
  auto a = reinterpret_cast<const Sym*>(ap);
  auto b = reinterpret_cast<const Sym*>(bp);
  if (a->addr >= b->addr && a->addr < b->addr + b->size)
    return 0;
  if (b->addr >= a->addr && b->addr < a->addr + a->size)
    return 0;
  return a->addr - b->addr;
}

const Sym* Symtab::FindSym(unsigned long addr) const
{
  Sym search = { .addr = addr };

  /* add last hit cache here */

  auto s = reinterpret_cast<const Sym*>(
    bsearch(&search, syms, num, sizeof(Sym), CmpSym));
  return s;
}

void Symtab::Dump() const
{
  for (unsigned i = 0; i < num; i++) {
    Sym* s = &syms[i];
    if (s->addr && s->name[0])
      printf("%lx %s\n", s->addr, s->name);
  }
}

void Symtab::Sort()
{
  qsort(syms, num, sizeof(Sym), CmpSym);
}

} // intel_processor_trace
