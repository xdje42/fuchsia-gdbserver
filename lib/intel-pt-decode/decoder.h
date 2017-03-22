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

// TODO(dje): wip wip wip

#pragma once

#include <vector>
#include <string>
#include <unordered_set>

// This is the header provided by Intel.
#include <intel-pt.h>

#include "debugger-utils/elf-reader.h"
#include "debugger-utils/ktrace-reader.h"

namespace intel_processor_trace {

// Parameters needed to drive the decoder.

struct DecoderConfig
{
  bool use_tsc_time = false;

  // Path to the kernel ELF file.
  std::string kernel_file_name;

  // IWBN if this came from sideband data.
  uint64_t kernel_cr3 = 0;

  // Path to the raw processor trace dump.
  // This file is produced with the "ipt" program.
  std::string pt_file_name;

  // Path to a text file containing a mapping of "id" values and their
  // corresponding PT dump files.
  // The format of each line is "id /path/to/pt-file".
  // "id" is either a cpu number for cpu-based tracing, or thread id for
  // thread-based tracing; in decimal.
  std::string pt_list_file_name;

  // Path to file containing cpuid info.
  // This file is produced with the "ipt" program.
  std::string cpuid_file_name;

  // Path to needed ktrace data.
  // This file is produced with the "ipt" program.
  std::string ktrace_file_name;

  // Optional additional files passed on the command line.
  std::vector<std::string> elf_file_names;

  // Path to the "ids.txt" files from the build.
  std::vector<std::string> ids_file_names;

  // Path to file containing linker map output.
  std::vector<std::string> map_file_names;
};

struct Process {
  Process(uint64_t p, uint64_t c, uint64_t start, uint64_t end);
  uint64_t pid;
  uint64_t cr3;
  // The time, in units ktrace uses, when the process was live.
  // An end time of zero means "unknown".
  uint64_t start_time, end_time;
};

struct MapEntry {
  uint64_t pid = 0;
  uint64_t base_addr = 0;
  uint64_t load_addr = 0;
  uint64_t end_addr = 0;
  std::string name;
  std::string so_name;
  std::string build_id;
};

struct BuildId {
  BuildId(const std::string& b, const std::string& f);
  std::string build_id;
  std::string file;
};

struct PtFile {
  PtFile(uint64_t i, const std::string& f);

  // The id of the cpu we are processing. Cpus are numbered 0...N.
  static constexpr uint64_t kIdUnset = ~(uint64_t)0;

  uint64_t id;
  std::string file;
};

struct Sym {
  char* name = nullptr;
  unsigned long addr = 0;
  unsigned long size = 0;
};

struct Symtab {
  Symtab* next = nullptr;
  unsigned num = 0;
  Sym* syms = nullptr;
  unsigned long cr3 = 0;
  unsigned long base = 0;
  unsigned long end = 0;
  char* file_name = nullptr;
  bool is_kernel = false;

  const Sym* FindSym(unsigned long addr) const;
  void Dump() const;
  void Sort();
};

class DecoderState {
 public:
  static std::unique_ptr<DecoderState> Create(const DecoderConfig& config);

  ~DecoderState();

  const Process* LookupProcessByPid(uint64_t pid);
  const Process* LookupProcessByCr3(uint64_t cr3);

  const MapEntry* LookupMapEntry(uint64_t pid, uint64_t addr);

  const BuildId* LookupBuildId(const std::string& bid);

  std::string LookupFile(const std::string& file);

  const Symtab* FindSymtab(unsigned long cr3, unsigned long pc);
  const Sym* FindSym(unsigned long cr3, unsigned long pc);
  const char* FindPcFileName(unsigned long cr3, unsigned long pc);

  bool SeenCr3(unsigned long cr3);

  double tsc_freq() const { return tsc_freq_; }
  void set_tsc_freq(double f) { tsc_freq_ = f; }

  uint64_t kernel_cr3() const { return kernel_cr3_; }
  void set_kernel_cr3(uint64_t cr3) { kernel_cr3_ = cr3; }

  const pt_config& config() const { return config_; }
  void set_nom_freq(uint8_t nom_freq) { config_.nom_freq = nom_freq; }

  bool AllocDecoder(const std::string& pt_file);
  void FreeDecoder();
  pt_insn_decoder* decoder() const { return decoder_; }

  const std::vector<Process>& processes() const { return processes_; }

  const std::vector<PtFile>& pt_files() const { return pt_files_; }

  const std::unordered_set<uint64_t>& unknown_cr3s() const {
    return unknown_cr3s_;
  }

 private:
  DecoderState();

  bool AllocImage(const std::string& name);

  bool ReadCpuidFile(const std::string& file);
  bool ReadKtraceFile(const std::string& file);
  bool ReadMapFile(const std::string& file);
  bool ReadIdsFile(const std::string& file);
  bool ReadPtListFile(const std::string& file);

  Symtab* AddSymtab(unsigned num, unsigned long cr3, unsigned long base,
                     const char* file_name, bool is_kernel);
  void ReadSymtab(debugserver::elf::Reader* elf, uint64_t cr3,
                  uint64_t base, uint64_t len, uint64_t offset,
                  const char* file_name, bool is_kernel);
  bool ReadElf1(const char* file_name, struct pt_image* image,
                uint64_t base, uint64_t cr3,
                uint64_t file_off, uint64_t map_len);
  bool ReadStaticElf(const char* file_name, pt_image* image,
                     uint64_t cr3, bool is_kernel);
  bool ReadElf(const std::string& file, uint64_t base, uint64_t cr3,
               uint64_t file_off, uint64_t map_len);
  bool ReadKernelElf(const std::string& file, uint64_t cr3);

  void SetKernelCr3(uint64_t cr3) { kernel_cr3_ = cr3; }

  static int ReadMemCallback(uint8_t* buffer, size_t size,
                             const struct pt_asid* asid,
                             uint64_t addr, void* context);

  static int ProcessKtraceRecord(debugserver::ktrace::KtraceRecord* rec,
                                 void* arg);

  bool AddProcess(uint64_t pid, uint64_t cr3, uint64_t start_time);
  bool MarkProcessExited(uint64_t pid, uint64_t end_time);

  bool AddMapEntry(const MapEntry&entry);
  void ClearMap();

  void AddBuildId(const std::string& file_dir, const std::string& build_id,
                  const std::string& path);

  void AddPtFile(const std::string& file_dir, uint64_t id,
                 const std::string& path);

  pt_config config_;
  pt_image* image_;
  pt_insn_decoder* decoder_;

  // According to intel-pt.h:pt_config this is only required if CYC
  // packets have been enabled in IA32_RTIT_CTRL.CYCEn.
  // If zero, timing calibration will only be able to use MTC and CYC
  // packets. If not zero, timing calibration will also be able to use CBR
  // packets.
  double tsc_freq_;

  uint64_t kernel_cr3_;

  std::vector<Process> processes_;
  std::vector<MapEntry> maps_;
  std::vector<BuildId> build_ids_;
  std::vector<PtFile> pt_files_;

  // List of cr3 values seen that we don't have processes for.
  // This helps printers explain the results to human readers.
  std::unordered_set<uint64_t> unknown_cr3s_;

  Symtab* symtabs_;
};

} // intel_processor_trace
