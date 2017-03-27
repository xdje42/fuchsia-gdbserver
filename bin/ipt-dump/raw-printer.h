// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstdio>

#include <memory>
#include <string>

#include "lib/ftl/macros.h"

#include "intel-pt-decode/decoder.h"
#include "printer.h"

namespace intel_processor_trace {

class RawPrinter
{
 public:

  enum class Space { kUnknown, kKernel, kUser };

  struct PrintState
  {
    uint64_t total_insncnt = 0;
    uint64_t current_ts = 0;

    // The current position in the PT file, as reported by pt_insn_get_offset.
    uint64_t current_pos;

    // The space when current_symtab/current_function were last set.
    Space current_space = Space::kUnknown;

    // These are nullptr if unknown.
    const Symtab* current_symtab = nullptr;
    const Sym* current_function = nullptr;

    // cr3 value when current_symtab/current_function were last set.
    uint64_t current_cr3 = pt_asid_no_cr3;

    // The current pc value.
    uint64_t current_pc = 0;

    // The current core bus ratio as recorded in the trace (0 = unknown).
    uint32_t current_core_bus_ratio = 0;
  };

  static std::unique_ptr<RawPrinter>
    Create(DecoderState* decoder, const PrinterConfig& config);

  ~RawPrinter();

  // Raw-print the trace(s).
  // Returns the number of insns processed.
  // This number is approximate in that errors for individual instructions
  // still count towards to the total.
  uint64_t PrintFiles();

 private:
  RawPrinter(FILE* output, DecoderState* decoder,
             const PrinterConfig& config);

  void Printf(const char* format, ...);
  RawPrinter::Space GetSpace(uint64_t cr3, const Symtab* symtab);
  void PrintInsn(const pt_insn* insn, PrintState* ps);
  int ProcessNextInsn(struct pt_insn_decoder* pt_decoder, PrintState* ps);

  uint64_t PrintOneFile(const PtFile& pt_file);

  FILE* out_file_;
  DecoderState* state_;
  PrinterConfig config_;

  FTL_DISALLOW_COPY_AND_ASSIGN(RawPrinter);
};

} // intel_processor_trace
