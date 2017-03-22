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

class PrettyPrinter
{
 public:

  struct GlobalPrintState
  {
    uint64_t first_ts;
    uint64_t last_ts;
    uint32_t core_bus_ratio;
  };

  struct LocalPrintState
  {
    int indent;
    int prev_speculative;
  };

  static std::unique_ptr<PrettyPrinter>
    Create(DecoderState* decoder, const PrinterConfig& config);

  ~PrettyPrinter();

  // Pretty-print the trace(s).
  // Returns the number of insns processed.
  // This number is approximate in that errors for individual instructions
  // still count towards to the total.
  uint64_t PrintFiles();

  void Printf(const char* format, ...);

 private:
  PrettyPrinter(FILE* output, DecoderState* decoder,
                const PrinterConfig& config);

  uint64_t PrintOneFile(const PtFile& pt_file);

  void PrintHeader(uint64_t id);

  void PrintPc(const Sym* sym, uint64_t ip, uint64_t cr3, bool print_cr3);
  void PrintPc(uint64_t ip, uint64_t cr3, bool print_cr3);
  void PrintEv(const char* name, const IptInsn* insn);
  void PrintEvent(const IptInsn* insn);
  void PrintTsx(const IptInsn* insn, int* prev_spec, int* indent);
  void PrintTic(uint64_t tic);
  void PrintTimeIndent();
  void PrintTime(uint64_t ts, uint64_t* last_ts, uint64_t* first_ts);
  void PrintInsn(struct pt_insn* insn, uint64_t total_insncnt,
                 uint64_t ts, struct dis* d, uint64_t cr3);
  int RemoveLoops(IptInsn* l, int nr);
  void PrintLoop(const IptInsn* si, const LocalPrintState* lps);
  void PrintKernelMarker(const IptInsn* si, const Symtab* symtab);
  void PrintInsnTime(const IptInsn* si, GlobalPrintState* gps);
  void ReportLost(const IptInsn* si);
  void PrintOutput(const IptInsn* insnbuf, int sic,
                   LocalPrintState* lps, GlobalPrintState* gps);

  FILE* output_;
  DecoderState* state_;
  PrinterConfig config_;

  FTL_DISALLOW_COPY_AND_ASSIGN(PrettyPrinter);
};

} // intel_processor_trace
