// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <fstream>
#include <memory>
#include <string>

#include "apps/tracing/lib/trace_converters/chromium_exporter.h"

#include "lib/ftl/macros.h"

#include "intel-pt-decode/decoder.h"
#include "printer.h"

namespace intel_processor_trace {

class ChromePrinter
{
 public:

  // If no output file is specified, write the output here.
  static constexpr char kDefaultOutputFileName[] = "tmp-ipt.json";

  enum class Space { kUnknown, kKernel, kUser };

  struct PrintState
  {
    // The number of the cpu we're processing.
    uint32_t cpu_num = 0;

    // The last timestamp seen in the trace, zero means none seen yet.
    uint64_t last_ts = 0;

    // These are nullptr if unknown.
    const Symtab* current_symtab = nullptr;
    const Sym* current_function = nullptr;

    // cr3 value when current_symtab/current_function were last set.
    uint64_t current_cr3 = pt_asid_no_cr3;

    // pid,tid when current_symtab/current_function were last set.
    uint64_t current_pid = 0;
    uint64_t current_tid = 0;

    // The space when current_symtab/current_function were last set.
    Space current_space = Space::kUnknown;

    // True if we're in the kernel, having transitioned from userspace.
    bool currently_in_kernel = false;

    // True if we have emitted at least one "begin function" record.
    bool emitted_function = false;
  };

  static std::unique_ptr<ChromePrinter>
    Create(DecoderState* state, const PrinterConfig& config);

  ~ChromePrinter();

  std::string Header();

  // Print the insns in a format for chrome://tracing.
  // Returns the number of insns processed.
  // This number is approximate in that errors for individual instructions
  // still count towards to the total.
  uint64_t PrintFiles();

 private:
  ChromePrinter(std::ofstream& output, DecoderState* state,
                const PrinterConfig& config);

  uint64_t PrintOneFile(const PtFile& pt_file);

  void PreprocessTrace();

  bool Cr3IsUserSpace(uint64_t cr3);
  Space GetSpace(const IptInsn* si, const Symtab* symtab);
  uint64_t PidForDisplay(const IptInsn* si, const PrintState* ps);
  uint64_t TidForDisplay(const IptInsn* si, const PrintState* ps,
                         const Symtab* symtab);

  void EmitBeginFunctionRecord(const IptInsn* si, PrintState* ps);
  void EmitEndFunctionRecord(uint64_t tic, PrintState* ps);
  void EmitBeginSyscallRecord(uint64_t tic, uint64_t pid, uint64_t tid);
  void EmitEndSyscallRecord(uint64_t tic, uint64_t pid, uint64_t tid);
  void EmitErrorRecord(int error, uint64_t ts, uint64_t tic);
  void EmitCoreBusRatioRecord(uint32_t ratio, uint64_t ts, uint64_t tic);

  void ProcessInsn(const IptInsn* si, PrintState* ps);

  DecoderState* state_;
  PrinterConfig config_;

  std::unique_ptr<tracing::ChromiumExporter> exporter_;

  FTL_DISALLOW_COPY_AND_ASSIGN(ChromePrinter);
};

} // intel_processor_trace
