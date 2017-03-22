// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome-printer.h"

#define _GNU_SOURCE 1

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <vector>
#include <string>

#include <intel-pt.h>

#include "apps/tracing/lib/trace/reader.h"

#include "lib/ftl/command_line.h"
#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_number_conversions.h"
#include "lib/ftl/strings/string_printf.h"

#include "intel-pt-decode/decoder.h"
#include "printer.h"

namespace intel_processor_trace {

constexpr char ChromePrinter::kDefaultOutputFileName[];

std::unique_ptr<ChromePrinter> ChromePrinter::Create(
    DecoderState* state,
    const PrinterConfig& config)
{
  std::string output_file_name = config.output_file_name;
  if (config.output_file_name == "") {
    output_file_name = kDefaultOutputFileName;
    FTL_LOG(INFO) << "Output file defaulting to: " << output_file_name;
  }

  std::ofstream out_file(output_file_name,
                         std::ios_base::out | std::ios_base::trunc);
  if (!out_file.is_open()) {
    FTL_LOG(ERROR) << "Unable to open file for writing: "
                   << config.output_file_name;
    return nullptr;
  }

  auto printer = std::unique_ptr<ChromePrinter>(
      new ChromePrinter(out_file, state, config));
  return printer;
}

ChromePrinter::ChromePrinter(std::ofstream& out_file,
                             DecoderState* state,
                             const PrinterConfig& config)
  : state_(state),
    config_(config)
{
  exporter_.reset(
    new tracing::ChromiumExporter(std::move(out_file)));
}

ChromePrinter::~ChromePrinter()
{
}

#if 0

static double TscUs(IptDecoderState* state, int64_t t)
{
  if (state->tsc_freq() == 0)
    return t;
  return (t / (state->tsc_freq() * 1000));
}

void ChromePrinter::PrintTime(uint64_t ts, uint64_t* last_ts,
                              uint64_t* first_ts)
{
  char buf[30];
  if (!*first_ts && !config_.abstime)
    *first_ts = ts;
  if (!*last_ts)
    *last_ts = ts;
  double rtime = TscUs(state_, ts - *first_ts);
  snprintf(buf, sizeof buf, "%-9.*f [%+-.*f]",
           state_->tsc_freq() ? 3 : 0,
           rtime,
           state_->tsc_freq() ? 3 : 0,
           TscUs(state_, ts - *last_ts));
  *last_ts = ts;
  Printf("%-24s", buf);
}

#endif

bool ChromePrinter::Cr3IsUserSpace(uint64_t cr3)
{
  // TODO(dje): In practice this test is insufficient.
  return cr3 != state_->kernel_cr3();
}

ChromePrinter::Space ChromePrinter::GetSpace(const IptInsn* si,
                                             const Symtab* symtab)
{
  if (symtab) {
    if (symtab->is_kernel)
      return Space::kKernel;
    else
      return Space::kUser;
  } else if (si->cr3 != pt_asid_no_cr3) {
    // If we're in kernel space on behalf of userspace that is intended to
    // be caught by the preceding case (symtab != nullptr).
    if (si->cr3 == state_->kernel_cr3())
      return Space::kKernel;
    else
      return Space::kUser;
  } else {
    return Space::kUnknown;
  }
}

uint64_t ChromePrinter::PidForDisplay(const IptInsn* si, const PrintState* ps)
{
  // Chrome doesn't understand cpus, it only understand processes and threads.
  // For cpu view: processes are cpus, threads are processes.
  // For process view: processes are processes, threads are cpus.
  uint64_t pid;
  const intel_processor_trace::Process* p =
    state_->LookupProcessByCr3(si->cr3);

  if (p) {
    if (config_.view == OutputView::kCpu) {
      pid = ps->cpu_num;
    } else {
      pid = p->pid;
    }
  } else {
    // chrome://tracing prints pids in decimal so print cr3 in decimal too
    // so that it's easy to match up.
    FTL_VLOG(2) << ftl::StringPrintf("Unable to find process for cr3 0x%"
                                     PRIx64 "(%" PRIu64 ")",
                                     si->cr3, si->cr3);
    if (config_.view == OutputView::kCpu) {
      pid = ps->cpu_num;
    } else {
      pid = si->cr3;
    }
  }

  return pid;
}

uint64_t ChromePrinter::TidForDisplay(const IptInsn* si, const PrintState* ps,
                                      const Symtab* symtab)
{
  // Chrome doesn't understand cpus, it only understand processes and threads.
  // For cpu view: processes are cpus, threads are processes.
  // For process view: processes are processes, threads are cpus.
  // So this function basically just does the opposite of PidForDisplay.
  uint64_t tid;
  const intel_processor_trace::Process* p =
    state_->LookupProcessByCr3(si->cr3);

  if (p) {
    if (config_.view == OutputView::kCpu) {
      tid = p->pid;
    } else {
      tid = ps->cpu_num;
    }
  } else {
    // No need to log the lookup failure here, we already did so in
    // PidForDisplay.
    if (config_.view == OutputView::kCpu) {
      tid = si->cr3;
    } else {
      tid = ps->cpu_num;
    }
  }

  return tid;
}

void ChromePrinter::EmitBeginFunctionRecord(const IptInsn* si, PrintState* ps)
{
  std::vector<tracing::reader::Argument> arguments;

  tracing::ProcessThread process_thread(ps->current_pid, ps->current_tid);

  tracing::reader::Record record(tracing::reader::Record::Event{
      si->tic, // FIXME
      process_thread,
      std::move("insns"),
      std::move(ps->current_function ? ps->current_function->name : "unknown"),
      std::move(arguments),
      tracing::reader::EventData(
          tracing::reader::EventData::DurationBegin{})});

  exporter_->ExportRecord(record);
}

void ChromePrinter::EmitEndFunctionRecord(uint64_t tic, PrintState* ps)
{
  std::vector<tracing::reader::Argument> arguments;

  tracing::ProcessThread process_thread(ps->current_pid, ps->current_tid);

  tracing::reader::Record record(tracing::reader::Record::Event{
      tic,
      process_thread,
      std::move("insns"),
      std::move(ps->current_function ? ps->current_function->name : "unknown"),
      std::move(arguments),
      tracing::reader::EventData(
          tracing::reader::EventData::DurationEnd{})});

  exporter_->ExportRecord(record);
}

void ChromePrinter::EmitBeginSyscallRecord(uint64_t tic,
                                           uint64_t pid, uint64_t tid)
{
  std::vector<tracing::reader::Argument> arguments;

  tracing::ProcessThread process_thread(pid, tid);

  tracing::reader::Record record(tracing::reader::Record::Event{
      tic,
      process_thread,
      std::move("insns"),
      std::move("in-kernel"), // FIXME
      std::move(arguments),
      tracing::reader::EventData(
          tracing::reader::EventData::DurationBegin{})});

  exporter_->ExportRecord(record);
}

void ChromePrinter::EmitEndSyscallRecord(uint64_t tic,
                                         uint64_t pid, uint64_t tid)
{
  std::vector<tracing::reader::Argument> arguments;

  tracing::ProcessThread process_thread(pid, tid);

  tracing::reader::Record record(tracing::reader::Record::Event{
      tic,
      process_thread,
      std::move("insns"),
      std::move("in-kernel"), // FIXME
      std::move(arguments),
      tracing::reader::EventData(
          tracing::reader::EventData::DurationEnd{})});

  exporter_->ExportRecord(record);
}

void ChromePrinter::EmitErrorRecord(int error, uint64_t ts, uint64_t tic)
{
  std::vector<tracing::reader::Argument> arguments;

  tracing::ProcessThread process_thread(0, 0);

  tracing::reader::Record record(tracing::reader::Record::Event{
      tic, // FIXME
      process_thread,
      std::move("error"), // category
      std::move("error"), // name
      std::move(arguments),
      // TODO(dje): The scope here is wip.
      tracing::reader::EventData(
          tracing::reader::EventData::Instant{tracing::EventScope::kProcess})});

  exporter_->ExportRecord(record);
}

void ChromePrinter::EmitCoreBusRatioRecord(uint32_t ratio, uint64_t ts,
                                           uint64_t tic)
{
  std::vector<tracing::reader::Argument> arguments;

  tracing::ProcessThread process_thread(0, 0);

  tracing::reader::Record record(tracing::reader::Record::Event{
      tic, // FIXME
      process_thread,
      std::move("core-bus-ratio"), // category
      std::move("core-bus-ratio"), // name
      std::move(arguments),
      tracing::reader::EventData(
          tracing::reader::EventData::Instant{tracing::EventScope::kGlobal})});

  exporter_->ExportRecord(record);
}

void ChromePrinter::ProcessInsn(const IptInsn* si, PrintState* ps)
{
  const Symtab* symtab = state_->FindSymtab(si->cr3, si->pc);
  const Sym* sym = symtab ? symtab->FindSym(si->pc) : nullptr;
  Space space = GetSpace(si, symtab);
  uint64_t pid = PidForDisplay(si, ps);
  uint64_t tid = TidForDisplay(si, ps, symtab);

  // If still in the same function nothing to do.
  if (si->cr3 == ps->current_cr3 &&
      sym == ps->current_function &&
      space == ps->current_space &&
      pid == ps->current_pid &&
      tid == ps->current_tid)
    return;

  // We're in a different function now for the purposes of display.
  // [It could be the same source function, but in a different process,
  // for example.]
  //
  // Note: It's ok at this point if |sym| is nullptr.
  // We just emit it as the "unknown" function.

  if (ps->emitted_function)
    EmitEndFunctionRecord(si->tic, ps);

  // If executing a user space program, mark syscalls as contained by function
  // "in-kernel". This is done to distinguish userspace from kernelspace
  // without having to do a hack like give them separate thread ids, and also
  // keeps them together (in proximity) in the display.
  //
  // For our purposes here treat the "unknown" space as userspace. We can only
  // guess, so we pick something that keeps the display cleaner (for some
  // definition of "cleaner" - TODO(dje): revisit in time).

  bool in_same_process = ps->emitted_function && si->cr3 == ps->current_cr3;

  if (!in_same_process) {
    // In a different process.
    // Close off the wrapping in-kernel record if present.
    if (ps->currently_in_kernel) {
      FTL_DCHECK(ps->emitted_function);
      EmitEndSyscallRecord(si->tic, ps->current_pid, ps->current_tid);
      ps->currently_in_kernel = false;
    }
  }

  Space previous_space = ps->current_space;
  // If this is a different program then assume the previous space was
  // userspace. This allows us to restart the in-kernel wrapping if we're
  // still in a syscall.
  if (!in_same_process)
    previous_space = Space::kUser;

  bool is_user_space_prog = Cr3IsUserSpace(si->cr3);
  bool do_syscall_record_keeping =
    is_user_space_prog &&
    si->cr3 != pt_asid_no_cr3;
  bool is_user_to_kernel_transition =
    do_syscall_record_keeping &&
    (previous_space == Space::kUser || previous_space == Space::kUnknown) &&
    space == Space::kKernel;
  bool is_kernel_to_user_transition =
    do_syscall_record_keeping &&
    previous_space == Space::kKernel &&
    (space == Space::kUser || space == Space::kUnknown);

  if (do_syscall_record_keeping) {
    if (is_kernel_to_user_transition) {
      if (ps->currently_in_kernel) {
        EmitEndSyscallRecord(si->tic, ps->current_pid, ps->current_tid); // FIXME
        ps->currently_in_kernel = false;
      }
    } else if (is_user_to_kernel_transition) {
      FTL_DCHECK(!ps->currently_in_kernel);
      EmitBeginSyscallRecord(si->tic, pid, tid); // FIXME
      ps->currently_in_kernel = true;
    }
  } else {
    // Not doing in-kernel wrapping. Make sure we close off any previous
    // record.
    if (ps->currently_in_kernel) {
      EmitEndSyscallRecord(si->tic, ps->current_pid, ps->current_tid);
      ps->currently_in_kernel = false;
    }
  }

  ps->current_symtab = symtab;
  ps->current_function = sym;
  ps->current_cr3 = si->cr3;
  ps->current_space = space;
  ps->current_pid = pid;
  ps->current_tid = tid;
  ps->emitted_function = true;
  EmitBeginFunctionRecord(si, ps);
}

static bool IsInterestingEvent(const struct pt_insn& insn)
{
  return (insn.enabled || insn.disabled ||
          insn.resumed || insn.interrupted ||
          insn.resynced || insn.stopped);
}

void ChromePrinter::PreprocessTrace()
{
}

uint64_t ChromePrinter::PrintOneFile(const PtFile& pt_file)
{
  if (!state_->AllocDecoder(pt_file.file)) {
    FTL_LOG(ERROR) << "Unable to open pt file: " << pt_file.file;
    return 0;
  }

  PrintState ps;
  if (config_.id != PrinterConfig::kIdUnset)
    ps.cpu_num = config_.id;
  else
    ps.cpu_num = pt_file.id;

  // Before we do anything preprocess the trace to find unknown cr3 values.
  PreprocessTrace();

  struct pt_insn_decoder* pt_decoder = state_->decoder();
  uint64_t total_insncnt = 0;
  // The current core bus ratio as recorded in the trace (0 = unknown).
  uint32_t core_bus_ratio = 0;

  for (;;) {
    // Every time we get an error while reading the trace we start over
    // at the top of this loop.

    int err = pt_insn_sync_forward(pt_decoder);
    if (err < 0) {
      uint64_t pos;
      pt_insn_get_offset(pt_decoder, &pos);
      std::string message = ftl::StringPrintf("%llx: sync forward: %s\n",
                                              (unsigned long long)pos,
                                              pt_errstr(pt_errcode(err)));
      if (err == -pte_eos) {
        FTL_LOG(INFO) << message;
      } else {
        FTL_LOG(ERROR) << message;
      }
      break;
    }

    // For error reporting.
    uint64_t errcr3 = 0;
    uint64_t errip = 0;

    // A count of the number of insns since the last emitted record.
    unsigned int insncnt = 0;

    for (;;) {
      // This is the data we obtain from libipt.
      struct pt_insn insn;
      // This is our copy of the insn's data.
      IptInsn sinsn;
      // Keep code similar with PrintInsns() for now.
      IptInsn* si = &sinsn;

      // Do the increment before checking the result of pt_insn_next so that
      // error lines have reference numbers as well.
      ++total_insncnt;

      // TODO(dje): Verify this always stores values in the arguments even
      // if there's an error (which according to intel-pt.h can only be
      // -pte_no_time).
      pt_insn_time(pt_decoder, &si->ts, &si->lost_mtc, &si->lost_cyc);
      if (si->ts && si->ts == ps.last_ts) {
        // If the timestamp of this one is the same as the previous, we
        // essentially don't know it, so indicate so.
        si->ts = 0;
      }

      insn.ip = 0;
      err = pt_insn_next(pt_decoder, &insn, sizeof(struct pt_insn));
      if (err < 0) {
        pt_insn_get_cr3(pt_decoder, &errcr3);
        errip = insn.ip;
        EmitErrorRecord(err, si->ts ? si->ts : ps.last_ts, total_insncnt);
        break;
      }

      // TODO(dje): use lost counts

      pt_insn_get_cr3(pt_decoder, &si->cr3);

      // Watch for changes to the core bus ratio recorded in the trace.
      uint32_t ratio;
      pt_insn_core_bus_ratio(pt_decoder, &ratio);
      if (ratio != core_bus_ratio) {
        EmitCoreBusRatioRecord(ratio, si->ts ? si->ts : ps.last_ts,
                               total_insncnt);
        core_bus_ratio = ratio;
      }

      if (insn.iclass == ptic_call ||
          insn.iclass == ptic_far_call ||
          insn.iclass == ptic_return ||
          insn.iclass == ptic_far_return ||
          // Always print if we have a time (for now).
          si->ts ||
          IsInterestingEvent(insn)) {
        ; // interesting insn
      } else {
        // not interesting
        ++insncnt;
        continue;
      }

      // This happens when -K is used. Match everything for now.
      if (si->cr3 == -1UL)
        si->cr3 = 0;

      si->iclass = insn.iclass;
      si->tic = total_insncnt;
      si->pc = insn.ip;

      // Record the number of insns since the last record.
      si->insn_delta = insncnt;
      // And restart the count, starting with this insn.
      insncnt = 1;

      TransferEvents(si, &insn);

      ProcessInsn(si, &ps);

      if (si->ts)
        ps.last_ts = si->ts;
    }

    if (err == -pte_eos)
      break;

    {
      uint64_t pos;
      pt_insn_get_offset(pt_decoder, &pos);
      FTL_LOG(ERROR) << ftl::StringPrintf("[%8llu] %llx:%llx:%llx: error %s",
                                          (unsigned long long)total_insncnt,
                                          (unsigned long long)pos,
                                          (unsigned long long)errcr3,
                                          (unsigned long long)errip,
                                          pt_errstr(pt_errcode(err)));
    }
  }

  if (ps.emitted_function) {
    EmitEndFunctionRecord(total_insncnt, &ps);
    if (ps.currently_in_kernel) {
      EmitEndSyscallRecord(total_insncnt, ps.current_pid, ps.current_tid);
      ps.currently_in_kernel = false;
    }
  }

  state_->FreeDecoder();

  return total_insncnt;
}

uint64_t ChromePrinter::PrintFiles()
{
  uint64_t total_insns = 0;

  for (const auto& file : state_->pt_files()) {
    total_insns += PrintOneFile(file);
  }

  return total_insns;
}

} // intel_processor_trace
