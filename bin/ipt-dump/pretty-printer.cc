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

#include "pretty-printer.h"

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

#include "lib/ftl/command_line.h"
#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_number_conversions.h"
#include "lib/ftl/strings/string_printf.h"

#include "intel-pt-decode/decoder.h"
#include "intel-pt-decode/util.h"
#include "printer.h"

#ifdef HAVE_UDIS86
#include <udis86.h>
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define container_of(ptr, type, member) \
  ((type*)((char*)(ptr) - offsetof(type, member)))

namespace intel_processor_trace {

// The number of insns we process at a time, e.g., looking for loops.
#define NINSN 256

std::unique_ptr<PrettyPrinter> PrettyPrinter::Create(
    DecoderState* state, const PrinterConfig& config)
{
  FILE* f = stdout;
  if (config.output_file_name != "") {
    f = fopen(config.output_file_name.c_str(), "w");
    if (!f) {
      FTL_LOG(ERROR) << "Unable to open file for writing: "
                     << config.output_file_name;
      return nullptr;
    }
  }

  auto printer = std::unique_ptr<PrettyPrinter>(
      new PrettyPrinter(f, state, config));
  return printer;
}

PrettyPrinter::PrettyPrinter(FILE* output,
                             DecoderState* state,
                             const PrinterConfig& config)
  : output_(output),
    state_(state),
    config_(config)
{
}

PrettyPrinter::~PrettyPrinter()
{
  if (config_.output_file_name != "")
    fclose(output_);
}

void PrettyPrinter::Printf(const char* format, ...)
{
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

void PrettyPrinter::PrintPc(const Sym* sym, uint64_t ip, uint64_t cr3,
                            bool print_cr3)
{
  if (sym) {
    Printf("%s", sym->name);
    if (ip - sym->addr > 0)
      Printf("+%ld", ip - sym->addr);
    if (config_.dump_pc) {
      Printf(" [");
      if (print_cr3)
        Printf("%lx:", cr3);
      Printf("%lx]", ip);
    }
  } else {
    if (print_cr3)
      Printf("%lx:", cr3);
    Printf("%lx", ip);
  }
}

void PrettyPrinter::PrintPc(uint64_t ip, uint64_t cr3, bool print_cr3)
{
  const Sym* sym = state_->FindSym(cr3, ip);
  PrintPc(sym, ip, cr3, print_cr3);
}

void PrettyPrinter::PrintEv(const char* name, const IptInsn* insn)
{
  Printf("%s ", name);
  PrintPc(insn->pc, insn->cr3, true);
  Printf("\n");
}

void PrettyPrinter::PrintEvent(const IptInsn* insn)
{
#if 0 /* Until these flags are reliable in libipt... */
  if (insn->enabled)
    PrintEv("enabled", insn);
  if (insn->disabled)
    PrintEv("disabled", insn);
  if (insn->resumed)
    PrintEv("resumed", insn);
#endif
  if (insn->interrupted)
    PrintEv("interrupted", insn);
  if (insn->resynced)
    PrintEv("resynced", insn);
  if (insn->stopped)
    PrintEv("stopped", insn);
}

void PrettyPrinter::PrintTsx(const IptInsn* insn, int* prev_spec, int* indent)
{
  if (insn->speculative != *prev_spec) {
    *prev_spec = insn->speculative;
    Printf("%*stransaction\n", *indent, "");
    *indent += 4;
  }
  if (insn->aborted) {
    Printf("%*saborted\n", *indent, "");
    *indent -= 4;
  }
  if (insn->committed) {
    Printf("%*scommitted\n", *indent, "");
    *indent -= 4;
  }
  if (*indent < 0)
    *indent = 0;
}

static double TscUs(DecoderState* state, int64_t t)
{
  if (state->tsc_freq() == 0)
    return t;
  return (t / (state->tsc_freq() * 1000));
}

void PrettyPrinter::PrintTic(uint64_t tic)
{
  Printf("[%8" PRIu64 "] ", tic);
}

void PrettyPrinter::PrintTimeIndent()
{
  Printf("%*s", 24, "");
}

void PrettyPrinter::PrintTime(uint64_t ts, uint64_t* last_ts,
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

static const char* InsnClass(enum pt_insn_class iclass)
{
  static const char* const class_name[] = {
    [ptic_error] = "error",
    [ptic_other] = "other",
    [ptic_call] = "call",
    [ptic_return] = "ret",
    [ptic_jump] = "jump",
    [ptic_cond_jump] = "cjump",
    [ptic_far_call] = "fcall",
    [ptic_far_return] = "fret",
    [ptic_far_jump] = "fjump",
  };
  return iclass < ARRAY_SIZE(class_name) ? class_name[iclass] : "?";
}

#ifdef HAVE_UDIS86

struct dis
{
  ud_t ud_obj;
  IptDecoderState* state;
  uint64_t cr3;
};

static const char* DisResolve(struct ud* u, uint64_t addr, int64_t* off)
{
  struct dis* d = container_of(u, struct dis, ud_obj);
  Sym* sym = d->state->FindSym(d->cr3, addr);
  if (sym) {
    *off = addr - sym->val;
    return sym->name;
  } else {
    return nullptr;
  }
}

static void InitDis(struct dis* d)
{
  ud_init(&d->ud_obj);
  ud_set_syntax(&d->ud_obj, UD_SYN_ATT);
  ud_set_sym_resolver(&d->ud_obj, DisResolve);
}

#else

struct dis {};
static void InitDis(struct dis* d) {}

#endif

#define NUM_WIDTH 35

void PrettyPrinter::PrintInsn(struct pt_insn* insn, uint64_t total_insncnt,
                              uint64_t ts, struct dis* d, uint64_t cr3)
{
  int i;
  int n;
  // TODO(dje): remove " insn"
  Printf("[%8llu] %llx %llu %5s insn: ",
         (unsigned long long)total_insncnt,
         (unsigned long long)insn->ip,
         (unsigned long long)ts,
         InsnClass(insn->iclass));
  n = 0;
  for (i = 0; i < insn->size; i++) {
    Printf("%02x ", insn->raw[i]);
    n += 3;
  }
#ifdef HAVE_UDIS86
  d->state = state;
  d->cr3 = cr3;
  if (insn->mode == ptem_32bit)
    ud_set_mode(&d->ud_obj, 32);
  else
    ud_set_mode(&d->ud_obj, 64);
  ud_set_pc(&d->ud_obj, insn->pc);
  ud_set_input_buffer(&d->ud_obj, insn->raw, insn->size);
  ud_disassemble(&d->ud_obj);
  Printf("%*s%s", NUM_WIDTH - n, "", ud_insn_asm(&d->ud_obj));
#endif
  if (insn->enabled)
    Printf("\tENA");
  if (insn->disabled)
    Printf("\tDIS");
  if (insn->resumed)
    Printf("\tRES");
  if (insn->interrupted)
    Printf("\tINT");
  Printf("\n");
#if 0 // TODO(dje): use libbacktrace?
  if (dump_dwarf)
    print_addr(state->FindIpFn(insn->pc, cr3), insn->pc);
#endif
}

#define NO_ENTRY ((unsigned char)-1)
#define CHASHBITS 8

#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

int PrettyPrinter::RemoveLoops(IptInsn* l, int nr)
{
  int i, j, off;
  unsigned char chash[1 << CHASHBITS];
  memset(chash, NO_ENTRY, sizeof(chash));

  for (i = 0; i < nr; i++) {
    int h = (l[i].pc * GOLDEN_RATIO_PRIME_64) >> (64 - CHASHBITS);

    l[i].iterations = 0;
    l[i].loop_start = l[i].loop_end = false;
    if (chash[h] == NO_ENTRY) {
      chash[h] = i;
    } else if (l[chash[h]].pc == l[i].pc) {
      bool is_loop = true;
      unsigned insn = 0;

      off = 0;
      for (j = chash[h]; j < i && i + off < nr; j++, off++) {
        if (l[j].pc != l[i + off].pc) {
          is_loop = false;
          break;
        }
        insn += l[j].insn_delta;
      }
      if (is_loop) {
        j = chash[h];
        l[j].loop_start = true;
        if (l[j].iterations == 0)
          l[j].iterations++;
        l[j].iterations++;
        Printf("loop %llx-%llx %d-%d %u insn iter %d\n", 
               (unsigned long long)l[j].pc, 
               (unsigned long long)l[i].pc,
               j, i,
               insn, l[j].iterations);
        memmove(l + i, l + i + off,
                (nr - (i + off)) * sizeof(IptInsn));
        l[i-1].loop_end = true;
        nr -= off;
      }
    }
  }
  return nr;
}

void PrettyPrinter::PrintLoop(const IptInsn* si, const LocalPrintState* ps)
{
  if (si->loop_start) {
    PrintTic(si->tic);
    PrintTimeIndent();
    Printf(" %5s  %*sloop start %u iterations ", "", ps->indent, "", si->iterations);
    PrintPc(si->pc, si->cr3, true);
    Printf("\n");
  }
  if (si->loop_end) {
    PrintTic(si->tic);
    PrintTimeIndent();
    Printf(" %5s  %*sloop end ", "", ps->indent, "");
    PrintPc(si->pc, si->cr3, true);
    Printf("\n");
  }
}

void PrettyPrinter::PrintKernelMarker(const IptInsn* si, const Symtab* symtab)
{
  if (symtab) {
    if (symtab->is_kernel)
      Printf(" K");
    else
      Printf(" U");
  } else if (si->cr3 != pt_asid_no_cr3) {
    // If we're in kernel space on behalf of userspace that is intended to
    // be caught by the preceding case (symtab != nullptr).
    if (si->cr3 == state_->kernel_cr3())
      Printf(" K");
    else
      Printf(" U");
  } else {
    Printf(" ?");
  }
}

void PrettyPrinter::PrintInsnTime(const IptInsn* si,
                                  GlobalPrintState* gps)
{
  if (si->ts)
    PrintTime(si->ts, &gps->last_ts, &gps->first_ts);
  else
    PrintTimeIndent();
}

void PrettyPrinter::ReportLost(const IptInsn* si)
{
  if (config_.report_lost_mtc_cyc && si->ts) {
    if (si->lost_mtc)
      Printf("  [lost-mtc:%u]", si->lost_mtc);
    if (si->lost_cyc)
      Printf("  [lost-cyc:%u]", si->lost_cyc);
  }
}

void PrettyPrinter::PrintOutput(const IptInsn* insnbuf, int sic,
                                LocalPrintState* lps,
                                GlobalPrintState* gps)
{
  for (int i = 0; i < sic; i++) {
    const IptInsn* si = &insnbuf[i];

    if (si->speculative || si->aborted || si->committed)
      PrintTsx(si, &lps->prev_speculative, &lps->indent);
    if (si->core_bus_ratio && si->core_bus_ratio != gps->core_bus_ratio) {
      Printf("frequency %d\n", si->core_bus_ratio);
      gps->core_bus_ratio = si->core_bus_ratio;
    }
    if (si->enabled || si->disabled ||
        si->resumed || si->interrupted ||
        si->resynced || si->stopped)
      PrintEvent(si);
    if (config_.detect_loop && (si->loop_start || si->loop_end))
      PrintLoop(si, lps);

    // Note: For accurate output, the collection of instructions we do
    // here needs to match the records printed by decode.
    switch (si->iclass) {
    case ptic_call:
    case ptic_far_call: {
      PrintTic(si->tic);
      PrintInsnTime(si, gps);
      Printf("[+%4u]", si->insn_delta);
      const Symtab* symtab = state_->FindSymtab(si->cr3, si->pc);
      const Sym* sym = symtab ? symtab->FindSym(si->pc) : nullptr;
      PrintKernelMarker(si, symtab);
      Printf(" %-7s", IclassName(si->iclass));
      Printf(" %*s", lps->indent, "");
      PrintPc(sym, si->pc, si->cr3, true);
      Printf(" -> ");
      PrintPc(si->dst, si->cr3, false);
      ReportLost(si);
      Printf("\n");
      lps->indent += 4;
      break;
    }
    case ptic_return:
    case ptic_far_return: {
      PrintTic(si->tic);
      PrintInsnTime(si, gps);
      Printf("[+%4u]", si->insn_delta);
      const Symtab* symtab = state_->FindSymtab(si->cr3, si->pc);
      const Sym* sym = symtab ? symtab->FindSym(si->pc) : nullptr;
      PrintKernelMarker(si, symtab);
      Printf(" %-7s", IclassName(si->iclass));
      Printf(" %*s", lps->indent, "");
      PrintPc(sym, si->pc, si->cr3, true);
      ReportLost(si);
      Printf("\n");
      lps->indent -= 4;
      if (lps->indent < 0)
        lps->indent = 0;
      break;
    }
    default: {
      // Always print if we have a time (for now).
      // Also print error records so that insn counts in the output are
      // easier to follow (more accurate).
      if (si->ts || si->iclass == ptic_error) {
        PrintTic(si->tic);
        PrintInsnTime(si, gps);
        Printf("[+%4u]", si->insn_delta);
        const Symtab* symtab = state_->FindSymtab(si->cr3, si->pc);
        const Sym* sym = symtab ? symtab->FindSym(si->pc) : nullptr;
        PrintKernelMarker(si, symtab);
        Printf(" %-7s", IclassName(si->iclass));
        Printf(" %*s", lps->indent, "");
        PrintPc(sym, si->pc, si->cr3, true);
        ReportLost(si);
        Printf("\n");
      }
      break;
    }
    } // switch
  }
}

void PrettyPrinter::PrintHeader(uint64_t id)
{
  Printf("PT dump for id %" PRIu64 "\n", id);
  Printf("%-10s %-9s %-13s %-7s %c %-7s %s\n",
         "REF#",
         "TIME",
         "DELTA",
         "INSNs",
         '@',
         "ICLASS",
         "LOCATION");
}

uint64_t PrettyPrinter::PrintOneFile(const PtFile& pt_file)
{
  if (!state_->AllocDecoder(pt_file.file)) {
    FTL_LOG(ERROR) << "Unable to open pt file: " << pt_file.file;
    return 0;
  }
  config_.id = pt_file.id;

  struct pt_insn_decoder* pt_decoder = state_->decoder();
  GlobalPrintState gps = { };
  uint64_t last_ts = 0;
  struct dis dis;

  PrintHeader(pt_file.id);

  gps.first_ts = 0;
  gps.last_ts = 0;

  // This doesn't need to be accurate, it's main purpose is to generate
  // referenceable numbers in the output. It's also used as a measure of
  // the number of insns we've processed.
  uint64_t total_insncnt = 0;

  InitDis(&dis);

  for (;;) {
    // Every time we get an error while reading the trace we start over
    // at the top of this loop.

    LocalPrintState lps = { };

    int err = pt_insn_sync_forward(pt_decoder);
    if (err < 0) {
      uint64_t pos;
      pt_insn_get_offset(pt_decoder, &pos);
      Printf("%llx: sync forward: %s\n",
             (unsigned long long)pos,
             pt_errstr(pt_errcode(err)));
      break;
    }

    // For error reporting.
    uint64_t errcr3 = 0;
    uint64_t errip = 0;

    // Reset core bus ratio calculations.
    uint32_t prev_ratio = 0;

    // A count of the number of insns since the last emitted record.
    unsigned int insncnt = 0;

    do {
      // Insns processed in this iteration.
      IptInsn insnbuf[NINSN];
      // Index into |insnbuf|.
      int sic = 0;

      // For calls we peek ahead to the next insn to see what function
      // was called. If true |insn| is already filled in.
      bool peeked_ahead = false;
      struct pt_insn insn;

      while (!err && sic < NINSN) {
        IptInsn* si = &insnbuf[sic];

        // Do the increment before checking the result of pt_insn_next so that
        // error lines have reference numbers as well.
        ++total_insncnt;

        // TODO(dje): Verify this always stores values in the arguments even
        // if there's an error (which according to intel-pt.h can only be
        // -pte_no_time).
        pt_insn_time(pt_decoder, &si->ts, &si->lost_mtc, &si->lost_cyc);
        if (si->ts && si->ts == last_ts)
          si->ts = 0;

        if (!peeked_ahead) {
          insn.ip = 0;
          err = pt_insn_next(pt_decoder, &insn, sizeof(struct pt_insn));
          if (err < 0) {
            pt_insn_get_cr3(pt_decoder, &errcr3);
            errip = insn.ip;
            if (insncnt > 0) {
              // Emit a record for the first error in a sequence of them,
              // in part so we don't lose track of the insns counted so far.
              si->iclass = ptic_error;
              si->ts = 0;
              si->tic = total_insncnt;
              si->cr3 = errcr3;
              si->pc = errip;
              si->insn_delta = insncnt;
              insncnt = 0;
              ++sic;
            }
            break;
          }
        }
        peeked_ahead = false;
        ++insncnt;

        // TODO(dje): use lost counts

        pt_insn_get_cr3(pt_decoder, &si->cr3);
        if (config_.dump_insn)
          PrintInsn(&insn, total_insncnt, si->ts, &dis, si->cr3);

        // Watch for changes to the core bus ratio recorded in the trace.
        uint32_t ratio;
        si->core_bus_ratio = 0;
        pt_insn_core_bus_ratio(pt_decoder, &ratio);
        if (ratio != prev_ratio) {
          si->core_bus_ratio = ratio;
          prev_ratio = ratio;
        }

        // This happens when -K is used. Match everything for now.
        if (si->cr3 == -1UL)
          si->cr3 = 0;

        si->iclass = insn.iclass;

        // Note: For accurate output, the collection of instructions we do
        // here needs to match the records printed by PrintOutput.
        if (insn.iclass == ptic_call || insn.iclass == ptic_far_call) {
          si->tic = total_insncnt;
          si->pc = insn.ip;
          si->insn_delta = insncnt;
          insncnt = 0;
          ++sic;
          TransferEvents(si, &insn);
          // Peek at the next insn to see what subroutine we called.
          insn.ip = 0;
          err = pt_insn_next(pt_decoder, &insn, sizeof(struct pt_insn));
          if (err < 0) {
            si->dst = 0;
            pt_insn_get_cr3(pt_decoder, &errcr3);
            errip = insn.ip;
            break;
          }
          peeked_ahead = true;
          si->dst = insn.ip;
        } else if (insn.iclass == ptic_return ||
                   insn.iclass == ptic_far_return ||
                   // Always print if we have a time (for now).
                   si->ts) {
          si->tic = total_insncnt;
          si->pc = insn.ip;
          si->insn_delta = insncnt;
          insncnt = 0;
          ++sic;
          TransferEvents(si, &insn);
        } else if (insn.enabled || insn.disabled ||
                   insn.resumed || insn.interrupted ||
                   insn.resynced || insn.stopped ||
                   insn.aborted) {
#if 0 // part of experiment to get accurate insn counts in output
          si->tic = total_insncnt;
          si->pc = insn.ip;
          si->insn_delta = insncnt;
          insncnt = 0;
          ++sic;
          TransferEvents(si, &insn);
#else
          continue;
#endif
        } else {
          // not interesting
          continue;
        }

        if (si->ts)
          last_ts = si->ts;
      } // while (!err && sic < NINSN)

      if (config_.detect_loop)
        sic = RemoveLoops(insnbuf, sic);
      PrintOutput(insnbuf, sic, &lps, &gps);
    } while (err == 0);

    if (err == -pte_eos)
      break;

    {
      uint64_t pos;
      pt_insn_get_offset(pt_decoder, &pos);
      Printf("[%8llu] %llx:%llx:%llx: error %s\n",
             (unsigned long long)total_insncnt,
             (unsigned long long)pos,
             (unsigned long long)errcr3,
             (unsigned long long)errip,
             pt_errstr(pt_errcode(err)));
    }
  }

  state_->FreeDecoder();

  return total_insncnt;
}

uint64_t PrettyPrinter::PrintFiles()
{
  uint64_t total_insns = 0;

  for (const auto& file : state_->pt_files()) {
    total_insns += PrintOneFile(file);
  }

  return total_insns;
}

} // intel_processor_trace
