// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arch.h"

#include <cinttypes>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <unistd.h>

#include <magenta/device/intel-pt.h>
#include <magenta/device/ktrace.h>
#include <magenta/ktrace.h>
#include <magenta/syscalls.h>

#include "lib/ftl/logging.h"

#include "arch-x86.h"
#include "dso-list.h"
#include "memory-process.h"
#include "thread.h"
#include "util.h"
#include "x86-cpuid.h"
#include "x86-pt.h"

// This is a global variable that exists in the dynamic linker, and thus in
// every processes's address space (since Fuchsia is PIE-only). It contains
// various information provided by the dynamic linker for use by debugging
// tools.
extern struct r_debug* _dl_debug_addr;

namespace debugserver {
namespace arch {

int ComputeGdbSignal(const mx_exception_context_t& context) {
  int sigval;
  auto arch_exception = context.arch.u.x86_64.vector;

  switch (arch_exception) {
    case x86::INT_DIVIDE_0:
      sigval = 8;
      break;
    case x86::INT_DEBUG:
      sigval = 5;
      break;
    case x86::INT_NMI:
      sigval = 29;
      break;
    case x86::INT_BREAKPOINT:
      sigval = 5;
      break;
    case x86::INT_OVERFLOW:
      sigval = 8;
      break;
    case x86::INT_BOUND_RANGE:
      sigval = 11;
      break;
    case x86::INT_INVALID_OP:
      sigval = 4;
      break;
    case x86::INT_DEVICE_NA:  // e.g., Coprocessor Not Available
      sigval = 8;
      break;
    case x86::INT_DOUBLE_FAULT:
      sigval = 7;
      break;
    case x86::INT_COPROCESSOR_SEGMENT_OVERRUN:
    case x86::INT_INVALID_TSS:
    case x86::INT_SEGMENT_NOT_PRESENT:
    case x86::INT_STACK_FAULT:
    case x86::INT_GP_FAULT:
    case x86::INT_PAGE_FAULT:
      sigval = 11;
      break;
    case x86::INT_RESERVED:  // -> SIGUSR1
      sigval = 10;
      break;
    case x86::INT_FPU_FP_ERROR:
    case x86::INT_ALIGNMENT_CHECK:
      sigval = 7;
      break;
    case x86::INT_MACHINE_CHECK:  // -> SIGURG
      sigval = 23;
      break;
    case x86::INT_SIMD_FP_ERROR:
      sigval = 8;
      break;
    case x86::INT_VIRT:  // Virtualization Exception -> SIGVTALRM
      sigval = 26;
      break;
    case 21:  // Control Protection Exception
      sigval = 11;
      break;
    case 22 ... 31:
      sigval = 10;  // reserved (-> SIGUSR1 for now)
      break;
    default:
      sigval = 12;  // "software generated" (-> SIGUSR2 for now)
      break;
  }

  FTL_VLOG(1) << "x86 (AMD64) exception (" << arch_exception
              << ") mapped to: " << sigval;

  return sigval;
}

bool IsSingleStepException(const mx_exception_context_t& context) {
  auto arch_exception = context.arch.u.x86_64.vector;
  return arch_exception == x86::INT_DEBUG;
}

void DumpArch(FILE* out) {
  x86::x86_feature_debug(out);
  if (x86::HaveProcessorTrace()) {
    const x86::ProcessorTraceFeatures* pt = x86::GetProcessorTraceFeatures();
    x86::DumpProcessorTraceFeatures(out, pt);
  }
}

}  // namespace arch
}  // namespace debugserver
