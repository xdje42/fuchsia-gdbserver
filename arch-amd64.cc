// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arch.h"

#include <magenta/perf.h>
#include <magenta/syscalls.h>
#include <stdio.h>

#include "lib/ftl/logging.h"

#include "arch-x86.h"
#include "thread.h"
#include "util.h"
#include "x86-cpuid.h"
#include "x86-pt.h"

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

static bool HaveProcessorTrace() {
  x86::x86_feature_init();
  return x86::x86_feature_test(X86_FEATURE_PT);
}

void DumpArch() {
  x86::x86_feature_debug();
  if (HaveProcessorTrace()) {
    x86::processor_trace_features pt;
    x86::get_processor_trace_features(&pt);
    x86::dump_processor_trace_features(&pt);
  }
}

void StartPerf() {
  if (!HaveProcessorTrace())
    return;

  auto status = mx_perf_trace_control(mx_process_self(), PERF_ACTION_INIT, 0, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("init perf", status);
    return;
  }
  status = mx_perf_trace_control(mx_process_self(), PERF_ACTION_START, 0, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("start perf", status);
    return;
  }
}

void StopPerf() {
  if (!HaveProcessorTrace())
    return;

  auto status = mx_perf_trace_control(mx_process_self(), PERF_ACTION_STOP, 0, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("stop perf", status);
    return;
  }
  size_t capture_size = 0;
  status = mx_perf_trace_control(mx_process_self(), PERF_ACTION_GET_SIZE, 0, &capture_size);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("get perf size", status);
    return;
  }

  printf("PT captured %zu bytes\n", capture_size);
  void* buf = malloc(capture_size);
  if (buf != NULL) {
    uint32_t actual;
    status = mx_perf_trace_read(mx_process_self(), buf, 0, capture_size, &actual);
    if (status != NO_ERROR) {
      util::LogErrorWithMxStatus("read perf", status);
    } else {
#if 0
      printf("PT results:\n");
      util::hexdump_ex(buf, actual, 0);
#else
      FILE* f = fopen("/tmp/pt.dump", "wb");
      if (f != NULL) {
        size_t n = fwrite(buf, actual, 1, f);
        if (n != 1)
          printf("Error writing /tmp/pt.dump\n");
        fclose(f);
      } else {
        printf("Unable to write PT dump to /tmp/pt.dump\n");
      }
#endif
    }
    free(buf);
  }

  status = mx_perf_trace_control(mx_process_self(), PERF_ACTION_END, 0, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("end perf", status);
    return;
  }
}

void DumpPerf() {
}

}  // namespace arch
}  // namespace debugserver
