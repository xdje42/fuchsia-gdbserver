// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arch.h"

#include <cinttypes>
#include <link.h>

#include <magenta/mtrace.h>
#include <magenta/syscalls.h>
#include <stdio.h>

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

static bool HaveProcessorTrace() {
  x86::x86_feature_init();
  return x86::x86_feature_test(X86_FEATURE_PT);
}

void DumpArch(FILE* out) {
  x86::x86_feature_debug(out);
  if (HaveProcessorTrace()) {
    x86::processor_trace_features pt;
    x86::get_processor_trace_features(&pt);
    x86::dump_processor_trace_features(out, &pt);
  }
}

void StartPerf() {
  if (!HaveProcessorTrace())
    return;

  auto status = mx_mtrace_control(mx_process_self(), MTRACE_ACTION_ALLOC, 0,
                                  nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("init perf", status);
    return;
  }
  status = mx_mtrace_control(mx_process_self(), MTRACE_ACTION_START, 0,
                             nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("start perf", status);
    return;
  }
}

void StopPerf() {
  if (!HaveProcessorTrace())
    return;

  auto status = mx_mtrace_control(mx_process_self(), MTRACE_ACTION_STOP, 0,
                                  nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("stop perf", status);
    return;
  }

  uint32_t num_cpus = mx_num_cpus();
  size_t capture_size[num_cpus];
  size_t actual;
  status = mx_mtrace_read(mx_process_self(), MTRACE_READ_DATA_SIZE,
                          &capture_size, 0, sizeof(size_t) * num_cpus,
                          &actual);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("get perf size", status);
    return;
  }

  printf("PT captured:");
  for (size_t cpu = 0; cpu < num_cpus; ++cpu)
    printf(" %zu", capture_size[cpu]);
  printf("\n");

  for (uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
    void* buf = malloc(capture_size[cpu]);
    if (buf != nullptr) {
      status = mx_mtrace_read(mx_process_self(), MTRACE_READ_DATA_BYTES + cpu,
                              buf, 0, capture_size[cpu], &actual);
      if (status != NO_ERROR) {
        util::LogErrorWithMxStatus("read perf", status);
      } else {
#if 0
        printf("PT results:\n");
        util::hexdump_ex(buf, actual, 0);
#else
        char file_name[100];
        sprintf(file_name, "/tmp/pt%u.dump", cpu);
        FILE* f = fopen(file_name, "wb");
        if (f != nullptr) {
          if (actual != 0) {
            size_t n = fwrite(buf, actual, 1, f);
            if (n != 1)
              printf("Error writing %s\n", file_name);
          }
          fclose(f);
        } else {
          printf("Unable to write PT dump to %s\n", file_name);
        }
#endif
      }
      free(buf);
    }
  }

  status = mx_mtrace_control(mx_process_self(), MTRACE_ACTION_FREE, 0,
                             nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("end perf", status);
    return;
  }
}

static std::string perm_string(uint32_t flags) {
  std::string result("---");
  if (flags & PF_R)
    result[0] = 'r';
  if (flags & PF_W)
    result[1] = 'w';
  if (flags & PF_X)
    result[2] = 'x';
  return result;
}

// TODO(dje): wip wip wip

void DumpPerf() {
  FILE* f = fopen("/tmp/pt.cpuid", "w");
  if (f != nullptr) {
    DumpArch(f);
    fclose(f);
  } else {
    fprintf(stderr, "Unable to write PT config to /tmp/pt.cpuid\n");
  }

  f = fopen("/tmp/pt.map", "w");
  if (f != nullptr) {
    auto r_debug = _dl_debug_addr;
    mx_vaddr_t r_map = reinterpret_cast<mx_vaddr_t>(r_debug->r_map);
    ProcessMemory self(mx_process_self());
    elf::dsoinfo_t* dsos = elf::dso_fetch_list(self, r_map,
                                               "/system/bin/mydb");
    if (dsos != nullptr) {
      for (const elf::dsoinfo_t* dso = dsos; dso != nullptr; dso = dso->next) {
        for (uint32_t i = 0; i < dso->num_loadable_phdrs; ++i) {
          const elf::phdr_type* p = &dso->loadable_phdrs[i];
          // TODO(dje): fake dev/inode, and keep output same format as linux,
          // for now.
          fprintf(f, "%08" PRIxPTR "-%08" PRIxPTR " %s %08" PRIxPTR " 00:00 0 %s\n",
                  dso->base + p->p_vaddr,
                  dso->base + p->p_vaddr + p->p_memsz,
                  perm_string(p->p_flags).c_str(),
                  p->p_offset,
                  dso->name);
        }
      }
      dso_free_list(dsos);
    } else {
      fprintf(stderr, "Unable to obtain dso list\n");
    }
    fclose(f);
  } else {
    fprintf(stderr, "Unable to write PT map to /tmp/pt.map\n");
  }
}

}  // namespace arch
}  // namespace debugserver
