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

static int ipt_fd = -1;

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

  ipt_fd = open("/dev/misc/intel-pt", O_RDONLY);
  if (ipt_fd < 0)
    return;

  auto ssize = ioctl_ipt_alloc(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("init perf", ssize);
    return;
  }
  ssize = ioctl_ipt_start(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("start perf", ssize);
    return;
  }
}

void StopPerf() {
  if (!HaveProcessorTrace())
    return;
  if (ipt_fd < 0)
    return;

  auto ssize = ioctl_ipt_stop(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("stop perf", ssize);
    return;
  }

  static const char output_file[] = "/tmp/ptout";
  ssize = ioctl_ipt_write_file(ipt_fd, output_file, strlen(output_file));
  if (ssize != 0) {
    util::LogErrorWithMxStatus("stop perf", ssize);
    return;
  }

  ssize = ioctl_ipt_free(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("end perf", ssize);
    return;
  }

  close(ipt_fd);
  ipt_fd = -1;
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
