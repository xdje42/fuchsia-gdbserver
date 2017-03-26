// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstdint>

#include <magenta/device/intel-pt.h>
#include <magenta/syscalls.h>

#include "lib/ftl/macros.h"
#include "lib/ftl/strings/string_view.h"

#include "inferior-control/exception-port.h"
#include "inferior-control/process.h"
#include "inferior-control/server.h"
#include "inferior-control/thread.h"

namespace debugserver {

constexpr uint32_t kDefaultMode = IPT_MODE_CPUS;
constexpr uint32_t kDefaultMaxThreads = 16;
constexpr size_t kDefaultNumBuffers = 16;
constexpr size_t kDefaultBufferOrder = 2;  // 16kb
constexpr bool kDefaultIsCircular = false;

// The parameters controlling data collection.

struct IptConfig {
  IptConfig()
    : mode(kDefaultMode),
      num_cpus(mx_system_get_num_cpus()),
      max_threads(kDefaultMaxThreads),
      num_buffers(kDefaultNumBuffers),
      buffer_order(kDefaultBufferOrder),
      is_circular(kDefaultIsCircular),
      branch(true),
      cr3_match(0),
      cr3_match_set(false),
      cyc(false),
      cyc_thresh(0),
      mtc(false),
      mtc_freq(0),
      psb_freq(0),
      os(true),
      user(true),
      retc(true),
      tsc(true)
    {
      addr[0] = AddrFilter::kOff;
      addr[1] = AddrFilter::kOff;
    }

  // One of IPT_MODE_CPUS, IPT_MODE_THREADS.
  uint32_t mode;
  // The number of cpus on this system, as reported by mx_system_get_num_cpus().
  uint32_t num_cpus;
  // When tracing threads, the max number of threads we can trace.
  uint32_t max_threads;
  size_t num_buffers;
  size_t buffer_order;
  bool is_circular;

  enum class AddrFilter { kOff = 0, kEnable = 1, kStop = 2 };
  struct AddrRange {
    // "" if no ELF
    std::string elf;
    uint64_t begin, end;
  };

  // The various fields of IA32_RTIT_CTL MSR, and support MSRs.
  AddrFilter addr[2];
  AddrRange addr_range[2];
  bool branch;
  // zero if disabled
  uint64_t cr3_match;
  // True if cr3_match was specified on the command line.
  bool cr3_match_set;
  bool cyc;
  uint32_t cyc_thresh;
  bool mtc;
  uint32_t mtc_freq;
  uint32_t psb_freq;
  bool os, user;
  bool retc;
  bool tsc;

  // Return the value to write to the CTL MSR.
  uint64_t CtlMsr() const;

  // Return values for the addr range MSRs.
  uint64_t AddrBegin(unsigned index) const;
  uint64_t AddrEnd(unsigned index) const;
};

// IptServer implements the main loop, which basically just waits until
// the inferior exits. The exception port thread does all the heavy lifting
// when tracing threads.
//
// NOTE: This class is generally not thread safe. Care must be taken when
// calling methods which modify the internal state of a IptServer instance.
class IptServer final : public Server {
 public:
  IptServer(const IptConfig& config, const std::string& output_path_prefix);

  bool Run() override;

 private:
  bool StartInferior();
  bool DumpResults();

  // IOLoop::Delegate overrides.
  void OnBytesRead(const ftl::StringView& bytes) override;
  void OnDisconnected() override;
  void OnIOError() override;

  // Process::Delegate overrides.
  void OnThreadStarting(Process* process,
                        Thread* thread,
                        const mx_exception_context_t& context) override;
  void OnThreadExiting(Process* process,
                       Thread* thread,
                       const mx_excp_type_t type,
                       const mx_exception_context_t& context) override;
  void OnProcessExit(Process* process,
                     const mx_excp_type_t type,
                     const mx_exception_context_t& context) override;
  void OnArchitecturalException(Process* process,
                                Thread* thread,
                                const mx_excp_type_t type,
                                const mx_exception_context_t& context) override;

  IptConfig config_;
  std::string output_path_prefix_;

  FTL_DISALLOW_COPY_AND_ASSIGN(IptServer);
};

}  // namespace debugserver
