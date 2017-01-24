// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(dje): wip wip wip

#include "server-ipt.h"

#include <cinttypes>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>

#include <magenta/device/intel-pt.h>
#include <magenta/device/ktrace.h>
#include <magenta/ktrace.h>
#include <magenta/syscalls.h>

#include <mxio/util.h>

#include "lib/ftl/command_line.h"
#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_printf.h"
#include "lib/ftl/strings/string_number_conversions.h"

#include "arch.h"
#include "arch-x86.h"
#include "ipt-ctrl.h"
#include "util.h"
#include "x86-pt.h"

constexpr char kUsageString[] =
    "Usage: ipt [options] program [args...]\n"
    "       ipt [options] step-option\n"
    "\n"
    "  program - the path to the executable to run\n"
    "\n"
    "Options:\n"
    "  --dump-arch        print random facts about the architecture and exit\n"
    "  --help             show this help message\n"
    "  --quiet[=level]    set quietness level (opposite of verbose)\n"
    "  --verbose[=level]  set debug verbosity level\n"
    "  --num-buffers=N    set number of buffers\n"
    "                     The default is 16.\n"
    "  --buffer-order=N   set buffer size, in pages, as a power of 2\n"
    "                     The default is 2: 16KB buffers.\n"
    "  --circular         use a circular trace buffer\n"
    "                     Otherwise tracing stops when the buffer fills.\n"
    "  --ctl-config=BITS  set user-settable bits in CTL MSR\n"
    "                     See Intel docs on IA32_RTIT_CTL MSR.\n"
    "  --mode=cpu|thread  set the tracing mode\n"
    "                     Must be specified with a program to run.\n"
    "\n"
    "Options for controlling steps in process:\n"
    "Only the first one seen is processed.\n"
    "These cannot be specified with a program to run.\n"
    "\n"
    "  --init             allocate PT resources (buffers) and exit\n"
    "  --start            turn on PT and exit\n"
    "  --stop             turn off PT and exit\n"
    "  --dump             dump PT data and exit\n"
    "  --reset            reset PT (release all resources) and exit\n"
    "\n"
    "Notes:\n"
    "--verbose=<level> : sets |min_log_level| to -level\n"
    "--quiet=<level>   : sets |min_log_level| to +level\n"
    "Quiet supersedes verbose if both are specified.\n"
    "Defined log levels:\n"
    "-n - verbosity level n\n"
    " 0 - INFO - this is the default level\n"
    " 1 - WARNING\n"
    " 2 - ERROR\n"
    " 3 - FATAL\n"
    "Note that negative log levels mean more verbosity.\n";

static void PrintUsageString() {
  std::cout << kUsageString << std::endl;
}

int main(int argc, char* argv[]) {
  ftl::CommandLine cl = ftl::CommandLineFromArgcArgv(argc, argv);

  if (cl.HasOption("help", nullptr)) {
    PrintUsageString();
    return EXIT_SUCCESS;
  }

  if (!ftl::SetLogSettingsFromCommandLine(cl))
    return EXIT_FAILURE;

  FTL_LOG(INFO) << "Starting ipt.";

  if (cl.HasOption("dump-arch", nullptr)) {
    debugserver::arch::DumpArch(stdout);
    return EXIT_SUCCESS;
  }

  debugserver::PerfConfig config;
  std::string arg;

  if (cl.GetOptionValue("mode", &arg)) {
    uint32_t mode;
    if (arg == "cpu") {
      mode = IPT_MODE_CPUS;
    } else if (arg == "thread") {
      mode = IPT_MODE_THREADS;
    } else {
      FTL_LOG(ERROR) << "Not a valid mode value: " << arg;
      return EXIT_FAILURE;
    }
    config.mode = mode;
  }

  if (cl.GetOptionValue("num-buffers", &arg)) {
    size_t num_buffers;
    if (!ftl::StringToNumberWithError<size_t>(ftl::StringView(arg),
                                              &num_buffers)) {
      FTL_LOG(ERROR) << "Not a valid buffer size: " << arg;
      return EXIT_FAILURE;
    }
    config.num_buffers = num_buffers;
  }

  if (cl.GetOptionValue("buffer-order", &arg)) {
    size_t buffer_order;
    if (!ftl::StringToNumberWithError<size_t>(ftl::StringView(arg),
                                              &buffer_order)) {
      FTL_LOG(ERROR) << "Not a valid buffer order: " << arg;
      return EXIT_FAILURE;
    }
    config.buffer_order = buffer_order;
  }

  if (cl.HasOption("circular", nullptr)) {
    config.is_circular = true;
  }

  if (cl.GetOptionValue("ctl-config", &arg)) {
    uint64_t ctl_config;
    if (!ftl::StringToNumberWithError<uint64_t>(ftl::StringView(arg),
                                                &ctl_config, ftl::Base::k16)) {
      FTL_LOG(ERROR) << "Not a valid CTL config value: " << arg;
      return EXIT_FAILURE;
    }
    config.ctl_config = ctl_config;
  }

  debugserver::util::Argv inferior_argv(cl.positional_args().begin(),
                                        cl.positional_args().end());

  if (cl.HasOption("init", nullptr) ||
      cl.HasOption("start", nullptr) ||
      cl.HasOption("stop", nullptr) ||
      cl.HasOption("dump", nullptr) ||
      cl.HasOption("reset", nullptr)) {
    if (inferior_argv.size() != 0) {
      FTL_LOG(ERROR) << "Program cannot be specified";
      return EXIT_FAILURE;
    }
    if (cl.HasOption("mode", nullptr)) {
      FTL_LOG(ERROR) << "Mode cannot be specified";
      return EXIT_FAILURE;
    }
  }

  if (cl.HasOption("init", nullptr)) {
    if (!debugserver::InitPerf(config))
      return EXIT_FAILURE;
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("start", nullptr)) {
    if (!debugserver::StartPerf(config)) {
      FTL_LOG(WARNING) << "Start failed, but buffers not removed";
      return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("stop", nullptr)) {
    debugserver::StopPerf(config);
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("dump", nullptr)) {
    debugserver::DumpPerf(config);
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("reset", nullptr)) {
    debugserver::ResetPerf(config);
    return EXIT_SUCCESS;
  }

  if (inferior_argv.size() == 0) {
    FTL_LOG(ERROR) << "Missing program";
    return EXIT_FAILURE;
  }

  debugserver::IptServer ipt(config);

  auto inferior = new debugserver::Process(&ipt, &ipt, inferior_argv);

  ipt.set_current_process(inferior);

  auto status = ipt.Run();

  if (!status) {
    FTL_LOG(ERROR) << "ipt exited with error";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
