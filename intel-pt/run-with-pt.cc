// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(dje): wip wip wip

#include <cinttypes>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <unistd.h>

#include <iostream>

#include <launchpad/launchpad.h>
#include <magenta/device/intel-pt.h>
#include <magenta/device/ktrace.h>
#include <magenta/ktrace.h>
#include <magenta/syscalls.h>

#include <mxio/util.h>

#include "lib/ftl/command_line.h"
#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_printf.h"

#include "util.h"
#include "x86-pt.h"

static int ktrace_fd = -1;
static mx_handle_t ktrace_handle = MX_HANDLE_INVALID;
static int ipt_fd = -1;

static void DumpArch(FILE* out) {
  if (x86::HaveProcessorTrace()) {
    const x86::ProcessorTraceFeatures* pt = x86::GetProcessorTraceFeatures();
    x86::DumpProcessorTraceFeatures(out, pt);
  }
}

static void StartPerf() {
  ssize_t ssize;
  mx_status_t status;

  if (!x86::HaveProcessorTrace())
    return;

  ktrace_fd = open("/dev/misc/ktrace", O_RDONLY);
  if (ktrace_fd < 0)
    return;
  ssize = ioctl_ktrace_get_handle(ktrace_fd, &ktrace_handle);
  if (ssize != sizeof(ktrace_handle)) {
    util::LogErrorWithErrno("get ktrace handle");
    goto Fail;
  }
  status = mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("ktrace stop", status);
    goto FailResumeKtrace;
  }
  status = mx_ktrace_control(ktrace_handle, KTRACE_ACTION_REWIND, 0, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("ktrace rewind", status);
    goto FailResumeKtrace;
  }
  status = mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START,
                             KTRACE_GRP_TASKS, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("ktrace start", status);
    goto FailResumeKtrace;
  }

  ipt_fd = open("/dev/misc/intel-pt", O_RDONLY);
  if (ipt_fd < 0) {
    goto FailResumeKtrace;
  }
  ssize = ioctl_ipt_alloc(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("init perf", ssize);
    goto FailResumeKtrace;
  }
  ssize = ioctl_ipt_start(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("start perf", ssize);
    goto FailResumeKtrace;
  }

  return;

 FailResumeKtrace:
  // TODO(dje): Resume original ktracing.
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START, 0, nullptr);
  // fall through

 Fail:
  mx_handle_close(ktrace_handle);
  ktrace_handle = MX_HANDLE_INVALID;
  close(ktrace_fd);
  ktrace_fd = -1;
  close(ipt_fd);
  ipt_fd = -1;
}

static void StopPerf() {
  if (!x86::HaveProcessorTrace())
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

  auto status = mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP,
                                  0, nullptr);
  if (status == NO_ERROR) {
    // Save the trace, before we restore it to its original setting.
    static const char path[] = "/tmp/ptout.ktrace";
    int dest_fd = open(path, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    if (dest_fd >= 0) {
      ssize_t count;
      char buf[1024];
      while ((count = read(ktrace_fd, buf, sizeof(buf))) != 0) {
        if (write(dest_fd, buf, count) != count) {
          FTL_LOG(ERROR) << "error writing " << path;
        }
      }
      close(dest_fd);
    } else {
      util::LogErrorWithErrno(ftl::StringPrintf("unable to create %s", path));
    }
  } else {
    util::LogErrorWithMxStatus("stop ktrace", status);
  }

  close(ipt_fd);
  ipt_fd = -1;
  if (ktrace_handle != MX_HANDLE_INVALID) {
    // TODO(dje): Resume original ktracing.
    mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
    mx_ktrace_control(ktrace_handle, KTRACE_ACTION_REWIND, 0, nullptr);
    mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START, 0, nullptr);
    mx_handle_close(ktrace_handle);
    ktrace_handle = MX_HANDLE_INVALID;
  }
  close(ktrace_fd);
  ktrace_fd = -1;
}

static void DumpPerf() {
  FILE* f = fopen("/tmp/ptout.cpuid", "w");
  if (f != nullptr) {
    DumpArch(f);
    fclose(f);
  } else {
    FTL_LOG(ERROR) << "unable to write PT config to /tmp/pt.cpuid";
  }
}

constexpr char kUsageString[] =
    "Usage: run-with-pt [options] program [args...]\n"
    "\n"
    "  program - the path to the executable to run\n"
    "\n"
    "Options:\n"
    "  --dump-arch        print random facts about the architecture at startup\n"
    "  --help             show this help message\n"
    "  --quiet[=level]    set quietness level (opposite of verbose)\n"
    "  --verbose[=level]  set debug verbosity level\n"
    "\n"
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

  if (cl.HasOption("dump-arch", nullptr)) {
    DumpArch(stdout);
  }

  std::vector<std::string> inferior_argv(cl.positional_args().begin(),
                                         cl.positional_args().end());

  if (inferior_argv.size() == 0) {
    FTL_LOG(ERROR) << "Missing program";
    return EXIT_FAILURE;
  }

  const char* c_args[inferior_argv.size()];
  for (size_t i = 0; i < inferior_argv.size(); ++i)
    c_args[i] = inferior_argv[i].c_str();
  const char* name = util::basename(c_args[0]);

  StartPerf();

  mx_handle_t inferior =
    launchpad_launch_mxio(name, inferior_argv.size(), c_args);
  if (inferior < 0) {
    util::LogErrorWithMxStatus("error starting process", inferior);
    return EXIT_FAILURE;
  }

  mx_signals_t signals = MX_SIGNAL_SIGNALED;
  mx_signals_t pending;
  int64_t timeout = MX_TIME_INFINITE;
  mx_status_t status = mx_handle_wait_one(inferior, signals, timeout,
                                          &pending);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("mx_handle_wait_one failed", status);
  }

  mx_info_process_t info;
  if ((status = mx_object_get_info(inferior, MX_INFO_PROCESS, &info,
                                   sizeof(info), NULL, NULL)) == NO_ERROR) {
    printf("Process exited with code %d\n", info.return_code);
  } else {
    util::LogErrorWithMxStatus("mx_object_get_info failed", status);
  }

  mx_handle_close(inferior);

  StopPerf();
  DumpPerf();

  return EXIT_SUCCESS;
}
