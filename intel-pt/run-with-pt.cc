// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(dje): wip wip wip

#include <cinttypes>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
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
#include "lib/ftl/strings/string_number_conversions.h"

#include "util.h"
#include "x86-pt.h"

static constexpr char ipt_device_path[] = "/dev/misc/intel-pt";
static constexpr char ktrace_device_path[] = "/dev/misc/ktrace";

static constexpr char pt_output_path_prefix[] = "/tmp/ptout";
static constexpr char ktrace_output_path[] = "/tmp/ptout.ktrace";

static constexpr char ldso_trace_env_var[] = "LD_TRACE_FILE";
static constexpr char ldso_trace_output_path[] = "/tmp/ptout.ldso";

static constexpr char cpuid_output_path[] = "/tmp/ptout.cpuid";

struct PerfConfig {
  PerfConfig()
    : buffer_size(0), num_buffers(0) { }
  // zero means "unset, use default"
  size_t buffer_size;
  size_t num_buffers;
};

static bool OpenDevices(int* out_ipt_fd, int* out_ktrace_fd,
                        mx_handle_t* out_ktrace_handle) {
  int ipt_fd = -1;
  int ktrace_fd = -1;
  mx_handle_t ktrace_handle = MX_HANDLE_INVALID;

  if (out_ipt_fd) {
    ipt_fd = open(ipt_device_path, O_RDONLY);
    if (ipt_fd < 0) {
      util::LogErrorWithErrno("open intel-pt");
      return false;
    }
  }

  if (out_ktrace_fd || out_ktrace_handle) {
    ktrace_fd = open(ktrace_device_path, O_RDONLY);
    if (ktrace_fd < 0) {
      util::LogErrorWithErrno("open ktrace");
      close(ipt_fd);
      return false;
    }
  }

  if (out_ktrace_handle) {
    ssize_t ssize = ioctl_ktrace_get_handle(ktrace_fd, &ktrace_handle);
    if (ssize != sizeof(ktrace_handle)) {
      util::LogErrorWithErrno("get ktrace handle");
      close(ipt_fd);
      close(ktrace_fd);
      return false;
    }
  }

  if (out_ipt_fd)
    *out_ipt_fd = ipt_fd;
  if (out_ktrace_fd)
    *out_ktrace_fd = ktrace_fd;
  else if (ktrace_fd != -1)
    close(ktrace_fd);
  if (out_ktrace_handle)
    *out_ktrace_handle = ktrace_handle;

  return true;
}

static void DumpArch(FILE* out) {
  if (x86::HaveProcessorTrace()) {
    const x86::ProcessorTraceFeatures* pt = x86::GetProcessorTraceFeatures();
    x86::DumpProcessorTraceFeatures(out, pt);
  }
}

static void StartPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "StartPerf called";

  int ipt_fd;
  mx_handle_t ktrace_handle;
  ssize_t ssize;
  mx_status_t status;

  if (!x86::HaveProcessorTrace()) {
    FTL_LOG(INFO) << "PT not supported";
    return;
  }

  if (!OpenDevices(&ipt_fd, nullptr, &ktrace_handle))
    return;

  status = mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("ktrace stop", status);
    goto Fail;
  }
  status = mx_ktrace_control(ktrace_handle, KTRACE_ACTION_REWIND, 0, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("ktrace rewind", status);
    goto Fail;
  }
  // For now just include task info in the ktrace - we need it, and we don't
  // want to risk the ktrace buffer filling without it.
  status = mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START,
                             KTRACE_GRP_TASKS, nullptr);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus("ktrace start", status);
    goto Fail;
  }

  ssize = ioctl_ipt_alloc(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("init perf", ssize);
    goto Fail;
  }
  ssize = ioctl_ipt_start(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("start perf", ssize);
    ioctl_ipt_free(ipt_fd);
    goto Fail;
  }

  close(ipt_fd);
  mx_handle_close(ktrace_handle);
  return;

 Fail:

  // TODO(dje): Resume original ktracing.
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START, 0, nullptr);

  mx_handle_close(ktrace_handle);
  close(ipt_fd);
}

static void StopPerf() {
  FTL_LOG(INFO) << "StopPerf called";

  int ipt_fd;
  mx_handle_t ktrace_handle;
  ssize_t ssize;
  mx_status_t status;

  if (!x86::HaveProcessorTrace()) {
    FTL_LOG(INFO) << "PT not supported";
    return;
  }

  if (!OpenDevices(&ipt_fd, nullptr, &ktrace_handle))
    return;

  ssize = ioctl_ipt_stop(ipt_fd);
  if (ssize != 0) {
    // TODO(dje): This is really bad, this shouldn't fail.
    util::LogErrorWithMxStatus("stop perf", ssize);
  }

  status = mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  if (status != NO_ERROR) {
    // TODO(dje): This shouldn't fail either, should it?
    util::LogErrorWithMxStatus("stop ktrace", status);
  }

  close(ipt_fd);
  mx_handle_close(ktrace_handle);
}

// Write all output files.
// This assumes tracing has already been stopped.

static void DumpPerf() {
  FTL_LOG(INFO) << "DumpPerf called";

  int ipt_fd, ktrace_fd;
  ssize_t ssize;

  if (!x86::HaveProcessorTrace()) {
    FTL_LOG(INFO) << "PT not supported";
    return;
  }

  if (!OpenDevices(&ipt_fd, &ktrace_fd, nullptr))
    return;

  ssize = ioctl_ipt_write_file(ipt_fd, pt_output_path_prefix,
                               strlen(pt_output_path_prefix));
  if (ssize != 0) {
    util::LogErrorWithMxStatus("stop perf", ssize);
  }
  close(ipt_fd);

  int dest_fd = open(ktrace_output_path, O_CREAT | O_TRUNC | O_RDWR,
                     S_IRUSR | S_IWUSR);
  if (dest_fd >= 0) {
    ssize_t count;
    char buf[1024];
    while ((count = read(ktrace_fd, buf, sizeof(buf))) != 0) {
      if (write(dest_fd, buf, count) != count) {
        FTL_LOG(ERROR) << "error writing " << ktrace_output_path;
      }
    }
    close(dest_fd);
  } else {
    util::LogErrorWithErrno(ftl::StringPrintf("unable to create %s",
                                              ktrace_output_path));
  }
  close(ktrace_fd);

  FILE* f = fopen(cpuid_output_path, "w");
  if (f != nullptr) {
    DumpArch(f);
    fclose(f);
  } else {
    FTL_LOG(ERROR) << "unable to write PT config to " << cpuid_output_path;
  }
}

// Reset perf collection to its original state.
// This means restoring ktrace to its original state, and freeing all PT
// resources.
// This assumes tracing has already been stopped.

static void ResetPerf() {
  FTL_LOG(INFO) << "ResetPerf called";

  int ipt_fd;
  mx_handle_t ktrace_handle;
  ssize_t ssize;

  if (!x86::HaveProcessorTrace()) {
    FTL_LOG(INFO) << "PT not supported";
    return;
  }

  if (!OpenDevices(&ipt_fd, nullptr, &ktrace_handle))
    return;

  ssize = ioctl_ipt_free(ipt_fd);
  if (ssize != 0) {
    util::LogErrorWithMxStatus("end perf", ssize);
  }

  close(ipt_fd);
 
  // TODO(dje): Resume original ktracing.
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_REWIND, 0, nullptr);
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START, 0, nullptr);
  mx_handle_close(ktrace_handle);
}

constexpr char kUsageString[] =
    "Usage: run-with-pt [options] program [args...]\n"
    "\n"
    "  program - the path to the executable to run\n"
    "\n"
    "Options:\n"
    "  --dump-arch        print random facts about the architecture at startup\n"
    "  --stop-pt          turn off PT and exit\n"
    "  --help             show this help message\n"
    "  --quiet[=level]    set quietness level (opposite of verbose)\n"
    "  --verbose[=level]  set debug verbosity level\n"
    "  --buffer-size=N    set buffer size\n"
    "  --num-buffers=N    set number of buffers\n"
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

  if (cl.HasOption("stop-pt", nullptr)) {
    StopPerf();
    ResetPerf();
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("dump-arch", nullptr)) {
    DumpArch(stdout);
  }

  PerfConfig config;

  std::string arg;

  if (cl.GetOptionValue("buffer-size", &arg)) {
    size_t buffer_size;
    if (!ftl::StringToNumberWithError<size_t>(ftl::StringView(arg),
                                              &buffer_size)) {
      FTL_LOG(ERROR) << "Not a valid buffer size: " << optarg;
      return EXIT_FAILURE;
    }
    config.buffer_size = buffer_size;
  }

  if (cl.GetOptionValue("num-buffers", &arg)) {
    size_t num_buffers;
    if (!ftl::StringToNumberWithError<size_t>(ftl::StringView(arg),
                                              &num_buffers)) {
      FTL_LOG(ERROR) << "Not a valid buffer size: " << optarg;
      return EXIT_FAILURE;
    }
    config.num_buffers = num_buffers;
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

  // We need details of where the program and its dsos are loaded.
  // This data is obtained from the dynamic linker.
  // TODO(dje): Is there a better way?
  setenv(ldso_trace_env_var, ldso_trace_output_path, 1);

  FTL_LOG(INFO) << "Starting program: " << inferior_argv[0];

  int rc = EXIT_SUCCESS;  

  // Defer turning on tracing as long as possible so that we don't include
  // all this initialization.
  StartPerf(config);

  // N.B. It's important that the PT device be closed at this point as we
  // don't want the inferior to inherit the open descriptor: the device can
  // only be opened once at a time.

  mx_handle_t inferior =
    launchpad_launch_mxio(name, inferior_argv.size(), c_args);
  if (inferior > 0) {
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
  } else {
    util::LogErrorWithMxStatus("error starting process", inferior);
    rc = EXIT_FAILURE;
  }

  StopPerf();
  if (rc == EXIT_SUCCESS)
    DumpPerf();
  ResetPerf();

  return rc;
}
