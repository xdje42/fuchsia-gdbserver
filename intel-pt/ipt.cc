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

constexpr size_t kDefaultNumBuffers = 16;
constexpr size_t kDefaultBufferOrder = 2;  // 16kb
constexpr bool kDefaultIsCircular = false;
constexpr uint64_t kDefaultCtlConfig = (
  IPT_CTL_USER_ALLOWED | IPT_CTL_OS_ALLOWED |
  IPT_CTL_BRANCH_EN |
  IPT_CTL_TSC_EN);

struct PerfConfig {
  PerfConfig()
    : num_cpus(mx_num_cpus()),
      num_buffers(kDefaultNumBuffers),
      buffer_order(kDefaultBufferOrder),
      is_circular(kDefaultIsCircular),
      ctl_config(kDefaultCtlConfig)
    { }
  uint32_t num_cpus;
  size_t num_buffers;
  size_t buffer_order;
  bool is_circular;
  uint64_t ctl_config;
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

static bool InitPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "InitPerf called";

  int ipt_fd;
  mx_handle_t ktrace_handle;
  ssize_t ssize;

  if (!x86::HaveProcessorTrace()) {
    FTL_LOG(INFO) << "PT not supported";
    return false;
  }

  if (!OpenDevices(&ipt_fd, nullptr, &ktrace_handle))
    return false;

  for (uint32_t cpu = 0; cpu < config.num_cpus; ++cpu) {
    ioctl_ipt_buffer_config_t ipt_config;
    uint32_t descriptor;
    memset(&ipt_config, 0, sizeof(ipt_config));
    ipt_config.num_buffers = config.num_buffers;
    ipt_config.buffer_order = config.buffer_order;
    ipt_config.is_circular = config.is_circular;
    ipt_config.ctl = config.ctl_config;
    ssize = ioctl_ipt_alloc_buffer(ipt_fd, &ipt_config, &descriptor);
    if (ssize < 0) {
      util::LogErrorWithMxStatus("init perf", ssize);
      goto Fail;
    }
  }

  ssize = ioctl_ipt_cpu_mode_alloc(ipt_fd);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("init perf", ssize);
    goto Fail;
  }

  close(ipt_fd);
  mx_handle_close(ktrace_handle);
  return true;

 Fail:
  close(ipt_fd);
  mx_handle_close(ktrace_handle);
  return false;
}

static bool StartPerf() {
  FTL_LOG(INFO) << "StartPerf called";

  int ipt_fd;
  mx_handle_t ktrace_handle;
  ssize_t ssize;
  mx_status_t status;

  if (!x86::HaveProcessorTrace()) {
    FTL_LOG(INFO) << "PT not supported";
    return false;
  }

  if (!OpenDevices(&ipt_fd, nullptr, &ktrace_handle))
    return false;

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

  ssize = ioctl_ipt_cpu_mode_start(ipt_fd);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("start perf", ssize);
    ioctl_ipt_cpu_mode_free(ipt_fd);
    goto Fail;
  }

  close(ipt_fd);
  mx_handle_close(ktrace_handle);
  return true;

 Fail:

  // TODO(dje): Resume original ktracing.
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START, 0, nullptr);

  mx_handle_close(ktrace_handle);
  close(ipt_fd);
  return false;
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

  ssize = ioctl_ipt_cpu_mode_stop(ipt_fd);
  if (ssize < 0) {
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

// Subroutine of DumpPerf to simplify it.

static mx_status_t WriteCpuData(const PerfConfig& config, int ipt_fd,
                                uint32_t cpu, const char* output_prefix) {
  std::string output_path = ftl::StringPrintf("%s.%u.pt", output_prefix, cpu);
  const char* c_path = output_path.c_str();

  int fd = -1;
  mx_status_t status = NO_ERROR;
  size_t bytes_left;
  char buf[4096];

  ioctl_ipt_buffer_data_t data;
  ssize_t ssize = ioctl_ipt_get_buffer_data(ipt_fd, &cpu, &data);
  if (ssize < 0) {
    util::LogErrorWithMxStatus(ftl::StringPrintf("ioctl_ipt_get_buffer_data: cpu %u",
                                                 cpu),
                               ssize);
    goto Fail;
  }

  fd = open(c_path, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    util::LogErrorWithErrno(ftl::StringPrintf("unable to write file: %s",
                                              c_path));
    status = ERR_BAD_PATH;
    goto Fail;
  }

  bytes_left = data.capture_size;
  for (uint32_t i = 0; i < config.num_buffers && bytes_left > 0; ++i) {
    ioctl_ipt_buffer_handle_rqst_t handle_rqst;
    handle_rqst.descriptor = cpu;
    handle_rqst.buffer_num = i;
    mx_handle_t vmo;
    ssize = ioctl_ipt_get_buffer_handle(ipt_fd, &handle_rqst, &vmo);
    if (ssize < 0) {
      util::LogErrorWithMxStatus(ftl::StringPrintf("ioctl_ipt_get_buffer_handle: cpu %u, buffer %u",
                                                   cpu, i),
                                 ssize);
      goto Fail;
    }

    // TODO(dje): Should fetch from vmo.
    size_t buffer_size = (1 << config.buffer_order) * PAGE_SIZE;

    size_t buffer_remaining = buffer_size;
    size_t offset = 0;
    while (buffer_remaining && bytes_left) {
      size_t to_write = sizeof(buf);
      if (to_write > buffer_remaining)
        to_write = buffer_remaining;
      if (to_write > bytes_left)
        to_write = bytes_left;
      size_t actual;
      status = mx_vmo_read(vmo, buf, offset, to_write, &actual);
      if (status != NO_ERROR) {
        util::LogErrorWithMxStatus(ftl::StringPrintf("mx_vmo_read: cpu %u, buffer %u, offset %zu",
                                                     cpu, i, offset),
                                   status);
        goto Fail;
      }
      if (write(fd, buf, to_write) != (ssize_t) to_write) {
        util::LogError(ftl::StringPrintf("short write, file: %s\n", c_path));
        status = ERR_IO;
        goto Fail;
      }
      offset += to_write;
      buffer_remaining -= to_write;
      bytes_left -= to_write;
    }
  }

  assert(bytes_left == 0);
  close(fd);
  fd = -1;
  status = NO_ERROR;

 Fail:
  // We don't delete the file on failure on purpose, it is kept for
  // debugging purposes.
  if (fd != -1)
    close(fd);
  return status;
}

// Write all output files.
// This assumes tracing has already been stopped.

static void DumpPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "DumpPerf called";

  int ipt_fd, ktrace_fd;

  if (!x86::HaveProcessorTrace()) {
    FTL_LOG(INFO) << "PT not supported";
    return;
  }

  if (!OpenDevices(&ipt_fd, &ktrace_fd, nullptr))
    return;

  for (uint32_t cpu = 0; cpu < config.num_cpus; ++cpu) {
    auto status = WriteCpuData(config, ipt_fd, cpu, pt_output_path_prefix);
    if (status != NO_ERROR) {
      util::LogErrorWithMxStatus(ftl::StringPrintf("dump perf of cpu %u", cpu),
                                 status);
      // Keep trying to dump other cpu's data.
    }
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

  ssize = ioctl_ipt_cpu_mode_free(ipt_fd);
  if (ssize < 0) {
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
    "Usage: pt-ctrl [options] program [args...]\n"
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

static int RunAndDump(const std::vector<std::string>& inferior_argv,
                      PerfConfig& config) {
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

  if (!InitPerf(config))
    return EXIT_FAILURE;

  // Defer turning on tracing as long as possible so that we don't include
  // all the initialization.
  if (!StartPerf()) {
    ResetPerf();
    return EXIT_FAILURE;
  }

  int rc = EXIT_SUCCESS;

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
    DumpPerf(config);
  ResetPerf();

  return rc;
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
    return EXIT_SUCCESS;
  }

  PerfConfig config;
  std::string arg;

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

  std::vector<std::string> inferior_argv(cl.positional_args().begin(),
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
  }

  if (cl.HasOption("init", nullptr)) {
    if (!InitPerf(config))
      return EXIT_FAILURE;
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("start", nullptr)) {
    if (!StartPerf()) {
      FTL_LOG(WARNING) << "Start failed, but buffers not removed";
      return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("stop", nullptr)) {
    StopPerf();
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("dump", nullptr)) {
    DumpPerf(config);
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("reset", nullptr)) {
    ResetPerf();
    return EXIT_SUCCESS;
  }

  return RunAndDump(inferior_argv, config);
}
