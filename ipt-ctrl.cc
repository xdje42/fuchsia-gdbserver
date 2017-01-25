// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(dje): wip wip wip

#include "ipt-ctrl.h"

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

#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_printf.h"

#include "arch.h"
#include "arch-x86.h"
#include "server-ipt.h"
#include "util.h"
#include "x86-pt.h"

namespace debugserver {

static constexpr char ipt_device_path[] = "/dev/misc/intel-pt";
static constexpr char ktrace_device_path[] = "/dev/misc/ktrace";

static constexpr char pt_output_path_prefix[] = "/tmp/ptout";
static constexpr char ktrace_output_path[] = "/tmp/ptout.ktrace";

static constexpr char cpuid_output_path[] = "/tmp/ptout.cpuid";

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

bool SetPerfMode(const PerfConfig& config) {
  int ipt_fd;

  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return false;

  uint32_t mode = config.mode;
  ssize_t ssize = ioctl_ipt_set_mode(ipt_fd, &mode);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("set perf mode", ssize);
    goto Fail;
  }

  close(ipt_fd);
  return true;

 Fail:
  close(ipt_fd);
  return false;
}

bool InitCpuPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "InitCpuPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_CPUS);

  int ipt_fd;
  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return false;

  ssize_t ssize;

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
      util::LogErrorWithMxStatus("init cpu perf", ssize);
      goto Fail;
    }
    // Buffers are automagically assigned to cpus, descriptor == cpu#,
    // so we can just ignore descriptor here.
  }

  ssize = ioctl_ipt_cpu_mode_alloc(ipt_fd);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("init perf", ssize);
    goto Fail;
  }

  close(ipt_fd);
  return true;

 Fail:
  close(ipt_fd);
  return false;
}

bool InitThreadPerf(Thread* thread, const PerfConfig& config) {
  FTL_LOG(INFO) << "InitThreadPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_THREADS);

  int ipt_fd;
  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return false;

  ioctl_ipt_buffer_config_t ipt_config;
  uint32_t descriptor;
  memset(&ipt_config, 0, sizeof(ipt_config));
  ipt_config.num_buffers = config.num_buffers;
  ipt_config.buffer_order = config.buffer_order;
  ipt_config.is_circular = config.is_circular;
  ipt_config.ctl = config.ctl_config;
  ssize_t ssize = ioctl_ipt_alloc_buffer(ipt_fd, &ipt_config, &descriptor);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("init thread perf", ssize);
    goto Fail;
  }

  thread->set_ipt_buffer(descriptor);
  return true;

 Fail:
  return false;
}

// This must be called before a process is started so we emit a ktrace
// process start record for it.

bool InitPerfPreProcess(const PerfConfig& config) {
  FTL_LOG(INFO) << "InitPerfPreProcess called";

  mx_handle_t ktrace_handle;
  mx_status_t status;

  if (!OpenDevices(nullptr, nullptr, &ktrace_handle))
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

  return true;

 Fail:

  // TODO(dje): Resume original ktracing.
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START, 0, nullptr);

  mx_handle_close(ktrace_handle);
  return false;
}

bool StartCpuPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "StartCpuPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_CPUS);

  int ipt_fd;
  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return false;

  ssize_t ssize = ioctl_ipt_cpu_mode_start(ipt_fd);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("start cpu perf", ssize);
    ioctl_ipt_cpu_mode_free(ipt_fd);
    goto Fail;
  }

  close(ipt_fd);
  return true;

 Fail:

  close(ipt_fd);
  return false;
}

bool StartThreadPerf(Thread* thread, const PerfConfig& config) {
  FTL_LOG(INFO) << "StartThreadPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_THREADS);

  int ipt_fd;
  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return false;

  if (thread->ipt_buffer() < 0) {
    FTL_LOG(INFO) << ftl::StringPrintf("Thread %" PRId64 " has no IPT buffer",
                                       thread->id());
    // TODO(dje): For now. This isn't an error in the normal sense.
    return true;
  }

  ioctl_ipt_assign_buffer_thread_t assign;
  assign.thread = thread->handle();
  assign.descriptor = thread->ipt_buffer();
  ssize_t ssize = ioctl_ipt_assign_buffer_thread(ipt_fd, &assign);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("assigning ipt buffer to thread", ssize);
    goto Fail;
  }

  close(ipt_fd);
  return true;

 Fail:
  close(ipt_fd);
  return false;
}

void StopCpuPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "StopCpuPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_CPUS);

  int ipt_fd;
  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return;

  ssize_t ssize = ioctl_ipt_cpu_mode_stop(ipt_fd);
  if (ssize < 0) {
    // TODO(dje): This is really bad, this shouldn't fail.
    util::LogErrorWithMxStatus("stop cpu perf", ssize);
  }

  close(ipt_fd);
}

void StopThreadPerf(Thread* thread, const PerfConfig& config) {
  FTL_LOG(INFO) << "StopThreadPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_THREADS);
}

void StopPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "StopPerf called";

  mx_handle_t ktrace_handle;
  if (!OpenDevices(nullptr, nullptr, &ktrace_handle))
    return;

  mx_status_t status =
    mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  if (status != NO_ERROR) {
    // TODO(dje): This shouldn't fail either, should it?
    util::LogErrorWithMxStatus("stop ktrace", status);
  }

  mx_handle_close(ktrace_handle);
}

// Subroutine of DumpCpuPerf to simplify it.

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

    mx_handle_close(vmo);
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

void DumpCpuPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "DumpCpuPerf called";

  int ipt_fd, ktrace_fd;
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
    arch::DumpArch(f);
    fclose(f);
  } else {
    FTL_LOG(ERROR) << "unable to write PT config to " << cpuid_output_path;
  }
}

void DumpThreadPerf(Thread* thread, const PerfConfig& config) {
  FTL_LOG(INFO) << "DumpThreadPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_THREADS);

  int ipt_fd;
  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return;

  if (thread->ipt_buffer() < 0) {
    FTL_LOG(INFO) << ftl::StringPrintf("Thread %" PRId64 " has no IPT buffer",
                                       thread->id());
    // TODO(dje): For now. This isn't an error in the normal sense.
    return;
  }

  ioctl_ipt_assign_buffer_thread_t assign;
  assign.thread = thread->handle();
  assign.descriptor = thread->ipt_buffer();
  ssize_t ssize = ioctl_ipt_assign_buffer_thread(ipt_fd, &assign);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("assigning ipt buffer to thread", ssize);
    goto Fail;
  }

 Fail:
  close(ipt_fd);
}

// Reset perf collection to its original state.
// This means freeing all PT resources.
// This assumes tracing has already been stopped.

void ResetCpuPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "ResetCpuPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_CPUS);

  int ipt_fd;
  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return;

  ssize_t ssize = ioctl_ipt_cpu_mode_free(ipt_fd);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("end perf", ssize);
  }

  close(ipt_fd);
}

void ResetThreadPerf(Thread* thread, const PerfConfig& config) {
  FTL_LOG(INFO) << "ResetThreadPerf called";
  FTL_DCHECK(config.mode == IPT_MODE_THREADS);

  int ipt_fd;
  if (!OpenDevices(&ipt_fd, nullptr, nullptr))
    return;

  if (thread->ipt_buffer() < 0) {
    FTL_LOG(INFO) << ftl::StringPrintf("Thread %" PRId64 " has no IPT buffer",
                                       thread->id());
    // TODO(dje): For now. This isn't an error in the normal sense.
    return;
  }

  ioctl_ipt_assign_buffer_thread_t assign;
  assign.thread = thread->handle();
  assign.descriptor = thread->ipt_buffer();
  ssize_t ssize = ioctl_ipt_assign_buffer_thread(ipt_fd, &assign);
  if (ssize < 0) {
    util::LogErrorWithMxStatus("assigning ipt buffer to thread", ssize);
    goto Fail;
  }

 Fail:
  close(ipt_fd);
}

// Reset perf collection to its original state.
// This means restoring ktrace to its original state.
// This assumes tracing has already been stopped.

void ResetPerf(const PerfConfig& config) {
  FTL_LOG(INFO) << "ResetPerf called";

  mx_handle_t ktrace_handle;
  if (!OpenDevices(nullptr, nullptr, &ktrace_handle))
    return;
 
  // TODO(dje): Resume original ktracing.
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_STOP, 0, nullptr);
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_REWIND, 0, nullptr);
  mx_ktrace_control(ktrace_handle, KTRACE_ACTION_START, 0, nullptr);

  mx_handle_close(ktrace_handle);
}

} // debugserver namespace
