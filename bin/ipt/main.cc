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

#include <mxio/util.h>

#include "lib/ftl/command_line.h"
#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/split_string.h"
#include "lib/ftl/strings/string_printf.h"
#include "lib/ftl/strings/string_number_conversions.h"

#ifdef __x86_64__  // for other arches we're just a stub, TO-128

#include <magenta/device/intel-pt.h>
#include <magenta/syscalls.h>

#include "debugger-utils/util.h"
#include "debugger-utils/x86-pt.h"

#include "inferior-control/arch.h"
#include "inferior-control/arch-x86.h"

#include "control.h"
#include "server.h"

static constexpr char ldso_trace_env_var[] = "LD_TRACE";
static constexpr char ldso_trace_value[] = "1";

static constexpr char default_output_path_prefix[] = "/tmp/ptout";

constexpr char kUsageString[] =
  "Usage: ipt [options] program [args...]\n"
  "       ipt [options] --control action1 [action2 ...]\n"
  "\n"
  "  program - the path to the executable to run\n"
  "\n"
  "Actions (performed when --control is specified):\n"
  "These cannot be specified with a program to run.\n"
  "  init               allocate PT resources (buffers)\n"
  "  start              turn on PT\n"
  "  stop               turn off PT\n"
  "  dump               dump PT data\n"
  "  reset              reset PT (release all resources)\n"
  "\n"
  "Options:\n"
  "  --control          perform the specified actions\n"
  "  --dump-arch        print random facts about the architecture and exit\n"
  "  --help             show this help message and exit\n"
  "  --output-path-prefix PREFIX\n"
  "                     set the file path prefix of output files\n"
  "                       The default is \"/tmp/ptout\".\n"
  "  --quiet[=level]    set quietness level (opposite of verbose)\n"
  "  --verbose[=level]  set debug verbosity level\n"
  "\n"
  "IPT configuration options:\n"
  "  --buffer-order=N   set buffer size, in pages, as a power of 2\n"
  "                       The default is 2: 16KB buffers.\n"
  "  --circular         use a circular trace buffer\n"
  "                       Otherwise tracing stops when the buffer fills.\n"
  "                       The default is non-circular.\n"
  "  --mode=cpu|thread  set the tracing mode\n"
  "                       Must be specified with a program to run.\n"
  "                       The default is cpu.\n"
  "  --num-buffers=N    set number of buffers\n"
  "                       The default is 16.\n"
  "\n"
  "IPT Control configuration options (IA32_RTIT_CTL MSR):\n"
  "  --config=option1;option2;...\n"
  "\n"
  "  --config may be specified any number of times.\n"
  "  Values are applied in order.\n"
  "  Boolean values may be set with just the name, \"=on\" is optional.\n"
  "\n"
  "  addr0=off|enable|stop\n"
  "                     Set the addr0 filter register.\n"
  "                     enable: trace is enabled in the specified range\n"
  "                     stop: trace is stopped on entering specified range\n"
  "  addr0-range=BEGIN,END\n"
  "                     BEGIN,END are numerical addresses\n"
  "  addr0-range=ELF,BEGIN,END\n"
  "                     BEGIN,END are numerical addresses within ELF\n"
  "                       The values are before PIE adjustments.\n"
  "                       If the values are in hex they must begin with 0x.\n"
  "                       This option can only be used when running the\n"
  "                       test program directly.\n"
  "  addr1=off|enable|stop\n"
  "  addr1-range=BEGIN,END\n"
  "  addr1-range=ELF,BEGIN,END\n"
  "                     Same as addr0.\n"
  "  branch=on|off      set/reset the BranchEn bit\n"
  "  cr3-match=off|VALUE\n"
  "                     set/reset the Cr3Filter bit, and the CR3_MATCH MSR\n"
  "                       If VALUE is in hex it must begin with 0x.\n"
  "                       The default is zero(off) if not running a program,\n"
  "                       or the cr3 of the program being run.\n"
  "  cyc=on|off         set/reset the CycEn bit\n"
  "  cyc-thresh=VALUE(0...15)\n"
  "                     set the value of the CycThresh field\n"
  "  mtc=on|off         set/reset the MtcEn bit\n"
  "  mtc-freq=VALUE(0...15)\n"
  "                     set the value of the MtcFreq field\n"
  "  os=on|off          set/reset the OS bit\n"
  "  psb-freq=VALUE(0...15)\n"
  "                     set the value of the PsbFreq field\n"
  "  retc=on|off        reset/set the DisRetc bit\n"
  "                       [the inverted value is what h/w uses]\n"
  "  tsc=on|off         set/reset the TscEn bit\n"
  "  user=on|off        set/reset the USER bit\n"
  "The default is: branch;os;user;retc;tsc.\n"
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

static bool BeginsWith(ftl::StringView str, ftl::StringView prefix,
                       ftl::StringView* arg) {
  size_t prefix_size = prefix.size();
  if (str.size() < prefix_size)
    return false;
  if (str.substr(0, prefix_size) != prefix)
    return false;
  *arg = str.substr(prefix_size);
  return true;
}

static bool ParseFlag(const char* name, const ftl::StringView& arg,
                      bool* value) {
  if (arg == "on")
    *value = true;
  else if (arg == "off")
    *value = false;
  else {
    FTL_LOG(ERROR) << "Invalid value for " << name << ": " << arg;
    return false;
  }
  return true;
}

// If only ftl string/number conversions supported 0x.

static bool ParseNumber(const char* name, const ftl::StringView& arg,
                        uint64_t* value) {
  if (arg.size() > 2 &&
      arg[0] == '0' &&
      (arg[1] == 'x' || arg[1] == 'X')) {
    if (!ftl::StringToNumberWithError<uint64_t>(arg, value, ftl::Base::k16)) {
      FTL_LOG(ERROR) << "Invalid value for " << name << ": " << arg;
      return false;
    }
  } else {
    if (!ftl::StringToNumberWithError<uint64_t>(arg, value)) {
      FTL_LOG(ERROR) << "Invalid value for " << name << ": " << arg;
      return false;
    }
  }
  return true;
}

static bool ParseCr3Match(const char* name,
                          const ftl::StringView& arg,
                          uint64_t* value) {
  if (arg == "off") {
    *value = 0;
    return true;
  } else {
    return ParseNumber(name, arg, value);
  }
}

static bool ParseAddrConfig(const char* name,
                            const ftl::StringView& arg,
                            debugserver::IptConfig::AddrFilter* value) {
  if (arg == "off")
    *value = debugserver::IptConfig::AddrFilter::kOff;
  else if (arg == "enable")
    *value = debugserver::IptConfig::AddrFilter::kEnable;
  else if (arg == "stop")
    *value = debugserver::IptConfig::AddrFilter::kStop;
  else {
    FTL_LOG(ERROR) << "Invalid value for " << name << ": " << arg;
    return false;
  }
  return true;
}

static bool ParseAddrRange(const char* name,
                           const ftl::StringView& arg,
                           debugserver::IptConfig::AddrRange* value) {
  std::vector<ftl::StringView> range_strings =
    ftl::SplitString(ftl::StringView(arg), ",",
                     ftl::kTrimWhitespace, ftl::kSplitWantNonEmpty);
  if (range_strings.size() != 2 && range_strings.size() != 3) {
    FTL_LOG(ERROR) << "Invalid value for " << name << ": " << arg;
    return false;
  }
  unsigned i = 0;
  if (range_strings.size() == 3) {
    value->elf = range_strings[0].ToString();
    ++i;
  }
  if (!ParseNumber(name, range_strings[i], &value->begin))
    return false;
  if (!ParseNumber(name, range_strings[i + 1], &value->end))
    return false;
  return true;
}

static bool ParseFreqValue(const char* name,
                           const ftl::StringView& arg,
                           uint32_t* value) {
  if (!ftl::StringToNumberWithError<uint32_t>(arg, value)) {
    FTL_LOG(ERROR) << "Invalid value for " << name << ": " << arg;
    return false;
  }
  return true;
}

static bool ParseConfigOption(debugserver::IptConfig* config,
                              const std::string& options_string) {
  std::vector<ftl::StringView> options =
    ftl::SplitString(ftl::StringView(options_string), ";",
                     ftl::kTrimWhitespace, ftl::kSplitWantNonEmpty);

  ftl::StringView arg;

  for (const auto& o : options) {
    if (BeginsWith(o, "addr0=", &arg)) {
      if (!ParseAddrConfig("addr0", arg, &config->addr[0]))
	return false;
    } else if (BeginsWith(o, "addr0-range=", &arg)) {
      if (!ParseAddrRange("addr0-range", arg, &config->addr_range[0]))
	return false;
    } else if (BeginsWith(o, "addr1=", &arg)) {
      if (!ParseAddrConfig("addr1", arg, &config->addr[1]))
	return false;
    } else if (BeginsWith(o, "addr1-range=", &arg)) {
      if (!ParseAddrRange("addr1-range", arg, &config->addr_range[1]))
	return false;
    } else if (o == "branch") {
      config->branch = true;
    } else if (BeginsWith(o, "branch=", &arg)) {
      if (!ParseFlag("branch", arg, &config->branch))
        return false;
    } else if (BeginsWith(o, "cr3-match=", &arg)) {
      if (!ParseCr3Match("cr3-match", arg, &config->cr3_match))
        return false;
      config->cr3_match_set = true;
    } else if (o == "cyc") {
      config->cyc = true;
    } else if (BeginsWith(o, "cyc=", &arg)) {
      if (!ParseFlag("cyc", arg, &config->cyc))
        return false;
    } else if (BeginsWith(o, "cyc-thresh=", &arg)) {
      if (!ParseFreqValue("cyc-thresh", arg, &config->cyc_thresh))
	return false;
    } else if (o == "mtc") {
      config->mtc = true;
    } else if (BeginsWith(o, "mtc=", &arg)) {
      if (!ParseFlag("mtc", arg, &config->mtc))
        return false;
    } else if (BeginsWith(o, "mtc-freq=", &arg)) {
      if (!ParseFreqValue("mtc-freq", arg, &config->mtc_freq))
	return false;
    } else if (o == "os") {
      config->os = true;
    } else if (BeginsWith(o, "os=", &arg)) {
      if (!ParseFlag("os", arg, &config->os))
        return false;
    } else if (BeginsWith(o, "psb-freq=", &arg)) {
      if (!ParseFreqValue("psb-freq", arg, &config->psb_freq))
	return false;
    } else if (o == "retc") {
      config->retc = true;
    } else if (BeginsWith(o, "retc=", &arg)) {
      if (!ParseFlag("retc", arg, &config->retc))
        return false;
    } else if (o == "tsc") {
      config->tsc = true;
    } else if (BeginsWith(o, "tsc=", &arg)) {
      if (!ParseFlag("tsc", arg, &config->tsc))
        return false;
    } else if (o == "user") {
      config->user = true;
    } else if (BeginsWith(o, "user=", &arg)) {
      if (!ParseFlag("user", arg, &config->user))
        return false;
    } else {
      FTL_LOG(ERROR) << "Invalid value for --config: " << o;
      return false;
    }
  }

  return true;
}

static debugserver::IptConfig GetIptConfig(const ftl::CommandLine& cl) {
  debugserver::IptConfig config;
  std::string arg;

  if (cl.GetOptionValue("buffer-order", &arg)) {
    size_t buffer_order;
    if (!ftl::StringToNumberWithError<size_t>(ftl::StringView(arg),
                                              &buffer_order)) {
      FTL_LOG(ERROR) << "Not a valid buffer order: " << arg;
      exit(EXIT_FAILURE);
    }
    config.buffer_order = buffer_order;
  }

  if (cl.HasOption("circular", nullptr)) {
    config.is_circular = true;
  }

  if (cl.GetOptionValue("mode", &arg)) {
    uint32_t mode;
    if (arg == "cpu") {
      mode = IPT_MODE_CPUS;
    } else if (arg == "thread") {
      mode = IPT_MODE_THREADS;
    } else {
      FTL_LOG(ERROR) << "Not a valid mode value: " << arg;
      exit(EXIT_FAILURE);
    }
    config.mode = mode;
  }

  if (cl.GetOptionValue("num-buffers", &arg)) {
    size_t num_buffers;
    if (!ftl::StringToNumberWithError<size_t>(ftl::StringView(arg),
                                              &num_buffers)) {
      FTL_LOG(ERROR) << "Not a valid buffer size: " << arg;
      exit(EXIT_FAILURE);
    }
    config.num_buffers = num_buffers;
  }

  // We support multiple --config options, so we can't use GetOptionValue here.
  const std::vector<ftl::CommandLine::Option>& options = cl.options();
  for (const auto& o : options) {
    if (o.name == "config") {
      if (!ParseConfigOption(&config, o.value)) {
        exit(EXIT_FAILURE);
      }
    }
  }

  return config;
}

static bool ControlIpt(const debugserver::IptConfig& config,
                       const std::string& output_path_prefix,
                       const ftl::CommandLine& cl) {
  // We only support the cpu mode here.
  // This isn't a full test as we only actually set the mode for "init".
  // But it catches obvious mistakes like passing --mode=thread.
  if (config.mode != IPT_MODE_CPUS) {
    FTL_LOG(ERROR) << "--control requires cpu mode";
    return false;
  }

  for (const std::string& action : cl.positional_args()) {
    if (action == "init") {
      if (!SetPerfMode(config))
        return false;
      if (!debugserver::InitCpuPerf(config))
        return false;
      if (!debugserver::InitPerfPreProcess(config))
        return false;
    } else if (action == "start") {
      if (!debugserver::StartCpuPerf(config)) {
        FTL_LOG(WARNING) << "Start failed, but buffers not removed";
        return false;
      }
    } else if (action == "stop") {
      debugserver::StopCpuPerf(config);
      debugserver::StopPerf(config);
    } else if (action == "dump") {
      debugserver::DumpCpuPerf(config, output_path_prefix);
      debugserver::DumpPerf(config, output_path_prefix);
    } else if (action == "reset") {
      debugserver::ResetCpuPerf(config);
      debugserver::ResetPerf(config);
    } else {
      FTL_LOG(ERROR) << "Unrecognized action: " << action;
      return false;
    }
  }

  return true;
}

static bool RunProgram(const debugserver::IptConfig& config,
                       const std::string& output_path_prefix,
                       const ftl::CommandLine& cl) {
  debugserver::util::Argv inferior_argv(cl.positional_args().begin(),
                                        cl.positional_args().end());

  if (inferior_argv.size() == 0) {
    FTL_LOG(ERROR) << "Missing program";
    return false;
  }

  // We need details of where the program and its dsos are loaded.
  // This data is obtained from the dynamic linker.
  // TODO(dje): MG-519: ld.so can't write to files, and the only thing it
  // can write to at the moment is the kernel debug log.
  setenv(ldso_trace_env_var, ldso_trace_value, 1);

  debugserver::IptServer ipt(config, output_path_prefix);

  auto inferior = new debugserver::Process(&ipt, &ipt);
  inferior->set_argv(inferior_argv);

  ipt.set_current_process(inferior);

  return ipt.Run();
}

int main(int argc, char* argv[]) {
  ftl::CommandLine cl = ftl::CommandLineFromArgcArgv(argc, argv);

  if (!ftl::SetLogSettingsFromCommandLine(cl))
    return EXIT_FAILURE;

  if (cl.HasOption("help", nullptr)) {
    PrintUsageString();
    return EXIT_SUCCESS;
  }

  if (cl.HasOption("dump-arch", nullptr)) {
    debugserver::arch::DumpArch(stdout);
    return EXIT_SUCCESS;
  }

  if (!debugserver::arch::x86::HaveProcessorTrace()) {
    FTL_LOG(ERROR) << "PT not supported";
    return EXIT_FAILURE;
  }

  debugserver::IptConfig config = GetIptConfig(cl);

  std::string output_path_prefix;
  if (!cl.GetOptionValue("output-path-prefix", &output_path_prefix))
    output_path_prefix = default_output_path_prefix;

  FTL_LOG(INFO) << "ipt control program starting";

  bool success;
  if (cl.HasOption("control", nullptr)) {
    success = ControlIpt(config, output_path_prefix, cl);
  } else {
    success = RunProgram(config, output_path_prefix, cl);
  }

  if (!success) {
    FTL_LOG(INFO) << "ipt exited with error";
    return EXIT_FAILURE;
  }

  FTL_LOG(INFO) << "ipt control program exiting";
  return EXIT_SUCCESS;
}

#else  // !__x86_64

int main(int argc, char* argv[]) {
  FTL_LOG(ERROR) << "ipt is for x86_64 only";
  return EXIT_FAILURE;
}

#endif  // !__x86_64
