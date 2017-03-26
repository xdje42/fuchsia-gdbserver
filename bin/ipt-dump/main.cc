// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include <intel-pt.h>

#include "lib/ftl/command_line.h"
#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_number_conversions.h"
#include "lib/ftl/strings/string_printf.h"
#include "lib/ftl/time/stopwatch.h"

#include "intel-pt-decode/decoder.h"
#include "chrome-printer.h"
#include "pretty-printer.h"
#include "printer.h"

using namespace intel_processor_trace;

static constexpr char usage_string[] =
  "ipt-dump [options]\n"
  "\n"
  "These options are required:\n"
  "\n"
  "--pt=FILE           PT input file\n"
  "--pt-list=FILE      Text file containing list of PT files\n"
  "                      Exactly one of --pt,--pt-list is required.\n"
  "--cpuid=FILE        Name of the .cpuid file (sideband data)\n"
  "--ids=FILE          An \"ids.txt\" file, which provides build-id\n"
  "                      to debug-info-containing ELF file (sideband data)\n"
  "                     May be specified multiple times.\n"
  "--ktrace=FILE       Name of the .ktrace file (sideband data)\n"
  "--map=FILE          Name of file containing mappings of ELF files to\n"
  "                      their load addresses (sideband data)\n"
  "                      This output currently comes from the dynamic linker\n"
  "                      when env var LD_TRACE=1 is set, and can be the output\n"
  "                      from loglistener.\n"
  "                      May be specified multiple times.\n"
  "\n"
  "The remaining options are optional.\n"
  "\n"
  "Input options:\n"
  "--elf=binary        ELF input PT files\n"
  "                      May be specified multiple times.\n"
  "                      This option is not useful with PIE executables,\n"
  "                      use sideband derived data instead.\n"
  "--kernel=PATH       Name of the kernel ELF file\n"
  "--kernel-cr3=CR3    CR3 value for the kernel (base 16)\n"
  "\n"
  "General output options:\n"
  "--output-format=raw|calls|chrome\n"
  "                    Default is \"calls\"\n"
  "--output-file=PATH\n"
  "                    For raw,calls the default is stdout.\n"
  "                    For chrome the default is tmp-ipt.json\n"
  "\n"
  "Options for \"--output-format=calls\":\n"
  "--pc                Dump numeric instruction addresses\n"
  "--insn              Dump instruction bytes\n"
  "--tsc               Print time as TSC\n"
  "--time=abs          Print absolute time\n"
  "--time=rel          Print relative time (trace begins at time 0)\n"
  "--report-lost       Report lost mtc,cyc packets\n"
  "--verbose=N         Set verbosity to N\n"
#if 0 // TODO(dje): needs more debugging
  "--loop              Detect loops\n"
#endif
  "\n"
  "Options for \"--output-format=chrome\":\n"
  "--id=ID             ID value to put in the output\n"
  "                      For cpu tracing, this is used to specify the cpu\n"
  "                      number if the PT dump is provided with --p.\n"
  "--view=cpu|process  Set the major axis of display, by cpu or process\n"
  "                      Chrome only understands processes and threads.\n"
  "                      Cpu view: processes are cpus, threads are processes.\n"
  "                      Process view: processes are processes, threads are cpus.\n"
  "                      The default is the cpu view.\n"
  ;

static void Usage(FILE* f)
{
  fprintf(f, "%s", usage_string);
}

static bool ParseOption(const char* arg, ftl::StringView* out_name,
                        const char** out_value)
{
  size_t len = strlen(arg);
  if (len < 2u || arg[0] != '-' || arg[1] != '-')
    return false;
  if (len == 2u) {
    // caller has to distinguish the "--" case
    return false;
  }

  // Note: The option name *must* be at least one character, so start at
  // position 3 -- "--=foo" will yield a name of "=foo" and no value.
  // (Passing a starting |pos| that's "too big" is OK.)
  const char* equals = strchr(arg + 3, '=');
  if (!equals) {
    *out_name = ftl::StringView(arg + 2);
    *out_value = "";
    return true;
  }

  *out_name = ftl::StringView(arg + 2, equals - arg - 2);
  *out_value = equals + 1;
  return true;
}

static int ParseArgv(int argc, char** argv,
                     DecoderConfig* decoder_config,
              PrinterConfig* printer_config)
{
  // While IWBN to use ftl::CommandLine here we need to support passing
  // multiple values for certain options (akin to -I options to the compiler).
  // So we do our own parsing, but we support the same syntax as ftl.

  int n;
  for (n = 1; n < argc; ++n) {
    ftl::StringView option;
    const char* value;

    if (strcmp(argv[n], "--") == 0)
      break;

    if (!ParseOption(argv[n], &option, &value))
      break;

    // TODO(dje): parsing of boolean options could be better

    if (option == "output-format") {
      if (strcmp(value, "raw") == 0) {
        printer_config->output_format = OutputFormat::kRaw;
      } else if (strcmp(value, "calls") == 0) {
        printer_config->output_format = OutputFormat::kCalls;
      } else if (strcmp(value, "chrome") == 0) {
        printer_config->output_format = OutputFormat::kChrome;
      } else {
        FTL_LOG(ERROR) << "Bad value for --output-format: " << value;
        return -1;
      }
      continue;
    }

    if (option == "output-file") {
      printer_config->output_file_name = value;
      continue;
    }

    if (option == "time") {
      if (strcmp(value, "abs") == 0) {
        printer_config->abstime = true;
      } else if (strcmp(value, "rel") == 0) {
        printer_config->abstime = false;
      } else {
        FTL_LOG(ERROR) << "Bad value for --time: " << value;
        return -1;
      }
      continue;
    }

    if (option == "elf") {
      if (strlen(value) == 0) {
        FTL_LOG(ERROR) << "Empty ELF file name";
        return -1;
      }
      decoder_config->elf_file_names.push_back(value);
      continue;
    }

    if (option == "pt") {
      if (strlen(value) == 0) {
        FTL_LOG(ERROR) << "Empty PT file name";
        return -1;
      }
      if (decoder_config->pt_file_name != "" ||
          decoder_config->pt_list_file_name != "") {
        FTL_LOG(ERROR) << "Only one of --pt/--pt-list supported";
        return -1;
      }
      decoder_config->pt_file_name = value;
      continue;
    }

    if (option == "pt-list") {
      if (strlen(value) == 0) {
        FTL_LOG(ERROR) << "Empty PT-list file name";
        return -1;
      }
      if (decoder_config->pt_file_name != "" ||
          decoder_config->pt_list_file_name != "") {
        FTL_LOG(ERROR) << "Only one of --pt/--pt-list supported";
        return -1;
      }
      decoder_config->pt_list_file_name = value;
      continue;
    }

    if (option == "pc") {
      printer_config->dump_pc = true;
      continue;
    }

    if (option == "insn") {
      printer_config->dump_insn = true;
      continue;
    }

#if 0 // TODO(dje): needs more debugging
    if (option == "loop") {
      printer_config->detect_loop = true;
      continue;
    }
#endif

    if (option == "report-lost") {
      printer_config->report_lost_mtc_cyc = true;
      continue;
    }

    if (option == "id") {
      if (!ftl::StringToNumberWithError<uint32_t>(ftl::StringView(value),
                                                  &printer_config->id,
                                                  ftl::Base::k16)) {
        FTL_LOG(ERROR) << "Not a hex number: " << value;
        return -1;
      }
      continue;
    }

    if (option == "view") {
      if (strcmp(value, "cpu") == 0) {
        printer_config->view = OutputView::kCpu;
      } else if (strcmp(value, "process") == 0) {
        printer_config->view = OutputView::kProcess;
      } else {
        FTL_LOG(ERROR) << "Bad value for --view: " << value;
        return -1;
      }
      continue;
    }

    if (option == "tsc") {
      decoder_config->use_tsc_time = true;
      continue;
    }

    if (option == "kernel") {
      if (strlen(value) == 0) {
        FTL_LOG(ERROR) << "Empty kernel file name";
        return -1;
      }
      decoder_config->kernel_file_name = value;
      continue;
    }

    if (option == "kernel-cr3") {
      if (!ftl::StringToNumberWithError<uint64_t>(ftl::StringView(value),
                                                  &decoder_config->kernel_cr3,
                                                  ftl::Base::k16)) {
        FTL_LOG(ERROR) << "Not a valid cr3 number: " << value;
        return -1;
      }
      continue;
    }

    if (option == "cpuid") {
      if (strlen(value) == 0) {
        FTL_LOG(ERROR) << "Empty cpuid file name";
        return -1;
      }
      decoder_config->cpuid_file_name = value;
      continue;
    }

    if (option == "ids") {
      if (strlen(value) == 0) {
        FTL_LOG(ERROR) << "Empty ids file name";
        return -1;
      }
      decoder_config->ids_file_names.push_back(value);
      continue;
    }

    if (option == "ktrace") {
      if (strlen(value) == 0) {
        FTL_LOG(ERROR) << "Empty ktrace file name";
        return -1;
      }
      decoder_config->ktrace_file_name = value;
      continue;
    }

    if (option == "map") {
      if (strlen(value) == 0) {
        FTL_LOG(ERROR) << "Empty map file name";
        return -1;
      }
      decoder_config->map_file_names.push_back(value);
      continue;
    }

    if (option == "verbose") {
      // already processed by ftl::SetLogSettingsFromCommandLine
      continue;
    }

    FTL_LOG(ERROR) << "Unrecognized option: " << option;
    return -1;
  }

  if (n < argc && strcmp(argv[n], "--") == 0)
    ++n;

  if (decoder_config->pt_file_name == "" &&
      decoder_config->pt_list_file_name == "") {
    FTL_LOG(ERROR) << "One of --pt=FILE, --pt-list=FILE must be specified";
    return -1;
  }
  if (decoder_config->cpuid_file_name == "") {
    FTL_LOG(ERROR) << "--cpuid=FILE must be specified";
    return -1;
  }
  if (decoder_config->ktrace_file_name == "") {
    FTL_LOG(ERROR) << "--ktrace=FILE must be specified";
    return -1;
  }
#if 0 // TODO(dje): still needed?
  if (decoder_config->ids_file_names.size() == 0) {
    FTL_LOG(ERROR) << "--ids=FILE must be specified";
    return -1;
  }
  if (decoder_config->map_file_names.size() == 0) {
    FTL_LOG(ERROR) << "--map=FILE must be specified";
    return -1;
  }
#endif

  return n;
}

int main(int argc, char** argv)
{
  ftl::CommandLine cl = ftl::CommandLineFromArgcArgv(argc, argv);
  if (!ftl::SetLogSettingsFromCommandLine(cl))
    return EXIT_FAILURE;

  if (cl.HasOption("help")) {
    Usage(stdout);
    return EXIT_SUCCESS;
  }

  DecoderConfig decoder_config;
  PrinterConfig printer_config;
  int n = ParseArgv(argc, argv, &decoder_config, &printer_config);
  if (n < 0)
    return EXIT_FAILURE;

  if (n != argc) {
    FTL_LOG(ERROR) << "No positional parameters";
    return EXIT_FAILURE;
  }

  ftl::Stopwatch stop_watch;
  stop_watch.Start();

  auto decoder = DecoderState::Create(decoder_config);
  if (!decoder) {
    FTL_LOG(ERROR) << "Error creating decoder";
    return EXIT_FAILURE;
  }

  uint64_t total_insns;
  if (printer_config.output_format == OutputFormat::kCalls) {
    auto printer = PrettyPrinter::Create(decoder.get(), printer_config);
    if (!printer) {
      FTL_LOG(ERROR) << "Error creating printer";
      return EXIT_FAILURE;
    }
    total_insns = printer->PrintFiles();
  } else if (printer_config.output_format == OutputFormat::kChrome) {
    auto printer = ChromePrinter::Create(decoder.get(), printer_config);
    if (!printer) {
      FTL_LOG(ERROR) << "Error creating printer";
      return EXIT_FAILURE;
    }
    total_insns = printer->PrintFiles();
  } else { // TODO(dje): RAW
    FTL_LOG(ERROR) << "Invalid output format\n";
    return EXIT_FAILURE;
  }

  ftl::TimeDelta delta = stop_watch.Elapsed();
  int64_t seconds = delta.ToSeconds();
  int milliseconds = delta.ToMilliseconds() % 1000;
  FTL_LOG(INFO) << ftl::StringPrintf(
    "%" PRIu64 " insns processed in %" PRId64 ".%03d seconds\n",
    total_insns, seconds, milliseconds);

  return EXIT_SUCCESS;
}
