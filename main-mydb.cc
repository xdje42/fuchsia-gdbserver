// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "lib/ftl/command_line.h"
#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_number_conversions.h"

#include "server-mydb.h"
#include "process.h"
#include "readline.h"
#include "util.h"

namespace {

constexpr char kUsageString[] =
    "Usage: mydb [options] [program [args...]]\n"
    "\n"
    "  program - the path to the executable to run\n"
    "\n"
    "e.g. mydb /path/to/executable\n"
    "\n"
    "Options:\n"
    "  --help             show this help message\n"
    "  --verbose[=level]  set debug verbosity level\n"
    "  --quiet[=level]    set quietness level (opposite of verbose)\n"
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


void PrintUsageString() {
  std::cout << kUsageString << std::endl;
}

}  // namespace

int main(int argc, char* argv[]) {
  ftl::CommandLine cl = ftl::CommandLineFromArgcArgv(argc, argv);

  if (cl.HasOption("help", nullptr)) {
    PrintUsageString();
    return EXIT_SUCCESS;
  }

  if (!ftl::SetLogSettingsFromCommandLine(cl))
    return EXIT_FAILURE;

  FTL_LOG(INFO) << "Starting mydb.";

  debugserver::MydbServer mydb;

  std::vector<std::string> inferior_argv(cl.positional_args().begin(),
                                         cl.positional_args().end());
  auto inferior = new debugserver::Process(&mydb, &mydb, inferior_argv);

  mydb.set_current_process(inferior);

  auto status = mydb.Run();
  if (!status) {
    FTL_LOG(ERROR) << "Mydb exited with error";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
