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
#include "lib/mtl/handles/object_info.h"

#include "process.h"
#include "server-rsp.h"

namespace {

constexpr char kUsageString[] =
    "Usage: debugserver [options] port [program [args...]]\n"
    "\n"
    "  port    - TCP port\n"
    "  program - the path to the executable to run\n"
    "\n"
    "e.g. debugserver 2345 /path/to/executable\n"
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
  if (cl.positional_args().size() < 1) {
    PrintUsageString();
    return EXIT_FAILURE;
  }

  if (!ftl::SetLogSettingsFromCommandLine(cl))
    return EXIT_FAILURE;

  uint16_t port;
  if (!ftl::StringToNumberWithError<uint16_t>(cl.positional_args()[0], &port)) {
    FTL_LOG(ERROR) << "Not a valid port number: " << cl.positional_args()[0];
    return EXIT_FAILURE;
  }

  FTL_LOG(INFO) << "Starting server.";

  // Give this thread an identifiable name for debugging purposes.
  mtl::SetCurrentThreadName("server (main)");

  debugserver::RspServer server(port);

  std::vector<std::string> inferior_argv(cl.positional_args().begin() + 1,
                                         cl.positional_args().end());
  auto inferior = new debugserver::Process(&server, &server, inferior_argv);

  // It's simpler to set the current process here since we don't support
  // multiple processes yet. The process is not live yet however, it does not
  // exist to the kernel yet. Calling Process::Initialize() is left to the
  // vRun command.
  server.set_current_process(inferior);

  bool status = server.Run();
  if (!status) {
    FTL_LOG(ERROR) << "Server exited with error";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
