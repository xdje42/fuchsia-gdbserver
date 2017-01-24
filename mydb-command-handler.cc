// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Near term TODO(dje):
// - info registers
// - info threads
// - set current thread
// - thread apply all
// - set args
// - x - examine memory
// - attach/detach
// - breakpoints
// - run inferior in different tty

#include "mydb-command-handler.h"

#include <cinttypes>
#include <string>

#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_number_conversions.h"
#include "lib/ftl/strings/string_printf.h"

#include "backtrace.h"
#include "readline.h"
#include "registers.h"
#include "server-mydb.h"
#include "thread.h"
#include "util.h"

namespace debugserver {
namespace mydb {

// How much memory to dump, in bytes.
// Space for this is allocated on the stack, so this can't be too large.
constexpr size_t kMemoryDumpSize = 256;

static void help_command(const util::Argv& argv, const CommandEnvironment& env) {
  if (argv.size() == 1) {
    for (auto c : env.commands()) {
      env.Print(ftl::StringPrintf("%10s %s\n", c->name, c->short_help));
    }
  } else {
      const Command* c = env.LookupCommand(argv[1]);
      if (c != nullptr) {
        if (c->long_help) {
          env.Print(ftl::StringPrintf("%10s %s\n\n%s\n", c->name, c->short_help, c->long_help));
        } else {
          env.Print(ftl::StringPrintf("%10s %s\n", c->name, c->short_help));
        }
      } else {
        env.Print(ftl::StringPrintf("Unknown command: %s\n", argv[1].c_str()));
      }
  }
}

const Command help_cmd = {
  "help",
  "Print list of commands",
  "To display help for a particular command use \"help <command>\".",
  help_command
};

const Command h_cmd = {
  "h",
  "An alias of the help command",
  nullptr,
  help_command
};

static void file_command(const util::Argv& argv, const CommandEnvironment& env) {
  if (argv.size() < 2) {
    env.Print("Usage: file /program/path [args...]\n");
    return;
  }

  Process* process = env.server()->current_process();
  if (!process) {
    // TODO(dje): This shouldn't currently happen, but will
    // need to support it in time.
    env.Print("No current process to run");
    return;
  }

  switch (process->state()) {
  case Process::State::kNew:
  case Process::State::kGone:
    break;
  default:
    env.Print("Current program still running\n");
    return;
  }

  process->set_argv(util::Argv(argv.begin() + 1, argv.end()));
}

const Command file_cmd = {
  "file",
  "Select the program to debug",
  "Usage: file /program/path [args...]",
  file_command
};

static void backtrace_command(const util::Argv& argv, const CommandEnvironment& env) {
  Thread* thread = env.server()->current_thread();
  if (!thread) {
    env.Print("No current thread to backtrace\n");
    return;
  }

  arch::Registers* regs = thread->registers();
  if (!regs->RefreshGeneralRegisters()) {
    env.Print("Unable to read registers\n");
    return;
  }

  mx_vaddr_t pc = regs->GetPC();
  mx_vaddr_t sp = regs->GetSP();
  mx_vaddr_t fp = regs->GetFP();

  backtrace(thread, env, pc, sp, fp, true);
}

const Command backtrace_cmd = {
  "backtrace",
  "Print a backtrace for the current thread",
  nullptr,
  backtrace_command
};

const Command bt_cmd = {
  "bt",
  "An alias for the backtrace command",
  nullptr,
  backtrace_command
};

static void run_command(const util::Argv& argv, const CommandEnvironment& env) {
  Process* process = env.server()->current_process();
  if (!process) {
    // This can't happen today, but it might eventually.
    env.Print("No current process to run");
    return;
  }

  const util::Argv& current_argv = process->argv();
  if (current_argv.size() == 0) {
    env.Print("No program specified\n");
    return;
  }
  if (argv.size() > 1) {
    util::Argv new_argv = argv;
    // Replace argv[0] ("run") with program path.
    new_argv[0] = current_argv[0];
    process->set_argv(new_argv);
  }

  switch (process->state()) {
  case Process::State::kNew:
  case Process::State::kGone:
    break;
  default:
    // TODO(dje): Kill currently running process first.
    env.Print("Unable to start new process,"
              " current process is still running\n");
    return;
  }

  if (!process->Initialize()) {
    env.Print("Failed to set up inferior\n");
    return;
  }

  FTL_DCHECK(!process->IsAttached());
  if (!process->Attach()) {
    env.Print("Failed to attach to process\n");
    return;
  }
  FTL_DCHECK(process->IsAttached());

  // On Linux, the program is considered "live" after vRun, e.g. $pc is set. On
  // Magenta, calling mx_process_start (called by launchpad_start, which is
  // called by Process::Start()) creates a synthetic exception of type
  // MX_EXCP_START if a debugger is attached to the process and halts until a
  // call to mx_task_resume (i.e. called by Thread::Resume() in gdbserver).
  if (!process->Start()) {
    env.Print("Failed to start process\n");
    return;
  }

  FTL_DCHECK(process->started());
}

const Command run_cmd = {
  "run",
  "Run the program",
  "If args are provided, they are passed to the program.\n"
  "If args are not provided, the previous set of args are used.",
  // TODO(dje): Provide a way to reset args to the empty list.
  run_command
};

const Command r_cmd = {
  "r",
  "An alias for the run command",
  nullptr,
  run_command
};

static void continue_command(const util::Argv& argv, const CommandEnvironment& env) {
  bool all = false;
  if (argv.size() == 2 && argv[1] == "-a") {
    all = true;
  } else if (argv.size() != 1) {
    env.Print("Usage: continue [-a]\n");
    return;
  }

  Process* process = env.server()->current_process();
  if (!process) {
    // This can't happen today, but it might eventually.
    env.Print("No current process to resume");
    return;
  }

  if (!process->IsAttached() ||
      !process->started()) {
    env.Print("Process is not running\n");
    return;
  }

  Thread* thread = env.server()->current_thread();
  if (!all && !thread) {
    env.Print("No current thread to resume\n");
    return;
  }

  if (!all) {
    FTL_DCHECK(thread);
    FTL_DCHECK(process == thread->process());
    switch (thread->state()) {
    case Thread::State::kNew:
    case Thread::State::kStopped:
      FTL_VLOG(1) << "Continuing thread " << thread->GetDebugName() << " state: "
                  << thread->StateName(thread->state());
      thread->Resume();
      break;
    default:
      env.Print(ftl::StringPrintf("Can't resume thread in state \"%s\"\n",
                                  thread->StateName(thread->state())));
      break;
    }
  } else {
    process->ForEachThread([](Thread* thread) {
      switch (thread->state()) {
      case Thread::State::kNew:
      case Thread::State::kStopped:
        FTL_VLOG(1) << "Continuing thread " << thread->GetDebugName() << " state: "
                    << thread->StateName(thread->state());
        thread->Resume();
        break;
      default:
        break;
      }
    });
  }
}

const Command continue_cmd = {
  "continue",
  "Resume the current thread from where it left off",
  "Usage: continue [-a]\n"
  "If \"-a\" is specified, resume all stopped threads.",
  continue_command
};

const Command c_cmd = {
  "c",
  "An alias for the continue command",
  nullptr,
  continue_command
};

static void stepi_command(const util::Argv& argv, const CommandEnvironment& env) {
  Thread* thread = env.server()->current_thread();
  if (!thread) {
    env.Print("No current thread to resume\n");
    return;
  }

  Process* process = thread->process();
  // If there's a current thread these should be true.
  // TODO(dje): I think.
  FTL_DCHECK(process->IsAttached());
  FTL_DCHECK(process->started());

  switch (thread->state()) {
  case Thread::State::kStopped:
    FTL_VLOG(1) << "Stepping thread " << thread->GetDebugName() << " state: "
                << thread->StateName(thread->state());
    thread->Step();
    break;
  default:
    env.Print(ftl::StringPrintf("Can't step thread in state \"%s\"\n",
                                thread->StateName(thread->state())));
    break;
  }
}

const Command stepi_cmd = {
  "stepi",
  "Step the current thread one instruction",
  nullptr,
  stepi_command
};

const Command si_cmd = {
  "si",
  "An alias for the stepi command",
  nullptr,
  stepi_command
};

static void quit_command(const util::Argv& argv, const CommandEnvironment& env) {
  env.server()->PostQuitMessageLoop(true);
}

const Command quit_cmd = {
  "quit",
  "Quit mydb",
  nullptr,
  quit_command
};

const Command q_cmd = {
  "q",
  "An alias for the quit command",
  nullptr,
  quit_command
};

static void dumpthread_command(const util::Argv& argv, const CommandEnvironment& env) {
  Thread* thread = env.server()->current_thread();
  if (!thread) {
    env.Print("No current thread\n");
    return;
  }

  Process* process = thread->process();

  // info registers

  env.Print("Registers:\n");

  arch::Registers* regs = thread->registers();
  if (!regs->RefreshGeneralRegisters()) {
    env.Print("Unable to read registers\n");
    return;
  }

  std::string gregs = regs->FormatRegset(0);
  env.Print(gregs);

  mx_vaddr_t pc = regs->GetPC();
  mx_vaddr_t sp = regs->GetSP();
  mx_vaddr_t fp = regs->GetFP();

  // x/32gx $sp

  env.Print("Bottom of user stack:\n");

  size_t len = kMemoryDumpSize;
  uint8_t buf[len];
  auto res = mx_process_read_memory(process->handle(), sp, buf, len, &len);
  if (res < 0) {
    env.Print(ftl::StringPrintf("Failed reading %p memory; error: %d\n", (void*)sp, res));
  } else if (len != 0) {
    util::hexdump_ex(buf, len, sp);
  }

  // info sharedlibraries

  env.Print("Shared libraries:\n");
  if (!process->DsosLoaded())
    process->TryBuildLoadedDsosList();
  elf::dsoinfo_t* dso_list = process->GetDsos();
  if (dso_list) {
    elf::dso_print_list(dso_list);
  } else {
    env.Print("*** Unable to obtain shared library list. ***\n");
    env.Print("*** Backtrace may be incomplete.          ***\n");
  }

  // backtrace

  env.Print("Backtrace:\n");
  backtrace(thread, env, pc, sp, fp, true);
}

const Command dumpthread_cmd = {
  "dumpthread",
  "Print various information about a thread",
  "This command is essentially a wrapper of 4 gdb commands:\n"
  "info registers\n"
  "x/32gx $sp\n"
  "info sharedlibraries\n"
  "backtrace",
  dumpthread_command
};

const Command dt_cmd = {
  "dt",
  "An alias for the dumpthread command",
  nullptr,
  dumpthread_command
};

static void it_command(const util::Argv& argv, const CommandEnvironment& env) {
  Process* process = env.server()->current_process();
  if (!process) {
    // This can't happen today, but it might eventually.
    env.Print("No current process");
    return;
  }

  env.Print("Threads:\n");
  Thread* current_thread = env.server()->current_thread();
  int ordinal = 1;
  process->ForEachThread([env = &env,
                          ordinal = &ordinal,
                          current_thread](Thread* thread) {
    env->Print(ftl::StringPrintf("%c#%-3d %12s %s\n",
                                 thread == current_thread ? '*' : ' ',
                                 *ordinal,
                                 thread->GetName().c_str(),
                                 thread->StateName(thread->state())));
    ++*ordinal;
  });
}

const Command it_cmd = {
  "it",
  "Print info of all threads",
  nullptr,
  it_command
};

static void t_command(const util::Argv& argv, const CommandEnvironment& env) {
  if (argv.size() != 2) {
    env.Print("Usage: t koid\n");
    return;
  }

  Process* process = env.server()->current_process();
  if (!process) {
    // This can't happen today, but it might eventually.
    env.Print("No current process");
    return;
  }

  const std::string& id = argv[1];
  mx_koid_t koid;
  if (!ftl::StringToNumberWithError<mx_koid_t>(id, &koid)) {
    env.Print("Invalid thread koid\n");
    return;
  }
  Thread* thread = process->FindThreadById(koid);
  if (!thread) {
    env.Print("Invalid thread\n");
    return;
  }

  env.server()->SetCurrentThread(thread);
}

const Command t_cmd = {
  "t",
  "Set the current thread",
  "Usage: t <thread-koid>\n"
  "Use the \"it\" command to get the list of threads.",
  t_command
};

static void v_command(const util::Argv& argv, const CommandEnvironment& env) {
  if (argv.size() == 1) {
    ftl::LogSettings settings = ftl::GetLogSettings();
    env.Print(ftl::StringPrintf("Current verbosity level is %d\n",
                                (int) settings.min_log_level));
    return;
  }

  if (argv.size() != 2) {
    env.Print("Usage: v [level]\n");
    return;
  }

  int level;
  if (!ftl::StringToNumberWithError<int>(argv[1], &level)) {
    env.Print("Invalid verbosity level\n");
    return;
  }

  ftl::LogSettings settings = ftl::GetLogSettings();
  settings.min_log_level = level;
  ftl::SetLogSettings(settings);
}

const Command v_cmd = {
  "v",
  "Set verbosity level",
  "Usage: v [level]\n"
  "Log levels:\n"
  "-n = verbosity level n\n"
  "-1 = verbosity level 1\n"
  " 0 = INFO\n"
  " 1 = WARNING\n"
  " 2 = ERROR\n"
  " 3 = FATAL\n"
  "If no level is provided, the current level is printed.",
  v_command
};

static void invalid_command(const util::Argv& argv, const CommandEnvironment& env) {
  env.Print(ftl::StringPrintf("Invalid command: %s\n", argv[0].c_str()));
}

const Command invalid_cmd = {
  "invalid",
  "Internal command handler for invalid commands",
  nullptr,
  invalid_command
};

CommandEnvironment::CommandEnvironment(MydbServer* server)
    : server_(server) {
}

const Command* CommandEnvironment::LookupCommand(const ftl::StringView& name) const {
  return server_->command_handler().Lookup(name);
}

void CommandEnvironment::Print(const ftl::StringView& text) const {
  server_->PostWriteTask(text);
}

const std::vector<const Command*>& CommandEnvironment::commands() const {
  return server_->command_handler().commands();
}

CommandHandler::CommandHandler(MydbServer* server)
    : server_(server) {
  FTL_DCHECK(server_);

  Add(&backtrace_cmd);
  Add(&bt_cmd);
  Add(&continue_cmd);
  Add(&c_cmd);
  Add(&dumpthread_cmd);
  Add(&dt_cmd);
  Add(&file_cmd);
  Add(&help_cmd);
  Add(&h_cmd);
  Add(&it_cmd);
  Add(&quit_cmd);
  Add(&q_cmd);
  Add(&run_cmd);
  Add(&r_cmd);
  Add(&stepi_cmd);
  Add(&si_cmd);
  Add(&t_cmd);
  Add(&v_cmd);
}

void CommandHandler::Invoke(const ftl::StringView& command, const CommandEnvironment& env) {
  FTL_VLOG(2) << "Command: " << command;

  util::Argv argv;
  if (command.size() == 0) {
    ftl::StringView line = util::get_history(0);
    if (line.size() == 0)
      return;
    argv = util::BuildArgv(line);
  } else {
    argv = util::BuildArgv(command);
  }

  const Command* c = Lookup(argv[0]);
  if (!c)
    c = &invalid_cmd;
  FTL_VLOG(2) << "Found command: " << c->name;
  (*c->invoker)(argv, env);

  // The command has completed so ask for the next command.
  // For commands that resume the inferior this is like
  // always adding '&' to the end of the command.
  env.server()->PostReadTask();
}

void CommandHandler::Add(const Command* c) {
  commands_.push_back(c);
}

const Command* CommandHandler::Lookup(const ftl::StringView& name) const {
  for (auto c : commands_) {
    if (name == ftl::StringView(c->name))
      return c;
  }
  return nullptr;
}

}  // namespace mydb
}  // namespace debugserver
