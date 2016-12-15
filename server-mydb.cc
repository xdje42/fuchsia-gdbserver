// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "server-mydb.h"

#include <array>
#include <cinttypes>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_printf.h"

#include "readline.h"
#include "util.h"

static const char kDefaultPrompt[] = "mydb> ";

namespace debugserver {

MydbServer::MydbServer()
    : command_handler_(this),
      env_(this) {
}

bool MydbServer::Run() {
  FTL_DCHECK(!io_loop_);

#if 0
  // |client_sock_| should be ready to be consumed now.
  // FIXME: We need two descriptors, stdin and stdout.
  // Move client_sock to RspServer?
  FTL_DCHECK(client_sock_.is_valid());
#endif

  util::set_prompt(kDefaultPrompt);

  if (!exception_port_.Run()) {
    FTL_LOG(ERROR) << "Failed to initialize exception port!";
    return false;
  }

  io_loop_ = std::make_unique<MydbIOLoop>(0, 1, this);
  io_loop_->Run();

  // Start the main loop.
  message_loop_.Run();

  FTL_LOG(INFO) << "Main loop exited";

  // Tell the I/O loop to quit its message loop and wait for it to finish.
  io_loop_->Quit();

  // Tell the exception port to quit and wait for it to finish.
  exception_port_.Quit();

  return run_status_;
}

void MydbServer::PostReadTask() {
  FTL_DCHECK(io_loop_);

  // Queue this via the message loop (which then queues the request via
  // the write loop) so that all command output gets printed first.
  message_loop_.task_runner()->PostTask([ this ] {
    io_loop_->PostReadAfterWritesTask();
  });
}

void MydbServer::PostWriteTask(const ftl::StringView& text) {
  FTL_DCHECK(io_loop_);

  // Copy the text into a std::string to capture it in the closure.
  message_loop_.task_runner()->PostTask(
    [ this, text = text.ToString() ] {
      io_loop_->PostWriteTask(ftl::StringView(text.data(), text.size()));
    });
}

void MydbServer::SetCurrentThread(Thread* thread) {
  if (thread) {
    std::string prompt =
      ftl::StringPrintf("%" PRId64 " %s", thread->id(), kDefaultPrompt);
    util::set_prompt(prompt);
  } else {
    util::set_prompt(kDefaultPrompt);
  }

  // Now forward on to baseclass.
  Server::SetCurrentThread(thread);
}

void MydbServer::OnBytesRead(const ftl::StringView& bytes_read) {
  command_handler_.Invoke(bytes_read, env_);
}

void MydbServer::OnDisconnected() {
  if (!quit_called()) {
    FTL_LOG(INFO) << "Client disconnected";
    // Exit successfully in the case of a remote disconnect.
    QuitMessageLoop(true);
  }
}

void MydbServer::OnIOError() {
  if (!quit_called()) {
    FTL_LOG(ERROR) << "An I/O error has occurred. Exiting the main loop.";
    QuitMessageLoop(false);
  }
}

void MydbServer::OnThreadStarted(Process* process,
                             Thread* thread,
                             const mx_exception_context_t& context) {
  FTL_DCHECK(process);

  PrintException(process, thread, MX_EXCP_START, context);

  switch (process->state()) {
  case Process::State::kStarting:
  case Process::State::kRunning:
    break;
  default:
    FTL_DCHECK(false);
  }
}

void MydbServer::OnProcessOrThreadExited(Process* process,
                                     Thread* thread,
                                     const mx_excp_type_t type,
                                     const mx_exception_context_t& context) {
  // If the process is gone, unset current thread.
  if (!thread)
    SetCurrentThread(nullptr);
  PrintException(process, thread, type, context);
}

void MydbServer::OnArchitecturalException(Process* process,
                                      Thread* thread,
                                      const mx_excp_type_t type,
                                      const mx_exception_context_t& context) {
  FTL_DCHECK(process);
  FTL_DCHECK(thread);
  // TODO(armansito): Fine-tune this check if we ever support multi-processing.
  FTL_DCHECK(process == current_process());

  PrintException(process, thread, type, context);
}

void MydbServer::PrintException(Process* process, Thread* thread,
                                mx_excp_type_t type,
                                const mx_exception_context_t& context) {
  if (MX_EXCP_IS_ARCH(type)) {
    printf("Thread %s received exception %s\n",
           thread->GetDebugName().c_str(),
           util::ExceptionToString(type, context).c_str());
    printf("PC 0x%" PRIxPTR "\n", context.arch.pc);
  } else {
    switch (type) {
    case MX_EXCP_START:
      printf("Thread %s started\n", thread->GetDebugName().c_str());
      break;
    case MX_EXCP_GONE:
      if (thread)
        printf("Thread %s exited\n", thread->GetDebugName().c_str());
      else
        printf("Process %s exited, rc %d\n",
               process->GetName().c_str(), process->ExitCode());
      break;
    default:
      break;
    }
  }
}

}  // namespace debugserver
