// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include "lib/ftl/macros.h"
#include "lib/ftl/strings/string_view.h"

#include "debug-info-cache.h"
#include "exception-port.h"
#include "io-loop-mydb.h"
#include "mydb-command-handler.h"
#include "process.h"
#include "server.h"
#include "thread.h"

namespace debugserver {

// MydbServer implements the main loop and handles commands received from the
// user.
//
// NOTE: This class is generally not thread safe. Care must be taken when
// calling methods such as SetCurrentThread() which modify the internal state
// of a MydbServer instance.
class MydbServer final : public Server {
 public:
  MydbServer();

  bool Run() override;

  // Posts a request to read the next command.
  // The task is posted via the write task to ensure all currently posted
  // writes complete first.
  void PostReadTask();

  // Posts a task to write text to the terminal.
  void PostWriteTask(const ftl::StringView& text);

  const mydb::CommandHandler& command_handler() const {
    return command_handler_;
  }

  mydb::DebugInfoCache& debug_info_cache() { return debug_info_cache_; }

  // Set the prompt.
  // This adds the current thread's id to the prompt.
  void SetCurrentThread(Thread* thread) override;

 private:
  // IOLoop::Delegate overrides.
  void OnBytesRead(const ftl::StringView& bytes) override;
  void OnDisconnected() override;
  void OnIOError() override;

  // Process::Delegate overrides.
  void OnThreadStarted(Process* process,
                       Thread* thread,
                       const mx_exception_context_t& context) override;
  void OnProcessOrThreadExited(Process* process,
                               Thread* thread,
                               const mx_excp_type_t type,
                               const mx_exception_context_t& context) override;
  void OnArchitecturalException(Process* process,
                                Thread* thread,
                                const mx_excp_type_t type,
                                const mx_exception_context_t& context) override;

  // The CommandHandler that is responsible for interpreting received commands
  // and routing them to the correct handler.
  mydb::CommandHandler command_handler_;

  // Commands can run in various "environments" (or states).
  // This is the global state that is normally used.
  mydb::CommandEnvironment env_;

  // Keep a cache of loaded debug info to maintain some performance
  // without loading debug info for all shared libs.
  mydb::DebugInfoCache debug_info_cache_;

  FTL_DISALLOW_COPY_AND_ASSIGN(MydbServer);
};

}  // namespace debugserver
