// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <array>
#include <atomic>
#include <memory>
#include <queue>

#include "lib/ftl/files/unique_fd.h"
#include "lib/ftl/macros.h"
#include "lib/ftl/strings/string_view.h"
#include "lib/mtl/tasks/message_loop.h"

#include "command-handler.h"
#include "exception-port.h"
#include "io-loop.h"
#include "process.h"
#include "thread.h"

namespace debugserver {

// Server implements the main loop and handles commands.
//
// NOTE: This class is generally not thread safe. Care must be taken when
// calling methods such as SetCurrentThread(), and QueueNotification() which
// modify the internal state of a Server instance.
class Server : public IOLoop::Delegate, public Process::Delegate {
 public:
  Server();
  ~Server();

  // Starts the main loop.
  // Returns when the main loop exits (e.g. due to a closed client connection).
  // Returns true if the main loop exits cleanly, or false in the case of an
  // error.
  // TODO(armansito): More clearly define the error scenario.
  // TODO(dje): This mightn't need to be virtual, but it provides consistency
  // among the uses.
  virtual bool Run() = 0;

  // Returns a raw pointer to the current inferior. The instance pointed to by
  // the returned pointer is owned by this Server instance and should not be
  // deleted.
  Process* current_process() const { return current_process_.get(); }

  // Sets the current process. This cleans up the current process (if any) and
  // takes ownership of |process|.
  void set_current_process(Process* process) {
    current_process_.reset(process);
  }

  // Returns a raw pointer to the current thread.
  Thread* current_thread() const { return current_thread_.get(); }

  // Assigns the current thread.
  // This is virtual to allow the interactive debugger to update the prompt.
  virtual void SetCurrentThread(Thread* thread);

  // Returns a mutable reference to the main message loop. The returned instance
  // is owned by this Server instance and should not be deleted.
  mtl::MessageLoop* message_loop() { return &message_loop_; }

  // Returns a mutable reference to the exception port. The returned instance is
  // owned by this Server instance and should not be deleted.
  ExceptionPort* exception_port() { return &exception_port_; }

  // Call this to schedule termination of gdbserver.
  // Any outstanding messages will be sent first.
  // N.B. The Server will exit its main loop asynchronously so any
  // subsequently posted tasks will be dropped.
  void PostQuitMessageLoop(bool status);

  // Return true if the i/o loop is shutting down.
  bool quit_called() { return io_loop_->quit_called(); }

 protected:
  // Sets the run status and quits the main message loop.
  void QuitMessageLoop(bool status);

  // The current thread under debug. We only keep a weak pointer here, since the
  // instance itself is owned by a Process and may get removed.
  ftl::WeakPtr<Thread> current_thread_;

  // The main loop.
  mtl::MessageLoop message_loop_;

  // The IOLoop used for blocking I/O operations over |client_sock_|.
  // |message_loop_| and |client_sock_| both MUST outlive |io_loop_|. We take
  // care to clean it up in the destructor.
  std::unique_ptr<IOLoop> io_loop_;

  // File descriptors for the sockets (or terminal) used for communication.
  // TODO(dje): Rename from *sock* after things are working.
  ftl::UniqueFD client_sock_;

  // The ExceptionPort used by inferiors to receive exceptions.
  // (This is declared after |message_loop_| since that needs to have been
  // created before this can be initialized).
  ExceptionPort exception_port_;

  // Strong pointer to the current inferior process that is being debugged.
  // NOTE: This must be declared after |exception_port_| above, since the
  // process may do work in its destructor to detach itself from the
  // |exception_port_|.
  std::unique_ptr<Process> current_process_;

  // Stores the global error state. This is used to determine the return value
  // for "Run()" when |message_loop_| exits.
  bool run_status_;

  FTL_DISALLOW_COPY_AND_ASSIGN(Server);
};

}  // namespace debugserver
