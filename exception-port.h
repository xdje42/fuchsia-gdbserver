// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <magenta/syscalls/exception.h>
#include <magenta/types.h>
#include <mx/port.h>

#include "lib/ftl/macros.h"
#include "lib/ftl/memory/ref_ptr.h"
#include "lib/ftl/tasks/task_runner.h"

namespace debugserver {

class Process;
class Thread;

// Maintains a dedicated thread for listening to exceptions from multiple
// processes and provides an interface that processes can use to subscribe to
// exception notifications.
class ExceptionPort final {
 public:
  // A Key is vended as a result of a call to Bind()
  using Key = uint64_t;

  // Handler callback invoked when the kernel reports an exception. For more
  // information about the possible values and fields of the |type| and
  // |context| parameters, see <magenta/syscalls/exception.h>.
  using Callback = std::function<void(const mx_excp_type_t type,
                                      const mx_exception_context_t& context)>;

  ExceptionPort();
  ~ExceptionPort();

  // Creates an exception port and starts waiting for events on it in a special
  // thread. Returns false if there is an error during set up.
  bool Run();

  // Quits the listening loop, closes the exception port and joins the
  // underlying thread. This must be called AFTER a successful call to Run().
  void Quit();

  // Binds an exception port for |process| and associates |callback| with it.
  // The returned key can be used to unbind this process later. On success, a
  // positive Key value will be returned. On failure, 0 will be returned.
  //
  // The |callback| will be posted on the origin thread's message loop, where
  // the origin thread is the thread on which this ExceptionPort instance was
  // created.
  //
  // This must be called AFTER a successful call to Run().
  Key Bind(const Process& process, const Callback& callback);

  // Unbinds a previously bound exception port and returns true on success.
  // This must be called AFTER a successful call to Run().
  bool Unbind(const Key key);

 private:
  struct BindData {
    BindData() = default;
    BindData(mx_handle_t process_handle, const Callback& callback)
        : process_handle(process_handle), callback(callback) {}

    mx_handle_t process_handle;
    Callback callback;
  };

  // Counter used for generating keys.
  static Key g_key_counter;

  // The worker function.
  void Worker();

  // Set to false by Quit(). This tells |io_thread_| whether it should terminate
  // its loop as soon as mx_port_wait returns.
  std::atomic_bool keep_running_;

  // The origin task runner used to post observer callback events to the thread
  // that created this object.
  ftl::RefPtr<ftl::TaskRunner> origin_task_runner_;

  // The exception port handle and a mutex for synchronizing access to it.
  // |io_thread_| only ever reads from |eport_handle_| but a call to Quit() can
  // set it to 0. This can really only happen if Quit() is called before
  // Worker() even runs on the |io_thread_| which is extremely unlikely. But we
  // play safe anyway.
  std::mutex eport_mutex_;
  mx::port eport_handle_;

  // The thread on which we wait on the exception port.
  std::thread io_thread_;

  // All callbacks that are currently bound to this port.
  std::unordered_map<Key, BindData> callbacks_;

  FTL_DISALLOW_COPY_AND_ASSIGN(ExceptionPort);
};

// Print an exception in user-friendly form.
// This doesn't have a better place at the moment.
void PrintException(Process* process, Thread* thread, mx_excp_type_t type,
                    const mx_exception_context_t& context);

}  // namespace debugserver
