// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <atomic>
#include <thread>

#include "lib/ftl/macros.h"
#include "lib/ftl/memory/ref_ptr.h"
#include "lib/ftl/strings/string_view.h"
#include "lib/ftl/tasks/task_runner.h"

namespace debugserver {

// Maintains dedicated threads for reads and writes on given file
// descriptors and allows read and write tasks to be scheduled from a single
// origin thread.
//
// This class is thread-safe as long as all the public methods are accessed from
// the thread that initialized this instance.
//
// TODO(armansito): This is a temporary solution until there is a
// mxio_get_handle (or equivalent) interface to get a mx_handle_t from socket
// fd to use with mtl::MessageLoop::AddHandler. That way we can avoid blocking
// reads and writes while also using a single thread. Then again this works fine
// too.
class IOLoop {
 public:
  // Delegate class for receiving asynchronous events for the result of
  // read/write operations. All operations will be posted on the MessageLoop of
  // the thread on which the IOLoop object was created.
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Called when new bytes have been read from the socket.
    virtual void OnBytesRead(const ftl::StringView& bytes_read) = 0;

    // Called when the remote end closes the TCP connection.
    virtual void OnDisconnected() = 0;

    // Called when there is an error in either the read or write tasks.
    virtual void OnIOError() = 0;
  };

  // Does not take ownership of any of the parameters. Care should be taken to
  // make sure that |delegate| and |in_fd,out_fd| outlive this object.
  IOLoop(int in_fd, int out_fd, Delegate* delegate);

  // The destructor calls Quit() and thus it may block.
  virtual ~IOLoop();

  // Initializes the underlying threads and message loops and runs them.
  void Run();

  // Quits the underlying message loops and block until the underlying threads
  // complete their tasks and join. Since the threads do blocking work
  // (read/write) this may block until either pending read and/or write returns.
  void Quit();

  // Called while quitting to unblock any i/o task.
  void UnblockIO();

  // Helper method for PostReadTask, only called from the read thread.
   // Process one read request.
  void OnReadTask();

  // Posts an asynchronous task on to listen for an incoming request (e.g.,
  // packet or command line).
  // Subsequent read tasks are automatically posted if ReadTask returns true.
  // Otherwise PostReadTask must be called again.
  // Called from Run() to start the first read task.
  void PostReadTask();

  // Posts an asynchronous task on the message loop to send a packet.
  void PostWriteTask(const ftl::StringView& bytes);

  // Post a read task after all currently posted writes have completed.
  void PostReadAfterWritesTask();

  bool quit_called() { return quit_called_; }

 protected:
  int in_fd() { return in_fd_; }
  int out_fd() { return out_fd_; }
  Delegate* delegate() { return delegate_; }
  ftl::RefPtr<ftl::TaskRunner>& origin_task_runner() {
    return origin_task_runner_;
  }

  // Notifies the delegate that there has been an I/O error.
  void ReportError();
  void ReportDisconnected();

 private:
  // Read and process one request.
  // Returns true if another task should be posted to read the next request.
  virtual bool ReadTask() = 0;

  // True if Quit() was called. This tells the |read_thread| to terminate its
  // loop as soon as any blocking call to read returns.
  std::atomic_bool quit_called_;

  // The file descriptors.
  // There are separate descriptors for input and output for use by terminal
  // related i/o loops (stdin + stdout). For socket related i/o these
  // descriptors are the same.
  int in_fd_, out_fd_;

  // The delegate that we send I/O events to.
  Delegate* delegate_;

  // True, if Run() has been called.
  bool is_running_;

  // The origin task runner used to post delegate events to the thread that
  // created this object.
  ftl::RefPtr<ftl::TaskRunner> origin_task_runner_;

  // The task runners for the I/O threads.
  ftl::RefPtr<ftl::TaskRunner> read_task_runner_;
  ftl::RefPtr<ftl::TaskRunner> write_task_runner_;

  // The I/O threads.
  std::thread read_thread_;
  std::thread write_thread_;

  FTL_DISALLOW_COPY_AND_ASSIGN(IOLoop);
};

}  // namespace debugserver
