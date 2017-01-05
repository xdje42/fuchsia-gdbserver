// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "io-loop.h"

#include <unistd.h>

#include "lib/ftl/logging.h"
#include "lib/mtl/handles/object_info.h"
#include "lib/mtl/tasks/message_loop.h"
#include "lib/mtl/threading/create_thread.h"

#include "util.h"

namespace debugserver {

IOLoop::IOLoop(int in_fd, int out_fd, Delegate* delegate)
    : quit_called_(false),
      in_fd_(in_fd),
      out_fd_(out_fd),
      delegate_(delegate),
      is_running_(false) {
  FTL_DCHECK(in_fd_ >= 0);
  FTL_DCHECK(out_fd_ >= 0);
  FTL_DCHECK(delegate_);
  FTL_DCHECK(mtl::MessageLoop::GetCurrent());

  origin_task_runner_ = mtl::MessageLoop::GetCurrent()->task_runner();
}

IOLoop::~IOLoop() {
  Quit();
}

void IOLoop::Run() {
  FTL_DCHECK(!is_running_);

  is_running_ = true;
  read_thread_ = mtl::CreateThread(&read_task_runner_, "i/o loop read task");
  write_thread_ = mtl::CreateThread(&write_task_runner_, "i/o loop write task");

  // Start the read loop going.
  PostReadTask();
}

void IOLoop::Quit() {
  FTL_DCHECK(is_running_);

  FTL_LOG(INFO) << "Quitting I/O loop";

  quit_called_ = true;

  auto quit_task = [] {
    // Tell the thread-local message loop to quit.
    FTL_DCHECK(mtl::MessageLoop::GetCurrent());
    mtl::MessageLoop::GetCurrent()->QuitNow();
  };
  read_task_runner_->PostTask(quit_task);
  write_task_runner_->PostTask(quit_task);

  if (read_thread_.joinable())
    read_thread_.join();
  if (write_thread_.joinable())
    write_thread_.join();

  FTL_LOG(INFO) << "I/O loop exited";
}

void IOLoop::OnReadTask() {
  FTL_DCHECK(mtl::MessageLoop::GetCurrent()->task_runner().get() ==
             read_task_runner_.get());

  ssize_t read_size = read(fd_, in_buffer_.data(), kMaxBufferSize);

  // 0 bytes means that the remote end closed the TCP connection.
  if (read_size == 0) {
    FTL_VLOG(1) << "Client closed connection";
    ReportDisconnected();
    return;
  }

  // There was an error
  if (read_size < 0) {
    util::LogErrorWithErrno("Error occurred while waiting for a packet");
    ReportError();
    return;
  }

  ftl::StringView bytes_read(in_buffer_.data(), read_size);
  FTL_VLOG(2) << "-> " << util::EscapeNonPrintableString(bytes_read);

  // Notify the delegate that we read some bytes. We copy the buffer data
  // into the closure as |in_buffer_| can get modified before the closure
  // runs.
  // TODO(armansito): Pass a weakptr to |delegate_|?
  origin_task_runner_->PostTask([ bytes_read = bytes_read.ToString(), this ] {
    delegate_->OnBytesRead(bytes_read);
  });

  if (!quit_called_)
    read_task_runner_->PostTask(std::bind(&IOLoop::OnReadTask, this));
}

void IOLoop::StartReadLoop() {
  // Make sure the call is coming from the origin thread.
  FTL_DCHECK(mtl::MessageLoop::GetCurrent()->task_runner().get() ==
             origin_task_runner_.get());
  read_task_runner_->PostTask(std::bind(&IOLoop::OnReadTask, this));
}

void IOLoop::UnblockIO() {
  close(in_fd_);
  in_fd_ = -1;
}

void IOLoop::OnReadTask() {
  bool another = ReadTask();

  if (another && !quit_called_)
    read_task_runner_->PostTask(std::bind(&IOLoop::OnReadTask, this));
}

void IOLoop::PostReadTask() {
  // Make sure the call is coming from the origin thread.
  FTL_DCHECK(mtl::MessageLoop::GetCurrent()->task_runner().get() ==
             origin_task_runner_.get());

  // TODO(armansito): Pass a refptr/weakptr to |this|?
  ftl::Closure read_task = [this, &read_task] {
    bool another = ReadTask();

    if (another && !quit_called_)
      read_task_runner_->PostTask(read_task);
  };

  read_task_runner_->PostTask(std::bind(&IOLoop::OnReadTask, this));
}

void IOLoop::PostWriteTask(const ftl::StringView& bytes) {
  // We copy the data into the closure.
  // TODO(armansito): Pass a refptr/weaktpr to |this|?
  write_task_runner_->PostTask([ this, bytes = bytes.ToString() ] {
    // Short writes can happen, so keep looping until it's all written.
    size_t count = bytes.size();
    const char* data = bytes.data();
    while (count > 0) {
      ssize_t bytes_written = write(out_fd_, data, count);
      if (bytes_written <= 0) {
        util::LogErrorWithErrno("Failed to send bytes");
        ReportError();
        return;
      }
      data += bytes_written;
      count -= bytes_written;
    }
    FTL_VLOG(2) << "<- " << util::EscapeNonPrintableString(bytes);
  });
}

void IOLoop::PostReadAfterWritesTask() {
  write_task_runner_->PostTask([ this ] {
    // TODO(armansito): Pass a refptr/weakptr to |this|?
    ftl::Closure read_task = [this, &read_task] {
      bool another = ReadTask();

      if (another && !quit_called_)
        read_task_runner_->PostTask(read_task);
    };

    read_task_runner_->PostTask(read_task);
  });
}

void IOLoop::ReportError() {
  // TODO(armansito): Pass a refptr/weakptr to |this|?
  origin_task_runner_->PostTask([this] { delegate_->OnIOError(); });
}

void IOLoop::ReportDisconnected() {
  // TODO(armansito): Pass a refptr/weakptr to |this|?
  origin_task_runner_->PostTask([this] { delegate_->OnDisconnected(); });
}

}  // namespace debugserver
