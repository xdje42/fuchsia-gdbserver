// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "io-loop-mydb.h"

#include "lib/ftl/logging.h"

#include "readline.h"

#include "util.h"

namespace debugserver {

MydbIOLoop::MydbIOLoop(int in_fd, int out_fd, Delegate* delegate)
    : IOLoop(in_fd, out_fd, delegate) {
}

bool MydbIOLoop::ReadTask() {
  ftl::StringView line;
  int rc = util::readline(&line);

  if (rc < 0) {
    FTL_VLOG(1) << "Client closed connection";
    ReportDisconnected();
    return false;
  }

  FTL_VLOG(2) << "-> " << util::EscapeNonPrintableString(line);

  if (quit_called())
    return false;

  // Notify the delegate that we read some bytes. We copy the buffer data
  // into the closure as |line| can get modified before the closure runs.
  // TODO(armansito): Pass a weakptr to |delegate_|?
  origin_task_runner()->PostTask([ line = line.ToString(), this ] {
    delegate()->OnBytesRead(line);
  });

  // Don't schedule another read task yet:
  // The command may require further keyboard input.
  return false;
}

}  // namespace debugserver
