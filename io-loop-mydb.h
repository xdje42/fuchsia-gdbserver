// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include "io_loop.h"

namespace debugserver {

class MydbIOLoop final : public IOLoop {
 public:
  MydbIOLoop(int in_fd, int out_fd, Delegate* delegate);

 private:
  bool ReadTask() override;

  FTL_DISALLOW_COPY_AND_ASSIGN(MydbIOLoop);
};

}  // namespace debugserver
