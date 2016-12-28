// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include "io-loop.h"

#include <array>

namespace debugserver {

class RspIOLoop final : public IOLoop {
 public:
  RspIOLoop(int in_fd, int out_fd, Delegate* delegate);

 private:
  bool ReadTask() override;

  // Maximum number of characters in the inbound buffer.
  constexpr static size_t kMaxBufferSize = 4096;

  // Buffer used for reading incoming bytes.
  std::array<char, kMaxBufferSize> in_buffer_;

  FTL_DISALLOW_COPY_AND_ASSIGN(RspIOLoop);
};

}  // namespace debugserver
