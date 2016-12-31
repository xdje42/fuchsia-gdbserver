// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <magenta/types.h>

#include "memory.h"

namespace debugserver {

// The API for accessing process memory.

class ProcessMemory final : public util::Memory {
 public:
  explicit ProcessMemory(mx_handle_t handle);

  bool Read(uintptr_t address, void* out_buffer, size_t length) const override;
  bool Write(uintptr_t address, const void* data, size_t length) const override;

  void SetHandle(mx_handle_t handle);
  void Clear();

 private:
  mx_handle_t handle_;  // weak

  FTL_DISALLOW_COPY_AND_ASSIGN(ProcessMemory);
};

}  // namespace debugserver
