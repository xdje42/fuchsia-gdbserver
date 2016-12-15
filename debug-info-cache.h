// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <array>
#include <cstddef>
#include <string>

#include <backtrace/backtrace.h>
#include <magenta/types.h>

#include "dso-list.h"

namespace debugserver {
namespace mydb {

// Keep open debug info for this many files.
// TODO(dje): Be more flexible. Later!
constexpr size_t kDebugInfoCacheNumWays = 2;

// A cache of data stored for each executable + shared lib.
// This lets us lazily obtain debug info, and only keep
// a subset of it in memory.
// Data is looked up by build id.

class DebugInfoCache {
 public:
  DebugInfoCache();
  ~DebugInfoCache();

  mx_status_t GetDebugInfo(elf::dsoinfo_t* dso,
                           backtrace_state** out_bt_state);
    
 private:
  size_t last_used_ = 0;

  struct way {
    // This is the "tag".
    std::string build_id;
    // Owned by us.
    backtrace_state* bt_state = nullptr;
  };

  std::array<way, kDebugInfoCacheNumWays> ways_;
};

}  // namespace mydb
}  // namespace debugserver
