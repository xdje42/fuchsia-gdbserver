// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debug-info-cache.h"

#include <array>
#include <inttypes.h>
#include <stddef.h>
//#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <backtrace/backtrace.h>

#include <ngunwind/libunwind.h>
#include <ngunwind/fuchsia.h>

#include <magenta/types.h>
#include <magenta/syscalls.h>
#include <magenta/syscalls/object.h>

#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_printf.h"

#include "backtrace.h"
#include "dso-list.h"
#include "util.h"

namespace debugserver {
namespace mydb {

// backtrace_so_iterator function.
// We don't use libbacktrace to do unwinding, we only use it to get
// file,line#,function_name for each pc. Therefore we don't need it to
// iterate over all shared libs.

static int
bt_so_iterator (void* iter_state, backtrace_so_callback* callback, void* data) {
  // Return non-zero so iteration stops.
  return 1;
}

DebugInfoCache::DebugInfoCache() {
}

DebugInfoCache::~DebugInfoCache() {
  for (auto w : ways_) {
    backtrace_destroy_state(w.bt_state, bt_error_callback, nullptr);
  }
}

// Find debug info (for now backtrace_state) for DSO.
// Returns NO_ERROR if debug info is found.
// If the result is NO_ERROR then |*out_bt_state| is set to the
// accompanying libbacktrace state if available or nullptr if not.

mx_status_t DebugInfoCache::GetDebugInfo(elf::dsoinfo_t* dso,
                                         backtrace_state** out_bt_state) {
#if 0 // Skip using libbacktrace until leaks are fixed.
  return ERR_NOT_FOUND;
#endif

  const size_t nr_ways = ways_.size();

  for (size_t i = 0; i < nr_ways; ++i) {
    if (ways_[i].build_id == dso->buildid) {
      FTL_VLOG(1) << ftl::StringPrintf(
          "Using cached debug info entry for dso %s/%s",
          dso->name, dso->buildid);
      *out_bt_state = ways_[i].bt_state;
      return NO_ERROR;
    }
  }

  // Not found in the cache.

  const char* debug_file = nullptr;
  auto status = elf::dso_find_debug_file(dso, &debug_file);
  if (status != NO_ERROR)
    return status;

  struct backtrace_state* bt_state =
    backtrace_create_state(debug_file, 0 /*!threaded*/,
                           bt_error_callback, nullptr);
  if (bt_state == nullptr) {
    FTL_LOG(ERROR) << "backtrace_create_state failed (OOM)";
    return ERR_NO_MEMORY;
  }

  // last_used_+1: KISS until there's data warranting something better
  size_t way = (last_used_ + 1) % nr_ways;
  if (ways_[way].build_id != "") {
    // Free the entry.
    backtrace_destroy_state(ways_[way].bt_state, bt_error_callback, nullptr);
    ways_[way].build_id = "";
    ways_[way].bt_state = nullptr;
  }

  backtrace_set_so_iterator(bt_state, bt_so_iterator, nullptr);
  backtrace_set_base_address(bt_state, dso->base);

  ways_[way].build_id = dso->buildid;
  ways_[way].bt_state = bt_state;
  *out_bt_state = bt_state;
  last_used_ = way;
  return NO_ERROR;
}

}  // namespace mydb
}  // namespace debugserver
