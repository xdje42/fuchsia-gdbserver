// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <array>
#include <cstddef>

#include <backtrace/backtrace.h>
#include <magenta/types.h>

#include "mydb-command-handler.h"

namespace debugserver {

class Thread;

namespace mydb {

class CommandState;

// Helper function to perform a backtrace.
void backtrace(Thread* thread, const CommandEnvironment& env,
               mx_vaddr_t pc, mx_vaddr_t sp, mx_vaddr_t fp,
               bool use_libunwind);

// Error callback for libbacktrace.
void bt_error_callback(void* vdata, const char* msg, int errnum);

}  // namespace mydb
}  // namespace debugserver
