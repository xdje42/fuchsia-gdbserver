// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstdio>

#include <magenta/syscalls/exception.h>
#include <magenta/types.h>

namespace debugserver {
namespace arch {

// Maps the architecture-specific exception code to a UNIX compatible signal
// value that GDB understands. Returns -1  if the current architecture is not
// currently supported.
int ComputeGdbSignal(const mx_exception_context_t& context);

// Returns true if |context| is a single-stepping exception.
bool IsSingleStepException(const mx_exception_context_t& context);

// Dump random bits about the architecuture.
// TODO(dje): Switch to iostreams later.
void DumpArch(FILE* out);

// Experiments with Intel PT.
void StartPerf();
void StopPerf();
void DumpPerf();

}  // namespace arch
}  // namespace debugserver
