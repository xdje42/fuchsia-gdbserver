// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printer.h"

namespace intel_processor_trace {

void TransferEvents(IptInsn* si, const struct pt_insn* insn)
{
#define T(x) si->x = insn->x
  T(speculative);
  T(aborted);
  T(committed);
  T(enabled);
  T(disabled);
  T(resumed);
  T(interrupted);
  T(resynced);
  T(stopped);
#undef T
}

} // intel_processor_trace
