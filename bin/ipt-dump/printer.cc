// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printer.h"

#include "lib/ftl/arraysize.h"

namespace intel_processor_trace {

const char* InsnClass(enum pt_insn_class iclass)
{
  static const char* const class_name[] = {
    [ptic_error] = "error",
    [ptic_other] = "other",
    [ptic_call] = "call",
    [ptic_return] = "ret",
    [ptic_jump] = "jump",
    [ptic_cond_jump] = "cjump",
    [ptic_far_call] = "fcall",
    [ptic_far_return] = "fret",
    [ptic_far_jump] = "fjump",
  };
  return iclass < arraysize(class_name) ? class_name[iclass] : "???";
}

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
