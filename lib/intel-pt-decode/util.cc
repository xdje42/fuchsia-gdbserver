// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "util.h"

namespace intel_processor_trace {

const char* IclassName(enum pt_insn_class iclass)
{
  // Note: The output expects this to be 7 chars or less.
  switch (iclass) {
  case ptic_error: return "error";
  case ptic_other: return "other";
  case ptic_call: return "call";
  case ptic_return: return "return";
  case ptic_jump: return "jump";
  case ptic_cond_jump: return "cjump";
  case ptic_far_call: return "fcall";
  case ptic_far_return: return "freturn";
  case ptic_far_jump: return "fjump";
  default: return "???";
  }
}

} // intel_processor_trace
