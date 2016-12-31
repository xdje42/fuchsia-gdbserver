// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstdint>
#include <cstdio>

#include "lib/ftl/logging.h"

namespace debugserver {
namespace arch {
namespace x86 {

struct processor_trace_features {
  bool have_pt;
  bool to_pa;
  bool multiple_to_pa_entries;
  bool single_range;
  bool trace_transport_output;
  bool payloads_are_lip;
  bool cycle_accurate_mode;
  bool filtering_stop_mtc;
  bool cr3_match;
  uint32_t num_addr_ranges;
  bool supports_filter_ranges;
  bool supports_stop_ranges;
  uint32_t cycle_thresh_mask;
  uint32_t psb_freq_mask;
  uint32_t mtc_freq_mask;
  uint32_t tsc_ratio_num, tsc_ratio_den;
  float bus_freq;
};

void get_processor_trace_features(processor_trace_features *pt);

// TODO(dje): Switch to iostreams later.
void dump_processor_trace_features(FILE* out, processor_trace_features *pt);

}  // namespace x86
}  // namespace arch
}  // namespace debugserver
