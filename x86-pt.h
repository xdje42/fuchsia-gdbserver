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

struct ProcessorTraceFeatures {
  bool initialized;
  bool have_pt;

  bool cr3_match;
  bool cycle_accurate_mode;
  bool ip_filtering;
  bool mtc;
  bool ptwrite;
  bool power_events;

  uint32_t addr_cfg_max;
  bool supports_filter_ranges;
  bool supports_stop_ranges;
  uint32_t num_addr_ranges;

  uint32_t mtc_freq_mask;
  uint32_t cycle_thresh_mask;
  uint32_t psb_freq_mask;

  bool to_pa;
  bool multiple_to_pa_entries;
  bool single_range;
  bool trace_transport_output;
  bool payloads_are_lip;

  uint32_t tsc_ratio_num, tsc_ratio_den;
  float bus_freq;
};

bool HaveProcessorTrace();

// WARNING: Until the first call completes this is not thread safe.
const ProcessorTraceFeatures* GetProcessorTraceFeatures();

// TODO(dje): iostreams. later.
void DumpProcessorTraceFeatures(FILE* out, const ProcessorTraceFeatures *pt);

}  // namespace x86
}  // namespace arch
}  // namespace debugserver
