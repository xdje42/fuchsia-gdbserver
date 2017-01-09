// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "x86-pt.h"

#include <cpuid.h>

#include "lib/ftl/logging.h"

/* Trick to get a 1 of the right size */
#define ONE(x) (1 + ((x) - (x)))
#define BIT(x, bit) ((x) & (ONE(x) << (bit)))
#define BITS_SHIFT(x, high, low) \
  (((x) >> (low)) & ((ONE(x)<<((high)-(low)+1))-1))

namespace x86 {

static ProcessorTraceFeatures pt_features;

bool HaveProcessorTrace() {
  const ProcessorTraceFeatures* ptf = GetProcessorTraceFeatures();
  return ptf->have_pt;
}

const ProcessorTraceFeatures* GetProcessorTraceFeatures() {
  ProcessorTraceFeatures* pt = &pt_features;
  unsigned a, b, c, d, max_leaf;

  if (pt->initialized)
    return pt;

  pt->initialized = true;

  max_leaf = __get_cpuid_max(0, nullptr);
  if (max_leaf < 0x14) {
    FTL_LOG(INFO) << "no PT support";
    return &pt_features;
  }

  __cpuid_count(0x07, 0, a, b, c, d);
  if (!BIT(b, 25)) {
    FTL_LOG(INFO) << "no PT support";
    return &pt_features;
  }

  pt->have_pt = true;

  __cpuid_count(0x14, 0, a, b, c, d);
  if (BIT(b, 2))
    pt->addr_cfg_max = 2;
  if (BIT(b, 1) && a >= 1) {
    unsigned a1, b1, c1, d1;
    __cpuid_count(0x14, 1, a1, b1, c1, d1);
    pt->mtc_freq_mask = (a1 >> 16) & 0xffff;
    pt->cycle_thresh_mask = b1 & 0xffff;
    pt->psb_freq_mask = (b1 >> 16) & 0xffff;
    pt->num_addr_ranges = a1 & 0x3;
  }

  pt->cr3_filtering = !!BIT(b, 0);
  pt->cycle_accurate_mode = !!BIT(b, 1);
  pt->ip_filtering = !!BIT(b, 2);
  pt->mtc = !!BIT(b, 3);
  pt->ptwrite = !!BIT(b, 4);
  pt->power_events = !!BIT(b, 5);

  pt->to_pa = !!BIT(c, 0);
  pt->multiple_to_pa_entries = !!BIT(c, 1);
  pt->single_range = !!BIT(c, 2);
  pt->trace_transport_output = !!BIT(c, 3);
  pt->payloads_are_lip = !!BIT(c, 31);

  if (max_leaf >= 0x15) {
    unsigned a1 = 0, b1 = 0, c1 = 0, d1 = 0;
    __cpuid(0x15, a1, b1, c1, d1);
    pt->tsc_ratio_den = a1;
    pt->tsc_ratio_num = b1;
    if (a1 && b1)
      pt->bus_freq = 1. / ((float)a1 / (float)b1);
  }

  return pt;
}

void DumpProcessorTraceFeatures(FILE* out, const ProcessorTraceFeatures* pt) {
  fprintf(out, "Processor trace:");

  if (!pt->have_pt) {
    fprintf(out, " not supported\n");
    return;
  }

  fprintf(out, "\n");
  fprintf(out, "to_pa: %d\n", pt->to_pa);
  fprintf(out, "multiple_to_pa_entries: %d\n", pt->multiple_to_pa_entries);
  fprintf(out, "single_range: %d\n", pt->single_range);
  fprintf(out, "trace_transport_output: %d\n", pt->trace_transport_output);
  fprintf(out, "payloads_are_lip: %d\n", pt->payloads_are_lip);
  fprintf(out, "cycle_accurate_mode: %d\n", pt->cycle_accurate_mode);
  fprintf(out, "filtering_stop_mtc: %d\n", pt->ip_filtering);
  fprintf(out, "cr3_match: %d\n", pt->cr3_filtering);
  fprintf(out, "num_addr_ranges: %u\n", pt->num_addr_ranges);
  fprintf(out, "cycle_thresh_mask: 0x%x\n", pt->cycle_thresh_mask);
  fprintf(out, "psb_freq_mask: 0x%x\n", pt->psb_freq_mask);
  fprintf(out, "mtc_freq_mask: 0x%x\n", pt->mtc_freq_mask);
  fprintf(out, "tsc_ratio_numerator: %u\n", pt->tsc_ratio_num);
  fprintf(out, "tsc_ratio demoninator: %u\n", pt->tsc_ratio_den);
  if (pt->bus_freq != 0)
    fprintf(out, "bus_freq: %f\n", pt->bus_freq);
}

}  // namespace x86
