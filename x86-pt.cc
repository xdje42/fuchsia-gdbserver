// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "x86-pt.h"

#include <cpuid.h>

#include "x86-cpuid.h"

namespace debugserver {
namespace arch {
namespace x86 {

/* Trick to get a 1 of the right size */
#define ONE(x) (1 + ((x) - (x)))
#define BIT(x, bit) ((x) & (ONE(x) << (bit)))
#define BITS_SHIFT(x, high, low) \
  (((x) >> (low)) & ((ONE(x)<<((high)-(low)+1))-1))

void get_processor_trace_features(processor_trace_features *pt) {
  x86_feature_init();
  memset(pt, 0, sizeof(*pt));

  if (!x86_feature_test(X86_FEATURE_PT))
    return;

  // This code is derived from https://github.com/andikleen/simple-pt

  unsigned a, b, c, d;
  unsigned addr_cfg_max = 0;
  unsigned mtc_freq_mask = 0;
  unsigned cyc_thresh_mask = 0;
  unsigned psb_freq_mask = 0;
  unsigned num_addr_ranges = 0;
  unsigned max_leaf = __get_cpuid_max(0, nullptr);
  float bus_freq = 0;

  __cpuid_count(0x14, 0, a, b, c, d);
  if (BIT(b, 2))
    addr_cfg_max = 2;
  if (BIT(b, 1) && a >= 1) {
    unsigned a1, b1, c1, d1;
    __cpuid_count(0x14, 1, a1, b1, c1, d1);
    mtc_freq_mask = (a1 >> 16) & 0xffff;
    cyc_thresh_mask = b1 & 0xffff;
    psb_freq_mask = (b1 >> 16) & 0xffff;
    num_addr_ranges = a1 & 0x3;
  }

  unsigned a1 = 0, b1 = 0, c1 = 0, d1 = 0;
  if (max_leaf >= 0x15) {
    __cpuid(0x15, a1, b1, c1, d1);
    if (a1 && b1)
      bus_freq = 1. / ((float)a1 / (float)b1);
  }

  pt->have_pt = true;
  pt->to_pa = !!BIT(c, 0);
  pt->multiple_to_pa_entries = !!BIT(c, 1);
  pt->single_range = !!BIT(c, 2);
  pt->trace_transport_output = !!BIT(c, 3);
  pt->payloads_are_lip = !!BIT(c, 31);
  pt->cycle_accurate_mode = !!BIT(b, 1);
  pt->filtering_stop_mtc = !!BIT(b, 2);
  pt->cr3_match = !!BIT(b, 0);
  pt->num_addr_ranges = num_addr_ranges;
  pt->supports_filter_ranges = addr_cfg_max >= 1;
  pt->supports_stop_ranges = addr_cfg_max >= 2;
  pt->cycle_thresh_mask = cyc_thresh_mask;
  pt->psb_freq_mask = psb_freq_mask;
  pt->mtc_freq_mask = mtc_freq_mask;
  pt->tsc_ratio_den = a1;
  pt->tsc_ratio_num = b1;
  if (a1 && b1)
    pt->bus_freq = 1. / ((float)a1 / (float)b1);
}

void dump_processor_trace_features(processor_trace_features *pt) {
  printf("Processor trace:");
  if (!pt->have_pt) {
    printf(" not supported\n");
    return;
  }

  printf("\n");
  printf("to_pa: %d\n", pt->to_pa);
  printf("multiple_to_pa_entries: %d\n", pt->multiple_to_pa_entries);
  printf("single_range: %d\n", pt->single_range);
  printf("trace_transport_output: %d\n", pt->trace_transport_output);
  printf("payloads_are_lip: %d\n", pt->payloads_are_lip);
  printf("cycle_accurate_mode: %d\n", pt->cycle_accurate_mode);
  printf("filtering_stop_mtc: %d\n", pt->filtering_stop_mtc);
  printf("cr3_match: %d\n", pt->cr3_match);
  printf("num_addr_ranges: %u\n", pt->num_addr_ranges);
  printf("supports_filter_ranges: %d\n", pt->supports_filter_ranges);
  printf("supports_stop_ranges: %d\n", pt->supports_stop_ranges);
  printf("cycle_thresh_mask: 0x%x\n", pt->cycle_thresh_mask);
  printf("psb_freq_mask: 0x%x\n", pt->psb_freq_mask);
  printf("mtc_freq_mask: 0x%x\n", pt->mtc_freq_mask);
  printf("tsc_ratio_numerator: %u\n", pt->tsc_ratio_num);
  printf("tsc_ratio demoninator: %u\n", pt->tsc_ratio_den);
  if (pt->bus_freq != 0)
    printf("bus_freq: %f\n", pt->bus_freq);
}

}  // namespace x86
}  // namespace arch
}  // namespace debugserver
