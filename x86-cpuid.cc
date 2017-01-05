// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// This file is copied from magenta/kernel/arch/x86/feature.c.
// TODO(dje): As with generic elf, dwarf, et.al, move to application
// independent library.

#include "x86-cpuid.h"

#include <cpuid.h>
#include <cstdint>
#include <cstring>
#include <stdatomic.h> // TODO(dje)

namespace debugserver {
namespace arch {
namespace x86 {

/* Trick to get a 1 of the right size */
#define ONE(x) (1 + ((x) - (x)))
#define BITS_SHIFT(x, high, low) \
  (((x) >> (low)) & ((ONE(x)<<((high)-(low)+1))-1))

struct cpuid_leaf _cpuid[MAX_SUPPORTED_CPUID + 1];
struct cpuid_leaf _cpuid_ext[MAX_SUPPORTED_CPUID_EXT - X86_CPUID_EXT_BASE + 1];
uint32_t max_cpuid = 0;
uint32_t max_ext_cpuid = 0;

enum x86_vendor_list x86_vendor;

static struct x86_model_info model_info;

static atomic_bool initialized = ATOMIC_VAR_INIT(false);

void x86_feature_init(void)
{
    if (atomic_exchange(&initialized, true)) {
        return;
    }

    /* test for cpuid count */
    __cpuid(0, _cpuid[0].a, _cpuid[0].b, _cpuid[0].c, _cpuid[0].d);

    max_cpuid = _cpuid[0].a;
    if (max_cpuid > MAX_SUPPORTED_CPUID)
        max_cpuid = MAX_SUPPORTED_CPUID;

    /* figure out the vendor */
    union {
        uint32_t vendor_id[3];
        char vendor_string[13];
    } vu;
    vu.vendor_id[0] = _cpuid[0].b;
    vu.vendor_id[1] = _cpuid[0].d;
    vu.vendor_id[2] = _cpuid[0].c;
    vu.vendor_string[12] = '\0';
    if (!strcmp(vu.vendor_string, "GenuineIntel")) {
        x86_vendor = X86_VENDOR_INTEL;
    } else if (!strcmp(vu.vendor_string, "AuthenticAMD")) {
        x86_vendor = X86_VENDOR_AMD;
    } else {
        x86_vendor = X86_VENDOR_UNKNOWN;
    }

    /* read in the base cpuids */
    for (uint32_t i = 1; i <= max_cpuid; i++) {
        __cpuid_count(i, 0, _cpuid[i].a, _cpuid[i].b, _cpuid[i].c, _cpuid[i].d);
    }

    /* test for extended cpuid count */
    __cpuid(X86_CPUID_EXT_BASE, _cpuid_ext[0].a, _cpuid_ext[0].b,
            _cpuid_ext[0].c, _cpuid_ext[0].d);

    max_ext_cpuid = _cpuid_ext[0].a;
    if (max_ext_cpuid > MAX_SUPPORTED_CPUID_EXT)
        max_ext_cpuid = MAX_SUPPORTED_CPUID_EXT;

    /* read in the extended cpuids */
    for (uint32_t i = X86_CPUID_EXT_BASE + 1; i - 1 < max_ext_cpuid; i++) {
        uint32_t index = i - X86_CPUID_EXT_BASE;
        __cpuid_count(i, 0, _cpuid_ext[index].a, _cpuid_ext[index].b,
                      _cpuid_ext[index].c, _cpuid_ext[index].d);
    }

    /* populate the model info */
    const struct cpuid_leaf* leaf = x86_get_cpuid_leaf(X86_CPUID_MODEL_FEATURES);
    if (leaf) {
        model_info.processor_type = BITS_SHIFT(leaf->a, 13, 12);
        model_info.family = BITS_SHIFT(leaf->a, 11, 8);
        model_info.model = BITS_SHIFT(leaf->a, 7, 4);
        model_info.stepping = BITS_SHIFT(leaf->a, 3, 0);
        model_info.display_family = model_info.family;
        model_info.display_model = model_info.model;

        if (model_info.family == 0xf) {
            model_info.display_family += BITS_SHIFT(leaf->a, 27, 20);
        }
        if (model_info.family == 0xf || model_info.family == 0x6) {
            model_info.display_model += BITS_SHIFT(leaf->a, 19, 16) << 4;
        }
    }
}

bool x86_get_cpuid_subleaf(
        enum x86_cpuid_leaf_num num, uint32_t subleaf, struct cpuid_leaf *leaf)
{
    if (num < X86_CPUID_EXT_BASE) {
        if (num > max_cpuid)
            return false;
    } else if (num > max_ext_cpuid) {
        return false;
    }

    __cpuid_count((uint32_t)num, subleaf, leaf->a, leaf->b, leaf->c, leaf->d);
    return true;
}

bool x86_topology_enumerate(uint8_t level, struct x86_topology_level *info)
{
    uint32_t eax, ebx, ecx, edx;
    __cpuid_count(X86_CPUID_TOPOLOGY, level, eax, ebx, ecx, edx);

    uint8_t type = (ecx >> 8) & 0xff;
    if (type == X86_TOPOLOGY_INVALID) {
        return false;
    }

    info->right_shift = eax & 0x1f;
    info->type = type;
    return true;
}

const struct x86_model_info * x86_get_model(void)
{
    return &model_info;
}

void x86_feature_debug(FILE* out)
{
    static const struct {
        struct x86_cpuid_bit bit;
        const char *name;
    } features[] = {
        { X86_FEATURE_FPU, "fpu" },
        { X86_FEATURE_SSE, "sse" },
        { X86_FEATURE_SSE2, "sse2" },
        { X86_FEATURE_SSE3, "sse3" },
        { X86_FEATURE_SSSE3, "ssse3" },
        { X86_FEATURE_SSE4_1, "sse4.1" },
        { X86_FEATURE_SSE4_2, "sse4.2" },
        { X86_FEATURE_MMX, "mmx" },
        { X86_FEATURE_AVX, "avx" },
        { X86_FEATURE_AVX2, "avx2" },
        { X86_FEATURE_FXSR, "fxsr" },
        { X86_FEATURE_XSAVE, "xsave" },
        { X86_FEATURE_AESNI, "aesni" },
        { X86_FEATURE_TSC_ADJUST, "tsc_adj" },
        { X86_FEATURE_SMEP, "smep" },
        { X86_FEATURE_SMAP, "smap" },
        { X86_FEATURE_RDRAND, "rdrand" },
        { X86_FEATURE_RDSEED, "rdseed" },
        { X86_FEATURE_PT, "pt" },
        { X86_FEATURE_PKU, "pku" },
        { X86_FEATURE_SYSCALL, "syscall" },
        { X86_FEATURE_NX, "nx" },
        { X86_FEATURE_HUGE_PAGE, "huge" },
        { X86_FEATURE_RDTSCP, "rdtscp" },
        { X86_FEATURE_INVAR_TSC, "invar_tsc" },
        { X86_FEATURE_TSC_DEADLINE, "tsc_deadline" },
    };

    x86_feature_init();

    const char *vendor_string;
    switch (x86_vendor) {
        default:
        case X86_VENDOR_UNKNOWN: vendor_string = "unknown"; break;
        case X86_VENDOR_INTEL: vendor_string = "Intel"; break;
        case X86_VENDOR_AMD: vendor_string = "AMD"; break;
    }
    fprintf(out, "Vendor: %s\n", vendor_string);

    auto model = x86_get_model();
    fprintf(out, "Model:");
    fprintf(out, " processor %u, family %u, model %u, stepping %u",
            model->processor_type, model->family, model->model,
            model->stepping);
    fprintf(out, ", display: family %u, model %u",
            model->display_family, model->display_model);
    fprintf(out, "\n");

    fprintf(out, "Features:\n");
    size_t col = 0;
    for (auto& f : features) {
        if (x86_feature_test(f.bit))
            col += fprintf(out, "%s ", f.name);
        if (col >= 80) {
            fprintf(out, "\n");
            col = 0;
        }
    }
    if (col > 0)
        fprintf(out, "\n");
}

}  // namespace x86
}  // namespace arch
}  // namespace debugserver
