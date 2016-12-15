// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// N.B. The offline symbolizer (scripts/symbolize) reads our output,
// don't break it.

// TODO: printf -> write posts

#include "backtrace.h"

#include <array>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <backtrace/backtrace.h>

#include <ngunwind/libunwind.h>
#include <ngunwind/fuchsia.h>

#include <magenta/types.h>
#include <magenta/syscalls.h>
#include <magenta/syscalls/object.h>

#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_printf.h"

#include "debug-info-cache.h"
#include "dso-list.h"
#include "mydb-command-handler.h"
#include "process.h"
#include "server-mydb.h"
#include "thread.h"
#include "util.h"

namespace debugserver {
namespace mydb {

void bt_error_callback(void* vdata, const char* msg, int errnum) {
  if (errnum > 0)
    FTL_LOG(ERROR) << ftl::StringPrintf("%s: %s\n", msg, strerror (errnum));
  else
    FTL_LOG(ERROR) << ftl::StringPrintf("%s\n", msg);
}

// Data to pass back from backtrace_pcinfo.
// We don't use libbacktrace to print the backtrace, we only use it to
// obtain file,line#,function_name.

struct bt_pcinfo_data
{
  const char* filename;
  int lineno;
  const char* function;
};

// Callback invoked by libbacktrace.

static int
btprint_callback(void* vdata, uintptr_t pc, const char* filename, int lineno,
                 const char* function) {
  auto data = reinterpret_cast<bt_pcinfo_data*> (vdata);

  data->filename = filename;
  data->lineno = lineno;
  data->function = function;

  return 0;
}

static void btprint(Process* process, const CommandEnvironment& env,
                    int n, uintptr_t pc, uintptr_t sp) {
  elf::dsoinfo_t* dso = process->LookupDso(pc);
  if (dso == nullptr) {
    // The pc is not in any DSO.
    printf("bt#%02d: pc %p sp %p\n",
           n, (void*) pc, (void*) sp);
    return;
  }

  backtrace_state* bt_state;
  DebugInfoCache& di_cache = env.server()->debug_info_cache();
  auto status = di_cache.GetDebugInfo(dso, &bt_state);
  if (status != NO_ERROR)
    bt_state = nullptr;

  // Try to use libbacktrace if we can.

  struct bt_pcinfo_data pcinfo_data;
  memset(&pcinfo_data, 0, sizeof(pcinfo_data));

  if (bt_state != nullptr) {
    auto ret = backtrace_pcinfo(bt_state, pc, btprint_callback,
                                bt_error_callback, &pcinfo_data);
    if (ret == 0) {
      // FIXME: How to interpret the result is seriously confusing.
      // There are cases where zero means failure and others where
      // zero means success. For now we just assume that pcinfo_data
      // will only be filled in on success.
    }
  }

  printf("bt#%02d: pc %p sp %p (%s,%p)",
         n, (void*) pc, (void*) sp, dso->name, (void*) (pc - dso->base));
  if (pcinfo_data.filename != nullptr && pcinfo_data.lineno > 0) {
    const char* base = util::basename(pcinfo_data.filename);
    printf(" %s:%d", base, pcinfo_data.lineno);
  }
  if (pcinfo_data.function != nullptr)
    printf(" %s", pcinfo_data.function);
  printf("\n");
}

static int dso_lookup_for_unw(struct dsoinfo* dso_list_arg, unw_word_t pc,
                              unw_word_t* base, const char** name) {
  auto dso_list = reinterpret_cast<elf::dsoinfo_t*>(dso_list_arg);
  const elf::dsoinfo_t* dso = elf::dso_lookup(dso_list, pc);
  if (dso == nullptr)
    return 0;
  *base = dso->base;
  *name = dso->name;
  return 1;
}

void backtrace(Thread* thread, const CommandEnvironment& env,
               uintptr_t pc, uintptr_t sp, uintptr_t fp,
               bool use_libunwind) {
  Process* process = thread->process();

  // Prepend "app:" to the name we print for the process binary to tell the
  // reader (and the symbolize script!) that the name is the process's.
  // The name property is only 32 characters which may be insufficient.
  // N.B. The symbolize script looks for "app" and "app:".
#define PROCESS_NAME_PREFIX "app:"
#define PROCESS_NAME_PREFIX_LEN (sizeof(PROCESS_NAME_PREFIX) - 1)
  char name[MX_MAX_NAME_LEN + PROCESS_NAME_PREFIX_LEN];
  strcpy(name, PROCESS_NAME_PREFIX);
  auto status = mx_object_get_property(process->handle(),
                                       MX_PROP_NAME, name + PROCESS_NAME_PREFIX_LEN,
                                       sizeof(name) - PROCESS_NAME_PREFIX_LEN);
  if (status != NO_ERROR) {
    util::LogErrorWithMxStatus(
        "mx_object_get_property, falling back to \"app\" for program name",
        status);
    strlcpy(name, "app", sizeof(name));
  }

  elf::dsoinfo_t* dso_list = process->GetDsos();

  // Set up libunwind if requested.

  bool libunwind_ok = use_libunwind;
  int verbosity = ftl::GetVlogVerbosity();
  // ftl verbosity settings are unusual, larger negative numbers mean
  // more verbose.
  // Don't turn on libunwind debugging for verbosity level 1 (== -1).
  // Note: max libunwind debugging level is 16
  if (verbosity <= -2) {
    unw_set_debug_level((-verbosity) - 1);
  }

  unw_fuchsia_info_t* fuchsia = nullptr;
  unw_addr_space_t remote_as = nullptr;

  if (libunwind_ok) {
    fuchsia = unw_create_fuchsia(process->handle(), thread->handle(),
                                 reinterpret_cast<struct dsoinfo*>(dso_list),
                                 dso_lookup_for_unw);
    if (fuchsia == nullptr)
      {
        FTL_LOG(ERROR) << "unw_fuchsia_create failed (OOM)";
        libunwind_ok = false;
      }
  }

  if (libunwind_ok) {
    remote_as =
      unw_create_addr_space((unw_accessors_t*) &_UFuchsia_accessors, 0);
    if (remote_as == nullptr)
      {
        FTL_LOG(ERROR) << "unw_create_addr_space failed (OOM)";
        libunwind_ok = false;
      }
  }

  unw_cursor_t cursor;
  if (libunwind_ok) {
    int ret = unw_init_remote(&cursor, remote_as, fuchsia);
    if (ret < 0) {
      FTL_LOG(ERROR) << "unw_init_remote failed: " << ret;
      libunwind_ok = false;
    }
  }

  if (!libunwind_ok) {
    FTL_LOG(ERROR) << "Unable to initialize libunwind.";
    FTL_LOG(ERROR) << "Falling back on heuristics which likely won't work";
    FTL_LOG(ERROR) << "with optimized code.";
  }

  // TODO: Handle libunwind not finding .eh_frame in which case fallback
  // on using heuristics. Ideally this would be handled on a per-DSO basis.

  // On with the show.

  int n = 1;
  btprint(process, env, n++, pc, sp);
  while ((sp >= 0x1000000) && (n < 50)) {
    if (libunwind_ok) {
      int ret = unw_step(&cursor);
      if (ret < 0) {
        FTL_LOG(ERROR) << ftl::StringPrintf(
            "unw_step failed for pc %p, aborting backtrace here", (void*) pc);
        break;
      }
      if (ret == 0)
        break;
      unw_word_t val;
      unw_get_reg(&cursor, UNW_REG_IP, &val);
      pc = val;
      unw_get_reg(&cursor, UNW_REG_SP, &val);
      sp = val;
    } else {
      sp = fp;
      if (!process->ReadMemory(fp + 8, &pc, sizeof(pc))) {
        break;
      }
      if (!process->ReadMemory(fp, &fp, sizeof(fp))) {
        break;
      }
    }
    btprint(process, env, n++, pc, sp);
  }
  printf("bt#%02d: end\n", n);

  unw_destroy_addr_space(remote_as);
  unw_destroy_fuchsia(fuchsia);
}

}  // namespace mydb
}  // namespace debugserver
