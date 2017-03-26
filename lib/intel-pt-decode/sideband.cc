// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "decoder.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include <map>

#include "lib/ftl/files/path.h"
#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_printf.h"

#include "debugger-utils/ktrace-reader.h"
#include "debugger-utils/util.h"

namespace intel_processor_trace {

using namespace debugserver;

bool DecoderState::ReadCpuidFile(const std::string& file)
{
  FTL_LOG(INFO) << "Loading cpuid data from " << file;

  FILE* f = fopen(file.c_str(), "r");
  if (!f) {
    util::LogErrorWithErrno("error opening cpuid file");
    return false;
  }

  char* line = nullptr;
  size_t linelen = 0;
  int lineno = 1;

  for ( ; getline(&line, &linelen, f) > 0; ++lineno) {
    size_t n = strlen(line);
    if (n > 0 && line[n - 1] == '\n')
      line[n - 1] = '\0';
    FTL_VLOG(2) << ftl::StringPrintf("read %d: %s", lineno, line);

    if (line[0] == '\0' || line[0] == '#')
      continue;

    if (strcmp(line, "Vendor: Intel") == 0) {
      config_.cpu.vendor = pcv_intel;
    } else if (sscanf(line, "tsc_ratio: %u %u",
               &config_.cpuid_0x15_eax,
               &config_.cpuid_0x15_ebx) == 2) {
      // ok
      // Note: According to intel-pt.h:pt_config this is only used if MTC
      // packets have been enabled in IA32_RTIT_CTRL.MTCEn.
    } else if (sscanf(line, "family: %hu",
                      &config_.cpu.family) == 1) {
      // ok
    } else if (sscanf(line, "model: %hhu",
                      &config_.cpu.model) == 1) {
      // ok
    } else if (sscanf(line, "stepping: %hhu",
                      &config_.cpu.stepping) == 1) {
      // ok
    } else if (sscanf(line, "mtc_freq: %hhu",
                      &config_.mtc_freq) == 1) {
      // This isn't from cpuid, it's the value of IA32_RTIT_CTL.MTCFreq
      // when the trace was collected, but ipt-ctrl.cc puts the value here
      // (otherwise we'd need another source of sideband data, hmmm, unless
      // we put it in the ktrace data).
      // According to intel-pt.h:pt_config this is only required if MTC
      // packets have been enabled in IA32_RTIT_CTRL.MTCEn.
      if (config_.mtc_freq)
        config_.mtc_freq--;
    } else if (sscanf(line, "nom_freq: %hhu",
                      &config_.nom_freq) == 1) {
      // This is currently obtained from the ktrace record, but we allow for
      // providing it here.
      tsc_freq_ = config_.nom_freq / 10.0;
    } else {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
    }
  }

  // TODO(dje): How to handle errata? See intel-pt.h:pt_errata.

  free(line);
  fclose(f);

  return true;
}

struct KtraceData
{
  DecoderState* state;
};

int DecoderState::ProcessKtraceRecord(
    debugserver::ktrace::KtraceRecord* rec, void* arg)
{
  KtraceData* data = reinterpret_cast<KtraceData*>(arg);

  // We're interested in TAG_IPT_* records.

  switch (rec->hdr.tag) {
  case TAG_IPT_START: {
    // N.B. There may be many IPT_START/STOP records present.
    // We only want the last one.
    FTL_LOG(INFO) << "Ktrace IPT start, ts " << rec->hdr.ts;
    const ktrace_rec_32b* r = &rec->r_32B;
    uint64_t kernel_cr3 = r->c | ((uint64_t) r->d << 32);
    data->state->set_nom_freq(r->a);
    data->state->set_tsc_freq(r->a / 10.0);
    data->state->set_kernel_cr3(kernel_cr3);
    FTL_LOG(INFO) <<
      ftl::StringPrintf("Ktrace IPT start, ts %" PRIu64
                        ", nom_freq %u, kernel cr3 0x%" PRIx64,
                        rec->hdr.ts, r->a, kernel_cr3);
    break;
  }
  case TAG_IPT_STOP:
    FTL_LOG(INFO) << "Ktrace IPT stop, ts " << rec->hdr.ts;
    break;
  case TAG_IPT_PROCESS_CREATE: {
    const ktrace_rec_32b* r = &rec->r_32B;
    uint64_t pid = r->a | ((uint64_t) r->b << 32);
    uint64_t cr3 = r->c | ((uint64_t) r->d << 32);
    FTL_LOG(INFO) <<
      ftl::StringPrintf("Ktrace process create, ts %" PRIu64
                        ", pid %" PRIu64 ", cr3 0x%" PRIx64,
                        rec->hdr.ts, pid, cr3);
    if (!data->state->AddProcess(pid, cr3, rec->hdr.ts)) {
      FTL_LOG(ERROR) << "Error adding process: " << pid;
    }
    break;
  }
  case TAG_PROC_EXIT: {
    const ktrace_rec_32b* r = &rec->r_32B;
    uint64_t pid = r->a | ((uint64_t) r->b << 32);
    FTL_LOG(INFO) <<
      ftl::StringPrintf("Ktrace process exit, ts %" PRIu64
                        ", pid %" PRIu64,
                        rec->hdr.ts, pid);
    // N.B. We don't remove the process from any table here. This pass is run
    // before we scan the actual PT dump.
    if (!data->state->MarkProcessExited(pid, rec->hdr.ts)) {
      FTL_LOG(ERROR) << "Error marking process exit: " << pid;
    }
    break;
  }
  }

  return 0;
}

bool DecoderState::ReadKtraceFile(const std::string& file)
{
  FTL_LOG(INFO) << "Loading ktrace data from " << file;

  int fd = open(file.c_str(), O_RDONLY);
  if (fd < 0) {
    util::LogErrorWithErrno("error opening ktrace file");
    return false;
  }

  KtraceData data = { this };
  int rc = debugserver::ktrace::ReadFile(fd, ProcessKtraceRecord, &data);
  if (rc != 0) {
    FTL_LOG(ERROR) << ftl::StringPrintf("Error %d reading ktrace file", rc);
    return false;
  }

  close(fd);

  return true;
}

bool DecoderState::ReadMapFile(const std::string& file)
{
  FTL_LOG(INFO) << "Loading map data from " << file;

  FILE* f = fopen(file.c_str(), "r");
  if (!f) {
    util::LogErrorWithErrno("error opening map file");
    return false;
  }

  char* line = nullptr;
  size_t linelen = 0;
  int lineno = 1;

  std::map<uint64_t, MapEntry> map_data;

  for ( ; getline(&line, &linelen, f) > 0; ++lineno) {
    size_t n = strlen(line);
    if (n > 0 && line[n - 1] == '\n')
      line[n - 1] = '\0';
    FTL_VLOG(2) << ftl::StringPrintf("read %d: %s", lineno, line);

#define MAX_LINE_LEN 1024
    if (linelen > MAX_LINE_LEN) {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
    }

    if (!strcmp(line, "\n"))
      continue;
    if (line[0] == '#')
      continue;

    // If this is a new boot, start over.
    if (strstr(line, "welcome to lk/MP")) {
      ClearMap();
      continue;
    }

    char prefix[linelen];
    char build_id[linelen];
    char name[linelen];
    char so_name[linelen];
    // The sequence number is used for grouping records, done beforehand, but
    // is no longer needed after that.
    unsigned seqno;
    uint64_t pid, base_addr, load_addr, end_addr;

    // ld.so dumps the data in three separate records to avoid line-wrapping:
    // a: base load end
    // b: build_id
    // c: name so_name
    // TODO(dje): See MG-519. This is a temp hack until ld.so logs this data
    // via something better.

#define GET_ENTRY_ID(pid, seqno) (((pid) << 8) + (seqno))

    if (sscanf(line, "%[^@]@trace_load: %" PRIu64 ":%ua"
               " 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64,
               prefix, &pid, &seqno, &base_addr, &load_addr, &end_addr) == 6) {
      uint64_t id = GET_ENTRY_ID(pid, seqno);
      if (map_data.find(id) != map_data.end()) {
        FTL_LOG(ERROR) << "Already have map entry for: " << line;
        continue;
      }
      struct MapEntry entry;
      entry.pid = pid;
      entry.base_addr = base_addr;
      entry.load_addr = load_addr;
      entry.end_addr = end_addr;
      map_data[id] = entry;
    } else if (sscanf(line, "%[^@]@trace_load: %" PRIu64 ":%ub"
                      " %s",
                      prefix, &pid, &seqno, build_id) == 4) {
      uint64_t id = GET_ENTRY_ID(pid, seqno);
      auto entry_iter = map_data.find(id);
      if (entry_iter == map_data.end()) {
        FTL_LOG(ERROR) << "Missing entry (A record) for: " << line;
        continue;
      }
      (*entry_iter).second.build_id = build_id;
    } else if (sscanf(line, "%[^@]@trace_load: %" PRIu64 ":%uc"
                      " %s %s",
                      prefix, &pid, &seqno, name, so_name) == 5) {
      uint64_t id = GET_ENTRY_ID(pid, seqno);
      auto entry_iter = map_data.find(id);
      if (entry_iter == map_data.end()) {
        FTL_LOG(ERROR) << "Missing entry (A record) for: " << line;
        continue;
      }
      MapEntry& entry = (*entry_iter).second;
      entry.name = name;
      entry.so_name = so_name;
      // We should now have the full record.
      if (!AddMapEntry(entry)) {
        FTL_LOG(ERROR) << "Error adding map entry, last line: " << line;
      }
    } else {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
    }
  }

  free(line);
  fclose(f);

  return true;
}

bool DecoderState::ReadIdsFile(const std::string& file)
{
  FTL_LOG(INFO) << "Loading ids data from " << file;

  FILE* f = fopen(file.c_str(), "r");
  if (!f) {
    util::LogErrorWithErrno("error opening ids file");
    return false;
  }

  char* line = nullptr;
  size_t linelen = 0;
  int lineno = 1;

  for ( ; getline(&line, &linelen, f) > 0; ++lineno) {
    size_t n = strlen(line);
    if (n > 0 && line[n - 1] == '\n')
      line[n - 1] = '\0';
    FTL_VLOG(2) << ftl::StringPrintf("read %d: %s", lineno, line);

#define MAX_LINE_LEN 1024
    if (linelen > MAX_LINE_LEN) {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
      continue;
    }

    if (!strcmp(line, "\n"))
      continue;
    if (line[0] == '#')
      continue;

    char build_id[linelen];
    char path[linelen];
    if (sscanf(line, "%s %s", build_id, path) == 2) {
      AddBuildId(files::GetDirectoryName(file), build_id, path);
    } else {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
    }
  }

  free(line);
  fclose(f);

  return true;
}

bool DecoderState::ReadPtListFile(const std::string& file)
{
  FTL_LOG(INFO) << "Loading pt file list from " << file;

  FILE* f = fopen(file.c_str(), "r");
  if (!f) {
    util::LogErrorWithErrno("error opening pt file list file");
    return false;
  }

  char* line = nullptr;
  size_t linelen = 0;
  int lineno = 1;

  for ( ; getline(&line, &linelen, f) > 0; ++lineno) {
    size_t n = strlen(line);
    if (n > 0 && line[n - 1] == '\n')
      line[n - 1] = '\0';
    FTL_VLOG(2) << ftl::StringPrintf("read %d: %s", lineno, line);

#define MAX_LINE_LEN 1024
    if (linelen > MAX_LINE_LEN) {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
      continue;
    }

    if (!strcmp(line, "\n"))
      continue;
    if (line[0] == '#')
      continue;

    unsigned long long id;
    char path[linelen];
    if (sscanf(line, "%llu %s", &id, path) == 2) {
      AddPtFile(files::GetDirectoryName(file), id, path);
    } else {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
    }
  }

  free(line);
  fclose(f);

  return true;
}

} // intel_processor_trace
