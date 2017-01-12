
#include "state.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "lib/ftl/logging.h"
#include "lib/ftl/strings/string_printf.h"

#include "ktrace-reader.h"
#include "map.h"
#include "util.h"

bool IptDecoderState::ReadCpuidFile(const char* file) {
  FTL_LOG(INFO) << "Loading cpuid data from " << file;

  FILE* f = fopen(file, "r");
  if (!f) {
    util::LogErrorWithErrno("error opening cpuid file");
    return false;
  }

  char *line = nullptr;
  size_t linelen = 0;
  int lineno = 1;

  for ( ; getline(&line, &linelen, f) > 0; ++lineno) {
    size_t n = strlen(line);
    if (n > 0 && line[n - 1] == '\n')
      line[n - 1] = '\0';
    FTL_VLOG(2) << ftl::StringPrintf("read %d: %s", lineno, line);

    if (line[0] == '\0' || line[0] == '#')
      continue;

    if (sscanf(line, "tsc_ratio %u %u",
               &config_.cpuid_0x15_eax,
               &config_.cpuid_0x15_ebx) == 2) {
      /* ok */
    } else if (sscanf(line, "family %hu",
                      &config_.cpu.family) == 1) {
      config_.cpu.vendor = pcv_intel;
    } else if (sscanf(line, "model %hhu",
                      &config_.cpu.model) == 1) {
      /* ok */
    } else if (sscanf(line, "stepping %hhu",
                      &config_.cpu.stepping) == 1) {
    } else if (sscanf(line, "mtc_freq %hhu",
                      &config_.mtc_freq) == 1) {
      if (config_.mtc_freq)
        config_.mtc_freq--;
    } else if (sscanf(line, "nom_freq %hhu",
                      &config_.nom_freq) == 1) {
      tsc_freq_ = config_.nom_freq / 10.0;
    } else {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
    }
  }

  free(line);
  fclose(f);

  return true;
}

struct KtraceData {
  IptDecoderState* state;
};

static int ProcessKtraceRecord(perftools::ktrace::KtraceRecord* rec,
                               void* arg) {
  KtraceData* data = reinterpret_cast<KtraceData*>(arg);

  // We're interested in TAG_PROC_CREATE records. They let us connect cr3
  // values and process koids.

  if (rec->hdr.tag == TAG_PROC_CREATE) {
    ktrace_rec_32b* r = &rec->r_32B;

    uint64_t pid = r->a | ((uint64_t) r->b << 32);
    uint64_t cr3 = r->c | ((uint64_t) r->d << 32);

    if (!data->state->AddProcess(pid, cr3, r->ts)) {
      FTL_LOG(ERROR) << "Error adding process: " << pid;
    }
  }

  return 0;
}

bool IptDecoderState::ReadKtraceFile(const char* file) {
  FTL_LOG(INFO) << "Loading ktrace data from " << file;

  int fd = open(file, O_RDONLY);
  if (fd < 0) {
    util::LogErrorWithErrno("error opening ktrace file");
    return false;
  }

  KtraceData data = { this };
  int rc = perftools::ktrace::ReadFile(fd, ProcessKtraceRecord, &data);
  if (rc != 0) {
    FTL_LOG(ERROR) << ftl::StringPrintf("Error %d reading ktrace file", rc);
    return false;
  }

  close(fd);

  return true;
}

bool IptDecoderState::ReadMapFile(const char* file) {
  FTL_LOG(INFO) << "Loading map data from " << file;

  FILE* f = fopen(file, "r");
  if (!f) {
    util::LogErrorWithErrno("error opening map file");
    return false;
  }

  char *line = nullptr;
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
    }

    if (!strcmp(line, "\n"))
      continue;
    if (line[0] == '#')
      continue;

    // TODO(dje): replace with something more robust
    char buildid[linelen];
    char name[linelen];
    char so_name[linelen];
    // The sequence number is used for grouping records, done beforehand, but
    // is no longer needed after that.
    unsigned seqno;
    uint64_t pid, base_addr, load_addr, end_addr;
    if (sscanf(line, "trace_load: %" PRIu64 ":%x"
               " 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64
               " %s %s %s",
               &pid, &seqno, &base_addr, &load_addr, &end_addr,
               buildid, name, so_name) == 8) {
      if (!AddMap(pid, base_addr, load_addr, end_addr,
                  buildid, name, so_name)) {
        FTL_LOG(ERROR) << "Error adding map entry: " << line;
      }
    } else {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
    }
  }

  free(line);
  fclose(f);

  return true;
}

bool IptDecoderState::ReadIdsFile(const char* file) {
  FTL_LOG(INFO) << "Loading ids data from " << file;

  FILE* f = fopen(file, "r");
  if (!f) {
    util::LogErrorWithErrno("error opening ids file");
    return false;
  }

  char *line = nullptr;
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
    }

    if (!strcmp(line, "\n"))
      continue;
    if (line[0] == '#')
      continue;

    // TODO(dje): replace with something more robust
    char build_id[linelen];
    char path[linelen];
    if (sscanf(line, "%s %s", build_id, path) == 2) {
      if (!AddBuildId(file, build_id, path)) {
        FTL_LOG(ERROR) << "Error adding ids entry: " << line;
      }
    } else {
      FTL_VLOG(2) << ftl::StringPrintf("%d: ignoring: %s", lineno, line);
    }
  }

  free(line);
  fclose(f);

  return true;
}
