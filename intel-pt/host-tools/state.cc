
#include "state.h"

#include <inttypes.h>

#include <string>

#include <intel-pt.h>

#include "lib/ftl/logging.h"
#include "lib/ftl/files/path.h"
#include "lib/ftl/strings/string_printf.h"

#include "map.h"

Process::Process(uint64_t p, uint64_t c, uint64_t t)
    : pid(p), cr3(c), ts(t) {
  FTL_VLOG(2) <<
    ftl::StringPrintf("pid %" PRId64 " cr3 0x%" PRIx64 " ts %" PRId64,
                      p, c, t);
}

Map::Map(uint64_t p, uint64_t ba, uint64_t la, uint64_t ea,
         const char* bid, const char* n, const char* so)
    : pid(p), base_addr(ba), load_addr(la), end_addr(ea),
      buildid(bid), name(n), so_name(so) {
  FTL_VLOG(2) <<
    ftl::StringPrintf("pid %" PRId64 ", base 0x%" PRIx64
                      ", load 0x%" PRIx64 ", end 0x%" PRIx64
                      ", buildid %s, name %s, soname %s",
                      p, ba, la, ea, bid, n, so);
}

BuildId::BuildId(const std::string& b, const std::string& f)
    : build_id(b), file(f) {
  FTL_VLOG(2) << ftl::StringPrintf("buildid %s, file %s",
                                   b.c_str(), f.c_str());
}

IptDecoderState::IptDecoderState()
    : decoder_(nullptr),
      image_(nullptr),
      tsc_freq_(0),
      kernel_cr3_(0) {
  pt_config_init(&config_);
}

IptDecoderState::~IptDecoderState() {
  if(decoder_)
    pt_insn_free_decoder(decoder_);
  if (image_)
    pt_image_free(image_);
}

bool IptDecoderState::AllocDecoder(const char* pt_file) {
  unsigned zero = 0;

  pt_cpu_errata(&config_.errata, &config_.cpu);
  /* When no bit is set, set all, as libipt does not keep up with newer
   * CPUs otherwise.
   */
  if (!memcmp(&config_.errata, &zero, 4))
    memset(&config_.errata,0xff, sizeof(config_.errata));

  size_t len;
  unsigned char* map =
    reinterpret_cast<unsigned char*>(mapfile(pt_file, &len));
  if (!map) {
    fprintf(stderr, "Cannot open PT file %s: %s\n", pt_file, strerror(errno));
    exit(1);
  }
  config_.begin = map;
  config_.end = map + len;

  decoder_ = pt_insn_alloc_decoder(&config_);
  if (!decoder_) {
    fprintf(stderr, "Cannot create PT decoder\n");
    return false;
  }

  return true;
}

const Process* IptDecoderState::LookupProcess(uint64_t cr3) {
  for (auto& p : processes_) {
    if (cr3 == p.cr3 ||
        // If tracing just userspace, cr3 values in the trace may be this
        cr3 == pt_asid_no_cr3)
      return &p;
  }

  return nullptr;
}

const Map* IptDecoderState::LookupMap(uint64_t pid, uint64_t addr) {
  for (auto& m : maps_) {
    if (pid == m.pid && addr >= m.load_addr && addr < m.end_addr)
      return &m;
  }

  return nullptr;
}

const BuildId* IptDecoderState::LookupBuildId(const std::string& bid) {
  for (auto& b : build_ids_) {
    if (bid == b.build_id)
      return &b;
  }

  return nullptr;
}

std::string IptDecoderState::LookupFile(const std::string& file) {
  // TODO: This function is here in case we need to do fancier lookup later.
  return file;
}

// static
int IptDecoderState::ReadMemCallback(uint8_t* buffer, size_t size,
                                     const struct pt_asid* asid,
                                     uint64_t addr, void* context) {
  auto state = reinterpret_cast<IptDecoderState*>(context);
  uint64_t cr3 = asid->cr3;

  auto proc = state->LookupProcess(cr3);
  if (!proc) {
    FTL_VLOG(1) << ftl::StringPrintf("process lookup failed for cr3:"
                                     " 0x%" PRIx64, cr3);
    return -pte_nomap;
  }

  auto map = state->LookupMap(proc->pid, addr);
  if (!map) {
    FTL_VLOG(1) << ftl::StringPrintf("map lookup failed for cr3/addr:"
                                     " 0x%" PRIx64 "/0x%" PRIx64,
                                     cr3, addr);
    return -pte_nomap;
  }

  auto bid = state->LookupBuildId(map->buildid);
  if (!bid) {
    FTL_VLOG(1) << ftl::StringPrintf("buildid not found: %s, for cr3/addr:"
                                     " 0x%" PRIx64 "/0x%" PRIx64,
                                     map->buildid.c_str(), cr3, addr);
    return -pte_nomap;
  }

  auto file = state->LookupFile(bid->file);
  if (!file.size()) {
    FTL_VLOG(1) << ftl::StringPrintf("file not found: %s, for buildid %s, cr3/addr:"
                                     " 0x%" PRIx64 "/0x%" PRIx64,
                                     bid->file.c_str(), map->buildid.c_str(),
                                     cr3, addr);
    return -pte_nomap;
  }

  if (!state->ReadElf(file.c_str(), map->base_addr, cr3,
                      0, map->end_addr - map->load_addr)) {
    FTL_VLOG(1) << "Reading ELF file failed: " << file;
    return -pte_nomap;
  }

  return pt_image_read_for_callback(state->image_, buffer, size, asid, addr);
}

bool IptDecoderState::AllocImage(const char* name) {
  FTL_DCHECK(decoder_);

  struct pt_image *image = pt_image_alloc(name);
  FTL_DCHECK(image);

  pt_image_set_callback(image, ReadMemCallback, this);
  pt_insn_set_image(decoder_, image);

  FTL_DCHECK(!image_);
  image_ = image;

  return true;
}

bool IptDecoderState::AddProcess(uint64_t pid, uint64_t cr3, uint64_t ts) {
  processes_.push_back(Process(pid, cr3, ts));
  return true;
}

bool IptDecoderState::AddMap(uint64_t pid, uint64_t base_addr,
                             uint64_t load_addr, uint64_t end_addr,
                             const char* buildid,
                             const char* name, const char* so_name) {
  maps_.push_back(Map(pid, base_addr, load_addr, end_addr,
                      buildid, name, so_name));
  return true;
}

bool IptDecoderState::AddBuildId(const char* file, const char* build_id,
                                 const char* path) {
  std::string abs_path;

  // Convert relative paths to absolute ones.
  if (*path != '/') {
    std::string file_dir = files::GetDirectoryName(file);
    std::string abs_file_dir = files::AbsolutePath(file_dir);
    // file may be /a/b/c and path may be c/d/e.
    // TODO(dje): For now assume that's true.
    abs_path = abs_file_dir + "/../" + std::string(path);
  } else {
    abs_path = path;
  }
  build_ids_.push_back(BuildId(build_id, abs_path));
  return true;
}
