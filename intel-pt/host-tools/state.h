
#pragma once

#include <vector>
#include <string>

#include <intel-pt.h>

struct Process {
  Process(uint64_t p, uint64_t c, uint64_t t);
  uint64_t pid;
  uint64_t cr3;
  uint64_t ts;
};

struct Map {
  Map(uint64_t p, uint64_t ba, uint64_t la, uint64_t ea,
      const char* bid, const char* n, const char* so);
  uint64_t pid;
  uint64_t base_addr;
  uint64_t load_addr;
  uint64_t end_addr;
  std::string buildid;
  std::string name;
  std::string so_name;
};

struct BuildId {
  BuildId(const std::string& b, const std::string& f);
  std::string build_id;
  std::string file;
};

class IptDecoderState {
 public:
  pt_config config_;
  pt_insn_decoder* decoder_;
  pt_image* image_;
  double tsc_freq_; // TODO(dje): See dtools.c.

  std::vector<Process> processes_;
  std::vector<Map> maps_;
  std::vector<BuildId> build_ids_;

  bool AllocDecoder(const char* pt_file);

  bool AllocImage(const char* name);

  bool ReadCpuidFile(const char* file);
  bool ReadKtraceFile(const char* file);
  bool ReadMapFile(const char* file);
  bool ReadIdsFile(const char* file);

  bool ReadElf(const char* file, uint64_t base, uint64_t cr3,
               uint64_t file_off, uint64_t map_len);
  bool ReadStaticElf(const char* file);

  bool AddProcess(uint64_t pid, uint64_t cr3, uint64_t ts);
  bool AddMap(uint64_t pid,
              uint64_t base_addr, uint64_t load_addr, uint64_t end_addr,
              const char* buildid, const char* name, const char* so_name);
  bool AddBuildId(const char* file, const char* build_id, const char* path);

  static int ReadMemCallback(uint8_t* buffer, size_t size,
                             const struct pt_asid* asid,
                             uint64_t addr, void* context);

  const Process* LookupProcess(uint64_t cr3);
  const Map* LookupMap(uint64_t pid, uint64_t addr);
  const BuildId* LookupBuildId(const std::string& bid);
  std::string LookupFile(const std::string& file);

  IptDecoderState();
  ~IptDecoderState();
};
