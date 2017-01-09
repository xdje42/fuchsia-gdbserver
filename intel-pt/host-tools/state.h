
#pragma once

#include <vector>
#include <string>

#include <intel-pt.h>

class IptDecoderState {
 public:
  pt_config config_;
  pt_insn_decoder* decoder_;
  pt_image* image_;

  void SetImage(pt_image* image);

  bool ReadCpuidFile(const char* file);
  bool ReadIdsFile(const char* file);
  bool ReadKtraceFile(const char* file);
  bool ReadMapFile(const char* file);

  bool AllocDecoder(const char* pt_file);

  bool ReadElf(const char* file);
  bool ReadStaticElf(const char* file);

  IptDecoderState();
  ~IptDecoderState();
};
