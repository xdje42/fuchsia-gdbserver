
#include "state.h"

#include "lib/ftl/logging.h"

#include "map.h"

IptDecoderState::IptDecoderState()
    : decoder_(nullptr),
      image_(nullptr) {
}

IptDecoderState::~IptDecoderState() {
  if(decoder_)
    pt_insn_free_decoder(decoder_);
  if (image_)
    pt_image_free(image_);
}

bool IptDecoderState::ReadCpuidFile(const char* file) {
  return true;
}

bool IptDecoderState::ReadIdsFile(const char* file) {
  return true;
}

bool IptDecoderState::ReadKtraceFile(const char* file) {
  return true;
}

bool IptDecoderState::ReadMapFile(const char* file) {
  return true;
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

  struct pt_insn_decoder *decoder = pt_insn_alloc_decoder(&config_);
  if (!decoder) {
    fprintf(stderr, "Cannot create PT decoder\n");
    return false;
  }

  return true;
}

void IptDecoderState::SetImage(pt_image* image) {
  FTL_DCHECK(decoder_);
  FTL_DCHECK(image);
  pt_insn_set_image(decoder_, image);

  FTL_DCHECK(!image_);
  image_ = image;
}
