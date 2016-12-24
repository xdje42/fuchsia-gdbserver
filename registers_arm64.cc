// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "registers.h"

#include "lib/ftl/logging.h"

namespace debugserver {
namespace arch {

int GetPCRegisterNumber() {
  // TODO(armansito): Implement
  FTL_NOTIMPLEMENTED();
  return -1;
}

int GetFPRegisterNumber() {
  // TODO(armansito): Implement
  FTL_NOTIMPLEMENTED();
  return -1;
}

int GetSPRegisterNumber() {
  // TODO(armansito): Implement
  FTL_NOTIMPLEMENTED();
  return -1;
}

namespace {

class RegistersArm64 final : public Registers {
 public:
  RegistersArm64(Thread* thread) : Registers(thread) {}

  ~RegistersArm64() = default;

  bool IsSupported() override {
    FTL_NOTIMPLEMENTED();
    return false;
  }

  bool RefreshRegset(int regset) override {
    FTL_NOTIMPLEMENTED();
    return false;
  }

  bool WriteRegset(int regset) override {
    FTL_NOTIMPLEMENTED();
    return false;
  }

  std::string GetRegsetAsString(int regset) override {
    FTL_NOTIMPLEMENTED();
    return "";
  }

  bool SetRegset(int regset, const ftl::StringView& value) override {
    FTL_NOTIMPLEMENTED();
    return false;
  }

  std::string GetRegisterAsString(int regno) override {
    FTL_NOTIMPLEMENTED();
    return "";
  }

  bool GetRegister(int regno, void* buffer, size_t buf_size) override {
    FTL_NOTIMPLEMENTED();
    return false;
  }

  bool SetRegister(int regno, const void* value, size_t value_size) override {
    FTL_NOTIMPLEMENTED();
    return false;
  }

  bool SetSingleStep(bool enable) override {
    FTL_NOTIMPLEMENTED();
    return false;
  }

  std::string FormatRegset(int regset) override {
    return "unimplemented\n";
  }
};

}  // namespace

// static
std::unique_ptr<Registers> Registers::Create(Thread* thread) {
  return std::unique_ptr<Registers>(new RegistersArm64(thread));
}

// static
std::string Registers::GetUninitializedGeneralRegistersAsString() {
  // TODO(armansito): Implement.
  FTL_NOTIMPLEMENTED();
  return "";
}

// static
size_t Registers::GetRegisterSize() {
  FTL_NOTIMPLEMENTED();
  return 0;
}

}  // namespace arch
}  // namespace debugserver
