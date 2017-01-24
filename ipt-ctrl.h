// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(dje): wip wip wip

#pragma once

#include "server-ipt.h"

namespace debugserver {

bool InitPerf(const PerfConfig& config);

bool StartPerf(const PerfConfig& config);

void StopPerf(const PerfConfig& config);

void DumpPerf(const PerfConfig& config);

void ResetPerf(const PerfConfig& config);

} // debugserver namespace
