// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <string>

#include <magenta/status.h>

namespace util {

// Same as basename, except will not modify |file|.
// This assumes there are no trailing /s. If there are then |file| is returned
// as is.
const char* basename(const char* s);

// Logs the given |message|.
void LogError(const std::string& message);

// Logs the given |message| using the global errno variable, including the
// result of strerror in a nicely formatted way.
void LogErrorWithErrno(const std::string& message);

// Logs the given |message| using the string representation of |status| in a
// nicely formatted way.
void LogErrorWithMxStatus(const std::string& message, mx_status_t status);

}  // namespace util
