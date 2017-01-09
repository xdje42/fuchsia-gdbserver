// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "util.h"

#include <errno.h>
#include <string.h>

#include <magenta/status.h>

#include "lib/ftl/logging.h"

namespace util {

const char* basename(const char* s) {
  // This implementation is copied from musl's basename.c.
  size_t i;
  if (!s || !*s)
    return ".";
  i = strlen(s) - 1;
  if (i > 0 && s[i] == '/')
    return s;
  for (; i && s[i - 1] != '/'; i--)
    ;
  return s + i;
}

void LogErrorWithErrno(const std::string& message) {
  FTL_LOG(ERROR) << message << " (errno = " << errno << ", \""
                 << strerror(errno) << "\")";
}

void LogErrorWithMxStatus(const std::string& message, mx_status_t status) {
  FTL_LOG(ERROR) << message << ": " << mx_status_get_string(status)
                 << " (" << status << ")";
}

}  // namespace util
