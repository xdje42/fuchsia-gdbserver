// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include "lib/ftl/strings/string_view.h"

namespace debugserver {
namespace util {

// Fetch the next line from the console.
// Returns 0 for success, <0 for failure.
// Space for |line| is not guaranteed to survive the next call.
int readline(ftl::StringView* line);

// Set the title bar to |title|.
void settitle(const ftl::StringView& title);

// Set the prompt.
void set_prompt(const ftl::StringView& prompt);

// Return history entry |n|, n >= 0;
// Zero is the most recent entry.
// Space for the result is not guaranteed to survive the next call.
// Returns an empty string if there is no such entry.
ftl::StringView get_history(int n);

} // namespace util
} // namespace debugserver
