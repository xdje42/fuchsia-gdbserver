// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include "lib/ftl/macros.h"
#include "lib/ftl/strings/string_view.h"

#include "util.h"

namespace debugserver {

class MydbServer;

namespace mydb {

class CommandEnvironment;

using Invoker = void (const util::Argv& argv, const CommandEnvironment& env);

struct Command {
  const char* name;
  const char* short_help;
  const char* long_help;
  Invoker* invoker;
};

class CommandEnvironment final {
 public:
  CommandEnvironment(MydbServer* server);
  ~CommandEnvironment() = default;

  // Look up command |name|.
  // Returns nullptr if not found.
  const Command* LookupCommand(const ftl::StringView& name) const;

  // Print |text| on the terminal.
  void Print(const ftl::StringView& text) const;

  MydbServer* server() const { return server_; }

  const std::vector<const Command*>& commands() const;

 private:
  MydbServer* server_;

  FTL_DISALLOW_COPY_AND_ASSIGN(CommandEnvironment);
};

class CommandHandler final {
 public:
  explicit CommandHandler(MydbServer* server);
  ~CommandHandler() = default;

  // Lookup command |name|.
  // Returns nullptr if not found.
  const Command* Lookup(const ftl::StringView& name) const;

  void Invoke(const ftl::StringView& command, const CommandEnvironment& env);

  // TODO(dje): visitor?
  const std::vector<const Command*>& commands() const { return commands_; }

 private:
  void Add(const Command* c);

  // Set of commands.
  std::vector<const Command*> commands_;

  // The root MydbServer instance that owns us.
  MydbServer* server_;  // weak

  FTL_DISALLOW_COPY_AND_ASSIGN(CommandHandler);
};

}  // namespace mydb
}  // namespace debugserver
