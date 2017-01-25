// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <launchpad/launchpad.h>
#include <magenta/syscalls/exception.h>
#include <magenta/types.h>

#include "lib/ftl/macros.h"
#include "lib/mtl/tasks/message_loop.h"
#include "lib/mtl/tasks/message_loop_handler.h"

#include "breakpoint.h"
#include "dso-list.h"
#include "exception-port.h"
#include "memory-process.h"
#include "thread.h"
#include "util.h"

namespace debugserver {

class Server;
class Thread;

// Represents an inferior process that the stub is currently attached to.
class Process final {
 public:
 public:
  enum class State { kNew, kStarting, kRunning, kGone };

  // Delegate interface for listening to Process life-time events.
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Called when a new that is part of this process has been started.
    virtual void OnThreadStarted(Process* process,
                                 Thread* thread,
                                 const mx_exception_context_t& context) = 0;

    // Called when |thread| has exited.
    virtual void OnThreadExit(
        Process* process,
        Thread* thread,
        const mx_excp_type_t type,
        const mx_exception_context_t& context) = 0;

    // Called when |process| has exited.
    virtual void OnProcessExit(
        Process* process,
        const mx_excp_type_t type,
        const mx_exception_context_t& context) = 0;

    // Called when the kernel reports an architectural exception.
    virtual void OnArchitecturalException(
        Process* process,
        Thread* thread,
        const mx_excp_type_t type,
        const mx_exception_context_t& context) = 0;
  };

  // Note: |argv| includes the program to debug in argv[0].
  // TODO(armansito): Add a different constructor later for attaching to an
  // already running process.
  explicit Process(Server* server,
                   Delegate* delegate,
                   const util::Argv& argv);
  ~Process();

  std::string GetName() const;

  // Note: This includes the program in |argv[0]|.
  const util::Argv& argv() { return argv_; }
  void set_argv(const util::Argv& argv) { argv_ = argv; }

  // Returns the current state of this process.
  State state() const { return state_; }

  // Change the state to |new_state|.
  void set_state(State new_state);

  static const char* StateName(Process::State state);

  // Creates and initializes the inferior process but does not start it. Returns
  // false if there is an error.
  // Do not call this if the process is currently live (state is kStarting or
  // kRunning).
  bool Initialize();

  // Binds an exception port for receiving exceptions from the inferior process.
  // Returns true on success, or false in the case of an error. Initialize MUST
  // be called successfully before calling Attach().
  bool Attach();

  // Detaches an attached process.
  void Detach();

  // Starts running the process. Returns false in case of an error. Initialize()
  // MUST be called successfully before calling Start().
  bool Start();

  // Returns true if the process has been started via a call to Start();
  bool started() const { return started_; }

  // Returns true if the process is currently attached.
  bool IsAttached() const;

  // Returns the process handle. This handle is owned and managed by this
  // Process instance, thus the caller should not close the handle.
  mx_handle_t handle() const { return debug_handle_; }

  // Returns the process ID.
  mx_koid_t id() const { return id_; }

  // Returns a mutable handle to the set of breakpoints managed by this process.
  arch::ProcessBreakpointSet* breakpoints() { return &breakpoints_; }

  // Returns the base load address of the dynamic linker.
  mx_vaddr_t base_address() const { return base_address_; }

  // Returns the entry point of the dynamic linker.
  mx_vaddr_t entry_address() const { return entry_address_; }

  // Returns the thread with the thread ID |thread_id| that's owned by this
  // process. Returns nullptr if no such thread exists. The returned pointer is
  // owned and managed by this Process instance.
  Thread* FindThreadById(mx_koid_t thread_id);

  // Returns an arbitrary thread that is owned by this process. This picks the
  // first thread that is returned from mx_object_get_info for the
  // MX_INFO_PROCESS_THREADS topic. This will refresh all threads.
  // TODO(dje): ISTR GNU gdbserver being more random to avoid starving threads.
  Thread* PickOneThread();

  // Refreshes the complete Thread list for this process. Returns false if an
  // error is returned from a syscall.
  bool RefreshAllThreads();

  // Iterates through all cached threads and invokes |callback| for each of
  // them. |callback| is guaranteed to get called only before ForEachThread()
  // returns, so it is safe to bind local variables to |callback|.
  using ThreadCallback = std::function<void(Thread*)>;
  void ForEachThread(const ThreadCallback& callback);
  // Same as ForEachThread except ignores State::Gone threads.
  void ForEachLiveThread(const ThreadCallback& callback);

  // Reads the block of memory of length |length| bytes starting at address
  // |address| into |out_buffer|. |out_buffer| must be at least as large as
  // |length|. Returns true on success or false on failure.
  bool ReadMemory(uintptr_t address, void* out_buffer, size_t length);

  // Writes the block of memory of length |length| bytes from |data| to the
  // memory address |address| of this process. Returns true on success or false
  // on failure.
  bool WriteMemory(uintptr_t address, const void* data, size_t length);

  // Fetch the process's exit code.
  int ExitCode();

  // Return true if dsos, including the main executable, have been loaded
  // into the inferior.
  bool DsosLoaded() { return dsos_ != nullptr; }

  // Return list of loaded dsos.
  // Returns nullptr if none loaded yet or loading failed.
  // TODO(dje): constness wip
  elf::dsoinfo_t* GetDsos() const { return dsos_; }

  // Return the entry for the main executable from the dsos list.
  // Returns nullptr if not present (could happen if inferior data structure
  // has been clobbered).
  const elf::dsoinfo_t* GetExecDso();

  // Return the DSO for |pc| or nullptr if none.
  // TODO(dje): Result is not const for debug file lookup.
  elf::dsoinfo_t* LookupDso(mx_vaddr_t pc) const;

  // Try building the dso list.
  // This one is for use by mydb.
  void TryBuildLoadedDsosList();

 private:
  Process() = default;

  // The exception handler invoked by ExceptionPort.
  void OnException(const mx_excp_type_t type,
                   const mx_exception_context_t& context);

  // Release all resources held by the process.
  // Called after all other processing of a process exit has been done.
  void Clear();

  // Build list of loaded dsos.
  // If |thread| is non-null it is the thread we stopped in and is used
  // by the rsp server: Only try to build the dso list when we stop at the
  // dynamic linker breakpoint.
  // TODO(dje): For the rsp server this is only called once, after the main
  // executable has been loaded. Therefore this list will not contain
  // subsequently loaded dsos.
  void TryBuildLoadedDsosList(Thread* thread);

  // The server that owns us.
  Server* server_;  // weak

  // The delegate that we send life-cycle notifications to.
  Delegate* delegate_;  // weak

  // The argv that this process was initialized with.
  util::Argv argv_;

  // The launchpad_t instance used to bootstrap and run the process. The Process
  // owns this instance and holds on to it until it gets destroyed.
  launchpad_t* launchpad_ = nullptr;

  // The debug-capable handle that we use to invoke mx_debug_* syscalls.
  mx_handle_t debug_handle_ = MX_HANDLE_INVALID;

  // The current state of this process.
  State state_ = State::kNew;

  // The process ID (also the kernel object ID).
  mx_koid_t id_ = MX_KOID_INVALID;

  // The base load address of the dynamic linker.
  mx_vaddr_t base_address_ = 0;

  // The entry point of the dynamic linker.
  mx_vaddr_t entry_address_ = 0;

  // The key we receive after binding an exception port.
  ExceptionPort::Key eport_key_ = 0;

  // True, if the inferior has been run via a call to Start().
  bool started_ = false;

  // The API to access memory.
  ProcessMemory memory_;

  // The collection of breakpoints that belong to this process.
  arch::ProcessBreakpointSet breakpoints_;

  // The threads owned by this process. This is map is populated lazily when
  // threads are requested through FindThreadById().
  using ThreadMap = std::unordered_map<mx_koid_t, std::unique_ptr<Thread>>;
  ThreadMap threads_;

  // List of dsos loaded.
  // NULL if none have been loaded yet (including main executable).
  // TODO(dje): Code taking from crashlogger, to be rewritten.
  // TODO(dje): Doesn't include dsos loaded later.
  elf::dsoinfo_t* dsos_ = nullptr;

  // If true then building the dso list failed, don't try again.
  bool dsos_build_failed_ = false;

  FTL_DISALLOW_COPY_AND_ASSIGN(Process);
};

}  // namespace debugserver
