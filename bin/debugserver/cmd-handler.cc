// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cmd-handler.h"

#include <algorithm>
#include <cinttypes>
#include <string>

#include "debugger-utils/util.h"

#include "inferior-control/registers.h"
#include "inferior-control/thread.h"

#include "lib/ftl/logging.h"
#include "lib/ftl/strings/split_string.h"
#include "lib/ftl/strings/string_number_conversions.h"
#include "lib/ftl/strings/string_printf.h"

#include "server.h"
#include "thread-action-list.h"
#include "util.h"

namespace debugserver {

namespace {

const char kSupportedFeatures[] =
    "QNonStop+;"
#if 0  // TODO(dje)
  "QThreadEvents+;"
#endif
#if 0  // TODO(dje)
  "swbreak+;"
#endif
    "qXfer:auxv:read+";

const char kAttached[] = "Attached";
const char kCurrentThreadId[] = "C";
const char kFirstThreadInfo[] = "fThreadInfo";
const char kNonStop[] = "NonStop";
const char kRcmd[] = "Rcmd,";
const char kSubsequentThreadInfo[] = "sThreadInfo";
const char kSupported[] = "Supported";
const char kXfer[] = "Xfer";

// v Commands
const char kAttach[] = "Attach;";
const char kCont[] = "Cont;";
const char kKill[] = "Kill;";
const char kRun[] = "Run;";

// qRcmd commands
const char kExit[] = "exit";
const char kHelp[] = "help";
const char kQuit[] = "quit";

// This always returns true so that command handlers can simple call "return
// ReplyOK()" rather than "ReplyOK(); return true;
bool ReplyOK(const CommandHandler::ResponseCallback& callback) {
  callback("OK");
  return true;
}

// This always returns true so that command handlers can simple call "return
// ReplyWithError()" rather than "ReplyWithError(); return true;
bool ReplyWithError(util::ErrorCode error_code,
                    const CommandHandler::ResponseCallback& callback) {
  std::string error_rsp = util::BuildErrorPacket(error_code);
  callback(error_rsp);
  return true;
}

// Returns true if |str| starts with |prefix|.
bool StartsWith(const ftl::StringView& str, const ftl::StringView& prefix) {
  return str.substr(0, prefix.size()) == prefix;
}

std::vector<std::string> BuildArgvFor_vRun(const ftl::StringView& packet) {
  std::vector<std::string> argv;
  size_t len = packet.size();
  size_t s = 0;

  while (s < len) {
    size_t semi = packet.find(';', s);
    size_t n;
    if (semi == ftl::StringView::npos)
      n = len - s;
    else
      n = semi - s;
    std::vector<uint8_t> arg = util::DecodeByteArrayString(packet.substr(s, n));
    auto char_arg = reinterpret_cast<char*>(arg.data());
    argv.push_back(std::string(char_arg, arg.size()));
    if (semi == ftl::StringView::npos)
      s = len;
    else
      s = semi + 1;
  }

  return argv;
}

}  // namespace

CommandHandler::CommandHandler(Server* server)
    : server_(server), in_thread_info_sequence_(false) {
  FTL_DCHECK(server_);
}

bool CommandHandler::HandleCommand(const ftl::StringView& packet,
                                   const ResponseCallback& callback) {
  // GDB packets are prefixed with a letter that maps to a particular command
  // "family". We do the initial multiplexing here and let each individual
  // sub-handler deal with the rest.
  if (packet.empty()) {
    // TODO(armansito): Is there anything meaningful that we can do here?
    FTL_LOG(ERROR) << "Empty packet received";
    return false;
  }

  switch (packet[0]) {
    case '?':  // Indicate the reason the target halted
      if (packet.size() > 1)
        break;
      return HandleQuestionMark(callback);
    case 'c':  // Continue (at addr)
      return Handle_c(packet.substr(1), callback);
    case 'C':  // Continue with signal (optionally at addr)
      return Handle_C(packet.substr(1), callback);
    case 'D':  // Detach
      return Handle_D(packet.substr(1), callback);
    case 'g':  // Read general registers
      if (packet.size() > 1)
        break;
      return Handle_g(callback);
    case 'G':  // Write general registers
      return Handle_G(packet.substr(1), callback);
    case 'H':  // Set a thread for subsequent operations
      return Handle_H(packet.substr(1), callback);
    case 'm':  // Read memory
      return Handle_m(packet.substr(1), callback);
    case 'M':  // Write memory
      return Handle_M(packet.substr(1), callback);
    case 'q':  // General query packet
    case 'Q':  // General set packet
    {
      ftl::StringView prefix, params;
      util::ExtractParameters(packet.substr(1), &prefix, &params);

      FTL_VLOG(1) << "\'" << packet[0] << "\' packet - prefix: " << prefix
                  << ", params: " << params;

      if (packet[0] == 'q')
        return Handle_q(prefix, params, callback);
      return Handle_Q(prefix, params, callback);
    }
    case 'v':  // v-packets
      return Handle_v(packet.substr(1), callback);
    case 'z':  // Remove software breakpoint
    case 'Z':  // Insert software breakpoint
      return Handle_zZ(packet[0] == 'Z', packet.substr(1), callback);
    default:
      break;
  }

  return false;
}

bool CommandHandler::HandleQuestionMark(const ResponseCallback& callback) {
  // TODO(armansito): Implement this once we actually listen to thread/process
  // exceptions. The logic for NonStop mode is fairly simple:
  //    1. Tell Server to drop any pending and/or queued Stop Reply
  //    notifications.
  //
  //    2. Go through all processes and send a notification for the status of
  //    each.
  //
  //    3. If there is no inferior or the current inferior is not started, then
  //    reply "OK".
  return ReplyOK(callback);
}

bool CommandHandler::Handle_c(const ftl::StringView& packet,
                              const ResponseCallback& callback) {
  // If there is no current process or if the current process isn't attached,
  // then report an error.
  Process* current_process = server_->current_process();
  if (!current_process || !current_process->IsAttached()) {
    FTL_LOG(ERROR) << "c: No inferior";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  Thread* current_thread = server_->current_thread();

  // If the packet contains an address parameter, then try to set the program
  // counter to then continue at that address. Otherwise, the PC register will
  // remain untouched.
  mx_vaddr_t addr;
  if (!packet.empty()) {
    if (!ftl::StringToNumberWithError<mx_vaddr_t>(packet, &addr,
                                                  ftl::Base::k16)) {
      FTL_LOG(ERROR) << "c: Malformed address given: " << packet;
      return ReplyWithError(util::ErrorCode::INVAL, callback);
    }

    // If there is no current thread, then report error. This is a special case
    // that means that the process hasn't started yet.
    if (!current_thread) {
      FTL_DCHECK(!current_process->IsLive());
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }

    if (!current_thread->registers()->RefreshGeneralRegisters()) {
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }
    if (!current_thread->registers()->SetRegister(arch::GetPCRegisterNumber(),
                                                  &addr, sizeof(addr))) {
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }
    if (!current_thread->registers()->WriteGeneralRegisters()) {
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }

    // TODO(armansito): Restore the PC register to its original state in case of
    // a failure condition below?
  }

  // If there is a current thread, then tell it to continue.
  if (current_thread) {
    if (!current_thread->Resume())
      return ReplyWithError(util::ErrorCode::PERM, callback);

    return ReplyOK(callback);
  }

  // There is no current thread. This means that the process hasn't been started
  // yet. We start it and set the current thread to the first one the kernel
  // gives us.
  // TODO(armansito): Remove this logic now that we handle
  // MX_EXCP_THREAD_STARTING?
  FTL_DCHECK(!current_process->IsLive());
  if (!current_process->Start()) {
    FTL_LOG(ERROR) << "c: Failed to start the current inferior";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  // Try to set the current thread.
  // TODO(armansito): Can this be racy?
  current_thread = current_process->PickOneThread();
  if (current_thread)
    server_->SetCurrentThread(current_thread);

  return ReplyOK(callback);
}

bool CommandHandler::Handle_C(const ftl::StringView& packet,
                              const ResponseCallback& callback) {
  // If there is no current process or if the current process isn't attached,
  // then report an error.
  Process* current_process = server_->current_process();
  if (!current_process || !current_process->IsAttached()) {
    FTL_LOG(ERROR) << "C: No inferior";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  Thread* current_thread = server_->current_thread();
  if (!current_thread) {
    FTL_LOG(ERROR) << "C: No current thread";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  // Parse the parameters. The packet format is: sig[;addr]
  size_t semicolon = packet.find(';');
  if (semicolon == ftl::StringView::npos)
    semicolon = packet.size();

  unsigned int signo;
  if (!ftl::StringToNumberWithError<unsigned int>(packet.substr(0, semicolon),
                                                  &signo, ftl::Base::k16)) {
    FTL_LOG(ERROR) << "C: Malformed packet: " << packet;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  int thread_signo = current_thread->GetGdbSignal();
  if (thread_signo < 0) {
    FTL_LOG(ERROR) << "C: Current thread has received no signal";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  if (static_cast<unsigned int>(thread_signo) != signo) {
    FTL_LOG(ERROR) << "C: Signal numbers don't match - actual: " << thread_signo
                   << ", received: " << signo;
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  auto addr_param = packet.substr(semicolon);

  // If the packet contains an address parameter, then try to set the program
  // counter to then continue at that address. Otherwise, the PC register will
  // remain untouched.
  // TODO(armansito): Make Thread::Resume take an optional address argument so
  // we don't have to keep repeating this code.
  if (!addr_param.empty()) {
    mx_vaddr_t addr;
    if (!ftl::StringToNumberWithError<mx_vaddr_t>(addr_param, &addr,
                                                  ftl::Base::k16)) {
      FTL_LOG(ERROR) << "C: Malformed address given: " << packet;
      return ReplyWithError(util::ErrorCode::INVAL, callback);
    }

    if (!current_thread->registers()->RefreshGeneralRegisters()) {
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }
    if (!current_thread->registers()->SetRegister(arch::GetPCRegisterNumber(),
                                                  &addr, sizeof(addr))) {
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }
    if (!current_thread->registers()->WriteGeneralRegisters()) {
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }

    // TODO(armansito): Restore the PC register to its original state in case of
    // a failure condition below?
  }

  if (!current_thread->Resume()) {
    FTL_LOG(ERROR) << "Failed to resume thread";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  return ReplyOK(callback);
}

bool CommandHandler::Handle_D(const ftl::StringView& packet,
                              const ResponseCallback& callback) {
  // If there is no current process or if the current process isn't attached,
  // then report an error.
  Process* current_process = server_->current_process();
  if (!current_process) {
    FTL_LOG(ERROR) << "D: No inferior";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  // For now we only support detaching from the one process we have.
  if (packet[0] == ';') {
    mx_koid_t pid;
    if (!ftl::StringToNumberWithError<mx_koid_t>(packet.substr(1), &pid,
                                                 ftl::Base::k16)) {
      FTL_LOG(ERROR) << "D: bad pid: " << packet;
      return ReplyWithError(util::ErrorCode::INVAL, callback);
    }
    if (pid != current_process->id()) {
      FTL_LOG(ERROR) << "D: unknown pid: " << pid;
      return ReplyWithError(util::ErrorCode::INVAL, callback);
    }
  } else if (packet != "") {
    FTL_LOG(ERROR) << "D: Malformed packet: " << packet;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  if (!current_process->IsAttached()) {
    FTL_LOG(ERROR) << "D: Not attached to process " << current_process->id();
    return ReplyWithError(util::ErrorCode::NOENT, callback);
  }

  if (!current_process->Detach()) {
    // At the moment this shouldn't happen, but we don't want to kill the
    // debug session because of it. The details of the failure are already
    // logged by Detach().
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }
  return ReplyOK(callback);
}

bool CommandHandler::Handle_g(const ResponseCallback& callback) {
  // If there is no current process or if the current process isn't attached,
  // then report an error.
  Process* current_process = server_->current_process();
  if (!current_process || !current_process->IsAttached()) {
    FTL_LOG(ERROR) << "g: No inferior";
    return ReplyWithError(util::ErrorCode::NOENT, callback);
  }

  // If there is no current thread, then we reply with "0"s for all registers.
  // TODO(armansito): gG packets are technically used to read/write "ALL"
  // registers, not just the general registers. We'll have to take this into
  // account in the future, though for now we're just supporting general
  // registers.
  std::string result;
  if (!server_->current_thread()) {
    result = arch::Registers::GetUninitializedGeneralRegistersAsString();
  } else {
    arch::Registers* regs = server_->current_thread()->registers();
    FTL_DCHECK(regs);
    result = regs->GetGeneralRegistersAsString();
  }

  if (result.empty()) {
    FTL_LOG(ERROR) << "g: Failed to read register values";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  callback(result);
  return true;
}

bool CommandHandler::Handle_G(const ftl::StringView& packet,
                              const ResponseCallback& callback) {
  // If there is no current process or if the current process isn't attached,
  // then report an error.
  Process* current_process = server_->current_process();
  if (!current_process || !current_process->IsAttached()) {
    FTL_LOG(ERROR) << "G: No inferior";
    return ReplyWithError(util::ErrorCode::NOENT, callback);
  }

  // If there is no current thread report an error.
  Thread* current_thread = server_->current_thread();
  if (!current_thread) {
    FTL_LOG(ERROR) << "G: No current thread";
    return ReplyWithError(util::ErrorCode::NOENT, callback);
  }

  // We pass the packet here directly since arch::Registers handles the parsing.
  // TODO(armansito): gG packets are technically used to read/write "ALL"
  // registers, not just the general registers. We'll have to take this into
  // account in the future, though for now we're just supporting general
  // registers.
  if (!current_thread->registers()->SetGeneralRegisters(packet)) {
    FTL_LOG(ERROR) << "G: Failed to write to general registers";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }
  if (!current_thread->registers()->WriteGeneralRegisters()) {
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  return ReplyOK(callback);
}

bool CommandHandler::Handle_H(const ftl::StringView& packet,
                              const ResponseCallback& callback) {
  // Here we set the "current thread" for subsequent operations
  // (‘m’, ‘M’, ‘g’, ‘G’, et.al.).
  // There are two types of an H packet. 'c' and 'g'. We claim to not support
  // 'c' because it's specified as deprecated.

  // Packet should at least contain 'c' or 'g' and some characters for the
  // thread id.
  if (packet.size() < 2)
    return ReplyWithError(util::ErrorCode::INVAL, callback);

  switch (packet[0]) {
    case 'c':  // fall through
    case 'g': {
      int64_t pid, tid;
      bool has_pid;
      if (!util::ParseThreadId(packet.substr(1), &has_pid, &pid, &tid))
        return ReplyWithError(util::ErrorCode::INVAL, callback);

      // We currently support debugging only one process.
      // TODO(armansito): What to do with a process ID? Replying with an empty
      // packet for now.
      if (has_pid) {
        FTL_LOG(WARNING)
            << "Specifying a pid while setting the current thread is"
            << " not supported";
        return false;
      }

      // Setting the current thread to "all threads" doesn't make much sense.
      if (tid < 0) {
        FTL_LOG(ERROR) << "Cannot set the current thread to all threads";
        return ReplyWithError(util::ErrorCode::INVAL, callback);
      }

      Process* current_process = server_->current_process();

      // Note that at this point we may have a process but are not necessarily
      // attached yet. GDB sends the Hg0 packet early on, and expects it to
      // succeed.
      if (!current_process) {
        FTL_LOG(ERROR) << "No inferior exists";

        // If we're given a positive thread ID but there is currently no
        // inferior, then report error?
        if (!tid) {
          FTL_LOG(ERROR) << "Cannot set a current thread with no inferior";
          return ReplyWithError(util::ErrorCode::PERM, callback);
        }

        FTL_LOG(WARNING) << "Setting current thread to NULL for tid=0";

        server_->SetCurrentThread(nullptr);
        return ReplyOK(callback);
      }

      // If the process hasn't started yet it will have no threads. Since "Hg0"
      // is one of the first things that GDB sends after a connection (and
      // since we don't run the process right away), we lie to GDB and set the
      // current thread to null.
      if (!current_process->IsLive()) {
        FTL_LOG(INFO) << "Current process has no threads yet but we pretend to "
                      << "set one";
        server_->SetCurrentThread(nullptr);
        return ReplyOK(callback);
      }

      current_process->EnsureThreadMapFresh();

      Thread* thread;

      // A thread ID value of 0 means "pick an arbitrary thread".
      if (tid == 0)
        thread = current_process->PickOneThread();
      else
        thread = current_process->FindThreadById(tid);

      if (!thread) {
        FTL_LOG(ERROR) << "Failed to set the current thread";
        return ReplyWithError(util::ErrorCode::PERM, callback);
      }

      server_->SetCurrentThread(thread);
      return ReplyOK(callback);
    }
    default:
      break;
  }

  return false;
}

bool CommandHandler::Handle_m(const ftl::StringView& packet,
                              const ResponseCallback& callback) {
  // If there is no current process or if the current process isn't attached,
  // then report an error.
  Process* current_process = server_->current_process();
  if (!current_process || !current_process->IsAttached()) {
    FTL_LOG(ERROR) << "m: No inferior";
    return ReplyWithError(util::ErrorCode::NOENT, callback);
  }

  // The "m" packet should have two arguments for addr and length, separated by
  // a single comma.
  auto params = ftl::SplitString(packet, ",", ftl::kKeepWhitespace,
                                 ftl::kSplitWantNonEmpty);
  if (params.size() != 2) {
    FTL_LOG(ERROR) << "m: Malformed packet: " << packet;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  uintptr_t addr;
  size_t length;
  if (!ftl::StringToNumberWithError<uintptr_t>(params[0], &addr,
                                               ftl::Base::k16) ||
      !ftl::StringToNumberWithError<size_t>(params[1], &length,
                                            ftl::Base::k16)) {
    FTL_LOG(ERROR) << "m: Malformed params: " << packet;
    return ReplyWithError(util::ErrorCode::NOENT, callback);
  }

  std::unique_ptr<uint8_t[]> buffer(new uint8_t[length]);
  if (!current_process->ReadMemory(addr, buffer.get(), length)) {
    FTL_LOG(ERROR) << "m: Failed to read memory";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  std::string result = util::EncodeByteArrayString(buffer.get(), length);
  callback(result);
  return true;
}

bool CommandHandler::Handle_M(const ftl::StringView& packet,
                              const ResponseCallback& callback) {
  // If there is no current process or if the current process isn't attached,
  // then report an error.
  Process* current_process = server_->current_process();
  if (!current_process || !current_process->IsAttached()) {
    FTL_LOG(ERROR) << "M: No inferior";
    return ReplyWithError(util::ErrorCode::NOENT, callback);
  }

  // The "M" packet parameters look like this: "addr,length:XX...".
  // First, extract the addr,len and data sections. Using ftl::kSplitWantAll
  // here since the data portion could technically be empty if the given length
  // is 0.
  auto params =
      ftl::SplitString(packet, ":", ftl::kKeepWhitespace, ftl::kSplitWantAll);
  if (params.size() != 2) {
    FTL_LOG(ERROR) << "M: Malformed packet: " << packet;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  ftl::StringView data = params[1];

  // Extract addr and len
  params = ftl::SplitString(params[0], ",", ftl::kKeepWhitespace,
                            ftl::kSplitWantNonEmpty);
  if (params.size() != 2) {
    FTL_LOG(ERROR) << "M: Malformed packet: " << packet;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  uintptr_t addr;
  size_t length;
  if (!ftl::StringToNumberWithError<uintptr_t>(params[0], &addr,
                                               ftl::Base::k16) ||
      !ftl::StringToNumberWithError<size_t>(params[1], &length,
                                            ftl::Base::k16)) {
    FTL_LOG(ERROR) << "M: Malformed params: " << packet;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  FTL_VLOG(1) << ftl::StringPrintf("M: addr=0x%" PRIxPTR ", len=%lu", addr,
                                   length);

  auto data_bytes = util::DecodeByteArrayString(data);
  if (data_bytes.size() != length) {
    FTL_LOG(ERROR) << "M: payload length doesn't match length argument - "
                   << "payload size: " << data_bytes.size()
                   << ", length requested: " << length;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  // Short-circuit if |length| is 0.
  if (length &&
      !current_process->WriteMemory(addr, data_bytes.data(), length)) {
    FTL_LOG(ERROR) << "M: Failed to write memory";

    // TODO(armansito): The error code definitions from GDB aren't really
    // granular enough to aid debug various error conditions (e.g. we may want
    // to report why the memory write failed based on the mx_status_t returned
    // from Magenta). (See TODO in util.h).
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  return ReplyOK(callback);
}

bool CommandHandler::Handle_q(const ftl::StringView& prefix,
                              const ftl::StringView& params,
                              const ResponseCallback& callback) {
  if (prefix == kAttached)
    return HandleQueryAttached(params, callback);

  if (prefix == kCurrentThreadId)
    return HandleQueryCurrentThreadId(params, callback);

  if (prefix == kFirstThreadInfo)
    return HandleQueryThreadInfo(true, callback);

  // The qRcmd packet is different than most. It uses , as a delimiter, not :.
  if (StartsWith(prefix, kRcmd))
    return HandleQueryRcmd(prefix.substr(std::strlen(kRcmd)), callback);

  if (prefix == kSubsequentThreadInfo)
    return HandleQueryThreadInfo(false, callback);

  if (prefix == kSupported)
    return HandleQuerySupported(params, callback);

  if (prefix == kXfer)
    return HandleQueryXfer(params, callback);

  return false;
}

bool CommandHandler::Handle_Q(const ftl::StringView& prefix,
                              const ftl::StringView& params,
                              const ResponseCallback& callback) {
  if (prefix == kNonStop)
    return HandleSetNonStop(params, callback);

  return false;
}

bool CommandHandler::Handle_v(const ftl::StringView& packet,
                              const ResponseCallback& callback) {
  if (StartsWith(packet, kAttach))
    return Handle_vAttach(packet.substr(std::strlen(kAttach)), callback);
  if (StartsWith(packet, kCont))
    return Handle_vCont(packet.substr(std::strlen(kCont)), callback);
  if (StartsWith(packet, kKill))
    return Handle_vKill(packet.substr(std::strlen(kKill)), callback);
  if (StartsWith(packet, kRun))
    return Handle_vRun(packet.substr(std::strlen(kRun)), callback);

  return false;
}

bool CommandHandler::Handle_zZ(bool insert,
                               const ftl::StringView& packet,
                               const ResponseCallback& callback) {
// Z0 needs more work. Disabled until ready.
// One issue is we need to support the swbreak feature.
#if 0
  // A Z packet contains the "type,addr,kind" parameters before all other
  // optional parameters, which follow an optional ';' character. Check to see
  // if there are any optional parameters:
  size_t semicolon = packet.find(';');

  // ftl::StringView::find returns npos if it can't find the character. Adjust
  // |semicolon| to point just beyond the end of |packet| so that
  // packet.substr() works..
  if (semicolon == ftl::StringView::npos)
    semicolon = packet.size();

  auto params = ftl::SplitString(packet.substr(0, semicolon), ",",
                                 ftl::kKeepWhitespace, ftl::kSplitWantNonEmpty);
  if (params.size() != 3) {
    FTL_LOG(ERROR) << "zZ: 3 required parameters missing";
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  size_t type;
  uintptr_t addr;
  size_t kind;
  if (!ftl::StringToNumberWithError<uintptr_t>(params[0], &type,
                                               ftl::Base::k16) ||
      !ftl::StringToNumberWithError<uintptr_t>(params[1], &addr,
                                               ftl::Base::k16) ||
      !ftl::StringToNumberWithError<size_t>(params[2], &kind, ftl::Base::k16)) {
    FTL_LOG(ERROR) << "zZ: Failed to parse |type|, |addr| and |kind|";
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  auto optional_params = packet.substr(semicolon);

  // "Remove breakpoint" packets don't contain any optional fields.
  if (!insert && !optional_params.empty()) {
    FTL_LOG(ERROR) << "zZ: Malformed packet";
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  switch (type) {
    case 0:
      if (insert)
        return InsertSoftwareBreakpoint(addr, kind, optional_params, callback);
      return RemoveSoftwareBreakpoint(addr, kind, callback);
    default:
      break;
  }

  FTL_LOG(WARNING) << "Breakpoints of type " << type
                   << " currently not supported";
#endif
  return false;
}

bool CommandHandler::HandleQueryAttached(const ftl::StringView& params,
                                         const ResponseCallback& callback) {
  // We don't support multiprocessing yet, so make sure we received the version
  // of qAttached that doesn't have a "pid" parameter.
  if (!params.empty())
    return ReplyWithError(util::ErrorCode::INVAL, callback);

  // The response is "1" if we attached to an existing process, or "0" if we
  // created a new one. We currently don't support the former, so always send
  // "0".
  callback("0");
  return true;
}

bool CommandHandler::HandleQueryCurrentThreadId(
    const ftl::StringView& params,
    const ResponseCallback& callback) {
  // The "qC" packet has no parameters.
  if (!params.empty())
    return ReplyWithError(util::ErrorCode::INVAL, callback);

  Thread* current_thread = server_->current_thread();
  if (!current_thread) {
    // If there is a current process and it has been started, pick one thread
    // and set that as the current one. This is our work around for lying to GDB
    // about setting a current thread in response to an early Hg0 packet.
    Process* current_process = server_->current_process();
    if (!current_process || !current_process->IsLive()) {
      FTL_LOG(ERROR) << "qC: Current thread has not been set";
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }

    FTL_VLOG(1) << "qC: Picking one arbitrary thread";
    current_thread = current_process->PickOneThread();
    if (!current_thread) {
      FTL_VLOG(1) << "qC: Failed to pick a thread";
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }
  }

  std::string thread_id =
      ftl::NumberToString<mx_koid_t>(current_thread->id(), ftl::Base::k16);

  std::string reply = "QC" + thread_id;
  callback(reply);
  return true;
}

bool CommandHandler::HandleQueryRcmd(const ftl::StringView& command,
                                     const ResponseCallback& callback) {
  auto cmd = util::DecodeString(command);

  // We support both because qemu uses "quit" and GNU gdbserver uses "exit".
  if (cmd == kQuit || cmd == kExit) {
    ReplyOK(callback);
    server_->PostQuitMessageLoop(true);
  } else if (cmd == kHelp) {
    std::string text;
    text += "help - print this help text\n";
    text += "exit - quit debugserver\n";
    text += "quit - quit debugserver\n";
    callback(util::EncodeString(text));
  } else {
    callback(util::EncodeString("Invalid monitor command\n"));
  }

  return true;
}

bool CommandHandler::HandleQuerySupported(const ftl::StringView& params,
                                          const ResponseCallback& callback) {
  // We ignore the parameters for qSupported. Respond with the supported
  // features.
  callback(kSupportedFeatures);
  return true;
}

bool CommandHandler::HandleSetNonStop(const ftl::StringView& params,
                                      const ResponseCallback& callback) {
  // The only values we accept are "1" and "0".
  if (params.size() != 1)
    return ReplyWithError(util::ErrorCode::INVAL, callback);

  // We currently only support non-stop mode.
  char value = params[0];
  if (value == '1')
    return ReplyOK(callback);

  if (value == '0')
    return ReplyWithError(util::ErrorCode::PERM, callback);

  FTL_LOG(ERROR) << "QNonStop received with invalid value: " << (unsigned)value;
  return ReplyWithError(util::ErrorCode::INVAL, callback);
}

bool CommandHandler::HandleQueryThreadInfo(bool is_first,
                                           const ResponseCallback& callback) {
  FTL_DCHECK(server_);

  Process* current_process = server_->current_process();
  if (!current_process) {
    FTL_LOG(ERROR) << "Current process is not set";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  // For the "first" thread info query we reply with the complete list of
  // threads and always report "end of list" for subsequent queries. The GDB
  // Remote Protocol does not seem to define a MTU, however, we could be running
  // on a platform with resource constraints that may require us to break up the
  // sequence into multiple packets. For now we do not worry about this.

  if (!is_first) {
    // This is a subsequent query. Check that a thread info query sequence was
    // started (just for sanity) and report end of list.
    if (!in_thread_info_sequence_) {
      FTL_LOG(ERROR) << "qsThreadInfo received without first receiving "
                     << "qfThreadInfo";
      return ReplyWithError(util::ErrorCode::PERM, callback);
    }

    in_thread_info_sequence_ = false;
    callback("l");
    return true;
  }

  // This is the first query. Check the sequence state for sanity.
  if (in_thread_info_sequence_) {
    FTL_LOG(ERROR) << "qfThreadInfo received while already in an active "
                   << "sequence";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  current_process->EnsureThreadMapFresh();

  std::deque<std::string> thread_ids;
  size_t buf_size = 0;
  current_process->ForEachLiveThread([&thread_ids, &buf_size](Thread* thread) {
    std::string thread_id =
        ftl::NumberToString<mx_koid_t>(thread->id(), ftl::Base::k16);
    buf_size += thread_id.length();
    thread_ids.push_back(thread_id);
  });

  if (thread_ids.empty()) {
    // No ids to report. End of sequence.
    callback("l");
    return true;
  }

  in_thread_info_sequence_ = true;

  // Add the number of commas (|thread_ids.size() - 1|) plus the prefix "m")
  buf_size += thread_ids.size();

  std::unique_ptr<char[]> buffer(new char[buf_size]);
  buffer.get()[0] = 'm';
  util::JoinStrings(thread_ids, ',', buffer.get() + 1, buf_size - 1);

  callback(ftl::StringView(buffer.get(), buf_size));

  return true;
}

bool CommandHandler::HandleQueryXfer(const ftl::StringView& params,
                                     const ResponseCallback& callback) {
  // We only support qXfer:auxv:read::
  ftl::StringView auxv_read("auxv:read::");
  if (!StartsWith(params, auxv_read))
    return false;

  // Parse offset,length
  auto args = ftl::SplitString(params.substr(auxv_read.size()), ",",
                               ftl::kKeepWhitespace, ftl::kSplitWantNonEmpty);
  if (args.size() != 2) {
    FTL_LOG(ERROR) << "qXfer:auxv:read:: Malformed params: " << params;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  size_t offset, length;
  if (!ftl::StringToNumberWithError<size_t>(args[0], &offset, ftl::Base::k16) ||
      !ftl::StringToNumberWithError<size_t>(args[1], &length, ftl::Base::k16)) {
    FTL_LOG(ERROR) << "qXfer:auxv:read:: Malformed params: " << params;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  Process* current_process = server_->current_process();
  if (!current_process) {
    FTL_LOG(ERROR) << "qXfer:auxv:read: No current process is not set";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  // Build the auxiliary vector. This definition is provided by the Linux manual
  // page for the proc pseudo-filesystem (i.e. 'man proc'):
  // "This contains the contents of the ELF interpreter information passed to
  // the process at exec time. The format is one unsigned long ID plus one
  // unsigned long value for each entry. The last entry contains two zeros."
  // On Fuchsia we borrow this concept to save inventing something new.
  // We may have to eventually, but this works for now.
  // There is an extra complication that all the needed values aren't available
  // when the process starts: e.g., AT_ENTRY - the executable isn't loaded
  // until sometime after the process starts.
  constexpr size_t kMaxAuxvEntries = 10;
  struct {
    unsigned long key;
    unsigned long value;
  } auxv[kMaxAuxvEntries];

#define ADD_AUXV(_key, _value) \
  do {                         \
    auxv[n].key = (_key);      \
    auxv[n].value = (_value);  \
    ++n;                       \
  } while (0)

  size_t n = 0;
  ADD_AUXV(AT_BASE, current_process->base_address());
  if (current_process->DsosLoaded()) {
    const util::dsoinfo_t* exec = current_process->GetExecDso();
    if (exec) {
      ADD_AUXV(AT_ENTRY, exec->entry);
      ADD_AUXV(AT_PHDR, exec->phdr);
      ADD_AUXV(AT_PHENT, exec->phentsize);
      ADD_AUXV(AT_PHNUM, exec->phnum);
    }
  }
  ADD_AUXV(AT_NULL, 0);
  FTL_DCHECK(n <= countof(auxv));

#undef ADD_AUXV

  // We allow setting sizeof(auxv) as the offset, which would effectively result
  // in reading 0 bytes.
  if (offset > sizeof(auxv)) {
    FTL_LOG(ERROR) << "qXfer:auxv:read: invalid offset";
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  size_t end = n * sizeof(auxv[0]);
  size_t rsp_len = std::min(end - offset, length);
  char rsp[1 + rsp_len];

  rsp[0] = 'l';
  memcpy(rsp + 1, auxv + offset, rsp_len);

  callback(ftl::StringView(rsp, sizeof(rsp)));
  return true;
}

bool CommandHandler::Handle_vAttach(const ftl::StringView& packet,
                                    const ResponseCallback& callback) {
  // TODO(dje): The terminology we use makes this confusing.
  // Here when you see "process" think "inferior". An inferior must be created
  // first, and then we can attach the inferior to a process.
  Process* current_process = server_->current_process();
  if (!current_process) {
    FTL_LOG(ERROR) << "vAttach: no inferior selected";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  mx_koid_t pid;
  if (!ftl::StringToNumberWithError<mx_koid_t>(packet, &pid, ftl::Base::k16)) {
    FTL_LOG(ERROR) << "vAttach:: Malformed pid: " << packet;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  switch (current_process->state()) {
    case Process::State::kNew:
    case Process::State::kGone:
      break;
    default:
      FTL_LOG(ERROR)
          << "vAttach: need to kill the currently running process first";
      return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  if (!current_process->Initialize(pid)) {
    FTL_LOG(ERROR) << "Failed to set up inferior";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  FTL_DCHECK(!current_process->IsAttached());
  if (!current_process->Attach()) {
    FTL_LOG(ERROR) << "vAttach: Failed to attach process!";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }
  FTL_DCHECK(current_process->IsAttached());

  // It's Attach()'s job to mark the process as live, since it knows we just
  // attached to an already running program.
  FTL_DCHECK(current_process->IsLive());

  return ReplyOK(callback);
}

bool CommandHandler::Handle_vCont(const ftl::StringView& packet,
                                  const ResponseCallback& callback) {
  Process* current_process = server_->current_process();
  if (!current_process) {
    FTL_LOG(ERROR) << "vCont: no current process to run!";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  ThreadActionList actions(packet, current_process->id());
  if (!actions.valid()) {
    FTL_LOG(ERROR) << "vCont: \"" << packet << "\": error / not supported.";
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  FTL_DCHECK(current_process->IsLive());
  FTL_DCHECK(current_process->IsAttached());

  // Before we start calling GetAction we need to resolve "pick one" thread
  // values.
  for (auto e : actions.actions()) {
    if (e.tid() == 0) {
      FTL_DCHECK(e.pid() > 0);
      // TODO(dje): For now we assume there is only one process.
      FTL_DCHECK(current_process->id() == e.pid() ||
                 e.pid() == ThreadActionList::kAll);
      Thread* t = current_process->PickOneThread();
      if (t)
        e.set_picked_tid(t->id());
    }
  }
  actions.MarkPickOnesResolved();

  // First pass over all actions: Find any errors that we can so that we
  // don't cause any thread to run if there's an error.

  bool action_list_ok = true;
  current_process->ForEachLiveThread(
      [&actions, ok_ptr = &action_list_ok](Thread * thread) {
        mx_koid_t pid = thread->process()->id();
        mx_koid_t tid = thread->id();
        ThreadActionList::Action action = actions.GetAction(pid, tid);
        switch (action) {
          case ThreadActionList::Action::kStep:
            switch (thread->state()) {
              case Thread::State::kNew:
                FTL_LOG(ERROR) << "vCont;s: can't step thread in kNew state";
                *ok_ptr = false;
                return;
              default:
                break;
            }
          default:
            break;
        }
      });
  if (!action_list_ok)
    return ReplyWithError(util::ErrorCode::INVAL, callback);

  current_process->ForEachLiveThread([&actions](Thread* thread) {
    mx_koid_t pid = thread->process()->id();
    mx_koid_t tid = thread->id();
    ThreadActionList::Action action = actions.GetAction(pid, tid);
    FTL_VLOG(1) << "vCont; Thread " << thread->GetDebugName()
                << " state: " << thread->StateName(thread->state())
                << " action: " << ThreadActionList::ActionToString(action);
    switch (action) {
      case ThreadActionList::Action::kContinue:
        switch (thread->state()) {
          case Thread::State::kNew:
          case Thread::State::kStopped:
            thread->Resume();
            break;
          default:
            break;
        }
      case ThreadActionList::Action::kStep:
        switch (thread->state()) {
          case Thread::State::kStopped:
            thread->Step();
            break;
          default:
            break;
        }
      default:
        break;
    }
  });

  // We defer sending a stop-reply packet. Server will send it out when threads
  // stop. At this point in time GDB is just expecting "OK".
  return ReplyOK(callback);
}

bool CommandHandler::Handle_vKill(const ftl::StringView& packet,
                                  const ResponseCallback& callback) {
  FTL_VLOG(2) << "Handle_vKill: " << packet;

  Process* current_process = server_->current_process();
  if (!current_process) {
    // This can't happen today, but it might eventually.
    FTL_LOG(ERROR) << "vRun: no current process to kill!";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  mx_koid_t pid;
  if (!ftl::StringToNumberWithError<mx_koid_t>(packet, &pid, ftl::Base::k16)) {
    FTL_LOG(ERROR) << "vAttach:: Malformed pid: " << packet;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  // Since we only support one process at the moment, only allow killing
  // that one.
  if (pid != current_process->id()) {
    FTL_LOG(ERROR) << "vAttach:: not our pid: " << pid;
    return ReplyWithError(util::ErrorCode::INVAL, callback);
  }

  switch (current_process->state()) {
    case Process::State::kNew:
    case Process::State::kGone:
      FTL_LOG(ERROR) << "vKill: process not running";
      return ReplyWithError(util::ErrorCode::PERM, callback);
    default:
      break;
  }

  if (!current_process->Kill()) {
    FTL_LOG(ERROR) << "Failed to kill inferior";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  return ReplyOK(callback);
}

bool CommandHandler::Handle_vRun(const ftl::StringView& packet,
                                 const ResponseCallback& callback) {
  FTL_VLOG(2) << "Handle_vRun: " << packet;

  Process* current_process = server_->current_process();
  if (!current_process) {
    // This can't happen today, but it might eventually.
    FTL_LOG(ERROR) << "vRun: no current process to run!";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  if (!packet.empty()) {
    std::vector<std::string> argv = BuildArgvFor_vRun(packet);
    current_process->set_argv(argv);
  }

  switch (current_process->state()) {
    case Process::State::kNew:
    case Process::State::kGone:
      break;
    default:
      FTL_LOG(ERROR)
          << "vRun: need to kill the currently running process first";
      return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  if (!current_process->Initialize()) {
    FTL_LOG(ERROR) << "Failed to set up inferior";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  FTL_DCHECK(!current_process->IsAttached());
  if (!current_process->Attach()) {
    FTL_LOG(ERROR) << "vRun: Failed to attach process!";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }
  FTL_DCHECK(current_process->IsAttached());

  // On Linux, the program is considered "live" after vRun, e.g. $pc is set. On
  // Magenta, calling mx_process_start (called by launchpad_start, which is
  // called by Process::Start()) creates a synthetic exception of type
  // MX_EXCP_START if a debugger is attached to the process and halts until a
  // call to mx_task_resume (i.e. called by Thread::Resume() in gdbserver).
  if (!current_process->Start()) {
    FTL_LOG(ERROR) << "vRun: Failed to start process";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  FTL_DCHECK(current_process->IsLive());

  // We defer sending a stop-reply packet. Server will send it out when it
  // receives an OnThreadStarting() event from |current_process|.

  return true;
}

bool CommandHandler::InsertSoftwareBreakpoint(
    uintptr_t addr,
    size_t kind,
    const ftl::StringView& optional_params,
    const ResponseCallback& callback) {
  FTL_VLOG(1) << ftl::StringPrintf(
      "Insert software breakpoint at %" PRIxPTR ", kind: %lu", addr, kind);

  Process* current_process = server_->current_process();
  if (!current_process) {
    FTL_LOG(ERROR) << "No current process exists";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  // TODO(armansito): Handle |optional_params|.

  if (!current_process->breakpoints()->InsertSoftwareBreakpoint(addr, kind)) {
    FTL_LOG(ERROR) << "Failed to insert software breakpoint";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  return ReplyOK(callback);
}

bool CommandHandler::RemoveSoftwareBreakpoint(
    uintptr_t addr,
    size_t kind,
    const ResponseCallback& callback) {
  FTL_VLOG(1) << ftl::StringPrintf("Remove software breakpoint at %" PRIxPTR,
                                   addr);

  Process* current_process = server_->current_process();
  if (!current_process) {
    FTL_LOG(ERROR) << "No current process exists";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  if (!current_process->breakpoints()->RemoveSoftwareBreakpoint(addr)) {
    FTL_LOG(ERROR) << "Failed to remove software breakpoint";
    return ReplyWithError(util::ErrorCode::PERM, callback);
  }

  return ReplyOK(callback);
}

}  // namespace debugserver
