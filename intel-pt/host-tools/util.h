
#pragma once

#include <string>

#ifdef __Fuchsia__
#include <magenta/status.h>
#endif

namespace util {

char* xstrdup(const char* s);

// Same as basename, except will not modify |file|.
// This assumes there are no trailing /s. If there are then |file| is returned
// as is.
const char* basename(const char* s);

// Logs the given |message| using the global errno variable, including the
// result of strerror in a nicely formatted way.
void LogErrorWithErrno(const std::string& message);

#ifdef __Fuchsia__

// Logs the given |message| using the string representation of |status| in a
// nicely formatted way.
void LogErrorWithMxStatus(const std::string& message, mx_status_t status);

#endif

}  // namespace util
