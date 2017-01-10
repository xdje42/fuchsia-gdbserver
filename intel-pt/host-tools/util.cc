
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/ftl/logging.h"

namespace util {

char* xstrdup(const char* s) {
  char* result = strdup(s);
  if (!result) {
    fprintf(stderr, "strdup OOM\n");
    exit(1);
  }
  return result;
}

const char* basename(const char* s) {
  // This implementation is copied from musl's basename.c.
  // It is different because it will not modify its argument.
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

#ifdef __Fuchsia__

void LogErrorWithMxStatus(const std::string& message, mx_status_t status) {
  FTL_LOG(ERROR) << message << ": " << mx_status_get_string(status)
                 << " (" << status << ")";
}

#endif

}  // namespace util
