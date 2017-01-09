
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

char* xstrdup(const char* s) {
  char* result = strdup(s);
  if (!result) {
    fprintf(stderr, "strdup OOM\n");
    exit(1);
  }
  return result;
}
