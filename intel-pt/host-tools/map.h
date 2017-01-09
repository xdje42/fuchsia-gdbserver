
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void *mapfile(char *fn, size_t *size);
void unmapfile(void *map, size_t size);

#ifdef __cplusplus
} // extern "C"
#endif
