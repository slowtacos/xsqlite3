#pragma once
#include <stddef.h>
#include <stdio.h>

void die(const char *fmt, ...);
long eftell(FILE *stream);
int efseek(FILE *stream, long offset, int whence);
FILE *efopen(const char *pathname, const char *mode);
void *emalloc(size_t size);
int efclose(FILE *stream);
