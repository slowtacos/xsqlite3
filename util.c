/* See LICENSE file for copyright and license details. */
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

void die(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  if (fmt[0] && fmt[strlen(fmt)-1] == ':') {
    fputc(' ', stderr);
    perror(NULL);
  } else {
    fputc('\n', stderr);
  }
  exit(1);
}

long eftell(FILE *stream) {
  long r = ftell(stream);
  if (r == -1)
    die("ftell:");
  return r;
}

int efseek(FILE *stream, long offset, int whence) {
  int r = fseek(stream, offset, whence);
  if (r == -1)
    die("fseek:");
  return r;
}

void *emalloc(size_t size) {
  void *p = malloc(size);
  if (!p)
    die("malloc:");
  return p;
}

FILE *efopen(const char *pathname, const char *mode) {
  FILE *f = fopen(pathname, mode);
  if (!f)
    die("fopen:");
  return f;
}

int efclose(FILE *stream) {
  int r = fclose(stream);
  if (r != 0)
    die("fclose:");
  return r;
}
