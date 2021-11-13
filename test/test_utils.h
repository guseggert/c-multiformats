#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "cmocka.h"

extern struct CMUnitTest tests[];  // NOLINT
extern size_t num_tests;           // NOLINT

#define add_test(f) \
  tests[num_tests++] = (struct CMUnitTest) { #f, f, NULL, NULL, NULL }
