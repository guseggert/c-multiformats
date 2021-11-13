#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cid_tests.c"  // NOLINT
#include "cmocka.h"
#include "multibase.h"
#include "multibase_tests.c"  // NOLINT
#include "multihash.h"
#include "multihash_tests.c"  // NOLINT
#include "varint.h"
#include "varint_tests.c"  // NOLINT

#ifndef __clang_analyzer__

struct CMUnitTest tests[1000] = {0}; // NOLINT
size_t num_tests = 0; // NOLINT

int main(void) {
  add_multibase_tests();
  add_varint_tests();
  add_multihash_tests();
  add_cid_tests();

  cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
