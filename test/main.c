#include <stddef.h>

#include "cid_tests.c"  // NOLINT
#include "cmocka.h"
#include "multiaddr_tests.c"  // NOLINT
#include "multibase_tests.c"  // NOLINT
#include "multihash_tests.c"  // NOLINT
#include "varint_tests.c"     // NOLINT

#ifndef __clang_analyzer__

// these are set by the add_test macro in test_utils.h
struct CMUnitTest tests[1000] = {0};  // NOLINT
size_t num_tests = 0;                 // NOLINT

int main(void) {
  add_multibase_tests();
  add_varint_tests();
  add_multihash_tests();
  add_cid_tests();
  add_multiaddr_tests();

  cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
