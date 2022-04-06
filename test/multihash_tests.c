#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmocka.h"
#include "multihash.h"
#include "test_utils.h"

static void mh_hash_sha2_256_test() {
  char* input_str = "hello, world";
  uint8_t* input = (uint8_t*)input_str;
  size_t result_size = 0;
  mh_err err = mh_digest_size(MH_FN_CODE_MURMUR3_X64_64, 13, &result_size);
  if (err) {
    printf("computing digest size: %s\n", mh_err_str(err));
    fail();
  }
  uint8_t* digest = calloc(result_size, sizeof(uint8_t));
  if (!digest) {
    printf("mem error allocating digest\n");
    fail();
  }
  err = mh_digest(input, 13, MH_FN_CODE_MURMUR3_X64_64, digest, result_size);
  if (err) {
    printf("computing digest: %s\n", mh_err_str(err));
    free(digest);
    fail();
  }
  printf("TEST digest input='%s' digest=", input_str);
  for (size_t i = 0; i < result_size; i++) {
    printf("%hhx", digest[i]);
  }
  printf("\n");
  free(digest);
}

__attribute__((unused)) static void add_multihash_tests() { add_test(mh_hash_sha2_256_test); }
