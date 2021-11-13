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
  uint8_t* input = (uint8_t*)"asdf";
  size_t result_len = 0;
  mh_err err = mh_digest_len(MH_FN_SHA2_256, 4, &result_len);
  if (err) {
    printf("computing digest length: %s\n", MH_ERR_STRS[err]);
    fail();
  }
  uint8_t* digest = calloc(result_len, sizeof(uint8_t));
  if (digest == NULL) {
    printf("mem error allocating digest\n");
    fail();
  }
  err = mh_hash(input, 4, MH_FN_SHA2_256, digest, result_len);
  if (err) {
    printf("computing digest: %s\n", MH_ERR_STRS[err]);
    free(digest);
    fail();
  }
  printf("digest: '");
  for (size_t i = 0; i < result_len; i++) {
    printf("%hhx", digest[i]);
  }
  printf("'\n");
  free(digest);
}

__attribute__((unused)) static void add_multihash_tests() { add_test(mh_hash_sha2_256_test); }
