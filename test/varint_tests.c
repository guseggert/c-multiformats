#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmocka.h"
#include "test_utils.h"
#include "varint.h"

static void varint_test() {
  // 0 should return w/ size of 1
  {
    size_t varint_size = 0;
    varint_err err = uint64_to_varint(0, NULL, &varint_size);
    printf("varint_size: %lu\n", varint_size);
    uint8_t* varint = malloc(sizeof(uint8_t) * varint_size);
    err = uint64_to_varint(0, varint, &varint_size);
    assert_int_equal(0, err);
    assert_int_equal(1, varint_size);
    uint8_t expected[1] = {0};
    assert_memory_equal(expected, varint, varint_size);
    free(varint);
  }

  // (2^64)-1 should return correctly
  {
    size_t varint_size = 0;
    varint_err err = uint64_to_varint(UINT64_MAX, NULL, &varint_size);
    uint8_t* varint = malloc(sizeof(uint8_t) * varint_size);
    err = uint64_to_varint(UINT64_MAX, varint, &varint_size);
    assert_int_equal(0, err);
    assert_int_equal(10, varint_size);
    uint8_t expected[10] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 1};
    assert_memory_equal(expected, varint, varint_size);
    free(varint);
  }

  // happy case reading uint64 varint
  {
    uint8_t bytes[3] = {172 /*1010 1100*/, 2 /*0000 0010*/, 129};
    uint64_t val = 0;
    size_t varint_size = 0;
    varint_err err = varint_to_uint64(bytes, 3, &val, &varint_size);
    assert_int_equal(0, err);
    assert_int_equal(2, varint_size);
    assert_int_equal(300, val);
  }

  // reading invalid uint64 varint
  {
    uint8_t bytes[11] = {172 /*1010 1100*/, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172};
    uint64_t val = 0;
    size_t varint_size = 0;
    varint_err err = varint_to_uint64(bytes, 3, &val, &varint_size);
    assert_int_equal(VARINT_ERR_INVALID_INPUT, err);
  }
}

__attribute__((unused)) static void add_varint_tests() { add_test(varint_test); }
