#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cmocka.h"
#include "multiaddr.h"
#include "test_utils.h"
#include "varint.h"

#ifndef __clang_analyzer__

static void test_ma_comps_str(char* expected_str, ma_err expected_err, size_t comps_len, ...) {
  ma_comp* comps = calloc(comps_len, sizeof(ma_comp));
  va_list args;
  va_start(args, comps_len);
  for (size_t i = 0; i < comps_len; i++) {
    comps[i] = va_arg(args, ma_comp);
  }
  va_end(args);

  printf("testing ma_comps_str, expecting: %s\n", expected_str);

  size_t comps_str_len = 0;
  ma_err err = ma_comps_str_len(comps, comps_len, &comps_str_len);
  if (expected_err) {
    if (err) {
      assert_int_equal(expected_err, err);
      free(comps);
      return;
    }
  } else {
    assert_int_equal(expected_err, err);
  }

  char* str = calloc(comps_str_len, sizeof(char));
  err = ma_comps_str(comps, comps_len, str);
  assert_int_equal(expected_err, err);

  assert_string_equal(expected_str, str);

  free(comps);
  free(str);
}

static void ma_comps_str_test() {
  test_ma_comps_str("/ip4/foo/unix/bar/baz",
                    MA_ERR_OK,
                    2,
                    (ma_comp){.proto = MA_PROTO_CODE_IP4, .value = "foo", .value_len = 3},
                    (ma_comp){.proto = MA_PROTO_CODE_UNIX, .value = "/bar/baz", .value_len = 8});
  test_ma_comps_str("/ip4/foo", MA_ERR_OK, 1, (ma_comp){.proto = MA_PROTO_CODE_IP4, .value = "foo", .value_len = 3});
  test_ma_comps_str(NULL, MA_ERR_UNKNOWN_PROTOCOL, 1, (ma_comp){.proto = 123123, .value = "foo", .value_len = 3});
}

static void ma_str_next_comp_happy_test() {
  ma_str_parse_state state = {.multiaddr = "/ip4/foo/unix/bar/baz"};
  ma_comp comp = {0};

  ma_err err = ma_str_next_comp(&state, &comp);
  assert_int_equal(0, err);
  assert_false(state.done);
  assert_int_equal(MA_PROTO_CODE_IP4, comp.proto);
  assert_int_equal(3, comp.value_len);
  assert_memory_equal("foo", comp.value, 3);

  err = ma_str_next_comp(&state, &comp);
  assert_int_equal(0, err);
  assert_false(state.done);
  assert_int_equal(MA_PROTO_CODE_UNIX, comp.proto);
  assert_int_equal(8, comp.value_len);
  assert_memory_equal("/bar/baz", comp.value, 8);

  err = ma_str_next_comp(&state, &comp);
  assert_int_equal(0, err);
  assert_true(state.done);
}

static void ma_verify_protocols_test() {
  uint8_t varint[UINT64_MAX_BYTES];
  size_t varint_len = 0;

  const ma_proto* cur = protos;
  while (cur != NULL) {
    printf("verifying protocol %s\n", cur->name);

    varint_err err = uint64_to_varint(cur->code, varint, &varint_len);
    assert_int_equal(0, err);
    assert_int_equal(varint_len, cur->code_varint_len);
    assert_memory_equal(varint, cur->code_varint, varint_len);
    cur = cur->next;
  }
}

__attribute__((unused)) static void add_multiaddr_tests() {
  add_test(ma_comps_str_test);
  add_test(ma_str_next_comp_happy_test);
  add_test(ma_verify_protocols_test);
}

#endif
