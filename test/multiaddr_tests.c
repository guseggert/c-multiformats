#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cmocka.h"
#include "multiaddr.h"
#include "multibase.h"
#include "test_utils.h"
#include "varint.h"

#ifndef __clang_analyzer__

static void test_ma_str_decode_next(const char* name, const char* multiaddr, ma_err expected_err, size_t comps_len, ...) {
  size_t multiaddr_len = strlen(multiaddr);
  ma_str_decoder decoder = {.multiaddr = multiaddr, .multiaddr_len = multiaddr_len};
  ma_str_comp cur_comp = {0};
  printf("TEST %s '%s'\n", name, multiaddr);

  ma_err err = MA_ERR_OK;

  va_list args;

  va_start(args, comps_len);

  size_t i = 0;
  while (!decoder.done && err == MA_ERR_OK) {
    printf("\tcomp %lu\n", i);
    err = ma_str_decode_next(&decoder, &cur_comp);
    if (err != MA_ERR_OK) {
      break;
    }
    ma_str_comp expected_comp = va_arg(args, ma_str_comp);
    assert_int_equal(expected_comp.proto_code, cur_comp.proto_code);
    assert_int_equal(expected_comp.value_len, cur_comp.value_len);
    assert_memory_equal(expected_comp.value, cur_comp.value, expected_comp.value_len);
    i++;
  }

  va_end(args);

  assert_int_equal(i, comps_len);
  assert_int_equal(expected_err, err);
  if (expected_err == MA_ERR_OK) {
    assert_true(decoder.done);
  }
}

static void ma_str_decode_next_tests() {
  test_ma_str_decode_next("decoding a path protocol should work",
                          "/unix/foo/bar",
                          MA_ERR_OK,
                          1,
                          (ma_str_comp){.proto_code = MA_PROTO_CODE_UNIX, .value = "/foo/bar", .value_len = 8});
  test_ma_str_decode_next("decoding a non-path protocol should work",
                          "/ip4/100.100.100.100",
                          MA_ERR_OK,
                          1,
                          (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "100.100.100.100", .value_len = 15});
  test_ma_str_decode_next("decoding [non-path, path, non-path] should only result in two components",
                          "/ip4/1.1.1.1/unix/foo/bar/ip4/1.1.1.1",
                          MA_ERR_OK,
                          2,
                          (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "1.1.1.1", .value_len = 7},
                          (ma_str_comp){.proto_code = MA_PROTO_CODE_UNIX, .value = "/foo/bar/ip4/1.1.1.1", .value_len = 20});
  test_ma_str_decode_next("decoding an empty string should return an error", "", MA_ERR_INVALID_INPUT, 0);

  // error cases
  test_ma_str_decode_next("decoding a protocol with a missing value should return an error", "/ip4", MA_ERR_INVALID_INPUT, 0);
  test_ma_str_decode_next("decoding a component with no protocol identifier should return an error", "//", MA_ERR_UNKNOWN_PROTOCOL, 0);
  test_ma_str_decode_next("decoding a component with no protocol id but followed by a valid component should return an error",
                          "///ip4/addr",
                          MA_ERR_UNKNOWN_PROTOCOL,
                          0);
  test_ma_str_decode_next("decoding a subsequent component with a missing value should return an error",
                          "/ip4/254.254.254.254/ip4",
                          MA_ERR_INVALID_INPUT,
                          1,
                          (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "254.254.254.254", .value_len = 15});
}

static void test_ma_str_encode(const char* name, const char* expected_str, ma_err expected_err, size_t comps_len, ...) {
  printf("TEST %s: '%s'\n", name, expected_str);
  va_list args;

  size_t expected_str_len = strlen(expected_str);

  ma_str_comp* comps = calloc(comps_len, sizeof(ma_str_comp));

  va_start(args, comps_len);
  for (size_t i = 0; i < comps_len; i++) {
    comps[i] = va_arg(args, ma_str_comp);
  }
  va_end(args);

  size_t str_len = 0;
  ma_err err = ma_str_encode(comps, comps_len, NULL, &str_len);
  assert_int_equal(expected_err, err);
  assert_int_equal(expected_str_len, str_len);

  char* str = calloc(str_len, sizeof(char));
  err = ma_str_encode(comps, comps_len, str, NULL);
  assert_int_equal(expected_err, err);

  assert_memory_equal(expected_str, str, str_len);

  free(str);
  free(comps);
}

static void ma_str_encode_tests() {
  test_ma_str_encode("encoding a single protocol should work",
                     "/ip4/1.1.1.1",
                     MA_ERR_OK,
                     1,
                     (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "1.1.1.1", .value_len = 7});
  test_ma_str_encode("encoding a protocol followed by path protocol should work",
                     "/ip4/127.0.0.1/unix/foo/bar",
                     MA_ERR_OK,
                     2,
                     (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "127.0.0.1", .value_len = 9},
                     (ma_str_comp){.proto_code = MA_PROTO_CODE_UNIX, .value = "/foo/bar", .value_len = 8});
  test_ma_str_encode("ip4: should reject a single leading zero",
                     "",
                     MA_ERR_INVALID_INPUT,
                     1,
                     (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "1.1.01.1", .value_len = 8});
  test_ma_str_encode("ip4: should reject multiple leading zeros",
                     "",
                     MA_ERR_INVALID_INPUT,
                     1,
                     (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "0000.0.0.0", .value_len = 10});
  test_ma_str_encode("ip4: should accept max value",
                     "/ip4/255.255.255.255",
                     MA_ERR_OK,
                     1,
                     (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "255.255.255.255", .value_len = 15});

  test_ma_str_encode("ip4: should accept zero values",
                     "/ip4/0.0.0.0",
                     MA_ERR_OK,
                     1,
                     (ma_str_comp){.proto_code = MA_PROTO_CODE_IP4, .value = "0.0.0.0", .value_len = 7});

  test_ma_str_encode("encoding no components should produce an empty string", "", MA_ERR_OK, 0);
  test_ma_str_encode("encoding a component with an unknown protocol id should return an error",
                     "",
                     MA_ERR_UNKNOWN_PROTOCOL,
                     1,
                     (ma_str_comp){.proto_code = 135135});
}

static void test_ma_bytes_decode_next(const char* name, const uint8_t* bytes, size_t bytes_len, ma_err expected_err, size_t comps_len,
                                      ...) {
  ma_bytes_decoder decoder = {.multiaddr = bytes, .multiaddr_size = bytes_len};
  ma_bytes_comp cur_comp = {0};

  char bytes_str[1000] = {0};
  size_t bytes_str_len = 0;
  mb_err err = mb_encode(bytes, bytes_len, MB_ENC_BASE16UPPER, (uint8_t*)bytes_str, 500, &bytes_str_len);
  assert_int_equal(MB_ERR_OK, err);
  bytes_str[bytes_str_len] = '\0';
  printf("TEST %s: '%s', len: %lu\n", name, bytes_str, bytes_len);

  va_list args;
  va_start(args, comps_len);
  for (size_t i = 0; i < comps_len; i++) {
    printf("\tcomp %lu\n", i);
    ma_bytes_comp expected_comp = va_arg(args, ma_bytes_comp);
    ma_err maerr = ma_bytes_decode_next(&decoder, &cur_comp);
    assert_int_equal(expected_err, maerr);
    assert_int_equal(expected_comp.proto_code, cur_comp.proto_code);
    assert_int_equal(expected_comp.value_size, cur_comp.value_size);
    assert_memory_equal(expected_comp.value, cur_comp.value, expected_comp.value_size);
  }
  va_end(args);
}

static void ma_bytes_decode_next_tests() {
  test_ma_bytes_decode_next("single protocol w/ constant-sized value",
                            (uint8_t[17]){0x06, 1, 2, 3},
                            17,
                            MA_ERR_OK,
                            1,
                            (ma_bytes_comp){.proto_code = MA_PROTO_CODE_TCP, .value = (uint8_t[16]){1, 2, 3}, .value_size = 16});

  test_ma_bytes_decode_next("two protocols w/ constant-sized values",
                            (uint8_t[34]){0x06, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06, 10},
                            34,
                            MA_ERR_OK,
                            2,
                            (ma_bytes_comp){.proto_code = MA_PROTO_CODE_TCP, .value = (uint8_t[16]){1, 2, 3}, .value_size = 16},
                            (ma_bytes_comp){.proto_code = MA_PROTO_CODE_TCP, .value = (uint8_t[16]){10}, .value_size = 16});

  test_ma_bytes_decode_next("single protocol w/ path value",
                            (uint8_t[6]){0x90, 0x03, 0x03, 1, 2, 3},
                            6,
                            MA_ERR_OK,
                            1,
                            (ma_bytes_comp){.proto_code = MA_PROTO_CODE_UNIX, .value = (uint8_t[3]){1, 2, 3}, .value_size = 3});

  test_ma_bytes_decode_next(
      "two path protocols are invalid", (uint8_t[11]){0x90, 0x03, 0x03, 1, 2, 3, 0x90, 0x03, 0x02, 4, 5}, 11, MA_ERR_INVALID_INPUT, 0);

  test_ma_bytes_decode_next("constant-sized protocol followed by path protocol",
                            (uint8_t[23]){0x06, 10, 11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x90, 0x03, 0x03, 1, 2, 3},
                            23,
                            MA_ERR_OK,
                            2,
                            (ma_bytes_comp){.proto_code = MA_PROTO_CODE_TCP, .value = (uint8_t[16]){10, 11, 12}, .value_size = 16},
                            (ma_bytes_comp){.proto_code = MA_PROTO_CODE_UNIX, .value = (uint8_t[3]){1, 2, 3}, .value_size = 3});

  /* ma_test_bytes_next_comp((uint8_t[23]){0x90, 0x03, 3, 1, 2, 3, 0x06, 1}, */
  /*                         23, */
  /*                         MA_ERR_OK, */
  /*                         2, */
  /*                         (ma_bytes_comp){.proto_code = MA_PROTO_CODE_UNIX, .value = (uint8_t[3]){1, 2, 3}, .value_size = 3}, */
  /*                         (ma_bytes_comp){.proto_code = MA_PROTO_CODE_TCP, .value = (uint8_t[16]){1, 2, 3}, .value_size = 16}); */

  test_ma_bytes_decode_next("constant-sized protocol is one byte too short", (uint8_t[16]){0x06, 1, 2, 3}, 16, MA_ERR_INVALID_INPUT, 0);
  test_ma_bytes_decode_next("constant-sized protocol is one byte too long", (uint8_t[18]){0x06, 1, 2, 3}, 18, MA_ERR_INVALID_INPUT, 0);
  test_ma_bytes_decode_next(
      "path protocol has value varint that points past the input", (uint8_t[5]){0x90, 0x03, 3, 1, 2}, 5, MA_ERR_INVALID_INPUT, 0);
  test_ma_bytes_decode_next("path protocol has value varint that points before the end of the input",
                            (uint8_t[7]){0x90, 0x03, 3, 1, 2, 3, 4},
                            7,
                            MA_ERR_INVALID_INPUT,
                            0);
}

/* ma_err ma_add_proto(ma_proto* proto); */

/* ma_err ma_proto_by_name(const char* name, const ma_proto** proto); */

/* ma_err ma_proto_by_code(ma_proto_code code, const ma_proto** proto); */

static void ma_verify_protocols_tests() {
  uint8_t varint[VARINT_UINT64_MAX_BYTES];
  size_t varint_size = 0;

  const ma_proto* cur = protos;
  while (cur != NULL) {
    printf("verifying protocol %s\n", cur->name);

    // verify that the protocol code varints are correct
    varint_err err = uint64_to_varint(cur->code, varint, &varint_size);
    assert_int_equal(0, err);
    assert_int_equal(varint_size, cur->code_varint_size);
    assert_memory_equal(varint, cur->code_varint, varint_size);
    cur = cur->next;
  }
}

__attribute__((unused)) static void add_multiaddr_tests() {
  add_test(ma_str_encode_tests);
  add_test(ma_str_decode_next_tests);
  add_test(ma_bytes_decode_next_tests);
  add_test(ma_verify_protocols_tests);
}

#endif
