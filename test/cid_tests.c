#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "cid.h"
#include "cmocka.h"
#include "test_utils.h"

#ifndef __clang_analyzer__

static void cid_read_version_cidv0() {
  uint8_t cid[34] = {0x12, 0x20};
  uint64_t actual_version = 0;
  cid_err err = cid_read_version(cid, 34, &actual_version);
  assert_string_equal("no error", CID_ERR_STRS[err]);
  assert_int_equal(0, actual_version);
}

static void cid_read_version_cidv1() {
  uint8_t cid[] = {0x01};
  uint64_t actual_version = 0;
  cid_err err = cid_read_version(cid, 1, &actual_version);
  assert_string_equal("no error", CID_ERR_STRS[err]);
  assert_int_equal(1, actual_version);
}

static void cid_read_version_cidv2() {
  uint8_t cid[] = {0x02};
  uint64_t actual_version = 0;
  cid_err err = cid_read_version(cid, 1, &actual_version);
  assert_string_equal("no error", CID_ERR_STRS[err]);
  assert_int_equal(2, actual_version);
}

static void cid_read_version_invalid_varint() {
  uint8_t cid[] = {0x80};
  cid_err err = cid_read_version(cid, 1, NULL);
  assert_string_equal("invalid CID", CID_ERR_STRS[err]);
}

static void cid_read_content_type_test() {
  uint8_t cid[] = {0x01, 0x02};
  uint64_t actual_content_type = 0;
  cid_err err = cid_read_content_type(cid, 2, &actual_content_type);
  assert_string_equal("no error", CID_ERR_STRS[err]);
  assert_int_equal(2, actual_content_type);
}

static void cid_read_content_type_invalid_varint() {
  uint8_t cid[] = {0x01, 0x80};
  cid_err err = cid_read_content_type(cid, 2, NULL);
  assert_string_equal("invalid CID", CID_ERR_STRS[err]);
}

static void cid_read_multihash_cidv0() {
  uint8_t cid[34] = {0x12, 0x20, 0x01};
  const uint8_t* multihash = NULL;
  size_t multihash_len = 0;
  cid_err err = cid_read_multihash(cid, 34, &multihash, &multihash_len);
  assert_string_equal("no error", CID_ERR_STRS[err]);
  assert_int_equal(34, multihash_len);
  assert_true(cid == multihash);
  assert_memory_equal(cid, multihash, 34);
}

static void cid_read_multihash_cidv1() {
  uint8_t cid[] = {0x01, 0x01, 0x01, 0x01};
  const uint8_t* multihash = NULL;
  size_t multihash_len = 0;
  cid_err err = cid_read_multihash(cid, 4, &multihash, &multihash_len);
  assert_string_equal("no error", CID_ERR_STRS[err]);
  assert_int_equal(2, multihash_len);
  assert_true(cid + 2 == multihash);
  assert_memory_equal(cid + 2, multihash, 2);
}

static void cid_read_multihash_cidv2() {
  uint8_t cid[] = {0x02, 0x02, 0x03};
  const uint8_t* multihash = NULL;
  size_t multihash_len = 0;
  cid_err err = cid_read_multihash(cid, 3, &multihash, &multihash_len);
  assert_int_equal(CID_ERR_UNSUPPORTED_VERSION, err);
}

static void cid_read_multihash_invalid_version() {
  uint8_t cid[] = {0x08, 0x02, 0x02};
  const uint8_t* multihash = NULL;
  size_t multihash_len = 0;
  cid_err err = cid_read_multihash(cid, 3, &multihash, &multihash_len);
  assert_int_equal(CID_ERR_INVALID_INPUT, err);
}

__attribute__((unused)) static void add_cid_tests() {
  add_test(cid_read_version_cidv0);
  add_test(cid_read_version_cidv1);
  add_test(cid_read_version_cidv2);
  add_test(cid_read_version_invalid_varint);
  add_test(cid_read_content_type_test);
  add_test(cid_read_content_type_invalid_varint);
  add_test(cid_read_multihash_cidv0);
  add_test(cid_read_multihash_cidv1);
  add_test(cid_read_multihash_cidv2);
  add_test(cid_read_multihash_invalid_version);
}

#endif
