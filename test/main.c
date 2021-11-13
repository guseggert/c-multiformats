#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cmocka.h"
#include "multibase.h"
#include "multihash.h"
#include "varint.h"

#ifndef __clang_analyzer__

static void varint() {
  // 0 should return w/ length of 1
  {
    uint8_t* varint = malloc(sizeof(uint8_t) * UINT64_MAX_BYTES);
    size_t varint_len = 0;
    varint_err_t err = uint64_to_varint(0, varint, &varint_len);
    assert_int_equal(0, err);
    assert_int_equal(1, varint_len);
    uint8_t expected[1] = {0};
    assert_memory_equal(expected, varint, varint_len);
    free(varint);
  }

  // (2^64)-1 should return correctly
  {
    uint8_t* varint = malloc(sizeof(uint8_t) * UINT64_MAX_BYTES);
    size_t varint_len = 0;
    varint_err_t err = uint64_to_varint(UINT64_MAX, varint, &varint_len);
    assert_int_equal(0, err);
    assert_int_equal(10, varint_len);
    uint8_t expected[10] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 1};
    assert_memory_equal(expected, varint, varint_len);
    free(varint);
  }

  // happy case reading uint64 varint
  {
    uint8_t bytes[3] = {172 /*1010 1100*/, 2 /*0000 0010*/, 129};
    uint64_t val = 0;
    size_t varint_len = 0;
    varint_err_t err = varint_to_uint64(bytes, 3, &val, &varint_len);
    assert_int_equal(0, err);
    assert_int_equal(2, varint_len);
    assert_int_equal(300, val);
  }

  // reading invalid uint64 varint
  {
    uint8_t bytes[11] = {172 /*1010 1100*/, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172};
    uint64_t val = 0;
    size_t varint_len = 0;
    varint_err_t err = varint_to_uint64(bytes, 3, &val, &varint_len);
    assert_int_equal(VARINT_ERR_INVALID_INPUT, err);
  }
}

static void mb_test_encode(char* input, size_t input_len, mb_enc_t encoding, char* expected, size_t expected_len, mb_err_t expected_err) {
  printf("testing encode: input=");
  for (unsigned long i = 0; i < strlen(input); i++) {
    printf("%02hhX", input[i]);
  }
  const char* encoding_name = NULL;
  mb_err_t enc_name_err = mb_enc_name(encoding, &encoding_name);
  if (enc_name_err) {
    fail_msg("error finding encoding name: %s", MB_ERR_STRS[enc_name_err]);
  }
  printf("\tencoding=%s\texpected=%s\n", encoding_name, expected);

  uint8_t* in = (uint8_t*)input;
  size_t res_len = mb_encode_len(in, input_len, encoding);
  uint8_t* res_buf = calloc(res_len, sizeof(uint8_t));
  size_t enc_bytes = 0;
  mb_err_t err = mb_encode(in, input_len, encoding, res_buf, res_len, &enc_bytes);

  printf("encoded (%lu)=", enc_bytes);
  for (unsigned long i = 0; i < res_len; i++) {
    printf("%c", res_buf[i]);
  }
  printf("\t");
  printf("hex=");
  for (unsigned long i = 0; i < res_len; i++) {
    printf("%02hhX", res_buf[i]);
  }
  printf("\n");

  const char* actual_err_str = MB_ERR_STRS[err];
  const char* expected_err_str = MB_ERR_STRS[expected_err];
  assert_string_equal(expected_err_str, actual_err_str);

  if (err) {
    goto cleanup;
  }

  assert_int_equal(expected_len, enc_bytes);
  assert_memory_equal(expected, res_buf, expected_len);

cleanup:
  free(res_buf);
}

static void mb_test_decode(char* input, size_t input_len, char* expected, size_t expected_len, mb_err_t expected_err) {
  printf("testing decode: input=%s\n", input);
  uint8_t* in = (uint8_t*)input;
  size_t res_len = mb_decode_len((uint8_t*)input, input_len);
  uint8_t* res_buf = calloc(res_len, sizeof(uint8_t));
  size_t dec_bytes = 0;
  mb_err_t err = mb_decode(in, input_len, NULL, res_buf, res_len, &dec_bytes);

  const char* actual_err_str = MB_ERR_STRS[err];
  const char* expected_err_str = MB_ERR_STRS[expected_err];
  assert_string_equal(expected_err_str, actual_err_str);

  if (err) {
    goto cleanup;
  }

  assert_int_equal(expected_len, dec_bytes);
  assert_memory_equal(expected, res_buf, expected_len);

cleanup:
  free(res_buf);
}

static void mb_encode_base2_test() {
  mb_test_encode("yes mani !", 10, MB_ENC_BASE2, "001111001011001010111001100100000011011010110000101101110011010010010000000100001", 81,
                 0);
  mb_test_encode("\x00yes mani !", 11, MB_ENC_BASE2,
                 "00000000001111001011001010111001100100000011011010110000101101110011010010010000000100001", 89, 0);
  mb_test_encode("\x00\x00yes mani !", 12, MB_ENC_BASE2,
                 "0000000000000000001111001011001010111001100100000011011010110000101101110011010010010000000100001", 97, 0);
}

static void mb_decode_base2_test() {
  mb_test_decode("001100001", 9, "a", 1, 0);
  mb_test_decode("00110000101100001", 17, "aa", 2, 0);
  mb_test_decode("001111001011001010111001100100000011011010110000101101110011010010010000000100001", 81, "yes mani !", 10, 0);
}

static void mb_encode_base64_test() {
  mb_test_encode("yes mani !", 10, MB_ENC_BASE64, "meWVzIG1hbmkgIQ", 15, 0);
  mb_test_encode("\x00yes mani !", 11, MB_ENC_BASE64, "mAHllcyBtYW5pICE", 16, 0);
  mb_test_encode("\x00\x00yes mani !", 12, MB_ENC_BASE64, "mAAB5ZXMgbWFuaSAh", 17, 0);
  mb_test_encode("\x01", 1, MB_ENC_BASE64, "mAQ", 3, 0);
  mb_test_encode("\x00", 1, MB_ENC_BASE64, "mAA", 3, 0);
  mb_test_encode("\x60\xff\xff\x51", 4, MB_ENC_BASE64, "mYP//UQ", 7, 0);
  mb_test_encode("\x8a\xa0\x2a\xd7", 4, MB_ENC_BASE64, "miqAq1w", 7, 0);
  mb_test_encode("\x2b", 1, MB_ENC_BASE64, "mKw", 3, 0);
}
static void mb_decode_base64_test() {
  mb_test_decode("mKw", 3, "\x2b", 1, 0);
  mb_test_decode("mAQ", 3, "\x01", 1, 0);
  mb_test_decode("mAA", 3, "\x00", 1, 0);
  mb_test_decode("mAAA", 4, "\x00\x00", 2, 0);
  mb_test_decode("mAAAA", 5, "\x00\x00\x00", 3, 0);
  mb_test_decode("mAAAAA", 6, "", 0, MB_ERR_INVALID_INPUT);
  mb_test_decode("mAAAAAA", 7, "\x00\x00\x00\x00", 4, 0);
  mb_test_decode("mAAAAAAA", 8, "\x00\x00\x00\x00\x00", 5, 0);
  mb_test_decode("mAAAAAAAA", 9, "\x00\x00\x00\x00\x00\x00", 6, 0);
  mb_test_decode("mAAAAAAAAA", 10, "", 0, MB_ERR_INVALID_INPUT);
  mb_test_decode("mAQE", 4, "\x01\x01", 2, 0);
  mb_test_decode("mAQEB", 5, "\x01\x01\x01", 3, 0);
  mb_test_decode("meWVzIG1hbmkgIQ", 15, "yes mani !", 10, 0);
  mb_test_decode("mAAB5ZXMgbWFuaSAh", 17, "\x00\x00yes mani !", 12, 0);
  mb_test_decode("m&#^#*&", 7, "", 0, MB_ERR_INVALID_INPUT);
  mb_test_decode("mYP//UQ", 7, "\x60\xff\xff\x51", 4, 0);
  mb_test_decode("miqAqA", 6, "", 0, MB_ERR_INVALID_INPUT);
}

static void mb_encode_base32_test() {
  mb_test_encode("yes mani !", 10, MB_ENC_BASE32, "bpfsxgidnmfxgsibb", 17, 0);
  mb_test_encode("\x00yes mani !", 11, MB_ENC_BASE32, "bab4wk4zanvqw42jaee", 19, 0);
  mb_test_encode("\x00\x00yes mani !", 12, MB_ENC_BASE32, "baaahszltebwwc3tjeaqq", 21, 0);
  mb_test_encode("", 0, MB_ENC_BASE32, "b", 1, 0);
}

static void mb_decode_base32_test() {
  mb_test_decode("bpfsxgidnmfxgsibb", 17, "yes mani !", 10, 0);
  mb_test_decode("bab4wk4zanvqw42jaee", 19, "\x00yes mani !", 11, 0);
  mb_test_decode("baaahszltebwwc3tjeaqq", 21, "\x00\x00yes mani !", 12, 0);
  mb_test_decode("b", 1, "", 0, 0);
  // todo(guseggert) more test cases
}

static void mb_encode_base32upper_test() {
  mb_test_encode("yes mani !", 10, MB_ENC_BASE32UPPER, "BPFSXGIDNMFXGSIBB", 17, 0);
  mb_test_encode("\x00yes mani !", 11, MB_ENC_BASE32UPPER, "BAB4WK4ZANVQW42JAEE", 19, 0);
  mb_test_encode("\x00\x00yes mani !", 12, MB_ENC_BASE32UPPER, "BAAAHSZLTEBWWC3TJEAQQ", 21, 0);
  mb_test_encode("", 0, MB_ENC_BASE32, "b", 1, 0);
}

static void mb_decode_base32upper_test() {
  mb_test_decode("BPFSXGIDNMFXGSIBB", 17, "yes mani !", 10, 0);
  mb_test_decode("BAB4WK4ZANVQW42JAEE", 19, "\x00yes mani !", 11, 0);
  mb_test_decode("BAAAHSZLTEBWWC3TJEAQQ", 21, "\x00\x00yes mani !", 12, 0);
  mb_test_decode("b", 1, "", 0, 0);
  // todo(guseggert) more test cases
}

static void mb_encode_base16_test() {
  mb_test_encode("yes mani !", 10, MB_ENC_BASE16, "f796573206d616e692021", 21, 0);
  mb_test_encode("\x00yes mani !", 11, MB_ENC_BASE16, "f00796573206d616e692021", 23, 0);
  mb_test_encode("\x00\x00yes mani !", 12, MB_ENC_BASE16, "f0000796573206d616e692021", 25, 0);
  mb_test_encode("", 0, MB_ENC_BASE16, "f", 1, 0);
}
static void mb_decode_base16_test() {
  mb_test_decode("f796573206d616e692021", 21, "yes mani !", 10, 0);
  mb_test_decode("f00796573206d616e692021", 23, "\x00yes mani !", 11, 0);
  mb_test_decode("f0000796573206d616e692021", 25, "\x00\x00yes mani !", 12, 0);
  mb_test_decode("f", 1, "", 0, 0);
}
static void mb_encode_base16upper_test() {
  mb_test_encode("yes mani !", 10, MB_ENC_BASE16UPPER, "F796573206D616E692021", 21, 0);
  mb_test_encode("\x00yes mani !", 11, MB_ENC_BASE16UPPER, "F00796573206D616E692021", 23, 0);
  mb_test_encode("\x00\x00yes mani !", 12, MB_ENC_BASE16UPPER, "F0000796573206D616E692021", 25, 0);
  mb_test_encode("", 0, MB_ENC_BASE16UPPER, "F", 1, 0);
}
static void mb_decode_base16upper_test() {
  mb_test_decode("F796573206D616E692021", 21, "yes mani !", 10, 0);
  mb_test_decode("F00796573206D616E692021", 23, "\x00yes mani !", 11, 0);
  mb_test_decode("F0000796573206D616E692021", 25, "\x00\x00yes mani !", 12, 0);
  mb_test_decode("F", 1, "", 0, 0);
}

static void mb_encode_identity_test() {
  mb_test_encode("yes mani !", 10, MB_ENC_IDENTITY, "\x00yes mani !", 11, 0);
  mb_test_encode("\x00yes mani !", 11, MB_ENC_IDENTITY, "\x00\x00yes mani !", 12, 0);
  mb_test_encode("\x00\x00yes mani !", 12, MB_ENC_IDENTITY, "\x00\x00\x00yes mani !", 13, 0);
  mb_test_encode("", 0, MB_ENC_IDENTITY, "\x00", 1, 0);

  // not specific to identity encoding, but just testing general behavior
  // todo(guseggert): fix this
  // mb_test_encode("asdf", 4, 3939, "", 0, MB_ERR_UNKNOWN_ENC);
}

static void mb_decode_identity_test() {
  mb_test_decode("\x00yes mani !", 11, "yes mani !", 10, 0);
  mb_test_decode("\x00\x00yes mani !", 12, "\x00yes mani !", 11, 0);
  mb_test_decode("\x00\x00\x00yes mani !", 13, "\x00\x00yes mani !", 12, 0);
  mb_test_decode("\x00", 1, "", 0, 0);
}

static void mb_encode_base58btc_test() {
  mb_test_encode("yes mani !", 10, MB_ENC_BASE58BTC, "z7paNL19xttacUY", 15, 0);
  mb_test_encode("\x00yes mani !", 11, MB_ENC_BASE58BTC, "z17paNL19xttacUY", 16, 0);
  mb_test_encode("\x00\x00yes mani !", 12, MB_ENC_BASE58BTC, "z117paNL19xttacUY", 17, 0);
  mb_test_encode("Hello World!", 12, MB_ENC_BASE58BTC, "z2NEpo7TZRRrLZSi2U", 18, 0);
  mb_test_encode("The quick brown fox jumps over the lazy dog.", 44, MB_ENC_BASE58BTC,
                 "zUSm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z", 61, 0);
  mb_test_encode("\x00\x00\x28\x7f\xb4\xcd", 6, MB_ENC_BASE58BTC, "z11233QC4", 9, 0);
  mb_test_encode("\x2a\xfb\x74\x2d\xd5\x2a\x2a\x8b\x26\x2d", 10, MB_ENC_BASE58BTC, "z3R4TS7L5HBnRMW", 15, 0);
}

static void mb_decode_base58btc_test() {
  mb_test_decode("z7paNL19xttacUY", 15, "yes mani !", 10, 0);
  mb_test_decode("z17paNL19xttacUY", 16, "\x00yes mani !", 11, 0);
  mb_test_decode("z117paNL19xttacUY", 17, "\x00\x00yes mani !", 12, 0);
  mb_test_decode("z2NEpo7TZRRrLZSi2U", 18, "Hello World!", 12, 0);
  mb_test_decode("zUSm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z", 61, "The quick brown fox jumps over the lazy dog.", 44,
                 0);
  mb_test_decode("z11233QC4", 9, "\x00\x00\x28\x7f\xb4\xcd", 6, 0);
  mb_test_decode("z3R4TS7L5HBnRMW", 15, "\x2a\xfb\x74\x2d\xd5\x2a\x2a\x8b\x26\x2d", 10, 0);

  mb_test_decode("z*$()$*", 7, "", 0, MB_ERR_INVALID_INPUT);
  mb_test_decode("z11233QC@", 9, "", 0, MB_ERR_INVALID_INPUT);
}

static void mb_test_enc_by_name(char* name, mb_enc_t expected_enc, mb_err_t expected_err) {
  mb_enc_t actual_enc = 0;
  mb_err_t actual_err = mb_enc_by_name(name, &actual_enc);

  const char* actual_err_str = MB_ERR_STRS[actual_err];
  const char* expected_err_str = MB_ERR_STRS[expected_err];
  assert_string_equal(expected_err_str, actual_err_str);

  if (actual_err) {
    return;
  }

  assert_int_equal(expected_enc, actual_enc);
}
static void mb_enc_by_name_test() {
  mb_test_enc_by_name("z", MB_ENC_BASE58BTC, 0);
  mb_test_enc_by_name("base58btc", MB_ENC_BASE58BTC, 0);
  mb_test_enc_by_name("foo", 0, MB_ERR_UNKNOWN_ENC);
}

static void mh_hash_sha2_256_test() {
  uint8_t* input = (uint8_t*)"asdf";
  size_t result_len = 0;
  mh_err_t err = mh_digest_len(MH_FN_SHA2_256, 4, &result_len);
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

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(varint),
      cmocka_unit_test(mb_encode_identity_test),
      cmocka_unit_test(mb_decode_identity_test),
      cmocka_unit_test(mb_decode_base2_test),
      cmocka_unit_test(mb_encode_base2_test),
      cmocka_unit_test(mb_encode_base16_test),
      cmocka_unit_test(mb_decode_base16_test),
      cmocka_unit_test(mb_encode_base16upper_test),
      cmocka_unit_test(mb_decode_base16upper_test),
      cmocka_unit_test(mb_encode_base32_test),
      cmocka_unit_test(mb_decode_base32_test),
      cmocka_unit_test(mb_encode_base32upper_test),
      cmocka_unit_test(mb_decode_base32upper_test),
      cmocka_unit_test(mb_encode_base58btc_test),
      cmocka_unit_test(mb_decode_base58btc_test),
      cmocka_unit_test(mb_encode_base64_test),
      cmocka_unit_test(mb_decode_base64_test),
      cmocka_unit_test(mb_enc_by_name_test),
      cmocka_unit_test(mh_hash_sha2_256_test),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
