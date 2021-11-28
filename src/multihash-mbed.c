#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multihash.h"
#include "murmur3.h"

static mh_err mh_mbed_hash(mbedtls_md_type_t code, const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  (void)digest_len;
  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(code);
  if (md_info == NULL) {
    return MH_ERR_UNSUPPORTED_HASHFN;
  }
  int err = mbedtls_md(md_info, (unsigned char*)input, input_len, (unsigned char*)digest);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }
  return MH_ERR_OK;
}
static mh_err mh_mbed_hash_len(mbedtls_md_type_t code, size_t input_len, size_t* const digest_len) {
  (void)input_len;
  (void)digest_len;
  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(code);
  if (md_info == NULL) {
    return MH_ERR_UNSUPPORTED_HASHFN;
  }
  unsigned char size = mbedtls_md_get_size(md_info);
  *digest_len = (size_t)size;
  return MH_ERR_OK;
}

mh_err mh_mbed_sha1(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_mbed_hash(MBEDTLS_MD_SHA1, input, input_len, digest, digest_len);
}
mh_err mh_mbed_sha1_len(size_t input_len, size_t* const digest_len) { return mh_mbed_hash_len(MBEDTLS_MD_SHA1, input_len, digest_len); }
const mh_func mh_fn_sha1 = {
    .name = "sha1",
    .code = MH_FN_CODE_SHA1,
    .hash_fn = &mh_mbed_sha1,
    .hash_fn_len = &mh_mbed_sha1_len,
    .next = NULL,
};

mh_err mh_mbed_sha224(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_mbed_hash(MBEDTLS_MD_SHA224, input, input_len, digest, digest_len);
}
mh_err mh_mbed_sha224_len(size_t input_len, size_t* const digest_len) { return mh_mbed_hash_len(MBEDTLS_MD_SHA224, input_len, digest_len); }
const mh_func mh_fn_sha2_224 = {
    .name = "sha2-224",
    .code = MH_FN_CODE_SHA2_224,
    .hash_fn = &mh_mbed_sha224,
    .hash_fn_len = &mh_mbed_sha224_len,
    .next = &mh_fn_sha1,
};

mh_err mh_mbed_sha256(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_mbed_hash(MBEDTLS_MD_SHA256, input, input_len, digest, digest_len);
}
mh_err mh_mbed_sha256_len(size_t input_len, size_t* const digest_len) { return mh_mbed_hash_len(MBEDTLS_MD_SHA256, input_len, digest_len); }
const mh_func mh_fn_sha2_256 = {
    .name = "sha2-256",
    .code = MH_FN_CODE_SHA2_256,
    .hash_fn = &mh_mbed_sha256,
    .hash_fn_len = &mh_mbed_sha256_len,
    .next = &mh_fn_sha2_224,
};

mh_err mh_mbed_sha384(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_mbed_hash(MBEDTLS_MD_SHA384, input, input_len, digest, digest_len);
}
mh_err mh_mbed_sha384_len(size_t input_len, size_t* const digest_len) { return mh_mbed_hash_len(MBEDTLS_MD_SHA384, input_len, digest_len); }
const mh_func mh_fn_sha2_384 = {
    .name = "sha2-384",
    .code = MH_FN_CODE_SHA2_384,
    .hash_fn = &mh_mbed_sha384,
    .hash_fn_len = &mh_mbed_sha384_len,
    .next = &mh_fn_sha2_256,
};

mh_err mh_mbed_sha512(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_mbed_hash(MBEDTLS_MD_SHA512, input, input_len, digest, digest_len);
}
mh_err mh_mbed_sha512_len(size_t input_len, size_t* const digest_len) { return mh_mbed_hash_len(MBEDTLS_MD_SHA512, input_len, digest_len); }
const mh_func mh_fn_sha2_512 = {
    .name = "sha2-512",
    .code = MH_FN_CODE_SHA2_512,
    .hash_fn = &mh_mbed_sha512,
    .hash_fn_len = &mh_mbed_sha512_len,
    .next = &mh_fn_sha2_384,
};
