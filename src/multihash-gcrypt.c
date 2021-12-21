#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multihash.h"
#include "murmur3.h"

static mh_err mh_gcrypt_hash(int code, const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  (void)digest_size;
  gcry_md_hash_buffer(code, digest, input, input_size);
  return MH_ERR_OK;
}
static mh_err mh_gcrypt_hash_size(int code, size_t input_size, size_t* const digest_size) {
  (void)input_size;
  (void)digest_size;
  *digest_size = gcry_md_get_algo_dlen(code);
  return MH_ERR_OK;
}
mh_err mh_gcrypt_sha1(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA1, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha1_size(size_t input_size, size_t* const digest_size) { return mh_gcrypt_hash_size(GCRY_MD_SHA1, input_size, digest_size); }
const mh_func mh_fn_sha1 = {
    .name = "sha1",
    .code = MH_FN_CODE_SHA1,
    .hash_fn = &mh_gcrypt_sha1,
    .hash_fn_size = &mh_gcrypt_sha1_size,
    .next = NULL,
};
mh_err mh_gcrypt_sha2_256(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA256, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha2_256_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA256, input_size, digest_size);
}
const mh_func mh_fn_sha2_256 = {
    .name = "sha2-256",
    .code = MH_FN_CODE_SHA2_256,
    .hash_fn = &mh_gcrypt_sha2_256,
    .hash_fn_size = &mh_gcrypt_sha2_256_size,
    .next = &mh_fn_sha1,
};
mh_err mh_gcrypt_sha2_512(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA512, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha2_512_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA512, input_size, digest_size);
}
const mh_func mh_fn_sha2_512 = {
    .name = "sha2-512",
    .code = MH_FN_CODE_SHA2_512,
    .next = &mh_fn_sha2_256,
    .hash_fn = &mh_gcrypt_sha2_512,
    .hash_fn_size = &mh_gcrypt_sha2_512_size,
};
mh_err mh_gcrypt_sha3_512(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA3_512, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha3_512_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA3_512, input_size, digest_size);
}
const mh_func mh_fn_sha3_512 = {
    .name = "sha3-512",
    .code = MH_FN_CODE_SHA3_512,
    .next = &mh_fn_sha2_512,
    .hash_fn = &mh_gcrypt_sha3_512,
    .hash_fn_size = &mh_gcrypt_sha3_512_size,
};
mh_err mh_gcrypt_sha3_384(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA3_384, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha3_384_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA3_384, input_size, digest_size);
}
const mh_func mh_fn_sha3_384 = {
    .name = "sha3-384",
    .code = MH_FN_CODE_SHA3_384,
    .next = &mh_fn_sha3_512,
    .hash_fn = &mh_gcrypt_sha3_384,
    .hash_fn_size = &mh_gcrypt_sha3_384_size,
};
mh_err mh_gcrypt_sha3_256(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA3_256, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha3_256_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA3_256, input_size, digest_size);
}
const mh_func mh_fn_sha3_256 = {
    .name = "sha3-256",
    .code = MH_FN_CODE_SHA3_256,
    .next = &mh_fn_sha3_384,
    .hash_fn = &mh_gcrypt_sha3_256,
    .hash_fn_size = &mh_gcrypt_sha3_256_size,
};
mh_err mh_gcrypt_sha3_224(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA3_224, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha3_224_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA3_224, input_size, digest_size);
}
const mh_func mh_fn_sha3_224 = {
    .name = "sha3-224",
    .code = MH_FN_CODE_SHA3_224,
    .next = &mh_fn_sha3_256,
    .hash_fn = &mh_gcrypt_sha3_224,
    .hash_fn_size = &mh_gcrypt_sha3_224_size,
};
mh_err mh_gcrypt_sha2_384(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA384, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha2_384_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA384, input_size, digest_size);
}
const mh_func mh_fn_sha2_384 = {
    .name = "sha2-384",
    .code = MH_FN_CODE_SHA2_384,
    .next = &mh_fn_sha3_224,
    .hash_fn = &mh_gcrypt_sha2_384,
    .hash_fn_size = &mh_gcrypt_sha2_384_size,
};
mh_err mh_gcrypt_sha2_224(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA224, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha2_224_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA224, input_size, digest_size);
}
const mh_func mh_fn_sha2_224 = {
    .name = "sha2-224",
    .code = MH_FN_CODE_SHA2_224,
    .next = &mh_fn_sha2_384,
    .hash_fn = &mh_gcrypt_sha2_224,
    .hash_fn_size = &mh_gcrypt_sha2_224_size,
};
mh_err mh_gcrypt_sha2_512_224(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA512_224, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha2_512_224_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA512_224, input_size, digest_size);
}
const mh_func mh_fn_sha2_512_224 = {
    .name = "sha2-512-224",
    .code = MH_FN_CODE_SHA2_512_224,
    .next = &mh_fn_sha2_224,
    .hash_fn = &mh_gcrypt_sha2_512_224,
    .hash_fn_size = &mh_gcrypt_sha2_512_224_size,
};
mh_err mh_gcrypt_sha2_512_256(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  return mh_gcrypt_hash(GCRY_MD_SHA512_256, input, input_size, digest, digest_size);
}
mh_err mh_gcrypt_sha2_512_256_size(size_t input_size, size_t* const digest_size) {
  return mh_gcrypt_hash_size(GCRY_MD_SHA512_256, input_size, digest_size);
}
const mh_func mh_fn_sha2_512_256 = {
    .name = "sha2-512-256",
    .code = MH_FN_CODE_SHA2_512_256,
    .next = &mh_fn_sha2_512_224,
    .hash_fn = &mh_gcrypt_sha2_512_256,
    .hash_fn_size = &mh_gcrypt_sha2_512_256_size,
};
