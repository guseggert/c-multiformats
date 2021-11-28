#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multihash.h"
#include "murmur3.h"

mh_err mh_openssl_hash(const EVP_MD* md, const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();

  if (!EVP_DigestInit(ctx, md)) {
    EVP_MD_CTX_free(ctx);
    return MH_ERR_INVALID_INPUT;
  }
  if (!EVP_DigestUpdate(ctx, input, input_len)) {
    EVP_MD_CTX_free(ctx);
    return MH_ERR_INVALID_INPUT;
  }

  unsigned int size = 0;
  int err = 0;
  if ((EVP_MD_meth_get_flags(md) & EVP_MD_FLAG_XOF) != 0) {
    err = EVP_DigestFinalXOF(ctx, digest, digest_len);
  } else {
    err = EVP_DigestFinal(ctx, digest, &size);
  }

  EVP_MD_CTX_free(ctx);
  return err == 0 ? MH_ERR_INVALID_INPUT : MH_ERR_OK;
}

mh_err mh_openssl_hash_len(const EVP_MD* md, size_t input_len, size_t* const digest_len) {
  (void)input_len;
  // to avoid heap allocations, this returns the cumulative size of both the digest and the context
  // and then we divide the memory into those two pieces when we use it to compute the digest
  int size = EVP_MD_size(md);
  *digest_len = (size_t)size;
  return MH_ERR_OK;
}

mh_err mh_openssl_sha1(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha1(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha1_len(size_t input_len, size_t* const digest_len) { return mh_openssl_hash_len(EVP_sha1(), input_len, digest_len); }
const mh_func mh_fn_sha1 = {
    .name = "sha1",
    .code = MH_FN_CODE_SHA1,
    .hash_fn = &mh_openssl_sha1,
    .hash_fn_len = &mh_openssl_sha1_len,
    .next = NULL,
};

mh_err mh_openssl_sha2_256(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha256(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha2_256_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha256(), input_len, digest_len);
}
const mh_func mh_fn_sha2_256 = {
    .name = "sha2-256",
    .code = MH_FN_CODE_SHA2_256,
    .hash_fn = &mh_openssl_sha2_256,
    .hash_fn_len = &mh_openssl_sha2_256_len,
    .next = &mh_fn_sha1,
};

mh_err mh_openssl_sha2_512(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha512(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha2_512_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha512(), input_len, digest_len);
}
const mh_func mh_fn_sha2_512 = {
    .name = "sha2-512",
    .code = MH_FN_CODE_SHA2_512,
    .hash_fn = &mh_openssl_sha2_512,
    .hash_fn_len = &mh_openssl_sha2_512_len,
    .next = &mh_fn_sha2_256,
};

mh_err mh_openssl_sha3_512(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha3_512(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha3_512_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha3_512(), input_len, digest_len);
}
const mh_func mh_fn_sha3_512 = {
    .name = "sha3-512",
    .code = MH_FN_CODE_SHA3_512,
    .hash_fn = &mh_openssl_sha3_512,
    .hash_fn_len = &mh_openssl_sha3_512_len,
    .next = &mh_fn_sha2_512,
};

mh_err mh_openssl_sha3_384(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha3_384(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha3_384_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha3_384(), input_len, digest_len);
}
const mh_func mh_fn_sha3_384 = {
    .name = "sha3-384",
    .code = MH_FN_CODE_SHA3_384,
    .hash_fn = &mh_openssl_sha3_384,
    .hash_fn_len = &mh_openssl_sha3_384_len,
    .next = &mh_fn_sha3_512,
};

mh_err mh_openssl_sha3_256(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha3_256(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha3_256_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha3_256(), input_len, digest_len);
}
const mh_func mh_fn_sha3_256 = {
    .name = "sha3-256",
    .code = MH_FN_CODE_SHA3_256,
    .hash_fn = &mh_openssl_sha3_256,
    .hash_fn_len = &mh_openssl_sha3_256_len,
    .next = &mh_fn_sha3_384,
};

mh_err mh_openssl_sha3_224(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha3_224(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha3_224_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha3_224(), input_len, digest_len);
}
const mh_func mh_fn_sha3_224 = {
    .name = "sha3-224",
    .code = MH_FN_CODE_SHA3_224,
    .hash_fn = &mh_openssl_sha3_224,
    .hash_fn_len = &mh_openssl_sha3_224_len,
    .next = &mh_fn_sha3_256,
};

mh_err mh_openssl_sha2_384(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha384(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha2_384_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha384(), input_len, digest_len);
}
const mh_func mh_fn_sha2_384 = {
    .name = "sha2-384",
    .code = MH_FN_CODE_SHA2_384,
    .hash_fn = &mh_openssl_sha2_384,
    .hash_fn_len = &mh_openssl_sha2_384_len,
    .next = &mh_fn_sha3_224,
};

mh_err mh_openssl_sha2_224(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha224(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha2_224_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha224(), input_len, digest_len);
}
const mh_func mh_fn_sha2_224 = {
    .name = "sha2-224",
    .code = MH_FN_CODE_SHA2_224,
    .hash_fn = &mh_openssl_sha2_224,
    .hash_fn_len = &mh_openssl_sha2_224_len,
    .next = &mh_fn_sha2_384,
};

mh_err mh_openssl_sha2_512_224(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha512_224(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha2_512_224_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha512_224(), input_len, digest_len);
}
const mh_func mh_fn_sha2_512_224 = {
    .name = "sha2-512-224",
    .code = MH_FN_CODE_SHA2_512_224,
    .hash_fn = &mh_openssl_sha2_512_224,
    .hash_fn_len = &mh_openssl_sha2_512_224_len,
    .next = &mh_fn_sha2_224,
};

mh_err mh_openssl_shake_128(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_shake128(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_shake_128_len(size_t input_len, size_t* const digest_len) {
  (void)input_len;
  *digest_len = 32;
  return MH_ERR_OK;
}
const mh_func mh_fn_shake_128 = {
    .name = "shake-128",
    .code = MH_FN_CODE_SHAKE_128,
    .hash_fn = &mh_openssl_shake_128,
    .hash_fn_len = &mh_openssl_shake_128_len,
    .next = &mh_fn_sha2_512_224,
};

mh_err mh_openssl_shake_256(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_shake256(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_shake_256_len(size_t input_len, size_t* const digest_len) {
  (void)input_len;
  *digest_len = 64;
  return MH_ERR_OK;
}
const mh_func mh_fn_shake_256 = {
    .name = "shake-256",
    .code = MH_FN_CODE_SHAKE_256,
    .hash_fn = &mh_openssl_shake_256,
    .hash_fn_len = &mh_openssl_shake_256_len,
    .next = &mh_fn_shake_128,
};

mh_err mh_openssl_sha2_512_256(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  return mh_openssl_hash(EVP_sha512_256(), input, input_len, digest, digest_len);
}
mh_err mh_openssl_sha2_512_256_len(size_t input_len, size_t* const digest_len) {
  return mh_openssl_hash_len(EVP_sha512_256(), input_len, digest_len);
}
const mh_func mh_fn_sha2_512_256 = {
    .name = "sha2-512-256",
    .code = MH_FN_CODE_SHA2_512_256,
    .hash_fn = &mh_openssl_sha2_512_256,
    .hash_fn_len = &mh_openssl_sha2_512_256_len,
    .next = &mh_fn_shake_256,
};
