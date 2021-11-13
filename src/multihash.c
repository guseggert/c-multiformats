#include "multihash.h"

#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

#include "varint.h"

mh_err_t mh_hash_gcrypt(int algo, const uint8_t* const input, size_t input_len, uint8_t* const digest) {
  gcry_md_hash_buffer(algo, digest, input, input_len);
  return MH_ERR_OK;
}

static enum gcry_md_algos fn_to_gcrypt_algo(mh_fn_t fn) {
  switch (fn) {
    case MH_FN_SHA1:
      return GCRY_MD_SHA1;
    case MH_FN_SHA2_256:
      return GCRY_MD_SHA256;
    case MH_FN_SHA2_512:
      return GCRY_MD_SHA512;
    case MH_FN_SHA3_512:
      return GCRY_MD_SHA3_512;
    case MH_FN_SHA3_384:
      return GCRY_MD_SHA3_384;
    case MH_FN_SHA3_256:
      return GCRY_MD_SHA3_256;
    case MH_FN_SHA3_224:
      return GCRY_MD_SHA3_224;
    case MH_FN_SHA2_384:
      return GCRY_MD_SHA384;
    case MH_FN_SHA2_224:
      return GCRY_MD_SHA224;
    case MH_FN_SHA2_512_224:
      return GCRY_MD_SHA512_224;
    case MH_FN_SHA2_512_256:
      return GCRY_MD_SHA512_256;
    default:
      return GCRY_MD_NONE;
  }
}

mh_err_t mh_hash(const uint8_t* const input, size_t input_len, mh_fn_t fn, uint8_t* const digest, size_t digest_len) {
  if (fn == MH_FN_IDENTITY) {
    memcpy(digest, input, digest_len);
    return MH_ERR_OK;
  }
  enum gcry_md_algos algo = fn_to_gcrypt_algo(fn);
  if (algo == 0) {
    return MH_ERR_UNSUPPORTED_HASHFN;
  }
  return mh_hash_gcrypt(algo, input, input_len, digest);
}

mh_err_t mh_digest_len(mh_fn_t fn, size_t input_len, size_t* const digest_len) {
  if (fn == MH_FN_IDENTITY) {
    return input_len;
  }
  enum gcry_md_algos algo = fn_to_gcrypt_algo(fn);
  if (algo == 0) {
    return MH_ERR_UNSUPPORTED_HASHFN;
  }

  *digest_len = gcry_md_get_algo_dlen(algo);
  return MH_ERR_OK;
}

mh_err_t mh_read_fn(const uint8_t* bytes, size_t bytes_len, mh_fn_t* fn) {
  uint64_t mh_varint = 0;
  varint_err_t err = varint_to_uint64(bytes, bytes_len, &mh_varint, NULL);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }
  if (fn != NULL) {
    *fn = mh_varint;
  }
  return MH_ERR_OK;
}

mh_err_t mh_read_digest(const uint8_t* bytes, size_t bytes_len, size_t* digest_size, const uint8_t** digest) {
  if (bytes_len < 3) {
    return MH_ERR_INVALID_INPUT;
  }
  uint64_t mh_varint = 0;
  size_t mh_varint_len = 0;
  varint_err_t err = varint_to_uint64(bytes, bytes_len, &mh_varint, &mh_varint_len);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }

  uint64_t digest_varint = 0;
  size_t digest_varint_len = 0;
  err = varint_to_uint64(bytes + mh_varint_len, bytes_len - mh_varint_len, &digest_varint, &digest_varint_len);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }

  if (digest_size != NULL) {
    *digest_size = digest_varint;
  }
  if (digest != NULL) {
    *digest = bytes + mh_varint_len + digest_varint_len;
  }

  return MH_ERR_OK;
}

bool mh_validate(const uint8_t* bytes, size_t bytes_len) {
  mh_err_t err = mh_read_fn(bytes, bytes_len, NULL);
  if (err) {
    return err;
  }
  err = mh_read_digest(bytes, bytes_len, NULL, NULL);
  if (err) {
    return err;
  }

  return MH_ERR_OK;
}
