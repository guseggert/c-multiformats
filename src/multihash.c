#include "multihash.h"

#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

#include "varint.h"

mh_err_t mh_hash_gcrypt(int algo, const uint8_t* const input, size_t input_len, uint8_t** const result, size_t* const result_len) {
  unsigned int hash_len = gcry_md_get_algo_dlen(algo);
  unsigned char* hash = malloc(sizeof(unsigned char) * hash_len);
  if (hash == NULL) {
    return MH_ERR_MEMORY;
  }
  gcry_md_hash_buffer(algo, hash, input, input_len);
  *result = hash;
  *result_len = hash_len;
  return MH_ERR_OK;
}

mh_err_t mh_hash(const uint8_t* const input, size_t input_len, mh_enc_t encoding, uint8_t** const result, size_t* const result_len) {
  switch (encoding) {
    case MH_ENC_IDENTITY:
      *result = malloc(input_len);
      if (*result == NULL) {
        return MH_ERR_MEMORY;
      }
      memcpy(*result, input, input_len);
      *result_len = input_len;
      return MH_ERR_OK;
    case MH_ENC_SHA1:
      return mh_hash_gcrypt(GCRY_MD_SHA1, input, input_len, result, result_len);
    case MH_ENC_SHA2_256:
      return mh_hash_gcrypt(GCRY_MD_SHA256, input, input_len, result, result_len);
    case MH_ENC_SHA2_512:
      return mh_hash_gcrypt(GCRY_MD_SHA512, input, input_len, result, result_len);
    case MH_ENC_SHA3_512:
      return mh_hash_gcrypt(GCRY_MD_SHA3_512, input, input_len, result, result_len);
    case MH_ENC_SHA3_384:
      return mh_hash_gcrypt(GCRY_MD_SHA3_384, input, input_len, result, result_len);
    case MH_ENC_SHA3_256:
      return mh_hash_gcrypt(GCRY_MD_SHA3_256, input, input_len, result, result_len);
    case MH_ENC_SHA3_224:
      return mh_hash_gcrypt(GCRY_MD_SHA3_224, input, input_len, result, result_len);
    case MH_ENC_SHA2_384:
      return mh_hash_gcrypt(GCRY_MD_SHA384, input, input_len, result, result_len);
    case MH_ENC_SHA2_224:
      return mh_hash_gcrypt(GCRY_MD_SHA224, input, input_len, result, result_len);
    case MH_ENC_SHA2_512_224:
      return mh_hash_gcrypt(GCRY_MD_SHA512_224, input, input_len, result, result_len);
    case MH_ENC_SHA2_512_256:
      return mh_hash_gcrypt(GCRY_MD_SHA512_256, input, input_len, result, result_len);
    default:
      return MH_ERR_UNKNOWN_HASHFN;
  }
  return MH_ERR_OK;
}

mh_err_t mh_parse(const uint8_t* const bytes, size_t bytes_len, mh_t** const multihash) {
  if (bytes_len < 3) {
    return MH_ERR_INVALID_INPUT;
  }
  // read varint prefix
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

  size_t digest_size = bytes_len - mh_varint_len - digest_varint_len;
  const uint8_t* digest_bytes = bytes + mh_varint_len + digest_varint_len;
  uint8_t* digest_copy = malloc(sizeof(uint8_t) * digest_size);
  if (digest_copy == NULL) {
    return MH_ERR_MEMORY;
  }
  memcpy(digest_copy, digest_bytes, digest_size);

  mh_t* mh = malloc(sizeof(mh_t));

  mh->hash_func_code = mh_varint;
  mh->digest_size = digest_size;
  mh->digest = digest_copy;

  *multihash = mh;

  return MH_ERR_OK;
}

void mh_free(mh_t* mh) {
  free((void*)mh->digest);
  free(mh);
}
