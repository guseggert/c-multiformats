#ifndef MULTIHASH_H
#define MULTIHASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  MH_ERR_OK = 0,
  MH_ERR_UNKNOWN_HASHFN,
  MH_ERR_UNSUPPORTED_HASHFN,
  MH_ERR_INVALID_INPUT,
  MH_ERR_MEMORY,
} mh_err;

static const char* const MH_ERR_STRS[] = {
    "no error",
    "unknown hash function",
    "unsupported hash function",
    "invalid multihash",
    "unable to allocate memory",
};

#define MH_NUM_FNS 14
typedef enum {
  MH_FN_IDENTITY = 0x00,
  MH_FN_SHA1 = 0x11,
  MH_FN_SHA2_256,
  MH_FN_SHA2_512,
  MH_FN_SHA3_512,
  MH_FN_SHA3_384,
  MH_FN_SHA3_256,
  MH_FN_SHA3_224,
  MH_FN_SHA2_384 = 0x20,
  MH_FN_MURMUR3_X64_64 = 0x22,
  MH_FN_SHA2_256_TRUNC254_PADDED = 0x1012,
  MH_FN_SHA2_224 = 0x1013,
  MH_FN_SHA2_512_224,
  MH_FN_SHA2_512_256,
} mh_fn;

/**
 * Extracts the hash function @fn from the multihash @bytes of length @bytes_len.
 *
 * @fn is not set if it is null.
 */
mh_err mh_read_fn(const uint8_t* bytes, size_t bytes_len, mh_fn* fn);

/**
 * Extracts the @digest from the multihash @bytes of length @bytes_len.
 *
 * This does not copy the bytes, it merely returns a pointer to the same underlying data.
 *
 * @digest_size and @digest are only set if they are not respectively null.
 */
mh_err mh_read_digest(const uint8_t* bytes, size_t bytes_len, size_t* digest_size, const uint8_t** digest);

/**
 * Returns true if the given @bytes of length @bytes_len constitute a valid multihash.
 */
bool mh_validate(const uint8_t* bytes, size_t bytes_len);

/**
 * Computes the digest length @digest_len for the given hash function @fn given the input length @input_len.
 */
mh_err mh_digest_len(mh_fn fn, size_t input_len, size_t* digest_len);

/**
 * Computes the @digest of the given length @digest_len of @input of length @input_len bytes, using the @fn hash function.
 */
mh_err mh_digest(const uint8_t* input, size_t input_len, mh_fn fn, uint8_t* digest, size_t digest_len);

/**
 * Computes the length @encode_len of the mutlihash encoding for the given hash function @fn and @input_len.
 */
mh_err mh_encode_len(mh_fn fn, size_t input_len, size_t* encode_len);

/**
 * Computes the digest of the given @input of length @input_len bytes, using the @fn hash function,
 * and encodes the result as a multihash in @bytes of given length @bytes_len.
 */
mh_err mh_encode(const uint8_t* input, size_t input_len, mh_fn fn, uint8_t* bytes, size_t bytes_len);
#endif
