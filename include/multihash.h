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

const char* mh_err_str(mh_err err);

typedef uint64_t mh_fn_code;
const mh_fn_code MH_FN_CODE_IDENTITY = 0x00;
const mh_fn_code MH_FN_CODE_SHA1 = 0x11;
const mh_fn_code MH_FN_CODE_SHA2_256 = 0x12;
const mh_fn_code MH_FN_CODE_SHA2_512 = 0x13;
const mh_fn_code MH_FN_CODE_SHA3_512 = 0x14;
const mh_fn_code MH_FN_CODE_SHA3_384 = 0x15;
const mh_fn_code MH_FN_CODE_SHA3_256 = 0x16;
const mh_fn_code MH_FN_CODE_SHA3_224 = 0x17;
const mh_fn_code MH_FN_CODE_SHAKE_128 = 0x18;
const mh_fn_code MH_FN_CODE_SHAKE_256 = 0x19;
const mh_fn_code MH_FN_CODE_KECCAK_224 = 0x1a;
const mh_fn_code MH_FN_CODE_BLAKE3 = 0x1e;
const mh_fn_code MH_FN_CODE_SHA2_384 = 0x20;
const mh_fn_code MH_FN_CODE_MURMUR3_X64_64 = 0x22;
const mh_fn_code MH_FN_CODE_SHA2_256_TRUNC254_PADDED = 0x1012;
const mh_fn_code MH_FN_CODE_SHA2_224 = 0x1013;
const mh_fn_code MH_FN_CODE_SHA2_512_224 = 0x1014;
const mh_fn_code MH_FN_CODE_SHA2_512_256 = 0x1015;

typedef struct mh_func {
  const mh_fn_code code;
  const char* const name;
  // Disables this function for lookups
  const bool disabled;
  mh_err (*const hash_fn)(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size);
  mh_err (*const hash_fn_size)(size_t input_size, size_t* const digest_size);
  const struct mh_func* next;
} mh_func;

/**
 * Register hash functions @funcs. These are placed at the front of the list,
 * so the most recently registered functions take precedence.
 */
void mh_add_funcs(mh_func* funcs);

mh_err mh_func_by_name(const char* name, const mh_func** func);

mh_err mh_func_by_code(mh_fn_code fn_code, const mh_func** func);

/**
 * Extracts the hash function code @fn_code from the multihash @bytes of size @bytes_size.
 *
 * @fn_code is not set if it is null.
 */
mh_err mh_read_fn_code(const uint8_t* bytes, size_t bytes_size, mh_fn_code* fn_code);

/**
 * Extracts the @digest from the multihash @bytes of size @bytes_size.
 *
 * This does not copy the bytes, it merely returns a pointer to the same underlying data.
 *
 * @digest_size and @digest are only set if they are not respectively null.
 */
mh_err mh_read_digest(const uint8_t* bytes, size_t bytes_size, size_t* digest_size, const uint8_t** digest);

/**
 * Returns true if the given @bytes of size @bytes_size constitute a valid multihash.
 */
bool mh_validate(const uint8_t* bytes, size_t bytes_size);

/**
 * Computes the digest size @digest_size for the given hash function @fn given the input size @input_size.
 */
mh_err mh_digest_size(mh_fn_code fn_code, size_t input_size, size_t* digest_size);

/**
 * Computes the @digest of the given size @digest_size of @input of size @input_size bytes, using the @fn hash function.
 */
mh_err mh_digest(const uint8_t* input, size_t input_size, mh_fn_code fn_code, uint8_t* digest, size_t digest_size);

/**
 * Computes the size @encode_size of the mutlihash encoding for the given hash function @fn and @input_size.
 */
mh_err mh_encode_size(mh_fn_code fn_code, size_t input_size, size_t* encode_size);

/**
 * Computes the digest of the given @input of size @input_size bytes, using the @fn hash function,
 * and encodes the result as a multihash in @bytes of given size @bytes_size.
 */
mh_err mh_encode(const uint8_t* input, size_t input_size, mh_fn_code fn_code, uint8_t* bytes, size_t bytes_size);
#endif
