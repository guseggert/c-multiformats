#ifndef MULTIHASH_H
#define MULTIHASH_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
  uint64_t hash_func_code;
  size_t digest_size;
  const uint8_t* digest;
} mh_t;

typedef enum mh_err {
  MH_ERR_OK = 0,
  MH_ERR_UNKNOWN_HASHFN,
  MH_ERR_MEMORY,
  MH_ERR_INVALID_INPUT,
} mh_err_t;

static const char* const MH_ERR_STRS[] = {
    "no error",
    "unknown hash function",
    "unable to allocate memory",
    "invalid input",
};

#define mh_enc_max_code 0x22
typedef enum mh_enc {
  MH_ENC_IDENTITY = 0x00,
  MH_ENC_SHA1 = 0x11,
  MH_ENC_SHA2_256,
  MH_ENC_SHA2_512,
  MH_ENC_SHA3_512,
  MH_ENC_SHA3_384,
  MH_ENC_SHA3_256,
  MH_ENC_SHA3_224,
  MH_ENC_SHA2_384 = 0x20,
  MH_ENC_SHA2_224 = 0x1013,
  MH_ENC_SHA2_512_224,
  MH_ENC_SHA2_512_256,
} mh_enc_t;

/**
 * Parse multihash @bytes of length @bytes_len into @multihash.
 *
 * This allocates memory for @multihash which must be freed with mh_free().
 */
mh_err_t mh_parse(const uint8_t* bytes, size_t bytes_len, mh_t** multihash);

mh_err_t mh_hash(const uint8_t* input, size_t input_len, mh_enc_t encoding, uint8_t** result, size_t* result_len);

void mh_free(mh_t* mh);

#endif
