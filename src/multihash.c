#include "multihash.h"

#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"
#include "murmur3.h"
#include "varint.h"

mh_err mh_digest_gcrypt(int algo, const uint8_t* const input, size_t input_len, uint8_t* const digest) {
  gcry_md_hash_buffer(algo, digest, input, input_len);
  return MH_ERR_OK;
}

static enum gcry_md_algos fn_to_gcrypt_algo(mh_fn fn) {
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

static mh_err murmur3_x86_64(const uint8_t* const input, size_t input_len, uint8_t* const digest) {
  // This is defined as the first half of x64-128.
  //
  // Unfortunately to use this library we must allocate a 16-byte buffer and then copy the first
  // 8 bytes to the result buffer, which breaks the convention of not allocating.
  uint64_t* buf = malloc(2 * sizeof(uint64_t));
  if (buf == NULL) {
    return MH_ERR_MEMORY;
  }

  MurmurHash3_x64_128(input, (int)input_len, 0, buf);

  // be careful to keep this agnostic to arch endianness
  uint64_t first64 = buf[0];
  digest[0] = (first64 >> 56) & 0xFF;
  digest[1] = (first64 >> 48) & 0xFF;
  digest[2] = (first64 >> 40) & 0xFF;
  digest[3] = (first64 >> 32) & 0xFF;
  digest[4] = (first64 >> 24) & 0xFF;
  digest[5] = (first64 >> 16) & 0xFF;
  digest[6] = (first64 >> 8) & 0xFF;
  digest[7] = first64 & 0xFF;

  free(buf);
  return MH_ERR_OK;
}

static mh_err sha2_256_trunc254_padded(const uint8_t* const input, size_t input_len, uint8_t* const digest) {
  //  SHA2-256 with the two most significant bits from the last byte zeroed (as via a mask with 0x3f)
  unsigned int digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest, input, input_len);
  digest[digest_len - 1] &= 0x3f;
  return MH_ERR_OK;
}

mh_err mh_digest(const uint8_t* const input, size_t input_len, mh_fn fn, uint8_t* const digest, size_t digest_len) {
  switch (fn) {
    case MH_FN_IDENTITY:
      memcpy(digest, input, digest_len);
      return MH_ERR_OK;
    case MH_FN_MURMUR3_X64_64:
      return murmur3_x86_64(input, input_len, digest);
    case MH_FN_SHA2_256_TRUNC254_PADDED:
      return sha2_256_trunc254_padded(input, input_len, digest);
    default: {
      enum gcry_md_algos algo = fn_to_gcrypt_algo(fn);
      if (algo == 0) {
        return MH_ERR_UNSUPPORTED_HASHFN;
      }
      return mh_digest_gcrypt(algo, input, input_len, digest);
    }
  }
}

mh_err mh_digest_len(mh_fn fn, size_t input_len, size_t* const digest_len) {
  switch (fn) {
    case MH_FN_IDENTITY:
      *digest_len = input_len;
      return MH_ERR_OK;
    case MH_FN_MURMUR3_X64_64:
      *digest_len = 8;
      return MH_ERR_OK;
    case MH_FN_SHA2_256_TRUNC254_PADDED:
      *digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
      return MH_ERR_OK;
    default: {
      enum gcry_md_algos algo = fn_to_gcrypt_algo(fn);
      if (algo == 0) {
        return MH_ERR_UNSUPPORTED_HASHFN;
      }
      *digest_len = gcry_md_get_algo_dlen(algo);
      return MH_ERR_OK;
    }
  }
}

mh_err mh_encode_len(mh_fn fn, size_t input_len, size_t* encode_len) {
  // <fncode><digestsize><digest>
  // length of fn varint
  size_t fn_varint_len = 0;
  varint_err vi_err = uint64_to_varint(fn, NULL, &fn_varint_len);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }
  // length of digest
  size_t digest_len = 0;
  mh_err err = mh_digest_len(fn, input_len, &digest_len);
  if (err) {
    return err;
  }

  // length of digest varint
  size_t digest_varint_len = 0;
  vi_err = uint64_to_varint(digest_len, NULL, &digest_varint_len);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }

  *encode_len = fn_varint_len + digest_varint_len + digest_len;
  return MH_ERR_OK;
}

mh_err mh_encode(const uint8_t* input, size_t input_len, mh_fn fn, uint8_t* bytes, size_t bytes_len) {
  // <fncode><digestsize><digest>
  // fn code varint
  size_t fn_varint_len = 0;
  varint_err vi_err = uint64_to_varint(fn, bytes, &fn_varint_len);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }
  // digest varint
  size_t digest_len = 0;
  mh_err err = mh_digest_len(fn, input_len, &digest_len);
  if (err) {
    return err;
  }
  size_t digest_varint_len = 0;
  vi_err = uint64_to_varint(digest_len, bytes + fn_varint_len, &digest_varint_len);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }

  // digest
  err = mh_digest(input, input_len, fn, bytes + fn_varint_len + digest_varint_len, bytes_len - fn_varint_len - digest_varint_len);
  if (err) {
    return err;
  }

  return MH_ERR_OK;
}

mh_err mh_read_fn(const uint8_t* bytes, size_t bytes_len, mh_fn* fn) {
  uint64_t mh_varint = 0;
  varint_err err = varint_to_uint64(bytes, bytes_len, &mh_varint, NULL);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }
  if (fn != NULL) {
    *fn = mh_varint;
  }
  return MH_ERR_OK;
}

mh_err mh_read_digest(const uint8_t* bytes, size_t bytes_len, size_t* digest_size, const uint8_t** digest) {
  if (bytes_len < 3) {
    return MH_ERR_INVALID_INPUT;
  }
  uint64_t mh_varint = 0;
  size_t mh_varint_len = 0;
  varint_err err = varint_to_uint64(bytes, bytes_len, &mh_varint, &mh_varint_len);
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
  mh_err err = mh_read_fn(bytes, bytes_len, NULL);
  if (err) {
    return err;
  }
  err = mh_read_digest(bytes, bytes_len, NULL, NULL);
  if (err) {
    return err;
  }

  return MH_ERR_OK;
}

typedef struct {
  char* name;
  mh_fn code;
} mh_func;

// these correlate to the mh_fn enum 
static const mh_func codes[MH_NUM_FNS] = {
    {.name = "identity", .code = MH_FN_IDENTITY},
    {.name = "sha1", .code = MH_FN_SHA1},
    {.name = "sha2-256", .code = MH_FN_SHA2_256},
    {.name = "sha2-512", .code = MH_FN_SHA2_512},
    {.name = "sha3-512", .code = MH_FN_SHA3_512},
    {.name = "sha3-384", .code = MH_FN_SHA3_384},
    {.name = "sha3-256", .code = MH_FN_SHA3_256},
    {.name = "sha3-224", .code = MH_FN_SHA3_224},
    {.name = "sha2-384", .code = MH_FN_SHA2_384},
    {.name = "murmur3-x64-64", .code = MH_FN_MURMUR3_X64_64},
    {.name = "sha2-256-trunc254-padded", .code = MH_FN_SHA2_256_TRUNC254_PADDED},
    {.name = "sha2-224", .code = MH_FN_SHA2_224},
    {.name = "sha2-512-224", .code = MH_FN_SHA2_512_224},
    {.name = "sha2-512-256", .code = MH_FN_SHA2_512_256},
};

static bool mh_func_by_name(const char* const name, mh_func* f) {
  for (size_t i = 0; i < MH_NUM_FNS; i++) {
    if (strcmp(name, codes[i].name) == 0) {
      *f = codes[i];
      return true;
    }
  }
  return false;
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    printf("usage: %s <hash func name> <string>\n", argv[0]);
    return 1;
  }
  char* hash_func_name = argv[1];
  char* input_str = argv[2];
  size_t input_str_len = strlen(input_str);

  mh_func f = {0};
  if (!mh_func_by_name(hash_func_name, &f)) {
    printf("unknown hash func '%s'\n", hash_func_name);
    return 1;
  }

  size_t mh_len = 0;
  mh_err err = mh_encode_len(f.code, input_str_len, &mh_len);
  if (err) {
    printf("error computing multihash length: %s\n", MH_ERR_STRS[err]);
    return 1;
  }
  uint8_t* mh = malloc(mh_len * sizeof(uint8_t));
  if (mh == NULL) {
    printf("error allocating memory for multihash\n");
    return 1;
  }
  err = mh_encode((uint8_t*)input_str, input_str_len, f.code, mh, mh_len);
  if (err) {
    printf("error computing multihash: %s\n", MH_ERR_STRS[err]);
    free(mh);
    return 1;
  }
  size_t mh_enc_len = mb_encode_len(mh, mh_len, MB_ENC_BASE16);
  uint8_t* mh_enc = calloc(mh_enc_len + 1, sizeof(uint8_t));  // extra byte for null terminator
  if (mh_enc == NULL) {
    printf("error allocating memory for encoding multihash\n");
    free(mh);
    return 1;
  }
  mh_enc[mh_enc_len] = '\0';

  size_t mh_enc_bytes = 0;
  mb_err mb_err = mb_encode(mh, mh_len, MB_ENC_BASE16, mh_enc, mh_enc_len, &mh_enc_bytes);
  if (mb_err) {
    printf("error encoding multihash: %s\n", MB_ERR_STRS[mb_err]);
    free(mh);
    free(mh_enc);
    return 1;
  }
  printf("%s\n", (char*)mh_enc);

  free(mh);
  free(mh_enc);
  return 0;
}
