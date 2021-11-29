#include "multihash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"
#include "murmur3.h"
#include "varint.h"

static mh_err murmur3_x64_64(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  (void)digest_len;
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

static mh_err murmur3_x64_64_len(size_t input_len, size_t* const digest_len) {
  (void)input_len;
  *digest_len = 8;
  return MH_ERR_OK;
}

static mh_err sha2_256_trunc254_padded(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  // SHA2-256 with the two most significant bits from the last byte zeroed (as via a mask with 0x3f)
  // re-use whatever implementation is provided by the backend
  const mh_func* func = NULL;
  mh_err err = mh_func_by_code(MH_FN_CODE_SHA2_256, &func);
  if (err) {
    return err;
  }
  err = func->hash_fn(input, input_len, digest, digest_len);
  if (err) {
    return err;
  }
  digest[digest_len - 1] &= 0x3f;
  return MH_ERR_OK;
}

static mh_err sha2_256_trunc254_padded_len(size_t input_len, size_t* const digest_len) {
  const mh_func* func = NULL;
  mh_err err = mh_func_by_code(MH_FN_CODE_SHA2_256, &func);
  if (err) {
    return err;
  }
  return func->hash_fn_len(input_len, digest_len);
}

static mh_err identity(const uint8_t* const input, size_t input_len, uint8_t* const digest, size_t digest_len) {
  (void)input_len;
  memcpy(digest, input, digest_len);
  return MH_ERR_OK;
}

static mh_err identity_len(size_t input_len, size_t* const digest_len) {
  *digest_len = input_len;
  return MH_ERR_OK;
}

#ifdef MH_BACKEND_GCRYPT
#include "multihash-gcrypt.c"  // NOLINT
#elifdef MH_BACKEND_MBED
#include "multihash-mbed.c"  // NOLINT
const mh_func mh_fn_sha2_512_256 = {.disabled = true, .next = &mh_fn_sha2_512};
#elifdef MH_BACKEND_OPENSSL
#include "multihash-openssl.c"  // NOLINT
#else
const mh_func mh_fn_sha2_512_256 = {.disabled = true, .next = NULL};
#endif

const mh_func mh_fn_murmur3_x64_64 = {
    .name = "murmur3-x64-64",
    .code = MH_FN_CODE_MURMUR3_X64_64,
    .hash_fn = murmur3_x64_64,
    .hash_fn_len = murmur3_x64_64_len,
    .next = &mh_fn_sha2_512_256,
};
const mh_func mh_fn_sha2_256_trunc254_padded = {
    .name = "sha2-256-trunc254-padded",
    .code = MH_FN_CODE_SHA2_256_TRUNC254_PADDED,
    .hash_fn = sha2_256_trunc254_padded,
    .hash_fn_len = sha2_256_trunc254_padded_len,
    .next = &mh_fn_murmur3_x64_64,
};
const mh_func mh_fn_identity = {
    .name = "identity",
    .code = MH_FN_CODE_IDENTITY,
    .hash_fn = identity,
    .hash_fn_len = identity_len,
    .next = &mh_fn_sha2_256_trunc254_padded,
};
static const mh_func* mh_funcs = &mh_fn_identity;  // NOLINT

void mh_add_funcs(mh_func* funcs) {
  if (funcs == NULL) {
    return;
  }
  mh_func* cur_func = funcs;
  while (cur_func->next != NULL) {
    cur_func = (mh_func*)cur_func->next;
  }
  cur_func->next = mh_funcs;
  mh_funcs = cur_func;
}

mh_err mh_digest(const uint8_t* const input, size_t input_len, mh_fn_code fn_code, uint8_t* const digest, size_t digest_len) {
  const mh_func* cur_func = &mh_fn_identity;
  while (cur_func != NULL) {
    if (cur_func->code == fn_code) {
      return cur_func->hash_fn(input, input_len, digest, digest_len);
    }
    cur_func = cur_func->next;
  }
  return MH_ERR_UNKNOWN_HASHFN;
}

mh_err mh_digest_len(mh_fn_code fn_code, size_t input_len, size_t* const digest_len) {
  const mh_func* cur_func = &mh_fn_identity;
  while (cur_func != NULL) {
    if (cur_func->code == fn_code) {
      return cur_func->hash_fn_len(input_len, digest_len);
    }
    cur_func = cur_func->next;
  }
  return MH_ERR_UNKNOWN_HASHFN;
}

mh_err mh_encode_len(mh_fn_code fn_code, size_t input_len, size_t* encode_len) {
  // <fncode><digestsize><digest>
  // length of fn varint
  size_t fn_varint_len = 0;
  varint_err vi_err = uint64_to_varint(fn_code, NULL, &fn_varint_len);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }
  // length of digest
  size_t digest_len = 0;
  mh_err err = mh_digest_len(fn_code, input_len, &digest_len);
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

mh_err mh_encode(const uint8_t* input, size_t input_len, mh_fn_code fn_code, uint8_t* bytes, size_t bytes_len) {
  // <fncode><digestsize><digest>
  // fn code varint
  size_t fn_varint_len = 0;
  varint_err vi_err = uint64_to_varint(fn_code, bytes, &fn_varint_len);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }
  // digest varint
  size_t digest_len = 0;
  mh_err err = mh_digest_len(fn_code, input_len, &digest_len);
  if (err) {
    return err;
  }
  size_t digest_varint_len = 0;
  vi_err = uint64_to_varint(digest_len, bytes + fn_varint_len, &digest_varint_len);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }

  // digest
  err = mh_digest(input, input_len, fn_code, bytes + fn_varint_len + digest_varint_len, bytes_len - fn_varint_len - digest_varint_len);
  if (err) {
    return err;
  }

  return MH_ERR_OK;
}

mh_err mh_read_fn_code(const uint8_t* bytes, size_t bytes_len, mh_fn_code* fn_code) {
  uint64_t mh_varint = 0;
  varint_err err = varint_to_uint64(bytes, bytes_len, &mh_varint, NULL);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }
  if (fn_code != NULL) {
    *fn_code = mh_varint;
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
  mh_err err = mh_read_fn_code(bytes, bytes_len, NULL);
  if (err) {
    return err;
  }
  err = mh_read_digest(bytes, bytes_len, NULL, NULL);
  if (err) {
    return err;
  }

  return MH_ERR_OK;
}

mh_err mh_func_by_name(const char* const name, const mh_func** func) {
  const mh_func* cur_func = &mh_fn_identity;
  while (cur_func != NULL) {
    if (cur_func->disabled) {
      cur_func = cur_func->next;
      continue;
    }
    if (!strcmp(name, cur_func->name)) {
      *func = cur_func;
      return MH_ERR_OK;
    }
    cur_func = cur_func->next;
  }
  return MH_ERR_UNKNOWN_HASHFN;
}

mh_err mh_func_by_code(mh_fn_code fn_code, const mh_func** func) {
  const mh_func* cur_func = &mh_fn_identity;
  while (cur_func != NULL) {
    if (cur_func->disabled) {
      cur_func = cur_func->next;
      continue;
    }
    if (fn_code == cur_func->code) {
      *func = cur_func;
      return MH_ERR_OK;
    }
    cur_func = cur_func->next;
  }
  return MH_ERR_UNKNOWN_HASHFN;
}
