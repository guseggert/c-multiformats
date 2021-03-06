#include "multihash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"
#include "murmur3.h"
#include "varint.h"

const char* mh_err_str(mh_err err) {
  switch (err) {
    case MH_ERR_OK:
      return "no error";
    case MH_ERR_UNKNOWN_HASHFN:
      return "unknown hash function";
    case MH_ERR_UNSUPPORTED_HASHFN:
      return "unsupported hash function";
    case MH_ERR_INVALID_INPUT:
      return "invalid multihash input";
    case MH_ERR_MEMORY:
      return "unable to allocate memory";
    default:
      return "unknown multihash error";
  }
}

static mh_err murmur3_x64_64(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  (void)digest_size;

  uint64_t buf[2] = {0};

  MurmurHash3_x64_128(input, (int)input_size, 0, buf);

  // be careful to keep this agnostic to arch endianness
  uint64_t first64 = buf[0];
  digest[0] = (uint8_t)((first64 >> 56) & 0xFF);
  digest[1] = (uint8_t)((first64 >> 48) & 0xFF);
  digest[2] = (uint8_t)((first64 >> 40) & 0xFF);
  digest[3] = (uint8_t)((first64 >> 32) & 0xFF);
  digest[4] = (uint8_t)((first64 >> 24) & 0xFF);
  digest[5] = (uint8_t)((first64 >> 16) & 0xFF);
  digest[6] = (uint8_t)((first64 >> 8) & 0xFF);
  digest[7] = (uint8_t)(first64 & 0xFF);

  return MH_ERR_OK;
}

static mh_err murmur3_x64_64_size(size_t input_size, size_t* const digest_size) {
  (void)input_size;
  *digest_size = 8;
  return MH_ERR_OK;
}

static mh_err sha2_256_trunc254_padded(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  // SHA2-256 with the two most significant bits from the last byte zeroed (as via a mask with 0x3f)
  // re-use whatever implementation is provided by the backend
  const mh_func* func = NULL;
  mh_err err = mh_func_by_code(MH_FN_CODE_SHA2_256, &func);
  if (err) {
    return err;
  }
  err = func->hash_fn(input, input_size, digest, digest_size);
  if (err) {
    return err;
  }
  digest[digest_size - 1] &= 0x3f;
  return MH_ERR_OK;
}

static mh_err sha2_256_trunc254_padded_size(size_t input_size, size_t* const digest_size) {
  const mh_func* func = NULL;
  mh_err err = mh_func_by_code(MH_FN_CODE_SHA2_256, &func);
  if (err) {
    return err;
  }
  return func->hash_fn_size(input_size, digest_size);
}

static mh_err identity(const uint8_t* const input, size_t input_size, uint8_t* const digest, size_t digest_size) {
  (void)input_size;
  memcpy(digest, input, digest_size);
  return MH_ERR_OK;
}

static mh_err identity_size(size_t input_size, size_t* const digest_size) {
  *digest_size = input_size;
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
    .hash_fn_size = murmur3_x64_64_size,
    .next = &mh_fn_sha2_512_256,
};
const mh_func mh_fn_sha2_256_trunc254_padded = {
    .name = "sha2-256-trunc254-padded",
    .code = MH_FN_CODE_SHA2_256_TRUNC254_PADDED,
    .hash_fn = sha2_256_trunc254_padded,
    .hash_fn_size = sha2_256_trunc254_padded_size,
    .next = &mh_fn_murmur3_x64_64,
};
const mh_func mh_fn_identity = {
    .name = "identity",
    .code = MH_FN_CODE_IDENTITY,
    .hash_fn = identity,
    .hash_fn_size = identity_size,
    .next = &mh_fn_sha2_256_trunc254_padded,
};

const mh_func* mh_funcs = &mh_fn_identity;  // NOLINT

void mh_funcs_add(mh_func* funcs) {
  if (!funcs) {
    return;
  }
  mh_func* cur_func = funcs;
  while (cur_func->next) {
    cur_func = (mh_func*)cur_func->next;
  }
  cur_func->next = mh_funcs;
  mh_funcs = cur_func;
}

mh_err mh_digest(const uint8_t* const input, size_t input_size, mh_fn_code fn_code, uint8_t* const digest, size_t digest_size) {
  const mh_func* cur_func = mh_funcs;
  while (cur_func) {
    if (cur_func->code == fn_code) {
      return cur_func->hash_fn(input, input_size, digest, digest_size);
    }
    cur_func = cur_func->next;
  }
  return MH_ERR_UNKNOWN_HASHFN;
}

mh_err mh_digest_size(mh_fn_code fn_code, size_t input_size, size_t* const digest_size) {
  const mh_func* cur_func = mh_funcs;
  while (cur_func) {
    if (cur_func->code == fn_code) {
      if (digest_size) {
        return cur_func->hash_fn_size(input_size, digest_size);
      }
    }
    cur_func = cur_func->next;
  }
  return MH_ERR_UNKNOWN_HASHFN;
}

mh_err mh_encode_size(mh_fn_code fn_code, size_t input_size, size_t* encode_size) {
  // <fncode><digestsize><digest>
  // size of fn varint
  size_t fn_varint_size = 0;
  varint_err vi_err = uint64_to_varint(fn_code, NULL, &fn_varint_size);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }
  // size of digest
  size_t digest_size = 0;
  mh_err err = mh_digest_size(fn_code, input_size, &digest_size);
  if (err) {
    return err;
  }

  // size of digest varint
  size_t digest_varint_size = 0;
  vi_err = uint64_to_varint(digest_size, NULL, &digest_varint_size);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }

  *encode_size = fn_varint_size + digest_varint_size + digest_size;

  return MH_ERR_OK;
}

mh_err mh_encode(const uint8_t* input, size_t input_size, mh_fn_code fn_code, uint8_t* bytes, size_t bytes_size) {
  // <fncode><digestsize><digest>
  // fn code varint
  size_t fn_varint_size = 0;
  varint_err vi_err = uint64_to_varint(fn_code, bytes, &fn_varint_size);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }
  // digest varint
  size_t digest_size = 0;
  mh_err err = mh_digest_size(fn_code, input_size, &digest_size);
  if (err) {
    return err;
  }
  size_t digest_varint_size = 0;
  vi_err = uint64_to_varint(digest_size, bytes + fn_varint_size, &digest_varint_size);
  if (vi_err) {
    return MH_ERR_INVALID_INPUT;
  }

  // digest
  err =
      mh_digest(input, input_size, fn_code, bytes + fn_varint_size + digest_varint_size, bytes_size - fn_varint_size - digest_varint_size);
  if (err) {
    return err;
  }

  return MH_ERR_OK;
}

mh_err mh_read_fn_code(const uint8_t* bytes, size_t bytes_size, mh_fn_code* fn_code) {
  uint64_t mh_varint = 0;
  varint_err err = varint_to_uint64(bytes, bytes_size, &mh_varint, NULL);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }
  if (fn_code) {
    *fn_code = mh_varint;
  }
  return MH_ERR_OK;
}

mh_err mh_read_digest(const uint8_t* bytes, size_t bytes_size, size_t* digest_size, const uint8_t** digest) {
  if (bytes_size < 3) {
    return MH_ERR_INVALID_INPUT;
  }
  uint64_t mh_varint = 0;
  size_t mh_varint_size = 0;
  varint_err err = varint_to_uint64(bytes, bytes_size, &mh_varint, &mh_varint_size);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }

  uint64_t digest_varint = 0;
  size_t digest_varint_size = 0;
  err = varint_to_uint64(bytes + mh_varint_size, bytes_size - mh_varint_size, &digest_varint, &digest_varint_size);
  if (err) {
    return MH_ERR_INVALID_INPUT;
  }

  if (digest_size) {
    *digest_size = digest_varint;
  }
  if (digest) {
    *digest = bytes + mh_varint_size + digest_varint_size;
  }

  return MH_ERR_OK;
}

bool mh_validate(const uint8_t* bytes, size_t bytes_size) {
  mh_err err = mh_read_fn_code(bytes, bytes_size, NULL);
  if (err) {
    return err;
  }
  err = mh_read_digest(bytes, bytes_size, NULL, NULL);
  if (err) {
    return err;
  }

  return MH_ERR_OK;
}

mh_err mh_func_by_name(const char* const name, const mh_func** func) {
  const mh_func* cur_func = &mh_fn_identity;
  while (cur_func) {
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
  while (cur_func) {
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
