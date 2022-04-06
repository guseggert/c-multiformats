#include "varint.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"

const char *varint_err_str(varint_err err) {
  switch (err) {
    case VARINT_ERR_OK:
      return "no error";
    case VARINT_ERR_INVALID_INPUT:
      return "invalid varint";
    case VARINT_ERR_INPUT_TOO_BIG:
      return "varint input too big";
    case VARINT_ERR_BUF_SIZE:
      return "varint buffer size too small";
    default:
      return "unknown varint error";
  }
}

// 0x80 = 1000 0000
// 0x7f = 0111 1111
varint_err varint_to_uint64(const uint8_t *bytes, size_t bytes_size, uint64_t *const val, size_t *const varint_size) {
  size_t size = 0;
  uint64_t v = 0;
  for (size_t i = 0; i < bytes_size && i < VARINT_UINT64_MAX_BYTES; i++) {
    v |= (bytes[i] & 0x7fU) << (7 * i);
    size++;
    if (!(bytes[i] & 0x80)) {
      if (val) {
        *val = v;
      }
      if (varint_size) {
        *varint_size = size;
      }
      return VARINT_ERR_OK;
    }
  }
  return VARINT_ERR_INVALID_INPUT;
}

varint_err uint64_to_varint(uint64_t n, uint8_t *const varint, size_t *const varint_size) {
  uint64_t a = 0;
  if (varint) {
    // first byte is always zero
    varint[0] = 0;
    for (size_t i = 0; i < VARINT_UINT64_MAX_BYTES && n > 0; i++) {
      a += n >= 0x80;
      varint[i] = (uint8_t)(n | 0x80);
      n >>= 7;
    }
    varint[a] &= 0x7f;
  } else {
    for (size_t i = 0; i < VARINT_UINT64_MAX_BYTES && n > 0; i++) {
      a += n >= 0x80;
      n >>= 7;
    }
  }
  if (varint_size) {
    *varint_size = a + 1;
  }
  return VARINT_ERR_OK;
}
