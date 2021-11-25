#include "varint.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"

// 0x80 = 1000 0000
// 0x7f = 0111 1111
varint_err varint_to_uint64(const uint8_t *bytes, size_t bytes_len, uint64_t *const val, size_t *const varint_len) {
  size_t len = 0;
  uint64_t v = 0;
  for (size_t i = 0; i < bytes_len && i < UINT64_MAX_BYTES; i++) {
    v |= (bytes[i] & 0x7f) << (7 * i);
    len++;
    if (!(bytes[i] & 0x80)) {
      if (val != NULL) {
        *val = v;
      }
      if (varint_len != NULL) {
        *varint_len = len;
      }
      return VARINT_ERR_OK;
    }
  }
  return VARINT_ERR_INVALID_INPUT;
}

varint_err uint64_to_varint(uint64_t n, uint8_t *const varint, size_t *const varint_len) {
  uint64_t a = 0;
  for (size_t i = 0; i < UINT64_MAX_BYTES; i++) {
    a += n >= 0x80;
    if (varint != NULL) {
      varint[i] = n | 0x80;
    }
    n >>= 7;
  }
  if (varint != NULL) {
    varint[a] ^= 0x80;
  }
  if (varint_len != NULL) {
    *varint_len = a + 1;
  }
  return VARINT_ERR_OK;
}
