#include "multibase.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* mb_err_str(mb_err err) {
  switch (err) {
    case MB_ERR_OK:
      return "no error";
    case MB_ERR_UNKNOWN_ENC:
      return "unknown multibase encoding";
    case MB_ERR_INVALID_INPUT:
      return "invalid multibase";
    case MB_ERR_BUF_SIZE:
      return "multibase buffer size too small";
    default:
      return "unknown error";
  }
}

typedef struct {
  char* name;
  mb_err (*encode)(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                   size_t* const result_size);
  mb_err (*decode)(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                   size_t* const result_size);
  size_t (*encode_size)(const uint8_t* const input, size_t input_size);
  size_t (*decode_size)(const uint8_t* const input, size_t input_size);
  mb_enc enc;
  unsigned char code;
} mb_encoding;

size_t mb_base2_encode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return input_size * 8;
}
mb_err mb_base2_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                       size_t* const result_size) {
  (void)result_buf_size;
  for (size_t i = 0; i < input_size; i++) {
    uint8_t b = input[i];
    for (unsigned char j = 7; j <= 7; j--) {
      size_t idx = i * 8 + j;
      result_buf[idx] = '0' + ((b >> (7 - j)) & 1);
    }
  }
  *result_size = input_size * 8;
  return MB_ERR_OK;
}

size_t mb_base2_decode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return (input_size + 7) / 8;
}
mb_err mb_base2_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                       size_t* const result_size) {
  (void)result_buf_size;
  size_t res_idx = 0;
  for (size_t i = 0; i < input_size; i++) {
    uint8_t cur_res_bit_num = i % 8;
    uint8_t res_byte = input[i] - '0';
    if (res_byte > 1) {
      return MB_ERR_INVALID_INPUT;
    }
    result_buf[res_idx] |= (uint8_t)(res_byte << (7U - cur_res_bit_num));

    if (cur_res_bit_num == 7) {
      res_idx++;
    }
  }
  *result_size = (input_size + 7) / 8;
  return MB_ERR_OK;
}

size_t mb_base10_encode_size(const uint8_t* const input, size_t input_size) {
  // this is approximate, sometimes it can be overshoot by 1 byte
  size_t zeros = 0;
  while (zeros < input_size && !input[zeros]) {
    zeros++;
  }
  return ((input_size - zeros) * 242 / 100 + 1) + zeros;
}

mb_err mb_base10_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                        size_t* const result_size) {
  // the implementation of base10 is very similar to base58, leading zeros are treated specially to preserve zero-byte padding
  size_t num_zeros = 0;

  while (num_zeros < input_size && input[num_zeros] == 0) {
    result_buf[num_zeros] = '0';
    num_zeros++;
  }

  size_t high = result_buf_size;
  uint16_t carry = 0;
  size_t j = 0;
  for (size_t i = num_zeros; i < input_size; i++, high = j) {
    carry = input[i];
    for (j = result_buf_size - 1; (j >= high) || carry; j--) {
      // in this loop, the max val of carry is 256 * 10 = 2560
      carry += (uint16_t)(256 * result_buf[j]);
      result_buf[j] = (uint8_t)(carry % 10);
      carry /= 10;
      if (!j) {
        break;
      }
    }
  }

  // find the start of the non-zero section
  size_t b10_bytes_idx = num_zeros;
  for (; b10_bytes_idx < result_buf_size && !result_buf[b10_bytes_idx]; b10_bytes_idx++) {
    // nothing
  }

  // then swap everything left as necessary
  size_t unused = b10_bytes_idx - num_zeros;
  size_t i = b10_bytes_idx;

  for (; i < result_buf_size; i++) {
    result_buf[i - unused] = result_buf[i] + 48;
  }
  *result_size = i - unused;

  return MB_ERR_OK;
}

size_t mb_base10_decode_size(const uint8_t* const input, size_t input_size) {
  // this is approximate, sometimes it can overshoot by 1 byte
  size_t zeros = 0;
  while (zeros < input_size && input[zeros] == '0') {
    zeros++;
  }
  return ((input_size - zeros) * 416 / 1000 + 1) + zeros;
}

mb_err mb_base10_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                        size_t* const result_size) {
  if (input_size == 0) {
    return MB_ERR_OK;
  }

  size_t num_zeros = 0;
  while (num_zeros < input_size && input[num_zeros] == '0') {
    num_zeros++;
  }

  size_t high = result_buf_size;
  uint32_t carry = 0;
  size_t j = 0;
  for (size_t i = num_zeros; i < input_size; i++, high = j) {
    if (input[i] < '0' || input[i] > '9') {
      return MB_ERR_INVALID_INPUT;
    }
    carry = input[i] - 48;
    for (j = result_buf_size - 1; (j >= high) || carry; j--) {
      // in this loop, the max val of carry is 10 * 256 = 2560
      carry += (uint32_t)(10 * (uint32_t)result_buf[j]);
      result_buf[j] = (uint8_t)(carry % 256);
      // want 102, got 12
      carry /= 256;
      if (!j) {
        break;
      }
    }
  }

  // write zeros
  if (num_zeros > 0) {
    memset(result_buf, 0, num_zeros);
  }

  // find the first non-zero byte of the buf
  size_t b10_bytes_idx = 0;
  for (; b10_bytes_idx < result_buf_size && !result_buf[b10_bytes_idx]; b10_bytes_idx++) {
    // nothing
  }

  // swap left as necessary
  size_t i = num_zeros;
  for (; b10_bytes_idx < result_buf_size; i++, b10_bytes_idx++) {
    result_buf[i] = result_buf[b10_bytes_idx];
  }

  *result_size = i;

  return MB_ERR_OK;
}

size_t mb_identity_encode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return input_size;
}
mb_err mb_identity_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                          size_t* const result_size) {
  (void)result_buf_size;
  memcpy(result_buf, input, input_size);
  *result_size = input_size;
  return MB_ERR_OK;
}

size_t mb_identity_decode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return input_size;
}
mb_err mb_identity_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                          size_t* const result_size) {
  (void)result_buf_size;
  return mb_identity_encode(input, input_size, result_buf, result_buf_size, result_size);
}

// derivation, given le=encoded size and ld=decoded size:
// le = (8 * ld + 5) / 6
// ld = ceil((6 * le - 5) / 8)
// ld = (6 * le + 2) / 8
// ld = (3 * le + 1) / 4
size_t mb_base64_decode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return ((3 * input_size) + 1) / 4;
}
mb_err mb_base64_decode_lookup(const char* lookup, const uint8_t* const input, size_t input_size, uint8_t* const result,
                               size_t* const result_size) {
  size_t res_idx = 0;
  uint16_t bit_accum = 0;
  uint8_t bit_accum_bits = 0;

  for (size_t input_idx = 0; input_idx < input_size; input_idx++) {
    // read an input byte into accumulator (only the bottom 6 bits)
    char ch = lookup[input[input_idx]];
    if (ch == -1) {
      return MB_ERR_INVALID_INPUT;
    }

    // stick the 6 bits onto the accumulator
    bit_accum <<= 6;
    bit_accum = (uint16_t)(bit_accum | (ch & 63));
    bit_accum_bits += 6;

    // if there's a byte in accumulator, add it to result
    if (bit_accum_bits >= 8) {
      uint8_t b = (uint8_t)((bit_accum & (0xFF << (bit_accum_bits - 8))) >> (bit_accum_bits - 8));
      result[res_idx++] = b;
      bit_accum_bits -= 8;
    }
  }
  // there are three valid cases for bit_accum_bits here, 0, 2, and 4
  // a value of 6 indicates a non-integral number of octets, which is invalid base64
  if (bit_accum_bits == 6) {
    return MB_ERR_INVALID_INPUT;
  }
  *result_size = res_idx;
  return MB_ERR_OK;
}

// reference: https://datatracker.ietf.org/doc/html/rfc4648
size_t mb_base64_encode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return (input_size * 8 + 5) / 6;
}
mb_err mb_base64_encode_alphabet(const char* const alphabet, const uint8_t* const input, size_t input_size, uint8_t* const result,
                                 size_t* const result_size) {
  size_t res_idx = 0;
  uint16_t bit_accum = 0;
  uint8_t bit_accum_bits = 0;

  for (size_t input_idx = 0; input_idx < input_size; input_idx++) {
    // read off a byte from the input
    bit_accum <<= 8;
    bit_accum = (uint16_t)(bit_accum | input[input_idx]);
    bit_accum_bits += 8;

    while (bit_accum_bits >= 6) {
      // read off top 6 bits, leave the rest
      // 63=111111, and we want the top 6 bits
      uint8_t next_6_bits = (uint8_t)((bit_accum & (63 << (bit_accum_bits - 6))) >> (bit_accum_bits - 6));
      // top bits are garbage at this point
      bit_accum_bits -= 6;
      result[res_idx++] = (uint8_t)alphabet[next_6_bits];
    }
  }
  // if there's leftover stuff, stick it in the last byte
  // worst case here is bit_accum_bits=6
  // (bit_accum_bits=4, read last byte so bit_accum_bits=12, then read 6 bits off so bit_accum_bits=6)
  // so we know we only need to read at most 6 bits from the accum
  if (bit_accum_bits > 0) {
    // take whatever's left, pad it to the right with zeros if it's <6 bits
    uint8_t rest = (uint8_t)((bit_accum & (UINT16_MAX >> (16 - bit_accum_bits))) << (6 - bit_accum_bits));
    result[res_idx++] = (uint8_t)alphabet[rest];
  }
  *result_size = res_idx;

  return MB_ERR_OK;
}

size_t mb_base32_encode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return (input_size * 8 + 4) / 5;
}
mb_err mb_base32_encode_alphabet(const char* const alphabet, const uint8_t* const input, size_t input_size, uint8_t* const result,
                                 size_t* const result_size) {
  size_t res_idx = 0;
  uint16_t bit_accum = 0;
  uint8_t bit_accum_bits = 0;
  for (size_t input_idx = 0; input_idx < input_size; input_idx++) {
    bit_accum <<= 8;
    bit_accum = (uint16_t)(bit_accum | input[input_idx]);
    bit_accum_bits += 8;
    while (bit_accum_bits >= 5) {
      uint8_t next_5_bits = (uint8_t)((bit_accum & (31 << (bit_accum_bits - 5))) >> (bit_accum_bits - 5));
      bit_accum_bits -= 5;
      result[res_idx++] = (uint8_t)alphabet[next_5_bits];
    }
  }
  if (bit_accum_bits > 0) {
    uint8_t rest = (uint8_t)((bit_accum & (UINT16_MAX >> (16 - bit_accum_bits))) << (5 - bit_accum_bits));
    result[res_idx++] = (uint8_t)alphabet[rest];
  }
  *result_size = res_idx;
  return MB_ERR_OK;
}
mb_err mb_base32_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                        size_t* const result_size) {
  (void)result_buf_size;
  return mb_base32_encode_alphabet("abcdefghijklmnopqrstuvwxyz234567", input, input_size, result_buf, result_size);
}
mb_err mb_base32upper_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                             size_t* const result_size) {
  (void)result_buf_size;
  return mb_base32_encode_alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", input, input_size, result_buf, result_size);
}

// TODO(guseggert): generalize this so it can be used for base 2^n (base2, base4, base8, base16, base32, base64)
size_t mb_base32_decode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return (input_size * 5 + 3) / 8;
}
mb_err mb_base32_decode_lookup(const char* lookup, const uint8_t* const input, size_t input_size, uint8_t* const result_buf,
                               size_t* const result_size) {
  size_t res_idx = 0;
  uint16_t bit_accum = 0;
  uint8_t bit_accum_bits = 0;

  for (size_t input_idx = 0; input_idx < input_size; input_idx++) {
    char ch = lookup[input[input_idx]];
    if (ch == -1) {
      return MB_ERR_INVALID_INPUT;
    }
    bit_accum <<= 5;
    bit_accum = (uint16_t)(bit_accum | (ch & 31));
    bit_accum_bits += 5;

    if (bit_accum_bits >= 8) {
      uint8_t b = (uint8_t)((bit_accum & (0xFF << (bit_accum_bits - 8))) >> (bit_accum_bits - 8));
      result_buf[res_idx++] = b;
      bit_accum_bits -= 8;
    }
  }
  if (bit_accum_bits == 6) {
    return MB_ERR_INVALID_INPUT;
  }
  *result_size = res_idx;
  return MB_ERR_OK;
}
mb_err mb_base32_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                        size_t* const result_size) {
  (void)result_buf_size;
  static const char lookup[] = {
      -1, -1, -1, -1, -1, -1, -1, -1,  // 0-7
      -1, -1, -1, -1, -1, -1, -1, -1,  // 8-15
      -1, -1, -1, -1, -1, -1, -1, -1,  // 16-23
      -1, -1, -1, -1, -1, -1, -1, -1,  // 24-31
      -1, -1, -1, -1, -1, -1, -1, -1,  // 32-39
      -1, -1, -1, -1, -1, -1, -1, -1,  // 40-47
      -1, -1, 26, 27, 28, 29, 30, 31,  // 48-55
      -1, -1, -1, -1, -1, -1, -1, -1,  // 56-63
      -1, -1, -1, -1, -1, -1, -1, -1,  // 64-71
      -1, -1, -1, -1, -1, -1, -1, -1,  // 72-79
      -1, -1, -1, -1, -1, -1, -1, -1,  // 80-87
      -1, -1, -1, -1, -1, -1, -1, -1,  // 88-95
      -1, 0,  1,  2,  3,  4,  5,  6,   // 96-103
      7,  8,  9,  10, 11, 12, 13, 14,  // 104-111
      15, 16, 17, 18, 19, 20, 21, 22,  // 112-119
      23, 24, 25, -1, -1, -1, -1, -1,  // 120-127
  };
  return mb_base32_decode_lookup(lookup, input, input_size, result_buf, result_size);
}
mb_err mb_base32upper_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                             size_t* const result_size) {
  (void)result_buf_size;
  static const char lookup[] = {
      -1, -1, -1, -1, -1, -1, -1, -1,  // 0-7
      -1, -1, -1, -1, -1, -1, -1, -1,  // 8-15
      -1, -1, -1, -1, -1, -1, -1, -1,  // 16-23
      -1, -1, -1, -1, -1, -1, -1, -1,  // 24-31
      -1, -1, -1, -1, -1, -1, -1, -1,  // 32-39
      -1, -1, -1, -1, -1, -1, -1, -1,  // 40-47
      -1, -1, 26, 27, 28, 29, 30, 31,  // 48-55
      -1, -1, -1, -1, -1, -1, -1, -1,  // 56-63
      -1, 0,  1,  2,  3,  4,  5,  6,   // 64-71
      7,  8,  9,  10, 11, 12, 13, 14,  // 72-79
      15, 16, 17, 18, 19, 20, 21, 22,  // 80-87
      23, 24, 25, -1, -1, -1, -1, -1,  // 88-95
      -1, -1, -1, -1, -1, -1, -1, -1,  // 96-103
      -1, -1, -1, -1, -1, -1, -1, -1,  // 104-111
      -1, -1, -1, -1, -1, -1, -1, -1,  // 112-119
      -1, -1, -1, -1, -1, -1, -1, -1,  // 120-127
  };
  return mb_base32_decode_lookup(lookup, input, input_size, result_buf, result_size);
}

mb_err mb_base64_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                        size_t* const result_size) {
  (void)result_buf_size;
  return mb_base64_encode_alphabet(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", input, input_size, result_buf, result_size);
}
mb_err mb_base64_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                        size_t* const result_size) {
  (void)result_buf_size;
  static const char lookup[] = {
      -1, -1, -1, -1, -1, -1, -1, -1,  // 0-7
      -1, -1, -1, -1, -1, -1, -1, -1,  // 8-15
      -1, -1, -1, -1, -1, -1, -1, -1,  // 16-23
      -1, -1, -1, -1, -1, -1, -1, -1,  // 24-31
      -1, -1, -1, -1, -1, -1, -1, -1,  // 32-39
      -1, -1, -1, 62, -1, -1, -1, 63,  // 40-47
      52, 53, 54, 55, 56, 57, 58, 59,  // 48-55
      60, 61, -1, -1, -1, -1, -1, -1,  // 56-63
      -1, 0,  1,  2,  3,  4,  5,  6,   // 64-71
      7,  8,  9,  10, 11, 12, 13, 14,  // 72-79
      15, 16, 17, 18, 19, 20, 21, 22,  // 80-87
      23, 24, 25, 0,  0,  0,  0,  0,   // 88-95
      0,  26, 27, 28, 29, 30, 31, 32,  // 96-103
      33, 34, 35, 36, 37, 38, 39, 40,  // 104-111
      41, 42, 43, 44, 45, 46, 47, 48,  // 112-119
      49, 50, 51, -1, -1, -1, -1, -1,  // 120-127
  };
  return mb_base64_decode_lookup(lookup, input, input_size, result_buf, result_size);
}

mb_err mb_base64url_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                           size_t* const result_size) {
  (void)result_buf_size;
  return mb_base64_encode_alphabet(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", input, input_size, result_buf, result_size);
}
mb_err mb_base64url_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                           size_t* const result_size) {
  (void)result_buf_size;
  static const char lookup[] = {
      -1, -1, -1, -1, -1, -1, -1, -1,  // 0-7
      -1, -1, -1, -1, -1, -1, -1, -1,  // 8-15
      -1, -1, -1, -1, -1, -1, -1, -1,  // 16-23
      -1, -1, -1, -1, -1, -1, -1, -1,  // 24-31
      -1, -1, -1, -1, -1, -1, -1, -1,  // 32-39
      -1, -1, -1, -1, -1, 62, -1, -1,  // 40-47
      52, 53, 54, 55, 56, 57, 58, 59,  // 48-55
      60, 61, -1, -1, -1, -1, -1, -1,  // 56-63
      -1, 0,  1,  2,  3,  4,  5,  6,   // 64-71
      7,  8,  9,  10, 11, 12, 13, 14,  // 72-79
      15, 16, 17, 18, 19, 20, 21, 22,  // 80-87
      23, 24, 25, 0,  0,  0,  0,  63,  // 88-95
      0,  26, 27, 28, 29, 30, 31, 32,  // 96-103
      33, 34, 35, 36, 37, 38, 39, 40,  // 104-111
      41, 42, 43, 44, 45, 46, 47, 48,  // 112-119
      49, 50, 51, -1, -1, -1, -1, -1,  // 120-127
  };
  return mb_base64_decode_lookup(lookup, input, input_size, result_buf, result_size);
}

size_t mb_base16_encode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return input_size * 2;
}
mb_err mb_base16_encode_alphabet(const char* const alphabet, const uint8_t* const input, size_t input_size, uint8_t* const result_buf,
                                 size_t* const result_size) {
  for (size_t i = 0, j = 0; i < input_size; i++, j += 2) {
    uint8_t b = input[i];
    result_buf[j] = (uint8_t)alphabet[(b >> 4) & 0xf];
    result_buf[j + 1] = (uint8_t)alphabet[b & 0xf];
  }
  *result_size = input_size * 2;
  return MB_ERR_OK;
}
mb_err mb_base16_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                        size_t* const result_size) {
  (void)result_buf_size;
  return mb_base16_encode_alphabet("0123456789abcdef", input, input_size, result_buf, result_size);
}
mb_err mb_base16upper_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                             size_t* const result_size) {
  (void)result_buf_size;
  return mb_base16_encode_alphabet("0123456789ABCDEF", input, input_size, result_buf, result_size);
}

size_t mb_base16_decode_size(const uint8_t* const input, size_t input_size) {
  (void)input;
  return input_size / 2;
}
mb_err mb_base16_decode_lookup(const char* const lookup, const uint8_t* const input, size_t input_size, uint8_t* const result_buf,
                               size_t* const result_size) {
  if (input_size % 2 != 0) {
    return MB_ERR_INVALID_INPUT;
  }
  for (size_t i = 0, j = 0; i < input_size; i += 2, j++) {
    result_buf[j] = (uint8_t)(result_buf[j] | (lookup[input[i]] << 4));
    result_buf[j] = (uint8_t)(result_buf[j] | (lookup[input[i + 1]]));
  }
  *result_size = input_size / 2;
  return MB_ERR_OK;
}
mb_err mb_base16_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                        size_t* const result_size) {
  (void)result_buf_size;
  static const char lookup[] = {
      -1, -1, -1, -1, -1, -1, -1, -1,  // 0-7
      -1, -1, -1, -1, -1, -1, -1, -1,  // 8-15
      -1, -1, -1, -1, -1, -1, -1, -1,  // 16-23
      -1, -1, -1, -1, -1, -1, -1, -1,  // 24-31
      -1, -1, -1, -1, -1, -1, -1, -1,  // 32-39
      -1, -1, -1, -1, -1, -1, -1, -1,  // 40-47
      0,  1,  2,  3,  4,  5,  6,  7,   // 48-55
      8,  9,  -1, -1, -1, -1, -1, -1,  // 56-63
      -1, -1, -1, -1, -1, -1, -1, -1,  // 64-71
      -1, -1, -1, -1, -1, -1, -1, -1,  // 72-79
      -1, -1, -1, -1, -1, -1, -1, -1,  // 80-87
      -1, -1, -1, -1, -1, -1, -1, -1,  // 88-95
      -1, 10, 11, 12, 13, 14, 15, -1,  // 96-103
      -1, -1, -1, -1, -1, -1, -1, -1,  // 104-111
      -1, -1, -1, -1, -1, -1, -1, -1,  // 112-119
      -1, -1, -1, -1, -1, -1, -1, -1,  // 120-127
  };
  return mb_base16_decode_lookup(lookup, input, input_size, result_buf, result_size);
}
mb_err mb_base16upper_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                             size_t* const result_size) {
  (void)result_buf_size;
  static const char lookup[] = {
      -1, -1, -1, -1, -1, -1, -1, -1,  // 0-7
      -1, -1, -1, -1, -1, -1, -1, -1,  // 8-15
      -1, -1, -1, -1, -1, -1, -1, -1,  // 16-23
      -1, -1, -1, -1, -1, -1, -1, -1,  // 24-31
      -1, -1, -1, -1, -1, -1, -1, -1,  // 32-39
      -1, -1, -1, -1, -1, -1, -1, -1,  // 40-47
      0,  1,  2,  3,  4,  5,  6,  7,   // 48-55
      8,  9,  -1, -1, -1, -1, -1, -1,  // 56-63
      -1, 10, 11, 12, 13, 14, 15, -1,  // 64-71
      -1, -1, -1, -1, -1, -1, -1, -1,  // 72-79
      -1, -1, -1, -1, -1, -1, -1, -1,  // 80-87
      -1, -1, -1, -1, -1, -1, -1, -1,  // 88-95
      -1, -1, -1, -1, -1, -1, -1, -1,  // 96-103
      -1, -1, -1, -1, -1, -1, -1, -1,  // 104-111
      -1, -1, -1, -1, -1, -1, -1, -1,  // 112-119
      -1, -1, -1, -1, -1, -1, -1, -1,  // 120-127
  };
  return mb_base16_decode_lookup(lookup, input, input_size, result_buf, result_size);
}

size_t mb_base58btc_encode_size(const uint8_t* const input, size_t input_size) {
  // this is approximate, sometimes it can be overshoot by 1 byte
  size_t zeros = 0;
  while (zeros < input_size && !input[zeros]) {
    zeros++;
  }
  return ((input_size - zeros) * 138 / 100 + 1) + zeros;
}

// reference: https://tools.ietf.org/id/draft-msporny-base58-01.html
mb_err mb_base58btc_encode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                           size_t* const result_size) {
  if (input_size == 0) {
    return MB_ERR_OK;
  }

  const char* alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  size_t num_zeros = 0;

  while (num_zeros < input_size && input[num_zeros] == 0) {
    result_buf[num_zeros] = '1';
    num_zeros++;
  }

  size_t high = result_buf_size;
  uint16_t carry = 0;
  size_t j = 0;
  for (size_t i = num_zeros; i < input_size; i++, high = j) {
    carry = input[i];
    for (j = result_buf_size - 1; (j >= high) || carry; j--) {
      // in this loop, max val of carry is 256 * 58 = 14848
      carry += (uint16_t)(256 * result_buf[j]);
      result_buf[j] = (uint8_t)(carry % 58);
      carry /= 58;
      if (!j) {
        break;
      }
    }
  }

  // there could be extra zeros to the left of the result, so swap left if necessaryo

  // find the start of the non-zero section
  size_t b58_bytes_idx = num_zeros;
  for (; b58_bytes_idx < result_buf_size && !result_buf[b58_bytes_idx]; b58_bytes_idx++) {
    // nothing
  }

  // then swap everything left as necessary
  size_t unused = b58_bytes_idx - num_zeros;
  size_t i = b58_bytes_idx;
  for (; i < result_buf_size; i++) {
    result_buf[i - unused] = (uint8_t)alphabet[result_buf[i]];
  }
  *result_size = i - unused;
  return MB_ERR_OK;
}

size_t mb_base58btc_decode_size(const uint8_t* const input, size_t input_size) {
  // this is approximate, sometimes it can overshoot by 1 byte
  size_t zeros = 0;
  while (zeros < input_size && input[zeros] == '1') {
    zeros++;
  }
  return ((input_size - zeros) * 733 / 1000 + 1) + zeros;
}

mb_err mb_base58btc_decode(const uint8_t* const input, size_t input_size, uint8_t* const result_buf, size_t result_buf_size,
                           size_t* const result_size) {
  static const char lookup[] = {
      -1, -1, -1, -1, -1, -1, -1, -1,  // 0-7
      -1, -1, -1, -1, -1, -1, -1, -1,  // 8-15
      -1, -1, -1, -1, -1, -1, -1, -1,  // 16-23
      -1, -1, -1, -1, -1, -1, -1, -1,  // 24-31
      -1, -1, -1, -1, -1, -1, -1, -1,  // 32-39
      -1, -1, -1, -1, -1, -1, -1, -1,  // 40-47
      -1, 0,  1,  2,  3,  4,  5,  6,   // 48-55
      7,  8,  -1, -1, -1, -1, -1, -1,  // 56-63
      -1, 9,  10, 11, 12, 13, 14, 15,  // 64-71
      16, -1, 17, 18, 19, 20, 21, -1,  // 72-79
      22, 23, 24, 25, 26, 27, 28, 29,  // 80-87
      30, 31, 32, -1, -1, -1, -1, -1,  // 88-95
      -1, 33, 34, 35, 36, 37, 38, 39,  // 96-103
      40, 41, 42, 43, -1, 44, 45, 46,  // 104-111
      47, 48, 49, 50, 51, 52, 53, 54,  // 112-119
      55, 56, 57, -1, -1, -1, -1, -1,  // 120-127
  };
  if (input_size == 0) {
    return MB_ERR_OK;
  }

  size_t num_zeros = 0;

  while (num_zeros < input_size && input[num_zeros] == '1') {
    num_zeros++;
  }

  size_t high = result_buf_size;
  uint16_t carry = 0;
  size_t j = 0;
  for (size_t i = num_zeros; i < input_size; i++, high = j) {
    char ch = lookup[input[i]];  // NOLINT
    if (ch < 0) {
      return MB_ERR_INVALID_INPUT;
    }
    carry = (uint8_t)ch;
    for (j = result_buf_size - 1; (j >= high) || carry; j--) {
      // in this loop, max val of carry is 256 * 58 = 14848
      carry += (uint16_t)(58 * result_buf[j]);
      result_buf[j] = (uint8_t)carry % 256;
      carry /= 256;
      if (!j) {
        break;
      }
    }
  }

  // write zeros
  if (num_zeros > 0) {
    memset(result_buf, 0, num_zeros);
  }

  // find the first non-zero byte of the buf
  size_t b58_bytes_idx = 0;
  for (; b58_bytes_idx < result_buf_size && !result_buf[b58_bytes_idx]; b58_bytes_idx++) {
    // nothing
  }
  // swap left as necessary
  size_t i = num_zeros;
  for (; b58_bytes_idx < result_buf_size; i++, b58_bytes_idx++) {
    result_buf[i] = result_buf[b58_bytes_idx];
  }

  *result_size = i;

  return MB_ERR_OK;
}

// these correlate to the mb_enc enum
static const mb_encoding codes[NUM_ENCODINGS] = {
    {
        .code = '\0',
        .name = "identity",
        .enc = MB_ENC_IDENTITY,
        .encode_size = &mb_identity_encode_size,
        .encode = &mb_identity_encode,
        .decode_size = &mb_identity_decode_size,
        .decode = &mb_identity_decode,
    },
    {
        .code = '0',
        .name = "base2",
        .enc = MB_ENC_BASE2,
        .encode_size = &mb_base2_encode_size,
        .encode = &mb_base2_encode,
        .decode_size = &mb_base2_decode_size,
        .decode = &mb_base2_decode,
    },
    {
        .code = '9',
        .name = "base10",
        .enc = MB_ENC_BASE10,
        .encode_size = &mb_base10_encode_size,
        .encode = &mb_base10_encode,
        .decode_size = &mb_base10_decode_size,
        .decode = &mb_base10_decode,
    },
    {
        .code = 'f',
        .name = "base16",
        .enc = MB_ENC_BASE16,
        .encode_size = &mb_base16_encode_size,
        .encode = &mb_base16_encode,
        .decode_size = &mb_base16_decode_size,
        .decode = &mb_base16_decode,
    },
    {
        .code = 'F',
        .name = "base16upper",
        .enc = MB_ENC_BASE16UPPER,
        .encode_size = &mb_base16_encode_size,
        .encode = &mb_base16upper_encode,
        .decode_size = &mb_base16_decode_size,
        .decode = &mb_base16upper_decode,
    },
    {
        .code = 'b',
        .name = "base32",
        .enc = MB_ENC_BASE32,
        .encode_size = &mb_base32_encode_size,
        .encode = &mb_base32_encode,
        .decode_size = &mb_base32_decode_size,
        .decode = &mb_base32_decode,
    },
    {
        .code = 'B',
        .name = "base32upper",
        .enc = MB_ENC_BASE32UPPER,
        .encode_size = &mb_base32_encode_size,
        .encode = &mb_base32upper_encode,
        .decode_size = &mb_base32_decode_size,
        .decode = &mb_base32upper_decode,
    },
    {
        .code = 'z',
        .name = "base58btc",
        .enc = MB_ENC_BASE58BTC,
        .encode_size = &mb_base58btc_encode_size,
        .encode = &mb_base58btc_encode,
        .decode_size = &mb_base58btc_decode_size,
        .decode = &mb_base58btc_decode,
    },
    {
        .code = 'm',
        .name = "base64",
        .enc = MB_ENC_BASE64,
        .encode_size = &mb_base64_encode_size,
        .encode = &mb_base64_encode,
        .decode_size = &mb_base64_decode_size,
        .decode = &mb_base64_decode,
    },
    {
        .code = 'u',
        .name = "base64url",
        .enc = MB_ENC_BASE64URL,
        .encode_size = &mb_base64_encode_size,
        .encode = &mb_base64url_encode,
        .decode_size = &mb_base64_decode_size,
        .decode = &mb_base64url_decode,
    },
};

size_t mb_encode_size(const uint8_t* const input, size_t input_size, mb_enc encoding) {
  if (input_size == 0) {
    return 1;
  }
  return codes[encoding].encode_size(input, input_size) + 1;
}

mb_err mb_encode(const uint8_t* const input, size_t input_size, mb_enc encoding, uint8_t* const result_buf, size_t result_buf_size,
                 size_t* result_size) {
  if (encoding > NUM_ENCODINGS - 1) {
    return MB_ERR_UNKNOWN_ENC;
  }
  // encoding always writes at least one byte for the multibase prefix
  if (result_buf_size < 1) {
    return MB_ERR_BUF_SIZE;
  }
  mb_encoding enc = codes[encoding];
  result_buf[0] = enc.code;
  if (input_size == 0 || input == NULL) {
    *result_size = 1;
    return MB_ERR_OK;
  }
  mb_err err = enc.encode(input, input_size, result_buf + 1, result_buf_size - 1, result_size);
  (*result_size)++;
  return err;
}

mb_err mb_encode_as(const uint8_t* input, size_t input_size, mb_enc encoding, uint8_t* result_buf, size_t result_buf_size,
                    size_t* result_size) {
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].enc == encoding) {
      return codes[i].encode(input, input_size, result_buf, result_buf_size, result_size);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

size_t mb_encode_as_size(const uint8_t* input, size_t input_size, mb_enc encoding) {
  if (input_size == 0) {
    return 0;
  }
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].enc == encoding) {
      return codes[i].encode_size(input, input_size);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

size_t mb_decode_size(const uint8_t* const input, size_t input_size) {
  if (input_size == 1) {
    return 0;
  }
  uint8_t prefix = input[0];
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].code == prefix) {
      return codes[i].decode_size(input + 1, input_size - 1);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

size_t mb_decode_as_size(const uint8_t* const input, size_t input_size, mb_enc encoding) {
  if (input_size == 0) {
    return 0;
  }
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].enc == encoding) {
      return codes[i].decode_size(input, input_size);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_decode_as(const uint8_t* input, size_t input_size, mb_enc encoding, uint8_t* result_buf, size_t result_buf_size,
                    size_t* result_size) {
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].enc == encoding) {
      if (input_size == 0) {
        return MB_ERR_OK;
      }
      return codes[i].decode(input, input_size, result_buf, result_buf_size, result_size);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_decode(const uint8_t* const input, size_t size, mb_enc* const encoding, uint8_t* const result_buf, size_t result_buf_size,
                 size_t* const result_size) {
  if (size < 1) {
    return MB_ERR_INVALID_INPUT;
  }
  uint8_t prefix = input[0];
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].code == prefix) {
      if (encoding != NULL) {
        *encoding = (mb_enc)i;
      }
      if (size == 1) {
        return MB_ERR_OK;
      }
      return codes[i].decode(input + 1, size - 1, result_buf, result_buf_size, result_size);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_enc_by_name(const char* const name, mb_enc* const enc) {
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (strcmp(codes[i].name, name) == 0) {
      *enc = (mb_enc)i;
      return MB_ERR_OK;
    }
    if (strlen(name) == 1 && (unsigned char)name[0] == codes[i].code) {
      *enc = (mb_enc)i;
      return MB_ERR_OK;
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_enc_name(mb_enc enc, const char** const name) {
  *name = codes[enc].name;

  return MB_ERR_OK;
}
