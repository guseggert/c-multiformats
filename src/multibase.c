#include "multibase.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char* name;
  mb_err (*encode)(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written);
  mb_err (*decode)(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written);
  size_t (*encode_len)(const uint8_t* const input, size_t input_len);
  size_t (*decode_len)(const uint8_t* const input, size_t input_len);
  mb_enc enc;
  unsigned char code;
} mb_encoding;

size_t mb_base2_encode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return input_len * 8;
}
mb_err mb_base2_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
  for (size_t i = 0; i < input_len; i++) {
    uint8_t b = input[i];
    for (char j = 7; j >= 0; j--) {
      size_t idx = i * 8 + j;
      result[idx] = '0' + ((b >> (7 - j)) & 1);
    }
  }
  *written = input_len * 8;
  return MB_ERR_OK;
}

size_t mb_base2_decode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return (input_len + 7) / 8;
}
mb_err mb_base2_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
  size_t res_idx = 0;
  for (size_t i = 0; i < input_len; i++) {
    unsigned char cur_res_bit_num = i % 8;
    uint8_t res_byte = input[i] - '0';
    if (res_byte > 1) {
      return MB_ERR_INVALID_INPUT;
    }
    result[res_idx] |= (res_byte << (7U - cur_res_bit_num));

    if (cur_res_bit_num == 7) {
      res_idx++;
    }
  }
  *written = (input_len + 7) / 8;
  return MB_ERR_OK;
}

size_t mb_identity_encode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return input_len;
}
mb_err mb_identity_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
  memcpy(result, input, input_len);
  *written = input_len;
  return MB_ERR_OK;
}

size_t mb_identity_decode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return input_len;
}
mb_err mb_identity_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
  return mb_identity_encode(input, input_len, result, result_len, written);
}

// derivation, given le=encoded len and ld=decoded len:
// le = (8 * ld + 5) / 6
// ld = ceil((6 * le - 5) / 8)
// ld = (6 * le + 2) / 8
// ld = (3 * le + 1) / 4
size_t mb_base64_decode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return ((3 * input_len) + 1) / 4;
}
mb_err mb_base64_decode_lookup(const char* lookup, const uint8_t* const input, size_t input_len, uint8_t* const result,
                               size_t* const written) {
  size_t res_idx = 0;
  uint16_t bit_accum = 0;
  uint8_t bit_accum_bits = 0;

  for (size_t input_idx = 0; input_idx < input_len; input_idx++) {
    // read an input byte into accumulator (only the bottom 6 bits)
    char ch = lookup[input[input_idx]];
    if (ch == -1) {
      return MB_ERR_INVALID_INPUT;
    }

    // stick the 6 bits onto the accumulator
    bit_accum <<= 6;
    bit_accum |= ch & 63;
    bit_accum_bits += 6;

    // if there's a byte in accumulator, add it to result
    if (bit_accum_bits >= 8) {
      uint8_t b = (bit_accum & (0xFF << (bit_accum_bits - 8))) >> (bit_accum_bits - 8);
      result[res_idx++] = b;
      bit_accum_bits -= 8;
    }
  }
  // there are three valid cases for bit_accum_bits here, 0, 2, and 4
  // a value of 6 indicates a non-integral number of octets, which is invalid base64
  if (bit_accum_bits == 6) {
    return MB_ERR_INVALID_INPUT;
  }
  *written = res_idx;
  return MB_ERR_OK;
}

// reference: https://datatracker.ietf.org/doc/html/rfc4648
size_t mb_base64_encode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return (input_len * 8 + 5) / 6;
}
mb_err mb_base64_encode_alphabet(const char* const alphabet, const uint8_t* const input, size_t input_len, uint8_t* const result,
                                 size_t* const written) {
  size_t res_idx = 0;
  uint16_t bit_accum = 0;
  uint8_t bit_accum_bits = 0;

  for (size_t input_idx = 0; input_idx < input_len; input_idx++) {
    // read off a byte from the input
    bit_accum <<= 8;
    bit_accum |= input[input_idx];
    bit_accum_bits += 8;

    while (bit_accum_bits >= 6) {
      // read off top 6 bits, leave the rest
      // 63=111111, and we want the top 6 bits
      uint8_t next_6_bits = (bit_accum & (63 << (bit_accum_bits - 6))) >> (bit_accum_bits - 6);
      // top bits are garbage at this point
      bit_accum_bits -= 6;
      result[res_idx++] = alphabet[next_6_bits];
    }
  }
  // if there's leftover stuff, stick it in the last byte
  // worst case here is bit_accum_bits=6
  // (bit_accum_bits=4, read last byte so bit_accum_bits=12, then read 6 bits off so bit_accum_bits=6)
  // so we know we only need to read at most 6 bits from the accum
  if (bit_accum_bits > 0) {
    // take whatever's left, pad it to the right with zeros if it's <6 bits
    uint8_t rest = (bit_accum & (UINT16_MAX >> (16 - bit_accum_bits))) << (6 - bit_accum_bits);
    result[res_idx++] = alphabet[rest];
  }
  *written = res_idx;

  return MB_ERR_OK;
}

size_t mb_base32_encode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return (input_len * 8 + 4) / 5;
}
mb_err mb_base32_encode_alphabet(const char* const alphabet, const uint8_t* const input, size_t input_len, uint8_t* const result,
                                 size_t* const written) {
  size_t res_idx = 0;
  uint16_t bit_accum = 0;
  uint8_t bit_accum_bits = 0;
  for (size_t input_idx = 0; input_idx < input_len; input_idx++) {
    bit_accum <<= 8;
    bit_accum |= input[input_idx];
    bit_accum_bits += 8;
    while (bit_accum_bits >= 5) {
      uint8_t next_5_bits = (bit_accum & (31 << (bit_accum_bits - 5))) >> (bit_accum_bits - 5);
      bit_accum_bits -= 5;
      result[res_idx++] = alphabet[next_5_bits];
    }
  }
  if (bit_accum_bits > 0) {
    uint8_t rest = (bit_accum & (UINT16_MAX >> (16 - bit_accum_bits))) << (5 - bit_accum_bits);
    result[res_idx++] = alphabet[rest];
  }
  *written = res_idx;
  return MB_ERR_OK;
}
mb_err mb_base32_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
  return mb_base32_encode_alphabet("abcdefghijklmnopqrstuvwxyz234567", input, input_len, result, written);
}
mb_err mb_base32upper_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len,
                             size_t* const written) {
  (void)result_len;
  return mb_base32_encode_alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", input, input_len, result, written);
}

// TODO(guseggert): generalize this so it can be used for base 2^n (base2, base4, base8, base16, base32, base64)
size_t mb_base32_decode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return (input_len * 5 + 3) / 8;
}
mb_err mb_base32_decode_lookup(const char* lookup, const uint8_t* const input, size_t input_len, uint8_t* const result,
                               size_t* const written) {
  size_t res_idx = 0;
  uint16_t bit_accum = 0;
  uint8_t bit_accum_bits = 0;

  for (size_t input_idx = 0; input_idx < input_len; input_idx++) {
    char ch = lookup[input[input_idx]];
    if (ch == -1) {
      return MB_ERR_INVALID_INPUT;
    }
    bit_accum <<= 5;
    bit_accum |= ch & 31;
    bit_accum_bits += 5;

    if (bit_accum_bits >= 8) {
      uint8_t b = (bit_accum & (0xFF << (bit_accum_bits - 8))) >> (bit_accum_bits - 8);
      result[res_idx++] = b;
      bit_accum_bits -= 8;
    }
  }
  if (bit_accum_bits == 6) {
    return MB_ERR_INVALID_INPUT;
  }
  *written = res_idx;
  return MB_ERR_OK;
}
mb_err mb_base32_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
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
  return mb_base32_decode_lookup(lookup, input, input_len, result, written);
}
mb_err mb_base32upper_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len,
                             size_t* const written) {
  (void)result_len;
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
  return mb_base32_decode_lookup(lookup, input, input_len, result, written);
}

mb_err mb_base64_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
  return mb_base64_encode_alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", input, input_len, result, written);
}
mb_err mb_base64_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
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
  return mb_base64_decode_lookup(lookup, input, input_len, result, written);
}

mb_err mb_base64url_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
  return mb_base64_encode_alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", input, input_len, result, written);
}
mb_err mb_base64url_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
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
  return mb_base64_decode_lookup(lookup, input, input_len, result, written);
}

size_t mb_base16_encode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return input_len * 2;
}
mb_err mb_base16_encode_alphabet(const char* const alphabet, const uint8_t* const input, size_t input_len, uint8_t* const result,
                                 size_t* const written) {
  for (size_t i = 0, j = 0; i < input_len; i++, j += 2) {
    uint8_t b = input[i];
    result[j] = alphabet[(b >> 4) & 0xf];
    result[j + 1] = alphabet[b & 0xf];
  }
  *written = input_len * 2;
  return MB_ERR_OK;
}
mb_err mb_base16_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
  return mb_base16_encode_alphabet("0123456789abcdef", input, input_len, result, written);
}
mb_err mb_base16upper_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len,
                             size_t* const written) {
  (void)result_len;
  return mb_base16_encode_alphabet("0123456789ABCDEF", input, input_len, result, written);
}

size_t mb_base16_decode_len(const uint8_t* const input, size_t input_len) {
  (void)input;
  return input_len / 2;
}
mb_err mb_base16_decode_lookup(const char* const lookup, const uint8_t* const input, size_t input_len, uint8_t* const result,
                               size_t* const written) {
  if (input_len % 2 != 0) {
    return MB_ERR_INVALID_INPUT;
  }
  for (size_t i = 0, j = 0; i < input_len; i += 2, j++) {
    result[j] |= lookup[input[i]] << 4;
    result[j] |= lookup[input[i + 1]];
  }
  *written = input_len / 2;
  return MB_ERR_OK;
}
mb_err mb_base16_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  (void)result_len;
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
  return mb_base16_decode_lookup(lookup, input, input_len, result, written);
}
mb_err mb_base16upper_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len,
                             size_t* const written) {
  (void)result_len;
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
  return mb_base16_decode_lookup(lookup, input, input_len, result, written);
}

size_t mb_base58btc_encode_len(const uint8_t* const input, size_t input_len) {
  // this is approximate, sometimes it can be overshoot by 1 byte
  size_t zeros = 0;
  while (zeros < input_len && !input[zeros]) {
    zeros++;
  }
  return ((input_len - zeros) * 138 / 100 + 1) + zeros;
}

// reference: https://tools.ietf.org/id/draft-msporny-base58-01.html
mb_err mb_base58btc_encode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
  if (input_len == 0) {
    return MB_ERR_OK;
  }

  const char* alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  size_t num_zeros = 0;

  while (num_zeros < input_len && input[num_zeros] == 0) {
    result[num_zeros] = '1';
    num_zeros++;
  }

  size_t high = result_len;
  int carry = 0;
  size_t j = 0;
  for (size_t i = num_zeros; i < input_len; i++, high = j) {
    carry = input[i];
    for (j = result_len - 1; (j > high) || carry; j--) {
      carry += 256 * result[j];
      result[j] = carry % 58;
      carry /= 58;
      if (!j) {
        break;
      }
    }
  }

  // there could be extra zeros to the left of the result, so swap left if necessary

  // find the start of the non-zero section
  size_t b58_bytes_idx = num_zeros;
  for (; b58_bytes_idx < result_len && !result[b58_bytes_idx]; b58_bytes_idx++) {
    // nothing
  }

  // then swap everything left as necessary
  size_t unused = b58_bytes_idx - num_zeros;
  size_t i = b58_bytes_idx;
  for (; i < result_len; i++) {
    result[i - unused] = alphabet[result[i]];
  }
  *written = i - unused;
  return MB_ERR_OK;
}

size_t mb_base58btc_decode_len(const uint8_t* const input, size_t input_len) {
  // this is approximate, sometimes it can overshoot by 1 byte
  size_t zeros = 0;
  while (zeros < input_len && input[zeros] == '1') {
    zeros++;
  }
  return ((input_len - zeros) * 733 / 1000 + 1) + zeros;
}

mb_err mb_base58btc_decode(const uint8_t* const input, size_t input_len, uint8_t* const result, size_t result_len, size_t* const written) {
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
  if (input_len == 0) {
    return MB_ERR_OK;
  }

  size_t num_zeros = 0;

  while (num_zeros < input_len && input[num_zeros] == '1') {
    num_zeros++;
  }

  size_t high = result_len;
  int carry = 0;
  size_t j = 0;
  for (size_t i = num_zeros; i < input_len; i++, high = j) {
    carry = lookup[input[i]];  // NOLINT
    if (carry == -1) {
      return MB_ERR_INVALID_INPUT;
    }
    for (j = result_len - 1; (j > high) || carry; j--) {
      carry += 58 * result[j];
      result[j] = carry % 256;
      carry /= 256;
      if (!j) {
        break;
      }
    }
  }

  // write zeros
  if (num_zeros > 0) {
    memset(result, 0, num_zeros);
  }

  // find the first non-zero byte of the buf
  size_t b58_bytes_idx = 0;
  for (; b58_bytes_idx < result_len && !result[b58_bytes_idx]; b58_bytes_idx++) {
    // nothing
  }
  // swap left as necessary
  size_t i = num_zeros;
  for (; b58_bytes_idx < result_len; i++, b58_bytes_idx++) {
    result[i] = result[b58_bytes_idx];
  }

  *written = i;

  return MB_ERR_OK;
}

// these correlate to the mb_enc enum
const mb_encoding codes[NUM_ENCODINGS] = {
    {
        .code = '\x00',
        .name = "identity",
        .enc = MB_ENC_IDENTITY,
        .encode_len = &mb_identity_encode_len,
        .encode = &mb_identity_encode,
        .decode_len = &mb_identity_decode_len,
        .decode = &mb_identity_decode,
    },
    {
        .code = '0',
        .name = "base2",
        .enc = MB_ENC_BASE2,
        .encode_len = &mb_base2_encode_len,
        .encode = &mb_base2_encode,
        .decode_len = &mb_base2_decode_len,
        .decode = &mb_base2_decode,
    },
    {
        .code = 'f',
        .name = "base16",
        .enc = MB_ENC_BASE16,
        .encode_len = &mb_base16_encode_len,
        .encode = &mb_base16_encode,
        .decode_len = &mb_base16_decode_len,
        .decode = &mb_base16_decode,
    },
    {
        .code = 'F',
        .name = "base16upper",
        .enc = MB_ENC_BASE16UPPER,
        .encode_len = &mb_base16_encode_len,
        .encode = &mb_base16upper_encode,
        .decode_len = &mb_base16_decode_len,
        .decode = &mb_base16upper_decode,
    },
    {
        .code = 'b',
        .name = "base32",
        .enc = MB_ENC_BASE32,
        .encode_len = &mb_base32_encode_len,
        .encode = &mb_base32_encode,
        .decode_len = &mb_base32_decode_len,
        .decode = &mb_base32_decode,
    },
    {
        .code = 'B',
        .name = "base32upper",
        .enc = MB_ENC_BASE32UPPER,
        .encode_len = &mb_base32_encode_len,
        .encode = &mb_base32upper_encode,
        .decode_len = &mb_base32_decode_len,
        .decode = &mb_base32upper_decode,
    },
    {
        .code = 'z',
        .name = "base58btc",
        .enc = MB_ENC_BASE58BTC,
        .encode_len = &mb_base58btc_encode_len,
        .encode = &mb_base58btc_encode,
        .decode_len = &mb_base58btc_decode_len,
        .decode = &mb_base58btc_decode,
    },
    {
        .code = 'm',
        .name = "base64",
        .enc = MB_ENC_BASE64,
        .encode_len = &mb_base64_encode_len,
        .encode = &mb_base64_encode,
        .decode_len = &mb_base64_decode_len,
        .decode = &mb_base64_decode,
    },
    {
        .code = 'u',
        .name = "base64url",
        .enc = MB_ENC_BASE64URL,
        .encode_len = &mb_base64_encode_len,
        .encode = &mb_base64url_encode,
        .decode_len = &mb_base64_decode_len,
        .decode = &mb_base64url_decode,
    },
};

size_t mb_encode_len(const uint8_t* const input, size_t input_len, mb_enc encoding) {
  if (input_len == 0) {
    return 1;
  }
  return codes[encoding].encode_len(input, input_len) + 1;
}

mb_err mb_encode(const uint8_t* const input, size_t input_len, mb_enc encoding, uint8_t* const result_buf, size_t result_buf_len,
                 size_t* written) {
  if (encoding > NUM_ENCODINGS - 1) {
    return MB_ERR_UNKNOWN_ENC;
  }
  // encoding always writes at least one byte for the multibase prefix
  if (result_buf_len < 1) {
    return MB_ERR_BUF_SIZE;
  }
  mb_encoding enc = codes[encoding];
  result_buf[0] = enc.code;
  if (input_len == 0 || input == NULL) {
    *written = 1;
    return MB_ERR_OK;
  }
  mb_err err = enc.encode(input, input_len, result_buf + 1, result_buf_len - 1, written);
  (*written)++;
  return err;
}

size_t mb_decode_len(const uint8_t* const input, size_t input_len) {
  if (input_len == 1) {
    return 0;
  }
  uint8_t prefix = input[0];
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].code == prefix) {
      return codes[i].decode_len(input + 1, input_len - 1);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_decode_as_len(const uint8_t* const input, size_t input_len, mb_enc encoding) {
  if (input_len == 0) {
    return 0;
  }
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].enc == encoding) {
      return codes[i].decode_len(input, input_len);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_decode_as(const uint8_t* input, size_t input_len, mb_enc encoding, uint8_t* result_buf, size_t result_buf_len, size_t* written) {
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].enc == encoding) {
      if (input_len == 0) {
        return MB_ERR_OK;
      }
      return codes[i].decode(input, input_len, result_buf, result_buf_len, written);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_decode(const uint8_t* const input, size_t len, mb_enc* const encoding, uint8_t* const result_buf, size_t result_buf_len,
                 size_t* const written) {
  if (len < 1) {
    return MB_ERR_INVALID_INPUT;
  }
  uint8_t prefix = input[0];
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (codes[i].code == prefix) {
      if (encoding != NULL) {
        *encoding = i;
      }
      if (len == 1) {
        return MB_ERR_OK;
      }
      return codes[i].decode(input + 1, len - 1, result_buf, result_buf_len, written);
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_enc_by_name(const char* const name, mb_enc* const enc) {
  for (size_t i = 0; i < NUM_ENCODINGS; i++) {
    if (strcmp(codes[i].name, name) == 0) {
      *enc = i;
      return MB_ERR_OK;
    }
    if (strlen(name) == 1 && (unsigned char)name[0] == codes[i].code) {
      *enc = i;
      return MB_ERR_OK;
    }
  }
  return MB_ERR_UNKNOWN_ENC;
}

mb_err mb_enc_name(mb_enc enc, const char** const name) {
  *name = codes[enc].name;

  return MB_ERR_OK;
}

// converts a multibase-encoded input string into a different multibase encoding
int main(int argc, char* argv[]) {
  int exit_code = EXIT_SUCCESS;

  if (argc != 3) {
    exit_code = 1;
    printf("Usage: %s [new_encoding] [encoded_data]\n", argv[0]);
    goto exit;
  }

  char* enc_str = argv[1];
  char* input = argv[2];

  mb_enc enc = 0;
  mb_err err = mb_enc_by_name(enc_str, &enc);
  if (err) {
    printf("getting encoding '%s': %s\n", enc_str, MB_ERR_STRS[err]);
    exit_code = 1;
    goto exit;
  }

  // decode the input
  size_t str_len = strlen(input);
  size_t dec_len = mb_decode_len((uint8_t*)input, str_len);
  if (dec_len == 0) {
    printf("\n");
    return 0;
  }
  uint8_t* dec_buf = calloc(dec_len, sizeof(uint8_t));
  mb_enc dec_enc = 0;
  size_t dec_bytes = 0;
  mb_err dec_err = mb_decode((uint8_t*)input, str_len, &dec_enc, dec_buf, dec_len, &dec_bytes);
  if (dec_err) {
    printf("decoding: %s\n", MB_ERR_STRS[dec_err]);
    exit_code = 1;
    goto free_dec_buf;
  }

  // re-encode
  size_t enc_len = mb_encode_len(dec_buf, dec_len, enc);
  uint8_t* enc_buf = calloc(enc_len, sizeof(uint8_t));
  size_t enc_bytes = 0;
  mb_err enc_err = mb_encode(dec_buf, dec_len, enc, enc_buf, enc_len, &enc_bytes);
  if (enc_err) {
    printf("encoding: %s\n", MB_ERR_STRS[enc_err]);
    exit_code = 1;
    goto free_enc_buf;
  }

  // print
  for (size_t i = 0; i < enc_len; i++) {
    printf("%c", enc_buf[i]);
  }
  printf("\n");

free_enc_buf:
  free(enc_buf);
free_dec_buf:
  free(dec_buf);
exit:
  return exit_code;
}
