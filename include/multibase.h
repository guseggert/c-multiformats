#ifndef MULTIBASE_H
#define MULTIBASE_H

#include <stdint.h>
#include <stdio.h>

typedef uint8_t mb_err;
#define MB_ERR_OK 0
#define MB_ERR_UNKNOWN_ENC 1
#define MB_ERR_INVALID_INPUT 2
#define MB_ERR_BUF_SIZE 3

const char* mb_err_str(mb_err err);

#define MB_NUM_ENCODINGS 10
typedef uint8_t mb_enc;
#define MB_ENC_IDENTITY 0
#define MB_ENC_BASE2 1
#define MB_ENC_BASE10 2
#define MB_ENC_BASE16 3
#define MB_ENC_BASE16UPPER 4
#define MB_ENC_BASE32 5
#define MB_ENC_BASE32UPPER 6
#define MB_ENC_BASE58BTC 7
#define MB_ENC_BASE64 8
#define MB_ENC_BASE64URL 9

/**
 * Encodes @input_size bytes of @input into a multibase string using @encoding, stored in @result_buf.
 *
 * This always writes at least one byte into @result_buf.
 *
 * The number of bytes written are set in @result_size.
 *
 * @result_size is not necessarily the same as @result_buf_size, because in certain base encodings we
 * can't precisely know the result size a priori.
 */
mb_err mb_encode(const uint8_t* input, size_t input_size, mb_enc encoding, uint8_t* result_buf, size_t result_buf_size,
                 size_t* result_size);

/**
 * Directly encodes @input_size bytes of @input into @result_buf without a multibase prefix, encoded as @encoding.
 *
 * @result_buf must be cleared before calling this.
 */
mb_err mb_encode_as(const uint8_t* input, size_t input_size, mb_enc encoding, uint8_t* result_buf, size_t result_buf_size,
                    size_t* result_size);

/**
 * Decodes @input_size bytes of @input, stored in @result_buf. See mb_encode().
 *
 * @result_buf must be cleared before calling this.
 */
mb_err mb_decode(const uint8_t* input, size_t input_size, mb_enc* encoding, uint8_t* result_buf, size_t result_buf_size,
                 size_t* result_size);

/**
 * Decodes @input_size bytes of @input into @result_buf, assuming it is encoded as @encoding without the multibase prefix.
 *
 * @result_buf must be cleared before calling this.
 */
mb_err mb_decode_as(const uint8_t* input, size_t input_size, mb_enc encoding, uint8_t* result_buf, size_t result_buf_size,
                    size_t* result_size);

/**
 * Sets @enc to the encoding matching @name.
 *
 * The @name can be either the prefix such as 'z' or the full name such as 'base58btc'.
 *
 * Returns an error if an encoding matching @name can't be found.
 */
mb_err mb_enc_by_name(const char* name, mb_enc* enc);

/**
 * Sets @name to the name of the given encoding.
 */
mb_err mb_enc_name(mb_enc enc, const char** name);

#endif
