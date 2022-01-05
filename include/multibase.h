#ifndef MULTIBASE_H
#define MULTIBASE_H

#include <stdint.h>
#include <stdio.h>

typedef enum {
  MB_ERR_OK = 0,
  MB_ERR_UNKNOWN_ENC,
  MB_ERR_INVALID_INPUT,
  MB_ERR_BUF_SIZE,
} mb_err;

// TODO(guseggert): hide this stuff behind a function to get the error msg (makes it easier for language bindings)
static const char* const MB_ERR_STRS[] = {
    "no error",
    "unknown multibase encoding",
    "invalid multibase",
    "multibase buffer size too small",
};

#define NUM_ENCODINGS 10
typedef enum {
  MB_ENC_IDENTITY = 0,
  MB_ENC_BASE2,
  MB_ENC_BASE10,
  MB_ENC_BASE16,
  MB_ENC_BASE16UPPER,
  MB_ENC_BASE32,
  MB_ENC_BASE32UPPER,
  MB_ENC_BASE58BTC,
  MB_ENC_BASE64,
  MB_ENC_BASE64URL,
} mb_enc;

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
 * Returns the recommended buffer size for encoding @input, so that the caller can allocate memory for encoding.
 *
 * This guarantees to return a size >= the actual encoded size. I.e. in some cases the encoded representation may be
 * smaller than the value computed by this function.
 */
size_t mb_encode_size(const uint8_t* input, size_t input_size, mb_enc encoding);

/**
 * Directly encodes @input_size bytes of @input into @result_buf without a multibase prefix, encoded as @encoding.
 *
 * @result_buf must be cleared before calling this.
 */
mb_err mb_encode_as(const uint8_t* input, size_t input_size, mb_enc encoding, uint8_t* result_buf, size_t result_buf_size,
                    size_t* result_size);

size_t mb_encode_as_size(const uint8_t* input, size_t input_size, mb_enc encoding);

/**
 * Decodes @input_size bytes of @input, stored in @result_buf. See mb_encode().
 *
 * @result_buf must be cleared before calling this.
 */
mb_err mb_decode(const uint8_t* input, size_t input_size, mb_enc* encoding, uint8_t* result_buf, size_t result_buf_size,
                 size_t* result_size);

/**
 * Returns the recommended buffer size for decoding @input, so that the caller can allocate memory for decoding.
 *
 * @see mb_encode_len()
 */
size_t mb_decode_size(const uint8_t* input, size_t input_size);

/**
 * Decodes @input_size bytes of @input into @result_buf, assuming it is encoded as @encoding without the multibase prefix.
 *
 * @result_buf must be cleared before calling this.
 */
mb_err mb_decode_as(const uint8_t* input, size_t input_size, mb_enc encoding, uint8_t* result_buf, size_t result_buf_size,
                    size_t* result_size);

size_t mb_decode_as_size(const uint8_t* input, size_t input_size, mb_enc encoding);

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
