#ifndef MULTIBASE_H
#define MULTIBASE_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

typedef enum mb_err {
  MB_ERR_OK = 0,
  MB_ERR_UNKNOWN_ENC,
  MB_ERR_INVALID_INPUT,
  MB_ERR_BUF_SIZE,
} mb_err_t;

static const char* const MB_ERR_STRS[] = {
    "no error",
    "unknown encoding",
    "invalid input",
    "buffer size too small",
};

#define NUM_ENCODINGS 9
typedef enum mb_enc {
  MB_ENC_IDENTITY = 0,
  MB_ENC_BASE2,
  MB_ENC_BASE16,
  MB_ENC_BASE16UPPER,
  MB_ENC_BASE32,
  MB_ENC_BASE32UPPER,
  MB_ENC_BASE58BTC,
  MB_ENC_BASE64,
  MB_ENC_BASE64URL,
} mb_enc_t;

/**
 * Encode @input_len bytes of @input into a multibase string using @encoding, stored in @result_buf.
 *
 * This always writes at least one byte into @result_buf.
 *
 * The number of bytes written are set in @written.
 *
 * @written is not necessarily the same as @result_buf_len, because in certain base encodings we
 * can't accurately know the result size a priori.
 */
mb_err_t mb_encode(const uint8_t* input, size_t input_len, mb_enc_t encoding, uint8_t* result_buf, size_t result_buf_len, size_t* written);

/**
 * Returns the recommended buffer size for encoding @input, so that the caller can allocate memory for encoding.
 *
 * This guarantees to return a size >= the actual encoded size. I.e. in some cases the encoded representation may be
 * smaller than the value computed by this function.
 */
size_t mb_encode_len(const uint8_t* input, size_t input_len, mb_enc_t encoding);

/**
 * Decode @input_len bytes of @input, stored in @result_buf. See mb_encode().
 *
 * @result_buf must be cleared before calling this.
 */
mb_err_t mb_decode(const uint8_t* input, size_t input_len, mb_enc_t* encoding, uint8_t* result_buf, size_t result_buf_len, size_t* written);


mb_err_t mb_decode_as_len(const uint8_t* input, size_t input_len, mb_enc_t encoding);

/**
 * Decode @input_len bytes of @input into @result_buf, assuming it is encoded as @encoding.
 *
 * The @input bytes generally shouldn't contain the multibase prefix when using this.
 *
 * @result_buf must be cleared before calling this.
 */
mb_err_t mb_decode_as(const uint8_t* input, size_t input_len, mb_enc_t encoding, uint8_t* result_buf, size_t result_buf_len,
                      size_t* written);

/**
 * Returns the recommended buffer size for decoding @input, so that the caller can allocate memory for decoding.
 *
 * @see mb_encode_len()
 */
size_t mb_decode_len(const uint8_t* input, size_t input_len);

/**
 * Sets @enc to the encoding matching @name.
 *
 * The @name can be either the prefix such as 'z' or the full name such as 'base58btc'.
 *
 * Returns an error if an encoding matching @name can't be found.
 */
mb_err_t mb_enc_by_name(const char* name, mb_enc_t* enc);

/**
 * Sets @name to the name of the given encoding.
 */
mb_err_t mb_enc_name(mb_enc_t enc, const char** name);

#endif
