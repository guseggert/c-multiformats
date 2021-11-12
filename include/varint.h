#include <stdint.h>
#include <stdlib.h>

#ifndef VARINT_H
#define VARINT_H

typedef enum varint_err {
  VARINT_ERR_OK = 0,
  VARINT_ERR_INVALID_INPUT,
  VARINT_ERR_INPUT_TOO_BIG,
  VARINT_ERR_BUF_SIZE,
} varint_err_t;

static const char *const VARINT_ERR_STRS[] = {
    "no error",
    "invalid input",
    "input too big",
    "buffer size too small",
};

#define UINT64_MAX_BYTES 10

/**
 * Convert the uint64 @n into a varint and store @varint_len bytes in @varint.
 *
 * The @varint buffer must be long enough to hold the varint. Generally the buffer should be of size @UINT64_MAX_BYTES.
 */
varint_err_t uint64_to_varint(uint64_t n, uint8_t *varint, size_t *varint_len);

/**
 * Convert a varint at the front of @bytes to a uint64 @val. This can be used to read either an exact varint,
 * or a varint prefix from a byte array. The size in bytes of the varint from @bytes will be set to @varint_len,
 * if @varint_len is not NULL.
 *
 * An error is returned if a valid uint64 varint cannot be read from @bytes within @bytes_len bytes.
 */
varint_err_t varint_to_uint64(const uint8_t *bytes, size_t bytes_len, uint64_t *val, size_t *varint_len);

#endif
