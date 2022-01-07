#ifndef VARINT_H
#define VARINT_H

#include <stdint.h>
#include <stdlib.h>

typedef enum {
  VARINT_ERR_OK = 0,
  VARINT_ERR_INVALID_INPUT,
  VARINT_ERR_INPUT_TOO_BIG,
  VARINT_ERR_BUF_SIZE,
} varint_err;

const char* varint_err_str(varint_err err);

/**
 * The maximum number of bytes to encode a uint64 as a varint.
 */
#define VARINT_UINT64_MAX_BYTES 10

/**
 * Converts the uint64 @n into a varint and stores @varint_size bytes in @varint.
 *
 * The @varint buffer must be long enough to hold the varint. Generally the buffer should be of size @VARINT_UINT64_MAX_BYTES.
 *
 * Both @varint and @varint_len are respectively set only if they are not NULL, otherwise they are ignored.
 * So you can e.g. pre-compute the length of a varint without the varint by passing NULL for @varint.
 */
varint_err uint64_to_varint(uint64_t n, uint8_t *varint, size_t *varint_size);

/**
 * Converts a varint at the front of @bytes to a uint64 @val.
 *
 * This can be used to read either an exact varint, or a varint prefix from a byte array. The size in bytes of the varint from @bytes will
 * be set to @varint_size, if @varint_size is not NULL.
 *
 * Returns an error if a valid uint64 varint cannot be read from @bytes within @bytes_len bytes.
 */
varint_err varint_to_uint64(const uint8_t *bytes, size_t bytes_size, uint64_t *val, size_t *varint_size);

#endif
