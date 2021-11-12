#ifndef CID_H
#define CID_H

#include <stdint.h>
#include <stdlib.h>

#include "multihash.h"

typedef struct {
  uint64_t version;
  uint64_t content_type;
  mh_t* multihash;
} cid_t;

typedef enum cid_err {
  CID_ERR_OK = 0,
  CID_ERR_INVALID_INPUT,
  CID_UNSUPPORTED_VERSION,
  CID_ERR_MEMORY,
} cid_err_t;

static const char* const CID_ERR_STRS[] = {
    "no error",
    "invalid input",
    "unsupported CID version",
    "unable to allocate memory",
};

/**
 * Parse a byte-encoded CID @bytes of length @bytes_len into @cid.
 */
cid_err_t cid_decode_bytes(const uint8_t* bytes, size_t bytes_len, cid_t** cid);

/**
 * Parse an ASCII/UTF8-encoded CID @str into @cid. The raw decoded CID bytes
 * will be set to @cid_bytes, if it is not null. If @cid_bytes are set, then
 * the memory must freed by the caller.
 *
 * @str must be a proper C string with a null terminator.
 */
cid_err_t cid_decode_str(const char* str, cid_t** cid);

void cid_free(cid_t* cid);

#endif
