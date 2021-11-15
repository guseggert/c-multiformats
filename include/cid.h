#ifndef CID_H
#define CID_H

#include <stdint.h>
#include <stdlib.h>

typedef enum {
  CID_CODEC_RAW = 0x55,
  CID_CODEC_DAG_PROTOBUF = 0x70,
  CID_CODEC_DAG_CBOR = 0x71,
  CID_CODEC_LIBP2P_KEY = 0x72,
} cid_codec;

typedef enum {
  CID_ERR_OK = 0,
  CID_ERR_INVALID_INPUT,
  CID_ERR_UNSUPPORTED_VERSION,
  CID_ERR_MEMORY,
} cid_err;

static const char* const CID_ERR_STRS[] = {
    "no error",
    "invalid CID",
    "unsupported CID version",
    "unable to allocate memory",
};

/**
 * Reads the CID @version from @cid bytes of size @cid_len.
 */
cid_err cid_read_version(const uint8_t* cid, size_t cid_len, uint64_t* version);

/**
 * Reads the content type @content_type from @cid bytes of size @cid_len.
 */
cid_err cid_read_content_type(const uint8_t* cid, size_t cid_len, uint64_t* content_type);

/**
 * Reads the @multihash bytes and length @multihash_len from @cid bytes of size @cid_len.
 *
 * No heap memory is allocated, @multihash points to an element of @cid.
 */
cid_err cid_read_multihash(const uint8_t* cid, size_t cid_len, const uint8_t** multihash, size_t* multihash_len);

/**
 * Computes the length @len in bytes to convert the CID string @cid to CID bytes.
 *
 * Call this before cid_str_to_bytes() to compute the buffer size to allocate.
 */
cid_err cid_str_to_bytes_len(const char* cid, size_t* len);

/**
 * Returns an error if @cid of @cid_len bytes is an invalid CID, otherwise return @CID_ERR_OK;
 */
cid_err cid_validate(const uint8_t* cid, size_t cid_len);

/**
 * Returns an error if the null-terminated ASCII/UTF8-encoded CID string @cid is an
 * invalid CID, otherwise returns @CID_ERR_OK.
 */
cid_err cid_str_validate(const char* cid);

/**
 * Converts a null-terminated ASCII/UTF8-encoded CID string @cid to CID bytes,
 * writing @bytes_len bytes to buffer @buf of length @buf_len bytes.
 *
 * The @buf must be cleared before calling this.
 */
cid_err cid_str_to_bytes(const char* cid, uint8_t* buf, size_t buf_len, size_t* bytes_len);

#endif
