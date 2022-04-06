#ifndef CID_H
#define CID_H

#include <multibase.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint64_t cid_codec;
#define CID_CODEC_RAW 0x55
#define CID_CODEC_DAG_PROTOBUF 0x70
#define CID_CODEC_DAG_CBOR 0x71
#define CID_CODEC_LIBP2P_KEY 0x72

typedef uint8_t cid_err;
#define CID_ERR_OK 0
#define CID_ERR_INVALID_INPUT 1
#define CID_ERR_UNSUPPORTED_VERSION 2
#define CID_ERR_MEMORY 3
#define CID_ERR_CIDV0_MH_FN 4
#define CID_ERR_INVALID_MULTIHASH 5
#define CID_ERR_INVALID_CODEC 6

const char* cid_err_str(cid_err err);

/**
 * Reads the CID @version from @cid bytes of size @cid_size.
 */
cid_err cid_read_version(const uint8_t* cid, size_t cid_size, uint64_t* version);

/**
 * Reads the content type @content_type from @cid bytes of size @cid_size.
 */
cid_err cid_read_content_type(const uint8_t* cid, size_t cid_size, uint64_t* content_type);

/**
 * Reads the @multihash bytes and size @multihash_size from @cid bytes of size @cid_size.
 *
 * @multihash points to an element of @cid.
 */
cid_err cid_read_multihash(const uint8_t* cid, size_t cid_size, const uint8_t** multihash, size_t* multihash_size);

/**
 * Constructs a CIDv0 @cid of @cid_size bytes from a @multihash of @multihash_size bytes.
 *
 * The multihash must be a sha2-256 digest, otherwise this will return an error.
 */
cid_err cid_v0(const uint8_t* multihash, size_t multihash_size, uint8_t* cid, size_t* cid_size);

/**
 * Constructs a CIDv1 @cid of @cid_size bytes from a @mutlihash of @multihash_size bytes and the given @codec.
 *
 * The multihash is assumed to be valid, if it is invalid then this may produce an invalid CID.
 */
cid_err cid_v1(const uint8_t* multihash, size_t multihash_size, cid_codec codec, uint8_t* cid, size_t* cid_size);

/**
 * Returns an error if byte-encoded @cid of @cid_size bytes is an invalid/unrecognized CID, otherwise return @CID_ERR_OK;
 *
 * To validate a CID string, first convert it to bytes using cid_str_to_bytes(), then call this function.
 */
cid_err cid_validate(const uint8_t* cid, size_t cid_size);

/**
 * Converts a null-terminated ASCII/UTF8-encoded CID string @cid to CID bytes,
 * writing @bytes_size bytes to buffer @buf of length @buf_size bytes.
 *
 * The @buf must be cleared before calling this.
 */
cid_err cid_str_to_bytes(const char* cid, uint8_t* buf, size_t buf_size, size_t* bytes_size);

/**
 * Convert a byte-encoded CID @cid of @cid_size bytes to a null-terminated string-encoded CID of @cid_str_size bytes.
 *
 * If a CIDv0 is passed, the encoding @enc is ignored since CIDv0 is always encoded with non-prefixed base58btc.
 */
cid_err cid_bytes_to_str(const uint8_t* cid, size_t cid_size, mb_enc enc, char* cid_str_buf, size_t cid_str_buf_size, size_t* cid_str_size);

#endif
