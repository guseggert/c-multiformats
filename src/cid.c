#include "cid.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"
#include "multihash.h"
#include "varint.h"

static cid_err cid_read_version_varint(const uint8_t* const bytes, size_t bytes_size, uint64_t* const version_varint, size_t* bytes_read) {
  if (bytes_size == 34 && bytes[0] == 0x12 && bytes[1] == 0x20) {
    // cidv0
    if (version_varint != NULL) {
      *version_varint = 0;
    }
    if (bytes_read != NULL) {
      *bytes_read = 0;
    }
    return CID_ERR_OK;
  }
  varint_err varint_err = varint_to_uint64(bytes, bytes_size, version_varint, bytes_read);
  if (varint_err) {
    return CID_ERR_INVALID_INPUT;
  }
  return CID_ERR_OK;
}

cid_err cid_read_version(const uint8_t* const cid, size_t cid_size, uint64_t* const version) {
  return cid_read_version_varint(cid, cid_size, version, NULL);
}

static cid_err cid_read_content_type_varint(const uint8_t* const bytes, size_t bytes_size, uint64_t version, uint64_t* content_type,
                                            size_t* bytes_read) {
  if (version == 0) {
    if (content_type != NULL) {
      *content_type = CID_CODEC_DAG_PROTOBUF;
    }
    if (bytes_read != NULL) {
      *bytes_read = 0;
    }
    return CID_ERR_OK;
  }
  if (version == 1) {
    uint64_t multicodec_varint = 0;
    size_t multicodec_varint_size = 0;
    varint_err varint_err = varint_to_uint64(bytes, bytes_size, &multicodec_varint, &multicodec_varint_size);
    if (varint_err) {
      return CID_ERR_INVALID_INPUT;
    }
    if (content_type != NULL) {
      *content_type = multicodec_varint;
    }
    if (bytes_read != NULL) {
      *bytes_read = multicodec_varint_size;
    }
    return CID_ERR_OK;
  }
  return CID_ERR_UNSUPPORTED_VERSION;
}

cid_err cid_read_content_type(const uint8_t* const cid, size_t cid_size, uint64_t* content_type) {
  size_t bytes_read = 0;
  uint64_t version = 0;
  cid_err err = cid_read_version_varint(cid, cid_size, &version, &bytes_read);
  if (err) {
    return err;
  }
  return cid_read_content_type_varint(cid + bytes_read, cid_size - bytes_read, version, content_type, NULL);
}

cid_err cid_read_multihash(const uint8_t* cid, size_t cid_size, const uint8_t** multihash, size_t* multihash_size) {
  size_t bytes_read = 0;
  uint64_t version = 0;
  cid_err err = cid_read_version_varint(cid, cid_size, &version, &bytes_read);
  if (err) {
    return err;
  }
  if (version == 0) {
    if (multihash != NULL) {
      *multihash = cid;
    }
    if (multihash_size != NULL) {
      *multihash_size = cid_size;
    }
    return CID_ERR_OK;
  }
  if (version == 1) {
    size_t b = 0;
    err = cid_read_content_type_varint(cid + bytes_read, cid_size - bytes_read, version, NULL, &b);
    if (err) {
      return err;
    }
    bytes_read += b;

    if (multihash != NULL) {
      *multihash = cid + bytes_read;
    }
    if (multihash_size != NULL) {
      *multihash_size = cid_size - bytes_read;
    }
    return CID_ERR_OK;
  }
  if (version == 2 || version == 3) {
    return CID_ERR_UNSUPPORTED_VERSION;
  }
  return CID_ERR_INVALID_INPUT;
}

/**
 * Returns the number of code points in a UTF-8 encoded string.
 * For ASCII strings, this just returns the number of characters.
 */
static size_t utf8_len(const uint8_t* const bytes, size_t len) {
  size_t codepoints = 0;
  for (size_t i = 0; i < len; i++) {
    codepoints += (bytes[i] & 0xc0) != 0x80;  // count non-continuation bytes
  }
  return codepoints;
}

cid_err cid_str_to_bytes_size(const char* cid, size_t* size) {
  unsigned long num_bytes = strlen(cid);
  uint8_t* str_bytes = (uint8_t*)cid;
  size_t str_len = utf8_len(str_bytes, num_bytes);
  if (str_len == 46 && cid[0] == 'Q' && cid[1] == 'm') {
    *size = mb_decode_as_size(str_bytes, num_bytes, MB_ENC_BASE58BTC);
    return CID_ERR_OK;
  }
  *size = mb_decode_size(str_bytes, num_bytes);
  return CID_ERR_OK;
}

cid_err cid_str_to_bytes(const char* const cid, uint8_t* const buf, size_t buf_size, size_t* const bytes_size) {
  unsigned long num_bytes = strlen(cid);
  uint8_t* str_bytes = (uint8_t*)cid;
  size_t str_len = utf8_len(str_bytes, num_bytes);
  if (str_len == 46 && cid[0] == 'Q' && cid[1] == 'm') {
    size_t dec_bytes = 0;
    mb_err dec_err = mb_decode_as(str_bytes, num_bytes, MB_ENC_BASE58BTC, buf, buf_size, &dec_bytes);
    if (dec_err) {
      return CID_ERR_INVALID_INPUT;
    }
    *bytes_size = dec_bytes;
    return CID_ERR_OK;
  }
  size_t dec_bytes = 0;
  mb_err dec_err = mb_decode(str_bytes, num_bytes, NULL, buf, buf_size, &dec_bytes);
  if (dec_err) {
    return CID_ERR_INVALID_INPUT;
  }
  if (dec_bytes > 0 && buf[0] == 0x12) {
    return CID_ERR_INVALID_INPUT;
  }
  *bytes_size = dec_bytes;
  return CID_ERR_OK;
}

cid_err cid_validate(const uint8_t* const cid, size_t cid_size) { return cid_read_multihash(cid, cid_size, NULL, NULL); }

cid_err cid_str_validate(const char* const cid) {
  size_t size = 0;
  cid_err err = cid_str_to_bytes_size(cid, &size);
  if (err) {
    return err;
  }
  // TODO(guseggert) remove this calloc
  uint8_t* buf = calloc(size, sizeof(uint8_t));
  if (buf == NULL) {
    return CID_ERR_MEMORY;
  }
  size_t buf_bytes = 0;
  err = cid_str_to_bytes(cid, buf, size, &buf_bytes);
  if (err) {
    free(buf);
    return err;
  }
  err = cid_validate(buf, buf_bytes);
  free(buf);
  return err;
}
