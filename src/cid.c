#include "cid.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"
#include "multihash.h"
#include "varint.h"

const char* cid_err_str(cid_err err) {
  switch (err) {
    case CID_ERR_OK:
      return "no error";
    case CID_ERR_INVALID_INPUT:
      return "invalid CID";
    case CID_ERR_UNSUPPORTED_VERSION:
      return "unsupported CID version";
    case CID_ERR_MEMORY:
      return "unable to allocate memory";
    case CID_ERR_CIDV0_MH_FN:
      return "cidv0 multihash must be sha2-256";
    case CID_ERR_INVALID_MULTIHASH:
      return "invalid multihash";
    default:
      return "unknown error";
  }
}

static cid_err cid_read_version_varint(const uint8_t* const bytes, size_t bytes_size, uint64_t* const version_varint, size_t* bytes_read) {
  if (bytes_size == 34 && bytes[0] == 0x12 && bytes[1] == 0x20) {
    // cidv0
    if (version_varint) {
      *version_varint = 0;
    }
    if (bytes_read) {
      *bytes_read = 0;
    }
    return CID_ERR_OK;
  }
  varint_err verr = varint_to_uint64(bytes, bytes_size, version_varint, bytes_read);
  if (verr) {
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
    if (content_type) {
      *content_type = CID_CODEC_DAG_PROTOBUF;
    }
    if (bytes_read) {
      *bytes_read = 0;
    }
    return CID_ERR_OK;
  }
  if (version == 1) {
    uint64_t multicodec_varint = 0;
    size_t multicodec_varint_size = 0;
    varint_err verr = varint_to_uint64(bytes, bytes_size, &multicodec_varint, &multicodec_varint_size);
    if (verr) {
      return CID_ERR_INVALID_INPUT;
    }
    if (content_type) {
      *content_type = multicodec_varint;
    }
    if (bytes_read) {
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
    if (multihash) {
      *multihash = cid;
    }
    if (multihash_size) {
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

    if (multihash) {
      *multihash = cid + bytes_read;
    }
    if (multihash_size) {
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

cid_err cid_str_to_bytes(const char* const cid, uint8_t* const cid_bytes_buf, size_t cid_bytes_buf_size, size_t* const cid_bytes_size) {
  unsigned long num_bytes = strlen(cid);
  uint8_t* str_bytes = (uint8_t*)cid;
  size_t str_len = utf8_len(str_bytes, num_bytes);

  // cidv0
  if (str_len == 46 && cid[0] == 'Q' && cid[1] == 'm') {
    mb_err dec_err = mb_decode_as(str_bytes, num_bytes, MB_ENC_BASE58BTC, cid_bytes_buf, cid_bytes_buf_size, cid_bytes_size);
    if (dec_err) {
      return CID_ERR_INVALID_INPUT;
    }
    return CID_ERR_OK;
  }

  // cidv1
  mb_err dec_err = mb_decode(str_bytes, num_bytes, NULL, cid_bytes_buf, cid_bytes_buf_size, cid_bytes_size);
  if (dec_err) {
    return CID_ERR_INVALID_INPUT;
  }
  if (*cid_bytes_size > 0 && cid_bytes_buf && cid_bytes_buf[0] == 0x12) {
    return CID_ERR_INVALID_INPUT;
  }
  return CID_ERR_OK;
}

cid_err cid_validate(const uint8_t* const cid, size_t cid_size) {
  size_t mh_size = 0;
  cid_err err = cid_read_multihash(cid, cid_size, NULL, &mh_size);
  if (err) {
    return err;
  }
  uint64_t version = 0;
  err = cid_read_version(cid, cid_size, &version);
  if (err) {
    return err;
  }

  // if cidv0, check for a valid sha2-256 multihash
  if (version == 0) {
    size_t digest_size = 0;
    mh_err mherr = mh_read_digest(cid, mh_size, &digest_size, NULL);
    if (mherr) {
      return CID_ERR_INVALID_MULTIHASH;
    }
    if (digest_size != 32) {
      return CID_ERR_CIDV0_MH_FN;
    }
    mh_fn_code fn_code = 0;
    mherr = mh_read_fn_code(cid, cid_size, &fn_code);
    if (mherr) {
      return CID_ERR_INVALID_MULTIHASH;
    }
    if (fn_code != MH_FN_CODE_SHA2_256) {
      return CID_ERR_INVALID_INPUT;
    }
    return CID_ERR_OK;
  }

  // if cidv1, just check that we can read the mutlihash fn code
  // deeper multihash validation should be carried out separately
  if (version == 1) {
    const uint8_t* multihash = NULL;
    size_t multihash_size = 0;
    err = cid_read_multihash(cid, cid_size, &multihash, &multihash_size);
    if (err) {
      return err;
    }
    mh_err mherr = mh_read_fn_code(multihash, multihash_size, NULL);
    if (mherr) {
      return CID_ERR_INVALID_MULTIHASH;
    }
    return CID_ERR_OK;
  }

  return CID_ERR_UNSUPPORTED_VERSION;
}

cid_err cid_v0(const uint8_t* multihash, size_t multihash_size, uint8_t* cid, size_t* cid_size) {
  if (multihash_size != 32) {
    return CID_ERR_INVALID_MULTIHASH;
  }
  mh_fn_code fn_code = 0;
  mh_err mherr = mh_read_fn_code(multihash, multihash_size, &fn_code);
  if (mherr) {
    return CID_ERR_INVALID_MULTIHASH;
  }
  if (fn_code != MH_FN_CODE_SHA2_256) {
    return CID_ERR_CIDV0_MH_FN;
  }

  // cidv0 is [0x12, 0x20, ...<multihash>]
  if (cid_size) {
    *cid_size = multihash_size + 2;
  }
  if (cid) {
    cid[0] = 0x12;
    cid[1] = 0x20;
    memcpy(cid + 2, multihash, multihash_size);
  }

  return CID_ERR_OK;
}

cid_err cid_v1(const uint8_t* multihash, size_t multihash_size, cid_codec codec, uint8_t* cid, size_t* cid_size) {
  // <cid-version><multicodec-content-type><multihash-content-address>
  uint8_t codec_varint[VARINT_UINT64_MAX_BYTES] = {0};
  size_t varint_size = 0;
  varint_err verr = uint64_to_varint(codec, codec_varint, &varint_size);
  if (verr) {
    return CID_ERR_INVALID_CODEC;
  }
  if (cid) {
    cid[0] = 1;
    memcpy(cid + 1, codec_varint, varint_size);
    memcpy(cid + 1 + varint_size, multihash, multihash_size);
  }
  if (cid_size) {
    *cid_size = 1 + varint_size + multihash_size;
  }
  return CID_ERR_OK;
}

cid_err cid_bytes_to_str(const uint8_t* cid, size_t cid_size, mb_enc enc, char* cid_str_buf, size_t cid_str_buf_size,
                         size_t* cid_str_size) {
  uint64_t version = 0;
  cid_err err = cid_read_version(cid, cid_size, &version);
  if (err) {
    return err;
  }
  uint8_t* cid_str_bytes = (uint8_t*)cid_str_buf;
  if (version == 0) {
    // encode as non-prefixed base58btc
    mb_err mberr = mb_encode_as(cid, cid_size, MB_ENC_BASE58BTC, cid_str_bytes, cid_str_buf_size, cid_str_size);
    if (mberr) {
      return CID_ERR_INVALID_INPUT;
    }
    return CID_ERR_OK;
  }
  if (version == 1) {
    size_t cid_enc_size = 0;
    mb_err mberr = mb_encode(cid, cid_size, enc, cid_str_bytes, cid_str_buf_size, &cid_enc_size);
    if (mberr) {
      return CID_ERR_INVALID_INPUT;
    }
    return CID_ERR_OK;
  }
  return CID_ERR_UNSUPPORTED_VERSION;
}
