#include "cid.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"
#include "multicodec.h"
#include "multihash.h"
#include "varint.h"

static cid_err cid_read_version_varint(const uint8_t* const bytes, size_t bytes_len, uint64_t* const version_varint, size_t* bytes_read) {
  if (bytes_len == 34 && bytes[0] == 0x12 && bytes[1] == 0x20) {
    // cidv0
    if (version_varint != NULL) {
      *version_varint = 0;
    }
    if (bytes_read != NULL) {
      *bytes_read = 0;
    }
    return CID_ERR_OK;
  }
  varint_err varint_err = varint_to_uint64(bytes, bytes_len, version_varint, bytes_read);
  if (varint_err) {
    return CID_ERR_INVALID_INPUT;
  }
  return CID_ERR_OK;
}

cid_err cid_read_version(const uint8_t* const cid, size_t cid_len, uint64_t* const version) {
  return cid_read_version_varint(cid, cid_len, version, NULL);
}

static cid_err cid_read_content_type_varint(const uint8_t* const bytes, size_t bytes_len, uint64_t version, uint64_t* content_type,
                                            size_t* bytes_read) {
  if (version == 0) {
    if (content_type != NULL) {
      *content_type = MC_DAG_PB;
    }
    if (bytes_read != NULL) {
      *bytes_read = 0;
    }
    return CID_ERR_OK;
  }
  if (version == 1) {
    uint64_t multicodec_varint = 0;
    size_t multicodec_varint_len = 0;
    varint_err varint_err = varint_to_uint64(bytes, bytes_len, &multicodec_varint, &multicodec_varint_len);
    if (varint_err) {
      return CID_ERR_INVALID_INPUT;
    }
    if (content_type != NULL) {
      *content_type = multicodec_varint;
    }
    if (bytes_read != NULL) {
      *bytes_read = multicodec_varint_len;
    }
    return CID_ERR_OK;
  }
  return CID_ERR_UNSUPPORTED_VERSION;
}

cid_err cid_read_content_type(const uint8_t* const cid, size_t cid_len, uint64_t* content_type) {
  size_t bytes_read = 0;
  uint64_t version = 0;
  cid_err err = cid_read_version_varint(cid, cid_len, &version, &bytes_read);
  if (err) {
    return err;
  }
  return cid_read_content_type_varint(cid + bytes_read, cid_len - bytes_read, version, content_type, NULL);
}

cid_err cid_read_multihash(const uint8_t* cid, size_t cid_len, const uint8_t** multihash, size_t* multihash_len) {
  size_t bytes_read = 0;
  uint64_t version = 0;
  cid_err err = cid_read_version_varint(cid, cid_len, &version, &bytes_read);
  if (err) {
    return err;
  }
  if (version == 0) {
    if (multihash != NULL) {
      *multihash = cid;
    }
    if (multihash_len != NULL) {
      *multihash_len = cid_len;
    }
    return CID_ERR_OK;
  }
  if (version == 1) {
    size_t b = 0;
    err = cid_read_content_type_varint(cid + bytes_read, cid_len - bytes_read, version, NULL, &b);
    if (err) {
      return err;
    }
    bytes_read += b;

    if (multihash != NULL) {
      *multihash = cid + bytes_read;
    }
    if (multihash_len != NULL) {
      *multihash_len = cid_len - bytes_read;
    }
    return CID_ERR_OK;
  }
  if (version == 2 || version == 3) {
    return CID_ERR_UNSUPPORTED_VERSION;
  }
  return CID_ERR_INVALID_INPUT;
}

static size_t utf8_len(const uint8_t* const bytes, size_t len) {
  size_t codepoints = 0;
  for (size_t i = 0; i < len; i++) {
    codepoints += (bytes[i] & 0xc0) != 0x80;  // count non-continuation bytes
  }
  return codepoints;
}

cid_err cid_str_to_bytes_len(const char* cid, size_t* len) {
  unsigned long num_bytes = strlen(cid);
  uint8_t* str_bytes = (uint8_t*)cid;
  size_t str_len = utf8_len(str_bytes, num_bytes);
  if (str_len == 46 && cid[0] == 'Q' && cid[1] == 'm') {
    *len = mb_decode_as_len(str_bytes, num_bytes, MB_ENC_BASE58BTC);
    return CID_ERR_OK;
  }
  *len = mb_decode_len(str_bytes, num_bytes);
  return CID_ERR_OK;
}

cid_err cid_str_to_bytes(const char* const cid, uint8_t* const buf, size_t buf_len, size_t* const bytes_len) {
  unsigned long num_bytes = strlen(cid);
  uint8_t* str_bytes = (uint8_t*)cid;
  size_t str_len = utf8_len(str_bytes, num_bytes);
  if (str_len == 46 && cid[0] == 'Q' && cid[1] == 'm') {
    size_t dec_bytes = 0;
    mb_err dec_err = mb_decode_as(str_bytes, num_bytes, MB_ENC_BASE58BTC, buf, buf_len, &dec_bytes);
    if (dec_err) {
      return CID_ERR_INVALID_INPUT;
    }
    *bytes_len = dec_bytes;
    return CID_ERR_OK;
  }
  size_t dec_bytes = 0;
  mb_err dec_err = mb_decode(str_bytes, num_bytes, NULL, buf, buf_len, &dec_bytes);
  if (dec_err) {
    return CID_ERR_INVALID_INPUT;
  }
  if (dec_bytes > 0 && buf[0] == 0x12) {
    return CID_ERR_INVALID_INPUT;
  }
  *bytes_len = dec_bytes;
  return CID_ERR_OK;
}

cid_err cid_validate(const uint8_t* const cid, size_t cid_len) { return cid_read_multihash(cid, cid_len, NULL, NULL); }

cid_err cid_str_validate(const char* const cid) {
  size_t len = 0;
  cid_err err = cid_str_to_bytes_len(cid, &len);
  if (err) {
    return err;
  }
  uint8_t* buf = calloc(len, sizeof(uint8_t));
  if (buf == NULL) {
    return CID_ERR_MEMORY;
  }
  size_t buf_bytes = 0;
  err = cid_str_to_bytes(cid, buf, len, &buf_bytes);
  if (err) {
    free(buf);
    return err;
  }
  err = cid_validate(buf, buf_bytes);
  free(buf);
  return err;
}

// cid-inspect: prints information about a CID
int main(int argc, char* argv[]) {
  (void)argc;
  (void)argv;
  int exit_code = 0;

  if (argc != 2) {
    printf("usage: %s <cid>\n", argv[0]);
    return 1;
  }
  char* cid_str = argv[1];
  // bafykbzacecexdyefm2dztcz7wyj7e4mregekb7d76isvk4cviosljaih6xwea
  // QmbwdMkf5NLZFDT8j8fEeS3rxihM55wsz57sfLr3K1AvxS
  size_t buf_len = 0;
  cid_err err = cid_str_to_bytes_len(cid_str, &buf_len);
  if (err) {
    printf("%s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto exit;
  }
  uint8_t* buf = calloc(buf_len, sizeof(uint8_t));
  if (buf == NULL) {
    printf("mem error\n");
    exit_code = 1;
    goto exit;
  }
  size_t bytes_len = 0;
  err = cid_str_to_bytes(cid_str, buf, buf_len, &bytes_len);
  if (err) {
    printf("converting CID to bytes: %s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto free_buf;
  }

  uint64_t version = 0;
  err = cid_read_version(buf, bytes_len, &version);
  if (err) {
    printf("reading version: %s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto free_buf;
  }

  uint64_t content_type = 0;
  err = cid_read_content_type(buf, bytes_len, &content_type);
  if (err) {
    printf("reading content type: %s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto free_buf;
  }

  const uint8_t* multihash = NULL;
  size_t multihash_len = 0;
  err = cid_read_multihash(buf, bytes_len, &multihash, &multihash_len);
  if (err) {
    printf("reading multihash: %s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto free_buf;
  }

  const uint8_t* digest = NULL;
  size_t digest_size = 0;
  mh_err mh_err = mh_read_digest(multihash, multihash_len, &digest_size, &digest);
  if (mh_err) {
    printf("error reading digest: %s\n", MH_ERR_STRS[mh_err]);
    exit_code = 1;
    goto free_buf;
  }

  size_t digest_enc_buf_len = mb_encode_len(digest, digest_size, MB_ENC_BASE16UPPER);
  uint8_t* digest_enc_buf = calloc(digest_enc_buf_len + 1, sizeof(uint8_t));  // add null terminator
  if (digest_enc_buf == NULL) {
    printf("mem error\n");
    exit_code = 1;
    goto exit;
  }
  digest_enc_buf[digest_enc_buf_len] = '\0';

  size_t digest_enc_buf_bytes = 0;
  mb_err mb_err = mb_encode(digest, digest_size, MB_ENC_BASE16UPPER, digest_enc_buf, digest_enc_buf_len, &digest_enc_buf_bytes);
  if (mb_err) {
    printf("error encoding digest: %s\n", MB_ERR_STRS[mb_err]);
    exit_code = 1;
    goto free_digest_buf;
  }

  mh_fn fn = 0;
  mh_err = mh_read_fn(multihash, multihash_len, &fn);
  if (mh_err) {
    printf("error reading multihash function: %s\n", MH_ERR_STRS[mh_err]);
    exit_code = 1;
    goto free_digest_buf;
  }

  printf("Content type: 0x%02lX\n", content_type);
  printf("Version: %lu\n", version);
  printf("Hash function: 0x%02X\n", fn);
  printf("Digest size: %lu\n", digest_size);
  printf("Digest: %s\n", (char*)digest_enc_buf);

free_digest_buf:
  free(digest_enc_buf);
free_buf:
  free(buf);
exit:
  return exit_code;
}
