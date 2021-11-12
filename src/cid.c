#include "cid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"
#include "multicodec.h"
#include "multihash.h"
#include "varint.h"

cid_err_t cid_decode_bytes(const uint8_t* const bytes, size_t bytes_len, cid_t** cid) {
  if (bytes_len == 34 && bytes[0] == 0x12 && bytes[1] == 0x20) {
    // cidv0
    mh_t* mh = NULL;
    mh_err_t mh_err = mh_parse(bytes, bytes_len, &mh);
    if (mh_err) {
      return CID_ERR_INVALID_INPUT;
    }
    cid_t* c = malloc(sizeof(cid_t));
    if (c == NULL) {
      mh_free(mh);
      return CID_ERR_MEMORY;
    }
    c->multihash = mh;
    c->content_type = MC_DAG_PB;
    c->version = 0;
    *cid = c;
    return CID_ERR_OK;
  }
  // read version from first varint
  uint64_t version_varint = 0;
  size_t version_varint_len = 0;
  varint_err_t varint_err = varint_to_uint64(bytes, bytes_len, &version_varint, &version_varint_len);
  if (varint_err) {
    return CID_ERR_INVALID_INPUT;
  }

  switch (version_varint) {
    case 0x01: {
      // cidv1
      uint64_t multicodec_varint = 0;
      size_t multicodec_varint_len = 0;
      varint_err = varint_to_uint64(bytes + version_varint_len, bytes_len - version_varint_len, &multicodec_varint, &multicodec_varint_len);
      if (varint_err) {
        return CID_ERR_INVALID_INPUT;
      }
      mh_t* mh = NULL;
      mh_err_t mh_err =
          mh_parse(bytes + version_varint_len + multicodec_varint_len, bytes_len - version_varint_len - multicodec_varint_len, &mh);
      if (mh_err) {
        if (mh_err == MH_ERR_MEMORY) {
          return CID_ERR_MEMORY;
        }
        return CID_ERR_INVALID_INPUT;
      }
      cid_t* c = malloc(sizeof(cid_t));
      if (c == NULL) {
        mh_free(mh);
        return CID_ERR_MEMORY;
      }
      c->content_type = multicodec_varint;
      c->multihash = mh;
      c->version = 1;
      *cid = c;

      return CID_ERR_OK;
    }
    case 0x02:
    case 0x03:
      return CID_UNSUPPORTED_VERSION;
    default:
      return CID_ERR_INVALID_INPUT;
  }
}

static size_t utf8_len(const uint8_t* const bytes, size_t len) {
  size_t codepoints = 0;
  for (size_t i = 0; i < len; i++) {
    codepoints += (bytes[i] & 0xc0) != 0x80;  // count non-continuation bytes
  }
  return codepoints;
}

cid_err_t cid_decode_str(const char* const str, cid_t** cid) {
  unsigned long num_bytes = strlen(str);
  uint8_t* str_bytes = (uint8_t*)str;
  size_t str_len = utf8_len(str_bytes, num_bytes);
  if (str_len == 46 && str[0] == 'Q' && str[1] == 'm') {
    // cidv0, decode as base58btc and then parse the bytes
    size_t buf_len = mb_decode_as_len(str_bytes, num_bytes, MB_ENC_BASE58BTC);
    uint8_t* buf = calloc(buf_len, sizeof(uint8_t));
    size_t dec_bytes = 0;
    mb_err_t dec_err = mb_decode_as(str_bytes, num_bytes, MB_ENC_BASE58BTC, buf, buf_len, &dec_bytes);
    if (dec_err) {
      free(buf);
      return CID_ERR_INVALID_INPUT;
    }

    cid_t* c = NULL;
    cid_err_t cid_err = cid_decode_bytes(buf, buf_len, &c);
    free(buf);
    if (cid_err) {
      return cid_err;
    }
    *cid = c;
    return CID_ERR_OK;
  }
  size_t buf_len = mb_decode_len(str_bytes, num_bytes);
  uint8_t* buf = calloc(buf_len, sizeof(uint8_t));
  size_t dec_bytes = 0;
  mb_enc_t enc = 0;
  mb_err_t dec_err = mb_decode(str_bytes, num_bytes, &enc, buf, buf_len, &dec_bytes);
  if (dec_err) {
    free(buf);
    return CID_ERR_INVALID_INPUT;
  }
  if (dec_bytes > 0 && buf[0] == 0x12) {
    free(buf);
    return CID_ERR_INVALID_INPUT;
  }
  cid_t* c = NULL;
  cid_err_t cid_err = cid_decode_bytes(buf, dec_bytes, &c);
  if (cid_err) {
    free(buf);
    return cid_err;
  }
  *cid = c;

  free(buf);
  return CID_ERR_OK;
}

void cid_free(cid_t* cid) {
  mh_free(cid->multihash);
  free(cid);
}

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
  cid_t* cid = NULL;

  cid_err_t err = cid_decode_str(cid_str, &cid);
  if (err) {
    printf("%s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto exit;
  }
  printf("content type: 0x%02lX\n", cid->content_type);
  printf("version: %lu\n", cid->version);
  printf("hash func: 0x%02lX\n", cid->multihash->hash_func_code);
  printf("digest size: %lu\n", cid->multihash->digest_size);

  size_t buf_len = mb_encode_len(cid->multihash->digest, cid->multihash->digest_size, MB_ENC_BASE16);
  uint8_t* buf = calloc(buf_len + 1, sizeof(uint8_t));
  if (buf == NULL) {
    cid_free(cid);
    printf("error allocating mem\n");
    exit_code = 1;
    goto exit;
  }
  size_t written = 0;
  mb_err_t mb_err = mb_encode(cid->multihash->digest, cid->multihash->digest_size, MB_ENC_BASE16, buf, buf_len, &written);
  if (mb_err) {
    cid_free(cid);
    free(buf);
    printf("error encoding: %s\n", MB_ERR_STRS[mb_err]);
    exit_code = 1;
    goto exit;
  }
  buf[buf_len] = '\0';
  printf("digest: %s\n", (char*)buf);
  cid_free(cid);
  free(buf);

exit:
  return exit_code;
}
