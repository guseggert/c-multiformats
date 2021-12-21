#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cid.h"
#include "multiaddr.h"
#include "multibase.h"
#include "multihash.h"
#include "varint.h"

int cid_inspect(int argc, char* argv[]) {
  int exit_code = 0;

  if (argc != 3) {
    printf("usage: %s cid-inspect <cid>\n", argv[0]);
    return 1;
  }
  char* cid_str = argv[2];
  // bafykbzacecexdyefm2dztcz7wyj7e4mregekb7d76isvk4cviosljaih6xwea
  // QmbwdMkf5NLZFDT8j8fEeS3rxihM55wsz57sfLr3K1AvxS
  size_t buf_size = 0;
  cid_err err = cid_str_to_bytes_size(cid_str, &buf_size);
  if (err) {
    printf("%s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto exit;
  }
  uint8_t* buf = calloc(buf_size, sizeof(uint8_t));
  if (buf == NULL) {
    printf("mem error\n");
    exit_code = 1;
    goto exit;
  }
  size_t bytes_size = 0;
  err = cid_str_to_bytes(cid_str, buf, buf_size, &bytes_size);
  if (err) {
    printf("converting CID to bytes: %s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto free_buf;
  }

  uint64_t version = 0;
  err = cid_read_version(buf, bytes_size, &version);
  if (err) {
    printf("reading version: %s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto free_buf;
  }

  uint64_t content_type = 0;
  err = cid_read_content_type(buf, bytes_size, &content_type);
  if (err) {
    printf("reading content type: %s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto free_buf;
  }

  const uint8_t* multihash = NULL;
  size_t multihash_size = 0;
  err = cid_read_multihash(buf, bytes_size, &multihash, &multihash_size);
  if (err) {
    printf("reading multihash: %s\n", CID_ERR_STRS[err]);
    exit_code = 1;
    goto free_buf;
  }

  const uint8_t* digest = NULL;
  size_t digest_size = 0;
  mh_err mh_err = mh_read_digest(multihash, multihash_size, &digest_size, &digest);
  if (mh_err) {
    printf("error reading digest: %s\n", MH_ERR_STRS[mh_err]);
    exit_code = 1;
    goto free_buf;
  }

  size_t digest_enc_buf_size = mb_encode_size(digest, digest_size, MB_ENC_BASE16UPPER);
  uint8_t* digest_enc_buf = calloc(digest_enc_buf_size + 1, sizeof(uint8_t));  // add null terminator
  if (digest_enc_buf == NULL) {
    printf("mem error\n");
    exit_code = 1;
    goto exit;
  }
  digest_enc_buf[digest_enc_buf_size] = '\0';

  size_t digest_enc_buf_bytes = 0;
  mb_err mb_err = mb_encode(digest, digest_size, MB_ENC_BASE16UPPER, digest_enc_buf, digest_enc_buf_size, &digest_enc_buf_bytes);
  if (mb_err) {
    printf("error encoding digest: %s\n", MB_ERR_STRS[mb_err]);
    exit_code = 1;
    goto free_digest_buf;
  }

  mh_fn_code fn_code = 0;
  mh_err = mh_read_fn_code(multihash, multihash_size, &fn_code);
  if (mh_err) {
    printf("error reading multihash function: %s\n", MH_ERR_STRS[mh_err]);
    exit_code = 1;
    goto free_digest_buf;
  }

  printf("Content type: 0x%02lX\n", content_type);
  printf("Version: %lu\n", version);
  printf("Hash function: 0x%02lX\n", fn_code);
  printf("Digest size: %lu\n", digest_size);
  printf("Digest: %s\n", (char*)digest_enc_buf);

free_digest_buf:
  free(digest_enc_buf);
free_buf:
  free(buf);
exit:
  return exit_code;
}

int multiaddr(int argc, char** argv) {
  (void)argc;
  (void)argv;

  ma_str_comp comps[] = {
      {.proto_code = MA_PROTO_CODE_UNIX, .value = "/bar/WHATISTHIS"},
      {.proto_code = MA_PROTO_CODE_UNIX, .value = "/foo/bar"},
      {.proto_code = MA_PROTO_CODE_TCP, .value = "tcp-val"},
  };
  size_t comps_size = sizeof(comps) / sizeof(ma_str_comp);
  char str[1000] = {0};
  ma_err err = ma_str_encode(comps, comps_size, str, NULL);
  if (err) {
    printf("error: %s\n", MA_ERR_STRS[err]);
    return 1;
  }

  /* char* str = calloc(comps_size, sizeof(char)); */
  /* err = ma_comps_str(comps, comps_size, str, NULL); */
  /* if (err) { */
  /*   printf("error: %s\n", MA_ERR_STRS[err]); */
  /*   free(str); */
  /*   return 1; */
  /* } */

  printf("%s\n", str);

  return 0;
}

int multibase(int argc, char* argv[]) {
  int exit_code = EXIT_SUCCESS;

  if (argc != 4) {
    exit_code = 1;
    printf("Usage: %s multibase [new_encoding] [encoded_data]\n", argv[0]);
    goto exit;
  }

  char* enc_str = argv[2];
  char* input = argv[3];

  mb_enc enc = 0;
  mb_err err = mb_enc_by_name(enc_str, &enc);
  if (err) {
    printf("getting encoding '%s': %s\n", enc_str, MB_ERR_STRS[err]);
    exit_code = 1;
    goto exit;
  }

  // decode the input
  size_t str_len = strlen(input);
  size_t dec_size = mb_decode_size((uint8_t*)input, str_len);
  if (dec_size == 0) {
    printf("\n");
    return 0;
  }
  uint8_t* dec_buf = calloc(dec_size, sizeof(uint8_t));
  mb_enc dec_enc = 0;
  size_t dec_bytes = 0;
  mb_err dec_err = mb_decode((uint8_t*)input, str_len, &dec_enc, dec_buf, dec_size, &dec_bytes);
  if (dec_err) {
    printf("decoding: %s\n", MB_ERR_STRS[dec_err]);
    exit_code = 1;
    goto free_dec_buf;
  }

  // re-encode
  size_t enc_size = mb_encode_size(dec_buf, dec_size, enc);
  uint8_t* enc_buf = calloc(enc_size, sizeof(uint8_t));
  size_t enc_bytes = 0;
  mb_err enc_err = mb_encode(dec_buf, dec_size, enc, enc_buf, enc_size, &enc_bytes);
  if (enc_err) {
    printf("encoding: %s\n", MB_ERR_STRS[enc_err]);
    exit_code = 1;
    goto free_enc_buf;
  }

  // print
  for (size_t i = 0; i < enc_size; i++) {
    printf("%c", enc_buf[i]);
  }
  printf("\n");

free_enc_buf:
  free(enc_buf);
free_dec_buf:
  free(dec_buf);
exit:
  return exit_code;
}

int multihash(int argc, char* argv[]) {
  if (argc != 4) {
    printf("usage: %s multihash <hash func name> <string>\n", argv[0]);
    return 1;
  }
  char* hash_func_name = argv[2];
  char* input_str = argv[3];
  size_t input_str_len = strlen(input_str);

  const mh_func* f = NULL;
  if (mh_func_by_name(hash_func_name, &f)) {
    printf("unknown hash func '%s'\n", hash_func_name);
    return 1;
  }

  size_t mh_size = 0;
  mh_err err = mh_encode_size(f->code, input_str_len, &mh_size);
  if (err) {
    printf("error computing multihash length: %s\n", MH_ERR_STRS[err]);
    return 1;
  }
  uint8_t* mh = malloc(mh_size * sizeof(uint8_t));
  if (mh == NULL) {
    printf("error allocating memory for multihash\n");
    return 1;
  }
  err = mh_encode((uint8_t*)input_str, input_str_len, f->code, mh, mh_size);
  if (err) {
    printf("error computing multihash: %s\n", MH_ERR_STRS[err]);
    free(mh);
    return 1;
  }
  size_t mh_enc_size = mb_encode_size(mh, mh_size, MB_ENC_BASE16);
  uint8_t* mh_enc = calloc(mh_enc_size + 1, sizeof(uint8_t));  // extra byte for null terminator
  if (mh_enc == NULL) {
    printf("error allocating memory for encoding multihash\n");
    free(mh);
    return 1;
  }
  mh_enc[mh_enc_size] = '\0';

  size_t mh_enc_bytes = 0;
  mb_err mb_err = mb_encode(mh, mh_size, MB_ENC_BASE16, mh_enc, mh_enc_size, &mh_enc_bytes);
  if (mb_err) {
    printf("error encoding multihash: %s\n", MB_ERR_STRS[mb_err]);
    free(mh);
    free(mh_enc);
    return 1;
  }
  printf("%s\n", (char*)mh_enc);

  free(mh);
  free(mh_enc);
  return 0;
}

int varint(int argc, char* argv[]) {
  if (argc < 4) {
    goto usage;
  }
  char* cmd = argv[2];

  if (strcmp("encode", cmd) == 0) {
    char* n_str = argv[4];
    unsigned long str_len = strlen(n_str);
    if (str_len == 0) {
      goto usage;
    }

    char* encoding = argv[3];

    long num = 0;
    if (str_len > 2 && n_str[0] == '0' && (n_str[1] == 'x' || n_str[1] == 'X')) {
      num = strtol(n_str, NULL, 16);
    } else {
      num = strtol(n_str, NULL, 10);
    }

    uint8_t* varint = calloc(10, sizeof(uint8_t));
    size_t varint_size = 0;
    varint_err err = uint64_to_varint((uint64_t)num, varint, &varint_size);
    if (err) {
      printf("error: %s\n", VARINT_ERR_STRS[err]);
      return 1;
    }

    mb_enc enc = 0;
    mb_err mberr = mb_enc_by_name(encoding, &enc);
    if (mberr) {
      free(varint);
      printf("encoding '%s': %s\n", encoding, MB_ERR_STRS[mberr]);
      return 1;
    }

    size_t mb_enc_size = mb_encode_size(varint, varint_size, enc);
    uint8_t* enc_bytes = calloc(mb_enc_size, sizeof(uint8_t));
    size_t result_size = 0;
    mberr = mb_encode(varint, varint_size, enc, enc_bytes, mb_enc_size, &result_size);
    if (mberr) {
      free(varint);
      free(enc_bytes);
      printf("%s\n", MB_ERR_STRS[mberr]);
      return 1;
    }
    for (size_t i = 0; i < result_size; i++) {
      printf("%c", enc_bytes[i]);
    }
    printf("\n");
    free(varint);
    free(enc_bytes);
    return 0;
  }
  if (strcmp("decode", cmd) == 0) {
    const char* enc_str = argv[3];
    const uint8_t* enc = (uint8_t*)enc_str;
    unsigned long enc_str_len = strlen(enc_str);
    size_t dec_size = mb_decode_size(enc, enc_str_len);
    uint8_t* dec_bytes = calloc(dec_size, sizeof(uint8_t));
    size_t dec_result_size = 0;
    mb_err err = mb_decode(enc, enc_str_len, NULL, dec_bytes, dec_size, &dec_result_size);
    if (err) {
      free(dec_bytes);
      printf("%s\n", MB_ERR_STRS[err]);
      return 1;
    }
    uint64_t n = 0;
    varint_err verr = varint_to_uint64(dec_bytes, dec_result_size, &n, NULL);
    if (verr) {
      free(dec_bytes);
      printf("%s\n", VARINT_ERR_STRS[verr]);
      return 1;
    }
    printf("%lu\n", n);
    free(dec_bytes);
  }

usage:
  printf("usage: %s varint <encode|decode> <int>\n", argv[0]);
  return 1;
}

typedef struct {
  char* name;
  int (*fn)(int argc, char** argv);
} cmd;

#define NUM_COMMANDS 5
static const cmd cmds[NUM_COMMANDS] = {
    {.name = "cid-inspect", .fn = cid_inspect},
    {.name = "multiaddr", .fn = multiaddr},
    {.name = "multibase", .fn = multibase},
    {.name = "multihash", .fn = multihash},
    {.name = "varint", .fn = varint},
};

int main(int argc, char** argv) {
  if (argc < 2) {
    goto usage;
  }
  char* command = argv[1];
  for (size_t i = 0; i < NUM_COMMANDS; i++) {
    cmd cur_cmd = cmds[i];
    if (!strcmp(command, cur_cmd.name)) {
      return cur_cmd.fn(argc, argv);
    }
  }

usage:
  printf("usage: %s <command>\n", argv[0]);
  printf("commands:\n");
  for (size_t i = 0; i < NUM_COMMANDS; i++) {
    printf("\t%s\n", cmds[i].name);
  }
}
