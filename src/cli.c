#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    printf("%s\n", cid_err_str(err));
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
    printf("converting CID to bytes: %s\n", cid_err_str(err));
    exit_code = 1;
    goto free_buf;
  }

  uint64_t version = 0;
  err = cid_read_version(buf, bytes_size, &version);
  if (err) {
    printf("reading version: %s\n", cid_err_str(err));
    exit_code = 1;
    goto free_buf;
  }

  uint64_t content_type = 0;
  err = cid_read_content_type(buf, bytes_size, &content_type);
  if (err) {
    printf("reading content type: %s\n", cid_err_str(err));
    exit_code = 1;
    goto free_buf;
  }

  const uint8_t* multihash = NULL;
  size_t multihash_size = 0;
  err = cid_read_multihash(buf, bytes_size, &multihash, &multihash_size);
  if (err) {
    printf("reading multihash: %s\n", cid_err_str(err));
    exit_code = 1;
    goto free_buf;
  }

  const uint8_t* digest = NULL;
  size_t digest_size = 0;
  mh_err mherr = mh_read_digest(multihash, multihash_size, &digest_size, &digest);
  if (mherr) {
    printf("error reading digest: %s\n", mh_err_str(mherr));
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
  mb_err mberr = mb_encode(digest, digest_size, MB_ENC_BASE16UPPER, digest_enc_buf, digest_enc_buf_size, &digest_enc_buf_bytes);
  if (mberr) {
    printf("error encoding digest: %s\n", mb_err_str(mberr));
    exit_code = 1;
    goto free_digest_buf;
  }

  mh_fn_code fn_code = 0;
  mherr = mh_read_fn_code(multihash, multihash_size, &fn_code);
  if (mherr) {
    printf("error reading multihash function: %s\n", mh_err_str(mherr));
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

  if (argc != 3) {
    printf("usage: %s multiaddr <multiaddr>\n", argv[0]);
    return 1;
  }

  char* multiaddr = argv[2];
  size_t multiaddr_len = strlen(multiaddr);

  ma_str_decoder decoder = {.multiaddr = multiaddr, .multiaddr_len = multiaddr_len};
  ma_str_comp cur_comp = {0};
  const ma_proto* cur_proto = NULL;
  while (!decoder.done) {
    ma_err err = ma_str_decode_next(&decoder, &cur_comp);
    if (err) {
      printf("error decoding multiaddr: %s\n", ma_err_str(err));
      return 1;
    }
    err = ma_proto_by_code(cur_comp.proto_code, &cur_proto);
    if (err) {
      printf("looking up code %lu: %s\n", cur_comp.proto_code, ma_err_str(err));
      return 1;
    }

    size_t bytes_size = 0;
    err = cur_proto->str_to_bytes(cur_proto, cur_comp.value, cur_comp.value_len, NULL, &bytes_size);
    if (err) {
      printf("computing bytes size: %s\n", ma_err_str(err));
      return 1;
    }

    uint8_t* bytes = calloc(bytes_size, sizeof(uint8_t));
    err = cur_proto->str_to_bytes(cur_proto, cur_comp.value, cur_comp.value_len, bytes, NULL);
    if (err) {
      printf("converting string to bytes: %s\n", ma_err_str(err));
      return 1;
    }

    size_t str_len = 0;
    err = cur_proto->bytes_to_str(cur_proto, bytes, bytes_size, NULL, &str_len);
    if (err) {
      printf("computing string length: %s\n", ma_err_str(err));
      return 1;
    }

    char* str = calloc(str_len + 1, sizeof(char));
    err = cur_proto->bytes_to_str(cur_proto, bytes, bytes_size, str, NULL);
    if (err) {
      printf("converting bytes back to string: %s\n", ma_err_str(err));
      return 1;
    }

    printf("protocol=%s, value=", cur_proto->name);
    for (size_t i = 0; i < cur_comp.value_len; i++) {
      printf("%c", cur_comp.value[i]);
    }
    printf(", bytes=");
    for (size_t i = 0; i < bytes_size; i++) {
      printf("%02hx ", bytes[i]);
    }
    printf(", str_len=%lu, str=", str_len);
    for (size_t i = 0; i < str_len; i++) {
      //      printf("%02hx ", str[i]);
      printf("%c", str[i]);
    }
    printf("\n");
    free(bytes);
  }

  return 0;
}

int multibase(int argc, char* argv[]) {
  uint8_t* input_buf = NULL;
  uint8_t* dec_buf = NULL;
  uint8_t* enc_buf = NULL;

  int exit_code = EXIT_SUCCESS;

  if (argc < 4) {
    printf("Usage: %s multibase <new_encoding> <encoded_data> [--raw-input]\n", argv[0]);
    return 1;
  }

  char* enc_str = argv[2];
  char* input = argv[3];

  bool raw_input = false;

  if (argc == 5) {
    if (strcmp(argv[4], "--raw-input") == 0) {
      raw_input = true;
    } else {
      printf("Usage: %s multibase <new_encoding> <encoded_data> [--raw-input]\n", argv[0]);
      return 1;
    }
  }

  mb_enc enc = 0;
  mb_err err = mb_enc_by_name(enc_str, &enc);
  if (err) {
    printf("getting encoding '%s': %s\n", enc_str, mb_err_str(err));
    return 1;
  }

  size_t input_buf_len = strlen(input);
  if (raw_input) {
    input_buf = calloc(input_buf_len, sizeof(uint8_t));
    memcpy(input_buf, input, input_buf_len);  // NOLINT
  } else {
    // decode the input
    size_t str_len = strlen(input);
    size_t dec_size = mb_decode_size((uint8_t*)input, str_len);
    if (dec_size == 0) {
      printf("\n");
      goto exit;
    }
    dec_buf = calloc(dec_size, sizeof(uint8_t));
    mb_enc dec_enc = 0;
    size_t dec_bytes = 0;
    mb_err dec_err = mb_decode((uint8_t*)input, str_len, &dec_enc, dec_buf, dec_size, &dec_bytes);
    if (dec_err) {
      printf("decoding: %s\n", mb_err_str(dec_err));
      exit_code = 1;
      goto exit;
    }
    input_buf_len = dec_bytes;
    input_buf = calloc(input_buf_len, sizeof(uint8_t));
    memcpy(input_buf, dec_buf, input_buf_len);
  }

  // encode the result
  size_t enc_size = mb_encode_size(input_buf, input_buf_len, enc);
  enc_buf = calloc(enc_size, sizeof(uint8_t));
  size_t enc_bytes = 0;
  mb_err enc_err = mb_encode(input_buf, input_buf_len, enc, enc_buf, enc_size, &enc_bytes);
  if (enc_err) {
    printf("encoding: %s\n", mb_err_str(enc_err));
    exit_code = 1;
    goto exit;
  }

  // print
  for (size_t i = 0; i < enc_bytes; i++) {
    printf("%c", enc_buf[i]);
  }
  printf("\n");

exit:
  if (enc_buf) {
    free(enc_buf);
  }
  if (dec_buf) {
    free(dec_buf);
  }
  if (input_buf) {
    free(input_buf);
  }
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
    printf("error computing multihash length: %s\n", mh_err_str(err));
    return 1;
  }
  uint8_t* mh = malloc(mh_size * sizeof(uint8_t));
  if (mh == NULL) {
    printf("error allocating memory for multihash\n");
    return 1;
  }
  err = mh_encode((uint8_t*)input_str, input_str_len, f->code, mh, mh_size);
  if (err) {
    printf("error computing multihash: %s\n", mh_err_str(err));
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
  mb_err mberr = mb_encode(mh, mh_size, MB_ENC_BASE16, mh_enc, mh_enc_size, &mh_enc_bytes);
  if (mberr) {
    printf("error encoding multihash: %s\n", mb_err_str(mberr));
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
      printf("error: %s\n", varint_err_str(err));
      return 1;
    }

    mb_enc enc = 0;
    mb_err mberr = mb_enc_by_name(encoding, &enc);
    if (mberr) {
      free(varint);
      printf("encoding '%s': %s\n", encoding, mb_err_str(mberr));
      return 1;
    }

    size_t mb_enc_size = mb_encode_size(varint, varint_size, enc);
    uint8_t* enc_bytes = calloc(mb_enc_size, sizeof(uint8_t));
    size_t result_size = 0;
    mberr = mb_encode(varint, varint_size, enc, enc_bytes, mb_enc_size, &result_size);
    if (mberr) {
      free(varint);
      free(enc_bytes);
      printf("%s\n", mb_err_str(mberr));
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
      printf("%s\n", mb_err_str(err));
      return 1;
    }
    uint64_t n = 0;
    varint_err verr = varint_to_uint64(dec_bytes, dec_result_size, &n, NULL);
    if (verr) {
      free(dec_bytes);
      printf("%s\n", varint_err_str(verr));
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
