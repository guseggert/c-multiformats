#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multibase.h"

int main(int argc, char* argv[]) {
  int exit_code = EXIT_SUCCESS;

  if (argc != 3) {
    exit_code = 1;
    printf("Usage: %s [new_encoding] [encoded_data]\n", argv[0]);
    goto exit;
  }

  char* enc_str = argv[1];
  char* input = argv[2];

  mb_enc enc = 0;
  mb_err err = mb_enc_by_name(enc_str, &enc);
  if (err) {
    printf("getting encoding '%s': %s\n", enc_str, MB_ERR_STRS[err]);
    exit_code = 1;
    goto exit;
  }

  // decode the input
  size_t str_len = strlen(input);
  size_t dec_len = mb_decode_len((uint8_t*)input, str_len);
  uint8_t* dec_buf = calloc(dec_len, sizeof(uint8_t));
  mb_enc dec_enc = 0;
  size_t dec_bytes = 0;
  mb_err dec_err = mb_decode((uint8_t*)input, str_len, &dec_enc, dec_buf, dec_len, &dec_bytes);
  if (dec_err) {
    printf("decoding: %s\n", MB_ERR_STRS[dec_err]);
    exit_code = 1;
    goto free_dec_buf;
  }

  // re-encode
  size_t enc_len = mb_encode_len(dec_buf, dec_len, enc);
  uint8_t* enc_buf = calloc(enc_len, sizeof(uint8_t));
  size_t enc_bytes = 0;
  mb_err enc_err = mb_encode(dec_buf, dec_len, enc, enc_buf, enc_len, &enc_bytes);
  if (enc_err) {
    printf("encoding: %s\n", MB_ERR_STRS[enc_err]);
    exit_code = 1;
    goto free_enc_buf;
  }

  // print
  for (size_t i = 0; i < enc_len; i++) {
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
