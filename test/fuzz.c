#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "multibase.h"

void print_buf(char* name, const uint8_t* buf, size_t len) {
  if (buf == NULL) {
    printf("%s: NULL\n", name);
    return;
  }
  printf("%s: ", name);
  for (size_t i = 0; i < len; i++) {
    if (i > 0) {
      printf(":");
    }
    printf("%02X", buf[i]);
  }
  printf("\n");
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // require at least 1 byte
  if (size < 2) {
    return 0;
  }

  // pick an encoding using the first byte
  mb_enc enc = data[0] % NUM_ENCODINGS;

  // temporarily disable base32 until decode is done
  if (enc == MB_ENC_BASE32) {
    return 0;
  }

  // encode the data
  size_t enc_buf_len = mb_encode_len(data, size, enc);
  uint8_t* enc_buf = calloc(enc_buf_len, sizeof(uint8_t));
  if (enc_buf == NULL) {
    printf("unable to allocate memory for encoding\n");
    print_buf("data", data, size);
    exit(1);  // NOLINT
  }
  size_t enc_bytes = 0;
  mb_err enc_err = mb_encode(data, size, enc, enc_buf, enc_buf_len, &enc_bytes);
  if (enc_err) {
    printf("error encoding: %s\n", MB_ERR_STRS[enc_err]);
    print_buf("data", data, size);
    free(enc_buf);
    exit(1);  // NOLINT
  }

  // decode it back
  size_t dec_buf_len = mb_decode_len(enc_buf, enc_bytes);
  uint8_t* dec_buf = calloc(dec_buf_len, sizeof(uint8_t));
  if (dec_buf == NULL) {
    printf("unable to allocate memory for decoding\n");
    print_buf("data", data, size);
    print_buf("enc_buf", enc_buf, enc_buf_len);
    free(enc_buf);
    exit(1);  // NOLINT
  }
  mb_enc dec_enc = 0;
  size_t dec_bytes = 0;
  mb_err dec_err = mb_decode(enc_buf, enc_bytes, &dec_enc, dec_buf, dec_buf_len, &dec_bytes);
  if (dec_err) {
    printf("error decoding: %s\n", MB_ERR_STRS[dec_err]);
    print_buf("data", data, size);
    print_buf("enc_buf", enc_buf, enc_buf_len);
    free(enc_buf);
    free(dec_buf);
    exit(1);  // NOLINT
  }

  // validate

  if (dec_enc != enc) {
    printf("expected decoding '%d' but got '%d'\n", enc, dec_enc);
    print_buf("data", data, size);
    print_buf("enc_buf", enc_buf, enc_buf_len);
    print_buf("dec_buf", dec_buf, dec_buf_len);
    free(enc_buf);
    free(dec_buf);

    exit(1);  // NOLINT
  }
  // decoded bytes are the same as input bytes[1:]
  if (size != dec_bytes) {
    printf("expected decoded length '%lu' but got '%lu'\n", size, dec_buf_len);
    print_buf("data", data, size);
    print_buf("enc_buf", enc_buf, enc_buf_len);
    print_buf("dec_buf", dec_buf, dec_buf_len);
    free(enc_buf);
    free(dec_buf);
    exit(1);  // NOLINT
  }
  for (size_t i = 0; i < size; i++) {
    if (dec_buf[i] != data[i]) {
      printf("expected offset=%lu to be %hhx but was %hhx\n", i, data[i], dec_buf[i]);
      print_buf("data", data, size);
      print_buf("enc_buf", enc_buf, enc_buf_len);
      print_buf("dec_buf", dec_buf, dec_buf_len);
      free(enc_buf);
      free(dec_buf);
      exit(1);  // NOLINT
    }
  }

  free(enc_buf);
  free(dec_buf);
  return 0;
}
