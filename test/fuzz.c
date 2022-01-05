#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "multibase.h"

void print_buf(char* name, const uint8_t* buf, size_t buf_size) {
  if (buf == NULL) {
    printf("%s: NULL\n", name);
    return;
  }
  printf("%s: ", name);
  for (size_t i = 0; i < buf_size; i++) {
    if (i > 0) {
      printf(":");
    }
    printf("%02X", buf[i]);
  }
  printf("\n");
}

int fuzz_multibase(const uint8_t* data, size_t size) {
  // fuzzing strategies:
  // - pick a random encoding, encode input data, decode, verify result is identical to input
  // - TODO(guseggert): decode random input data (checks cases missed by above such as invalid encoding)

  // require at least two bytes
  if (size < 2) {
    return 0;
  }
  
  // pick an encoding using the first byte
  mb_enc enc = data[0] % NUM_ENCODINGS;

  // encode the data
  size_t enc_buf_size = mb_encode_size(data, size, enc);
  uint8_t* enc_buf = calloc(enc_buf_size, sizeof(uint8_t));
  if (enc_buf == NULL) {
    printf("unable to allocate memory for encoding\n");
    print_buf("data", data, size);
    exit(1);  // NOLINT
  }
  size_t enc_bytes = 0;
  mb_err enc_err = mb_encode(data, size, enc, enc_buf, enc_buf_size, &enc_bytes);
  if (enc_err) {
    printf("error encoding: %s\n", MB_ERR_STRS[enc_err]);
    print_buf("data", data, size);
    free(enc_buf);
    exit(1);  // NOLINT
  }

  // decode it back
  size_t dec_buf_size = mb_decode_size(enc_buf, enc_bytes);
  uint8_t* dec_buf = calloc(dec_buf_size, sizeof(uint8_t));
  if (dec_buf == NULL) {
    printf("unable to allocate memory for decoding\n");
    print_buf("data", data, size);
    print_buf("enc_buf", enc_buf, enc_buf_size);
    free(enc_buf);
    exit(1);  // NOLINT
  }
  mb_enc dec_enc = 0;
  size_t dec_bytes = 0;
  mb_err dec_err = mb_decode(enc_buf, enc_bytes, &dec_enc, dec_buf, dec_buf_size, &dec_bytes);
  if (dec_err) {
    printf("error decoding: %s\n", MB_ERR_STRS[dec_err]);
    print_buf("data", data, size);
    print_buf("enc_buf", enc_buf, enc_buf_size);
    free(enc_buf);
    free(dec_buf);
    exit(1);  // NOLINT
  }

  // validate

  if (dec_enc != enc) {
    printf("expected decoding '%d' but got '%d'\n", enc, dec_enc);
    print_buf("data", data, size);
    print_buf("enc_buf", enc_buf, enc_buf_size);
    print_buf("dec_buf", dec_buf, dec_buf_size);
    free(enc_buf);
    free(dec_buf);

    exit(1);  // NOLINT
  }
  // decoded bytes are the same as input bytes[1:]
  if (size != dec_bytes) {
    printf("expected decoded size '%lu' but got '%lu'\n", size, dec_buf_size);
    print_buf("data", data, size);
    print_buf("enc_buf", enc_buf, enc_buf_size);
    print_buf("dec_buf", dec_buf, dec_buf_size);
    free(enc_buf);
    free(dec_buf);
    exit(1);  // NOLINT
  }
  for (size_t i = 0; i < size; i++) {
    if (dec_buf[i] != data[i]) {
      printf("expected offset=%lu to be %hhx but was %hhx\n", i, data[i], dec_buf[i]);
      print_buf("data", data, size);
      print_buf("enc_buf", enc_buf, enc_buf_size);
      print_buf("dec_buf", dec_buf, dec_buf_size);
      free(enc_buf);
      free(dec_buf);
      exit(1);  // NOLINT
    }
  }

  free(enc_buf);
  free(dec_buf);
  return 0;
}



typedef int (*const fuzz_func)(const uint8_t* data, size_t size);
#define NUM_COMPONENTS 1
static fuzz_func component_fns[NUM_COMPONENTS] = {
    &fuzz_multibase,
};
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // require at least 2 bytes
  if (size < 2) {
    return 0;
  }

  // pick a component to test
  size_t comp = data[0] % NUM_COMPONENTS;
  return component_fns[comp](data + 1, size - 1);
}
