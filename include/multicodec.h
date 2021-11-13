#ifndef MULTICODEC_H
#define MULTICODEC_H

#define mc_max_code 0x70
typedef enum {
  MC_IDENTITY = 0x00,
  MC_CIDV1 = 0x01,
  MC_DAG_PB = 0x70,
} mc;

typedef enum {
  MC_ERR_OK = 0,
  MC_ERR_UNKNOWN_CODEC,
} mc_err;

static const char* const MC_ERR_STRS[] = {
    "no error",
    "unknown codec",
};

#endif
