#ifndef MULTICODEC_H
#define MULTICODEC_H

#define mc_max_code 0x70
typedef enum mc {
  MC_IDENTITY = 0x00,
  MC_CIDV1 = 0x01,
  MC_DAG_PB = 0x70,
} mc_t;

typedef enum mc_err {
  MC_ERR_OK = 0,
  MC_ERR_NO_VARINT,
  MC_ERR_UNKNOWN_CODEC,
  MC_ERR_MEMORY,
} mc_err_t;

static const char* const MC_ERR_STRS[] = {
    "no error",
    "invalid varint",
    "unknown codec",
    "unable to allocate memory",
};

#endif