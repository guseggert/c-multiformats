#include "multiaddr.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "varint.h"

static bool bytes_eql(const char* a, size_t a_size, const char* b, size_t b_size) {
  if (a_size != b_size) {
    return false;
  }
  for (size_t i = 0; i < a_size; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

static ma_err identity_bytes_to_str(const struct proto* p, const uint8_t* const bytes, size_t bytes_size, char* str, size_t* str_len) {
  (void)p;
  if (str_len != NULL) {
    *str_len = bytes_size;
  }
  if (str != NULL) {
    memcpy(str, bytes, bytes_size);
  }
  return MA_ERR_OK;
}

static ma_err identity_str_to_bytes(const struct proto* p, const char* const str, const size_t str_len, uint8_t* bytes,
                                    size_t* bytes_size) {
  (void)p;
  if (bytes_size != NULL) {
    *bytes_size = str_len;
  }
  if (bytes != NULL) {
    memcpy(bytes, str, str_len);
  }
  return MA_ERR_OK;
}

static ma_err valid_validate_bytes(const struct proto* p, const uint8_t* bytes, size_t bytes_size) {
  (void)p;
  (void)bytes;
  (void)bytes_size;
  return MA_ERR_OK;
}

const ma_proto ma_proto_unix = {
    .name = "unix",
    .name_len = 4,
    .code = MA_PROTO_CODE_UNIX,
    .code_varint = (uint8_t[]){0x90, 0x03},
    .code_varint_size = 2,
    .has_value = true,
    .val_is_constant_size = false,
    .val_is_path = true,
    .bytes_to_str = &identity_bytes_to_str,
    .str_to_bytes = &identity_str_to_bytes,
    .validate_bytes = &valid_validate_bytes,
    .next = NULL,
};
const ma_proto ma_proto_tcp = {
    .name = "tcp",
    .name_len = 3,
    .code = MA_PROTO_CODE_TCP,
    .code_varint = (uint8_t[]){0x06},
    .code_varint_size = 1,
    .has_value = true,
    .val_is_constant_size = true,
    .val_size = 16,
    .val_is_path = false,
    .bytes_to_str = &identity_bytes_to_str,
    .str_to_bytes = &identity_str_to_bytes,
    .validate_bytes = &valid_validate_bytes,
    .next = &ma_proto_unix,
};
const ma_proto ma_proto_ip4 = {
    .name = "ip4",
    .name_len = 3,
    .code = MA_PROTO_CODE_IP4,
    .code_varint = (uint8_t[]){0x04},
    .code_varint_size = 1,
    .has_value = true,
    .val_size = 32,
    .val_is_path = false,
    .bytes_to_str = &identity_bytes_to_str,
    .str_to_bytes = &identity_str_to_bytes,
    .validate_bytes = &valid_validate_bytes,
    .next = &ma_proto_tcp,
};
const ma_proto* protos = &ma_proto_ip4;  // NOLINT

ma_err ma_add_proto(ma_proto* proto) {
  if (protos != NULL) {
    proto->next = protos;
  }
  protos = proto;
  return MA_ERR_OK;
}

static ma_err ma_proto_by_name_and_size(const char* name, size_t size, const ma_proto** proto) {
  const ma_proto* cur = protos;
  while (cur != NULL) {
    if (bytes_eql(name, size, cur->name, cur->name_len)) {
      *proto = cur;
      return MA_ERR_OK;
    }
    cur = cur->next;
  }
  return MA_ERR_UNKNOWN_PROTOCOL;
}

ma_err ma_proto_by_name(const char* name, const ma_proto** proto) {
  size_t name_len = strlen(name);
  return ma_proto_by_name_and_size(name, name_len, proto);
}

ma_err ma_proto_by_code(const ma_proto_code code, const ma_proto** proto) {
  const ma_proto* cur = protos;
  while (cur != NULL) {
    if (code == cur->code) {
      *proto = cur;
      return MA_ERR_OK;
    }
    cur = cur->next;
  }
  return MA_ERR_UNKNOWN_PROTOCOL;
}

static ma_err ma_bytes_comp_to_bytes(const ma_bytes_comp* const comp, uint8_t* const bytes, size_t* bytes_size) {
  size_t idx = 0;
  const ma_proto* proto = NULL;
  ma_err err = ma_proto_by_code(comp->proto_code, &proto);
  if (err) {
    return err;
  }

  err = proto->validate_bytes(proto, comp->value, comp->value_size);
  if (err) {
    return err;
  }

  if (bytes != NULL) {
    memcpy(bytes + idx, proto->code_varint, proto->code_varint_size);
  }
  idx += proto->code_varint_size;

  // write the value, if there is one to write
  if (proto->has_value) {
    if (proto->val_is_constant_size) {
      // sanity check, the component value size should exactly equal the size as defined in the protocol
      if (proto->val_size != comp->value_size) {
        return MA_ERR_INVALID_INPUT;
      }
      if (bytes != NULL) {
        memcpy(bytes + idx, comp->value, comp->value_size);
      }
      idx += comp->value_size;
    } else {
      uint8_t varint[VARINT_UINT64_MAX_BYTES] = {0};
      size_t varint_size = 0;
      varint_err err = uint64_to_varint(comp->value_size, varint, &varint_size);
      if (err) {
        return MA_ERR_INVALID_INPUT;
      }
      if (bytes != NULL) {
        memcpy(bytes + idx, varint, varint_size);
        memcpy(bytes + idx + varint_size, comp->value, comp->value_size);
      }
      idx += varint_size + comp->value_size;
    }
  }

  if (bytes_size != NULL) {
    *bytes_size = idx;
  }

  return MA_ERR_OK;
}

ma_err ma_bytes_encode(const ma_bytes_comp* const comps, size_t comps_size, uint8_t* bytes, size_t* bytes_size) {
  size_t idx = 0;
  for (size_t i = 0; i < comps_size; i++) {
    size_t size = 0;
    uint8_t* comp_bytes = bytes == NULL ? NULL : bytes + idx;
    ma_err err = ma_bytes_comp_to_bytes(&comps[i], comp_bytes, &size);
    if (err) {
      return err;
    }
    idx += size;
  }
  if (bytes_size != NULL) {
    *bytes_size = idx;
  }
  return MA_ERR_OK;
}

ma_err ma_bytes_decode_next(ma_bytes_decoder* decoder, ma_bytes_comp* comp) {
  if (decoder->done) {
    return MA_ERR_OK;
  }

  if (decoder->cur_byte >= decoder->multiaddr_size) {
    decoder->done = true;
    return MA_ERR_OK;
  }

  // clear the component struct
  memset(comp, 0, sizeof(ma_bytes_comp));

  size_t cur_byte = decoder->cur_byte;
  const uint8_t* bytes = (uint8_t*)decoder->multiaddr;
  size_t cur_bytes_size = decoder->multiaddr_size - cur_byte;

  // read the proto code varint
  uint64_t code = 0;
  size_t varint_size = 0;
  varint_err verr = varint_to_uint64(bytes + cur_byte, cur_bytes_size, &code, &varint_size);
  if (verr) {
    return MA_ERR_INVALID_INPUT;
  }

  comp->proto_code = code;
  cur_byte += varint_size;
  cur_bytes_size -= varint_size;

  // lookup the protocol
  const ma_proto* proto = NULL;
  ma_err err = ma_proto_by_code(code, &proto);
  if (err) {
    return err;
  }

  // if there's no value, we're done
  if (!proto->has_value) {
    decoder->cur_byte = cur_byte;
    return MA_ERR_OK;
  }

  // read the value

  // constant-sized value
  if (proto->val_is_constant_size) {
    // sanity check, should not point past input bytes
    if (cur_bytes_size < proto->val_size) {
      return MA_ERR_INVALID_INPUT;
    }
    comp->value = (uint8_t*)bytes + cur_byte;
    comp->value_size = proto->val_size;
    decoder->cur_byte = cur_byte + proto->val_size;
    return MA_ERR_OK;
  }

  // it's a variable-size value, read another varint to determine value size
  uint64_t value_size = 0;
  size_t value_varint_size = 0;
  verr = varint_to_uint64(bytes + cur_byte, cur_bytes_size, &value_size, &value_varint_size);
  if (verr) {
    return MA_ERR_INVALID_INPUT;
  }

  // sanity check
  // the varint should not point past the input bytes
  if (value_size + cur_byte > decoder->multiaddr_size - 1) {
    return MA_ERR_INVALID_INPUT;
  }

  cur_byte += value_varint_size;

  comp->value = (uint8_t*)bytes + cur_byte;
  comp->value_size = value_size;

  cur_byte += value_size;

  decoder->cur_byte = cur_byte;

  // if this was a path protocol, then we should be at the end
  if (proto->val_is_path && decoder->cur_byte != decoder->multiaddr_size) {
    printf("%lu %lu %lu %lu\n", value_size, value_varint_size, decoder->cur_byte, decoder->multiaddr_size);
    return MA_ERR_INVALID_INPUT;
  }

  return MA_ERR_OK;
}

// Reads the next multiaddr element from a string.
//
// If the end of str is reached (null terminator), elem_start is set to null.
//
// This considers a multiaddr like '//' to be valid (in that case it will read two elements with elem_len=0).
static ma_err next_str_elem(ma_str_decoder* const decoder, const char** elem_start, size_t* const elem_len) {
  size_t s_start = decoder->cur_char;
  const char* e_start = decoder->multiaddr + s_start;

  if (e_start[0] == '\0') {
    *elem_start = NULL;
    return MA_ERR_OK;
  }
  if (e_start[0] != '/') {
    return MA_ERR_INVALID_INPUT;
  }

  s_start++;
  e_start++;

  size_t size = 0;

  for (; s_start != decoder->multiaddr_len && e_start[size] != '/'; size++, s_start++) {
  }

  *elem_start = e_start;
  *elem_len = size;
  decoder->cur_char = s_start;

  return MA_ERR_OK;
}

ma_err ma_str_decode_next(ma_str_decoder* const decoder, ma_str_comp* const comp) {
  if (decoder->done) {
    return MA_ERR_OK;
  }

  char* elem_start = NULL;
  size_t elem_len = 0;

  ma_err err = next_str_elem(decoder, (const char**)&elem_start, &elem_len);
  if (err) {
    return err;
  }
  // there are no more elements, we've reached the end of the multiaddr
  if (elem_start == NULL) {
    decoder->done = true;
    return MA_ERR_OK;
  }

  // lookup the protocol
  const ma_proto* proto = NULL;
  err = ma_proto_by_name_and_size(elem_start, elem_len, &proto);
  if (err) {
    return err;
  }

  comp->proto_code = proto->code;
  comp->value = NULL;
  comp->value_len = 0;

  if (!proto->has_value) {
    return MA_ERR_OK;
  }

  // read the value

  if (proto->val_is_path) {
    // this is a path protocol, so the component value is the rest of the muiltiaddr
    // note that we don't validate the path here
    comp->value = elem_start + elem_len;
    comp->value_len = decoder->multiaddr_len - decoder->cur_char;
    decoder->cur_char = decoder->multiaddr_len;
    return MA_ERR_OK;
  }

  // there must be another element at this point, so read it
  err = next_str_elem(decoder, (const char**)&elem_start, &elem_len);
  if (err) {
    return err;
  }
  if (elem_start == NULL) {
    return MA_ERR_INVALID_INPUT;
  }

  comp->value = elem_start;
  comp->value_len = elem_len;

  return MA_ERR_OK;
}

ma_err ma_str_comp_to_str(const ma_str_comp* const comp, char* const str, size_t* str_len) {
  const ma_proto* proto = NULL;
  ma_err err = ma_proto_by_code(comp->proto_code, &proto);
  if (err) {
    return err;
  }

  size_t idx = 0;

  if (str != NULL) {
    str[0] = '/';
    memcpy(str + 1, proto->name, proto->name_len);
  }
  idx += 1 + proto->name_len;

  if (!proto->has_value) {
    if (str_len != NULL) {
      *str_len = idx;
    }
    return MA_ERR_OK;
  }

  // add leading slash for non-path values
  if (!proto->val_is_path) {
    if (str != NULL) {
      str[idx] = '/';
    }
    idx++;
  }

  if (str != NULL) {
    memcpy(str + idx, comp->value, comp->value_len);
  }
  idx += comp->value_len;

  if (str_len != NULL) {
    *str_len = idx;
  }

  return MA_ERR_OK;
}

ma_err ma_str_encode(const ma_str_comp* comps, size_t comps_size, char* str, size_t* str_len) {
  size_t idx = 0;
  for (size_t i = 0; i < comps_size; i++) {
    size_t len = 0;
    char* comp_str = str == NULL ? NULL : str + idx;
    ma_err err = ma_str_comp_to_str(&comps[i], comp_str, &len);
    if (err) {
      return err;
    }
    idx += len;
  }

  if (str_len != NULL) {
    *str_len = idx;
  }
  return MA_ERR_OK;
}

ma_err ma_str_to_bytes(const char* str, size_t str_len, uint8_t* bytes, size_t* bytes_size) {
  ma_str_decoder decoder = {.multiaddr = str, .multiaddr_len = str_len};
  ma_str_comp cur_comp = {0};
  size_t bytes_idx = 0;
  while (1) {
    // read next component
    ma_err err = ma_str_decode_next(&decoder, &cur_comp);
    if (err) {
      return err;
    }
    if (decoder.done) {
      continue;
    }

    // lookup the protocol
    const ma_proto* proto = NULL;
    err = ma_proto_by_code(cur_comp.proto_code, &proto);
    if (err) {
      return err;
    }

    // write component varint code
    if (bytes != NULL) {
      memcpy(bytes + bytes_idx, proto->code_varint, proto->code_varint_size);
    }
    bytes_idx += proto->code_varint_size;

    // there is no value for this component, nothing left to do
    if (!proto->has_value) {
      continue;
    }

    // component value varint prefix, if required
    size_t size = 0;
    if (!proto->val_is_constant_size) {
      proto->str_to_bytes(proto, cur_comp.value, cur_comp.value_len, NULL, &size);
      size_t varint_size = 0;
      uint8_t varint[VARINT_UINT64_MAX_BYTES];
      varint_err err = uint64_to_varint(size, varint, &varint_size);
      if (err) {
        return MA_ERR_INVALID_INPUT;
      }
      if (bytes != NULL) {
        memcpy(bytes + bytes_idx, varint, varint_size);
      }
      bytes_idx += varint_size;
    } else {
      size = proto->val_size;
    }

    // component value
    if (bytes != NULL) {
      err = proto->str_to_bytes(proto, cur_comp.value, cur_comp.value_len, bytes + bytes_idx, NULL);
      if (err) {
        return err;
      }
    }
    bytes_idx += size;
  }

  if (bytes_size != NULL) {
    *bytes_size = bytes_idx;
  }
}

ma_err ma_bytes_to_str(const uint8_t* bytes, size_t bytes_size, char* str, size_t* str_len) {
  size_t cur_idx = 0;

  ma_bytes_comp cur_bytes_comp = {0};
  ma_bytes_decoder decoder = {.multiaddr = bytes, .multiaddr_size = bytes_size};
  while (1) {
    ma_err err = ma_bytes_decode_next(&decoder, &cur_bytes_comp);
    if (err) {
      return err;
    }
    if (decoder.done) {
      break;
    }

    const ma_proto* proto = NULL;
    err = ma_proto_by_code(cur_bytes_comp.proto_code, &proto);
    if (err) {
      return err;
    }

    // write the name
    if (str != NULL) {
      str[cur_idx] = '/';
      memcpy(str + cur_idx + 1, proto->name, proto->name_len);
    }
    cur_idx += proto->name_len + 1;

    // add a slash prefix if it's not a path value
    if (!proto->val_is_path) {
      if (str != NULL) {
        str[cur_idx] = '/';
      }
      cur_idx++;
    }

    // convert the byte value to a string value and write it
    size_t size = 0;
    err = proto->bytes_to_str(proto, cur_bytes_comp.value, cur_bytes_comp.value_size, NULL, &size);
    if (err) {
      return err;
    }

    if (str != NULL) {
      err = proto->bytes_to_str(proto, cur_bytes_comp.value, cur_bytes_comp.value_size, str + cur_idx, NULL);
      if (err) {
        return err;
      }
    }
    cur_idx += size;
  }

  if (str_len != NULL) {
    *str_len = cur_idx;
  }

  return MA_ERR_OK;
}
