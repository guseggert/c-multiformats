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

/**
 * Converts a string-encoded uint32 to big-endian bytes.
 */
static ma_err uint32_str_to_bytes(const char* const str, const size_t str_len, uint8_t* bytes, size_t* bytes_size, uint32_t* num) {
  // protect from overflow
  if (str_len > 10) {
    return MA_ERR_INVALID_INPUT;
  }

  uint64_t n = 0;
  uint64_t place = 1;

  // convert the string into an int
  for (size_t i = 0; i < str_len; i++) {
    char c = str[str_len - i - 1];
    if (c < '0' || c > '9') {
      return MA_ERR_INVALID_INPUT;
    }
    n += place * (uint8_t)(c - 48);
    place *= 10;
  }
  if (n > UINT32_MAX) {
    return MA_ERR_INVALID_INPUT;
  }
  if (num != NULL) {
    *num = (uint32_t)n;
  }

  // chunk the int into big-endian bytes
  size_t bytes_idx = 0;
  for (size_t n_byte_idx = 0; n_byte_idx < 4; n_byte_idx++) {
    size_t to_shift = 8 * (3 - n_byte_idx);
    uint64_t b = (n & (0xffU << to_shift)) >> to_shift;
    if (b == 0 && bytes_idx == 0) {
      // find first non-zero byte
      continue;
    }
    if (bytes != NULL) {
      bytes[bytes_idx] = b & 0xff;
    }
    bytes_idx++;
  }
  if (bytes_size != NULL) {
    *bytes_size = bytes_idx;
  }
  return MA_ERR_OK;
}

static ma_err uint32_bytes_to_str(const uint8_t* bytes, size_t bytes_size, char* str, size_t* str_len, uint32_t* num) {
  if (bytes_size > 4) {
    return MA_ERR_INVALID_INPUT;
  }
  uint32_t n = 0;
  uint32_t place = 1;
  for (size_t i = 0; i < bytes_size; i++) {
    size_t idx = bytes_size - i - 1;
    n += place * bytes[idx];
    place *= 256;
  }

  if (num != NULL) {
    *num = n;
  }

  // special case: "0"
  if (n == 0) {
    if (str_len != NULL) {
      *str_len = 1;
    }
    if (str != NULL) {
      str[0] = '0';
    }
    return MA_ERR_OK;
  }

  uint32_t cur_place = 1;
  size_t num_digits = 0;
  for (uint32_t cur_n = n; cur_n != 0; cur_place *= 10, num_digits++, cur_n /= 10) {
    // nothing
  }

  uint32_t cur_n = n;
  for (size_t cur_digit = 0; cur_digit < num_digits; cur_digit++, cur_place /= 10) {
    if (str != NULL) {
      str[cur_digit] = (char)((cur_n / (cur_place / 10)) + 48);
      cur_n %= (cur_place / 10);
    }
  }
  if (str_len != NULL) {
    *str_len = num_digits;
  }
  return MA_ERR_OK;
}

static ma_err port_str_to_bytes(const struct proto* p, const char* const str, const size_t str_len, uint8_t* bytes, size_t* bytes_size) {
  (void)p;
  uint32_t n = 0;
  ma_err err = uint32_str_to_bytes(str, str_len, bytes, bytes_size, &n);
  if (err) {
    return err;
  }
  if (n > 65535) {
    return MA_ERR_INVALID_INPUT;
  }
  return MA_ERR_OK;
}

static ma_err port_validate_str(const struct proto* p, const char* const str, size_t str_len) {
  return port_str_to_bytes(p, str, str_len, NULL, NULL);
}

static ma_err port_bytes_to_str(const struct proto* p, const uint8_t* bytes, size_t bytes_size, char* str, size_t* str_len) {
  (void)p;
  uint32_t n = 0;
  ma_err err = uint32_bytes_to_str(bytes, bytes_size, str, str_len, &n);
  if (err) {
    return err;
  }
  if (n > 65535) {
    return MA_ERR_INVALID_INPUT;
  }
  return MA_ERR_OK;
}

static ma_err port_validate_bytes(const struct proto* p, const uint8_t* bytes, size_t bytes_size) {
  return port_bytes_to_str(p, bytes, bytes_size, NULL, NULL);
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

static ma_err valid_validate_str(const struct proto* p, const char* const str, size_t str_len) {
  (void)p;
  (void)str;
  (void)str_len;
  return MA_ERR_OK;
}

static ma_err ip4_str_to_bytes(const struct proto* p, const char* const str, const size_t str_len, uint8_t* bytes, size_t* bytes_size) {
  (void)p;
  if (bytes_size != NULL) {
    *bytes_size = 4;
  }

  size_t cur_str_idx = 0;
  size_t cur_str_len = str_len;
  for (size_t i = 0; i < 4; i++) {
    // missing an octet
    if (cur_str_len == 0) {
      return MA_ERR_INVALID_INPUT;
    }
    if (i > 0) {
      if (str[cur_str_idx] != '.') {
        return MA_ERR_INVALID_INPUT;
      }
      cur_str_idx++;
      cur_str_len--;
    }

    // convert to a 16-byte int first, so we can tell if we would overflow an 8-byte int
    uint16_t tmp_digit = 0;

    size_t j = cur_str_idx;
    for (; '0' <= str[j] && str[j] <= '9'; j++) {
      // don't accept non-zero digits with leading zeros
      if ((cur_str_idx - j) > 0 && str[cur_str_idx] == '0') {
        return MA_ERR_INVALID_INPUT;
      }
      tmp_digit = (uint16_t)(tmp_digit * 10 + (uint8_t)str[j] - '0');
      if (tmp_digit > 0xFF) {
        return MA_ERR_INVALID_INPUT;
      }
    }

    // no digit was read
    if (j == cur_str_idx) {
      return MA_ERR_INVALID_INPUT;
    }

    cur_str_len -= j - cur_str_idx;
    cur_str_idx = j;

    if (bytes != NULL) {
      bytes[i] = (uint8_t)tmp_digit;
    }
  }

  return MA_ERR_OK;
}

static ma_err ip4_validate_str(const struct proto* p, const char* const str, size_t str_len) {
  return ip4_str_to_bytes(p, str, str_len, NULL, NULL);
}

static ma_err ip4_bytes_to_str(const struct proto* p, const uint8_t* const bytes, size_t bytes_size, char* str, size_t* str_len) {
  (void)p;
  if (bytes_size != 4) {
    return MA_ERR_INVALID_INPUT;
  }

  // max size is xxx.xxx.xxx.xxx\0 = 16
  char buf[16] = {0};
  int chars = snprintf(buf, 16, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
  if (chars < 0 || chars >= 16) {
    return MA_ERR_INVALID_INPUT;
  }

  if (str != NULL) {
    memcpy(str, buf, (size_t)chars);
  }
  if (str_len != NULL) {
    *str_len = (size_t)chars;
  }

  return MA_ERR_OK;
}

static ma_err ip4_validate_bytes(const struct proto* p, const uint8_t* const bytes, size_t bytes_size) {
  return ip4_bytes_to_str(p, bytes, bytes_size, NULL, NULL);
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
    .validate_str = &valid_validate_str,
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
    .bytes_to_str = &port_bytes_to_str,
    .str_to_bytes = &port_str_to_bytes,
    .validate_bytes = &port_validate_bytes,
    .validate_str = &port_validate_str,
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
    .bytes_to_str = &ip4_bytes_to_str,
    .str_to_bytes = &ip4_str_to_bytes,
    .validate_bytes = &ip4_validate_bytes,
    .validate_str = &ip4_validate_str,
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

static ma_err ma_bytes_encode_comp(const ma_bytes_comp* const comp, uint8_t* const bytes, size_t* bytes_size) {
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
      varint_err verr = uint64_to_varint(comp->value_size, varint, &varint_size);
      if (verr) {
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
    ma_err err = ma_bytes_encode_comp(&comps[i], comp_bytes, &size);
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
    return MA_ERR_INVALID_INPUT;
  }

  return MA_ERR_OK;
}

// Reads the next multiaddr element from a string.
//
// This considers a multiaddr like '//' to be valid (in that case it will read two elements with elem_len=0).
static ma_err ma_str_decode_next_elem(ma_str_decoder* const decoder, const char** elem_start, size_t* const elem_len) {
  if (decoder->done) {
    return MA_ERR_INVALID_INPUT;
  }
  size_t s_start = decoder->cur_char;
  const char* e_start = decoder->multiaddr + s_start;

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

  //  if (e_start[0] == '\0') {
  if (s_start == decoder->multiaddr_len) {
    decoder->done = true;
  }

  return MA_ERR_OK;
}

ma_err ma_str_decode_next(ma_str_decoder* const decoder, ma_str_comp* const comp) {
  char* elem_start = NULL;
  size_t elem_len = 0;

  ma_err err = ma_str_decode_next_elem(decoder, (const char**)&elem_start, &elem_len);
  if (err) {
    return err;
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
    decoder->done = true;
  } else {
    // there must be another element at this point, so read it
    err = ma_str_decode_next_elem(decoder, (const char**)&elem_start, &elem_len);
    if (err) {
      return err;
    }
    comp->value = elem_start;
    comp->value_len = elem_len;
  }

  err = proto->validate_str(proto, comp->value, comp->value_len);
  if (err) {
    return err;
  }

  return MA_ERR_OK;
}

static ma_err ma_str_encode_comp(const ma_str_comp* const comp, char* const str, size_t* str_len) {
  const ma_proto* proto = NULL;
  ma_err err = ma_proto_by_code(comp->proto_code, &proto);
  if (err) {
    return err;
  }

  err = proto->validate_str(proto, comp->value, comp->value_len);
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
    ma_err err = ma_str_encode_comp(&comps[i], comp_str, &len);
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
  while (!decoder.done) {
    // read next component
    ma_err err = ma_str_decode_next(&decoder, &cur_comp);
    if (err) {
      return err;
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
      varint_err verr = uint64_to_varint(size, varint, &varint_size);
      if (verr) {
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

  return MA_ERR_OK;
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
