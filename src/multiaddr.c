#include "multiaddr.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Reads the next multiaddr element from a string.
//
// Upon return:
// str_start is set to the offset of str that is the beginning of the next element (including forward slash)
// elem_start is set to the beginning of the element that was read (excluding forward slash)
// elem_len is set to the length of the element that was read
//
// The elem_start char array is NOT a null-terminated string, it's a pointer into str.
//
// If the end of str is reached (null terminator), elem_start is set to null.
//
// This considers a multiaddr like '//' to be valid (in that case it will read two elements with elem_len=0).
static ma_err next_str_elem(const char* const str, size_t* str_start, const char** elem_start, size_t* const elem_len) {
  const char* e_start = str + *str_start;
  size_t s_start = *str_start;

  if (e_start[0] == '\0') {
    *elem_start = NULL;
    return MA_ERR_OK;
  }
  if (e_start[0] != '/') {
    return MA_ERR_INVALID_INPUT;
  }

  s_start++;
  e_start++;

  size_t len = 0;

  for (; e_start[len] != '\0' && e_start[len] != '/'; len++, s_start++) {
  }

  *elem_start = e_start;
  *str_start = s_start;
  *elem_len = len;

  return MA_ERR_OK;
}

static bool bytes_eql(const char* a, size_t a_len, const char* b, size_t b_len) {
  if (a_len != b_len) {
    return false;
  }
  for (size_t i = 0; i < a_len; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

// protocol definitions, these are defined in reverse order as they also form a linked list
const ma_proto ma_proto_unix = {
    .name = "unix",
    .name_len = 4,
    .code = MA_PROTO_CODE_UNIX,
    .code_varint = (uint8_t[]){0x90, 0x03},
    .code_varint_len = 2,
    .size = -1,
    .path = true,
    .next = NULL,
};
const ma_proto ma_proto_tcp = {
    .name = "tcp",
    .name_len = 3,
    .code = MA_PROTO_CODE_TCP,
    .code_varint = (uint8_t[]){0x06},
    .code_varint_len = 1,
    .size = 16,
    .path = false,
    .next = &ma_proto_unix,
};
const ma_proto ma_proto_ip4 = {
    .name = "ip4",
    .name_len = 3,
    .code = MA_PROTO_CODE_IP4,
    .code_varint = (uint8_t[]){0x04},
    .code_varint_len = 1,
    .size = 32,
    .path = false,
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

ma_err ma_proto_by_name(const char* name, size_t name_len, const ma_proto** proto) {
  const ma_proto* cur = protos;
  while (cur != NULL) {
    if (bytes_eql(name, name_len, cur->name, cur->name_len)) {
      *proto = cur;
      return MA_ERR_OK;
    }
    cur = cur->next;
  }
  return MA_ERR_UNKNOWN_PROTOCOL;
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

ma_err ma_comp_str_len(ma_comp* comp, size_t* len) {
  const ma_proto* proto = NULL;
  ma_err err = ma_proto_by_code(comp->proto, &proto);
  if (err) {
    return err;
  }

  *len = 3 + proto->name_len + comp->value_len;  // first slash, second slash, null term => 3

  if (proto->path) {
    // path values include the forward slash, which we counted twice, so decrement to only count once
    // path values are relatively rare
    (*len)--;
  }

  return MA_ERR_OK;
}

ma_err ma_comp_str(ma_comp* comp, char* str) {
  size_t idx = 0;
  str[idx++] = '/';
  const ma_proto* proto = NULL;
  ma_err err = ma_proto_by_code(comp->proto, &proto);
  if (err) {
    return err;
  }
  memcpy(str + idx, proto->name, proto->name_len);
  idx += proto->name_len;

  if (!proto->path) {
    // path values have leading forward slashes
    str[idx++] = '/';
  }

  memcpy(str + idx, comp->value, comp->value_len);

  return MA_ERR_OK;
}

ma_err ma_comps_str_len(ma_comp* comps, size_t comps_len, size_t* len) {
  size_t size = 0;
  for (size_t i = 0; i < comps_len; i++) {
    size_t comp_str_len = 0;
    ma_err err = ma_comp_str_len(&comps[i], &comp_str_len);
    if (err) {
      return err;
    }
    size += (comp_str_len - 1);  // don't count null term on individual components
  }
  *len = size + 1;  // null term
  return MA_ERR_OK;
}

ma_err ma_comps_str(ma_comp* comps, size_t comps_len, char* str) {
  size_t idx = 0;
  for (size_t i = 0; i < comps_len; i++) {
    size_t comp_str_len = 0;
    ma_err err = ma_comp_str_len(&comps[i], &comp_str_len);
    if (err) {
      return err;
    }
    err = ma_comp_str(&comps[i], str + idx);
    if (err) {
      return err;
    }
    idx += (comp_str_len - 1);  // don't count null term
  }
  str[idx] = '\0';
  return MA_ERR_OK;
}

ma_err ma_str_next_comp(ma_str_parse_state* state, ma_comp* comp) {
  if (state->done) {
    return MA_ERR_OK;
  }

  // clear the component struct
  memset(comp, 0, sizeof(ma_comp));

  const char* elem_start = NULL;
  size_t elem_len = 0;

  ma_err err = next_str_elem(state->multiaddr, &state->cur_char, &elem_start, &elem_len);
  if (err) {
    return err;
  }
  // there are no more elements, we've reached the end of the multiaddr
  if (elem_start == NULL) {
    state->done = true;
    return MA_ERR_OK;
  }

  // lookup the protocol
  const ma_proto *proto = NULL;
  err = ma_proto_by_name(elem_start, elem_len, &proto);
  if (err) {
    return err;
  }

  if (proto->size == 0) {
    return MA_ERR_OK;
  }

  comp->proto = proto->code;

  // read the next element
  err = next_str_elem(state->multiaddr, &state->cur_char, &elem_start, &elem_len);
  if (err) {
    return err;
  }
  if (elem_start == NULL) {
    return MA_ERR_INVALID_INPUT;
  }

  comp->value = elem_start;

  if (proto->path) {
    // this is a path protocol, so the component value is the rest of the muiltiaddr
    // note that we don't validate the path here
    size_t multiaddr_len = strlen(state->multiaddr);
    // include '/' at the start of the path, which is less surprising
    comp->value_len = (multiaddr_len - state->cur_char) + elem_len + 1;
    comp->value -= 1;
    state->cur_char = multiaddr_len;
    return MA_ERR_OK;
  }

  comp->value_len = elem_len;

  return MA_ERR_OK;
}
