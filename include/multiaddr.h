#ifndef MULTIADDR_H
#define MULTIADDR_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
  MA_ERR_OK = 0,
  MA_ERR_UNKNOWN_PROTOCOL,
  MA_ERR_INVALID_INPUT,
  MA_ERR_INVALID_INPUT_EMPTY,
  MA_ERR_INVALID_INPUT_BEGIN_SLASH,
} ma_err;

static const char* const MA_ERR_STRS[] = {
    "no error",
    "unknown protocol",
    "invalid multiaddr input",
    "invalid multiaddr input: empty",
    "invalid multiaddr input: must begin with /",
};

typedef uint64_t ma_proto_code;
const ma_proto_code MA_PROTO_CODE_IP4 = 0x0004;
const ma_proto_code MA_PROTO_CODE_TCP = 0x0006;
const ma_proto_code MA_PROTO_CODE_UNIX = 0x0190;

// There are two kinds of encodings for multiaddrs: byte encoding and string encoding
//
//
// String encoding:
//
// Let's define some concepts here that aren't in the multiaddr repo:
//
// An element is any string with a leading '/'.
// This can include subsequent forward slashes, or not.
//
// A component is made up of exactly one or two elements. The first element always contains the protocol id.
// The optional second element is called the "protocol value". Its exact value depends on the protocol id.
//
// A multiaddr is a list of components.
//
// Examples of valid multiaddrs:
//
// /proto1/val1/proto2/val2  ("/proto1/val1" is a component made of elements "/proto1" and "/val1")
//
// /proto1  (this is a component without a protocol value)
//
// /proto1/path/for/proto1
// This is a component whose protocol value is the element "/path/for/proto1".
// This protocol value is a "path".
// A multiaddr can only have a single path, and it is always the last element of a multiaddr.

/**
 * Defines a protocol with the information needed to encode and decode it as part of a multiaddr.
 */
typedef struct proto {
  const ma_proto_code code;
  // A varint representation of the code
  const uint8_t* const code_varint;
  // The length in bytes of @code_varint
  const size_t code_varint_len;
  // A null-terminated string of the name of the protocol, used in the string encoding
  const char* const name;
  // The length of @name, not including the null terminator, i.e. as returned by strlen()
  const size_t name_len;
  // The size in bytes of byte-encoded values
  const size_t size;
  // True if values are paths
  const bool path;
  // The next protocol in the protocol list, generally you should set to NULL for custom protos and then register with @ma_add_proto()
  const struct proto* next;
  // Returns the length in bytes necessary to convert a string-encoded component value to a byte-encoded component value for the given
  // protocol
  ma_err (*const str_to_bytes_len)(struct proto* p, const char* str, size_t str_len, size_t* bytes_len);
  // Converts a string-encoded component value to a byte-encoded component value for the given protocol
  ma_err (*const str_to_bytes)(struct proto* p, const char* str, size_t str_len, uint8_t* bytes);
  // Returns the length in bytes necessary to convert a byte-encoded component value to a string-encoded component value for the given
  // protocol
  ma_err (*const bytes_to_str_len)(struct proto* p, const uint8_t* bytes, size_t bytes_len, size_t* str_len);
  // Converts a byte-encoded component value to a string-encoded component value
  ma_err (*const bytes_to_str)(struct proto* p, const uint8_t* bytes, size_t bytes_len, char* str);
  // Validate the given component value for the given protocol
  ma_err (*const validate_bytes)(struct proto* p, const uint8_t* bytes, size_t bytes_len);
} ma_proto;

extern const ma_proto ma_proto_unix;
extern const ma_proto ma_proto_tcp;
extern const ma_proto ma_proto_ip4;
extern const ma_proto* protos;  // NOLINT

/**
 * Register a protocol at the front of the list.
 */
ma_err ma_add_proto(ma_proto* proto);

/**
 * A multiaddr component. The byte pointers in this struct point to locations in @multiaddr from @ma_parse_state.
 *
 * The @value is not a null-terminated string.
 */
typedef struct {
  ma_proto_code proto;
  const char* value;
  size_t value_len;
} ma_comp;

/**
 * Encodes the state of a byte-encoded multiaddr parser.
 *
 * The caller should initialize the @multiaddr string.
 */
typedef struct {
  const char* const multiaddr;

  size_t cur_char;
  bool done;
} ma_str_parse_state;

/**
 * Parse the next component of a multiaddr string.
 *
 * Call this repeatedly to iterate over the components of a multiaddr. This does not allocate heap memory.
 *
 * @statedone is set to true when there are no more components in the multiaddr.
 */
ma_err ma_str_next_comp(ma_str_parse_state* state, ma_comp* comp);

/**
 * Convert a component into a null-terminated string representation.
 *
 * For a full multiaddr string, these can simply be concatenated.
 */
ma_err ma_comp_str(ma_comp* comp, char* str);

/**
 * Compute the size in bytes @len of the string-encoded form of the given component @comp.
 */
ma_err ma_comp_str_len(ma_comp* comp, size_t* len);

ma_err ma_comps_str(ma_comp* comps, size_t comps_len, char* str);
ma_err ma_comps_str_len(ma_comp* comps, size_t comps_len, size_t* len);

/* ma_err ma_str_to_bytes_len(const char* str, size_t* bytes_len); */
/* ma_err ma_str_to_bytes(const char* str, uint8_t* bytes, size_t bytes_len); */

/* ma_err ma_bytes_to_str_len(const uint8_t* bytes, size_t* str_len); */
/* ma_err ma_bytes_to_str(const uint8_t* bytes, size_t bytes_len, char* str); */
#endif
