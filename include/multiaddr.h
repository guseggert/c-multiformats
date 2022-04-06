#ifndef MULTIADDR_H
#define MULTIADDR_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint8_t ma_err;
#define MA_ERR_OK 0
#define MA_ERR_UNKNOWN_PROTOCOL 1
#define MA_ERR_INVALID_INPUT 2

const char* ma_err_str(ma_err err);

typedef uint64_t ma_proto_code;
#define MA_PROTO_CODE_IP4 0x0004
#define MA_PROTO_CODE_TCP 0x0006
#define MA_PROTO_CODE_UNIX 0x0190

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
// The optional second element is the "protocol value". Its existence and exact value depends on the protocol id.
//
// Finally, a multiaddr is a sequence of components.
//
// Examples of valid multiaddrs:
//
// /proto1/val1/proto2/val2  ("/proto1/val1" is a component made of elements "/proto1" and "/val1")
//
// /proto1  (assuming proto1 is defined to not have a protocol value)
//
// /proto1/path/for/proto1
// Assuming proto1 is defined to have a "path value", this component's value is the element "/path/for/proto1".
// A multiaddr can only have a single path-valued component, and it is always the last component of a multiaddr.
//
// /proto1/path/for/proto1/proto2/val1
// This multiaddr only has a single component with a value /path/for/proto1/proto2/val1.
// Although it looks like it has two components, because the first component has a path value, everything after it
// is included as its value.
//
//
// Multiaddr byte encodings use varints to separate components, instead of slashes. Some protocols encode
// their values differently when byte-encoded, while some use ASCII encoding for both byte and string encodings.
// For example, IPv4 addresses are string-encoded as "127.0.0.1" but byte-encoded as 4 8-bit integers. The string
// encoding is variable-size, while the byte encoding's size is known a priori.
//
// Each byte-encoded component is one of the following forms:
// - <varint_protocol_code>  (no value)
// - <varint_protocol_code><value_bytes>  (constant-size value)
// - <varint_protocol_code><varint_value_size><value_bytes>  (variable-size value)
//
// When relevant, bytes are always output with big endian encoding, and input assumes big endian encoding.
//
// This implementation is organized into a set of functions for byte-encoded multiaddrs,
// functions for string-encoded multiaddrs, and functions to convert between the two. This
// design is mainly to facilitate avoiding dynamic heap allocations, since the relationship
// between string and byte encodings are not known statically.
/**
 * Defines a protocol with the information needed to encode and decode it as part of a multiaddr.
 */
typedef struct proto {
  const ma_proto_code code;
  // A varint representation of the code
  const uint8_t* const code_varint;
  // The size of @code_varint
  const size_t code_varint_size;
  // The name of the protocol, used in the string encoding
  const char* const name;
  // The length of @name, not including the null terminator, i.e. as returned by strlen()
  const size_t name_len;
  // True if there are values for this protocol. If false, the other value fields are ignored.
  const bool has_value;
  // True if values for this protocol are constant-sized. If false, they are assumed to be variable-sized.
  const bool val_is_constant_size;
  // The size in bytes of byte-encoded values. This is ignored if values are variable-sized.
  const size_t val_size;
  // True if values are paths
  const bool val_is_path;
  // The next protocol in the protocol list, generally you should set to NULL for custom protos and then register with @ma_add_proto()
  const struct proto* next;
  // Converts a string-encoded component value to a byte-encoded component value for the given protocol
  ma_err (*const str_to_bytes)(const struct proto* p, const char* str, size_t str_len, uint8_t* bytes, size_t* bytes_size);
  // Converts a byte-encoded component value to a string-encoded component value
  ma_err (*const bytes_to_str)(const struct proto* p, const uint8_t* bytes, size_t bytes_size, char* str, size_t* str_len);
  // Validate the given byte component value for the given protocol
  ma_err (*const validate_bytes)(const struct proto* p, const uint8_t* bytes, size_t bytes_size);
  // Validate the given string component value for the given protocol
  ma_err (*const validate_str)(const struct proto* p, const char* str, size_t str_len);

} ma_proto;

extern const ma_proto ma_proto_unix;
extern const ma_proto ma_proto_tcp;
extern const ma_proto ma_proto_ip4;
extern const ma_proto* protos;  // NOLINT

/**
 * Registers a protocol at the front of the list.
 */
ma_err ma_add_proto(ma_proto* proto);

ma_err ma_proto_by_name(const char* name, const ma_proto** proto);

ma_err ma_proto_by_code(ma_proto_code code, const ma_proto** proto);

/**
 * A multiaddr byte-encoded component.
 */
typedef struct {
  ma_proto_code proto_code;
  uint8_t* value;
  size_t value_size;
} ma_bytes_comp;

/**
 * A multiaddr byte decoder.
 *
 * @multiaddr is the multiaddr to decode, which should be set by the caller.
 *
 * @cur_byte contains the offset of the current byte to decode, which is updated by each
 * call to ma_bytes_decode_next(). It should not be mutated by the caller.
 *
 * @done signals to the caller when the decoder is finished decoding the @multiaddr bytes.
 */
typedef struct {
  const uint8_t* const multiaddr;
  const size_t multiaddr_size;

  size_t cur_byte;
  bool done;
} ma_bytes_decoder;

/**
 * Decodes the next component of a byte-encoded multiaddr.
 *
 * Call this repeatedly to iterate over the components of a multiaddr.
 *
 * @decoder.done is set to true when there are no more components in the multiaddr.
 */
ma_err ma_bytes_decode_next(ma_bytes_decoder* decoder, ma_bytes_comp* comp);

/**
 * Converts a list of byte-encoded components into a byte-encoded multiaddr.
 *
 * If @str is NULL, it is not set and only the size @str_bytes_size is computed.
 *
 * If @str_bytes_size is not NULL, it is set to the number of bytes of the string representation, including the null terminator.
 *
 * This is useful for "encapsulating" or "decapsulating" a protocol from a multiaddr. E.g. if you want to remove the last protocol in a
 * multiaddr string, construct a list of components @comps using @ma_str_next_comp() that excludes the last protocol, and pass that list
 * to this function to convert it back into a multiaddr.
 */
ma_err ma_bytes_encode(const ma_bytes_comp* comps, size_t comps_size, uint8_t* bytes, size_t* bytes_size);

/**
 * A multiaddr string-encoded component.
 */
typedef struct {
  ma_proto_code proto_code;
  char* value;
  size_t value_len;
} ma_str_comp;

/**
 * A multiaddr string decoder.
 *
 * @multiaddr is the null-terminated multiaddr to decode, which should be set by the caller.
 *
 * @cur_char contains the offset of the current char to decode, which is updated by each
 * call to ma_str_decode_next(). It should not be mutated by the caller.
 *
 * @done signals to the caller when the decoder is finished decoding the @multiaddr string.
 */
typedef struct {
  const char* const multiaddr;
  const size_t multiaddr_len;

  size_t cur_char;
  bool done;
} ma_str_decoder;

/**
 * Decodes the next component of a string-encoded multiaddr.
 *
 * Call this repeatedly to iterate over the components of a multiaddr.
 *
 * @decoder.done is set to true when there are no more components in the multiaddr.
 */
ma_err ma_str_decode_next(ma_str_decoder* decoder, ma_str_comp* comp);

/**
 * Converts a list of string-encoded components into a string-encoded multiaddr.
 *
 * If @str is NULL, it is not set and only the size @str_size is computed.
 *
 * If @str_len is not NULL, it is set to the length of the string representation.
 */
ma_err ma_str_encode(const ma_str_comp* comps, size_t comps_size, char* str, size_t* str_len);

/**
 * Converts a string-encoded multiaddr @str to a byte-encoded multiaddr.
 *
 * If @bytes is NULL, it is not set and only the size is computed and set on @bytes_size.
 */
ma_err ma_str_to_bytes(const char* str, size_t str_len, uint8_t* bytes, size_t* bytes_size);

/**
 * Converts a byte-encoded multiaddr into a string-encoded multiaddr.
 *
 * If @str is NULL, it is not set and only the size is computed and set on @str_size.
 */
ma_err ma_bytes_to_str(const uint8_t* bytes, size_t bytes_size, char* str, size_t* str_len);
#endif
