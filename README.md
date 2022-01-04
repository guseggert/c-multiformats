This is a C implementation of [multiformats](https://github.com/multiformats/multiformats).

Its goal is to be a portable implementation that can be reused across as many programming languages, operating systems, and architectures as possible. In addition to running tests locally, I also test this on an STM32 MCU.

This has a design goal of avoiding dynamic heap allocations, so APIs are generally usable with only stack allocations, constant-sized buffers, mem pools, etc. There are currently two exceptions to this: 
* The murmur3-x64-64 hash function, due to limitations of the underlying library
* The OpenSSL multihash backend, due to limitations in OpenSSL

This is under early development and APIs may break or be incomplete.

Current feature list:

* [x] uint64 [varint](https://github.com/multiformats/unsigned-varint)
* [x] [multibase](https://github.com/multiformats/multibase)
  * [x] dynamically register custom encodings
  * [x] identity
  * [x] base2
  * [x] base10
  * [x] base16
  * [x] base16upper
  * [x] base32
  * [x] base32upper
  * [x] base58btc
  * [x] base64
  * [x] base64url
  * [ ] base64pad
* [x] [multihash](https://github.com/multiformats/multihash)
  * [x] dynamically register custom hash fns
  * [x] identity
  * [x] murmur3-x64-64
  * [x] sha2-256-trunc254-padded
	* requires that a sha2-256 implementation is available
  * [x] libgcrypt backend
	* [x] sha1
	* [x] sha2-256
	* [x] sha2-512
	* [x] sha3-512
	* [x] sha3-384
	* [x] sha3-256
	* [x] sha3-224
	* [x] sha2-384
	* [x] sha2-224
	* [x] sha2-512-224
	* [x] sha2-512-256
  * [x] OpenSSL backend
  	* [x] sha1
	* [x] sha2-256
	* [x] sha2-512
	* [x] sha3-512
	* [x] sha3-384
	* [x] sha3-256
	* [x] sha3-224
	* [x] sha2-384
	* [x] sha2-224
	* [x] sha2-512-224
	* [x] sha2-512-256
    * [x] shake-128
    * [x] shake-256
  * [x] Mbed TLS backend
	* [x] sha1
	* [x] sha2-224
	* [x] sha2-256
	* [x] sha2-384
	* [x] sha2-512
  * [ ] wolfSSL backend
  * [ ] poseidon-bls12_381-a2-fc1
  * [ ] blake2b family
  * [ ] blake3
  * [ ] keccak-{224,256,384,512}
* [x] [cidv0](https://github.com/multiformats/cid#cidv0)
* [x] [cidv1](https://github.com/multiformats/cid#cidv1)
* [-] [multiaddr](https://github.com/multiformats/multiaddr)
  * [x] dynamically register custom protocols
  * Protocols
	* [x] IPv4
	* [ ] IPv6
	* [x] TCP
  
This is also run through extensive static and dynamic analysis, including:

* Address Sanitizer, Leak Sanitizer, Memory Sanitizer, Undefined Behavior Sanitizer
* Valgrind
* Fuzz testing using libfuzzer

## Dependencies
- Runtime
  - Libc
- Optional
  - Crypto backends
	- Libgcrypt
	- OpenSSL 1.1
	- Mbed TLS
- Build/Test
  - CMake
  - cmocka
  - Clang-13
  - include-what-you-use
  - clang-tidy
  - clang-format

## Building
Clang is recommended, due to additional static analysis, but GCC is also tested and supported.

```
cmake . -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang
make
```

You can select the crypto backend for multihash with the following settings when running `cmake`:

- `MH_BACKEND_GCRYPT`
- `MH_BACKEND_MBED`
- `MH_BACKEND_OPENSSL`

If no backend is specified, then only the built-in hash functions will be available. You can also use custom crypto backends by registering hash functions at runtime with `mh_add_funcs()`.

## Contributing
Contributions are greatly appreciated. If something doesn't work for you, please open an issue (and if you can, help fix it!).
