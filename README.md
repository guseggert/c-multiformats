This is a C implementation of [multiformats](https://github.com/multiformats/multiformats).

Its goal is to be a portable implementation that can be reused across as many programming languages, operating systems, and architectures as possible.

Current feature list:

* [x] uint64 [varint](https://github.com/multiformats/unsigned-varint)
* [x] [multibase](https://github.com/multiformats/multibase)
  * [x] identity
  * [x] base2
  * [x] base16
  * [x] base16upper
  * [x] base32
  * [x] base32upper
  * [x] base58btc
  * [x] base64
  * [x] base64url
  * [ ] base64pad
* [x] [multihash](https://github.com/multiformats/multihash)
  * [x] identity
  * [x] sha1
  * [x] sha2-256
  * [x] sha2-512
  * [x] sha3-512
  * [x] sha3-384
  * [x] sha3-256
  * [x] sha3-224
  * [x] sha2-384
  * [x] murmur3-x64-64
  * [x] sha2-256-trunc254-padded
  * [x] sha2-224
  * [x] sha2-512-224
  * [x] sha2-512-256
  * [ ] poseidon-bls12_381-a2-fc1
* [x] [cidv0](https://github.com/multiformats/cid#cidv0)
* [x] [cidv1](https://github.com/multiformats/cid#cidv1)
* [ ] [multiaddr](https://github.com/multiformats/multiaddr)

This is also run through extensive static and dynamic analysis, including:

* Address Sanitizer, Leak Sanitizer, Memory Sanitizer, Thread Sanitizer, Undefined Behavior Sanitizer
* Valgrind
* Fuzz testing using libfuzzer

## Dependencies
- Runtime
  - Libgcrypt (for multihash)
- Build/Test
  - CMake
  - cmocka
  - Clang
  - include-what-you-use
  - clang-tidy
  - clang-format

## Building
Clang is recommended but GCC can also be used.

```
cmake . -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang
make
```

## Contributing
Contributions are greatly appreciated. If something doesn't work for you, please open an issue (and if you can, help fix it!).
