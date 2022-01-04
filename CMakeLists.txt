cmake_minimum_required(VERSION 3.20)
project(c-multiformats LANGUAGES C)

include(deps/CMakeLists.txt)

set(CMAKE_C_STANDARD_REQUIRED on)
set(C_STANDARD 11)

enable_testing()

string(APPEND CMAKE_C_FLAGS " -Wall -Wextra -fstack-protector-all -Wstack-protector -Wshadow -Wdouble-promotion -Wformat=2 -Wformat-security -Wundef -fno-common -pedantic -D_POSIX_C_SOURCE=201112L")
string(APPEND CMAKE_C_FLAGS_DEBUG " -O0 -g -fno-omit-frame-pointer -ftrapv")
string(APPEND CMAKE_C_FLAGS_RELEASE " -D_FORTIFY_SOURCE=2 -O3")
string(APPEND CMAKE_LINKER_FLAGS_RELEASE " -shared -Wl,-z,defs -Wl,-z,now")
string(APPEND CMAKE_LINKER_FLAGS_DEBUG " -fno-omit-frame-pointer")
string(APPEND CMAKE_EXE_LINKER_FLAGS_DEBUG " -fno-omit-frame-pointer")

set(
  CMAKE_C_CLANG_TIDY
  clang-tidy;
  -config-file=.clang-tidy;
)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  string(APPEND CMAKE_C_FLAGS_RELEASE " -fanalyzer -Wformat-truncation=2 -Wformat-overflow=2")
endif()

if(IWYU)
  find_program(iwyu include-what-you-use)
  if(iwyu)
    set(CMAKE_C_INCLUDE_WHAT_YOU_USE "${iwyu};-Xiwyu;--no_fwd_decls")
  endif()
endif()

add_library(
  multibase
  SHARED
  ./include/multibase.h
  ./src/multibase.c
)
set_target_properties(multibase PROPERTIES VERSION 1)
set_target_properties(multibase PROPERTIES SOVERSION 1)
set_target_properties(multibase PROPERTIES PUBLIC_HEADER include/multibase.h)
target_include_directories(multibase PUBLIC include)
target_compile_options(multibase PRIVATE -Werror -Wconversion)

add_library(
  multihash
  SHARED
  ./include/multihash.h
  ./src/multihash.c
)
set_target_properties(multihash PROPERTIES VERSION 1)
set_target_properties(multihash PROPERTIES SOVERSION 1)
set_target_properties(multihash PROPERTIES PUBLIC_HEADER include/multihash.h)
target_include_directories(multihash PUBLIC include deps/murmur3)
target_link_libraries(multihash PUBLIC multibase varint murmur3)
target_compile_options(multihash PRIVATE -Werror -Wconversion)

# configure the multihash crypto backend

if(MH_BACKEND_OPENSSL)
  include(FindPkgConfig)
  pkg_check_modules(openssl REQUIRED IMPORTED_TARGET openssl)
  add_compile_definitions(MH_BACKEND_OPENSSL)
  target_link_libraries(multihash PUBLIC PkgConfig::openssl)
elseif(MH_BACKEND_MBED)
  add_compile_definitions(MH_BACKEND_MBED)
  target_link_libraries(multihash PUBLIC mbedtls)
elseif(MH_BACKEND_GCRYPT)
  add_compile_definitions(MH_BACKEND_GCRYPT)
  target_link_libraries(multihash PUBLIC gcrypt)
endif()

add_library(
  varint
  SHARED
  ./include/varint.h
  ./src/varint.c
)
set_target_properties(varint PROPERTIES VERSION 1)
set_target_properties(varint PROPERTIES SOVERSION 1)
set_target_properties(varint PROPERTIES PUBLIC_HEADER include/varint.h)
target_include_directories(varint PRIVATE include)
target_compile_options(varint PRIVATE -Werror -Wconversion)

add_library(
  cid
  SHARED
  ./include/cid.h
  ./src/cid.c
)
set_target_properties(cid PROPERTIES VERSION 1)
set_target_properties(cid PROPERTIES SOVERSION 1)
set_target_properties(cid PROPERTIES PUBLIC_HEADER include/cid.h)
target_include_directories(cid PRIVATE include)
target_compile_options(cid PRIVATE -Werror -Wconversion)
target_link_libraries(cid multibase multihash varint)

add_library(
  multiaddr
  SHARED
  ./include/multiaddr.h
  ./src/multiaddr.c
)
set_target_properties(multiaddr PROPERTIES VERSION 1)
set_target_properties(multiaddr PROPERTIES SOVERSION 1)
set_target_properties(multiaddr PROPERTIES PUBLIC_HEADER include/cid.h)
target_include_directories(multiaddr PRIVATE include)
target_compile_options(multiaddr PRIVATE -Werror -Wconversion)
target_link_libraries(multiaddr varint)

add_executable(run-tests ./test/main.c)
target_link_libraries(run-tests cmocka multibase multihash varint cid multiaddr m)
target_include_directories(run-tests PRIVATE include)
target_compile_options(run-tests PRIVATE -Werror -Wconversion)

add_executable(run-tests-asan ./test/main.c)
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  target_compile_options(
    run-tests-asan PRIVATE
    -fsanitize=address,undefined,nullability,integer
    -fno-optimize-sibling-calls
    -fsanitize-address-use-after-scope
    -fno-omit-frame-pointer
    -Werror
    -Wconversion
  )
  target_link_options(
    run-tests-asan PRIVATE
    -fsanitize=address,undefined,nullability
    -g
  )
else()
  target_compile_options(
    run-tests-asan PRIVATE
    -fsanitize=address,undefined
    -fno-optimize-sibling-calls
    -fsanitize-address-use-after-scope
    -fno-omit-frame-pointer
    -Werror
    -Wconversion
  )
  target_link_options(
    run-tests-asan PRIVATE
    -fsanitize=address,undefined
    -g
  )
endif()

target_link_libraries(run-tests-asan cmocka multibase multihash varint cid multiaddr m)
target_include_directories(run-tests-asan PRIVATE include)

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  add_executable(run-tests-msan ./test/main.c)
  target_compile_options(run-tests-msan PRIVATE -fsanitize=memory -g -O1 -Werror -Wconversion)
  target_link_options(run-tests-msan PRIVATE -fsanitize=memory -g)
  target_link_libraries(run-tests-msan cmocka multibase multihash varint cid multiaddr m)
  target_include_directories(run-tests-msan PRIVATE include)
endif()

add_executable(run-tests-tsan ./test/main.c)
target_compile_options(run-tests-tsan PRIVATE -fsanitize=thread -g -O1 -Werror -Wconversion)
target_link_options(run-tests-tsan PRIVATE -fsanitize=thread -g)
target_link_libraries(run-tests-tsan cmocka multibase multihash varint cid multiaddr m)
target_include_directories(run-tests-tsan PRIVATE include)

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  add_executable(fuzz-asan ./test/fuzz.c)
  target_compile_options(fuzz-asan PRIVATE -fsanitize=fuzzer,address -g -O1 -Werror -Wconversion)
  target_link_options(fuzz-asan PRIVATE -fsanitize=fuzzer,address -g)
  target_link_libraries(fuzz-asan multibase multihash varint cid multiaddr m)
  target_include_directories(fuzz-asan PRIVATE include)

  # used for running fuzzer with valgrind, since valgrind and asan don't play nicely
  add_executable(fuzz ./test/fuzz.c)
  target_compile_options(fuzz PRIVATE -fsanitize=fuzzer -g -O1 -Werror -Wconversion)
  target_link_options(fuzz PRIVATE -fsanitize=fuzzer -g)
  target_link_libraries(fuzz multibase multihash varint cid multiaddr m)
  target_include_directories(fuzz PRIVATE include)
endif()

add_test(NAME test COMMAND run-tests-asan)

add_executable(mf ./src/cli.c)
target_include_directories(mf PRIVATE include)
target_link_libraries(mf varint multibase multihash cid multiaddr)
target_compile_options(mf PRIVATE -Werror -Wconversion)
