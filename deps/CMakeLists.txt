cmake_minimum_required(VERSION 3.20)
project(c-multiformats LANGUAGES C)

add_library(
  murmur3
  SHARED
  ./deps/murmur3/murmur3.h
  ./deps/murmur3/murmur3.c
)
set_target_properties(murmur3 PROPERTIES CXX_CLANG_TIDY "")
set_target_properties(murmur3 PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES $<TARGET_PROPERTY:murmur3,INTERFACE_INCLUDE_DIRECTORIES>)
target_compile_options(murmur3 PRIVATE -Wno-all -Wno-extra)
