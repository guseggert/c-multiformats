#!/bin/bash

set -e

dump_and_fail_if_exists() {
    if [[ -f "$1" ]]; then
	echo
	cat "$1"
	echo
	echo "FAILED"
	exit 1
    fi
}

mkdir -p build/tests
cd build/tests

cp ../../.clang-tidy .

# build with GCC
cmake -B . -S ../.. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gcc
make

# gcc tests w/ valgrind
valgrind -s --track-origins=yes ./run-tests

# build with clang & static analysis
scan-build cmake -B . -S ../.. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang
scan-build make

# clang tests w/ valgrind
valgrind -s --track-origins=yes ./run-tests

export ASAN_OPTIONS=suppressions=../../asan.supp:log_path=asan:symbolize=1
ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)
export ASAN_SYMBOLIZER_PATH

# tests w/ asan
./run-tests-asan &
pid=$!
wait $pid
dump_and_fail_if_exists "asan.log.$pid"

# tests w/ msan
./run-tests-msan &
pid=$!
wait $pid
dump_and_fail_if_exists "asan.log.$pid"

# tests w/ tsan
./run-tests-tsan &
pid=$!
wait $pid
dump_and_fail_if_exists "asan.log.$pid"

# fuzz w/ asan
./fuzz-asan -max_total_time=5 -workers=10 -jobs=10 ../../test/corpus
# fuzz w/ valgrind
valgrind ./fuzz -max_total_time=5 ../../test/corpus

echo
echo "PASSED"
