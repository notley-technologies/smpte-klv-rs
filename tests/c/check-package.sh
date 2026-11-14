#!/usr/bin/env bash
# Build and run installed consumers on Linux or macOS.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
prefix="$work/prefix"
lib="$prefix/lib"
make install PREFIX="$prefix" TARGET_DIR="$work/target"
export PKG_CONFIG_PATH="$lib/pkgconfig"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
test "$(pkg-config --modversion smpte_klv)" = "$version"
header_version=$(awk '/^#define SMPTE_KLV_VERSION_(MAJOR|MINOR|PATCH) / {print $3}' include/smpte_klv.h | paste -sd . -)
test "$header_version" = "$version"
test "$(sed -n 's/^#define SMPTE_KLV_VERSION_STRING "\(.*\)"/\1/p' include/smpte_klv.h)" = "$version"
cmp include/smpte_klv.h "$prefix/include/smpte_klv.h"
cflags=(-std=c99 -Wall -Wextra -Werror -pedantic)
expected='@0 060E2B34020B01010E01030101000000 4 bytes'
case $(uname -s) in
    Linux)
        shared="$lib/libsmpte_klv.so.1"
        test "$(readlink "$lib/libsmpte_klv.so")" = libsmpte_klv.so.1
        readelf -d "$shared" | grep 'SONAME.*\[libsmpte_klv.so.1\]'
        nm -D --defined-only "$shared" | awk '{print $NF}' | sort > "$work/exported"
        ;;
    Darwin)
        shared="$lib/libsmpte_klv.1.dylib"
        test "$(readlink "$lib/libsmpte_klv.dylib")" = libsmpte_klv.1.dylib
        test "$(otool -D "$shared" | tail -1)" = "@rpath/libsmpte_klv.1.dylib"
        nm -gUj "$shared" | sed 's/^_//' | sort > "$work/exported"
        ;;
esac
sed -E -n 's/^[a-z_0-9 *]+ (\*?)(smpte_klv_[a-z_]+)\(.*/\2/p' include/smpte_klv.h | sort > "$work/declared"
diff -u "$work/declared" "$work/exported"
c++ -std=c++11 -Wall -Wextra -Werror -pedantic -x c++ -fsyntax-only "$prefix/include/smpte_klv.h"

# pkg-config --static supplies Rust's native dependencies. Substitute the
# archive for -lsmpte_klv so the linker cannot pick the shared object.
read -r -a shared_flags <<< "$(pkg-config --cflags --libs smpte_klv)"
read -r -a static_flags <<< "$(pkg-config --static --cflags --libs smpte_klv)"
for i in "${!static_flags[@]}"; do
    if [[ ${static_flags[i]} == -lsmpte_klv ]]; then static_flags[i]="$lib/libsmpte_klv.a"; fi
done
for linkage in shared static; do
    if [[ $linkage == shared ]]; then flags=("${shared_flags[@]}" "-Wl,-rpath,$lib"); else flags=("${static_flags[@]}"); fi
    for program in tests/c/abi_test examples/c/klv_encode examples/c/klv_dump; do
        cc "${cflags[@]}" "$program.c" "${flags[@]}" -o "$work/${program##*/}"
    done
    "$work/abi_test"
    "$work/klv_encode" "$work/sample.klv"
    test "$("$work/klv_dump" "$work/sample.klv")" = "$expected"
done
for static in OFF ON; do
    build="$work/cmake-$static"
    cmake -S examples/c -B "$build" -DCMAKE_PREFIX_PATH="$prefix" -DSMPTE_KLV_STATIC="$static"
    cmake --build "$build"
    "$build/klv_encode" "$work/cmake.klv"
    cmp "$work/sample.klv" "$work/cmake.klv"
    test "$("$build/klv_dump" "$work/cmake.klv")" = "$expected"
done
make uninstall PREFIX="$prefix"
test -z "$(find "$prefix" \( -type f -o -type l \) -print)"
