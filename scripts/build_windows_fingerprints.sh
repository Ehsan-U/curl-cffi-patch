#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "$0")/.." && pwd)
work_dir=$(realpath -m "${1:?Usage: build_windows_fingerprints.sh /absolute/build/directory}")
native_source="$work_dir/source"
native_build="$work_dir/build"
native_prefix="$work_dir/install"
archive_dir="$work_dir/archive"

mkdir -p "$work_dir"
if [ -e "$native_source" ]; then
    echo "Use a fresh build directory: $native_source already exists" >&2
    exit 1
fi
curl_chrome145 -fsSL https://github.com/lexiforest/curl-impersonate/archive/refs/tags/v2.2.2.tar.gz -o "$work_dir/source.tar.gz"
mkdir -p "$native_source" "$archive_dir/include"
tar -xf "$work_dir/source.tar.gz" -C "$native_source" --strip-components=1
cat "$project_root/ffi/patches/curl-windows-fingerprints.patch" >> "$native_source/patches/curl.patch"
cat "$project_root/ffi/patches/boringssl-windows-fingerprints.patch" >> "$native_source/patches/boringssl.patch"
cat "$project_root/ffi/patches/ngtcp2-windows-fingerprints.patch" >> "$native_source/patches/ngtcp2.patch"

make -C "$native_source" prepare-libidn2 BUILD_DIR="$native_build" JOBS=4
# Keep CMake's OpenSSL discovery away from the host OpenSSL static dependencies.
export PKG_CONFIG_LIBDIR="$native_build/deps/install/lib/pkgconfig"
cmake -S "$native_source" -B "$native_build" -G Ninja -DCMAKE_INSTALL_PREFIX="$native_prefix" -DSUBJOBS=4
cmake --build "$native_build" --parallel 2
make -C "$native_source" checkbuild BUILD_DIR="$native_build"
cmake --install "$native_build"

libraries=("$native_prefix/lib/libcurl-impersonate.a")
for name in z zstd brotlidec brotlicommon brotlienc nghttp2 nghttp3 ngtcp2 ngtcp2_crypto_boringssl ssl crypto idn2; do
    libraries+=("$native_build/deps/install/lib/lib$name.a")
done
gcc -r -o "$archive_dir/libcurl-impersonate.full.o" \
    -Wl,--whole-archive "${libraries[@]}" -Wl,--no-whole-archive \
    -Wl,--start-group "$(g++ -print-file-name=libstdc++.a)" \
    "$(gcc -print-file-name=libgcc_eh.a)" "$(gcc -print-file-name=libgcc.a)" \
    -Wl,--end-group
ar rcs "$archive_dir/libcurl-impersonate.a" "$archive_dir/libcurl-impersonate.full.o"
cp -a "$native_prefix/include/curl" "$archive_dir/include/"

cd "$project_root"
IMPERSONATE_BUILD_DIR="$archive_dir" IMPERSONATE_LINK_TYPE=static uv pip install --no-cache --reinstall-package curl-cffi-patch -e '.[test,dev,integration]'
