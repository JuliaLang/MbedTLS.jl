#!/bin/sh
set -e
# meant to be run from deps/ directory to satisfy build.jl
if ! cmake --version > /dev/null 2>&1; then
  echo "cmake command not found. installing cmake is required for building from source."
  exit 1
fi

mkdir -p usr/lib
cd mbedtls-$VERSION
cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
make lib
cd ..
cp mbedtls-$VERSION/library/libmbedtls.* usr/lib/
cp mbedtls-$VERSION/library/libmbedcrypto.* usr/lib/
cp mbedtls-$VERSION/library/libmbedx509.* usr/lib/