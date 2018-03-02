#!/bin/sh
# meant to be run from deps/ directory to satisfy build.jl
if ! cmake --version > /dev/null 2>&1; then
  echo "cmake command not found. installing cmake is required for building from source."
  exit 1
fi

git clone https://github.com/ARMmbed/mbedtls.git
VERSION="2.7.1"
git checkout mbedtls-$VERSION
cd mbedtls/
cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
make lib
cd ..
mkdir -p usr/lib
cp mbedtls/library/libmbed*.* usr/lib/