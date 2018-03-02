#!/bin/sh
# meant to be run from deps/ directory to satisfy build.jl
if ! cmake --version > /dev/null 2>&1; then
  echo "cmake command not found. installing cmake is required for building from source."
  exit 1
fi

pwd
ls
mkdir -p usr/lib
cd mbedtls-$VERSION
cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
make lib
cd ../..
cp mbedtls-$VERSION/library/libmbed*.* usr/lib/