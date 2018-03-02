#!/bin/sh
# meant to be run from deps/ directory to satisfy build.jl
if ! cmake --version > /dev/null 2>&1; then
  echo "cmake command not found. installing cmake is required for building from source."
  exit 1
fi

VERSION="2.7.0"

if [ -z "$" ]; then
    wget https://tls.mbed.org/download/mbedtls-$VERSION-apache.tgz
    tar xfz mbedtls-$VERSION-apache.tgz
else
    wget https://tls.mbed.org/download/mbedtls-$VERSION-gpl.tgz
    tar xfz mbedtls-$VERSION-gpl.tgz
fi

cd mbedtls-$VERSION
cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
make lib
cd ..
mkdir -p usr/lib
cp mbedtls-$VERSION/library/libmbed*.* usr/lib/