#!/bin/sh
set -e
# meant to be run from deps/ directory to satisfy build.jl

g++ -shared -fPIC -Iusr/include/mbedtls helper.cxx -o usr/lib/libhelper.so
