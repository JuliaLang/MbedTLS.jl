#!/bin/sh

if ! cmake --version > /dev/null 2>&1; then
  echo "cmake command not found. installing cmake is required for building from source."
  exit 1
fi
