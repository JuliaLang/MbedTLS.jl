#!/bin/bash

command -v cmake > /dev/null

if [[ $? -ne 0 ]]; then
  echo "cmake not installed. cmake is required for building from source."
  exit 1
fi
