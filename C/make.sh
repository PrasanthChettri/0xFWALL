#!/bin/bash
mkdir -p ./target

clang -O2 -g -target bpf -c kernel.c -o ./target/kernel.o
clang -O2 -g -c loader.c -o loader.o
ar rcs ./target/libloader.a loader.o
rm loader.o

echo "Build complete: kernel.o and libloader.a stored in ./target"