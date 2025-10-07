#!/bin/bash

echo "Building Module Stomping..."

mkdir -p build

echo "Compiling shellcode generator..."
gcc -O2 -o build/generate_shellcode.exe src/generate_shellcode.c

if [ $? -ne 0 ]; then
    echo "Failed to build shellcode generator!"
    exit 1
fi

echo "Compiling module stomping injector..."
gcc -O2 -municode -o build/module_stomping.exe src/module_stomping.c -lpsapi

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo ""
    echo "Executables:"
    echo "  - build/module_stomping.exe"
    echo "  - build/generate_shellcode.exe"
else
    echo "Build failed!"
    exit 1
fi
