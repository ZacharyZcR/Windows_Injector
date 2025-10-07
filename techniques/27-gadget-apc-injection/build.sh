#!/bin/bash

echo "Building Gadget APC Injection..."

mkdir -p build

echo "Compiling shellcode generator..."
gcc -O2 -o build/generate_shellcode.exe src/generate_shellcode.c

if [ $? -ne 0 ]; then
    echo "Failed to build shellcode generator!"
    exit 1
fi

echo "Compiling gadget APC injector..."
gcc -O2 -o build/gadget_apc_injection.exe src/gadget_apc_injection.c -lpsapi -lntdll

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo ""
    echo "Executables:"
    echo "  - build/gadget_apc_injection.exe"
    echo "  - build/generate_shellcode.exe"
else
    echo "Build failed!"
    exit 1
fi
