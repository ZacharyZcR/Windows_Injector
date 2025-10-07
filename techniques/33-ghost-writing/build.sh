#!/bin/bash

echo "========================================="
echo "GhostWriting Injection - Build Script"
echo "========================================="
echo ""
echo "NOTE: GhostWriting is a 32-bit technique."
echo "This script requires a 32-bit compiler (i686-w64-mingw32-gcc)."
echo ""

# Check if 32-bit compiler exists
if command -v i686-w64-mingw32-gcc &> /dev/null; then
    echo "[*] Using i686-w64-mingw32-gcc..."
    i686-w64-mingw32-gcc src/ghost_writing.c \
        -o ghost_writing.exe \
        -luser32 \
        -O2 \
        -Wall
else
    echo "[!] 32-bit compiler not found."
    echo "[*] Attempting to compile with gcc -m32..."
    echo ""

    gcc src/ghost_writing.c \
        -o ghost_writing.exe \
        -luser32 \
        -m32 \
        -O2 \
        -Wall
fi

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Build successful: ghost_writing.exe"
    echo ""
    echo "Usage:"
    echo "  ./ghost_writing.exe"
    echo ""
    echo "This will inject into Explorer.exe's shell window thread."
else
    echo ""
    echo "[-] Build failed!"
    echo ""
    echo "This technique requires a 32-bit Windows compiler."
    echo "Please install i686-w64-mingw32-gcc or use a 32-bit MinGW environment."
    echo ""
    echo "Source code is available in src/ghost_writing.c for reference."
    exit 1
fi
