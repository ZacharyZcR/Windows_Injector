#!/bin/bash

echo "=========================================="
echo "GhostWriting-2 Injection - Build Script"
echo "=========================================="
echo ""
echo "NOTE: GhostWriting-2 is a 32-bit technique."
echo "This script requires a 32-bit compiler (i686-w64-mingw32-gcc)."
echo ""

# Check if 32-bit compiler exists
if command -v i686-w64-mingw32-gcc &> /dev/null; then
    echo "[*] Using i686-w64-mingw32-gcc..."
    i686-w64-mingw32-gcc src/ghost.c \
        -o ghostwriting2.exe \
        -O2 \
        -Wall
else
    echo "[!] 32-bit compiler not found."
    echo "[*] Attempting to compile with gcc -m32..."
    echo ""

    gcc src/ghost.c \
        -o ghostwriting2.exe \
        -m32 \
        -O2 \
        -Wall
fi

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Build successful: ghostwriting2.exe"
    echo ""
    echo "Usage:"
    echo "  ./ghostwriting2.exe <thread_id>"
    echo ""
    echo "Example:"
    echo "  ./ghostwriting2.exe 1234"
    echo ""
    echo "Tip: Use Process Hacker or similar tools to find thread IDs"
else
    echo ""
    echo "[-] Build failed!"
    echo ""
    echo "This technique requires a 32-bit Windows compiler."
    echo "Please install i686-w64-mingw32-gcc or use a 32-bit MinGW environment."
    echo ""
    echo "Source code is available in src/ for reference."
    exit 1
fi
