#!/bin/bash
# ===================================================================
# Build Script for Advanced Process Hollowing (No NtUnmapViewOfSection)
# Based on: PichichiH0ll0wer by itaymigdal
# ===================================================================

echo "==================================================================="
echo "Building Advanced Process Hollowing"
echo "==================================================================="
echo ""

# Check for MinGW cross-compiler
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[-] x86_64-w64-mingw32-gcc not found!"
    echo "[*] Install MinGW-w64 cross-compiler:"
    echo "    Ubuntu/Debian: sudo apt install mingw-w64"
    echo "    macOS: brew install mingw-w64"
    exit 1
fi

# Create build directory
mkdir -p build

# Step 1: Compile main injector
echo "[*] Step 1: Compiling advanced_hollowing.exe..."
x86_64-w64-mingw32-gcc -o build/advanced_hollowing.exe src/advanced_hollowing.c \
    -lntdll -O2 -s
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed!"
    exit 1
fi
echo "[+] advanced_hollowing.exe compiled successfully"
echo ""

# Step 2: Check for test payload
echo "[*] Step 2: Checking for test payload..."
if [ -f "build/test_payload.exe" ]; then
    echo "[+] Test payload found: build/test_payload.exe"
else
    echo "[!] No test payload found"
    echo "[*] You can use any PE executable as payload for testing"
fi
echo ""

echo "==================================================================="
echo "[+] Build completed successfully!"
echo "==================================================================="
echo ""
echo "Usage:"
echo "  cd build"
echo "  wine advanced_hollowing.exe \"C:\\\\Windows\\\\System32\\\\notepad.exe\" test_payload.exe"
echo ""
