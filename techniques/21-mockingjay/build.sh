#!/bin/bash
# ========================================
# Mockingjay - Linux/macOS Build Script
# ========================================

echo "========================================"
echo "Building Mockingjay Process Injection"
echo "========================================"
echo

# Create output directory
mkdir -p build

# [1] Compile RWX Finder
echo "[1/3] Compiling RWX Finder..."
gcc -O2 -o build/rwx_finder src/rwx_finder.c -ldbghelp
if [ $? -ne 0 ]; then
    echo "[!] Failed to compile rwx_finder"
    exit 1
fi
echo "[+] rwx_finder compiled successfully"
echo

# [2] Compile Mockingjay injector
echo "[2/3] Compiling Mockingjay injector..."
gcc -O2 -o build/mockingjay src/mockingjay.c -ldbghelp -lpsapi
if [ $? -ne 0 ]; then
    echo "[!] Failed to compile mockingjay"
    exit 1
fi
echo "[+] mockingjay compiled successfully"
echo

# [3] Generate test shellcode (optional)
echo "[3/3] Generating test shellcode..."
if [ -f "../common/generate_shellcode.c" ]; then
    gcc -o build/generate_shellcode ../common/generate_shellcode.c
    if [ $? -eq 0 ]; then
        ./build/generate_shellcode build/payload.bin
        echo "[+] Test shellcode generated: build/payload.bin"
    fi
else
    echo "[i] Shellcode generator not found, skipping..."
fi
echo

echo "========================================"
echo "Build Complete!"
echo "========================================"
echo
echo "Output files:"
echo "  - build/rwx_finder     (RWX section scanner)"
echo "  - build/mockingjay     (Mockingjay injector)"
if [ -f "build/payload.bin" ]; then
    echo "  - build/payload.bin    (Test shellcode)"
fi
echo
echo "Usage:"
echo "  # Step 1: Find DLLs with RWX sections"
echo "  ./build/rwx_finder \"C:\\Windows\\System32\""
echo
echo "  # Step 2: Inject shellcode into RWX section"
echo "  ./build/mockingjay \"C:\\path\\to\\vulnerable.dll\" build/payload.bin"
echo
echo "Note:"
echo "  - Some DLLs may contain RWX sections (e.g., msys-2.0.dll)"
echo "  - Use rwx_finder to scan your system"
echo
