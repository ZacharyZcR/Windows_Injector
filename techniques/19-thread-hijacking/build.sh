#!/bin/bash

# ========================================
# Thread Hijacking - Linux/MSYS Build Script
# ========================================

echo "========================================"
echo "Building Thread Hijacking"
echo "========================================"
echo ""

# 创建输出目录
mkdir -p build

echo "[*] Step 1: Compiling generate_shellcode.exe..."
gcc -O2 -o build/generate_shellcode.exe src/generate_shellcode.c
if [ $? -ne 0 ]; then
    echo "[!] Failed to compile generate_shellcode.exe"
    exit 1
fi
echo "[+] generate_shellcode.exe compiled successfully"
echo ""

echo "[*] Step 2: Compiling thread_hijacking.exe..."
gcc -O2 -o build/thread_hijacking.exe src/thread_hijacking.c
if [ $? -ne 0 ]; then
    echo "[!] Failed to compile thread_hijacking.exe"
    exit 1
fi
echo "[+] thread_hijacking.exe compiled successfully"
echo ""

echo "[*] Step 3: Generating test payload..."
cd build
./generate_shellcode.exe calc
if [ $? -ne 0 ]; then
    echo "[!] Failed to generate payload"
    cd ..
    exit 1
fi
cd ..
echo "[+] Payload generated successfully"
echo ""

echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "Output files:"
echo "  - build/thread_hijacking.exe"
echo "  - build/generate_shellcode.exe"
echo "  - build/calc_shellcode.bin"
echo ""
echo "Usage:"
echo "  build/thread_hijacking.exe \"C:\\Windows\\System32\\notepad.exe\" build/calc_shellcode.bin"
echo ""
