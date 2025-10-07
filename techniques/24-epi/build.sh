#!/bin/bash

# ========================================
# EPI - Build Script
# ========================================

echo "========================================"
echo "Building EPI (Entry Point Injection)"
echo "========================================"
echo

# 创建输出目录
mkdir -p build

echo "[*] Compiling EPI..."
echo

gcc -O2 -o build/epi.exe src/epi.c -lntdll
if [ $? -ne 0 ]; then
    echo "[!] Failed to compile epi.exe"
    exit 1
fi

echo "[+] epi.exe compiled successfully"
echo

echo "========================================"
echo "Build Complete!"
echo "========================================"
echo
echo "Output files:"
echo "  - build/epi.exe"
echo
echo "Usage:"
echo "  build/epi.exe <PID> <shellcode_file> [options]"
echo
echo "Options:"
echo "  -f              Force trigger (create thread with ExitThread)"
echo "  -d <DLL名称>    Specify target DLL (default: kernelbase.dll)"
echo
echo "Example:"
echo "  build/epi.exe 1234 payload.bin"
echo "  build/epi.exe 1234 payload.bin -f"
echo "  build/epi.exe 1234 payload.bin -d kernel32.dll -f"
echo
echo "Recommended targets:"
echo "  - notepad.exe"
echo "  - explorer.exe"
echo "  - Any GUI program with frequent thread creation"
echo
echo "⚠️  Warning:"
echo "  - Choose processes that frequently create/destroy threads"
echo "  - Perform operations in target (open file, click button) to trigger"
echo "  - Use -f option to trigger immediately (creates remote thread)"
echo
