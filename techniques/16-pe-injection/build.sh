#!/bin/bash
# PE Injection Build Script (Linux/MinGW)

echo "========================================"
echo "  Building PE Injection (x64)"
echo "========================================"

mkdir -p build

echo ""
echo "[1/2] 编译 payload.exe..."
gcc -m64 src/payload.c \
    -o build/payload.exe \
    -O2 \
    -s \
    -mwindows \
    -Wall

if [ $? -ne 0 ]; then
    echo "[!] payload.exe 编译失败"
    exit 1
fi

echo "[+] payload.exe 编译成功"

echo ""
echo "[2/2] 编译 pe_inject.exe..."
gcc -m64 src/pe_inject.c \
    -o build/pe_inject.exe \
    -O2 \
    -s \
    -lpsapi \
    -Wall

if [ $? -ne 0 ]; then
    echo "[!] pe_inject.exe 编译失败"
    exit 1
fi

echo "[+] pe_inject.exe 编译成功"

echo ""
echo "========================================"
echo "  构建完成!"
echo "========================================"
echo ""
ls -lh build/*.exe

echo ""
echo "用法:"
echo "  build/pe_inject.exe <进程名或PID> build/payload.exe"
echo ""
echo "示例:"
echo "  build/pe_inject.exe notepad.exe build/payload.exe"
