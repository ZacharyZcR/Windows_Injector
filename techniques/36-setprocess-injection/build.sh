#!/bin/bash

echo "[*] Building SetProcessInjection..."

# 检查编译器
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[x] x86_64-w64-mingw32-gcc not found!"
    echo "[!] Please install MinGW-w64"
    exit 1
fi

# 编译
x86_64-w64-mingw32-gcc -o setprocess_injection.exe \
    src/setprocess_injection.c \
    -lntdll \
    -O2 \
    -s

if [ $? -eq 0 ]; then
    echo "[+] Build successful: setprocess_injection.exe"
    echo ""
    echo "[!] Usage:"
    echo "    1. Start notepad.exe on Windows"
    echo "    2. Run: ./setprocess_injection.exe"
    echo "    3. Interact with notepad to trigger the callback"
    echo "    4. A MessageBox should appear"
else
    echo "[x] Build failed"
    exit 1
fi
