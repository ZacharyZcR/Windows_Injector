#!/bin/bash

echo "[*] Building Thread Name-Calling Injection..."

# 检查编译器
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[x] x86_64-w64-mingw32-gcc not found!"
    echo "[!] Please install MinGW-w64"
    exit 1
fi

# 编译
x86_64-w64-mingw32-gcc -o thread_namecalling.exe \
    src/thread_namecalling.c \
    -lntdll \
    -O2 \
    -s

if [ $? -eq 0 ]; then
    echo "[+] Build successful: thread_namecalling.exe"
    echo ""
    echo "[!] Usage:"
    echo "    1. Start notepad.exe on Windows"
    echo "    2. Get its PID"
    echo "    3. Run: ./thread_namecalling.exe <PID>"
    echo "    4. Interact with notepad to trigger APC"
    echo "    5. A MessageBox should appear"
else
    echo "[x] Build failed"
    exit 1
fi
