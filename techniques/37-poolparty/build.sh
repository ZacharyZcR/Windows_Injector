#!/bin/bash

echo "[*] Building PoolParty TP_WORK Injection..."

# 检查编译器
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[x] x86_64-w64-mingw32-gcc not found!"
    echo "[!] Please install MinGW-w64"
    exit 1
fi

# 编译
x86_64-w64-mingw32-gcc -o poolparty_tpwork.exe \
    src/poolparty_tpwork.c \
    -lntdll \
    -O2 \
    -s

if [ $? -eq 0 ]; then
    echo "[+] Build successful: poolparty_tpwork.exe"
    echo ""
    echo "[!] Usage:"
    echo "    1. Start notepad.exe on Windows"
    echo "    2. Run: ./poolparty_tpwork.exe"
    echo "    3. Interact with notepad to trigger execution"
    echo "    4. A MessageBox should appear"
else
    echo "[x] Build failed"
    exit 1
fi
