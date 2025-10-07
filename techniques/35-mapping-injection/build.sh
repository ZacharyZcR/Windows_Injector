#!/bin/bash

echo "============================================"
echo "Mapping Injection - Build Script"
echo "============================================"
echo ""
echo "NOTE: This technique requires Windows 10 1703+ (Build 15063+)"
echo "      It uses MapViewOfFile3 API which is not available in older versions."
echo ""

gcc src/mapping_injection.c \
    -o mapping_injection.exe \
    -O2 \
    -Wall \
    -lntdll

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Build successful: mapping_injection.exe"
    echo ""
    echo "Usage:"
    echo "  ./mapping_injection.exe"
    echo ""
    echo "The program will inject into explorer.exe by default."
    echo "Requires Administrator privileges (SeDebugPrivilege)."
else
    echo ""
    echo "[-] Build failed!"
    exit 1
fi
