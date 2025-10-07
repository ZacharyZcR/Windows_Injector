#!/bin/bash

echo "[+] Building Process Forking Injection POC (Dirty Vanity)"

mkdir -p build
cd build

echo "[+] Compiling generate_shellcode.exe..."
gcc -o generate_shellcode.exe ../src/generate_shellcode.c -lkernel32 -luser32 -O2
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile generate_shellcode.exe"
    exit 1
fi

echo "[+] Compiling process_forking.exe..."
gcc -o process_forking.exe ../src/process_forking.c -lkernel32 -O2
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile process_forking.exe"
    exit 1
fi

echo ""
echo "[+] Build completed successfully!"
echo ""
echo "[+] Binaries:"
echo "    - build/process_forking.exe"
echo "    - build/generate_shellcode.exe"
echo ""
echo "[+] Next steps:"
echo "    1. Generate shellcode: ./generate_shellcode.exe all"
echo "    2. Run injection: ./process_forking.exe <target_pid> calc_shellcode.bin"
echo ""

cd ..
