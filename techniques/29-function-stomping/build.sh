#!/bin/bash

echo "[+] Building Function Stomping Injection POC"

mkdir -p build
cd build

echo "[+] Compiling generate_shellcode.exe..."
gcc -o generate_shellcode.exe ../src/generate_shellcode.c -lkernel32 -luser32 -O2
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile generate_shellcode.exe"
    exit 1
fi

echo "[+] Compiling function_stomping.exe..."
gcc -o function_stomping.exe ../src/function_stomping.c -lkernel32 -lpsapi -lshlwapi -O2
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile function_stomping.exe"
    exit 1
fi

echo ""
echo "[+] Build completed successfully!"
echo ""
echo "[+] Binaries:"
echo "    - build/function_stomping.exe"
echo "    - build/generate_shellcode.exe"
echo ""
echo "[+] Next steps:"
echo "    1. Generate shellcode: ./generate_shellcode.exe all"
echo "    2. Run injection: ./function_stomping.exe <pid> calc_shellcode.bin kernel32.dll CreateFileW"
echo "    3. Trigger from target: Call CreateFileW from target process"
echo ""

cd ..
