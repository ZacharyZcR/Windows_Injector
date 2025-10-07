#!/bin/bash

echo "[+] Building Caro-Kann Injection POC"

mkdir -p build
cd build

echo "[+] Compiling generate_shellcode.exe..."
gcc -o generate_shellcode.exe ../src/generate_shellcode.c -lkernel32 -luser32 -O2
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile generate_shellcode.exe"
    exit 1
fi

echo "[+] Compiling xor_encrypt.exe..."
gcc -o xor_encrypt.exe ../src/xor_encrypt.c -O2
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile xor_encrypt.exe"
    exit 1
fi

echo "[+] Compiling extract_stub.exe..."
gcc -o extract_stub.exe ../src/extract_stub.c -O2
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile extract_stub.exe"
    exit 1
fi

echo "[+] Compiling caro_kann.exe..."
gcc -o caro_kann.exe ../src/caro_kann.c -lkernel32 -O2
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile caro_kann.exe"
    exit 1
fi

echo ""
echo "[+] Build completed successfully!"
echo ""
echo "[+] Binaries:"
echo "    - build/caro_kann.exe"
echo "    - build/generate_shellcode.exe"
echo "    - build/xor_encrypt.exe"
echo "    - build/extract_stub.exe"
echo ""
echo "[+] Next steps:"
echo "    1. Generate shellcode: ./generate_shellcode.exe all"
echo "    2. Encrypt shellcode: ./xor_encrypt.exe calc_shellcode.bin calc_encrypted.bin"
echo "    3. Compile decrypt stub (see README.md for instructions)"
echo "    4. Extract stub: ./extract_stub.exe decrypt_stub.exe decrypt_stub.bin"
echo "    5. Run injection: ./caro_kann.exe <pid> calc_encrypted.bin decrypt_stub.bin"
echo ""
echo "[!] Note: decrypt_stub.c requires special compilation flags for PIC"
echo "[!] See README.md for detailed instructions"
echo ""

cd ..
