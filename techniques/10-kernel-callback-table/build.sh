#!/bin/bash
# ===================================================================
# Kernel Callback Table Injection - Build Script (Linux/MinGW)
# ===================================================================

echo "==================================================================="
echo "Building Kernel Callback Table Injection"
echo "==================================================================="
echo

mkdir -p build
cd build

echo "[*] Step 1: Compiling shellcode generator..."
x86_64-w64-mingw32-gcc ../src/generate_shellcode.c -o generate_shellcode.exe -O2 -Wall
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile shellcode generator"
    cd ..
    exit 1
fi
echo "[+] Shellcode generator compiled"

echo
echo "[*] Step 2: Generating payload..."
wine generate_shellcode.exe payload.bin 2>/dev/null || ./generate_shellcode.exe payload.bin
if [ $? -ne 0 ]; then
    echo "[-] Failed to generate payload"
    cd ..
    exit 1
fi
echo "[+] Payload generated"

echo
echo "[*] Step 3: Compiling main injector..."
x86_64-w64-mingw32-gcc ../src/kernel_callback_injection.c -o kernel_callback_injection.exe -O2 -Wall
if [ $? -ne 0 ]; then
    echo "[-] Failed to compile main injector"
    cd ..
    exit 1
fi
echo "[+] Main injector compiled"

cd ..

echo
echo "==================================================================="
echo "[+] Build completed successfully!"
echo
echo "Output files:"
echo "  - build/kernel_callback_injection.exe  (Main injector)"
echo "  - build/generate_shellcode.exe         (Shellcode generator)"
echo "  - build/payload.bin                    (Test payload)"
echo
echo "Usage:"
echo "  cd build"
echo "  wine kernel_callback_injection.exe payload.bin"
echo
echo "==================================================================="
echo

exit 0
