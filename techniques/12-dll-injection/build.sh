#!/bin/bash
# ===================================================================
# Build Script for DLL Injection
# Based on: hasherezade/dll_injector
# ===================================================================

echo "==================================================================="
echo "Building DLL Injection"
echo "==================================================================="
echo ""

# Check for MinGW cross-compiler
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[-] x86_64-w64-mingw32-gcc not found!"
    echo "[*] Install MinGW-w64 cross-compiler:"
    echo "    Ubuntu/Debian: sudo apt install mingw-w64"
    echo "    macOS: brew install mingw-w64"
    exit 1
fi

# Create build directory
mkdir -p build

# Step 1: Compile test DLL
echo "[*] Step 1: Compiling test_dll.dll..."
x86_64-w64-mingw32-gcc -shared -o build/test_dll.dll src/test_dll.c \
    -O2 -s -Wl,--subsystem,windows
if [ $? -ne 0 ]; then
    echo "[-] Test DLL compilation failed!"
    exit 1
fi
echo "[+] test_dll.dll compiled successfully"
echo ""

# Step 2: Compile DLL injector
echo "[*] Step 2: Compiling dll_injection.exe..."
x86_64-w64-mingw32-gcc -o build/dll_injection.exe src/dll_injection.c \
    -lpsapi -O2 -s
if [ $? -ne 0 ]; then
    echo "[-] Injector compilation failed!"
    exit 1
fi
echo "[+] dll_injection.exe compiled successfully"
echo ""

echo "==================================================================="
echo "[+] Build completed successfully!"
echo "==================================================================="
echo ""
echo "Files created:"
echo "  build/dll_injection.exe  - DLL injector"
echo "  build/test_dll.dll       - Test DLL"
echo ""
echo "Usage (with Wine):"
echo "  cd build"
echo ""
echo "  # Inject to existing process"
echo "  wine dll_injection.exe 1234 test_dll.dll"
echo ""
echo "  # Inject to new process"
echo "  wine dll_injection.exe 'C:\\Windows\\System32\\notepad.exe' test_dll.dll"
echo ""
echo "  # Unload DLL"
echo "  wine dll_injection.exe 1234 test_dll.dll --unload"
echo ""
echo "  # Check if DLL is loaded"
echo "  wine dll_injection.exe 1234 test_dll.dll --check"
echo ""
