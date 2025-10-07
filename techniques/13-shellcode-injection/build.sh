#!/bin/bash
# ===================================================================
# Build Script for Classic Shellcode Injection
# Based on: plackyhacker/Shellcode-Injection-Techniques
# ===================================================================

echo "==================================================================="
echo "Building Classic Shellcode Injection"
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

# Step 1: Compile shellcode generator
echo "[*] Step 1: Compiling generate_shellcode.exe..."
x86_64-w64-mingw32-gcc -o build/generate_shellcode.exe src/generate_shellcode.c \
    -O2 -s
if [ $? -ne 0 ]; then
    echo "[-] Shellcode generator compilation failed!"
    exit 1
fi
echo "[+] generate_shellcode.exe compiled successfully"
echo ""

# Step 2: Generate test shellcode
echo "[*] Step 2: Generating test shellcode..."
cd build
wine generate_shellcode.exe calc
if [ $? -ne 0 ]; then
    echo "[-] Shellcode generation failed!"
    cd ..
    exit 1
fi
cd ..
echo "[+] Test shellcode generated"
echo ""

# Step 3: Compile shellcode injector
echo "[*] Step 3: Compiling shellcode_injection.exe..."
x86_64-w64-mingw32-gcc -o build/shellcode_injection.exe src/shellcode_injection.c \
    -O2 -s
if [ $? -ne 0 ]; then
    echo "[-] Injector compilation failed!"
    exit 1
fi
echo "[+] shellcode_injection.exe compiled successfully"
echo ""

echo "==================================================================="
echo "[+] Build completed successfully!"
echo "==================================================================="
echo ""
echo "Files created:"
echo "  build/shellcode_injection.exe  - Shellcode injector"
echo "  build/generate_shellcode.exe   - Shellcode generator"
echo "  build/calc_shellcode.bin       - Test shellcode (calc.exe)"
echo ""
echo "Usage (with Wine):"
echo "  cd build"
echo ""
echo "  # Inject to existing process"
echo "  wine shellcode_injection.exe 1234 calc_shellcode.bin"
echo ""
echo "  # Inject to new process"
echo "  wine shellcode_injection.exe 'C:\\Windows\\System32\\notepad.exe' calc_shellcode.bin"
echo ""
echo "  # Generate custom shellcode"
echo "  wine generate_shellcode.exe calc"
echo ""
