#!/bin/bash

echo "========================================"
echo "GhostInjector - Build Script (Full)"
echo "========================================"
echo ""

OUT_DIR="bin"
OUT_NAME="ghostinjector.exe"

mkdir -p "$OUT_DIR"

echo "[*] Compiling GhostInjector with all dependencies..."
echo ""

# Include directories
INCLUDES="-I./Neptune/include \
          -I./Neptune/modulerules \
          -I./NThread/include \
          -I./NThread/modulerules \
          -I./NThreadOSUtils/include"

# Source files
SOURCES="src/main.c \
         Neptune/src/neptune.c \
         Neptune/src/nerror.c \
         Neptune/src/log.c \
         Neptune/src/nmem.c \
         Neptune/src/ntime.c \
         Neptune/src/nfile.c \
         Neptune/src/nmutex.c \
         NThread/src/nthread.c \
         NThread/src/ntmem.c \
         NThread/src/nttunnel.c \
         NThread/src/ntutils.c \
         NThreadOSUtils/src/ntosutils.c \
         NThreadOSUtils/src/ntosutilswin.c"

# Definitions
DEFINES="-DLOG_LEVEL_1 \
         -DNEPTUNE_ENABLE_MEMMEM \
         -DLOG_ON_STDOUT=1"

# Compile
gcc -O2 $INCLUDES $DEFINES $SOURCES \
    -o "$OUT_DIR/$OUT_NAME" \
    -lpsapi \
    -static

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Build successful!"
    echo "[+] Output: $OUT_DIR/$OUT_NAME"
    echo ""
    echo "Usage:"
    echo "  ./$OUT_DIR/$OUT_NAME <thread_id|process_id> <dll_path>"
    echo ""
    echo "Example:"
    echo "  ./$OUT_DIR/$OUT_NAME 1234 C:\\\\path\\\\to\\\\your.dll"
    echo ""
else
    echo ""
    echo "[-] Build failed!"
    echo ""
fi
