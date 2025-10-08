#!/bin/bash

echo "[*] Building PoolParty (Official Implementation)"
echo ""

MSBUILD="/c/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/amd64/MSBuild.exe"

if [ ! -f "$MSBUILD" ]; then
    echo "[x] MSBuild not found at: $MSBUILD"
    echo "[!] Please install Visual Studio 2022"
    exit 1
fi

# Build Release x64
"$MSBUILD" PoolParty.sln -p:Configuration=Release -p:Platform=x64

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Build successful!"
    echo "[+] Output: src/x64/Release/PoolParty.exe"
    echo ""

    # Copy to current directory
    if [ -f "src/x64/Release/PoolParty.exe" ]; then
        cp src/x64/Release/PoolParty.exe .
        echo "[+] Copied to: PoolParty.exe"
    fi
else
    echo ""
    echo "[x] Build failed"
    exit 1
fi
