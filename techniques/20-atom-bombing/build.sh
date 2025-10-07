#!/bin/bash

# ========================================
# Atom Bombing - Linux/MSYS Build Script
# ========================================

echo "========================================"
echo "Building Atom Bombing"
echo "========================================"
echo ""

# 创建输出目录
mkdir -p build

echo "[*] Compiling atom_bombing.exe..."
echo ""
echo "[!] 注意：原始 Atom Bombing 设计为 x86 架构"
echo "[!] 本实现为教育演示版本"
echo ""

gcc -O2 -o build/atom_bombing.exe src/atom_bombing.c
if [ $? -ne 0 ]; then
    echo "[!] Failed to compile atom_bombing.exe"
    exit 1
fi

echo "[+] atom_bombing.exe compiled successfully"
echo ""

echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "Output files:"
echo "  - build/atom_bombing.exe (x86)"
echo ""
echo "Usage:"
echo "  1. 启动一个 32 位程序（如 notepad.exe）"
echo "  2. build/atom_bombing.exe notepad.exe"
echo ""
echo "注意事项:"
echo "  - 需要管理员权限"
echo "  - 目标进程必须是 32 位"
echo "  - 目标进程必须有可用的线程"
echo ""
