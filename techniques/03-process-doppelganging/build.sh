#!/bin/bash

echo "======================================"
echo "  Process Doppelgänging 构建脚本"
echo "======================================"

# 检测系统架构
if [ "$(uname -m)" == "x86_64" ]; then
    ARCH="x64"
    echo "检测到 64 位系统"
else
    ARCH="x86"
    echo "检测到 32 位系统"
fi

# 创建构建目录
BUILD_DIR="build/${ARCH}"
mkdir -p ${BUILD_DIR}

echo ""
echo "[1/3] 编译测试载荷..."
gcc -o ${BUILD_DIR}/test_payload.exe src/test_payload.c \
    -luser32 -mwindows \
    -O2 -s

if [ $? -ne 0 ]; then
    echo "错误：测试载荷编译失败"
    exit 1
fi
echo "    ✓ 测试载荷编译成功"

echo ""
echo "[2/3] 编译 Process Doppelgänging 主程序..."
gcc -o ${BUILD_DIR}/process_doppelganging.exe \
    src/process_doppelganging.c \
    src/pe_utils.c \
    -lntdll -lktmw32 -luserenv \
    -O2 -municode -D_UNICODE -DUNICODE

if [ $? -ne 0 ]; then
    echo "错误：主程序编译失败"
    exit 1
fi
echo "    ✓ 主程序编译成功"

echo ""
echo "[3/3] 编译完成"
echo "======================================"
echo "输出文件："
echo "  ${BUILD_DIR}/process_doppelganging.exe"
echo "  ${BUILD_DIR}/test_payload.exe"
echo ""
echo "运行示例："
echo "  ${BUILD_DIR}/process_doppelganging.exe ${BUILD_DIR}/test_payload.exe"
echo "======================================"
