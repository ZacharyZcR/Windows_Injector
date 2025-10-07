#!/bin/bash
# Reflective DLL Injection - Build Script (Cross-Platform)
# 使用 MinGW 交叉编译 Windows x64 可执行文件

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║       Building Reflective DLL Injection (x64)           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo

# 检测编译器
if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    CC="x86_64-w64-mingw32-gcc"
    echo "[+] 使用交叉编译器: $CC"
elif command -v gcc &> /dev/null; then
    CC="gcc"
    echo "[+] 使用本地编译器: $CC"
else
    echo "[!] 错误: 未找到 GCC 编译器"
    echo "[!] 请安装 mingw-w64: sudo apt install mingw-w64"
    exit 1
fi

# 设置变量
SRC_DIR="src"
BUILD_DIR="build"
CFLAGS="-Wall -Wextra -O2 -s -m64"
LDFLAGS="-ladvapi32"

# 创建构建目录
mkdir -p "$BUILD_DIR"

# 清理旧文件
echo "[*] 清理旧文件..."
rm -f "$BUILD_DIR"/*.exe "$BUILD_DIR"/*.dll

# ============================================
# 1. 编译测试 DLL（包含 ReflectiveLoader）
# ============================================
echo
echo "[1/2] 编译测试 DLL..."
echo "     输入: $SRC_DIR/test_dll.c"
echo "     输出: $BUILD_DIR/reflective_dll.dll"

$CC -shared \
    "$SRC_DIR/test_dll.c" \
    -o "$BUILD_DIR/reflective_dll.dll" \
    $CFLAGS \
    -DDLLEXPORT="__declspec(dllexport)" \
    -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

echo "     ✅ DLL 编译成功"

# ============================================
# 2. 编译注入器
# ============================================
echo
echo "[2/2] 编译注入器..."
echo "     输入: $SRC_DIR/inject.c, $SRC_DIR/LoadLibraryR.c"
echo "     输出: $BUILD_DIR/inject.exe"

$CC "$SRC_DIR/inject.c" \
    "$SRC_DIR/LoadLibraryR.c" \
    -o "$BUILD_DIR/inject.exe" \
    $CFLAGS \
    $LDFLAGS

echo "     ✅ 注入器编译成功"

# ============================================
# 显示构建结果
# ============================================
echo
echo "════════════════════════════════════════════════════════════"
echo "构建完成! 输出文件:"
echo "════════════════════════════════════════════════════════════"

for file in "$BUILD_DIR"/*.exe "$BUILD_DIR"/*.dll; do
    if [ -f "$file" ]; then
        size=$(du -h "$file" | cut -f1)
        echo "  $(basename "$file") - $size"
    fi
done

echo
echo "════════════════════════════════════════════════════════════"
echo "使用示例:"
echo "════════════════════════════════════════════════════════════"
echo
echo "1. 启动目标进程 (例如记事本):"
echo "   start notepad"
echo
echo "2. 运行注入器:"
echo "   $BUILD_DIR/inject.exe notepad.exe"
echo
echo "或者直接使用 PID:"
echo "   $BUILD_DIR/inject.exe 1234"
echo
echo "3. 注入成功后会显示消息框"
echo
echo "注意事项:"
echo "  - 仅支持 x64 进程"
echo "  - DLL 必须导出 ReflectiveLoader 函数"
echo "  - 需要管理员权限注入系统进程"
echo
