#!/bin/bash
# SetWindowsHookEx Injection - Build Script (Cross-Platform)
# 使用 MinGW 交叉编译 Windows 可执行文件

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║          Building SetWindowsHookEx Injection            ║"
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
CFLAGS="-Wall -Wextra -O2 -s"
LDFLAGS="-luser32 -lgdi32"

# 创建构建目录
mkdir -p "$BUILD_DIR"

# 清理旧文件
echo "[*] 清理旧文件..."
rm -f "$BUILD_DIR"/*.exe "$BUILD_DIR"/*.dll

# ============================================
# 1. 编译测试 DLL
# ============================================
echo
echo "[1/2] 编译测试 DLL..."
echo "     输入: $SRC_DIR/hook_dll.c"
echo "     输出: $BUILD_DIR/hook.dll"

$CC -shared \
    "$SRC_DIR/hook_dll.c" \
    -o "$BUILD_DIR/hook.dll" \
    $CFLAGS \
    $LDFLAGS

echo "     ✅ DLL 编译成功"

# ============================================
# 2. 编译注入器
# ============================================
echo
echo "[2/2] 编译注入器..."
echo "     输入: $SRC_DIR/setwindowshookex_injection.c"
echo "     输出: $BUILD_DIR/setwindowshookex_injection.exe"

$CC "$SRC_DIR/setwindowshookex_injection.c" \
    -o "$BUILD_DIR/setwindowshookex_injection.exe" \
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
echo "1. 启动一个 GUI 程序 (例如记事本):"
echo "   start notepad"
echo
echo "2. 运行注入器:"
echo "   $BUILD_DIR/setwindowshookex_injection.exe \"无标题 - 记事本\" \$(pwd)/$BUILD_DIR/hook.dll"
echo
echo "3. 注入成功后会显示消息框"
echo
echo "注意事项:"
echo "  - 只能注入有窗口的 GUI 进程"
echo "  - DLL 路径必须是绝对路径"
echo "  - 目标窗口标题支持部分匹配"
echo
