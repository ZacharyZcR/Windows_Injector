#!/bin/bash

echo "======================================"
echo "   进程镂空项目构建脚本"
echo "======================================"

# 进入源代码目录
cd "$(dirname "$0")/src"

# 编译主程序
echo ""
echo "[1/2] 编译主程序 process_hollowing.exe ..."
gcc -o ../process_hollowing.exe process_hollowing.c pe.c -ldbghelp -lntdll -I.

if [ $? -eq 0 ]; then
    echo "    ✓ process_hollowing.exe 编译成功"
else
    echo "    ✗ process_hollowing.exe 编译失败"
    exit 1
fi

# 编译测试载荷
echo ""
echo "[2/2] 编译测试载荷 test_payload.exe ..."
gcc -o ../test_payload.exe test_payload.c

if [ $? -eq 0 ]; then
    echo "    ✓ test_payload.exe 编译成功"
else
    echo "    ✗ test_payload.exe 编译失败"
    exit 1
fi

# 返回项目目录
cd ..

# 显示文件信息
echo ""
echo "======================================"
echo "   编译完成！"
echo "======================================"
echo ""
echo "生成的文件："
ls -lh *.exe

echo ""
echo "使用方法："
echo "  ./process_hollowing.exe <目标进程> <源程序>"
echo ""
echo "测试示例："
echo "  ./process_hollowing.exe notepad.exe test_payload.exe"
echo ""
