@echo off
chcp 65001 > nul
setlocal enabledelayedexpansion

echo ======================================
echo   Early Bird APC Injection 构建脚本
echo ======================================

REM 检测系统架构
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set ARCH=x64
    echo 检测到 64 位系统
) else (
    set ARCH=x86
    echo 检测到 32 位系统
)

REM 创建构建目录
set BUILD_DIR=build\%ARCH%
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo [1/4] 编译 shellcode 生成器...
gcc -o "%BUILD_DIR%\generate_shellcode.exe" src\generate_shellcode.c ^
    -O2 -s

if errorlevel 1 (
    echo 错误：shellcode 生成器编译失败
    exit /b 1
)
echo     √ Shellcode 生成器编译成功

echo.
echo [2/4] 生成测试 shellcode...
"%BUILD_DIR%\generate_shellcode.exe" "%BUILD_DIR%\payload.bin"

if errorlevel 1 (
    echo 错误：shellcode 生成失败
    exit /b 1
)
echo     √ Shellcode 生成成功

echo.
echo [3/4] 编译 Early Bird APC 主程序...
gcc -o "%BUILD_DIR%\early_bird_apc.exe" src\early_bird_apc.c ^
    -lpsapi ^
    -O2 -s

if errorlevel 1 (
    echo 错误：主程序编译失败
    exit /b 1
)
echo     √ 主程序编译成功

echo.
echo [4/4] 编译测试载荷（可选）...
gcc -o "%BUILD_DIR%\test_payload.exe" src\test_payload.c ^
    -luser32 -mwindows ^
    -O2 -s

if errorlevel 1 (
    echo 警告：测试载荷编译失败（非致命错误）
) else (
    echo     √ 测试载荷编译成功
)

echo.
echo [完成] 编译完成
echo ======================================
echo 输出文件：
echo   %BUILD_DIR%\early_bird_apc.exe
echo   %BUILD_DIR%\payload.bin
echo   %BUILD_DIR%\test_payload.exe
echo.
echo 运行示例：
echo   REM 使用预生成的 shellcode：
echo   %BUILD_DIR%\early_bird_apc.exe C:\Windows\System32\notepad.exe %BUILD_DIR%\payload.bin
echo.
echo   REM 或使用自定义 shellcode：
echo   %BUILD_DIR%\early_bird_apc.exe C:\Windows\System32\calc.exe your_payload.bin
echo ======================================

endlocal
