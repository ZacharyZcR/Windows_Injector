@echo off
chcp 65001 > nul
setlocal enabledelayedexpansion

echo ======================================
echo   Process Herpaderping 构建脚本
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
echo [1/3] 编译测试载荷...
gcc -o "%BUILD_DIR%\test_payload.exe" src\test_payload.c ^
    -luser32 -mwindows ^
    -O2 -s

if errorlevel 1 (
    echo 错误：测试载荷编译失败
    exit /b 1
)
echo     √ 测试载荷编译成功

echo.
echo [2/3] 编译 Process Herpaderping 主程序...
gcc -o "%BUILD_DIR%\process_herpaderping.exe" ^
    src\process_herpaderping.c ^
    src\pe_utils.c ^
    -lntdll -luserenv ^
    -O2 -municode -D_UNICODE -DUNICODE

if errorlevel 1 (
    echo 错误：主程序编译失败
    exit /b 1
)
echo     √ 主程序编译成功

echo.
echo [3/3] 编译完成
echo ======================================
echo 输出文件：
echo   %BUILD_DIR%\process_herpaderping.exe
echo   %BUILD_DIR%\test_payload.exe
echo.
echo 运行示例：
echo   %BUILD_DIR%\process_herpaderping.exe %BUILD_DIR%\test_payload.exe %BUILD_DIR%\target.exe
echo ======================================

endlocal
