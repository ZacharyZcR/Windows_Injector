@echo off
REM ========================================
REM PowerLoaderEx - Windows Build Script
REM ========================================

echo ========================================
echo Building PowerLoaderEx
echo ========================================
echo.

REM 创建输出目录
if not exist "build" mkdir build

echo [*] Compiling PowerLoaderEx...
echo.
echo [!] 注意：此技术仅在 Windows 7 测试
echo [!] x64 版本相对稳定，x86 需要完整 ROP 链
echo.

gcc -O2 -o build\powerloader_ex.exe src\powerloader_ex.c -lshlwapi -mwindows
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile powerloader_ex.exe
    exit /b 1
)

echo [+] powerloader_ex.exe compiled successfully
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Output files:
echo   - build\powerloader_ex.exe
echo.
echo Usage:
echo   build\powerloader_ex.exe
echo.
echo Requirements:
echo   - Windows 7 (测试环境)
echo   - Explorer.exe 必须运行
echo   - 需要创建 c:\x.dll (要注入的 DLL)
echo.
echo ⚠️  警告:
echo   - 此技术依赖 Windows 内部结构
echo   - 可能在其他 Windows 版本失效
echo   - 仅用于安全研究和教育目的
echo.
