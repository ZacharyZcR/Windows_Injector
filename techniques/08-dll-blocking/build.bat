@echo off
REM ===================================================================
REM Ruy-Lopez DLL Blocking - Master Build Script
REM ===================================================================
REM
REM 完整构建流程：
REM 1. 编译 PIC shellcode (hook.bin)
REM 2. 编译主注入器 (dll_blocking.exe)

echo.
echo ===================================================================
echo Ruy-Lopez DLL Blocking - Master Build
echo ===================================================================
echo.

REM 步骤 1：构建 shellcode
echo [*] Building PIC Shellcode...
call build_shellcode.bat
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [-] Shellcode build failed!
    exit /b 1
)

echo.
echo.

REM 步骤 2：构建主注入器
echo [*] Building Main Injector...
call build_injector.bat
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [-] Injector build failed!
    exit /b 1
)

echo.
echo.
echo ===================================================================
echo [+] Build completed successfully!
echo.
echo Output files:
echo   - src\hook.bin          (PIC shellcode)
echo   - src\dll_blocking.exe  (Main injector)
echo.
echo Usage:
echo   cd src
echo   dll_blocking.exe
echo.
echo ===================================================================
echo.

exit /b 0
