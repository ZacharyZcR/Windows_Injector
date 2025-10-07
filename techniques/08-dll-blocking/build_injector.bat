@echo off
REM ===================================================================
REM Ruy-Lopez DLL Blocking - Injector Builder
REM ===================================================================
REM
REM 编译主注入器程序（dll_blocking.exe）

echo ===================================================================
echo Building Main Injector (dll_blocking.exe)
echo ===================================================================
echo.

cd src

echo [*] Compiling dll_blocking.c...
gcc dll_blocking.c -o dll_blocking.exe -lntdll -O2 -Wall
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to compile dll_blocking.c
    cd ..
    exit /b 1
)
echo [+] dll_blocking.exe compiled successfully

echo.
echo ===================================================================
echo [+] Main Injector built successfully!
echo [+] Output: src\dll_blocking.exe
echo ===================================================================

cd ..
exit /b 0
