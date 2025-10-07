@echo off
REM ========================================
REM Thread Hijacking - Windows Build Script
REM ========================================

echo ========================================
echo Building Thread Hijacking
echo ========================================
echo.

REM 创建输出目录
if not exist "build" mkdir build

echo [*] Step 1: Compiling generate_shellcode.exe...
gcc -O2 -o build\generate_shellcode.exe src\generate_shellcode.c
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile generate_shellcode.exe
    exit /b 1
)
echo [+] generate_shellcode.exe compiled successfully
echo.

echo [*] Step 2: Compiling thread_hijacking.exe...
gcc -O2 -o build\thread_hijacking.exe src\thread_hijacking.c
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile thread_hijacking.exe
    exit /b 1
)
echo [+] thread_hijacking.exe compiled successfully
echo.

echo [*] Step 3: Generating test payload...
cd build
generate_shellcode.exe calc
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to generate payload
    cd ..
    exit /b 1
)
cd ..
echo [+] Payload generated successfully
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Output files:
echo   - build\thread_hijacking.exe
echo   - build\generate_shellcode.exe
echo   - build\calc_shellcode.bin
echo.
echo Usage:
echo   build\thread_hijacking.exe "C:\Windows\System32\notepad.exe" build\calc_shellcode.bin
echo.
