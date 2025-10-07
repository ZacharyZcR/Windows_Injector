@echo off
REM ===================================================================
REM Early Cascade Injection - Build Script
REM ===================================================================

echo ===================================================================
echo Building Early Cascade Injection
echo ===================================================================
echo.

if not exist build mkdir build
cd build

echo [*] Step 1: Compiling shellcode generator...
gcc ..\src\generate_shellcode.c -o generate_shellcode.exe -O2 -Wall
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to compile shellcode generator
    cd ..
    exit /b 1
)
echo [+] Shellcode generator compiled

echo.
echo [*] Step 2: Generating payload...
generate_shellcode.exe payload.bin
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to generate payload
    cd ..
    exit /b 1
)
echo [+] Payload generated

echo.
echo [*] Step 3: Compiling main injector...
gcc ..\src\early_cascade.c -o early_cascade.exe -O2 -Wall
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to compile main injector
    cd ..
    exit /b 1
)
echo [+] Main injector compiled

cd ..

echo.
echo ===================================================================
echo [+] Build completed successfully!
echo.
echo Output files:
echo   - build\early_cascade.exe      (Main injector)
echo   - build\generate_shellcode.exe (Shellcode generator)
echo   - build\payload.bin            (Test payload)
echo.
echo Usage:
echo   cd build
echo   early_cascade.exe "C:\Windows\System32\notepad.exe" payload.bin
echo.
echo ===================================================================
echo.

exit /b 0
