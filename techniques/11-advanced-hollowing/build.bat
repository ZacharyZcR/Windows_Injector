@echo off
REM ===================================================================
REM Build Script for Advanced Process Hollowing (No NtUnmapViewOfSection)
REM Based on: PichichiH0ll0wer by itaymigdal
REM ===================================================================

echo ===================================================================
echo Building Advanced Process Hollowing
echo ===================================================================
echo.

REM Create build directory
if not exist build mkdir build

REM Step 1: Compile main injector
echo [*] Step 1: Compiling advanced_hollowing.exe...
gcc -o build\advanced_hollowing.exe src\advanced_hollowing.c ^
    -lntdll -O2 -s
if %ERRORLEVEL% NEQ 0 (
    echo [-] Compilation failed!
    exit /b 1
)
echo [+] advanced_hollowing.exe compiled successfully
echo.

REM Step 2: Check for test payload
echo [*] Step 2: Checking for test payload...
if exist build\test_payload.exe (
    echo [+] Test payload found: build\test_payload.exe
) else (
    echo [!] No test payload found
    echo [*] You can use any PE executable as payload for testing
    echo [*] Example: copy C:\Windows\System32\calc.exe build\test_payload.exe
)
echo.

echo ===================================================================
echo [+] Build completed successfully!
echo ===================================================================
echo.
echo Usage:
echo   cd build
echo   advanced_hollowing.exe "C:\Windows\System32\notepad.exe" test_payload.exe
echo.
