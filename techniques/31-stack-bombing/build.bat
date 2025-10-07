@echo off
echo ========================================
echo Stack Bombing Injection - Build Script
echo ========================================
echo.

set SRC_DIR=src
set OUT_DIR=bin
set OUT_NAME=stack_bombing.exe

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo [*] Compiling Stack Bombing injection...
echo.

gcc -O2 ^
    %SRC_DIR%/stack_bombing.c ^
    %SRC_DIR%/memmem.c ^
    %SRC_DIR%/procs_and_threads.c ^
    %SRC_DIR%/gadget_finder.c ^
    %SRC_DIR%/rop_chain.c ^
    %SRC_DIR%/set_remote_memory.c ^
    %SRC_DIR%/inject.c ^
    -o %OUT_DIR%/%OUT_NAME% ^
    -lpsapi ^
    -luser32 ^
    -lkernel32 ^
    -lntdll ^
    -static

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Build successful!
    echo [+] Output: %OUT_DIR%\%OUT_NAME%
    echo.
    echo Usage:
    echo   %OUT_DIR%\%OUT_NAME% notepad.exe
    echo.
) else (
    echo.
    echo [-] Build failed!
    echo.
)

pause
