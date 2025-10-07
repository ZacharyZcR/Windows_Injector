@echo off
echo Building Gadget APC Injection...

if not exist "build" mkdir build

echo Compiling shellcode generator...
gcc -O2 -o build\generate_shellcode.exe src\generate_shellcode.c

if %ERRORLEVEL% NEQ 0 (
    echo Failed to build shellcode generator!
    exit /b 1
)

echo Compiling gadget APC injector...
gcc -O2 -o build\gadget_apc_injection.exe src\gadget_apc_injection.c -lpsapi -lntdll

if %ERRORLEVEL% == 0 (
    echo Build successful!
    echo.
    echo Executables:
    echo   - build\gadget_apc_injection.exe
    echo   - build\generate_shellcode.exe
) else (
    echo Build failed!
    exit /b 1
)
