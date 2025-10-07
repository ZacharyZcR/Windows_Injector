@echo off
echo Building Module Stomping...

if not exist "build" mkdir build

echo Compiling shellcode generator...
gcc -O2 -o build\generate_shellcode.exe src\generate_shellcode.c

if %ERRORLEVEL% NEQ 0 (
    echo Failed to build shellcode generator!
    exit /b 1
)

echo Compiling module stomping injector...
gcc -O2 -municode -o build\module_stomping.exe src\module_stomping.c -lpsapi

if %ERRORLEVEL% == 0 (
    echo Build successful!
    echo.
    echo Executables:
    echo   - build\module_stomping.exe
    echo   - build\generate_shellcode.exe
) else (
    echo Build failed!
    exit /b 1
)
