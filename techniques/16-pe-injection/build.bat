@echo off
REM PE Injection Build Script (Windows)

echo ========================================
echo   Building PE Injection (x64)
echo ========================================

if not exist build mkdir build

echo.
echo [1/2] 编译 payload.exe...
gcc -m64 src\payload.c ^
    -o build\payload.exe ^
    -O2 ^
    -s ^
    -mwindows ^
    -Wall

if %ERRORLEVEL% neq 0 (
    echo [!] payload.exe 编译失败
    exit /b 1
)

echo [+] payload.exe 编译成功

echo.
echo [2/2] 编译 pe_inject.exe...
gcc -m64 src\pe_inject.c ^
    -o build\pe_inject.exe ^
    -O2 ^
    -s ^
    -lpsapi ^
    -Wall

if %ERRORLEVEL% neq 0 (
    echo [!] pe_inject.exe 编译失败
    exit /b 1
)

echo [+] pe_inject.exe 编译成功

echo.
echo ========================================
echo   构建完成!
echo ========================================
echo.
dir /b build\*.exe

echo.
echo 用法:
echo   build\pe_inject.exe ^<进程名或PID^> build\payload.exe
echo.
echo 示例:
echo   build\pe_inject.exe notepad.exe build\payload.exe
