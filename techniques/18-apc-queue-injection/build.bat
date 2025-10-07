@echo off
REM APC Queue Injection Build Script (Windows)

echo ========================================
echo   Building APC Queue Injection (x64)
echo ========================================

if not exist build mkdir build

echo.
echo [1/2] 编译 generate_shellcode.exe...
gcc -m64 src\generate_shellcode.c ^
    -o build\generate_shellcode.exe ^
    -O2 ^
    -s ^
    -Wall

if %ERRORLEVEL% neq 0 (
    echo [!] generate_shellcode.exe 编译失败
    exit /b 1
)

echo [+] generate_shellcode.exe 编译成功

echo.
echo [2/2] 编译 apc_queue_injection.exe...
gcc -m64 src\apc_queue_injection.c ^
    -o build\apc_queue_injection.exe ^
    -O2 ^
    -s ^
    -Wall

if %ERRORLEVEL% neq 0 (
    echo [!] apc_queue_injection.exe 编译失败
    exit /b 1
)

echo [+] apc_queue_injection.exe 编译成功

echo.
echo [3/3] 生成测试 shellcode...
cd build
generate_shellcode.exe messagebox payload.bin
cd ..

echo.
echo ========================================
echo   构建完成!
echo ========================================
echo.
dir /b build\*.exe build\*.bin

echo.
echo 用法:
echo   build\apc_queue_injection.exe ^<进程名或PID^> build\payload.bin
echo.
echo 示例:
echo   build\apc_queue_injection.exe notepad.exe build\payload.bin
echo.
echo 注意:
echo   目标进程的线程必须进入 alertable 状态时才会执行 APC
