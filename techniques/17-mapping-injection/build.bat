@echo off
REM Mapping Injection Build Script (Windows)

echo ========================================
echo   Building Mapping Injection (x64)
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
echo [2/2] 编译 mapping_injection.exe...
gcc -m64 src\mapping_injection.c ^
    -o build\mapping_injection.exe ^
    -O2 ^
    -s ^
    -Wall

if %ERRORLEVEL% neq 0 (
    echo [!] mapping_injection.exe 编译失败
    exit /b 1
)

echo [+] mapping_injection.exe 编译成功

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
echo   build\mapping_injection.exe ^<进程名或PID^> build\payload.bin
echo.
echo 示例:
echo   build\mapping_injection.exe explorer.exe build\payload.bin
echo.
echo 注意:
echo   需要 Windows 10 1703+ (build 10.0.15063+)
