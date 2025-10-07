@echo off
REM ===================================================================
REM Ruy-Lopez DLL Blocking - Shellcode Builder
REM ===================================================================
REM
REM 编译 PIC (Position Independent Code) shellcode
REM 这个 shellcode 会被注入到目标进程，hook NtCreateSection

echo ===================================================================
echo Building PIC Shellcode (HookShellcode)
echo ===================================================================
echo.

cd src

echo [*] Step 1: Compiling ApiResolve.c...
gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,--no-seh
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to compile ApiResolve.c
    exit /b 1
)
echo [+] ApiResolve.o compiled successfully

echo.
echo [*] Step 2: Compiling HookShellcode.c...
gcc HookShellcode.c -Wall -m64 -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o HookShellcode.o -Wl,--no-seh
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to compile HookShellcode.c
    exit /b 1
)
echo [+] HookShellcode.o compiled successfully

echo.
echo [*] Step 3: Linking objects...
ld -s ApiResolve.o HookShellcode.o -o HookShellcode.exe
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to link objects
    exit /b 1
)
echo [+] HookShellcode.exe linked successfully

echo.
echo [*] Step 4: Compiling extract tool...
gcc extract.c -o extract.exe
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to compile extract.c
    exit /b 1
)
echo [+] extract.exe compiled successfully

echo.
echo [*] Step 5: Extracting .text section to hook.bin...
extract.exe
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to extract shellcode
    exit /b 1
)
echo [+] hook.bin generated successfully

echo.
echo ===================================================================
echo [+] PIC Shellcode built successfully!
echo [+] Output: src\hook.bin
echo ===================================================================

cd ..
exit /b 0
