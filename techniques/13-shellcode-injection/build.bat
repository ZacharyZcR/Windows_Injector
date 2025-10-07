@echo off
REM ===================================================================
REM Build Script for Classic Shellcode Injection
REM Based on: plackyhacker/Shellcode-Injection-Techniques
REM ===================================================================

echo ===================================================================
echo Building Classic Shellcode Injection
echo ===================================================================
echo.

REM Create build directory
if not exist build mkdir build

REM Step 1: Compile shellcode generator
echo [*] Step 1: Compiling generate_shellcode.exe...
gcc -o build\generate_shellcode.exe src\generate_shellcode.c ^
    -O2 -s
if %ERRORLEVEL% NEQ 0 (
    echo [-] Shellcode generator compilation failed!
    exit /b 1
)
echo [+] generate_shellcode.exe compiled successfully
echo.

REM Step 2: Generate test shellcode
echo [*] Step 2: Generating test shellcode...
cd build
.\generate_shellcode.exe calc
if %ERRORLEVEL% NEQ 0 (
    echo [-] Shellcode generation failed!
    cd ..
    exit /b 1
)
cd ..
echo [+] Test shellcode generated
echo.

REM Step 3: Compile shellcode injector
echo [*] Step 3: Compiling shellcode_injection.exe...
gcc -o build\shellcode_injection.exe src\shellcode_injection.c ^
    -O2 -s
if %ERRORLEVEL% NEQ 0 (
    echo [-] Injector compilation failed!
    exit /b 1
)
echo [+] shellcode_injection.exe compiled successfully
echo.

echo ===================================================================
echo [+] Build completed successfully!
echo ===================================================================
echo.
echo Files created:
echo   build\shellcode_injection.exe  - Shellcode injector
echo   build\generate_shellcode.exe   - Shellcode generator
echo   build\calc_shellcode.bin       - Test shellcode (calc.exe)
echo.
echo Usage:
echo   cd build
echo.
echo   # Inject to existing process
echo   shellcode_injection.exe 1234 calc_shellcode.bin
echo.
echo   # Inject to new process
echo   shellcode_injection.exe "C:\Windows\System32\notepad.exe" calc_shellcode.bin
echo.
echo   # Generate custom shellcode
echo   generate_shellcode.exe calc
echo.
