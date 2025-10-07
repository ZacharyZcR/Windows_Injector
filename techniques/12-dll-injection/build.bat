@echo off
REM ===================================================================
REM Build Script for DLL Injection
REM Based on: hasherezade/dll_injector
REM ===================================================================

echo ===================================================================
echo Building DLL Injection
echo ===================================================================
echo.

REM Create build directory
if not exist build mkdir build

REM Step 1: Compile test DLL
echo [*] Step 1: Compiling test_dll.dll...
gcc -shared -o build\test_dll.dll src\test_dll.c ^
    -O2 -s -Wl,--subsystem,windows
if %ERRORLEVEL% NEQ 0 (
    echo [-] Test DLL compilation failed!
    exit /b 1
)
echo [+] test_dll.dll compiled successfully
echo.

REM Step 2: Compile DLL injector
echo [*] Step 2: Compiling dll_injection.exe...
gcc -o build\dll_injection.exe src\dll_injection.c ^
    -lpsapi -O2 -s
if %ERRORLEVEL% NEQ 0 (
    echo [-] Injector compilation failed!
    exit /b 1
)
echo [+] dll_injection.exe compiled successfully
echo.

echo ===================================================================
echo [+] Build completed successfully!
echo ===================================================================
echo.
echo Files created:
echo   build\dll_injection.exe  - DLL injector
echo   build\test_dll.dll       - Test DLL
echo.
echo Usage:
echo   cd build
echo.
echo   # Inject to existing process
echo   dll_injection.exe 1234 test_dll.dll
echo.
echo   # Inject to new process
echo   dll_injection.exe "C:\Windows\System32\notepad.exe" test_dll.dll
echo.
echo   # Unload DLL
echo   dll_injection.exe 1234 test_dll.dll --unload
echo.
echo   # Check if DLL is loaded
echo   dll_injection.exe 1234 test_dll.dll --check
echo.
