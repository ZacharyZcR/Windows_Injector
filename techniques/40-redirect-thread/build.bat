@echo off
echo Building RedirectThread...

gcc -o redirect_thread.exe ^
    src/redirect_thread.c ^
    -lntdll -lpsapi ^
    -mconsole ^
    -O2 -s

if %ERRORLEVEL% EQU 0 (
    echo Build successful: redirect_thread.exe
) else (
    echo Build failed!
    exit /b 1
)
