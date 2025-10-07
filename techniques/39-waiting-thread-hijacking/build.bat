@echo off
echo Building Waiting Thread Hijacking...

gcc -o waiting_thread_hijacking.exe ^
    src/waiting_thread_hijacking.c ^
    -lntdll -lpsapi ^
    -mconsole ^
    -O2 -s

if %ERRORLEVEL% EQU 0 (
    echo Build successful: waiting_thread_hijacking.exe
) else (
    echo Build failed!
    exit /b 1
)
