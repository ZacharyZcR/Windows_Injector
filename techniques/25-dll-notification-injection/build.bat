@echo off
echo Building DLL Notification Injection...

if not exist "build" mkdir build

gcc -O2 -o build\dll_notification_injection.exe src\dll_notification_injection.c -lntdll

if %ERRORLEVEL% == 0 (
    echo Build successful!
    echo Output: build\dll_notification_injection.exe
) else (
    echo Build failed!
    exit /b 1
)
