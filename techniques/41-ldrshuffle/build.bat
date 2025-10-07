@echo off
echo Building LdrShuffle...

gcc -o ldrshuffle.exe ^
    src/ldrshuffle.c ^
    -lntdll ^
    -mconsole ^
    -O2 -s

if %ERRORLEVEL% EQU 0 (
    echo Build successful: ldrshuffle.exe
) else (
    echo Build failed!
    exit /b 1
)
