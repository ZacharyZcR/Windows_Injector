#!/bin/bash

echo "Building DLL Notification Injection..."

mkdir -p build

gcc -O2 -o build/dll_notification_injection.exe src/dll_notification_injection.c -lntdll

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Output: build/dll_notification_injection.exe"
else
    echo "Build failed!"
    exit 1
fi
