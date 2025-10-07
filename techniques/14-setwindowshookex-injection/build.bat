@echo off
REM SetWindowsHookEx Injection - Build Script (Windows)
REM 编译 SetWindowsHookEx 注入工具和测试 DLL

setlocal

echo ╔══════════════════════════════════════════════════════════╗
echo ║          Building SetWindowsHookEx Injection            ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

REM 设置编译器和目录
set CC=gcc
set WINDRES=windres
set SRC_DIR=src
set BUILD_DIR=build
set CFLAGS=-Wall -Wextra -O2 -s
set LDFLAGS=-luser32 -lgdi32

REM 创建构建目录
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM 清理旧文件
echo [*] 清理旧文件...
del /Q "%BUILD_DIR%\*.exe" "%BUILD_DIR%\*.dll" 2>nul

REM ============================================
REM 1. 编译测试 DLL
REM ============================================
echo.
echo [1/2] 编译测试 DLL...
echo     输入: %SRC_DIR%\hook_dll.c
echo     输出: %BUILD_DIR%\hook.dll

%CC% -shared ^
    %SRC_DIR%\hook_dll.c ^
    -o %BUILD_DIR%\hook.dll ^
    %CFLAGS% ^
    %LDFLAGS%

if %ERRORLEVEL% NEQ 0 (
    echo [!] DLL 编译失败!
    exit /b 1
)

echo     ✅ DLL 编译成功

REM ============================================
REM 2. 编译注入器
REM ============================================
echo.
echo [2/2] 编译注入器...
echo     输入: %SRC_DIR%\setwindowshookex_injection.c
echo     输出: %BUILD_DIR%\setwindowshookex_injection.exe

%CC% %SRC_DIR%\setwindowshookex_injection.c ^
    -o %BUILD_DIR%\setwindowshookex_injection.exe ^
    %CFLAGS% ^
    %LDFLAGS%

if %ERRORLEVEL% NEQ 0 (
    echo [!] 注入器编译失败!
    exit /b 1
)

echo     ✅ 注入器编译成功

REM ============================================
REM 显示构建结果
REM ============================================
echo.
echo ════════════════════════════════════════════════════════════
echo 构建完成! 输出文件:
echo ════════════════════════════════════════════════════════════

for %%F in ("%BUILD_DIR%\*.exe" "%BUILD_DIR%\*.dll") do (
    if exist "%%F" (
        for %%A in ("%%F") do (
            set "size=%%~zA"
            setlocal enabledelayedexpansion
            set /a size_kb=!size! / 1024
            echo   %%~nxA - !size_kb! KB
            endlocal
        )
    )
)

echo.
echo ════════════════════════════════════════════════════════════
echo 使用示例:
echo ════════════════════════════════════════════════════════════
echo.
echo 1. 启动一个 GUI 程序 (例如记事本):
echo    start notepad
echo.
echo 2. 运行注入器:
echo    %BUILD_DIR%\setwindowshookex_injection.exe "无标题 - 记事本" %CD%\%BUILD_DIR%\hook.dll
echo.
echo 3. 注入成功后会显示消息框
echo.
echo 注意事项:
echo   - 只能注入有窗口的 GUI 进程
echo   - DLL 路径必须是绝对路径
echo   - 目标窗口标题支持部分匹配
echo.

endlocal
