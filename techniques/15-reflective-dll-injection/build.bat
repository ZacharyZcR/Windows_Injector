@echo off
REM Reflective DLL Injection - Build Script (Windows)
REM 编译反射 DLL 注入工具（x64 版本）

setlocal

echo ╔══════════════════════════════════════════════════════════╗
echo ║       Building Reflective DLL Injection (x64)           ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

REM 设置编译器和目录
set CC=gcc
set SRC_DIR=src
set BUILD_DIR=build
set CFLAGS=-Wall -Wextra -O2 -s -m64
set LDFLAGS=-ladvapi32

REM 创建构建目录
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM 清理旧文件
echo [*] 清理旧文件...
del /Q "%BUILD_DIR%\*.exe" "%BUILD_DIR%\*.dll" 2>nul

REM ============================================
REM 1. 编译测试 DLL（包含 ReflectiveLoader）
REM ============================================
echo.
echo [1/2] 编译测试 DLL...
echo     输入: %SRC_DIR%\test_dll.c
echo     输出: %BUILD_DIR%\reflective_dll.dll

%CC% -shared ^
    %SRC_DIR%\test_dll.c ^
    -o %BUILD_DIR%\reflective_dll.dll ^
    %CFLAGS% ^
    -DDLLEXPORT="__declspec(dllexport)" ^
    -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

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
echo     输入: %SRC_DIR%\inject.c, %SRC_DIR%\LoadLibraryR.c
echo     输出: %BUILD_DIR%\inject.exe

%CC% %SRC_DIR%\inject.c ^
    %SRC_DIR%\LoadLibraryR.c ^
    -o %BUILD_DIR%\inject.exe ^
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
echo 1. 启动目标进程 (例如记事本):
echo    start notepad
echo.
echo 2. 运行注入器:
echo    %BUILD_DIR%\inject.exe notepad.exe
echo.
echo 或者直接使用 PID:
echo    %BUILD_DIR%\inject.exe 1234
echo.
echo 3. 注入成功后会显示消息框
echo.
echo 注意事项:
echo   - 仅支持 x64 进程
echo   - DLL 必须导出 ReflectiveLoader 函数
echo   - 需要管理员权限注入系统进程
echo.

endlocal
