@echo off
chcp 65001 >nul
echo ======================================
echo    事务性镂空项目构建脚本
echo ======================================
echo.

REM 进入源代码目录
cd /d "%~dp0src"

REM 编译主程序
echo [1/2] 编译主程序 transacted_hollowing.exe ...
gcc -o ..\transacted_hollowing.exe transacted_hollowing.c pe_utils.c ^
    -lktmw32 -lntdll -municode -I.

if %errorlevel% equ 0 (
    echo     ✓ transacted_hollowing.exe 编译成功
) else (
    echo     ✗ transacted_hollowing.exe 编译失败
    pause
    exit /b 1
)

REM 编译测试载荷
echo.
echo [2/2] 编译测试载荷 test_payload.exe ...
gcc -o ..\test_payload.exe test_payload.c

if %errorlevel% equ 0 (
    echo     ✓ test_payload.exe 编译成功
) else (
    echo     ✗ test_payload.exe 编译失败
    pause
    exit /b 1
)

REM 返回项目目录
cd ..

REM 显示完成信息
echo.
echo ======================================
echo    编译完成！
echo ======================================
echo.
echo 生成的文件：
dir /B *.exe 2>nul
echo.
echo 使用方法：
echo   transacted_hollowing.exe ^<载荷路径^> [目标进程]
echo.
echo 测试示例：
echo   transacted_hollowing.exe test_payload.exe
echo   transacted_hollowing.exe test_payload.exe notepad.exe
echo.
pause
