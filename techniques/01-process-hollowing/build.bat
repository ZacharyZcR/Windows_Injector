@echo off
chcp 65001 >nul
echo ======================================
echo    进程镂空项目构建脚本
echo ======================================
echo.

REM 进入源代码目录
cd /d "%~dp0src"

REM 编译主程序
echo [1/2] 编译主程序 process_hollowing.exe ...
gcc -o ..\process_hollowing.exe process_hollowing.c pe.c -ldbghelp -lntdll -I.

if %errorlevel% equ 0 (
    echo     ✓ process_hollowing.exe 编译成功
) else (
    echo     ✗ process_hollowing.exe 编译失败
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
dir /B *.exe
echo.
echo 使用方法：
echo   process_hollowing.exe ^<目标进程^> ^<源程序^>
echo.
echo 测试示例：
echo   process_hollowing.exe notepad.exe test_payload.exe
echo.
pause
