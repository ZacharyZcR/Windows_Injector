# ===================================================================
# Ruy-Lopez DLL Blocking - AMSI Test Script
# ===================================================================
#
# 此脚本用于测试 AMSI (Antimalware Scan Interface) 是否被成功阻止加载
#
# 使用方法：
# 1. 运行 dll_blocking.exe（会创建挂起的 PowerShell 进程）
# 2. PowerShell 启动后，会自动加载这个脚本（如果配置了）
# 或者手动在新 PowerShell 窗口中运行此脚本
#
# 预期结果：
# - 如果 amsi.dll 被成功阻止，AMSI 相关功能将不可用
# - 某些通常会被 AMSI 拦截的操作可以执行

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "AMSI DLL Loading Test" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

# 测试 1：检查 amsi.dll 是否已加载
Write-Host "[*] Test 1: Checking if amsi.dll is loaded..." -ForegroundColor Yellow

$amsidll = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.Location -like "*amsi.dll" }

if ($amsidll) {
    Write-Host "[-] FAIL: amsi.dll is loaded!" -ForegroundColor Red
    Write-Host "    Location: $($amsidll.Location)" -ForegroundColor Red
} else {
    Write-Host "[+] PASS: amsi.dll is NOT loaded!" -ForegroundColor Green
}

Write-Host ""

# 测试 2：检查当前进程加载的模块
Write-Host "[*] Test 2: Enumerating loaded modules..." -ForegroundColor Yellow

$currentProcess = Get-Process -Id $PID
$modules = $currentProcess.Modules | Where-Object { $_.ModuleName -like "*amsi*" }

if ($modules) {
    Write-Host "[-] FAIL: AMSI module found in process!" -ForegroundColor Red
    foreach ($mod in $modules) {
        Write-Host "    - $($mod.ModuleName) at $($mod.BaseAddress)" -ForegroundColor Red
    }
} else {
    Write-Host "[+] PASS: No AMSI module found in process!" -ForegroundColor Green
}

Write-Host ""

# 测试 3：尝试使用 AMSI API（如果存在）
Write-Host "[*] Test 3: Testing AMSI functionality..." -ForegroundColor Yellow

try {
    # 尝试访问 AMSI 相关类型
    $amsiUtils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

    if ($amsiUtils) {
        Write-Host "[-] WARNING: AmsiUtils type is available" -ForegroundColor Yellow

        # 检查 AMSI 是否实际工作
        $amsiInitFailed = $amsiUtils.GetField('amsiInitFailed', 'NonPublic,Static')
        if ($amsiInitFailed) {
            $value = $amsiInitFailed.GetValue($null)
            Write-Host "    amsiInitFailed = $value" -ForegroundColor Yellow

            if ($value -eq $true) {
                Write-Host "[+] PASS: AMSI initialization failed!" -ForegroundColor Green
            } else {
                Write-Host "[-] FAIL: AMSI is initialized and working!" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "[+] PASS: AMSI types not accessible!" -ForegroundColor Green
    Write-Host "    Exception: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host ""

# 测试 4：列出所有加载的 DLL（供参考）
Write-Host "[*] Test 4: Listing key loaded DLLs..." -ForegroundColor Yellow

$keyDlls = $currentProcess.Modules |
    Where-Object {
        $_.ModuleName -like "*.dll" -and
        ($_.ModuleName -like "*ntdll*" -or
         $_.ModuleName -like "*kernel32*" -or
         $_.ModuleName -like "*amsi*")
    } |
    Select-Object ModuleName, BaseAddress, Size

if ($keyDlls) {
    $keyDlls | Format-Table -AutoSize
} else {
    Write-Host "    No key DLLs found" -ForegroundColor Gray
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "Test completed!" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
