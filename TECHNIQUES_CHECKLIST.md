# 注入技术清单

## 已实现 ✅

### 1. 进程镂空（Process Hollowing）
- **目录**：`techniques/01-process-hollowing/`
- **完成日期**：2024-10-06
- **描述**：创建挂起进程，卸载原镜像，注入新代码
- **特点**：完整中文注释、支持 32/64 位、详细日志

### 2. 事务性镂空（Transacted Hollowing）
- **目录**：`techniques/02-transacted-hollowing/`
- **完成日期**：2024-10-06
- **描述**：使用 NTFS 事务机制创建内存节，载荷不落地
- **特点**：高隐蔽性、SEC_IMAGE 映射、事务回滚删除文件
- **技术等级**：⭐⭐⭐⭐⭐

### 3. 进程变脸（Process Doppelgänging）
- **目录**：`techniques/03-process-doppelganging/`
- **完成日期**：2024-10-06
- **描述**：利用 NTFS 事务和 NtCreateProcessEx API 直接从内存节创建进程
- **特点**：无文件关联、完全匿名、极高隐蔽性、不需要目标进程
- **技术等级**：⭐⭐⭐⭐⭐
- **关键 API**：NtCreateProcessEx、CreateTransaction、RtlCreateProcessParametersEx

### 4. 进程伪装（Process Herpaderping）
- **目录**：`techniques/04-process-herpaderping/`
- **完成日期**：2024-10-06
- **描述**：创建镜像节后修改磁盘文件，利用节缓存机制欺骗安全产品
- **特点**：时序攻击、归因错误、无需事务、绕过 Defender 和 EDR
- **技术等级**：⭐⭐⭐⭐⭐
- **关键 API**：NtCreateSection、NtCreateProcessEx、文件覆盖
- **发现者**：Johnny Shaw (2020)

---

## 计划实现 📋

### 5. DLL 注入（DLL Injection）
- **预计目录**：`techniques/05-dll-injection/`
- **优先级**：⭐⭐⭐⭐⭐
- **难度**：⭐⭐
- **方法**：
  - CreateRemoteThread + LoadLibrary
  - NtCreateThreadEx
  - QueueUserAPC
  - SetWindowsHookEx
- **参考资源**：
  - https://github.com/zodiacon/InjectDll
  - https://github.com/secrary/InjectProc

### 6. 反射 DLL 注入（Reflective DLL Injection）
- **预计目录**：`techniques/06-reflective-dll/`
- **优先级**：⭐⭐⭐⭐
- **难度**：⭐⭐⭐⭐
- **描述**：手动加载 DLL 到内存，不经过文件系统
- **参考资源**：
  - https://github.com/stephenfewer/ReflectiveDLLInjection

### 7. APC 注入（APC Injection）
- **预计目录**：`techniques/07-apc-injection/`
- **优先级**：⭐⭐⭐⭐
- **难度**：⭐⭐⭐
- **描述**：利用异步过程调用注入代码
- **参考资源**：
  - https://github.com/aaaddress1/APC-Injection

### 8. Atom Bombing
- **预计目录**：`techniques/08-atom-bombing/`
- **优先级**：⭐⭐⭐
- **难度**：⭐⭐⭐⭐
- **描述**：利用全局 Atom 表和 APC 注入代码
- **参考资源**：
  - https://github.com/BreakingMalwareResearch/atom-bombing

### 9. 进程幽灵（Process Ghosting）
- **预计目录**：`techniques/09-process-ghosting/`
- **优先级**：⭐⭐⭐
- **难度**：⭐⭐⭐⭐⭐
- **描述**：利用删除待处理的文件映射创建进程
- **参考资源**：
  - https://github.com/hasherezade/process_ghosting

### 10. 线程执行劫持（Thread Execution Hijacking）
- **预计目录**：`techniques/10-thread-hijacking/`
- **优先级**：⭐⭐⭐⭐
- **难度**：⭐⭐⭐
- **描述**：挂起线程，修改上下文，注入代码

### 11. PROPagate 注入
- **预计目录**：`techniques/11-propagate/`
- **优先级**：⭐⭐
- **难度**：⭐⭐⭐
- **描述**：利用窗口属性注入代码

### 12. Shim 注入
- **预计目录**：`techniques/12-shim-injection/`
- **优先级**：⭐⭐
- **难度**：⭐⭐⭐⭐
- **描述**：应用程序兼容性垫片注入

### 13. IAT 钩子（IAT Hooking）
- **预计目录**：`techniques/13-iat-hooking/`
- **优先级**：⭐⭐⭐⭐⭐
- **难度**：⭐⭐
- **描述**：修改导入地址表劫持函数调用

### 14. 内联钩子（Inline Hooking）
- **预计目录**：`techniques/14-inline-hooking/`
- **优先级**：⭐⭐⭐⭐⭐
- **难度**：⭐⭐⭐
- **描述**：修改函数开头字节跳转到自定义代码

### 15. ALPC 注入
- **预计目录**：`techniques/15-alpc-injection/`
- **优先级**：⭐⭐
- **难度**：⭐⭐⭐⭐⭐
- **描述**：高级本地过程调用注入

### 16. 额外窗口内存注入（Extra Window Memory）
- **预计目录**：`techniques/16-ewm-injection/`
- **优先级**：⭐⭐
- **难度**：⭐⭐⭐
- **描述**：利用额外窗口内存注入代码

### 17. Ctrl Inject
- **预计目录**：`techniques/17-ctrl-inject/`
- **优先级**：⭐⭐
- **难度**：⭐⭐⭐
- **描述**：利用控制台窗口注入

---

## 添加新技术的模板

当你要添加新技术时，遵循以下结构：

```
techniques/XX-technique-name/
├── README.md              # 技术文档
├── build.sh               # Linux/macOS 构建脚本
├── build.bat              # Windows 构建脚本
├── CMakeLists.txt         # CMake 构建文件
└── src/                   # 源代码目录
    ├── main.c             # 主程序
    ├── technique.c        # 技术实现
    ├── technique.h        # 头文件
    └── test_payload.c     # 测试载荷（可选）
```

### README.md 应包含：
1. 技术原理
2. 实现步骤
3. 编译方法
4. 使用示例
5. 检测与防御
6. 参考资源

### 构建脚本应支持：
- 从 `src/` 目录编译
- 输出到项目根目录
- 显示详细的编译信息

### 代码规范：
- 使用中文注释
- 函数前添加功能说明
- 输出信息中文化
- 详细的执行日志

---

## 学习路径建议

### 初学者路径
1. ✅ Process Hollowing（已完成）
2. ✅ Transacted Hollowing（已完成）
3. DLL Injection - CreateRemoteThread
4. IAT Hooking
5. Inline Hooking

### 进阶路径
6. Reflective DLL Injection
7. APC Injection
8. Thread Execution Hijacking
9. Atom Bombing

### 高级路径
10. ✅ Process Doppelgänging（已完成）
11. ✅ Process Herpaderping（已完成）
12. Process Ghosting
13. ALPC Injection

---

## 注意事项

1. **法律合规**：所有技术仅用于安全研究和教育目的
2. **测试环境**：在虚拟机或隔离环境中测试
3. **文档完整**：每个技术都要有完整的中文文档
4. **代码质量**：保持代码简洁、注释清晰
5. **参考资源**：注明所有参考资料的来源

---

## 贡献指南

欢迎贡献新的注入技术！提交前请确保：

- [ ] 代码编译通过
- [ ] 包含完整的 README.md
- [ ] 提供构建脚本
- [ ] 中文注释完整
- [ ] 测试通过

---

**更新日期**：2024-10-06
