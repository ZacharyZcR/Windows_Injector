# Windows Process Injection Techniques

English | [简体中文](./README.md)

A comprehensive collection of 41 Windows process injection techniques implemented in C, covering classic methods to cutting-edge research.

## Overview

This repository contains complete implementations of Windows process injection techniques, systematically organized from fundamental concepts to advanced evasion methods. Each technique is a standalone implementation with detailed documentation explaining the underlying mechanics, detection strategies, and practical applications.

**Not a penetration testing framework**. Not a red team toolkit. This is a reference implementation for understanding Windows internals, security research, and defensive programming.

## Project Statistics

- **41 Technique Implementations**: 100% working, real-world code
- **Language**: Pure C with minimal dependencies
- **Target Platform**: Windows x64 (with x86 support where applicable)
- **Build System**: MinGW/GCC compatible

## Technique Categories

### Process Manipulation (1-5)

Advanced attacks leveraging Windows process creation mechanisms:

1. **Process Hollowing**
2. **Transacted Hollowing**
3. **Process Doppelgänging**
4. **Process Herpaderping**
5. **Process Ghosting**

### Early Execution and Callback (6-10)

Hijacking execution flow during process/thread initialization:

6. **Early Bird APC**
7. **Entry Point Injection**
8. **DLL Blocking (Ruy-Lopez)**
9. **Early Cascade**
10. **Kernel Callback Table**

### Classic Injection (11-20)

Foundational Windows injection methods:

11. **Advanced Hollowing**
12. **DLL Injection**
13. **Shellcode Injection**
14. **SetWindowsHookEx**
15. **Reflective DLL Injection**
16. **PE Injection**
17. **Mapping Injection**
18. **APC Queue Injection**
19. **Thread Hijacking**
20. **Atom Bombing**

### Advanced Evasion (21-31)

Innovative methods to bypass modern security defenses:

21. **Mockingjay** - RWX Section Injection
22. **PowerLoaderEx** - Shared Desktop Heap Injection
23. **Threadless Inject**
24. **EPI** - DLL Entry Point Hijacking
25. **DLL Notification Injection**
26. **Module Stomping**
27. **Gadget APC Injection**
28. **Process Forking (Dirty Vanity)**
29. **Function Stomping**
30. **Caro-Kann** - Encrypted Shellcode Memory Scan Evasion
31. **Stack Bombing**

### Modern Cutting-Edge (32-41)

Latest security research from 2023-2024:

32. **GhostInjector**
33. **GhostWriting**
34. **GhostWriting-2**
35. **Mapping Injection** (Enhanced)
36. **SetProcessInjection** - ProcessInstrumentationCallback Injection
37. **PoolParty** - Windows Thread Pool Injection (TP_WORK/TP_WAIT/TP_TIMER/TP_IO/TP_JOB/TP_ALPC/TP_DIRECT)
38. **Thread Name-Calling**
39. **Waiting Thread Hijacking**
40. **RedirectThread** - CONTEXT-Only Injection (ROP Gadget + DLL Pointer)
41. **LdrShuffle** - EntryPoint Hijacking

## Project Structure

```
Injection/
├── techniques/
│   ├── 01-process-hollowing/
│   ├── 02-transacted-hollowing/
│   ├── ...
│   └── 41-ldrshuffle/
│       ├── src/
│       │   └── ldrshuffle.c
│       ├── build.bat
│       └── README.md
├── README.md
└── TECHNIQUE_VERIFICATION.md
```

Each technique directory contains:
- **src/**: Complete source code implementation
- **build.bat/build.sh**: Standalone build script
- **README.md**: Detailed technical documentation
- **Executable**: Compiled binary (after building)

## Building

### Prerequisites
- MinGW-w64 (GCC for Windows)
- Windows SDK headers

### Build Single Technique
```batch
cd techniques\01-process-hollowing
build.bat
```

### Build All Techniques
```batch
for /d %d in (techniques\*) do (
    if exist "%d\build.bat" (
        cd "%d" && call build.bat && cd ..\..
    )
)
```

## Usage

Each technique is a standalone executable demonstrating the injection method:

```batch
cd techniques\41-ldrshuffle
ldrshuffle.exe
```

Most implementations include:
- **Verbose Output**: Shows each step of the injection process
- **Error Handling**: Explains why operations fail
- **Safety Checks**: Validates prerequisites before execution

## Documentation

- **README.md**: Chinese version - project overview
- **README_EN.md**: This file - English version of project overview
- **TECHNIQUE_VERIFICATION.md**: Detailed technical breakdown of all 41 techniques
- **techniques/XX-name/README.md**: Per-technique deep dive with execution flow diagrams

## Security Notice

**This repository is for educational and defensive security research only.**

These techniques are implemented to:
- Understand Windows security internals
- Develop detection strategies
- Improve endpoint protection
- Train security professionals

Unauthorized use of these techniques for illegal access is unlawful and unethical.

## Reference Repositories

Each technique in this project is based on original research implementations. Below is the complete list of all reference repositories (sorted by technique number):

### Process Manipulation (1-5)
1. [m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing) - Process Hollowing
2. [hasherezade/transacted_hollowing](https://github.com/hasherezade/transacted_hollowing) - Transacted Hollowing
3. [hasherezade/process_doppelganging](https://github.com/hasherezade/process_doppelganging) - Process Doppelgänging
4. [jxy-s/herpaderping](https://github.com/jxy-s/herpaderping) - Process Herpaderping
5. [hasherezade/process_ghosting](https://github.com/hasherezade/process_ghosting) - Process Ghosting

### Early Execution and Callback (6-10)
6. [S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) - Early Bird APC (includes Ruy-Lopez/HookForward)
7. [diversenok/Suspending-Techniques](https://github.com/diversenok/Suspending-Techniques) - Entry Point Injection (AddressOfEntryPoint-injection)
8. [S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) - DLL Blocking (includes Ruy-Lopez/DllBlock)
9. [D1rkMtr/earlycascade-injection](https://github.com/D1rkMtr/earlycascade-injection) - Early Cascade
10. [odzhan/injection](https://github.com/odzhan/injection) - Kernel Callback Table (KernelCallbackTable-Injection-PoC)

### Classic Injection (11-20)
11. [snovvcrash/PichichiH0ll0wer](https://github.com/snovvcrash/PichichiH0ll0wer) - Advanced Hollowing (Nim)
12. [stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) - DLL Injection (also used for Reflective DLL Injection)
13. [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) - Shellcode Injection (reference)
14. [hfiref0x/WinObjEx64](https://github.com/hfiref0x/WinObjEx64) - SetWindowsHookEx (reference)
15. [stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) - Reflective DLL Injection
16. [NUL0x4C/PE-Injection](https://github.com/NUL0x4C/PE-Injection) - PE Injection
17. [hasherezade/process_doppelganging](https://github.com/hasherezade/process_doppelganging) - Mapping Injection (reference)
18. [Kudaes/Rust-APC-Queue-Injection](https://github.com/Kudaes/Rust-APC-Queue-Injection) - APC Queue Injection (Rust)
19. [iGh0st/ThreadHijacking](https://github.com/iGh0st/ThreadHijacking) - Thread Hijacking (C#)
20. [BreakingMalwareResearch/atom-bombing](https://github.com/BreakingMalwareResearch/atom-bombing) - Atom Bombing

### Advanced Evasion (21-31)
21. [secur30nly/Mockingjay](https://github.com/secur30nly/Mockingjay) - Mockingjay
22. [BreakingMalware/PowerLoaderEx](https://github.com/BreakingMalware/PowerLoaderEx) - PowerLoaderEx
23. [CCob/ThreadlessInject](https://github.com/CCob/ThreadlessInject) - Threadless Inject
24. [Kudaes/EPI](https://github.com/Kudaes/EPI) - EPI
25. [Dec0ne/DllNotificationInjection](https://github.com/Dec0ne/DllNotificationInjection) and [ShorSec/DllNotificationInjection](https://github.com/ShorSec/DllNotificationInjection) - DLL Notification Injection
26. [D1rkMtr/D1rkInject](https://github.com/D1rkMtr/D1rkInject) - Module Stomping
27. [LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection](https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection) - Gadget APC Injection
28. [deepinstinct/Dirty-Vanity](https://github.com/deepinstinct/Dirty-Vanity) - Process Forking
29. [Idov31/FunctionStomping](https://github.com/Idov31/FunctionStomping) - Function Stomping
30. [S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) - Caro-Kann
31. [StackBombing/StackBombing](https://github.com/StackBombing/StackBombing) - Stack Bombing

### Modern Cutting-Edge (32-41)
32. [woldann/GhostInjector](https://github.com/woldann/GhostInjector) - GhostInjector (dependencies: NThread, NThreadOSUtils, Neptune)
33. [c0de90e7/GhostWriting](https://github.com/c0de90e7/GhostWriting) - GhostWriting
34. [fern89/ghostwriting-2](https://github.com/fern89/ghostwriting-2) - GhostWriting-2
35. [antonioCoco/Mapping-Injection](https://github.com/antonioCoco/Mapping-Injection) - Mapping Injection (Enhanced)
36. [OtterHacker/SetProcessInjection](https://github.com/OtterHacker/SetProcessInjection) - SetProcessInjection
37. [SafeBreach-Labs/PoolParty](https://github.com/SafeBreach-Labs/PoolParty) - PoolParty
38. [hasherezade/thread_namecalling](https://github.com/hasherezade/thread_namecalling) - Thread Name-Calling
39. [hasherezade/waiting_thread_hijacking](https://github.com/hasherezade/waiting_thread_hijacking) - Waiting Thread Hijacking
40. [Friends-Security/RedirectThread](https://github.com/Friends-Security/RedirectThread) - RedirectThread
41. [RWXstoned/LdrShuffle](https://github.com/RWXstoned/LdrShuffle) - LdrShuffle

## Acknowledgments

### Researchers and Organizations
- **@hasherezade** - Multiple pioneering research contributions in Windows process injection (Process Doppelgänging, Transacted Hollowing, Process Ghosting, Waiting Thread Hijacking, Thread Name-Calling)
- **SafeBreach Labs** - Complete PoolParty technique suite implementation
- **@RWXstoned** - LdrShuffle EntryPoint hijacking technique
- **Friends-Security** - RedirectThread CONTEXT-Only injection research
- **@stephenfewer** - Reflective DLL Injection, the foundation of modern in-memory execution
- **BreakingMalware Research** - AtomBombing and PowerLoaderEx
- **@jxy-s** - Process Herpaderping timing attack
- **@m0n0ph1** - Classic Process Hollowing implementation
- **@CCob** - Threadless Inject technique
- **@Idov31** - Function Stomping technique
- **@S3cur3Th1sSh1t** - Caro-Kann encrypted evasion
- **@antonioCoco** - Enhanced Mapping Injection
- **All other researchers** - Contributions in their respective domains

### Community Resources
- [Pinvoke.net](http://pinvoke.net/) - Win32 API reference
- [Undocumented NT Functions](http://undocumented.ntinternals.net/)
- [Windows Internals Book Series](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals) by Mark Russinovich
- [Black Hat 2019 - Process Injection Techniques](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf)
- [DEF CON 23 - Injection on Steroids](https://www.youtube.com/watch?v=6nZw5qLYMm4)

### Development Tools
This project was developed using **[Claude Code](https://claude.com/claude-code)**, Anthropic's official AI programming assistant. Claude Code provided critical support in:
- Code implementation and debugging
- Technical documentation writing
- Project structure organization
- Security best practice recommendations

## Why C?

- **Minimal Dependencies**: No runtime, no frameworks, just Windows APIs
- **Transparency**: Every operation is explicit
- **Educational**: Shows exactly what's happening at the API level
- **Portability**: Works with any C compiler (MinGW, MSVC, Clang)

## Roadmap

This project is feature-complete with 41 techniques. Future work may include:

- [ ] ARM64 Windows support
- [ ] Kernel-mode injection techniques
- [ ] Enhanced detection evasion analysis
- [ ] Performance benchmarking suite

## Contributing

Contributions are welcome for:
- Bug fixes in existing implementations
- Documentation improvements
- New technique implementations (with original research attribution)
- Detection strategy enhancements

Please ensure:
1. Code compiles with MinGW-w64
2. New techniques include detailed README.md
3. Proper attribution for research sources
4. Testing on Windows 10/11

## License

This project is for educational purposes. Individual techniques may have different licenses - see each technique's README for details.

---

**Research, Learn, Defend.**
