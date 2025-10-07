# Technique 41: LdrShuffle - EntryPoint Hijacking

## Overview

LdrShuffle is a stealthy code execution technique that works by modifying the `EntryPoint` field of loaded modules at runtime. By overwriting the `EntryPoint` in a DLL's `_LDR_DATA_TABLE_ENTRY` structure, we can redirect execution to arbitrary code whenever the Windows Loader invokes that DLL's `DllMain()` function.

**Original Research**: RWXstoned (2024)
**Reference**: https://github.com/RWXstoned/LdrShuffle

## Core Concept

Every Windows process maintains a list of `_LDR_DATA_TABLE_ENTRY` structures in its PEB (Process Environment Block). Each structure describes a loaded DLL and contains:
- DLL base address
- **EntryPoint** ← The address of `DllMain()`
- Size of image
- DLL name
- Various flags and metadata

When Windows needs to call a DLL's `DllMain()` (during process/thread attach/detach events), it reads the `EntryPoint` from this structure and calls it.

**The Attack**: Overwrite the `EntryPoint` to point to our malicious code instead!

## When Does DllMain() Get Called?

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:  // DLL loaded into process
        case DLL_PROCESS_DETACH:  // DLL being unloaded
        case DLL_THREAD_ATTACH:   // New thread created ← We trigger this!
        case DLL_THREAD_DETACH:   // Thread being destroyed
    }
    return TRUE;
}
```

**Key Insight**: Creating a new thread triggers `DLL_THREAD_ATTACH` for all loaded DLLs (unless `DontCallForThreads` flag is set).

## Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. Load Sacrificial DLL (e.g., version.dll)            │
│    - Any DLL that won't cause stability issues          │
│    - Avoid critical DLLs like ntdll.dll, kernel32.dll   │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 2. Find DLL's _LDR_DATA_TABLE_ENTRY in PEB             │
│    - Walk PEB->Ldr->InMemoryOrderModuleList            │
│    - Match DLL by name (BaseDllName)                    │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 3. Backup Original EntryPoint                           │
│    - Save EntryPoint in OriginalBase field              │
│    - Store in DATA_T structure for later restoration    │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 4. Overwrite EntryPoint with Runner() Address          │
│    - EntryPoint now points to our malicious code        │
│    - Windows doesn't know the difference!               │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 5. Trigger Execution via CreateThread()                │
│    - Create a dummy thread                              │
│    - Windows calls "DllMain" for DLL_THREAD_ATTACH      │
│    - Actually calls Runner() instead!                   │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 6. Runner() Executes                                    │
│    - Restore original EntryPoint                        │
│    - Execute our malicious API call                     │
│    - Call original DllMain() (proxy)                    │
│    - Thread continues normally                          │
└─────────────────────────────────────────────────────────┘
```

## Technical Deep Dive

### PEB_LDR_DATA Structure

```c
typedef struct _PEB {
    ...
    PPEB_LDR_DATA Ldr;  // ← Points to loader data
    ...
} PEB;

typedef struct _PEB_LDR_DATA {
    ...
    LIST_ENTRY InMemoryOrderModuleList;  // ← Doubly-linked list of modules
    ...
} PEB_LDR_DATA;
```

### _LDR_DATA_TABLE_ENTRY2 Structure (Simplified)

```c
typedef struct _LDR_DATA_TABLE_ENTRY2 {
    LIST_ENTRY InMemoryOrderLinks;  // Links to next/prev modules
    PVOID DllBase;                  // Base address of DLL
    PVOID EntryPoint;               // ← Address of DllMain() - WE MODIFY THIS
    ULONG SizeOfImage;              // Size of DLL image
    UNICODE_STRING BaseDllName;     // DLL name (e.g., "version.dll")
    ...
    ULONG_PTR OriginalBase;         // ← We backup EntryPoint here
    ...
} LDR_DATA_TABLE_ENTRY2;
```

### DATA_T Structure

```c
typedef struct _DATA_T {
    // LDR manipulation
    ULONG_PTR runner;            // Address of Runner() function
    ULONG_PTR bakOriginalBase;   // Backup of OriginalBase
    ULONG_PTR bakEntryPoint;     // Backup of original EntryPoint
    HANDLE event;                // Synchronization event

    // Function call setup
    ULONG_PTR ret;               // Return value storage
    DWORD createThread;          // Run in new thread? (for wininet/winhttp)
    ULONG_PTR function;          // API function to call
    DWORD dwArgs;                // Number of arguments
    ULONG_PTR args[MAX_ARGS];    // Arguments array
} DATA_T;
```

### Runner() Function - The Heart of LdrShuffle

```c
VOID Runner(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    // Windows thinks it's calling DllMain(), but it's actually calling us!

    // 1. Get our DATA_T structure (contains all our setup)
    PDATA_T pDataT = g_pDataT;

    // 2. Restore original EntryPoint
    //    - Find _LDR_DATA_TABLE_ENTRY matching hinstDLL
    //    - Set EntryPoint = bakEntryPoint
    //    - Set OriginalBase = bakOriginalBase
    RestoreLdr(hinstDLL, pDataT);

    // 3. Execute our malicious API call
    //    - Use function pointer from pDataT->function
    //    - Pass arguments from pDataT->args[]
    //    - Store return value in pDataT->ret
    if (pDataT->createThread) {
        CreateThread(NULL, 0, RunInThread, pDataT, 0, NULL);
    } else {
        pDataT->ret = ((APICALL_4)pDataT->function)(args[0], args[1], args[2], args[3]);
    }

    // 4. Call original DllMain (proxy the call)
    //    - This ensures normal DLL behavior
    ((DLLMAIN)bakEntryPoint)(hinstDLL, fdwReason, lpvReserved);
}
```

## Callstack Analysis

When `Runner()` is invoked by Windows, the callstack looks completely legitimate:

```
MessageBoxA()                    ← Our malicious API
Runner()                         ← Our fake DllMain
ntdll!LdrpCallInitRoutine()      ← Windows Loader function
ntdll!LdrpInitializeThread()     ← Windows thread initialization
ntdll!LdrInitializeThunk()       ← Windows kernel transition
kernel32!BaseThreadInitThunk()   ← Thread entry point
ntdll!RtlUserThreadStart()       ← Thread start routine
```

**Key Advantage**: The callstack appears to originate from legitimate Windows internals, not from suspicious functions like `CreateRemoteThread`.

## Use Cases

### 1. Code Execution Primitive

Execute arbitrary code in the current process without alerting EDR/AV that monitors:
- `CreateThread`
- `QueueUserAPC`
- `SetThreadContext`

### 2. API Proxying

Call sensitive APIs (e.g., network functions) with a clean callstack:
- The API appears to be called from Windows Loader
- Not from suspicious shellcode or injected DLL
- Bypasses callstack-based detections

### 3. Cross-Process Injection

With `PROCESS_VM_READ | PROCESS_VM_WRITE` permissions:
- Modify remote process's `_LDR_DATA_TABLE_ENTRY`
- Inject shellcode
- Wait for next thread creation/destruction
- Shellcode executes without `CreateRemoteThread`

## Advantages

### 1. No Suspicious APIs
- ❌ No `CreateRemoteThread`
- ❌ No `QueueUserAPC`
- ❌ No `SetThreadContext`
- ✅ Only `CreateThread` (for triggering, appears normal)

### 2. Clean Callstack
- Execution originates from `ntdll!LdrpCallInitRoutine()`
- Appears as legitimate DLL initialization
- Bypasses callstack-based detections

### 3. Flexible Execution
- Can execute any API with arbitrary arguments
- Can run in new thread (for complex APIs like wininet)
- Can proxy calls to appear legitimate

### 4. Memory Resident
- No need to write shellcode to disk
- All modifications in-memory
- Works with existing loaded DLLs

## Limitations and Challenges

### 1. Loader Lock
When `DllMain()` is called, a Loader Lock is held:
- Some APIs will deadlock (e.g., `LoadLibrary`)
- Complex APIs (wininet, winhttp) require running in new thread
- Not all operations are safe

### 2. Stability Concerns
- Modifying critical DLLs (ntdll, kernel32) can cause crashes
- Race conditions if DLL is unloaded
- Thread synchronization issues

### 3. Timing Dependency
- Requires thread creation/destruction to trigger
- Cannot control exact execution timing
- May wait for natural thread events

### 4. Detection Surface
- Memory modifications to PEB structures
- EDR can monitor PEB/LDR integrity
- Suspicious patterns: EntryPoint changed

## Implementation

### Building

```batch
cd techniques\41-ldrshuffle
build.bat
```

### Usage

```batch
# Run LdrShuffle (will load version.dll and hijack its EntryPoint)
ldrshuffle.exe

# Press ENTER when prompted to trigger execution
# A MessageBox will appear, called from hijacked EntryPoint
```

### Example Output

```
========================================
LdrShuffle - EntryPoint Hijacking
========================================

[*] Loading sacrificial DLL: version.dll
[+] Loaded at: 0x00007FFE12340000

[*] Setting up MessageBoxA() call

[*] Modifying LDR entry for version.dll
[+] Found LDR entry for version.dll
    DllBase: 0x00007FFE12340000
    EntryPoint: 0x00007FFE12345678
    OriginalBase: 0x00007FFE12340000
[+] LDR entry modified:
    New EntryPoint: 0x00000000004012A0 (Runner)
    Backup in OriginalBase: 0x00007FFE12345678

[*] Press ENTER to create thread and trigger execution...

[*] Creating dummy thread to trigger DLL_THREAD_ATTACH
[*] Created dummy thread: 1234
[*] Waiting for Runner to execute...
        [Runner][5678] - called on module 0x00007FFE12340000 for reason 2
        [Runner][5678] - about to perform call in current thread
        [Runner][5678] - completed

[+] Execution completed!
[+] Return value: 0x1

[*] Done!
```

## Code Structure

### Main Components

1. **`GetPEB()`**
   - Returns pointer to Process Environment Block
   - Uses `__readgsqword(0x60)` on x64
   - Uses `__readfsdword(0x30)` on x86

2. **`FindLdrEntry()`**
   - Walks `PEB->Ldr->InMemoryOrderModuleList`
   - Finds `_LDR_DATA_TABLE_ENTRY2` for target DLL
   - Matches by `BaseDllName` (e.g., "version.dll")

3. **`UpdateLdr()`**
   - Backs up original `EntryPoint` and `OriginalBase`
   - Overwrites `EntryPoint` with `Runner()` address
   - Stores backup in `OriginalBase` field

4. **`RestoreLdr()`**
   - Finds DLL's `_LDR_DATA_TABLE_ENTRY2`
   - Restores original `EntryPoint`
   - Restores original `OriginalBase`

5. **`Runner()`**
   - Fake DllMain() that Windows calls
   - Restores original EntryPoint
   - Executes malicious API call
   - Calls original DllMain() (proxying)

6. **`RunInThread()`**
   - Helper to run complex APIs in new thread
   - Required for wininet/winhttp functions
   - Avoids Loader Lock deadlocks

## Detection and Evasion

### What Defenders Might See

**Memory Modifications**:
- ✓ Changes to PEB/LDR structures
- ✓ EntryPoint field modified
- ✓ OriginalBase repurposed for backup

**Behavioral Indicators**:
- ✓ Thread creation followed by immediate API call
- ✓ API called from unusual thread context
- ✓ Suspicious API from DLL initialization routine

### Detection Strategies

1. **PEB/LDR Integrity Monitoring**:
   - Hash all `_LDR_DATA_TABLE_ENTRY` structures
   - Alert on `EntryPoint` changes
   - Monitor `OriginalBase` field modifications

2. **Callstack Analysis**:
   - While callstack looks legitimate, analyze API calls from `DllMain()`
   - Flag unusual APIs (network, crypto) from DLL init
   - Correlate thread creation with API calls

3. **Memory Scanning**:
   - Scan for `EntryPoint` pointing outside DLL bounds
   - Check `EntryPoint` not in `.text` section
   - Validate against on-disk PE headers

### Evasion Improvements

The original LdrShuffle project explores additional variations:
- Cross-process injection (LdrInject)
- Modified Cobalt Strike beacons for Loader Lock compatibility
- Selective thread event filtering (only `DLL_THREAD_ATTACH`)

## Comparison with Other Techniques

| Feature | LdrShuffle | ThreadHijacking | APC Injection |
|---------|------------|-----------------|---------------|
| Suspicious APIs | ❌ None | ✅ SuspendThread | ✅ QueueUserAPC |
| Callstack | ✅ Clean | ⚠️ Modified | ✅ Clean |
| Timing Control | ⚠️ Limited | ✅ Precise | ✅ Precise |
| Stability | ⚠️ Loader Lock | ✅ Good | ✅ Good |
| Innovation | ✅✅✅ Very High | ⚠️ Medium | ⚠️ Medium |
| Detection | ⚠️ PEB modifications | ⚠️ Context changes | ⚠️ APC queue |

## Advanced Topics

### Why Use OriginalBase for Backup?

The `OriginalBase` field in `_LDR_DATA_TABLE_ENTRY` is typically not used after DLL loading. We repurpose it to store the original `EntryPoint`:

```c
// Before modification
OriginalBase = 0x00007FFE12340000  (original DLL base)
EntryPoint   = 0x00007FFE12345678  (real DllMain)

// After modification
OriginalBase = 0x00007FFE12345678  (backup of real DllMain)
EntryPoint   = 0x0000000000401000  (Runner function)
```

This allows `Runner()` to find and restore the original `EntryPoint` later.

### The DontCallForThreads Flag

Some DLLs have the `DontCallForThreads` flag set in their `_LDR_DATA_TABLE_ENTRY`. If this flag is set:
- Windows will NOT call `DllMain()` for `DLL_THREAD_ATTACH` / `DLL_THREAD_DETACH`
- Our hijacked `EntryPoint` won't be triggered by thread creation
- Only `DLL_PROCESS_ATTACH` / `DLL_PROCESS_DETACH` will trigger it

**Solution**: Choose a DLL without this flag (most DLLs don't have it).

### Loader Lock Deadlocks

The Loader Lock is a critical section that protects DLL loading/unloading. When `DllMain()` is called, this lock is held. Calling certain APIs will deadlock:

**Unsafe APIs** (will deadlock):
- `LoadLibrary` / `LoadLibraryEx`
- `FreeLibrary`
- `GetModuleHandle` (sometimes)

**Safe APIs**:
- `VirtualAlloc` / `VirtualProtect`
- `CreateThread`
- `Sleep`
- `MessageBoxA`

**Complex APIs** (need `createThread = 1`):
- `InternetOpenW`
- `HttpSendRequestA`
- Most wininet/winhttp functions

## References

- [GitHub - RWXstoned/LdrShuffle](https://github.com/RWXstoned/LdrShuffle)
- [DarkLoadLibrary - Batsec](https://github.com/bats3c/DarkLoadLibrary)
- [MDSec - Bypassing Image Load Kernel Callbacks](https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/)
- [Windows Internals - DLL Loading](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function)

## License

This implementation is for educational and defensive security research purposes only.
