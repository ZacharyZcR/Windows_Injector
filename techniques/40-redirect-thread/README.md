# Technique 40: RedirectThread - Context-Only Injection

## Overview

RedirectThread represents a paradigm shift in process injection techniques by focusing on **execution-only primitives** rather than the traditional allocate → write → execute pattern. This technique demonstrates how to inject code without explicitly allocating memory or writing shellcode using WriteProcessMemory.

**Original Research**: Friends Security (2025)
**Reference**: https://github.com/Friends-Security/RedirectThread
**Blog Post**: [The CONTEXT-Only Attack Surface](https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/)

## Core Philosophy

**Traditional Injection**:
```
1. VirtualAllocEx() - Allocate memory
2. WriteProcessMemory() - Write shellcode
3. CreateRemoteThread() - Execute
```

**RedirectThread Approach**:
```
Skip steps 1 & 2, focus only on execution primitives
```

## Techniques Implemented

### 1. DLL Pointer Injection

Instead of allocating memory and writing a DLL path, this technique leverages existing strings in the target process's memory space.

**How It Works**:
1. Find the string "0\0" (or any DLL name) in ntdll.dll's readonly data section
2. Get LoadLibraryA address (same across processes due to ASLR with same base)
3. CreateRemoteThread(LoadLibraryA, pointer_to_"0")
4. Target process loads "0.dll" without any memory allocation/writing

**Key Insight**: System DLLs contain many readable strings that can be used as parameters to functions.

### 2. NtCreateThread with ROP Gadget

The most innovative technique - achieving full shellcode injection using only NtCreateThread, without WriteProcessMemory.

**Core Mechanism**: ROP Gadget-based execution

## NtCreateThread ROP Gadget Injection

### Overview

This technique uses `NtCreateThread` with a specially crafted `CONTEXT` structure to execute functions via ROP (Return-Oriented Programming) gadgets.

### ROP Gadget: push r1; push r2; ret

The core gadget we search for in the target process:
```assembly
push r1    ; Push first register onto stack
push r2    ; Push second register onto stack
ret        ; Return (jump to address on top of stack)
```

**Execution Flow**:
```
1. RIP points to gadget address
2. r1 = ExitThread address
3. r2 = Target function address
4. Arguments in RCX, RDX, R8, R9 (x64 calling convention)

Stack after push r1; push r2:
[ExitThread]  ← RSP after push r2
[Function]    ← What ret will jump to

5. ret pops Function address and jumps to it
6. When Function returns, it pops ExitThread and jumps to it
7. Thread exits cleanly
```

### Complete Injection Flow

#### Step 1: Allocate Memory
```c
CreateRemoteThreadViaGadget(
    RCX = 0x60000,              // lpAddress
    RDX = shellcode_size,       // dwSize
    R8  = MEM_COMMIT|MEM_RESERVE,  // flAllocationType
    R9  = PAGE_EXECUTE_READWRITE,   // flProtect
    Function = VirtualAlloc,
    ExitThread = ExitThread
)
```

**What happens**:
- NtCreateThread creates a thread with RIP = gadget address
- gadget: push ExitThread; push VirtualAlloc; ret
- ret jumps to VirtualAlloc
- VirtualAlloc(0x60000, size, ...) allocates memory
- VirtualAlloc returns to ExitThread
- Thread exits

**Result**: Memory allocated at 0x60000 without VirtualAllocEx!

#### Step 2: Write Shellcode (Byte-by-Byte)
```c
for (i = 0; i < shellcode_size; i++) {
    CreateRemoteThreadViaGadget(
        RCX = 0x60000 + i,      // Destination
        RDX = 1,                // Length (1 byte)
        R8  = shellcode[i],     // Fill byte
        R9  = 0,                // Unused
        Function = RtlFillMemory,
        ExitThread = ExitThread
    )
}
```

**What happens**:
- For each byte, create a thread calling RtlFillMemory
- RtlFillMemory(dest+i, 1, byte) fills one byte
- Repeat for all shellcode bytes

**Result**: Shellcode written without WriteProcessMemory!

#### Step 3: Execute Shellcode
```c
CreateRemoteThreadViaGadget(
    RCX = 0,                    // Unused
    RDX = 0,                    // Unused
    R8  = 0,                    // Unused
    R9  = 0,                    // Unused
    Function = 0x60000,         // Shellcode address
    ExitThread = ExitThread
)
```

**What happens**:
- gadget: push ExitThread; push 0x60000; ret
- ret jumps to shellcode at 0x60000
- Shellcode executes
- When done, returns to ExitThread

**Result**: Shellcode executed!

## Technical Deep Dive

### CONTEXT Structure Manipulation

The key to this technique is the `CONTEXT` structure passed to `NtCreateThread`:

```c
CONTEXT ctx;
ctx.Rip = gadget_address;        // Instruction pointer
ctx.Rsp = stack_base;            // Stack pointer
ctx.Rcx = arg1;                  // Function argument 1
ctx.Rdx = arg2;                  // Function argument 2
ctx.R8  = arg3;                  // Function argument 3
ctx.R9  = arg4;                  // Function argument 4
ctx.Rax = value_for_gadget_r1;   // First pushed register
ctx.Rbx = value_for_gadget_r2;   // Second pushed register
```

### INITIAL_TEB Structure

NtCreateThread requires a stack to be pre-allocated:

```c
PVOID stack = VirtualAllocEx(hProcess, NULL, 1MB, MEM_COMMIT, PAGE_READWRITE);

INITIAL_TEB teb;
teb.StackBase = stack + 1MB;     // Top of stack (highest address)
teb.StackLimit = stack;           // Bottom of stack (lowest address)
```

### Gadget Search Algorithm

```
For each executable memory region:
    For each byte offset:
        Check if instruction matches: push r1
        Check if next instruction matches: push r2 (different register)
        Check if next instruction matches: ret
        If all match: Found gadget!
```

**Constraints**:
- r1 and r2 must be different registers
- Gadget must be in executable memory
- Common in ntdll.dll, kernel32.dll

## Advantages

### 1. No WriteProcessMemory
- Bypass EDR/AV hooks on WriteProcessMemory
- No direct memory writing signatures

### 2. No VirtualAllocEx (for shellcode)
- Memory allocated via ROP gadget calling VirtualAlloc inside target process
- Appears as legitimate internal allocation

### 3. Minimal API Usage
- DLL Injection: Only `CreateRemoteThread`
- NtCreateThread: Only `NtCreateThread` (undocumented API)
- Both leverage existing memory and code

### 4. Execution-Only Primitive
- Focus on controlling execution flow via CONTEXT
- Leverages existing code (ROP gadgets)
- No external code injection

## Limitations

### 1. Performance
- NtCreateThread method creates one thread per byte of shellcode
- Very slow for large payloads (100+ bytes = 100+ threads)
- Each thread creation has overhead

### 2. Noise
- Multiple thread creation events highly visible to EDR
- ETW (Event Tracing for Windows) will log all thread creations
- Not stealthy in terms of event volume

### 3. Gadget Dependency
- Requires suitable ROP gadget in target process
- Gadget search can be time-consuming
- May not find suitable gadget in some processes

### 4. Stability
- Relies on ASLR producing same base addresses across processes
- System DLL bases must match (usually does on Windows 10+)
- Stack allocation can fail if memory is constrained

## Implementation

### Building

```batch
cd techniques\40-redirect-thread
build.bat
```

### Usage

#### DLL Pointer Injection
```batch
# Inject 0.dll using existing memory pointer
redirect_thread.exe --dll-pointer 1234 0.dll

# Note: DLL must exist in target's DLL search path or current directory
```

#### NtCreateThread Shellcode Injection
```batch
# Inject MessageBox shellcode using NtCreateThread + ROP gadget
redirect_thread.exe --ntcreatethread 1234
```

### Example Output (NtCreateThread)

```
========================================
RedirectThread - Context-Only Injection
========================================

[*] Starting NtCreateThread injection
[+] Found ROP gadget at: 0x00007FFE12345678 (reg1=0, reg2=1)
[+] VirtualAlloc: 0x00007FFE11111111
[+] ExitThread: 0x00007FFE22222222
[+] RtlFillMemory: 0x00007FFE33333333
[*] Step 1: Allocating memory at 0x60000 (size: 4096)
[+] Memory allocated successfully
[*] Step 2: Writing shellcode (72 bytes)
  [*] Progress: 72/72 bytes written
[+] Shellcode written successfully
[*] Step 3: Executing shellcode
[+] Shellcode executed successfully

[+] Injection successful!
```

## Code Structure

### Main Components

1. **FindUniquePushPushRetGadget()**
   - Scans executable memory for ROP gadgets
   - Pattern: push r1; push r2; ret
   - Returns gadget address and register IDs

2. **CreateRemoteThreadViaGadget()**
   - Creates thread using NtCreateThread
   - Sets up CONTEXT with gadget and arguments
   - Allocates remote stack via VirtualAllocEx

3. **InjectShellcodeUsingNtCreateThread()**
   - Orchestrates the 3-step injection:
     1. Allocate memory (VirtualAlloc via ROP)
     2. Write shellcode (RtlFillMemory byte-by-byte via ROP)
     3. Execute shellcode (direct jump via ROP)

4. **InjectDllPointerOnly()**
   - Finds existing string in target process memory
   - Calls LoadLibraryA via CreateRemoteThread

## Detection and Evasion

### What Defenders See

**DLL Pointer Injection**:
- ✓ CreateRemoteThread event
- ✓ LoadLibrary call in target process
- ❌ No VirtualAllocEx
- ❌ No WriteProcessMemory

**NtCreateThread ROP**:
- ✓ Multiple NtCreateThread calls (very visible!)
- ✓ VirtualAlloc called from within target process
- ✓ RtlFillMemory called repeatedly
- ❌ No WriteProcessMemory from external process
- ❌ No CreateRemoteThread (uses NtCreateThread instead)

### Detection Strategies

1. **Thread Creation Monitoring**:
   - High volume of thread creations in short time
   - Threads with unusual entry points (ROP gadgets)
   - Threads with identical CONTEXT patterns

2. **Stack Analysis**:
   - Threads starting at non-function boundaries
   - Stack containing pushed registers before function call

3. **Behavioral Analysis**:
   - Repeated VirtualAlloc/RtlFillMemory calls
   - Memory region being filled byte-by-byte
   - Execution jumping to recently filled memory

### Evasion Improvements

The original RedirectThread project implements:
- Two-step thread hijacking (suspend existing thread instead of creating new)
- APC-based delivery (QueueUserAPC, NtQueueApcThreadEx2)
- SetThreadContext manipulation without suspension

## Comparison with Other Techniques

| Feature | RedirectThread | Classic Injection | APC Injection |
|---------|---------------|-------------------|---------------|
| WriteProcessMemory | ❌ No | ✅ Yes | ✅ Yes |
| VirtualAllocEx | ⚠️ For stack only | ✅ Yes | ✅ Yes |
| Thread Creation | ✅ Many (noisy) | ✅ One | ❌ No |
| Speed | ⚠️ Slow | ✅ Fast | ✅ Fast |
| Innovation | ✅✅✅ Very High | ❌ None | ⚠️ Medium |
| Stealth | ⚠️ Low (many threads) | ⚠️ Medium | ✅ High |

## Advanced Concepts

### Why ROP Gadget?

You might ask: why not just set RIP to VirtualAlloc directly?

**Answer**: Calling conventions and return addresses.

```assembly
// Direct call (doesn't work):
RIP = VirtualAlloc
RCX, RDX, R8, R9 = arguments
// Problem: When VirtualAlloc returns, it will jump to whatever is on the stack
// The stack is empty or contains garbage → crash!

// ROP gadget (works):
RIP = gadget (push ExitThread; push VirtualAlloc; ret)
// Stack after push: [ExitThread] [VirtualAlloc]
// ret pops VirtualAlloc and jumps to it
// When VirtualAlloc returns, it pops ExitThread and jumps to it
// Thread exits cleanly!
```

### Why NtCreateThread Instead of CreateRemoteThread?

1. **Lower-level API**: NtCreateThread is the kernel-level function
2. **More control**: Direct CONTEXT and INITIAL_TEB manipulation
3. **Less monitored**: Many security products hook CreateRemoteThread but not NtCreateThread
4. **Research value**: Demonstrates capabilities of low-level thread creation

### Address Space Layout Randomization (ASLR)

**Key Assumption**: System DLLs (ntdll.dll, kernel32.dll) load at the same base address in all processes on the same system.

**Why this works**:
- Windows uses system-wide ASLR for system DLLs
- Base address randomized at boot time
- All processes share the same randomized base

**What this enables**:
- VirtualAlloc address in our process = VirtualAlloc address in target process
- Can pass function pointers directly without resolution

## References

- [GitHub - Friends-Security/RedirectThread](https://github.com/Friends-Security/RedirectThread)
- [Blog - The CONTEXT-Only Attack Surface](https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/)
- [Return-Oriented Programming (ROP) - Wikipedia](https://en.wikipedia.org/wiki/Return-oriented_programming)
- [NtCreateThread Documentation - Undocumented NTInternals](http://undocumented.ntinternals.net/)

## License

This implementation is for educational and defensive security research purposes only.
