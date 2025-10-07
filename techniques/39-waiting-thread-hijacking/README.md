# Technique 39: Waiting Thread Hijacking

## Overview

Waiting Thread Hijacking is a stealthy code injection technique that exploits threads in a waiting state by overwriting their return addresses on the stack. Unlike traditional injection methods that allocate new threads or modify executable memory, this technique leverages existing threads that are already in a waiting state, making it harder to detect.

**Original Research**: Check Point Research (2025)
**Reference**: https://research.checkpoint.com/2025/waiting-thread-hijacking/

## How It Works

### Core Concept

When a thread enters a waiting state (e.g., waiting on a queue, event, or I/O), its execution context is preserved on the stack, including the return address that will be used when the thread resumes execution. By carefully overwriting this return address with a pointer to our shellcode, we can hijack the thread's control flow when it wakes up.

### Attack Flow

```
1. Enumerate Process Threads
   │
   ├─ Use NtQuerySystemInformation(SystemProcessInformation)
   └─ Get extended thread information including state and wait reason

2. Find Suitable Waiting Thread
   │
   ├─ Filter threads by state (Waiting)
   ├─ Optionally filter by wait reason (e.g., WrQueue)
   └─ Validate thread is in a stable waiting state

3. Read Thread Context
   │
   ├─ Get thread context (RSP = stack pointer)
   └─ Read return address from stack at RSP

4. Validate Return Address
   │
   ├─ Check return address points to ntdll.dll/kernel32.dll/kernelbase.dll
   └─ Ensure thread will eventually return (not deadlocked)

5. Prepare Shellcode
   │
   ├─ Create stub that saves/restores all registers
   ├─ Insert actual payload (e.g., MessageBox)
   ├─ Add cleanup code that jumps back to original return address
   └─ Store original return address in first 8 bytes

6. Inject Shellcode
   │
   ├─ Allocate memory in target process (PAGE_READWRITE)
   ├─ Write shellcode with embedded original return address
   ├─ Change memory protection to PAGE_EXECUTE_READ
   └─ Overwrite return address on stack to point to shellcode+8

7. Wait for Execution
   │
   └─ When thread wakes up, it will execute shellcode and cleanly return
```

### Shellcode Structure

```
+------------------------+
| Original Return Addr   | ← 8 bytes (offset 0x00)
+------------------------+
| Register Save Stub     | ← pushfq, push rax-r15, sub rsp (offset 0x08)
+------------------------+
| Actual Payload         | ← Your code (e.g., MessageBox)
+------------------------+
| Register Restore Stub  | ← add rsp, pop r15-rax, popfq
+------------------------+
| Jump Back              | ← mov rax, [saved_ret]; jmp rax
+------------------------+

Return address on stack is overwritten to point to offset 0x08 (after saved return)
```

## Technical Details

### Key Structures

```c
// Thread state enumeration
Waiting = 5  // Thread is in a waiting state

// Wait reasons (examples)
WrQueue = 15              // Waiting on queue
WrLpcReceive = 16         // Waiting for LPC message
WrDelayExecution = 11     // Sleep/delay
WrUserRequest = 13        // User-mode wait
```

### Required Permissions

- **PROCESS_VM_READ**: Read stack to get return address
- **PROCESS_VM_WRITE**: Overwrite return address
- **PROCESS_VM_OPERATION**: Allocate memory and change protections
- **THREAD_GET_CONTEXT**: Get thread's RSP
- **THREAD_QUERY_INFORMATION**: Query thread state

### Advantages

1. **Stealthy**: No new threads created, uses existing thread
2. **Clean execution**: Registers are preserved, thread continues normally after injection
3. **No APC**: Doesn't use alertable APCs which are commonly monitored
4. **No RWX memory**: Shellcode can be PAGE_EXECUTE_READ
5. **Targeted**: Can choose specific wait reasons for more control

### Limitations

1. **Timing-dependent**: Thread must actually wake up for code to execute
2. **Thread availability**: Requires a suitable waiting thread
3. **Return address validation**: Must point to system DLLs for safety
4. **Stack manipulation**: Corrupted stack if not done carefully

## Implementation

### Building

```batch
cd techniques\39-waiting-thread-hijacking
build.bat
```

### Usage

```batch
# Inject into PID 1234 (default: WrQueue wait reason)
waiting_thread_hijacking.exe 1234

# Inject with specific wait reason
waiting_thread_hijacking.exe 1234 15

# Accept any wait reason
waiting_thread_hijacking.exe 1234 0xFFFFFFFF
```

### Example Output

```
========================================
Waiting Thread Hijacking
========================================

[*] Target PID: 1234
[*] Wait reason filter: 15 (0xFFFFFFFF = any)
[*] Found process, analyzing 24 threads
[*] TID 5678: State=Waiting, WaitReason=15
[*] Return address 0x00007FFE12345678 in module: ntdll.dll
[*] RSP: 0x000000A1B2C3D4E0, Return address: 0x00007FFE12345678
[+] Found suitable thread: TID 5678
[+] Target thread found: TID 5678
[+] RSP: 0x000000A1B2C3D4E0
[+] Original return address: 0x00007FFE12345678
[+] Allocated shellcode at: 0x00000180A0001000 (size: 148 bytes)
[+] Shellcode written successfully
[+] Shellcode is now executable
[+] Return address overwritten!
[+] Shellcode will execute when thread returns

[+] Injection successful!
[*] Wait for the target thread to return from its waiting state
```

## Code Structure

### Main Components

1. **`FindWaitingThread()`**
   - Enumerates all threads using `NtQuerySystemInformation`
   - Filters by wait state and wait reason
   - Reads thread context and stack return address
   - Validates return address points to system DLLs

2. **`IsValidReturnTarget()`**
   - Checks if return address is in ntdll/kernel32/kernelbase
   - Prevents crashes from invalid hijacking targets

3. **`InjectWaitingThread()`**
   - Allocates memory for shellcode
   - Builds complete shellcode with stub + payload + cleanup
   - Patches original return address into shellcode
   - Overwrites return address on stack

### Shellcode Components

1. **Register Save Stub** (`g_shellcode_stub`)
   - Saves all general-purpose registers
   - Saves flags (RFLAGS)
   - Allocates shadow space

2. **Payload** (`g_payload_messagebox`)
   - Example: Shows MessageBox
   - Can be replaced with any shellcode

3. **Cleanup Stub** (`g_shellcode_cleanup`)
   - Restores shadow space
   - Restores all registers
   - Loads original return address
   - Jumps back to continue normal execution

## Detection Evasion

### What This Technique Avoids

- ❌ No `CreateRemoteThread` or `RtlCreateUserThread`
- ❌ No `QueueUserAPC` / `NtQueueApcThread`
- ❌ No `SetThreadContext` (commonly monitored)
- ❌ No new thread creation events
- ❌ No RWX memory regions

### What Defenders Might See

- ✓ Memory allocation in target process (VirtualAllocEx)
- ✓ Memory writes to target process (WriteProcessMemory)
- ✓ Memory protection changes (VirtualProtectEx)
- ✓ Stack manipulation (writing to thread stack)
- ✓ Process/thread handle acquisition

### Mitigation Strategies

1. **Monitor stack integrity**: Implement stack canaries or shadow stacks
2. **Thread state monitoring**: Watch for unusual waiting thread behavior
3. **Memory integrity**: Scan for suspicious RX memory regions
4. **Return address validation**: Hardware-assisted control flow integrity (CET)
5. **Process handle monitoring**: Alert on suspicious cross-process handle access

## Comparison with Other Techniques

| Feature | Waiting Thread Hijack | APC Injection | Thread Hijack (Suspend) |
|---------|----------------------|---------------|-------------------------|
| Stealth | High | Medium | Low |
| Reliability | Medium (timing) | High | High |
| Thread Creation | No | No | No |
| Alertable Required | No | Yes | No |
| Suspend/Resume | No | No | Yes |
| Stack Manipulation | Yes | No | Yes |

## Wait Reason Reference

Common wait reasons you might target:

| Value | Name | Description |
|-------|------|-------------|
| 11 | WrDelayExecution | Thread sleeping (Sleep()) |
| 13 | WrUserRequest | User-mode synchronization |
| 15 | WrQueue | Waiting on I/O completion queue |
| 16 | WrLpcReceive | Waiting for LPC message |
| 17 | WrLpcReply | Waiting for LPC reply |

## References

- [Check Point Research - Waiting Thread Hijacking (2025)](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [Original Implementation by hasherezade](https://github.com/hasherezade/waiting_thread_hijacking)
- [Windows Internals - Thread States](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/thread-states)

## License

This implementation is for educational and defensive security research purposes only.
