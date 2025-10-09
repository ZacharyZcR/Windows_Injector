# RedirectThread

This tool explores various techniques for remote code execution and thread manipulation on Windows, originating from the `CONTEXT` struct.

For a detailed explanation of the research and techniques, please refer to our blog post: **[New Process Injection Class: The CONTEXT-Only Attack Surface](https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/)**

## TL;DR

Most process injection techniques follow a familiar pattern:
allocate → write → execute.

In this research, we ask: what if we skip allocation and writing entirely?

By focusing on execution-only primitives, we found distinct approaches to inject code without allocating / writing memory:

*   Inject a DLL using only `LoadLibraryA`.
*   Call arbitrary WinAPI functions with parameters using `SetThreadContext`, without suspending a thread.
*   Utilize only `NtCreateThread` to remotely allocate, write and execute shellcode.
*   Expand the technique to APC functions such as `QueueUserAPC`.

This isn’t classic thread hijacking — we don’t necessarily suspend/resume a thread mid-execution to overwrite it.

## Projects Included

This solution contains the following main projects:

*   **`RedirectThread`**: A tool demonstrating various remote thread injection techniques utilizing the `CONTEXT` struct while avoiding allocating / writing memory remotely (and some ROP gadgets).
*   **`AlertableThreadsForDays`**: A utility for creating alertable threads, for testing with APC-based injection methods.

## Usage

```
Usage: C:\RedirectThread.exe [options]

Required Options:
  --pid <pid>                 Target process ID to inject into
  --inject-dll                Perform DLL injection (hardcoded to "0.dll")
  --inject-shellcode <file>   Perform shellcode injection from file
  --inject-shellcode-bytes <hex>  Perform shellcode injection from hex string (e.g. 9090c3)

Delivery Method Options:
  --method <method>           Specify code execution method
     CreateRemoteThread       Default, creates a remote thread
     NtCreateThread           Uses NtCreateThread (less traceable)
     QueueUserAPC             Uses QueueUserAPC (requires --tid)
     QueueUserAPC2            Uses QueueUserAPC2 (requires --tid)
     NtQueueApcThread         Uses NtQueueApcThread (requires --tid)
     NtQueueApcThreadEx       Uses NtQueueApcThreadEx (requires --tid)
     NtQueueApcThreadEx2      Uses NtQueueApcThreadEx2 (requires --tid)

Context Method Options:
  --context-method <method>   Specify context manipulation method
     rop-gadget               Default, uses ROP gadget technique
     two-step                 Uses a two-step thread hijacking approach

Additional Options:
  --tid <tid>                 Target thread ID (required for APC methods)
  --alloc-size <size>         Memory allocation size in bytes (default: 4096)
  --alloc-perm <hex>          Memory protection flags in hex (default: 0x40)
  --alloc-address <hex>       Specify base address for allocation (hex, optional)
  --use-suspend               Use thread suspension for increased reliability
  --verbose                   Enable verbose output
  --enter-debug               Pause execution at key points for debugger attachment

Example:
  C:\RedirectThread.exe --pid 1234 --inject-dll mydll.dll
  C:\RedirectThread.exe --pid 1234 --inject-shellcode payload.bin --verbose
  C:\RedirectThread.exe --pid 1234 --inject-shellcode payload.bin --method NtCreateThread
  C:\RedirectThread.exe --pid 1234 --inject-shellcode-bytes 9090c3 --method QueueUserAPC --tid 5678
  C:\RedirectThread.exe --pid 1234 --inject-shellcode-bytes $bytes --context-method two-step --method NtQueueUserApcThreadEx2 --tid 5678
```

## Building the Project

You can build this project using either CMake or Visual Studio directly with the provided solution file (`RedirectThread.sln`).

### Option 1: Using CMake

This project can be built using CMake. You can either use CMake from the command line (if CMake is installed and in your system's PATH) or leverage the CMake Tools extension if you are using Visual Studio Code.

#### Prerequisites

*   A C++ compiler that supports C++17 (e.g., MSVC, GCC, Clang).
*   CMake (version 3.10 or higher).

#### Build Steps

The following steps describe building with CMake from the command line. If you are using the CMake Tools extension in VSCode, you can often perform the configuration and build steps through the extension's UI instead of running these commands manually.

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd RedirectThread
    ```

2.  **Create a build directory and navigate into it:**
    ```bash
    mkdir build
    cd build
    ```

3.  **Configure the project with CMake:**
    *   For Visual Studio (example for Visual Studio 2019, 64-bit):
        ```bash
        cmake .. -G "Visual Studio 16 2019" -A x64
        ```
    *   For Makefiles (example):
        ```bash
        cmake ..
        ```
    *   For other generators, please refer to CMake documentation.

4.  **Build the project:**
    *   For Visual Studio:
        ```bash
        cmake --build . --config Release
        ```
    *   For Makefiles:
        ```bash
        make
        ```

    Executables will typically be located in a subdirectory within your build folder (e.g., `build/Release` or `build/RedirectThread/Release`).

### Option 2: Using Visual Studio Solution File

1.  Open `RedirectThread.sln` in Visual Studio.
2.  Select the desired build configuration (e.g., Release, x64).
3.  Build the solution (Build > Build Solution).

    Executables will be located in the respective project output directories (e.g., `x64/Release`).

