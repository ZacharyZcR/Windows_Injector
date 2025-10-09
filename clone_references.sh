#!/bin/bash

# Clone all reference repositories for 41 injection techniques
# This script will attempt to clone each repository and track success/failure

cd reference || exit 1

SUCCESS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

declare -A REPOS

# Technique 1-5: Process Manipulation
REPOS[01]="https://github.com/m0n0ph1/Process-Hollowing"
REPOS[02]="https://github.com/hasherezade/transacted_hollowing"
REPOS[03]="https://github.com/hasherezade/process_doppelganging"
REPOS[04]="https://github.com/jxy-s/herpaderping"
REPOS[05]="https://github.com/hasherezade/process_ghosting"

# Technique 6-10: Early Execution and Callbacks
REPOS[06]="https://github.com/S3cur3Th1sSh1t/Caro-Kann"  # Early Bird APC
REPOS[07]="https://github.com/diversenok/Suspending-Techniques"  # Entry Point Injection
REPOS[08]="https://github.com/S3cur3Th1sSh1t/Caro-Kann"  # DLL Blocking (same as 06)
REPOS[09]="https://github.com/Cracked5pider/earlycascade-injection"
REPOS[10]="https://github.com/0xHossam/KernelCallbackTable-Injection-PoC"  # Kernel Callback Table

# Technique 11-20: Classic Injection
REPOS[11]="https://github.com/itaymigdal/PichichiH0ll0wer"  # Advanced Hollowing
REPOS[12]="https://github.com/stephenfewer/ReflectiveDLLInjection"  # DLL Injection
REPOS[13]="SKIP"  # Shellcode Injection - no specific repo (metasploit reference)
REPOS[14]="SKIP"  # SetWindowsHookEx - no specific repo (reference only)
REPOS[15]="https://github.com/stephenfewer/ReflectiveDLLInjection"  # Same as 12
REPOS[16]="https://github.com/AlSch092/PE-Injection"
REPOS[17]="SKIP"  # Mapping Injection - reference to doppelganging
REPOS[18]="https://github.com/0xflux/Rust-APC-Queue-Injection"
REPOS[19]="https://github.com/BreakingMalwareResearch/atom-bombing"
REPOS[20]="https://github.com/BreakingMalwareResearch/atom-bombing"

# Technique 21-31: Advanced Evasion
REPOS[21]="https://github.com/caueb/Mockingjay"
REPOS[22]="https://github.com/BreakingMalware/PowerLoaderEx"
REPOS[23]="https://github.com/CCob/ThreadlessInject"
REPOS[24]="https://github.com/Kudaes/EPI"
REPOS[25-1]="https://github.com/Dec0ne/DllNotificationInjection"  # DLL Notification (version 1)
REPOS[25-2]="https://github.com/ShorSec/DllNotificationInjection"  # DLL Notification (version 2)
REPOS[26]="https://github.com/d1rkmtrr/D1rkInject"  # Module Stomping
REPOS[27]="https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection"
REPOS[28]="https://github.com/deepinstinct/Dirty-Vanity"  # Process Forking
REPOS[29]="https://github.com/Idov31/FunctionStomping"
REPOS[30]="https://github.com/S3cur3Th1sSh1t/Caro-Kann"  # Same as 06
REPOS[31]="https://github.com/maziland/StackBombing"

# Technique 32-41: Modern Cutting-Edge
REPOS[32]="https://github.com/woldann/GhostInjector"
REPOS[33]="https://github.com/c0de90e7/GhostWriting"
REPOS[34]="https://github.com/fern89/ghostwriting-2"
REPOS[35]="https://github.com/antonioCoco/Mapping-Injection"
REPOS[36]="https://github.com/OtterHacker/SetProcessInjection"
REPOS[37]="https://github.com/SafeBreach-Labs/PoolParty"
REPOS[38]="https://github.com/hasherezade/thread_namecalling"
REPOS[39]="https://github.com/hasherezade/waiting_thread_hijacking"
REPOS[40]="https://github.com/Friends-Security/RedirectThread"
REPOS[41]="https://github.com/RWXstoned/LdrShuffle"

echo "========================================="
echo "Cloning Reference Repositories"
echo "========================================="
echo ""

for tech_id in $(echo "${!REPOS[@]}" | tr ' ' '\n' | sort -V); do
    repo_url="${REPOS[$tech_id]}"

    # Handle SKIP entries
    if [ "$repo_url" == "SKIP" ]; then
        echo "[SKIP] Technique $tech_id - No specific repository"
        ((SKIP_COUNT++))
        continue
    fi

    # Extract repo name from URL
    repo_name=$(basename "$repo_url" .git)
    dir_name="${tech_id}-${repo_name}"

    # Skip if already cloned (for duplicates like Caro-Kann)
    if [ -d "$dir_name" ]; then
        echo "[EXISTS] $dir_name already cloned, skipping"
        continue
    fi

    echo "[$tech_id] Cloning $repo_name..."

    if git clone --depth 1 "$repo_url" "$dir_name" 2>&1 | grep -q "fatal\|error"; then
        echo "  ✗ FAILED to clone $repo_url"
        ((FAIL_COUNT++))
    else
        echo "  ✓ SUCCESS: $dir_name"
        ((SUCCESS_COUNT++))
    fi

    echo ""
done

echo "========================================="
echo "Clone Summary"
echo "========================================="
echo "✓ Success: $SUCCESS_COUNT"
echo "✗ Failed:  $FAIL_COUNT"
echo "⊘ Skipped: $SKIP_COUNT"
echo "========================================="
