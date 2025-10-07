#ifndef PE_H
#define PE_H

#include <windows.h>
#include <dbghelp.h>
#include "internals.h"

// ===== PE 相关辅助函数 =====

/**
 * 查找远程进程的 PEB 地址
 * @param hProcess 进程句柄
 * @return PEB 地址，失败返回 0
 */
DWORD FindRemotePEB(HANDLE hProcess);

/**
 * 读取远程进程的 PEB
 * @param hProcess 进程句柄
 * @return PEB 指针，失败返回 NULL（需要调用者释放）
 */
MY_PEB* ReadRemotePEB(HANDLE hProcess);

/**
 * 读取远程进程的镜像信息
 * @param hProcess 进程句柄
 * @param lpImageBaseAddress 镜像基址
 * @return LOADED_IMAGE 指针，失败返回 NULL（需要调用者释放）
 */
PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress);

/**
 * 获取 NT 头
 * @param pImageBase 镜像基址指针
 * @return NT 头指针
 */
PIMAGE_NT_HEADERS GetNTHeaders(PVOID pImageBase);

/**
 * 从缓冲区获取加载的镜像信息
 * @param pImageBase 镜像基址指针
 * @return LOADED_IMAGE 指针（需要调用者释放）
 */
PLOADED_IMAGE GetLoadedImage(PVOID pImageBase);

#endif // PE_H
