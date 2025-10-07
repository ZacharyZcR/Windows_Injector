#ifndef PE_UTILS_H
#define PE_UTILS_H

#include <windows.h>

/**
 * 读取文件到内存缓冲区
 * @param filePath 文件路径
 * @param fileSize 输出文件大小
 * @return 文件内容缓冲区（需要调用者释放），失败返回 NULL
 */
BYTE* ReadFileToBuffer(const WCHAR* filePath, DWORD* fileSize);

/**
 * 判断 PE 文件是否为 64 位
 * @param peBuffer PE 文件缓冲区
 * @return TRUE 为 64 位，FALSE 为 32 位
 */
BOOL IsPE64Bit(BYTE* peBuffer);

/**
 * 获取 PE 文件的入口点 RVA
 * @param peBuffer PE 文件缓冲区
 * @return 入口点 RVA
 */
DWORD GetEntryPointRVA(BYTE* peBuffer);

/**
 * 获取 PE 文件的 ImageBase
 * @param peBuffer PE 文件缓冲区
 * @return ImageBase 地址
 */
ULONG_PTR GetImageBase(BYTE* peBuffer);

#endif // PE_UTILS_H
