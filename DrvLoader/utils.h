#pragma once
#include <ntifs.h>
#include <ntimage.h>

// 64\32位版本,根据基址和名称得到函数地址,导出表解析
PVOID MmGetSystemRoutineAddressEx(ULONG64 modBase, CHAR* searchFnName);

// 得到R0模块 基址&大小
ULONG_PTR GetModuleR0(PUCHAR moduleName, ULONG_PTR* moduleSize);