#pragma once
#include <ntifs.h>
#include <ntimage.h>

// 64\32λ�汾,���ݻ�ַ�����Ƶõ�������ַ,���������
PVOID MmGetSystemRoutineAddressEx(ULONG64 modBase, CHAR* searchFnName);

// �õ�R0ģ�� ��ַ&��С
ULONG_PTR GetModuleR0(PUCHAR moduleName, ULONG_PTR* moduleSize);