#include "utils.h"
#include "Unrevealed.h"

// 64\32位版本,根据基址和名称得到函数地址,导出表解析
PVOID MmGetSystemRoutineAddressEx(ULONG64 modBase, CHAR* searchFnName)
{
	if (modBase == 0 || searchFnName == NULL)  return NULL;
	SIZE_T funcAddr = 0;

	do
	{
		PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)modBase;
		PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(modBase + pDosHdr->e_lfanew);
		PIMAGE_FILE_HEADER pFileHdr = &pNtHdr->FileHeader;
		PIMAGE_OPTIONAL_HEADER64 pOphtHdr64 = NULL;
		PIMAGE_OPTIONAL_HEADER32 pOphtHdr32 = NULL;

		if (pFileHdr->Machine == IMAGE_FILE_MACHINE_I386) pOphtHdr32 = (PIMAGE_OPTIONAL_HEADER32)&pNtHdr->OptionalHeader;
		else pOphtHdr64 = (PIMAGE_OPTIONAL_HEADER64)&pNtHdr->OptionalHeader;

		ULONG VirtualAddress = 0;
		if (pOphtHdr64 != NULL) VirtualAddress = pOphtHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		else VirtualAddress = pOphtHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		// 根据 PE 64位/32位 得到导出表
		PIMAGE_EXPORT_DIRECTORY pExportTable = (IMAGE_EXPORT_DIRECTORY*)(modBase + VirtualAddress);
		if (NULL == pExportTable) break;

		PULONG pAddrFns = (PULONG)(modBase + pExportTable->AddressOfFunctions);
		PULONG pAddrNames = (PULONG)(modBase + pExportTable->AddressOfNames);
		PUSHORT pAddrNameOrdinals = (PUSHORT)(modBase + pExportTable->AddressOfNameOrdinals);

		ULONG funcOrdinal, i;
		char* funcName;
		for (ULONG i = 0; i < pExportTable->NumberOfNames; ++i)
		{
			funcName = (char*)(modBase + pAddrNames[i]);
			if (modBase < MmUserProbeAddress)
			{
				__try
				{
					if (!_strnicmp(searchFnName, funcName, strlen(searchFnName)))
					{
						if (funcName[strlen(searchFnName)] == 0)
						{
							funcAddr = modBase + pAddrFns[pAddrNameOrdinals[i]];
							break;
						}
					}
				}
				__except (1) { continue; }
			}
			else
			{
				if (MmIsAddressValid(funcName) && MmIsAddressValid(funcName + strlen(searchFnName)))
				{
					if (!_strnicmp(searchFnName, funcName, strlen(searchFnName)))
					{
						if (funcName[strlen(searchFnName)] == 0)
						{
							funcOrdinal = pExportTable->Base + pAddrNameOrdinals[i] - 1;
							funcAddr = modBase + pAddrFns[funcOrdinal];
							break;
						}
					}
				}
			}
		}
	} while (0);
	return (PVOID)funcAddr;
}

// 得到R0模块 基址&大小
ULONG_PTR GetModuleR0(PUCHAR moduleName, ULONG_PTR* moduleSize)
{
	if (moduleName == NULL) return 0;

	ULONG_PTR moudleBase = 0;
	PUCHAR kernelModuleName = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PROCESS_MODULES_INFORMATION rtlMoudles = { 0 };
	PPROCESS_MODULES_INFORMATION systemMoudlesInfo = NULL;

	ULONG* retLen = 0;
	status = ZwQuerySystemInformation(SystemModuleInformation, systemMoudlesInfo, 0, &retLen);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		systemMoudlesInfo = ExAllocatePool(PagedPool, retLen);
		if (systemMoudlesInfo)
		{
			memset(systemMoudlesInfo, 0, retLen);
			status = ZwQuerySystemInformation(SystemModuleInformation, systemMoudlesInfo, retLen, &retLen);
			if (!NT_SUCCESS(status))
			{
				goto end;
			}

			if (_stricmp(moduleName, "ntoskrnl.exe") == 0 || _stricmp(moduleName, "ntkrnlpa.exe") == 0)
			{
				PSYSTEM_MODULE_INFORMATION moudleInfo = &systemMoudlesInfo->Modules[0];
				moudleBase = moudleInfo->ImageBase;
				if (moduleSize)
				{
					*moduleSize = moudleInfo->ImageSize;
				}
				goto end;
			}
		}

	}

	kernelModuleName = ExAllocatePool(PagedPool, strlen(moduleName) + 1);
	if (kernelModuleName && systemMoudlesInfo)
	{
		memset(kernelModuleName, 0, strlen(moduleName) + 1);
		memcpy(kernelModuleName, moduleName, strlen(moduleName));
		_strupr(kernelModuleName);

		for (int i = 0; i < systemMoudlesInfo->NumberOfModules; i++)
		{
			PSYSTEM_MODULE_INFORMATION moudleInfo = &systemMoudlesInfo->Modules[i];
			PUCHAR pathName = _strupr(moudleInfo->FullPathName);
			if (strstr(pathName, kernelModuleName))
			{
				moudleBase = moudleInfo->ImageBase;
				if (moduleSize) *moduleSize = moudleInfo->ImageSize;
				break;
			}
		}
		ExFreePool(kernelModuleName);
	}

end:
	if (systemMoudlesInfo)
	{
		ExFreePool(systemMoudlesInfo);
	}
	return moudleBase;
}