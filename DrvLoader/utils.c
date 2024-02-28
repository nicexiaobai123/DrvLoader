#include "utils.h"
#include "Unrevealed.h"

// 64\32位版本,根据基址和名称得到函数地址,导出表解析
PVOID MmGetSystemRoutineAddressEx(ULONG64 modBase, CHAR* searchFnName)
{
	if (modBase == 0 || searchFnName == NULL)  return NULL;

	ULONG64 funcAddr = 0;
	do
	{
		PIMAGE_OPTIONAL_HEADER32 optionHeader32 = NULL;
		PIMAGE_OPTIONAL_HEADER64 optionHeader64 = NULL;
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)modBase;
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(modBase + dosHeader->e_lfanew);

		if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) optionHeader64 = &ntHeaders->OptionalHeader;
		else optionHeader32 = &ntHeaders->OptionalHeader;

		ULONG virtualAddress = 0;
		virtualAddress = (optionHeader64 != NULL ? optionHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress :
			optionHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (virtualAddress == 0)
		{
			break;
		}

		PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(modBase + virtualAddress);
		PULONG fnsAddress = (PULONG)(modBase + exportDir->AddressOfFunctions);
		PULONG namesAddress = (PULONG)(modBase + exportDir->AddressOfNames);
		PUSHORT ordinalsAddress = (PUSHORT)(modBase + exportDir->AddressOfNameOrdinals);

		ULONG funcOrdinal, i;
		for (ULONG i = 0; i < exportDir->NumberOfNames; i++)
		{
			char* funcName = (char*)(modBase + namesAddress[i]);
			if (modBase < MmUserProbeAddress)
			{
				__try
				{
					if (_strnicmp(searchFnName, funcName, strlen(searchFnName)) == 0)
					{
						if (funcName[strlen(searchFnName)] == 0)
						{
							funcAddr = modBase + fnsAddress[ordinalsAddress[i]];
							break;
						}
					}
				}
				__except (1) 
				{ 
					continue; 
				}
			}
			else
			{
				if (MmIsAddressValid(funcName) && _strnicmp(searchFnName, funcName, strlen(searchFnName)) == 0)
				{
					if (funcName[strlen(searchFnName)] == 0)
					{
						// 基序号+ordinals = 真实序号
						funcOrdinal = exportDir->Base + ordinalsAddress[i] - 1;
						funcAddr = modBase + fnsAddress[funcOrdinal];
						break;
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