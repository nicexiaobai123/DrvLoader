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

// 删除驱动加载的注册表配置,根据注册表路径
NTSTATUS RtlDeleteDrvRegPath(PUNICODE_STRING regPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regPath->Buffer, L"DisplayName");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regPath->Buffer, L"ErrorControl");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regPath->Buffer, L"ImagePath");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regPath->Buffer, L"Start");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regPath->Buffer, L"Type");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regPath->Buffer, L"WOW64");

	//拼装字符串
	ULONG alloSize = regPath->MaximumLength + 0X100;
	PWCH enumPath = (PWCH)ExAllocatePool(PagedPool, alloSize);
	if (enumPath)
	{
		memset(enumPath, 0, alloSize);
		memcpy(enumPath, regPath->Buffer, regPath->Length);
		wcscat(enumPath, L"\\Enum");

		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumPath, L"enumPath");
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumPath, L"INITSTARTFAILED");
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enumPath, L"NextInstance");

		HANDLE hKeyEnum = NULL;
		OBJECT_ATTRIBUTES enumObj = { 0 };
		UNICODE_STRING unEnumName;
		RtlInitUnicodeString(&unEnumName, enumPath);
		InitializeObjectAttributes(&enumObj, &unEnumName, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = ZwOpenKey(&hKeyEnum, KEY_ALL_ACCESS, &enumObj);
		if (NT_SUCCESS(status))
		{
			ZwDeleteKey(hKeyEnum);
			ZwClose(hKeyEnum);
		}
		ExFreePool(enumPath);
	}

	//删除根部
	if (NT_SUCCESS(status))
	{
		HANDLE hKeyRoot = NULL;
		OBJECT_ATTRIBUTES rootObj = { 0 };
		InitializeObjectAttributes(&rootObj, regPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = ZwOpenKey(&hKeyRoot, KEY_ALL_ACCESS, &rootObj);
		if (NT_SUCCESS(status))
		{
			ZwDeleteKey(hKeyRoot);
			ZwClose(hKeyRoot);
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}

// 根据文件路径强制删除文件
NTSTATUS RtlForceDeleteFile(PWCH filePath)
{
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES objFile = { 0 };
	IO_STATUS_BLOCK ioBlock = { 0 };
	UNICODE_STRING unFileName = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&unFileName, filePath);
	InitializeObjectAttributes(&objFile, &unFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&hFile, GENERIC_READ, &objFile, &ioBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, NULL);
	if (NT_SUCCESS(status))
	{
		PFILE_OBJECT fileObj = NULL;
		status = ObReferenceObjectByHandle(hFile, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, &fileObj, NULL);
		if (NT_SUCCESS(status))
		{
			// 内核直接改文件对象属性,然后删除
			fileObj->DeleteAccess = TRUE;
			fileObj->DeletePending = FALSE;
			fileObj->SectionObjectPointer->DataSectionObject = NULL;
			fileObj->SectionObjectPointer->ImageSectionObject = NULL;
			//pFile->SectionObjectPointer->SharedCacheMap = NULL;
			ObDereferenceObject(fileObj);
		}
		ZwClose(hFile);
		status = ZwDeleteFile(&objFile);
	}
	return status;
}