#include "DrvLoader.h"
#include "Unrevealed.h"
#include "utils.h"

// 是否是PE,携带检查是否是64位
BOOLEAN IsPEValid(IN PUCHAR buffer, OUT BOOLEAN* isPE64)
{
	if (!buffer) return FALSE;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
		if (ntHeaders && ntHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			// 模数在ntHeaders前部分,前部分ntHeaders64位与32位是一样的
			if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				if (isPE64) *isPE64 = TRUE;
				return TRUE;
			}
			else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			{
				if (isPE64) *isPE64 = FALSE;
				return TRUE;
			}
		}
	}
	return FALSE;
}

//  -----------  接口支持x64、x86 PE文件  ----------- 
// 驱动这里使用这些接口支不支持都无所谓，因为驱动去修复的PE文件一定与本身字长相等(64位系统只可运行64位驱动,不像3环)

// 文件buffer转imagebuffer
NTSTATUS FileToImageBuffer(IN PUCHAR fileBuffer, OUT PUCHAR* imageBuffer, OUT PSIZE_T imageSize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!fileBuffer || !imageBuffer || !imageSize)
	{
		goto end;
	}

	BOOLEAN isPE64 = FALSE;
	if (!IsPEValid(fileBuffer, &isPE64))
	{
		status = STATUS_INVALID_PARAMETER_1;
		goto end;
	}

	ULONG tmpSizeOfImage = 0;
	PUCHAR tmpImageBuffer = NULL;
	PIMAGE_OPTIONAL_HEADER32 optionHeader32 = NULL;
	PIMAGE_OPTIONAL_HEADER64 optionHeader64 = NULL;
	PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(fileBuffer);
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	if (isPE64)
	{
		optionHeader64 = &ntHeaders->OptionalHeader;
		tmpSizeOfImage = optionHeader64->SizeOfImage;
		tmpImageBuffer = ExAllocatePool(NonPagedPool, tmpSizeOfImage);
		if (tmpImageBuffer)
		{
			memset(tmpImageBuffer, 0, tmpSizeOfImage);
			memcpy(tmpImageBuffer, fileBuffer, optionHeader64->SizeOfHeaders);
		}
	}
	else
	{
		optionHeader32 = &ntHeaders->OptionalHeader;
		tmpSizeOfImage = optionHeader32->SizeOfImage;
		tmpImageBuffer = ExAllocatePool(NonPagedPool, tmpSizeOfImage);
		if (tmpImageBuffer)
		{
			memset(tmpImageBuffer, 0, tmpSizeOfImage);
			memcpy(tmpImageBuffer, fileBuffer, optionHeader32->SizeOfHeaders);
		}
	}

	//拉伸PE 结构
	if (tmpImageBuffer)
	{
		for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			memcpy(tmpImageBuffer + sectionHeader->VirtualAddress, fileBuffer + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);
			sectionHeader++;
		}
		status = STATUS_SUCCESS;
	}
	
	// 返回值
	*imageBuffer = tmpImageBuffer;
	*imageSize = tmpSizeOfImage;
end:
	return status;
}

// 修复重定位
BOOLEAN RepairRelocation(PUCHAR imageBuffer)
{
	BOOLEAN isPE64 = FALSE;
	if (IsPEValid(imageBuffer, &isPE64))
	{
		ULONG64 imageBase = 0;
		PIMAGE_OPTIONAL_HEADER32 optionHeader32 = NULL;
		PIMAGE_OPTIONAL_HEADER64 optionHeader64 = NULL;
		PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(imageBuffer);
		if (isPE64)
		{
			optionHeader64 = &ntHeaders->OptionalHeader;
			imageBase = optionHeader64->ImageBase;
		}
		else
		{
			optionHeader32 = &ntHeaders->OptionalHeader;
			imageBase = optionHeader32->ImageBase;
		}

		PIMAGE_DATA_DIRECTORY dataDirReloc = NULL;
		PIMAGE_BASE_RELOCATION baseRelocation = NULL;
		dataDirReloc = optionHeader32 ? &optionHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] : &optionHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		baseRelocation = (PIMAGE_BASE_RELOCATION)(imageBuffer + dataDirReloc->VirtualAddress);
		while (baseRelocation->SizeOfBlock && baseRelocation->VirtualAddress)
		{
			PUSHORT relocBlock = (PUSHORT)((PUCHAR)baseRelocation + sizeof(IMAGE_BASE_RELOCATION));
			UINT32	numberOfRelocations = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			for (int i = 0; i < numberOfRelocations; i++)
			{
				if (relocBlock && ((relocBlock[i] >> 12) == IMAGE_REL_BASED_DIR64))
				{
					PUINT64	repairAddress = (PUINT64)((PUINT8)imageBuffer + baseRelocation->VirtualAddress + (relocBlock[i] & 0x0FFF));
					UINT64	delta = *repairAddress - (ULONG64)imageBase + (PUINT8)imageBuffer;
					*repairAddress = delta;
				}
				else if (relocBlock && ((relocBlock[i] >> 12) == IMAGE_REL_BASED_HIGHLOW))
				{
					PUINT32	repairAddress = (PUINT32)((PUINT8)imageBuffer + baseRelocation->VirtualAddress + (relocBlock[i] & 0x0FFF));
					UINT32	delta = *repairAddress - (ULONG32)imageBase + (PUINT8)imageBuffer;
					*repairAddress = delta;
				}
			}
			baseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)baseRelocation + baseRelocation->SizeOfBlock);
		}
		return TRUE;
	}
	return FALSE;
}

// 0环独有的修复IAT接口,3环不必去查询模块再查模块导出表对应函数地址填
// 0环全按名称导入
BOOLEAN RepairIAT(PUCHAR imageBuffer)
{
	BOOLEAN isSuccess = TRUE;
	BOOLEAN isPE64 = FALSE;
	if (IsPEValid(imageBuffer, &isPE64))
	{
		PIMAGE_OPTIONAL_HEADER32 optionHeader32 = NULL;
		PIMAGE_OPTIONAL_HEADER64 optionHeader64 = NULL;
		PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(imageBuffer);
		if (isPE64)
		{
			optionHeader64 = &ntHeaders->OptionalHeader;

			PIMAGE_DATA_DIRECTORY dataDirImport = &optionHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imageBuffer + dataDirImport->VirtualAddress);
			for (; importDescriptor->Name; importDescriptor++)
			{
				PUCHAR libName = (imageBuffer + importDescriptor->Name);
				ULONG_PTR libBase = GetModuleR0(libName, NULL);
				if (libBase)
				{
					PIMAGE_THUNK_DATA64 thunkName = (PIMAGE_THUNK_DATA64)(imageBuffer + importDescriptor->OriginalFirstThunk);
					PIMAGE_THUNK_DATA64 thunkFunc = (PIMAGE_THUNK_DATA64)(imageBuffer + importDescriptor->FirstThunk);
					for (; thunkName->u1.ForwarderString; ++thunkName, ++thunkFunc)
					{
						PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(imageBuffer + thunkName->u1.AddressOfData);
						ULONG_PTR funcAddress = MmGetSystemRoutineAddressEx(libBase, importByName->Name);
						if (funcAddress)
						{
							thunkFunc->u1.Function = (ULONG_PTR)funcAddress;
						}
						else
						{
							isSuccess = FALSE;
							continue;;
						}
					}
				}
			}
		}
		else
		{
			optionHeader32 = &ntHeaders->OptionalHeader;

			PIMAGE_DATA_DIRECTORY dataDirImport = &optionHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imageBuffer + dataDirImport->VirtualAddress);
			for (; importDescriptor->Name; importDescriptor++)
			{
				PUCHAR libName = (imageBuffer + importDescriptor->Name);
				ULONG_PTR libBase = GetModuleR0(libName, NULL);
				if (libBase)
				{
					PIMAGE_THUNK_DATA32 thunkName = (PIMAGE_THUNK_DATA32)(imageBuffer + importDescriptor->OriginalFirstThunk);
					PIMAGE_THUNK_DATA32 thunkFunc = (PIMAGE_THUNK_DATA32)(imageBuffer + importDescriptor->FirstThunk);
					for (; thunkName->u1.ForwarderString; ++thunkName, ++thunkFunc)
					{
						PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(imageBuffer + thunkName->u1.AddressOfData);
						ULONG_PTR funcAddress = MmGetSystemRoutineAddressEx(libBase, importByName->Name);
						if (funcAddress)
						{
							thunkFunc->u1.Function = (ULONG_PTR)funcAddress;
						}
						else
						{
							isSuccess = FALSE;
							break;
						}
					}
				}
			}
		}
	}
	return isSuccess;
}

// 0环独有的修复cookie接口
VOID RepairCookie(char* imageBuffer)
{
	if (!imageBuffer) return FALSE;
	PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBuffer);
	PIMAGE_DATA_DIRECTORY pConfigDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	PIMAGE_LOAD_CONFIG_DIRECTORY config = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pConfigDir->VirtualAddress + imageBuffer);
	*(PULONG_PTR)(config->SecurityCookie) += 0x20;
}

//  -----------  --------------  ----------- 

// 加载驱动接口
typedef NTSTATUS(NTAPI* DriverEntryPfn)(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg);

BOOLEAN LoadDriver(PUCHAR fileBuffer)
{
	BOOLEAN isSuccess = FALSE;
	SIZE_T imageSize = 0;
	PUCHAR imageBase = NULL;
	if (NT_SUCCESS(FileToImageBuffer(fileBuffer, &imageBase, &imageSize)))
	{
		if (RepairRelocation(imageBase))
		{
			if (RepairIAT(imageBase))
			{
				RepairCookie(imageBase);

				// call 入口点
				PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBase);
				ULONG entryPoint = pNts->OptionalHeader.AddressOfEntryPoint;
				DriverEntryPfn EntryPointFunc = (DriverEntryPfn)(imageBase + entryPoint);
				NTSTATUS stat = EntryPointFunc(NULL, NULL);
				if (NT_SUCCESS(stat))
				{
					isSuccess = TRUE;
				}
				// 清空PE头
				memset(imageBase, 0, PAGE_SIZE);
			}
		}

		if (!isSuccess)
		{
			ExFreePool(imageBase);
		}
	}
	return FALSE;
}