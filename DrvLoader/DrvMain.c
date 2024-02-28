#include "DrvLoader.h"
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

	driver->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}