#include "DrvLoader.h"

VOID DriverUnLoad(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

	KdPrint((" --- DriverUnLoad --- \r\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING regPath)
{
	UNREFERENCED_PARAMETER(regPath);

	driver->DriverUnload = DriverUnLoad;

	KdPrint((" --- DriverEntry --- \r\n"));

	return STATUS_SUCCESS;
}