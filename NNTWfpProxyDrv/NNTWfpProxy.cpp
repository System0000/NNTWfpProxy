extern "C"
{
#include "NNTWfpProxy.h"
}
PDEVICE_OBJECT DeviceObject = NULL;
VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UnInitWfp();
	IoDeleteDevice(DeviceObject);
	DbgPrint("NNTWfpProxy Unload\r\n");
	return;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	DriverObject->DriverUnload = Unload;
	status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	DbgPrint("Begin to InitializeWfp");
	status = InitializeWfp();

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(DeviceObject);
	}
	return status;
}