/*  processdumper: console utility for software analysis
 *  Copyright(C) 2017  Peter Bohning
 *  This program is free software : you can redistribute it and / or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. */
#include <ntddk.h>
#include <wdf.h>
#include "warontencent.h"
#include "idt.h"

typedef struct _KSERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}KSERVICE_DESCRIPTOR_TABLE, *PKSERVICE_DESCRIPTOR_TABLE;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION;

#define DEVICE_NAME			"\\Device\\warontencent"
#define DEVICE_SYMLINK_NAME	"\\DosDevices\\warontencent"

#define _WIDESTRING(text) L##text
#define WIDESTRING(text) _WIDESTRING(text)
#define PRESET_UNICODE_STRING(symbol, buffer) \
        UNICODE_STRING symbol = \
            { \
            sizeof(WIDESTRING(buffer)) - sizeof(WCHAR), \
            sizeof(WIDESTRING(buffer)), \
            WIDESTRING(buffer) \
            };

PRESET_UNICODE_STRING(uDeviceName, DEVICE_NAME)
PRESET_UNICODE_STRING(uSymlinkName, DEVICE_SYMLINK_NAME)

//extern PKSERVICE_DESCRIPTOR_TABLE __imp_KeServiceDescriptorTable;

//typedef NTSTATUS (*ZwQuerySystemInformationPtr)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

DRIVER_INITIALIZE DriverEntry;
//EVT_WDF_DRIVER_DEVICE_ADD KmdfHelloWorldEvtDeviceAdd;
DRIVER_UNLOAD Unload;
NTSTATUS DispatchCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

void get_some_addresses(void);
NTSTATUS enum_processes(PIRP Irp, PIO_STACK_LOCATION IrpSp);

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	//WDF_DRIVER_CONFIG config;
	PDEVICE_OBJECT pDeviceObject = 0;
	//UNICODE_STRING devicename;

	//KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, ));
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: DriverEntry %p %p\n", DriverObject, RegistryPath);
	
	//RtlInitUnicodeString(&devicename, L"\\\\Device\\warontencent");
	if((status = IoCreateDevice(DriverObject, 0, &uDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject)) != STATUS_SUCCESS)
	{
		return status;		//allegedly unloads the driver
	}

	//to be accessible from user space
	if((status = IoCreateSymbolicLink(&uSymlinkName, &uDeviceName)) != STATUS_SUCCESS)
	{
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] =
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
	DriverObject->DriverUnload = &Unload;
	status = STATUS_SUCCESS;

	//WDF_DRIVER_CONFIG_INIT(&config, KmdfHelloWorldEvtDeviceAdd);
	//status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

	get_some_addresses();

	try
	{
		queryidt();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: queryidt failed\n");
	}

	return status;
}

void get_some_addresses(void)
{
	void * ntopenprocess_;
	void * ntqueryinformationprocess_ = NULL;
	UNICODE_STRING func_name;

	try
	{
		RtlInitUnicodeString(&func_name, L"NtOpenProcess");
		ntopenprocess_ = MmGetSystemRoutineAddress(&func_name);
		//ntqueryinformationprocess_ = MmGetSystemRoutineAddress((PUNICODE_STRING)L"NtQueryInformationProcess");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: ntopenprocess %p %p\n", ntopenprocess_, ntqueryinformationprocess_);
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: exception\n");
	}
}

NTSTATUS enum_processes(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS status;
	ULONG returnlen;
	PVOID pbuffer;
	//unsigned int i;

	/*UNICODE_STRING func_name;
	void * _ZwQuerySystemInformation = NULL;

	try
	{
		RtlInitUnicodeString(&func_name, L"ZwQuerySystemInformation");
		_ZwQuerySystemInformation = MmGetSystemRoutineAddress(&func_name);
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: can't get ZwQuerySystemInformation\n");
		
	}
	if(!_ZwQuerySystemInformation)
	{
		Irp->IoStatus.Information = 0;
		return STATUS_SUCCESS;
	}*/
	try
	{
		/*if(irpSp->Parameters.DeviceIoControl.InputBufferLength == sizeof(int))
		{
			StealthHook hookType = *(StealthHook*)Irp->AssociatedIrp.SystemBuffer;
			hookSysCall(hookType);
		}*/
		pbuffer = ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.DeviceIoControl.OutputBufferLength, 'loop'); if(NULL == pbuffer) return STATUS_INSUFFICIENT_RESOURCES;
		//pbuffer = 0;
		status = 0;
		returnlen = 0;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: zwquery BZ before %d %d after %d\n", IrpSp->Parameters.DeviceIoControl.InputBufferLength, IrpSp->Parameters.DeviceIoControl.OutputBufferLength, returnlen);
		status = ZwQuerySystemInformation(SystemProcessInformation, pbuffer , IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &returnlen);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: %d %d\n", status, returnlen);
		//returnlen = 500;
		//for(i = 0; i < returnlen; i++)
		//	((char *)Irp->AssociatedIrp.SystemBuffer)[i] = ((char *)_ZwQuerySystemInformation)[i];
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: some ids %d %d %d\n", ((SYSTEM_PROCESS_INFORMATION *)pbuffer)[3].UniqueProcessId, ((SYSTEM_PROCESS_INFORMATION *)pbuffer)[4].UniqueProcessId, ((SYSTEM_PROCESS_INFORMATION *)pbuffer)[5].UniqueProcessId);
		//((SYSTEM_PROCESS_INFORMATION *)pbuffer)[0].UniqueProcessId = (HANDLE)666;
		//((char *)pbuffer)[0] = 0x77;
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, pbuffer, returnlen);
		ExFreePoolWithTag(pbuffer, 'loop');
		//returnlen = 10;
		//((char *)Irp->UserBuffer)[1] = 0x16;
		/*((char *)Irp->AssociatedIrp.SystemBuffer)[0] = 0x55;
		((char *)Irp->AssociatedIrp.SystemBuffer)[1] = 0x66;
		((char *)Irp->AssociatedIrp.SystemBuffer)[2] = 0x77;
		((char *)Irp->AssociatedIrp.SystemBuffer)[3] = 0x88;*/
		//((char *)Irp->UserBuffer)[0] = 0x65;
		//((char *)Irp->UserBuffer)[1] = 0x76;
		//((char *)Irp->UserBuffer)[2] = 0x87;
		//((char *)Irp->UserBuffer)[3] = 0x98;
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = returnlen;
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

/*NTSTATUS KmdfHelloWorldEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
	NTSTATUS status;
	WDFDEVICE hDevice;
	UNREFERENCED_PARAMETER(Driver);
	UNREFERENCED_PARAMETER(DeviceInit);
	//KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: KmdfHelloWorldEvtDeviceAdd\n"));
	//status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);
	return status;
}*/



VOID Unload(struct _DRIVER_OBJECT *DriverObject)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: Unload  %p\n", DriverObject);
	//IoDeleteDevice(DriverObject->DeviceObject);
	PDEVICE_OBJECT pNextDeviceObj = DriverObject->DeviceObject;
	IoDeleteSymbolicLink(&uSymlinkName);

	while(pNextDeviceObj)
	{
		PDEVICE_OBJECT pdThisDeviceObj = pNextDeviceObj;
		pNextDeviceObj = pdThisDeviceObj->NextDevice;
		IoDeleteDevice(pdThisDeviceObj);
	}
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: Dispatch Create/Close %p\n", Irp);
	return status;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_QUERYPROCESSES:
			status = enum_processes(Irp, irpSp);
			break;
		case IOCTL_REQUESTINTCODE:
			//status = requestintcode(Irp, irpSp);
			break;
		default:
			Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			Irp->IoStatus.Information = 0;
			break;
	}

	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}