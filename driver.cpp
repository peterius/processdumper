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

/* Jan Newger's IDAStealth was helpful for this service manager/driver stuff */
#include <Windows.h>
#include <stdio.h>
#include <string>
#include "driver.h"
#include "resource.h"

#define DRIVER_NAME				"warontencent.sys"
#define DRIVER_NAME_WIDE		L"warontencent.sys"
#define DEVICE_NAME				"\\\\Device\\warontencent"

wchar_t fullpath[MAX_PATH + 1];
char fullpatha[MAX_PATH + 1];

int load_unload_driver(bool load);
int saveDriverData(void);

int install_driver(void)
{
	GetFullPathName(DRIVER_NAME_WIDE, MAX_PATH, fullpath, NULL);
	GetFullPathNameA(DRIVER_NAME, MAX_PATH, fullpatha, NULL);
	if(saveDriverData() < 0)
		{ fprintf(stderr, "Failed to save driver data\n"); return -1; }
	load_unload_driver(true);
	return 0;
}

int uninstall_driver(void)
{
	//in case we're just calling this cold:
	GetFullPathName(DRIVER_NAME_WIDE, MAX_PATH, fullpath, NULL);
	GetFullPathNameA(DRIVER_NAME, MAX_PATH, fullpatha, NULL);
	load_unload_driver(false);
	DeleteFileA(DRIVER_NAME);
	return 0;
}

int load_unload_driver(bool load)
{
	DWORD lastError = 0;
	SERVICE_STATUS stat;

	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(hSCManager == NULL) { fprintf(stderr, "Unable to open service manager %d\n", GetLastError()); return -1; }

	SC_HANDLE hService = CreateService(hSCManager, DRIVER_NAME_WIDE, DRIVER_NAME_WIDE, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, fullpath, NULL, NULL, NULL, NULL, NULL);
	if(!hService)
	{
		lastError = GetLastError();
		if(lastError == ERROR_SERVICE_EXISTS || lastError == ERROR_SERVICE_MARKED_FOR_DELETE)
		{
			hService = OpenService(hSCManager, DRIVER_NAME_WIDE, SERVICE_ALL_ACCESS);
		}
		else
		{
			CloseServiceHandle(hSCManager);
			fprintf(stderr, "Error while trying to create driver service with name: %s %d\n", DRIVER_NAME, lastError);
			//487 ERROR_INVALID_ADDRESS
			//87 INVALID_PARAMETER
			//1072 ERROR_SERVICE_MARKED_FOR_DELETE
			return -1;
		}
	}

	QueryServiceStatus(hService, &stat);
	printf("Service Type %d state %d accepted %08x\n", stat.dwServiceType, stat.dwCurrentState, stat.dwControlsAccepted);
	if(stat.dwCurrentState == SERVICE_RUNNING && load)
	{
		printf("driver already running\n");
		return 0;
	}
	if(load)
	{
		if(!StartService(hService, 0, NULL))
		{
			lastError = GetLastError();
			if(lastError != ERROR_SERVICE_ALREADY_RUNNING)
			{
				CloseServiceHandle(hSCManager);
				CloseServiceHandle(hService);
				fprintf(stderr, "Error while trying to start driver service %d\n", lastError);
				//2 ERROR_FILE_NOT_FOUND
				//577 ERROR_INVALID_IMAGE_HASH
				//123 ERROR_INVALID_NAME
			}
		}
	}
	else
	{
		SERVICE_STATUS ss;
		if(!ControlService(hService, SERVICE_CONTROL_STOP, &ss))
		{
			lastError = GetLastError();
			fprintf(stderr, "Error while stopping driver %d\n", lastError);
			//ERROR_INVALID_SERVICE_CONTROL
			//1062 ERROR_SERVICE_NOT_ACTIVE
		}
		if(!DeleteService(hService))
		{
			lastError = GetLastError();
			CloseServiceHandle(hSCManager);
			CloseServiceHandle(hService);
			fprintf(stderr, "Error while trying to stop driver %d\n", lastError);
			//6 ERROR_INVALID_HANDLE
			//1072 ERROR_SERVICE_MARKED_FOR_DELETE
		}
	}

	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hService);

	return 0;
}

int saveDriverData(void)
{
	size_t size;
	FILE* hFile;
	HMODULE prog = GetModuleHandle(L"processdumper.exe");
	HRSRC hResInfo = FindResource(prog, L"IDR_WARONTENCENT", L"DRV");
	if(!hResInfo) { fprintf(stderr, "Cannot find driver resource\n"); return -1; }

	HGLOBAL resData = LoadResource(prog, hResInfo);
	if(!resData) return -1;

	void* dataPtr = LockResource(resData);
	if(dataPtr) size = SizeofResource(prog, hResInfo);
	else { fprintf(stderr, "Cannot get driver resource\n"); return -1; }
	int retVal = -1;

	fopen_s(&hFile, DRIVER_NAME, "wb");
	if(!hFile) return -1;

	if(fwrite(dataPtr, size, 1, hFile)) retVal = 0;
	fclose(hFile);

	Sleep(10000);
	return retVal;

}

int driverIoCtl(int ioctlCode, char * inbuffer, unsigned long insize, char * outbuffer, unsigned long * outsize)
{
	std::string device = "\\\\.\\warontencent";
	HANDLE hDevice = CreateFileA(device.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hDevice != INVALID_HANDLE_VALUE)
	{
		//DWORD bytesReturned;
		//  DeviceIoControl(hDevice, ioctlCode, &param, sizeof(unsigned int), NULL, 0, &bytesReturned, NULL))
		if(!DeviceIoControl(hDevice, ioctlCode, inbuffer, insize, outbuffer, *outsize, outsize, NULL))
		{
			DWORD lastErr = GetLastError();
			CloseHandle(hDevice);
			fprintf(stderr, "Unable to send IOCTL command to driver %s %d\n", device.c_str(), lastErr);
			return -1;
		}
		CloseHandle(hDevice);
	}
	else
	{
		fprintf(stderr, "Unable to open driver object: %s %d\n", device.c_str(),  GetLastError());
		//53 ERROR_BAD_NETPATH
		//3 ERROR_PATH_NOT_FOUND
		//2 ERROR_FILE_NOT_FOUND
		return -1;
	}
	return 0;
}