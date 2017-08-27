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
#include <stdint.h>
#include <WinSock2.h>
#include "helperlib.h"
#include "functionprototypes.h"
#include "logging.h"
#include "hook.h"
#include "justforvs.h"
#include "errors.h"

int status = 0;
SOCKET IPCSocket = NULL;

CRITICAL_SECTION critsection;

void test_info(void);
int setup_ipc_socket(uint16_t port);
int sendData(char * data, unsigned int size);
int fix_imports(void);
extern "C"
{
void nullsub(void);
}

typedef int(*WSAStartupPtr)(WORD wVersionRequested, LPWSADATA lpWSAData);
typedef int(*WSACleanupPtr)(void);
typedef int(*WSAGetLastErrorPtr)(void);
typedef int(*connectPtr)(SOCKET s, const struct sockaddr *name, int namelen);
typedef u_short(* /*WSAAPI*/ htonsPtr)(u_short hostshort);
typedef unsigned long(*inet_addrPtr)(const char *cp);
typedef int(*closesocketPtr)(SOCKET s);
typedef SOCKET(* /*WSAAPI*/ socketPtr)(int af, int type, int protocol);
typedef int(*sendPtr)(SOCKET s, const char *buf, int len, int flags);

LoadLibraryPtr OurLoadLibrary = (LoadLibraryPtr)0x6000000000000006;
GetProcAddressPtr OurGetProcAddress = (GetProcAddressPtr)0x6000000000000006;

/* These must have cursory definitions or they aren't exported... */
char logfileName[MAX_PATH + 1] = { 0x06, 0x00, 0x00, 0x06 };
wchar_t functionstohookfile[MAX_PATH + 1] = { 0x00, 0x01, 0x05, 0x10};

WSAStartupPtr _WSAStartup;
WSACleanupPtr _WSACleanup;
WSAGetLastErrorPtr _WSAGetLastError;
connectPtr _connect;
htonsPtr _htons;
inet_addrPtr _inet_addr;
closesocketPtr _closesocket;
socketPtr _socket;
sendPtr _send;
InitializeCriticalSectionPtr InitializeCriticalSection_0;
DeleteCriticalSectionPtr DeleteCriticalSection_0;
EnterCriticalSectionPtr EnterCriticalSection_0;
LeaveCriticalSectionPtr LeaveCriticalSection_0;
VirtualAllocPtr VirtualAlloc_0;
VirtualFreePtr VirtualFree_0;
GetCurrentProcessPtr GetCurrentProcess_0;
GetProcessIdPtr GetProcessId_0;
CreateToolhelp32SnapshotPtr CreateToolhelp32Snapshot_0;
CloseHandlePtr CloseHandle_0;
GetLastErrorPtr GetLastError_0;
Module32FirstWPtr Module32FirstW_0;
Module32NextWPtr Module32NextW_0;
ExitThreadPtr ExitThread_0;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		status++;
		break;
	}
	return TRUE;
}

DWORD WINAPI DLLIPCThread(LPVOID param)
{
	uint16_t port = (uint16_t )((DWORD)param & 0xffff);
	bool hijack = ((DWORD)param & 0x80000000);
	int ret;

	ret = fix_imports();
	if(ret < 0)
	{
		if(hijack)
			return 0;
		ExitThread_0(HELPER_FIXIMPORT_FAILED);
	}

	if(port)
	{
		ret = setup_ipc_socket(port);
		if(ret < 0)
		{}// ExitThread_0(ret);
		else
		{
			test_info();

			_closesocket(IPCSocket);
			_WSACleanup();
		}
	}
	try
	{
		if(setup_logging_file(logfileName) < 0)
		{
			if(hijack)
				return 0;
			ExitThread_0(LOGGING_FILE_FAILED);				//no point to going further... 
		}
	}
	catch(...)
	{
		if(hijack)
			return 0;
		ExitThread_0(-1);
	}
	logPrintf(utf8("软件开始\n"));
	logPrintf(utf8("PID %d Name: %s\n"), GetProcessId_0(GetCurrentProcess_0()), "UNHANDLED");
	logPrintf(utf8("Image Path: %s\n"), "UNHANDLED");			//tooltip should have this... 
	if(hijack)
		logPrintf("hijacked thread\n");
#ifdef _WIN64
	char * temp = (char *)&DLLIPCThread;
	logwPrintf(L"Our entry %08x%08x\n", PRINTARG64(temp));
#else
	logPrintf("Our entry %08x\n", (char *)&DLLIPCThread);
#endif //_WIN64

	InitializeCriticalSection_0(&critsection);

	ret = allocate_hook_space();
	if(ret < 0)
	{
		if(hijack)
			return 0;
		ExitThread_0(ret);
	}
	logPrintf("Hook space allocated\n");
	ret = hook_imports();
	if(ret < 0)
	{
		if(hijack)
			return 0;
		ExitThread_0(ret);
	}
	if(hijack)
		return 0;
	ExitThread_0(HELPERLIB_SUCCESS);
	return 0;
}

DWORD WINAPI UnloadHelperLib(LPVOID param)
{
	logPrintf("Cleaning up hooks...\n");
	cleanup_hook_space();
	DeleteCriticalSection_0(&critsection);

	logPrintf("Closing log...\n");
	close_logging_file();

	ExitThread_0(0);
	return 0;
}

void test_info(void)
{
	HANDLE pH;
	DWORD pid;
	char buffer[30];

	memset_0(buffer, 0x00, 30);

	pH = GetCurrentProcess_0();
	pid = GetProcessId_0(pH);

	*(DWORD *)&(buffer[0]) = pid;
	*(DWORD *)&(buffer[4]) = status;
	memcpy_0(&(buffer[8]), logfileName, 10);
	sendData(buffer, 30);
}

int setup_ipc_socket(uint16_t port)
{
	WSADATA wsaData;
	struct sockaddr_in clientService;
	int iResult;
	int i;

	memset_0(&wsaData, 0, sizeof(WSADATA));

	iResult = _WSAStartup(MAKEWORD(2, 2), &wsaData);
	if(iResult != 0) {
		return -1;
	}
	
	IPCSocket = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(IPCSocket == INVALID_SOCKET) {
		_WSACleanup();
		return -1;
	}
	
	//memset_0(&clientService, 0, sizeof(sockaddr_in));			//definitely causes weird xmm0 [esp + 0x10] crash
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = _inet_addr("127.0.0.1");
	clientService.sin_port = _htons(port);
	for(i = 0; i < 8; i++)
		clientService.sin_zero[i] = 0;

	iResult = _connect(IPCSocket, (sockaddr *)&clientService, sizeof(clientService));
	if(iResult == SOCKET_ERROR) {
		iResult = _WSAGetLastError();
		iResult = -iResult;
		_closesocket(IPCSocket);
		/*if(iResult == SOCKET_ERROR)
			wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());*/
		_WSACleanup();
		return iResult;
	}

	return 0;
}

int sendData(char * data, unsigned int size)
{
	int sent;
	char * d;
	unsigned int s;
	unsigned int total;
	
	total = 0;
	d = data;
	while(total < size)
	{
		if(size > total + 512)
			s = 512;
		else
			s = size - total;
		sent = _send(IPCSocket, d, s, 0);
		if(sent == SOCKET_ERROR)
		{
			_closesocket(IPCSocket);
			_WSACleanup();
			return -1;
		}
		total += sent;
		d += sent;
	}
	return 0;
}

/* This kind of seems unnecessary, it was from back when I wanted the library to be
 * lighter... but on the other hand, then we don't have an import table, I guess
 * it's okay. */
int fix_imports(void)
{
	HMODULE ws2lib = OurLoadLibrary(L"ws2_32.dll");
	HMODULE k32lib = OurLoadLibrary(L"kernel32.dll");
	HMODULE stdlib;
	if(!ws2lib || !k32lib)
		return -1;
	_WSAStartup = (WSAStartupPtr)OurGetProcAddress(ws2lib, "WSAStartup");
	_WSACleanup = (WSACleanupPtr)OurGetProcAddress(ws2lib, "WSACleanup");
	_WSACleanup = (WSACleanupPtr)&nullsub;
	_WSAGetLastError = (WSAGetLastErrorPtr)OurGetProcAddress(ws2lib, "WSAGetLastError");
	_connect = (connectPtr)OurGetProcAddress(ws2lib, "connect");
	_htons = (htonsPtr)OurGetProcAddress(ws2lib, "htons");
	_inet_addr = (inet_addrPtr)OurGetProcAddress(ws2lib, "inet_addr");
	_closesocket = (closesocketPtr)OurGetProcAddress(ws2lib, "closesocket");
	_socket = (socketPtr)OurGetProcAddress(ws2lib, "socket");
	_send = (sendPtr)OurGetProcAddress(ws2lib, "send");
	InitializeCriticalSection_0 = (InitializeCriticalSectionPtr)OurGetProcAddress(k32lib, "InitializeCriticalSection");
	DeleteCriticalSection_0 = (DeleteCriticalSectionPtr)OurGetProcAddress(k32lib, "DeleteCriticalSection");
	EnterCriticalSection_0 = (EnterCriticalSectionPtr)OurGetProcAddress(k32lib, "EnterCriticalSection");
	LeaveCriticalSection_0 = (LeaveCriticalSectionPtr)OurGetProcAddress(k32lib, "LeaveCriticalSection");
	GetCurrentProcess_0 = (GetCurrentProcessPtr)OurGetProcAddress(k32lib, "GetCurrentProcess");
	VirtualAlloc_0 = (VirtualAllocPtr)OurGetProcAddress(k32lib, "VirtualAlloc");
	VirtualFree_0 = (VirtualFreePtr)OurGetProcAddress(k32lib, "VirtualFree");
	GetProcessId_0 = (GetProcessIdPtr)OurGetProcAddress(k32lib, "GetProcessId");
	CreateToolhelp32Snapshot_0 = (CreateToolhelp32SnapshotPtr)OurGetProcAddress(k32lib, "CreateToolhelp32Snapshot");
	CloseHandle_0 = (CloseHandlePtr)OurGetProcAddress(k32lib, "CloseHandle");
	GetLastError_0 = (GetLastErrorPtr)OurGetProcAddress(k32lib, "GetLastError");
	Module32FirstW_0 = (Module32FirstWPtr)OurGetProcAddress(k32lib, "Module32FirstW");
	Module32NextW_0 = (Module32NextWPtr)OurGetProcAddress(k32lib, "Module32NextW");
	VirtualProtect_0 = (VirtualProtectPtr)OurGetProcAddress(k32lib, "VirtualProtect");
	CreateFileW_0 = (CreateFileWPtr)OurGetProcAddress(k32lib, "CreateFileW");
	GetFileSize_0 = (GetFileSizePtr)OurGetProcAddress(k32lib, "GetFileSize");
	ReadFile_0 = (ReadFilePtr)OurGetProcAddress(k32lib, "ReadFile");
	SetFilePointer_0 = (SetFilePointerPtr)OurGetProcAddress(k32lib, "SetFilePointer");
	WideCharToMultiByte_0 = (WideCharToMultiBytePtr)OurGetProcAddress(k32lib, "WideCharToMultiByte");
	ExitThread_0 = (ExitThreadPtr)OurGetProcAddress(k32lib, "ExitThread");
	GetTimeFormatEx_0 = (GetTimeFormatExPtr)OurGetProcAddress(k32lib, "GetTimeFormatEx");
	GetDateFormatEx_0 = (GetDateFormatExPtr)OurGetProcAddress(k32lib, "GetDateFormatEx");

	stdlib = OurLoadLibrary(L"msvcrt.dll");
	if(!stdlib)
		return -1;
	_fopen = (fopenPtr)OurGetProcAddress(stdlib, "fopen");
	_fwrite = (fwritePtr)OurGetProcAddress(stdlib, "fwrite");
	_fclose = (fclosePtr)OurGetProcAddress(stdlib, "fclose");
	_fflush = (fflushPtr)OurGetProcAddress(stdlib, "fflush");
	_sprintf = (sprintfPtr)OurGetProcAddress(stdlib, "sprintf");
	vsnprintf_0 = (vsnprintfPtr)OurGetProcAddress(stdlib, "vsnprintf");
	vsnwprintf_0 = (vsnwprintfPtr)OurGetProcAddress(stdlib, "_vsnwprintf");
	snprintf_0 = (snprintfPtr)OurGetProcAddress(stdlib, "snprintf");
	strlen_0 = (strlenPtr)OurGetProcAddress(stdlib, "strlen");
	wcslen_0 = (wcslenPtr)OurGetProcAddress(stdlib, "wcslen");
	strcmp_0 = (strcmpPtr)OurGetProcAddress(stdlib, "strcmp");
	stricmp_0 = (stricmpPtr)OurGetProcAddress(stdlib, "_stricmp");
	malloc_0 = (mallocPtr)OurGetProcAddress(stdlib, "malloc");
	realloc_0 = (reallocPtr)OurGetProcAddress(stdlib, "realloc");
	free_0 = (freePtr)OurGetProcAddress(stdlib, "free");
	swscanf_0 = (swscanfPtr)OurGetProcAddress(stdlib, "swscanf");
	sscanf_0 = (sscanfPtr)OurGetProcAddress(stdlib, "sscanf");
	wcstombs_0 = (wcstombsPtr)OurGetProcAddress(stdlib, "wcstombs");
	return 0;
}

void nullsub(void)
{
	//because we don't know what we're cleaning up with the WSACleanup... could kill something active.
}

//these may be somehow compiled in with 64 bit, but not 32?  I don't know...
void * memset_0(void *dest, int c, size_t count)
{
	unsigned int i;
	for(i = 0; i < count; i++)
		((char*)dest)[i] = c;
	return dest;
}

void * memcpy_0(void *dest, const void *src, size_t count)
{
	unsigned int i;
	for(i = 0; i < count; i++)
		((char*)dest)[i] = ((char *)src)[i];
	return dest;
}

int memcmp_0(const void * a, const void * b, size_t count)
{
	unsigned int i;
	for(i = 0; i < count; i++)
	{
		if(((char*)a)[i] != ((char *)b)[i])
			return -1;
	}
	return 0;
}
