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
#include <stdio.h>
#include <stdexcept>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <VersionHelpers.h>
#include <signal.h>  
#include "kernelreplacements.h"
#include "libraryloader.h"
#include "loadfiles.h"
#include "reconstitute.h"
#include "query.h"
#include "ipcsocket.h"
#include "driver.h"
#include "helperlib/errors.h"

#define NOINJECTIONCOMM
#define FUNCTIONSTOHOOKFILE			L"functionstohook.xml"
#define HELPERLOGFILE				"C:\\Users\\Peterius\\Documents\\anothergoddamnday.log"


typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef WCHAR * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

bool produceoutput = true;			//a little awkward, basically for testing
bool driver = true;
bool attemptinject = true;
HMODULE kernel32DLL = NULL;
HMODULE k32DLL = NULL;
HMODULE ntDLL = NULL;
HMODULE fakentDLL = NULL;

uint32_t g_pid;
char * functionstohookfilename;
char * helperlogfilename;
char * g_injectedbaseaddress;
char * unhookaddress;

HANDLE sync_event = NULL;

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

typedef struct _SYSTEM_BASIC_INFORMATION {
	BYTE Reserved1[24];
	PVOID Reserved2[4];
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	BYTE Reserved1[52];
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

//typedef uint32_t REALADDRESS;
typedef uint64_t REALADDRESS;

#define STATUS_ACCESS_DENIED	0xc0000022

typedef HANDLE (WINAPI * CreateToolhelp32SnapshotPtr)(DWORD dwFlags, DWORD th32ProcessID);
typedef FARPROC (WINAPI * GetProcAddressPtr)(HMODULE hModule, LPCSTR  lpProcName);
typedef NTSTATUS (WINAPI * NtQuerySystemInformationPtr)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS (* ZwOpenProcessPtr)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);

typedef int (WINAPI * lstrlenPtr)(LPCTSTR lpString);

CreateToolhelp32SnapshotPtr realCreateToolhelp32Snapshot = NULL;
GetProcAddressPtr realGetProcAddress = NULL;
GetProcAddressPtr ourGetProcAddress = NULL;
NtQuerySystemInformationPtr ourNtQuerySystemInformation = NULL;
NtQuerySystemInformationPtr realNtQuerySystemInformation = NULL;
NtQuerySystemInformationPtr fakeNtQuerySystemInformation = NULL;
ZwOpenProcessPtr ourZwOpenProcess = NULL;

void sigintcatch(int signal);
int filterException(int code, PEXCEPTION_POINTERS ex);
void dump_current_module(HANDLE process, char * name);
int enummodulepulldown(HANDLE processH, char * outputdirname);
void MakeLibrariesExecutable(void);
BOOL EnableDebugPrivilege(BOOL bEnable);
void CheckProcessPrivileges(uint16_t pid);
BOOL GetLogonSID(HANDLE hToken, PSID *ppsid);
WCHAR * GetLastErrorString(void);
int ListProcessThreads(uint32_t pid);
int injectProcess(HANDLE pH, BOOL wow64, char * code, unsigned int size);
int uninjectProcess(HANDLE pH);
uint32_t Get32ProcAddress(char * lib, char * _funcname);
extern "C"
{
NTSTATUS __stdcall AMD64_NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
void GetIDT64(char * idt6);
}
//NTSTATUS __stdcall DirectNTQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
void custom_library_loader_stuff(void);
inline void queryidt(void);

#pragma pack(1)
struct idtentry
{
	unsigned short base_lo;
	unsigned short sel;        /* Our kernel segment goes here! */
	unsigned char always0;     /* This will ALWAYS be set to 0! */
	unsigned char flags;       /* Set using the above table! */
	unsigned short base_hi;
};

#pragma pack(1)
struct idtentry64
{
	unsigned short offset1;
	unsigned short sel;        /* Our kernel segment goes here! */
	unsigned char always0;     /* This will ALWAYS be set to 0! */
	unsigned char flags;       /* Set using the above table! */
	unsigned short offset2;
	unsigned long offset3;
	unsigned long reserved0;
};

void queryidt(void)
{
	//char idt32[6];
	char idt64[10];
	uint16_t idtlimit;
	//uint32_t idtp;
	uint64_t idt64p;
	int i;
	//struct idtentry * idtentryp;
#ifdef IGUESSWERENOTTHEKERNEL
	struct idtentry64 * idtentry64p;
#endif //IGUESSWERENOTTHEKERNEL
	memset(idt64, 0, 10);
	GetIDT64(idt64);

	idtlimit = *(uint16_t *)idt64;
	idt64p = *(uint64_t *)(idt64 + 2);

	printf("IDT: ");
	for(i = 0; i < 10; i++)
		printf("%02x", (unsigned char)idt64[i]);
	printf("\n");
	printf("%04x %08x%08x\n", idtlimit, PRINTARG64(idt64p));

	/*idtentryp = (struct idtentry *)idtp;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentryp->base_lo, idtentryp->sel, idtentryp->always0, idtentryp->flags, idtentryp->base_hi);
	idtentryp++;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentryp->base_lo, idtentryp->sel, idtentryp->always0, idtentryp->flags, idtentryp->base_hi);
	idtentryp++;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentryp->base_lo, idtentryp->sel, idtentryp->always0, idtentryp->flags, idtentryp->base_hi);
	idtentryp++;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentryp->base_lo, idtentryp->sel, idtentryp->always0, idtentryp->flags, idtentryp->base_hi);
	idtentryp++;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentryp->base_lo, idtentryp->sel, idtentryp->always0, idtentryp->flags, idtentryp->base_hi);
	idtentryp++;*/
//#define IGUESSWERENOTTHEKERNEL
#ifdef IGUESSWERENOTTHEKERNEL
	idtentry64p = (struct idtentry64 *)idt64p;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printf(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	/*idtentry64p++;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printf(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printf(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printf(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;
	printf("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printf(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;*/
#endif //IGUESSWERENOTTHEKERNEL
}

void sigintcatch(int signal)
{
	HANDLE pH;

	if(attemptinject && g_injectedbaseaddress)
	{
		pH = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, g_pid);
		if(!pH || pH == INVALID_HANDLE_VALUE)
		{
			fprintf(stderr, "uninject process OpenProcess failed (%d)\n", GetLastError());
			return;
		}
		uninjectProcess(pH);
	}
	printf("Exiting\n");
}

int main(int argc, char ** argv)
{
	int i;
	REALADDRESS addr;
	char * outputfilename = NULL;
	char * outputdirname = NULL;
	char * reconfromdir = NULL;
	char * queryfromdir = NULL;
	//char * imagepath = NULL;
	int len;
	WCHAR * errstring;
	char * imagepath = NULL;
	DWORD err;

	functionstohookfilename = NULL;
	helperlogfilename = NULL;
	g_pid = (uint32_t)-1;
	g_injectedbaseaddress = NULL;

	for(i = 0; i < argc; i++)
	{
		if(strcmp("-o", argv[i]) == 0)
		{
			i++;
			outputdirname = (char *)malloc(strlen(argv[i]) + 1);
			sprintf(outputdirname, argv[i]);
		}
		else if(strcmp("-r", argv[i]) == 0)
		{
			i++;
			reconfromdir = (char *)malloc(strlen(argv[i]) + 1);
			sprintf(reconfromdir, argv[i]);
		}
		else if(strcmp("-l", argv[i]) == 0)
		{
			i++;
			helperlogfilename = (char *)malloc(MAX_PATH);
			GetFullPathNameA(argv[i], MAX_PATH, helperlogfilename, NULL);
		}
		else if(strcmp("-q", argv[i]) == 0)
		{
			i++;
			queryfromdir = (char *)malloc(strlen(argv[i]) + 1);
			sprintf(queryfromdir, argv[i]);
		}
		else if(strcmp("-p", argv[i]) == 0)
		{
			i++;
			sscanf(argv[i], "%u", &g_pid);
		}
		else if(strcmp("-d", argv[i]) == 0)
		{
			produceoutput = false;
		}
		else if(strcmp("-j", argv[i]) == 0)
		{
			attemptinject = false;
		}
		else if(strcmp("-n", argv[i]) == 0)
		{
			driver = false;
		}
		else if(strcmp("--functions", argv[i]) == 0)
		{
			i++;
			functionstohookfilename = (char *)malloc(strlen(argv[i]) + 1);
			sprintf(functionstohookfilename, argv[i]);
		}
		else if(strcmp("--help", argv[i]) == 0 || strcmp("-h", argv[i]) == 0)
		{
			printf("./processdumper -dn -o [dirname] -p [pid] -r [previousoutdir] -q [previousoutdir] -l [logfile]\n");
			printf("\t-r [outdir]: reconstruct from previous output directory\n");
			printf("\t-q [outdir]: query previously reconstituted exe/dll\n");
			printf("\t-d: don't produce output files or reconstitute\n");
			printf("\t-n: don't install driver\n");
			printf("\t-j: don't attempt to inject process\n");
			printf("\t-l [logfilename]: injected library will log to this file\n");
			printf("\t--functions [xmlfile]: specify functions to hook\n");
			return 0;
		}
	}

	if(reconfromdir)
	{
		reconstitute_from_directory(reconfromdir);
		if(reconstitute() < 0)
			fprintf(stderr, "Reconstitution failed\n");
		cleanup_reconstitution();
		free(reconfromdir);
		return 0;
	}
	else if(queryfromdir)
	{
		query_from_directory(queryfromdir);
		if(reconstitute() < 0)
			fprintf(stderr, "Query failed\n");
		cleanup_reconstitution();
		free(queryfromdir);
		return 0;
	}

	if(g_pid == (uint32_t)-1)
	{
		fprintf(stderr, "No process id specified, quitting.\n");
		if(outputdirname)
			free(outputdirname);
		return 0;
	}

	if(!outputdirname)
	{
		fprintf(stderr, "No output directory specified, using PID...\n");
		outputdirname = (char *)malloc(10);
		sprintf(outputdirname, "%d", g_pid);
	}

	if(!helperlogfilename)
	{
		helperlogfilename = (char *)malloc(strlen(HELPERLOGFILE) + 1);
		sprintf(helperlogfilename, HELPERLOGFILE);
	}

	if(driver && install_driver() < 0)
		fprintf(stderr, "Failed to install driver\n");

	if(!EnableDebugPrivilege(TRUE))
	{
		fprintf(stderr, "Unable to enable debug privileges\n");
		//RemoveDirectoryA(outputdirname);
		free(outputdirname);
		return -1;
	}


	queryidt();
	

	fakentDLL = LoadLibrary(L"ntdll.dll");
	printf("fakentdll.dll: %p\n", fakentDLL);
	if(!fakentDLL)
	{
		errstring = GetLastErrorString();
		//5 ACCESS_DENIED
		fwprintf(stderr, L"LoadLibrary fake ntdll.dll failed(%s)\n", errstring);
		free(errstring);
	}
	fakeNtQuerySystemInformation = (NtQuerySystemInformationPtr)GetProcAddress(fakentDLL, "NtQuerySystemInformation");
	fakeNtQuerySystemInformation(SystemBasicInformation, 0, 0, (PULONG)fakentDLL);
	k32DLL = LoadLibrary(L"kernel32.dll");
	if(!k32DLL)
	{
		errstring = GetLastErrorString();
		//5 ACCESS_DENIED
		fwprintf(stderr, L"LoadLibrary fake ntdll.dll failed(%s)\n", errstring);
		free(errstring);
	}

	CheckProcessPrivileges(g_pid);

#ifdef TESTTHIS
	/* Let's get something real here: */
	//kernel32DLL = LoadLibrary(L".\\kernel32.dll");
	kernel32DLL = LoadLibrary(L"C:\\MinGW\\msys\\1.0\\home\\peterius\\projects\\processdumper\\Debug\\realkernel32.dll");
	printf("kernel32.dll: %p\n", kernel32DLL);
	if(!kernel32DLL)
	{
		errstring = GetLastErrorString();
		//5 ACCESS_DENIED
		fwprintf(stderr, L"LoadLibrary kernel32.dll failed(%s)\n", errstring);
		free(errstring);
	}
	ntDLL = LoadLibrary(L"C:\\MinGW\\msys\\1.0\\home\\peterius\\projects\\processdumper\\Debug\\ntdll.dll");
	printf("ntdll.dll: %p\n", ntDLL);
	if(!ntDLL)
	{
		errstring = GetLastErrorString();
		//5 ACCESS_DENIED
		fwprintf(stderr, L"LoadLibrary ntdll.dll failed(%s)\n", errstring);
		free(errstring);
	}

	//to get NtQuery... asm... 
	fakentDLL = LoadLibrary(L"ntdll.dll");
	printf("fakentdll.dll: %p\n", fakentDLL);
	if(!fakentDLL)
	{
		errstring = GetLastErrorString();
		//5 ACCESS_DENIED
		fwprintf(stderr, L"LoadLibrary fake ntdll.dll failed(%s)\n", errstring);
		free(errstring);
	}
	fakeNtQuerySystemInformation = (NtQuerySystemInformationPtr)GetProcAddress(fakentDLL, "NtQuerySystemInformation");
	fakeNtQuerySystemInformation(SystemBasicInformation, 0, 0, (PULONG)fakentDLL);

	if(0)
		custom_library_loader_stuff();

	
	addr = (REALADDRESS)&LoadLibrary;
	if(addr)
	{
		for(i = 0; i < 0x32; i += 8)
			printf("%02x%02x%02x%02x, %02x%02x%02x%02x\n", ((unsigned char *)addr)[i], ((unsigned char *)addr)[i + 1], ((unsigned char *)addr)[i + 2], ((unsigned char *)addr)[i + 3],
			((unsigned char *)addr)[i + 4], ((unsigned char *)addr)[i + 5], ((unsigned char *)addr)[i + 6], ((unsigned char *)addr)[i + 7]);
	}

	

	if(kernel32DLL)
	{
		realGetProcAddress = (GetProcAddressPtr)GetProcAddress(kernel32DLL, "GetProcAddress");
		if(0)			//FIXME 64 bit
			printf("Real %p vs %p vs %p ours %p\n", &realGetProcAddress, (uint32_t)&GetProcAddress, KernelGetProcAddress(kernel32DLL, "GetProcAddress"), ourGetProcAddress);
		realCreateToolhelp32Snapshot = (CreateToolhelp32SnapshotPtr)GetProcAddress(kernel32DLL, "CreateToolhelp32Snapshot");
	}
	//HMODULE ntoskernelexe = LoadLibrary(L"C:\\Windows\\System32\\ntoskrnl.exe");
	//HMODULE ntoskernelexe = LoadLibrary(L"C:\\Windows\\WinSxS\\amd64_microsoft-windows-os-kernel_31bf3856ad364e35_10.0.15063.483_none_0119a15f1a94826b\\ntoskrnl.exe");
	HMODULE ntoskernelexe = LoadLibrary(L"C:\\MinGW\\msys\\1.0\\home\\peterius\\projects\\processdumper\\Debug\\blahblah.lib");
	printf("ntoskernelexe: %p\n", ntoskernelexe);
	if(!kernel32DLL)
	{
		errstring = GetLastErrorString();
		//5 ACCESS_DENIED
		fwprintf(stderr, L"LoadLibrary ntoskernelexe failed(%s)\n", errstring);
		free(errstring);
	}

	ZwOpenProcessPtr realNtOpenProcess;
	//ZwOpenProcessPtr realNtOpenProcess = (ZwOpenProcessPtr)GetProcAddress(ntoskernelexe, "ZwOpenProcess");
	if(fakentDLL)
		realNtOpenProcess = (ZwOpenProcessPtr)GetProcAddress(fakentDLL, "ZwOpenProcess");
	printf("zwopenprocess %p\n", realNtOpenProcess);
#endif //TESTTHIS

	if(driver)
	{
		DWORD * allprocesses;
		DWORD allprocesses_size;
		//DWORD request;
		//request = pid;
		DWORD size;
		
		SYSTEM_PROCESS_INFORMATION * processes;
		size = 2048 * sizeof(SYSTEM_PROCESS_INFORMATION);
		processes = (SYSTEM_PROCESS_INFORMATION *)calloc(size, sizeof(char));
		if(driverIoCtl(IOCTL_QUERYPROCESSES, NULL, 0, (char *)processes, &size) < 0)
			fprintf(stderr, "driver ioctl receive failed\n");
		else
		{
			allprocesses = (DWORD *)malloc(10000 * sizeof(DWORD));
			/*if(EnumProcesses(allprocesses, 10000 * sizeof(DWORD), &allprocesses_size) == 0)
			{
				fprintf(stderr, "Can't enumerate processes\n");
				free(allprocesses);
				allprocesses = NULL;
			}
			else
			{
				for(i = 0; i < (allprocesses_size / sizeof(DWORD)); i++)
				{
					if(allprocesses[i] == pid)
					{
						printf("But the process was there afterall...\n");
						break;
					}
				}
				if(i == (allprocesses_size / sizeof(DWORD)))
					printf("Couldn't find the process even in enumeration\n");
			}*/
			/*printf("Fine.\n");
			for(i = 0; i < size; i++)
				printf("%02x%02x%02x%02x ", ((unsigned char *)processes)[i], ((unsigned char *)processes)[i + 1], ((unsigned char *)processes)[i + 2], ((unsigned char *)processes)[i + 3]);
			printf("\n");*/
			printf("Notes from afar %d %02x %02x %02x\n", size, ((unsigned char *)processes)[0], ((unsigned char *)processes)[1], ((unsigned char *)processes)[2]);
			printf("From the kernel %p %d:\n", processes, size);
			SYSTEM_PROCESS_INFORMATION * spi_instance = (SYSTEM_PROCESS_INFORMATION *)processes;
			/*while(1)
			{
				printf("pid: %d %08x handles %d\n", spi_instance->UniqueProcessId, spi_instance->UniqueProcessId, spi_instance->HandleCount);
				for(i = 0; i < (allprocesses_size / sizeof(DWORD)); i++)
				{
					if(allprocesses[i] == (DWORD)spi_instance->UniqueProcessId)
						break;
				}
				if(i == (allprocesses_size / sizeof(DWORD)))
					printf("Found unenumerated process: %d\n", spi_instance->UniqueProcessId);

				if(spi_instance->NextEntryOffset == 0)
					break;
				else
					spi_instance = (SYSTEM_PROCESS_INFORMATION *)((char *)spi_instance + spi_instance->NextEntryOffset);
			}*/
			free(allprocesses);
		}
		free(processes);
	}

	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	SYSTEM_PROCESS_INFORMATION * spi;
	SYSTEM_BASIC_INFORMATION * basic;
	DWORD * allprocesses;
	DWORD allprocesses_size;
	DWORD spi_size;
	DWORD status;
	

	cid.UniqueProcess = (HANDLE)g_pid;
	cid.UniqueThread = 0;
	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = NULL;
	oa.ObjectName = NULL;
	oa.Attributes = 0;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;


	HANDLE processH = OpenProcess(PROCESS_QUERY_INFORMATION | READ_CONTROL | PROCESS_VM_READ, FALSE, g_pid);
	//HANDLE processH = OpenProcess(SYNCHRONIZE, FALSE, pid);
	/*HANDLE processH;
	if(!realNtOpenProcess(&processH, PROCESS_QUERY_INFORMATION | READ_CONTROL, &oa, &cid))*/		/* PROCESS_TERMINATE*/
	if(!processH)
	{	
		err = GetLastError();
		switch(err)
		{
			case ERROR_ACCESS_DENIED:
				printf("ACCESS DENIED openprocess\n");
				break;
			case ERROR_INVALID_PARAMETER:
				printf("INVALID PARAMETER openprocess\n");
				allprocesses = (DWORD *)malloc(10000 * sizeof(DWORD));
				if(EnumProcesses(allprocesses, 10000 * sizeof(DWORD), &allprocesses_size) == 0)
				{
					fprintf(stderr, "Can't enumerate processes\n");
					free(allprocesses);
					allprocesses = NULL;
				}
				else
				{
					for(i = 0; i < (allprocesses_size / sizeof(DWORD)); i++)
					{
						if(allprocesses[i] == g_pid)
						{
							printf("But the process was there afterall...\n");
							break;
						}
					}
					if(i == (allprocesses_size / sizeof(DWORD)))
						printf("Couldn't find the process even in enumeration\n");
				}
				basic = (SYSTEM_BASIC_INFORMATION *)malloc(sizeof(SYSTEM_BASIC_INFORMATION));
				status = AMD64_NtQuerySystemInformation(SystemBasicInformation, basic, sizeof(SYSTEM_BASIC_INFORMATION), &spi_size);
				printf("STATUS: %8x %d\n", status, basic->NumberOfProcessors);
				
				status = fakeNtQuerySystemInformation(SystemBasicInformation, basic, sizeof(SYSTEM_BASIC_INFORMATION), &spi_size);
				printf("usual STATUS: %8x %d\n", status, basic->NumberOfProcessors);
				free(basic);

				spi = (SYSTEM_PROCESS_INFORMATION *)calloc(10000, sizeof(SYSTEM_PROCESS_INFORMATION));
				status = fakeNtQuerySystemInformation(SystemProcessInformation, spi, 10000 * sizeof(SYSTEM_PROCESS_INFORMATION), &spi_size);
#define NTSTATUS_SUCCESS					0
#define NTSTATUS_OBJECT_TYPE_MISMATCH		0xc0000024
#define NTSTATUS_ACCESS_VIOLATION			0xc0000005
#define NTSTATUS_INVALID_HANDLE				0xc0000008
				if(status == NTSTATUS_SUCCESS)
				{
					SYSTEM_PROCESS_INFORMATION * spi_instance = spi;
					printf("size: %d\n", spi_size);
					while(1)
					{
						printf("pid: %d %08x\n", spi_instance->UniqueProcessId, spi_instance->UniqueProcessId);
						for(i = 0; i < sizeof(SYSTEM_PROCESS_INFORMATION); i++)
							printf("%02x", ((unsigned char *)spi_instance)[i]);
						printf("Exiting so as not to print all this shit out\n");
						goto main_exit;
						for(i = 0; i < (allprocesses_size / sizeof(DWORD)); i++)
						{
							if(allprocesses[i] == (DWORD)spi_instance->UniqueProcessId)
								break;
						}
						if(i == (allprocesses_size / sizeof(DWORD)))
							printf("Found unenumerated process: %d\n", spi_instance->UniqueProcessId);

						if(spi_instance->NextEntryOffset == 0)
							break;
					}
				}
				else if(status == NTSTATUS_OBJECT_TYPE_MISMATCH)
				{
					fprintf(stderr, "DirectNtQuery object type mismatch size: %d\n", spi_size);
				}
				else if(status == NTSTATUS_ACCESS_VIOLATION)
				{
					fprintf(stderr, "DirectNtQuery access violation size: %d\n", spi_size);
				}
				else
				{
					fprintf(stderr, "DirectNtQuery failed (%u: %08x)\n", status, status);
				}
				free(spi);
				free(allprocesses);
				break;
			default:
				errstring = GetLastErrorString();
				//5 ACCESS_DENIED
				fwprintf(stderr, L"OpenProcess %d failed(%d: %s)\n", g_pid, err, errstring);
				free(errstring);
				break;
		}
		//goto main_exit;
	}

#define IMAGE_PATH_LEN		500
	if(produceoutput)
	{
		if(!CreateDirectoryA(outputdirname, NULL))
		{
			fprintf(stderr, "Can't create directory: %s\n", outputdirname);
			CloseHandle(processH);
			free(outputdirname);
			return -1;
		}
	}

	imagepath = (char *)malloc(IMAGE_PATH_LEN * 2);
	len = IMAGE_PATH_LEN * 2;
	if(!QueryFullProcessImageName(processH, PROCESS_NAME_NATIVE, (LPWSTR)imagepath, (PDWORD)&len))
	{
		errstring = GetLastErrorString();
		fwprintf(stderr, L"QueryFullProcessImageName failed(%s)\n", errstring);
		free(errstring);
	}
	//for(i = 0; i < len * 2; i++)			//since it's wide characters
	//	printf("%c", imagepath[i]);
	printf("Image path: ");
	wprintf(L"%s\n", (LPWSTR)imagepath);

	free(imagepath);

	ListProcessThreads(g_pid);

	enummodulepulldown(processH, outputdirname);

	CloseHandle(processH);
	

	if(attemptinject)
	{
		char * dll;
		unsigned int dllsize;
		HANDLE pH;
		BOOL wow64;
		
		//pid = GetProcessId(GetCurrentProcess());

		pH = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, g_pid);
		if(!pH)
		{
			fprintf(stderr, "inject process OpenProcess failed (%d)\n", GetLastError());
			return -1;
		}

		IsWow64Process(pH, &wow64);

		attemptinject = 0;
		if(!wow64 && load_a_file("helperlib.dll", &dll, &dllsize) < 0)
			fprintf(stderr, "Failed to load %s\n", "helperlib.dll");
		else if(wow64 && load_a_file("helperlib32.dll", &dll, &dllsize) < 0)
			fprintf(stderr, "Failed to load %s\n", "helperlib32.dll");
		else if(injectProcess(pH, wow64, dll, dllsize) < 0)
			fprintf(stderr, "inject process failed\n");
		else
			attemptinject = 1;	//injected
		
		pH = NULL;
		if(attemptinject)
		{
		
#ifndef NOINJECTIONCOMM
			WaitForSingleObject(sync_event, INFINITE);
#endif //!NOINJECTIONCOMM
			/*struct sigaction sigIntHandler;

			sigIntHandler.sa_handler = sigintcatch;
			sigemptyset(&sigIntHandler.sa_mask);
			sigIntHandler.sa_flags = 0;

			sigaction(SIGINT, &sigIntHandler, NULL);*/

			signal(SIGINT, sigintcatch);
			while(1) {}			//wait for sigint
		}
	}

	if(reconstitute() < 0)
		fprintf(stderr, "Reconstitution failed\n");
	cleanup_reconstitution();
	//ListProcessThreads(pid);

main_exit:
	//RemoveDirectoryA(outputdirname);
	free(outputdirname);
	free(helperlogfilename);

	//FIXME silly dll names
	//if(fakentDLL)
	//	FreeLibrary(fakentDLL);
	if(ntDLL)
		FreeLibrary(ntDLL);
	if(kernel32DLL)
		FreeLibrary(kernel32DLL);
	if(k32DLL)
		FreeLibrary(k32DLL);
	if(0)
		cleanupLibraryLoader();

	if(driver && uninstall_driver() < 0)
		fprintf(stderr, "Failed to uninstall driver\n");

	/*
	dump_current_module(GetCurrentProcess(), "ntdll.dll");
	dump_current_module(GetCurrentProcess(), "kernel32.dll");

	free(outputdirname);*/
}

int filterException(int code, PEXCEPTION_POINTERS ex)
{
	printf("Exception: %08x %p\n", code, ex);
	return EXCEPTION_EXECUTE_HANDLER;
}

// FIXME FIXME FIXME 64
void dump_current_module(HANDLE process, char * name)
{
	HANDLE m;
	HMODULE h;
	DWORD bytes_written;;
	MODULEINFO modinfo;
	char * addr, r;
	//BOOL wow64;
	char * outname = (char *)calloc(strlen(name) + 6, sizeof(char));

	//IsWow64Process(process, &wow64);

	h = GetModuleHandleA(name);
	GetModuleInformation(process, h, &modinfo, sizeof(MODULEINFO));
	printf("%s %08x %08x\n", name, h, modinfo.SizeOfImage);
	//curent directory, does this work FIXME?
	sprintf(outname, "inmem%s", name);
	m = CreateFileA(outname, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	for(addr = (char *)h; addr < (char *)h + modinfo.SizeOfImage; addr += 1024)
	{
		if(!WriteFile(m, (char *)addr, 1024, &bytes_written, NULL))
			printf("Error: %d\n", GetLastError());
		//printf("Bytes Written: %d\n", bytes_written);
	}
	addr -= 1024;
	r = (char *)h + modinfo.SizeOfImage - addr;
	if(r)
		WriteFile(m, (char *)addr, r, &bytes_written, NULL);
	CloseHandle(m);
}

int enummodulepulldown(HANDLE processH, char * outputdirname)
{
	int i;
	HMODULE hMods[1024];
	DWORD cbNeeded;
	BOOL wow64;
	int files_of_data_written = 0;

	if(IsWow64Process(processH, &wow64) == 0)
	{
		fprintf(stderr, "IsWow64Process failed: %d\n", GetLastError());
	}

	if(!wow64)
		printf("64 bit process !! \n");

	if(EnumProcessModulesEx(processH, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
	{
		/* Are these always 32 bit ?!?!? FIXME shouldn't we check the process?*/
		printf("Enum %d %d\n", cbNeeded, (cbNeeded / sizeof(HMODULE)));
		for(i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];
			MODULEINFO modinfo;
			char * outname;
			HANDLE outfileh;
			DWORD bytes_written;
			SIZE_T bytes_read;
			char * addr;
			DWORD remaining;
			char * thebuffer;

			// Get the full path to the module's file.

			if(GetModuleFileNameEx(processH, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.

				//printf("\t%s (0x%08X)\n", szModName, hMods[i]);
			}
			else
				fprintf(stderr, "Can't get Module filename %08x\n", hMods[i]);
			if(GetModuleInformation(processH, hMods[i], &modinfo, sizeof(MODULEINFO)) == 0)
			{
				fprintf(stderr, "GetModuleInformation failed: (%d)\n", GetLastError());
				continue;
			}
			/*if(wow64)
			printf("%08x : %08x\n", hMods[i], modinfo.SizeOfImage);
			else
			printf("%08x%08x : %08x\n", PRINTARG64(hMods[i]), modinfo.SizeOfImage);*/

			if(szModName[0] != 0x00)
			{
				outname = (char *)calloc(strlen((char *)szModName) + strlen(outputdirname) + 40, sizeof(char));
				if(wow64)
					sprintf(outname, "%s/inmem_%08x_%s", outputdirname, hMods[i], (char *)szModName);
				else
					sprintf(outname, "%s/inmem_%08x%08x_%s", outputdirname, PRINTARG64(hMods[i]), (char *)szModName);
			}
			else
			{
				outname = (char *)calloc(8 + strlen(outputdirname) + 40, sizeof(char));
				if(wow64)
					sprintf(outname, "%s/inmem_%08x.dll", outputdirname, hMods[i]);
				else
					sprintf(outname, "%s/inmem_%08x%08x.dll", outputdirname, PRINTARG64(hMods[i]));
			}
			specify_reconstitution_path(outputdirname);
			thebuffer = (char *)malloc(modinfo.SizeOfImage);
			if(!thebuffer)
			{
				fprintf(stderr, "Can't allocate read buffer\n");
				goto proc_alloc_dump_fail;
			}
			if(produceoutput)
				outfileh = CreateFileA(outname, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			/* So what... just this try/catch block foils or fixes whatever the tencent stuff is crashing on ??? */
			try
			{
				if(produceoutput && !outfileh)
				{
					fprintf(stderr, "Error creating file %s: %d\n", outname, GetLastError());
				}
				else if(ReadProcessMemory(processH, hMods[i], thebuffer, modinfo.SizeOfImage, &bytes_read) == 0)
				{
					if(GetLastError() == ERROR_PARTIAL_COPY)
						fprintf(stderr, "Error reading process memory: partial copy?\n");
					else
						fprintf(stderr, "Error reading process memory: %d\n", GetLastError());
					//299 ERROR_PARTIAL_COPY
				}
				else if(produceoutput)
				{
					add_module_for_reconstitution((char *)hMods[i], thebuffer, modinfo.SizeOfImage);
					for(addr = thebuffer; addr < thebuffer + modinfo.SizeOfImage; addr += 1024)
					{
						if(!WriteFile(outfileh, (char *)addr, 1024, &bytes_written, NULL))
						{
							fprintf(stderr, "Write error: %d\n", GetLastError());
							CloseHandle(outfileh);
							goto proc_alloc_dump_fail;
						}
						//printf("Bytes Written: %d\n", bytes_written);
					}
					addr -= 1024;
					remaining = thebuffer + modinfo.SizeOfImage - addr;
					if(remaining)
					{
						WriteFile(outfileh, (char *)addr, remaining, &bytes_written, NULL);
						files_of_data_written++;
					}
					else if(bytes_written)
						files_of_data_written++;
					CloseHandle(outfileh);
				}
			}
			catch(...)
			{
				fprintf(stderr, "exception!\n");
			}
proc_alloc_dump_fail:
			free(outname);
		}
	}
	else
	{
		fprintf(stderr, "EnumProcessModules failed: (%d)\n", GetLastError());
	}

	printf("Total files with data written: %d\n", files_of_data_written);

	return 0;
}

void MakeLibrariesExecutable(void)
{
	unsigned int i, j, k;
	DWORD oldprotect;

	printf("Making libraries executable...\n");
	for(i = 0; i < libraries; i++)
	{
		for(j = 0; j < librarylist[i]->imports; j++)
		{
			if(!librarylist[i]->importlist[j]->may_not_not_be_executable)
			{
				for(k = 0; k < librarylist[i]->importlist[j]->sections; k++)
				{
					if(!VirtualProtect(librarylist[i]->importlist[j]->sectionlist[k].data, librarylist[i]->importlist[j]->sectionlist[k].size,
						/*PAGE_READWRITE | PAGE_EXECUTE*/PAGE_EXECUTE_READWRITE, &oldprotect))
					{
						printf("Virtualprotect error %d\n", GetLastError());
					}
					//else printf("oldprotect %08x\n", oldprotect);

				}
				librarylist[i]->importlist[j]->may_not_not_be_executable = true;
			}
		}
		if(!librarylist[i]->may_not_not_be_executable)
		{

			for(k = 0; k < librarylist[i]->sections; k++)
			{
				if(!VirtualProtect(librarylist[i]->sectionlist[k].data, librarylist[i]->sectionlist[k].size,
					/*PAGE_READWRITE | PAGE_EXECUTE*/PAGE_EXECUTE_READWRITE, &oldprotect))
				{
					printf("Virtualprotect error %d\n", GetLastError());
				}
			}
			librarylist[i]->may_not_not_be_executable = true;
		}
	}
}

BOOL EnableDebugPrivilege(BOOL bEnable)
{
	HANDLE hToken = nullptr;
	LUID luid, luid2;//, luid3, luid4, luid5, luid6, luid7, luid8, luid9, luid10;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid2)) return FALSE;
	/*if(!LookupPrivilegeValue(NULL, SE_AUDIT_NAME, &luid3)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luid4)) return FALSE;  
	if(!LookupPrivilegeValue(NULL, SE_TAKE_OWNERSHIP_NAME, &luid5)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_SECURITY_NAME, &luid6)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_INC_BASE_PRIORITY_NAME, &luid7)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid8)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_PROF_SINGLE_PROCESS_NAME, &luid9)) return FALSE;
	if(!LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &luid10)) return FALSE;*/
	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 2;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	tokenPriv.Privileges[1].Luid = luid2;
	tokenPriv.Privileges[1].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	/*tokenPriv.Privileges[2].Luid = luid3;
	tokenPriv.Privileges[2].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	tokenPriv.Privileges[3].Luid = luid4;
	tokenPriv.Privileges[3].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	tokenPriv.Privileges[4].Luid = luid5;
	tokenPriv.Privileges[4].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	tokenPriv.Privileges[5].Luid = luid6;
	tokenPriv.Privileges[5].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	tokenPriv.Privileges[6].Luid = luid7;
	tokenPriv.Privileges[6].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	tokenPriv.Privileges[7].Luid = luid8;
	tokenPriv.Privileges[7].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	tokenPriv.Privileges[8].Luid = luid9;
	tokenPriv.Privileges[8].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	tokenPriv.Privileges[9].Luid = luid10;
	tokenPriv.Privileges[9].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;*/

	if(!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;

	return TRUE;
}

void CheckProcessPrivileges(uint16_t pid)
{
	HANDLE hToken = NULL;
	HANDLE processH;
	PSID psid;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	ZwOpenProcessPtr realNtOpenProcess = (ZwOpenProcessPtr)GetProcAddress(fakentDLL, "ZwOpenProcess");

	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;
	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = NULL;
	oa.ObjectName = NULL;
	oa.Attributes = 0;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;

	if(!realNtOpenProcess(&processH, PROCESS_QUERY_INFORMATION | READ_CONTROL, &oa, &cid))		/* PROCESS_TERMINATE*/
		fprintf(stderr, "realNtOpenProcess failed\n");
	//processH = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if(!processH)
	{
		fprintf(stderr, "OpenProcess failed\n");
		return;
	}
	if(!OpenProcessToken(processH, TOKEN_QUERY, &hToken))
	{
		fprintf(stderr, "OpenProcessToken failed\n");
		return;
	}
	if(!GetLogonSID(hToken, &psid))
	{
		fprintf(stderr, "GetLogonSID failed\n");
		return;
	}
}

BOOL GetLogonSID(HANDLE hToken, PSID *ppsid)
{
	BOOL bSuccess = FALSE;
	DWORD dwIndex;
	DWORD dwLength = 0;
	PTOKEN_GROUPS ptg = NULL;

	// Verify the parameter passed in is not NULL.
	if(NULL == ppsid)
		goto Cleanup;

	// Get required buffer size and allocate the TOKEN_GROUPS buffer.

	if(!GetTokenInformation(
		hToken,         // handle to the access token
		TokenGroups,    // get information about the token's groups 
		(LPVOID)ptg,   // pointer to TOKEN_GROUPS buffer
		0,              // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		if(GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			goto Cleanup;

		ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY, dwLength);

		if(ptg == NULL)
			goto Cleanup;
	}

	// Get the token group information from the access token.

	if(!GetTokenInformation(
		hToken,         // handle to the access token
		TokenGroups,    // get information about the token's groups 
		(LPVOID)ptg,   // pointer to TOKEN_GROUPS buffer
		dwLength,       // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		goto Cleanup;
	}

	// Loop through the groups to find the logon SID.

	for(dwIndex = 0; dwIndex < ptg->GroupCount; dwIndex++)
		if((ptg->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID)
			== SE_GROUP_LOGON_ID)
		{
			// Found the logon SID; make a copy of it.

			dwLength = GetLengthSid(ptg->Groups[dwIndex].Sid);
			*ppsid = (PSID)HeapAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY, dwLength);
			if(*ppsid == NULL)
				goto Cleanup;
			if(!CopySid(dwLength, *ppsid, ptg->Groups[dwIndex].Sid))
			{
				HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
				goto Cleanup;
			}
			break;
		}

	bSuccess = TRUE;

Cleanup:

	// Free the buffer for the token groups.

	if(ptg != NULL)
		HeapFree(GetProcessHeap(), 0, (LPVOID)ptg);

	return bSuccess;
}

#define ERROR_STRING_LEN		50
WCHAR * GetLastErrorString(void)
{
	int errid = GetLastError();
	WCHAR * out;
	out = (WCHAR *)malloc(ERROR_STRING_LEN * 2);
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, 0, 0, out, ERROR_STRING_LEN, NULL);

	//cut off the FormatMessage newline
	out[wcslen(out) - 2] = (WCHAR)0x0000;
	return out;
}

int ListProcessThreads(uint32_t pid)
{
	HANDLE th32H = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	WCHAR * errstring;
	DWORD err;

	//ERROR_PARTIAL_COPY 299
	th32H = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE, pid);
	//th32H = realCreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE, pid);
	if(th32H == INVALID_HANDLE_VALUE)
	{
		errstring = GetLastErrorString();
		fwprintf(stderr, L"CreateToolhelp32Snapshot failed(%s)\n", GetLastErrorString());
		free(errstring);
		return -1;
	}

	te32.dwSize = sizeof(THREADENTRY32);

	if(!Thread32First(th32H, &te32))
	{
		err = GetLastError();
		errstring = GetLastErrorString();
		//18 ERROR_NO_MORE_FILES
		if(err == ERROR_NO_MORE_FILES)
			fprintf(stderr, "CreateToolhelp32Snapshot found no files?!\n");
		else
			fwprintf(stderr, L"Thread32First failed(%d: %s)\n", GetLastError(), GetLastErrorString());
		free(errstring);
		CloseHandle(th32H);     // Must clean up the snapshot object!
		return -1;
	}


	do
	{
		if(1)
		{
			printf("\n     OWNER PID      = 0x%08x", te32.th32OwnerProcessID);
			printf("\n     THREAD ID      = 0x%08x", te32.th32ThreadID);
			printf("\n     base priority  = %d", te32.tpBasePri);
			printf("\n     delta priority = %d", te32.tpDeltaPri);
		}
	} while(Thread32Next(th32H, &te32));

	CloseHandle(th32H);

	return 0;
}

#define ERROR_PARTIAL_COPY					299
//closes previously opened handle for wow64 check, dll choice, a little ugly...
int injectProcess(HANDLE pH, BOOL wow64, char * code, unsigned int size)
{
	char * baseaddress;
	size_t bytes_written;
	char * entryaddress;
	char ** datasymbol;
	HANDLE thread;
	DWORD thread_id;
	DWORD texitcode;
	uint16_t port;
	char * section_address;
	unsigned int section_size;
	char * section_data;
	char * call;

	get_next_section(code, &section_address, &section_data, &section_size);
	baseaddress = (char *)VirtualAllocEx(pH, NULL, 0x20000, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!baseaddress)
	{
		fprintf(stderr, "inject process VirtualAllocEx failed (%d)\n", GetLastError());
		CloseHandle(pH);
		return -1;
	}
	else if(baseaddress != section_address)
	{
		printf("Couldn't load at requested address, relocating...\n");
		section_address = baseaddress;
	}
	baseaddress = (char *)VirtualAllocEx(pH, section_address, section_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(!baseaddress)
	{
		fprintf(stderr, "inject process VirtualAllocEx 2 failed (%d)\n", GetLastError());
		CloseHandle(pH);
		return -1;
	}
	
	rebase(baseaddress, code, size);
	if(wow64)
	{
		uint32_t call32;
		printf("WoW64!\n");
		

		call32 = Get32ProcAddress("kernel32.dll", "LoadLibraryW");
		printf("call: %08x\n", call32);
		datasymbol = (char **)get_symbol_from_filedata(code, size, "OurLoadLibrary", 0);
		if(datasymbol && call32)
			*datasymbol = (char *)call32;
		else
		{
			fprintf(stderr, "Can't find LoadLibraryW\n");
			CloseHandle(pH);
			return -1;
		}

		call32 = Get32ProcAddress("kernel32.dll", "GetProcAddress");
		printf("call: %08x\n", call32);
		datasymbol = (char **)get_symbol_from_filedata(code, size, "OurGetProcAddress", 0);
		if(datasymbol && call32)
			*datasymbol = (char *)call32;
		else
		{
			fprintf(stderr, "Can't find GetProcAddress\n");
			CloseHandle(pH);
			return -1;
		}
	}
	else
	{
		datasymbol = (char **)get_symbol_from_filedata(code, size, "OurLoadLibrary", 0);
		if(datasymbol && k32DLL && (call = (char *)GetProcAddress(k32DLL, "LoadLibraryW")))
			*datasymbol = (char *)call;
		else
		{
			fprintf(stderr, "Can't find LoadLibraryW\n");
			CloseHandle(pH);
			return -1;
		}
		datasymbol = (char **)get_symbol_from_filedata(code, size, "OurGetProcAddress", 0);
		if(datasymbol && k32DLL && (call = (char *)GetProcAddress(k32DLL, "GetProcAddress")))
			*datasymbol = (char *)call;
		else
		{
			fprintf(stderr, "Can't find GetProcAddress\n");
			CloseHandle(pH);
			return -1;
		}
	}
	entryaddress = get_symbol_from_filedata(code, size, "DLLIPCThread", 1);		//already rebased...
	if(!entryaddress)
	{
		fprintf(stderr, "Can't find DLLIPCThread entry address\n");
		CloseHandle(pH);
		return -1;
	}
	unhookaddress = get_symbol_from_filedata(code, size, "UnloadHelperLib", 1);		//already rebased...
	if(!unhookaddress)
	{
		fprintf(stderr, "Can't find UnloadHelperLib address\n");
		CloseHandle(pH);
		return -1;
	}
	datasymbol = (char **)get_symbol_from_filedata(code, size, "logfileName", 0);
	if(datasymbol)
		strcpy((char *)datasymbol, helperlogfilename);
	else
	{
		fprintf(stderr, "Can't find logfileName\n");
		CloseHandle(pH);
		return -1;
	}
	datasymbol = (char **)get_symbol_from_filedata(code, size, "functionstohookfile", 0);
	if(datasymbol)
	{
		//FIXME if there's no file, or we don't provide one on the command line or something
		//we need to set the first character as zero
		//*(wchar_t *)datasymbol = 0;
		wchar_t * wpath = (wchar_t *)calloc(MAX_PATH + 1, sizeof(wchar_t));
		if(functionstohookfilename)
		{
			size_t converted;
			wchar_t * wname;
			wname = (wchar_t *)calloc((strlen(functionstohookfilename) + 1), sizeof(wchar_t));
			mbstowcs_s(&converted, wname, (strlen(functionstohookfilename) + 1), functionstohookfilename, strlen(functionstohookfilename));
			GetFullPathName(wname, MAX_PATH, wpath, NULL);
			wprintf(L"Using function hook file %s\n", wpath);
		}
		else
			GetFullPathName(FUNCTIONSTOHOOKFILE, MAX_PATH, wpath, NULL);
		lstrcpyW((wchar_t *)datasymbol, wpath);
		free(wpath);
	}
	else
	{
		fprintf(stderr, "Can't find functionstohookfile\n");
		CloseHandle(pH);
		return -1;
	}
	if(!WriteProcessMemory(pH, baseaddress, code, section_size, &bytes_written))
	{
		fprintf(stderr, "inject process WriteProcessMemory failed (%d)\n", GetLastError());
		CloseHandle(pH);
		return -1;
	}
	g_injectedbaseaddress = baseaddress;			//for later unhooking

	while(get_next_section(code, &section_address, &section_data, &section_size))
	{
		baseaddress = (char *)VirtualAllocEx(pH, section_address, section_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(!baseaddress)
		{
			fprintf(stderr, "inject process VirtualAllocEx 3 failed (%d)\n", GetLastError());
			CloseHandle(pH);
			return -1;
		}
		else if(baseaddress != section_address)
		{
			fprintf(stderr, "virtual alloc couldn't load section at RVA!\n");
			//would have to relocate the section...
			//probably should check for the total memory before using the base... FIXME
			CloseHandle(pH);
			return -1;
		}
		if(!WriteProcessMemory(pH, baseaddress, section_data, section_size, &bytes_written))
		{
			fprintf(stderr, "inject process WriteProcessMemory failed (%d)\n", GetLastError());
			CloseHandle(pH);
			return -1;
		}
	}

	printf("Injected\n");
#ifndef NOINJECTIONCOMM
	sync_event = CreateEvent(NULL, TRUE, FALSE, L"sync-event");
	port = setup_local_socket();
	if(port == -1)
		{ CloseHandle(pH); return -1; }
	//CloseHandle(sync_event);		//automatically done at process termination
#else
	port = 0;
#endif //!NOINJECTIONCOMM

	printf("Creating remote: %08x%08x 32: %08x\n", PRINTARG64(entryaddress), entryaddress);
	thread = CreateRemoteThread(pH, NULL, 0, (LPTHREAD_START_ROUTINE)entryaddress, (LPVOID)port, 0, &thread_id);
	if(!thread || thread == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "inject process CreateRemoteThread failed (%d)\n", GetLastError());
		CloseHandle(pH);
		return -1;
	}
	printf("Thread %08x\n", thread);

	WaitForSingleObject(thread, INFINITE);
	GetExitCodeThread(thread, &texitcode);
	CloseHandle(thread);

	if(texitcode != HELPERLIB_SUCCESS)
	{
		printf("Injection procedure likely failed: %d\n", texitcode);
		unhookaddress = 0;
	}
	else
		printf("Injection procedure complete\n");

	CloseHandle(pH);
	return 0;
}

int uninjectProcess(HANDLE pH)
{
	HANDLE thread;
	DWORD thread_id;
	BOOL wow64;
	char * dll;
	unsigned int dllsize;
	char * section_address;
	unsigned int section_size;
	char * section_data;

	if(!unhookaddress)
		printf("injection probably failed and cleaned up.\n");
	else
	{
		printf("Creating remote: %08x%08x 32: %08x\n", PRINTARG64(unhookaddress), unhookaddress);
		thread = CreateRemoteThread(pH, NULL, 0, (LPTHREAD_START_ROUTINE)unhookaddress, NULL, 0, &thread_id);
		if(!thread)
		{
			fprintf(stderr, "uninject process CreateRemoteThread failed (%d)\n", GetLastError());
			CloseHandle(pH);
			return -1;
		}
	
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}
	printf("Uninjection procedure complete, unmapping memory...\n");

	IsWow64Process(pH, &wow64);

	if(!wow64 && load_a_file("helperlib.dll", &dll, &dllsize) < 0)
		{ fprintf(stderr, "Failed to load %s\n", "helperlib.dll"); return -1; }
	else if(wow64 && load_a_file("helperlib32.dll", &dll, &dllsize) < 0)
		{ fprintf(stderr, "Failed to load %s\n", "helperlib32.dll"); return -1; }

	/* Total overkill, we really just need the sections but... */
	rebase(g_injectedbaseaddress, dll, dllsize);

	get_next_section(dll, &section_address, &section_data, &section_size);

	if(!VirtualFreeEx(pH, section_address, section_size, MEM_RELEASE))
		fprintf(stderr, "VirtualFree failed %d\n", GetLastError());
	while(get_next_section(dll, &section_address, &section_data, &section_size))
	{
		if(!VirtualFreeEx(pH, section_address, section_size, MEM_RELEASE))
			fprintf(stderr, "VirtualFree failed %d\n", GetLastError());
	}

	CloseHandle(pH);

	return 0;
}

/* So that we can get the basic setup functions for a 32 bit injection from this 64 bit application */
uint32_t Get32ProcAddress(char * lib, char * _funcname)
{
	WCHAR * funcname;
	STARTUPINFO startupinfo;
	PROCESS_INFORMATION processinfo;
	DWORD exitcode;

	memset(&startupinfo, 0, sizeof(STARTUPINFO));
	memset(&processinfo, 0, sizeof(PROCESS_INFORMATION));


	WCHAR exePath[512];
	size_t converted;
	WCHAR * wname, * commandline;

	wname = (WCHAR *)calloc((strlen("thirtytwobithelper.exe") + 1), sizeof(wchar_t));
	mbstowcs_s(&converted, wname, (strlen("thirtytwobithelper.exe") + 1), "thirtytwobithelper.exe", strlen("thirtytwobithelper.exe"));
	GetFullPathName(wname, 512, exePath, NULL);


	commandline = (WCHAR *)calloc((strlen(lib) + strlen(_funcname) + 2), sizeof(wchar_t));
	mbstowcs_s(&converted, commandline, (strlen(lib) + 1), lib, strlen(lib));
	funcname = (WCHAR *)calloc((strlen(_funcname) + 1), sizeof(wchar_t));
	mbstowcs_s(&converted, funcname, (strlen(_funcname) + 1), _funcname, strlen(_funcname));

	wsprintf(&(commandline[wcslen(commandline)]), L" %s", funcname);

	if(!CreateProcess(
		exePath,           //  pointer to name of executable module  
		commandline,         //  pointer to command line string  
		NULL,                //  pointer to process security attributes  
		NULL,                //  pointer to thread security attributes  
		TRUE,                //  handle inheritance flag  
		0,                   //  creation flags  
		NULL,                //  pointer to new environment block  
		NULL,                //  pointer to current directory name  
		&startupinfo,        //  pointer to STARTUPINFO  
		&processinfo         //  pointer to PROCESS_INFORMATION  
	))
	{
		fprintf(stderr, "Create 32 bit helper process failed %d\n", GetLastError());
		return NULL;
	}

	WaitForSingleObject(processinfo.hProcess, INFINITE);
	GetExitCodeProcess(processinfo.hProcess, &exitcode);

	free(wname);
	free(commandline);
	free(funcname);

	return exitcode;
}


/*NTSTATUS __stdcall DirectNTQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	mov r10, rcx
		mov eax, 36
		test byte ptr ds : [7FFE0308], 1
		jne ntdll.7FFDACDD5A65
		syscall
		ret
		int 2E
		ret
	return (NTSTATUS)0;
}*/


#ifdef X86
__declspec(naked)
NTSTATUS __stdcall DirectNTQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{


	//IsWindows10OrGreater
	//For Windows 7
	//if(OSMajorVersion == 6 && OSMinorVersion == 1)
	if(IsWindows7OrGreater())
	{
		__asm
		{
			mov eax, 0x105
			call SystemCall_WIN7
			ret 0x10
			SystemCall_WIN7:
			mov edx, esp
				sysenter
		}
	}
	//For Windows Vista & Longhorn
	//if(OSMajorVersion == 6 && OSMinorVersion == 0)
	if(IsWindowsVistaOrGreater())
	{
		__asm
		{
			mov eax, 0xF8
			call SystemCall_VISTA
			ret 0x10

			SystemCall_VISTA:

			mov edx, esp
				sysenter
		}
	}

	//For Windows XP
	//if(OSMajorVersion == 5 && OSMinorVersion == 1)
	if(IsWindowsXPOrGreater())
	{
		__asm
		{
			mov eax, 0xAD
			call SystemCall_XP
			ret 0x10

			SystemCall_XP:

			mov edx, esp
				sysenter
		}

	}

	//For Windows 2000
	//if(OSMajorVersion == 5 && OSMinorVersion == 0)
	if(1)
	{
		__asm
		{
			mov eax, 0x97
			lea edx, DWORD * ss : [esp + 4]
			INT 0x2E
			ret 0x10
		}

	}
}
#endif //X86

/* because I'm too lazy to try to fix this up for x64 tonight, or probably anytime soon
 * I just want to see how it's evading the OpenProcess */
void custom_library_loader_stuff(void)
{
	uint32_t addr;			//REALADDRESS FIXME
	int i;
	WCHAR * errstring;

	addImportPath(".\\");
	OverridingLibraryLoader("kernel32.dll");				//lots of missing api-ms stuff
															//OverridingLibraryLoader("KernelBase.dll");
															//OverridingLibraryLoader("x64gui.dll");
	MakeLibrariesExecutable();
	ourNtQuerySystemInformation = (NtQuerySystemInformationPtr)GetOverridingProcAddress("ntdll.dll", "NtQuerySystemInformation");
	if(ntDLL)
		realNtQuerySystemInformation = (NtQuerySystemInformationPtr)GetProcAddress(ntDLL, "NtQuerySystemInformation");
	printf("NtQuery... %p %p\n", realNtQuerySystemInformation, ourNtQuerySystemInformation);

	addr = (uint32_t)GetOverridingProcAddress("kernel32.dll", "LoadLibraryA");
	printf("LoadLibrary %08x\n", addr);
	//preview the code:
	if(addr)
	{
		for(i = 0; i < 0x32; i += 8)
			printf("%02x%02x%02x%02x, %02x%02x%02x%02x\n", ((unsigned char *)addr)[i], ((unsigned char *)addr)[i + 1], ((unsigned char *)addr)[i + 2], ((unsigned char *)addr)[i + 3],
			((unsigned char *)addr)[i + 4], ((unsigned char *)addr)[i + 5], ((unsigned char *)addr)[i + 6], ((unsigned char *)addr)[i + 7]);
		printf("\n");
	}

	lstrlenPtr test = (lstrlenPtr)GetOverridingProcAddress("kernel32.dll", "lstrlenW");
	lstrlenPtr test2 = (lstrlenPtr)GetOverridingProcAddress("KERNELBASE.dll", "lstrlenW");
	//ourNtQuerySystemInformation(SystemBasicInformation, 0, 0, 0);
	lstrlenW((WCHAR *)L"Blah\n");
	//test((WCHAR *)0x55);
	errstring = GetLastErrorString();
	//5 ACCESS_DENIED
	fwprintf(stderr, L"ourNtQueryInformationProcess failed (%s)\n", errstring);
	free(errstring);
}

