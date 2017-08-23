﻿/*  processdumper: console utility for software analysis
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
#pragma once
#include <Windows.h>
#include <intrin.h>
#include "hook.h"
#include "logging.h"
#include "functionprototypes.h"
#include "hookstructures.h"
#include "xmlhookloader.h"
#include "argspecutil.h"

unsigned long dispatch_magic = 0x66555467;
strcmpPtr strcmp_0;
stricmpPtr stricmp_0;
VirtualProtectPtr VirtualProtect_0;

char * hookspace = NULL;
unsigned int hookspace_size;
unsigned int hooked_funcs;

unsigned int hookfuncsize;
unsigned int totalhooksize;

struct hooked_func * curhook_hfstruct;
void * curhook_stackpointer;
void * curhook_origret;
void * curhook_stackandretval;
value_t g_next_dispatch_length;

int isofprecallinterest(argtypep arg);
int isofpostcallinterest(argtypep arg);
void dispatch_arg(void * p, argtypep arg);
int hook_import_table(char * baseaddr, unsigned int size, bool unhook=false);
struct hooked_func * shouldwehook(char * libname, unsigned short ordinal, char * funcname);
int generate_hook(struct hooked_func * proto_hfstruct);
void cleanup_hook(struct hooked_func * hfstruct);

#ifdef _WIN64
#define OUR_SP_ADDITIONS			(3 * 8)
#else
#define OUR_SP_ADDITIONS			(3 * 4)
#endif //_WIN64

void hookfuncfunc(void * sp, unsigned long functiondispatch)
{
	//堆栈可以损失，不可以用
	struct arg_spec * arg_spec;

	EnterCriticalSection_0(&critsection);
	curhook_stackpointer = sp;
	curhook_origret = *(void **)((char *)curhook_stackpointer + OUR_SP_ADDITIONS);

	curhook_hfstruct = (struct hooked_func *)(hookspace + (functiondispatch * totalhooksize));
#ifdef _WIN64
	logPrintf("%08x%08x called %s\n", PRINTARG64(curhook_origret), curhook_hfstruct->origname);
#else
	logPrintf("%08x called %s\n", curhook_origret, curhook_hfstruct->origname);
#endif //_WIN64

	g_next_dispatch_length = 0;
	arg_spec = curhook_hfstruct->arg;
	while(arg_spec)
	{
		logPrintf("arg_spec type %04x %p\n", arg_spec->type, arg_spec->deref);
		if(isofprecallinterest(arg_spec))
#ifdef _WIN64
			dispatch_arg((char *)curhook_stackpointer + OUR_SP_ADDITIONS + 8, arg_spec);
#else
			dispatch_arg((char *)curhook_stackpointer + OUR_SP_ADDITIONS + 4, arg_spec);
#endif //_WIN64
		arg_spec = arg_spec->next_spec;
	}
	
	/* We want the stack as the function has consumed it, but we'll push the return on there too */
#ifdef _WIN64
	logPrintf("orig func %08x%08x\n", PRINTARG64(curhook_hfstruct->origfunc));
#else
#endif //_WIN64
	curhook_stackandretval = call_orig_func_as_if(curhook_stackpointer, curhook_hfstruct->origfunc, RETURNTOHERE);		//need to leave critical section
	logPrintf("returns:\n");
	/* How do we differentiate return values in the log FIXME */
	g_next_dispatch_length = 0;
	arg_spec = curhook_hfstruct->arg;
	while(arg_spec)
	{
		if(isofpostcallinterest(arg_spec))
		{
			logPrintf("\t");
#ifdef _WIN64
			if(arg_spec->type & ARGSPECRETURN_VALUE)
				dispatch_arg((char *)curhook_stackandretval, arg_spec);
			else
				dispatch_arg((char *)curhook_stackandretval + OUR_SP_ADDITIONS + 8, arg_spec);
#else
			if(arg_spec->type & ARGSPECRETURN_VALUE)
				dispatch_arg((char *)curhook_stackandretval, arg_spec);
			else
				dispatch_arg((char *)curhook_stackandretval + OUR_SP_ADDITIONS + 4, arg_spec);
#endif //_WIN64
		}
		arg_spec = arg_spec->next_spec;
	}

	LeaveCriticalSection_0(&critsection);
	cleanup_hooking(curhook_stackandretval, curhook_origret);
	//never gets here
}

int isofprecallinterest(argtypep arg)
{
	if(!arg)
		return 0;
	arg = deref_end(arg);
	if(arg->type & ARGSPECOFPRECALLINTEREST)
		return 1;
	return 0;
}

int isofpostcallinterest(argtypep arg)
{
	if(!arg)
		return 0;
	arg = deref_end(arg);
	if(arg->type & ARGSPECOFPOSTCALLINTEREST)
		return 1;
	return 0;
}

/* maybe we want a try/catch here for exceptions but... if the process is throwing
 * bad data to apis, we're out anyway and we shouldn't be looking at anything
 * assumed to be uninitialized, or at least not dereferencing it*/
void dispatch_arg(void * p, argtypep arg)
{
	unsigned int i;
	argchecktype type;
#ifdef _WIN64
	unsigned long long temp;
#endif //_WIN64
	//__debugbreak();
	/* At some point, I probably want to use the ->type type space
	 * to do a lookup where we can store some variable names from the XML FIXME */

	type = arg->type;
	p = (char *)p + arg->offset;
	while(arg->deref)
	{
		arg = arg->deref;
		p = (char *)p + arg->offset;
	}

	if(type & ARGSPECARRAY)
		logPrintf("WARNING: dispatch array argument unhandled!\n");

	//final data
	switch(type & ARGSPECTYPEMASK)
	{
		case ARG_TYPE_INT8:
			if(type & ARGSPECLENRELATED)
			{
				if(type & ARGSPECPOINTER)
					g_next_dispatch_length = (value_t)**(char **)p;
				else
					g_next_dispatch_length = (value_t)*(char *)p;
			}
			else if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%d, ", (*(char **)p)[i]);
				logPrintf("%d\n", (*(char **)p)[i]);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("INT8: %d\n", *(char *)p);
			break;
		case ARG_TYPE_UINT8:
			if(type & ARGSPECLENRELATED)
			{
				if(type & ARGSPECPOINTER)
					g_next_dispatch_length = (value_t)**(unsigned char **)p;
				else
					g_next_dispatch_length = (value_t)*(unsigned char *)p;
			}
			else if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("UCHAR[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%u, ", (*(unsigned char **)p)[i]);
				logPrintf("%u\n", (*(unsigned char **)p)[i]);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("UINT8: %u\n", *(unsigned char *)p);
			break;
		case ARG_TYPE_INT16:
			if(type & ARGSPECLENRELATED)
			{
				if(type & ARGSPECPOINTER)
					g_next_dispatch_length = (value_t)**(short **)p;
				else
					g_next_dispatch_length = (value_t)*(short *)p;
			}
			else if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("SHORT[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%d, ", (*(short **)p)[i]);
				logPrintf("%d\n", (*(short **)p)[i]);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("SHORT: %d\n", *(short *)p);
			break;
		case ARG_TYPE_UINT16:
			if(type & ARGSPECLENRELATED)
			{
				if(type & ARGSPECPOINTER)
					g_next_dispatch_length = (value_t)**(unsigned short **)p;
				else
					g_next_dispatch_length = (value_t)*(unsigned short *)p;
			}
			else if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("USHORT[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%u, ", (*(unsigned short **)p)[i]);
				logPrintf("%u\n", (*(unsigned short **)p)[i]);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("USHORT: %u\n", *(unsigned short *)p);
			break;
		case ARG_TYPE_INT32:
			if(type & ARGSPECLENRELATED)
			{
				if(type & ARGSPECPOINTER)
					g_next_dispatch_length = (value_t)**(long **)p;
				else
					g_next_dispatch_length = (value_t)*(long *)p;
			}
			else if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("LONG[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%d, ", (*(long **)p)[i]);
				logPrintf("%d\n", (*(long **)p)[i]);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("LONG: %d\n", *(long *)p);
			break;
		case ARG_TYPE_UINT32:
			if(type & ARGSPECLENRELATED)
			{
				if(type & ARGSPECPOINTER)
					g_next_dispatch_length = (value_t)**(unsigned long **)p;
				else
					g_next_dispatch_length = (value_t)*(unsigned long *)p;
			}
			else if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("ULONG[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%u, ", (*(unsigned long **)p)[i]);
				logPrintf("%u\n", (*(unsigned long **)p)[i]);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("ULONG: %u\n", *(unsigned long *)p);
			break;
#ifdef _WIN64
		//FIXME This probably doesn't work and won't be used anyway...:
		case ARG_TYPE_UINT64:
			if(type & ARGSPECLENRELATED)
			{
				if(type & ARGSPECPOINTER)
					g_next_dispatch_length = (value_t)**(unsigned long long **)p;
				else
					g_next_dispatch_length = (value_t)*(unsigned long long *)p;
			}
			else if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("ULONGLONG[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%u, ", (*(unsigned long long **)p)[i]);
				logPrintf("%u\n", (*(unsigned long long **)p)[i]);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("ULONGLONG: %u\n", *(unsigned long long *)p);
			break;
#endif //_WIN64
		case ARG_TYPE_PTR:
			if(type & ARGSPECLENRELATED)
				logPrintf("WARNING: length related pointer to pointer ?!?\n");
#ifdef _WIN64
			if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("PTR[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
				{
					temp = (*(unsigned long long **)p)[i];
					logPrintf("%08x%08x, ", PRINTARG64(temp));
				}
				temp = (*(unsigned long long **)p)[i];
				logPrintf("%08x%08x\n", PRINTARG64(temp));
				g_next_dispatch_length = 0;
			}
			else
			{
				temp = *(unsigned long long *)p;
				logPrintf("PTR: %08x%08x\n", PRINTARG64(temp));
			}
#else
			if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("PTR[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%08x, ", (*(unsigned long **)p)[i]);
				logPrintf("%08x\n", (*(unsigned long **)p)[i]);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("PTR: %08x\n", *(unsigned long *)p);
#endif //_WIN64
			break;
		case ARG_TYPE_CHAR:
			if(type & ARGSPECPOINTER)
			{
				logData((unsigned char *)p, g_next_dispatch_length);			//but it's a char not an unsigned char ?!?! FIXME
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("CHAR %c", *(char *)p);
			break;
		case ARG_TYPE_UCHAR:
			if(type & ARGSPECPOINTER)
			{
				logData((unsigned char *)p, g_next_dispatch_length);
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("UCHAR %c", *(unsigned char *)p);
			break;
		case ARG_TYPE_BOOL:
			if(type & ARGSPECPOINTER)
			{
				if(!g_next_dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					g_next_dispatch_length = 8;
				}
				logPrintf("BOOL[]: ");
				for(i = 0; i < g_next_dispatch_length - 1; i++)
					logPrintf("%s, ", ((*(bool **)p)[i] ? "true" : "false"));
				logPrintf("%s\n", ((*(bool **)p)[i] ? "true" : "false"));
				g_next_dispatch_length = 0;
			}
			else
				logPrintf("BOOL %s\n", (*(bool *)p ? "true" : "false"));
			break;
		case ARG_TYPE_WCHAR:
			if(type & ARGSPECPOINTER)
			{
				logwData((unsigned char *)p, g_next_dispatch_length * 2);			//make sure size is always per type size... 
				g_next_dispatch_length = 0;
			}
			else
				logwPrintf(L"WCHAR %c", *(wchar_t *)p);
			break;
		case ARG_TYPE_STR:
			logPrintf("STR: %s\n", *(char **)p);
			break;
		case ARG_TYPE_WSTR:
			//FIXME FIXME FIXME
			logwPrintf(L"WSTR: %s\n", *(wchar_t **)p);
			break;
		case ARG_TYPE_IP4:
			logPrintf("IP4: %08x\n", *(unsigned long *)p);
			break;
		case ARG_TYPE_IP6:
			logPrintf("IP6?!?!: %08x\n", *(unsigned long *)p);
			break;
		default:
			logPrintf("WARNING: arg dispatch unhandled type\n");
			break;
	}
}

typedef struct tagMODULEENTRY64 {
	DWORD   dwSize;
	DWORD   th32ModuleID;
	DWORD   th32ProcessID;
	DWORD   GlblcntUsage;
	DWORD   ProccntUsage;
	DWORD	ourfriendtheundocumenteddword;
	BYTE    *modBaseAddr;
	DWORD   modBaseSize;
	DWORD	noneotherthanthesame;
	HMODULE hModule;
	TCHAR   szModule[0x160];
	TCHAR   szExePath[0x2c0];
} MODULEENTRY64, *PMODULEENTRY64;

int hook_imports(bool unhook)
{
	HANDLE th32;
#ifdef _WIN64
	MODULEENTRY64 me32;			//...
#else
	MODULEENTRY32W me32;
#endif //_WIN64
	th32 = CreateToolhelp32Snapshot_0(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId_0(GetCurrentProcess_0()));
	if(th32 == INVALID_HANDLE_VALUE)
	{
		logPrintf("ERROR: Toolhelp failed %d\n", GetLastError_0());
		return -1;
	}
#ifdef _WIN64
	me32.dwSize = sizeof(MODULEENTRY32W);
#else
	me32.dwSize = sizeof(MODULEENTRY32W);
#endif //_WIN64
	if(!Module32FirstW_0(th32, (MODULEENTRY32 *)&me32))
	{
		logPrintf("ERROR: Module32First failed: %d\n", GetLastError_0());
		CloseHandle_0(th32);
		return -1;
	}

	do
	{
		logwPrintf(L"\n\n\tMODULE NAME:\t%s", me32.szModule);
		logwPrintf(L"\n\tExecutable:\t\t%s", me32.szExePath);
		logPrintf("\n\tProcess ID:\t%08x", me32.th32ProcessID);
		logPrintf("\n\tRef count (g):\t%04x", me32.GlblcntUsage);
		logPrintf("\n\tRef count (p):\t%04x", me32.ProccntUsage);
#ifdef _WIN64
		logPrintf("\n\tBase address:\t%08x%08x", PRINTARG64(me32.modBaseAddr));
#else
		logPrintf("\n\tBase address:\t%08x", (DWORD)me32.modBaseAddr);
#endif //_WIN64
		logPrintf("\n\tBase size:\t%d\n", me32.modBaseSize);
		/*_tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		_tprintf(TEXT("\n     Executable     = %s"), me32.szExePath);
		_tprintf(TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);
		_tprintf(TEXT("\n     Ref count (g)  = 0x%04X"), me32.GlblcntUsage);
		_tprintf(TEXT("\n     Ref count (p)  = 0x%04X"), me32.ProccntUsage);
		_tprintf(TEXT("\n     Base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
		_tprintf(TEXT("\n     Base size      = %d"), me32.modBaseSize);*/

		hook_import_table((char *)me32.modBaseAddr, me32.modBaseSize, unhook);

	} while(Module32NextW_0(th32, (MODULEENTRY32 *)&me32));

	CloseHandle_0(th32);
	return 0;
}

//#define IMPORTTABLE_DEBUG

int hook_import_table(char * baseaddr, unsigned int size, bool unhook)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_IMPORT_DESCRIPTOR * importdir;
	unsigned int i, j, tablesize, k;
	char * libname;
	char * symbolname;
#ifdef _WIN64
	ULONGLONG * nametable, *addresstable;
#else
	DWORD * nametable, * addresstable;
#endif //_WIN64
	struct hooked_func * hfstruct;
	IMAGE_SECTION_HEADER * import_address_section_hdr;
	DWORD memory_protection = NULL;
	char * origfunc;

#ifdef _WIN64
	IMAGE_NT_HEADERS64 * peheader;
#else
	IMAGE_NT_HEADERS32 * peheader;
#endif //_WIN64

	dosheader = (IMAGE_DOS_HEADER *)baseaddr;
#ifdef _WIN64
	peheader = (IMAGE_NT_HEADERS64 *)(baseaddr + dosheader->e_lfanew);
#else
	peheader = (IMAGE_NT_HEADERS32 *)(baseaddr + dosheader->e_lfanew);
#endif //_WIN64

	if(peheader->Signature != 0x00004550)
	{
		logPrintf("WARNING: bad PE signature!\n");
		return -1;
	}
#ifdef _WIN64
	origfunc = (char *)66;
	if(peheader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		logPrintf("WARNING: bad PE Machine type!\n");
		return -1;
	}
#else
	if(peheader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		logPrintf("WARNING: bad PE Machine type!\n");
		return -1;
	}
#endif //_WIN64

	
	if(!peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{ logPrintf("No imports\n"); return 0; }

	importdir = (IMAGE_IMPORT_DESCRIPTOR *)(baseaddr + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if(!importdir)
		{ logPrintf("No import table\n"); return 0; }
		
	tablesize = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	for(i = 0; i < tablesize; i++)
	{
		if(!importdir[i].Characteristics)	//should be size - 1 anyway
			break;
#ifdef IMPORTTABLE_DEBUG
		logPrintf("*******************\t\t%08x *%08x %08x\n", importdir[i].OriginalFirstThunk, importdir[i].Name, importdir[i].FirstThunk);
#endif //IMPORTTABLE_DEBUG
		libname = baseaddr + importdir[i].Name;
#ifdef IMPORTTABLE_DEBUG
		logPrintf("*******************\t\t%s\n", libname);
#endif //IMPORTTABLE_DEBUG
	
		/* These appear to be backwards from when they're in file? */
#ifdef _WIN64
		addresstable = (ULONGLONG *)(baseaddr + importdir[i].FirstThunk);
		nametable = (ULONGLONG *)(baseaddr + importdir[i].OriginalFirstThunk);
#else
		addresstable = (DWORD *)(baseaddr + importdir[i].FirstThunk);
		nametable = (DWORD *)(baseaddr + importdir[i].OriginalFirstThunk);
#endif //_WIN64
#ifdef _WIN64
		import_address_section_hdr = (IMAGE_SECTION_HEADER *)(peheader->FileHeader.SizeOfOptionalHeader + (char *)peheader + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader));
#else
		import_address_section_hdr = (IMAGE_SECTION_HEADER *)(peheader->FileHeader.SizeOfOptionalHeader + (char *)peheader + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader));	//0x18
#endif //_WIN64	
		for(j = 0; j < peheader->FileHeader.NumberOfSections; j++)
		{
			//FIXME 64
#ifdef _WIN64
			if((char *)addresstable >= (char *)import_address_section_hdr->VirtualAddress + (ULONGLONG)baseaddr && (char *)addresstable < (char *)import_address_section_hdr->VirtualAddress + (ULONGLONG)baseaddr + import_address_section_hdr->SizeOfRawData)
#else
			if((char *)addresstable >= (char *)import_address_section_hdr->VirtualAddress + (DWORD)baseaddr && (char *)addresstable < (char *)import_address_section_hdr->VirtualAddress + (DWORD)baseaddr + import_address_section_hdr->SizeOfRawData)
#endif //_WIN64
				break;
			import_address_section_hdr++;
		}
		if(j == peheader->FileHeader.NumberOfSections)
		{
			logPrintf("ERROR: Couldn't find import address table section header\n");
			return -1;
		}
#ifdef IMPORTTABLE_DEBUG
#ifdef _WIN64
		char * temp;
		temp = baseaddr + import_address_section_hdr->VirtualAddress;
		logPrintf("import table section %08x%08x size %08x\n", PRINTARG64(temp), import_address_section_hdr->SizeOfRawData);
#endif //_WIN64
#endif //IMPORTTABLE_DEBUG
		k = 0;
		for(;;)
		{
			//__debugbreak();
#ifdef _WIN64
			if(*nametable & 0x8000000000000000)
#else
			if(*nametable & 0x80000000)
#endif //_WIN64
			{
				//symbol = import_symbol_lookup(exportingfile, (unsigned char *)(*nametable & 0xffff));
#ifdef IMPORTTABLE_DEBUG
				logPrintf("@%d ->", *nametable & 0xffff);
#endif //IMPORTTABLE_DEBUG
				hfstruct = shouldwehook(libname, *nametable & 0xffff, NULL);
			}
			else
			{
				//logPrintf("%08x -> ", *nametable);
				if(!(*nametable))
					break;
				symbolname = (char *)(baseaddr + *nametable);
#ifdef IMPORTTABLE_DEBUG
				logPrintf("%d %s -> ", *(unsigned short *)symbolname, symbolname + 2);
#endif //IMPORTTABLE_DEBUG
				hfstruct = shouldwehook(libname, *(unsigned short *)symbolname, symbolname + 2);
			}
#ifdef IMPORTTABLE_DEBUG
#ifdef _WIN64
			temp = (char *)*addresstable;
			logPrintf("%08x%08x\n", PRINTARG64(temp));
#else
			logPrintf("%08x\n", *addresstable);
#endif //_WIN64
#endif //IMPORTTABLE_DEBUG
			if(hfstruct)
			{
//#ifdef _WIN64
//#else
				if(!memory_protection)
				{
					if(!VirtualProtect_0(import_address_section_hdr->VirtualAddress + baseaddr, import_address_section_hdr->SizeOfRawData, PAGE_EXECUTE_READWRITE, &memory_protection))
					{
						logPrintf("ERROR: VirtualProtect failed, unable to set memory protection %d\n", GetLastError_0());
						return -1;
					}
				}
				//__debugbreak();
				if(unhook)
				{
					if(!hfstruct->origfunc)
						logPrintf("ERROR: no original function for unhooking\n");
					else
					{
						origfunc = LockHook((char *)addresstable, (char *)hfstruct->origfunc);
						if(origfunc != hfstruct->hook)
							logPrintf("WARNING: something else hooked this function ?!?\n");
					}
				}
				else
					origfunc = LockHook((char *)addresstable, hfstruct->hook);
				if(hfstruct->origfunc && origfunc != (char *)hfstruct->origfunc)
#ifdef _WIN64
					logPrintf("WARNING: Overwriting hook %08x%08x for %s with %08x%08x\n", PRINTARG64(hfstruct->origfunc), hfstruct->origname, PRINTARG64(origfunc));
#else
					logPrintf("WARNING: Overwriting hook %08x for %s with %08x\n", (char *)hfstruct->origfunc, hfstruct->origname, (char *)origfunc);
#endif //_WIN64
				if(unhook)
				{}			// multiple libraries could be hooked with this same hook, so keep the origfunc available
				else
					hfstruct->origfunc = (void(*)(void))origfunc;

//#endif //_WIN64
			}
			
			k++;
			nametable++;
			addresstable++;
		}
	}

	if(memory_protection)
	{
		DWORD temp;
		if(!VirtualProtect_0(import_address_section_hdr->VirtualAddress + baseaddr, import_address_section_hdr->SizeOfRawData, memory_protection, &temp))
		{
			logPrintf("ERROR: VirtualProtect failed, unable to restore memory protection %d\n", GetLastError_0());
			return -1;
		}
	}
	return 0;
}

/* I don't know why I'm using both... I guess if I loaded it from a file, but... no
 * there's still the problem of the name allocation... */
struct hooked_func * shouldwehook(char * libname, unsigned short ordinal, char * funcname)
{
	unsigned int i;
	struct hooked_func * hfstruct;

	hfstruct = (struct hooked_func *)hookspace;
	for(i = 0; i < hooked_funcs; i++)
	{
		if((hfstruct->origlibname[0] == '*' && hfstruct->origlibname[1] == 0x00) || stricmp_0(libname, hfstruct->origlibname) == 0)
		{
			if(funcname && strcmp_0(funcname, hfstruct->origname) == 0)
			{
				return hfstruct;
			}
			else if(!funcname && ordinal == hfstruct->origordinal)
			{
				return hfstruct;
			}
		}
		hfstruct = (struct hooked_func *)(((char *)hfstruct) + totalhooksize);
	}

	return NULL;
}

//造空间
int allocate_hook_space(void)
{
	hookspace_size = 0x10000;
	hookspace = (char *)VirtualAlloc_0(NULL, hookspace_size, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!hookspace)
	{
		logPrintf("ERROR: VirtualAlloc failed %d\n", GetLastError_0());
		return -1;
	}
	hookspace = (char *)VirtualAlloc_0(hookspace, hookspace_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(!hookspace)
	{
		logPrintf("ERROR: VirtualAlloc commit failed %d\n", GetLastError_0());
		return -1;
	}

	hookfuncsize = (char *)&EndHook - (char *)&Hook;
	totalhooksize = sizeof(struct hooked_func) + (unsigned int)hookfuncsize;
	hooked_funcs = 0;

	if(loadxmlhookfile() < 0)
		return -1;
	return 0;
}

void cleanup_hook_space(void)
{
	unsigned int i;
	hook_imports(true);
	for(i = 0; i < hooked_funcs; i++)
		cleanup_hook((struct hooked_func *)(hookspace + (i * totalhooksize)));
	if(hookspace)
		VirtualFree_0(hookspace, hookspace_size, MEM_RELEASE);
	xmlcleanup();
}

struct hooked_func * get_hooked_func_struct(void)
{
	unsigned int i;
	char * hookfunc;
	struct hooked_func * hfstruct;

	if(((hooked_funcs + 1) * totalhooksize) > hookspace_size)
	{
		logPrintf("ERROR: Allocated hook space full!\n");
		return NULL;
	}
	hookfunc = (char *)&Hook;

	hfstruct = (struct hooked_func *)(hookspace + (hooked_funcs * totalhooksize));

	hfstruct->our_number = hooked_funcs;
	hooked_funcs++;
	hfstruct->hook = ((char *)hfstruct) + sizeof(struct hooked_func);		//just tack it on the end... 
	memcpy_0(hfstruct->hook, hookfunc, hookfuncsize);
	for(i = 0; i < hookfuncsize - 4; i++)
	{
		if(memcmp_0(&(hfstruct->hook[i]), (char *)&dispatch_magic, 4) == 0)
		{
			memcpy_0(&(hfstruct->hook[i]), (char *)&(hfstruct->our_number), 4);
			break;
		}
	}

	hfstruct->origfunc = NULL;
	hfstruct->arg = NULL;
	return hfstruct;
}

//造钩
int generate_hook(struct hooked_func * proto_hfstruct)
{
	struct hooked_func * hfstruct;
	unsigned long num;
	hfstruct = get_hooked_func_struct();
	if(hfstruct)
	{
		num = hfstruct->our_number;
		memcpy_0(hfstruct, proto_hfstruct, sizeof(struct hooked_func));
		hfstruct->our_number = num;
	}
	
	return 0;
}

void cleanup_hook(struct hooked_func * hfstruct)
{
	if(hfstruct->origname)
		free_0(hfstruct->origname);
	if(hfstruct->origlibname)
		free_0(hfstruct->origlibname);
	cleanup_arg_spec(hfstruct->arg);
	
}
