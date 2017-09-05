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
#pragma once
#include <Windows.h>
#include <intrin.h>
#include "hook.h"
#include "logging.h"
#include "functionprototypes.h"
#include "hookstructures.h"
#include "xmlhookloader.h"
#include "argspecutil.h"
#include "errors.h"

 //#define LOGLIBRARYIMPORTS
 //#define IMPORTTABLE_DEBUG

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

void assign_arg_ref(void * p, argtypep arg);
void dispatch_arg(void * p, argtypep arg, argtypep container, unsigned short pre_post);
int hook_import_table(char * baseaddr, unsigned int size, bool unhook=false);
struct hooked_func * shouldwehook(char * libname, unsigned short ordinal, char * funcname);
int generate_hook(struct hooked_func * proto_hfstruct);
void cleanup_hook(struct hooked_func * hfstruct);

#ifdef _WIN64
#define OUR_SP_ADDITIONS			(4 * 8)
#else
#define OUR_SP_ADDITIONS			(5 * 4)
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

	arg_spec = curhook_hfstruct->arg;
	while(arg_spec)
	{
		logPrintf("arg_spec type %04x %p\n", arg_spec->type, arg_spec->deref);
#ifdef _WIN64
			dispatch_arg((char *)curhook_stackpointer + OUR_SP_ADDITIONS + 8, arg_spec, NULL, ARGSPECOFPRECALLINTEREST);
#else
			dispatch_arg((char *)curhook_stackpointer + OUR_SP_ADDITIONS + 4, arg_spec, NULL, ARGSPECOFPRECALLINTEREST);
#endif //_WIN64
		if(!(arg_spec->type & ARGSPECRETURN_VALUE))			//cheaper to assign the value in case, then check if its used
#ifdef _WIN64
			assign_arg_ref((char *)curhook_stackpointer + OUR_SP_ADDITIONS + 8, arg_spec);
#else
			assign_arg_ref((char *)curhook_stackpointer + OUR_SP_ADDITIONS + 4, arg_spec);
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

	arg_spec = curhook_hfstruct->arg;
	while(arg_spec)
	{
		logPrintf("\t");
		logPrintf("arg_spec type %04x %p\n\t", arg_spec->type, arg_spec->deref);
#ifdef _WIN64
		if(arg_spec->type & ARGSPECRETURN_VALUE)
			dispatch_arg((char *)curhook_stackandretval, arg_spec, NULL, ARGSPECOFPOSTCALLINTEREST);
		else
			dispatch_arg(NULL, arg_spec, NULL, ARGSPECOFPOSTCALLINTEREST);
#else
		if(arg_spec->type & ARGSPECRETURN_VALUE)
			dispatch_arg((char *)curhook_stackandretval, arg_spec, NULL, ARGSPECOFPOSTCALLINTEREST);
		else
			dispatch_arg(NULL, arg_spec, NULL, ARGSPECOFPOSTCALLINTEREST);
#endif //_WIN64
		arg_spec = arg_spec->next_spec;
	}

	LeaveCriticalSection_0(&critsection);
	cleanup_hooking(curhook_stackandretval, curhook_origret);
	//never gets here
}

void assign_arg_ref(void * p, argtypep arg)
{
	arg->arg_value = *((char **)((char *)p + arg->offset));
	logPrintf("Assigning %p\n", arg->arg_value);
}

/* maybe we want a try/catch here for exceptions but... if the process is throwing
 * bad data to apis, we're out anyway and we shouldn't be looking at anything
 * assumed to be uninitialized, or at least not dereferencing it
 * FIXME on the other hand, we want the API to report the exception, not our stuff FIXME */
/* This is terrible, we basically use the "container" just so that we don't loop through the arg level
 * arg specs... and it's like, why not, then I should just put everything in here... test it in here...*/
void dispatch_arg(void * p, argtypep arg, argtypep container, unsigned short pre_post)
{
	unsigned int i;
	void * offset_p;
	value_t dispatch_length;

#ifdef _WIN64
	unsigned long long temp;
#endif //_WIN64

	/* At some point, I probably want to use the ->type type space
	 * to do a lookup where we can store some variable names from the XML FIXME */

	do
	{
		if(p)
			offset_p = (char *)p + arg->offset;
		else
			offset_p = &(arg->arg_value);

		if(arg->deref)
		{
			logPrintf("...p %p deref %p offset %d %04x\n", offset_p, arg->deref, arg->offset, arg->type);
			//p = *(char **)base_p + arg->deref->offset;
			if(arg->deref_len)
			{
				/* FIXME maybe we only want to print these index things if we're printing part of
				 * the struct pre/post call */
				logPrintf("*[%d]:\n", arg->deref_len->val_val);
				while(arg->index < arg->deref_len->val_val)
				{
					logPrintf("\t.%d:\n", arg->index);
					//but something has to deref it? fine if this is from container but... 
					//no, 1 deref, what's the problem ?!?
					logPrintf("will do %p + %d\n", *(char **)offset_p, (arg->index * arg->size));
					dispatch_arg(*(char **)offset_p + (arg->index * arg->size), arg->deref, arg, pre_post);
					arg->index++;
				}
				//reset the index, maybe for postcall
				arg->index = 0;
			}
			else
				dispatch_arg(*(char **)offset_p, arg->deref, arg, pre_post);
		}
		else if(arg->type & pre_post)
		{
		// we don't want to print if there's a deref... why would we... 
			logPrintf("...p %p no deref offset %d %04x\n", offset_p, arg->offset, arg->type);
		__try
		{

	if(arg->type & ARGSPECARRAY)
		logPrintf("WARNING: dispatch array argument unhandled!\n");
	
	if((arg->type & ARGSPECLENRELATED) && arg->arg_name)
		logPrintf("%s:\n", arg->arg_name);
	//final data
	switch(arg->type & ARGSPECTYPEMASK)
	{
		case ARG_TYPE_INT8:
			if(arg->type & ARGSPECLENRELATED)
			{
				/* All we have to do is forget a postcall for a precall in the XML and the deref
				 * here will choke on a length pointer... FIXME */
				if(arg->type & ARGSPECPOINTER)
					arg->val_val = (value_t)**(char **)offset_p;
				else
					arg->val_val = (value_t)*(char *)offset_p;
			}
			else if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					/* FIXME we should have it just not put 0s on the stack or put an error if the stack is empty FIXME */
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("INT8[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%d, ", (*(char **)offset_p)[i]);
				logPrintf("%d\n", (*(char **)offset_p)[i]);
			}
			else
				logPrintf("INT8: %d\n", *(char *)offset_p);
			break;
		case ARG_TYPE_UINT8:
			if(arg->type & ARGSPECLENRELATED)
			{
				if(arg->type & ARGSPECPOINTER)
					arg->val_val = (value_t)**(unsigned char **)offset_p;
				else
					arg->val_val = (value_t)*(unsigned char *)offset_p;
			}
			else if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("UINT8[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%u, ", (*(unsigned char **)offset_p)[i]);
				logPrintf("%u\n", (*(unsigned char **)offset_p)[i]);
			}
			else
				logPrintf("UINT8: %u\n", *(unsigned char *)offset_p);
			break;
		case ARG_TYPE_INT16:
			if(arg->type & ARGSPECLENRELATED)
			{
				if(arg->type & ARGSPECPOINTER)
					arg->val_val = (value_t)**(short **)offset_p;
				else
					arg->val_val = (value_t)*(short *)offset_p;
			}
			else if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("SHORT[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%d, ", (*(short **)offset_p)[i]);
				logPrintf("%d\n", (*(short **)offset_p)[i]);
			}
			else
				logPrintf("SHORT: %d\n", *(short *)offset_p);
			break;
		case ARG_TYPE_UINT16:
			if(arg->type & ARGSPECLENRELATED)
			{
				if(arg->type & ARGSPECPOINTER)
					arg->val_val = (value_t)**(unsigned short **)offset_p;
				else
					arg->val_val = (value_t)*(unsigned short *)offset_p;
			}
			else if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("USHORT[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%u, ", (*(unsigned short **)offset_p)[i]);
				logPrintf("%u\n", (*(unsigned short **)offset_p)[i]);
			}
			else
				logPrintf("USHORT: %u\n", *(unsigned short *)offset_p);
			break;
		case ARG_TYPE_INT32:
			if(arg->type & ARGSPECLENRELATED)
			{
				if(arg->type & ARGSPECPOINTER)
					arg->val_val = (value_t)**(long**)offset_p;
				else
					arg->val_val = (value_t)*(long *)offset_p;
			}
			else if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("LONG[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%d, ", (*(long **)offset_p)[i]);
				logPrintf("%d\n", (*(long **)offset_p)[i]);
			}
			else
				logPrintf("LONG: %d\n", *(long *)offset_p);
			break;
		case ARG_TYPE_UINT32:
			if(arg->type & ARGSPECLENRELATED)
			{
				if(arg->type & ARGSPECPOINTER)
					arg->val_val = (value_t)**(unsigned long**)offset_p;
				else
					arg->val_val = (value_t)*(unsigned long *)offset_p;
			}
			else if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("ULONG[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%u, ", (*(unsigned long **)offset_p)[i]);
				logPrintf("%u\n", (*(unsigned long **)offset_p)[i]);
			}
			else
				logPrintf("ULONG: %u\n", *(unsigned long *)offset_p);
			break;
#ifdef _WIN64
		//FIXME This probably doesn't work and won't be used anyway...:
		case ARG_TYPE_UINT64:
			if(arg->type & ARGSPECLENRELATED)
			{
				if(arg->type & ARGSPECPOINTER)
					arg->val_val = (value_t)**(unsigned long long**)offset_p;
				else
					arg->val_val = (value_t)*(unsigned long long *)offset_p;
			}
			else if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("ULONGLONG[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%u, ", (*(unsigned long long **)offset_p)[i]);
				logPrintf("%u\n", (*(unsigned long long **)offset_p)[i]);
			}
			else
				logPrintf("ULONGLONG: %u\n", *(unsigned long long *)offset_p);
			break;
#endif //_WIN64
		case ARG_TYPE_PTR:
			if(arg->type & ARGSPECLENRELATED)
				logPrintf("WARNING: length related pointer to pointer ?!?\n");
#ifdef _WIN64
			if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("PTR[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
				{
					temp = (*(unsigned long long **)offset_p)[i];
					logPrintf("%08x%08x, ", PRINTARG64(temp));
				}
				temp = (*(unsigned long long **)offset_p)[i];
				logPrintf("%08x%08x\n", PRINTARG64(temp));
			}
			else
			{
				temp = *(unsigned long long *)offset_p;
				logPrintf("PTR: %08x%08x\n", PRINTARG64(temp));
			}
#else
			if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("PTR[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%08x, ", (*(unsigned long **)offset_p)[i]);
				logPrintf("%08x\n", (*(unsigned long **)offset_p)[i]);
			}
			else
				logPrintf("PTR: %08x\n", *(unsigned long *)offset_p);
#endif //_WIN64
			break;
		case ARG_TYPE_CHAR:
			if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch pointer argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logData(*(unsigned char **)offset_p, dispatch_length);			//but it's a char not an unsigned char ?!?! FIXME
			}
			else
				logPrintf("CHAR %c", *(char *)offset_p);
			break;
		case ARG_TYPE_UCHAR:
			if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				logPrintf("dispatch length %d %p %p\n", dispatch_length, offset_p, (offset_p ? (*(unsigned char **)offset_p) : (unsigned char *)-1));
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch pointer argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logData(*(unsigned char **)offset_p, dispatch_length);
			}
			else
				logPrintf("UCHAR %c", *(unsigned char *)offset_p);
			break;
		case ARG_TYPE_BOOL:
			if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n"); 
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len > (struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch array argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logPrintf("BOOL[]: ");
				for(i = 0; i < dispatch_length - 1; i++)
					logPrintf("%s, ", ((*(bool **)offset_p)[i] ? "true" : "false"));
				logPrintf("%s\n", ((*(bool **)offset_p)[i] ? "true" : "false"));
			}
			else
				logPrintf("BOOL %s\n", (*(bool *)offset_p ? "true" : "false"));
			break;
		case ARG_TYPE_WCHAR:
			if(arg->type & ARGSPECPOINTER && !(*(char **)offset_p))
				logPrintf("NULL\n");
			else if(arg->type & ARGSPECPOINTER)
			{
				if(arg->deref_len >(struct arg_spec *)0x10000)
					dispatch_length = arg->deref_len->val_val;
				else
					dispatch_length = (value_t)arg->deref_len;
				if(!dispatch_length)
				{
					logPrintf("WARNING: dispatch pointer argument with no preceeding length, trying 8!\n");
					dispatch_length = 8;
				}
				logwData(*(unsigned char **)offset_p, dispatch_length * 2);			//make sure size is always per arg->type size... 
			}
			else
				logwPrintf(L"WCHAR %c", *(wchar_t *)offset_p);
			break;
		case ARG_TYPE_STR:
			logPrintf("STR: %s\n", *(char **)offset_p);
			break;
		case ARG_TYPE_WSTR:
			//FIXME FIXME FIXME
			logwPrintf(L"WSTR: %s\n", *(wchar_t **)offset_p);
			break;
		case ARG_TYPE_IP4:
			logPrintf("IP4: %d.%d.%d.%d\n", ((unsigned char *)offset_p)[0], ((unsigned char *)offset_p + 1)[0], ((unsigned char *)offset_p + 2)[0], ((unsigned char *)offset_p + 3)[0]);
			break;
		case ARG_TYPE_IP6:
			logPrintf("IP6?!?!: %08x\n", *(unsigned long *)offset_p);
			break;
		case ARG_TYPE_STRUCT:
			/* FIXME This is silly, we shouldn't have dereferenced the pointers if we
			 * aren't really accessing elements of the structures, but it's an xml loader
			 * problem, i.e., when we dereference pointers passed as leaf elements */
			logPrintf("struct *: %p\n", offset_p);
			break;
		default:
			logPrintf("WARNING: arg dispatch unhandled type\n");
			break;
	}
	}
	__except(EXCEPTION_ACCESS_VIOLATION)
	{
		logPrintf("EXCEPTION\n");
	}
	}
	}
	while(container && (arg = arg->next_spec));
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

#define UNHOOK_IMPORTS					true
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
		return CREATETOOLHELP_FAILED;
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
		return MODULEFIRST_FAILED;
	}

	do
	{
#ifdef LOGLIBRARYIMPORTS
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
#endif //LOGLIBRARYIMPORTS

		// FIXME ignore errors here ?!?
		hook_import_table((char *)me32.modBaseAddr, me32.modBaseSize, unhook);

	} while(Module32NextW_0(th32, (MODULEENTRY32 *)&me32));

	CloseHandle_0(th32);
	return 0;
}

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
	{
#ifdef LOGLIBRARYIMPORTS
		logPrintf("No imports\n");
#endif //LOGLIBRARYIMPORTS	
		return 0;
	}

	importdir = (IMAGE_IMPORT_DESCRIPTOR *)(baseaddr + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if(!importdir)
	{
#ifdef LOGLIBRARYIMPORTS
		logPrintf("No import table\n");
#endif //LOGLIBRARYIMPORTS
		return 0;
	}
		
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
					/* FIXME FIXME FIXME  if a library is loaded later, it might not be hooked, but possibly we picked it up
					 * as a dependency library, it just wasn't currently in memory, so we couldn't hook it's further imports... */
					if(!hfstruct->origfunc)
						logPrintf("ERROR: no original function for unhooking\n");
					else if(*(char **)addresstable == (char *)hfstruct->origfunc)
					{}			
					else
					{
						origfunc = LockHook((char *)addresstable, (char *)hfstruct->origfunc);
						if(origfunc != hfstruct->hook)
							logPrintf("WARNING: something else hooked this function %p ?!?\n", origfunc);
					}
				}
				else
					origfunc = LockHook((char *)addresstable, hfstruct->hook);
				if(!unhook && hfstruct->origfunc && origfunc != (char *)hfstruct->origfunc)
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
		return VIRTUALALLOC_FAILED;
	}
	hookspace = (char *)VirtualAlloc_0(hookspace, hookspace_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(!hookspace)
	{
		logPrintf("ERROR: VirtualAlloc commit failed %d\n", GetLastError_0());
		return VIRTUALALLOC_FAILED;
	}

	hookfuncsize = (char *)&EndHook - (char *)&Hook;
	totalhooksize = sizeof(struct hooked_func) + (unsigned int)hookfuncsize;
	hooked_funcs = 0;

	if(loadxmlhookfile() < 0)
		return XMLLOAD_FAILED;

	return 0;
}

void cleanup_hook_space(void)
{
	unsigned int i;
	hook_imports(UNHOOK_IMPORTS);
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
