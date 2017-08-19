/*  processdumper: console utility for software analysis
 *  Copyright(C) 2017  Peter Bohning
 *  This program is free software : you can redistribute it and / or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 *	GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. */
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

typedef FILE * (* fopenPtr)( const char *filename, const char *mode);
typedef int (* fclosePtr)(FILE *stream);
typedef size_t (* fwritePtr)(const void *buffer, size_t size, size_t count, FILE *stream);
typedef int(*fflushPtr)(FILE *stream);
typedef int (* sprintfPtr)(char *buffer, const char *format, ...);
typedef int (* vsnprintfPtr)(char * s, size_t n, const char * format, va_list arg);
typedef int(*vsnwprintfPtr)(wchar_t * s, size_t n, const wchar_t * format, va_list arg);
typedef int(*snprintfPtr)(char *buffer, size_t count, const char *format, ...);
typedef size_t (* strlenPtr)(const char *str);
typedef size_t(* wcslenPtr)(const wchar_t *str);
typedef size_t (* wcstombsPtr)(char *mbstr, const wchar_t *wcstr, size_t count);
typedef int (* strcmpPtr)(const char *string1, const char *string2);
typedef int (* stricmpPtr)(const char *string1, const char *string2);
typedef void * (*mallocPtr)(size_t n);
typedef void * (*reallocPtr)(void* ptr, size_t size);
typedef void * (*freePtr)(void* ptr);
typedef int (* swscanfPtr)(const wchar_t *buffer, const wchar_t *format, ...);
typedef int (* sscanfPtr)(const char *str, const char * format, ...);

typedef void (WINAPI * InitializeCriticalSectionPtr)(LPCRITICAL_SECTION lpCriticalSection);
typedef void (WINAPI * DeleteCriticalSectionPtr)(LPCRITICAL_SECTION lpCriticalSection);
typedef void (WINAPI * EnterCriticalSectionPtr)(LPCRITICAL_SECTION lpCriticalSection);
typedef void (WINAPI * LeaveCriticalSectionPtr)(LPCRITICAL_SECTION lpCriticalSection);
typedef LPVOID (WINAPI * VirtualAllocPtr)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI * VirtualFreePtr)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef HANDLE(WINAPI * GetCurrentProcessPtr)(void);
typedef DWORD(WINAPI * GetProcessIdPtr)(HANDLE Process);
typedef HANDLE (WINAPI * CreateToolhelp32SnapshotPtr)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL (WINAPI * CloseHandlePtr)(HANDLE hObject);
typedef DWORD (WINAPI * GetLastErrorPtr)(void);
typedef BOOL (WINAPI * Module32FirstWPtr)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL(WINAPI * Module32NextWPtr)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL (WINAPI * VirtualProtectPtr)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
/* Quite frankly, I think we could just loadlibrary the kernel library and link against it, and we'd be good
 * to go... but maybe I don't want an import table or something */
typedef HANDLE(__stdcall * CreateFileWPtr)(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
					DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef DWORD (WINAPI * GetFileSizePtr)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef BOOL (WINAPI * ReadFilePtr)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef DWORD(WINAPI * SetFilePointerPtr)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
typedef int ( * WideCharToMultiBytePtr)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);
typedef VOID (WINAPI * ExitThreadPtr)(DWORD dwExitCode);

extern fopenPtr _fopen;
extern fclosePtr _fclose;
extern fwritePtr _fwrite;
extern fflushPtr _fflush;
extern sprintfPtr _sprintf;
/* Changed function format because there are _func decorated names all over the place... but too lazy to fix old */
extern vsnprintfPtr vsnprintf_0;
extern vsnwprintfPtr vsnwprintf_0;
extern snprintfPtr snprintf_0;
extern strlenPtr strlen_0;
extern wcslenPtr wcslen_0;
extern wcstombsPtr wcstombs_0;
extern strcmpPtr strcmp_0;
extern stricmpPtr stricmp_0;
extern mallocPtr malloc_0;
extern reallocPtr realloc_0;
extern freePtr free_0;
extern swscanfPtr swscanf_0;
extern sscanfPtr sscanf_0;

extern InitializeCriticalSectionPtr InitializeCriticalSection_0;
extern DeleteCriticalSectionPtr DeleteCriticalSection_0;
extern EnterCriticalSectionPtr EnterCriticalSection_0;
extern LeaveCriticalSectionPtr LeaveCriticalSection_0;
extern VirtualAllocPtr VirtualAlloc_0;
extern VirtualFreePtr VirtualFree_0;
extern GetCurrentProcessPtr GetCurrentProcess_0;
extern GetProcessIdPtr GetProcessId_0;
extern CreateToolhelp32SnapshotPtr CreateToolhelp32Snapshot_0;
extern CloseHandlePtr CloseHandle_0;
extern GetLastErrorPtr GetLastError_0;
extern Module32FirstWPtr Module32FirstW_0;
extern Module32NextWPtr Module32NextW_0;
extern VirtualProtectPtr VirtualProtect_0;
extern CreateFileWPtr CreateFileW_0;
extern GetFileSizePtr GetFileSize_0;
extern ReadFilePtr ReadFile_0;
extern SetFilePointerPtr SetFilePointer_0;
extern WideCharToMultiBytePtr WideCharToMultiByte_0;
extern ExitThreadPtr ExitThread_0;

void * memset_0(void *dest, int c, size_t count);
void * memcpy_0(void *dest, const void *src, size_t count);
int memcmp_0(const void * a, const void * b, size_t count);


/* For hooks */
/*typedef HANDLE (* WINAPI CreateFileAPtr)(
	_In_     LPCSTR                lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
);
*/
// CloseHandlePtr


