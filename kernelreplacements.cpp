//from http://alter.org.ua/docs/nt_kernel/procaddr/#KernelGetProcAddress

#include <Windows.h>
#define WIN9X_SUPPORT

PVOID KernelGetProcAddress(PVOID ModuleBase, PCHAR pFunctionName)
{
	PVOID pFunctionAddress = NULL;

	__try
	{
		ULONG                 size = 0;
#ifndef WIN9X_SUPPORT
		
		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)
			RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

		ULONG                 addr = /*(PUCHAR)*/((ULONG)exports - (ULONG)ModuleBase);
#else
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG)ModuleBase + dos->e_lfanew);

		PIMAGE_DATA_DIRECTORY expdir = (PIMAGE_DATA_DIRECTORY)(nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);
		ULONG                 addr = expdir->VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((ULONG)ModuleBase + addr);
#endif
		PULONG functions = (PULONG)((ULONG)ModuleBase + exports->AddressOfFunctions);
		PSHORT ordinals = (PSHORT)((ULONG)ModuleBase + exports->AddressOfNameOrdinals);
		PULONG names = (PULONG)((ULONG)ModuleBase + exports->AddressOfNames);
		ULONG  max_name = exports->NumberOfNames;
		ULONG  max_func = exports->NumberOfFunctions;

		ULONG i;

		for(i = 0; i < max_name; i++)
		{
			ULONG ord = ordinals[i];
			if(i >= max_name || ord >= max_func) {
				return NULL;
			}
			if(functions[ord] < addr || functions[ord] >= addr + size)
			{
				if(strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
				{
					pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
					break;
				}
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		pFunctionAddress = NULL;
	}

	return pFunctionAddress;
} // end KernelGetProcAddress()