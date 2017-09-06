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
#include <Windows.h>
#include <Psapi.h>
#include "specialhooks.h"
#include "argspecutil.h"
#include "functionprototypes.h"
#include "hook.h"
#include "logging.h"

GetModuleInformationPtr GetModuleInformation_0;

char * specialhooknames[SPECIALHOOKS] = { "llhook" };
specialhookfuncptr specialhook[SPECIALHOOKS];

void setup_special_hooks(void)
{
	specialhook[0] = &特別の後のLoadLibrary;
}

specialhookfuncptr lookup_special_hook(char * name)
{
	int i;
	if(!name)
		return NULL;
	for(i = 0; i < SPECIALHOOKS; i++)
	{
		if(strcmp_0(name, specialhooknames[i]) == 0)
			return specialhook[i];
	}
	logPrintf("Special hook %s not found\n", name);
	return NULL;
}

/* We won't use the return for now... maybe we never will... FIXME */
void * 特別の後のLoadLibrary(struct arg_spec * arg)
{
	MODULEINFO modinfo;
	char * baseaddr;
	//hook the newly loaded library... after it's loaded

	baseaddr = 0;
	while(arg)
	{
		if(arg->type & ARGSPECRETURN_VALUE)
		{
			baseaddr = (char *)arg->arg_value;
			break;
		}
		arg = arg->next_spec;
	}
	if(!baseaddr)
	{
		logPrintf(utf8("特別の後のLoadLibrary could not find return argument\n"));
		return NULL;
	}
	GetModuleInformation_0(GetCurrentProcess_0(), (HMODULE)baseaddr, &modinfo, sizeof(MODULEINFO));

	if(hook_import_table(baseaddr, modinfo.SizeOfImage) < 0)
	{
		logPrintf("additional library load hook failed\n");
		return NULL;
	}
#ifdef FIXME
	if(hook_export_table(baseaddr, modinfo.SizeOfImage) < 0)
	{	
		logPrintf("additional library load hook failed\n");
		return NULL;
	}
#endif //FIXME
	logPrintf("Additional library loaded and hooked\n");

	return NULL;
}