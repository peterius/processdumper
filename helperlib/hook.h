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
#include "hookasm.h"

extern CRITICAL_SECTION critsection;
extern void * curhook_stackpointer;

int allocate_hook_space(void);
void cleanup_hook_space(void);
int hook_imports(bool unhook=false);
int hook_import_table(char * baseaddr, unsigned int size, bool unhook = false);
int hook_export_table(char * baseaddr, unsigned int size, bool unhook = false);
struct hooked_func * get_hooked_func_struct(void);

extern "C"
{
void hookfuncfunc(void * sp, unsigned long functiondispatch);
extern void (WINAPI * LeaveCriticalSection_0)(LPCRITICAL_SECTION lpCriticalSection);
}