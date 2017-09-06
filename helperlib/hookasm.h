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

extern "C"
{
	void Hook(void);
	void EndHook(void);
	char * LockHook(char * loc, char * hookaddr);
#define RETURNTOHERE		1
	void * call_orig_func_as_if(void * sp, void(*origfunc)(void), int ret);
	void cleanup_hooking(void * sp, void * origret, LPCRITICAL_SECTION lpCriticalSection);
}