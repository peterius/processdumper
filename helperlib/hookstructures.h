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

//base types

#define ARG_TYPE_INT8					0
#define ARG_TYPE_UINT8					1
#define ARG_TYPE_INT16					2
#define ARG_TYPE_UINT16					3	
#define ARG_TYPE_INT32					4
#define ARG_TYPE_UINT32					5
#define ARG_TYPE_INT64					6
#define ARG_TYPE_UINT64					7
#define ARG_TYPE_PTR					8
#define ARG_TYPE_CHAR					9
#define ARG_TYPE_UCHAR					10
#define ARG_TYPE_WCHAR					11


#define ARG_TYPE_STRUCT					12


#define ARG_TYPE_STR					15				//null terminated
#define ARG_TYPE_WSTR					16				//null terminated

#define ARG_TYPE_BOOL					17
#define ARG_TYPE_IP4					18
#define ARG_TYPE_IP6					19


#define NUMBER_UNASSIGNED		0xffffffff
// since we're just dumping it all to file... 

struct hooked_func
{
	void(*origfunc)(void);
	char * origlibname;			//DO NOT FREE OR ALLOCATE
	unsigned int origordinal;
	char * origname;			//DO NOT FREE OR ALLOCATE
	char * hook;
	unsigned long our_number;
	struct arg_spec * arg;
};
