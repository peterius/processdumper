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

typedef struct arg_spec
{
	char * arg_name;
	unsigned long offset;
	struct arg_spec * deref_type;			//could use union, but how do we make sure about the mask...
	struct arg_spec * deref_len;
	struct arg_spec * next_spec;
} * argtypep;

#define ARGSPECOFINTERESTMASK			0xe000
#define ARGSPECARRAY					0x1000
#define ARGSPECRETURN_VALUE				0x2000
#define ARGSPECOFPRECALLINTEREST		0x4000
#define ARGSPECOFPOSTCALLINTEREST		0x8000
#define ARGSPECLENRELATED				0x0800
#define ARGSPECTYPEMASK					0x07ff

#ifdef _WIN64
typedef unsigned long long value_t;
typedef long long svalue_t;
#else
typedef unsigned long value_t;
typedef long svalue_t;
#endif //_WIN64

#ifdef _WIN64
#define ARGSPECDEREFMASK		0xffffffffffff0000
#else
#define ARGSPECDEREFMASK		0xffff0000
#endif //_WIN64

typedef value_t argchecktype;

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

#define ARG_TYPE_STRUCT					9
#define ARG_TYPE_STRUCT_ELEMENT			10
//#define ARG_TYPE_LEN					11
#define ARG_TYPE_CHARP					12
#define ARG_TYPE_UCHARP					13
#define ARG_TYPE_WCHARP					14
#define ARG_TYPE_STR					15
#define ARG_TYPE_WSTR					16

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
