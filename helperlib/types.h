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

#ifdef _WIN64
typedef unsigned long long value_t;
typedef long long svalue_t;
#else
typedef unsigned long value_t;
typedef long svalue_t;
#endif //_WIN64

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

#define ARG_TYPE_INTERNAL_MSG			44

#ifdef _WIN64
#define SIZE_OF_PTR_TYPE		8
#else
#define SIZE_OF_PTR_TYPE		4
#endif //_WIN64

#define our_size_of(x)		((x == ARG_TYPE_INT8 || x == ARG_TYPE_UINT8) ? 1 : ( \
							(x == ARG_TYPE_INT16 || x == ARG_TYPE_UINT16) ? 2 : ( \
							(x == ARG_TYPE_INT32 || x == ARG_TYPE_UINT32) ? 4 : ( \
							(x == ARG_TYPE_INT64 || x == ARG_TYPE_UINT64) ? 8 : ( \
							(x == ARG_TYPE_PTR) ? SIZE_OF_PTR_TYPE : 1)))))
