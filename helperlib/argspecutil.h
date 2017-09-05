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
typedef unsigned long argchecktype;

typedef struct arg_spec
{
	char * arg_name;
	char * arg_value;
	unsigned long offset;
	argchecktype type;
	struct arg_spec * deref;			//could use union, but how do we make sure about the mask...
	value_t index;
	value_t size;
	value_t val_val;
	struct arg_spec * deref_len;
	struct arg_spec * next_spec;
} *argtypep;

#define ARGSPECOFINTERESTMASK			0xe000
#define ARGSPECPOINTER					0x0800			//pointer to a basic type
#define ARGSPECARRAY					0x1000
#define ARGSPECRETURN_VALUE				0x2000
#define ARGSPECOFPRECALLINTEREST		0x4000
#define ARGSPECOFPOSTCALLINTEREST		0x8000
#define ARGSPECLENRELATED				0x0400			//save the value for something to reference
#define ARGSPECTYPEMASK					0x03ff

void insert_arg_spec(struct arg_spec * a, struct arg_spec * r, struct arg_spec * q);
struct arg_spec * copy_arg_spec_chain(struct arg_spec * s);
struct arg_spec * deref_end(struct arg_spec * s);
struct arg_spec * get_container_by_deref(struct arg_spec * cont, struct arg_spec * s, struct arg_spec * e);
void cleanup_arg_spec(struct arg_spec * arg_spec);
