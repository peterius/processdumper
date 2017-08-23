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
#include "helperlib.h"
#include "functionprototypes.h"
#include "xmlhookloader.h"
#include "hook.h"
#include "logging.h"
#include "hookstructures.h"
#include "argspecutil.h"

mallocPtr malloc_0;
reallocPtr realloc_0;
freePtr free_0;
CreateFileWPtr CreateFileW_0;
GetFileSizePtr GetFileSize_0;
ReadFilePtr ReadFile_0;
SetFilePointerPtr SetFilePointer_0;
swscanfPtr swscanf_0;
sscanfPtr sscanf_0;
wcstombsPtr wcstombs_0;
WideCharToMultiBytePtr WideCharToMultiByte_0;

#define ISNUMBER(x)				(((x >= '0' && x <= '9') || (x == '-'))? 1 : 0)

struct type_def
{
	char * name;
	unsigned short basetype;
	unsigned short offset;
	struct type_def * offset_relative_to;
	struct type_def * basetype_ref;
	struct scope * scope;
};

struct value
{
	char * name;
	value_t val;
};

struct scope
{
	char * name;
	enum _defines
	{
		global_or_unknown = 0,
		library,
		function,
		type,
		type_closed
	} defines;
	struct type_def ** type_definition;
	unsigned int type_definitions;
	struct value * value;
	unsigned int values;
};

struct scope ** scope_stack;
unsigned long scope_stack_size;

#define CURRENT_SCOPE					scope_stack[scope_stack_size - 1]

struct scope ** scope_list;
unsigned long scopes;

enum s_bool
{
	fase = 0,
	tru = 1,
	unspecified
};

void create_basic_types(void);
void enter_scope(struct scope * scope);
void leave_scope(void);
struct scope * get_add_scope(char * libn);
struct scope * add_scope(void);
void cleanup_scope(struct scope * scope);
struct type_def * lookup_type(char * name, bool cur_scope);
struct type_def *  add_type(char * name, char * basetypename, bool isptr, bool lookupoffset);
unsigned int size_of_struct(struct type_def * s);
unsigned int size_of_type(struct type_def * t);
unsigned short calculate_offset(void);
struct value * lookup_value(char * name);
void add_value_by_name(char * name, char * value);
void add_value(char * name, value_t value);
void add_signed_value(char * name, svalue_t value);
void fixup_function_lengths(struct hooked_func * hfstruct);
int parse(char * data, unsigned int size);
void xmldebugPrint(char * d, int s);
void whitespace(char ** d);
int wstrncmp(char * a, char * b, int n);
int wstrcmp(char * a, char * b);
int countto(char * d, char w);
char * get_quoted_value(char ** d);
value_t get_quoted_numeric_value(char ** d, bool * neg);
s_bool get_quoted_boolean(char ** d);

char * g_xmlfile_buffer;
char * base_type_names[] = { "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t", "void *", "char", "unsigned char", "wchar_t" };

char len_type[] = "size_t";			//is this appropriate, I just want to use it to signal buffer lengths... FIXME
char bool_type[] = "bool";
char ip4_type[] = "ip4_t";
char ip6_type[] = "ip6_t";
char struct_type[] = "struct";
char struct_type_element[] = "element";
char wild_lib[] = "*";

void create_basic_types(void)
{
	int i;

	//global scope
	scopes = 1;
	scope_list = (struct scope **)malloc_0(sizeof(struct scope *));
	scope_list[0] = (struct scope *)malloc_0(sizeof(struct scope));
	scope_stack_size = 1;
	scope_stack = (struct scope **)malloc_0(sizeof(struct scope *));
	scope_stack[0] = scope_list[0];

	scope_list[0]->name = NULL;
	scope_list[0]->defines = scope::global_or_unknown;
	scope_list[0]->type_definitions = 19;
	scope_list[0]->type_definition = (struct type_def **)malloc_0(scope_list[0]->type_definitions * sizeof(struct type_def *));

	for(i = 0; i < 12; i++)
	{
		scope_list[0]->type_definition[i] = (struct type_def *)malloc_0(sizeof(struct type_def));
		scope_list[0]->type_definition[i]->name = base_type_names[i];
		scope_list[0]->type_definition[i]->basetype = i;
		scope_list[0]->type_definition[i]->basetype_ref = NULL;
		scope_list[0]->type_definition[i]->scope = NULL;
		scope_list[0]->type_definition[i]->offset = 0;
		scope_list[0]->type_definition[i]->offset_relative_to = NULL;
	}
	scope_list[0]->type_definition[i] = NULL;
	i++;
	scope_list[0]->type_definition[i] = (struct type_def *)malloc_0(sizeof(struct type_def));
	scope_list[0]->type_definition[i]->name = struct_type;
	scope_list[0]->type_definition[i]->basetype = ARG_TYPE_STRUCT;
	scope_list[0]->type_definition[i]->basetype_ref = NULL;
	scope_list[0]->type_definition[i]->scope = NULL;
	scope_list[0]->type_definition[i]->offset = 0;
	scope_list[0]->type_definition[i]->offset_relative_to = NULL;
	i++;
	// what is this struct_element for again ?!?! 
	scope_list[0]->type_definition[i] = NULL;
	/*scope_list[0]->type_definition[10] = (struct type_def *)malloc_0(sizeof(struct type_def));
	scope_list[0]->type_definition[10]->name = struct_type_element;
	scope_list[0]->type_definition[10]->basetype = ARG_TYPE_STRUCT_ELEMENT;
	scope_list[0]->type_definition[10]->basetype_ref = NULL;
	scope_list[0]->type_definition[10]->scope = NULL;
	scope_list[0]->type_definition[10]->offset = 0;
	scope_list[0]->type_definition[10]->offset_relative_to = NULL;*/
	i++;
	scope_list[0]->type_definition[i] = NULL;
	/*scope_list[0]->type_definition[11] = (struct type_def *)malloc_0(sizeof(struct type_def));
	scope_list[0]->type_definition[11]->name = len_type;
	scope_list[0]->type_definition[11]->basetype = ARG_TYPE_LEN;
	scope_list[0]->type_definition[11]->basetype_ref = scope_list[0]->type_definition[ARG_TYPE_UINT32];
	scope_list[0]->type_definition[11]->scope = NULL;
	scope_list[0]->type_definition[11]->offset = 0;
	scope_list[0]->type_definition[11]->offset_relative_to = NULL;*/
	i++;
	scope_list[0]->type_definition[i] = (struct type_def *)malloc_0(sizeof(struct type_def));
	scope_list[0]->type_definition[i]->name = bool_type;
	scope_list[0]->type_definition[i]->basetype = ARG_TYPE_BOOL;
	scope_list[0]->type_definition[i]->basetype_ref = scope_list[0]->type_definition[ARG_TYPE_UINT8];			//double check FIXME FIXME FIXME
	scope_list[0]->type_definition[i]->scope = NULL;
	scope_list[0]->type_definition[i]->offset = 0;
	scope_list[0]->type_definition[i]->offset_relative_to = NULL;
	i++;
	scope_list[0]->type_definition[i] = (struct type_def *)malloc_0(sizeof(struct type_def));
	scope_list[0]->type_definition[i]->name = ip4_type;
	scope_list[0]->type_definition[i]->basetype = ARG_TYPE_IP4;
	scope_list[0]->type_definition[i]->basetype_ref = scope_list[0]->type_definition[ARG_TYPE_UINT32];
	scope_list[0]->type_definition[i]->scope = NULL;
	scope_list[0]->type_definition[i]->offset = 0;
	scope_list[0]->type_definition[i]->offset_relative_to = NULL;
	i++;
	/* FIXME FIXME FIXME IP6 */
	scope_list[0]->type_definition[i] = (struct type_def *)malloc_0(sizeof(struct type_def));
	scope_list[0]->type_definition[i]->name = ip6_type;
	scope_list[0]->type_definition[i]->basetype = ARG_TYPE_IP6;
	scope_list[0]->type_definition[i]->basetype_ref = scope_list[0]->type_definition[ARG_TYPE_UINT32];
	scope_list[0]->type_definition[i]->scope = NULL;
	scope_list[0]->type_definition[i]->offset = 0;
	scope_list[0]->type_definition[i]->offset_relative_to = NULL;
	//what about like... true and false ?? FIXME FIXME FIXME
	scope_list[0]->values = 0;
	scope_list[0]->value = NULL;
}

void enter_scope(struct scope * scope)
{
	if(!scope)
	{
		logPrintf("XML parse ERROR: attempting to enter NULL scope\n");
		return;
	}
	scope_stack_size++;
	scope_stack = (struct scope **)realloc_0(scope_stack, sizeof(struct scope *) * scope_stack_size);
	if(!scope_stack)
	{
		logPrintf("XML parse ERROR: enter scope realloc failure\n");
		return;
	}
	logPrintf("Entering scope %p with %d %d\n", scope, scope->type_definitions, scope->values);
	scope_stack[scope_stack_size - 1] = scope;
}

void leave_scope(void)
{
	if(scope_stack_size == 0)
	{
		logPrintf("XML parse error: attempt to leave global scope!\n");
		return;
	}
	scope_stack_size--;
	scope_stack = (struct scope **)realloc_0(scope_stack, sizeof(struct scope *) * scope_stack_size);
	if(!scope_stack)
	{
		logPrintf("XML parse ERROR: leave scope realloc failure\n");
		return;
	}
}

// only for library scopes
struct scope * get_add_scope(char * libn)
{
	unsigned int i;
	struct scope * scope;
	for(i = 0; i < scopes; i++)
	{
		if(scope_list[i]->name && strcmp_0(libn, scope_list[i]->name) == 0)
			return scope_list[i];
	}
	scope = add_scope();
	scope->name = libn;			//should be safe, this is the free point
	return scope;
}

struct scope * add_scope(void)
{
	scopes++;
	scope_list = (struct scope **)realloc_0(scope_list, sizeof(struct scope *) * scopes);
	if(!scope_list)
	{
		logPrintf("XML parse ERROR: enter scope realloc failure\n");
		return NULL;
	}
	scope_list[scopes - 1] = (struct scope *)malloc_0(sizeof(struct scope));
	char * m = (char *)scope_list[scopes - 1];
	for(unsigned int i = 0; i < sizeof(struct scope); i++)
		m[i] = 0x00;
	return (struct scope *)m;
}

void cleanup_scope(struct scope * scope)
{
	unsigned int i;
	if(scope->name)
		free_0(scope->name);
	for(i = 0; i < scope->type_definitions; i++)
	{
		if(scope->type_definition[i])
		{
			if(scope->type_definition[i]->name)
				free_0(scope->type_definition[i]->name);
		}
		free_0(scope->type_definition[i]);
	}
	free_0(scope->type_definition);
	for(i = 0; i < scope->values; i++)
	{
		if(scope->value[i].name)
			free_0(scope->value[i].name);
	}
	free_0(scope->value);
	free_0(scope);
}

#define CURRENT_SCOPE_ONLY					true
struct type_def * lookup_type(char * name, bool cur_scope=false)
{
	unsigned int scope_check_index = scope_stack_size - 1;
	unsigned int i;
	logPrintf("lookuptype %s\n", name);
	for(;;)
	{
		for(i = 0; i < scope_stack[scope_check_index]->type_definitions; i++)
		{
			if(!scope_stack[scope_check_index]->type_definition[i])
				continue;
			logPrintf("\t\t%s\n", scope_stack[scope_check_index]->type_definition[i]->name);
			if(scope_stack[scope_check_index]->type_definition[i]->name && wstrcmp(name, scope_stack[scope_check_index]->type_definition[i]->name) == 0)
			{
				return scope_stack[scope_check_index]->type_definition[i];
			}
		}
		if(cur_scope)
			break;
		if(scope_check_index == 0)
			break;
		scope_check_index--;
	}
	return NULL;
}

/* What about duplicate entries, arrays, structures... ?!? FIXME */
struct type_def * add_type(char * name, char * basetypename, bool isptr, bool lookupoffset)
{
	unsigned int scope_check_index = scope_stack_size - 1;
	struct type_def * type_def;
	struct type_def * looked_up_type_def = lookup_type(basetypename);

	if(lookup_type(name, CURRENT_SCOPE_ONLY))
		logPrintf("XML parse warning: duplicate type %s !\n", name);

	if(looked_up_type_def)
	{
		if(CURRENT_SCOPE->type_definitions == 0)
		{
			CURRENT_SCOPE->type_definitions = 1;
			CURRENT_SCOPE->type_definition = (struct type_def **)malloc_0(sizeof(struct type_def *));
		}
		else
		{
			CURRENT_SCOPE->type_definitions++;
			CURRENT_SCOPE->type_definition = (struct type_def **)realloc_0(CURRENT_SCOPE->type_definition, CURRENT_SCOPE->type_definitions * sizeof(struct type_def *));
		}
		type_def = (struct type_def *)malloc_0(sizeof(struct type_def));
		CURRENT_SCOPE->type_definition[CURRENT_SCOPE->type_definitions - 1] = type_def;
		type_def->name = name;
		if(lookupoffset)
		{
			type_def->offset = calculate_offset();
			type_def->offset_relative_to = scope_stack[scope_stack_size - 2]->type_definition[scope_stack[scope_stack_size - 2]->type_definitions - 1];
		}
		else
		{
			type_def->offset = 0;
			type_def->offset_relative_to = NULL;
		}
		if(isptr)
		{
			type_def->basetype = ARG_TYPE_PTR;
			type_def->basetype_ref = looked_up_type_def;
			logPrintf("adding pointer to %d\n", type_def->basetype_ref->basetype);
		}
		// not going to worry about arrays in nested structure types for now because of the sizes FIXME
		// FIXME basically we need a special basetype for PTR and ARRAY... 
		else
		{
			type_def->basetype = looked_up_type_def->basetype;
			type_def->basetype_ref = NULL;
		}
		logPrintf("Adding %s with offset %d\n", type_def->name, type_def->offset);
		return type_def;
	}
	return NULL;
}

unsigned int size_of_struct(struct type_def * s)
{
	struct scope * scope = s->scope;
	struct type_def * last_element;
	unsigned int i;

	if(scope->type_definitions == 0)
		return 0;
	i = scope->type_definitions - 1;
	do
	{
		last_element = scope->type_definition[i];
		i--;
	}
	while(!last_element->offset_relative_to && i);
	if(last_element->offset_relative_to)		//part of structure
		return last_element->offset + size_of_type(last_element);
	return 0;
}

unsigned int size_of_type(struct type_def * t)
{
	if(t->basetype == ARG_TYPE_PTR)
#ifdef _WIN64
		return 8;
#else
		return 4;
#endif //_WIN64

	if(t->basetype_ref)
		return size_of_type(t->basetype_ref);

	switch(t->basetype)
	{
		case ARG_TYPE_UINT8:
		case ARG_TYPE_INT8:
		case ARG_TYPE_CHAR:
		case ARG_TYPE_UCHAR:
			return 1;
			break;
		case ARG_TYPE_UINT16:
		case ARG_TYPE_INT16:
		case ARG_TYPE_WCHAR:
			return 2;
			break;
		case ARG_TYPE_UINT32:
		case ARG_TYPE_INT32:
			return 4;
			break;
		case ARG_TYPE_UINT64:
		case ARG_TYPE_INT64:
			return 8;
			break;
		case ARG_TYPE_STRUCT:
			return size_of_struct(t);
			break;
		default:
			logPrintf("XML parse error: couldn't calculate offset for element\n");
			return 0;
	}
	//...
}

//this is just per scope
unsigned short calculate_offset(void)
{
	struct type_def * previous_type;
	//must be current scope
	if(CURRENT_SCOPE->type_definitions == 1)	//no previous element
		return 0;
	previous_type = CURRENT_SCOPE->type_definition[CURRENT_SCOPE->type_definitions - 2];
	return previous_type->offset + size_of_type(previous_type);
}

struct value * lookup_value(char * name)
{
	unsigned int scope_check_index = scope_stack_size - 1;
	unsigned int i;

	for(;;)
	{
		for(i = 0; i < scope_stack[scope_check_index]->values; i++)
		{
			if(wstrcmp(name, scope_stack[scope_check_index]->value[i].name) == 0)
			{
				return &(scope_stack[scope_check_index]->value[i]);
			}
		}
		if(scope_check_index == 0)
			break;
		scope_check_index--;
	}
	logPrintf("XML parse error: can't resolve value name %s\n", name);
	return NULL;
}

void add_value_by_name(char * name, char * value)
{
	struct value * val = lookup_value(value);
	if(val)
		add_value(name, val->val);
}

void add_value(char * name, value_t value)
{
	if(CURRENT_SCOPE->values == 0)
	{
		CURRENT_SCOPE->values = 1;
		CURRENT_SCOPE->value = (struct value *)malloc_0(sizeof(struct value));
	}
	else
	{
		CURRENT_SCOPE->values++;
		CURRENT_SCOPE->value = (struct value *)realloc_0(CURRENT_SCOPE->value, CURRENT_SCOPE->values * sizeof(struct value));
	}
	CURRENT_SCOPE->value[CURRENT_SCOPE->values - 1].name = name;
	CURRENT_SCOPE->value[CURRENT_SCOPE->values - 1].val = value;
}

void add_signed_value(char * name, svalue_t value)
{
	if(CURRENT_SCOPE->values == 0)
	{
		CURRENT_SCOPE->values = 1;
		CURRENT_SCOPE->value = (struct value *)malloc_0(sizeof(struct value));
	}
	else
	{
		CURRENT_SCOPE->values++;
		CURRENT_SCOPE->value = (struct value *)realloc_0(CURRENT_SCOPE->value, CURRENT_SCOPE->values * sizeof(struct value));
	}
	CURRENT_SCOPE->value[CURRENT_SCOPE->values - 1].name = name;
	CURRENT_SCOPE->value[CURRENT_SCOPE->values - 1].val = (value_t)value;
}

void fixup_function_lengths(struct hooked_func * hfstruct)
{
	struct arg_spec * i, * j;
	
ffl_onemoretime:
	i = hfstruct->arg;
	while(i)
	{
		logPrintf("i %p %p\n", i, i->next_spec);
		if(i->deref_len)
		{
			j = hfstruct->arg;
			while(j)
			{
				if(j->arg_name && (j->arg_name, (char *)i->deref_len) == 0)
				{
					insert_arg_spec(hfstruct->arg, i, j);
					j->type |= ARGSPECLENRELATED;
					free_0(i->deref_len);
					i->deref_len = NULL;
					goto ffl_onemoretime;
				}
				j = j->next_spec;
			}
		}
		i = i->next_spec;
	}
}

int loadxmlhookfile(void)
{
	HANDLE xmlhookFile;
	unsigned int size;
	DWORD bytes_read;

	if(functionstohookfile[0] == 0x00)
	{
		logPrintf("No functions to hook xml file specified\n");
		return -1;
	}
	
	xmlhookFile = CreateFileW_0(functionstohookfile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(xmlhookFile == INVALID_HANDLE_VALUE)
	{
		logPrintf("Can't open functions to hook xml file %s: %d\n", functionstohookfile, GetLastError_0());
		return -1;
	}
	else if(!xmlhookFile)
	{
		logPrintf("Can't open functions to hook xml file %s: %d\n", functionstohookfile, GetLastError_0());
		return -1;
	}
	
	size = GetFileSize_0(xmlhookFile, NULL);

	g_xmlfile_buffer = (char *)malloc_0(size);
	if(!g_xmlfile_buffer)
	{
		logPrintf("ERROR: Can't allocate read file buffer\n");
		return -1;
	}
	if(!ReadFile_0(xmlhookFile, g_xmlfile_buffer, size, &bytes_read, NULL))
	{
		logPrintf("ERROR: Read failed %d\n", GetLastError_0());
		CloseHandle_0(xmlhookFile);
		return -1;
	}

	CloseHandle_0(xmlhookFile);

	create_basic_types();

	if(parse(g_xmlfile_buffer, size) < 0)
		return -1;

	return 0;
}

void xmlcleanup(void)
{
	unsigned int i;

	// what about arg_specs and type name lookups ?!?!? FIXME FIXME FIXME

	for(i = 0; i < scopes; i++)
		cleanup_scope(scope_list[i]);
	free_0(scope_stack);
	free_0(scope_list);
	// and type name lookups strings... 
	free_0(g_xmlfile_buffer);
}

/* Should probably check for duplicate attribute assignments so as not to leak everywhere but
 * I guess I don't care.  FIXME */
int parse(char * data, unsigned int size)
{
	char * d;
	char * end;
	int i;
	int depth = 0;
	char * inlibname;
	char * functionname;
	char * valuename;
	char * valuevalue;
	char * typevalue;
	char * typenamestr;
	char * typebasetype;
	char * argname;
	char * argtype;
	char * argsize;
	unsigned long functionargument_index;
#ifdef _WIN64
#define ARGUMENT_SIZE		8
#else
#define ARGUMENT_SIZE		4
#endif //_WIN64
	char * libn;
	int l;
	unsigned int ordinal;
	bool neg;
	bool is_an_element;
	bool is_return_value;
	s_bool log, precall, postcall, stacktrace;
	struct hooked_func * hfstruct;
	struct type_def * t;
	struct arg_spec * arg_spec;
	struct arg_spec * proto, * proto_end;
	argchecktype a;

	value_t numericvalue;
	svalue_t negvalue;

	inlibname = NULL;
	functionname = NULL;
	valuename = NULL;
	valuevalue = NULL;
	typevalue = NULL;
	typenamestr = NULL;
	typebasetype = NULL;
	hfstruct = NULL;
	argname = NULL;
	argtype = NULL;
	argsize = NULL;
	arg_spec = NULL;
	proto = NULL;
	proto_end = NULL;
	
	d = data;
	end = d + size;

	is_return_value = false;

	while(d < end)
	{
		xmldebugPrint(d, 10);
		if(*d == '<')
		{
			d++;
			whitespace(&d);
			if(wstrncmp(d, "!--", 3) == 0)
			{
				while((*d != '-' || *(d + 1) != '-' || *(d + 2) != '>') && d < end - 2)
					d++;
				if(d >= end - 2)
				{
					logPrintf("XML parse error: unmatched comment\n");
					return -1;
				}
				d += 3;
			}
			else if(*d == '/')
			{
				if(depth == 0)
				{
					logPrintf("XML parse error: unpaired end tag\n");
					return -1;
				}
				d++;
				if(wstrncmp(d, "lib", 3) == 0)
				{
					if(CURRENT_SCOPE->defines != scope::library)
					{
						logPrintf("XML parse error: unpaired library scope\n");
						return -1;
					}
					leave_scope();
					inlibname = NULL;
				}
				else if(wstrncmp(d, "function", 8) == 0)
				{
					fixup_function_lengths(hfstruct);
					leave_scope();
					logPrintf("hfstruct arg %p\n", hfstruct->arg);
					hfstruct = NULL;
					functionname = NULL;
					arg_spec = NULL;
				}
				else if(wstrncmp(d, "type", 4) == 0)
				{
					if(CURRENT_SCOPE->defines != scope::type)
					{
						logPrintf("XML parse error: nested type with no struct type\n");
						return -1;
					}
					CURRENT_SCOPE->defines = scope::type_closed;
					leave_scope();
				}
				else if(wstrncmp(d, "arg", 3) == 0)
				{
					if(CURRENT_SCOPE->defines != scope::type_closed)
					{
						logPrintf("XML parse error: nested arg with no struct type\n");
						return -1;
					}
					proto = NULL;
					leave_scope();
				}
				else if(wstrncmp(d, "return", 6) == 0)
				{
					if(CURRENT_SCOPE->defines != scope::type_closed)
					{
						logPrintf("XML parse error: nested return with no struct type\n");
						return -1;
					}
					proto = NULL;
					is_return_value = false;
					leave_scope();
				}
				else if(wstrncmp(d, "element", 7) == 0)
				{
					if(CURRENT_SCOPE->defines != scope::type && CURRENT_SCOPE->defines != scope::type_closed)
					{
						logPrintf("XML parse error: nested element with no struct type\n");
						return -1;
					}
					CURRENT_SCOPE->defines = scope::type_closed;			//we can safely close even if we're within an arg
					if(proto)		//inside an arg...
					{
						if(proto == proto_end)
						{
							logPrintf("XML parse error: element with no containing arg proto ?!?\n");
							return -1;
						}
						proto_end = get_prev_arg_spec_deref(proto, proto_end);
						proto_end->deref = NULL;
					}
					leave_scope();
				}
				else
				{
					logPrintf("XML parse error: bad end tag\n");
					return -1;
				}
				i = countto(d, '>');
				d += i + 1;
				depth--;
			}
			else if(wstrncmp(d, "?xml", 4) == 0)
			{
				// xml header
				d++;
				i = countto(d, '>');
				d += i + 1;
			}
			else if(wstrncmp(d, "lib", 3) == 0)
			{
				//<lib attributes ... 
				if(depth != 0)
				{
					logPrintf("XML parse error: nested lib element\n");
					return -1;
				}
				d += 3;
				whitespace(&d);
				if(wstrncmp(d, "name", 4) == 0)
				{
					i = countto(d, '=');
					d += i + 1;
					whitespace(&d);
					inlibname = get_quoted_value(&d);
					i = countto(d, '>');
					d += i + 1;
				}
				else
				{
					logPrintf("XML parse error: Bad lib element\n");
					return -1;
				}
				depth++;
				if(!inlibname)
				{
					logPrintf("XML parse error: lib element with no name\n");
					return -1;
				}
				enter_scope(get_add_scope(inlibname));
				CURRENT_SCOPE->defines = scope::library;
			}
			else if(wstrncmp(d, "function", 8) == 0)
			{
				//<function attributes ... 
				if(depth == 0 || (depth == 1 && inlibname))				//functions have to be either global, or within a library scope
				{
					depth++;
					d += 8;
					whitespace(&d);
					functionargument_index = 0;
					libn = NULL;
					stacktrace = unspecified;
					while(d < end && *d != '>')
					{
						if(*d == '/')
						{
							break;
						}
						else if(wstrncmp(d, "name", 4) == 0)
						{
							i = countto(d, '=');
							d += i + 1;
							whitespace(&d);
							functionname = get_quoted_value(&d);
						}
						else if(wstrncmp(d, "lib", 3) == 0)
						{
							i = countto(d, '=');
							d += i + 1;
							whitespace(&d);
							libn = get_quoted_value(&d);
							if(inlibname && wstrncmp(inlibname, libn, (int)strlen_0(libn)) != 0)
							{
								logPrintf("XML parse error: function specified lib name differs from containing element lib name\n");
								free_0(libn);
								return -1;
							}
						}
						else if(wstrncmp(d, "ordinal", 7) == 0)
						{
							i = countto(d, '=');
							d += i + 1;
							whitespace(&d);
							if(ISNUMBER(*(d + 1)))
							{
								ordinal = (unsigned short)get_quoted_numeric_value(&d, NULL);
							}
							else
							{
								logPrintf("XML parse error: non numeric value for ordinal\n");
								return -1;
							}
						}
						else if(wstrncmp(d, "stacktrace", 10) == 0)
						{
							i = countto(d, '=');
							d += i + 1;
							whitespace(&d);
							stacktrace = get_quoted_boolean(&d);
						}
						else
						{
							logPrintf("XML parse error: bad function attribute\n");
							return -1;
						}
						whitespace(&d);
					}
					if(functionname)
					{
						//set up basics for the hooked_func struct before catching arguments, return, etc..
						if(!libn)
						{
							if(inlibname)
							{
								l = (int)strlen_0(inlibname);
								libn = (char *)malloc_0(l + 1);
								memcpy_0(libn, inlibname, l);
								libn[l] = 0x00;
							}
							else
							{
								libn = (char *)malloc_0(2);
								libn[0] = '*';					//wild_lib
								libn[1] = 0x00;
							}
						}

						hfstruct = get_hooked_func_struct();
						if(!hfstruct)
						{
							logPrintf("XML parse error: couldn't get empty function hook structure\n");
							return -1;
						}
						hfstruct->origlibname = libn;
						hfstruct->origname = functionname;
						hfstruct->origordinal = ordinal;
						hfstruct->arg = NULL;
						arg_spec = NULL;

						if(*d == '/')
						{
							d += 2;
							
							//we just want to know if it's called, no captures

							hfstruct = NULL;
							functionname = NULL;
							depth--;
						}
						else 
						{
							d++;
							//could make sure there's no duplicates here... FIXME
							//or we could treat it like a lib, and allow errors
							//to be defined elsewhere per this function... 
							//but we'd want to check that it was within the same
							//lib, which means using the scope stack to look it
							//up... FIXME FIXME
							enter_scope(add_scope());
							CURRENT_SCOPE->defines = scope::function;
						}
					}
					else
					{
						logPrintf("XML parse error: function element with no name\n");
						return -1;
					}
				}
				else
				{
					logPrintf("XML parse error: Bad function element\n");
					return -1;
				}
			}
			else if(wstrncmp(d, "type", 4) == 0)
			{
				//<type attributes...
				d += 4;
				is_an_element = false;
parse_handletype:
				whitespace(&d);
				bool offset = false;
				while(d < end && *d != '/')
				{
					if(*d == '>')
					{
						depth++;
						//nested elements... 
						break;
					}
					if(wstrncmp(d, "name", 4) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						typenamestr = get_quoted_value(&d);
					}
					else if(wstrncmp(d, "type", 4) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						typevalue = get_quoted_value(&d);
					}
					else if(wstrncmp(d, "basetype", 8) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						typebasetype = get_quoted_value(&d);
					}
					else if(wstrncmp(d, "offset", 8) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						numericvalue = get_quoted_numeric_value(&d, NULL);
						offset = true;
					}
					else
					{
						logPrintf("XML parse error: bad type attribute\n");
						xmldebugPrint(d, 10);
						return -1;
					}
					whitespace(&d);
				}
				if(*d == '/')
				{
					d += 2;
					if(!typevalue)
					{
						if(typenamestr)
							logPrintf("XML parse error: attempting to define type %s with no type\n", typenamestr);
						else
							logPrintf("XML parse error: attempting to define type without type\n");
						return -1;
					}
					if(wstrcmp(typevalue, "pointer") == 0)
					{
						if(!typebasetype)
							logPrintf("XML parse error: pointer with no basetype\n");
						else
						{
							t = add_type(typenamestr, typebasetype, 1, is_an_element);
						}
					}
					else if(wstrcmp(typevalue, "array") == 0)
					{
						logPrintf("XML parse warning: skipping array type...\n");
						//FIXME
						//goto type_setup_struct_offset;
					}
					else if(wstrcmp(typevalue, "struct") == 0)
					{
						t = add_type(typenamestr, typevalue, 0, is_an_element);
						//no definition, we'll only log pointer
						// FIXME FIXME FIXME ... no, it's a structure, not a pointer to a structure... 
					}
					else
						t = add_type(typenamestr, typevalue, 0, is_an_element);
				}
				else
				{
					d++;
					if(wstrcmp(typevalue, "struct") != 0)
					{
						logPrintf("XML parse error: nested type is not struct\n");
						return -1;
					}
					t = add_type(typenamestr, typevalue, 0, is_an_element);
					t->scope = add_scope();
					enter_scope(t->scope);
					CURRENT_SCOPE->defines = scope::type;
				}
				if(typebasetype)
				{
					free_0(typebasetype);
					typebasetype = NULL;
				}
				if(typevalue)
				{
					free_0(typevalue);
					typevalue = NULL;
				}
			}
			else if(wstrncmp(d, "value", 5) == 0)
			{
				//<value attributes...
				d += 5;
				whitespace(&d);
				while(d < end && *d != '/')
				{
					if(wstrncmp(d, "name", 4) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						valuename = get_quoted_value(&d);
					}
					else if(wstrncmp(d, "value", 5) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						if(ISNUMBER(*(d + 1)))
						{
							numericvalue = get_quoted_numeric_value(&d, &neg);
							if(neg)
							{
								negvalue = numericvalue;
								negvalue = -negvalue;
							}
							else
								negvalue = 0;
							if(valuevalue)
								logPrintf("XML parse error: two value values!\n");
						}
						else
						{
							valuevalue = get_quoted_value(&d);
						}
					}
					else
					{
						logPrintf("XML parse error: bad value attribute\n");
						xmldebugPrint(d, 10);
						return -1;
					}
					whitespace(&d);
				}
				d += 2;
				if(!valuename)
				{
					logPrintf("XML parse error: value element with no name\n");
					return -1;
				}
				if(valuevalue)
				{
					add_value_by_name(valuename, valuevalue);
					free_0(valuevalue);
					valuevalue = NULL;
				}
				else
				{
					if(negvalue)
						add_value(valuename, negvalue);
					else
						add_value(valuename, numericvalue);
					numericvalue = 0;
				}
				valuename = NULL;
			}
			else if(wstrncmp(d, "element", 7) == 0)
			{
				d += 7;
				is_an_element = true;
				if(CURRENT_SCOPE->defines == scope::type)			//still defining...
					goto parse_handletype;
				else if(arg_spec)
				{
					//FIXME FIXME FIXME there's no check here for if an element is defined outside
					//of an arg... i.e., a "/>" at the end of the arg and we die on the lookup
					goto parse_handlearg;
				}
				else
				{
					logPrintf("XML parse error: element element not within type or arg\n");
					return -1;
				}
			}
			else if(wstrncmp(d, "arg", 3) == 0)
			{
				//<arg attributes...
				if(!functionname || !hfstruct)
				{
					logPrintf("XML parse error: arg element outside of function\n");
					return -1;
				}
				d += 3;
				is_return_value = false;			// is this enough?
parse_handlearg:
				whitespace(&d);
				//defaults
				log = unspecified;
				precall = unspecified;
				postcall = unspecified;
				while(d < end && *d != '/')
				{
					if(*d == '>')
					{
						depth++;
						//nested elements... 
						break;
					}
					if(wstrncmp(d, "name", 4) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						argname = get_quoted_value(&d);
						xmldebugPrint(d, 20);
						/* FIXME FIXME FIXME what about this strcmp_0, wstrncmp stuff... 
						 * also, more lenient parser errors... */
						if(strcmp_0(argname, "return") == 0)
						{
							logPrintf("XML parse error: can't use 'return' as an argument name\n");
							return -1;
						}
					}
					else if(wstrncmp(d, "type", 4) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						argtype = get_quoted_value(&d);
					}
					else if(wstrncmp(d, "size", 4) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						argsize = get_quoted_value(&d);
					}
					else if(wstrncmp(d, "log", 3) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						log = get_quoted_boolean(&d);
					}
					else if(wstrncmp(d, "precall", 7) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						precall = get_quoted_boolean(&d);
					}
					else if(wstrncmp(d, "postcall", 8) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						postcall = get_quoted_boolean(&d);
					}
					else
					{
						logPrintf("XML parse error: bad arg attribute\n");
						xmldebugPrint(d, 10);
						return -1;
					}
					whitespace(&d);
				}
				if(*d == '/')
				{
					d += 2;
					if(!argtype && !argname)
					{
						logPrintf("XML parse error: arg with no type and no name\n");
						return -1;
					}
					if(log != fase && (precall != fase || postcall == tru))
					{
						if(!argtype)
						{
							t = lookup_type(argname, CURRENT_SCOPE_ONLY);
							if(!t)
							{
								logPrintf("XML parse error: unspecified type %s arg not in structure\n", argname);
								return -1;
							}
						}
						else
							t = lookup_type(argtype);
						if(!t)
						{
							logPrintf("XML parse error: type %s arg not found\n", argtype);
							return -1;
						}
						if(t->basetype == ARG_TYPE_STRUCT)
						{
							logPrintf("XML parse error: raw, empty structure specified as argument\n");
							return -1;
						}
						a = 0;
						//if(is_return_value)
						//	__debugbreak();
						//if(!argsize && t->basetype == ARG_TYPE_PTR)
						//	__debugbreak();
						if(precall != fase && !is_return_value)
							a |= ARGSPECOFPRECALLINTEREST;
						if(postcall == tru || (is_return_value && postcall != fase))
							a |= ARGSPECOFPOSTCALLINTEREST;
						if(is_return_value)
							a |= ARGSPECRETURN_VALUE;
						logPrintf("arg %s %04x\n", argname, a);
						if(t->basetype > 20)
							logPrintf("XML parse error: high base type %d\n", t->basetype);
						if(t->basetype == ARG_TYPE_PTR && !t->basetype_ref)		//DEBUG
						{
							logPrintf("XML parse error: pointer with no basetype_ref!\n");
							return -1;
						}
						
						// FIXME wait... are char and unsigned char * strings different ?!?! FIXME
						if(t->basetype == ARG_TYPE_PTR && !argsize && (t->basetype_ref->basetype == ARG_TYPE_CHAR || t->basetype_ref->basetype == ARG_TYPE_UCHAR))
							a |= ARG_TYPE_STR;
						else if(t->basetype == ARG_TYPE_PTR && !argsize && t->basetype_ref->basetype == ARG_TYPE_WCHAR)
							a |= ARG_TYPE_WSTR;
						else if(t->basetype == ARG_TYPE_PTR)
						{
							a |= t->basetype_ref->basetype;
							a |= ARGSPECPOINTER;
						}
						else
							a |= t->basetype;
						struct arg_spec * ad;
						if(!arg_spec)
						{
							if(!proto)
							{
								arg_spec = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
								ad = arg_spec;
							}
							else
							{
								arg_spec = copy_arg_spec_chain(proto);
								ad = deref_end(hfstruct->arg);
								ad->deref = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
								ad = ad->deref;
							}
							logPrintf("starting arg spec %p\n", arg_spec);
							arg_spec->next_spec = NULL;
							hfstruct->arg = arg_spec;
						}
						else
						{
							if(proto)
							{
								arg_spec->next_spec = copy_arg_spec_chain(proto);
								ad = deref_end(arg_spec->next_spec);
								ad->deref = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
								ad = ad->deref;
							}
							else
							{
								arg_spec->next_spec = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
								ad = arg_spec->next_spec;
							}
							logPrintf("adding arg spec %p\n", arg_spec->next_spec);
							arg_spec = arg_spec->next_spec;
							arg_spec->next_spec = NULL;
						}
						if(CURRENT_SCOPE->defines == scope::type)
							ad->offset = t->offset;
						else if(is_return_value)
							ad->offset = 0;
						else
							ad->offset = (ARGUMENT_SIZE * functionargument_index++);
						ad->arg_name = argname;
						argname = NULL;
						arg_spec->deref_len = (argtypep)argsize;				//make it easy for fixup_function_lengths
						ad->deref = NULL;
						argsize = NULL;
						arg_spec->type = a;			//i.e., the eventual dereferenced type... 
					}
				}
				else
				{
					d++;
					if(!argtype)
					{
						if(!argname)
						{
							logPrintf("XML parse error: nested arg with no type or name\n");
							return -1;
						}
						//could be a nested structure or element defined simply by name
						t = lookup_type(argname, CURRENT_SCOPE_ONLY);
						if(!t)
						{
							logPrintf("XML parse error: unspecified type %s arg not in structure\n", argname);
							return -1;
						}
					}
					else
						t = lookup_type(argtype);
					if(!t)
					{
						logPrintf("XML parse error: type %s arg not found\n", argtype);
						return -1;
					}
					if(t->basetype == ARG_TYPE_PTR)
						enter_scope(t->basetype_ref->scope);
					else if(t->basetype == ARG_TYPE_STRUCT)
						enter_scope(t->scope);
					else
					{
						logPrintf("XML parse error: nested arg with bad type\n");
						return -1;
					}
					//only log if it's a pointer and not a raw structure which would just be used for scope
					if(t->basetype == ARG_TYPE_PTR)
					{
						struct arg_spec * ad;
						a = 0;
						if(log == tru || precall == tru || postcall == tru)
						{
							if(precall != fase && !is_return_value)
								a |= ARGSPECOFPRECALLINTEREST;
							if(postcall == tru || (is_return_value && postcall != fase))
								a |= ARGSPECOFPOSTCALLINTEREST;
							if(is_return_value)
								a |= ARGSPECRETURN_VALUE;
							if(t->basetype > 20)
								logPrintf("XML parse error: high base type %d\n", t->basetype);
							if(t->basetype == ARG_TYPE_PTR)
							{
								a |= t->basetype_ref->basetype;
								a |= ARGSPECPOINTER;
							}
							else
								a |= t->basetype;
						}
						logPrintf("nested arg %s %04x\n", argname ? argname : "no name", a);
						ad = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
						ad->next_spec = NULL;
						if(CURRENT_SCOPE->defines == scope::type)
							ad->offset = t->offset;
						else if(is_return_value)
							ad->offset = 0;
						else
							ad->offset = (ARGUMENT_SIZE * functionargument_index++);
						/* FIXME FIXME FIXME we might want the arg_name but we'd have to make a copy of it... */
						ad->arg_name = NULL;
						ad->deref_len = NULL;
						ad->type = ARG_TYPE_PTR;
						/* It has to be arg_type_ptr because we don't know what will be caught within it, and we need
						 * a deref regardless... what about structures as offsets without deref except, they'd be
						 * a deref from the... oh I guess we don't pass structures as arguments... still FIXME FIXME FIXME */
						ad->deref = NULL;
						if(a)			//we're logging this:
						{
							if(!arg_spec)
							{
								if(!proto)
								{
									arg_spec = ad;
								}
								else
								{
									arg_spec = copy_arg_spec_chain(proto);
									deref_end(arg_spec)->deref = ad;
								}
								logPrintf("starting arg_spec chain: %p arg_spec\n", arg_spec);
								arg_spec->next_spec = NULL;
								hfstruct->arg = arg_spec;
							}
							else
							{
								if(proto)
								{
									arg_spec->next_spec = copy_arg_spec_chain(proto);
									deref_end(arg_spec->next_spec)->deref = ad;
								}
								else
								{
									arg_spec->next_spec = ad;
								}
								logPrintf("adding arg_spec chain: %p arg_spec\n", arg_spec->next_spec);
								arg_spec = arg_spec->next_spec;
								arg_spec->next_spec = NULL;
							}
							//make it easy for fixup_function_lengths
							arg_spec->arg_name = argname;
							argname = NULL;
							arg_spec->deref_len = (argtypep)argsize;
							argsize = NULL;
							arg_spec->type = a;
						}
						//setup the additional arg_spec deref chain for contained elements... 
						//if its a structure and not a pointer, like nested structures then no deref, just track offsets
						if(proto)
						{
							// this is an element opening tag:
							proto_end->deref = ad;
							proto_end = ad;
							/* FIXME we could remove proto_end and just use deref_end to look it up at the time... it's kind
							 * of one more variable to keep track of but whatever... */
						}
						else
						{
							proto = arg_spec;
							proto_end = proto;
						}
					}

				}
				/* We actually probably want to save the argname somewhere so that it can be used by the
				 * hook logger FIXME FIXME FIXME */
				if(argname)
				{
					free_0(argname);
					argname = NULL;
				}
				if(argtype)
				{
					free_0(argtype);
					argtype = NULL;
				}
				if(argsize)
				{
					free_0(argsize);
					argsize = NULL;
				}
			}
			else if(wstrncmp(d, "return", 6) == 0)
			{
				//<return attributes...
				if(!functionname)
				{
					logPrintf("XML parse error: return element outside of function\n");
					return -1;
				}
				//FIXME FIXME FIXME should check to make sure we're not inside of an <arg> </arg>
				d += 6;
				whitespace(&d);
				l = (int)strlen_0("return value");
				argname = (char *)malloc_0((l + 1) * sizeof(char));
				memcpy_0(argname, "return value", l * sizeof(char));
				argname[l] = 0x00;
				is_return_value = true;
				goto parse_handlearg;
			}
			else if(wstrncmp(d, "success", 7) == 0)
			{
				//<success attributes...
				if(!functionname)
				{
					logPrintf("XML parse error: success element outside of function\n");
					return -1;
				}
				d += 7;
				whitespace(&d);
				while(d < end && *d != '/')
				{
					if(wstrncmp(d, "return", 6) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						d++;
						if(wstrncmp(d, "equal", 5) == 0)
						{
							d += 5;
						}
						else if(wstrncmp(d, "notequal", 8) == 0)
						{
							d += 8;
						}
						else if(wstrncmp(d, "lessthan", 8) == 0)
						{
							d += 8;
						}
						else if(wstrncmp(d, "lessthanorequal", 15) == 0)
						{
							d += 15;
						}
						else if(wstrncmp(d, "greaterthan", 11) == 0)
						{
							d += 11;
						}
						else if(wstrncmp(d, "greaterthanorequal", 18) == 0)
						{
							d += 18;
						}
						else
						{
							logPrintf("XML parse error: bad success return qualifier\n");
							return -1;
						}
						d++;
					}
					else if(wstrncmp(d, "value", 5) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						if(ISNUMBER(*(d + 1)))
						{
							numericvalue = get_quoted_numeric_value(&d, NULL);
						}
						else
						{
							valuevalue = get_quoted_value(&d);
						}
					}
					else
					{
						logPrintf("XML parse error: bad success attribute\n");
						xmldebugPrint(d, 10);
						return -1;
					}
					whitespace(&d);
				}
				d += 2;
			}
		}
		else
			return 0;
		whitespace(&d);
	}
	return 0;
}

void whitespace(char ** d)
{
	while(**d == ' ' || **d == '\t' || **d == 0x0a || **d == 0x0d)
		(*d)++;
}

int wstrncmp(char * a, char * b, int n)
{
	while(n--)
	{
		if(*a != *b)
			return -1;
		a++;
		b++;
	}
	return 0;
}

int wstrcmp(char * a, char * b)
{
	while(*a && *b)
	{
		if(*a != *b)
			return -1;
		a++;
		b++;
	}
	if(*a || *b)
		return -1;
	return 0;
}

void xmldebugPrint(char * d, int s)
{
	for(int g = 0; g < s; g++)
		logPrintf("%c", *(d + g));
	logPrintf("\n");
}

// if the xml file is garbage, just let it go down, no size checks
// also FIXME FIXME we could really tighten this up with the strcmps...
int countto(char * d, char w)
{
	int i = 0;
	while(*(d + i) != w)
		i++;
	return i;
}

char * get_quoted_value(char ** d)
{
	char quote = **d;
	char * str;
	int i;
	(*d)++;

	i = countto(*d, quote);
	str = (char *)malloc_0((i * sizeof(char)) + 1);
	memcpy_0(str, *d, i * sizeof(char));
	str[i] = 0x00;
	(*d) += i * sizeof(char);
	(*d)++;		//endquote
	return str;
}

value_t get_quoted_numeric_value(char ** d, bool * neg)
{
	char quote = **d;
	int i;
#ifdef _WIN64
	unsigned long long value;
#else
	unsigned long value;
#endif //_WIN64
	(*d)++;

	if(neg && (**d) == '-')
	{
		*neg = true;
		(*d)++;
	}
	else if(neg)
		*neg = false;

	i = countto(*d, quote);
	if((**d) == '0' && (*((*d) + 1) == 'x' || *((*d) + 1) == 'X'))
	{
		(*d) += 2;
		if(sscanf_0(*d, "%x", &value) != 1)
		{
			logPrintf("XML parse error: get numeric value failed\n");
			return NULL;
		}
		(*d) += (i - 2);
		(*d)++;		//endquote
		return value;
	}
	else if(*(*d + i - 1) == 'h')
	{
		if(sscanf_0(*d, "%x", &value) != 1)
		{
			logPrintf("XML parse error: get numeric value failed\n");
			return NULL;
		}
		(*d) += i;
		(*d)++;		//endquote
		return value;
	}
	if(sscanf_0(*d, "%u", &value) != 1)
	{
		logPrintf("XML parse error: get numeric value failed\n");
		return NULL;
	}
	(*d) += i;
	(*d)++;		//endquote
	return value;
}

s_bool get_quoted_boolean(char ** d)
{
	char quote = **d;
	int i;
	(*d)++;

	i = countto(*d, quote);
	if(**d == '1' || **d == 't' || **d == 'T')
	{
		(*d) += i + 1;
		return tru;
	}
	else if(**d == '0' || **d == 'f' || **d == 'F')
	{
		(*d) += i + 1;
		return fase;
	}
	logPrintf("XML parse error: bad boolean, assuming true\n");
	(*d) += i + 1;
	return tru;
}


