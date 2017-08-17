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
#include <Windows.h>
#include "helperlib.h"
#include "functionprototypes.h"
#include "xmlhookloader.h"
#include "hook.h"
#include "logging.h"
#include "hookstructures.h"

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

#ifdef _WIN64
typedef unsigned long long value_t;
typedef long long svalue_t;
#else
typedef unsigned long value_t;
typedef long svalue_t;
#endif //_WIN64

struct type_def
{
	char * name;
	unsigned short basetype;
	unsigned short offset;
	struct type_def * basetype_ref;
	struct type_def * scope_ref;
};

struct value
{
	char * name;
	value_t val;
};

struct scope
{
	struct type_def * type_definition;
	unsigned int type_definitions;
	struct value * value;
	unsigned int values;
};

struct scope * scope_stack;
unsigned long scope_stack_size;

enum s_bool
{
	fase = 0,
	tru = 1,
	unspecified
};

void create_basic_types(void);
void enter_scope(void);
void leave_scope(void);
void cleanup_scope(struct scope * scope);
struct type_def * lookup_type(char * name, struct type_def * scope_ref);
struct type_def *  add_type(char * name, char * basetypename, bool isptr);
struct value * lookup_value(char * name);
void add_value_by_name(char * name, char * value);
void add_value(char * name, value_t value);
void add_signed_value(char * name, svalue_t value);
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
char * base_type_names[] = { "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t" };

char void_ptr_type[] = "void *";
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
	struct scope * g_scope;

	scope_stack_size = 1;
	scope_stack = (struct scope *)malloc_0(sizeof(struct scope));
	g_scope = scope_stack;

	g_scope->type_definitions = 15;
	g_scope->type_definition = (struct type_def *)malloc_0(g_scope->type_definitions * sizeof(struct type_def));

	for(i = 0; i < 8; i++)
	{
		g_scope->type_definition[i].name = base_type_names[i];
		g_scope->type_definition[i].basetype = i;
		g_scope->type_definition[i].basetype_ref = NULL;
		g_scope->type_definition[i].scope_ref = NULL;
	}
	/* We really just want a pointer base type, not necessarily a void *... but... I guess it's okay... */
	g_scope->type_definition[8].name = void_ptr_type;
	g_scope->type_definition[8].basetype = ARG_TYPE_PTR;
	g_scope->type_definition[8].basetype_ref = NULL;
	g_scope->type_definition[8].scope_ref = NULL;
	g_scope->type_definition[9].name = struct_type;
	g_scope->type_definition[9].basetype = ARG_TYPE_STRUCT;
	g_scope->type_definition[9].basetype_ref = NULL;
	g_scope->type_definition[9].scope_ref = NULL;
	// what is this struct_element for again ?!?! 
	g_scope->type_definition[10].name = struct_type_element;
	g_scope->type_definition[10].basetype = ARG_TYPE_STRUCT_ELEMENT;
	g_scope->type_definition[10].basetype_ref = NULL;
	g_scope->type_definition[10].scope_ref = NULL;
	g_scope->type_definition[11].name = len_type;
	g_scope->type_definition[11].basetype = ARG_TYPE_LEN;
	g_scope->type_definition[11].basetype_ref = &(g_scope->type_definition[ARG_TYPE_UINT32]);
	g_scope->type_definition[11].scope_ref = NULL;
	g_scope->type_definition[12].name = bool_type;
	g_scope->type_definition[12].basetype = ARG_TYPE_BOOL;
	if(sizeof(bool) != 1)
		logPrintf("OH SHIT %d\n", sizeof(bool));
	g_scope->type_definition[12].basetype_ref = &(g_scope->type_definition[ARG_TYPE_UINT8]);			//double check FIXME FIXME FIXME
	g_scope->type_definition[12].scope_ref = NULL;
	g_scope->type_definition[13].name = ip4_type;
	g_scope->type_definition[13].basetype = ARG_TYPE_IP4;
	g_scope->type_definition[13].basetype_ref = &(g_scope->type_definition[ARG_TYPE_UINT32]);
	g_scope->type_definition[13].scope_ref = NULL;
	/* FIXME FIXME FIXME IP6 */
	g_scope->type_definition[14].name = ip6_type;
	g_scope->type_definition[14].basetype = ARG_TYPE_IP6;
	g_scope->type_definition[14].basetype_ref = &(g_scope->type_definition[ARG_TYPE_UINT32]);
	g_scope->type_definition[14].scope_ref = NULL;
	g_scope->values = 0;
	g_scope->value = NULL;
}

void enter_scope(void)
{
	unsigned int i;
	scope_stack_size++;
	scope_stack = (struct scope *)realloc_0(scope_stack, sizeof(struct scope) * scope_stack_size);
	if(!scope_stack)
	{
		logPrintf("XML parse ERROR: enter scope realloc failure\n");
		return;
	}
	char * m = (char *)&(scope_stack[scope_stack_size - 1]);
	for(i = 0; i < sizeof(struct scope); i++)
		m[i] = 0x00;
}

void leave_scope(void)
{
	if(scope_stack_size == 0)
	{
		logPrintf("XML parse error: attempt to leave global scope!\n");
		return;
	}
	cleanup_scope(&scope_stack[scope_stack_size - 1]);
	scope_stack_size--;
	scope_stack = (struct scope *)realloc_0(scope_stack, sizeof(struct scope) * scope_stack_size);
	if(!scope_stack)
	{
		logPrintf("XML parse ERROR: leave scope realloc failure\n");
		return;
	}
}

void cleanup_scope(struct scope * scope)
{
	unsigned int i;
	for(i = 0; i < scope->type_definitions; i++)
	{
		if(scope->type_definition[i].name)
			free_0(scope->type_definition[i].name);
	}
	free_0(scope->type_definition);
	for(i = 0; i < scope->values; i++)
	{
		if(scope->value[i].name)
			free_0(scope->value[i].name);
	}
	free_0(scope->value);
}

struct type_def * lookup_type(char * name, struct type_def * scope_ref)
{
	unsigned int scope_check_index = scope_stack_size - 1;
	unsigned int i;
	logPrintf("lookuptype %s %p\n", name, scope_ref);
	for(;;)
	{
		for(i = 0; i < scope_stack[scope_check_index].type_definitions; i++)
		{
			logPrintf("\t\t%s\n", scope_stack[scope_check_index].type_definition[i].name);
			if(wstrcmp(name, scope_stack[scope_check_index].type_definition[i].name) == 0 && (!scope_ref || scope_ref == scope_stack[scope_check_index].type_definition[i].scope_ref))
			{
				return &(scope_stack[scope_check_index].type_definition[i]);
			}
		}
		if(scope_check_index == 0)
			break;
		scope_check_index--;
	}
	logPrintf("XML parse error: can't resolve type %s\n", name);
	return NULL;
}

/* What about duplicate entries, arrays, structures... ?!? FIXME */
struct type_def * add_type(char * name, char * basetypename, bool isptr)
{
	unsigned int scope_check_index = scope_stack_size - 1;
	struct type_def * type_def;
	struct type_def * looked_up_type_def = lookup_type(basetypename, NULL);

	if(looked_up_type_def)
	{
		if(scope_stack[scope_stack_size - 1].type_definitions == 0)
		{
			scope_stack[scope_stack_size - 1].type_definitions = 1;
			scope_stack[scope_stack_size - 1].type_definition = (struct type_def *)malloc_0(sizeof(struct type_def));
		}
		else
		{
			scope_stack[scope_stack_size - 1].type_definitions++;
			scope_stack[scope_stack_size - 1].type_definition = (struct type_def *)realloc_0(scope_stack[scope_stack_size - 1].type_definition, scope_stack[scope_stack_size - 1].type_definitions * sizeof(struct type_def));
		}
		type_def = &(scope_stack[scope_stack_size - 1].type_definition[scope_stack[scope_stack_size - 1].type_definitions - 1]);
		type_def->name = name;
		if(isptr)
		{
			type_def->basetype = ARG_TYPE_PTR;
			type_def->basetype_ref = looked_up_type_def;
		}
		// not going to worry about arrays in nested structure types for now because of the sizes FIXME
		else
		{
			type_def->basetype = looked_up_type_def->basetype;
		}
		return type_def;
	}
	return NULL;
}

unsigned short calculate_offset(struct type_def * st_type)
{
	struct type_def * previous_type;
	//must be current scope
	previous_type = &(scope_stack[scope_stack_size - 1].type_definition[scope_stack[scope_stack_size - 1].type_definitions - 2]);
	if(previous_type == st_type)		//first element
		return 0;
	switch(previous_type->basetype)
	{
		case ARG_TYPE_UINT8:
		case ARG_TYPE_INT8:
			return previous_type->offset + 1;
			break;
		case ARG_TYPE_UINT16:
		case ARG_TYPE_INT16:
			return previous_type->offset + 2;
			break;
		case ARG_TYPE_UINT32:
		case ARG_TYPE_INT32:
			return previous_type->offset + 4;
			break;
		case ARG_TYPE_UINT64:
		case ARG_TYPE_INT64:
			return previous_type->offset + 8;
			break;
		case ARG_TYPE_PTR:
#ifdef _WIN64
			return previous_type->offset + 8;
#else
			return previous_type->offset + 4;
#endif //_WIN64
			break;
		default:
			logPrintf("XML parse error: couldn't calculate offset for element of %s\n", st_type->name);
			return 0;
	}
	//...
}

struct value * lookup_value(char * name)
{
	unsigned int scope_check_index = scope_stack_size - 1;
	unsigned int i;

	for(;;)
	{
		for(i = 0; i < scope_stack[scope_check_index].values; i++)
		{
			if(wstrcmp(name, scope_stack[scope_check_index].value[i].name) == 0)
			{
				return &(scope_stack[scope_check_index].value[i]);
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

#ifdef _WIN64
void add_value(char * name, unsigned long long value)
#else
void add_value(char * name, unsigned long value)
#endif //_WIN64
{
	if(scope_stack[scope_stack_size - 1].values == 0)
	{
		scope_stack[scope_stack_size - 1].values = 1;
		scope_stack[scope_stack_size - 1].value = (struct value *)malloc_0(sizeof(struct value));
	}
	else
	{
		scope_stack[scope_stack_size - 1].values++;
		scope_stack[scope_stack_size - 1].value = (struct value *)realloc_0(scope_stack[scope_stack_size - 1].value, scope_stack[scope_stack_size - 1].values * sizeof(struct value));
	}
	scope_stack[scope_stack_size - 1].value[scope_stack[scope_stack_size - 1].values - 1].name = name;
	scope_stack[scope_stack_size - 1].value[scope_stack[scope_stack_size - 1].values - 1].val = value;
}


#ifdef _WIN64
void add_signed_value(char * name, long long value)
#else
void add_signed_value(char * name, long value)
#endif //_WIN64
{
	if(scope_stack[scope_stack_size - 1].values == 0)
	{
		scope_stack[scope_stack_size - 1].values = 1;
		scope_stack[scope_stack_size - 1].value = (struct value *)malloc_0(sizeof(struct value));
	}
	else
	{
		scope_stack[scope_stack_size - 1].values++;
		scope_stack[scope_stack_size - 1].value = (struct value *)realloc_0(scope_stack[scope_stack_size - 1].value, scope_stack[scope_stack_size - 1].values * sizeof(struct value));
	}
	scope_stack[scope_stack_size - 1].value[scope_stack[scope_stack_size - 1].values - 1].name = name;
#ifdef _WIN64
	scope_stack[scope_stack_size - 1].value[scope_stack[scope_stack_size - 1].values - 1].val = (unsigned long long)value;
#else
	scope_stack[scope_stack_size - 1].value[scope_stack[scope_stack_size - 1].values - 1].val = (unsigned long)value;
#endif //_WIN64
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
	//size = 10000;
	//SetFilePointer_0(xmlhookFile, 0, NULL, FILE_BEGIN);
	logPrintf("Filesize %d\n", size);
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

	// what about arg_specs and type name lookups ?!?!? FIXME FIXME FIXME
	for(unsigned int i = 0; i < scope_stack_size; i++)
		cleanup_scope(&scope_stack[i]);

	return 0;
}

void xmlcleanup(void)
{
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
	char * str;
	char * inlibname;
	char * functionname;
	char * valuename;
	char * valuevalue;
	char * typevalue;
	char * typenamestr;
	char * typebasetype;
	char * argname;
	char * argtype;
	unsigned long functionargument_index;
	char * libn, *funcn;
	int l;
	unsigned int ordinal;
	bool neg;
	s_bool log, precall, postcall;
	struct hooked_func * hfstruct;
	struct type_def * type_struct_type, * arg_struct_type;
	struct type_def * t;
	struct arg_spec * arg_spec;
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
	type_struct_type = NULL;
	arg_struct_type = NULL;
	arg_spec = NULL;
	d = data;
	end = d + size;

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
					leave_scope();
					inlibname = NULL;
				}
				else if(wstrncmp(d, "function", 8) == 0)
				{
					leave_scope();
					functionname = NULL;
					arg_spec = NULL;
				}
				else if(wstrncmp(d, "type", 4) == 0)
				{
					if(!type_struct_type)
					{
						logPrintf("XML parse error: nested type with no struct type\n");
						return -1;
					}
					leave_scope();
					type_struct_type = type_struct_type->scope_ref;
				}
				else if(wstrncmp(d, "arg", 3) == 0)
				{
					if(!arg_struct_type)
					{
						logPrintf("XML parse error: nested arg with no struct type\n");
						return -1;
					}
					leave_scope();
					arg_struct_type = arg_struct_type->scope_ref;
				}
				else if(wstrncmp(d, "return", 6) == 0)
				{
					if(!arg_struct_type)
					{
						logPrintf("XML parse error: nested return with no struct type\n");
						return -1;
					}
					leave_scope();
					arg_struct_type = arg_struct_type->scope_ref;
				}
				else if(wstrncmp(d, "element", 7) == 0)
				{
					if(!type_struct_type && !arg_struct_type)
					{
						logPrintf("XML parse error: nested element with no struct type\n");
						return -1;
					}
					leave_scope();
					if(type_struct_type)
						type_struct_type = type_struct_type->scope_ref;
					else
						arg_struct_type = arg_struct_type->scope_ref;
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
				enter_scope();
			}
			else if(wstrncmp(d, "function", 8) == 0)
			{
				//<function attributes ... 
				if(depth == 0 || (depth == 1 && inlibname))
				{
					depth++;
					d += 8;
					whitespace(&d);
					functionargument_index = 0;
					libn = NULL;
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
							if(inlibname && wstrncmp(inlibname, libn, strlen_0(libn)) != 0)
							{
								logPrintf("XML parse error: function lib name differs from containing element lib name\n");
								free_0(inlibname);
								free_0(str);
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
								ordinal = get_quoted_numeric_value(&d, NULL);
							}
							else
							{
								logPrintf("XML parse error: non numeric value for ordinal\n");
								return -1;
							}
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
						__debugbreak();

						//set up basics for the hooked_func struct before catching arguments, return, etc..
						if(!libn)
						{
							if(inlibname)
							{
								l = strlen_0(inlibname);
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
						/*l = (strlen_0(functionname) / 2);
						funcn = (char *)malloc_0(l + 1);
						wcstombs_0(funcn, functionname, l);*/

						hfstruct = get_hooked_func_struct();
						if(!hfstruct)
						{
							logPrintf("XML parse error: couldn't get empty function hook structure\n");
							return -1;
						}
						hfstruct->origlibname = libn;
						hfstruct->origname = functionname;
						hfstruct->origordinal = ordinal;

						if(*d == '/')
						{
							d += 2;
							
							//we just want to know if it's called, no captures

							hfstruct = NULL;
							free_0(functionname);
							functionname = NULL;
							depth--;
						}
						else 
						{
							d++;
							enter_scope();
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
							t = add_type(typenamestr, typebasetype, 1);
							goto type_setup_struct_offset;
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
						t = add_type(typenamestr, typevalue, 0);
						//no definition, we'll only log pointer
						goto type_setup_struct_offset;
					}
					else
					{
						
						t = add_type(typenamestr, typevalue, 0);
type_setup_struct_offset:
						if(type_struct_type)
						{
							if(offset)
								t->offset = offset;
							else
								t->offset = calculate_offset(type_struct_type);
							t->scope_ref = type_struct_type;
						}
						else if(arg_struct_type)
						{
							if(offset)
								t->offset = offset;
							else
								t->offset = calculate_offset(arg_struct_type);
							t->scope_ref = arg_struct_type;
						}
						else
						{
							if(offset)
								t->offset = offset;
							else
								t->offset = 0;
							t->scope_ref = NULL;
						}
					}
				}
				else
				{
					d++;
					if(wstrcmp(typevalue, "struct") != 0)
					{
						logPrintf("XML parse error: nested type is not struct\n");
						return -1;
					}
					t = add_type(typenamestr, typevalue, 0);
					//same as above...
					if(type_struct_type)
					{
						if(offset)
							t->offset = offset;
						else
							t->offset = calculate_offset(type_struct_type);
						t->scope_ref = type_struct_type;
					}
					else if(arg_struct_type)
					{
						if(offset)
							t->offset = offset;
						else
							t->offset = calculate_offset(arg_struct_type);
						t->scope_ref = arg_struct_type;
					}
					else
					{
						if(offset)
							t->offset = offset;
						else
							t->offset = 0;
						t->scope_ref = NULL;
					}
					type_struct_type = t;
					enter_scope();
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
				if(type_struct_type)
					goto parse_handletype;
				else if(arg_spec)
					goto parse_handlearg;
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
					}
					else if(wstrncmp(d, "type", 4) == 0)
					{
						i = countto(d, '=');
						d += i + 1;
						whitespace(&d);
						argtype = get_quoted_value(&d);
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
					if(!argtype)
					{
						logPrintf("XML parse error: arg with no type\n");
						/* FIXME FIXME FIXME
						 * elements within arguments, need to look up and there's scope problems, scope stack
						 * hold the types, etc.. */
						return -1;
					}
					if(log != fase && (precall != fase || postcall == tru))
					{
						t = lookup_type(argtype, arg_struct_type);
						
						a = 0;
						if(precall != fase)
							a |= ARGSPECOFPRECALLINTEREST;
						if(postcall == tru)
							a |= ARGSPECOFPOSTCALLINTEREST;
						if(t->basetype > 20)
							logPrintf("XML parse error: high base type %d\n", t->basetype);
						a |= t->basetype;
						if(!arg_spec)
						{
							arg_spec = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
							arg_spec->next_spec = NULL;
							hfstruct->arg = arg_spec;
						}
						else
						{
							arg_spec->next_spec = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
							arg_spec = arg_spec->next_spec;
							arg_spec->next_spec = NULL;
						}
						if(arg_struct_type)
							arg_spec->offset = t->offset;
						else
							arg_spec->offset = functionargument_index++;
						arg_spec->deref_type = (argtypep)a;
					}
				}
				else
				{
					d++;
					if(!argtype)
					{
						logPrintf("XML parse error: nested arg with no type\n");
						return -1;
					}
					struct type_def * t = lookup_type(argtype, arg_struct_type);
					//if(t->basetype != ARG_TYPE_STRUCT && t->basetype != ARG_TYPE_STRUCT_ELEMENT)
					if(t->basetype != ARG_TYPE_PTR && t->basetype != ARG_TYPE_STRUCT)		//all structures have to be passed as pointer... unless we're already in one...
					{
						logPrintf("XML parse error: nested arg with bad type\n");
						return -1;
					}
					arg_struct_type = t;
					if((log == tru || precall == tru || postcall == tru))
					{
						a = 0;
						if(precall != fase)
							a |= ARGSPECOFPRECALLINTEREST;
						if(postcall == tru)
							a |= ARGSPECOFPOSTCALLINTEREST;
						if(t->basetype > 20)
							logPrintf("XML parse error: high base type %d\n", t->basetype);
						a |= t->basetype;
						if(!arg_spec)
						{
							arg_spec = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
							arg_spec->next_spec = NULL;
							hfstruct->arg = arg_spec;
						}
						else
						{
							arg_spec->next_spec = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
							arg_spec = arg_spec->next_spec;
							arg_spec->next_spec = NULL;
						}
						if(arg_struct_type)
							arg_spec->offset = t->offset;
						else
							arg_spec->offset = functionargument_index++;
						arg_spec->deref_type = (argtypep)a;
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
			}
			else if(wstrncmp(d, "return", 6) == 0)
			{
				//<return attributes...
				if(!functionname)
				{
					logPrintf("XML parse error: return element outside of function\n");
					return -1;
				}
				d += 6;
				whitespace(&d);
				l = strlen_0("return value");
				argname = (char *)malloc_0((l + 1) * sizeof(char));
				memcpy_0(argname, "return value", l * sizeof(char));
				argname[l] = 0x00;
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
				__debugbreak();
			}
		}
		else
			return 0;
		whitespace(&d);
	}
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
	char * str;
	int i;
	(*d)++;

	i = countto(*d, quote);
	if(**d == '1' || **d == 't' || **d == 'T')
	{
		(*d) += i + 1;
		(*d)++;		//endquote
		return tru;
	}
	else if(**d == '0' || **d == 'f' || **d == 'F')
	{
		(*d) += i + 1;
		(*d)++;		//endquote
		return fase;
	}
	logPrintf("XML parse error: bad boolean, assuming true\n");
	(*d) += i + 1;
	(*d)++;		//endquote
	return tru;
}


