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
#ifndef uint32_t
#include <inttypes.h>
#endif //!uint32_t

#include <stdio.h>

typedef uint32_t ADDRESS;
typedef uint64_t ADDRESS64;

typedef enum enum_binaryformat
{
	elf32, elf64,
	pe, pe64,
	universal_macho,
	raw		//no format
} enum_binaryformat;

#define SECTION_IN_MEMORY				0x00000001
#define SECTION_NOT_IN_FILE				0x00000002
#define SECTION_DONT_DRAW				0x00000004
#define SECTION_IMPORTED				0x00000008
#define SECTION_CODE					0x00000100
#define SECTION_DATA					0x00000200
#define SECTION_RUN_IN_FILE				0x10000000

void OverridingLibraryLoader(char * libraryname, bool query=false);
void cleanupLibraryLoader(void);
void addImportPath(char * path);
void * GetOverridingProcAddress(char * libraryname, char * functionname);
void renameByExportName(char * libraryname);

//helper routines
#define PRINTARG64(x)	((uint32_t *)&x)[1], ((uint32_t *)&x)[0]

int parse_file_format(struct file * file);
void cleanupFile(struct file * file);
struct section * add_section(struct file * file, ADDRESS addr, unsigned long size, unsigned long contiguous_size, char allocate, char * name);
struct section * add_section64(struct file * file, ADDRESS64 addr, unsigned long size, unsigned long contiguous_size, char allocate, char * name);
int rebase(char * image_base, char * code, unsigned int size);
char * get_symbol_from_filedata(char * data, unsigned int size, char * name, bool image_based);
char * get_image_base(char * data);
int get_next_section(char * data, char ** v, char ** d, unsigned int * z);

extern struct file ** librarylist;
extern unsigned int libraries;

struct name_ {
	char * name;	//dont free
	ADDRESS offset;
};

struct section {
	char * name;
	unsigned long fileoffset;
	char * data;

	unsigned long flags;
	ADDRESS address;
	ADDRESS64 address64;
	ADDRESS wantedAddress;				//expected from the file RVA + ImageBase
	ADDRESS64 wantedAddress64;			//expected from the file RVA + ImageBase
	unsigned int size;

	struct file * file;

	unsigned long names;
	unsigned long namelistsize;
	struct name_ * namelist;

	int windows;
	struct window ** windowlist;
	bool section64;
};

struct file {
	char * path;
	char * name;
	FILE * fp;
	unsigned int filesize;
	unsigned char * data;
	enum_binaryformat format;
	uint16_t characteristics;

	unsigned int sections;
	struct section * sectionlist;

	ADDRESS entry_address;
	ADDRESS virtual_base;
	ADDRESS image_base;

	ADDRESS64 entry_address64;
	ADDRESS64 virtual_base64;
	ADDRESS64 image_base64;

	unsigned int exports;
	ADDRESS * export_addresses;
	unsigned char ** export_names;
	char * exportfilename;

	unsigned int imports;
	struct file ** importlist;
	struct file * importedby;

	struct emuctx * emuctx;
	bool may_not_not_be_executable;
};
