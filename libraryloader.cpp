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

/* This was originally from library loading code from another project I wrote a while ago for linux, 
 * mac os X and windows, and I co-opted it to use it here. But there's a lot of cruft and the nature
 * of this project is somewhat exploratory, so it's not really written all that well and there a lot
 * of similar duplicate procedures.  And of course, objects aren't really necessary here.  But perhaps
 * if I cleaned it up later... */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include "libraryloader.h"
#include "winnt.h"

char * DataDirectoryString[] =
{
	"Export table",
	"Import table",
	"Resource table",
	"Exception table",
	"Certificate table"
	"Base relocation table",
	"Debugging information",
	"Architecture-specific",
	"Global pointer",
	"Thread Local Storage",
	"Load configuration",
	"Bound import",
	"Import address",
	"Delay import",
	"The CLR Header",
	"Reserved"
};

#define ASSERT(x) \
		if(!x) { fprintf(stderr, "assert failure at %s: %s\t%s\n", __FILE__, __LINE__, "__func__"); exit(-1); }

char ** importpathlist = NULL;
unsigned int importpaths = 0;

struct file ** librarylist = NULL;
unsigned int libraries = 0;

void addLoadedLibrary(struct file * file);
//void cleanupFile(struct file * file);
int fill_file_struct(char * path, struct file ** file);
struct file * get_fake_file(unsigned char * data, unsigned int size);
char * get_ptr_to_simple_name(char * path);
uint64_t add64bit(uint64_t a, uint64_t b);
//int parse_file_format(struct file * file);
void get_entry_addresses(struct file * file);
void get_entry_addresses64(struct file * file);
char * get_pe_data_from_rva(struct file * file, DWORD rva);
char * get_pe_data_from_rva64(struct file * file, DWORD rva);
void load_imports(struct file * file);
void load_imports64(struct file * file);
int load_additional_file(struct file * file, char * path);
void resolve_imports(struct file * file);
void resolve_imports64(struct file * file);
uint32_t find_address_in_loaded_file(struct file * file, ADDRESS addr);
uint64_t find_address_in_loaded_file64(struct file * file, ADDRESS64 addr);
//struct section * add_section(struct file * file, ADDRESS addr, unsigned long size, unsigned long contiguous_size, char allocate, char * name);
//struct section * add_section64(struct file * file, ADDRESS64 addr, unsigned long size, unsigned long contiguous_size, char allocate, char * name);
struct file * getFileByName(char * libraryname);
struct file * get_loaded_file_from_name(struct file * loadingfile, char * name);
ADDRESS import_symbol_lookup(struct file * file, unsigned char * name);
ADDRESS64 import_symbol_lookup64(struct file * file, unsigned char * name);
void basic_section_init(struct section * section);
void rebase_sections(struct file * file);
void do_relocations(struct file * file);
void do_relocations_for_file32(struct file * inmemfile, struct file * file);
void do_relocations_for_file64(struct file * inmemfile, struct file * file);
char * lazy_in_place_rva_to_offset32(char * data, char * rva);
char * lazy_in_place_rva_to_offset64(char * data, char * rva);

/* Issue... what if there's a mix of 32 and 64 bit files... that they import here and there...
 * pretty sure this needs to be restructured for that... otherwise it will use the wrong load
 * or resolve or get entry FIXME */
void OverridingLibraryLoader(char * libraryname, bool query)
{
	struct file * file;

	if(fill_file_struct(libraryname, &file) != 0)
		return;

	switch(file->format)
	{
		case pe:
			if(query)
				get_entry_addresses(file);
			load_imports(file);
			resolve_imports(file);
			//FIXME... so turns out this is a mess... 
			//this is from back when I was writing this and compiling it as 32 bit... so... 
			//file->data is to the platform of this application which may or may not be pe 32
			//but if it's not, then we need to other things to get it to load, like transition between the
			//code... but that's all dependent on this being a 64 bit app so, etc., etc., FIXME
			//file->virtual_base = file->data;		//since we're executing it as loaded in memory...
			do_relocations(file);
			break;
		case pe64:
			if(query)
				get_entry_addresses64(file);
			load_imports64(file);
			resolve_imports64(file);
			file->virtual_base64 = (ULONGLONG)file->data;		//assuming 64 bit app...
			do_relocations(file);
			break;
		default:
			fprintf(stderr, "Unhandled file format\n");
			return;
			break;
	}

	addLoadedLibrary(file);
	return;
}

void cleanupLibraryLoader(void)
{
	unsigned int i, j;
	for(i = 0; i < libraries; i++)
	{
		for(j = 0; j < librarylist[i]->imports; j++)
			cleanupFile(librarylist[i]->importlist[j]);
		cleanupFile(librarylist[i]);
	}

	free(librarylist);
}

void cleanupFile(struct file * file)
{

	//unsigned int i;
	if(file->data);
		free(file->data);
	if(file->name)
		free(file->name);
	if(file->exportfilename)
		free(file->exportfilename);
	free(file->sectionlist);

	// free everything FIXME
}

void addImportPath(char * path)
{
	importpaths++;
	if(!importpathlist)
		importpathlist = (char **)calloc(importpaths, sizeof(char *));
	else
		importpathlist = (char **)realloc(importpathlist, importpaths * sizeof(char *));
	importpathlist[importpaths - 1] = (char *)calloc(1, strlen(path) + 1);
	strcpy(importpathlist[importpaths - 1], path);
}

void addLoadedLibrary(struct file * file)
{
	if(!libraries)
	{
		libraries = 1;
		librarylist = (struct file **)calloc(libraries, sizeof(struct file *));
		librarylist[0] = file;
	}
	else
	{
		libraries++;
		librarylist = (struct file **)realloc(librarylist, libraries * sizeof(struct file *));
		librarylist[libraries - 1] = file;
	}
}

int fill_file_struct(char * path, struct file ** file)
{
	struct stat buf;
	char * simplename;

	*file = NULL;

	if(stat(path, &buf) != 0)
	{
		switch(errno)
		{
		case EACCES:
			//throwErrorDialog("File Error", "No permission to see %s", path);
			fprintf(stderr, "No permission to open \"%s\"\n", path);
			return -1;
		case ENOENT:
			//throwErrorDialog("File Error", "File \"%s\" does not exist", path);
			fprintf(stderr, "File \"%s\" does not exist\n", path);
			return -1;
		case ENOMEM:
			//throwErrorDialog("File Error", "Out of memory");
			fprintf(stderr, "Out of memory, can't open file\n");
			return -1;
		default:
			//throwErrorDialog("File Error", "Unknown error -%d", errno);
			fprintf(stderr, "Can't open file, unknown errno %d\n", errno);
			return -1;
		}
	}
	if(!buf.st_size)
	{
		//throwErrorDialog("File Error", "Can't open 0 length file");
		fprintf(stderr, "Can't open 0 length file\n");
		return -1;
	}

	*file = (struct file *)calloc(1, sizeof(struct file));
	(*file)->fp = fopen(path, "rb");
	if(!(*file)->fp)
	{
		switch(errno)
		{
		case EACCES:
			//throwErrorDialog("File Error", "No permission to read %s", path);
			fprintf(stderr, "No permission to open \"%s\"\n", path);
			return -1;
		default:
			//throwErrorDialog("File Error", "Unknown error -%d", errno);
			fprintf(stderr, "Can't open file, unknown errno %d\n", errno);
			break;
		}
		free(*file);
		return -1;
	}

	(*file)->path = (char *)calloc(strlen(path) + 1, sizeof(char));
	strcpy((*file)->path, path);
	(*file)->filesize = buf.st_size;

	simplename = get_ptr_to_simple_name(path);
	(*file)->name = (char *)calloc(strlen(simplename) + 1, 1);
	strcpy((*file)->name, simplename);

	/* Hope its not too slow with large files to open it here.  It makes
	* the error dialogs, etc., easier */
	(*file)->data = (unsigned char *)calloc((*file)->filesize, sizeof(unsigned char));

	fread((*file)->data, (*file)->filesize, sizeof(unsigned char), (*file)->fp);

	fclose((*file)->fp);

	if(parse_file_format(*file) != 0)
	{
		free((*file)->path);
		free((*file)->name);
		free((*file)->data);
		fclose((*file)->fp);
		free(*file);
		return -1;
	}

	return 0;
}

char * get_ptr_to_simple_name(char * path)
{
	int i;

	for(i = strlen(path); i > 0; i--)
	{
		if(path[i] == '/')
			break;
	}
	if(path[i] == '/')
		i++;
	return &(path[i]);
}

uint64_t add64bit(uint64_t a, uint64_t b)
{
	uint64_t c;
	uint32_t * c32 = (uint32_t *)&c;
	uint32_t * b32 = (uint32_t *)&b;
	uint32_t * a32 = (uint32_t *)&a;

	c32[1] = a32[1] + b32[1];
	//printf("%08x%08x %08x%08x\n", b32[1], b32[0], a32[1], a32[0]);
	c32[0] = a32[0] + b32[0];
	if(c32[0] < a32[0] + b32[0])
		c32[1] += 1;
	//printf("%08x%08x %08x%08x\n", c32[1], c32[0], a32[1], a32[0]);
	return c;
}

int parse_file_format(struct file * file)
{
	unsigned int i;

	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader = NULL;
	IMAGE_NT_HEADERS64 * pe64header = NULL;
	IMAGE_SECTION_HEADER * section;


	struct section tempsection;
	int swapped;
	int format_recognized = 0;


	if(file->data[0] == 'M' && file->data[1] == 'Z')
	{
		dosheader = (IMAGE_DOS_HEADER *)file->data;
		peheader = (IMAGE_NT_HEADERS32 *)(file->data + dosheader->e_lfanew);
		if(peheader->Signature != 0x00004550)
			return -1;
		file->characteristics = peheader->FileHeader.Characteristics;
		if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		{
			file->format = pe;
			format_recognized = 1;
		}
		else if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
		{
			fprintf(stderr, "Itanium Machine Type Unsupported\n");
			return -1;
		}
		else if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		{
			file->format = pe64;
			format_recognized = 1;
			pe64header = (IMAGE_NT_HEADERS64 *)peheader;
			peheader = NULL;
		}
		else
		{
			fprintf(stderr, "Unrecognized PE Machine Type: %04x\n", peheader->FileHeader.Machine);
			return -1;
		}
		
		if(file->format == pe)
		{
			printf("Image Base: %8x\n", peheader->OptionalHeader.ImageBase);
			file->image_base = peheader->OptionalHeader.ImageBase;

			file->entry_address = peheader->OptionalHeader.AddressOfEntryPoint + peheader->OptionalHeader.ImageBase;
			printf("Entry: %8x\n", file->entry_address);
			file->sections = peheader->FileHeader.NumberOfSections;
			file->sectionlist = (struct section *)calloc(file->sections, sizeof(struct section));

			//0x18 is sizeof(IMAGE_NT_HEADERS) except its not ?!?
//#ifdef X64
			section = (IMAGE_SECTION_HEADER *)(peheader->FileHeader.SizeOfOptionalHeader + (char *)peheader + 0x18);//IMAGE_FIRST_SECTION(peheader);

			for(i = 0; i < file->sections; i++)		//off by one?
			{
				printf("section: %s %08x size %d", section->Name, section->VirtualAddress, section->SizeOfRawData);
				file->sectionlist[i].name = (char *)calloc(strlen((char *)section->Name) + 1, sizeof(char));
				strcpy(file->sectionlist[i].name, (char *)section->Name);

				file->sectionlist[i].size = section->SizeOfRawData;
				file->sectionlist[i].fileoffset = section->PointerToRawData;
				file->sectionlist[i].data = (char *)&file->data[section->PointerToRawData];
				printf(" [%08x]\n", file->sectionlist[i].data);
				file->sectionlist[i].file = file;
				basic_section_init(&file->sectionlist[i]);
				/* FIXME we should check which sections are loaded into memory and which are not
				 * to make the VirtualProtect calls accurate */
				if(section->Characteristics & IMAGE_SCN_LNK_REMOVE)		//not sure
					file->sectionlist[i].flags = 0;
				else if(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)		//for .reloc
					file->sectionlist[i].flags = 0;									//otherwise we end up trying to patch the wrong file with an imported reloc table
				else
					file->sectionlist[i].flags = SECTION_IN_MEMORY | SECTION_CODE;	//SECTION_CODE for now
				file->sectionlist[i].address = section->VirtualAddress + peheader->OptionalHeader.ImageBase;
				file->sectionlist[i].wantedAddress = file->sectionlist[i].address;

				section++;
			}

			printf("import: %08x %08x\n", peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
				peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
			printf("iat: %08x %08x\n", peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress,
				peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
		}
		else if(file->format == pe64)
		{
			printf("Image Base: %08x%08x\n", PRINTARG64(pe64header->OptionalHeader.ImageBase));
			file->image_base64 = pe64header->OptionalHeader.ImageBase;
			
			file->entry_address64 = add64bit(pe64header->OptionalHeader.AddressOfEntryPoint, pe64header->OptionalHeader.ImageBase);
			printf("Entry: %08x%08x\n", PRINTARG64(file->entry_address64));
			file->sections = pe64header->FileHeader.NumberOfSections;
			file->sectionlist = (struct section *)calloc(file->sections, sizeof(struct section));

			//0x18 is sizeof(IMAGE_NT_HEADERS) except its not ?!?
//#ifdef X64
			section = (IMAGE_SECTION_HEADER *)(pe64header->FileHeader.SizeOfOptionalHeader + (char *)pe64header + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader));//IMAGE_FIRST_SECTION(peheader);
	
			printf("Sections: %d\n", file->sections);
			for(i = 0; i < file->sections; i++)		//off by one?
			{
				printf("section: %s %08x size %08x\n", section->Name, section->VirtualAddress, section->SizeOfRawData);
				file->sectionlist[i].name = (char *)calloc(strlen((char *)section->Name) + 1, sizeof(char));
				strcpy(file->sectionlist[i].name, (char *)section->Name);

				file->sectionlist[i].size = section->SizeOfRawData;
				file->sectionlist[i].fileoffset = section->PointerToRawData;
				file->sectionlist[i].data = (char *)&file->data[section->PointerToRawData];
				file->sectionlist[i].file = file;
				basic_section_init(&file->sectionlist[i]);
				//.reloc are IMAGE_SCN_MEM_DISCARDABLE
				if(section->Characteristics & IMAGE_SCN_LNK_REMOVE)		//not sure
					file->sectionlist[i].flags = 0;
				else
					file->sectionlist[i].flags = SECTION_IN_MEMORY | SECTION_CODE;	//SECTION_CODE for now
				file->sectionlist[i].address64 = section->VirtualAddress + pe64header->OptionalHeader.ImageBase;
				file->sectionlist[i].wantedAddress64 = file->sectionlist[i].address64;
				//wantedAddress FIXME 64
				printf("\t:%08x%08x %08x\n", PRINTARG64(file->sectionlist[i].address64), file->sectionlist[i].size);
				section++;
			}

			printf("import: %08x %08x\n", pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
				pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
			printf("iat: %08x %08x\n", pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress,
				pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
		}
	}

	if(!format_recognized)
	{
		fprintf(stderr, "File format not recognized\n");
		return -1;
	}

	//ensure, whatever the format, the sections are consecutive in memory
	//this is so add_section can check and insert easily
	if(file->image_base64 == 0)
	{
		do
		{
			swapped = 0;
			for(i = 0; i < file->sections - 1; i++)
			{
				if(!(file->sectionlist[i].flags & SECTION_IN_MEMORY))
					continue;
				if(file->sectionlist[i].address > file->sectionlist[i + 1].address)
				{
					tempsection = file->sectionlist[i];
					file->sectionlist[i] = file->sectionlist[i + 1];
					file->sectionlist[i + 1] = tempsection;
					swapped = 1;
				}
			}
		} while(swapped);
	}
	else
	{
		do
		{
			swapped = 0;
			for(i = 0; i < file->sections - 1; i++)
			{
				if(!(file->sectionlist[i].flags & SECTION_IN_MEMORY))
					continue;
				if(file->sectionlist[i].address64 > file->sectionlist[i + 1].address64)
				{
					tempsection = file->sectionlist[i];
					file->sectionlist[i] = file->sectionlist[i + 1];
					file->sectionlist[i + 1] = tempsection;
					swapped = 1;
				}
			}
		} while(swapped);
	}
	return 0;
}

#define PLACEHOLDER_FILENAME			"fakename"

struct file * get_fake_file(unsigned char * data, unsigned int size)
{
	struct file * file;

	file = (struct file *)calloc(1, sizeof(struct file));
	file->data = data;
	file->filesize = size;
	file->name = (char *)calloc(strlen(PLACEHOLDER_FILENAME) + 1, sizeof(char));
	strcpy(file->name, PLACEHOLDER_FILENAME);
	parse_file_format(file);

	return file;
}

void get_entry_addresses(struct file * file)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader;
	IMAGE_EXPORT_DIRECTORY * exportdir;
	DWORD * functionoffsets, * nameptr;
	WORD * ordinaltable;
	unsigned int i;
	char * exname;

	//to start with:
	//address_work_list_push(address_work_list, (ADDRESS)file->entry_address);

	dosheader = (IMAGE_DOS_HEADER *)file->data;
	peheader = (IMAGE_NT_HEADERS32 *)(file->data + dosheader->e_lfanew);

	exportdir = (IMAGE_EXPORT_DIRECTORY *)get_pe_data_from_rva(file, peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if(!exportdir)
	{
		printf("Error: can't find section referred to by export image directory\n"); return;
	}

	exname = get_pe_data_from_rva(file, exportdir->Name);
	if(!file->exportfilename && exname)
	{
		file->exportfilename = (char *)calloc(strlen(exname) + 1, sizeof(char));
		strcpy(file->exportfilename, exname);
	}
	printf("Export Name: %s\n", exname);
	functionoffsets = (DWORD *)get_pe_data_from_rva(file, exportdir->AddressOfFunctions);
	ordinaltable = (WORD *)get_pe_data_from_rva(file, exportdir->AddressOfNameOrdinals);
	nameptr = (DWORD *)get_pe_data_from_rva(file, exportdir->AddressOfNames);
	printf("Exports:\n");
	for(i = 0; i < exportdir->NumberOfFunctions; i++)
	{
		if(!ordinaltable)
		{
			printf("\t%d(-): *%08x (%08x)", i + exportdir->Base, functionoffsets[i], (functionoffsets[i] + peheader->OptionalHeader.ImageBase));
			if(nameptr && nameptr[i])
				printf(" %s\n", get_pe_data_from_rva(file, nameptr[i]));
			else
				printf("\n");
		}
		else if(ordinaltable[i] < exportdir->NumberOfFunctions && functionoffsets[ordinaltable[i]])
		{
			printf("\t%d(%d): %08x (%08x)", i + exportdir->Base, ordinaltable[i], functionoffsets[ordinaltable[i]], (functionoffsets[ordinaltable[i]] + peheader->OptionalHeader.ImageBase));
			if(nameptr && nameptr[i])
				printf(" %s\n", get_pe_data_from_rva(file, nameptr[i]));
			else
				printf("\n");
		}
		else
		{
			printf("\t%d(%d): *%08x (%08x)", i + exportdir->Base, ordinaltable[i], functionoffsets[i], (functionoffsets[i] + peheader->OptionalHeader.ImageBase));
			if(nameptr && nameptr[i])
				printf(" %s\n", get_pe_data_from_rva(file, nameptr[i]));
			else
				printf("\n");
		}
	}
}

void get_entry_addresses64(struct file * file)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS64 * pe64header;
	IMAGE_EXPORT_DIRECTORY * exportdir;
	DWORD * functionoffsets, * nameptr;
	WORD * ordinaltable;
	unsigned int i;
	ADDRESS64 offsetplusbase;
	char * exname;

	dosheader = (IMAGE_DOS_HEADER *)file->data;
	pe64header = (IMAGE_NT_HEADERS64 *)(file->data + dosheader->e_lfanew);

	exportdir = (IMAGE_EXPORT_DIRECTORY *)get_pe_data_from_rva64(file, pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if(!exportdir)
	{
		printf("Error: can't find section referred to by export image directory\n"); return;
	}

	for(i = 0; i < sizeof(IMAGE_EXPORT_DIRECTORY); i++)
		printf("%02x", ((unsigned char *)exportdir)[i]);
	printf("\n");

	exname = get_pe_data_from_rva64(file, exportdir->Name);
	if(!file->exportfilename && exname)
	{
		file->exportfilename = (char *)calloc(strlen(exname) + 1, sizeof(char));
		strcpy(file->exportfilename, exname);
	}

	printf("Export Name: %s\n", exname);
	functionoffsets = (DWORD *)get_pe_data_from_rva64(file, exportdir->AddressOfFunctions);
	ordinaltable = (WORD *)get_pe_data_from_rva64(file, exportdir->AddressOfNameOrdinals);
	nameptr = (DWORD *)get_pe_data_from_rva64(file, exportdir->AddressOfNames);
	printf("%p %p %p %d\n", functionoffsets, ordinaltable, nameptr, exportdir->NumberOfFunctions);
	printf("Exports:\n");
	for(i = 0; i < exportdir->NumberOfFunctions; i++)
	{
		if(!ordinaltable)
		{
			offsetplusbase = functionoffsets[i];
			offsetplusbase = add64bit(pe64header->OptionalHeader.ImageBase, offsetplusbase);
			printf("\t%d(-): *%08x (%08x%08x)", i + exportdir->Base, functionoffsets[i], PRINTARG64(offsetplusbase));
			if(nameptr && nameptr[i])
				printf(" %s\n", get_pe_data_from_rva64(file, nameptr[i]));
			else
				printf("\n");
		}
		else if(ordinaltable[i] < exportdir->NumberOfFunctions && functionoffsets[ordinaltable[i]])
		{
			offsetplusbase = functionoffsets[ordinaltable[i]];
			offsetplusbase = add64bit(pe64header->OptionalHeader.ImageBase, offsetplusbase);
			printf("\t%d(%d): %08x (%08x%08x) %s\n", i + exportdir->Base, ordinaltable[i], functionoffsets[ordinaltable[i]], PRINTARG64(offsetplusbase), get_pe_data_from_rva64(file, nameptr[i]));
			//address_work_list_push(address_work_list, (ADDRESS)(functionoffsets[i] + peheader->OptionalHeader.ImageBase));
		}
		else
		{
			offsetplusbase = functionoffsets[i];
			offsetplusbase = add64bit(pe64header->OptionalHeader.ImageBase, offsetplusbase);
			printf("\t%d(%d): *%08x (%08x%08x)", i + exportdir->Base, ordinaltable[i], functionoffsets[i], PRINTARG64(offsetplusbase));
			if(nameptr && nameptr[i])
				printf(" %s\n", get_pe_data_from_rva64(file, nameptr[i]));
			else
				printf("\n");
		}
	}
}

void renameByExportName(char * libraryname)
{
	struct file * file = getFileByName(libraryname);
	char * simplename = NULL;
	char * oldname;
	int i, j;
	int len;

	if(!file)
	{
		simplename = get_ptr_to_simple_name(libraryname);
		file = getFileByName(simplename);
	}
	if(file && file->exportfilename && strcmp(file->name, file->exportfilename) != 0)
	{
		/*len = strlen(file->path);
		for(i = 0; i < len - 1; i++)
		{
			if(file->path[i] == '/' && file->path[i + 1] == '/')
			{
				for(j = i + 1; j < len; j++)
					file->path[j] = file->path[j + 1];
			}
		}*/
		printf("PATH %s\n", file->path);
		printf("EXPORT %s\n", file->exportfilename);
		if(!simplename)
			simplename = get_ptr_to_simple_name(file->path);

		oldname = (char *)calloc(strlen(file->path) + 1, sizeof(char));
		strcpy(oldname, file->path);
		if(strlen(file->exportfilename) > strlen(simplename))
			file->path = (char *)realloc(file->path, strlen(file->path) - strlen(simplename) + strlen(file->exportfilename) + 1);
		sprintf(&(file->path[strlen(file->path) - strlen(simplename)]), "%s", file->exportfilename);

		if(rename(oldname, file->path) != 0)
			printf("Can't rename %d\n", errno);
		printf("renaming %s to %s\n", oldname, file->path);
		free(file->name);
		file->name = (char *)calloc(strlen(file->exportfilename) + 1, sizeof(char));
		strcpy(file->name, file->exportfilename);
	}
}

char * get_pe_data_from_rva(struct file * file, DWORD rva)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader;
	unsigned int i;

	dosheader = (IMAGE_DOS_HEADER *)file->data;
	peheader = (IMAGE_NT_HEADERS32 *)(file->data + dosheader->e_lfanew);

	for(i = 0; i < file->sections; i++)
	{
		if(rva >= file->sectionlist[i].wantedAddress - peheader->OptionalHeader.ImageBase &&
			rva < file->sectionlist[i].wantedAddress - peheader->OptionalHeader.ImageBase + file->sectionlist[i].size)
			break;
	}

	if(i == file->sections)
		return NULL;
	return (char *)&file->data[rva - (file->sectionlist[i].wantedAddress - peheader->OptionalHeader.ImageBase) + file->sectionlist[i].fileoffset];
}

//wantedAddress64 FIXME
char * get_pe_data_from_rva64(struct file * file, DWORD rva)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS64 * pe64header;
	unsigned int i;

	dosheader = (IMAGE_DOS_HEADER *)file->data;
	pe64header = (IMAGE_NT_HEADERS64 *)(file->data + dosheader->e_lfanew);

	for(i = 0; i < file->sections; i++)
	{
		if(rva >= file->sectionlist[i].address64 - pe64header->OptionalHeader.ImageBase &&
			rva < file->sectionlist[i].address64 - pe64header->OptionalHeader.ImageBase + file->sectionlist[i].size)
			break;
	}
	//printf("pe_data_from_rva64: %08x%08x (%08x%08x) %08x\n", PRINTARG64(file->sectionlist[i].address64),  PRINTARG64(pe64header->OptionalHeader.ImageBase), file->sectionlist[i].fileoffset);
	//printf("%08x - %08x + \n", rva, (file->sectionlist[i].address64 - pe64header->OptionalHeader.ImageBase));
	if(i == file->sections)
		return NULL;
	return (char *)&file->data[rva - (file->sectionlist[i].address64 - pe64header->OptionalHeader.ImageBase) + file->sectionlist[i].fileoffset];
}

void load_imports(struct file * file)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader;
	IMAGE_IMPORT_DESCRIPTOR * importdir;

	char * filename;
	unsigned int size;
	unsigned int i;
	struct file * importatfile;

	dosheader = (IMAGE_DOS_HEADER *)file->data;
	peheader = (IMAGE_NT_HEADERS32 *)(file->data + dosheader->e_lfanew);

	if(!peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		printf("No imports\n"); return;
	}
	importdir = (IMAGE_IMPORT_DESCRIPTOR *)get_pe_data_from_rva(file, peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if(!importdir)
	{
		printf("Error: can't find section referred to by import image directory\n"); return;
	}
	size = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	for(i = 0; i < size; i++)
	{
		if(!importdir[i].Characteristics)	//should be size - 1 anyway
			break;
		printf("%08x %08x %08x ", importdir[i].OriginalFirstThunk, importdir[i].Name, importdir[i].FirstThunk);
		filename = get_pe_data_from_rva(file, importdir[i].Name);
		printf("%s\n", filename);
		if(file->importedby)
			importatfile = file->importedby;
		else
			importatfile = file;
		load_additional_file(importatfile, filename);
	}

	//is this the place to do this?
	for(i = 0; i < file->imports; i++)
		load_imports(file->importlist[i]);
}

void load_imports64(struct file * file)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS64 * pe64header;
	IMAGE_IMPORT_DESCRIPTOR * importdir;

	char * filename;
	unsigned int size;
	unsigned int i;
	struct file * importatfile;

	dosheader = (IMAGE_DOS_HEADER *)file->data;
	pe64header = (IMAGE_NT_HEADERS64 *)(file->data + dosheader->e_lfanew);

	if(!pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		printf("No imports\n"); return;
	}
	importdir = (IMAGE_IMPORT_DESCRIPTOR *)get_pe_data_from_rva64(file, pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if(!importdir)
	{
		printf("Error: can't find section referred to by import image directory\n"); return;
	}
	size = pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	for(i = 0; i < size; i++)
	{
		if(!importdir[i].Characteristics)	//should be size - 1 anyway
			break;
		printf("%08x %08x %08x ", importdir[i].OriginalFirstThunk, importdir[i].Name, importdir[i].FirstThunk);
		filename = get_pe_data_from_rva64(file, importdir[i].Name);
		printf("%s\n", filename);
		if(file->importedby)
			importatfile = file->importedby;
		else
			importatfile = file;
		load_additional_file(importatfile, filename);
	}

	//is this the place to do this?
	for(i = 0; i < file->imports; i++)
		load_imports64(file->importlist[i]);
}

int load_additional_file(struct file * file, char * path)
{
	char * simplename;
	struct file * importfile;
	struct stat buf;
	char anotherpath[100];
	int i;
	unsigned int j;
	int trycase = 2;

	simplename = get_ptr_to_simple_name(path);
	
	for(i = 0; i < (int)file->imports; i++)
	{
		if(strcmp(file->importlist[i]->name, simplename) == 0)								//was strcasecmp
			return 0;		//don't load it twice
	}
	//check previously, separately loaded libraries:
	for(j = 0; j < libraries; j++)
	{
		if(strcmp(librarylist[j]->name, simplename) == 0)									//was strcasecmp
			return 0;		//don't load it twice
		for(i = 0; i < (int)librarylist[j]->imports; i++)
		{
			if(strcmp(librarylist[j]->importlist[i]->name, simplename) == 0)				//was strcasecmp
				return 0;		//don't load it twice
		}
	}
laf_casetryagain:
	i = -1;
	strcpy(anotherpath, path);
	while(stat(anotherpath, &buf) != 0 && ++i < (int)importpaths)
	{
		strcpy(anotherpath, importpathlist[i]);
		if(anotherpath[strlen(anotherpath) - 1] != '/')
		{
			anotherpath[strlen(anotherpath) + 1] = 0x00;
			anotherpath[strlen(anotherpath)] = '/';
		}
		strcpy(&(anotherpath[strlen(anotherpath)]), simplename);
	}

	if(i == (int)importpaths)
	{
		if((file->format == pe || file->format == pe64) && trycase)
		{
			if(isupper(simplename[0]) && islower(simplename[1]))
				trycase--;
			else
				trycase = 0;
			if(trycase)
				toupper(simplename[1]);
			if(islower(simplename[1]))
			{
				for(j = 0; j < strlen(simplename); j++)
					simplename[j] = toupper(simplename[j]);
			}
			else
			{
				for(j = 0; j < strlen(simplename); j++)
					simplename[j] = tolower(simplename[j]);
			}
			goto laf_casetryagain;
		}
		fprintf(stderr, "Can't find or open \"%s\"\n", path);
		return -1;
	}
	if(fill_file_struct(anotherpath, &importfile) < 0)
		return -1;
	file->imports++;
	file->importlist = (struct file **)realloc(file->importlist, file->imports * sizeof(struct file *));
	file->importlist[file->imports - 1] = importfile;
	importfile->importedby = file;
	if(importfile->importedby->format != importfile->format)
		fprintf(stderr, "WARNING format of imported file does not match importing file!\n");
	return 0;
}

//#define PRINT_SYMBOL_RESOLVES
/* What if two files wanted to load imports to the same address ?  we must check that... */
void resolve_imports(struct file * file)
{

	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader;
	IMAGE_IMPORT_DESCRIPTOR * importdir;
	DWORD * nametable, *addresstable;

	unsigned int i, k, n;
	int j;
	unsigned int size;
	struct section * importsection;
	struct section * importtext;
	struct file * f;
	ADDRESS symbol;
	char * name;
	char allocate;
	char * exportingfilename;
	struct file * exportingfile;

	if(!file->importedby)
		file->virtual_base = file->image_base;

	for(i = 0; i < file->imports; i++)
	{
		if(file->importlist[i]->format != file->format)
		{
			fprintf(stderr, "WARNING: skipping import with different file format\n");
			continue;
		}
		printf("Imported sections(x86): %s\n", file->importlist[i]->name);
		for(j = 0; j < (int)file->importlist[i]->sections; j++)
		{
			importtext = &(file->importlist[i]->sectionlist[j]);
			if(!(importtext->flags & SECTION_CODE) && !(importtext->flags & SECTION_DATA))
				continue;
			if(importtext->flags & SECTION_NOT_IN_FILE)
				allocate = 1;
			else
				allocate = 0;
			printf(":: %08x %08x\n", importtext->address, file->importlist[i]->virtual_base);
			if(!file->importlist[i]->virtual_base)
			{
				importsection = add_section(file, importtext->address, importtext->size,
					file->importlist[i]->filesize, allocate, importtext->name);
				if(!importsection)
					return;
				file->importlist[i]->virtual_base = importsection->address - (importtext->address - file->importlist[i]->image_base);
			}
			else
				importsection = add_section(file, file->importlist[i]->virtual_base + (importtext->address - file->importlist[i]->image_base),
					importtext->size, 0, allocate, importtext->name);
			if(!importsection)
				return;
			importsection->size = importtext->size;
			/* This is so ugly, it should be done in add_section but whatever.  Yeah, we change the virtual_base above so we can't
			 * use it after the first section for the original wantedAddress, may as well not even set it in add_section*/
			importsection->wantedAddress = importtext->address;
			//FIXME I have no clue anymore, I just don't care... what about wantedAddress64 ?!?! FIXME
			/* fileoffset could be useful for later
			* also might just want to have a pointer back to the real section */
			importsection->fileoffset = importtext->fileoffset;
			importsection->data = importtext->data;
			importsection->flags |= SECTION_IMPORTED;
			importsection->file = file->importlist[i];
			//importsection->flags = SECTION_IN_MEMORY | SECTION_IMPORTED;
			printf("\t%08x %08x (%08x) %s\n", importsection->address, importtext->fileoffset, importsection->size, importsection->name);
		}
	}

	f = NULL;
	for(j = 0; j < (int)file->imports; j++)
	{
		if(!f)
		{
			f = file;
			j--;
		}
		else
			f = file->importlist[j];
		if(f->format != file->format)
		{
			// already reported the error
			continue;
		}
		printf("Resolving imports of %s...\n", f->name);

		dosheader = (IMAGE_DOS_HEADER *)f->data;
		peheader = (IMAGE_NT_HEADERS32 *)(f->data + dosheader->e_lfanew);

		if(!peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
			continue;
		importdir = (IMAGE_IMPORT_DESCRIPTOR *)get_pe_data_from_rva(f, peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if(!importdir)
		{
			fprintf(stderr, "Error: can't find section referred to by import image directory\n"); return;
		}

		size = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		for(i = 0; i < size; i++)
		{
			if(!importdir[i].Characteristics)	//should be size - 1 anyway
				break;
			exportingfilename = get_pe_data_from_rva(f, importdir[i].Name);
			exportingfile = get_loaded_file_from_name(f, exportingfilename);
			if(!exportingfile)
				continue;
			printf("From %s:\n\n", exportingfilename);
			nametable = (DWORD *)get_pe_data_from_rva(f, importdir[i].FirstThunk);
			addresstable = (DWORD *)get_pe_data_from_rva(f, importdir[i].OriginalFirstThunk);
			if(!addresstable || !nametable)
				continue;
			//print(info, "%s:\n", get_pe_data_from_rva(f, importdir[i].Name));
			k = 0;
			for(;;)
			{
				if(*nametable & 0x80000000)
				{
					printf("\t%04x\n", *nametable & 0xffff);
					symbol = import_symbol_lookup(exportingfile, (unsigned char *)(*nametable & 0xffff));
				}
				else
				{
					name = get_pe_data_from_rva(f, *nametable);
					if(!name)
						break;
					printf("\t%04x\t %s\n", *(unsigned short *)name, name + 2);
					symbol = 0;
					if(*(unsigned short *)name)
						symbol = import_symbol_lookup(exportingfile, (unsigned char *)(unsigned long)*(unsigned short *)name);
					if(!symbol)
						symbol = import_symbol_lookup(exportingfile, (unsigned char *)(name + 2));
				}
				/*for(n = 0; n < file->sections; n++)
				{
					printf("Section: %s %08x %08x\n", file->sectionlist[n].name, file->sectionlist[n].address, file->sectionlist[n].size);
					if(symbol > file->sectionlist[n].address && symbol < file->sectionlist[n].address + file->sectionlist[n].size)
					{
						if(file->sectionlist[n].file != file)
							printf("True SymbolF %08x\n", symbol - file->sectionlist[n].address - file->virtual_base);
						else
							printf("True Symbol %08x\n", symbol - file->virtual_base);
						break;
					}
				}
				if(n == file->sections)
					printf("Symbol %08x %s not loaded\n", symbol, name + 2);*/
				printf("Symbol %08x\n", symbol);
				if(!symbol)
						printf("Warning: NULL import symbol for %s\n", name + 2);
				else {}
				/*  *** Get symbol in file data *** */
					//memcpy(get_pe_data_from_rva(f, (DWORD)((DWORD *)importdir[i].FirstThunk) + k), get_pe_data_from_rva(exportingfile, symbol), sizeof(DWORD));
				ADDRESS tablefill =	(ADDRESS)get_pe_data_from_rva(f, (DWORD)(importdir[i].FirstThunk + (k * sizeof(DWORD))));
				printf("Writing to %08x %08x:\n", tablefill, get_pe_data_from_rva(exportingfile, symbol));
				fflush(stdout);
				*(uint32_t *)tablefill = (uint32_t)get_pe_data_from_rva(exportingfile, symbol);
				
				//printf("Writing to %08x\n", ((unsigned long)f->virtual_base) + ((unsigned long)(((DWORD *)importdir[i].FirstThunk) + k)));
				//write_memory(file->emuctx, ((unsigned long)f->virtual_base) + (unsigned long)(((DWORD *)importdir[i].FirstThunk) + k), symbol, 32);
				//memcpy((char *)((unsigned long)f->virtual_base) + (unsigned long)(((DWORD *)importdir[i].FirstThunk) + k), (char *)symbol, 32);
				//find_address_in_loaded_file(f, (unsigned long)(((DWORD *)importdir[i].FirstThunk) + k));
				addresstable++;
				nametable++;
				k++;
			}
		}
	}
}

void resolve_imports64(struct file * file)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS64 * pe64header;
	IMAGE_IMPORT_DESCRIPTOR * importdir;
	DWORD * nametable, *addresstable;

	unsigned int i, k;
	int j;
	unsigned int size;
	struct section * importsection;
	struct section * importtext;
	struct file * f;
	ADDRESS symbol;
	char * name;
	char allocate;

	if(!file->importedby)
		file->virtual_base64 = file->image_base64;

	for(i = 0; i < file->imports; i++)
	{
		if(file->importlist[i]->format != file->format)
		{
			fprintf(stderr, "WARNING: skipping import with different file format\n");
			continue;
		}
		printf("Imported sections(x64): %s\n", file->importlist[i]->name);
		for(j = 0; j < (int)file->importlist[i]->sections; j++)
		{
			importtext = &(file->importlist[i]->sectionlist[j]);
			if(!(importtext->flags & SECTION_CODE) && !(importtext->flags & SECTION_DATA))
				continue;
			if(importtext->flags & SECTION_NOT_IN_FILE)
				allocate = 1;
			else
				allocate = 0;
			printf("%08x%08x: %08x\n", PRINTARG64(file->importlist[i]->virtual_base64), importtext->address);
			if(!file->importlist[i]->virtual_base64)
			{
				importsection = add_section64(file, importtext->address64, importtext->size,
					file->importlist[i]->filesize, allocate, importtext->name);
				if(!importsection)
					return;
				file->importlist[i]->virtual_base64 = importsection->address64 - (importtext->address64 - file->importlist[i]->image_base);
			}
			else
				importsection = add_section64(file, file->importlist[i]->virtual_base64 + (importtext->address64 - file->importlist[i]->image_base),
					importtext->size, 0, allocate, importtext->name);
			if(!importsection)
				return;
			importsection->size = importtext->size;
			/* fileoffset could be useful for later
			* also might just want to have a pointer back to the real section */
			importsection->fileoffset = importtext->fileoffset;
			importsection->data = importtext->data;
			importsection->flags |= SECTION_IMPORTED;
			importsection->file = file->importlist[i];
			//importsection->flags = SECTION_IN_MEMORY | SECTION_IMPORTED;
			printf("\t%08x%08x %08x (%08x) %s\n", PRINTARG64(importsection->address64), importtext->fileoffset, importsection->size, importsection->name);
		}
	}

	f = NULL;
	for(j = 0; j < (int)file->imports; j++)
	{
		if(!f)
		{
			f = file;
			j--;
		}
		else
			f = file->importlist[j];
		if(f->format != file->format)
		{
			// already reported the error
			continue;
		}
		printf("Resolving imports of %s...\n", f->name);

		dosheader = (IMAGE_DOS_HEADER *)f->data;
		pe64header = (IMAGE_NT_HEADERS64 *)(f->data + dosheader->e_lfanew);

		if(!pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
			continue;
		importdir = (IMAGE_IMPORT_DESCRIPTOR *)get_pe_data_from_rva64(f, pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if(!importdir)
		{
			fprintf(stderr, "Error: can't find section referred to by import image directory\n"); return;
		}

		size = pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		printf("data directory size %d\n", size);
		for(i = 0; i < size; i++)
		{
			if(!importdir[i].Characteristics)	//should be size - 1 anyway
				break;
			printf("tot %p %p\n", importdir[i].FirstThunk, importdir[i].OriginalFirstThunk);
			nametable = (DWORD *)get_pe_data_from_rva64(f, importdir[i].FirstThunk);
			addresstable = (DWORD *)get_pe_data_from_rva64(f, importdir[i].OriginalFirstThunk);
			printf("na %p %p\n", nametable, addresstable);
			if(!addresstable || !nametable)
				continue;
			printf("%s:\n", get_pe_data_from_rva64(f, importdir[i].Name));
			k = 0;
			for(;;)
			{
				if(*nametable & 0x80000000)
				{
					printf("\t%04x\n", *nametable & 0xffff);
					symbol = import_symbol_lookup64(file, (unsigned char *)(*nametable & 0xffff));
				}
				else
				{
					name = get_pe_data_from_rva64(f, *nametable);
					printf("returned name: %p\n", name);
					if(!name)
						break;
					printf("\t%04x\t %s\n", *(unsigned short *)name, name + 2);
					symbol = 0;
					if(*(unsigned short *)name)
						symbol = import_symbol_lookup64(file, (unsigned char *)(unsigned long)*(unsigned short *)name);
					if(!symbol)
						symbol = import_symbol_lookup64(file, (unsigned char *)(name + 2));
				}
				printf("Symbol %08x%08x\n", PRINTARG64(symbol));
				printf("Writing to %08x\n", ((unsigned long)f->virtual_base64) + ((unsigned long)(((uint64_t *)importdir[i].FirstThunk) + k)));
				//write_memory(file->emuctx, ((unsigned long)f->virtual_base) + (unsigned long)(((DWORD *)importdir[i].FirstThunk) + k), symbol, 32);
				//memcpy((char *)((unsigned long)f->virtual_base) + (unsigned long)(((DWORD *)importdir[i].FirstThunk) + k), (char *)symbol, 32);
				find_address_in_loaded_file64(f, (unsigned long)(((DWORD *)importdir[i].FirstThunk) + k));			//64 FIXME ?
				//memcpy((char *)find_address_in_loaded_file64(f, (unsigned long)(((uint64_t *)importdir[i].FirstThunk) + k)), (char *)symbol, 64);
				addresstable++;
				addresstable++;		//64?
				nametable++;
				nametable++;		//64?
				k++;
			}
		}
	}
}

uint32_t find_address_in_loaded_file(struct file * file, ADDRESS addr)
{
	unsigned int i, section_index;

	for(i = 0; i < file->sections; i++)
	{
		if(!(file->sectionlist[i].flags & SECTION_IN_MEMORY))
			continue;
		printf("find_in_file: %08x (%08x)\n", file->sectionlist[i].address, addr);
		printf("%08x %p\n", (addr - file->sectionlist[i].address), file->sectionlist[i].data);

		if(addr >= file->sectionlist[i].address &&
			(addr - file->sectionlist[i].address) < file->sectionlist[i].size)
		{
			section_index = i;
			break;
		}
		if(addr < file->sectionlist[i].address)
		{
			i = file->sections; break;
		}
	}

	if(i == file->sections)
		return NULL;

	//if(nametag)
	//	lookup_name(&file->sectionlist[i], addr, nametag);
	printf("find_in_file: %08x (%08x)\n", file->sectionlist[section_index].address, addr);
	printf("%08x\n", (addr - file->sectionlist[section_index].address));
	if(1) return NULL;
	return (uint32_t)(addr - file->sectionlist[section_index].address) + (unsigned long)file->sectionlist[section_index].data;
}

uint64_t find_address_in_loaded_file64(struct file * file, ADDRESS64 addr)
{
	unsigned int i, section_index;
	
	for(i = 0; i < file->sections; i++)
	{
		if(!(file->sectionlist[i].flags & SECTION_IN_MEMORY))
			continue;
		printf("find_in_file: %08x%08x (%08x%08x)\n", PRINTARG64(file->sectionlist[i].address64), PRINTARG64(addr));
		printf("%08x %p\n", (addr - file->sectionlist[i].address64), file->sectionlist[i].data);

		if(addr >= file->sectionlist[i].address64 &&
			(addr - file->sectionlist[i].address64) < file->sectionlist[i].size)
		{
			section_index = i;
			break;
		}
		if(addr < file->sectionlist[i].address)
		{
			i = file->sections; break;
		}
	}

	if(i == file->sections)
		return NULL;

	//if(nametag)
	//	lookup_name(&file->sectionlist[i], addr, nametag);
	printf("find_in_file: %08x%08x (%08x%08x)\n", PRINTARG64(file->sectionlist[section_index].address64), PRINTARG64(addr));
	printf("%08x\n", (addr - file->sectionlist[section_index].address64));
	if(1) return NULL;
	return (uint64_t)(addr - file->sectionlist[section_index].address64) + (unsigned long)file->sectionlist[section_index].data;
}

struct section * add_section(struct file * file, ADDRESS addr, unsigned long size, unsigned long contiguous_size, char allocate, char * name)
{
	struct section * section;
	unsigned int i, j;
	ADDRESS sectionend;
	unsigned long thissize;

	if(contiguous_size)
	{
		thissize = size;
		size = contiguous_size;
	}
	i = 0;
	if(addr + size <= file->sectionlist[0].address)			//fit it in at the beginning
		goto as_go;
	for(i = 0; i < file->sections; i++)
	{
		if(addr >= file->sectionlist[i].address + file->sectionlist[i].size &&
			(i == file->sections - 1 || addr + size <= file->sectionlist[i + 1].address))
			break;
	}

	if(i == file->sections && i != 0)
	{
		printf("Can't use address %08x, finding another\n", addr);
		for(i = 0; i < file->sections; i++)
		{
			printf("\t%08x %08x\n", file->sectionlist[i].address, file->sectionlist[i].size);
			sectionend = file->sectionlist[i].address + file->sectionlist[i].size;
			if(sectionend & 0xffff)
				sectionend = (sectionend & 0xffff0000) + 0x10000;
			if(sectionend > 0x0010000 &&
				(i == file->sections - 1 || sectionend + size <= file->sectionlist[i + 1].address))
			{
				addr = sectionend;
				break;
			}
		}
	}
as_go:
	if(contiguous_size)
		size = thissize;

	if(i == file->sections && i != 0)			// ??? FIXME
	{
		fprintf(stderr, "ERROR: can't allocate section\n"); return 0;
	}

	file->sections++;
	file->sectionlist = (struct section *)realloc(file->sectionlist, file->sections * sizeof(struct section));

	for(j = file->sections - 1; j > i + 1; j--)
		file->sectionlist[j] = file->sectionlist[j - 1];
	if(file->sections == 1)
		section = &file->sectionlist[0];
	else
		section = &(file->sectionlist[i + 1]);

	if(name)
	{
		section->name = (char *)calloc(strlen(name) + 1, 1);
		strcpy(section->name, name);
	}
	else
		section->name = NULL;
	section->flags = SECTION_IN_MEMORY | SECTION_NOT_IN_FILE | SECTION_DONT_DRAW;
	section->size = size;
	section->address = addr;
	section->wantedAddress = NULL;
	section->wantedAddress64 = NULL;
	section->file = NULL;
	printf("ADDING SECTION %08x %08x\n", addr, size);
	basic_section_init(section);
	if(allocate)
	{
		section->fileoffset = (unsigned long)malloc(size);
		section->data = (char *)section->fileoffset;
	}
	return section;
}

struct section * add_section64(struct file * file, ADDRESS64 addr, unsigned long size, unsigned long contiguous_size, char allocate, char * name)
{
	struct section * section;
	unsigned int i, j;
	ADDRESS64 sectionend;
	unsigned long thissize;

	if(contiguous_size)
	{
		thissize = size;
		size = contiguous_size;
	}
	i = 0;
	if(addr + size <= file->sectionlist[0].address64)			//fit it in at the beginning
		goto as64_go;
	for(i = 0; i < file->sections; i++)
	{
		if(addr >= file->sectionlist[i].address64 + file->sectionlist[i].size &&
			(i == file->sections - 1 || addr + size <= file->sectionlist[i + 1].address64))
			break;
	}

	if(i == file->sections && i != 0)
	{
		printf("Can't use address %08x%08x, finding another\n", PRINTARG64(addr));
		for(i = 0; i < file->sections; i++)
		{
			printf("\t%08x%08x %08x", PRINTARG64(file->sectionlist[i].address64), file->sectionlist[i].size);
			sectionend = file->sectionlist[i].address64 + file->sectionlist[i].size;
			printf(" %08x%08x\n", PRINTARG64(sectionend));
			if(sectionend & 0xffff)
				sectionend = (sectionend & 0xffffffffffff0000) + 0x10000;
			if(sectionend > 0x0010000 &&
				(i == file->sections - 1 || sectionend + size <= file->sectionlist[i + 1].address64))
			{
				addr = sectionend;
				break;
			}
		}
	}
as64_go:
	if(contiguous_size)
		size = thissize;

	if(i == file->sections && i != 0)
	{
		fprintf(stderr, "ERROR: can't allocate section\n"); return 0;
	}

	file->sections++;
	file->sectionlist = (struct section *)realloc(file->sectionlist, file->sections * sizeof(struct section));

	for(j = file->sections - 1; j > i + 1; j--)
		file->sectionlist[j] = file->sectionlist[j - 1];
	if(file->sections == 1)
		section = &file->sectionlist[0];
	else
		section = &(file->sectionlist[i + 1]);

	if(name)
	{
		section->name = (char *)calloc(strlen(name) + 1, 1);
		strcpy(section->name, name);
	}
	else
		section->name = NULL;
	section->flags = SECTION_IN_MEMORY | SECTION_NOT_IN_FILE | SECTION_DONT_DRAW;
	section->size = size;
	section->address64 = addr;
	section->file = NULL;

	printf("ADDING SECTION %08x%08x %08x\n", PRINTARG64(addr), size);
	basic_section_init(section);
	if(allocate)
	{
		section->fileoffset = (unsigned long)malloc(size);
		section->data = (char *)section->fileoffset;
	}
	return section;
}

struct file * getFileByName(char * libraryname)
{
	unsigned int i, j;
	for(j = 0; j < libraries; j++)
	{
		printf("%s\n", librarylist[j]->name);
		if(strcmp(librarylist[j]->name, libraryname) == 0)									//was strcasecmp
			return librarylist[j];
		for(i = 0; i < librarylist[j]->imports; i++)
		{
			printf("%s\n", librarylist[j]->importlist[i]->name);
			if(strcmp(librarylist[j]->importlist[i]->name, libraryname) == 0)				//was strcasecmp
				return librarylist[j]->importlist[i];
		}
	}
	return NULL;;
}

void * GetOverridingProcAddress(char * libraryname, char * functionname)
{
	
	struct file * importlibraryfile;
	ADDRESS import_symbol;

	importlibraryfile = getFileByName(libraryname);

	if(!importlibraryfile)
	{
		fprintf(stderr, "Can't find library %s\n", libraryname);
		return NULL;
	}

	import_symbol = import_symbol_lookup(importlibraryfile, (unsigned char *)functionname);
	return (void *)get_pe_data_from_rva(importlibraryfile, import_symbol);
}

struct file * get_loaded_file_from_name(struct file * loadingfile, char * name)
{
	unsigned int i;

	for(i = 0; i < loadingfile->imports; i++)
	{
		if(strcmp(name, loadingfile->importlist[i]->name) == 0)
			return loadingfile->importlist[i];
	}
	fprintf(stderr, "Can't find %s in loaded import files\n", name);
	return NULL;
}

/* It's assumed that we know the library the function is in... 
 * that may not be the fastest way to do this... */
ADDRESS import_symbol_lookup(struct file * file, unsigned char * name)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader;
	IMAGE_NT_HEADERS64 * pe64header;
	IMAGE_EXPORT_DIRECTORY * exportdir;
	DWORD * functionoffsets;
	DWORD * nameptr;
	WORD * ordinaltable;

	unsigned int j;

	if(!file)
		return NULL;

	if(!file->virtual_base)
	{
		fprintf(stderr, "Warning: import file %s has no virtual base, unused?\n", file->name);
		//return NULL;
	}
	dosheader = (IMAGE_DOS_HEADER *)file->data;
	peheader = (IMAGE_NT_HEADERS32 *)(file->data + dosheader->e_lfanew);

	exportdir = (IMAGE_EXPORT_DIRECTORY *)get_pe_data_from_rva(file, peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if(!exportdir)
	{
		fprintf(stderr, "can't find section referred to by export image directory\n");
		return NULL;
	}

	functionoffsets = (DWORD *)get_pe_data_from_rva(file, exportdir->AddressOfFunctions);
	ordinaltable = (WORD *)get_pe_data_from_rva(file, exportdir->AddressOfNameOrdinals);
	nameptr = (DWORD *)get_pe_data_from_rva(file, exportdir->AddressOfNames);

	printf("Name: %08x\n", name);				//maybe import name table "hint"
	if(name < (unsigned char *)0x10000)
		return NULL;
		//return functionoffsets[(unsigned long)name - exportdir->Base]/* + file->virtual_base*/;			//PROBABLY NOT FIXME
	else
		printf("Searching for %s...\n", name);
	for(j = 0; j < exportdir->NumberOfFunctions; j++)
	{
		if(functionoffsets[ordinaltable[j]])
		{
			if(j < exportdir->NumberOfNames)
			{
				//printf("%d %s %08x %04x\n", j, get_pe_data_from_rva(file, nameptr[j]), functionoffsets[ordinaltable[j]], ordinaltable[j]/*+ file->virtual_base*/);
				if(strcmp((char *)name, (char *)get_pe_data_from_rva(file, nameptr[j])) == 0)
					return functionoffsets[ordinaltable[j]];
			}
		}
	}

	fprintf(stderr, "Error: can't find symbol %s\n", name);
	return NULL;
}

/* May not quite need...  what is the symbol?  Maybe it's just an offset on the base not the virtual base? */
ADDRESS64 import_symbol_lookup64(struct file * file, unsigned char * name)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader;
	IMAGE_NT_HEADERS64 * pe64header;
	IMAGE_EXPORT_DIRECTORY * exportdir;
	DWORD * functionoffsets;
	DWORD * nameptr;

	unsigned int j;

	if(!file)
		return NULL;

	if(!file->virtual_base64)
	{
		fprintf(stderr, "Warning: import file %s has no virtual base, unused?\n", file->name);
		//return NULL;
	}
	dosheader = (IMAGE_DOS_HEADER *)file->data;
	pe64header = (IMAGE_NT_HEADERS64 *)(file->data + dosheader->e_lfanew);

	exportdir = (IMAGE_EXPORT_DIRECTORY *)get_pe_data_from_rva64(file, pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if(!exportdir)
	{
		fprintf(stderr, "Error: can't find section referred to by export image directory\n");
		return NULL;
	}

	functionoffsets = (DWORD *)get_pe_data_from_rva64(file, exportdir->AddressOfFunctions);
	nameptr = (DWORD *)get_pe_data_from_rva64(file, exportdir->AddressOfNames);
	printf("%08x %08x\n", name, exportdir->Base);
	if(name < (unsigned char *)0x10000)
		//return functionoffsets[(unsigned long)name - exportdir->Base] + file->virtual_base64;
		return add64bit(functionoffsets[(unsigned long)name - exportdir->Base], file->virtual_base64);
	for(j = 0; j < exportdir->NumberOfFunctions; j++)
	{
		if(functionoffsets[j])
		{
			if(j < exportdir->NumberOfNames)
			{
				uint64_t fuckyoutoo = add64bit(functionoffsets[j], file->virtual_base64);
				printf("FUCK YOU %s %08x%08x\n", get_pe_data_from_rva64(file, nameptr[j]), PRINTARG64(fuckyoutoo));
				if(strcmp((char *)name, (char *)get_pe_data_from_rva64(file, nameptr[j])) == 0)
					return add64bit(functionoffsets[j], file->virtual_base64);
			}
		}
	}

	fprintf(stderr, "Error: can't find symbol %s\n", name);
	return NULL;
}

void basic_section_init(struct section * section)
{
	section->names = 0;
	section->namelistsize = 0;
	section->namelist = NULL;
	section->windows = 0;
	section->windowlist = NULL;
}

#define IMAGE_REL_BASED_ABSOLUTE					0x0000
#define IMAGE_REL_BASED_HIGH						0x1000
#define IMAGE_REL_BASED_LOW							0x2000

#define IMAGE_REL_BASED_HIGHLOW						0x3000
#define IMAGE_REL_BASED_DIR64						0xa000

#define RELOCATION_DEBUG

/* We're calling this after a library and all it's dependency libraries have been loaded
 * and their symbols resolved */
void do_relocations(struct file * file)
{
	unsigned int l;

	//	return (char *)&file->data[rva - (file->sectionlist[i].address - peheader->OptionalHeader.ImageBase) + file->sectionlist[i].fileoffset];
	if(file->format == pe)
	{
		do_relocations_for_file32(file, file);
		for(l = 0; l < file->imports; l++)
			do_relocations_for_file32(file, file->importlist[l]);
	}
	else if(file->format == pe64)
	{
		do_relocations_for_file64(file, file);
		for(l = 0; l < file->imports; l++)
			do_relocations_for_file64(file, file->importlist[l]);
	}
	else
		fprintf(stderr, "relocations for unhandled file format!\n");
}

//so for instance inmemfile describes where the sections are in loaded memory, the rvas, etc., and the file is the import and reloc tables
void do_relocations_for_file32(struct file * inmemfile, struct file * file)
{
	unsigned int i, j, locsection, destsection;
	uint32_t blocksize, blockrva;
	uint32_t fixup;
	uint16_t w;
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader;
	uint32_t loc;
	uint32_t cumulative;
	uint32_t image_base;

#ifdef RELOCATION_DEBUG
	printf("FILENAME %s\n", file->name);
#endif //RELOCATION_DEBUG
	//for the origial import image base:
	dosheader = (IMAGE_DOS_HEADER *)file->data;
	peheader = (IMAGE_NT_HEADERS32 *)(file->data + dosheader->e_lfanew);
	for(i = 0; i < file->sections; i++)
	{
		if(strcmp(".reloc", file->sectionlist[i].name) == 0)
		{
			printf("Found relocation section...\n");
			fflush(stdout);
			fflush(stderr);
			j = 0;
			cumulative = 0;
			while(j < file->sectionlist[i].size)
			{
				blockrva = *(uint32_t *)&file->sectionlist[i].data[j];
				blocksize = *(uint32_t *)&file->sectionlist[i].data[j + 4];
#ifdef RELOCATION_DEBUG
				printf("%08x %08x\n", blockrva, blocksize);
#endif //RELOCATION_DEBUG
				if(!blocksize)			//were done
				{
					j = file->sectionlist[i].size;
					break;
				}
				// main file loaded section should still retain the original wantedAddress
				for(locsection = 0; locsection < inmemfile->sections; locsection++)
				{
#ifdef RELOCATION_DEBUG
					printf("%08x %08x %08x\n", inmemfile->sectionlist[locsection].wantedAddress, inmemfile->sectionlist[locsection].wantedAddress + inmemfile->sectionlist[locsection].size, inmemfile->image_base);
#endif //RELOCATION_DEBUG
					if(blockrva + inmemfile->image_base >= inmemfile->sectionlist[locsection].wantedAddress &&
						blockrva + inmemfile->image_base < inmemfile->sectionlist[locsection].wantedAddress + inmemfile->sectionlist[locsection].size)
						break;
				}
				if(locsection == inmemfile->sections)
				{
					fprintf(stderr, "Can't find section for relocations %08x\n", blockrva);
					j += blocksize;
				}
				else
				{
					j += 8;			//past header
					for(; j < cumulative + blocksize; j += 2)
					{
						w = *(uint16_t *)&file->sectionlist[i].data[j];
						if((w & 0xf000) == IMAGE_REL_BASED_HIGHLOW)
						{
							loc = (w & 0xfff) + blockrva - (inmemfile->sectionlist[locsection].wantedAddress - inmemfile->image_base);
#ifdef RELOCATION_DEBUG
							printf("loc %08x\n", loc);
#endif //RELOCATION_DEBUG
							fixup = *(uint32_t *)&inmemfile->sectionlist[locsection].data[loc];
#ifdef RELOCATION_DEBUG
							printf("\t%08x to...\n", fixup);
#endif //RELOCATION_DEBUG
							//fixup -= (inmemfile->sectionlist[i].address - peheader->OptionalHeader.ImageBase);
							//fixup -= peheader->OptionalHeader.ImageBase;
							/*fixup -= inmemfile->sectionlist[k].wantedAddress;
							fixup += (uint32_t)inmemfile->sectionlist[k].data;*/

							for(destsection = 0; destsection < inmemfile->sections; destsection++)
							{
#ifdef RELOCATION_DEBUG
								printf("%08x %08x %08x\n", inmemfile->sectionlist[destsection].wantedAddress, inmemfile->sectionlist[destsection].wantedAddress + inmemfile->sectionlist[destsection].size, inmemfile->image_base);
#endif //RELOCATION_DEBUG
								if(fixup >= inmemfile->sectionlist[destsection].wantedAddress &&
									fixup < inmemfile->sectionlist[destsection].wantedAddress + inmemfile->sectionlist[destsection].size)
									break;
							}
							if(destsection == inmemfile->sections)
							{
								fprintf(stderr, "WARNING: Can't find address to fixup in loaded sections! %08x\n", fixup);
								//hope that memory is consecutive and that this is some kind of between loaded sections kernel trick...
								for(destsection = 0; destsection < inmemfile->sections; destsection++)
								{
									if(fixup > inmemfile->sectionlist[destsection].wantedAddress)
										break;
								}
							}
							if(destsection == inmemfile->sections)		//no way right?
								destsection--;
							fixup -= inmemfile->sectionlist[destsection].wantedAddress;
							//fixup += (uint32_t)inmemfile->sectionlist[n].data;		//i.e, the location in loaded memory this is running from... 
							fixup += (uint32_t)inmemfile->sectionlist[destsection].address;		//doublecheck that this points to loaded file data if we use this in 32 FIXME!!
#ifdef RELOCATION_DEBUG
							printf("...%08x\n", fixup);
							if(inmemfile->sectionlist[locsection].file)
								printf("-> %s + %08x\n", inmemfile->sectionlist[locsection].file->name, fixup - (uint32_t)inmemfile->sectionlist[destsection].address);
							else
								printf("-> + %08x\n", fixup - (uint32_t)inmemfile->sectionlist[destsection].address);
#endif //RELOCATION_DEBUG
							memcpy((uint32_t *)&(inmemfile->sectionlist[locsection].data[loc]), &fixup, sizeof(uint32_t));
						}
						else if(w == 0) {}			//end of relocation block
						else
							fprintf(stderr, "WARNING: Unknown relocation!!! %08x\n", w);
						fflush(stdout); fflush(stderr);
					}
				}
				cumulative += blocksize;
			}
		}
	}
fflush(stdout);
fflush(stderr);
}

/* FIXME we're not using the virtual_base which is what we should be using all over the place, but I feel lazier and lazier...
 * this is such a throw away project... I don't feel like, what, tracking down all the usages of the virtual base and changing
 * them and it's not like this is the other disassembler project nor like the overriding loader is going to work for anything...
 * oh fuck it... I really need it, I'll just do it and see what it breaks...  
 * shit.  the problem is that we didn't consistently use the file struct since it was a hold over from the disassembler setup.
 * so the wantedaddress, etc., stuff... it's not setup... the peheader image base probably should be changed when loaded
 * ... whatever, no idea if this works FIXME*/
void do_relocations_for_file64(struct file * inmemfile, struct file * file)
{
	unsigned int i, j, k, n;
	uint32_t blocksize, blockrva;
	uint64_t fixup;
	uint16_t w;
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS64 * pe64header;
	uint64_t loc;
	uint64_t cumulative;
	uint64_t image_base;
#ifdef RELOCATION_DEBUG
	uint64_t temp64;

	printf("FILENAME %s\n", file->name);
#endif //RELOCATION_DEBUG
	//for the origial import image base:
	dosheader = (IMAGE_DOS_HEADER *)file->data;
	pe64header = (IMAGE_NT_HEADERS64 *)(file->data + dosheader->e_lfanew);
	for(i = 0; i < file->sections; i++)
	{
		if(strcmp(".reloc", file->sectionlist[i].name) == 0)
		{
			printf("Found relocation section...\n");
			fflush(stdout);
			fflush(stderr);
			j = 0;
			cumulative = 0;
			while(j < file->sectionlist[i].size)
			{
				blockrva = *(uint32_t *)&file->sectionlist[i].data[j];
				blocksize = *(uint32_t *)&file->sectionlist[i].data[j + 4];
#ifdef RELOCATION_DEBUG
				printf("%08x %08x\n", blockrva, blocksize);
#endif //RELOCATION_DEBUG
				if(!blocksize)			//were done
				{
					j = file->sectionlist[i].size;
					break;
				}
				// main file loaded section should still retain the original wantedAddress
				for(k = 0; k < inmemfile->sections; k++)
				{
#ifdef RELOCATION_DEBUG
					temp64 = inmemfile->sectionlist[k].wantedAddress64 + inmemfile->sectionlist[k].size;
					printf("%08x%08x %08x%08x %08x%08x\n", PRINTARG64(inmemfile->sectionlist[k].wantedAddress64), PRINTARG64(temp64), PRINTARG64(file->image_base64));
#endif //RELOCATION_DEBUG
					if(blockrva + file->image_base64 >= inmemfile->sectionlist[k].wantedAddress64 &&
						blockrva + file->image_base64 < inmemfile->sectionlist[k].wantedAddress64 + inmemfile->sectionlist[k].size)
						break;
				}
				if(k == inmemfile->sections)
				{
					fprintf(stderr, "Can't find section for relocations %08x\n", blockrva);
					j += blocksize;
				}
				else
				{
					j += 8;			//past header
					for(; j < cumulative + blocksize; j += 2)
					{
						w = *(uint16_t *)&file->sectionlist[i].data[j];
						if((w & 0xf000) == IMAGE_REL_BASED_HIGHLOW)
						{
							printf("32bit relocation option in 64 bit PE?!?\n");
						}
						else if((w & 0xf000) == IMAGE_REL_BASED_DIR64)
						{
							loc = (w & 0xfff) + blockrva - (inmemfile->sectionlist[k].wantedAddress64 - file->image_base64);
#ifdef RELOCATION_DEBUG
							printf("loc %08x%08x\n", PRINTARG64(loc));
#endif //RELOCATION_DEBUG
							fixup = *(uint64_t *)&inmemfile->sectionlist[k].data[loc];
#ifdef RELOCATION_DEBUG
							printf("\t%08x%08x to...\n", PRINTARG64(fixup));
#endif //RELOCATION_DEBUG
							//fixup -= (inmemfile->sectionlist[i].address - peheader->OptionalHeader.ImageBase);
							//fixup -= peheader->OptionalHeader.ImageBase;
							/*fixup -= inmemfile->sectionlist[k].wantedAddress;
							fixup += (uint32_t)inmemfile->sectionlist[k].data;*/

							for(n = 0; n < inmemfile->sections; n++)
							{
#ifdef RELOCATION_DEBUG
								temp64 = inmemfile->sectionlist[n].wantedAddress64 + inmemfile->sectionlist[n].size;
								printf("%08x%08x %08x%08x %08x%08x\n", PRINTARG64(inmemfile->sectionlist[n].wantedAddress64), PRINTARG64(temp64), PRINTARG64(file->image_base64));
#endif //RELOCATION_DEBUG
								if(fixup >= inmemfile->sectionlist[n].wantedAddress64 &&
									fixup < inmemfile->sectionlist[n].wantedAddress64 + inmemfile->sectionlist[n].size)
									break;
							}
							if(n == inmemfile->sections)
							{
								fprintf(stderr, "WARNING: Can't find address to fixup in loaded sections! %08x\n", fixup);
								//hope that memory is consecutive and that this is some kind of between loaded sections kernel trick...
								for(n = 0; n < inmemfile->sections; n++)
								{
									if(fixup > inmemfile->sectionlist[n].wantedAddress64)
										break;
								}
							}
							if(n == inmemfile->sections)		//no way right?
								n--;
							fixup -= inmemfile->sectionlist[n].wantedAddress64;
							//fixup += (uint64_t)inmemfile->sectionlist[n].data;			//i.e, the location in loaded memory this is running from... 
							fixup += (uint64_t)inmemfile->sectionlist[n].address64;
#ifdef RELOCATION_DEBUG
							printf("...%08x%08x\n", PRINTARG64(fixup));
							temp64 = fixup - (uint64_t)inmemfile->sectionlist[n].address64;
							if(inmemfile->sectionlist[k].file)
								printf("-> %s + %08x%08x\n", inmemfile->sectionlist[k].file->name, PRINTARG64(temp64));
							else
								printf("-> + %08x%08x\n", PRINTARG64(temp64));
#endif //RELOCATION_DEBUG
							memcpy((uint64_t *)&(inmemfile->sectionlist[k].data[loc]), &fixup, sizeof(uint64_t));
						}
						else if(w == 0) {}			//end of relocation block
						else
							fprintf(stderr, "WARNING: Unknown relocation!!! %08x\n", w);
						fflush(stdout); fflush(stderr);
					}
				}
				cumulative += blocksize;
			}
		}
	}
	fflush(stdout);
	fflush(stderr);
}

/* this feels so silly, assuming any of this works at all, because it's so similar to now things I've written
 * three times with this... but it's like I don't there's a reason to use the struct file and set all that up
 * and it's a little different, the offsets are just to the file data, etc.. unless what... I want to use the
 * old stuff and add something to make it do it in place in file?  but the thing still has to kind of
 * fix it's own imports so... ugh.  it's so similar to find_address_in_loaded_file, etc.. I just feel like
 * it would take longer to think about the old stuff and fix it up or see how it's different than to just
 * rewrite it.  and then what on the library too... I could try to think about what would be useful on the
 * library... I'm just so tired.  */
/* anyway... a note on what I'm using this for:
 * this rebases to where the code will be loaded into memory... NOT where it is currently as loaded from a file. */
int rebase(char * image_base, char * code, unsigned int size)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader = NULL;
	IMAGE_NT_HEADERS64 * pe64header = NULL;
	IMAGE_SECTION_HEADER * section;
	IMAGE_EXPORT_DIRECTORY * exportdir = NULL;
	DWORD * functionoffsets, * nameptr;
	uint16_t * ordinaltable;
	int i;
	char * addr;
	struct file * file;

	struct section tempsection;
	int swapped;
	int format_recognized = 0;

	file = get_fake_file((unsigned char *)code, size);

	if(file)
	{
		dosheader = (IMAGE_DOS_HEADER *)code;
		peheader = (IMAGE_NT_HEADERS32 *)(code + dosheader->e_lfanew);
		if(peheader->Signature != 0x00004550)
			return -1;
		if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		{
		}
		else if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		{
			pe64header = (IMAGE_NT_HEADERS64 *)peheader;
			peheader = NULL;
		}
		else
		{
			fprintf(stderr, "Unrecognized PE Machine Type: %04x\n", peheader->FileHeader.Machine);
			return -1;
		}

		if(peheader)
		{
			file->image_base = peheader->OptionalHeader.ImageBase;
			peheader->OptionalHeader.ImageBase = (DWORD)image_base;
			file->virtual_base = (DWORD)image_base;
			printf("Rebasing %08x to %08x\n", file->image_base, image_base);
			rebase_sections(file);

			section = (IMAGE_SECTION_HEADER *)(peheader->FileHeader.SizeOfOptionalHeader + (char *)peheader + 0x18);//IMAGE_FIRST_SECTION(peheader);

			exportdir = (IMAGE_EXPORT_DIRECTORY *)lazy_in_place_rva_to_offset32(code, (char *)peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if(!exportdir)
				{ fprintf(stderr, "No export table\n"); return 0; }

			functionoffsets = (DWORD *)lazy_in_place_rva_to_offset32(code, (char *)exportdir->AddressOfFunctions);
			ordinaltable = (uint16_t *)lazy_in_place_rva_to_offset32(code, (char *)exportdir->AddressOfNameOrdinals);
			nameptr = (DWORD *)lazy_in_place_rva_to_offset32(code, (char *)exportdir->AddressOfNames);
			printf("Exports:\n");
			for(i = 0; i < exportdir->NumberOfFunctions; i++)
			{
				if(functionoffsets[i])
				{
					//not right since functionoffsets are relative to section rva not fileoffset of section...
					addr = (char *)(functionoffsets[i] + peheader->OptionalHeader.ImageBase);
					printf("\t%d: %08x (%08x)\n", i + exportdir->Base, functionoffsets[i], PRINTARG64(addr));
				}
			}

			do_relocations_for_file32(file, file);
		}
		else if(pe64header)
		{
			file->image_base64 = pe64header->OptionalHeader.ImageBase;
			pe64header->OptionalHeader.ImageBase = (ULONGLONG)image_base;
			file->virtual_base64 = (ULONGLONG)image_base;
			printf("Rebasing from %08x%08x to %08x%08x\n", PRINTARG64(file->image_base64), PRINTARG64(image_base));
			printf("Before Memory Write: %08x%08x\n", PRINTARG64(code));
			rebase_sections(file);

			section = (IMAGE_SECTION_HEADER *)(pe64header->FileHeader.SizeOfOptionalHeader + (char *)pe64header + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader));//IMAGE_FIRST_SECTION(peheader);
			printf("WTF %08x\n", pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			exportdir = (IMAGE_EXPORT_DIRECTORY *)lazy_in_place_rva_to_offset64(code, (char *)pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if(!exportdir)
				{ fprintf(stderr, "No export table\n"); return 0; }
			functionoffsets = (DWORD *)lazy_in_place_rva_to_offset64(code, (char *)exportdir->AddressOfFunctions);
			ordinaltable = (uint16_t *)lazy_in_place_rva_to_offset64(code, (char *)exportdir->AddressOfNameOrdinals);
			nameptr = (DWORD *)lazy_in_place_rva_to_offset64(code, (char *)exportdir->AddressOfNames);
			printf("Exports:\n");
			for(i = 0; i < exportdir->NumberOfFunctions; i++)
			{
				if(functionoffsets[i])
				{
					addr = (char *)(functionoffsets[i] + pe64header->OptionalHeader.ImageBase);
					//not right since functionoffsets are relative to section rva not fileoffset of section...
					printf("\t%d: %08x (%08x%08x)\n", i + exportdir->Base, functionoffsets[i], PRINTARG64(addr));
				}
			}
			do_relocations_for_file64(file, file);
		}

		file->data = NULL;		//don't free that data...
		cleanupFile(file);
	}
	return 0;
}

void rebase_sections(struct file * file)
{
	unsigned int i;

	for(i = 0; i < file->sections; i++)
	{
		if(file->format == pe)
		{
			file->sectionlist[i].address -= file->image_base;
			file->sectionlist[i].address += file->virtual_base;
		}
		else if(file->format == pe64)
		{
			file->sectionlist[i].address64 -= file->image_base64;
			file->sectionlist[i].address64 += file->virtual_base64;
		}
	}
}

char * get_symbol_from_filedata(char * data, unsigned int size, char * name, bool image_based)
{
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader = NULL;
	IMAGE_NT_HEADERS64 * pe64header = NULL;
	IMAGE_SECTION_HEADER * section;
	IMAGE_EXPORT_DIRECTORY * exportdir = NULL;
	char * orig_image_base;
	DWORD * functionoffsets, *nameptr;
	uint16_t * ordinaltable;
	int i;
	char * addr;

	struct section tempsection;
	int swapped;
	int format_recognized = 0;

	
	dosheader = (IMAGE_DOS_HEADER *)data;
	peheader = (IMAGE_NT_HEADERS32 *)(data + dosheader->e_lfanew);
		
	if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pe64header = (IMAGE_NT_HEADERS64 *)peheader;
		peheader = NULL;
	}
		
	if(peheader)
	{
		exportdir = (IMAGE_EXPORT_DIRECTORY *)lazy_in_place_rva_to_offset32(data, (char *)peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if(!exportdir)
			{ fprintf(stderr, "No export table\n"); return NULL; }
		functionoffsets = (DWORD *)lazy_in_place_rva_to_offset32(data, (char *)exportdir->AddressOfFunctions);
		ordinaltable = (uint16_t *)lazy_in_place_rva_to_offset32(data, (char *)exportdir->AddressOfNameOrdinals);
		nameptr = (DWORD *)lazy_in_place_rva_to_offset32(data, (char *)exportdir->AddressOfNames);

		for(i = 0; i < exportdir->NumberOfFunctions; i++)
		{
			if(functionoffsets[ordinaltable[i]])
			{
				if(i < exportdir->NumberOfNames)
				{
					//printf("%d %s %08x %04x\n", j, get_pe_data_from_rva(file, nameptr[j]), functionoffsets[ordinaltable[j]], ordinaltable[j]/*+ file->virtual_base*/);
					
					if(strcmp(name, (char *)lazy_in_place_rva_to_offset32(data, (char *)nameptr[i])) == 0)
					{
						if(image_based)
							return peheader->OptionalHeader.ImageBase + (char *)functionoffsets[ordinaltable[i]];
						else
							return lazy_in_place_rva_to_offset32(data, (char *)functionoffsets[ordinaltable[i]]);
					}
				}
			}
		}
	}
	else if(pe64header)
	{
		exportdir = (IMAGE_EXPORT_DIRECTORY *)lazy_in_place_rva_to_offset64(data, (char *)pe64header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if(!exportdir)
			{ fprintf(stderr, "No export table\n"); return NULL; }
		functionoffsets = (DWORD *)lazy_in_place_rva_to_offset64(data, (char *)exportdir->AddressOfFunctions);
		ordinaltable = (uint16_t *)lazy_in_place_rva_to_offset64(data, (char *)exportdir->AddressOfNameOrdinals);
		nameptr = (DWORD *)lazy_in_place_rva_to_offset64(data, (char *)exportdir->AddressOfNames);

		for(i = 0; i < exportdir->NumberOfFunctions; i++)
		{
				
			if(functionoffsets[ordinaltable[i]])
			{
				if(i < exportdir->NumberOfNames)
				{
					//printf("%d %s %08x %04x\n", j, get_pe_data_from_rva(file, nameptr[j]), functionoffsets[ordinaltable[j]], ordinaltable[j]/*+ file->virtual_base*/);
					if(strcmp(name, (char *)lazy_in_place_rva_to_offset64(data, (char *)nameptr[i])) == 0)
					{
						if(image_based)
							return pe64header->OptionalHeader.ImageBase + (char *)functionoffsets[ordinaltable[i]];
						else
							return lazy_in_place_rva_to_offset64(data, (char *)functionoffsets[ordinaltable[i]]);
					}
				}
			}
		}
	}
	fprintf(stderr, "Can't find export %s\n", name);

	return NULL;
}

char * lazy_in_place_rva_to_offset32(char * data, char * rva)
{
	IMAGE_SECTION_HEADER * section;
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader = NULL;
	int i;
	char * addr;

	dosheader = (IMAGE_DOS_HEADER *)data;
	peheader = (IMAGE_NT_HEADERS32 *)(data + dosheader->e_lfanew);

	section = (IMAGE_SECTION_HEADER *)(peheader->FileHeader.SizeOfOptionalHeader + (char *)peheader + 0x18);//IMAGE_FIRST_SECTION(peheader);

	for(i = 0; i < peheader->FileHeader.NumberOfSections; i++)
	{
		if(rva >= (char *)section[i].VirtualAddress && rva < (char *)section[i].VirtualAddress + section[i].SizeOfRawData)
		{
			addr = data + section[i].PointerToRawData + ((DWORD)rva - section[i].VirtualAddress);
			return addr;
		}
	}
	return NULL;
}

char * lazy_in_place_rva_to_offset64(char * data, char * rva)
{
	IMAGE_SECTION_HEADER * section;
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS64 * pe64header = NULL;

	dosheader = (IMAGE_DOS_HEADER *)data;
	pe64header = (IMAGE_NT_HEADERS64 *)(data + dosheader->e_lfanew);

	section = (IMAGE_SECTION_HEADER *)(pe64header->FileHeader.SizeOfOptionalHeader + (char *)pe64header + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader));//IMAGE_FIRST_SECTION(peheader);
	int i;
	char * addr;
	for(i = 0; i < pe64header->FileHeader.NumberOfSections; i++)
	{
		if(rva >= (char *)section[i].VirtualAddress && rva < (char *)section[i].VirtualAddress + section[i].SizeOfRawData)
		{
			addr = data + section[i].PointerToRawData + ((DWORD)rva - section[i].VirtualAddress);
			printf("lazy: %08x%08x\n", PRINTARG64(addr));
			return addr;
		}
	}
	return NULL;
}

char * get_image_base(char * data)
{
	IMAGE_SECTION_HEADER * section;
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader = NULL;
	IMAGE_NT_HEADERS64 * pe64header = NULL;

	dosheader = (IMAGE_DOS_HEADER *)data;
	peheader = (IMAGE_NT_HEADERS32 *)(data + dosheader->e_lfanew);

	if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pe64header = (IMAGE_NT_HEADERS64 *)peheader;
		return (char *)pe64header->OptionalHeader.ImageBase;
	}
	else
	{
		return (char *)peheader->OptionalHeader.ImageBase;
	}
}

int get_next_section(char * data, char ** v, char ** d, unsigned int * z)
{
	static int i = 0;
	static char * cur_data = 0;

	if(cur_data && cur_data != data)
	{
		i = 0;
		cur_data = 0;
		printf("Resetting get_next_section\n");
	}

	IMAGE_SECTION_HEADER * section;
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader = NULL;
	IMAGE_NT_HEADERS64 * pe64header = NULL;

	dosheader = (IMAGE_DOS_HEADER *)data;
	peheader = (IMAGE_NT_HEADERS32 *)(data + dosheader->e_lfanew);

	if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pe64header = (IMAGE_NT_HEADERS64 *)peheader;
		if(i == pe64header->FileHeader.NumberOfSections)
		{
			cur_data = 0;
			i = 0;
			return 0;
		}
		section = (IMAGE_SECTION_HEADER *)(pe64header->FileHeader.SizeOfOptionalHeader + (char *)pe64header + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader));//IMAGE_FIRST_SECTION(peheader);
		if(!cur_data)
		{
			*d = data;
			*v = (char *)pe64header->OptionalHeader.ImageBase;
			*z = section[0].PointerToRawData;
			i = 0;
			cur_data = data;
			return 1;
		}
		*d = (char *)data + section[i].PointerToRawData;
		*v = (char *)pe64header->OptionalHeader.ImageBase + section[i].VirtualAddress;
		*z = section[i].SizeOfRawData;
		i++;
	}
	else    //pe here, pe64 above
	{
		if(i == peheader->FileHeader.NumberOfSections)
		{
			cur_data = 0;
			i = 0;
			return 0;
		}
		section = (IMAGE_SECTION_HEADER *)(peheader->FileHeader.SizeOfOptionalHeader + (char *)peheader + 0x18);//IMAGE_FIRST_SECTION(peheader);
		if(!cur_data)
		{
			*d = data;
			*v = (char *)peheader->OptionalHeader.ImageBase;
			*z = section[0].PointerToRawData;
			i = 0;
			cur_data = data;
			return 1;
		}
		*d = (char *)data + section[i].PointerToRawData;
		*v = (char *)peheader->OptionalHeader.ImageBase + section[i].VirtualAddress;
		*z = section[i].SizeOfRawData;
		i++;
	}

	return 1;
}

