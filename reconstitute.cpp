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
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
//#include <dirent.h>			//*nix ?
#include "winnt.h"
#include "reconstitute.h"
#include "libraryloader.h"
#include "loadfiles.h"

struct recon_module
{
	char * real_address;
	unsigned long size;
	int dll;
	struct file * file;
};

char * path = NULL;
struct recon_module * recon_module = NULL;
unsigned int recon_modules;

void write_to_disk(struct file * file);

//ugly but whatever...
void specify_reconstitution_path(char * p)
{
	if(path)
		free(path);
	path = (char *)calloc(strlen(p) + 1, sizeof(char));
	strcpy(path, p);
}

void add_module_for_reconstitution(char * address, char * buffer, unsigned int size)
{
	struct section * sect;
	struct recon_module * mod;

	if(!recon_module)
	{
		recon_modules = 1;
		recon_module = (struct recon_module *)calloc(1, sizeof(struct recon_module));
	}
	else
	{
		recon_modules++;
		recon_module = (struct recon_module *)realloc(recon_module, recon_modules * sizeof(struct recon_module));
	}
	mod = &(recon_module[recon_modules - 1]);
	mod->file = (struct file *)calloc(1, sizeof(struct file));
	//not sure this is the same usage as libraryloader:
	//ourfile->image_base = (uint32_t)address;
	mod->file->data = (unsigned char *)buffer;
	mod->size = size;
	mod->real_address = address;
	mod->file->filesize = size;

	if(parse_file_format(mod->file) < 0)
		fprintf(stderr, "Parse file failed\n");

	//dont rely on ourfile->data, ourfile->fileformat, etc.,
	if(!(mod->file->characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
		printf("Not an executable image?\n");
	if(mod->file->characteristics & IMAGE_FILE_DLL)
		mod->dll = 1;
	else
		mod->dll = 0;
}

int reconstitute_from_directory(char * dirname)
{
	uint32_t load_address;
	char * buffer;
	unsigned long size;
	int ret;
	wchar_t * wdirname;
	size_t converted;

	specify_reconstitution_path(dirname);
	if(dirname[strlen(dirname)] == '/')
		dirname[strlen(dirname)] = 0x00;
	specify_reconstitution_path(dirname);
	wdirname = (wchar_t *)calloc(strlen(dirname) + 1, sizeof(wchar_t));
	mbstowcs_s(&converted, wdirname, (strlen(dirname) + 1), dirname, strlen(dirname));

	while((ret = load_files(wdirname, &load_address, &buffer, &size)) > 0)
	{
		/* FIXME so far we're pulling uint32_t off the filenames because that's from EnumProcess which
		 * needs to be improved.  For now, I'll just check the rvas */
		if(buffer)
			add_module_for_reconstitution((char *)load_address, buffer, size);
	}
	if(ret < 0)
	{
		fprintf(stderr, "File load failed\n");
		return ret;
	}
	return 0;
}

int reconstitute(void)
{
	int i, j, k, possible_exec_index;
	int current_section;
	struct section * section;
	struct recon_module * mod;
	IMAGE_DOS_HEADER * dosheader;
	IMAGE_NT_HEADERS32 * peheader = NULL;
	IMAGE_NT_HEADERS64 * pe64header = NULL;
	IMAGE_SECTION_HEADER * sectionhdr;
	struct file * outputfile;

	possible_exec_index = -1;
	for(i = 0; i < recon_modules; i++)
	{
		if(!(recon_module[i].dll))
		{
			if(possible_exec_index != -1)
				fprintf(stderr, "Warning: Found two possible executable module!\n");
			else
				possible_exec_index = i;
		}
	}
	if(possible_exec_index == -1)
		fprintf(stderr, "Warning: Found no likely executable module!\n");

	for(i = 0; i < recon_modules; i++)
	{
		mod = &(recon_module[i]);
		dosheader = (IMAGE_DOS_HEADER *)mod->file->data;
		peheader = (IMAGE_NT_HEADERS32 *)(mod->file->data + dosheader->e_lfanew);
		if(peheader->Signature != 0x00004550)
		{
			fprintf(stderr, "Module with bad PE signature!\n");
			continue;
		}
		if(peheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)			//anything else and we would have choked earlier
		{
			pe64header = (IMAGE_NT_HEADERS64 *)peheader;
			peheader = NULL;
		}
		outputfile = (struct file *)calloc(1, sizeof(struct file));
		if(peheader)
		{
			//unlikely we have a real name...
			outputfile->name = (char *)calloc(1 + 8 + 4 + 1, sizeof(char));
			if(mod->dll)
				sprintf(outputfile->name, "M%08x.dll", mod->real_address);
			else
				sprintf(outputfile->name, "M%08x.exe", mod->real_address);
			outputfile->filesize = mod->size;
			outputfile->data = (unsigned char *)malloc(mod->size);
			if(!outputfile->data)
			{
				fprintf(stderr, "Can't allocate output file data\n");
				continue;
			}
			memcpy(outputfile->data, mod->file->data, ((char *)peheader - (char *)dosheader) + peheader->FileHeader.SizeOfOptionalHeader + 0x18 +
								(peheader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
			outputfile->image_base = peheader->OptionalHeader.ImageBase;
			if(peheader->OptionalHeader.ImageBase != (DWORD)mod->real_address)
				printf("Module not loaded at suggested Image Base %08x instead %08x\n", outputfile->image_base, mod->real_address);

			/*printf("Data directories: \n");
			for(j = 0; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1; j++)
			{
				printf("%s\n\tAddress: %08x Size: %08x\n", DataDirectoryString[j], peheader->OptionalHeader.DataDirectory[j].VirtualAddress, peheader->OptionalHeader.DataDirectory[j].Size);
			}*/

			//only used for libraryloader:
			//outputfile->entry_address = peheader->OptionalHeader.AddressOfEntryPoint + peheader->OptionalHeader.ImageBase;
			outputfile->sections = peheader->FileHeader.NumberOfSections;
			outputfile->sectionlist = (struct section *)calloc(outputfile->sections, sizeof(struct section));
			
			sectionhdr = (IMAGE_SECTION_HEADER *)(peheader->FileHeader.SizeOfOptionalHeader + (char *)peheader + 0x18);//IMAGE_FIRST_SECTION(peheader);
			for(current_section = 0; current_section < mod->file->sections; current_section++)
			{
				section = &(outputfile->sectionlist[current_section]);
				section->fileoffset = sectionhdr->PointerToRawData;
				section->size = sectionhdr->SizeOfRawData;

				for(k = 0; k < current_section; k++)
				{
					if(section->fileoffset >= outputfile->sectionlist[k].fileoffset && section->fileoffset < outputfile->sectionlist[k].fileoffset + outputfile->sectionlist[k].size)
						fprintf(stderr, "Warning: section overlap!\n");
					else if(section->fileoffset + section->size >= outputfile->sectionlist[k].fileoffset && section->fileoffset + section->size < outputfile->sectionlist[k].fileoffset + outputfile->sectionlist[k].size)
						fprintf(stderr, "Warning: section overlap!\n");
				}
				if(section->fileoffset + section->size > mod->size)
					fprintf(stderr, "Can't write memory, would overflow module size\n");
				else
					memcpy(&(outputfile->data[section->fileoffset]), &(mod->file->data[sectionhdr->VirtualAddress]), section->size);
				section->address = sectionhdr->VirtualAddress + peheader->OptionalHeader.ImageBase;

				sectionhdr++;
			}
			write_to_disk(outputfile);
			cleanupFile(outputfile);
		}
		else  //64 bit
		{
			//unlikely we have a real name...
			outputfile->name = (char *)calloc(1 + 16 + 4 + 1, sizeof(char));
			if(mod->dll)
				sprintf(outputfile->name, "M%08x%08x.dll", PRINTARG64(mod->real_address));
			else
				sprintf(outputfile->name, "M%08x%08x.exe", PRINTARG64(mod->real_address));
			outputfile->filesize = mod->size; 
			outputfile->data = (unsigned char *)malloc(mod->size);
			if(!outputfile->data)
			{
				fprintf(stderr, "Can't allocate output file data\n");
				continue;
			}
			memcpy(outputfile->data, mod->file->data, ((char *)pe64header - (char *)dosheader) + pe64header->FileHeader.SizeOfOptionalHeader + 0x18 +
				(pe64header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
			outputfile->image_base64 = pe64header->OptionalHeader.ImageBase;
			if(pe64header->OptionalHeader.ImageBase != (ULONGLONG)mod->real_address)
				printf("Module not loaded at suggested Image Base %08x%08x instead %08x%08x\n", PRINTARG64(outputfile->image_base64), PRINTARG64(mod->real_address));

			/*printf("Data directories: \n");
			for(j = 0; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1; j++)
			{
				printf("%s\n\tAddress: %08x Size: %08x\n", DataDirectoryString[j], pe64header->OptionalHeader.DataDirectory[j].VirtualAddress, pe64header->OptionalHeader.DataDirectory[j].Size);
			}*/

			//only used for libraryloader:
			//outputfile->entry_address = pe64header->OptionalHeader.AddressOfEntryPoint + pe64header->OptionalHeader.ImageBase;
			outputfile->sections = pe64header->FileHeader.NumberOfSections;
			outputfile->sectionlist = (struct section *)calloc(outputfile->sections, sizeof(struct section));
			
			sectionhdr = (IMAGE_SECTION_HEADER *)(pe64header->FileHeader.SizeOfOptionalHeader + (char *)pe64header + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader));//IMAGE_FIRST_SECTION(peheader);
			for(current_section = 0; current_section < mod->file->sections; current_section++)
			{
				section = &(outputfile->sectionlist[current_section]);
				section->fileoffset = sectionhdr->PointerToRawData;
				section->size = sectionhdr->SizeOfRawData;

				for(k = 0; k < current_section; k++)
				{
					if(section->fileoffset >= outputfile->sectionlist[k].fileoffset && section->fileoffset < outputfile->sectionlist[k].fileoffset + outputfile->sectionlist[k].size)
						fprintf(stderr, "Warning: section overlap!\n");
					else if(section->fileoffset + section->size >= outputfile->sectionlist[k].fileoffset && section->fileoffset + section->size < outputfile->sectionlist[k].fileoffset + outputfile->sectionlist[k].size)
						fprintf(stderr, "Warning: section overlap!\n");
				}
				if(section->fileoffset + section->size > mod->size)
					fprintf(stderr, "Can't write memory, would overflow module size\n");
				else
					memcpy(&(outputfile->data[section->fileoffset]), &(mod->file->data[sectionhdr->VirtualAddress]), section->size);
				section->address = sectionhdr->VirtualAddress + pe64header->OptionalHeader.ImageBase;

				sectionhdr++;
			}
			write_to_disk(outputfile);
			cleanupFile(outputfile);
		}
	}
	return 0;
}

void cleanup_reconstitution(void)
{
	int  i;
	for(i = 0; i < recon_modules; i++)
	{
		cleanupFile(recon_module[i].file);
	}
	free(recon_module);
	if(path)
		free(path);
}

void write_to_disk(struct file * file)
{
	FILE * fp;
	unsigned long written;
	char * outpath;
	if(!path)
	{
		path = (char *)calloc(3, sizeof(char));
		sprintf(path, "./");
	}
	outpath = (char *)calloc(strlen(path) + strlen(file->name) + 2, sizeof(char));
	sprintf(outpath, "%s/%s", path, file->name);
	fp = fopen(outpath, "wb");
	if(!fp)
	{
		switch(errno)
		{
		case EACCES:
			//throwErrorDialog("File Error", "No permission to read %s", outpath);
			fprintf(stderr, "No permission to write to\"%s\"\n", outpath);
			return;
		default:
			//throwErrorDialog("File Error", "Unknown error -%d", errno);
			fprintf(stderr, "Can't open file for writing, unknown errno %d\n", errno);
			break;
		}
		return;
	}


	written = fwrite(file->data, sizeof(char), file->filesize, fp);
	if(written != file->filesize)
		fprintf(stderr, "Only wrote %d bytes\n", written);
	fclose(fp);
}
