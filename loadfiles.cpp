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
#include <stdio.h>
#include <stdlib.h>
#include "loadfiles.h"

/* sigh... I should just write a damn c++ object... */
HANDLE hDir = NULL;
WCHAR * currentdir = NULL;
WIN32_FIND_DATA findData;
WCHAR path[500];

int get_next_filename(wchar_t * dir, wchar_t ** filename);

int get_next_filename(wchar_t * dir, wchar_t ** filename)
{
	WCHAR * widestring;
	int ret;

	*filename = NULL;

	if(currentdir && dir != currentdir)
	{
		printf("Switching directory ?!?\n");
		currentdir = NULL;
		FindClose(hDir);
		hDir = NULL;
	}

	if(!currentdir)
	{
		//if(dirname[strlen(dirname)] == '/')
		//	dirname[strlen(dirname)] = 0x00;
		widestring = (WCHAR *)calloc(wcslen(dir) + 1, sizeof(WCHAR));
		//mbstowcs_s(&converted, widestring, (strlen(dirname) + 1) * sizeof(WCHAR), dirname, strlen(dirname));
		wsprintf(&(widestring[wcslen(widestring)]), L"%s\\*", dir);

		hDir = FindFirstFile(widestring, &findData);
		if(hDir == INVALID_HANDLE_VALUE)
		{
			wprintf(L"Can't find directory %s %d\n", widestring, GetLastError());
			return -1;
		}
		free(widestring);
		if(!hDir)
		{
			fprintf(stderr, "Null directory handle\n");
			return -1;
		}

		if(!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			fwprintf(stderr, L"%s is not a directory\n", findData.cFileName);
			FindClose(hDir);
			hDir = NULL;
			return -1;
		}
		currentdir = dir;
	}
	do
	{
		if(!(ret = FindNextFile(hDir, &findData)))
		{
			FindClose(hDir);
			hDir = NULL;
			currentdir = NULL;
			if(ret < 0)
			{
				printf("findnext failed %d\n", GetLastError());
				return -1;
			}
			//ERROR_NO_MORE_FILES 18
			return 0;
		}
	} while(findData.cFileName[0] == '.');

	*filename = (wchar_t *)calloc(wcslen(findData.cFileName) + 1, sizeof(wchar_t));
	wcscpy(*filename, findData.cFileName);
	return 1;
}

int load_files(wchar_t * dirname, uint32_t * addr, char ** buffer, unsigned long * size)
{
	int ret;
	wchar_t * filename;
	HANDLE hfile;
	DWORD bytes_read;

	if((ret = get_next_filename(dirname, &filename)) != 1)
		return ret;

	wprintf(L"%s\n", filename);
	*buffer = 0;

	if(swscanf_s(filename, L"inmem_%08x_", addr) == 1)
	{
		printf("Load address: %08x\n", *addr);

		wsprintf(path, L"%s//%s", dirname, filename);
		free(filename);
		hfile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hfile)
		{
			if(findData.nFileSizeHigh)
				fprintf(stderr, "WARNING: file size has highpart!\n");
			*size = findData.nFileSizeLow;
			*buffer = (char *)malloc(*size);
			if(!ReadFile(hfile, *buffer, *size, &bytes_read, NULL))
			{
				fprintf(stderr, "File read error %d\n", GetLastError());
				free(*buffer);
				*buffer = 0;
				return 1;
			}
			if(bytes_read != *size)
			{
				fprintf(stderr, "Only read %d bytes\n", bytes_read);
				//this is pretty serious...
				free(*buffer);
				*buffer = 0;
				return 1;
			}
			CloseHandle(hfile);
		}
		else
			fprintf(stderr, "File open error %d\n", GetLastError());
	}
	return 1;
}

// *nix ?
/*DIR * dp;
struct dirent * ep;
struct path;

if(dirname)
{
dp = opendir(dirname);

if(dp != NULL)
{
while(ep = readdir(dp))
{
len = strlen(ep->d_name);
printf("FILE: %s\n", ep->d_name);
}

closedir(dp);
}
else
perror("Couldn't open the directory");
}*/

int load_a_file(char * name, char ** buffer, unsigned int * size)
{
	WCHAR dllPath[512];
	HANDLE hFile;
	size_t converted;
	WCHAR * wname;
	DWORD bytes_read;

	wname = (WCHAR *)calloc((strlen(name) + 1), sizeof(wchar_t));
	mbstowcs_s(&converted, wname, (strlen(name) + 1), name, strlen(name));

	GetFullPathName(wname, 512, dllPath, NULL);

	hFile = CreateFileW(dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		fwprintf(stderr, L"Can't open %s for loading: %d\n", dllPath, GetLastError());
		return -1;
	}
	else if(!hFile)
	{
		fwprintf(stderr, L"Can't open %s for loading\n", dllPath);
		return -1;
	}
	*size = GetFileSize(hFile, NULL);

	*buffer = (char *)malloc(*size);

	if(!ReadFile(hFile, *buffer, *size, &bytes_read, NULL))
	{
		fprintf(stderr, "Read failed %d\n", GetLastError());
		CloseHandle(hFile);
		return -1;
	}

	return 0;
}

//dll exe
int get_next_filename(wchar_t * dirname, char ** outname)
{
	wchar_t * filename;
	size_t converted;
	int ret;

	if((ret = get_next_filename(dirname, &filename)) != 1)
		return ret;

	if(wcscmp(&(filename[wcslen(filename) - 4]), L".dll") == 0 ||
		wcscmp(&(filename[wcslen(filename) - 4]), L".exe") == 0)
	{
		wsprintf(path, L"%s//%s", currentdir, filename);
		*outname = (char *)calloc(200, sizeof(char));
		converted = wcstombs(*outname, path, 200);
	}
	return 1;
}
