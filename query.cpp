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
#include <string.h>
#include "query.h"
#include "loadfiles.h"
#include "libraryloader.h"

int query_from_directory(char * dirname)
{
	uint32_t load_address;
	char * buffer;
	unsigned long size;
	int ret;
	wchar_t * wdirname;
	size_t converted;
	char * filename;

	/*specify_reconstitution_path(dirname);*/
	if(dirname[strlen(dirname)] == '/')
		dirname[strlen(dirname)] = 0x00;
	//specify_reconstitution_path(dirname);
	wdirname = (wchar_t *)calloc(strlen(dirname) + 1, sizeof(wchar_t));
	mbstowcs_s(&converted, wdirname, (strlen(dirname) + 1), dirname, strlen(dirname));

	addImportPath(".\\");
	while((ret = get_next_filename(wdirname, &filename)) > 0)
	{
		OverridingLibraryLoader(filename, true);
		renameByExportName(filename);
	}
	if(ret < 0)
	{
		fprintf(stderr, "File load failed\n");
		return ret;
	}
	return 0;
}