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
//#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "logging.h"
#include "functionprototypes.h"
#include "hook.h"

FILE * loggingfile;
wchar_t wline[500];
char line[500];

fopenPtr _fopen;
fclosePtr _fclose;
fwritePtr _fwrite;
fflushPtr _fflush;
sprintfPtr _sprintf;
snprintfPtr snprintf_0;
vsnprintfPtr vsnprintf_0;
vsnwprintfPtr vsnwprintf_0;
strlenPtr strlen_0;
wcslenPtr wcslen_0;
GetTimeFormatExPtr GetTimeFormatEx_0;
GetDateFormatExPtr GetDateFormatEx_0;

int setup_logging_file(char * filename)
{
	LPWSTR timestring;
#ifdef UNICODE_BOM
	unsigned char bom[] = { 0xFF, 0xFE };
	
	loggingfile = _fopen(filename, "r");
	if(!loggingfile)
	{
		loggingfile = _fopen(filename, "wb");
		_fwrite(bom, sizeof(unsigned char), sizeof(bom), loggingfile);
	}
	else
	{
		_fclose(loggingfile);
#endif //UNICODE_BOM
		loggingfile = _fopen(filename, "ab+");
#ifdef UNICODE_BOM
	}
#endif //UNICODE_BOM
	if(!loggingfile)
		return -1;
	timestring = (LPWSTR)malloc_0(50);
	GetDateFormatEx_0(LOCALE_NAME_SYSTEM_DEFAULT, 0, NULL, L"yyyyMMdd", timestring, 50, NULL);
	WideCharToMultiByte_0(CP_UTF8, 0, timestring, -1, line, 500, NULL, NULL);
	_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
	_fwrite(" ", sizeof(char), 1, loggingfile);
	GetTimeFormatEx_0(LOCALE_NAME_SYSTEM_DEFAULT, 0, NULL, NULL, timestring, 50);
	WideCharToMultiByte_0(CP_UTF8, 0, timestring, -1, line, 500, NULL, NULL);
	_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
	_fwrite("\n", sizeof(char), 1, loggingfile);
	free_0(timestring);
	return 0;
}

void close_logging_file(void)
{
	_fclose(loggingfile);
}

#define CHARFORMAT(x)		(unsigned char)((x > 0x1f && x < 0x7f) ? x : 0x2e)

void logData(unsigned char * data, unsigned int size)
{
	char line[80];
	unsigned int i, s;
	unsigned int samebytecount;
	unsigned char samebyte;

	_sprintf(line, "Data[%08x]:\n", size);
	_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
	i = 0;
	samebytecount = 0;
	samebyte = 0x00;
	if(size >= 0x10)
	{
		for(i = 0; i <= size - 0x10; i += 0x10)
		{
			_sprintf(line, "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
				data[i], data[i + 1], data[i + 2], data[i + 3], data[i + 4], data[i + 5], data[i + 6], data[i + 7],
				data[i + 8], data[i + 9], data[i + 0xa], data[i + 0xb], data[i + 0xc], data[i + 0xd], data[i + 0xe], data[i + 0xf],
				CHARFORMAT(data[i]), CHARFORMAT(data[i + 1]), CHARFORMAT(data[i + 2]), CHARFORMAT(data[i + 3]), CHARFORMAT(data[i + 4]), CHARFORMAT(data[i + 5]), CHARFORMAT(data[i + 6]), CHARFORMAT(data[i + 7]),
				CHARFORMAT(data[i + 8]), CHARFORMAT(data[i + 9]), CHARFORMAT(data[i + 0xa]), CHARFORMAT(data[i + 0xb]), CHARFORMAT(data[i + 0xc]), CHARFORMAT(data[i + 0xd]), CHARFORMAT(data[i + 0xe]), CHARFORMAT(data[i + 0xf]));
			_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
			if(samebyte != data[i])
			{
				samebyte = data[i];
				samebytecount = 0;
			}
			if(data[i + 1] == samebyte && data[i + 2] == samebyte && data[i + 3] == samebyte && data[i + 4] == samebyte && data[i + 5] == samebyte && data[i + 6] == samebyte && data[i + 7] == samebyte
				&& data[i + 8] == samebyte && data[i + 9] == samebyte && data[i + 0xa] == samebyte && data[i + 0xb] == samebyte && data[i + 0xc] == samebyte && data[i + 0xd] == samebyte && data[i + 0xe] == samebyte && data[i + 0xf] == samebyte)
				samebytecount++;
			else
				samebytecount = 0;
			if(samebytecount == 4)
			{
				samebytecount = 0;
				i += 0x10;
				while(i <= size - 0x10 && data[i] == samebyte && data[i + 1] == samebyte && data[i + 2] == samebyte && data[i + 3] == samebyte && data[i + 4] == samebyte && data[i + 5] == samebyte && data[i + 6] == samebyte && data[i + 7] == samebyte
					&& data[i + 8] == samebyte && data[i + 9] == samebyte && data[i + 0xa] == samebyte && data[i + 0xb] == samebyte && data[i + 0xc] == samebyte && data[i + 0xd] == samebyte && data[i + 0xe] == samebyte && data[i + 0xf] == samebyte)
				{
					samebytecount++;
					i += 0x10;
				}
				i -= 0x10;	//for the for loop
				_sprintf(line, "0x%08x lines of 0x10 %02x\n", samebytecount, samebyte);
				_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
				samebytecount = 0;
			}
		}
	}
	if(i == size)
		return;
	s = i;
	if(size > 4)
	{
		while(i < size - 4)
		{
			_sprintf(line, "%02x%02x%02x%02x ", data[i], data[i + 1], data[i + 2], data[i + 3]);
			_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
			i += 4;
		}
	}
	while(i < size)
	{
		_sprintf(line, "%02x", data[i]);
		_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
		i++;
	}
	for(i; i < s + 0x10; i++)
	{
		if(i % 4 == 0)
			_sprintf(line, "   ");
		else
			_sprintf(line, "  ");
		_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
	}
	_sprintf(line, " ");
	_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
	while(s < size)
	{
		_sprintf(line, "%c", CHARFORMAT(data[s]));
		_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
		s++;
	}
	_sprintf(line, "\n");
	_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
}

// ?? FIXME
#define WCHARFORMATP(x)		((wchar_t *)x)

void logwData(unsigned char * data, unsigned int size)
{
	unsigned int i, s, k;
	unsigned int sameshortcount;
	wchar_t sameshort;

	_sprintf(line, "WData[%08x]:\n", size);
	_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
	i = 0;
	sameshortcount = 0;
	sameshort = 0x0000;
	if(size >= 0x10)
	{
		for(i = 0; i <= size - 0x10; i += 0x10)
		{
			logwPrintf(L"%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %c%c%c%c%c%c%c%c\n",
				data[i], data[i + 1], data[i + 2], data[i + 3], data[i + 4], data[i + 5], data[i + 6], data[i + 7],
				data[i + 8], data[i + 9], data[i + 0xa], data[i + 0xb], data[i + 0xc], data[i + 0xd], data[i + 0xe], data[i + 0xf],
				WCHARFORMATP(data)[i], WCHARFORMATP(data)[i + 1], WCHARFORMATP(data)[i + 2], WCHARFORMATP(data)[i + 3],
				WCHARFORMATP(data)[i + 4], WCHARFORMATP(data)[i + 5], WCHARFORMATP(data)[i + 6], WCHARFORMATP(data)[i + 7]);
			if(sameshort != WCHARFORMATP(data)[i])
			{
				sameshort = WCHARFORMATP(data)[i];
				sameshortcount = 0;
			}
			if(WCHARFORMATP(data)[i + 1] == sameshort && WCHARFORMATP(data)[i + 2] == sameshort && WCHARFORMATP(data)[i + 3] == sameshort &&
				WCHARFORMATP(data)[i + 4] == sameshort && WCHARFORMATP(data)[i + 5] == sameshort && WCHARFORMATP(data)[i + 6] == sameshort && WCHARFORMATP(data)[i + 7] == sameshort)
				sameshortcount++;
			else
				sameshortcount = 0;
			if(sameshortcount == 4)
			{
				sameshortcount = 0;
				i += 0x10;
				while(i <= size - 0x10 && WCHARFORMATP(data)[i] == sameshort && WCHARFORMATP(data)[i + 1] == sameshort && WCHARFORMATP(data)[i + 2] == sameshort && WCHARFORMATP(data)[i + 3] == sameshort &&
					WCHARFORMATP(data)[i + 4] == sameshort && WCHARFORMATP(data)[i + 5] == sameshort && WCHARFORMATP(data)[i + 6] == sameshort && WCHARFORMATP(data)[i + 7] == sameshort)
				{
					sameshortcount++;
					i += 0x10;
				}
				i -= 0x10;	//for the for loop
				_sprintf(line, "0x%08x lines of 0x10 %04x\n", sameshortcount, sameshort);
				_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
				sameshortcount = 0;
			}
		}
	}
	if(i == size)
		return;
	s = i;
	if(size > 4)
	{
		while(i < size - 4)
		{
			logwPrintf(L"%02x%02x%02x%02x ", data[i], data[i + 1], data[i + 2], data[i + 3]);
			i += 4;
		}
	}
	while(i < size)
	{
		logwPrintf(L"%02x", data[i]);
		i++;
	}
	for(i; i < s + 0x10; i++)
	{
		if(i % 4 == 0)
			logwPrintf(L"  ");
		else
			logwPrintf(L" ");
	}
	k = s;
	while(s < size)
	{
		logwPrintf(L"%c", WCHARFORMATP(data)[k]);
		k++;
		s += 2;
	}
}

void logPrintf(const char * format, ...)
{
	va_list args;
	va_start(args, format);
	vsnprintf_0(line, 500, format, args);
	va_end(args);
	_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
	_fflush(loggingfile);
}

void logwPrintf(const wchar_t * format, ...)
{
	va_list args;
	va_start(args, format);
	vsnwprintf_0(wline, 500, format, args);
	va_end(args);
	//b = wcstombs_0(line, wline, 500);
	//_fwrite(line, sizeof(char), b, loggingfile);
	WideCharToMultiByte_0(CP_UTF8, 0, wline, -1, line, 500, NULL, NULL);
	_fwrite(line, sizeof(char), strlen_0(line), loggingfile);
	_fflush(loggingfile);
}

void logFuncInfo(void)
{
#ifdef _WIN64
	logPrintf("Caller %08x%08x ", PRINTARG64(curhook_stackpointer));
#else
	logPrintf("Caller %08x ", curhook_stackpointer);
#endif //_WIN64


}