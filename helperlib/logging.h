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
#include "justforvs.h"

#ifdef _WIN64
#define PRINTARG64(x)	((unsigned long *)&x)[1], ((unsigned long *)&x)[0]
#endif //_WIN64

int setup_logging_file(char * filename);
void close_logging_file(void);

void logData(unsigned char * data, unsigned int size);
void logwData(unsigned char * data, unsigned int size);
void logPrintf(const char * format, ...);
void logwPrintf(const wchar_t * format, ...);
