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

#define HELPER_FIXIMPORT_FAILED						-2
#define LOGGING_FILE_FAILED							-3
#define VIRTUALALLOC_FAILED							-4
#define XMLLOAD_FAILED								-5
#define CREATETOOLHELP_FAILED						-6
#define MODULEFIRST_FAILED							-7

/* Because I suspect DLL_THREAD_ATTACH can silently kill us... */
#define HELPERLIB_SUCCESS							67
