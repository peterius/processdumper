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

typedef HMODULE (WINAPI * LoadLibraryPtr)(LPCTSTR lpFileName);
typedef FARPROC (WINAPI * GetProcAddressPtr)(HMODULE hModule, LPCSTR lpProcName);

#define MAX_PATH					260
extern "C" {
DWORD WINAPI DLLIPCThread(LPVOID param);//__declspec(dllexport)
DWORD WINAPI UnloadHelperLib(LPVOID param);
extern LoadLibraryPtr OurLoadLibrary;
extern GetProcAddressPtr OurGetProcAddress;
__declspec(dllexport) extern char logfileName[MAX_PATH + 1];
__declspec(dllexport) extern wchar_t functionstohookfile[MAX_PATH + 1];
}
