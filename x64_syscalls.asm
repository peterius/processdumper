;  processdumper: console utility for software analysis
;  Copyright(C) 2017  Peter Bohning
;  This program is free software : you can redistribute it and / or modify
;  it under the terms of the GNU General Public License as published by
;  the Free Software Foundation, either version 3 of the License, or
;  (at your option) any later version.
;
;  This program is distributed in the hope that it will be useful,
;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
;  GNU General Public License for more details.
;
;  You should have received a copy of the GNU General Public License
;  along with this program.  If not, see <http://www.gnu.org/licenses/>.
PUBLIC AMD64_NtQuerySystemInformation
PUBLIC GetIDT64

_TEXT SEGMENT

AMD64_NtQuerySystemInformation PROC

mov r10, rcx
mov eax, 36

; test byte ptr ds : [7FFE0308], 1
; jne ntdll.7FFDACDD5A65

;jmp @@other
syscall
ret
@@other:
	int 2eh
ret

AMD64_NtQuerySystemInformation ENDP

;void GetIDT64(char * idt6);
GetIDT64 Proc
sidt [rcx]
ret
GetIDT64 ENDP


_TEXT ENDS

END
