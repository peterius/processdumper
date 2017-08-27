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
.386
.model flat, c
PUBLIC Hook
PUBLIC EndHook
PUBLIC LockHook
PUBLIC call_orig_func_as_if
PUBLIC cleanup_hooking
PUBLIC hijackcaller

EXTERN hookfuncfunc: PROC

_DATA SEGMENT
	saveretvalue dd 0
_DATA ENDS

_TEXT SEGMENT

;esi is used as a stack pointer verification

Hook PROC
	push ebp
	push esi
	push edi
	mov eax,esp		
	push 66555467h			;can't use a variable
	push eax
	mov eax,hookfuncfunc
	call eax
	int 3h
Hook ENDP
EndHook PROC
	int 3h
EndHook ENDP

;char * LockHook(char * loc, char * hookaddr);
LockHook PROC
	mov ecx, [esp + 4h]			;loc
	mov eax, [esp + 8h]			;hookaddr
	lock xchg eax, [ecx]
	ret
LockHook ENDP

;void call_orig_func_as_if(void * sp, void(*origfunc)(void), int ret);
call_orig_func_as_if PROC
	mov ecx,[esp+08h]
	mov dl,1
	cmp byte ptr [esp+0ch],dl
	je @@rettohandler
	mov esp,[esp+4h]
	pop edi
	pop esi
	pop ebp
	jmp ecx;
@@rettohandler:
	mov edx,[esp]
	mov saveretvalue,edx
	mov edx,[esp+4h]
	mov esp,edx
	pop edi
	pop esi
	pop ebp
	add esp,4h
	call ecx
	push ebp
	push esi
	push edi
	push eax		; the return value
	mov eax,esp		; return stack with return value
	sub esp,30h		; for good luck!
	jmp saveretvalue
call_orig_func_as_if ENDP

;void cleanup_hooking(void * sp, void * origret);
cleanup_hooking PROC
	mov ecx,[esp+08h]
	mov esp,[esp+4h]
	pop eax				; restore real return value
	pop edi
	pop esi
	pop ebp
	jmp ecx
cleanup_hooking ENDP

hijackcaller PROC
	push eax
	push ebx
	push ecx
	push edx
	push esi
	push edi
	push ebp
	mov eax,[esp+1ch]
	mov ebx,[esp+20h]
	push ebx
	call eax
	pop ebp
	pop edi
	pop esi
	pop edx
	pop ecx
	pop ebx
	pop eax
	add esp,8h
	ret
hijackcaller ENDP

_TEXT ENDS


END

