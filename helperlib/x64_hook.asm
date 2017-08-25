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
EXTERN hookfuncfunc: PROC

PUBLIC Hook
PUBLIC EndHook
PUBLIC LockHook
PUBLIC call_orig_func_as_if
PUBLIC cleanup_hooking

_DATA SEGMENT
	saveretvalue    dq 0
	saversi			dq 0
	saverdi			dq 0
_DATA ENDS

_TEXT SEGMENT

Hook PROC
	;safe by register shadow in rsp? 
	mov [rsp + 8h],rcx;
	mov [rsp + 10h],rdx;
	mov [rsp + 18h],r8;
	mov [rsp + 20h],r9;
	push rbp
	push rsi
	push rdi
	mov rcx,rsp
	mov rdx,66555467h			;can't use a variable
	sub rsp,20h					;register shadow
	mov r8,hookfuncfunc
	jmp r8
	int 3h
Hook ENDP
EndHook PROC
	int 3h
EndHook ENDP
;char * LockHook(char * loc, char * hookaddr);
LockHook PROC
	lock xchg rdx, [rcx]
	mov rax,rdx
	ret
LockHook ENDP

;char * call_orig_func_as_if(void * sp, void(*origfunc)(void), int ret);
call_orig_func_as_if PROC
	mov r10b,1
	cmp r8b,r10b
	je @@rettohandler
	mov r10,rdx
	mov rsp,rcx
	pop rdi
	pop rsi
	pop rbp
	mov rcx,[rsp+8h]
	mov rdx,[rsp+10h]
	mov r8,[rsp+18h]
	mov r9,[rsp+20h]
	jmp r10;
@@rettohandler:
	mov r10,[rsp]
	mov saveretvalue,r10
	mov r10,rdx
	mov rsp,rcx
	mov saversi,rsi			; because our caller uses this to cache something...
	mov saverdi,rdi
	pop rdi
	pop rsi
	pop rbp
	add rsp,8h		; don't need the real return address here...
	mov rcx,[rsp]
	mov rdx,[rsp+8h]
	mov r8,[rsp+10h]
	mov r9,[rsp+18h]
	call r10
	push rbp
	push rsi
	push rdi
	push rax		; the return value
	mov rax,rsp		; return stack with return value
	sub rsp,30h		; for good luck!
	mov rsi,saversi
	mov rdi,saverdi
	jmp saveretvalue
call_orig_func_as_if ENDP

;void cleanup_hooking(void * sp, void * origret);
cleanup_hooking PROC
	mov rsp,rcx
	pop rax
	pop rdi
	pop rsi
	pop rbp
	jmp rdx
cleanup_hooking ENDP

_TEXT ENDS

END
