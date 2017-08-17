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
#include <ntddk.h>

void GetIDT64(char * idt6);

#ifdef FROMTHEWEB
//https://www.codeproject.com/Articles/13677/Hooking-the-kernel-directl
// this routine hooks and restores IDT. 
// We have to make sure that this function runs only 
//on one CPU, so that we disable interrupts throughout 
// its execution in order to avoid context 
// swithches 
void HookIDT() 
{ 
ULONG handler1,handler2,idtbase,tempidt,a; UCHAR idtr[8]; 
//get the addresses that we have write to 
IDT handler1=(ULONG)&replacementbuff[0]; 
handler2=(ULONG)&replacementbuff[32]; 
//allocate temp. memory. This should be our first 
//step - from the moment we disable interrupts 
//till return we don't risk to call any code 
//that has not been written by ourselves 
//(theoretically this code may re-enable 
//interrupts without our knowledge, and then.....) 
tempidt=(ULONG)ExAllocatePool(NonPagedPool,2048); 
_asm { cli sidt idtr lea ebx,idtr mov eax,dword ptr[ebx+2] mov idtbase,eax } 
//check whether our IDT has already been hooked. 
//If yes, re-enable interrupts and return 
for(a=0;a<IdtsHooked;a++) 
{ if(idtbases[a]==idtbase)
{ _asm sti 
ExFreePool((void*)tempidt); 
KeSetEvent(&event,0,0); PsTerminateSystemThread(0); 
} }
_asm { 
//now we are going to load the copy of IDT into IDTR register 
// in my experience, modifying memory, 
//pointed to by IDTR register, is unsafe 
mov edi,tempidt mov esi,idtbase mov ecx,2048 rep movs lea ebx,idtr mov eax,tempidt mov dword ptr[ebx+2],eax lidt idtr 
//now we can safely modify IDT. Get ready mov ecx,idtbase 
//hook INT 1 
add ecx,8 mov ebx,handler1 mov word ptr[ecx],bx shr ebx,16 mov word ptr[ecx+6],bx 
///hook INT 3 
add ecx,16 mov ebx,handler2 mov word ptr[ecx],bx shr ebx,16 mov word ptr[ecx+6],bx
//reload the original idt 
lea ebx,idtr mov eax,idtbase mov dword ptr[ebx+2],eax lidt idtr sti } 
//now add the address of IDT we just 
//hooked to the list of hooked IDTs
idtbases[IdtsHooked]=idtbase; IdtsHooked++; ExFreePool((void*)tempidt); KeSetEvent(&event,0,0); PsTerminateSystemThread(0); } 

NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver,IN PUNICODE_STRING path) 
{ ULONG a;PUCHAR pool=0; UCHAR idtr[8];HANDLE threadhandle=0; 
//fill the array with machine codes replacementbuff[0]=255;replacementbuff[1]=37; a=(long)&replacementbuff[6]; memmove(&replacementbuff[2],&a,4); a=(long)&INT1Proxy;
memmove(&replacementbuff[6],&a,4); replacementbuff[32]=255;replacementbuff[33]=37; a=(long)&replacementbuff[38]; memmove(&replacementbuff[34],&a,4); a=(long)&BPXProxy;
memmove(&replacementbuff[38],&a,4); 
//save the original addresses of INT 1 and INT 3 handlers 
_asm { sidt idtr lea ebx,idtr mov ecx,dword ptr[ebx+2] 
/////save INT1 
add ecx,8 mov ebx,0 mov bx,word ptr[ecx+6] shl ebx,16 mov bx,word ptr[ecx] mov Int1RealHandler,ebx 
/////save INT3 
add ecx,16 mov ebx,0 mov bx,word ptr[ecx+6] shl ebx,16 mov bx,word ptr[ecx] mov BPXRealHandler,ebx } 
//hook INT 1 and INT 3 handlers - it has 
//to be done before overwriting NDIS 
//Run HookUnhookIDT() as a separate 
//thread until all IDTs get hooked 
KeInitializeEvent(&event,SynchronizationEvent,0); RtlZeroMemory(&idtbases[0],64); a=KeNumberProcessors[0]; 
while(1) { PsCreateSystemThread(&threadhandle, (ACCESS_MASK) 0L,0,0,0, (PKSTART_ROUTINE)HookIDT,0);
KeWaitForSingleObject(&event, Executive,KernelMode,0,0); if(IdtsHooked==a) break; } KeSetEvent(&event,0,0); 
//fill the structure... 
a=(ULONG)&IoCreateDevice; HookedFunctionDescriptor.RealCode=a; pool=ExAllocatePool(NonPagedPool,8);
memmove(pool,a,8); HookedFunctionDescriptor.ProxyCode=(ULONG)pool; 
//now let's proceed to overwriting memory 
_asm { 
//remove protection before overwriting 
mov eax,cr0 push eax and eax,0xfffeffff mov cr0,eax 
//insert breakpoint (0xCC opcode) 
mov ebx,a mov al,0xcc mov byte ptr[ebx],al 
//restore protection 
pop eax mov cr0,eax } return 0; }

#endif //from the web...


#pragma pack(1)
struct idtentry
{
	unsigned short base_lo;
	unsigned short sel;        /* Our kernel segment goes here! */
	unsigned char always0;     /* This will ALWAYS be set to 0! */
	unsigned char flags;       /* Set using the above table! */
	unsigned short base_hi;
};

#pragma pack(1)
struct idtentry64
{
	unsigned short offset1;
	unsigned short sel;        /* Our kernel segment goes here! */
	unsigned char always0;     /* This will ALWAYS be set to 0! */
	unsigned char flags;       /* Set using the above table! */
	unsigned short offset2;
	unsigned long offset3;
	unsigned long reserved0;
};

#define PRINTARG64(x)	((unsigned long  *)&x)[1], ((unsigned long *)&x)[0]
#define printk(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: "__VA_ARGS__)

void queryidt(void)
{
	//char idt32[6];
	char idt64[10];
	unsigned short idtlimit;
	//uint32_t idtp;
	unsigned long long idt64p;

	//struct idtentry * idtentryp;
	struct idtentry64 * idtentry64p;

	memset(idt64, 0, 10);
	GetIDT64(idt64);

	idtlimit = *(unsigned short *)idt64;
	idt64p = *(unsigned long long *)(idt64 + 2);

	printk("IDT: %04x %08x%08x\n", idtlimit, PRINTARG64(idt64p));


	idtentry64p = (struct idtentry64 *)idt64p;
	printk("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printk(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;
	printk("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printk(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;
	printk("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printk(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;
	printk("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printk(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;
	printk("low: %04x sel: %04x a0: %02x fl: %02x hi: %04x\n", idtentry64p->offset1, idtentry64p->sel, idtentry64p->always0, idtentry64p->flags, idtentry64p->offset2);
	printk(" hir: %08x res %08x\n", idtentry64p->offset3, idtentry64p->reserved0);
	idtentry64p++;
}

#ifdef NEVERMIND
NTSTATUS requestintcode(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	try
	{
		/*if(irpSp->Parameters.DeviceIoControl.InputBufferLength == sizeof(int))
		{
		StealthHook hookType = *(StealthHook*)Irp->AssociatedIrp.SystemBuffer;
		hookSysCall(hookType);
		}*/
		pbuffer = ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.DeviceIoControl.OutputBufferLength, 'loop'); if(NULL == pbuffer) return STATUS_INSUFFICIENT_RESOURCES;
		//pbuffer = 0;
		status = 0;
		returnlen = 0;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: zwquery BZ before %d %d after %d\n", IrpSp->Parameters.DeviceIoControl.InputBufferLength, IrpSp->Parameters.DeviceIoControl.OutputBufferLength, returnlen);
		status = ZwQuerySystemInformation(SystemProcessInformation, pbuffer, IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &returnlen);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: %d %d\n", status, returnlen);
		//returnlen = 500;
		//for(i = 0; i < returnlen; i++)
		//	((char *)Irp->AssociatedIrp.SystemBuffer)[i] = ((char *)_ZwQuerySystemInformation)[i];
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "warontencent: some ids %d %d %d\n", ((SYSTEM_PROCESS_INFORMATION *)pbuffer)[3].UniqueProcessId, ((SYSTEM_PROCESS_INFORMATION *)pbuffer)[4].UniqueProcessId, ((SYSTEM_PROCESS_INFORMATION *)pbuffer)[5].UniqueProcessId);
		//((SYSTEM_PROCESS_INFORMATION *)pbuffer)[0].UniqueProcessId = (HANDLE)666;
		//((char *)pbuffer)[0] = 0x77;
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, pbuffer, returnlen);
		ExFreePoolWithTag(pbuffer, 'loop');
		//returnlen = 10;
		//((char *)Irp->UserBuffer)[1] = 0x16;
		/*((char *)Irp->AssociatedIrp.SystemBuffer)[0] = 0x55;
		((char *)Irp->AssociatedIrp.SystemBuffer)[1] = 0x66;
		((char *)Irp->AssociatedIrp.SystemBuffer)[2] = 0x77;
		((char *)Irp->AssociatedIrp.SystemBuffer)[3] = 0x88;*/
		//((char *)Irp->UserBuffer)[0] = 0x65;
		//((char *)Irp->UserBuffer)[1] = 0x76;
		//((char *)Irp->UserBuffer)[2] = 0x87;
		//((char *)Irp->UserBuffer)[3] = 0x98;
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = returnlen;
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}
#endif //NEVERMIND