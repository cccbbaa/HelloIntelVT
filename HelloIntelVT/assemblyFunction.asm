

_TEXT SEGMENT 'CODE'


EXTERN CreateVirtualMachine : proc

PUBLIC AsmCreateVMM
AsmCreateVMM PROC
	sub rsp,100h
	pushfq  ; 8 Byte

    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp	; rsp
    push rbx
    push rdx
    push rcx
    push rax	
    
    
    sub rsp,100h
	mov rcx,rsp

	call CreateVirtualMachine

    int 3

	jmp AsmVmxResState
AsmCreateVMM ENDP

PUBLIC AsmVmxResState
AsmVmxResState:
	add rsp,100h
	pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    popfq
    add rsp,100h
    ret

getTSC:
	push rdx
	rdtsc
	shl rax,32
	shr rax,32

	shl rdx,32
	or rax,rdx
	pop rdx
	ret

;---------------------------;
;int spinlock(int *lockvar, unsigned long long timeout);
;---------------------------;

PUBLIC spinlock
spinlock:
	sub rsp, 8
	call getTSC
	mov [rsp],rax

spinlock_afterinit:
	lock bts dword ptr [rcx], 0
	jc spinlock_wait

	mov rax,1
	add rsp, 8
	ret

spinlock_wait:
	cmp rdx, 0
	je spinlock_aftertimeoutcheck

	call getTSC
	sub rax,[rsp]
	cmp rax,rdx
	ja spinlock_timeout

spinlock_aftertimeoutcheck:
	pause
	cmp dword ptr [rcx], 0
	je spinlock_afterinit
	jmp spinlock_wait

spinlock_timeout:
	xor rax, rax
	add rsp,8
	ret

PUBLIC getCS
getCS:
	mov ax,cs
	ret
	int 3
	int 3

PUBLIC getSS
getSS:
	mov ax,ss
	ret
	int 3
	int 3

PUBLIC getDS
getDS:
	mov ax,ds
	ret
	int 3
	int 3

PUBLIC getES
getES:
	mov ax,es
	ret	
	int 3
	int 3

PUBLIC getFS
getFS:
	mov ax,fs
	ret
	int 3
	int 3

PUBLIC getGS
getGS:
	mov ax,gs
	ret	
	int 3
	int 3

PUBLIC getTR
getTR:
	STR AX
	ret	
	int 3
	int 3

PUBLIC getGDTbase
getGDTbase:
	push rbp
	mov rbp,rsp
	sub rbp,20
	sgdt [rbp]
	mov rax,[rbp+2]
	pop rbp
	ret
	int 3
	int 3

PUBLIC getGDTlimit
getGDTlimit PROC

	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
	int 3
	int 3

getGDTlimit ENDP

PUBLIC getIDTbase
getIDTbase:
	push rbp
	mov rbp,rsp
	sub rbp,20
	sidt [rbp]
	mov rax,[rbp+2]
	pop rbp
	ret
	int 3
	int 3

PUBLIC reloadIdtr
reloadIdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lidt	fword ptr [rsp+6]
	pop		rax
	pop		rax
	ret
reloadIdtr ENDP

PUBLIC reloadGdtr
reloadGdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lgdt	fword ptr [rsp+6]	; do not try to modify stack selector with this ;)
	pop		rax
	pop		rax
	ret
reloadGdtr ENDP

PUBLIC SetBreakPointEx
SetBreakPointEx:
	int 3
	ret
	int 3
	int 3

PUBLIC DoVmCall
DoVmCall:
	vmcall
	ret

PUBLIC getLdtr
getLdtr PROC
	sldt	rax
	ret
	int 3
	int 3
getLdtr ENDP

PUBLIC Vmx_VmResume
Vmx_VmResume Proc
        vmresume
        ret
Vmx_VmResume endp

_TEXT   ENDS
        END