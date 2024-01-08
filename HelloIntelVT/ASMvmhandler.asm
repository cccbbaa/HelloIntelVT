


_TEXT SEGMENT 'CODE'

EXTERN CVMMEntryPoint : proc
EXTERN VmxVmresume : proc

AsmVmxOffHandler proc
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    mov qword ptr [rsp+60h],rbp
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
    pop rsp
    sti
    ret

AsmVmxOffHandler endp

PUBLIC VMMEntryPoint
VMMEntryPoint PROC
    
    ;int 3

    ;cli
    

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

    mov rcx,rsp
    sub rsp,100h
    call CVMMEntryPoint
    add rsp,100h
    ;cmp rax,0
    ;je AsmVmxOffHandler

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
   
    sub rsp,100h
    jmp VmxVmresume

VMMEntryPoint ENDP

_TEXT   ENDS
        END