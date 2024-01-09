REGISTER struct
    _rax     QWORD ?   ; 0x00
    _rcx     QWORD ?   ; 0x08
    _rdx     QWORD ?   ; 0x10
    _rbx     QWORD ?   ; 0x18
    _rsp     QWORD ?   ; 0x20
    _rbp     QWORD ?   ; 0x28
    _rsi     QWORD ?   ; 0x30
    _rdi     QWORD ?   ; 0x38
    _r8      QWORD ?   ; 0x40
    _r9      QWORD ?   ; 0x48
    _r10     QWORD ?   ; 0x50
    _r11     QWORD ?   ; 0x58
    _r12     QWORD ?   ; 0x60
    _r13     QWORD ?   ; 0x68
    _r14     QWORD ?   ; 0x70
    _r15     QWORD ?   ; 0x78

    _rflags  QWORD ?   ; Flags register
    _rip     QWORD ?   ; Instruction pointer

    _cs      WORD  ?   ; Code segment
    _ds      WORD  ?   ; Data segment
    _es      WORD  ?   ; Extra segment
    _fs      WORD  ?   ; FS segment
    _gs      WORD  ?   ; GS segment
    _ss      WORD  ?   ; Stack segment
REGISTER ends



_TEXT SEGMENT 'CODE'

EXTERN CVMMEntryPoint : proc
EXTERN VmxVmresume : proc

AsmVmxOffHandler proc

    mov rax, (REGISTER PTR [rcx])._rax
    mov rbx, (REGISTER PTR [rcx])._rbx
    mov rdx, (REGISTER PTR [rcx])._rdx
    mov rsp, (REGISTER PTR [rcx])._rsp
    mov rbp, (REGISTER PTR [rcx])._rbp
    mov rsi, (REGISTER PTR [rcx])._rsi
    mov rdi, (REGISTER PTR [rcx])._rdi
    mov r8, (REGISTER PTR [rcx])._r8
    mov r9, (REGISTER PTR [rcx])._r9
    mov r10, (REGISTER PTR [rcx])._r10
    mov r11, (REGISTER PTR [rcx])._r11
    mov r12, (REGISTER PTR [rcx])._r12
    mov r13, (REGISTER PTR [rcx])._r13
    mov r14, (REGISTER PTR [rcx])._r14
    mov r15, (REGISTER PTR [rcx])._r15

    push (REGISTER PTR [rcx])._rip
    push (REGISTER PTR [rcx])._rcx
    pop rcx

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
    cmp rax,0
    je VmxResumeHandler
    mov rcx, rax
    jmp AsmVmxOffHandler

VmxResumeHandler:
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