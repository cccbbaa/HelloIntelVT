#pragma once
#include <windef.h>

#define RPL_MASK                3
#define SELECTOR_TABLE_INDEX    0x04

typedef struct _VMX_GDTENTRY64
{
    UINT64 Base;
    UINT32 Limit;
    union
    {
        struct
        {
            UINT8 Flags1;
            UINT8 Flags2;
            UINT8 Flags3;
            UINT8 Flags4;
        } Bytes;
        struct
        {
            UINT16 SegmentType : 4;
            UINT16 DescriptorType : 1;
            UINT16 Dpl : 2;
            UINT16 Present : 1;

            UINT16 Reserved : 4;
            UINT16 System : 1;
            UINT16 LongMode : 1;
            UINT16 DefaultBig : 1;
            UINT16 Granularity : 1;

            UINT16 Unusable : 1;
            UINT16 Reserved2 : 15;
        } Bits;
        UINT32 AccessRights;
    };
    UINT16 Selector;
} VMX_GDTENTRY64, * PVMX_GDTENTRY64;

typedef union _KGDTENTRY64
{
    struct
    {
        UINT16 LimitLow;
        UINT16 BaseLow;
        union
        {
            struct
            {
                UINT8 BaseMiddle;
                UINT8 Flags1;
                UINT8 Flags2;
                UINT8 BaseHigh;
            } Bytes;
            struct
            {
                UINT32 BaseMiddle : 8;
                UINT32 Type : 5;
                UINT32 Dpl : 2;
                UINT32 Present : 1;
                UINT32 LimitHigh : 4;
                UINT32 System : 1;
                UINT32 LongMode : 1;
                UINT32 DefaultBig : 1;
                UINT32 Granularity : 1;
                UINT32 BaseHigh : 8;
            } Bits;
        };
        UINT32 BaseUpper;
        UINT32 MustBeZero;
    };
    struct
    {
        INT64 DataLow;
        INT64 DataHigh;
    };
} KGDTENTRY64, * PKGDTENTRY64;

typedef enum _SEGMENT_REGISTERS
{
    ES = 0,
    CS,
    SS,
    DS,
    FS,
    GS,
    LDTR,
    TR
}SEGMENT_REGISTERS;

typedef struct _SEGMENT_DESCRIPTOR
{
    USHORT LIMIT0;
    USHORT BASE0;
    UCHAR  BASE1;
    UCHAR  ATTR0;
    UCHAR  LIMIT1ATTR1;
    UCHAR  BASE2;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

typedef union _SEGMENT_ATTRIBUTES
{
    USHORT UCHARs;
    struct
    {
        USHORT TYPE : 4; /* 0;  Bit 40-43 */
        USHORT S : 1;    /* 4;  Bit 44 */
        USHORT DPL : 2;  /* 5;  Bit 45-46 */
        USHORT P : 1;    /* 7;  Bit 47 */

        USHORT AVL : 1; /* 8;  Bit 52 */
        USHORT L : 1;   /* 9;  Bit 53 */
        USHORT DB : 1;  /* 10; Bit 54 */
        USHORT G : 1;   /* 11; Bit 55 */
        USHORT GAP : 4;

    } Fields;
} SEGMENT_ATTRIBUTES, * PSEGMENT_ATTRIBUTES;

typedef struct _SEGMENT_SELECTORS
{
    USHORT             SEL;
    SEGMENT_ATTRIBUTES ATTRIBUTES;
    ULONG32            LIMIT;
    ULONG64            BASE;
} SEGMENT_SELECTORS, * PSEGMENT_SELECTORS;


#pragma pack(push)
#pragma pack(1)
typedef struct _TSS64
{
    unsigned reserved1 : 32;
    unsigned long long RSP0;
    unsigned long long RSP1;
    unsigned long long RSP2;
    unsigned long long reserved2;

    unsigned long long IST1;
    unsigned long long IST2;
    unsigned long long IST3;
    unsigned long long IST4;
    unsigned long long IST5;
    unsigned long long IST6;
    unsigned long long IST7;
    unsigned long long reserved3;
    unsigned reserved4 : 16;
    unsigned IOBASE : 16;
} TSS64, * PTSS64;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct IDTDescriptor {
    unsigned short Limit;
    unsigned long long Base;
}IDTDescriptor;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * The 64-bit RFLAGS register contains a group of status flags, a control flag, and a group of system flags in 64-bit mode.
 * The upper 32 bits of RFLAGS register is reserved. The lower 32 bits of RFLAGS is the same as EFLAGS.
 *
 * @see EFLAGS
 * @see Vol1[3.4.3.4(RFLAGS Register in 64-Bit Mode)] (reference)
 */
typedef union
{
    struct
    {
        /**
         * @brief Carry flag
         *
         * [Bit 0] See the description in EFLAGS.
         */
        UINT64 CarryFlag : 1;
#define RFLAGS_CARRY_FLAG_BIT                                        0
#define RFLAGS_CARRY_FLAG_FLAG                                       0x01
#define RFLAGS_CARRY_FLAG_MASK                                       0x01
#define RFLAGS_CARRY_FLAG(_)                                         (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Reserved - always 1
         */
        UINT64 ReadAs1 : 1;
#define RFLAGS_READ_AS_1_BIT                                         1
#define RFLAGS_READ_AS_1_FLAG                                        0x02
#define RFLAGS_READ_AS_1_MASK                                        0x01
#define RFLAGS_READ_AS_1(_)                                          (((_) >> 1) & 0x01)

        /**
         * @brief Parity flag
         *
         * [Bit 2] See the description in EFLAGS.
         */
        UINT64 ParityFlag : 1;
#define RFLAGS_PARITY_FLAG_BIT                                       2
#define RFLAGS_PARITY_FLAG_FLAG                                      0x04
#define RFLAGS_PARITY_FLAG_MASK                                      0x01
#define RFLAGS_PARITY_FLAG(_)                                        (((_) >> 2) & 0x01)
        UINT64 Reserved1 : 1;

        /**
         * @brief Auxiliary Carry flag
         *
         * [Bit 4] See the description in EFLAGS.
         */
        UINT64 AuxiliaryCarryFlag : 1;
#define RFLAGS_AUXILIARY_CARRY_FLAG_BIT                              4
#define RFLAGS_AUXILIARY_CARRY_FLAG_FLAG                             0x10
#define RFLAGS_AUXILIARY_CARRY_FLAG_MASK                             0x01
#define RFLAGS_AUXILIARY_CARRY_FLAG(_)                               (((_) >> 4) & 0x01)
        UINT64 Reserved2 : 1;

        /**
         * @brief Zero flag
         *
         * [Bit 6] See the description in EFLAGS.
         */
        UINT64 ZeroFlag : 1;
#define RFLAGS_ZERO_FLAG_BIT                                         6
#define RFLAGS_ZERO_FLAG_FLAG                                        0x40
#define RFLAGS_ZERO_FLAG_MASK                                        0x01
#define RFLAGS_ZERO_FLAG(_)                                          (((_) >> 6) & 0x01)

        /**
         * @brief Sign flag
         *
         * [Bit 7] See the description in EFLAGS.
         */
        UINT64 SignFlag : 1;
#define RFLAGS_SIGN_FLAG_BIT                                         7
#define RFLAGS_SIGN_FLAG_FLAG                                        0x80
#define RFLAGS_SIGN_FLAG_MASK                                        0x01
#define RFLAGS_SIGN_FLAG(_)                                          (((_) >> 7) & 0x01)

        /**
         * @brief Trap flag
         *
         * [Bit 8] See the description in EFLAGS.
         */
        UINT64 TrapFlag : 1;
#define RFLAGS_TRAP_FLAG_BIT                                         8
#define RFLAGS_TRAP_FLAG_FLAG                                        0x100
#define RFLAGS_TRAP_FLAG_MASK                                        0x01
#define RFLAGS_TRAP_FLAG(_)                                          (((_) >> 8) & 0x01)

        /**
         * @brief Interrupt enable flag
         *
         * [Bit 9] See the description in EFLAGS.
         */
        UINT64 InterruptEnableFlag : 1;
#define RFLAGS_INTERRUPT_ENABLE_FLAG_BIT                             9
#define RFLAGS_INTERRUPT_ENABLE_FLAG_FLAG                            0x200
#define RFLAGS_INTERRUPT_ENABLE_FLAG_MASK                            0x01
#define RFLAGS_INTERRUPT_ENABLE_FLAG(_)                              (((_) >> 9) & 0x01)

        /**
         * @brief Direction flag
         *
         * [Bit 10] See the description in EFLAGS.
         */
        UINT64 DirectionFlag : 1;
#define RFLAGS_DIRECTION_FLAG_BIT                                    10
#define RFLAGS_DIRECTION_FLAG_FLAG                                   0x400
#define RFLAGS_DIRECTION_FLAG_MASK                                   0x01
#define RFLAGS_DIRECTION_FLAG(_)                                     (((_) >> 10) & 0x01)

        /**
         * @brief Overflow flag
         *
         * [Bit 11] See the description in EFLAGS.
         */
        UINT64 OverflowFlag : 1;
#define RFLAGS_OVERFLOW_FLAG_BIT                                     11
#define RFLAGS_OVERFLOW_FLAG_FLAG                                    0x800
#define RFLAGS_OVERFLOW_FLAG_MASK                                    0x01
#define RFLAGS_OVERFLOW_FLAG(_)                                      (((_) >> 11) & 0x01)

        /**
         * @brief I/O privilege level field
         *
         * [Bits 13:12] See the description in EFLAGS.
         */
        UINT64 IoPrivilegeLevel : 2;
#define RFLAGS_IO_PRIVILEGE_LEVEL_BIT                                12
#define RFLAGS_IO_PRIVILEGE_LEVEL_FLAG                               0x3000
#define RFLAGS_IO_PRIVILEGE_LEVEL_MASK                               0x03
#define RFLAGS_IO_PRIVILEGE_LEVEL(_)                                 (((_) >> 12) & 0x03)

        /**
         * @brief Nested task flag
         *
         * [Bit 14] See the description in EFLAGS.
         */
        UINT64 NestedTaskFlag : 1;
#define RFLAGS_NESTED_TASK_FLAG_BIT                                  14
#define RFLAGS_NESTED_TASK_FLAG_FLAG                                 0x4000
#define RFLAGS_NESTED_TASK_FLAG_MASK                                 0x01
#define RFLAGS_NESTED_TASK_FLAG(_)                                   (((_) >> 14) & 0x01)
        UINT64 Reserved3 : 1;

        /**
         * @brief Resume flag
         *
         * [Bit 16] See the description in EFLAGS.
         */
        UINT64 ResumeFlag : 1;
#define RFLAGS_RESUME_FLAG_BIT                                       16
#define RFLAGS_RESUME_FLAG_FLAG                                      0x10000
#define RFLAGS_RESUME_FLAG_MASK                                      0x01
#define RFLAGS_RESUME_FLAG(_)                                        (((_) >> 16) & 0x01)

        /**
         * @brief Virtual-8086 mode flag
         *
         * [Bit 17] See the description in EFLAGS.
         */
        UINT64 Virtual8086ModeFlag : 1;
#define RFLAGS_VIRTUAL_8086_MODE_FLAG_BIT                            17
#define RFLAGS_VIRTUAL_8086_MODE_FLAG_FLAG                           0x20000
#define RFLAGS_VIRTUAL_8086_MODE_FLAG_MASK                           0x01
#define RFLAGS_VIRTUAL_8086_MODE_FLAG(_)                             (((_) >> 17) & 0x01)

        /**
         * @brief Alignment check (or access control) flag
         *
         * [Bit 18] See the description in EFLAGS.
         *
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        UINT64 AlignmentCheckFlag : 1;
#define RFLAGS_ALIGNMENT_CHECK_FLAG_BIT                              18
#define RFLAGS_ALIGNMENT_CHECK_FLAG_FLAG                             0x40000
#define RFLAGS_ALIGNMENT_CHECK_FLAG_MASK                             0x01
#define RFLAGS_ALIGNMENT_CHECK_FLAG(_)                               (((_) >> 18) & 0x01)

        /**
         * @brief Virtual interrupt flag
         *
         * [Bit 19] See the description in EFLAGS.
         */
        UINT64 VirtualInterruptFlag : 1;
#define RFLAGS_VIRTUAL_INTERRUPT_FLAG_BIT                            19
#define RFLAGS_VIRTUAL_INTERRUPT_FLAG_FLAG                           0x80000
#define RFLAGS_VIRTUAL_INTERRUPT_FLAG_MASK                           0x01
#define RFLAGS_VIRTUAL_INTERRUPT_FLAG(_)                             (((_) >> 19) & 0x01)

        /**
         * @brief Virtual interrupt pending flag
         *
         * [Bit 20] See the description in EFLAGS.
         */
        UINT64 VirtualInterruptPendingFlag : 1;
#define RFLAGS_VIRTUAL_INTERRUPT_PENDING_FLAG_BIT                    20
#define RFLAGS_VIRTUAL_INTERRUPT_PENDING_FLAG_FLAG                   0x100000
#define RFLAGS_VIRTUAL_INTERRUPT_PENDING_FLAG_MASK                   0x01
#define RFLAGS_VIRTUAL_INTERRUPT_PENDING_FLAG(_)                     (((_) >> 20) & 0x01)

        /**
         * @brief Identification flag
         *
         * [Bit 21] See the description in EFLAGS.
         */
        UINT64 IdentificationFlag : 1;
#define RFLAGS_IDENTIFICATION_FLAG_BIT                               21
#define RFLAGS_IDENTIFICATION_FLAG_FLAG                              0x200000
#define RFLAGS_IDENTIFICATION_FLAG_MASK                              0x01
#define RFLAGS_IDENTIFICATION_FLAG(_)                                (((_) >> 21) & 0x01)
        UINT64 Reserved4 : 42;
    };

    UINT64 AsUInt;
} RFLAGS;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct _GUEST_REGS
{
    ULONG64 rax; // 0x00
    ULONG64 rcx; // 0x08
    ULONG64 rdx; // 0x10
    ULONG64 rbx; // 0x18
    ULONG64 rsp; // 0x20
    ULONG64 rbp; // 0x28
    ULONG64 rsi; // 0x30
    ULONG64 rdi; // 0x38
    ULONG64 r8;  // 0x40
    ULONG64 r9;  // 0x48
    ULONG64 r10; // 0x50
    ULONG64 r11; // 0x58
    ULONG64 r12; // 0x60
    ULONG64 r13; // 0x68
    ULONG64 r14; // 0x70
    ULONG64 r15; // 0x78
} GUEST_REGS, * PGUEST_REGS;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _REGISGER
{
    ULONG64 rax; // 0x00
    ULONG64 rcx; // 0x08
    ULONG64 rdx; // 0x10
    ULONG64 rbx; // 0x18
    ULONG64 rsp; // 0x20
    ULONG64 rbp; // 0x28
    ULONG64 rsi; // 0x30
    ULONG64 rdi; // 0x38
    ULONG64 r8;  // 0x40
    ULONG64 r9;  // 0x48
    ULONG64 r10; // 0x50
    ULONG64 r11; // 0x58
    ULONG64 r12; // 0x60
    ULONG64 r13; // 0x68
    ULONG64 r14; // 0x70
    ULONG64 r15; // 0x78

    ULONG64 rflags;
    ULONG64 rip;

    WORD cs;
    WORD ds;
    WORD es;
    WORD fs;
    WORD gs;
    WORD ss;

} Register, * pRegister;
#pragma pack(pop)

#pragma pack(push, 1)
typedef union
{
    struct
    {
        /**
         * [Bits 3:0] Number of control register (0 for CLTS and LMSW). Bit 3 is always 0 on processors that do not support Intel
         * 64 architecture as they do not support CR8.
         */
        UINT64 ControlRegister : 4;
#define VMX_EXIT_QUALIFICATION_MOV_CR_CONTROL_REGISTER_BIT           0
#define VMX_EXIT_QUALIFICATION_MOV_CR_CONTROL_REGISTER_FLAG          0x0F
#define VMX_EXIT_QUALIFICATION_MOV_CR_CONTROL_REGISTER_MASK          0x0F
#define VMX_EXIT_QUALIFICATION_MOV_CR_CONTROL_REGISTER(_)            (((_) >> 0) & 0x0F)
#define VMX_EXIT_QUALIFICATION_REGISTER_CR0                          0x00000000
#define VMX_EXIT_QUALIFICATION_REGISTER_CR2                          0x00000002
#define VMX_EXIT_QUALIFICATION_REGISTER_CR3                          0x00000003
#define VMX_EXIT_QUALIFICATION_REGISTER_CR4                          0x00000004
#define VMX_EXIT_QUALIFICATION_REGISTER_CR8                          0x00000008

        /**
         * [Bits 5:4] Access type.
         */
        UINT64 AccessType : 2;
#define VMX_EXIT_QUALIFICATION_MOV_CR_ACCESS_TYPE_BIT                4
#define VMX_EXIT_QUALIFICATION_MOV_CR_ACCESS_TYPE_FLAG               0x30
#define VMX_EXIT_QUALIFICATION_MOV_CR_ACCESS_TYPE_MASK               0x03
#define VMX_EXIT_QUALIFICATION_MOV_CR_ACCESS_TYPE(_)                 (((_) >> 4) & 0x03)
#define VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR                      0x00000000
#define VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR                    0x00000001
#define VMX_EXIT_QUALIFICATION_ACCESS_CLTS                           0x00000002
#define VMX_EXIT_QUALIFICATION_ACCESS_LMSW                           0x00000003

        /**
         * [Bit 6] LMSW operand type. For CLTS and MOV CR, cleared to 0.
         */
        UINT64 LmswOperandType : 1;
#define VMX_EXIT_QUALIFICATION_MOV_CR_LMSW_OPERAND_TYPE_BIT          6
#define VMX_EXIT_QUALIFICATION_MOV_CR_LMSW_OPERAND_TYPE_FLAG         0x40
#define VMX_EXIT_QUALIFICATION_MOV_CR_LMSW_OPERAND_TYPE_MASK         0x01
#define VMX_EXIT_QUALIFICATION_MOV_CR_LMSW_OPERAND_TYPE(_)           (((_) >> 6) & 0x01)
#define VMX_EXIT_QUALIFICATION_LMSW_OP_REGISTER                      0x00000000
#define VMX_EXIT_QUALIFICATION_LMSW_OP_MEMORY                        0x00000001
        UINT64 Reserved1 : 1;

        /**
         * [Bits 11:8] For MOV CR, the general-purpose register.
         */
        UINT64 GeneralPurposeRegister : 4;
#define VMX_EXIT_QUALIFICATION_MOV_CR_GENERAL_PURPOSE_REGISTER_BIT   8
#define VMX_EXIT_QUALIFICATION_MOV_CR_GENERAL_PURPOSE_REGISTER_FLAG  0xF00
#define VMX_EXIT_QUALIFICATION_MOV_CR_GENERAL_PURPOSE_REGISTER_MASK  0x0F
#define VMX_EXIT_QUALIFICATION_MOV_CR_GENERAL_PURPOSE_REGISTER(_)    (((_) >> 8) & 0x0F)
#define VMX_EXIT_QUALIFICATION_GENREG_RAX                            0x00000000
#define VMX_EXIT_QUALIFICATION_GENREG_RCX                            0x00000001
#define VMX_EXIT_QUALIFICATION_GENREG_RDX                            0x00000002
#define VMX_EXIT_QUALIFICATION_GENREG_RBX                            0x00000003
#define VMX_EXIT_QUALIFICATION_GENREG_RSP                            0x00000004
#define VMX_EXIT_QUALIFICATION_GENREG_RBP                            0x00000005
#define VMX_EXIT_QUALIFICATION_GENREG_RSI                            0x00000006
#define VMX_EXIT_QUALIFICATION_GENREG_RDI                            0x00000007
#define VMX_EXIT_QUALIFICATION_GENREG_R8                             0x00000008
#define VMX_EXIT_QUALIFICATION_GENREG_R9                             0x00000009
#define VMX_EXIT_QUALIFICATION_GENREG_R10                            0x0000000A
#define VMX_EXIT_QUALIFICATION_GENREG_R11                            0x0000000B
#define VMX_EXIT_QUALIFICATION_GENREG_R12                            0x0000000C
#define VMX_EXIT_QUALIFICATION_GENREG_R13                            0x0000000D
#define VMX_EXIT_QUALIFICATION_GENREG_R14                            0x0000000E
#define VMX_EXIT_QUALIFICATION_GENREG_R15                            0x0000000F
        UINT64 Reserved2 : 4;

        /**
         * [Bits 31:16] For LMSW, the LMSW source data. For CLTS and MOV CR, cleared to 0.
         */
        UINT64 LmswSourceData : 16;
#define VMX_EXIT_QUALIFICATION_MOV_CR_LMSW_SOURCE_DATA_BIT           16
#define VMX_EXIT_QUALIFICATION_MOV_CR_LMSW_SOURCE_DATA_FLAG          0xFFFF0000
#define VMX_EXIT_QUALIFICATION_MOV_CR_LMSW_SOURCE_DATA_MASK          0xFFFF
#define VMX_EXIT_QUALIFICATION_MOV_CR_LMSW_SOURCE_DATA(_)            (((_) >> 16) & 0xFFFF)
        UINT64 Reserved3 : 32;
    };

    UINT64 AsUInt;
} VMX_EXIT_QUALIFICATION_MOV_CR;
#pragma pack(pop)

#pragma pack(push, 1)

typedef union
{
    struct
    {
        /**
         * @brief Protection Enable
         *
         * [Bit 0] Enables protected mode when set; enables real-address mode when clear. This flag does not enable paging
         * directly. It only enables segment-level protection. To enable paging, both the PE and PG flags must be set.
         *
         * @see Vol3A[9.9(Mode Switching)]
         */
        UINT64 ProtectionEnable : 1;
#define CR0_PROTECTION_ENABLE_BIT                                    0
#define CR0_PROTECTION_ENABLE_FLAG                                   0x01
#define CR0_PROTECTION_ENABLE_MASK                                   0x01
#define CR0_PROTECTION_ENABLE(_)                                     (((_) >> 0) & 0x01)

        /**
         * @brief Monitor Coprocessor
         *
         * [Bit 1] Controls the interaction of the WAIT (or FWAIT) instruction with the TS flag (bit 3 of CR0). If the MP flag is
         * set, a WAIT instruction generates a device-not-available exception (\#NM) if the TS flag is also set. If the MP flag is
         * clear, the WAIT instruction ignores the setting of the TS flag.
         */
        UINT64 MonitorCoprocessor : 1;
#define CR0_MONITOR_COPROCESSOR_BIT                                  1
#define CR0_MONITOR_COPROCESSOR_FLAG                                 0x02
#define CR0_MONITOR_COPROCESSOR_MASK                                 0x01
#define CR0_MONITOR_COPROCESSOR(_)                                   (((_) >> 1) & 0x01)

        /**
         * @brief FPU Emulation
         *
         * [Bit 2] Indicates that the processor does not have an internal or external x87 FPU when set; indicates an x87 FPU is
         * present when clear. This flag also affects the execution of MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
         * When the EM flag is set, execution of an x87 FPU instruction generates a device-not-available exception (\#NM). This
         * flag must be set when the processor does not have an internal x87 FPU or is not connected to an external math
         * coprocessor. Setting this flag forces all floating-point instructions to be handled by software emulation.
         * Also, when the EM flag is set, execution of an MMX instruction causes an invalid-opcode exception (\#UD) to be
         * generated. Thus, if an IA-32 or Intel 64 processor incorporates MMX technology, the EM flag must be set to 0 to enable
         * execution of MMX instructions. Similarly for SSE/SSE2/SSE3/SSSE3/SSE4 extensions, when the EM flag is set, execution of
         * most SSE/SSE2/SSE3/SSSE3/SSE4 instructions causes an invalid opcode exception (\#UD) to be generated. If an IA-32 or
         * Intel 64 processor incorporates the SSE/SSE2/SSE3/SSSE3/SSE4 extensions, the EM flag must be set to 0 to enable
         * execution of these extensions. SSE/SSE2/SSE3/SSSE3/SSE4 instructions not affected by the EM flag include: PAUSE,
         * PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
         */
        UINT64 EmulateFpu : 1;
#define CR0_EMULATE_FPU_BIT                                          2
#define CR0_EMULATE_FPU_FLAG                                         0x04
#define CR0_EMULATE_FPU_MASK                                         0x01
#define CR0_EMULATE_FPU(_)                                           (((_) >> 2) & 0x01)

        /**
         * @brief Task Switched
         *
         * [Bit 3] Allows the saving of the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 context on a task switch to be delayed until an
         * x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction is actually executed by the new task. The processor sets this flag on
         * every task switch and tests it when executing x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
         * - If the TS flag is set and the EM flag (bit 2 of CR0) is clear, a device-not-available exception (\#NM) is raised prior
         * to the execution of any x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction; with the exception of PAUSE, PREFETCHh,
         * SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
         * - If the TS flag is set and the MP flag (bit 1 of CR0) and EM flag are clear, an \#NM exception is not raised prior to
         * the execution of an x87 FPU WAIT/FWAIT instruction.
         * - If the EM flag is set, the setting of the TS flag has no effect on the execution of x87
         * FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
         *   The processor does not automatically save the context of the x87 FPU, XMM, and MXCSR registers on a task switch.
         *   Instead, it sets the TS flag, which causes the processor to raise an \#NM exception whenever it encounters an x87
         *   FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction in the instruction stream for the new task (with the exception of the
         *   instructions listed above).
         *   The fault handler for the \#NM exception can then be used to clear the TS flag (with the CLTS instruction) and save
         *   the context of the x87 FPU, XMM, and MXCSR registers. If the task never encounters an x87
         *   FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction, the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 context is never saved.
         */
        UINT64 TaskSwitched : 1;
#define CR0_TASK_SWITCHED_BIT                                        3
#define CR0_TASK_SWITCHED_FLAG                                       0x08
#define CR0_TASK_SWITCHED_MASK                                       0x01
#define CR0_TASK_SWITCHED(_)                                         (((_) >> 3) & 0x01)

        /**
         * @brief Extension Type
         *
         * [Bit 4] Reserved in the Pentium 4, Intel Xeon, P6 family, and Pentium processors. In the Pentium 4, Intel Xeon, and P6
         * family processors, this flag is hardcoded to 1. In the Intel386 and Intel486 processors, this flag indicates support of
         * Intel 387 DX math coprocessor instructions when set.
         */
        UINT64 ExtensionType : 1;
#define CR0_EXTENSION_TYPE_BIT                                       4
#define CR0_EXTENSION_TYPE_FLAG                                      0x10
#define CR0_EXTENSION_TYPE_MASK                                      0x01
#define CR0_EXTENSION_TYPE(_)                                        (((_) >> 4) & 0x01)

        /**
         * @brief Numeric Error
         *
         * [Bit 5] Enables the native (internal) mechanism for reporting x87 FPU errors when set; enables the PC-style x87 FPU
         * error reporting mechanism when clear. When the NE flag is clear and the IGNNE\# input is asserted, x87 FPU errors are
         * ignored. When the NE flag is clear and the IGNNE\# input is deasserted, an unmasked x87 FPU error causes the processor
         * to assert the FERR\# pin to generate an external interrupt and to stop instruction execution immediately before
         * executing the next waiting floating-point instruction or WAIT/FWAIT instruction.
         * The FERR\# pin is intended to drive an input to an external interrupt controller (the FERR\# pin emulates the ERROR\#
         * pin of the Intel 287 and Intel 387 DX math coprocessors). The NE flag, IGNNE\# pin, and FERR\# pin are used with
         * external logic to implement PC-style error reporting. Using FERR\# and IGNNE\# to handle floating-point exceptions is
         * deprecated by modern operating systems; this non-native approach also limits newer processors to operate with one
         * logical processor active.
         *
         * @see Vol1[8.7(Handling x87 FPU Exceptions in Software)]
         * @see Vol1[A.1(APPENDIX A | EFLAGS Cross-Reference)]
         */
        UINT64 NumericError : 1;
#define CR0_NUMERIC_ERROR_BIT                                        5
#define CR0_NUMERIC_ERROR_FLAG                                       0x20
#define CR0_NUMERIC_ERROR_MASK                                       0x01
#define CR0_NUMERIC_ERROR(_)                                         (((_) >> 5) & 0x01)
        UINT64 Reserved1 : 10;

        /**
         * @brief Write Protect
         *
         * [Bit 16] When set, inhibits supervisor-level procedures from writing into readonly pages; when clear, allows
         * supervisor-level procedures to write into read-only pages (regardless of the U/S bit setting). This flag facilitates
         * implementation of the copy-onwrite method of creating a new process (forking) used by operating systems such as UNIX.
         *
         * @see Vol3A[4.1.3(Paging-Mode Modifiers)]
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        UINT64 WriteProtect : 1;
#define CR0_WRITE_PROTECT_BIT                                        16
#define CR0_WRITE_PROTECT_FLAG                                       0x10000
#define CR0_WRITE_PROTECT_MASK                                       0x01
#define CR0_WRITE_PROTECT(_)                                         (((_) >> 16) & 0x01)
        UINT64 Reserved2 : 1;

        /**
         * @brief Alignment Mask
         *
         * [Bit 18] Enables automatic alignment checking when set; disables alignment checking when clear. Alignment checking is
         * performed only when the AM flag is set, the AC flag in the EFLAGS register is set, CPL is 3, and the processor is
         * operating in either protected or virtual-8086 mode.
         */
        UINT64 AlignmentMask : 1;
#define CR0_ALIGNMENT_MASK_BIT                                       18
#define CR0_ALIGNMENT_MASK_FLAG                                      0x40000
#define CR0_ALIGNMENT_MASK_MASK                                      0x01
#define CR0_ALIGNMENT_MASK(_)                                        (((_) >> 18) & 0x01)
        UINT64 Reserved3 : 10;

        /**
         * @brief Not Write-through
         *
         * [Bit 29] When the NW and CD flags are clear, write-back (for Pentium 4, Intel Xeon, P6 family, and Pentium processors)
         * or write-through (for Intel486 processors) is enabled for writes that hit the cache and invalidation cycles are enabled.
         */
        UINT64 NotWriteThrough : 1;
#define CR0_NOT_WRITE_THROUGH_BIT                                    29
#define CR0_NOT_WRITE_THROUGH_FLAG                                   0x20000000
#define CR0_NOT_WRITE_THROUGH_MASK                                   0x01
#define CR0_NOT_WRITE_THROUGH(_)                                     (((_) >> 29) & 0x01)

        /**
         * @brief Cache Disable
         *
         * [Bit 30] When the CD and NW flags are clear, caching of memory locations for the whole of physical memory in the
         * processor's internal (and external) caches is enabled. When the CD flag is set, caching is restricted. To prevent the
         * processor from accessing and updating its caches, the CD flag must be set and the caches must be invalidated so that no
         * cache hits can occur.
         *
         * @see Vol3A[11.5.3(Preventing Caching)]
         * @see Vol3A[11.5(CACHE CONTROL)]
         */
        UINT64 CacheDisable : 1;
#define CR0_CACHE_DISABLE_BIT                                        30
#define CR0_CACHE_DISABLE_FLAG                                       0x40000000
#define CR0_CACHE_DISABLE_MASK                                       0x01
#define CR0_CACHE_DISABLE(_)                                         (((_) >> 30) & 0x01)

        /**
         * @brief Paging Enable
         *
         * [Bit 31] Enables paging when set; disables paging when clear. When paging is disabled, all linear addresses are treated
         * as physical addresses. The PG flag has no effect if the PE flag (bit 0 of register CR0) is not also set; setting the PG
         * flag when the PE flag is clear causes a general-protection exception (\#GP).
         * On Intel 64 processors, enabling and disabling IA-32e mode operation also requires modifying CR0.PG.
         *
         * @see Vol3A[4(PAGING)]
         */
        UINT64 PagingEnable : 1;
#define CR0_PAGING_ENABLE_BIT                                        31
#define CR0_PAGING_ENABLE_FLAG                                       0x80000000
#define CR0_PAGING_ENABLE_MASK                                       0x01
#define CR0_PAGING_ENABLE(_)                                         (((_) >> 31) & 0x01)
        UINT64 Reserved4 : 32;
    };

    UINT64 AsUInt;
} CR0;

typedef union
{
    struct
    {
        /**
         * @brief Virtual-8086 Mode Extensions
         *
         * [Bit 0] Enables interrupt- and exception-handling extensions in virtual-8086 mode when set; disables the extensions when
         * clear. Use of the virtual mode extensions can improve the performance of virtual-8086 applications by eliminating the
         * overhead of calling the virtual- 8086 monitor to handle interrupts and exceptions that occur while executing an 8086
         * program and, instead, redirecting the interrupts and exceptions back to the 8086 program's handlers. It also provides
         * hardware support for a virtual interrupt flag (VIF) to improve reliability of running 8086 programs in multitasking and
         * multiple-processor environments.
         *
         * @see Vol3B[20.3(INTERRUPT AND EXCEPTION HANDLING IN VIRTUAL-8086 MODE)]
         */
        UINT64 VirtualModeExtensions : 1;
#define CR4_VIRTUAL_MODE_EXTENSIONS_BIT                              0
#define CR4_VIRTUAL_MODE_EXTENSIONS_FLAG                             0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS_MASK                             0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS(_)                               (((_) >> 0) & 0x01)

        /**
         * @brief Protected-Mode Virtual Interrupts
         *
         * [Bit 1] Enables hardware support for a virtual interrupt flag (VIF) in protected mode when set; disables the VIF flag in
         * protected mode when clear.
         *
         * @see Vol3B[20.4(PROTECTED-MODE VIRTUAL INTERRUPTS)]
         */
        UINT64 ProtectedModeVirtualInterrupts : 1;
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_BIT                    1
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_FLAG                   0x02
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_MASK                   0x01
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS(_)                     (((_) >> 1) & 0x01)

        /**
         * @brief Time Stamp Disable
         *
         * [Bit 2] Restricts the execution of the RDTSC instruction to procedures running at privilege level 0 when set; allows
         * RDTSC instruction to be executed at any privilege level when clear. This bit also applies to the RDTSCP instruction if
         * supported (if CPUID.80000001H:EDX[27] = 1).
         */
        UINT64 TimestampDisable : 1;
#define CR4_TIMESTAMP_DISABLE_BIT                                    2
#define CR4_TIMESTAMP_DISABLE_FLAG                                   0x04
#define CR4_TIMESTAMP_DISABLE_MASK                                   0x01
#define CR4_TIMESTAMP_DISABLE(_)                                     (((_) >> 2) & 0x01)

        /**
         * @brief Debugging Extensions
         *
         * [Bit 3] References to debug registers DR4 and DR5 cause an undefined opcode (\#UD) exception to be generated when set;
         * when clear, processor aliases references to registers DR4 and DR5 for compatibility with software written to run on
         * earlier IA-32 processors.
         *
         * @see Vol3B[17.2.2(Debug Registers DR4 and DR5)]
         */
        UINT64 DebuggingExtensions : 1;
#define CR4_DEBUGGING_EXTENSIONS_BIT                                 3
#define CR4_DEBUGGING_EXTENSIONS_FLAG                                0x08
#define CR4_DEBUGGING_EXTENSIONS_MASK                                0x01
#define CR4_DEBUGGING_EXTENSIONS(_)                                  (((_) >> 3) & 0x01)

        /**
         * @brief Page Size Extensions
         *
         * [Bit 4] Enables 4-MByte pages with 32-bit paging when set; restricts 32-bit paging to pages of 4 KBytes when clear.
         *
         * @see Vol3A[4.3(32-BIT PAGING)]
         */
        UINT64 PageSizeExtensions : 1;
#define CR4_PAGE_SIZE_EXTENSIONS_BIT                                 4
#define CR4_PAGE_SIZE_EXTENSIONS_FLAG                                0x10
#define CR4_PAGE_SIZE_EXTENSIONS_MASK                                0x01
#define CR4_PAGE_SIZE_EXTENSIONS(_)                                  (((_) >> 4) & 0x01)

        /**
         * @brief Physical Address Extension
         *
         * [Bit 5] When set, enables paging to produce physical addresses with more than 32 bits. When clear, restricts physical
         * addresses to 32 bits. PAE must be set before entering IA-32e mode.
         *
         * @see Vol3A[4(PAGING)]
         */
        UINT64 PhysicalAddressExtension : 1;
#define CR4_PHYSICAL_ADDRESS_EXTENSION_BIT                           5
#define CR4_PHYSICAL_ADDRESS_EXTENSION_FLAG                          0x20
#define CR4_PHYSICAL_ADDRESS_EXTENSION_MASK                          0x01
#define CR4_PHYSICAL_ADDRESS_EXTENSION(_)                            (((_) >> 5) & 0x01)

        /**
         * @brief Machine-Check Enable
         *
         * [Bit 6] Enables the machine-check exception when set; disables the machine-check exception when clear.
         *
         * @see Vol3B[15(MACHINE-CHECK ARCHITECTURE)]
         */
        UINT64 MachineCheckEnable : 1;
#define CR4_MACHINE_CHECK_ENABLE_BIT                                 6
#define CR4_MACHINE_CHECK_ENABLE_FLAG                                0x40
#define CR4_MACHINE_CHECK_ENABLE_MASK                                0x01
#define CR4_MACHINE_CHECK_ENABLE(_)                                  (((_) >> 6) & 0x01)

        /**
         * @brief Page Global Enable
         *
         * [Bit 7] (Introduced in the P6 family processors.) Enables the global page feature when set; disables the global page
         * feature when clear. The global page feature allows frequently used or shared pages to be marked as global to all users
         * (done with the global flag, bit 8, in a page-directory or page-table entry). Global pages are not flushed from the
         * translation-lookaside buffer (TLB) on a task switch or a write to register CR3. When enabling the global page feature,
         * paging must be enabled (by setting the PG flag in control register CR0) before the PGE flag is set. Reversing this
         * sequence may affect program correctness, and processor performance will be impacted.
         *
         * @see Vol3A[4.10(CACHING TRANSLATION INFORMATION)]
         */
        UINT64 PageGlobalEnable : 1;
#define CR4_PAGE_GLOBAL_ENABLE_BIT                                   7
#define CR4_PAGE_GLOBAL_ENABLE_FLAG                                  0x80
#define CR4_PAGE_GLOBAL_ENABLE_MASK                                  0x01
#define CR4_PAGE_GLOBAL_ENABLE(_)                                    (((_) >> 7) & 0x01)

        /**
         * @brief Performance-Monitoring Counter Enable
         *
         * [Bit 8] Enables execution of the RDPMC instruction for programs or procedures running at any protection level when set;
         * RDPMC instruction can be executed only at protection level 0 when clear.
         */
        UINT64 PerformanceMonitoringCounterEnable : 1;
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_BIT                8
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_FLAG               0x100
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_MASK               0x01
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE(_)                 (((_) >> 8) & 0x01)

        /**
         * @brief Operating System Support for FXSAVE and FXRSTOR instructions
         *
         * [Bit 9] When set, this flag:
         * -# indicates to software that the operating system supports the use of the FXSAVE and FXRSTOR instructions,
         * -# enables the FXSAVE and FXRSTOR instructions to save and restore the contents of the XMM and MXCSR registers along
         * with the contents of the x87 FPU and MMX registers, and
         * -# enables the processor to execute SSE/SSE2/SSE3/SSSE3/SSE4 instructions, with the exception of the PAUSE, PREFETCHh,
         * SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
         * If this flag is clear, the FXSAVE and FXRSTOR instructions will save and restore the contents of the x87 FPU and MMX
         * registers, but they may not save and restore the contents of the XMM and MXCSR registers. Also, the processor will
         * generate an invalid opcode exception (\#UD) if it attempts to execute any SSE/SSE2/SSE3 instruction, with the exception
         * of PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT. The operating system or executive must
         * explicitly set this flag.
         *
         * @remarks CPUID feature flag FXSR indicates availability of the FXSAVE/FXRSTOR instructions. The OSFXSR bit provides
         *          operating system software with a means of enabling FXSAVE/FXRSTOR to save/restore the contents of the X87 FPU, XMM and
         *          MXCSR registers. Consequently OSFXSR bit indicates that the operating system provides context switch support for
         *          SSE/SSE2/SSE3/SSSE3/SSE4.
         */
        UINT64 OsFxsaveFxrstorSupport : 1;
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_BIT                            9
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_FLAG                           0x200
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_MASK                           0x01
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT(_)                             (((_) >> 9) & 0x01)

        /**
         * @brief Operating System Support for Unmasked SIMD Floating-Point Exceptions
         *
         * [Bit 10] Operating System Support for Unmasked SIMD Floating-Point Exceptions - When set, indicates that the operating
         * system supports the handling of unmasked SIMD floating-point exceptions through an exception handler that is invoked
         * when a SIMD floating-point exception (\#XM) is generated. SIMD floating-point exceptions are only generated by
         * SSE/SSE2/SSE3/SSE4.1 SIMD floating-point instructions.
         * The operating system or executive must explicitly set this flag. If this flag is not set, the processor will generate an
         * invalid opcode exception (\#UD) whenever it detects an unmasked SIMD floating-point exception.
         */
        UINT64 OsXmmExceptionSupport : 1;
#define CR4_OS_XMM_EXCEPTION_SUPPORT_BIT                             10
#define CR4_OS_XMM_EXCEPTION_SUPPORT_FLAG                            0x400
#define CR4_OS_XMM_EXCEPTION_SUPPORT_MASK                            0x01
#define CR4_OS_XMM_EXCEPTION_SUPPORT(_)                              (((_) >> 10) & 0x01)

        /**
         * @brief User-Mode Instruction Prevention
         *
         * [Bit 11] When set, the following instructions cannot be executed if CPL > 0: SGDT, SIDT, SLDT, SMSW, and STR. An attempt
         * at such execution causes a general-protection exception (\#GP).
         */
        UINT64 UsermodeInstructionPrevention : 1;
#define CR4_USERMODE_INSTRUCTION_PREVENTION_BIT                      11
#define CR4_USERMODE_INSTRUCTION_PREVENTION_FLAG                     0x800
#define CR4_USERMODE_INSTRUCTION_PREVENTION_MASK                     0x01
#define CR4_USERMODE_INSTRUCTION_PREVENTION(_)                       (((_) >> 11) & 0x01)

        /**
         * @brief 57-bit Linear Addresses
         *
         * [Bit 12] When set in IA-32e mode, the processor uses 5-level paging to translate 57-bit linear addresses. When clear in
         * IA-32e mode, the processor uses 4-level paging to translate 48-bit linear addresses. This bit cannot be modified in
         * IA-32e mode.
         *
         * @see Vol3C[4(PAGING)]
         */
        UINT64 LinearAddresses57Bit : 1;
#define CR4_LINEAR_ADDRESSES_57_BIT_BIT                              12
#define CR4_LINEAR_ADDRESSES_57_BIT_FLAG                             0x1000
#define CR4_LINEAR_ADDRESSES_57_BIT_MASK                             0x01
#define CR4_LINEAR_ADDRESSES_57_BIT(_)                               (((_) >> 12) & 0x01)

        /**
         * @brief VMX-Enable
         *
         * [Bit 13] Enables VMX operation when set.
         *
         * @see Vol3C[23(INTRODUCTION TO VIRTUAL MACHINE EXTENSIONS)]
         */
        UINT64 VmxEnable : 1;
#define CR4_VMX_ENABLE_BIT                                           13
#define CR4_VMX_ENABLE_FLAG                                          0x2000
#define CR4_VMX_ENABLE_MASK                                          0x01
#define CR4_VMX_ENABLE(_)                                            (((_) >> 13) & 0x01)

        /**
         * @brief SMX-Enable
         *
         * [Bit 14] Enables SMX operation when set.
         *
         * @see Vol2[6(SAFER MODE EXTENSIONS REFERENCE)]
         */
        UINT64 SmxEnable : 1;
#define CR4_SMX_ENABLE_BIT                                           14
#define CR4_SMX_ENABLE_FLAG                                          0x4000
#define CR4_SMX_ENABLE_MASK                                          0x01
#define CR4_SMX_ENABLE(_)                                            (((_) >> 14) & 0x01)
        UINT64 Reserved1 : 1;

        /**
         * @brief FSGSBASE-Enable
         *
         * [Bit 16] Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
         */
        UINT64 FsgsbaseEnable : 1;
#define CR4_FSGSBASE_ENABLE_BIT                                      16
#define CR4_FSGSBASE_ENABLE_FLAG                                     0x10000
#define CR4_FSGSBASE_ENABLE_MASK                                     0x01
#define CR4_FSGSBASE_ENABLE(_)                                       (((_) >> 16) & 0x01)

        /**
         * @brief PCID-Enable
         *
         * [Bit 17] Enables process-context identifiers (PCIDs) when set. Can be set only in IA-32e mode (if IA32_EFER.LMA = 1).
         *
         * @see Vol3A[4.10.1(Process-Context Identifiers (PCIDs))]
         */
        UINT64 PcidEnable : 1;
#define CR4_PCID_ENABLE_BIT                                          17
#define CR4_PCID_ENABLE_FLAG                                         0x20000
#define CR4_PCID_ENABLE_MASK                                         0x01
#define CR4_PCID_ENABLE(_)                                           (((_) >> 17) & 0x01)

        /**
         * @brief XSAVE and Processor Extended States-Enable
         *
         * [Bit 18] When set, this flag:
         * -# indicates (via CPUID.01H:ECX.OSXSAVE[bit 27]) that the operating system supports the use of the XGETBV, XSAVE and
         * XRSTOR instructions by general software;
         * -# enables the XSAVE and XRSTOR instructions to save and restore the x87 FPU state (including MMX registers), the SSE
         * state (XMM registers and MXCSR), along with other processor extended states enabled in XCR0;
         * -# enables the processor to execute XGETBV and XSETBV instructions in order to read and write XCR0.
         *
         * @see Vol3A[2.6(EXTENDED CONTROL REGISTERS (INCLUDING XCR0))]
         * @see Vol3A[13(SYSTEM PROGRAMMING FOR INSTRUCTION SET EXTENSIONS AND PROCESSOR EXTENDED)]
         */
        UINT64 OsXsave : 1;
#define CR4_OS_XSAVE_BIT                                             18
#define CR4_OS_XSAVE_FLAG                                            0x40000
#define CR4_OS_XSAVE_MASK                                            0x01
#define CR4_OS_XSAVE(_)                                              (((_) >> 18) & 0x01)

        /**
         * @brief Key-Locker-Enable
         *
         * [Bit 19] When set, the LOADIWKEY instruction is enabled; in addition, if support for the AES Key Locker instructions has
         * been activated by system firmware, CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 1 and the AES Key Locker instructions
         * are enabled. When clear, CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 0 and execution of any Key Locker instruction
         * causes an invalid-opcode exception (\#UD).
         */
        UINT64 KeyLockerEnable : 1;
#define CR4_KEY_LOCKER_ENABLE_BIT                                    19
#define CR4_KEY_LOCKER_ENABLE_FLAG                                   0x80000
#define CR4_KEY_LOCKER_ENABLE_MASK                                   0x01
#define CR4_KEY_LOCKER_ENABLE(_)                                     (((_) >> 19) & 0x01)

        /**
         * @brief SMEP-Enable
         *
         * [Bit 20] Enables supervisor-mode execution prevention (SMEP) when set.
         *
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        UINT64 SmepEnable : 1;
#define CR4_SMEP_ENABLE_BIT                                          20
#define CR4_SMEP_ENABLE_FLAG                                         0x100000
#define CR4_SMEP_ENABLE_MASK                                         0x01
#define CR4_SMEP_ENABLE(_)                                           (((_) >> 20) & 0x01)

        /**
         * @brief SMAP-Enable
         *
         * [Bit 21] Enables supervisor-mode access prevention (SMAP) when set.
         *
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        UINT64 SmapEnable : 1;
#define CR4_SMAP_ENABLE_BIT                                          21
#define CR4_SMAP_ENABLE_FLAG                                         0x200000
#define CR4_SMAP_ENABLE_MASK                                         0x01
#define CR4_SMAP_ENABLE(_)                                           (((_) >> 21) & 0x01)

        /**
         * @brief Protection-Key-Enable
         *
         * [Bit 22] Enables 4-level paging to associate each linear address with a protection key. The PKRU register specifies, for
         * each protection key, whether user-mode linear addresses with that protection key can be read or written. This bit also
         * enables access to the PKRU register using the RDPKRU and WRPKRU instructions.
         */
        UINT64 ProtectionKeyEnable : 1;
#define CR4_PROTECTION_KEY_ENABLE_BIT                                22
#define CR4_PROTECTION_KEY_ENABLE_FLAG                               0x400000
#define CR4_PROTECTION_KEY_ENABLE_MASK                               0x01
#define CR4_PROTECTION_KEY_ENABLE(_)                                 (((_) >> 22) & 0x01)

        /**
         * @brief Control-flow Enforcement Technology
         *
         * [Bit 23] Enables control-flow enforcement technology when set. This flag can be set only if CR0.WP is set, and it must
         * be clear before CR0.WP can be cleared.
         *
         * @see Vol1[18(CONTROL-FLOW ENFORCEMENT TECHNOLOGY (CET))]
         */
        UINT64 ControlFlowEnforcementEnable : 1;
#define CR4_CONTROL_FLOW_ENFORCEMENT_ENABLE_BIT                      23
#define CR4_CONTROL_FLOW_ENFORCEMENT_ENABLE_FLAG                     0x800000
#define CR4_CONTROL_FLOW_ENFORCEMENT_ENABLE_MASK                     0x01
#define CR4_CONTROL_FLOW_ENFORCEMENT_ENABLE(_)                       (((_) >> 23) & 0x01)

        /**
         * @brief Enable protection keys for supervisor-mode pages
         *
         * [Bit 24] 4-level paging and 5-level paging associate each supervisor-mode linear address with a protection key. When
         * set, this flag allows use of the IA32_PKRS MSR to specify, for each protection key, whether supervisor-mode linear
         * addresses with that protection key can be read or written.
         */
        UINT64 ProtectionKeyForSupervisorModeEnable : 1;
#define CR4_PROTECTION_KEY_FOR_SUPERVISOR_MODE_ENABLE_BIT            24
#define CR4_PROTECTION_KEY_FOR_SUPERVISOR_MODE_ENABLE_FLAG           0x1000000
#define CR4_PROTECTION_KEY_FOR_SUPERVISOR_MODE_ENABLE_MASK           0x01
#define CR4_PROTECTION_KEY_FOR_SUPERVISOR_MODE_ENABLE(_)             (((_) >> 24) & 0x01)
        UINT64 Reserved2 : 39;
    };

    UINT64 AsUInt;
} CR4;

#pragma pack(pop)

typedef struct _NT_KPROCESS
{
    DISPATCHER_HEADER Header;
    LIST_ENTRY        ProfileListHead;
    ULONG_PTR         DirectoryTableBase;
    UCHAR             Data[1];
} NT_KPROCESS, * PNT_KPROCESS;

typedef volatile struct _criticalSection
{
    volatile int locked;
    volatile int apicid;
    volatile int lockcount;
    char* name;
    int debuglevel;
} CriticalSection, * pCriticalSection;

typedef union _EptCommonEntry {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;       //!< [0]
        ULONG64 write_access : 1;      //!< [1]
        ULONG64 execute_access : 1;    //!< [2]
        ULONG64 memory_type : 3;       //!< [3:5]
        ULONG64 reserved1 : 6;         //!< [6:11]
        ULONG64 physial_address : 36;  //!< [12:48-1]
        ULONG64 reserved2 : 16;        //!< [48:63]
    } fields;
}EptCommonEntry;

//用于保存HOOK信息的双向链表
typedef struct _EptHookInfo
{
    ULONG_PTR RealPagePhyAddr;

    ULONG_PTR FakePagePhyAddr;
    ULONG_PTR FakePageVaAddr;

    ULONG_PTR OriginalFunAddr;
    ULONG_PTR OriginalFunHeadCode;

    LIST_ENTRY list;
} EptHookInfo, * PEptHookInfo;

typedef struct _exit_qualification_ept_violation
{
    union
    {
        UINT64 flags;

        struct
        {
            UINT64 data_read : 1;
            UINT64 data_write : 1;
            UINT64 data_execute : 1;
            UINT64 entry_read : 1;
            UINT64 entry_write : 1;
            UINT64 entry_execute : 1;
            UINT64 entry_execute_for_user_mode : 1;
            UINT64 valid_guest_linear_address : 1;
            UINT64 ept_translated_access : 1;
            UINT64 user_mode_linear_address : 1;
            UINT64 readable_writable_page : 1;
            UINT64 execute_disable_page : 1;
            UINT64 nmi_unblocking : 1;
        };
    };
}ExitQualificationEpt;