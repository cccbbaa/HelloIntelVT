#pragma once
#include <windef.h>

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x4000
{
	UINT Value;
	struct {
		UINT ExternalInterruptExiting : 1; // 为1的话外部中断会导致 VM exit 否则会通过guest的IDT正常传递
		UINT Reserved0 : 2;
		UINT NMIexiting : 1; // 为1的话 NMI 会导致 VM exit 否则会通过IDT中的描述符2正常传递
		UINT Reserved1 : 1;
		UINT VirtualNMIs : 1; // 为1时 NMI 永远不会被阻塞
		UINT VMXpreemptionTimer : 1; // 为1时VMX 抢占计时器在 VMX 非根操作中倒计时。当计时器倒计时至零时发生 VM exits
		UINT ProcessPostedInterrupts : 1; // 为1时CPU特殊处理具有发布中断通知向量的中断，更新虚拟 APIC 页面以发布中断请求
		UINT Reserved2 : 24;
	};
}PinBasedVMEC;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x4002
{
    UINT Value;
    struct {
        UINT Reserved0 : 2;            // 位 0-1 保留
        UINT InterruptWindowExiting : 1; // 位 2: 为1时，在 RFLAGS.IF=1 且没有其他中断阻塞时，任何指令的开始都会导致 VM exit
        UINT UseTSCOffsetting : 1;    // 位 3: 决定 RDTSC, RDTSCP, 以及读取 IA32_TIME_STAMP_COUNTER MSR 的 RDMSR 执行是否返回由 TSC 偏移字段修改的值
        UINT Reserved1 : 3;            // 位 4-6 保留
        UINT HLTExiting : 1;           // 位 7: 决定 HLT 执行是否导致 VM exit
        UINT Reserved2 : 1;            // 位 8 保留
        UINT INVLPGExiting : 1;        // 位 9: 决定 INVLPG 执行是否导致 VM exit
        UINT MWAITExiting : 1;         // 位 10: 决定 MWAIT 执行是否导致 VM exit
        UINT RDPMCExiting : 1;         // 位 11: 决定 RDPMC 执行是否导致 VM exit
        UINT RDTSCExiting : 1;         // 位 12: 决定 RDTSC 和 RDTSCP 执行是否导致 VM exit
        UINT Reserved3 : 2;            // 位 13-14 保留
        UINT CR3LoadExiting : 1;       // 位 15: 与 CR3-target 控制结合，决定对 CR3 的 MOV 加载是否导致 VM exit
        UINT CR3StoreExiting : 1;      // 位 16: 决定对 CR3 的 MOV 存储是否导致 VM exit
        UINT Reserved4 : 2;            // 位 17-18 保留
        UINT CR8LoadExiting : 1;       // 位 19: 决定对 CR8 的 MOV 加载是否导致 VM exit
        UINT CR8StoreExiting : 1;      // 位 20: 决定对 CR8 的 MOV 存储是否导致 VM exit
        UINT UseTPRShadow : 1;         // 位 21: 设置为1时启用 TPR 虚拟化和其他 APIC-虚拟化功能
        UINT NMIWindowExiting : 1;     // 位 22: 为1时，如果没有虚拟-NMI 阻塞，任何指令的开始都会导致 VM exit
        UINT MOVDrExiting : 1;         // 位 23: 决定 MOV DR 执行是否导致 VM exit
        UINT UnconditionalIOExiting : 1;// 位 24: 决定 I/O 指令执行是否导致 VM exit
        UINT UseIOBitmaps : 1;         // 位 25: 决定是否使用 I/O 位图来限制 I/O 指令的执行
        UINT Reserved5 : 1;            // 位 26 保留
        UINT MonitorTrapFlag : 1;      // 位 27: 为1时，启用监视器陷阱标志调试特性
        UINT UseMSRBitmaps : 1;        // 位 28: 决定是否使用 MSR 位图来控制 RDMSR 和 WRMSR 指令的执行
        UINT MONITORExiting : 1;       // 位 29: 决定 MONITOR 执行是否导致 VM exit
        UINT PAUSEExiting : 1;         // 位 30: 决定 PAUSE 执行是否导致 VM exit
        UINT ActivateSecondaryControls : 1;// 位 31: 决定是否使用次级处理器基础的 VM 执行控制
    };
} PrimaryProcessorBasedVMEC;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x400C
{
    UINT32 Value;
    struct {
        UINT32 Reserved0 : 2;            // 位 0-1 保留
        UINT32 SaveDebugControls : 1;    // 位 2: 决定在 VM 退出时是否保存 DR7 和 IA32_DEBUGCTL MSR
        UINT32 Reserved1 : 6;            // 位 3-8 保留
        UINT32 HostAddressSpaceSize : 1; // 位 9: 决定下一个 VM 退出后逻辑处理器是否处于 64 位模式
        UINT32 Reserved2 : 2;            // 位 10-11 保留
        UINT32 LoadIA32PerfGlobalCtrl : 1;// 位 12: 决定 IA32_PERF_GLOBAL_CTRL MSR 在 VM 退出时是否加载
        UINT32 Reserved3 : 2;            // 位 13-14 保留
        UINT32 AcknowledgeInterruptOnExit : 1;// 位 15: 决定是否在由于外部中断的 VM 退出时确认中断控制器
        UINT32 Reserved4 : 2;            // 位 16-17 保留
        UINT32 SaveIA32PAT : 1;          // 位 18: 决定 IA32_PAT MSR 在 VM 退出时是否保存
        UINT32 LoadIA32PAT : 1;          // 位 19: 决定 IA32_PAT MSR 在 VM 退出时是否加载
        UINT32 SaveIA32EFER : 1;         // 位 20: 决定 IA32_EFER MSR 在 VM 退出时是否保存
        UINT32 LoadIA32EFER : 1;         // 位 21: 决定 IA32_EFER MSR 在 VM 退出时是否加载
        UINT32 SaveVMXPreemptionTimerValue : 1; // 位 22: 决定 VMX 抢占计时器值在 VM 退出时是否保存
        UINT32 ClearIA32BNDCFGS : 1;     // 位 23: 决定 IA32_BNDCFGS MSR 在 VM 退出时是否清除
        UINT32 ConcealVMXFromPT : 1;     // 位 24: 如果此控制位为 1, Intel Processor Trace 在 VM 退出时不产生 PIP 或 VMCS 包
        UINT32 ClearIA32RTITCTL : 1;     // 位 25: 决定 IA32_RTIT_CTL MSR 在 VM 退出时是否清除
        UINT32 ClearIA32LBRCTL : 1;      // 位 26: 决定 IA32_LBR_CTL MSR 在 VM 退出时是否清除
        UINT32 Reserved5 : 1;            // 位 27 保留
        UINT32 LoadCETState : 1;         // 位 28: 决定在 VM 退出时是否加载 CET 相关的 MSR 和 SPP
        UINT32 LoadPKRS : 1;             // 位 29: 决定 IA32_PKRS MSR 在 VM 退出时是否加载
        UINT32 SaveIA32PerfGlobalCtrl : 1;// 位 30: 决定 IA32_PERF_GLOBAL_CTL MSR 在 VM 退出时是否保存
        UINT32 ActivateSecondaryControls : 1;// 位 31: 决定是否使用次级 VM-退出控制
    };
} PrimaryVMEC;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x4012
{
    UINT32 Value;
    struct {
        UINT32 Reserved0 : 2;                // 位 0-1 保留
        UINT32 LoadDebugControls : 1;        // 位 2: 决定在 VM 进入时是否加载 DR7 和 IA32_DEBUGCTL MSR
        UINT32 Reserved1 : 6;                // 位 3-8 保留
        UINT32 IA32eModeGuest : 1;           // 位 9: 决定 VM 进入后逻辑处理器是否处于 IA-32e 模式
        UINT32 EntryToSMM : 1;               // 位 10: 决定 VM 进入后逻辑处理器是否处于 SMM
        UINT32 DeactivateDualMonitorTreatment : 1; // 位 11: 决定在 VM 进入后是否停用双监控处理
        UINT32 Reserved2 : 1;                // 位 12 保留
        UINT32 LoadIA32PerfGlobalCtrl : 1;   // 位 13: 决定在 VM 进入时是否加载 IA32_PERF_GLOBAL_CTRL MSR
        UINT32 LoadIA32PAT : 1;              // 位 14: 决定在 VM 进入时是否加载 IA32_PAT MSR
        UINT32 LoadIA32EFER : 1;             // 位 15: 决定在 VM 进入时是否加载 IA32_EFER MSR
        UINT32 LoadIA32BNDCFGS : 1;          // 位 16: 决定在 VM 进入时是否加载 IA32_BNDCFGS MSR
        UINT32 ConcealVMXFromPT : 1;         // 位 17: 决定在 VM 进入时是否隐藏 VMX 从 PT
        UINT32 LoadIA32RTITCTL : 1;          // 位 18: 决定在 VM 进入时是否加载 IA32_RTIT_CTL MSR
        UINT32 Reserved3 : 1;                // 位 19 保留
        UINT32 LoadCETState : 1;             // 位 20: 决定在 VM 进入时是否加载 CET 状态
        UINT32 LoadGuestIA32LBRCTL : 1;      // 位 21: 决定在 VM 进入时是否加载 IA32_LBR_CTL MSR
        UINT32 LoadPKRS : 1;                 // 位 22: 决定在 VM 进入时是否加载 IA32_PKRS MSR
        UINT32 Reserved4 : 9;                // 位 23-31 保留
    };
} VMEntryControls;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x401E
{
    UINT32 Value;
    struct {
        UINT32 VirtualizeAPICAccesses : 1;  // 位 0: 如果此控制位为 1，则逻辑处理器特殊处理对具有 APIC-access 地址的页面的访问
        UINT32 EnableEPT : 1;               // 位 1: 如果此控制位为 1，则启用扩展页表 (EPT)
        UINT32 DescriptorTableExiting : 1;  // 位 2: 决定是否导致 LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT 和 STR 的执行导致 VM 退出
        UINT32 EnableRDTSCP : 1;            // 位 3: 如果此控制位为 0，则任何执行 RDTSCP 的操作都会导致 #UD
        UINT32 VirtualizeX2APICMode : 1;    // 位 4: 如果此控制位为 1，则逻辑处理器特殊处理对 APIC MSR 的 RDMSR 和 WRMSR
        UINT32 EnableVPID : 1;              // 位 5: 如果此控制位为 1，则启用虚拟处理器标识符 (VPID)
        UINT32 WBINVDExiting : 1;           // 位 6: 决定是否导致 WBINVD 和 WBNOINVD 的执行导致 VM 退出
        UINT32 UnrestrictedGuest : 1;       // 位 7: 决定是否允许客户软件在未分页的保护模式或实地址模式下运行
        UINT32 APICRegisterVirtualization : 1; // 位 8: 如果此控制位为 1，则逻辑处理器虚拟化某些 APIC 访问
        UINT32 VirtualInterruptDelivery : 1; // 位 9: 控制对挂起虚拟中断的评估和交付以及对控制中断优先级的 APIC 寄存器的仿真写入
        UINT32 PauseLoopExiting : 1;        // 位 10: 决定一系列 PAUSE 的执行是否可以导致 VM 退出
        UINT32 RDRANDExiting : 1;           // 位 11: 决定是否导致 RDRAND 的执行导致 VM 退出
        UINT32 EnableINVPCID : 1;           // 位 12: 如果此控制位为 0，则任何执行 INVPCID 的操作都会导致 #UD
        UINT32 EnableVMFunctions : 1;       // 位 13: 设置此控制位为 1 在 VMX 非根操作中启用使用 VMFUNC 指令
        UINT32 VMCSShadowing : 1;           // 位 14: 如果此控制位为 1，则 VMX 非根操作中的 VMREAD 和 VMWRITE 可以访问影子 VMCS
        UINT32 EnableENCLSExiting : 1;      // 位 15: 如果此控制位为 1，则 ENCLS 的执行会检查 ENCLS-exiting 位图来决定是否导致 VM 退出
        UINT32 RDSEEDExiting : 1;           // 位 16: 决定是否导致 RDSEED 的执行导致 VM 退出
        UINT32 EnablePML : 1;               // 位 17: 如果此控制位为 1，则对设置了 EPT 脏位的客户物理地址的访问首先会添加一个条目到页面修改日志
        UINT32 EPTViolationVE : 1;          // 位 18: 如果此控制位为 1，则 EPT 违规可能导致虚拟化异常 (#VE) 而不是 VM 退出
        UINT32 ConcealVMXFromPT : 1;        // 位 19: 如果此控制位为 1，则 Intel Processor Trace 抑制从 PIP 中指示处理器处于 VMX 非根操作
        UINT32 EnableXSAVESXRSTORS : 1;     // 位 20: 如果此控制位为 0，则任何执行 XSAVES 或 XRSTORS 的操作都会导致 #UD
        UINT32 Reserved0 : 1;               // 位 21 保留
        UINT32 ModeBasedExecuteControlForEPT : 1; // 位 22: 如果此控制位为 1，则 EPT 执行权限基于被访问的线性地址是用户模式还是监督模式
        UINT32 SubPageWritePermissionsForEPT : 1; // 位 23: 如果此控制位为 1，则 EPT 写权限可以是 128 字节的粒度
        UINT32 IntelPTUsesGuestPhysicalAddresses : 1; // 位 24: 如果此控制位为 1，则 Intel Processor Trace 使用的所有输出地址被视为客户物理地址并使用 EPT 转换
        UINT32 UseTSCScaling : 1;           // 位 25: 决定 RDTSC, RDTSCP 和读取 IA32_TIME_STAMP_COUNTER MSR 的 RDMSR 执行是否返回由 TSC 乘数字段修改的值
        UINT32 EnableUserWaitAndPause : 1;  // 位 26: 如果此控制位为 0，则任何执行 TPAUSE, UMONITOR 或 UMWAIT 的操作都会导致 #UD
        UINT32 EnablePCONFIG : 1;           // 位 27: 如果此控制位为 0，则任何执行 PCONFIG 的操作都会导致 #UD
        UINT32 EnableENCLVExiting : 1;      // 位 28: 如果此控制位为 1，则 ENCLV 的执行会检查 ENCLV-exiting 位图来决定是否导致 VM 退出
        UINT32 Reserved1 : 3;               // 位 29-31 保留
    };
} SecondaryProcessorBasedVMEC;
#pragma pack(pop)

#pragma pack(push, 1)

typedef struct VirtualMachineState
{
#define VMMemoryTag 'czvm'
    PVOID pVMXRegion;
    PHYSICAL_ADDRESS pVMXRegion_PA;
    PVOID pVMCSRegion;
    PHYSICAL_ADDRESS pVMCSRegion_PA;
    BOOLEAN bVMLAUNCHSuccess;
    BOOLEAN bVMXONSuccess;
    PVOID pIOBitmapA;
    PVOID pIOBitmapB;
    PHYSICAL_ADDRESS pIOBitmapA_PA;
    PHYSICAL_ADDRESS pIOBitmapB_PA;
    PVOID pMSRBitmap;
    PHYSICAL_ADDRESS pMSRBitmap_PA;
    PVOID pHostVMStack;

}VMState, *pVMState;

#pragma pack(pop)

