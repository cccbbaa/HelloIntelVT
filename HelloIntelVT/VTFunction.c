#include "VTFunction.h"
#include "HelpFunction.h"
#include "vmhelper.h"
#include "msrname.h"
#include "vmcsStruct.h"
#include "vmhandler.h"

VMState vmState[MAX_CPU_COUNT] = { 0 };
CriticalSection cSection = { 0 };

BOOL CheckVTIsSupport()
{
    
    int cpuidret[4] = { 0 }; // eax ebx ecx edx

    __cpuid(cpuidret, 1);

    if (((cpuidret[2] >> 5) % 2) == 0) { // rcx的第五位(从0开始)为1的话CPU就支持VT
        DbgPrintEx(0, 0, "This CPU not support Virtual Technology, rcx %x, cpuNumber [%d]\n", cpuidret[2], cpunr());
        return FALSE;
    }

    UINT64 msr3A = __readmsr(0x3A);
    if (!(msr3A & 0b1)) { // msr 3A的LOCK位要为1
        DbgPrintEx(0, 0, "Bios not open support Virtual Technology, cpuNumber [%d]\n", cpunr());
        return FALSE;
    }
    
    _CR0 cr0Value = { 0 };
    cr0Value.Value = __readcr0();

    if (cr0Value.PE != 1 || cr0Value.NE != 1 || cr0Value.PG != 1) {
        DbgPrintEx(0, 0, "CPU %d not open support Virtual Technology\n", cpunr());
        return FALSE;
    }
    
    _CR4 cr4Value = { 0 };
    cr4Value.Value = __readcr4();

    if (cr4Value.VMXE == 1) {
        DbgPrintEx(0, 0, "CPU %d alreay use Virtual Technology\n", cpunr());
    }
    
    return TRUE;
}

static BOOL AllocVMMmemory(int cpuNumber)
{
    vmState[cpuNumber].pVMCSRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, VMMemoryTag);
    if (!vmState[cpuNumber].pVMCSRegion)
    {
        DbgPrintEx(0, 0, "ExAllocatePool Error\n");
        return FALSE;
    }
    RtlZeroMemory(vmState[cpuNumber].pVMCSRegion, 0x1000);

    vmState[cpuNumber].pIOBitmapA = ExAllocatePoolWithTag(NonPagedPool, 0x1000, VMMemoryTag);
    if (!vmState[cpuNumber].pIOBitmapA)
    {
        DbgPrintEx(0, 0, "ExAllocatePool Error\n");
        return FALSE;
    }
    RtlZeroMemory(vmState[cpuNumber].pIOBitmapA, 0x1000);

    vmState[cpuNumber].pIOBitmapB = ExAllocatePoolWithTag(NonPagedPool, 0x1000, VMMemoryTag);
    if (!vmState[cpuNumber].pIOBitmapB)
    {
        DbgPrintEx(0, 0, "ExAllocatePool Error\n");
        return FALSE;
    }
    RtlZeroMemory(vmState[cpuNumber].pIOBitmapB, 0x1000);

    vmState[cpuNumber].pMSRBitmap = ExAllocatePoolWithTag(NonPagedPool, 0x1000, VMMemoryTag);
    if (!vmState[cpuNumber].pMSRBitmap)
    {
        DbgPrintEx(0, 0, "ExAllocatePool Error\n");
        return FALSE;
    }
    RtlZeroMemory(vmState[cpuNumber].pMSRBitmap, 0x1000);

    vmState[cpuNumber].pHostVMStack = ExAllocatePoolWithTag(NonPagedPool, VM_STACK_SIZE, VMMemoryTag);
    if (!vmState[cpuNumber].pHostVMStack)
    {
        DbgPrintEx(0, 0, "ExAllocatePool Error\n");
        return FALSE;
    }
    RtlZeroMemory(vmState[cpuNumber].pHostVMStack, VM_STACK_SIZE);

    return TRUE;
}

BOOL CreateVirtualMachine(UINT64 guestStack)
{
    EnterCriticalSection(&cSection, 0);

    int cpuNumber = cpunr();

    DbgPrintEx(0, 0, "guestStack: %llx\n", guestStack);

    if (vmState[cpuNumber].bVMXONSuccess == 0) {
        DbgPrintEx(0, 0, "No CPU execute VMXStart, please execute that before this\n");
        return FALSE;
    }


    if (AllocVMMmemory(cpuNumber) == FALSE) {
        return FALSE;
    }

    UINT64 msr480h = __readmsr(IA32_VMX_BASIC_MSR);
    // msr 480h 32位到44位是 VMXON 区域和任何 VMCS 区域分配的字节数
    //UINT64 VMCSRegionSize = (msr480h >> 32) & 0x1FFF;
    //DbgPrintEx(0, 0, "VMCSRegionSize: %lld\n", VMCSRegionSize);

    UINT VMCSRevision = msr480h & 0x7FFFFFFF;
    DbgPrintEx(0, 0, "VMCS revision: %d\n", VMCSRevision);
    // 需要把前4个字节设置为VMCS revision 也就是 msr 480h 的0到30位
    *(UINT*)(vmState[cpuNumber].pVMCSRegion) = VMCSRevision;

    vmState[cpuNumber].pVMCSRegion_PA = MmGetPhysicalAddress(vmState[cpuNumber].pVMCSRegion);

    // 初始化指定的VMCS，并将其启动状态设置为 Clear
    UCHAR Ret = __vmx_vmclear(&vmState[cpuNumber].pVMCSRegion_PA);
    if (Ret != 0) {
        if (Ret == 1) {
            DbgPrintEx(0, 0, "vmclear Error, %s\n", getVMInstructionErrorString());
        }
        else {
            DbgPrintEx(0, 0, "vmclear Failed %hhd\n", Ret);
        }

        goto CreateFailed;
    }

    // 从指定地址加载指向当前 VMCS 的指针
    Ret = __vmx_vmptrld(&vmState[cpuNumber].pVMCSRegion_PA);
    if (Ret != 0) {
        if (Ret == 1) {
            DbgPrintEx(0, 0, "vmptrld Error, %s\n", getVMInstructionErrorString());
        }
        else {
            DbgPrintEx(0, 0, "vmptrld Failed %hhd\n", Ret);
        }

        goto CreateFailed;
    }

    // 初始化 VMCS
    if (InitializeVMCS(cpunr(), guestStack) == FALSE) {
        DbgPrintEx(0, 0, "InitializeVMCS Failed\n");

        goto CreateFailed;
    }

    vmState[cpuNumber].bVMLAUNCHSuccess = TRUE;

    LeaveCriticalSection(&cSection);

    // 虚拟机，启动!!! 
    
    Ret = __vmx_vmlaunch();
    if (Ret != 0) {
        if (Ret == 1) {
            size_t i = 0;
            __vmx_vmread(vm_errorcode, &i);
            DbgPrintEx(0, 0, "vmlaunch Error, %lld %s\n", i, getVMInstructionErrorString());
        }
        else {
            DbgPrintEx(0, 0, "vmlaunch Failed %hhd\n", Ret);
        }
    }

    // 启动成功的话下面的代码不应该会被执行
    vmState[cpuNumber].bVMLAUNCHSuccess = FALSE;
    DbgPrintEx(0, 0, "vmlaunch Failed\n");

    return FALSE;

CreateFailed:
    {
        if(vmState[cpuNumber].pVMCSRegion) ExFreePoolWithTag(vmState[cpuNumber].pVMCSRegion, VMMemoryTag);
        vmState[cpuNumber].pVMCSRegion = NULL;
        vmState[cpuNumber].pVMCSRegion_PA.QuadPart = 0;

        return FALSE;
    }
}

BOOL InitializeVMCS(int cpuNumber, UINT64 guestStack)
{

    UCHAR Ret;
    // 1. Guest state fields
    // Intel 手册 第三卷 24.4.1

    /*Ret = __vmx_vmwrite(vm_cr0_guest_host_mask, 0xffffffffffffffffULL);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_cr4_guest_host_mask, 0xffffffffffffffffULL);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }*/

    Ret = __vmx_vmwrite(vm_guest_cr0, __readcr0());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_cr3, __readcr3());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_cr4, __readcr4());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    // DR7寄存器默认为0x400
    Ret = __vmx_vmwrite(vm_guest_dr7, 0x400);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    // Intel System Programming Guide 26.3.1.4 
    // Rflags
    // 保留位63:22（在不支持Intel 64架构的处理器上为位31:22）、位15、位5和位3在字段中必须为0，保留位1必须为1。
    // 如果“IA - 32e模式客户”VM进入控制为1或CR0字段中的位0（对应CR0.PE）为0，则VM标志（位17）必须为0。
    // 如果VM进入中断信息字段中的有效位（位31）为1且中断类型（位10 : 8）为外部中断，则IF标志（RFLAGS[位9]）必须为1。

    RFLAGS RFlags = { 0 };
    RFlags.AsUInt = __readeflags();
    RFlags.InterruptEnableFlag = 0; //进入Guest时关中断

    Ret = __vmx_vmwrite(vm_guest_rflags, RFlags.AsUInt);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_rsp, guestStack);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_rip, (UINT64)AsmVmxResState);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    UINT64 GDTbase = getGDTbase();
    VMX_GDTENTRY64 vmxGdtEntry = { 0 };

    VmxFillGuestSelectorData(CS, getCS());
    VmxFillGuestSelectorData(SS, getSS());
    VmxFillGuestSelectorData(DS, getDS());
    VmxFillGuestSelectorData(ES, getES());
    VmxFillGuestSelectorData(FS, getFS());
    VmxFillGuestSelectorData(GS, getGS());
    VmxFillGuestSelectorData(LDTR, getLdtr());
    WORD TRselector = getTR();
    VmxFillGuestSelectorData(TR, TRselector);

    __vmx_vmwrite(vm_guest_fs_base, __readmsr(IA32_FS_BASE_MSR));
    __vmx_vmwrite(vm_guest_gs_base, __readmsr(IA32_GS_BASE_MSR));

    Ret = __vmx_vmwrite(vm_guest_gdtr_base, getGDTbase());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_gdt_limit, getGDTlimit());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    IDTDescriptor idt;
    __sidt(&idt);

    Ret = __vmx_vmwrite(vm_guest_idtr_base, idt.Base);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_idt_limit, idt.Limit);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    // Intel 手册 第三卷 24.10
    Ret = __vmx_vmwrite(vm_vmcs_link_pointer, 0xffffffffffffffffULL);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    // Intel 手册 第三卷 24.4.1
    Ret = __vmx_vmwrite(vm_guest_IA32_DEBUGCTL, __readmsr(IA32_DEBUGCTL_MSR));// 用于控制处理器的调试特性，如分支记录、单步执行和最后分支记录等(Windows 不使用)
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS_MSR)); // 用于快速系统调用（SYSENTER/SYSEXIT 指令）
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP_MSR)); // 系统进入时的堆栈指针，用于 SYSENTER
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP_MSR)); // 系统进入时的指令指针，用于 SYSENTER
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_PERF_GLOBAL_CTRL, __readmsr(IA32_PERF_GLOBAL_CTRL_MSR)); // 用于控制性能监控计数器
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_PAT, __readmsr(IA32_PAT_MSR)); // 页面属性表，用于定义内存类型（如写回、写通等）
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_EFER, __readmsr(EFER_MSR)); // 扩展功能寄存器，包括诸如启用长模式（LME）、启用系统调用扩展（SCE）等标志
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    //Ret = __vmx_vmwrite(vm_guest_interruptability_state, (UINT64)0); //interruptibility state
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(0x4828, (UINT64)0); //smbase
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(0x6822, (UINT64)0); //pending debug exceptions
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}

    // 用于 Intel 的内存界限检查扩展 (MPX)，提供对边界检查配置的控制。它用于设置边界检查的启用状态和边界表的基址。
    // Windows不支持
    //Ret = __vmx_vmwrite(vm_guest_IA32_BNDCFGS, __readmsr(IA32_BNDCFGS_MSR)); 
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //Ret = __vmx_vmwrite(vm_guest_IA32_RTIT_CTL, __readmsr(IA32_RTIT_CTL_MSR)); // 与Intel PT(Processor Trace)相关，用于配置和控制处理器追踪功能，可以用于分析程序执行和调试
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //Ret = __vmx_vmwrite(vm_guest_IA32_LBR_CTL, __readmsr(IA32_LBR_CTL_MSR)); // 用于配置处理器的最后分支记录功能
    //if (Ret != 0) {
    //    SetBreakPointEx();
    //}

    Ret = __vmx_vmwrite(vm_host_IA32_S_CET, __readmsr(IA32_S_CET_MSR)); // 控制流程防护（Control-flow Enforcement Technology, CET）的状态。
    if (Ret != 0) {
        SetBreakPointEx();
    }
    Ret = __vmx_vmwrite(vm_host_IA32_INTERRUPT_SSP_TABLE_ADDR, __readmsr(IA32_INTERRUPT_SSP_TABLE_ADDR_MSR)); // 中断堆栈表地址，与 CET 相关
    if (Ret != 0) {
        SetBreakPointEx();
    }
    Ret = __vmx_vmwrite(vm_host_IA32_PKRS, __readmsr(IA32_PKRS_MSR)); // 保护密钥权限寄存器，用于内存保护键功能
    if (Ret != 0) {
        SetBreakPointEx();
    }

    // 2. Host state fields
    // Intel 手册 第三卷 24.5

    //BOOL hasCETSupport = FALSE;
    //{
    //    int cpuidret[4] = { 0 }; // eax ebx ecx edx
    //    __cpuid(cpuidret, 7);
    //    hasCETSupport = (cpuidret[2] & (1 << 7));
    //    DbgPrintEx(0, 0, "cpuidret: %d, %d, %d, %d\n", cpuidret[0], cpuidret[1], cpuidret[2], cpuidret[3]);
    //    DbgPrintEx(0, 0, "hasCETSupport: %hhu\n", hasCETSupport);
    //}

    Ret = __vmx_vmwrite(vm_host_cr0, __readcr0());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_cr0_read_shadow, __readcr0());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_cr3, FindSystemDirectoryTableBase());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_cr4, __readcr4());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_cr4_read_shadow, __readcr4());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    // Intel 手册 第三卷 26.2.3
    // 对于CS（代码段），SS（堆栈段），DS（数据段），ES，FS，GS和TR（任务寄存器）的选择器字段
    // 请求特权级别（RPL，位1:0）和表指示标志（TI标志，位2）必须为0。
    Ret = __vmx_vmwrite(vm_host_cs, getCS() & 0xFFF8);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_ss, getSS() & 0xFFF8);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_ds, getDS() & 0xFFF8);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_es, getES() & 0xFFF8);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_fs, getFS() & 0xFFF8);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_fs_base, __readmsr(0xc0000100));  //fs base
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_gs, getGS() & 0xFFF8);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_gs_base, __readmsr(0xc0000101));  //gs base
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_tr, TRselector & 0xFFF8);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    ConvertGdtEntry(GDTbase, TRselector, &vmxGdtEntry);

    Ret = __vmx_vmwrite(vm_host_tr_base, vmxGdtEntry.Base);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_gdtr_base, getGDTbase());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_idtr_base, getIDTbase());
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    
    
    // SYSENTER/SYSEXIT 似乎在 Windows 10 x64并没有用到
    Ret = __vmx_vmwrite(vm_host_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS_MSR)); // 用于快速系统调用（SYSENTER/SYSEXIT 指令）
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    
    Ret = __vmx_vmwrite(vm_host_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP_MSR)); // 系统进入时的堆栈指针，用于 SYSENTER
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    
    Ret = __vmx_vmwrite(vm_host_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP_MSR)); // 系统进入时的指令指针，用于 SYSENTER
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_PERF_GLOBAL_CTRL, __readmsr(IA32_PERF_GLOBAL_CTRL_MSR)); // 用于控制性能监控计数器
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_PAT, __readmsr(IA32_PAT_MSR)); // 页面属性表，用于定义内存类型（如写回、写通等）
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_EFER, __readmsr(EFER_MSR)); // 扩展功能寄存器，包括诸如启用长模式（LME）、启用系统调用扩展（SCE）等标志
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_S_CET, __readmsr(IA32_S_CET_MSR)); // 控制流程防护（Control-flow Enforcement Technology, CET）的状态。
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_INTERRUPT_SSP_TABLE_ADDR, __readmsr(IA32_INTERRUPT_SSP_TABLE_ADDR_MSR)); // 中断堆栈表地址，与 CET 相关
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    Ret = __vmx_vmwrite(vm_host_IA32_PKRS, __readmsr(IA32_PKRS_MSR)); // 保护密钥权限寄存器，用于内存保护键功能
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    size_t HostStack = (UINT64)vmState[cpuNumber].pHostVMStack + VM_STACK_SIZE - 0x300;
    HostStack = ((HostStack & ~(16 - 1)));
    Ret = __vmx_vmwrite(vm_host_rsp, HostStack);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_rip, (size_t)(PVOID)VMMEntryPoint);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    // 3. vm-control fields
    // 3.1 vm execution control

    // 对应位对应具体功能见 intel 文档第三卷 24.6.1
    {
        PinBasedVMEC pbVMEC = { 0 };
        // Intel手册第三卷 A.3.1 
        // 如果IA32_VMX_BASIC MSR的位55读为0，则所有有关基于管脚的VM执行控制的允许设置信息都包含在IA32_VMX_PINBASED_CTLS MSR中。
        // 如果IA32_VMX_BASIC MSR的位55读为1，则所有有关基于管脚的VM执行控制的允许设置信息都包含在IA32_VMX_TRUE_PINBASED_CTLS MSR中
        if ((__readmsr(IA32_VMX_BASIC_MSR) >> 55) % 2) {
            pbVMEC.Value = VmxAdjustControls(pbVMEC.Value, IA32_VMX_TRUE_PINBASED_CTLS_MSR);
        }
        else {
            pbVMEC.Value = VmxAdjustControls(pbVMEC.Value, IA32_VMX_PINBASED_CTLS_MSR);
        }
        Ret = __vmx_vmwrite(vm_execution_controls_pin, pbVMEC.Value);
        if (Ret != 0) {
            goto InitVMCSfailed;
        }
    }
    // intel 文档第三卷 24.6.3
    // 异常位图，是一个32位的字段，为idt中的0到31号异常分配了一个位。
    // 当异常发生时，它的向量会用来选择此字段中的一个位。如果该位为1，则异常会导致一个VM退出。
    // 如果位是0，则异常将通过IDT正常传递，使用与异常的向量对应的描述符。
    /*Ret = __vmx_vmwrite(vm_exception_bitmap, (UINT64)0xffff);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }*/

    // 页面错误代码掩码用于确定哪些页面错误的错误代码位会被检查以决定是否触发 VM 退出
    //Ret = __vmx_vmwrite(vm_page_fault_error_code_mask, (UINT64)0);
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //// 页面错误代码匹配值与页面错误代码掩码配合使用，以确定在页面错误发生时，哪些错误代码会导致 VM 退出
    //Ret = __vmx_vmwrite(vm_page_fault_error_code_match, (UINT64)0);
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}

    // CR3 目标计数用于快速切换到不同的页面目录（在某些形式的上下文切换中有用）。
    // 这个计数值告诉 VMX 硬件 CR3 目标值列表中有多少个条目是有效的。
    /*Ret = __vmx_vmwrite(vm_cr3_target_count, (UINT64)1);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }*/

    // 对应位对应具体功能见 intel 文档第三卷 24.6.2
    {
        PrimaryProcessorBasedVMEC ppbVMEC = { 0 };
        ppbVMEC.Value = 0;
        //ppbVMEC.CR3LoadExiting = 1;
        //ppbVMEC.CR3StoreExiting = 1;
        ppbVMEC.UseMSRBitmaps = 1;
        
        BOOLEAN bHasSecondaryProcBasedCTLS = FALSE;
        // Intel手册第三卷 A.3.2 
        // 如果IA32_VMX_BASIC MSR的位55读为0，则所有有关基于处理器的主要VM执行控制的允许设置信息都包含在IA32_VMX_PROCBASED_CTLS MSR中。
        // 如果IA32_VMX_BASIC MSR的位55读为1，则所有有关基于处理器的主要VM执行控制的允许设置信息都包含在IA32_VMX_TRUE_PROCBASED_CTLS MSR中。
        if ((__readmsr(IA32_VMX_BASIC_MSR) >> 55) % 2) {
            ppbVMEC.Value = VmxAdjustControls(ppbVMEC.Value, IA32_VMX_TRUE_PROCBASED_CTLS_MSR);
            if (__readmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR) >> 63) {
                bHasSecondaryProcBasedCTLS = TRUE;
                ppbVMEC.ActivateSecondaryControls = 1;
            }
        }
        else {
            ppbVMEC.Value = VmxAdjustControls(ppbVMEC.Value, IA32_VMX_PROCBASED_CTLS_MSR);
            if (__readmsr(IA32_VMX_PROCBASED_CTLS_MSR) >> 63) {
                bHasSecondaryProcBasedCTLS = TRUE;
                ppbVMEC.ActivateSecondaryControls = 1;
            }
        }
        Ret = __vmx_vmwrite(vm_execution_controls_cpu, ppbVMEC.Value);
        if (Ret != 0) {
            goto InitVMCSfailed;
        }

        if (bHasSecondaryProcBasedCTLS)
        {
            SecondaryProcessorBasedVMEC spbVMEC = { 0 };
            spbVMEC.Value = 0;
            spbVMEC.EnableRDTSCP = 1;
            spbVMEC.EnableXSAVESXRSTORS = 1;
            /*spbVMEC.EnableVPID = 1;
            spbVMEC.EnableINVPCID = 1;
            spbVMEC.EnableUserWaitAndPause = 1;
            spbVMEC.EnablePCONFIG = 1;*/

            spbVMEC.Value = VmxAdjustControls(spbVMEC.Value, IA32_VMX_PROCBASED_CTLS2_MSR);
            
            Ret = __vmx_vmwrite(vm_execution_controls_cpu_secondary, spbVMEC.Value);
            if (Ret != 0) {
                goto InitVMCSfailed;
            }
        }
    }

    // 3.2 vm exit control
    // 设置主要退出控制
    // Intel 手册第三卷 24.7.1 
    PrimaryVMEC pVMExitC = { 0 };
    pVMExitC.Value = 0;
    pVMExitC.HostAddressSpaceSize = 1; // 64位一定要设置，不然会错误7
    // Intel手册第三卷 A.4.1 
    // 如果IA32_VMX_BASIC MSR的位55为1时
    // 则所有有关主要VM退出控制的允许设置信息都包含在IA32_VMX_TRUE_EXIT_CTLS MSR中
    // 如果IA32_VMX_BASIC MSR的位55为0时
    // 则所有有关主要VM退出控制的允许设置信息都包含在IA32_VMX_EXIT_CTLS MSR中
    if ((__readmsr(IA32_VMX_BASIC_MSR) >> 55) % 2) {
        pVMExitC.Value = VmxAdjustControls(pVMExitC.Value, IA32_VMX_TRUE_EXIT_CTLS);
    }
    else {
        pVMExitC.Value = VmxAdjustControls(pVMExitC.Value, IA32_VMX_EXIT_CTLS_MSR);
    }
    
    Ret = __vmx_vmwrite(vm_exit_controls, pVMExitC.Value);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    //Ret = __vmx_vmwrite(vm_exit_msr_store_count, (UINT64)0); // 设置 VM 退出时保存 MSR（Model-Specific Register）的数量
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(vm_exit_msr_load_count, (UINT64)0); // 设置 VM 退出时加载 MSR 的数量
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}

    // 3.3 vm entery control
     // Intel 手册第三卷 24.8.1
    VMEntryControls pVMEntryC = { 0 };
    pVMEntryC.Value = 0;
    pVMEntryC.IA32eModeGuest = 1;
    // Intel手册第三卷 A.5
    // 如果IA32_VMX_BASIC MSR的位55读为0，则所有有关VM进入控制的允许设置信息都包含在IA32_VMX_ENTRY_CTLS MSR中。
    // 如果IA32_VMX_BASIC MSR的位55读为1，则所有有关VM进入控制的允许设置信息都包含在IA32_VMX_TRUE_ENTRY_CTLS MSR中
    if ((__readmsr(IA32_VMX_BASIC_MSR) >> 55) % 2) {
        pVMEntryC.Value = VmxAdjustControls(pVMEntryC.Value, IA32_VMX_TRUE_ENTRY_CTLS);
    }
    else {
        pVMEntryC.Value = VmxAdjustControls(pVMEntryC.Value, IA32_VMX_ENTRY_CTLS_MSR);
    }
    Ret = __vmx_vmwrite(vm_entry_controls, pVMEntryC.Value);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    //Ret = __vmx_vmwrite(vm_entry_msr_load_count, (UINT64)0); // 设置 VM 进入时加载 MSR 的数量
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //// 设置 VM 进入时的中断信息字段，这个字段通常包含关于导致 VM 进入的中断或异常的信息
    //Ret = __vmx_vmwrite(vm_entry_interruptioninfo, (UINT64)0); 
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //// 设置 VM 进入时的异常错误代码，如果 VM 进入是由于异常引起的，这个值通常会被用来提供有关该异常的更多信息。
    //Ret = __vmx_vmwrite(vm_entry_exceptionerrorcode, (UINT64)0); 
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //// 设置触发 VM 进入的指令的长度，在处理某些类型的 VM 进入（例如，由于中断或异常）时，这个长度可能会被用到。
    //Ret = __vmx_vmwrite(vm_entry_instructionlength, (UINT64)0);
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //// 设置任务优先级寄存器（Task Priority Register, TPR）阈值为 0。
    //// 这个值用于虚拟化 APIC（Advanced Programmable Interrupt Controller），特别是在使用 TPR 阴影和虚拟中断投递时。
    //Ret = __vmx_vmwrite(vm_tpr_threshold, (UINT64)0);
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}

    vmState[cpuNumber].pIOBitmapA_PA = MmGetPhysicalAddress(vmState[cpuNumber].pIOBitmapA);
    vmState[cpuNumber].pIOBitmapB_PA = MmGetPhysicalAddress(vmState[cpuNumber].pIOBitmapB);

    Ret = __vmx_vmwrite(vm_iobitmap_a, vmState[cpuNumber].pIOBitmapA_PA.QuadPart);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_iobitmap_b, vmState[cpuNumber].pIOBitmapB_PA.QuadPart);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    vmState[cpuNumber].pMSRBitmap_PA = MmGetPhysicalAddress(vmState[cpuNumber].pMSRBitmap);

    Ret = __vmx_vmwrite(vm_msrbitmap, vmState[cpuNumber].pMSRBitmap_PA.QuadPart); //MSR bitmap
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    //Ret = __vmx_vmwrite(vm_exit_msr_store_address, (UINT64)0xffffffffffffffff); //VM-Exit MSR store address(physical)
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(vm_exit_msr_load_address, (UINT64)0xffffffffffffffff); //VM-Exit MSR-Load address
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(vm_entry_msr_load_address, (UINT64)0xffffffffffffffff); //VM-Entry MSR-Load address
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(vm_executive_vmcs_pointer, (UINT64)0xffffffffffffffff); //Executive-VMCS pointer
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(vm_tsc_offset, (UINT64)0); //TSC offset
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(vm_virtual_apic_address, (UINT64)0xffffffffffffffff); //Virtual-APIC page address
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}

    return TRUE;

InitVMCSfailed:
    if (Ret == 1) {
        DbgPrintEx(0, 0, "vmwrite Error, %s\n", getVMInstructionErrorString());
    }
    else {
        DbgPrintEx(0, 0, "vmwrite Failed %hhd\n", Ret);
    }
    return FALSE;

}

BOOL VMMCreateForCurrentCPU()
{
    AsmCreateVMM();

    if (vmState[cpunr()].bVMLAUNCHSuccess)
    {
        DbgPrintEx(0, 0, "VM Number: %d Initialize Success\n", cpunr());
        return TRUE;
    }

    return FALSE;
}

void VMMCreateForCurrentCPU_DPC(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    AsmCreateVMM();
    
    if (vmState[cpunr()].bVMLAUNCHSuccess)
    {
        DbgPrintEx(0, 0, "VM Number: %d Initialize Success\n", cpunr());
    }

    //等待全部内核同步
    KeSignalCallDpcSynchronize(SystemArgument2);

    //释放锁
    KeSignalCallDpcDone(SystemArgument1);
}



void VMMCreate()
{
    KeGenericCallDpc(VMMCreateForCurrentCPU_DPC, NULL);
}

BOOL RemoveAllVM()
{
    for (unsigned int i = 0; i < GetCPUCount(); i++)
    {
        if (vmState[i].pVMCSRegion)
        {
            if (MmIsAddressValid(vmState[i].pVMCSRegion))
            {
                ExFreePoolWithTag(vmState[i].pVMCSRegion, VMMemoryTag);
                vmState[i].pVMCSRegion = NULL;
                vmState[i].pVMCSRegion_PA.QuadPart = 0;
            }
        }

        if (vmState[i].pIOBitmapA)
        {
            if (MmIsAddressValid(vmState[i].pIOBitmapA))
            {
                ExFreePoolWithTag(vmState[i].pIOBitmapA, VMMemoryTag);
                vmState[i].pIOBitmapA = NULL;
                vmState[i].pIOBitmapA_PA.QuadPart = 0;
            }
        }

        if (vmState[i].pIOBitmapB)
        {
            if (MmIsAddressValid(vmState[i].pIOBitmapB))
            {
                ExFreePoolWithTag(vmState[i].pIOBitmapB, VMMemoryTag);
                vmState[i].pIOBitmapB = NULL;
                vmState[i].pIOBitmapB_PA.QuadPart = 0;
            }
        }

        if (vmState[i].pMSRBitmap)
        {
            if (MmIsAddressValid(vmState[i].pMSRBitmap))
            {
                ExFreePoolWithTag(vmState[i].pMSRBitmap, VMMemoryTag);
                vmState[i].pMSRBitmap = NULL;
                vmState[i].pMSRBitmap_PA.QuadPart = 0;
            }
        }

        if (vmState[i].pHostVMStack)
        {
            if (MmIsAddressValid(vmState[i].pHostVMStack))
            {
                ExFreePoolWithTag(vmState[i].pHostVMStack, VMMemoryTag);
                vmState[i].pHostVMStack = NULL;
            }
        }

    }

    return TRUE;
}

BOOL VMXStart()
{
    KeGenericCallDpc(VTStartForCurrentCPU_DPC, NULL);

    return TRUE;
}

BOOL VMXStop()
{
    ULONG cpuCount = GetCPUCount();

    KeGenericCallDpc(VTStopForCurrentCPU_DPC, NULL);

    RemoveAllVM();

    return TRUE;
}

void VTStartForCurrentCPU_DPC(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    VTStart();

    //等待全部内核同步
    KeSignalCallDpcSynchronize(SystemArgument2);

    //释放锁
    KeSignalCallDpcDone(SystemArgument1);
}

void VTStopForCurrentCPU_DPC(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    VTStop();

    //等待全部内核同步
    KeSignalCallDpcSynchronize(SystemArgument2);

    //释放锁
    KeSignalCallDpcDone(SystemArgument1);
}

static BOOL AllocCurrentVMXONmemory(int cpuNumber)
{
    vmState[cpuNumber].pVMXRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, VMMemoryTag);
    if (!vmState[cpuNumber].pVMXRegion) {
        DbgPrintEx(0, 0, "ExAllocatePool Error\n");
        return FALSE;
    }
    RtlZeroMemory(vmState[cpuNumber].pVMXRegion, 0x1000);

    return TRUE;
}

BOOL VTStart()
{
    int cpuNumber = cpunr();

    AllocCurrentVMXONmemory(cpuNumber);

    if (CheckVTIsSupport() == FALSE) {
        return FALSE;
    }

    _CR4 cr4Value = { 0 };
    cr4Value.Value = __readcr4();

    cr4Value.VMXE = 1;
    __writecr4(cr4Value.Value); // 修改CR4的VMXE位

    // DbgPrintEx(0, 0, "VTStart CPU Number %d\n", cpunr());

    UINT64 msr480h = __readmsr(IA32_VMX_BASIC_MSR);
    // msr 480h 32位到44位是 VMXON 区域和任何 VMCS 区域分配的字节数
    // UINT64 VMXONRegionSize = (msr480h >> 32) & 0x1FFF;
    //DbgPrintEx(0, 0, "VMXONRegionSize: %lld\n", VMXONRegionSize);

    UINT VMCSRevision = msr480h & 0x7FFFFFFF;
    //DbgPrintEx(0, 0, "VMCS revision: %d\n", VMCSRevision);
    // 需要把前4个字节设置为VMCS revision 也就是 msr 480h 的0到30位
    *(UINT*)(vmState[cpuNumber].pVMXRegion) = VMCSRevision;

    vmState[cpuNumber].pVMXRegion_PA = MmGetPhysicalAddress(vmState[cpuNumber].pVMXRegion);
    
    char RetVMXON = __vmx_on(&vmState[cpuNumber].pVMXRegion_PA);
    if (RetVMXON != 0) {
        if (RetVMXON == 1) {
            DbgPrintEx(0, 0, "VMXON Error, %s", getVMInstructionErrorString());
        }
        else {
            DbgPrintEx(0, 0, "VMXON Failed %hhd\n", RetVMXON);
        }
        // 失败收尾
        {
            _CR4 cr4Value = { 0 };
            cr4Value.Value = __readcr4();

            cr4Value.VMXE = 0;
            __writecr4(cr4Value.Value); // 修改CR4的VMXE位

            ExFreePoolWithTag(vmState[cpuNumber].pVMXRegion, VMMemoryTag);
            vmState[cpuNumber].pVMXRegion = NULL;
            vmState[cpuNumber].pVMXRegion_PA.QuadPart = 0;
        }

        return FALSE;
    }

    //DbgPrintEx(0, 0, "VMXON Success at CPUNumber: %d\n", cpunr());
    vmState[cpuNumber].bVMXONSuccess = TRUE;
    return TRUE;
}

void VTStop()
{
    int cpuNumber = cpunr();

    if (vmState[cpuNumber].bVMXONSuccess == FALSE) {
        return;
    }

    _CR4 cr4Value = { 0 };
    cr4Value.Value = __readcr4();
    if (cr4Value.VMXE == 0) {
        DbgPrintEx(0, 0, "CPUNumber: %d not execute VMXON yet\n", cpunr());
        return;
    }

    __vmx_vmclear(&vmState[cpuNumber].pVMCSRegion_PA);
    __vmx_off();

    {
        _CR4 cr4Value = { 0 };
        cr4Value.Value = __readcr4();

        cr4Value.VMXE = 0;
        __writecr4(cr4Value.Value); // 修改CR4的VMXE位
    }

    vmState[cpuNumber].pVMXRegion_PA.QuadPart = 0;
    if (MmIsAddressValid(vmState[cpuNumber].pVMXRegion)) {
        ExFreePoolWithTag(vmState[cpuNumber].pVMXRegion, VMMemoryTag);
        vmState[cpuNumber].pVMXRegion = NULL;
    }

    vmState[cpuNumber].bVMXONSuccess = FALSE;
    //DbgPrintEx(0, 0, "VMXOFF at CPUNumber: %d\n", cpunr());
}
