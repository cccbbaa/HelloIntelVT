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

    if (((cpuidret[2] >> 5) % 2) == 0) { // rcx�ĵ���λ(��0��ʼ)Ϊ1�Ļ�CPU��֧��VT
        DbgPrintEx(0, 0, "This CPU not support Virtual Technology, rcx %x, cpuNumber [%d]\n", cpuidret[2], cpunr());
        return FALSE;
    }

    UINT64 msr3A = __readmsr(0x3A);
    if (!(msr3A & 0b1)) { // msr 3A��LOCKλҪΪ1
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
    // msr 480h 32λ��44λ�� VMXON ������κ� VMCS ���������ֽ���
    //UINT64 VMCSRegionSize = (msr480h >> 32) & 0x1FFF;
    //DbgPrintEx(0, 0, "VMCSRegionSize: %lld\n", VMCSRegionSize);

    UINT VMCSRevision = msr480h & 0x7FFFFFFF;
    DbgPrintEx(0, 0, "VMCS revision: %d\n", VMCSRevision);
    // ��Ҫ��ǰ4���ֽ�����ΪVMCS revision Ҳ���� msr 480h ��0��30λ
    *(UINT*)(vmState[cpuNumber].pVMCSRegion) = VMCSRevision;

    vmState[cpuNumber].pVMCSRegion_PA = MmGetPhysicalAddress(vmState[cpuNumber].pVMCSRegion);

    // ��ʼ��ָ����VMCS������������״̬����Ϊ Clear
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

    // ��ָ����ַ����ָ��ǰ VMCS ��ָ��
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

    // ��ʼ�� VMCS
    if (InitializeVMCS(cpunr(), guestStack) == FALSE) {
        DbgPrintEx(0, 0, "InitializeVMCS Failed\n");

        goto CreateFailed;
    }

    vmState[cpuNumber].bVMLAUNCHSuccess = TRUE;

    LeaveCriticalSection(&cSection);

    // �����������!!! 
    
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

    // �����ɹ��Ļ�����Ĵ��벻Ӧ�ûᱻִ��
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
    // Intel �ֲ� ������ 24.4.1

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

    // DR7�Ĵ���Ĭ��Ϊ0x400
    Ret = __vmx_vmwrite(vm_guest_dr7, 0x400);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    // Intel System Programming Guide 26.3.1.4 
    // Rflags
    // ����λ63:22���ڲ�֧��Intel 64�ܹ��Ĵ�������Ϊλ31:22����λ15��λ5��λ3���ֶ��б���Ϊ0������λ1����Ϊ1��
    // �����IA - 32eģʽ�ͻ���VM�������Ϊ1��CR0�ֶ��е�λ0����ӦCR0.PE��Ϊ0����VM��־��λ17������Ϊ0��
    // ���VM�����ж���Ϣ�ֶ��е���Чλ��λ31��Ϊ1���ж����ͣ�λ10 : 8��Ϊ�ⲿ�жϣ���IF��־��RFLAGS[λ9]������Ϊ1��

    RFLAGS RFlags = { 0 };
    RFlags.AsUInt = __readeflags();
    RFlags.InterruptEnableFlag = 0; //����Guestʱ���ж�

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

    // Intel �ֲ� ������ 24.10
    Ret = __vmx_vmwrite(vm_vmcs_link_pointer, 0xffffffffffffffffULL);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    // Intel �ֲ� ������ 24.4.1
    Ret = __vmx_vmwrite(vm_guest_IA32_DEBUGCTL, __readmsr(IA32_DEBUGCTL_MSR));// ���ڿ��ƴ������ĵ������ԣ����֧��¼������ִ�к�����֧��¼��(Windows ��ʹ��)
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS_MSR)); // ���ڿ���ϵͳ���ã�SYSENTER/SYSEXIT ָ�
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP_MSR)); // ϵͳ����ʱ�Ķ�ջָ�룬���� SYSENTER
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP_MSR)); // ϵͳ����ʱ��ָ��ָ�룬���� SYSENTER
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_PERF_GLOBAL_CTRL, __readmsr(IA32_PERF_GLOBAL_CTRL_MSR)); // ���ڿ������ܼ�ؼ�����
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_PAT, __readmsr(IA32_PAT_MSR)); // ҳ�����Ա����ڶ����ڴ����ͣ���д�ء�дͨ�ȣ�
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_guest_IA32_EFER, __readmsr(EFER_MSR)); // ��չ���ܼĴ����������������ó�ģʽ��LME��������ϵͳ������չ��SCE���ȱ�־
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

    // ���� Intel ���ڴ���޼����չ (MPX)���ṩ�Ա߽������õĿ��ơ����������ñ߽��������״̬�ͱ߽��Ļ�ַ��
    // Windows��֧��
    //Ret = __vmx_vmwrite(vm_guest_IA32_BNDCFGS, __readmsr(IA32_BNDCFGS_MSR)); 
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //Ret = __vmx_vmwrite(vm_guest_IA32_RTIT_CTL, __readmsr(IA32_RTIT_CTL_MSR)); // ��Intel PT(Processor Trace)��أ��������úͿ��ƴ�����׷�ٹ��ܣ��������ڷ�������ִ�к͵���
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //Ret = __vmx_vmwrite(vm_guest_IA32_LBR_CTL, __readmsr(IA32_LBR_CTL_MSR)); // �������ô�����������֧��¼����
    //if (Ret != 0) {
    //    SetBreakPointEx();
    //}

    Ret = __vmx_vmwrite(vm_host_IA32_S_CET, __readmsr(IA32_S_CET_MSR)); // �������̷�����Control-flow Enforcement Technology, CET����״̬��
    if (Ret != 0) {
        SetBreakPointEx();
    }
    Ret = __vmx_vmwrite(vm_host_IA32_INTERRUPT_SSP_TABLE_ADDR, __readmsr(IA32_INTERRUPT_SSP_TABLE_ADDR_MSR)); // �ж϶�ջ���ַ���� CET ���
    if (Ret != 0) {
        SetBreakPointEx();
    }
    Ret = __vmx_vmwrite(vm_host_IA32_PKRS, __readmsr(IA32_PKRS_MSR)); // ������ԿȨ�޼Ĵ����������ڴ汣��������
    if (Ret != 0) {
        SetBreakPointEx();
    }

    // 2. Host state fields
    // Intel �ֲ� ������ 24.5

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

    // Intel �ֲ� ������ 26.2.3
    // ����CS������Σ���SS����ջ�Σ���DS�����ݶΣ���ES��FS��GS��TR������Ĵ�������ѡ�����ֶ�
    // ������Ȩ����RPL��λ1:0���ͱ�ָʾ��־��TI��־��λ2������Ϊ0��
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
    
    
    // SYSENTER/SYSEXIT �ƺ��� Windows 10 x64��û���õ�
    Ret = __vmx_vmwrite(vm_host_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS_MSR)); // ���ڿ���ϵͳ���ã�SYSENTER/SYSEXIT ָ�
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    
    Ret = __vmx_vmwrite(vm_host_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP_MSR)); // ϵͳ����ʱ�Ķ�ջָ�룬���� SYSENTER
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    
    Ret = __vmx_vmwrite(vm_host_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP_MSR)); // ϵͳ����ʱ��ָ��ָ�룬���� SYSENTER
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_PERF_GLOBAL_CTRL, __readmsr(IA32_PERF_GLOBAL_CTRL_MSR)); // ���ڿ������ܼ�ؼ�����
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_PAT, __readmsr(IA32_PAT_MSR)); // ҳ�����Ա����ڶ����ڴ����ͣ���д�ء�дͨ�ȣ�
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_EFER, __readmsr(EFER_MSR)); // ��չ���ܼĴ����������������ó�ģʽ��LME��������ϵͳ������չ��SCE���ȱ�־
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_S_CET, __readmsr(IA32_S_CET_MSR)); // �������̷�����Control-flow Enforcement Technology, CET����״̬��
    if (Ret != 0) {
        goto InitVMCSfailed;
    }

    Ret = __vmx_vmwrite(vm_host_IA32_INTERRUPT_SSP_TABLE_ADDR, __readmsr(IA32_INTERRUPT_SSP_TABLE_ADDR_MSR)); // �ж϶�ջ���ַ���� CET ���
    if (Ret != 0) {
        goto InitVMCSfailed;
    }
    Ret = __vmx_vmwrite(vm_host_IA32_PKRS, __readmsr(IA32_PKRS_MSR)); // ������ԿȨ�޼Ĵ����������ڴ汣��������
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

    // ��Ӧλ��Ӧ���幦�ܼ� intel �ĵ������� 24.6.1
    {
        PinBasedVMEC pbVMEC = { 0 };
        // Intel�ֲ������ A.3.1 
        // ���IA32_VMX_BASIC MSR��λ55��Ϊ0���������йػ��ڹܽŵ�VMִ�п��Ƶ�����������Ϣ��������IA32_VMX_PINBASED_CTLS MSR�С�
        // ���IA32_VMX_BASIC MSR��λ55��Ϊ1���������йػ��ڹܽŵ�VMִ�п��Ƶ�����������Ϣ��������IA32_VMX_TRUE_PINBASED_CTLS MSR��
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
    // intel �ĵ������� 24.6.3
    // �쳣λͼ����һ��32λ���ֶΣ�Ϊidt�е�0��31���쳣������һ��λ��
    // ���쳣����ʱ����������������ѡ����ֶ��е�һ��λ�������λΪ1�����쳣�ᵼ��һ��VM�˳���
    // ���λ��0�����쳣��ͨ��IDT�������ݣ�ʹ�����쳣��������Ӧ����������
    /*Ret = __vmx_vmwrite(vm_exception_bitmap, (UINT64)0xffff);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }*/

    // ҳ����������������ȷ����Щҳ�����Ĵ������λ�ᱻ����Ծ����Ƿ񴥷� VM �˳�
    //Ret = __vmx_vmwrite(vm_page_fault_error_code_mask, (UINT64)0);
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //// ҳ��������ƥ��ֵ��ҳ���������������ʹ�ã���ȷ����ҳ�������ʱ����Щ�������ᵼ�� VM �˳�
    //Ret = __vmx_vmwrite(vm_page_fault_error_code_match, (UINT64)0);
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}

    // CR3 Ŀ��������ڿ����л�����ͬ��ҳ��Ŀ¼����ĳЩ��ʽ���������л������ã���
    // �������ֵ���� VMX Ӳ�� CR3 Ŀ��ֵ�б����ж��ٸ���Ŀ����Ч�ġ�
    /*Ret = __vmx_vmwrite(vm_cr3_target_count, (UINT64)1);
    if (Ret != 0) {
        goto InitVMCSfailed;
    }*/

    // ��Ӧλ��Ӧ���幦�ܼ� intel �ĵ������� 24.6.2
    {
        PrimaryProcessorBasedVMEC ppbVMEC = { 0 };
        ppbVMEC.Value = 0;
        //ppbVMEC.CR3LoadExiting = 1;
        //ppbVMEC.CR3StoreExiting = 1;
        ppbVMEC.UseMSRBitmaps = 1;
        
        BOOLEAN bHasSecondaryProcBasedCTLS = FALSE;
        // Intel�ֲ������ A.3.2 
        // ���IA32_VMX_BASIC MSR��λ55��Ϊ0���������йػ��ڴ���������ҪVMִ�п��Ƶ�����������Ϣ��������IA32_VMX_PROCBASED_CTLS MSR�С�
        // ���IA32_VMX_BASIC MSR��λ55��Ϊ1���������йػ��ڴ���������ҪVMִ�п��Ƶ�����������Ϣ��������IA32_VMX_TRUE_PROCBASED_CTLS MSR�С�
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
    // ������Ҫ�˳�����
    // Intel �ֲ������ 24.7.1 
    PrimaryVMEC pVMExitC = { 0 };
    pVMExitC.Value = 0;
    pVMExitC.HostAddressSpaceSize = 1; // 64λһ��Ҫ���ã���Ȼ�����7
    // Intel�ֲ������ A.4.1 
    // ���IA32_VMX_BASIC MSR��λ55Ϊ1ʱ
    // �������й���ҪVM�˳����Ƶ�����������Ϣ��������IA32_VMX_TRUE_EXIT_CTLS MSR��
    // ���IA32_VMX_BASIC MSR��λ55Ϊ0ʱ
    // �������й���ҪVM�˳����Ƶ�����������Ϣ��������IA32_VMX_EXIT_CTLS MSR��
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

    //Ret = __vmx_vmwrite(vm_exit_msr_store_count, (UINT64)0); // ���� VM �˳�ʱ���� MSR��Model-Specific Register��������
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //Ret = __vmx_vmwrite(vm_exit_msr_load_count, (UINT64)0); // ���� VM �˳�ʱ���� MSR ������
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}

    // 3.3 vm entery control
     // Intel �ֲ������ 24.8.1
    VMEntryControls pVMEntryC = { 0 };
    pVMEntryC.Value = 0;
    pVMEntryC.IA32eModeGuest = 1;
    // Intel�ֲ������ A.5
    // ���IA32_VMX_BASIC MSR��λ55��Ϊ0���������й�VM������Ƶ�����������Ϣ��������IA32_VMX_ENTRY_CTLS MSR�С�
    // ���IA32_VMX_BASIC MSR��λ55��Ϊ1���������й�VM������Ƶ�����������Ϣ��������IA32_VMX_TRUE_ENTRY_CTLS MSR��
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

    //Ret = __vmx_vmwrite(vm_entry_msr_load_count, (UINT64)0); // ���� VM ����ʱ���� MSR ������
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //// ���� VM ����ʱ���ж���Ϣ�ֶΣ�����ֶ�ͨ���������ڵ��� VM ������жϻ��쳣����Ϣ
    //Ret = __vmx_vmwrite(vm_entry_interruptioninfo, (UINT64)0); 
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //// ���� VM ����ʱ���쳣������룬��� VM �����������쳣����ģ����ֵͨ���ᱻ�����ṩ�йظ��쳣�ĸ�����Ϣ��
    //Ret = __vmx_vmwrite(vm_entry_exceptionerrorcode, (UINT64)0); 
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //// ���ô��� VM �����ָ��ĳ��ȣ��ڴ���ĳЩ���͵� VM ���루���磬�����жϻ��쳣��ʱ��������ȿ��ܻᱻ�õ���
    //Ret = __vmx_vmwrite(vm_entry_instructionlength, (UINT64)0);
    //if (Ret != 0) {
    //    goto InitVMCSfailed;
    //}
    //
    //// �����������ȼ��Ĵ�����Task Priority Register, TPR����ֵΪ 0��
    //// ���ֵ�������⻯ APIC��Advanced Programmable Interrupt Controller�����ر�����ʹ�� TPR ��Ӱ�������ж�Ͷ��ʱ��
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

    //�ȴ�ȫ���ں�ͬ��
    KeSignalCallDpcSynchronize(SystemArgument2);

    //�ͷ���
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

    //�ȴ�ȫ���ں�ͬ��
    KeSignalCallDpcSynchronize(SystemArgument2);

    //�ͷ���
    KeSignalCallDpcDone(SystemArgument1);
}

void VTStopForCurrentCPU_DPC(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    VTStop();

    //�ȴ�ȫ���ں�ͬ��
    KeSignalCallDpcSynchronize(SystemArgument2);

    //�ͷ���
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
    __writecr4(cr4Value.Value); // �޸�CR4��VMXEλ

    // DbgPrintEx(0, 0, "VTStart CPU Number %d\n", cpunr());

    UINT64 msr480h = __readmsr(IA32_VMX_BASIC_MSR);
    // msr 480h 32λ��44λ�� VMXON ������κ� VMCS ���������ֽ���
    // UINT64 VMXONRegionSize = (msr480h >> 32) & 0x1FFF;
    //DbgPrintEx(0, 0, "VMXONRegionSize: %lld\n", VMXONRegionSize);

    UINT VMCSRevision = msr480h & 0x7FFFFFFF;
    //DbgPrintEx(0, 0, "VMCS revision: %d\n", VMCSRevision);
    // ��Ҫ��ǰ4���ֽ�����ΪVMCS revision Ҳ���� msr 480h ��0��30λ
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
        // ʧ����β
        {
            _CR4 cr4Value = { 0 };
            cr4Value.Value = __readcr4();

            cr4Value.VMXE = 0;
            __writecr4(cr4Value.Value); // �޸�CR4��VMXEλ

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
        __writecr4(cr4Value.Value); // �޸�CR4��VMXEλ
    }

    vmState[cpuNumber].pVMXRegion_PA.QuadPart = 0;
    if (MmIsAddressValid(vmState[cpuNumber].pVMXRegion)) {
        ExFreePoolWithTag(vmState[cpuNumber].pVMXRegion, VMMemoryTag);
        vmState[cpuNumber].pVMXRegion = NULL;
    }

    vmState[cpuNumber].bVMXONSuccess = FALSE;
    //DbgPrintEx(0, 0, "VMXOFF at CPUNumber: %d\n", cpunr());
}
