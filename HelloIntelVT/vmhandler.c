#include "vmhandler.h"
#include "vmWriteReadHelper.h"

#include "HelpFunction.h"
#include "msrname.h"
#include "VTFunction.h"

Register restoreRegister[MAX_CPU_COUNT] = { 0 };

static void VMMcpuidHandler(PGUEST_REGS GuestRegs)
{
	if (GuestRegs->rax == 'cpur')
	{
		GuestRegs->rbx = cpunr();
		GuestRegs->rcx = 0x12345678;
		GuestRegs->rdx = 0x22334455;
		return;
	}
	// SetBreakPointEx();
	int cpuInfo[4] = { 0 };
	int function_id = GuestRegs->rax & 0xffffffff;
	int subfunction_id = GuestRegs->rcx & 0xffffffff;
	__cpuidex(cpuInfo, function_id, subfunction_id);

	GuestRegs->rax = cpuInfo[0];
	GuestRegs->rbx = cpuInfo[1];
	GuestRegs->rcx = cpuInfo[2];
	GuestRegs->rdx = cpuInfo[3];

}

static void VMMrdmsrHandler(PGUEST_REGS GuestRegs)
{
	LARGE_INTEGER Msr = { 0 };
	ULONG Register = GuestRegs->rcx & 0xffffffff;
	Msr.QuadPart = __readmsr(Register);
	GuestRegs->rax = Msr.LowPart;
	GuestRegs->rdx = Msr.HighPart;
}

static void VMMwrmsrHandler(PGUEST_REGS GuestRegs)
{
	LARGE_INTEGER Msr = { 0 };
	Msr.LowPart = GuestRegs->rax & 0xffffffff;
	Msr.HighPart = GuestRegs->rdx & 0xffffffff;
	ULONG Register = GuestRegs->rcx & 0xffffffff;
	__writemsr(Register, Msr.QuadPart);
}

static void VMMaccessCrHandler(PGUEST_REGS GuestRegs)
{
	VMX_EXIT_QUALIFICATION_MOV_CR Qualification = { 0 };
	__vmx_vmread(vm_exit_qualification, &Qualification.AsUInt);
	PULONG64 RegisterPtr = (PULONG64)(&GuestRegs->rax) + Qualification.GeneralPurposeRegister;

	switch (Qualification.AccessType)
	{
	case VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR:
	{
		switch (Qualification.ControlRegister)
		{
		case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
		{
			CR0 Cr0Fix0 = { 0 };
			CR0 Cr0Fix1 = { 0 };
			Cr0Fix0.AsUInt = __readmsr(IA32_VMX_CR0_FIXED0_MSR);
			Cr0Fix1.AsUInt = __readmsr(IA32_VMX_CR0_FIXED1_MSR);
			*RegisterPtr &= Cr0Fix1.AsUInt;
			*RegisterPtr |= Cr0Fix0.AsUInt;

			__vmx_vmwrite(vm_guest_cr0, *RegisterPtr);
			__vmx_vmwrite(vm_cr0_read_shadow, *RegisterPtr);
			break;
		}
		case VMX_EXIT_QUALIFICATION_REGISTER_CR3:
		{
			//[63bit]  �������޸�
			*RegisterPtr &= ~(1ull << 63);
			__vmx_vmwrite(vm_guest_cr3, *RegisterPtr);

			//
		   // ��������ʹ����VPID��ǩ��ʧЧ�����vm-exit�����������Զ���ˢ��tlb�����Ǳ����ֶ�ִ��
		   //
			// ����ʹ����VpidʧЧ ��Ϊ��������Ĭ��VPIDΪ1��
			//VmxInvvpid(INVVPID_TYPE::InvvpidSingleContext, 1, NULL);
			SetBreakPointEx();
			break;
		}
		case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
		{
			CR4 Cr4Fix0 = { 0 };
			CR4 Cr4Fix1 = { 0 };
			Cr4Fix0.AsUInt = __readmsr(IA32_VMX_CR4_FIXED0_MSR);
			Cr4Fix1.AsUInt = __readmsr(IA32_VMX_CR4_FIXED1_MSR);
			*RegisterPtr &= Cr4Fix1.AsUInt;
			*RegisterPtr |= Cr4Fix0.AsUInt;

			__vmx_vmwrite(vm_guest_cr4, *RegisterPtr);
			__vmx_vmwrite(vm_cr4_read_shadow, *RegisterPtr);
			break;
		}
		default:
			DbgPrint("δ������д CR %lld �Ĵ���\n", Qualification.ControlRegister);
			SetBreakPointEx();
			break;
		}
		break;
	}
	case VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR:
	{
		switch (Qualification.ControlRegister)
		{
		case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
		{
			__vmx_vmread(vm_guest_cr0, RegisterPtr);
			break;
		}
		case VMX_EXIT_QUALIFICATION_REGISTER_CR3:
		{
			__vmx_vmread(vm_guest_cr3, RegisterPtr);
			break;
		}
		case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
		{
			__vmx_vmread(vm_guest_cr4, RegisterPtr);
			break;
		}
		default:
			DbgPrint("δ�����Ķ� CR %lld �Ĵ���\n", Qualification.ControlRegister);
			SetBreakPointEx();
			break;
		}
		break;
	}
	default:
		DbgPrint("δ������MovCr AccessType: %lld \n", Qualification.AccessType);
		SetBreakPointEx();
		break;
	}
}

static void VMMxsetbvHandler(PGUEST_REGS GuestRegs)
{
	LARGE_INTEGER Val;
	unsigned int ext_ctrl_reg = GuestRegs->rcx & 0xffffffff;
	Val.LowPart = GuestRegs->rax & 0xffffffff;
	Val.HighPart = GuestRegs->rdx & 0xffffffff;
	_xsetbv(ext_ctrl_reg, Val.QuadPart);
}

static void VMMvmcallHandler(PGUEST_REGS GuestRegs)
{
	// rcx 'czvt'
	// rdx 'vm'
	// r8 'off'
	// r9 cpunr() + 1

	UINT64 result = ((GuestRegs->rcx * GuestRegs->r8) ^ GuestRegs->rdx) + (GuestRegs->r9);

	//��ȡ��ǰ�߼�������ID
	ULONG64 ProcessID = cpunr();

	if (result == (0x2b49e3ca491c55ULL + (cpunr() + 1ULL))) // vmoff
	{

		//��ȡGUEST CR3 ���óɵ�ǰCR3
		ULONG64 GuestCr3 = 0;
		__vmx_vmread(vm_guest_cr3, &GuestCr3);
		__writecr3(GuestCr3);

		//��ȡGUESTRSP��GUESTRIP 
		ULONG64 ExitInstructionLength = 0;
		__vmx_vmread(vm_guest_rip, &restoreRegister[ProcessID].rip);
		__vmx_vmread(vm_guest_rsp, &restoreRegister[ProcessID].rsp);
		__vmx_vmread(vm_guest_rflags, &restoreRegister[ProcessID].rflags);
		__vmx_vmread(vm_exit_instructionlength, &ExitInstructionLength);
		restoreRegister[ProcessID].rip += ExitInstructionLength;
		
		// ��ȡͨ�üĴ���
		{
			restoreRegister[ProcessID].rcx = GuestRegs->rcx;
			restoreRegister[ProcessID].rdx = GuestRegs->rdx;
			restoreRegister[ProcessID].rbx = GuestRegs->rbx;
			restoreRegister[ProcessID].rbp = GuestRegs->rbp;
			restoreRegister[ProcessID].rsi = GuestRegs->rsi;
			restoreRegister[ProcessID].rdi = GuestRegs->rdi;
			restoreRegister[ProcessID].r8 = GuestRegs->r8;
			restoreRegister[ProcessID].r9 = GuestRegs->r9;
			restoreRegister[ProcessID].r10 = GuestRegs->r10;
			restoreRegister[ProcessID].r11 = GuestRegs->r11;
			restoreRegister[ProcessID].r12 = GuestRegs->r12;
			restoreRegister[ProcessID].r13 = GuestRegs->r13;
			restoreRegister[ProcessID].r14 = GuestRegs->r14;
			restoreRegister[ProcessID].r15 = GuestRegs->r15;
		}

		//��ȡGUEST��FS GS CS DS ES IDT GDT �Ĵ��� ����ֵ����ǰhost  
		{
			ULONG64 FsBase = 0;
			__vmx_vmread(vm_guest_fs_base, &FsBase);
			__writemsr(IA32_FS_BASE_MSR, FsBase);

			ULONG64 Fs = 0;
			__vmx_vmread(vm_guest_fs, &Fs);
			restoreRegister[ProcessID].fs = Fs & 0xffff;
		}
		
		{
			ULONG64 gsBase = 0;
			__vmx_vmread(vm_guest_gs_base, &gsBase);
			__writemsr(IA32_GS_BASE_MSR, gsBase);

			ULONG64 gs = 0;
			__vmx_vmread(vm_guest_fs, &gs);
			restoreRegister[ProcessID].gs = gs & 0xffff;
		}

		{

			ULONG64 cs = 0;
			__vmx_vmread(vm_guest_cs, &cs);
			restoreRegister[ProcessID].cs = cs & 0xffff;
		}

		{

			ULONG64 ds = 0;
			__vmx_vmread(vm_guest_ds, &ds);
			restoreRegister[ProcessID].ds = ds & 0xffff;
		}

		{

			ULONG64 ss = 0;
			__vmx_vmread(vm_guest_ss, &ss);
			restoreRegister[ProcessID].ss = ss & 0xffff;
		}

		{

			ULONG64 es = 0;
			__vmx_vmread(vm_guest_es, &es);
			restoreRegister[ProcessID].es = es & 0xffff;
		}

		ULONG64 IdtBase, Idtlimit;
		__vmx_vmread(vm_guest_idtr_base, &IdtBase);
		__vmx_vmread(vm_guest_idt_limit, &Idtlimit);
		reloadIdtr((PVOID)IdtBase, Idtlimit & 0xffffffff);
		
		ULONG64 GdtBase, GdtLimit;
		__vmx_vmread(vm_guest_gdtr_base, &GdtBase);
		__vmx_vmread(vm_guest_gdt_limit, &GdtLimit);
		reloadGdtr((PVOID)GdtBase, GdtLimit & 0xffffffff);

		//����VmxClear ���ر������

		UCHAR Result = __vmx_vmclear(&(vmState[ProcessID].pVMCSRegion_PA));

		//�����ɹ��͵���VmOff�����ñ�־λ
		if (Result == 0)
		{
			__vmx_off();

			vmState[ProcessID].bVMLAUNCHSuccess = FALSE;
			vmState[ProcessID].bVMXONSuccess = FALSE;

			//�ָ�Cr4
			CR4 Cr4 = { 0 };
			Cr4.AsUInt = __readcr4();
			Cr4.VmxEnable = 0;
			__writecr4(Cr4.AsUInt);

		}
	}

	restoreRegister[ProcessID].rax = STATUS_SUCCESS;

}

void VmxVmresume()
{
	__vmx_vmresume();

	//����ɹ��Ͳ��ᵽ����
	ULONG64 ErrorCode = 0;
	__vmx_vmread(vm_errorcode, &ErrorCode);
	__vmx_off();

	DbgPrint("Error Vmresume Code : %llx\n", ErrorCode);

	__debugbreak();
}

PVOID CVMMEntryPoint(PGUEST_REGS pGuestRegs)
{
	// SetBreakPointEx();

	size_t ExitReason;
	size_t ExitInstructionLength;
	size_t Guestgdtlimit;
	size_t GuestRip;
	size_t GuestRsp;
	size_t GuestRflags;

	__vmx_vmread(vm_exit_reason, &ExitReason);
	__vmx_vmread(vm_exit_instructionlength, &ExitInstructionLength);
	__vmx_vmread(vm_guest_rflags, &GuestRflags);
	__vmx_vmread(vm_guest_rsp, &GuestRsp);
	__vmx_vmread(vm_guest_rip, &GuestRip);
	//__vmx_vmread(vm_guest_gdtr_base, &cGuestReg.gdtbase);
	//__vmx_vmread(vm_guest_gdt_limit, &Guestgdtlimit);
	//cGuestReg.gdtlimit = Guestgdtlimit;
	
	// SetBreakPointEx();

	switch (ExitReason)
	{
	case 0: // Exception or non-maskable interrupt (NMI)
	{
		size_t ExitInterruptionInfo = 0;
		__vmx_vmread(vm_exit_interruptioninfo, &ExitInterruptionInfo);
		if (ExitInterruptionInfo != 0x80000b0e) {
			DbgPrintEx(0, 0, "------Test------\ncpunr: %d\nvm_exit_reason: 0x%llx\nvm_exit_instructionlength: %lld\nvm_guest_rsp: 0x%llx\nvm_guest_rip: 0x%llx\nvm_guest_rflags: 0x%llx\n------Test------\n", cpunr(), ExitReason, ExitInstructionLength, GuestRsp, GuestRip, GuestRflags);
			DbgPrintEx(0, 0, "vm exit interruptioninfo: %llx\n", ExitInterruptionInfo);
		}
			
		switch (ExitInterruptionInfo)
		{
		case 0x80000300: //div by 0
			break;

		case 0x80000301: //int1 bp
			break;
			
		case 0x80000307: //fp exception
			break;

		case 0x80000b0e: //pagefault
			break;

		case 0x80000603: // int 3
			SetBreakPointEx();
			//if (vmread(vmread(vm_idtvector_information))==0)

			break;

		case 0x80000306: // #UD
			SetBreakPointEx();
			break;

		case 0x80000b0d: //GPF
		  //check if it's a CS:RIP that we know and can skip (for dosmode)
			break;

		}
	}
	case 8: // NMI window
		break;
	case 10: // CPUID
		VMMcpuidHandler(pGuestRegs);
		break;
	case 13: // execute INVD ����ʹ����������ʧЧ
	{
		__wbinvd();
		break;
	}
	
	case 18: // VMCALL
	{
		VMMvmcallHandler(pGuestRegs);
		
	}
		break;
	case 28: // CR access
		VMMaccessCrHandler(pGuestRegs);
		break;
	case 31: // RDMSR
		// SetBreakPointEx();
		VMMrdmsrHandler(pGuestRegs);
		break;
	case 32: // WRMSR
		// SetBreakPointEx();
		VMMwrmsrHandler(pGuestRegs);
		break;
	case 55: // xsetbv
		VMMxsetbvHandler(pGuestRegs);
		break;
	case 19: // vmclear
	case 20: // vmlaunch
	case 21: // vmptrld
	case 22: // vmptrst
	case 23: // vmread
	case 24: // vmresume
	case 25: // vmwrite
	case 26: // vmxoff
	case 27: // vmxon
	{
		RFLAGS RFlags = { 0 };
		RFlags.AsUInt = GuestRflags;
		RFlags.CarryFlag = 1;
		RFlags.ZeroFlag = 1;
		GuestRflags = RFlags.AsUInt;
		break;
	}

	default:
	{
		DbgPrintEx(0, 0, "vm_exit_reason: 0x%llx\nvm_exit_instructionlength: %lld\nvm_guest_rsp: 0x%llx\nvm_guest_rip: 0x%llx\nvm_guest_rflags: 0x%llx\n", ExitReason, ExitInstructionLength, GuestRsp, GuestRip, GuestRflags);

		SetBreakPointEx();
	}
		break;
	}

	if (vmState[cpunr()].bVMXONSuccess == FALSE) {
		return &restoreRegister[cpunr()];
	}

	// DbgPrintEx(0, 0, "------Test------\nvm_exit_reason: 0x%llx\nvm_exit_instructionlength: %lld\nvm_guest_rsp: 0x%llx\nvm_guest_rip: 0x%llx\nvm_guest_rflags: 0x%llx\n------Test------\n", ExitReason, ExitInstructionLength, GuestRsp, GuestRip, GuestRflags);
	// SetBreakPointEx();
	GuestRip += ExitInstructionLength;

	UCHAR Ret = __vmx_vmwrite(vm_guest_rip, GuestRip);
	if (Ret != 0) {
		SetBreakPointEx();
	}

	Ret = __vmx_vmwrite(vm_guest_rsp, GuestRsp);
	if (Ret != 0) {
		SetBreakPointEx();
	}

	Ret = __vmx_vmwrite(vm_guest_rflags, GuestRflags);
	if (Ret != 0) {
		SetBreakPointEx();
	}

	

	return 0;
}