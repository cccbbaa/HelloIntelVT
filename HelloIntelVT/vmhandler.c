#include "vmhandler.h"
#include "vmWriteReadHelper.h"
#include "HelpStruct.h"
#include "HelpFunction.h"
#include "msrname.h"

static void VMMcpuidHandler(PGUEST_REGS GuestRegs)
{
	if (GuestRegs->rax == 'CZVT')
	{
		GuestRegs->rbx = 0x88888888;
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
			//[63bit]  不允许修改
			*RegisterPtr &= ~(1ull << 63);
			__vmx_vmwrite(vm_guest_cr3, *RegisterPtr);

			//
		   // 由于我们使用了VPID标签而失效，因此vm-exit不会正常（自动）刷新tlb，我们必须手动执行
		   //
			// 调用使单个Vpid失效 因为我们设置默认VPID为1了
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
			DbgPrint("未处理的写 CR %lld 寄存器\n", Qualification.ControlRegister);
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
			DbgPrint("未处理的读 CR %lld 寄存器\n", Qualification.ControlRegister);
			SetBreakPointEx();
			break;
		}
		break;
	}
	default:
		DbgPrint("未处理的MovCr AccessType: %lld \n", Qualification.AccessType);
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

void VmxVmresume()
{
	__vmx_vmresume();

	//如果成功就不会到下面
	ULONG64 ErrorCode = 0;
	__vmx_vmread(vm_errorcode, &ErrorCode);
	__vmx_off();

	DbgPrint("Error Vmresume Code : %llx\n", ErrorCode);

	__debugbreak();
}

BOOL CVMMEntryPoint(PGUEST_REGS pGuestRegs)
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
	case 13: // execute INVD 可以使处理器缓存失效
	{
		__wbinvd();
		break;
	}
	
	case 18: // VMCALL
	{
		pGuestRegs->rax = STATUS_SUCCESS;
		DbgPrintEx(0, 0, "vm_exit_reason: 0x%llx\nvm_exit_instructionlength: %lld\nvm_guest_rsp: 0x%llx\nvm_guest_rip: 0x%llx\nvm_guest_rflags: 0x%llx\n", ExitReason, ExitInstructionLength, GuestRsp, GuestRip, GuestRflags);
		SetBreakPointEx();
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

	return TRUE;
}
