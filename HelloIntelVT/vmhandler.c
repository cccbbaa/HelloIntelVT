#include "vmhandler.h"
#include "vmWriteReadHelper.h"

#include "HelpFunction.h"
#include "msrname.h"
#include "VTFunction.h"

#include "EptHook.h"

Register restoreRegister[MAX_CPU_COUNT] = { 0 };
speedHackInfor sphInfor = { 0 };

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

	if (function_id == 1) { // 告诉Guest不支持虚拟化
		cpuInfo[2] &= (~0b100000);
	}

	GuestRegs->rax = cpuInfo[0];
	GuestRegs->rbx = cpuInfo[1];
	GuestRegs->rcx = cpuInfo[2];
	GuestRegs->rdx = cpuInfo[3];

}

static void VMMrdtscHandler(PGUEST_REGS GuestRegs)
{
	UINT64 realtime = __rdtsc();
}

static void VMMrdmsrHandler(PGUEST_REGS GuestRegs)
{
	LARGE_INTEGER Msr = { 0 };
	ULONG Register = GuestRegs->rcx & 0xffffffff;

	if (Register == 0x3A) // 虚拟化之后如果Guest要读0x3A获取是否支持虚拟化就告诉Guest不支持虚拟化
	{
		Msr.QuadPart = __readmsr(0x3A);
		Msr.QuadPart &= (~0b1);
	}
	else {
		Msr.QuadPart = __readmsr(Register);
	}

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

static UCHAR VMMinvvpid(UINT32 Type, UINT16 Vpid, UINT64 LinearAddress)
{
	UCHAR Result = 0;
	INVVPID_DESCRIPTOR Descriptor = { 0 };
	Descriptor.LinearAddress = LinearAddress;
	Descriptor.Vpid = Vpid;

	switch (Type)
	{
	case InvvpidIndividualAddress:
	{
		Result = __invvpid(Type, &Descriptor);
		break;
	}
	case InvvpidSingleContext:
	{
		Descriptor.LinearAddress = 0;
		Result = __invvpid(Type, &Descriptor);
		break;
	}
	case InvvpidAllContext:
	{
		Result = __invvpid(Type, NULL);
		break;
	}
	case InvvpidSingleContextRetainingGlobals:
	{
		Descriptor.LinearAddress = 0;
		Result = __invvpid(Type, NULL);
		break;
	}
	}
	return Result;
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
		    // 由于使用了VPID标签而失效，因此vm-exit不会正常（自动）刷新tlb，我们必须手动执行
		    //
			// 调用使单个Vpid失效 因为我们设置默认VPID为1了
			VMMinvvpid(InvvpidSingleContext, 1, 0);

			
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
			_CR4 cr4Value = { 0 };
			__vmx_vmread(vm_guest_cr4, &(cr4Value.Value));
			cr4Value.VMXE = 0;

			*RegisterPtr = cr4Value.Value;
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

static void VMMteardown(PGUEST_REGS GuestRegs, ULONG64 ProcessorID)
{
	//获取GUEST CR3 设置成当前CR3
	ULONG64 GuestCr3 = 0;
	__vmx_vmread(vm_guest_cr3, &GuestCr3);
	__writecr3(GuestCr3);

	//获取GUESTRSP和GUESTRIP 
	ULONG64 ExitInstructionLength = 0;
	__vmx_vmread(vm_guest_rip, &restoreRegister[ProcessorID].rip);
	__vmx_vmread(vm_guest_rsp, &restoreRegister[ProcessorID].rsp);
	__vmx_vmread(vm_guest_rflags, &restoreRegister[ProcessorID].rflags);
	__vmx_vmread(vm_exit_instructionlength, &ExitInstructionLength);
	restoreRegister[ProcessorID].rip += ExitInstructionLength;

	// 获取通用寄存器
	{
		restoreRegister[ProcessorID].rcx = GuestRegs->rcx;
		restoreRegister[ProcessorID].rdx = GuestRegs->rdx;
		restoreRegister[ProcessorID].rbx = GuestRegs->rbx;
		restoreRegister[ProcessorID].rbp = GuestRegs->rbp;
		restoreRegister[ProcessorID].rsi = GuestRegs->rsi;
		restoreRegister[ProcessorID].rdi = GuestRegs->rdi;
		restoreRegister[ProcessorID].r8 = GuestRegs->r8;
		restoreRegister[ProcessorID].r9 = GuestRegs->r9;
		restoreRegister[ProcessorID].r10 = GuestRegs->r10;
		restoreRegister[ProcessorID].r11 = GuestRegs->r11;
		restoreRegister[ProcessorID].r12 = GuestRegs->r12;
		restoreRegister[ProcessorID].r13 = GuestRegs->r13;
		restoreRegister[ProcessorID].r14 = GuestRegs->r14;
		restoreRegister[ProcessorID].r15 = GuestRegs->r15;
	}

	//获取GUEST里FS GS CS DS ES IDT GDT 寄存器 并赋值给当前host  
	{
		ULONG64 FsBase = 0;
		__vmx_vmread(vm_guest_fs_base, &FsBase);
		__writemsr(IA32_FS_BASE_MSR, FsBase);

		ULONG64 Fs = 0;
		__vmx_vmread(vm_guest_fs, &Fs);
		restoreRegister[ProcessorID].fs = Fs & 0xffff;
	}

	{
		ULONG64 gsBase = 0;
		__vmx_vmread(vm_guest_gs_base, &gsBase);
		__writemsr(IA32_GS_BASE_MSR, gsBase);

		ULONG64 gs = 0;
		__vmx_vmread(vm_guest_fs, &gs);
		restoreRegister[ProcessorID].gs = gs & 0xffff;
	}

	{

		ULONG64 cs = 0;
		__vmx_vmread(vm_guest_cs, &cs);
		restoreRegister[ProcessorID].cs = cs & 0xffff;
	}

	{

		ULONG64 ds = 0;
		__vmx_vmread(vm_guest_ds, &ds);
		restoreRegister[ProcessorID].ds = ds & 0xffff;
	}

	{

		ULONG64 ss = 0;
		__vmx_vmread(vm_guest_ss, &ss);
		restoreRegister[ProcessorID].ss = ss & 0xffff;
	}

	{

		ULONG64 es = 0;
		__vmx_vmread(vm_guest_es, &es);
		restoreRegister[ProcessorID].es = es & 0xffff;
	}

	ULONG64 IdtBase, Idtlimit;
	__vmx_vmread(vm_guest_idtr_base, &IdtBase);
	__vmx_vmread(vm_guest_idt_limit, &Idtlimit);
	reloadIdtr((PVOID)IdtBase, Idtlimit & 0xffffffff);

	ULONG64 GdtBase, GdtLimit;
	__vmx_vmread(vm_guest_gdtr_base, &GdtBase);
	__vmx_vmread(vm_guest_gdt_limit, &GdtLimit);
	reloadGdtr((PVOID)GdtBase, GdtLimit & 0xffffffff);

	//调用VmxClear 并关闭虚拟机

	UCHAR Result = __vmx_vmclear((PUINT64) & (vmState[ProcessorID].pVMCSRegion_PA));

	//清理成功就调用VmOff并设置标志位
	if (Result == 0)
	{
		__vmx_off();

		vmState[ProcessorID].bVMLAUNCHSuccess = FALSE;
		vmState[ProcessorID].bVMXONSuccess = FALSE;

		//恢复Cr4
		CR4 Cr4 = { 0 };
		Cr4.AsUInt = __readcr4();
		Cr4.VmxEnable = 0;
		__writecr4(Cr4.AsUInt);

	}
}

static void VMMvmcallHandler(PGUEST_REGS GuestRegs)
{
	//获取当前逻辑处理器ID
	ULONG64 ProcessorID = cpunr();

	switch (GuestRegs->rcx)
	{
	case 'hook':
	{
		if (GuestRegs->r8 == 0 && GuestRegs->r9 == 0)
		{
			if ((__readmsr(IA32_VMX_EPT_VPID_CAP_MSR) % 2) == 0) { // 第0位为0则不支持EPT使用可执行但是不可读不可写的内存
				restoreRegister[ProcessorID].rax = STATUS_UNSUCCESSFUL;
				DbgPrintEx(0, 0, "this cpu not support only execute memory\n");
				return;
			}

			PEptHookInfo hookInfo = (PEptHookInfo)GuestRegs->rdx;

			DbgPrintEx(0, 0, "ept hook at [0x%llx]\nFakePageVaAddr: [0x%llx]\nFakePagePhyAddr: [0x%llx]\nRealPagePhyAddr: [0x%llx]\n",
				hookInfo->OriginalFunAddr, hookInfo->FakePageVaAddr, hookInfo->FakePagePhyAddr, hookInfo->RealPagePhyAddr);

			EptCommonEntry* pte = GetPteByPhyAddr(hookInfo->RealPagePhyAddr);
			if (pte) {
				DbgPrintEx(0, 0, "pte: %p\n", pte);
				pte->fields.physial_address = hookInfo->FakePagePhyAddr >> 12;
				pte->fields.execute_access = 1;
				pte->fields.read_access = 0;
				pte->fields.write_access = 0;
			}
			else {
				SetBreakPointEx();
			}

			restoreRegister[ProcessorID].rax = STATUS_SUCCESS;
			return;
		}
	}
		break;
	default:
		break;
	}

	UINT64 result = ((GuestRegs->rcx * GuestRegs->r8) ^ GuestRegs->rdx) + (GuestRegs->r9);

	// rcx 'czvt'
	// rdx 'vm'
	// r8 'off'
	// r9 cpunr() + 1
	if (result == (0x2b49e3ca491c55ULL + (cpunr() + 1ULL))) // vmoff
	{
		VMMteardown(GuestRegs, ProcessorID);
	}

	restoreRegister[ProcessorID].rax = STATUS_SUCCESS;

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

static void VMMeptViolationHandler(UINT64 GuestRip)
{
	//获取触发EptViolation的物理地址
	ULONG_PTR GuestPhyAddr = 0;
	ExitQualificationEpt ExitQualification = { 0 };

	__vmx_vmread(vm_guest_physical_address, &GuestPhyAddr);
	__vmx_vmread(vm_exit_qualification, &(ExitQualification.flags));

	PEptHookInfo hookInfo = GetHookInfoByPA(GuestPhyAddr);

	if (!hookInfo) {
		hookInfo = GetHookInfoByVA(GuestRip);
	}

	if (hookInfo)
	{
		EptCommonEntry* pte = GetPteByPhyAddr(GuestPhyAddr);

		DbgPrintEx(0, 0, "-----------------------------------\nEptViolation at virtual address %llx\nEptViolation at physical address %llx\nFakePagePhyAddr: %llx\nFakePageVaAddr: %llx\nOriginalFunAddr: %llx\nOriginalFunHeadCode: %llx\nRealPagePhyAddr: %llx\nexecute_access: %lld\n",
			GuestRip, GuestPhyAddr, hookInfo->FakePagePhyAddr, hookInfo->FakePageVaAddr, hookInfo->OriginalFunAddr, hookInfo->OriginalFunHeadCode, hookInfo->RealPagePhyAddr, pte->fields.execute_access);

		DbgPrintEx(0, 0,
			"data_read: %lld\n"
			"data_write: %lld\n"
			"data_execute: %lld\n"
			"entry_read: %lld\n"
			"entry_write: %lld\n"
			"entry_execute: %lld\n"
			"entry_execute_for_user_mode: %lld\n"
			"valid_guest_linear_address: %lld\n"
			"ept_translated_access: %lld\n"
			"user_mode_linear_address: %lld\n"
			"readable_writable_page: %lld\n"
			"execute_disable_page: %lld\n"
			"nmi_unblocking: %lld\n",
			ExitQualification.data_read,
			ExitQualification.data_write,
			ExitQualification.data_execute,
			ExitQualification.entry_read,
			ExitQualification.entry_write,
			ExitQualification.entry_execute,
			ExitQualification.entry_execute_for_user_mode,
			ExitQualification.valid_guest_linear_address,
			ExitQualification.ept_translated_access,
			ExitQualification.user_mode_linear_address,
			ExitQualification.readable_writable_page,
			ExitQualification.execute_disable_page,
			ExitQualification.nmi_unblocking);
		DbgPrintEx(0, 0, "-----------------------------------\n");

		/*if (ExitQualification.data_read || ExitQualification.data_write) {
			SetBreakPointEx();
		}*/
		

		//如果触发EptViolation时，当前页是能执行，而这里只有两种情况，要么能执行不能读写，要么能读写不能执行
		//能执行说明它是读或写只能执行的页面而触发了EptViolation，让它读写原函数页
		if (pte->fields.execute_access && (ExitQualification.data_read || ExitQualification.data_write)) {
			pte->fields.execute_access = 0;
			pte->fields.read_access = 1;
			pte->fields.write_access = 1;
			pte->fields.physial_address = hookInfo->RealPagePhyAddr >> 12;
		}
		else {
			//如果触发EptViolation时，当前页是可读可写，说明它是执行触发了EptViolation，让它执行HOOK函数页
			pte->fields.execute_access = 1;
			pte->fields.read_access = 0;
			pte->fields.write_access = 0;
			pte->fields.physial_address = hookInfo->FakePagePhyAddr >> 12;
		}

	}
	else {
		SetBreakPointEx();
	}
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
	case 2: // TripleFault 三重错误
		DbgPrintEx(0, 0, "TripleFault at 0x%llx\n", GuestRip);
		SetBreakPointEx();
		break;
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
	case 16: // rdtsc 可以用来做变速
	{
		VMMrdtscHandler(pGuestRegs);
	}
		break;
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
	case 48: // EptViolation
		VMMeptViolationHandler(GuestRip);
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
	if (ExitReason != 48) {
		GuestRip += ExitInstructionLength;
	}

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
