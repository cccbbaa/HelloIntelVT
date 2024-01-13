#include "HelpFunction.h"
#include "vmWriteReadHelper.h"

ULONG GetCPUCount()
{
	ULONG cpucount = 0;
	KAFFINITY cpus = KeQueryActiveProcessors();

	while (cpus)
	{
		if (cpus % 2)
		{
			cpucount++;
		}

		cpus >>= 1;
	}

	return cpucount;
}

BOOL GetSegmentDescriptor(PVOID pSegmentSelector, USHORT Selector, PUCHAR GdtBase)
{
	PSEGMENT_DESCRIPTOR SegDesc;
	PSEGMENT_SELECTORS SegmentSelector = (PSEGMENT_SELECTORS)pSegmentSelector;
	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4)
	{
		return FALSE;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10))
	{
		//
		// LA_ACCESSED
		//
		ULONG64 tmp;

		//
		// this is a TSS or callgate etc, save the base high part
		//
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G)
	{
		//
		// 4096-bit granularity is enabled for this segment, scale the limit
		//
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}

//void PrintRegsByCPURegs(CPURegs cpuRegs)
//{
//	DbgPrintEx(0,0,"cpuRegs.rax: %llx\n", cpuRegs.rax);
//	DbgPrintEx(0, 0, "cpuRegs.rbx: %llx\n", cpuRegs.rbx);
//	DbgPrintEx(0, 0, "cpuRegs.rcx: %llx\n", cpuRegs.rcx);
//	DbgPrintEx(0, 0, "cpuRegs.rdx: %llx\n", cpuRegs.rdx);
//	DbgPrintEx(0, 0, "cpuRegs.rsi: %llx\n", cpuRegs.rsi);
//	DbgPrintEx(0, 0, "cpuRegs.rdi: %llx\n", cpuRegs.rdi);
//	DbgPrintEx(0, 0, "cpuRegs.rbp: %llx\n", cpuRegs.rbp);
//	DbgPrintEx(0, 0, "cpuRegs.rsp: %llx\n", cpuRegs.rsp);
//	DbgPrintEx(0, 0, "cpuRegs.r8: %llx\n", cpuRegs.r8);
//	DbgPrintEx(0, 0, "cpuRegs.r9: %llx\n", cpuRegs.r9);
//	DbgPrintEx(0, 0, "cpuRegs.r10: %llx\n", cpuRegs.r10);
//	DbgPrintEx(0, 0, "cpuRegs.r11: %llx\n", cpuRegs.r11);
//	DbgPrintEx(0, 0, "cpuRegs.r12: %llx\n", cpuRegs.r12);
//	DbgPrintEx(0, 0, "cpuRegs.r13: %llx\n", cpuRegs.r13);
//	DbgPrintEx(0, 0, "cpuRegs.r14: %llx\n", cpuRegs.r14);
//	DbgPrintEx(0, 0, "cpuRegs.r15 : %llx\n", cpuRegs.r15);
//	DbgPrintEx(0, 0, "cpuRegs.rflags : %llx\n", cpuRegs.rflags);
//	DbgPrintEx(0, 0, "cpuRegs.gdtbase : %llx\n", cpuRegs.gdtbase);
//	DbgPrintEx(0, 0, "cpuRegs.gdtlimit : %hx\n", cpuRegs.gdtlimit);
//	DbgPrintEx(0, 0, "cpuRegs.cs : %hx\n", cpuRegs.cs);
//	DbgPrintEx(0, 0, "cpuRegs.ss : %hx\n", cpuRegs.ss);
//	DbgPrintEx(0, 0, "cpuRegs.ds : %hx\n", cpuRegs.ds);
//	DbgPrintEx(0, 0, "cpuRegs.es : %hx\n", cpuRegs.es);
//	DbgPrintEx(0, 0, "cpuRegs.fs : %hx\n", cpuRegs.fs);
//	DbgPrintEx(0, 0, "cpuRegs.gs : %hx\n", cpuRegs.gs);
//}

UINT64 FindSystemDirectoryTableBase()
{
    //
        // Return CR3 of the system process.
        //
    NT_KPROCESS* SystemProcess = (NT_KPROCESS*)(PsInitialSystemProcess);
    return SystemProcess->DirectoryTableBase;
}

VOID VmxFillGuestSelectorData(ULONG SegmentRegister, USHORT Selector)
{
    SEGMENT_SELECTORS SegmentSelector = { 0 };
    ULONG            AccessRights;
    PUCHAR GdtBase = (PUCHAR)getGDTbase();

    GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
    AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    __vmx_vmwrite((UINT64)vm_guest_es + (UINT64)SegmentRegister * 2ULL, Selector);
    __vmx_vmwrite((UINT64)vm_guest_es_limit + (UINT64)SegmentRegister * 2ULL, SegmentSelector.LIMIT);
    __vmx_vmwrite((UINT64)vm_guest_es_access_rights + (UINT64)SegmentRegister * 2ULL, AccessRights);
    __vmx_vmwrite((UINT64)vm_guest_es_base + (UINT64)SegmentRegister * 2ULL, SegmentSelector.BASE);
}

void ConvertGdtEntry(UINT64 GdtBase, UINT16 Selector, PVMX_GDTENTRY64 VmxGdtEntry)
{
    PKGDTENTRY64 gdtEntry;

    //
    // Reject LDT or NULL entries
    //
    if ((Selector == 0) ||
        (Selector & SELECTOR_TABLE_INDEX) != 0)
    {
        VmxGdtEntry->Limit = VmxGdtEntry->AccessRights = 0;
        VmxGdtEntry->Base = 0;
        VmxGdtEntry->Selector = 0;
        VmxGdtEntry->Bits.Unusable = TRUE;
        return;
    }

    //
    // Read the GDT entry at the given selector, masking out the RPL bits.
    //
    gdtEntry = (PKGDTENTRY64)((uintptr_t)GdtBase + (Selector & ~RPL_MASK));

    //
    // Write the selector directly 
    //
    VmxGdtEntry->Selector = Selector;

    //
    // Use the LSL intrinsic to read the segment limit
    //
    VmxGdtEntry->Limit = __segmentlimit(Selector);

    //
    // Build the full 64-bit effective address, keeping in mind that only when
    // the System bit is unset, should this be done.
    //
    // NOTE: The Windows definition of KGDTENTRY64 is WRONG. The "System" field
    // is incorrectly defined at the position of where the AVL bit should be.
    // The actual location of the SYSTEM bit is encoded as the highest bit in
    // the "Type" field.
    //
    VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) |
        (gdtEntry->Bytes.BaseMiddle << 16) |
        (gdtEntry->BaseLow)) & 0xFFFFFFFF;
    VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ?
        ((uintptr_t)gdtEntry->BaseUpper << 32) : 0;

    //
    // Load the access rights
    //
    VmxGdtEntry->AccessRights = 0;
    VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
    VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;

    //
    // Finally, handle the VMX-specific bits
    //
    VmxGdtEntry->Bits.Reserved = 0;
    VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}

ULONG VmxAdjustControls(ULONG Ctl, ULONG Msr)
{
    LARGE_INTEGER MsrValue = { 0 };
    MsrValue.QuadPart = __readmsr(Msr);
    Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}

BOOLEAN EnterCriticalSection(pCriticalSection CS, UINT64 TimeOut)
{
    int apicid = cpunr() + 1;

    if ((CS->locked) && (CS->apicid == apicid))
    {
        // 这个CPU已经持有锁了，把持有计数加1
        CS->lockcount++;
        return TRUE;
    }
    
    int ret = spinlock(&(CS->locked), TimeOut);
    if (ret == 0) {
        return FALSE;
    }

    _ReadWriteBarrier();

    CS->lockcount = 1;
    CS->apicid = apicid;
    return TRUE;
}

BOOLEAN LeaveCriticalSection(pCriticalSection CS)
{

    int apicid = cpunr() + 1;
    int locked = CS->locked;
    int ownerAPICID = CS->apicid;
    
    if ((CS->locked) && (CS->apicid == apicid))
    {
        _ReadWriteBarrier();
        CS->lockcount--;
        _ReadWriteBarrier();
        if (CS->lockcount == 0)
        {
            CS->apicid = -1;
            _ReadWriteBarrier();
            CS->locked = 0;
            _ReadWriteBarrier();
        }
        return TRUE;
    }

    return FALSE;
}

INT GetPhysicalMemoryGigaBytes()
{
    PPHYSICAL_MEMORY_RANGE MemoryRanges = MmGetPhysicalMemoryRanges();
    if (!MemoryRanges)
    {
        // DbgPrint("Failed to get physical memory ranges\n");
        return 0;
    }

    PHYSICAL_ADDRESS TotalMemory = { 0 };
    for (PPHYSICAL_MEMORY_RANGE CurrentRange = MemoryRanges; CurrentRange->NumberOfBytes.QuadPart != 0; CurrentRange++)
    {
        TotalMemory.QuadPart += CurrentRange->NumberOfBytes.QuadPart;
    }

    if (TotalMemory.QuadPart == 0) {
        return 0;
    }

    ExFreePool(MemoryRanges);
    UINT result = (TotalMemory.QuadPart % 0x40000000) > 0 ? (TotalMemory.QuadPart / 0x40000000) + 1 : (TotalMemory.QuadPart / 0x40000000);

    return result;
}
