#pragma once
#include "kernelFunction.h"
#include "HelpStruct.h"

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID          Context);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2);

typedef VOID PREDPC_CALLBACK(int cpunr, PKDEFERRED_ROUTINE Dpc, PVOID DeferredContext, PVOID* SystemArgument1, PVOID* SystemArgument2);

typedef PREDPC_CALLBACK* PPREDPC_CALLBACK;

ULONG GetCPUCount();

BOOL GetSegmentDescriptor(PVOID pSegmentSelector, USHORT Selector, PUCHAR GdtBase);

// void PrintRegsByCPURegs(CPURegs cpuRegs);

UINT64 FindSystemDirectoryTableBase();

VOID VmxFillGuestSelectorData(ULONG SegmentRegister, USHORT Selector);

void ConvertGdtEntry(UINT64 GdtBase, UINT16 Selector, PVMX_GDTENTRY64 VmxGdtEntry);

/// <summary>
/// set 32-bit value by first 32 bits of readmsr value ANDed, and the last 32 bits ORed 
/// </summary>
/// <param name="Ctl">origin value</param>
/// <param name="Msr"></param>
/// <returns></returns>
ULONG VmxAdjustControls(ULONG Ctl, ULONG Msr);

BOOLEAN EnterCriticalSection(pCriticalSection CS, UINT64 TimeOut);

BOOLEAN LeaveCriticalSection(pCriticalSection CS);

// 获取物理内存大小，按GB大小返回(向上取整)
INT GetPhysicalMemoryGigaBytes();

PVOID kmalloc(ULONG_PTR size);

void kmDeAlloc();

// 通过物理地址获取对应的PTE
EptCommonEntry* GetPteByPhyAddr(ULONG_PTR addr);