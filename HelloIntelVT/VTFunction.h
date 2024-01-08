#pragma once
#include "kernelFunction.h"

#define VM_STACK_SIZE   24 * 1024
#define MAX_CPU_COUNT	64

typedef union __CR0
{
	UINT64 Value;
	struct {
		UINT64 PE : 1;
		UINT64 MP : 1;
		UINT64 EM : 1;
		UINT64 TS : 1;
		UINT64 ET : 1;
		UINT64 NE : 1;
		UINT64 Reserved_1 : 10;
		UINT64 WP : 1;
		UINT64 Reserved_2 : 1;
		UINT64 AM : 1;
		UINT64 Reserved_3 : 10;
		UINT64 NW : 1;
		UINT64 CD : 1;
		UINT64 PG : 1;
		UINT64 Reserved_64 : 32;
	};
}_CR0;

typedef union
{
	UINT64 Value;
	struct {
		unsigned VME : 1;
		unsigned PVI : 1;
		unsigned TSD : 1;
		unsigned DE : 1;
		unsigned PSE : 1;
		unsigned PAE : 1;
		unsigned MCE : 1;
		unsigned PGE : 1;
		unsigned PCE : 1;
		unsigned OSFXSR : 1;
		unsigned PSXMMEXCPT : 1;
		unsigned UNKONOWN_1 : 1;		//These are zero
		unsigned UNKONOWN_2 : 1;		//These are zero
		unsigned VMXE : 1;			//It's zero in normal
		unsigned Reserved : 18;		//These are zero
		unsigned Reserved_64:32;
	};
}_CR4;

// should called by VTStart
BOOL CheckVTIsSupport();

// create virtual machine after VMXStart
BOOL CreateVirtualMachine(UINT64 guestStack);

// should called by CreateVirtualMachine
BOOL InitializeVMCS(int VMIndex, UINT64 guestStack);

BOOL VMMCreateForCurrentCPU();

void VMMCreateForCurrentCPU_DPC(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

void VMMCreate();

BOOL RemoveAllVM();
// Initialize VMX
BOOL VMXStart();
// Uninitialize VMX
BOOL VMXStop();

// this function shouldn't called, unless called by VMXStart
void VTStartForCurrentCPU_DPC(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
// this function shouldn't called, unless called by VMXStop
void VTStopForCurrentCPU_DPC(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

// make sure this function called by VTStartForCurrentCPU_DPC
// Every CPU needs to execute this function to ensure
// VT is enabled throughout the operating system
BOOL VTStart();
// make sure this function called by VTStopForCurrentCPU_DPC
// Every CPU needs to execute this function to ensure
// VT is stop throughout the operating system
void VTStop();