#pragma once
#include "kernelFunction.h"
#include "HelpStruct.h"

extern void VMMEntryPoint();
extern void AsmVmxResState();

void VmxVmresume();

PVOID CVMMEntryPoint(PGUEST_REGS pGuestRegs);