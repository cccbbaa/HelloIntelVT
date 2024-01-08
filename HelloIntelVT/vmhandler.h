#pragma once
#include "kernelFunction.h"

extern void VMMEntryPoint();
extern void AsmVmxResState();

void VmxVmresume();

BOOL CVMMEntryPoint(PVOID pStack);