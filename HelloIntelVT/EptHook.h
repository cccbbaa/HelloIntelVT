#pragma once
#include "HelpFunction.h"

PVOID EptHook(PVOID TargetFunc, PVOID DetourFunc);

PEptHookInfo GetHookInfoByPA(ULONG_PTR physAddr);

PEptHookInfo GetHookInfoByVA(ULONG_PTR vaAddr);