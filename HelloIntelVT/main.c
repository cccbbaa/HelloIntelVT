#include "VTFunction.h"
#include "SSDT.h"
#include "EptHook.h"

HANDLE hThreadCreateVM;

typedef NTSTATUS(*pNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);


pNtOpenProcess OriginalNtOpenProcess = NULL;
int index = 0;

//代理函数
NTSTATUS MyNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
	if ((index % 100) == 0) {
		DbgPrintEx(0, 0, "HOOK NtOpenProcess 调用次数: %d\n", index);
	}
	index++;
	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}


VOID Unload(PDRIVER_OBJECT pDriver)
{
	VMXStop();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	pDriver->DriverUnload = Unload;

	if (GetCPUCount() > MAX_CPU_COUNT) {
		DbgPrintEx(0, 0, "Found Too Many CPU\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (VMXStart() == FALSE) {
		return STATUS_UNSUCCESSFUL;
	}

	/*if (VMMCreateForCurrentCPU() == FALSE) {
		VMXStop();
		SetBreakPointEx();
		return STATUS_UNSUCCESSFUL;
	}*/

	VMMCreate();

	LONG Index = AsdGetSSDTFunIndex("NtOpenProcess");
	DbgPrintEx(0, 0, "NtTerminateProcess Index: %d\n", Index);
	PVOID FuncAddr = (PVOID)FindSSDTFunctionByIndex(Index);
	DbgPrintEx(0, 0, "FuncAddr %p\n", FuncAddr);

	OriginalNtOpenProcess = (pNtOpenProcess)EptHook(FuncAddr, MyNtOpenProcess);

	return STATUS_SUCCESS;
}