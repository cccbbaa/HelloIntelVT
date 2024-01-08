#include "VTFunction.h"
#include "HelpFunction.h"

HANDLE hThreadCreateVM;

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
		return STATUS_UNSUCCESSFUL;
	}*/

	VMMCreate();

	// DoVmCall();

	return STATUS_SUCCESS;
}