#include "SSDT.h"

PVOID AsdGetModuleExport(PVOID pBase, PCCHAR name_ord)

{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;
	PUSHORT pAddressOfOrds;
	PULONG pAddressOfNames;
	PULONG pAddressOfFuncs;
	ASSERT(pBase != NULL);
	if (pBase == NULL) {
		// DbgPrintEx(0, 0, "AsdGetModuleExport Failed 0\r\n");
		return NULL;
	}
	// 如果不是PE文件直接返回
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		// DbgPrintEx(0, 0, "AsdGetModuleExport Failed 1\r\n");
		return NULL;
	}
	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);
	// 如果不是PE文件直接返回
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE) {
		// DbgPrintEx(0, 0, "AsdGetModuleExport Failed 2\r\n");
		return NULL;
	}
	// 64位模块
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (UINT_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32位模块
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (UINT_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR pName = NULL;
		// 通过索引查找
		if ((ULONG_PTR)name_ord <= 0xFFFF) OrdIndex = (USHORT)i;
		// 通过名称查找
		else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		else {
			// DbgPrintEx(0, 0, "AsdGetModuleExport Failed 3\r\n");
			return NULL;
		}

		// DbgPrintEx(0, 0, "FuncName: [%s]\r\n", pName);

		if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

			if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize) {
				// DbgPrintEx(0, 0, "AsdGetModuleExport Failed 4\r\n");
				return NULL;
			}
			break;
		}
	}

	return (PVOID)pAddress;
}

PVOID AsdKLoadLibrary(const wchar_t* full_dll_path)

{
#define SEC_IMAGE_ASD 0x1000000
	HANDLE hSection = NULL, hFile = NULL;
	UNICODE_STRING dllName = { 0 };
	PVOID BaseAddress = NULL;
	SIZE_T size = 0;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &dllName, OBJ_CASE_INSENSITIVE };
	IO_STATUS_BLOCK iosb = { 0 };
	RtlInitUnicodeString(&dllName, full_dll_path);
	// 打开文件
	status = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) return 0;
	oa.ObjectName = 0;
	// 创建节对象
	status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_EXECUTE,
		SEC_IMAGE_ASD, hFile);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("CreateSection Error:%x", status);
		return 0;
	}
	// 将节对象映射到进程的虚拟地址中
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0,
		1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("MapSection Error:%x", status);
		return 0;
	}

	ZwClose(hSection);
	ZwClose(hFile);
	return BaseAddress;
}

ULONG AsdGetSSDTFunIndex(PCHAR FuncName)
{
	ULONG_PTR tempFuncAddr = 0;
	ULONG FuncAddrId = 0;
	PVOID ntdll = AsdKLoadLibrary(L"\\SystemRoot\\System32\\ntdll.dll");
	if (!ntdll) return 0;
	tempFuncAddr = (ULONG_PTR)AsdGetModuleExport(ntdll, FuncName);
	if (!tempFuncAddr) return 0;
	FuncAddrId = *(PULONG)((PUCHAR)tempFuncAddr + 4);

	ZwUnmapViewOfSection(NtCurrentProcess(), ntdll);
	return FuncAddrId;
}

UINT_PTR GetKernelModuleBase(PULONG pimagesize, PWCHAR modulename)
{
	ULONG_PTR uret = 0;
	UNICODE_STRING disk;
	RtlInitUnicodeString(&disk, L"\\Driver\\Disk");

	PDRIVER_OBJECT driver_object;
	NTSTATUS status = ObReferenceObjectByName(&disk, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (void**)&driver_object);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "ObReferenceObjectByName Failed status: %x\r\n", status);
		return uret;
	}

	UNICODE_STRING kernelName = { 0 };

	PLDR_DATA_TABLE_ENTRY64 pEntry = (PLDR_DATA_TABLE_ENTRY64)driver_object->DriverSection;
	PLDR_DATA_TABLE_ENTRY64 First = (PLDR_DATA_TABLE_ENTRY64)driver_object->DriverSection;
	RtlInitUnicodeString(&kernelName, modulename);
	__try {
		do {
			if (pEntry->BaseDllName.Buffer != NULL)
			{
				//DbgPrintEx(0, 0, "DirverName: <%wZ>  kernelName: <%wZ>\r\n", &pEntry->BaseDllName, &kernelName);

				if (RtlCompareUnicodeString(&pEntry->BaseDllName, &kernelName, TRUE) == 0)
				{
					uret = (ULONG_PTR)pEntry->DllBase;
					if (pimagesize) *pimagesize = pEntry->SizeOfImage;
					break;
				}
				pEntry = (PLDR_DATA_TABLE_ENTRY64)pEntry->InLoadOrderLinks.Flink;
			}
			else {
				break;
			}

		} while (pEntry != First);
		// PLDR_DATA_TABLE_ENTRY64 本应是一个双向循环链表，但是有时候会碰到PLDR_DATA_TABLE_ENTRY64 是一个双向不循环链表的情况
		if (!uret)
		{
			PLDR_DATA_TABLE_ENTRY64 pEntry = (PLDR_DATA_TABLE_ENTRY64)driver_object->DriverSection;
			PLDR_DATA_TABLE_ENTRY64 First = (PLDR_DATA_TABLE_ENTRY64)driver_object->DriverSection;
			do {
				if (pEntry->BaseDllName.Buffer != NULL)
				{
					//DbgPrintEx(0, 0, "DirverName: <%wZ>  kernelName: <%wZ>\r\n", &pEntry->BaseDllName, &kernelName);

					if (RtlCompareUnicodeString(&pEntry->BaseDllName, &kernelName, TRUE) == 0)
					{
						uret = (ULONG_PTR)pEntry->DllBase;
						if (pimagesize) *pimagesize = pEntry->SizeOfImage;
						break;
					}
					pEntry = (PLDR_DATA_TABLE_ENTRY64)pEntry->InLoadOrderLinks.Blink;
				}
				else {
					break;
				}

			} while (pEntry != First);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ObDereferenceObject(driver_object);
		return uret;
	}

	ObDereferenceObject(driver_object);
	return uret;
}

UINT_PTR FindSSDTFunctionByIndex(DWORD index)

{
	ULONG_PTR uret = 0;
	PUCHAR kernelbase = NULL;
	ULONG kernelSize = 0;
	kernelbase = (PUCHAR)GetKernelModuleBase(&kernelSize, L"ntoskrnl.exe");
	if (!kernelbase) {
		DbgPrintEx(0, 0, "GetKernelModuleBase Failed\r\n");
		return uret;
	}

	BYTE KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7,
	0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 }; // and edi,20h and eax, 0FFFh

	ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
	ULONG Offset = 0;
	BOOLEAN bFound = FALSE;

	for (; Offset < kernelSize - signatureSize; Offset++)
	{
		if (RtlCompareMemory((kernelbase + Offset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
		{
			bFound = TRUE;
			break;
		}
	}
	if (!bFound) return uret;
	PUCHAR address = kernelbase + Offset + signatureSize;
	LONG jmpoffset = 0;

	if ((*address == 0x4c) && (*(address + 1) == 0x8d) && (*(address + 2) == 0x15))
	{
		DbgPrintEx(0, 0, "Address: [%p]\r\n", address);
		jmpoffset = *(PLONG)(address + 3);
	}

	PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)(address + jmpoffset + 7);// 获取SSDT地址

	PULONG tablestart = KeServiceDescriptorTable->ServiceTableBase; // 先指向第一个函数
	ULONG TableOffset = (tablestart[index]) >> 4;  // 拿到偏移，具体算法通过源码得出
	UINT_PTR FuncAddr = TableOffset + (UINT_PTR)tablestart;
	return FuncAddr;
}
