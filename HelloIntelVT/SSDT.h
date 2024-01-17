#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <windef.h>

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID ServiceTableBase; //这个指向系统服务函数地址表

	PULONG ServiceCounterTableBase;

	ULONG NumberOfService; //服务函数的个数

	PULONG ParamTableBase;

}SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY64 HashLinks;
		struct _Unkown1 {
			ULONG64 SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		ULONG64 LoadedImports;
	};
}LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

NTSTATUS ObReferenceObjectByName(
	PUNICODE_STRING objectName,
	ULONG attributes,
	PACCESS_STATE accessState,
	ACCESS_MASK desiredAccess,
	POBJECT_TYPE objectType,
	KPROCESSOR_MODE accessMode,
	PVOID parseContext, PVOID* object);

extern POBJECT_TYPE* IoDriverObjectType;

PVOID AsdGetModuleExport(PVOID pBase, PCCHAR name_ord);

// 将某个文件映射到内存中
PVOID AsdKLoadLibrary(const wchar_t* full_dll_path);

ULONG AsdGetSSDTFunIndex(PCHAR FuncName);

UINT_PTR GetKernelModuleBase(PULONG pimagesize, PWCHAR modulename);

// 直接从ntoskrnl.exe通过字节码定位，几乎适用全系统
UINT_PTR FindSSDTFunctionByIndex(DWORD index);