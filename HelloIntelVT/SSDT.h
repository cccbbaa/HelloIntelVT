#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <windef.h>

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID ServiceTableBase; //���ָ��ϵͳ��������ַ��

	PULONG ServiceCounterTableBase;

	ULONG NumberOfService; //�������ĸ���

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

// ��ĳ���ļ�ӳ�䵽�ڴ���
PVOID AsdKLoadLibrary(const wchar_t* full_dll_path);

ULONG AsdGetSSDTFunIndex(PCHAR FuncName);

UINT_PTR GetKernelModuleBase(PULONG pimagesize, PWCHAR modulename);

// ֱ�Ӵ�ntoskrnl.exeͨ���ֽ��붨λ����������ȫϵͳ
UINT_PTR FindSSDTFunctionByIndex(DWORD index);