#include "EptHook.h"
#include "nmd_assembly.h"

EptHookInfo HidePageEntry = { 0 };

static int GetAsmCodeLen(PVOID buffer, int IgnoreLength)
{
#define MAX_ASM_CODE_LEN 90
    const char* const buffer_end = (char*)buffer + MAX_ASM_CODE_LEN;

    nmd_x86_instruction instruction;
    char formatted_instruction[128];

    for (size_t i = 0; i < MAX_ASM_CODE_LEN; i += instruction.length)
    {
        if (!nmd_decode_x86((char*)buffer + i, buffer_end - ((char*)buffer + i), &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_MINIMAL))
            break;
#pragma warning(push)
#pragma warning(disable:4245)
        nmd_format_x86(&instruction, formatted_instruction, NMD_X86_INVALID_RUNTIME_ADDRESS, NMD_X86_FORMAT_FLAGS_DEFAULT);
#pragma warning(pop)
        if (i >= IgnoreLength) return i;
    }

    return 0;
}

static PEptHookInfo GetHookInfoByVirtualAddr(PVOID Func)
{
    if (HidePageEntry.list.Flink == NULL || IsListEmpty(&HidePageEntry.list)) {
        return NULL;
    }

    for (PLIST_ENTRY pListEntry = HidePageEntry.list.Flink; pListEntry != &HidePageEntry.list; pListEntry = pListEntry->Flink)
    {
        PEptHookInfo pEntry = CONTAINING_RECORD(pListEntry, EptHookInfo, list);
        if (Func == pEntry->OriginalFunAddr && Func) {
            return pEntry;
        }
    }

    return NULL;
}

PVOID EptHook(PVOID TargetFunc, PVOID DetourFunc)
{
    PVOID OriginalFuncHeadCode = NULL64;

    UCHAR JmpFakeAddr[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// mov rax,0
                            0x50,  // push rax
                            0xC3}; // ret
    UCHAR JmpOriginalFun[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // jmp 0xFFFF`FFFF`FFFF`FFFF

    // 已经hook了
    if (GetHookInfoByVirtualAddr(TargetFunc) != NULL) {
        return NULL;
    }

    ((PUINT64)(JmpFakeAddr + 2))[0] = DetourFunc;
    
    // 跳回原函数
    UINT_PTR WriteLen = GetAsmCodeLen(TargetFunc, sizeof(JmpFakeAddr));
    UINT_PTR JmpOriginalAddr = (UINT64)TargetFunc + WriteLen;
    ((PUINT64)(JmpOriginalFun + 6))[0] = JmpOriginalAddr;

    // 复制原函数页面
    PBYTE fakePage = kmalloc(PAGE_SIZE);
    RtlCopyMemory(fakePage, (PVOID)((UINT64)TargetFunc & 0xFFFFFFFFFFFFF000), PAGE_SIZE);

    // 保存原函数被修改的代码以及跳回原函数
    PVOID OriginalFunHeadCode = kmalloc(WriteLen + 14);
    RtlFillMemory(OriginalFunHeadCode, WriteLen + 14, 0x90);
    RtlCopyMemory(OriginalFunHeadCode, (PVOID)TargetFunc, WriteLen);
    RtlCopyMemory((PCHAR)(OriginalFunHeadCode) + WriteLen, JmpOriginalFun, 14);

    // 配置用于执行的假页面
    UINT_PTR offset = (UINT64)TargetFunc - ((UINT64)TargetFunc & 0xFFFFFFFFFFFFF000);
    RtlFillMemory(fakePage + offset, WriteLen, 0x90);
    RtlCopyMemory(fakePage + offset, &JmpFakeAddr, 12);

    if (HidePageEntry.list.Flink == NULL) {
        InitializeListHead(&HidePageEntry.list);
    }

    // 填写HOOK信息
    PEptHookInfo hidePage = (PEptHookInfo)kmalloc(sizeof(EptHookInfo));
    hidePage->FakePageVaAddr = fakePage;
    hidePage->FakePagePhyAddr = MmGetPhysicalAddress((PVOID)fakePage).QuadPart & 0xFFFFFFFFFFFFF000;
    hidePage->RealPagePhyAddr = MmGetPhysicalAddress((PVOID)((UINT_PTR)TargetFunc & 0xFFFFFFFFFFFFF000)).QuadPart;
    hidePage->OriginalFunAddr = TargetFunc;
    hidePage->OriginalFunHeadCode = (ULONG_PTR)OriginalFunHeadCode;

    //插入链表
    InsertTailList(&HidePageEntry.list, &hidePage->list);

    DoVmCall('hook', (ULONG_PTR)hidePage, 0, 0);

    return OriginalFunHeadCode;
}
