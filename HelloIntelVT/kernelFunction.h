#pragma once
#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

inline int cpunr(void)
{
	int x[4];
	__cpuid(&x[0], 1);

	return (x[1] >> 24);
}

extern WORD getCS(void);
extern WORD getSS(void);
extern WORD getDS(void);
extern WORD getES(void);
extern WORD getFS(void);
extern WORD getGS(void);
extern WORD getLdtr(void);
extern WORD getTR(void);
extern WORD getGDTlimit(void);
extern UINT64 getGDTbase(void);
extern UINT64 getIDTbase(void);
extern void SetBreakPointEx(void);
extern void Vmx_VmResume(void);
extern void DoVmCall(void);
extern void AsmCreateVMM(void);
// 超时单位为CPU时钟周期，比如3GHz的CPU单位就是0.33纳秒
// 设置为0即为不会超时
extern int spinlock(int* lockvar, unsigned long long timeout); 