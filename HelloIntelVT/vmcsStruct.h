#pragma once
#include <windef.h>

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x4000
{
	UINT Value;
	struct {
		UINT ExternalInterruptExiting : 1; // Ϊ1�Ļ��ⲿ�жϻᵼ�� VM exit �����ͨ��guest��IDT��������
		UINT Reserved0 : 2;
		UINT NMIexiting : 1; // Ϊ1�Ļ� NMI �ᵼ�� VM exit �����ͨ��IDT�е�������2��������
		UINT Reserved1 : 1;
		UINT VirtualNMIs : 1; // Ϊ1ʱ NMI ��Զ���ᱻ����
		UINT VMXpreemptionTimer : 1; // Ϊ1ʱVMX ��ռ��ʱ���� VMX �Ǹ������е���ʱ������ʱ������ʱ����ʱ���� VM exits
		UINT ProcessPostedInterrupts : 1; // Ϊ1ʱCPU���⴦����з����ж�֪ͨ�������жϣ��������� APIC ҳ���Է����ж�����
		UINT Reserved2 : 24;
	};
}PinBasedVMEC;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x4002
{
    UINT Value;
    struct {
        UINT Reserved0 : 2;            // λ 0-1 ����
        UINT InterruptWindowExiting : 1; // λ 2: Ϊ1ʱ���� RFLAGS.IF=1 ��û�������ж�����ʱ���κ�ָ��Ŀ�ʼ���ᵼ�� VM exit
        UINT UseTSCOffsetting : 1;    // λ 3: ���� RDTSC, RDTSCP, �Լ���ȡ IA32_TIME_STAMP_COUNTER MSR �� RDMSR ִ���Ƿ񷵻��� TSC ƫ���ֶ��޸ĵ�ֵ
        UINT Reserved1 : 3;            // λ 4-6 ����
        UINT HLTExiting : 1;           // λ 7: ���� HLT ִ���Ƿ��� VM exit
        UINT Reserved2 : 1;            // λ 8 ����
        UINT INVLPGExiting : 1;        // λ 9: ���� INVLPG ִ���Ƿ��� VM exit
        UINT MWAITExiting : 1;         // λ 10: ���� MWAIT ִ���Ƿ��� VM exit
        UINT RDPMCExiting : 1;         // λ 11: ���� RDPMC ִ���Ƿ��� VM exit
        UINT RDTSCExiting : 1;         // λ 12: ���� RDTSC �� RDTSCP ִ���Ƿ��� VM exit
        UINT Reserved3 : 2;            // λ 13-14 ����
        UINT CR3LoadExiting : 1;       // λ 15: �� CR3-target ���ƽ�ϣ������� CR3 �� MOV �����Ƿ��� VM exit
        UINT CR3StoreExiting : 1;      // λ 16: ������ CR3 �� MOV �洢�Ƿ��� VM exit
        UINT Reserved4 : 2;            // λ 17-18 ����
        UINT CR8LoadExiting : 1;       // λ 19: ������ CR8 �� MOV �����Ƿ��� VM exit
        UINT CR8StoreExiting : 1;      // λ 20: ������ CR8 �� MOV �洢�Ƿ��� VM exit
        UINT UseTPRShadow : 1;         // λ 21: ����Ϊ1ʱ���� TPR ���⻯������ APIC-���⻯����
        UINT NMIWindowExiting : 1;     // λ 22: Ϊ1ʱ�����û������-NMI �������κ�ָ��Ŀ�ʼ���ᵼ�� VM exit
        UINT MOVDrExiting : 1;         // λ 23: ���� MOV DR ִ���Ƿ��� VM exit
        UINT UnconditionalIOExiting : 1;// λ 24: ���� I/O ָ��ִ���Ƿ��� VM exit
        UINT UseIOBitmaps : 1;         // λ 25: �����Ƿ�ʹ�� I/O λͼ������ I/O ָ���ִ��
        UINT Reserved5 : 1;            // λ 26 ����
        UINT MonitorTrapFlag : 1;      // λ 27: Ϊ1ʱ�����ü����������־��������
        UINT UseMSRBitmaps : 1;        // λ 28: �����Ƿ�ʹ�� MSR λͼ������ RDMSR �� WRMSR ָ���ִ��
        UINT MONITORExiting : 1;       // λ 29: ���� MONITOR ִ���Ƿ��� VM exit
        UINT PAUSEExiting : 1;         // λ 30: ���� PAUSE ִ���Ƿ��� VM exit
        UINT ActivateSecondaryControls : 1;// λ 31: �����Ƿ�ʹ�ôμ������������� VM ִ�п���
    };
} PrimaryProcessorBasedVMEC;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x400C
{
    UINT32 Value;
    struct {
        UINT32 Reserved0 : 2;            // λ 0-1 ����
        UINT32 SaveDebugControls : 1;    // λ 2: ������ VM �˳�ʱ�Ƿ񱣴� DR7 �� IA32_DEBUGCTL MSR
        UINT32 Reserved1 : 6;            // λ 3-8 ����
        UINT32 HostAddressSpaceSize : 1; // λ 9: ������һ�� VM �˳����߼��������Ƿ��� 64 λģʽ
        UINT32 Reserved2 : 2;            // λ 10-11 ����
        UINT32 LoadIA32PerfGlobalCtrl : 1;// λ 12: ���� IA32_PERF_GLOBAL_CTRL MSR �� VM �˳�ʱ�Ƿ����
        UINT32 Reserved3 : 2;            // λ 13-14 ����
        UINT32 AcknowledgeInterruptOnExit : 1;// λ 15: �����Ƿ��������ⲿ�жϵ� VM �˳�ʱȷ���жϿ�����
        UINT32 Reserved4 : 2;            // λ 16-17 ����
        UINT32 SaveIA32PAT : 1;          // λ 18: ���� IA32_PAT MSR �� VM �˳�ʱ�Ƿ񱣴�
        UINT32 LoadIA32PAT : 1;          // λ 19: ���� IA32_PAT MSR �� VM �˳�ʱ�Ƿ����
        UINT32 SaveIA32EFER : 1;         // λ 20: ���� IA32_EFER MSR �� VM �˳�ʱ�Ƿ񱣴�
        UINT32 LoadIA32EFER : 1;         // λ 21: ���� IA32_EFER MSR �� VM �˳�ʱ�Ƿ����
        UINT32 SaveVMXPreemptionTimerValue : 1; // λ 22: ���� VMX ��ռ��ʱ��ֵ�� VM �˳�ʱ�Ƿ񱣴�
        UINT32 ClearIA32BNDCFGS : 1;     // λ 23: ���� IA32_BNDCFGS MSR �� VM �˳�ʱ�Ƿ����
        UINT32 ConcealVMXFromPT : 1;     // λ 24: ����˿���λΪ 1, Intel Processor Trace �� VM �˳�ʱ������ PIP �� VMCS ��
        UINT32 ClearIA32RTITCTL : 1;     // λ 25: ���� IA32_RTIT_CTL MSR �� VM �˳�ʱ�Ƿ����
        UINT32 ClearIA32LBRCTL : 1;      // λ 26: ���� IA32_LBR_CTL MSR �� VM �˳�ʱ�Ƿ����
        UINT32 Reserved5 : 1;            // λ 27 ����
        UINT32 LoadCETState : 1;         // λ 28: ������ VM �˳�ʱ�Ƿ���� CET ��ص� MSR �� SPP
        UINT32 LoadPKRS : 1;             // λ 29: ���� IA32_PKRS MSR �� VM �˳�ʱ�Ƿ����
        UINT32 SaveIA32PerfGlobalCtrl : 1;// λ 30: ���� IA32_PERF_GLOBAL_CTL MSR �� VM �˳�ʱ�Ƿ񱣴�
        UINT32 ActivateSecondaryControls : 1;// λ 31: �����Ƿ�ʹ�ôμ� VM-�˳�����
    };
} PrimaryVMEC;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x4012
{
    UINT32 Value;
    struct {
        UINT32 Reserved0 : 2;                // λ 0-1 ����
        UINT32 LoadDebugControls : 1;        // λ 2: ������ VM ����ʱ�Ƿ���� DR7 �� IA32_DEBUGCTL MSR
        UINT32 Reserved1 : 6;                // λ 3-8 ����
        UINT32 IA32eModeGuest : 1;           // λ 9: ���� VM ������߼��������Ƿ��� IA-32e ģʽ
        UINT32 EntryToSMM : 1;               // λ 10: ���� VM ������߼��������Ƿ��� SMM
        UINT32 DeactivateDualMonitorTreatment : 1; // λ 11: ������ VM ������Ƿ�ͣ��˫��ش���
        UINT32 Reserved2 : 1;                // λ 12 ����
        UINT32 LoadIA32PerfGlobalCtrl : 1;   // λ 13: ������ VM ����ʱ�Ƿ���� IA32_PERF_GLOBAL_CTRL MSR
        UINT32 LoadIA32PAT : 1;              // λ 14: ������ VM ����ʱ�Ƿ���� IA32_PAT MSR
        UINT32 LoadIA32EFER : 1;             // λ 15: ������ VM ����ʱ�Ƿ���� IA32_EFER MSR
        UINT32 LoadIA32BNDCFGS : 1;          // λ 16: ������ VM ����ʱ�Ƿ���� IA32_BNDCFGS MSR
        UINT32 ConcealVMXFromPT : 1;         // λ 17: ������ VM ����ʱ�Ƿ����� VMX �� PT
        UINT32 LoadIA32RTITCTL : 1;          // λ 18: ������ VM ����ʱ�Ƿ���� IA32_RTIT_CTL MSR
        UINT32 Reserved3 : 1;                // λ 19 ����
        UINT32 LoadCETState : 1;             // λ 20: ������ VM ����ʱ�Ƿ���� CET ״̬
        UINT32 LoadGuestIA32LBRCTL : 1;      // λ 21: ������ VM ����ʱ�Ƿ���� IA32_LBR_CTL MSR
        UINT32 LoadPKRS : 1;                 // λ 22: ������ VM ����ʱ�Ƿ���� IA32_PKRS MSR
        UINT32 Reserved4 : 9;                // λ 23-31 ����
    };
} VMEntryControls;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef union VMCS0x401E
{
    UINT32 Value;
    struct {
        UINT32 VirtualizeAPICAccesses : 1;  // λ 0: ����˿���λΪ 1�����߼����������⴦��Ծ��� APIC-access ��ַ��ҳ��ķ���
        UINT32 EnableEPT : 1;               // λ 1: ����˿���λΪ 1����������չҳ�� (EPT)
        UINT32 DescriptorTableExiting : 1;  // λ 2: �����Ƿ��� LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT �� STR ��ִ�е��� VM �˳�
        UINT32 EnableRDTSCP : 1;            // λ 3: ����˿���λΪ 0�����κ�ִ�� RDTSCP �Ĳ������ᵼ�� #UD
        UINT32 VirtualizeX2APICMode : 1;    // λ 4: ����˿���λΪ 1�����߼����������⴦��� APIC MSR �� RDMSR �� WRMSR
        UINT32 EnableVPID : 1;              // λ 5: ����˿���λΪ 1�����������⴦������ʶ�� (VPID)
        UINT32 WBINVDExiting : 1;           // λ 6: �����Ƿ��� WBINVD �� WBNOINVD ��ִ�е��� VM �˳�
        UINT32 UnrestrictedGuest : 1;       // λ 7: �����Ƿ�����ͻ������δ��ҳ�ı���ģʽ��ʵ��ַģʽ������
        UINT32 APICRegisterVirtualization : 1; // λ 8: ����˿���λΪ 1�����߼����������⻯ĳЩ APIC ����
        UINT32 VirtualInterruptDelivery : 1; // λ 9: ���ƶԹ��������жϵ������ͽ����Լ��Կ����ж����ȼ��� APIC �Ĵ����ķ���д��
        UINT32 PauseLoopExiting : 1;        // λ 10: ����һϵ�� PAUSE ��ִ���Ƿ���Ե��� VM �˳�
        UINT32 RDRANDExiting : 1;           // λ 11: �����Ƿ��� RDRAND ��ִ�е��� VM �˳�
        UINT32 EnableINVPCID : 1;           // λ 12: ����˿���λΪ 0�����κ�ִ�� INVPCID �Ĳ������ᵼ�� #UD
        UINT32 EnableVMFunctions : 1;       // λ 13: ���ô˿���λΪ 1 �� VMX �Ǹ�����������ʹ�� VMFUNC ָ��
        UINT32 VMCSShadowing : 1;           // λ 14: ����˿���λΪ 1���� VMX �Ǹ������е� VMREAD �� VMWRITE ���Է���Ӱ�� VMCS
        UINT32 EnableENCLSExiting : 1;      // λ 15: ����˿���λΪ 1���� ENCLS ��ִ�л��� ENCLS-exiting λͼ�������Ƿ��� VM �˳�
        UINT32 RDSEEDExiting : 1;           // λ 16: �����Ƿ��� RDSEED ��ִ�е��� VM �˳�
        UINT32 EnablePML : 1;               // λ 17: ����˿���λΪ 1����������� EPT ��λ�Ŀͻ������ַ�ķ������Ȼ����һ����Ŀ��ҳ���޸���־
        UINT32 EPTViolationVE : 1;          // λ 18: ����˿���λΪ 1���� EPT Υ����ܵ������⻯�쳣 (#VE) ������ VM �˳�
        UINT32 ConcealVMXFromPT : 1;        // λ 19: ����˿���λΪ 1���� Intel Processor Trace ���ƴ� PIP ��ָʾ���������� VMX �Ǹ�����
        UINT32 EnableXSAVESXRSTORS : 1;     // λ 20: ����˿���λΪ 0�����κ�ִ�� XSAVES �� XRSTORS �Ĳ������ᵼ�� #UD
        UINT32 Reserved0 : 1;               // λ 21 ����
        UINT32 ModeBasedExecuteControlForEPT : 1; // λ 22: ����˿���λΪ 1���� EPT ִ��Ȩ�޻��ڱ����ʵ����Ե�ַ���û�ģʽ���Ǽලģʽ
        UINT32 SubPageWritePermissionsForEPT : 1; // λ 23: ����˿���λΪ 1���� EPT дȨ�޿����� 128 �ֽڵ�����
        UINT32 IntelPTUsesGuestPhysicalAddresses : 1; // λ 24: ����˿���λΪ 1���� Intel Processor Trace ʹ�õ����������ַ����Ϊ�ͻ������ַ��ʹ�� EPT ת��
        UINT32 UseTSCScaling : 1;           // λ 25: ���� RDTSC, RDTSCP �Ͷ�ȡ IA32_TIME_STAMP_COUNTER MSR �� RDMSR ִ���Ƿ񷵻��� TSC �����ֶ��޸ĵ�ֵ
        UINT32 EnableUserWaitAndPause : 1;  // λ 26: ����˿���λΪ 0�����κ�ִ�� TPAUSE, UMONITOR �� UMWAIT �Ĳ������ᵼ�� #UD
        UINT32 EnablePCONFIG : 1;           // λ 27: ����˿���λΪ 0�����κ�ִ�� PCONFIG �Ĳ������ᵼ�� #UD
        UINT32 EnableENCLVExiting : 1;      // λ 28: ����˿���λΪ 1���� ENCLV ��ִ�л��� ENCLV-exiting λͼ�������Ƿ��� VM �˳�
        UINT32 Reserved1 : 3;               // λ 29-31 ����
    };
} SecondaryProcessorBasedVMEC;
#pragma pack(pop)

#pragma pack(push, 1)

typedef struct VirtualMachineState
{
#define VMMemoryTag 'czvm'
    PVOID pVMXRegion;
    PHYSICAL_ADDRESS pVMXRegion_PA;
    PVOID pVMCSRegion;
    PHYSICAL_ADDRESS pVMCSRegion_PA;
    BOOLEAN bVMLAUNCHSuccess;
    BOOLEAN bVMXONSuccess;
    PVOID pIOBitmapA;
    PVOID pIOBitmapB;
    PHYSICAL_ADDRESS pIOBitmapA_PA;
    PHYSICAL_ADDRESS pIOBitmapB_PA;
    PVOID pMSRBitmap;
    PHYSICAL_ADDRESS pMSRBitmap_PA;
    PVOID pHostVMStack;

}VMState, *pVMState;

#pragma pack(pop)

