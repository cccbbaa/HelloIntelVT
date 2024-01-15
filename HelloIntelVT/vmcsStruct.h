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

#define SIZE_2M (0x1000 * 512)

/**
 * @defgroup MEMORY_TYPE \
 *           Memory caching type
 *
 * The processor allows any area of system memory to be cached in the L1, L2, and L3 caches. In individual pages or regions
 * of system memory, it allows the type of caching (also called memory type) to be specified.
 *
 * @see Vol3A[11.11(MEMORY TYPE RANGE REGISTERS (MTRRS))]
 * @see Vol3A[11.5(CACHE CONTROL)]
 * @see Vol3A[11.3(METHODS OF CACHING AVAILABLE)] (reference)
 * @{
 */
 /**
  * @brief Strong Uncacheable (UC)
  *
  * System memory locations are not cached. All reads and writes appear on the system bus and are executed in program order
  * without reordering. No speculative memory accesses, pagetable walks, or prefetches of speculated branch targets are
  * made. This type of cache-control is useful for memory-mapped I/O devices. When used with normal RAM, it greatly reduces
  * processor performance.
  */
#define MEMORY_TYPE_UNCACHEABLE                                      0x00000000

  /**
   * @brief Write Combining (WC)
   *
   * System memory locations are not cached (as with uncacheable memory) and coherency is not enforced by the processor's bus
   * coherency protocol. Speculative reads are allowed. Writes may be delayed and combined in the write combining buffer (WC
   * buffer) to reduce memory accesses. If the WC buffer is partially filled, the writes may be delayed until the next
   * occurrence of a serializing event; such as, an SFENCE or MFENCE instruction, CPUID execution, a read or write to
   * uncached memory, an interrupt occurrence, or a LOCK instruction execution. This type of cache-control is appropriate for
   * video frame buffers, where the order of writes is unimportant as long as the writes update memory so they can be seen on
   * the graphics display. This memory type is available in the Pentium Pro and Pentium II processors by programming the
   * MTRRs; or in processor families starting from the Pentium III processors by programming the MTRRs or by selecting it
   * through the PAT.
   *
   * @see Vol3A[11.3.1(Buffering of Write Combining Memory Locations)]
   */
#define MEMORY_TYPE_WRITE_COMBINING                                  0x00000001

   /**
    * @brief Write-through (WT)
    *
    * Writes and reads to and from system memory are cached. Reads come from cache lines on cache hits; read misses cause
    * cache fills. Speculative reads are allowed. All writes are written to a cache line (when possible) and through to system
    * memory. When writing through to memory, invalid cache lines are never filled, and valid cache lines are either filled or
    * invalidated. Write combining is allowed. This type of cache-control is appropriate for frame buffers or when there are
    * devices on the system bus that access system memory, but do not perform snooping of memory accesses. It enforces
    * coherency between caches in the processors and system memory.
    */
#define MEMORY_TYPE_WRITE_THROUGH                                    0x00000004

    /**
     * @brief Write protected (WP)
     *
     * Reads come from cache lines when possible, and read misses cause cache fills. Writes are propagated to the system bus
     * and cause corresponding cache lines on all processors on the bus to be invalidated. Speculative reads are allowed. This
     * memory type is available in processor families starting from the P6 family processors by programming the MTRRs.
     */
#define MEMORY_TYPE_WRITE_PROTECTED                                  0x00000005

     /**
      * @brief Write-back (WB)
      *
      * Writes and reads to and from system memory are cached. Reads come from cache lines on cache hits; read misses cause
      * cache fills. Speculative reads are allowed. Write misses cause cache line fills (in processor families starting with the
      * P6 family processors), and writes are performed entirely in the cache, when possible. Write combining is allowed. The
      * write-back memory type reduces bus traffic by eliminating many unnecessary writes to system memory. Writes to a cache
      * line are not immediately forwarded to system memory; instead, they are accumulated in the cache. The modified cache
      * lines are written to system memory later, when a write-back operation is performed. Write-back operations are triggered
      * when cache lines need to be deallocated, such as when new cache lines are being allocated in a cache that is already
      * full. They also are triggered by the mechanisms used to maintain cache consistency. This type of cache-control provides
      * the best performance, but it requires that all devices that access system memory on the system bus be able to snoop
      * memory accesses to insure system memory and cache coherency.
      */
#define MEMORY_TYPE_WRITE_BACK                                       0x00000006

      /**
       * @brief Uncacheable (UC-)
       *
       * Has same characteristics as the strong uncacheable (UC) memory type, except that this memory type can be overridden by
       * programming the MTRRs for the WC memory type. This memory type is available in processor families starting from the
       * Pentium III processors and can only be selected through the PAT.
       */
#define MEMORY_TYPE_UNCACHEABLE_MINUS                                0x00000007
#define MEMORY_TYPE_INVALID                                          0x000000FF

       /**
        * MTRR Capability.
        *
        * @see Vol3A[11.11.2.1(IA32_MTRR_DEF_TYPE MSR)]
        * @see Vol3A[11.11.1(MTRR Feature Identification)] (reference)
        */
#define IA32_MTRR_CAPABILITIES                                       0x000000FE

typedef union
        {
            struct
            {
                /**
                 * @brief VCNT (variable range registers count) field
                 *
                 * [Bits 7:0] Indicates the number of variable ranges implemented on the processor.
                 */
                UINT64 VariableRangeCount : 8;
#define IA32_MTRR_CAPABILITIES_VARIABLE_RANGE_COUNT_BIT              0
#define IA32_MTRR_CAPABILITIES_VARIABLE_RANGE_COUNT_FLAG             0xFF
#define IA32_MTRR_CAPABILITIES_VARIABLE_RANGE_COUNT_MASK             0xFF
#define IA32_MTRR_CAPABILITIES_VARIABLE_RANGE_COUNT(_)               (((_) >> 0) & 0xFF)

                /**
                 * @brief FIX (fixed range registers supported) flag
                 *
                 * [Bit 8] Fixed range MTRRs (IA32_MTRR_FIX64K_00000 through IA32_MTRR_FIX4K_0F8000) are supported when set; no fixed range
                 * registers are supported when clear.
                 */
                UINT64 FixedRangeSupported : 1;
#define IA32_MTRR_CAPABILITIES_FIXED_RANGE_SUPPORTED_BIT             8
#define IA32_MTRR_CAPABILITIES_FIXED_RANGE_SUPPORTED_FLAG            0x100
#define IA32_MTRR_CAPABILITIES_FIXED_RANGE_SUPPORTED_MASK            0x01
#define IA32_MTRR_CAPABILITIES_FIXED_RANGE_SUPPORTED(_)              (((_) >> 8) & 0x01)
                UINT64 Reserved1 : 1;

                /**
                 * @brief WC (write combining) flag
                 *
                 * [Bit 10] The write-combining (WC) memory type is supported when set; the WC type is not supported when clear.
                 */
                UINT64 WcSupported : 1;
#define IA32_MTRR_CAPABILITIES_WC_SUPPORTED_BIT                      10
#define IA32_MTRR_CAPABILITIES_WC_SUPPORTED_FLAG                     0x400
#define IA32_MTRR_CAPABILITIES_WC_SUPPORTED_MASK                     0x01
#define IA32_MTRR_CAPABILITIES_WC_SUPPORTED(_)                       (((_) >> 10) & 0x01)

                /**
                 * @brief SMRR (System-Management Range Register) flag
                 *
                 * [Bit 11] The system-management range register (SMRR) interface is supported when bit 11 is set; the SMRR interface is
                 * not supported when clear.
                 */
                UINT64 SmrrSupported : 1;
#define IA32_MTRR_CAPABILITIES_SMRR_SUPPORTED_BIT                    11
#define IA32_MTRR_CAPABILITIES_SMRR_SUPPORTED_FLAG                   0x800
#define IA32_MTRR_CAPABILITIES_SMRR_SUPPORTED_MASK                   0x01
#define IA32_MTRR_CAPABILITIES_SMRR_SUPPORTED(_)                     (((_) >> 11) & 0x01)
                UINT64 Reserved2 : 52;
            };

            UINT64 AsUInt;
        } IA32_MTRR_CAPABILITIES_REGISTER;

/**
* @defgroup IA32_MTRR_PHYSBASE \
*           IA32_MTRR_PHYSBASE(n)
*
* IA32_MTRR_PHYSBASE(0-9).
*
* @remarks If CPUID.01H: EDX.MTRR[12] = 1
* @see Vol3A[11.11.2.3(Variable Range MTRRs)]
* @{
*/
typedef union
{
    struct
    {
        /**
            * [Bits 7:0] Specifies the memory type for the range.
            */
        UINT64 Type : 8;
#define IA32_MTRR_PHYSBASE_TYPE_BIT                                  0
#define IA32_MTRR_PHYSBASE_TYPE_FLAG                                 0xFF
#define IA32_MTRR_PHYSBASE_TYPE_MASK                                 0xFF
#define IA32_MTRR_PHYSBASE_TYPE(_)                                   (((_) >> 0) & 0xFF)
        UINT64 Reserved1 : 4;

        /**
            * [Bits 47:12] Specifies the base address of the address range. This 24-bit value, in the case where MAXPHYADDR is 36
            * bits, is extended by 12 bits at the low end to form the base address (this automatically aligns the address on a 4-KByte
            * boundary).
            */
        UINT64 PageFrameNumber : 36;
#define IA32_MTRR_PHYSBASE_PAGE_FRAME_NUMBER_BIT                     12
#define IA32_MTRR_PHYSBASE_PAGE_FRAME_NUMBER_FLAG                    0xFFFFFFFFF000
#define IA32_MTRR_PHYSBASE_PAGE_FRAME_NUMBER_MASK                    0xFFFFFFFFF
#define IA32_MTRR_PHYSBASE_PAGE_FRAME_NUMBER(_)                      (((_) >> 12) & 0xFFFFFFFFF)
        UINT64 Reserved2 : 16;
    };

    UINT64 AsUInt;
} IA32_MTRR_PHYSBASE_REGISTER;

/**
 * @defgroup IA32_MTRR_PHYSMASK \
 *           IA32_MTRR_PHYSMASK(n)
 *
 * IA32_MTRR_PHYSMASK(0-9).
 *
 * @remarks If CPUID.01H: EDX.MTRR[12] = 1
 * @see Vol3A[11.11.2.3(Variable Range MTRRs)]
 * @{
 */
typedef union
{
    struct
    {
        UINT64 Reserved1 : 11;

        /**
         * [Bit 11] Enables the register pair when set; disables register pair when clear.
         */
        UINT64 Valid : 1;
#define IA32_MTRR_PHYSMASK_VALID_BIT                                 11
#define IA32_MTRR_PHYSMASK_VALID_FLAG                                0x800
#define IA32_MTRR_PHYSMASK_VALID_MASK                                0x01
#define IA32_MTRR_PHYSMASK_VALID(_)                                  (((_) >> 11) & 0x01)

        /**
         * [Bits 47:12] Specifies a mask (24 bits if the maximum physical address size is 36 bits, 28 bits if the maximum physical
         * address size is 40 bits). The mask determines the range of the region being mapped, according to the following
         * relationships:
         * - Address_Within_Range AND PhysMask = PhysBase AND PhysMask
         * - This value is extended by 12 bits at the low end to form the mask value.
         * - The width of the PhysMask field depends on the maximum physical address size supported by the processor.
         * CPUID.80000008H reports the maximum physical address size supported by the processor. If CPUID.80000008H is not
         * available, software may assume that the processor supports a 36-bit physical address size.
         *
         * @see Vol3A[11.11.3(Example Base and Mask Calculations)]
         */
        UINT64 PageFrameNumber : 36;
#define IA32_MTRR_PHYSMASK_PAGE_FRAME_NUMBER_BIT                     12
#define IA32_MTRR_PHYSMASK_PAGE_FRAME_NUMBER_FLAG                    0xFFFFFFFFF000
#define IA32_MTRR_PHYSMASK_PAGE_FRAME_NUMBER_MASK                    0xFFFFFFFFF
#define IA32_MTRR_PHYSMASK_PAGE_FRAME_NUMBER(_)                      (((_) >> 12) & 0xFFFFFFFFF)
        UINT64 Reserved2 : 16;
    };

    UINT64 AsUInt;
} IA32_MTRR_PHYSMASK_REGISTER;

/**
 * @defgroup EPT \
 *           The extended page-table mechanism
 *
 * The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
 * When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory)
 * are instead treated as guest-physical addresses. Guest-physical addresses are translated by traversing a set of EPT
 * paging structures to produce physical addresses that are used to access memory.
 *
 * @see Vol3C[28.2(THE EXTENDED PAGE TABLE MECHANISM (EPT))] (reference)
 * @{
 */
 /**
  * @brief Extended-Page-Table Pointer (EPTP)
  *
  * The extended-page-table pointer (EPTP) contains the address of the base of EPT PML4 table, as well as other EPT
  * configuration information.
  *
  * @see Vol3C[28.2.2(EPT Translation Mechanism]
  * @see Vol3C[24.6.11(Extended-Page-Table Pointer (EPTP)] (reference)
  */
typedef union
{
    struct
    {
        /**
         * [Bits 2:0] EPT paging-structure memory type:
         * - 0 = Uncacheable (UC)
         * - 6 = Write-back (WB)
         * Other values are reserved.
         *
         * @see Vol3C[28.2.6(EPT and memory Typing)]
         */
        UINT64 MemoryType : 3;
#define EPT_POINTER_MEMORY_TYPE_BIT                                  0
#define EPT_POINTER_MEMORY_TYPE_FLAG                                 0x07
#define EPT_POINTER_MEMORY_TYPE_MASK                                 0x07
#define EPT_POINTER_MEMORY_TYPE(_)                                   (((_) >> 0) & 0x07)

        /**
         * [Bits 5:3] This value is 1 less than the EPT page-walk length.
         *
         * @see Vol3C[28.2.6(EPT and memory Typing)]
         */
        UINT64 PageWalkLength : 3;
#define EPT_POINTER_PAGE_WALK_LENGTH_BIT                             3
#define EPT_POINTER_PAGE_WALK_LENGTH_FLAG                            0x38
#define EPT_POINTER_PAGE_WALK_LENGTH_MASK                            0x07
#define EPT_POINTER_PAGE_WALK_LENGTH(_)                              (((_) >> 3) & 0x07)
#define EPT_PAGE_WALK_LENGTH_4                                       0x00000003

        /**
         * [Bit 6] Setting this control to 1 enables accessed and dirty flags for EPT.
         *
         * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
         */
        UINT64 EnableAccessAndDirtyFlags : 1;
#define EPT_POINTER_ENABLE_ACCESS_AND_DIRTY_FLAGS_BIT                6
#define EPT_POINTER_ENABLE_ACCESS_AND_DIRTY_FLAGS_FLAG               0x40
#define EPT_POINTER_ENABLE_ACCESS_AND_DIRTY_FLAGS_MASK               0x01
#define EPT_POINTER_ENABLE_ACCESS_AND_DIRTY_FLAGS(_)                 (((_) >> 6) & 0x01)

        /**
         * [Bit 7] Setting this control to 1 enables enforcement of access rights for supervisor shadow-stack pages.
         *
         * @see Vol3C[28.3.3.2(EPT Violations)]
         */
        UINT64 EnableSupervisorShadowStackPages : 1;
#define EPT_POINTER_ENABLE_SUPERVISOR_SHADOW_STACK_PAGES_BIT         7
#define EPT_POINTER_ENABLE_SUPERVISOR_SHADOW_STACK_PAGES_FLAG        0x80
#define EPT_POINTER_ENABLE_SUPERVISOR_SHADOW_STACK_PAGES_MASK        0x01
#define EPT_POINTER_ENABLE_SUPERVISOR_SHADOW_STACK_PAGES(_)          (((_) >> 7) & 0x01)
        UINT64 Reserved1 : 4;

        /**
         * [Bits 47:12] Bits N-1:12 of the physical address of the 4-KByte aligned EPT PML4 table.
         */
        UINT64 PageFrameNumber : 36;
#define EPT_POINTER_PAGE_FRAME_NUMBER_BIT                            12
#define EPT_POINTER_PAGE_FRAME_NUMBER_FLAG                           0xFFFFFFFFF000
#define EPT_POINTER_PAGE_FRAME_NUMBER_MASK                           0xFFFFFFFFF
#define EPT_POINTER_PAGE_FRAME_NUMBER(_)                             (((_) >> 12) & 0xFFFFFFFFF)
        UINT64 Reserved2 : 16;
    };

    UINT64 AsUInt;
} EPT_POINTER;

/**
 * @brief Format of an EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
 *
 * A 4-KByte naturally aligned EPT PML4 table is located at the physical address specified in bits 51:12 of the
 * extended-page-table pointer (EPTP), a VM-execution control field. An EPT PML4 table comprises 512 64-bit entries (EPT
 * PML4Es). An EPT PML4E is selected using the physical address defined as follows:
 * - Bits 63:52 are all 0.
 * - Bits 51:12 are from the EPTP.
 * - Bits 11:3 are bits 47:39 of the guest-physical address.
 * - Bits 2:0 are all 0.
 * Because an EPT PML4E is identified using bits 47:39 of the guest-physical address, it controls access to a 512- GByte
 * region of the guest-physical-address space.
 *
 * @see Vol3C[24.6.11(Extended-Page-Table Pointer (EPTP)]
 */
typedef union
{
    struct
    {
        /**
         * [Bit 0] Read access; indicates whether reads are allowed from the 512-GByte region controlled by this entry.
         */
        UINT64 ReadAccess : 1;
#define EPT_PML4E_READ_ACCESS_BIT                                    0
#define EPT_PML4E_READ_ACCESS_FLAG                                   0x01
#define EPT_PML4E_READ_ACCESS_MASK                                   0x01
#define EPT_PML4E_READ_ACCESS(_)                                     (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Write access; indicates whether writes are allowed from the 512-GByte region controlled by this entry.
         */
        UINT64 WriteAccess : 1;
#define EPT_PML4E_WRITE_ACCESS_BIT                                   1
#define EPT_PML4E_WRITE_ACCESS_FLAG                                  0x02
#define EPT_PML4E_WRITE_ACCESS_MASK                                  0x01
#define EPT_PML4E_WRITE_ACCESS(_)                                    (((_) >> 1) & 0x01)

        /**
         * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
         * instruction fetches are allowed from the 512-GByte region controlled by this entry.
         * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
         * allowed from supervisor-mode linear addresses in the 512-GByte region controlled by this entry.
         */
        UINT64 ExecuteAccess : 1;
#define EPT_PML4E_EXECUTE_ACCESS_BIT                                 2
#define EPT_PML4E_EXECUTE_ACCESS_FLAG                                0x04
#define EPT_PML4E_EXECUTE_ACCESS_MASK                                0x01
#define EPT_PML4E_EXECUTE_ACCESS(_)                                  (((_) >> 2) & 0x01)
        UINT64 Reserved1 : 5;

        /**
         * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 512-GByte region
         * controlled by this entry. Ignored if bit 6 of EPTP is 0.
         *
         * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
         */
        UINT64 Accessed : 1;
#define EPT_PML4E_ACCESSED_BIT                                       8
#define EPT_PML4E_ACCESSED_FLAG                                      0x100
#define EPT_PML4E_ACCESSED_MASK                                      0x01
#define EPT_PML4E_ACCESSED(_)                                        (((_) >> 8) & 0x01)
        UINT64 Reserved2 : 1;

        /**
         * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
         * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 512-GByte region
         * controlled by this entry. If that control is 0, this bit is ignored.
         */
        UINT64 UserModeExecute : 1;
#define EPT_PML4E_USER_MODE_EXECUTE_BIT                              10
#define EPT_PML4E_USER_MODE_EXECUTE_FLAG                             0x400
#define EPT_PML4E_USER_MODE_EXECUTE_MASK                             0x01
#define EPT_PML4E_USER_MODE_EXECUTE(_)                               (((_) >> 10) & 0x01)
        UINT64 Reserved3 : 1;

        /**
         * [Bits 47:12] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
         */
        UINT64 PageFrameNumber : 36;
#define EPT_PML4E_PAGE_FRAME_NUMBER_BIT                              12
#define EPT_PML4E_PAGE_FRAME_NUMBER_FLAG                             0xFFFFFFFFF000
#define EPT_PML4E_PAGE_FRAME_NUMBER_MASK                             0xFFFFFFFFF
#define EPT_PML4E_PAGE_FRAME_NUMBER(_)                               (((_) >> 12) & 0xFFFFFFFFF)
        UINT64 Reserved4 : 16;
    };

    UINT64 AsUInt;
} EPT_PML4E;

/**
 * @brief Format of an EPT Page-Directory Entry (PDE) that Maps a 2-MByte Page
 */
typedef union
{
    struct
    {
        /**
         * [Bit 0] Read access; indicates whether reads are allowed from the 2-MByte page referenced by this entry.
         */
        UINT64 ReadAccess : 1;
#define EPT_PDE_2MB_READ_ACCESS_BIT                                  0
#define EPT_PDE_2MB_READ_ACCESS_FLAG                                 0x01
#define EPT_PDE_2MB_READ_ACCESS_MASK                                 0x01
#define EPT_PDE_2MB_READ_ACCESS(_)                                   (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Write access; indicates whether writes are allowed from the 2-MByte page referenced by this entry.
         */
        UINT64 WriteAccess : 1;
#define EPT_PDE_2MB_WRITE_ACCESS_BIT                                 1
#define EPT_PDE_2MB_WRITE_ACCESS_FLAG                                0x02
#define EPT_PDE_2MB_WRITE_ACCESS_MASK                                0x01
#define EPT_PDE_2MB_WRITE_ACCESS(_)                                  (((_) >> 1) & 0x01)

        /**
         * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
         * instruction fetches are allowed from the 2-MByte page controlled by this entry.
         * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
         * allowed from supervisor-mode linear addresses in the 2-MByte page controlled by this entry.
         */
        UINT64 ExecuteAccess : 1;
#define EPT_PDE_2MB_EXECUTE_ACCESS_BIT                               2
#define EPT_PDE_2MB_EXECUTE_ACCESS_FLAG                              0x04
#define EPT_PDE_2MB_EXECUTE_ACCESS_MASK                              0x01
#define EPT_PDE_2MB_EXECUTE_ACCESS(_)                                (((_) >> 2) & 0x01)

        /**
         * [Bits 5:3] EPT memory type for this 2-MByte page.
         *
         * @see Vol3C[28.2.6(EPT and memory Typing)]
         */
        UINT64 MemoryType : 3;
#define EPT_PDE_2MB_MEMORY_TYPE_BIT                                  3
#define EPT_PDE_2MB_MEMORY_TYPE_FLAG                                 0x38
#define EPT_PDE_2MB_MEMORY_TYPE_MASK                                 0x07
#define EPT_PDE_2MB_MEMORY_TYPE(_)                                   (((_) >> 3) & 0x07)

        /**
         * [Bit 6] Ignore PAT memory type for this 2-MByte page.
         *
         * @see Vol3C[28.2.6(EPT and memory Typing)]
         */
        UINT64 IgnorePat : 1;
#define EPT_PDE_2MB_IGNORE_PAT_BIT                                   6
#define EPT_PDE_2MB_IGNORE_PAT_FLAG                                  0x40
#define EPT_PDE_2MB_IGNORE_PAT_MASK                                  0x01
#define EPT_PDE_2MB_IGNORE_PAT(_)                                    (((_) >> 6) & 0x01)

        /**
         * [Bit 7] Must be 1 (otherwise, this entry references an EPT page table).
         */
        UINT64 LargePage : 1;
#define EPT_PDE_2MB_LARGE_PAGE_BIT                                   7
#define EPT_PDE_2MB_LARGE_PAGE_FLAG                                  0x80
#define EPT_PDE_2MB_LARGE_PAGE_MASK                                  0x01
#define EPT_PDE_2MB_LARGE_PAGE(_)                                    (((_) >> 7) & 0x01)

        /**
         * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 2-MByte page
         * referenced by this entry. Ignored if bit 6 of EPTP is 0.
         *
         * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
         */
        UINT64 Accessed : 1;
#define EPT_PDE_2MB_ACCESSED_BIT                                     8
#define EPT_PDE_2MB_ACCESSED_FLAG                                    0x100
#define EPT_PDE_2MB_ACCESSED_MASK                                    0x01
#define EPT_PDE_2MB_ACCESSED(_)                                      (((_) >> 8) & 0x01)

        /**
         * [Bit 9] If bit 6 of EPTP is 1, dirty flag for EPT; indicates whether software has written to the 2-MByte page referenced
         * by this entry. Ignored if bit 6 of EPTP is 0.
         *
         * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
         */
        UINT64 Dirty : 1;
#define EPT_PDE_2MB_DIRTY_BIT                                        9
#define EPT_PDE_2MB_DIRTY_FLAG                                       0x200
#define EPT_PDE_2MB_DIRTY_MASK                                       0x01
#define EPT_PDE_2MB_DIRTY(_)                                         (((_) >> 9) & 0x01)

        /**
         * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
         * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 2-MByte page controlled
         * by this entry. If that control is 0, this bit is ignored.
         */
        UINT64 UserModeExecute : 1;
#define EPT_PDE_2MB_USER_MODE_EXECUTE_BIT                            10
#define EPT_PDE_2MB_USER_MODE_EXECUTE_FLAG                           0x400
#define EPT_PDE_2MB_USER_MODE_EXECUTE_MASK                           0x01
#define EPT_PDE_2MB_USER_MODE_EXECUTE(_)                             (((_) >> 10) & 0x01)
        UINT64 Reserved1 : 10;

        /**
         * [Bits 47:21] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
         */
        UINT64 PageFrameNumber : 27;
#define EPT_PDE_2MB_PAGE_FRAME_NUMBER_BIT                            21
#define EPT_PDE_2MB_PAGE_FRAME_NUMBER_FLAG                           0xFFFFFFE00000
#define EPT_PDE_2MB_PAGE_FRAME_NUMBER_MASK                           0x7FFFFFF
#define EPT_PDE_2MB_PAGE_FRAME_NUMBER(_)                             (((_) >> 21) & 0x7FFFFFF)
        UINT64 Reserved2 : 9;

        /**
         * [Bit 57] Verify guest paging. If the "guest-paging verification" VM-execution control is 1, indicates limits on the
         * guest paging structures used to access the 2-MByte page controlled by this entry (see Section 28.3.3.2). If that control
         * is 0, this bit is ignored.
         *
         * @see Vol3C[28.3.3.2(EPT Violations)]
         */
        UINT64 VerifyGuestPaging : 1;
#define EPT_PDE_2MB_VERIFY_GUEST_PAGING_BIT                          57
#define EPT_PDE_2MB_VERIFY_GUEST_PAGING_FLAG                         0x200000000000000
#define EPT_PDE_2MB_VERIFY_GUEST_PAGING_MASK                         0x01
#define EPT_PDE_2MB_VERIFY_GUEST_PAGING(_)                           (((_) >> 57) & 0x01)

        /**
         * [Bit 58] Paging-write access. If the "EPT paging-write control" VM-execution control is 1, indicates that guest paging
         * may update the 2-MByte page controlled by this entry (see Section 28.3.3.2). If that control is 0, this bit is ignored
         *
         * @see Vol3C[28.3.3.2(EPT Violations)]
         */
        UINT64 PagingWriteAccess : 1;
#define EPT_PDE_2MB_PAGING_WRITE_ACCESS_BIT                          58
#define EPT_PDE_2MB_PAGING_WRITE_ACCESS_FLAG                         0x400000000000000
#define EPT_PDE_2MB_PAGING_WRITE_ACCESS_MASK                         0x01
#define EPT_PDE_2MB_PAGING_WRITE_ACCESS(_)                           (((_) >> 58) & 0x01)
        UINT64 Reserved3 : 1;

        /**
         * [Bit 60] Supervisor shadow stack. If bit 7 of EPTP is 1, indicates whether supervisor shadow stack accesses are allowed
         * to guest-physical addresses in the 2-MByte page mapped by this entry (see Section 28.3.3.2)
         *
         * @see Vol3C[28.3.3.2(EPT Violations)]
         */
        UINT64 SupervisorShadowStack : 1;
#define EPT_PDE_2MB_SUPERVISOR_SHADOW_STACK_BIT                      60
#define EPT_PDE_2MB_SUPERVISOR_SHADOW_STACK_FLAG                     0x1000000000000000
#define EPT_PDE_2MB_SUPERVISOR_SHADOW_STACK_MASK                     0x01
#define EPT_PDE_2MB_SUPERVISOR_SHADOW_STACK(_)                       (((_) >> 60) & 0x01)
        UINT64 Reserved4 : 2;

        /**
         * [Bit 63] Suppress \#VE. If the "EPT-violation \#VE" VM-execution control is 1, EPT violations caused by accesses to this
         * page are convertible to virtualization exceptions only if this bit is 0. If "EPT-violation \#VE" VMexecution control is
         * 0, this bit is ignored.
         *
         * @see Vol3C[25.5.6.1(Convertible EPT Violations)]
         */
        UINT64 SuppressVe : 1;
#define EPT_PDE_2MB_SUPPRESS_VE_BIT                                  63
#define EPT_PDE_2MB_SUPPRESS_VE_FLAG                                 0x8000000000000000
#define EPT_PDE_2MB_SUPPRESS_VE_MASK                                 0x01
#define EPT_PDE_2MB_SUPPRESS_VE(_)                                   (((_) >> 63) & 0x01)
    };

    UINT64 AsUInt;
} EPT_PDE_2MB;

/**
 * @brief Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table
 */
 typedef union
 {
     struct
     {
         /**
          * [Bit 0] Read access; indicates whether reads are allowed from the 2-MByte region controlled by this entry.
          */
         UINT64 ReadAccess : 1;
#define EPT_PDE_READ_ACCESS_BIT                                      0
#define EPT_PDE_READ_ACCESS_FLAG                                     0x01
#define EPT_PDE_READ_ACCESS_MASK                                     0x01
#define EPT_PDE_READ_ACCESS(_)                                       (((_) >> 0) & 0x01)

         /**
          * [Bit 1] Write access; indicates whether writes are allowed from the 2-MByte region controlled by this entry.
          */
         UINT64 WriteAccess : 1;
#define EPT_PDE_WRITE_ACCESS_BIT                                     1
#define EPT_PDE_WRITE_ACCESS_FLAG                                    0x02
#define EPT_PDE_WRITE_ACCESS_MASK                                    0x01
#define EPT_PDE_WRITE_ACCESS(_)                                      (((_) >> 1) & 0x01)

         /**
          * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
          * instruction fetches are allowed from the 2-MByte region controlled by this entry.
          * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
          * allowed from supervisor-mode linear addresses in the 2-MByte region controlled by this entry.
          */
         UINT64 ExecuteAccess : 1;
#define EPT_PDE_EXECUTE_ACCESS_BIT                                   2
#define EPT_PDE_EXECUTE_ACCESS_FLAG                                  0x04
#define EPT_PDE_EXECUTE_ACCESS_MASK                                  0x01
#define EPT_PDE_EXECUTE_ACCESS(_)                                    (((_) >> 2) & 0x01)
         UINT64 Reserved1 : 5;

         /**
          * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 2-MByte region
          * controlled by this entry. Ignored if bit 6 of EPTP is 0.
          *
          * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
          */
         UINT64 Accessed : 1;
#define EPT_PDE_ACCESSED_BIT                                         8
#define EPT_PDE_ACCESSED_FLAG                                        0x100
#define EPT_PDE_ACCESSED_MASK                                        0x01
#define EPT_PDE_ACCESSED(_)                                          (((_) >> 8) & 0x01)
         UINT64 Reserved2 : 1;

         /**
          * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
          * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 2-MByte region controlled
          * by this entry. If that control is 0, this bit is ignored.
          */
         UINT64 UserModeExecute : 1;
#define EPT_PDE_USER_MODE_EXECUTE_BIT                                10
#define EPT_PDE_USER_MODE_EXECUTE_FLAG                               0x400
#define EPT_PDE_USER_MODE_EXECUTE_MASK                               0x01
#define EPT_PDE_USER_MODE_EXECUTE(_)                                 (((_) >> 10) & 0x01)
         UINT64 Reserved3 : 1;

         /**
          * [Bits 47:12] Physical address of 4-KByte aligned EPT page table referenced by this entry.
          */
         UINT64 PageFrameNumber : 36;
#define EPT_PDE_PAGE_FRAME_NUMBER_BIT                                12
#define EPT_PDE_PAGE_FRAME_NUMBER_FLAG                               0xFFFFFFFFF000
#define EPT_PDE_PAGE_FRAME_NUMBER_MASK                               0xFFFFFFFFF
#define EPT_PDE_PAGE_FRAME_NUMBER(_)                                 (((_) >> 12) & 0xFFFFFFFFF)
         UINT64 Reserved4 : 16;
     };

     UINT64 AsUInt;
 } EPT_PDE;

 /**
  * @brief Format of an EPT Page-Table Entry that Maps a 4-KByte Page
  */
 typedef union
 {
     struct
     {
         /**
          * [Bit 0] Read access; indicates whether reads are allowed from the 4-KByte page referenced by this entry.
          */
         UINT64 ReadAccess : 1;
#define EPT_PTE_READ_ACCESS_BIT                                      0
#define EPT_PTE_READ_ACCESS_FLAG                                     0x01
#define EPT_PTE_READ_ACCESS_MASK                                     0x01
#define EPT_PTE_READ_ACCESS(_)                                       (((_) >> 0) & 0x01)

         /**
          * [Bit 1] Write access; indicates whether writes are allowed from the 4-KByte page referenced by this entry.
          */
         UINT64 WriteAccess : 1;
#define EPT_PTE_WRITE_ACCESS_BIT                                     1
#define EPT_PTE_WRITE_ACCESS_FLAG                                    0x02
#define EPT_PTE_WRITE_ACCESS_MASK                                    0x01
#define EPT_PTE_WRITE_ACCESS(_)                                      (((_) >> 1) & 0x01)

         /**
          * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
          * instruction fetches are allowed from the 4-KByte page controlled by this entry.
          * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
          * allowed from supervisor-mode linear addresses in the 4-KByte page controlled by this entry.
          */
         UINT64 ExecuteAccess : 1;
#define EPT_PTE_EXECUTE_ACCESS_BIT                                   2
#define EPT_PTE_EXECUTE_ACCESS_FLAG                                  0x04
#define EPT_PTE_EXECUTE_ACCESS_MASK                                  0x01
#define EPT_PTE_EXECUTE_ACCESS(_)                                    (((_) >> 2) & 0x01)

         /**
          * [Bits 5:3] EPT memory type for this 4-KByte page.
          *
          * @see Vol3C[28.2.6(EPT and memory Typing)]
          */
         UINT64 MemoryType : 3;
#define EPT_PTE_MEMORY_TYPE_BIT                                      3
#define EPT_PTE_MEMORY_TYPE_FLAG                                     0x38
#define EPT_PTE_MEMORY_TYPE_MASK                                     0x07
#define EPT_PTE_MEMORY_TYPE(_)                                       (((_) >> 3) & 0x07)

         /**
          * [Bit 6] Ignore PAT memory type for this 4-KByte page.
          *
          * @see Vol3C[28.2.6(EPT and memory Typing)]
          */
         UINT64 IgnorePat : 1;
#define EPT_PTE_IGNORE_PAT_BIT                                       6
#define EPT_PTE_IGNORE_PAT_FLAG                                      0x40
#define EPT_PTE_IGNORE_PAT_MASK                                      0x01
#define EPT_PTE_IGNORE_PAT(_)                                        (((_) >> 6) & 0x01)
         UINT64 Reserved1 : 1;

         /**
          * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 4-KByte page
          * referenced by this entry. Ignored if bit 6 of EPTP is 0.
          *
          * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
          */
         UINT64 Accessed : 1;
#define EPT_PTE_ACCESSED_BIT                                         8
#define EPT_PTE_ACCESSED_FLAG                                        0x100
#define EPT_PTE_ACCESSED_MASK                                        0x01
#define EPT_PTE_ACCESSED(_)                                          (((_) >> 8) & 0x01)

         /**
          * [Bit 9] If bit 6 of EPTP is 1, dirty flag for EPT; indicates whether software has written to the 4-KByte page referenced
          * by this entry. Ignored if bit 6 of EPTP is 0.
          *
          * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
          */
         UINT64 Dirty : 1;
#define EPT_PTE_DIRTY_BIT                                            9
#define EPT_PTE_DIRTY_FLAG                                           0x200
#define EPT_PTE_DIRTY_MASK                                           0x01
#define EPT_PTE_DIRTY(_)                                             (((_) >> 9) & 0x01)

         /**
          * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
          * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 4-KByte page controlled
          * by this entry. If that control is 0, this bit is ignored.
          */
         UINT64 UserModeExecute : 1;
#define EPT_PTE_USER_MODE_EXECUTE_BIT                                10
#define EPT_PTE_USER_MODE_EXECUTE_FLAG                               0x400
#define EPT_PTE_USER_MODE_EXECUTE_MASK                               0x01
#define EPT_PTE_USER_MODE_EXECUTE(_)                                 (((_) >> 10) & 0x01)
         UINT64 Reserved2 : 1;

         /**
          * [Bits 47:12] Physical address of the 4-KByte page referenced by this entry.
          */
         UINT64 PageFrameNumber : 36;
#define EPT_PTE_PAGE_FRAME_NUMBER_BIT                                12
#define EPT_PTE_PAGE_FRAME_NUMBER_FLAG                               0xFFFFFFFFF000
#define EPT_PTE_PAGE_FRAME_NUMBER_MASK                               0xFFFFFFFFF
#define EPT_PTE_PAGE_FRAME_NUMBER(_)                                 (((_) >> 12) & 0xFFFFFFFFF)
         UINT64 Reserved3 : 9;

         /**
          * [Bit 57] Verify guest paging. If the "guest-paging verification" VM-execution control is 1, indicates limits on the
          * guest paging structures used to access the 4-KByte page controlled by this entry (see Section 28.3.3.2). If that control
          * is 0, this bit is ignored.
          *
          * @see Vol3C[28.3.3.2(EPT Violations)]
          */
         UINT64 VerifyGuestPaging : 1;
#define EPT_PTE_VERIFY_GUEST_PAGING_BIT                              57
#define EPT_PTE_VERIFY_GUEST_PAGING_FLAG                             0x200000000000000
#define EPT_PTE_VERIFY_GUEST_PAGING_MASK                             0x01
#define EPT_PTE_VERIFY_GUEST_PAGING(_)                               (((_) >> 57) & 0x01)

         /**
          * [Bit 58] Paging-write access. If the "EPT paging-write control" VM-execution control is 1, indicates that guest paging
          * may update the 4-KByte page controlled by this entry (see Section 28.3.3.2). If that control is 0, this bit is ignored
          *
          * @see Vol3C[28.3.3.2(EPT Violations)]
          */
         UINT64 PagingWriteAccess : 1;
#define EPT_PTE_PAGING_WRITE_ACCESS_BIT                              58
#define EPT_PTE_PAGING_WRITE_ACCESS_FLAG                             0x400000000000000
#define EPT_PTE_PAGING_WRITE_ACCESS_MASK                             0x01
#define EPT_PTE_PAGING_WRITE_ACCESS(_)                               (((_) >> 58) & 0x01)
         UINT64 Reserved4 : 1;

         /**
          * [Bit 60] Supervisor shadow stack. If bit 7 of EPTP is 1, indicates whether supervisor shadow stack accesses are allowed
          * to guest-physical addresses in the 4-KByte page mapped by this entry (see Section 28.3.3.2)
          *
          * @see Vol3C[28.3.3.2(EPT Violations)]
          */
         UINT64 SupervisorShadowStack : 1;
#define EPT_PTE_SUPERVISOR_SHADOW_STACK_BIT                          60
#define EPT_PTE_SUPERVISOR_SHADOW_STACK_FLAG                         0x1000000000000000
#define EPT_PTE_SUPERVISOR_SHADOW_STACK_MASK                         0x01
#define EPT_PTE_SUPERVISOR_SHADOW_STACK(_)                           (((_) >> 60) & 0x01)

         /**
          * [Bit 61] Sub-page write permissions. If the "sub-page write permissions for EPT" VM-execution control is 1, writes to
          * individual 128-byte regions of the 4-KByte page referenced by this entry may be allowed even if the page would normally
          * not be writable (see Section 28.3.4). If "sub-page write permissions for EPT" VM-execution control is 0, this bit is
          * ignored.
          *
          * @see Vol3C[28.3.4(Sub-Page Write Permissions)]
          */
         UINT64 SubPageWritePermissions : 1;
#define EPT_PTE_SUB_PAGE_WRITE_PERMISSIONS_BIT                       61
#define EPT_PTE_SUB_PAGE_WRITE_PERMISSIONS_FLAG                      0x2000000000000000
#define EPT_PTE_SUB_PAGE_WRITE_PERMISSIONS_MASK                      0x01
#define EPT_PTE_SUB_PAGE_WRITE_PERMISSIONS(_)                        (((_) >> 61) & 0x01)
         UINT64 Reserved5 : 1;

         /**
          * [Bit 63] Suppress \#VE. If the "EPT-violation \#VE" VM-execution control is 1, EPT violations caused by accesses to this
          * page are convertible to virtualization exceptions only if this bit is 0. If "EPT-violation \#VE" VMexecution control is
          * 0, this bit is ignored.
          *
          * @see Vol3C[25.5.6.1(Convertible EPT Violations)]
          */
         UINT64 SuppressVe : 1;
#define EPT_PTE_SUPPRESS_VE_BIT                                      63
#define EPT_PTE_SUPPRESS_VE_FLAG                                     0x8000000000000000
#define EPT_PTE_SUPPRESS_VE_MASK                                     0x01
#define EPT_PTE_SUPPRESS_VE(_)                                       (((_) >> 63) & 0x01)
     };

     UINT64 AsUInt;
 } EPT_PTE;

/**
 * @brief Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
 */
 typedef union
 {
     struct
     {
         /**
          * [Bit 0] Read access; indicates whether reads are allowed from the 1-GByte region controlled by this entry.
          */
         UINT64 ReadAccess : 1;
#define EPT_PDPTE_READ_ACCESS_BIT                                    0
#define EPT_PDPTE_READ_ACCESS_FLAG                                   0x01
#define EPT_PDPTE_READ_ACCESS_MASK                                   0x01
#define EPT_PDPTE_READ_ACCESS(_)                                     (((_) >> 0) & 0x01)

         /**
          * [Bit 1] Write access; indicates whether writes are allowed from the 1-GByte region controlled by this entry.
          */
         UINT64 WriteAccess : 1;
#define EPT_PDPTE_WRITE_ACCESS_BIT                                   1
#define EPT_PDPTE_WRITE_ACCESS_FLAG                                  0x02
#define EPT_PDPTE_WRITE_ACCESS_MASK                                  0x01
#define EPT_PDPTE_WRITE_ACCESS(_)                                    (((_) >> 1) & 0x01)

         /**
          * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
          * instruction fetches are allowed from the 1-GByte region controlled by this entry.
          * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
          * allowed from supervisor-mode linear addresses in the 1-GByte region controlled by this entry.
          */
         UINT64 ExecuteAccess : 1;
#define EPT_PDPTE_EXECUTE_ACCESS_BIT                                 2
#define EPT_PDPTE_EXECUTE_ACCESS_FLAG                                0x04
#define EPT_PDPTE_EXECUTE_ACCESS_MASK                                0x01
#define EPT_PDPTE_EXECUTE_ACCESS(_)                                  (((_) >> 2) & 0x01)
         UINT64 Reserved1 : 5;

         /**
          * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 1-GByte region
          * controlled by this entry. Ignored if bit 6 of EPTP is 0.
          *
          * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
          */
         UINT64 Accessed : 1;
#define EPT_PDPTE_ACCESSED_BIT                                       8
#define EPT_PDPTE_ACCESSED_FLAG                                      0x100
#define EPT_PDPTE_ACCESSED_MASK                                      0x01
#define EPT_PDPTE_ACCESSED(_)                                        (((_) >> 8) & 0x01)
         UINT64 Reserved2 : 1;

         /**
          * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
          * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 1-GByte region controlled
          * by this entry. If that control is 0, this bit is ignored.
          */
         UINT64 UserModeExecute : 1;
#define EPT_PDPTE_USER_MODE_EXECUTE_BIT                              10
#define EPT_PDPTE_USER_MODE_EXECUTE_FLAG                             0x400
#define EPT_PDPTE_USER_MODE_EXECUTE_MASK                             0x01
#define EPT_PDPTE_USER_MODE_EXECUTE(_)                               (((_) >> 10) & 0x01)
         UINT64 Reserved3 : 1;

         /**
          * [Bits 47:12] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
          */
         UINT64 PageFrameNumber : 36;
#define EPT_PDPTE_PAGE_FRAME_NUMBER_BIT                              12
#define EPT_PDPTE_PAGE_FRAME_NUMBER_FLAG                             0xFFFFFFFFF000
#define EPT_PDPTE_PAGE_FRAME_NUMBER_MASK                             0xFFFFFFFFF
#define EPT_PDPTE_PAGE_FRAME_NUMBER(_)                               (((_) >> 12) & 0xFFFFFFFFF)
         UINT64 Reserved4 : 16;
     };

     UINT64 AsUInt;
 } EPT_PDPTE;

typedef struct _VMM_EPT_PAGE_TABLE
{
#define EPT_PML4E_ENTRY_COUNT                                        0x00000200
#define EPT_PDPTE_ENTRY_COUNT                                        0x00000200
#define EPT_PDE_ENTRY_COUNT                                          0x00000200
#define EPT_PTE_ENTRY_COUNT                                          0x00000200

    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E      PML4T[EPT_PML4E_ENTRY_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE      PDPT[EPT_PDPTE_ENTRY_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE_2MB    PDT[EPT_PDE_ENTRY_COUNT][EPT_PTE_ENTRY_COUNT];


}VMM_EPT_PAGE_TABLE, * PVMM_EPT_PAGE_TABLE;

typedef struct _MTRR_RANGE
{
    ULONG64 Valid;
    ULONG64 Type;
    ULONG64 PhysicalAddressMin;
    ULONG64 PhysicalAddressMax;
}MTRR_RANGE, * PMTRR_RANGE;

typedef struct _EPT_STATE
{
    UINT_PTR* PML4T;
    EPT_POINTER EptPointer;
    BOOL bEptInitializeSuccess;
}EPT_STATE, * PEPT_STATE;

typedef struct INVVPID_DESCRIPTOR
{
    UINT16 Vpid;

    /**
     * Must be zero.
     */
    UINT16 Reserved1;

    /**
     * Must be zero.
     */
    UINT32 Reserved2;
    UINT64 LinearAddress;
} INVVPID_DESCRIPTOR;

enum INVVPID_TYPE
{
    /**
     * If the INVVPID type is 0, the logical processor invalidates linear mappings and combined mappings associated with the
     * VPID specified in the INVVPID descriptor and that would be used to translate the linear address specified in of the
     * INVVPID descriptor. Linear mappings and combined mappings for that VPID and linear address are invalidated for all PCIDs
     * and, for combined mappings, all EP4TAs. (The instruction may also invalidate mappings associated with other VPIDs and
     * for other linear addresses).
     */
    InvvpidIndividualAddress = 0x00000000,

    /**
     * If the INVVPID type is 1, the logical processor invalidates all linear mappings and combined mappings associated with
     * the VPID specified in the INVVPID descriptor. Linear mappings and combined mappings for that VPID are invalidated for
     * all PCIDs and, for combined mappings, all EP4TAs. (The instruction may also invalidate mappings associated with other
     * VPIDs).
     */
     InvvpidSingleContext = 0x00000001,

     /**
      * If the INVVPID type is 2, the logical processor invalidates linear mappings and combined mappings associated with all
      * VPIDs except VPID 0000H and with all PCIDs. (The instruction may also invalidate linear mappings with VPID 0000H.)
      * Combined mappings are invalidated for all EP4TAs.
      */
      InvvpidAllContext = 0x00000002,

      /**
       * If the INVVPID type is 3, the logical processor invalidates linear mappings and combined mappings associated with the
       * VPID specified in the INVVPID descriptor. Linear mappings and combined mappings for that VPID are invalidated for all
       * PCIDs and, for combined mappings, all EP4TAs. The logical processor is not required to invalidate information that was
       * used for global translations (although it may do so). (The instruction may also invalidate mappings associated with
       * other VPIDs).
       *
       * @see Vol3C[4.10(Caching Translation Information)]
       */
       InvvpidSingleContextRetainingGlobals = 0x00000003,
};
