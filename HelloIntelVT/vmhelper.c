#include "vmhelper.h"
#include "kernelFunction.h"

char* getVMInstructionErrorString(void)
/*
 * get the last vm error and return a pointer to the string describing that error
 */
{
    size_t i = 0;
    if (__vmx_vmread(vm_errorcode, &i) != 0) {
        return NULL;
    }

    char* result = NULL;
    switch (i)
    {
        case 0: result = "No error"; break;
        case 1: result = "VMCALL executed in VMX root operation"; break;
        case 2: result = "VMCLEAR with invalid physical address"; break;
        case 3: result = "VMCLEAR with VMXON pointer"; break;
        case 4: result = "VMLAUNCH with non-clear VMCS"; break;
        case 5: result = "VMRESUME with non-launched VMCS"; break;
        case 6: result = "VMRESUME with a corrupted VMCS"; break;
        case 7: result = "VM entry with invalid fields"; break;
        case 8: result = "VM entry with invalid host-state fields"; break;
        case 9: result = "VMPTRLD with invalid physical address"; break;
        case 10: result = "VMPTRLD with VMXON pointer"; break;
        case 11: result = "VMPTRLD with incorrect VMCS revision identifier"; break;
        case 12: result = "VMREAD/VMWRITE from/to unsupported VMCS component"; break;
        case 13: result = "VMWRITE to read-only VMCS component"; break;
        case 15: result = "VMXON executed in VMX root operation"; break;
        case 16: result = "VM entry with invalid executive-VMCS pointer"; break;
        case 17: result = "VM entry with non-launched executive-VMCS pointer"; break;
        case 18: result = "VM entry with executive-VMCS pointer but not VMXON pointer"; break;
        case 19: result = "VMCALL with non-clear VMCS"; break;
        case 20: result = "VMCALL with invalid VM-exit control fields"; break;
        case 22: result = "VMCALL with incorrect MSEG revision number"; break;
        case 23: result = "VMXOFF under dual-monitor treatment of SMIs and SMM"; break;
        case 24: result = "VMCALL with invalid SMM-monitor features"; break;
        case 25: result = "VM entry with invalid VM-execution control fields in executive VMCS"; break;
        case 26: result = "VM entry with events blocked by MOV SS"; break;
        case 28: result = "Invalid operand to INVEPT/INVVPID.";  break;

        default: result = "Undefined"; break;
    }


    return result;
}
