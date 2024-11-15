use libafl_qemu::GuestReg;
use log::*;
fn cpuid_common(pc : GuestReg, in_eax: u32, out_eax: *mut u32,out_ebx: *mut u32, out_ecx: *mut u32, out_edx: *mut u32)
{
    unsafe {
        let eax_info = *out_eax;
        let ebx_info = *out_ebx;
        let ecx_info = *out_ecx;
        let edx_info = *out_edx;
        debug!("cpuid {pc:#x} {in_eax:#x} {eax_info:#x} {ebx_info:#x} {ecx_info:#x} {edx_info:#x}");
    }
}

fn wrmsr_common(pc : GuestReg, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32)
{
    unsafe {
        let eax_info = *in_eax;
        let edx_info = *in_edx;
        debug!("wrmsr {pc:#x} {in_ecx:#x} {eax_info:#x} {edx_info:#x}");
    }
}