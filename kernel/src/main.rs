#![no_std]
#![no_main]
#![feature(const_fn)]
#![feature(lang_items)]
#![feature(core_intrinsics)]
#![feature(allocator_api)]
#![feature(llvm_asm)]
#![allow(dead_code)]
#![feature(global_asm)]
#![feature(panic_info_message)]

extern crate alloc;

extern crate serial;
extern crate cpu;
extern crate rangeset;
extern crate mmu;

#[macro_use] extern crate bytesafe_derive;

use core::sync::atomic::{AtomicUsize, Ordering};
use core::convert::TryInto;

/// Global allocator
#[global_allocator]
static GLOBAL_ALLOCATOR: mm::GlobalAllocator = mm::GlobalAllocator;

/// Whether or not floats are used. This is used by the MSVC calling convention
/// and it just has to exist.
#[export_name="_fltused"]
pub static FLTUSED: usize = 0;

macro_rules! print {
    ( $($arg:tt)* ) => ({
        use core::fmt::Write;
        use core::sync::atomic::{AtomicUsize, Ordering};
        static PRINT_LOCK:     AtomicUsize = AtomicUsize::new(0);
        static PRINT_LOCK_REL: AtomicUsize = AtomicUsize::new(0);

        let ticket = PRINT_LOCK.fetch_add(1, Ordering::SeqCst);
        while ticket != PRINT_LOCK_REL.load(Ordering::SeqCst) {}

        let _ = write!(&mut $crate::Writer, $($arg)*);

        PRINT_LOCK_REL.fetch_add(1, Ordering::SeqCst);
    })
}

/// ACPI code
pub mod acpi;

/// Panic handler
pub mod panic;

/// Core requirements needed for Rust, such as libc memset() and friends
pub mod core_reqs;

/// Bring in the memory manager
pub mod mm;

/// Writer implementation used by the `print!` macro
pub struct Writer;

impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial::write(s);
        Ok(())
    }
}

#[lang = "oom"]
#[no_mangle]
pub fn rust_oom(_layout: alloc::alloc::Layout) -> ! {
    panic!("Out of memory");
}

/// Main entry point for this codebase
#[no_mangle]
pub extern fn entry(param: u64) -> ! {
    static CORE_ID: AtomicUsize = AtomicUsize::new(0);

    // Convert the bootloader parameter into a reference
    let param = unsafe { &*(param as *const cpu::BootloaderStruct) };

    // Get a unique core identifier for this processor
    let core_id = CORE_ID.fetch_add(1, Ordering::SeqCst);

    if cpu::is_bsp() {
        unsafe {
            acpi::init(&param.phys_memory).expect("Failed to initialize ACPI");
        }
    }

    // Attempt to launch the next processor in the list
    if false {
        unsafe {
            acpi::launch_ap(core_id + 1);
        }
    }

    // First, detect if VM-x is supported on the machine
    // See section 23.6 in the Intel Manual "DISCOVERING SUPPORT FOR VMX"
    let cpu_features = cpu::get_cpu_features();
    assert!(cpu_features.vmx, "VM-x is not supported, halting");

    print!("VMX detected, enabling VM-x!\n");

    unsafe {
        // Set CR4.VMXE
        const CR4_VMXE: u64 = 1 << 13;
        const IA32_FEATURE_CONTROL: u32 = 0x3a;
        const IA32_VMX_BASIC: u32 = 0x480;
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        /// Bits that must be set to 0 in CR0 when doing a VMXON
        const IA32_VMX_CR0_FIXED0: u32 = 0x486;

        /// Bits that must be set to 1 in CR0 when doing a VMXON
        const IA32_VMX_CR0_FIXED1: u32 = 0x487;

        /// Bits that must be set to 0 in CR4 when doing a VMXON
        const IA32_VMX_CR4_FIXED0: u32 = 0x488;

        /// Bits that must be set to 1 in CR4 when doing a VMXON
        const IA32_VMX_CR4_FIXED1: u32 = 0x489;

        print!("CR0 Fixed 0 {:#010x}\nCR0 Fixed 1 {:#010x}\nCR4 Fixed 0 {:#010x}\nCR4 Fixed 1 {:#010x}\n",
            cpu::rdmsr(IA32_VMX_CR0_FIXED0), cpu::rdmsr(IA32_VMX_CR0_FIXED1),
            cpu::rdmsr(IA32_VMX_CR4_FIXED0), cpu::rdmsr(IA32_VMX_CR4_FIXED1));
        
        // Set the mandatory bits in CR0 and clear bits that are mandatory zero
        cpu::write_cr0((cpu::read_cr0() | cpu::rdmsr(IA32_VMX_CR0_FIXED0))
            & cpu::rdmsr(IA32_VMX_CR0_FIXED1));

        // Set the mandatory bits in CR4 and clear bits that are mandatory zero
        cpu::write_cr4((cpu::read_cr4() | cpu::rdmsr(IA32_VMX_CR4_FIXED0))
            & cpu::rdmsr(IA32_VMX_CR4_FIXED1));

        // Check if we need to set bits in IA32_FEATURE_CONTROL
        if (cpu::rdmsr(IA32_FEATURE_CONTROL) & VMX_LOCK_BIT) == 0 {
            // Lock bit not set, initialize IA32_FEATURE_CONTROL register
            let old = cpu::rdmsr(IA32_FEATURE_CONTROL);
            cpu::wrmsr(IA32_FEATURE_CONTROL,
                VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | old);
        }

        // Validate that VMXON is allowed outside of SMX mode
        // See section 23.7 in the Intel System Manual
        // "ENABLING AND ENTERING VMX OPERATION"
        let lock_and_vmx = VMXON_OUTSIDE_SMX | VMX_LOCK_BIT;
        assert!(
            (cpu::rdmsr(IA32_FEATURE_CONTROL) & lock_and_vmx) == lock_and_vmx,
            "VMXON not allowed outside of SMX operation according to \
             IA32_FEATURE_CONTROL, or lock bit is not set");

        // Enable VMX extensions
        cpu::write_cr4(cpu::read_cr4() | CR4_VMXE);
        print!("Set CR4.VMXE!\n");

        // Create a 4-KiB zeroed out physical page
        let vmxon_region = mm::alloc_page()
            .expect("Failed to allocate VMXON region");

        // Create a 4-KiB zeroed out physical page to point to the vmxon page
        let vmxon_ptr_page = mm::alloc_page()
            .expect("Failed to allocate VMXON pointer region");
        vmxon_ptr_page[..8].copy_from_slice(
            &(vmxon_region.as_mut_ptr() as usize).to_le_bytes());

        print!("vmxon region allocated at       {:p}\n\
                vmxon pointer page allocated at {:p}\n",
            vmxon_region.as_mut_ptr(),
            vmxon_ptr_page.as_mut_ptr());

        // Get the VMCS revision number
        let vmcs_revision_number =
            (cpu::rdmsr(IA32_VMX_BASIC) as u32) & 0x7fff_ffff;
        print!("VMCS revision number: {}\n", vmcs_revision_number);

        // Write in the VMCS revision number to the VMXON region
        vmxon_region[..4].copy_from_slice(&vmcs_revision_number.to_le_bytes());

        // Execute VMXON to enable VMX root operation
        llvm_asm!("vmxon [$0]" :: "r"(vmxon_ptr_page.as_mut_ptr()) :
            "memory", "cc" : "volatile", "intel");

        // Now we're in VMX root operation
        print!("VMXON complete\n");

        // Create a new zeroed out VMCS region, and write in the revision
        // number
        let vmcs_region = mm::alloc_page()
            .expect("Failed to allocate VMCS region");
        vmcs_region[..4].copy_from_slice(&vmcs_revision_number.to_le_bytes());

        // Create a 4-KiB zeroed out physical page to point to the vmxon page
        let vmcs_ptr_page = mm::alloc_page()
            .expect("Failed to allocate VMCS pointer region");
        vmcs_ptr_page[..8].copy_from_slice(
            &(vmcs_region.as_mut_ptr() as usize).to_le_bytes());

        // Activate this given VMCS
        llvm_asm!("vmptrld [$0]" :: "r"(vmcs_ptr_page.as_mut_ptr()) :
            "memory", "cc" : "volatile", "intel");

        const VM_INSTRUCTION_ERROR: u64 = 0x00004400;
        const EXIT_REASON:          u64 = 0x00004402;
        const PIN_BASED_CONTROLS:   u64 = 0x00004000;
        const PROC_BASED_CONTROLS:  u64 = 0x00004002;
        const PROC2_BASED_CONTROLS: u64 = 0x0000401e;
        const EXIT_CONTROLS:        u64 = 0x0000400c;
        const ENTRY_CONTROLS:       u64 = 0x00004012;
        const EPT_POINTER:          u64 = 0x0000201a;

        // Allocate the root level of the page table
        let ept_root = mm::alloc_page()
            .expect("Failed to allocate EPT root");

        let pdpt = mm::alloc_page().expect("Failed to allocate EPT PDPT");

        let pml4e_entry = (pdpt.as_mut_ptr() as usize) | 7;
        ept_root[..8].copy_from_slice(&pml4e_entry.to_le_bytes());
        pdpt[..8].copy_from_slice(&((1 << 7) | 7usize).to_le_bytes());

        cpu::vmwrite(EPT_POINTER, ept_root.as_mut_ptr() as u64 | (3 << 3));

        const IA32_VMX_PINBASED_CTLS:  u32 = 0x481;
        const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
        const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48b;
        const IA32_VMX_EXIT_CTLS: u32 = 0x483;
        const IA32_VMX_ENTRY_CTLS: u32 = 0x484;

        const ACTIVATE_SECONDARY_CONTROLS: u64 = 1 << 31;

        print!("Getting control requirements\n");

        let pinbased_ctrl0   = (cpu::rdmsr(IA32_VMX_PINBASED_CTLS) >>  0) & 0xffff_ffff;
        let pinbased_ctrl1   = (cpu::rdmsr(IA32_VMX_PINBASED_CTLS) >> 32) & 0xffff_ffff;
        let procbased_ctrl0  = (cpu::rdmsr(IA32_VMX_PROCBASED_CTLS) >>  0) & 0xffff_ffff;
        let procbased_ctrl1  = (cpu::rdmsr(IA32_VMX_PROCBASED_CTLS) >> 32) & 0xffff_ffff;
        let proc2based_ctrl0 = (cpu::rdmsr(IA32_VMX_PROCBASED_CTLS2) >>  0) & 0xffff_ffff;
        let proc2based_ctrl1 = (cpu::rdmsr(IA32_VMX_PROCBASED_CTLS2) >> 32) & 0xffff_ffff;
        let exit_ctrl0       = (cpu::rdmsr(IA32_VMX_EXIT_CTLS) >>  0) & 0xffff_ffff;
        let exit_ctrl1       = (cpu::rdmsr(IA32_VMX_EXIT_CTLS) >> 32) & 0xffff_ffff;
        let entry_ctrl0      = (cpu::rdmsr(IA32_VMX_ENTRY_CTLS) >>  0) & 0xffff_ffff;
        let entry_ctrl1      = (cpu::rdmsr(IA32_VMX_ENTRY_CTLS) >> 32) & 0xffff_ffff;

        let pinbased_minimum   = pinbased_ctrl0 & pinbased_ctrl1;
        let procbased_minimum  = procbased_ctrl0 & procbased_ctrl1;
        let proc2based_minimum = proc2based_ctrl0 & proc2based_ctrl1;
        let exit_minimum       = exit_ctrl0 & exit_ctrl1;
        let entry_minimum      = entry_ctrl0 & entry_ctrl1;

        const HOST_ADDRESS_SPACE: u64 = 1 << 9;
        const UNRESTRICTED_GUEST: u64 = 1 << 7;
        const EPT: u64 = 1 << 1;

        let procbased_minimum = procbased_minimum | ACTIVATE_SECONDARY_CONTROLS;
        let proc2based_minimum = proc2based_minimum | UNRESTRICTED_GUEST | EPT;

        let exit_minimum = exit_minimum | HOST_ADDRESS_SPACE;

        cpu::vmwrite(PIN_BASED_CONTROLS, pinbased_minimum);
        cpu::vmwrite(PROC_BASED_CONTROLS, procbased_minimum);
        cpu::vmwrite(PROC2_BASED_CONTROLS, proc2based_minimum);
        cpu::vmwrite(EXIT_CONTROLS, exit_minimum);
        cpu::vmwrite(ENTRY_CONTROLS, entry_minimum);

        print!(
            "Pin Controls:   {:#010x}\n\
             Proc Controls:  {:#010x}\n\
             Proc2 Controls: {:#010x}\n\
             Exit Controls:  {:#010x}\n\
             Entry Controls: {:#010x}\n",
             pinbased_minimum, procbased_minimum, proc2based_minimum,
             exit_minimum, entry_minimum);

        const GUEST_ES:   u64 = 0x800;
        const GUEST_CS:   u64 = 0x802;
        const GUEST_SS:   u64 = 0x804;
        const GUEST_DS:   u64 = 0x806;
        const GUEST_FS:   u64 = 0x808;
        const GUEST_GS:   u64 = 0x80a;
        const GUEST_LDTR: u64 = 0x80c;
        const GUEST_TR:   u64 = 0x80e;

        cpu::vmwrite(GUEST_ES,   0);
        cpu::vmwrite(GUEST_CS,   0);
        cpu::vmwrite(GUEST_SS,   0);
        cpu::vmwrite(GUEST_DS,   0);
        cpu::vmwrite(GUEST_FS,   0);
        cpu::vmwrite(GUEST_GS,   0);
        cpu::vmwrite(GUEST_LDTR, 0);
        cpu::vmwrite(GUEST_TR,   0);

        const GUEST_IA32_DEBUGCTL: u64 = 0x2802;
        const GUEST_PAT:           u64 = 0x2804;
        const GUEST_EFER:          u64 = 0x2806;

        cpu::vmwrite(GUEST_IA32_DEBUGCTL, 0);
        cpu::vmwrite(GUEST_PAT,           0x0007_0406_0007_0406);
        cpu::vmwrite(GUEST_EFER,          0);

        const GUEST_ES_LIMIT:   u64 = 0x4800;
        const GUEST_CS_LIMIT:   u64 = 0x4802;
        const GUEST_SS_LIMIT:   u64 = 0x4804;
        const GUEST_DS_LIMIT:   u64 = 0x4806;
        const GUEST_FS_LIMIT:   u64 = 0x4808;
        const GUEST_GS_LIMIT:   u64 = 0x480a;
        const GUEST_LDTR_LIMIT: u64 = 0x480c;
        const GUEST_TR_LIMIT:   u64 = 0x480e;
        const GUEST_GDTR_LIMIT: u64 = 0x4810;
        const GUEST_IDTR_LIMIT: u64 = 0x4812;

        cpu::vmwrite(GUEST_ES_LIMIT,   0xffff);
        cpu::vmwrite(GUEST_CS_LIMIT,   0xffff);
        cpu::vmwrite(GUEST_SS_LIMIT,   0xffff);
        cpu::vmwrite(GUEST_DS_LIMIT,   0xffff);
        cpu::vmwrite(GUEST_FS_LIMIT,   0xffff);
        cpu::vmwrite(GUEST_GS_LIMIT,   0xffff);
        cpu::vmwrite(GUEST_LDTR_LIMIT, 0xffff);
        cpu::vmwrite(GUEST_TR_LIMIT,   0xffff);
        cpu::vmwrite(GUEST_GDTR_LIMIT, 0xffff);
        cpu::vmwrite(GUEST_IDTR_LIMIT, 0xffff);

        const GUEST_ES_ACCESS_RIGHTS:   u64 = 0x4814;
        const GUEST_CS_ACCESS_RIGHTS:   u64 = 0x4816;
        const GUEST_SS_ACCESS_RIGHTS:   u64 = 0x4818;
        const GUEST_DS_ACCESS_RIGHTS:   u64 = 0x481a;
        const GUEST_FS_ACCESS_RIGHTS:   u64 = 0x481c;
        const GUEST_GS_ACCESS_RIGHTS:   u64 = 0x481e;
        const GUEST_LDTR_ACCESS_RIGHTS: u64 = 0x4820;
        const GUEST_TR_ACCESS_RIGHTS:   u64 = 0x4822;

        cpu::vmwrite(GUEST_ES_ACCESS_RIGHTS,   0x93);
        cpu::vmwrite(GUEST_CS_ACCESS_RIGHTS,   0x93);
        cpu::vmwrite(GUEST_SS_ACCESS_RIGHTS,   0x93);
        cpu::vmwrite(GUEST_DS_ACCESS_RIGHTS,   0x93);
        cpu::vmwrite(GUEST_FS_ACCESS_RIGHTS,   0x93);
        cpu::vmwrite(GUEST_GS_ACCESS_RIGHTS,   0x93);
        cpu::vmwrite(GUEST_LDTR_ACCESS_RIGHTS, 0x82);
        cpu::vmwrite(GUEST_TR_ACCESS_RIGHTS,   0x83);

        const VMCS_64BIT_GUEST_LINK_POINTER: u64 = 0x00002800;
        cpu::vmwrite(VMCS_64BIT_GUEST_LINK_POINTER, !0);

        let minimum_cr0 =
            cpu::rdmsr(IA32_VMX_CR0_FIXED0) & cpu::rdmsr(IA32_VMX_CR0_FIXED1);

        // Allow use of CR0.PG=0 (paging disabled) and CR0.PE=0
        // (protected mode disbled)
        let minimum_cr0 = minimum_cr0 & !0x8000_0001;

        let minimum_cr4 = cpu::rdmsr(IA32_VMX_CR4_FIXED0)
            & cpu::rdmsr(IA32_VMX_CR4_FIXED1);

        const GUEST_CR0:       u64 = 0x6800;
        const GUEST_CR3:       u64 = 0x6802;
        const GUEST_CR4:       u64 = 0x6804;
        const GUEST_ES_BASE:   u64 = 0x6806;
        const GUEST_CS_BASE:   u64 = 0x6808;
        const GUEST_SS_BASE:   u64 = 0x680a;
        const GUEST_DS_BASE:   u64 = 0x680c;
        const GUEST_FS_BASE:   u64 = 0x680e;
        const GUEST_GS_BASE:   u64 = 0x6810;
        const GUEST_LDTR_BASE: u64 = 0x6812;
        const GUEST_TR_BASE:   u64 = 0x6814;
        const GUEST_GDTR_BASE: u64 = 0x6816;
        const GUEST_IDTR_BASE: u64 = 0x6818;
        const GUEST_DR7:       u64 = 0x681a;
        const GUEST_RSP:       u64 = 0x681c;
        const GUEST_RIP:       u64 = 0x681e;
        const GUEST_RFLAGS:    u64 = 0x6820;

        print!("Using guest cr0 {:#x}\n", minimum_cr0);

        cpu::vmwrite(GUEST_CR0,       minimum_cr0);
        cpu::vmwrite(GUEST_CR3,       0);
        cpu::vmwrite(GUEST_CR4,       minimum_cr4);
        cpu::vmwrite(GUEST_ES_BASE,   0);
        cpu::vmwrite(GUEST_CS_BASE,   0);
        cpu::vmwrite(GUEST_SS_BASE,   0);
        cpu::vmwrite(GUEST_DS_BASE,   0);
        cpu::vmwrite(GUEST_FS_BASE,   0);
        cpu::vmwrite(GUEST_GS_BASE,   0);
        cpu::vmwrite(GUEST_LDTR_BASE, 0);
        cpu::vmwrite(GUEST_TR_BASE,   0);
        cpu::vmwrite(GUEST_GDTR_BASE, 0);
        cpu::vmwrite(GUEST_IDTR_BASE, 0);
        cpu::vmwrite(GUEST_DR7,       0x0000_0400);
        cpu::vmwrite(GUEST_RSP,       0x7000);
        cpu::vmwrite(GUEST_RIP,       0x8100);
        cpu::vmwrite(GUEST_RFLAGS,    2);

        const HOST_CR0: u64 = 0x6c00;
        const HOST_CR3: u64 = 0x6c02;
        const HOST_CR4: u64 = 0x6c04;

        const HOST_ES: u64 = 0xc00;
        const HOST_CS: u64 = 0xc02;
        const HOST_SS: u64 = 0xc04;
        const HOST_DS: u64 = 0xc06;
        const HOST_FS: u64 = 0xc08;
        const HOST_GS: u64 = 0xc0a;
        const HOST_TR: u64 = 0xc0c;

        const HOST_FS_BASE: u64 = 0x6c06;
        const HOST_GS_BASE: u64 = 0x6c08;
        const HOST_TR_BASE: u64 = 0x6c0a;
        const HOST_GDTR_BASE: u64 = 0x6c0c;
        const HOST_IDTR_BASE: u64 = 0x6c0e;
        const HOST_IA32_SYSENTER_ESP: u64 = 0x6c10;
        const HOST_IA32_SYSENTER_EIP: u64 = 0x6c12;
        const HOST_RSP: u64 = 0x6c14;
        const HOST_RIP: u64 = 0x6c16;

        cpu::vmwrite(HOST_CR0, cpu::read_cr0());
        cpu::vmwrite(HOST_CR3, cpu::read_cr3());
        cpu::vmwrite(HOST_CR4, cpu::read_cr4());

        cpu::vmwrite(HOST_ES, cpu::read_es() as u64);
        cpu::vmwrite(HOST_CS, cpu::read_cs() as u64);
        cpu::vmwrite(HOST_SS, cpu::read_ss() as u64);
        cpu::vmwrite(HOST_DS, cpu::read_ds() as u64);
        cpu::vmwrite(HOST_FS, cpu::read_fs() as u64);
        cpu::vmwrite(HOST_GS, cpu::read_gs() as u64);
        cpu::vmwrite(HOST_TR, cpu::read_ds() as u64);

        cpu::vmwrite(HOST_FS_BASE, 0);
        cpu::vmwrite(HOST_GS_BASE, 0);
        cpu::vmwrite(HOST_TR_BASE, 0);
        cpu::vmwrite(HOST_GDTR_BASE, 0);
        cpu::vmwrite(HOST_IDTR_BASE, 0);
        cpu::vmwrite(HOST_IA32_SYSENTER_ESP, 0);
        cpu::vmwrite(HOST_IA32_SYSENTER_EIP, 0);

        print!("About to launch VM!\n");

        // Launch the VM
        llvm_asm!(r#"
            // Save HOST_RSP
            mov rax, 0x6c14
            vmwrite rax, rsp

            // Save HOST_RIP
            mov rax, 0x6c16
            lea rbx, [rip + 1f]
            vmwrite rax, rbx

            vmlaunch

        1:

        "# ::: "rax", "rbx", "memory", "cc" : "volatile", "intel");

        // Read the abort indicator from VMLAUNCH
        let abort_indicator =
            u32::from_le_bytes(vmcs_region[4..8].try_into().unwrap());

        print!("Abort indicator is {:#x}\n", abort_indicator);

        print!("VM exit:              {:#x}\n", cpu::vmread(EXIT_REASON));
        print!("VM instruction error: {:#x}\n", cpu::vmread(VM_INSTRUCTION_ERROR));
    }

    loop {}
}
