#![no_std]
#![feature(asm)]

extern crate rangeset;

pub const MAX_CPUS: usize = 256;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct BootloaderStruct {
    /// If this is the BSP then this is a rangeset representing the free
    /// physical memory on the system.
    pub phys_memory: rangeset::RangeSet,

    /// Address to jump to perform a soft reboot
    pub soft_reboot_entry: u64,

    /// Pointer to KernelBuffer
    pub kernel_buffer: u64,
}

#[repr(C)]
pub struct KernelBuffer {
    pub kernel_buffer: u64,
    pub kernel_buffer_size: u64,
    pub kernel_buffer_max_size: u64,
}

/// Output the byte `val` to `port`
pub unsafe fn out8(port: u16, val: u8)
{
    asm!("out dx, al" :: "{al}"(val), "{dx}"(port) :: "intel", "volatile");
}

/// Input a byte from `port`
pub unsafe fn in8(port: u16) -> u8
{
    let ret: u8;
    asm!("in al, dx" : "={al}"(ret) : "{dx}"(port) :: "intel", "volatile");
    ret
}

/// Output the dword `val` to `port`
pub unsafe fn out32(port: u16, val: u32)
{
    asm!("out dx, eax" :: "{eax}"(val), "{dx}"(port) :: "intel", "volatile");
}

/// Input a dword from `port`
pub unsafe fn in32(port: u16) -> u32
{
    let ret: u32;
    asm!("in eax, dx" : "={eax}"(ret) : "{dx}"(port) :: "intel", "volatile");
    ret
}

/// Disable interrupts and halt forever
pub fn halt() -> !
{
    loop {
        unsafe {
            asm!("cli ; hlt" :::: "volatile");
        }
    }
}

/// Performs a rdmsr instruction on the msr specified by `msr`. Returns
/// 64-bit MSR contents.
#[inline(always)]
pub unsafe fn rdmsr(msr: u32) -> u64
{
	let high: u32;
	let low:  u32;

    asm!("rdmsr" :
         "={edx}"(high), "={eax}"(low) : "{ecx}"(msr) :
         "memory" :
         "volatile", "intel");

	return ((high as u64) << 32) | (low as u64);
}

/// Performs a wrmsr instruction on the msr specified by `msr`, writes `val`
#[inline(always)]
pub unsafe fn wrmsr(msr: u32, val: u64)
{
	asm!("wrmsr" ::
		 "{ecx}"(msr), "{eax}"(val as u32), "{edx}"((val >> 32) as u32) :
		 "memory" :
         "volatile", "intel");
}

/// Reads the contents of DR7
#[inline(always)]
pub unsafe fn read_dr7() -> u64
{
    let dr7;
    asm!("mov $0, dr7" : "=r"(dr7) ::: "intel", "volatile");
    dr7
}

#[cfg(target_pointer_width = "64")]
#[inline(always)]
/// Reads the contents of CR8
pub unsafe fn read_cr8() -> u64
{
    let cr8;
    asm!("mov $0, cr8" : "=r"(cr8) ::: "intel", "volatile");
    cr8
}

/// Reads the contents of CR3
#[inline(always)]
pub unsafe fn read_cr3() -> u64
{
    let cr3: u64;
    asm!("mov $0, cr3" : "=r"(cr3) ::: "intel", "volatile");
    cr3 & 0xffff_ffff_ffff_f000
}

/// Reads the contents of CR2
#[inline(always)]
pub unsafe fn read_cr2() -> u64
{
    let cr2;
    asm!("mov $0, cr2" : "=r"(cr2) ::: "intel", "volatile");
    cr2
}

/// Writes to dr0
#[inline(always)]
pub unsafe fn write_dr0(val: u64)
{
    asm!("mov dr0, $0" :: "r"(val) :: "intel", "volatile");
}

/// Writes to dr1
#[inline(always)]
pub unsafe fn write_dr1(val: u64)
{
    asm!("mov dr1, $0" :: "r"(val) :: "intel", "volatile");
}

/// Writes to dr2
#[inline(always)]
pub unsafe fn write_dr2(val: u64)
{
    asm!("mov dr2, $0" :: "r"(val) :: "intel", "volatile");
}

/// Writes to dr3
#[inline(always)]
pub unsafe fn write_dr3(val: u64)
{
    asm!("mov dr3, $0" :: "r"(val) :: "intel", "volatile");
}

/// Writes to CR2
#[inline(always)]
pub unsafe fn write_cr2(val: u64)
{
    asm!("mov cr2, $0" :: "r"(val) :: "intel", "volatile");
}

/// Writes to CR3
#[inline(always)]
pub unsafe fn write_cr3(val: u64)
{
    asm!("mov cr3, $0" :: "r"(val) : "memory" : "intel", "volatile");
}

/// Reads the contents of CR4
#[inline(always)]
pub unsafe fn read_cr4() -> u64
{
    let cr4;
    asm!("mov $0, cr4" : "=r"(cr4) ::: "intel", "volatile");
    cr4
}

/// Writes to CR4
#[inline(always)]
pub unsafe fn write_cr4(val: u64)
{
    asm!("mov cr4, $0" :: "r"(val) :: "intel", "volatile");
}

/// Load the interrupt table specified by vaddr
#[inline(always)]
pub unsafe fn lidt(vaddr: *const u8)
{
	asm!("lidt [$0]" ::
		 "r"(vaddr) :
		 "memory" :
		 "volatile", "intel");
}

/// Load the GDT specified by vaddr
#[inline(always)]
pub unsafe fn lgdt(vaddr: *const u8)
{
	asm!("lgdt [$0]" ::
		 "r"(vaddr) :
		 "memory" :
		 "volatile", "intel");
}

/// Load the task register with the segment specified by tss_seg.
#[inline(always)]
pub unsafe fn ltr(tss_seg: u16)
{
	asm!("ltr cx" :: "{cx}"(tss_seg) :: "volatile", "intel");
}

/// Write back all memory and invalidate caches
#[inline(always)]
pub fn wbinvd() {
    unsafe {
    	asm!("wbinvd" ::: "memory" : "volatile", "intel");
    }
}

/// Memory fence for both reads and writes
#[inline(always)]
pub fn mfence() {
    unsafe {
    	asm!("mfence" ::: "memory" : "volatile", "intel");
    }
}

/// Flushes cache line associted with the byte pointed to by `ptr`
#[inline(always)]
pub unsafe fn clflush(ptr: *const u8) {
    asm!("clflush [$0]" :: "r"(ptr as usize) : "memory" : "volatile", "intel");
}

/// Instruction fence (via write cr2) which serializes execution
#[inline]
pub fn ifence() {
    unsafe {
    	write_cr2(0);
    }
}

/// Read a random number and return it
#[inline(always)]
pub fn rdrand() -> u64 {
    let val: u64;
    unsafe {
    	asm!("rdrand $0" : "=r"(val) ::: "volatile", "intel");
    }
    val
}

/// Performs a rdtsc instruction, returns 64-bit TSC value
#[inline(always)]
pub fn rdtsc() -> u64
{
	let high: u32;
	let low:  u32;

    unsafe {
        asm!("rdtsc" :
             "={edx}"(high), "={eax}"(low) :::
             "volatile", "intel");
    }

	return ((high as u64) << 32) | (low as u64);
}

/// Performs a rdtscp instruction, returns 64-bit TSC value
#[inline(always)]
pub fn rdtscp() -> u64
{
	let high: u32;
	let low:  u32;

    unsafe {
        asm!("rdtscp" :
             "={edx}"(high), "={eax}"(low) :: "ecx" :
             "volatile", "intel");
    }

	return ((high as u64) << 32) | (low as u64);
}

/// Performs cpuid passing in eax and ecx as parameters. Returns a tuple
/// containing the resulting (eax, ebx, ecx, edx)
#[inline(always)]
pub unsafe fn cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32)
{
    let (oeax, oebx, oecx, oedx);

    asm!("cpuid" :
         "={eax}"(oeax), "={ebx}"(oebx), "={ecx}"(oecx), "={edx}"(oedx) :
         "{eax}"(eax), "{ecx}"(ecx) :: "volatile", "intel");

    (oeax, oebx, oecx, oedx)
}

/// Returns true if the current CPU is the BSP, otherwise returns false.
pub fn is_bsp() -> bool
{
    (unsafe { rdmsr(0x1b) } & (1 << 8)) != 0
}

/// Decrement the interrupt level. If the resulting interrupt level is 0,
/// enable interrupts.
#[inline(always)]
pub unsafe fn interrupts_enable()
{
	asm!("sti" :::: "volatile");
}

/// Disable interrupts and then increment the interrupt level.
#[inline(always)]
pub unsafe fn interrupts_disable()
{
	asm!("cli" :::: "volatile");
}

#[derive(Default, Debug)]
pub struct CPUFeatures {
    pub max_cpuid: u32,
    pub max_extended_cpuid: u32,

    pub fpu: bool,
    pub vme: bool,
    pub de:  bool,
    pub pse: bool,
    pub tsc: bool,
    pub mmx: bool,
    pub fxsr: bool,
    pub sse: bool,
    pub sse2: bool,
    pub htt: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub xsave: bool,
    pub avx: bool,
    pub apic: bool,

    pub lahf: bool,
    pub lzcnt: bool,
    pub prefetchw: bool,

    pub syscall: bool,
    pub xd: bool,
    pub gbyte_pages: bool,
    pub rdtscp: bool,
    pub bits64: bool,

    pub avx512f: bool,
}

/// Set the xcr0 register to a given value
pub unsafe fn write_xcr0(val: u64)
{
    asm!("xsetbv" :: "{ecx}"(0), "{eax}"(val as u32),
        "{edx}"((val >> 32) as u32) :: "intel", "volatile");
}

/// Get set of CPU features
pub fn get_cpu_features() -> CPUFeatures
{
    let mut features: CPUFeatures = Default::default();

    unsafe {
        features.max_cpuid          = cpuid(0, 0).0;
        features.max_extended_cpuid = cpuid(0x80000000, 0).0;

        if features.max_cpuid >= 1 {
            let cpuid_1 = cpuid(1, 0);
            features.fpu  = ((cpuid_1.3 >>  0) & 1) == 1;
            features.vme  = ((cpuid_1.3 >>  1) & 1) == 1;
            features.de   = ((cpuid_1.3 >>  2) & 1) == 1;
            features.pse  = ((cpuid_1.3 >>  3) & 1) == 1;
            features.tsc  = ((cpuid_1.3 >>  4) & 1) == 1;
            features.apic = ((cpuid_1.3 >>  9) & 1) == 1;
            features.mmx  = ((cpuid_1.3 >> 23) & 1) == 1;
            features.fxsr = ((cpuid_1.3 >> 24) & 1) == 1;
            features.sse  = ((cpuid_1.3 >> 25) & 1) == 1;
            features.sse2 = ((cpuid_1.3 >> 26) & 1) == 1;
            features.htt  = ((cpuid_1.3 >> 28) & 1) == 1;

            features.sse3    = ((cpuid_1.2 >>  0) & 1) == 1;
            features.ssse3   = ((cpuid_1.2 >>  9) & 1) == 1;
            features.sse4_1  = ((cpuid_1.2 >> 19) & 1) == 1;
            features.sse4_2  = ((cpuid_1.2 >> 20) & 1) == 1;
            features.xsave   = ((cpuid_1.2 >> 26) & 1) == 1;
            features.avx     = ((cpuid_1.2 >> 28) & 1) == 1;
        }

        if features.max_cpuid >= 7 {
            let cpuid_7 = cpuid(7, 0);
            features.avx512f = ((cpuid_7.1 >> 16) & 1) == 1;
        }

        if features.max_extended_cpuid >= 0x80000001 {
            let cpuid_e1 = cpuid(0x80000001, 0);

            features.lahf      = ((cpuid_e1.2 >> 0) & 1) == 1;
            features.lzcnt     = ((cpuid_e1.2 >> 5) & 1) == 1;
            features.prefetchw = ((cpuid_e1.2 >> 8) & 1) == 1;

            features.syscall     = ((cpuid_e1.3 >> 11) & 1) == 1;
            features.xd          = ((cpuid_e1.3 >> 20) & 1) == 1;
            features.gbyte_pages = ((cpuid_e1.3 >> 26) & 1) == 1;
            features.rdtscp      = ((cpuid_e1.3 >> 27) & 1) == 1;
            features.bits64      = ((cpuid_e1.3 >> 29) & 1) == 1;
        }
    }

    features
}

/// Get a random 64-bit value seeded with the TSC. This is crude but it works
/// early in the boot process. PXE network delays should make this have a
/// reasonable amount of entropy for boot-to-boot differences. But of course
/// should not be used for crypto.
pub fn rdtsc_rand() -> u64
{
    let mut init = rdtsc();

    /* 64 rounds of xorshift */
    for _ in 0..64 {
        init ^= init << 13;
        init ^= init >> 17;
        init ^= init << 43;
    }

    init
}

/// Canonicalize a 64-bit address such that bits [63:48] are sign extended
/// from bit 47
pub fn canonicalize_address(addr: u64) -> u64
{
    let mut addr: i64 = addr as i64;

    /* Canon addresses are 48-bits sign extended. Do a shift left by 16 bits
     * to mask off the top bits, then do an arithmetic shift right (note i64
     * type) to sign extend the 47th bit.
     */
    addr <<= 64 - 48;
    addr >>= 64 - 48;

    addr as u64
}

pub unsafe fn apic_read(offset: isize) -> u32
{
    assert!((offset & 0xf) == 0, "APIC offset not 4-byte aligned");
    assert!(offset >= 0 && offset < 4096, "APIC offset out of bounds");

    if !use_x2apic() {
        let apic = 0xfee00000 as *mut u32;
        core::ptr::read_volatile(apic.offset(offset / 4))
    } else {
        let msr = 0x800 + (offset >> 4);
        rdmsr(msr as u32) as u32
    }
}

pub unsafe fn apic_write(offset: isize, val: u32)
{
    assert!((offset & 0xf) == 0, "APIC offset not 4-byte aligned");
    assert!(offset >= 0 && offset < 4096, "APIC offset out of bounds");

    if !use_x2apic() {
        let apic = 0xfee00000 as *mut u32;
        core::ptr::write_volatile(apic.offset(offset / 4), val);
    } else {
        let msr = 0x800 + (offset >> 4);
        wrmsr(msr as u32, val as u64);
    }
}

pub fn use_x2apic() -> bool {
    unsafe {
        (cpuid(1, 0).2 & (1 << 21)) != 0
    }
}

/// Get current cores APIC ID
pub fn get_apic_id() -> usize
{
    unsafe {
        if use_x2apic() {
            apic_read(0x20) as usize
        } else {
            ((apic_read(0x20) >> 24) & 0xff) as usize
        }
    }
}

/// Initialize the APIC of this core
pub unsafe fn apic_init()
{
    /* Globally enable the APIC by setting EN in IA32_APIC_BASE_MSR */
    wrmsr(0x1b, rdmsr(0x1b) | (1 << 11));

    if use_x2apic() {
        /* If the x2apic is supported, enable x2apic mode */
        wrmsr(0x1b, rdmsr(0x1b) | (1 << 10));
    }

	/* Enable the APIC */
	apic_write(0xf0, 0x1ff);
}

/// Invalidate the page specified by `addr`
#[inline(always)]
pub unsafe fn invlpg(addr: usize)
{
    asm!("invlpg [$0]" :: "r"(addr) : "memory" : "volatile", "intel");
}
