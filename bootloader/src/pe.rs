use core;
use core::mem::size_of;
use core::alloc::{Layout, GlobalAlloc};
use alloc::vec::Vec;
use mmu::{PageTable, MapSize, PTBits};
use safecast::SafeCast;

/* Number of PE directories */
const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/* Machine types */
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/* IMAGE_FILE_HEADER.Characteristics */
const IMAGE_FILE_EXECUTABLE_IMAGE:    u16 = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;

/* IMAGE_OPTIONAL_HEADER.Magic */
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

/* Constants for ImageOptionalHeader64.Subsystem */
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;

/* Constants for ImageSectionHeader.Characteristics */
const IMAGE_SCN_CNT_CODE:               u32 = 0x00000020;
const IMAGE_SCN_CNT_INITIALIZED_DATA:   u32 = 0x00000040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
const IMAGE_SCN_MEM_DISCARDABLE:        u32 = 0x02000000;
const IMAGE_SCN_MEM_EXECUTE:            u32 = 0x20000000;
const IMAGE_SCN_MEM_READ:               u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE:              u32 = 0x80000000;

/* Constants for ImageOptionalHeader64.DllCharacteristics */
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA:       u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:          u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT:             u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

/* Constants for relocation types */
const IMAGE_REL_BASED_ABSOLUTE: u16 =  0;
const IMAGE_REL_BASED_DIR64:    u16 = 10;

/// IMAGE_NT_HEADERS64
#[repr(C, packed)]
#[allow(non_snake_case)]
#[derive(Default, ByteSafe)]
struct ImageNtHeaders64 {
    Signature:      [u8; 4],
    FileHeader:     ImageFileHeader,
    OptionalHeader: ImageOptionalHeader64,
}

/// IMAGE_FILE_HEADER
#[repr(C, packed)]
#[allow(non_snake_case)]
#[derive(Default, ByteSafe)]
struct ImageFileHeader {
    Machine:              u16,
    NumberOfSections:     u16,
    TimeDateStamp:        u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols:      u32,
    SizeOfOptionalHeader: u16,
    Characteristics:      u16,
}

/// IMAGE_OPTIONAL_HEADER64
#[repr(C, packed)]
#[allow(non_snake_case)]
#[derive(Default, ByteSafe)]
struct ImageOptionalHeader64 {
    Magic:                       u16,
    MajorLinkerVersion:          u8,
    MinorLinkerVersion:          u8,
    SizeOfCode:                  u32,
    SizeOfInitializedData:       u32,
    SizeOfUninitializedData:     u32,
    AddressOfEntryPoint:         u32,
    BaseOfCode:                  u32,
    ImageBase:                   u64,
    SectionAlignment:            u32,
    FileAlignment:               u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion:           u16,
    MinorImageVersion:           u16,
    MajorSubsystemVersion:       u16,
    MinorSubsystemVersion:       u16,
    Win32VersionValue:           u32,
    SizeOfImage:                 u32,
    SizeOfHeaders:               u32,
    CheckSum:                    u32,
    Subsystem:                   u16,
    DllCharacteristics:          u16,
    SizeOfStackReserve:          u64,
    SizeOfStackCommit:           u64,
    SizeOfHeapReserve:           u64,
    SizeOfHeapCommit:            u64,
    LoaderFlags:                 u32,
    NumberOfRvaAndSizes:         u32,
    DataDirectory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

/// IMAGE_DATA_DIRECTORY
#[repr(C, packed)]
#[allow(non_snake_case)]
#[derive(Default, ByteSafe)]
struct ImageDataDirectory {
    VirtualAddress: u32,
    Size:           u32,
}

/// IMAGE_SECTION_HEADER
#[repr(C, packed)]
#[allow(non_snake_case)]
#[derive(Default, ByteSafe)]
struct ImageSectionHeader {
    Name:                 [u8; 8],
    VirtualSize:          u32,
    VirtualAddress:       u32,
    SizeOfRawData:        u32,
    PointerToRawData:     u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations:  u16,
    NumberOfLinenumbers:  u16,
    Characteristics:      u32,
}

/// DOS/MZ header for PE files
#[repr(C, packed)]
#[allow(non_snake_case)]
#[derive(Default, ByteSafe)]
struct DosHeader {
    signature:  [u8; 2],
    dont_care1: [u8; 0x20],
    dont_care2: [u8; 0x1a],
    pe_ptr:     u32,
}

/// Relocation structure
#[repr(C, packed)]
#[allow(non_snake_case)]
#[derive(Default, ByteSafe)]
struct ImageBaseRelocation {
    VirtualAddress: u32,
    SizeOfBlock:    u32,
}

/// Representation of a PE section
///
/// All addresses stored are full virtual addresses (not RVA)
pub struct PESection {
    /// Virtual address which is the base of this section
    vaddr: u64,

    /// Read permissions
    read: bool,

    /// Write permissions
    write: bool,

    /// Execute permissions
    execute: bool,

    /// Discard this section (aka, don't load it only contains information)
    discard: bool,

    /// Raw contents of this section
    ///
    /// Always non-zero length and zero-padded to nearest 4k length
    contents: Vec<u8>,
}

/// Parsed PE file structure
///
/// All addresses stored are full virtual addresses (not RVA)
pub struct PEParsed {
    /// Original base address of the PE, used for relocation delta calculation
    base_addr: u64,

    /// Virtual size of loaded image (4k aligned)
    size_of_image: u64,

    /// Entry point for the PE
    entry: u64,
    
    /// Vector of virtual addresses in the PE file which need to have a 64-bit
    /// offset applied based on the delta from the original base address.
    relocations: Vec<u64>,

    /// Section information for each section in the PE
    sections: Vec<PESection>,
}

impl PEParsed {
    /// Determine the loaded size of this PE.
    pub fn loaded_size(&self) -> u64
    {
        self.size_of_image
    }

    /// Load this PE into a given `page_table` relocated to `base`
    pub fn load(&self, page_table: &mut PageTable<::Pmem>, base: u64) -> u64
    {
        /* Base address must be 4k aligned and nonzero */
        assert!(base > 0 && (base & 0xfff) == 0,
            "PE loading base address must be 4k aligned and nonzero");

        /* Layout for raw pages */
        let layout = Layout::from_size_align(4096, 4096).unwrap();

        /* Determine the relocation delta from the original file base */
        let diff = base.wrapping_sub(self.base_addr);

        /* Make sure this PE can be relocated to desired location */
        assert!(page_table.can_map_memory(base, self.loaded_size()).unwrap(),
                "Cannot reserve memory to map PE file");

        /* Load all of the sections into the page table */
        for section in &self.sections {
            /* x86 limitation is that all sections must be readable */
            assert!(section.read == true, "Section mapped not readable");

            /* If the section should be discarded, skip it */
            if section.discard {
                continue;
            }

            /* For each page in the section, map it in */
            for ii in (0..section.contents.len()).step_by(4096) {
                /* Compute new virtual address after the relocation
                 * Due to can_map_memory() check at the start of the function
                 * this +ii is safe from overflows.
                 */
                let vaddr = section.vaddr.wrapping_add(diff) + ii as u64;

                unsafe {
                    /* Allocate a page */
                    let raw_page =
                        ::GLOBAL_ALLOCATOR.alloc(layout.clone()) as *mut u8;

                    /* Copy memory contents into page */
                    core::ptr::copy_nonoverlapping(
                        section.contents[ii..ii+4096].as_ptr(),
                        raw_page, 4096);

                    /* Permissions for allocation. Set the write flag,
                     * NX flag, and present flag as needed.
                     */
                    let perms =
                        if section.write { PTBits::Writable as u64 }
                        else { 0 } |
                        if !section.execute { PTBits::ExecuteDisable as u64 }
                        else { 0 } | PTBits::Present as u64;

                    /* Map the page into the page table */
                    page_table.map_page_raw(vaddr, raw_page as u64 | perms,
                                            MapSize::Mapping4KiB,
                                            false).unwrap();
                }
            }
        }

        /* Apply relocations */
        for relocation in &self.relocations {
            /* Adjust the relocation vaddr to use the new base */
            let relocation = relocation.wrapping_add(diff);

            /* We assume relocations are 8-byte aligned to prevent needing to
             * straddle a page boundry. Could be changed if this is ever
             * encountered.
             */
            assert!((relocation & 7) == 0, "Relocation not 8-byte aligned");

            /* Translate the relocation vaddr to phys */
            match page_table.virt_to_phys(relocation).unwrap() {
                Some((reloc_phys, _)) => unsafe {
                    /* Convert the relocation physical address to a mutable
                     * reference, and apply the relocation delta to it.
                     */
                    let rr = (reloc_phys as *mut u64).as_mut().unwrap();
                    *rr = rr.wrapping_add(diff);
                },
                None => panic!("Relocation vaddr not present"),
            }
        }

        /* Return relocated entry point */
        self.entry.wrapping_add(diff)
    }
}

/// Load a PE file into a PEParsed structure
///
/// This loader is extremely strict. It checks that all flags that matter are
/// verified to match what we have tested and expect. These flags are
/// implemented with exact matches or whitelists rather than blacklists to
/// ensure this never succeeds in an unknown environment.
pub fn parse(file: &Vec<u8>) -> PEParsed
{
    /* Make sure file is large enough for DOS header */
    assert!(file.len() >= size_of::<DosHeader>(),
        "File too small for MZ header");

    /* Parse DOS header and validate signature */
    let dos_hdr: DosHeader = file[..size_of::<DosHeader>()].cast_copy();
    assert!(&dos_hdr.signature == b"MZ", "No MZ magic present");

    /* Safely compute the end pointer of the PE header. Since this value is
     * controlled by the file, we need to be careful to make sure it doesn't
     * overflow with a checked_add().
     */
    let pe_ptr = dos_hdr.pe_ptr as usize;
    let pe_end = pe_ptr.checked_add(size_of::<ImageNtHeaders64>()).
        expect("Integer overflow on PE offset");

    /* Validate PE header bounds */
    assert!(file.len() >= pe_end, "File too small for PE header");

    /* Parse PE header and validate signature */
    let pe: ImageNtHeaders64 = file[pe_ptr..pe_end].cast_copy();
    assert!(&pe.Signature == b"PE\0\0", "No PE magic present");

    /* Strictly validate all fields we care about in the IMAGE_FILE_HEADER.
     * This might be too strict, but we can relax it if needed later.
     */
    assert!(pe.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64,
            "PE file was not for amd64 machines");

    assert!(pe.FileHeader.NumberOfSections > 0, "PE file has no sections");

    assert!(pe.FileHeader.SizeOfOptionalHeader as usize ==
            size_of::<ImageOptionalHeader64>(),
            "PE file optional header size mismatch");

    assert!(pe.FileHeader.Characteristics ==
            (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE),
            "PE file has unexpected characteristics");

    /* Strictly validate all fields we care about in the IMAGE_OPTIONAL_HEADER.
     * This might be too strict, but we can relax it if needed later.
     */
    assert!(pe.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            "PE file is not a 64-bit executable");

    assert!(pe.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE,
            "PE file is not of native subsystem type");

    assert!(pe.OptionalHeader.SectionAlignment == 4096,
            "PE section alignment was not 4096");

    assert!(pe.OptionalHeader.DllCharacteristics == (
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
            IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE),
            "PE had unexpected DllCharacteristics");

    assert!(pe.OptionalHeader.LoaderFlags == 0,
            "PE had unexpected LoaderFlags");

    /* Grab and 4k-align SizeOfImage */
    let size_of_image = (pe.OptionalHeader.SizeOfImage.checked_add(0xfff)
        .expect("Integer overflow on SizeOfImage") & !0xfff) as u64;
    assert!(size_of_image > 0, "PE SizeOfImage is zero");

    /* Holds whether or not we found an executable and initialized section
     * containing the entry point.
     */
    let mut entry_point_valid = false;

    /* Construct vector to hold sections */
    let mut sections =
        Vec::with_capacity(pe.FileHeader.NumberOfSections as usize);

    /* No relocations by default */
    let mut relocations = None;

    /* Go through each section as reported by the PE */
    let mut section_ptr = pe_end;
    for _ in 0..pe.FileHeader.NumberOfSections {
        /* Validate bounds of this IMAGE_SECTION_HEADER */
        let section_end = section_ptr.checked_add(
            size_of::<ImageSectionHeader>()).
            expect("PE section integer overflow");
        assert!(file.len() >= section_end, "PE section out of bounds");

        /* Create an IMAGE_SECTION_HEADER */
        let section: ImageSectionHeader =
            file[section_ptr..section_end].cast_copy();

        /* Validate alignment and section size */
        assert!((section.VirtualAddress & 0xfff) == 0,
            "PE section virtual address was not 4k aligned");
        if section.VirtualSize == 0 {
            continue;
        }

        /* Round up the virtual size to the nearest 4k boundry */
        let rounded_vsize = (section.VirtualSize.checked_add(0xfff).
            expect("PE section virtual size integer overflow") & !0xfff)
            as usize;

        /* Make sure raw data size is <= vitrual size */
        assert!(section.SizeOfRawData as usize <= rounded_vsize,
                "Section raw data larger than virtual size");
        
        /* Validate bounds of raw data */
        let rd_start = section.PointerToRawData as usize;
        let rd_end   = rd_start.checked_add(section.SizeOfRawData as usize).
            expect("PE section raw data integer overflow");
        assert!(rd_end <= file.len(), "PE section raw data out of bounds");

        /* We expect no relocations in the section header */
        assert!(section.NumberOfRelocations == 0,
                "PE section has relocations, not supported");

        /* Compute start and end virtual addresses of this section */
        let section_start_vaddr = pe.OptionalHeader.ImageBase
            .checked_add(section.VirtualAddress as u64)
            .expect("Overflow on ImageBase + section RVA");
        let section_end_vaddr = section_start_vaddr
            .checked_add(rounded_vsize as u64)
            .expect("Overflow on section VA + section vsize");

        /* Validate that this section is inside of the image virtual size */
        assert!((section_end_vaddr - pe.OptionalHeader.ImageBase) <=
                size_of_image, "Section outside of virtual image space");

        /* Create a 4k-aligned region of memory which represents this sections
         * virtual memory layout. Padded after the raw data with zero bytes.
         */
        let mut contents = vec![0u8; rounded_vsize];
        contents[..rd_end-rd_start].copy_from_slice(&file[rd_start..rd_end]);

        /* Grab permissions */
        let perm_r  = (section.Characteristics & IMAGE_SCN_MEM_READ)       !=0;
        let perm_w  = (section.Characteristics & IMAGE_SCN_MEM_WRITE)      !=0;
        let perm_x  = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)    !=0;
        let discard = (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)!=0;

        /* Check that no unknown characteristics are set */
        assert!((section.Characteristics & !(
                    IMAGE_SCN_MEM_READ |
                    IMAGE_SCN_MEM_WRITE |
                    IMAGE_SCN_MEM_EXECUTE |
                    IMAGE_SCN_MEM_DISCARDABLE |
                    IMAGE_SCN_CNT_INITIALIZED_DATA |
                    IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                    IMAGE_SCN_CNT_CODE
                    )) == 0, "Unknown section characteristic set");

        assert!(!(perm_x && perm_w), "Executable section also writable");

        if perm_x {
            /* If this is an executable section, check if the entry point
             * falls in it. We check based on the raw data such that the entry
             * point also doesn't point to padding zero bytes.
             */
            let entry = pe.OptionalHeader.AddressOfEntryPoint;
            if entry >= section.VirtualAddress &&
                    entry < section.VirtualAddress
                    .checked_add(section.SizeOfRawData).unwrap() {
                entry_point_valid = true;
            }
        }

        /* If this is a relocation section, parse out relocations */
        if &section.Name == b".reloc\0\0" {
            /* Validate entire virtual size is initialized */
            assert!(section.SizeOfRawData >= section.VirtualSize,
                    "Portion of .reloc section not initialized");
            
            /* Slice down the 4k aligned contents to an exact size as specified
             * by the VirtualSize.
             */
            let mut relocs = &contents[..section.VirtualSize as usize];

            /* Check if we already have seen a relocation section */
            assert!(relocations.is_none(),
                "Multiple relocation sections present");

            /* Allocate room for at least all relocations. Due to headers this
             * allocation will be a bit larger than needed, but that's fine.
             */
            let mut reloc_parsed = Vec::with_capacity(relocs.len() / 2);

            while relocs.len() > 0 {
                /* Validate bounds */
                assert!(relocs.len() >= size_of::<ImageBaseRelocation>(),
                    ".reloc section too small for header");

                /* Parse out one relocation record */
                let ibr: ImageBaseRelocation =
                    relocs[..size_of::<ImageBaseRelocation>()].cast_copy();

                /* Validate relocation record base address is 4k aligned */
                assert!((ibr.VirtualAddress & 0xfff) == 0,
                    "Relocation VirtualAddress not page aligned");

                /* Validate block size is in bounds and large enough for header
                 */
                let blocksz = ibr.SizeOfBlock as usize;
                assert!(blocksz >= size_of::<ImageBaseRelocation>() &&
                        blocksz <= relocs.len(),
                        "Invalid relocation section VirtualSize");

                /* Compute the size of the relocation block payload and seek
                 * relocs forward to it.
                 */
                let blocksz = blocksz - size_of::<ImageBaseRelocation>();
                relocs = &relocs[size_of::<ImageBaseRelocation>()..];

                /* We expect 2 bytes per entry, thus the blocksz should be
                 * evenly divisible by 2.
                 */
                assert!((blocksz % 2) == 0,
                    ".reloc section not evenly divisible by 2");

                /* Cast the relocs to a &[u16] */
                let type_offsets: &[u16] = relocs[..blocksz].cast();

                for to in type_offsets {
                    /* Parse offset and type from relocation */
                    let offset = (to & 0x0fff) >>  0;
                    let typ    = (to & 0xf000) >> 12;

                    /* Skip absolute relocations */
                    if typ == IMAGE_REL_BASED_ABSOLUTE {
                        continue;
                    }

                    /* Currently we only support DIR64 relocations */
                    assert!(typ == IMAGE_REL_BASED_DIR64,
                            "Unsupported relocation type");

                    /* Add relocation to the relocation list */
                    reloc_parsed.push(
                        pe.OptionalHeader.ImageBase
                        .checked_add(ibr.VirtualAddress as u64).unwrap()
                        .checked_add(offset as u64).unwrap());
                }

                relocs = &relocs[blocksz..];
            }

            relocations = Some(reloc_parsed);
        }

        /* Add section to list */
        sections.push(PESection {
            vaddr:    section_start_vaddr,
            read:     perm_r,
            write:    perm_w,
            execute:  perm_x,
            discard:  discard,
            contents: contents,
        });

        /* Seek to next section */
        section_ptr += size_of::<ImageSectionHeader>();
    }

    assert!(entry_point_valid, "Entry point was not in executable section");

    PEParsed {
        entry:
            pe.OptionalHeader.ImageBase
            .checked_add(pe.OptionalHeader.AddressOfEntryPoint as u64).unwrap(),

        base_addr:     pe.OptionalHeader.ImageBase,
        relocations:   relocations.unwrap_or(Vec::new()),
        sections:      sections,
        size_of_image: size_of_image,
    }
}

