use core;
use safecast::SafeCast;
use core::sync::atomic::{AtomicUsize, Ordering};
use rangeset::{Range, RangeSet};

const MAX_APICS: usize = 300;
const MAX_NODES: usize = 16;

static NUM_CORES: AtomicUsize = AtomicUsize::new(0);

static mut APICS: [Option<ApicInfo>; MAX_APICS] = [None; MAX_APICS];
static mut NODES: [Option<NodeInfo>; MAX_NODES] = [None; MAX_NODES];

#[derive(Clone, Copy)]
struct ApicInfo {
    _apic_id: usize,
    node_id: Option<usize>,
}

#[derive(Copy)]
struct NodeInfo {
    node_id:       usize,
    memory:        RangeSet,
    orig:          RangeSet,
    page_freelist: u64,
}
impl Clone for NodeInfo { fn clone(&self) -> Self { *self } }

#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],
    checksum:  u8,
    oem_id:    [u8; 6],
    revision:  u8,
    rsdt_addr: u32,
}

#[repr(C, packed)]
#[derive(Default, ByteSafe)]
struct MemAffinity {
    typ:         u8,
    length:      u8,
    numa_id:     u32,
    reserved1:   u16,
    memory_base: u64,
    memory_size: u64,
    reserved2:   u32,
    flags:       u32,
    reserved3:   u64,
}

#[derive(Default)]
#[repr(C, packed)]
struct AcpiStandardHeader {
    signature:        [u8; 4],
    length:           u32,
    revision:         u8,
    checksum:         u8,
    oem_id:           [u8; 6],
    oem_table_id:     [u8; 8],
    oem_revision:     u32,
    creator_id:       u32,
    creator_revision: u32,
}

/// Gets the NUMA node identifier associated with the processor identified by
/// `apic_id`
pub fn get_node_id(apic_id: usize) -> Option<usize> {
    let apics = unsafe { &mut APICS };

    if apic_id >= apics.len() || apics[apic_id].is_none() {
        return None;
    }

    apics[apic_id].as_ref().unwrap().node_id
}

/// Converts our internal 0-indexed sequential core indentifier to it's actualy
/// APIC ID
pub fn core_id_to_apic_id(core_id: usize) -> Option<usize> {
    let apics = unsafe { &mut APICS };

    let mut ac_cid = 0usize;
    for ii in 0..MAX_APICS {
        if apics[ii].is_none() {
            continue;
        }

        if ac_cid == core_id {
            return Some(ii);
        }

        ac_cid += 1;
    }

    return None;
}

pub unsafe fn init_aps() {
    let our_apic = cpu::get_apic_id();

    let apics = &mut APICS;

    for ii in 0..MAX_APICS {
        if apics[ii as usize].is_none() {
            continue;
        }

        if ii == our_apic {
            continue;
        }

        if !cpu::use_x2apic() {
            cpu::apic_write(0x310, (ii as u32) << 24);
            cpu::apic_write(0x300, 0x4500);
        } else {
            cpu::wrmsr(0x830, ((ii as u64) << 32) | 0x4500);
        }
    }
}

pub unsafe fn launch_ap(core_id: usize) -> bool {
    let our_apic = cpu::get_apic_id();

    if let Some(apic_id) = core_id_to_apic_id(core_id) {
        if our_apic == apic_id {
            panic!("Attempted to launch BSP");
        }

        if !cpu::use_x2apic() {
            cpu::apic_write(0x310, (apic_id as u32) << 24);
            cpu::apic_write(0x300, 0x4500);
            cpu::apic_write(0x310, (apic_id as u32) << 24);
            cpu::apic_write(0x300, 0x4608);
            cpu::apic_write(0x310, (apic_id as u32) << 24);
            cpu::apic_write(0x300, 0x4608);
            true
        } else {
            cpu::wrmsr(0x830, ((apic_id as u64) << 32) | 0x4500);
            cpu::wrmsr(0x830, ((apic_id as u64) << 32) | 0x4608);
            cpu::wrmsr(0x830, ((apic_id as u64) << 32) | 0x4608);
            true
        }
    } else {
        false
    }
}

/// Attempts to decode a raw ACPI table based on a pointer
unsafe fn get_table<'a>(table_addr: *const u8) ->
    Result<(AcpiStandardHeader, &'a [u8]), &'static str>
{
    let header = core::ptr::read(table_addr as *const AcpiStandardHeader);

    /* Sanity check header length */
    if (header.length as usize) < core::mem::size_of::<AcpiStandardHeader>() {
        return Err("ACPI table length too small");
    }

    /* Check that the checksum was correct */
    let payload = core::slice::from_raw_parts(table_addr,
                                              header.length as usize);
    let mut sum = 0u8;
    for val in payload.iter() { sum = sum.wrapping_add(*val) }
    if sum != 0 {
        return Err("ACPI table checksum mismatch");
    }

    Ok((header, &payload[core::mem::size_of::<AcpiStandardHeader>()..]))
}

/// Attempts to allocate physical `size` bytes with `align` alignment on
/// `node_id`
/// 
/// This is not thread safe.
pub unsafe fn node_alloc(size: usize, align: usize, node_id: usize)
        -> *mut u8 {
    let nodes = &mut NODES;

    if nodes[node_id].is_none() {
        panic!("Invalid node passed to node_alloc()");
    }

    let node = nodes[node_id].as_mut().unwrap();
    let ret = node.memory.allocate(size as u64, align as u64);

    ret
}

/// Allocate a 4 KiB page that is 4 KiB aligned
/// 
/// This is not thread safe.
pub unsafe fn node_alloc_page(node_id: usize) -> *mut u8 {
    let nodes = &mut NODES;

    if nodes[node_id].is_none() {
        panic!("Invalid node passed to node_alloc()");
    }

    let node = nodes[node_id].as_mut().unwrap();

    if node.page_freelist != 0 {
        // Return a page from the freelist
        let cur_entry  = node.page_freelist;
        let next_entry = core::ptr::read(cur_entry as *mut u64);
        node.page_freelist = next_entry;
        cur_entry as *mut u8
    } else {
        node_alloc(4096, 4096, node_id)
    }
}

/// Add a page to the free list
/// 
/// This is not thread safe.
pub unsafe fn node_free_page(node_id: usize, page: *mut u8) {
    assert!((page as u64) & 0xfff == 0, "Tried to free non-page-aligned page");
    
    let nodes = &mut NODES;

    if nodes[node_id].is_none() {
        panic!("Invalid node passed to node_alloc()");
    }

    let node = nodes[node_id].as_mut().unwrap();

    let cur_entry = node.page_freelist;
    core::ptr::write(page as *mut u64, cur_entry);
    node.page_freelist = page as u64;
}

/// Returns the total number of bytes free on the system on all NUMA nodes
pub fn memory_stats() -> u64 {
    let nodes = unsafe { &mut NODES };

    let mut node_free_sum = 0u64;
    for node in nodes.iter() {
        if node.is_none() { continue; }
        node_free_sum += node.as_ref().unwrap().memory.sum();
    }

    node_free_sum
}

/// Identify APICs and NUMA nodes on the system
pub unsafe fn init(e820: &RangeSet) -> Result<(), &'static str> {
    const VERBOSE: bool = true;

    let apics = { &mut APICS };
    let nodes = { &mut NODES };

    let mut num_nodes = 0u64;

    let mut rsdp: Option<Rsdp> = None;

    /* Address of the EBDA */
    let ebda = (*(0x40e as *const u16) as usize) << 4;

    /* ACPI spec says to search the first 1 KiB of the EBDA for RSDP as well
     * as BIOS read-only memory space from 0xe0000 to 0xfffff
     */
    let ranges = [(ebda, ebda + 1024), (0xe0000, 0x100000)];

    /* Get the value of "RSD PTR " as a u64 */
    let rsd_magic: u64 = "RSD PTR ".as_bytes().cast_copy();

    'range_loop: for &(range_low, range_high) in &ranges {
        /* This should never happen because EDBA is << 4 and we specify the
         * other range. But it's nice to show our intent.
         *
         * ACPI manual says RSDP is always aligned on a 16-byte boundry
         */
        assert!(range_high > range_low && (range_low & 0xf) == 0 &&
                (range_high & 0xf) == 0,
                "Range is not 16-byte aligned or is invalid");

        /* Step through each 16-byte aligned address */
        for addr in (range_low..range_high).step_by(16) {
            /* Compute number of remaining bytes in this section */
            let remain = range_high - addr;

            /* Make sure we have enough bytes in this section to contain the
             * RSDP.
             */
            if remain < core::mem::size_of::<Rsdp>() {
                break;
            }

            /* Check if it has the RSDP magic */
            if *(addr as *const u64) != rsd_magic {
                continue;
            }

            /* Create a byte slice of the RSDP structure */
            let rsdp_bytes = core::slice::from_raw_parts(
                addr as *const u8, core::mem::size_of::<Rsdp>());

            /* Compute the 8-bit checksum and make sure it is zero. If it is
             * not zero, this is a bad match and we should skip it.
             */
            let sum = rsdp_bytes.iter()
                .fold(0u8, |acc, &x| acc.wrapping_add(x));
            if sum != 0 {
                continue;
            }

            /* We found the RSDP! */
            rsdp = Some(core::ptr::read(addr as *const Rsdp));
            break 'range_loop;
        }
    }

    /* Check if our search for the RSDP was successful. If it wasn't, return
     * out an error. Otherwise, unwrap it.
     */
    let rsdp = if let Some(rsdp) = rsdp {
        rsdp
    } else {
        return Err("Failed to find RSD PTR");
    };

    /* Create a copy of the RSDT and validate the checksum */
    let (_, rsdt_bytes) = get_table(rsdp.rsdt_addr as *const u8)?;
    if (rsdt_bytes.len() % 4) != 0 {
        return Err("RSDT table length not divisible by 4");
    }
    let rsdt: &[u32] = rsdt_bytes.cast();

    for table in rsdt {
        /* Go through each table in the RSDT and validate the checksum */
        let (hdr, bytes) = get_table(*table as *const u8)?;

        /* Handle 'APIC' table */
        if &hdr.signature == b"APIC" {
            if bytes.len() < 8 {
                return Err("Invalid MADT table size");
            }

            let mut madt_payload = &bytes[8..];

            /* Payload length must be at least 2 bytes to hold type and
             * record length.
             */
            while madt_payload.len() >= 2 {
                let typ     = madt_payload[0];
                let rec_len = madt_payload[1];

                /* Bounds check */
                if rec_len < 2 || (rec_len as usize) > madt_payload.len() {
                    return Err("Invalid MADT record length");
                }

                if typ == 0 {
                    /* Type 0 indicates a legacy Local APIC record */
                    /* Local APIC records must be 8 bytes */
                    if rec_len != 8 {
                        return Err("MADT legacy APIC record length invalid");
                    }

                    let _proc_id   = madt_payload[2] as usize;
                    let apic_id    = madt_payload[3] as usize;
                    let flags: u32 = madt_payload[4..8].cast_copy();

                    if apic_id >= MAX_APICS {
                        return Err("MADT APIC ID too large");
                    }

                    /* If the APIC is enabled */
                    if (flags & 1) != 0 {
                        NUM_CORES.fetch_add(1, Ordering::Relaxed);
                        apics[apic_id] = Some(ApicInfo {
                            _apic_id: apic_id,
                            node_id: None,
                        });
                    }
                } else if typ == 9 {
                    /* Type 9 indicates a Local x2APIC record */
                    if rec_len != 16 {
                        return Err("MADT x2APIC record length invalid");
                    }

                    let apic_id: u32 = madt_payload[4..8].cast_copy();
                    let flags:   u32 = madt_payload[8..12].cast_copy();
                    let apic_id = apic_id as usize;
                    
                    if apic_id >= MAX_APICS {
                        return Err("MADT x2APIC ID too large");
                    }

                    /* If the APIC is enabled */
                    if (flags & 1) != 0 {
                        NUM_CORES.fetch_add(1, Ordering::Relaxed);
                        apics[apic_id] = Some(ApicInfo {
                            _apic_id: apic_id,
                            node_id: None,
                        });
                    }
                }

                madt_payload = &madt_payload[rec_len as usize..];
            }
        }
    }

    let mut seen_srat = false;

    for table in rsdt {
        /* Go through each table in the RSDT and validate the checksum */
        let (hdr, bytes) = get_table(*table as *const u8)?;

        if !seen_srat && hdr.signature == "SRAT".as_bytes() {
            /* Dell workstation we have tested on has multiple SRATs, the
             * second is broken...
             */
            seen_srat = true;

            if bytes.len() < 12 {
                return Err("Invalid SRAT table size");
            }

            let mut srat_payload = &bytes[12..];

            /* Payload length must be at least 2 bytes to hold type and
             * record length.
             */
            while srat_payload.len() >= 2 {
                let typ     = srat_payload[0];
                let rec_len = srat_payload[1];

                /* Bounds check */
                if rec_len < 2 || (rec_len as usize) > srat_payload.len() {
                    return Err("Invalid SRAT record length");
                }

                if typ == 0 {
                    /* Legacy APIC/SAPIC affinity structure */
                    if rec_len != 16 {
                        return
                            Err("SRAT APIC affinity structure size invalid");
                    }

                    let apic_id        = srat_payload[3] as usize;
                    let flags: u32     = srat_payload[4..8].cast_copy();
                    let high_numa: u32 = srat_payload[8..12].cast_copy();
                    let numa_id        = ((srat_payload[2] as u32) |
                                          (high_numa & 0xffffff00)) as usize;

                    if apic_id >= MAX_APICS {
                        return Err("SRAT APIC ID too large");
                    }

                    if numa_id >= MAX_NODES {
                        return Err("SRAT APIC NUMA ID too large");
                    }

                    /* Check if this entry is enabled */
                    if (flags & 1) != 0 {
                        if apics[apic_id].is_none() {
                            return Err("SRAT entry maps invalid APIC id");
                        }

                        let spec_apic = apics[apic_id].as_mut().unwrap();

                        /* Validate that this APIC has not been mapped to a
                         * node already. This is pedantic, if we find ACPI
                         * implementations that map multiple, we can change
                         * this to a check that both mapping refer to the same
                         * node. If that fails we could change this to just
                         * replacing the with the latest mapping.
                         *
                         * Some systems have multiple SRATs, but we filter
                         * to only use one. The system that we observed
                         * multiple SRATs on has an invalid second SRAT. Stay
                         * classy Dell...
                         */
                        if spec_apic.node_id.is_some() {
                            return Err("SRAT entry double maps APIC id");
                        }

                        /* For the corresponding APIC, set up that it maps
                         * to this node.
                         */
                        spec_apic.node_id = Some(numa_id);
                    }
                } else if typ == 2 {
                    /* x2APIC affinity structure */
                    if rec_len != 24 {
                        return
                            Err("SRAT x2APIC affinity structure size invalid");
                    }

                    let numa_id: u32 = srat_payload[4..8].cast_copy();
                    let apic_id: u32 = srat_payload[8..12].cast_copy();
                    let flags:   u32 = srat_payload[12..16].cast_copy();
                    let numa_id = numa_id as usize;
                    let apic_id = apic_id as usize;

                    if apic_id >= MAX_APICS {
                        return Err("SRAT x2APIC ID too large");
                    }

                    if numa_id >= MAX_NODES {
                        return Err("SRAT x2APIC NUMA ID too large");
                    }

                    /* Check if this entry is enabled */
                    if (flags & 1) != 0 {
                        if apics[apic_id].is_none() {
                            return Err("SRAT entry maps invalid x2APIC id");
                        }

                        let spec_apic = apics[apic_id].as_mut().unwrap();

                        /* Validate that this APIC has not been mapped to a
                         * node already. This is pedantic, if we find ACPI
                         * implementations that map multiple, we can change
                         * this to a check that both mapping refer to the same
                         * node. If that fails we could change this to just
                         * replacing the with the latest mapping.
                         *
                         * Some systems have multiple SRATs, but we filter
                         * to only use one. The system that we observed
                         * multiple SRATs on has an invalid second SRAT. Stay
                         * classy Dell...
                         */
                        if spec_apic.node_id.is_some() {
                            return Err("SRAT entry double maps x2APIC id");
                        }

                        /* For the corresponding APIC, set up that it maps
                         * to this node.
                         */
                        spec_apic.node_id = Some(numa_id);
                    }
                } else if typ == 1 {
                    /* Memory affinity structure */
                    if rec_len as usize !=
                            core::mem::size_of::<MemAffinity>() {
                        return
                            Err("SRAT memory affinity structure size invalid");
                    }

                    /* Get an affinity structure */
                    let affin: MemAffinity =
                        srat_payload[..core::mem::size_of::<MemAffinity>()].
                        cast_copy();

                    if (affin.numa_id as usize) >= MAX_NODES {
                        return Err("SRAT affinity NUMA ID too large");
                    }

                    /* If this affinity is present */
                    if (affin.flags & 1) != 0 {
                        /* Create a new node if one doesn't exist for this
                         * numa_id.
                         */
                        if nodes[affin.numa_id as usize].is_none() {
                            nodes[affin.numa_id as usize] = Some(
                                NodeInfo {
                                    node_id:       affin.numa_id as usize,
                                    memory:        RangeSet::new(),
                                    orig:          RangeSet::new(),
                                    page_freelist: 0,
                                });
                            num_nodes += 1;
                        }

                        let node =
                            nodes[affin.numa_id as usize].as_mut().unwrap();

                        /* Insert this range into the global affinity table */
                        node.memory.insert(
                            Range {
                                start: affin.memory_base,
                                end:   affin.memory_base + affin.memory_size-1,
                            });
                        node.orig.insert(
                            Range {
                                start: affin.memory_base,
                                end:   affin.memory_base + affin.memory_size-1,
                            });
                    }
                }

                srat_payload = &srat_payload[rec_len as usize..];
            }
        }
    }

    if num_nodes == 0 {
        // This happens when there is a single node. Sometimes ACPI doesn't
        // report memory ranges so we'll just back down to the E820
        // We saw this on our Lenovo machine
        print!("No NUMA nodes reporting, creating a single node with E820\n");

        nodes[0] = Some(
            NodeInfo {
                node_id:       0,
                memory:        e820.clone(),
                orig:          e820.clone(),
                page_freelist: 0,
        });
    }

    /* Invert the memory map, getting the list if unusable ranges */
    let mut inverted = RangeSet::new();
    inverted.insert(Range{ start: 0, end: !0 });
    inverted.subtract(e820);

    /* From each node's mapping, remove this inverted range. Nodes will only
     * contain usable memory at this point.
     */
    for node in nodes.iter_mut() {
        if node.is_none() { continue; }
        node.as_mut().unwrap().memory.subtract(&inverted);
    }

    /* Compute the amount of free memory in all nodes */
    let mut node_free_sum = 0u64;
    for node in nodes.iter() {
        if node.is_none() { continue; }
        let free_mem = node.as_ref().unwrap().memory.sum();

        num_nodes += 1;

        if VERBOSE {
            print!("Node {:08x} | {} bytes free\n",
                node.as_ref().unwrap().node_id,
                free_mem);
        }

        node_free_sum += node.as_ref().unwrap().memory.sum();
    }
    
    if node_free_sum != e820.sum() {
        print!("Node free memory did not match E820 free memory {} {}\n",
            node_free_sum, e820.sum());
        return Err("Node free memory did not match E820 free memory");
    }

    print!("Detected {} CPUs\n", NUM_CORES.load(Ordering::Relaxed));

    Ok(())
}
