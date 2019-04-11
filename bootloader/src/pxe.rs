use alloc::vec::Vec;

use core;
use serial;
use cpu;
use realmode;
use realmode::SegOff;

const STATIC_KERNEL_BUFFER_SIZE: usize = 1024 * 1024;

/// List of PXE opcodes we support using
enum PXEOpcode<'a> {
    /// PXE opcode for getting cached packets (and thus IP addresses)
    GetCachedInfo(&'a mut PXENV_CACHED_INFO),

    /// PXE opcode to get a file size
    GetFileSize(&'a mut PXENV_TFTP_GET_FSIZE),

    /// PXE opcode to open a file
    Open(&'a mut PXENV_TFTP_OPEN),

    /// PXE opcode to read
    Read(&'a mut PXENV_TFTP_READ),

    /// PXE opcode to close a file
    Close(&'a mut PXENV_TFTP_CLOSE),
}

/// PXENV+ structure
#[repr(C, packed)]
struct PXENV {
    /// "PXENV+"
    sig:           [u8; 6],

    /// API version number. MSB=major LSB=minor. NBPs and OS
    /// drivers must check for this version number. If the API version
    /// number is 0x0201 or higher, use the !PXE structure. If the API
    /// version number is less than 0x0201, then use the PXENV+
    /// structure.
    version:       u16,

    /// Length of this structure in bytes. This length must be used when
    /// computing the checksum of this structure.
    length:        u8,

    /// Used to make 8-bit checksum of this structure equal zero.
    checksum:      u8,

    /// Far pointer to real-mode PXE/UNDI API entry point. May be CS:0000h.
    rmentry:       SegOff,

    /// 32-bit offset to protected-mode PXE/UNDI API entry point. Do not
    /// use this entry point. For protected-mode API services, use the
    /// !PXE structure
    pmoffset:      u32,

    /// Protected-mode selector of protected-mode PXE/UNDI API entry
    /// point. Do not use this entry point. For protected-mode API
    /// services, use the !PXE structure.
    pmsel:         u16,

    /// Stack segment address. Must be set to 0 when removed from memory.
    stackseg:      u16,

    /// Stack segment size in bytes.
    stacksize:     u16,

    /// BC code segment address. Must be set to 0 when removed from memory.
    bc_codeseg:    u16,

    /// BC code segment size. Must be set to 0 when removed from memory.
    bc_codesize:   u16,

    /// BC data segment address. Must be set to 0 when removed from memory.
    bc_dataseg:    u16,

    /// BC data segment size. Must be set to 0 when removed from memory.
    bc_datasize:   u16,

    /// UNDI data segment address. Must be set to 0 when removed from memory.
    undi_dataseg:  u16,

    /// UNDI data segment size. Must be set to 0 when removed from memory.
    undi_datasize: u16,

    /// UNDI code segment address. Must be set to 0 when removed from memory.
    undi_codeseg:  u16,

    /// UNDI code segment size. Must be set to 0 when removed from memory.
    undi_codesize: u16,

    /// Real mode segment offset pointer to !PXE structure. This field is
    /// only present if the API version number is 2.1 or greater.
    pxeptr:        SegOff,
}

/// Structure passed in to PXE when the TFTP_GET_FSIZE command is used.
#[repr(C, packed)]
struct PXENV_TFTP_GET_FSIZE {
    /// See PXENV_STATUS_xxx constants.
    status:     u16,

    /// IP address of TFTP server in network order.
    server_ip:  u32,

    /// IP address of relay agent in network order. If
    /// this address is set to zero, the IP layer will resolve this using
    /// its own routing table.
    gateway_ip: u32,

    /// Name of file to be downloaded. Null terminated
    filename:   [u8; 128],

    /// Size of the file in bytes.
    filesize:   u32,
}

/// Structure passed in to PXE when the TFTP_OPEN command is used.
#[repr(C, packed)]
struct PXENV_TFTP_OPEN {
    /// See the PXENV_STATUS_xxx constants.
    status: u16,

    /// TFTP server IP address in network order.
    server_ip: u32,

    /// Relay agent IP address in network order. If this
    /// address is set to zero, the IP layer will resolve this using its own
    /// routing table. The IP layer should provide space for a minimum of
    /// four routing entries obtained from default router and static route
    /// DHCP option tags in the DHCPackr message, plus any non-zero
    /// GIADDR field from the DHCPOffer message(s) accepted by the
    /// client.
    gateway_ip: u32,

    /// Name of file to be downloaded. Null terminated.
    filename: [u8; 128],

    /// UDP port TFTP server is listening to requests on
    tftp_port: u16,

    /// In:  Requested size of TFTP packet, in bytes; with a
    ///      minimum of 512 bytes.
    /// Out: Negotiated size of TFTP packet, in bytes; less than or
    ///      equal to the requested size
    packetsize: u16,
}

/// Structure passed in to PXE when the TFTP_READ command is used.
#[repr(C, packed)]
struct PXENV_TFTP_READ {
    /// Out: See the PXENV_STATUS_xxx constants.
    status: u16,

    /// Out: Packet number (1-65535) sent from the TFTP server.
    packet_num:  u16,

    /// Out: Number of bytes written to the packet buffer. Last packet
    /// if this is less thanthe size negotiated in TFTP_OPEN. Zero is valid.
    buffer_size: u16,

    /// In: Segment:Offset address of packet buffer.
    buffer: SegOff,
}

/// Structure passed in to PXE when the TFTP_CLOSE command is used.
#[repr(C, packed)]
struct PXENV_TFTP_CLOSE {
    /// Out: See the PXENV_STATUS_xxx constants.
    status: u16,
}

/// Structure passed in to PXE when the CACHED_INFO command is used.
#[repr(C, packed)]
struct PXENV_CACHED_INFO {
    /// See the PXENV_STATUS_xxx constants.
    status:       u16,

    /// Type of cached packet being requested.
    packet_type:  u16,

    /// In:  Maximum number of bytes of data that can be copied into Buffer.
    /// Out: Number of bytes of data that have been copied
    ///      into Buffer. If BufferSize and Buffer were both set to zero,
    ///      this field will contain the amount of data stored in Buffer in
    ///      the BC data segment.
    buffer_size:  u16,

    /// In:  Segment:Offset address of storage to be filled in by API service
    /// Out: If BufferSize and Buffer were both set to zero, this
    ///      field will contain the segment:offset address of the Buffer in
    ///      the BC data segment.
    buffer_segoff: SegOff,

    /// Out: Maximum size of the Buffer in the BC data segment.
    buffer_limit: u16,
}

/// !PXE structure, obtained via get_pxe() on a PXENV structure.
#[repr(C, packed)]
struct PXE_STRUCT {
    /// "!PXE"
    sig: [u8; 4],

    /// Length of this structure in bytes. This length must be
    /// used when computing the checksum of this structure.
    length: u8,

    /// Used to make structure byte checksum equal zero.
    checksum: u8,

    /// Revision of this structure is zero. (0x00)
    revision: u8,

    /// Must be zero.
    reserved: u8,

    /// Real mode segment:offset of UNDI ROM ID structure.
    /// Check this structure if you need to know the UNDI API
    /// revision level. Filled in by UNDI loader module.
    undi_rom_id: SegOff,

    /// Real mode segment:offset of BC ROM ID structure. Must
    /// be set to zero if BC is removed from memory. Check this
    /// structure if you need to know the BC API revision level.
    /// Filled in by base-code loader module.
    base_rom_id: SegOff,

    /// PXE API entry point for 16-bit stack segment. This API
    /// entry point is in the UNDI code segment and must not be
    /// CS:0000h. Filled in by UNDI loader module.
    entry_point_sp: SegOff,

    /// PXE API entry point for 32-bit stack segment. May be
    /// zero. This API entry point is in the UNDI code segment
    /// and must not be CS:0000h. Filled in by UNDI loader
    /// module.
    entry_point_esp: SegOff,

    /// Far pointer to DHCP/TFTP status call-out procedure. If
    /// this field is -1, DHCP/TFTP will not make status calls. If
    /// this field is zero, DHCP/TFTP will use the internal status
    /// call-out procedure. StatusCallout defaults to zero.
    /// Note: The internal status call-out procedure uses BIOS
    /// I/O interrupts and will only work in real mode. This field
    /// must be updated before making any base-code API calls
    /// in protected mode.
    status_callout: SegOff,

    /// Must be zero.
    reserved2: u8,

    /// Number of segment descriptors needed in protected
    /// mode and defined in this table. UNDI requires four
    /// descriptors. UNDI plus BC requires seven.
    seg_desc_cnt: u8,

    /// First protected mode selector assigned to PXE.
    /// Protected mode selectors assigned to PXE must be
    /// consecutive. Not used in real mode. Filled in by
    /// application before switching to protected mode.
    first_selector: u16,
}

impl PXENV
{
    /// Compute checksum of this structure, should be zero if the structure
    /// is valid.
    fn checksum(&self) -> u8
    {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<PXENV>())
        };

        bytes.iter().fold(0u8, |acc, &x| acc.wrapping_add(x))
    }

    /// From this PXENV!, finds the !PXE structure and returns a reference
    /// to it.
    fn get_pxe(&self) -> &PXE_STRUCT
    {
        let pxe = unsafe {
            &*(self.pxeptr.to_linear() as *const PXE_STRUCT)
        };

        /* Check the validity of the !PXE structure */
        assert!(pxe.length as usize != core::mem::size_of::<PXE_STRUCT>(),
            "!PXE structure size not expected");
        assert!(pxe.checksum() == 0, "!PXE checksum invalid");
        assert!(&pxe.sig == b"!PXE", "'!PXE' signature missing");

        pxe
    }
}

impl PXE_STRUCT
{
    /// Compute checksum of this structure, should be zero if the structure
    /// is valid.
    fn checksum(&self) -> u8
    {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                self.length as usize)
        };

        bytes.iter().fold(0u8, |acc, &x| acc.wrapping_add(x))
    }

    /// Performs a PXE call
    ///
    /// This is marked unsafe as a caller can potentially corrupt memory
    /// depending on the PXE interface and parameters. Eg. issue a PXE read
    /// request to a buffer location that is already reserved/in use.
    unsafe fn pxecall(&self, opcode: PXEOpcode)
    {
        /* Convert the opcode enum into a PXE opcode and pointer to
         * PXE parameter.
         */
        let (opcode, param) = match opcode {
            PXEOpcode::GetCachedInfo(x)  => (0x71, x as *mut _ as u16),
            PXEOpcode::GetFileSize(x)    => (0x25, x as *mut _ as u16),
            PXEOpcode::Open(x)           => (0x20, x as *mut _ as u16),
            PXEOpcode::Read(x)           => (0x22, x as *mut _ as u16),
            PXEOpcode::Close(x)          => (0x21, x as *mut _ as u16),
        };

        /* Perform the PXE call */
        realmode::pxecall(self.entry_point_sp.seg,
                          self.entry_point_sp.off,
                          opcode, 0, param);
    }

    /// Read 'filename' from the PXE server, return the contents as a Vec
    /// of u8s.
    fn tftp_read_file(&self, filename: &str) -> Vec<u8>
    {
        /* Make sure there is room for the filename + null terminator in the
         * PXE request.
         */
        assert!(filename.as_bytes().len() < 128,
            "Filename too long for PXE TFTP read");

        /* Get the DHCP server IP from PXE cached info */
        let server_ip = {
            let mut cached_info = PXENV_CACHED_INFO {
                status:        0,
                packet_type:   2, /* Request the DHCP ACK packet */ 
                buffer_size:   0,
                buffer_segoff: SegOff { off: 0, seg: 0 },
                buffer_limit:  0,
            };

            /* Do a PXE call of PXENV_GET_CACHED_INFO to get the DHCP ACK
             * packet. We use this cached ACK packet to obtain the IP
             * address of the DHCP server so we can request the kernel from it.
             */
            unsafe { self.pxecall(PXEOpcode::GetCachedInfo(&mut cached_info)); }

            assert!(cached_info.status == 0,
                    "Failed to get cached PXE information");

            /* We crudely grab the IP address from the DHCP ack
             * packet at byte offset 0x14.
             */
            unsafe {
                *((cached_info.buffer_segoff.to_linear() + 0x14) as *const u32)
            }
        };

        let filesize = {
            /* Construct a TFTP_GET_FSIZE request for 'filename' */
            let mut file_size_req = PXENV_TFTP_GET_FSIZE {
                status:     0,
                server_ip:  server_ip,
                gateway_ip: 0,
                filename:   [0; 128],
                filesize:   0,
            };
            
            /* Copy the filename into the read request */
            file_size_req.filename[..filename.as_bytes().len()]
                .copy_from_slice(filename.as_bytes());

            /* Perform the TFTP_GET_FSIZE request */
            unsafe { self.pxecall(PXEOpcode::GetFileSize(&mut file_size_req)); }

            assert!(file_size_req.status == 0,
                    "TFTP_GET_FSIZE: Failed to get file size");
            assert!(file_size_req.filesize > 0,
                    "TFTP_GET_FSIZE: File size was zero bytes");

            file_size_req.filesize
        };

        /* Allocate room for the file to download */
        assert!(filesize as usize <= STATIC_KERNEL_BUFFER_SIZE,
                "Kernel size too large, increase STATIC_KERNEL_BUFFER_SIZE");
        let mut buf = Vec::with_capacity(STATIC_KERNEL_BUFFER_SIZE);

        /* Create a stack local buffer (which will be in real-mode addressable
         * space) for use as an intermediate buffer during reads.
         *
         * 1428 is the largest size for a UDP packet according to TFTP
         * blocksize spec RFC 2348
         */
        let low_buf = [0u8; 1428];

        let nego_psize = {
            /* Construct a TFTP_OPEN request for 'filename' */
            let mut tftp_open = PXENV_TFTP_OPEN {
                status:     0,
                server_ip:  server_ip,
                gateway_ip: 0,
                filename:   [0; 128],
                tftp_port:  69u16.to_be(),
                packetsize: low_buf.len() as u16,
            };

            /* Copy the filename into the read request */
            tftp_open.filename[0..filename.as_bytes().len()]
                .copy_from_slice(filename.as_bytes());

            /* Perform the PXENV_OPEN_FILE request */
            unsafe { self.pxecall(PXEOpcode::Open(&mut tftp_open)); }

            assert!(tftp_open.status == 0,
                    "PXENV_OPEN_FILE: Failed to open file");
            assert!(tftp_open.packetsize >= 512,
                    "Negotiated TFTP packet size was smaller than minimum");
            assert!(tftp_open.packetsize <= low_buf.len() as u16,
                    "Negotiated TFTP packet size was larger than expected");

            tftp_open.packetsize
        };

        {
            loop {
                /* Construct a TFTP_READ request for 'filename' */
                let mut tftp_read = PXENV_TFTP_READ {
                    status:      0,
                    packet_num:  0,
                    buffer_size: 0,
                    buffer:
                        SegOff {
                            seg: 0,
                            off: low_buf.as_ptr() as u16,
                        },
                };

                /* Perform the PXENV_READ request */
                unsafe { self.pxecall(PXEOpcode::Read(&mut tftp_read)); }

                assert!(tftp_read.status == 0, "Failed to read file");
                assert!(tftp_read.buffer_size <= nego_psize,
                        "PXENV_TFTP_READ: Read file returned more \
                         than negotiated at open");

                /* Check if this read will exceed the expected filesize
                 *
                 * This could happen if the file on the server increased in
                 * size after we got the initial filesize. We check later for
                 * a match of size, but this cancels the transfer once we
                 * notice there is an issue.
                 */
                assert!(buf.len()
                            .wrapping_add(tftp_read.buffer_size as usize) <=
                        filesize as usize,
                        "File larger than expected");

                buf.extend_from_slice(
                    &low_buf[..tftp_read.buffer_size as usize]);

                /* Resolution of the progress bar */
                const PROG_BAR_WIDTH: usize = 50;

                /* Fancy progress bar :D */
                let prog = (buf.len() * PROG_BAR_WIDTH) / (filesize as usize);
                serial::write("\r|");
                for _ in 0..prog { serial::write_byte(b'='); }
                for _ in prog..PROG_BAR_WIDTH { serial::write_byte(b' '); }
                serial::write_byte(b'|');
                
                /* Read ends when first packet of different packetsize than
                 * original is read.
                 */
                if tftp_read.buffer_size != nego_psize {
                    break;
                }
            }

            /* Newline to go to a newline after our progress bar */
            serial::write_byte(b'\n');

            assert!(buf.len() == filesize as usize,
                "TFTP read did not match expected number of bytes");
        }

        {
            /* Close the opened file */
            let mut tftp_close = PXENV_TFTP_CLOSE { status: 0 };
            unsafe { self.pxecall(PXEOpcode::Close(&mut tftp_close)); }
            assert!(tftp_close.status == 0, "Failed to close file");
        }

        /* Return buffer */
        buf
    }
}

/// Using PXE download file named `filename`
///
/// Returns a vector of bytes containing the file contents.
pub fn download_file(filename: &str) -> Vec<u8>
{
    if !cpu::is_bsp() {
        panic!("PXE routines are not allowed on non-BSP cores");
    }

    let pxenv = unsafe {
        let mut regs = realmode::RegisterState {
            eax: 0x5650, ..Default::default()
        };

        /* Invoke BIOS ax=0x5650 int 0x1a to get PXENV+ structure */
        realmode::invoke_realmode(0x1a, &mut regs);

        /* Check for carry flag */
        assert!((regs.efl & 1) == 0, "PXE installation check failed, CF set");

        /* Check for PXE magic */
        assert!(regs.eax == 0x564e, "PXE installation check failed, magic");

        /* Create segoff representing PXENV structure */
        let pxe_segoff = SegOff { seg: regs.es, off: regs.ebx as u16 };
        &*(pxe_segoff.to_linear() as *const PXENV)
    };

    /* Validate PXENV+ structure */
    assert!(core::mem::size_of::<PXENV>() == pxenv.length as usize,
        "PXENV+ structure was not of expected size");
    assert!(pxenv.checksum() == 0, "PXENV+ checksum invalid");
    assert!(&pxenv.sig == b"PXENV+", "PXE signature not present");
    assert!(pxenv.version == 0x0201, "PXE version invalid (expected 2.1)");

    pxenv.get_pxe().tftp_read_file(filename)
}

