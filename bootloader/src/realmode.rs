extern {
    /// Invoke a realmode software interrupt, for BIOS calls
    /// 
    /// # Summary
    ///
    /// When this function is invoked, the register state is populated with
    /// the fields supplied from `register_state`, excluding segments, efl and
    /// esp. Once this context is loaded, a software interrupt of `int_num` is
    /// performed. Once the software interrupt is complete, the new register
    /// state is saved off to `register_state`, including segments, efl and
    /// esp fields.
    ///
    /// # Parameters
    ///
    /// * `int_num`        - Software interrupt number to invoke
    /// * `register_state` - Input/output context for interrupt
    ///
    pub fn invoke_realmode(int_num: u8, regs: &mut RegisterState);

    /// Invoke a PXE call using the real-mode PXE stack.
    /// 
    /// # Summary
    ///
    /// This function is used to invoke the real-mode PXE APIs provided by the
    /// EntryPointSP entry of the !PXE structure. The seg:off provided by
    /// EntryPointSP is what should be used for the first 2 parameters of this
    /// function. Provided the right real-mode stack, you then provide a PXE
    /// opcode in the `pxe_call` parameter, and point `param_seg`:`param_off`
    /// at the buffer describing the structure used by the opcode specified.
    ///
    /// # Parameters
    ///
    /// * `seg`       - Code segment of the real-mode PXE stack
    /// * `off`       - Code offset of the real-mode PXE stack
    /// * `pxe_call`  - PXE call opcode
    /// * `param_seg` - Data segment for the PXE parameter
    /// * `param_off` - Data offset for the PXE parameter
    ///
    pub fn pxecall(seg: u16, off: u16, pxe_call: u16,
                   param_seg: u16, param_off: u16);
}

/// Structure representing general purpose i386 register state
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RegisterState {
    pub eax: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebx: u32,
    pub esp: u32,
    pub ebp: u32,
    pub esi: u32,
    pub edi: u32,
    pub efl: u32,

    pub es: u16,
    pub ds: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

/// Simple SegOff structure for things that contain a segment and offset.
#[repr(C, packed)]
pub struct SegOff {
    pub off: u16,
    pub seg: u16,
}

impl SegOff {
    /// Convert a seg:off real-mode address into a linear 32-bit address
    pub fn to_linear(&self) -> usize
    {
        ((self.seg as usize) << 4) + (self.off as usize)
    }
}

