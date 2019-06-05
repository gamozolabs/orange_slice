[bits 16]
[org  0x7c00]

struc flatpe
	.entry:    resd 1
	.sections: resd 1
	.payload:
endstruc

struc flatpe_section
	.vaddr: resd 1
	.size:  resd 1
	.data:
endstruc

entry:
	; Disable interrupts and clear the direction flag
	cli
	cld

	; Set the A20 line
	in    al, 0x92
	or    al, 2
	out 0x92, al

	; Zero out DS for the lgdt
	xor ax, ax
	mov ds, ax

	; Load the gdt (for 32-bit protected mode)
	lgdt [ds:pm_gdt]

	; Set the protection bit
	mov eax, cr0
	or  eax, (1 << 0)
	mov cr0, eax

	; Jump to protected mode!
	jmp 0x0008:pm_entry

[bits 32]

pm_entry:
	; Set data segments for protected mode
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Set up a stack
	mov esp, 0x7c00

	; Zero out entire range where kernel can be loaded [0x10000, 0x20000)
	; This is our way of initializing all sections to zero so we only populate
	; sections with raw data
	mov edi, 0x10000
	mov ecx, 0x20000 - 0x10000
	xor eax, eax
	rep stosb

	; Get number of sections
	mov eax, [rust_entry + flatpe.sections]
	lea ebx, [rust_entry + flatpe.payload]
.lewp:
	test eax, eax
	jz   short .end

	mov edi, [ebx + flatpe_section.vaddr]
	lea esi, [ebx + flatpe_section.data]
	mov ecx, [ebx + flatpe_section.size]
	rep movsb

	add ebx, [ebx + flatpe_section.size]
	add ebx, flatpe_section_size
	dec eax
	jmp short .lewp
	
.end:
	; Jump into Rust!
	push dword kernel_buffer     ; kernel_buffer:     *mut KernelBuffer
	push dword [first_boot]      ; first_boot:        bool
	push dword soft_reboot_entry ; soft_reboot_entry: u32

	; Set that this is no longer the first boot
	mov dword [first_boot], 0

	call dword [rust_entry + flatpe.entry]

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; 16-bit real mode GDT

align 8
rmgdt_base:
	dq 0x0000000000000000 ; Null descriptor
	dq 0x00009a000000ffff ; 16-bit RO code, base 0, limit 0x0000ffff
	dq 0x000092000000ffff ; 16-bit RW data, base 0, limit 0x0000ffff

rmgdt:
	dw (rmgdt - rmgdt_base) - 1
	dq rmgdt_base
	
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; 32-bit protected mode GDT

align 8
pm_gdt_base:
	dq 0x0000000000000000
	dq 0x00CF9A000000FFFF
	dq 0x00CF92000000FFFF

pm_gdt:
	dw (pm_gdt - pm_gdt_base) - 1
	dd pm_gdt_base

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

align 8
reentry_longjmp:
	dd rmmode_again
	dw 0x0008

align 8
rm_idt:
	dw 0xffff
	dq 0

align 8
rm_gdt:
	dw 0xffff
	dq 0

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; Tracks if this is the first boot or not. This gets cleared to zero on the
; first boot, allowing the bootloader to know if it is in a soft reboot or
; not. This changes whether or not it needs to start up PXE again.
first_boot: dd 1

kernel_buffer:          dq 0
kernel_buffer_size:     dq 0
kernel_buffer_max_size: dq 0

; Boot magic
times 510-($-$$) db 0
dw 0xAA55

times 0x400-($-$$) db 0

[bits 16]

; Address 0x8000
ap_entry:
	; Disable interrupts and clear the direction flag
	cli
	cld

	; Zero out DS for the lgdt
	xor ax, ax
	mov ds, ax

	; Load the gdt (for 32-bit protected mode)
	lgdt [ds:pm_gdt]

	; Set the protection bit
	mov eax, cr0
	or  eax, (1 << 0)
	mov cr0, eax

	; Jump to protected mode!
	jmp 0x0008:ap_pm_entry

times 0x500-($-$$) db 0

[bits 16]

; Addres 0x8100
vm_entry:
	mov di, 0xb800
	mov es, di
	xor di, di
	mov cx, 80 * 25
	xor ax, ax
	rep stosw

	mov di, 0xb800
	mov es, di
	xor di, di
	mov cx, 80
	mov ax, 0x0f41
	rep stosw

	cli
	hlt
	jmp vm_entry

[bits 64]

soft_reboot_entry:
	cli

	; Set up a stack
	mov esp, 0x7c00

	; Clear registers
	xor rax, rax
	mov rbx, rax
	mov rcx, rax
	mov rdx, rax
	mov rsi, rax
	mov rdi, rax
	mov rbp, rax
	mov  r8, rax
	mov  r9, rax
	mov r10, rax
	mov r11, rax
	mov r12, rax
	mov r13, rax
	mov r14, rax
	mov r15, rax

	lgdt [rmgdt]

	; Must be far dword for Intel/AMD compatibility. AMD does not support
	; 64-bit offsets in far jumps in long mode, Intel does however. Force
	; it to be 32-bit as it works in both.
	jmp far dword [reentry_longjmp]

[bits 16]

align 16
rmmode_again:
	; Disable paging
	mov eax, cr0
	btr eax, 31
	mov cr0, eax

	; Disable long mode
	mov ecx, 0xc0000080
	rdmsr
	btr eax, 8
	wrmsr

	; Load up the segments to be 16-bit segments
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Disable protected mode
	mov eax, cr0
	btr eax, 0
	mov cr0, eax

	; Zero out all GPRs (clear out high parts for when we go into 16-bit)
	xor eax, eax
	mov ebx, eax
	mov ecx, eax
	mov edx, eax
	mov esi, eax
	mov edi, eax
	mov ebp, eax
	mov esp, 0x7c00

	; Reset the GDT and IDT to their original boot states
	lgdt [rm_gdt]
	lidt [rm_idt]

	; Jump back to the start of the bootloader
	jmp 0x0000:0x7c00

[bits 32]

ap_pm_entry:
	; Set data segments for protected mode
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Set up a stack
	mov esp, 0x7c00

	; Jump into Rust!
	push dword 0                 ; kernel_buffer:     *mut KernelBuffer
	push dword 0                 ; first_boot:        bool
	push dword soft_reboot_entry ; soft_reboot_entry: u32
	call dword [rust_entry + flatpe.entry]

rust_entry:
incbin "stage1.flat"

