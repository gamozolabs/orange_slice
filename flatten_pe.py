import sys, struct

IMAGE_FILE_MACHINE_I386 = 0x014c

MIN_ADDR = 0x10000
MAX_ADDR = 0x20000

if len(sys.argv) != 3:
    print("Usage: flatten_pe.py <input PE> <output flat name>")

pe_file = open(sys.argv[1], "rb").read()

# Check for MZ
assert pe_file[:2] == b"MZ", "No MZ header present"

# Grab pointer to PE header
pe_ptr = struct.unpack("<I", pe_file[0x3c:0x40])[0]

# Make new buffer with PE contents, check for magic
pe_header = pe_file[pe_ptr:]

signature, machine, num_sections, timedatestamp, symtable_pointer, \
        symtable_num, opthdr_size, characteristics, coff_magic, \
        major_linker, minor_linker, code_size, init_data_size, \
        uninit_data_size, entry, code_base, data_base, image_base, \
        section_align, file_align, majoros, minoros, majorimg, \
        minorimg, majorsubsys, minorsubsys, win32ver, image_size, \
        header_size, checksum, subsystem, dll_characteristics, \
        stack_reserve, stack_commit, heap_reserve, heap_commit, \
        loader_flags, num_tables = \
        struct.unpack("<IHHIIIHHHBBIIIIIIIIIHHHHHHIIIIHHIIIIII", \
        pe_header[:0x78])

assert signature == 0x00004550, "No PE magic present"
assert machine   == IMAGE_FILE_MACHINE_I386, "PE file is not 32-bit x86"
assert section_align == 0x1000, "Expected 4k aligned sections"

section_table = pe_header[0x18 + opthdr_size:]

sections = []
for _ in range(num_sections):
    name, vsize, vaddr, raw_data_size, raw_data_ptr, relocs, linenums, \
            num_relocs, num_linenums, characteristics = \
            struct.unpack("<QIIIIIIHHI", section_table[:0x28])
    section_table = section_table[0x28:]

    # Round up vsize to nearest 4k
    rounded_vsize = (vsize + 0xfff) & ~0xfff

    vaddr = vaddr + image_base
    vend  = vaddr + rounded_vsize

    assert vend > vaddr
    assert raw_data_size <= rounded_vsize
    assert vaddr >= MIN_ADDR and vaddr <  MAX_ADDR
    assert vend  >  MIN_ADDR and vend  <= MAX_ADDR

    # Skip zero sized raw data sections
    if raw_data_size <= 0:
        continue

    sections.append((vaddr, vend, \
            pe_file[raw_data_ptr:raw_data_ptr+raw_data_size]))

flattened = bytearray()
for (vaddr, vend, raw_data) in sections:
    # Should never happen as this is checked above
    assert len(raw_data) > 0

    print("%.8x %.8x" % (vaddr, len(raw_data)))

    flattened += struct.pack("<II", vaddr, len(raw_data))
    flattened += raw_data

with open(sys.argv[2], "wb") as fd:
    fd.write(struct.pack("<I", image_base + entry))
    fd.write(struct.pack("<I", len(sections)))
    fd.write(flattened)

