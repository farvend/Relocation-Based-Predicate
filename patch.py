import pefile
import struct
import sys


def main():
    exe_path = r"C:\Users\Ad\AppData\Local\Temp\rust-build\release\deps\dead_branch.exe"
    output_path = exe_path.replace(".exe", "_patched.exe")

    # VA .quad 0 из BN (после jmp, перед imul)
    quad_va = 0x00011021+1  # ← адрес .quad 0 напрямую, без +2

    pe = pefile.PE(exe_path)
    imagebase = pe.OPTIONAL_HEADER.ImageBase
    operand_rva = quad_va - imagebase - 2 # -2 так как эти байта точно будут 0
    operand_foff = pe.get_offset_from_rva(operand_rva)

    reloc_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    reloc_rva = reloc_dir.VirtualAddress
    reloc_size = reloc_dir.Size
    reloc_foff = pe.get_offset_from_rva(reloc_rva)

    pe_sig_offset = struct.unpack_from("<I", pe.__data__, 0x3C)[0]
    opt_hdr_offset = pe_sig_offset + 24
    dd_size_foff = opt_hdr_offset + 112 + 5 * 8 + 4

    reloc_section_size = None
    for s in pe.sections:
        if b".reloc" in s.Name:
            reloc_section_size = s.SizeOfRawData
            break

    pe.close()

    with open(exe_path, "rb") as f:
        data = bytearray(f.read())

    val = struct.unpack_from("<Q", data, operand_foff)[0]
    print(f"[*] .quad VA        : 0x{quad_va:X}")
    print(f"[*] .quad RVA       : 0x{operand_rva:X}")
    print(f"[*] .quad FileOff   : 0x{operand_foff:X}")
    print(f"[*] Значение        : 0x{val:016X}")

    # if val != 0:
    #     print(f"[!] Ожидались нули!")
    #     sys.exit(1)

    page_rva = operand_rva & ~0xFFF
    offset_in_page = operand_rva & 0xFFF
    entry_word = (0xA << 12) | offset_in_page
    reloc_block = bytearray(struct.pack("<IIHH", page_rva, 12, entry_word, 0))

    insert_pos = 0
    pos = 0
    while pos < reloc_size:
        block_page = struct.unpack_from("<I", data, reloc_foff + pos)[0]
        block_sz = struct.unpack_from("<I", data, reloc_foff + pos + 4)[0]
        if block_sz == 0:
            break
        if block_page > page_rva:
            insert_pos = pos
            break
        pos += block_sz
        insert_pos = pos

    if reloc_section_size and (reloc_size + 12) > reloc_section_size:
        sys.exit("[!] Нет места в секции .reloc")

    abs_insert = reloc_foff + insert_pos
    before = bytes(data[reloc_foff : abs_insert])
    after = bytes(data[abs_insert : reloc_foff + reloc_size])
    new_reloc = before + bytes(reloc_block) + after
    data[reloc_foff : reloc_foff + len(new_reloc)] = new_reloc

    new_size = reloc_size + 12
    struct.pack_into("<I", data, dd_size_foff, new_size)

    print(f"[+] Релокация: Page=0x{page_rva:X}  Offset=0x{offset_in_page:X}")
    print(f"[+] DD Size: 0x{reloc_size:X} -> 0x{new_size:X}")

    with open(output_path, "wb") as f:
        f.write(data)

    print(f"[+] Сохранено -> {output_path}")


if __name__ == "__main__":
    main()