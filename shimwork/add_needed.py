#!/usr/bin/env python3
"""Add a DT_NEEDED entry to an arm64 ELF shared library without patchelf.

Strategy:
 - The new string goes into the zero padding between PT_LOAD[0]'s current end
   (p_filesz) and the next segment's offset. LOAD[0]'s p_filesz/p_memsz are
   extended to cover it. The DT_NEEDED value is expressed relative to the
   existing DT_STRTAB base so the linker finds it at strtab_base + value.
 - The new .dynamic table is appended at the end of the file, page aligned,
   and the last PT_LOAD's p_filesz/p_memsz are extended to cover it.
   PT_DYNAMIC is repointed to the new table.
"""
import struct, sys

ELF_MAGIC = b"\x7fELF"
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_NEEDED, DT_STRTAB = 0, 1, 5


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]
def p64(v): return struct.pack("<Q", v)


def main(src, dst, needed, str_off):
    with open(src, "rb") as f:
        data = bytearray(f.read())

    assert data[:4] == ELF_MAGIC and data[4] == 2 and data[5] == 1, "not a 64-bit LE ELF"
    e_phoff = u64(data, 0x20)
    e_phentsize = u16(data, 0x36)
    e_phnum = u16(data, 0x38)
    phdrs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        phdrs.append({
            "type": u32(data, o),
            "flags": u32(data, o + 4),
            "offset": u64(data, o + 8),
            "vaddr": u64(data, o + 16),
            "paddr": u64(data, o + 24),
            "filesz": u64(data, o + 32),
            "memsz": u64(data, o + 40),
            "align": u64(data, o + 48),
        })

    loads = [p for p in phdrs if p["type"] == PT_LOAD]
    dyns = [p for p in phdrs if p["type"] == PT_DYNAMIC]
    assert len(dyns) == 1 and len(loads) >= 2, "unexpected phdr layout"
    dyn_ph = dyns[0]

    # read the old dynamic entries
    entries = []
    strtab = 0
    o = dyn_ph["offset"]
    for _ in range(dyn_ph["filesz"] // 16):
        tag, val = u64(data, o), u64(data, o + 8)
        o += 16
        if tag == DT_STRTAB:
            strtab = val
        if tag == DT_NULL:
            break
        entries.append((tag, val))

    assert strtab, "no DT_STRTAB"
    print(f"old dynamic: {len(entries)} entries, DT_STRTAB=0x{strtab:x}")

    # string placement inside the LOAD[0]..next-segment padding
    loads_sorted = sorted(loads, key=lambda p: p["offset"])
    first = loads_sorted[0]
    gap_start = first["offset"] + first["filesz"]
    gap_end = loads_sorted[1]["offset"] if len(loads_sorted) > 1 else gap_start
    s = needed.encode() + b"\x00"
    # keep the string inside the gap but in the *mapped* (extended) range
    assert gap_end - gap_start >= 64, "no padding gap between first segments"
    str_file_off = gap_start + 16
    if str_off:
        str_file_off = int(str_off, 0)
    assert gap_start <= str_file_off and str_file_off + len(s) <= gap_end, \
        "string does not fit in the padding gap"
    needed_val = str_file_off - strtab  # strtab-relative
    print(f"string at file 0x{str_file_off:x} (strtab-relative 0x{needed_val:x})")
    data[str_file_off:str_file_off + len(s)] = s

    # extend LOAD[0] to cover the string
    first["filesz"] = gap_end - first["offset"]
    first["memsz"] = max(first["memsz"], first["filesz"])

    # append the new dynamic table at the end of the file, page aligned
    page = 0x1000
    new_dyn_off = (len(data) + page - 1) & ~(page - 1)
    # extend DT_STRSZ so the linker's get_string CHECK 'index < strtab_size_'
    # passes for our string index (the exec path validates every string).
    DT_STRSZ = 10
    patched_entries = []
    for t, v in entries:
        if t == DT_STRSZ:
            v = max(v, needed_val + len(s))
            print(f"extended DT_STRSZ to 0x{v:x}")
        patched_entries.append((t, v))
    new_dyn = b"".join(p64(t) + p64(v) for t, v in patched_entries)
    new_dyn += p64(DT_NEEDED) + p64(needed_val)
    new_dyn += p64(DT_NULL) + p64(0)
    data.extend(b"\x00" * (new_dyn_off - len(data)))
    data.extend(new_dyn)
    new_end = len(data)

    # extend the last PT_LOAD to cover the appended table
    last = loads_sorted[-1]
    assert new_dyn_off >= last["offset"], "append region before last LOAD?"
    last["filesz"] = new_end - last["offset"]
    last["memsz"] = max(last["memsz"], last["filesz"])

    # repoint PT_DYNAMIC
    dyn_ph["offset"] = new_dyn_off
    dyn_ph["vaddr"] = new_dyn_off
    dyn_ph["paddr"] = new_dyn_off
    dyn_ph["filesz"] = len(new_dyn)
    dyn_ph["memsz"] = len(new_dyn)

    # write the phdrs back
    for i, p in enumerate(phdrs):
        o = e_phoff + i * e_phentsize
        struct.pack_into("<II", data, o, p["type"], p["flags"])
        struct.pack_into("<QQQQQQ", data, o + 8, p["offset"], p["vaddr"], p["paddr"],
                         p["filesz"], p["memsz"], p["align"])

    # Android's linker validates that the .dynamic section header matches
    # PT_DYNAMIC, so fix the section header too.
    e_shoff = u64(data, 0x28)
    e_shentsize = u16(data, 0x3A)
    e_shnum = u16(data, 0x3C)
    e_shstrndx = u16(data, 0x3E)
    shstr_o = e_shoff + e_shstrndx * e_shentsize
    shstr_off = u64(data, shstr_o + 24)
    patched = False
    for i in range(e_shnum):
        so = e_shoff + i * e_shentsize
        name_off = u32(data, so) + shstr_off
        end = data.find(b"\x00", name_off)
        name = data[name_off:end].decode("ascii", "replace")
        if name == ".dynamic":
            struct.pack_into("<QQQ", data, so + 16, new_dyn_off, new_dyn_off, len(new_dyn))
            patched = True
            print(f"patched .dynamic section header #{i}: offset/addr=0x{new_dyn_off:x}, size=0x{len(new_dyn):x}")
    assert patched, ".dynamic section header not found"

    # Android 16+ caps the linker's strtab_size_ with the .dynstr section size
    # (when section headers are present). If the injected string index exceeds
    # the .dynstr section size, get_string() CHECK 'index < strtab_size_' aborts
    # the process at load time - extend the section so the index stays in range.
    patched_dynstr = False
    for i in range(e_shnum):
        so = e_shoff + i * e_shentsize
        name_off = u32(data, so) + shstr_off
        end = data.find(b"\x00", name_off)
        name = data[name_off:end].decode("ascii", "replace")
        if name == ".dynstr":
            old_size = u64(data, so + 32)
            new_size = max(old_size, needed_val + len(s))
            struct.pack_into("<Q", data, so + 32, new_size)
            patched_dynstr = True
            print(f"patched .dynstr section header #{i}: size 0x{old_size:x} -> 0x{new_size:x}")
    assert patched_dynstr, ".dynstr section header not found"

    with open(dst, "wb") as f:
        f.write(data)
    print(f"wrote {dst} ({len(data)} bytes), new .dynamic at 0x{new_dyn_off:x}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
