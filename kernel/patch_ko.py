#!/usr/bin/env python3
"""Turn the module's unresolved kernel imports into absolute symbols.

The R5G kernel (4.19.125-perf, S2011 #2) does not export ~40 symbols that
KernelSU-Next needs (do_mount, selinux_state, init_mm, __set_fixmap, ...).
CONFIG_MODULE_FORCE_LOAD is off, so insmod would fail with "Unknown symbol".

Instead of editing KSU's source, rewrite the .ko's symbol table: every
undefined symbol that exists in the kernel's own symbol table is turned into
SHN_ABS with value = kbase + offset.  The module loader then treats it as a
local definition and relocates the instruction directly -- no export table,
no CRC checks.

Usage:
  patch_ko.py <in.ko> <out.ko> <kbase-hex> <syms-file>

syms-file lines: "<name> <offset-in-hex-from-_text>"
"""
import struct
import sys

SHN_ABS = 0xFFF1
SHT_SYMTAB = 2


def load_syms(path):
    m = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    m[parts[0]] = int(parts[1], 16)
                except ValueError:
                    pass
    return m


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        return 1
    src, dst, kbase_s, syms_path = sys.argv[1:5]
    kbase = int(kbase_s, 16)
    syms = load_syms(syms_path)

    data = bytearray(open(src, "rb").read())
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        print("not a little-endian ELF64")
        return 1

    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    def shdr(i):
        return struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)

    shstr = shdr(e_shstrndx)
    shstr_off = shstr[4]

    patched = []
    unresolved = []
    for i in range(e_shnum):
        sh = shdr(i)
        if sh[1] != SHT_SYMTAB:
            continue
        strtab = shdr(sh[6])
        stroff = strtab[4]
        entsize = sh[9] or 24
        for k in range(sh[5] // entsize):
            soff = sh[4] + k * entsize
            st_name, _info, _other, st_shndx, _val, _sz = \
                struct.unpack_from("<IBBHQQ", data, soff)
            if st_shndx != 0 or st_name == 0:
                continue
            end = data.index(b"\0", stroff + st_name)
            name = data[stroff + st_name:end].decode("ascii", "replace")
            if name not in syms:
                unresolved.append(name)
                continue
            val = kbase + syms[name]
            struct.pack_into("<H", data, soff + 6, SHN_ABS)
            struct.pack_into("<Q", data, soff + 8, val)
            patched.append((name, val))

    open(dst, "wb").write(data)
    print("patched %d symbols (kbase=%#x)" % (len(patched), kbase))
    for name, val in patched:
        print("  %-38s %#x" % (name, val))
    if unresolved:
        print("UNRESOLVED (must be provided by the module):")
        for n in sorted(set(unresolved)):
            print("  " + n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
