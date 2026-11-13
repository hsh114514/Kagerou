#!/usr/bin/env python3
"""Emit the name -> offset table the app needs to patch kernelsu.ko on device.

Only symbols the module actually imports are kept, so the asset stays tiny
instead of shipping the whole 128k-entry kernel symbol list.

Usage:
  gen_app_syms.py <kernelsu.ko> <syms> > app/app/src/main/assets/ksu_syms.tsv

The table goes to stdout and the diagnostics to stderr, so the tool has no
output path of its own: redirect it at the asset you want to update.
"""
import struct
import sys

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHN_UNDEF = 0


def parse(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise SystemExit("not ELF64")
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size, link, info, align, entsize = \
            struct.unpack_from("<IIQQQQIIQQ", data, off)
        secs.append(dict(name=name, type=typ, offset=offset, size=size,
                         link=link, entsize=entsize))

    undef = []
    for s in secs:
        if s["type"] != SHT_SYMTAB:
            continue
        strtab = secs[s["link"]]
        n = s["size"] // s["entsize"]
        for i in range(n):
            o = s["offset"] + i * s["entsize"]
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", data, o)
            if st_shndx != SHN_UNDEF or st_name == 0:
                continue
            end = data.index(b"\0", strtab["offset"] + st_name)
            name = data[strtab["offset"] + st_name:end].decode()
            undef.append(name)
    return undef


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_app_syms.py <kernelsu.ko> <syms>")
    ko, syms_file = sys.argv[1], sys.argv[2]
    undef = parse(ko)

    table = {}
    with open(syms_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.split()
            if len(p) >= 2:
                try:
                    table[p[0]] = int(p[1], 16)
                except ValueError:
                    pass

    missing = [n for n in undef if n not in table]
    lines = ["# symbol offset(text-relative hex) -- generated\n"]
    for name in undef:
        if name in table:
            lines.append("%s %x\n" % (name, table[name]))
    sys.stdout.buffer.write("".join(lines).encode("utf-8"))

    print("imports=%d resolved=%d missing=%d" %
          (len(undef), len(undef) - len(missing), len(missing)), file=sys.stderr)
    if missing:
        print("missing:", " ".join(missing[:20]), file=sys.stderr)


if __name__ == "__main__":
    main()
