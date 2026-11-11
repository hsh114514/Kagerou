package r5gk.boot;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * On-device replacement for patch_ko.py: turn the module's undefined kernel
 * imports into SHN_ABS symbols at kbase + offset, so the loader never consults
 * the export table or the modversion CRCs.
 */
final class ElfPatch {

    private static final int SHT_SYMTAB = 2;
    private static final int SHN_ABS = 0xFFF1;
    private static final int SYM_ENT = 24;

    private ElfPatch() {
    }

    static Map<String, Long> loadSyms(File tsv) throws IOException {
        Map<String, Long> map = new HashMap<>();
        for (String line : Util.readLines(tsv)) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] p = line.split("\\s+");
            if (p.length < 2) {
                continue;
            }
            try {
                map.put(p[0], Long.parseLong(p[1], 16));
            } catch (NumberFormatException ignored) {
            }
        }
        return map;
    }

    /** @return number of patched symbols */
    static int patch(File src, File dst, Map<String, Long> syms, long kbase) throws IOException {
        byte[] data;
        try (RandomAccessFile raf = new RandomAccessFile(src, "r")) {
            data = new byte[(int) raf.length()];
            raf.readFully(data);
        }
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F'
                || data[4] != 2 || data[5] != 1) {
            throw new IOException("not a little-endian ELF64");
        }

        long shoff = buf.getLong(0x28);
        int shentsize = buf.getShort(0x3A) & 0xffff;
        int shnum = buf.getShort(0x3C) & 0xffff;

        int patched = 0;
        for (int i = 0; i < shnum; i++) {
            int sh = (int) (shoff + (long) i * shentsize);
            int type = buf.getInt(sh + 4);
            if (type != SHT_SYMTAB) {
                continue;
            }
            long symOff = buf.getLong(sh + 0x18);
            long symSize = buf.getLong(sh + 0x20);
            int link = buf.getInt(sh + 0x28);
            int strSh = (int) (shoff + (long) link * shentsize);
            long strOff = buf.getLong(strSh + 0x18);

            int count = (int) (symSize / SYM_ENT);
            for (int k = 0; k < count; k++) {
                int off = (int) symOff + k * SYM_ENT;
                int stName = buf.getInt(off);
                int stShndx = buf.getShort(off + 6) & 0xffff;
                if (stShndx != 0 || stName == 0) {
                    continue;
                }
                String name = cstr(data, (int) strOff + stName);
                Long rel = syms.get(name);
                if (rel == null) {
                    continue;
                }
                buf.putShort(off + 6, (short) SHN_ABS);
                buf.putLong(off + 8, kbase + rel);
                patched++;
            }
        }

        try (FileOutputStream out = new FileOutputStream(dst)) {
            out.write(data);
        }
        return patched;
    }

    private static String cstr(byte[] data, int off) {
        int end = off;
        while (end < data.length && data[end] != 0) {
            end++;
        }
        return new String(data, off, end - off, StandardCharsets.US_ASCII);
    }
}
