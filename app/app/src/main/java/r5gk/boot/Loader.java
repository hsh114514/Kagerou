package r5gk.boot;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/**
 * Staging for the exploit.
 *
 * The APK's assets are unpacked twice: once into the app-private directory,
 * where ElfPatch rewrites the module, and once into the app's external files
 * directory.  The second copy exists because everything is executed as the
 * shell user: it cannot read /data/data/<pkg>, but it can read and copy
 * /storage/emulated/0/Android/data/<pkg>/files without any permission.
 */
final class Loader {

    static final String[] ASSETS = {
            "r5g.bin", "kernelsu.ko", "magiskpolicy",
            "ksu_enforce.sh", "ksu_load.sh", "ksu_syms.tsv",
            // The userspace half of KernelSU: after the module is in, this is
            // what creates /data/adb, the daemon and the module mounts.
            "ksud",
            // Merges modules_update into modules/ and brings Zygisk up; the
            // post-fs-data stage that normally does it never runs here.
            "ksu_modules.sh",
            // Installed by the shell after root; the app itself never gets to
            // write /data/app without a user prompt.
            "manager.apk",
    };

    private Loader() {
    }

    /** files/bin — private to the app, holds the patched module. */
    static File appBin(Context ctx) throws IOException {
        return makeDir(new File(ctx.getFilesDir(), "bin"));
    }

    /** <external>/bin — the copy the shell side reads. */
    static File shellBin(Context ctx) throws IOException {
        File ext = ctx.getExternalFilesDir(null);
        if (ext == null) {
            throw new IOException("外部存储不可用");
        }
        return makeDir(new File(ext, "bin"));
    }

    /** Copies every asset into {@code dir}, overwriting what is there. */
    static void stage(AssetManager am, File dir) throws IOException {
        for (String name : ASSETS) {
            stageOne(am, dir, name);
        }
    }

    /** One asset only, for the module actions that need no full staging. */
    static void stageOne(AssetManager am, File dir, String name) throws IOException {
        try (InputStream in = am.open(name)) {
            Util.copy(in, new File(dir, name));
        }
    }

    private static File makeDir(File dir) throws IOException {
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("Unable to create " + dir);
        }
        return dir;
    }
}
