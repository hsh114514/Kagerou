package r5gk.boot;

import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import moe.shizuku.server.IRemoteProcess;

/**
 * Same sequence as {@link Loader}, but every command runs through Shizuku,
 * i.e. as uid 2000 in the shell domain.
 *
 * Files cannot come from the app's private dir in this mode: the shell
 * process has no access to /data/data/<pkg>.  They are published to the
 * app's external files dir instead (readable by shell, no permission need)
 * and copied into /data/local/tmp, which is where the exploit can be exec'd
 * from and where the module can be insmod'ed.
 *
 * Each step is an argv list handed straight to execve() by the Shizuku
 * server; no shell, no word splitting, no command strings.
 */
final class ShizukuLoader {

    /** Working dir the shell side uses; shell may write this, apps may not. */
    private static final String TMP = "/data/local/tmp/r5gk";

    /** getExternalFilesDir(null) + "/bin" for package r5gk.boot, user 0. */
    static final String EXT = "/storage/emulated/0/Android/data/r5gk.boot/files/bin";

    private static final String KBASE_BASE = "0xffffff8008080000";
    private static final String PERMISSIVE_OFF = "0x31b6001";
    private static final String SIGENFORCE_OFF = "0x27b9558";
    private static final long STEP_TIMEOUT_MS = 180000L;

    private final File assetsDir;
    private final LogSink log;
    private final boolean installManagerApk;
    private String lastOutput = "";

    ShizukuLoader(File assetsDir, LogSink log, boolean installManagerApk) {
        this.assetsDir = assetsDir;
        this.log = log;
        this.installManagerApk = installManagerApk;
    }

    static boolean environmentReady(String path) {
        return EXT.equals(path);
    }

    /** @return null on success, otherwise a diagnostic */
    String run() {
        try {
            prepare();
            sync();

            // Before root, so the module sees the manager while it scans
            // /data/app for it (that scan is what hands the manager its root
            // rights).  Installing afterwards leaves it uncrowned until the
            // next run.
            if (installManagerApk) {
                installManager();
            } else {
                log.line("[*] KernelSU 管理器已是最新版本");
            }

            log.line("[*] 读取 KASLR slide …");
            Reply fit = fit();
            String slide = parseSlide(fit.out);
            if (slide == null) {
                return "无法获取 KASLR slide 原始输出：\n" + lastOutput;
            }
            log.line("[+] slide = " + slide);

            long kbase = Long.parseUnsignedLong(KBASE_BASE.substring(2), 16)
                    + Long.parseUnsignedLong(slide.substring(2), 16);
            log.line("[*] kbase = 0x" + Long.toHexString(kbase));

            Map<String, Long> map = ElfPatch.loadSyms(new File(assetsDir, "ksu_syms.tsv"));
            int n = ElfPatch.patch(new File(assetsDir, "kernelsu.ko"),
                    new File(EXT + "/kernelsu_r5g.ko"), map, kbase);
            log.line("[+] 已修改" + n + "个符号");
            if (n == 0) {
                return "模块符号修改失败,kernelsu.ko可能不匹配";
            }

            Reply c1 = copyModule();
            Reply c2 = chmodModule();
            if (c1.rc != 0 || c2.rc != 0) {
                return "模块拷贝到 /data/local/tmp 失败：\n" + c1.out + c2.out;
            }

            log.line("[*] Step 1/3：SELinux → Permissive");
            if (!chain(slide, true)) {
                return "宽容SELinux失败：" + shortReason(lastOutput);
            }
            log.line("[+] " + readEnforce());

            log.line("[*] Step 2/3：sig_enforce → 0");
            if (!chain(slide, false)) {
                return "禁用sig_enforce失败：" + shortReason(lastOutput);
            }

            log.line("[*] Step 3/3：加载模块, 补全SELinux策略");
            Reply rw = rootWrite(slide);
            log.line(rw.out.trim());
            if (!rw.out.contains("insmod rc=0")) {
                return "insmod 未确认成功：\n" + rw.out;
            }

            // The script's own tail can be lost when the policy switches back
            // to enforcing, and the exploit's child returns before the last
            // policy step is done, so the outcome is checked from here — with a
            // few retries, because the su domain only appears once magiskpolicy
            // has injected it.
            // Absolute paths: the Shizuku child gets an empty environment, so a
            // bare `id` is not found when the kernel falls back to /system/bin/sh
            // while ksud is still being installed.
            //
            // This is only a smoke test: whether it passes depends on the shell
            // uid being on the KernelSU allowlist (the manager's "Shell" toggle),
            // which is the user's choice, so it must not fail the run.
            log.line("[*] 验证 su …");
            Reply su = retry(new String[]{"/system/bin/su", "-c", "/system/bin/id"}, "uid=0");
            if (su.out.contains("uid=0")) {
                log.line("[+] " + su.out.trim().replace('\n', ' '));
            } else {
                log.line("[!] shell没有root权限，跳过");
            }
            Reply enf = retry(new String[]{"/system/bin/getenforce"}, "Enforcing");
            log.line("[+] SELinux " + enf.out.trim());
            if (!enf.out.contains("Enforcing")) {
                return "SELinux 未回到 Enforcing：\n" + enf.out;
            }
            return null;
        } catch (Exception e) {
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    /** Publish the staged assets where the shell process can read them. */
    private void prepare() throws Exception {
        File bin = new File(EXT);
        if (!bin.isDirectory() && !bin.mkdirs()) {
            throw new IllegalStateException("无法创建 " + EXT);
        }
        for (String name : Loader.ASSETS) {
            Util.copy(new FileInputStream(new File(assetsDir, name)), new File(bin, name));
        }
    }

    private void sync() throws Exception {
        Reply mk = mkdir();
        Reply cp = publish();
        Reply chmod = chmod();
        if (mk.rc != 0 || cp.rc != 0 || chmod.rc != 0) {
            throw new IllegalStateException("staging failed:\n" + mk.out + cp.out + chmod.out);
        }
    }

    private boolean chain(String slide, boolean permissive) throws Exception {
        for (int attempt = 1; attempt <= 3; attempt++) {
            Reply r = permissive ? probePermissive(slide) : probeSigEnforce(slide);
            lastOutput = r.out;

            boolean done = r.out.contains("route done");
            boolean ok = done ? r.out.contains("success=1") : true;
            if (ok || attempt == 3) {
                return ok;
            }
            log.line("[!] 第 " + attempt + " 次失败（" + shortReason(r.out) + "），重试 …");
            Thread.sleep(2000);
        }
        return false;
    }

    // ---- individual steps -------------------------------------------------
    //
    // Each one is a fixed argument vector for a fixed binary.  Only the KASLR
    // slide, which the exploit itself prints, ever travels as a value, and it
    // goes in as an environment entry rather than as part of a command.

    private Reply fit() throws Exception {
        return spawn(new String[]{"/data/local/tmp/r5gk/r5g.bin", "--fit"}, new String[0], TMP);
    }

    private Reply mkdir() throws Exception {
        return spawn(new String[]{"/system/bin/mkdir", "-p", "/data/local/tmp/r5gk"},
                new String[0], "/data/local/tmp");
    }

    private Reply publish() throws Exception {
        return spawn(new String[]{"/system/bin/cp",
                "/storage/emulated/0/Android/data/r5gk.boot/files/bin/r5g.bin",
                "/storage/emulated/0/Android/data/r5gk.boot/files/bin/magiskpolicy",
                "/storage/emulated/0/Android/data/r5gk.boot/files/bin/ksu_enforce.sh",
                "/storage/emulated/0/Android/data/r5gk.boot/files/bin/ksu_load.sh",
                "/storage/emulated/0/Android/data/r5gk.boot/files/bin/ksu_syms.tsv",
                "/storage/emulated/0/Android/data/r5gk.boot/files/bin/ksud",
                "/storage/emulated/0/Android/data/r5gk.boot/files/bin/ksu_modules.sh",
                "/data/local/tmp/r5gk/"}, new String[0], "/data/local/tmp");
    }

    private Reply chmod() throws Exception {
        return spawn(new String[]{"/system/bin/chmod", "751",
                "/data/local/tmp/r5gk/r5g.bin",
                "/data/local/tmp/r5gk/magiskpolicy",
                "/data/local/tmp/r5gk/ksu_enforce.sh",
                "/data/local/tmp/r5gk/ksu_load.sh",
                "/data/local/tmp/r5gk/ksu_modules.sh",
                "/data/local/tmp/r5gk/ksud"}, new String[0], "/data/local/tmp");
    }

    private Reply probePermissive(String slide) throws Exception {
        return spawn(new String[]{"/data/local/tmp/r5gk/r5g.bin", "--stack-probe"},
                new String[]{"IMAGE_DELTA=0", "KASLR_SLIDE=" + slide, "KEEPALIVE=1",
                        "STACK_CHILD_TARGET=1", "STACK_TARGET_OFF=" + PERMISSIVE_OFF}, TMP,
                "route done");
    }

    private Reply probeSigEnforce(String slide) throws Exception {
        return spawn(new String[]{"/data/local/tmp/r5gk/r5g.bin", "--stack-probe"},
                new String[]{"IMAGE_DELTA=0", "KASLR_SLIDE=" + slide, "KEEPALIVE=1",
                        "STACK_ZERO_WRITE=1", "STACK_TARGET_OFF=" + SIGENFORCE_OFF}, TMP,
                "route done");
    }

    private Reply rootWrite(String slide) throws Exception {
        // No keepalive here, so the child really exits: wait for it and take the
        // whole output (the ksud bootstrap is what we need to see).
        return spawn(new String[]{"/data/local/tmp/r5gk/r5g.bin", "--root-write",
                "/data/local/tmp/r5gk/ksu_load.sh"},
                new String[]{"IMAGE_DELTA=0", "KASLR_SLIDE=" + slide}, TMP);
    }

    private Reply copyModule() throws Exception {
        return spawn(new String[]{"/system/bin/cp",
                "/storage/emulated/0/Android/data/r5gk.boot/files/bin/kernelsu_r5g.ko",
                "/data/local/tmp/r5gk/kernelsu_r5g.ko"}, new String[0], TMP);
    }

    private Reply chmodModule() throws Exception {
        return spawn(new String[]{"/system/bin/chmod", "640",
                "/data/local/tmp/r5gk/kernelsu_r5g.ko"}, new String[0], TMP);
    }

    /**
     * Installs the bundled KernelSU manager.  Done as shell through the package
     * service, which is the same path adb takes, so no "install unknown apps"
     * prompt is involved.  Failure here does not make the root flow fail.
     */
    private void installManager() {
        log.line("[*] 安装 KernelSU 管理器");
        try {
            Reply cp = spawn(new String[]{"/system/bin/cp",
                    "/storage/emulated/0/Android/data/r5gk.boot/files/bin/manager.apk",
                    "/data/local/tmp/r5gk/manager.apk"}, new String[0], TMP);
            if (cp.rc != 0) {
                log.line("[-] 管理器拷贝失败：" + cp.out.trim());
                return;
            }
            Reply pm = spawn(new String[]{"/system/bin/pm", "install", "-r",
                    "/data/local/tmp/r5gk/manager.apk"}, new String[0], TMP, "Success");
            String out = pm.out.trim();
            if (out.contains("Success")) {
                log.line("[+] 管理器已安装");
            } else {
                log.line("[-] 管理器安装未成功：" + (out.isEmpty() ? "无输出" : out));
            }
        } catch (Exception e) {
            log.line("[-] 管理器安装异常：" + e);
        }
    }

    // ---- plumbing ---------------------------------------------------------

    private String parseSlide(String out) {
        lastOutput = out;
        for (String line : out.split("\n")) {
            String s = line.trim();
            if (s.startsWith("0x") && s.length() > 8) {
                return s;
            }
        }
        return null;
    }

    private static boolean contains(StringBuilder sb, String needle) {
        synchronized (sb) {
            return sb.indexOf(needle) >= 0;
        }
    }

    private static final class Reply {
        final int rc;
        final String out;

        Reply(int rc, String out) {
            this.rc = rc;
            this.out = out;
        }
    }

    private Reply spawn(String[] argv, String[] env, String dir) throws Exception {
        return spawn(argv, env, dir, null);
    }

    /**
     * Runs {@code argv} until its output contains {@code expect}.
     *
     * The policy patch and the su domain settle a moment after the root-write
     * child returns, so a single shot can see a half-applied state.
     */
    private Reply retry(String[] argv, String expect) throws Exception {
        Reply last = null;
        for (int attempt = 1; attempt <= 15; attempt++) {
            last = spawn(argv, new String[0], TMP);
            if (last.out.contains(expect)) {
                return last;
            }
            Thread.sleep(1500);
        }
        return last;
    }

    /**
     * Runs one argv list and collects its output.
     *
     * With KEEPALIVE=1 the exploit leaves a helper behind that keeps the
     * pipes open, so waiting for exit burns the whole timeout even though the
     * step finished; when a marker is given we stop as soon as it shows up.
     */
    private Reply spawn(String[] argv, String[] env, String dir, String marker)
            throws Exception {
        final IRemoteProcess p = ShizukuRunner.start(argv, env, dir);
        final StringBuilder out = new StringBuilder();

        Thread so = reader(p.getInputStream(), out);
        Thread se = reader(p.getErrorStream(), out);

        final int[] rc = {Integer.MIN_VALUE};
        Thread waiter = new Thread(() -> {
            try {
                rc[0] = p.waitFor();
            } catch (Exception ignored) {
            }
        }, "shizuku-wait");
        waiter.start();

        long deadline = System.currentTimeMillis() + STEP_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline && waiter.isAlive()) {
            if (marker != null && contains(out, marker)) {
                Thread.sleep(500);
                break;
            }
            Thread.sleep(200);
        }
        boolean timedOut = waiter.isAlive();
        if (timedOut && marker == null) {
            try {
                p.destroy();
            } catch (Exception ignored) {
            }
            rc[0] = -1;
            out.append("\n[timeout]");
        }
        // A marker hit means the step is done; the exploit's keepalive helper
        // keeps its pipes open, so we leave it alone instead of killing it.
        so.join(5000);
        se.join(5000);
        return new Reply(rc[0], out.toString());
    }

    private Thread reader(final ParcelFileDescriptor pfd, final StringBuilder sink) {
        if (pfd == null) {
            return new Thread();
        }
        Thread t = new Thread(() -> {
            // Append as bytes arrive: the marker check below needs to see
            // progress before the process closes its pipes.
            try (InputStream in = new FileInputStream(pfd.getFileDescriptor())) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) > 0) {
                    String s = new String(buf, 0, n, StandardCharsets.UTF_8);
                    synchronized (sink) {
                        sink.append(s);
                    }
                }
            } catch (Exception ignored) {
            }
        }, "shizuku-io");
        t.start();
        return t;
    }

    private static String shortReason(String out) {
        for (String line : out.split("\n")) {
            if (line.contains("route done")) {
                return line.trim();
            }
        }
        return out.isEmpty() ? "无输出" : out.trim();
    }

    private static String readEnforce() {
        try {
            java.util.List<String> v = Util.readLines(new File("/sys/fs/selinux/enforce"));
            String s = v.isEmpty() ? "?" : v.get(0).trim();
            return "SELinux enforce = " + s + (s.equals("1") ? " (Enforcing)" : " (Permissive)");
        } catch (Exception e) {
            return "SELinux enforce = 读取失败";
        }
    }
}
