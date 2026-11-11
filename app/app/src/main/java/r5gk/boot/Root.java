package r5gk.boot;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Runs one command as root.
 *
 * Two routes, in order: through Shizuku, i.e. as shell executing `su` (works
 * when the shell uid is on the KernelSU allowlist), then as the app itself
 * (which makes KernelSU show its grant dialog on first use).  This is the same
 * thing libsu would do, without pulling in a dependency for it.
 */
final class Root {

    private static final String TMP = "/data/local/tmp/r5gk";

    private static final int UNKNOWN = 0;
    private static final int VIA_SHIZUKU = 1;
    private static final int VIA_APP = 2;
    private static final int NONE = -1;

    private static int route = UNKNOWN;

    private Root() {
    }

    /** Confirms that a root shell is reachable, trying both routes once. */
    static synchronized boolean prepare() {
        // Only a working route is cached: Shizuku may come back (or the user
        // may grant root) after a failed attempt, and a refresh has to see that.
        if (route == VIA_SHIZUKU || route == VIA_APP) {
            return true;
        }
        if (probe(true)) {
            route = VIA_SHIZUKU;
            return true;
        }
        if (probe(false)) {
            route = VIA_APP;
            return true;
        }
        route = NONE;
        return false;
    }

    /**
     * @return combined output, or a diagnostic starting with an error if no
     * root shell could be obtained
     */
    static synchronized String run(String cmd, long timeoutMs) {
        if (!prepare()) {
            return "No root shell: start Shizuku, or allow Kagerou (or Shell) in the KernelSU manager.";
        }
        return route == VIA_SHIZUKU ? shizuku(cmd, timeoutMs) : app(cmd, timeoutMs);
    }

    static synchronized void reset() {
        route = UNKNOWN;
    }

    private static boolean probe(boolean viaShizuku) {
        // The app route makes KernelSU pop its grant dialog, so it needs long
        // enough for the user to answer it.
        long timeout = viaShizuku ? 6000 : 25000;
        String out = viaShizuku ? shizuku("/system/bin/id", timeout) : app("/system/bin/id", timeout);
        return out.contains("uid=0");
    }

    private static String shizuku(String cmd, long timeoutMs) {
        String out = ShizukuRunner.capture(
                new String[]{"/system/bin/su", "-c", cmd}, TMP, timeoutMs);
        return out;
    }

    private static String app(String cmd, long timeoutMs) {
        // libsu first: it handles the "su still starting / user answers the
        // KernelSU prompt" dance for us.
        try (com.topjohnwu.superuser.Shell shell = com.topjohnwu.superuser.Shell.Builder
                .create()
                .setTimeout((int) Math.max(5, timeoutMs / 1000))
                .build()) {
            if (!shell.isRoot()) {
                return "no root";
            }
            java.util.List<String> out = new java.util.ArrayList<>();
            java.util.List<String> err = new java.util.ArrayList<>();
            com.topjohnwu.superuser.Shell.Result result = shell.newJob()
                    .add(cmd)
                    .to(out, err)
                    .exec();
            StringBuilder sb = new StringBuilder();
            for (String line : out) {
                sb.append(line).append('\n');
            }
            for (String line : err) {
                sb.append(line).append('\n');
            }
            if (sb.length() == 0 && result.getCode() != 0) {
                sb.append("su exited with ").append(result.getCode());
            }
            return sb.length() == 0 ? "(no output)" : sb.toString();
        } catch (Throwable t) {
            return fallbackSu(cmd, timeoutMs);
        }
    }

    /** Plain fork/exec, for the case libsu refuses to start at all. */
    private static String fallbackSu(String cmd, long timeoutMs) {
        StringBuilder out = new StringBuilder();
        Process process = null;
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/su", "-c", cmd);
            pb.directory(new File(TMP).isDirectory() ? new File(TMP) : new File("/"));
            pb.redirectErrorStream(true);
            process = pb.start();
            final Process p = process;
            Thread reader = new Thread(() -> {
                try (BufferedReader in = new BufferedReader(
                        new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = in.readLine()) != null) {
                        synchronized (out) {
                            out.append(line).append('\n');
                        }
                    }
                } catch (Exception ignored) {
                }
            }, "root-io");
            reader.setDaemon(true);
            reader.start();

            if (!process.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                process.destroy();
                out.append("(timeout)\n");
            }
            reader.join(2000);
        } catch (Throwable t) {
            return "su failed: " + t;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
        synchronized (out) {
            return out.length() == 0 ? "(no output)" : out.toString();
        }
    }
}
