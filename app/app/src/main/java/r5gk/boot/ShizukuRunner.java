package r5gk.boot;

import android.content.pm.PackageManager;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;

/**
 * Thin wrapper over Shizuku's remote process API.
 *
 * The exploit needs perf_event_open to fit the KASLR slide, and the device
 * policy grants that only to shell / runas_app / a few system domains.  An
 * app that has Shizuku running can borrow the shell context for a child
 * process, which is exactly what the PC flow does over adb.
 */
final class ShizukuRunner {

    private ShizukuRunner() {
    }

    static boolean available() {
        try {
            return Shizuku.pingBinder() && Shizuku.getVersion() >= 11;
        } catch (Throwable t) {
            return false;
        }
    }

    static boolean permitted() {
        try {
            return Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Shows Shizuku's "allow this app to use the service" dialog. */
    static void request() {
        try {
            Shizuku.requestPermission(0);
        } catch (Throwable ignored) {
        }
    }

    static IRemoteProcess start(String[] cmd, String[] env, String dir) throws Exception {
        IShizukuService svc = IShizukuService.Stub.asInterface(Shizuku.getBinder());
        if (svc == null) {
            throw new IllegalStateException("shizuku service is null");
        }
        return svc.newProcess(cmd, env, dir);
    }

    /**
     * Runs a short, already-existing command and returns its combined output.
     * Used by the self-check only; the bring-up path has its own reader.
     */
    static String capture(String[] cmd, String dir, long timeoutMs) {
        StringBuilder out = new StringBuilder();
        try {
            IRemoteProcess p = start(cmd, new String[0], dir);
            Thread io = new Thread(() -> {
                try (java.io.InputStream in = new java.io.FileInputStream(
                        p.getInputStream().getFileDescriptor())) {
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        synchronized (out) {
                            out.append(new String(buf, 0, n, "UTF-8"));
                        }
                    }
                } catch (Exception ignored) {
                }
            }, "shizuku-check");
            io.setDaemon(true);
            io.start();

            long deadline = System.currentTimeMillis() + timeoutMs;
            while (System.currentTimeMillis() < deadline && io.isAlive()) {
                Thread.sleep(50);
            }
            if (io.isAlive()) {
                p.destroy();
            }
            io.join(2000);
        } catch (Throwable t) {
            return "Shizuku 执行失败：" + t;
        }
        synchronized (out) {
            return out.length() == 0 ? "(无输出)" : out.toString();
        }
    }
}
