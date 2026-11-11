package r5gk.boot;

/** Unprivileged environment facts an app is actually allowed to read. */
final class Probe {

    private Probe() {
    }

    /**
     * SELinux state is not readable from an app on this device and the LKM
     * hides itself from /proc/modules, so anything else is asked of the shell
     * domain through Shizuku (see MainActivity).
     */
    static String kernel() {
        String v = System.getProperty("os.version");
        return v == null || v.isEmpty() ? "未知" : v;
    }
}
