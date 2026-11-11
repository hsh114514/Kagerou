package r5gk.boot

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import r5gk.boot.ui.HomeScreen
import r5gk.boot.ui.ModuleScreen
import r5gk.boot.ui.theme.KagerouTheme
import java.io.File

/**
 * Kagerou — one-tap temporary root for the AQUOS R5G (908SH).
 *
 * The exploit needs perf_event_open to fit the KASLR slide, and the device
 * policy grants that to shell but not to untrusted_app.  So the whole flow
 * runs through Shizuku, i.e. as uid 2000 in the shell domain, exactly like the
 * PC flow over adb.  Nothing is written to any partition: the exploit patches
 * kernel memory, the module is insmod'ed from /data/local/tmp, and a reboot
 * leaves no trace.
 */
class MainActivity : ComponentActivity() {

    companion object {
        private const val MANAGER = "com.rifsxd.ksunext"
        private const val SHIZUKU = "moe.shizuku.privileged.api"
        private const val TMP_DIR = "/data/local/tmp/r5gk"
    }

    private val ui = Handler(Looper.getMainLooper())
    private val logBuffer = StringBuilder()

    private var phase by mutableStateOf(BootPhase.IDLE)
    private var status by mutableStateOf(
        "就绪。点击「获取临时 Root」开始，执行期间请保持本界面位于前台。",
    )
    private var rows by mutableStateOf(emptyList<Pair<String, String>>())
    private var log by mutableStateOf("")
    private var needsShizukuGrant by mutableStateOf(false)
    private var showShizuku by mutableStateOf(true)

    /** Set when a module action found no root at all. */
    private var rootGuide by mutableStateOf(false)

    /** Last few log lines, for the scrolling status card. */
    private var ticker by mutableStateOf(emptyList<String>())

    // ---- module page ------------------------------------------------------

    private var page by mutableStateOf("home")
    private var modules by mutableStateOf(emptyList<ModuleItem>())
    private var modulesBusy by mutableStateOf(false)
    private var modulesError by mutableStateOf("")

    /** One-shot text for the module page snackbar. */
    private var moduleMessage by mutableStateOf("")

    /** A single-module action is running (update / remove). */
    private var moduleActing by mutableStateOf(false)

    /**
     * The LKM hides itself from /proc/modules and /sys/module, so the only
     * reliable signal is "we loaded it during this process".
     */
    private var moduleLoaded by mutableStateOf(false)

    /** SELinux state is not readable from an app here; ask shell via Shizuku. */
    private var selinux by mutableStateOf("未知")
    private var selinuxChecked = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // The exploit dies with the foreground process; do not let the screen
        // time out in the middle of it.
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        setContent {
            KagerouTheme {
                if (page == "modules") {
                    ModuleScreen(
                        modules = modules,
                        busy = modulesBusy,
                        acting = moduleActing,
                        error = modulesError,
                        message = moduleMessage,
                        onMessageShown = { moduleMessage = "" },
                        onBack = { page = "home" },
                        onRefresh = ::loadModules,
                        onAction = ::moduleOp,
                    )
                } else {
                    HomeScreen(
                        phase = phase,
                        status = status,
                        ticker = ticker,
                        rows = rows,
                        log = log,
                        needsShizukuGrant = needsShizukuGrant,
                        showShizuku = showShizuku,
                        showRootGuide = rootGuide,
                        onDismissRootGuide = { rootGuide = false },
                        onRootGuideManager = {
                            rootGuide = false
                            openManager()
                        },
                        onStart = ::start,
                        onManager = ::openManager,
                        onSelfCheck = ::selfCheck,
                        onShizuku = ::openShizuku,
                        onGrant = { ShizukuRunner.request() },
                        onClearLog = ::clearLog,
                        onZygote = { moduleAction("zygote", "重启 zygote") },
                        onLsposed = { moduleAction("lsposed", "引导 LSPosed") },
                        onModules = ::openModules,
                    )
                }
            }
        }
        refresh()

        if (intent?.getBooleanExtra("autorun", false) == true) {
            ui.postDelayed(::start, 800)
        }
        if (intent?.getBooleanExtra("self_check", false) == true) {
            ui.postDelayed(::selfCheck, 800)
        }
        // Debug hook: `am start … --es module_action lsposed` without tapping.
        intent?.getStringExtra("module_action")?.let { action ->
            if (action == "zygote" || action == "lsposed") {
                ui.postDelayed({
                    moduleAction(action, if (action == "zygote") "重启 zygote" else "引导 LSPosed")
                }, 800)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    // ---- the one-tap flow -------------------------------------------------

    private fun start() {
        if (phase == BootPhase.RUNNING) {
            return
        }
        phase = BootPhase.RUNNING
        status = "正在提权,请保持本界面位于前台"
        clearLog()
        val startedAt = SystemClock.elapsedRealtime()

        Thread({
            val error = runBoot()
            val seconds = (SystemClock.elapsedRealtime() - startedAt) / 1000
            ui.post {
                phase = if (error == null) BootPhase.SUCCESS else BootPhase.FAILURE
                if (error == null) {
                    moduleLoaded = true
                    status = "完成,用时 $seconds 秒"
                } else {
                    // The raw output can be hundreds of lines; keep the card
                    // readable and leave the detail in the log.
                    if (error.contains('\n')) {
                        logLine(error)
                    }
                    val brief = error.substringBefore('\n')
                    status = "失败（用时 $seconds 秒）：$brief" +
                            if (error.contains('\n')) "（详见日志）" else ""
                }
                selinuxChecked = false
                refresh()
            }
        }, "kagerou-boot").start()
    }

    /** @return null on success, otherwise a diagnostic for the status card */
    private fun runBoot(): String? = try {
        val appBin = Loader.appBin(this)
        Loader.stage(assets, appBin)
        val shellBin = Loader.shellBin(this)
        logLine("[*] 已释放文件")

        when {
            !ShizukuRunner.available() ->
                "Shizuku未运行,应用无perf_event权限，请授予Shizuku权限"

            !ShizukuRunner.permitted() -> {
                ui.post { ShizukuRunner.request() }
                "请在Shizuku弹窗中允许本应用，然后再点一次"
            }

            !ShizukuLoader.environmentReady(shellBin.absolutePath) ->
                "外部存储路径与预期不符：" + shellBin.absolutePath

            else -> {
                logLine("[*] 以 shell 身份执行")
                val installManager = managerNeedsInstall(shellBin)
                val error = ShizukuLoader(appBin, LogSink { line -> logLine(line) }, installManager).run()
                if (error == null) {
                    // Module zips land in /data/adb/modules_update; the merge
                    // normally happens at post-fs-data, which never runs here.
                    logLine("[*] 同步模块（modules_update → modules）")
                    logLine(Root.run(moduleCommand("merge"), 30_000).trim())
                }
                error
            }
        }
    } catch (t: Throwable) {
        android.util.Log.e("r5gk.boot", "boot failed", t)
        t.toString()
    }

    /** Install the bundled manager when it is missing or newer than what is there. */
    private fun managerNeedsInstall(shellBin: File): Boolean {
        val bundled = try {
            packageManager.getPackageArchiveInfo(
                File(shellBin, "manager.apk").absolutePath,
                0,
            )?.versionCode
        } catch (t: Throwable) {
            null
        } ?: return true
        val installed = try {
            packageManager.getPackageInfo(MANAGER, 0).versionCode
        } catch (t: Throwable) {
            0
        }
        return installed < bundled
    }

    // ---- module page ------------------------------------------------------

    private fun openModules() {
        page = "modules"
        loadModules()
    }

    /** Reads the module list through ksu_modules.sh (needs root). */
    private fun loadModules() {
        if (modulesBusy) {
            return
        }
        modulesBusy = true
        modulesError = ""
        Thread({
            // The list is bracketed by #BEGIN/#END so a truncated capture can
            // be told from a real one and retried instead of showing half the
            // modules.
            var rows: List<ModuleItem> = emptyList()
            var out = ""
            var complete = false
            for (attempt in 1..3) {
                out = Root.run(moduleCommand("list"), 60_000)
                val parsed = parseModules(out)
                if (parsed != null) {
                    rows = parsed
                    complete = true
                    break
                }
                Thread.sleep(600)
            }
            val error = when {
                complete && rows.isEmpty() -> ""
                complete -> ""
                else -> out.trim().ifBlank { "模块列表读取不完整，请下拉重试" }
            }
            ui.post {
                if (complete) {
                    modules = rows
                }
                modulesError = error
                modulesBusy = false
            }
        }, "kagerou-modules").start()
    }

    /** @return the rows, or null when the output is not a complete listing */
    private fun parseModules(out: String): List<ModuleItem>? {
        val lines = out.lines()
        if (!lines.any { it.trim() == "#BEGIN" } || !lines.any { it.trim() == "#END" }) {
            return null
        }
        val rows = ArrayList<ModuleItem>()
        for (line in lines) {
            val p = line.split('\t')
            if (p.size >= 8 && p[0] != "#BEGIN" && p[0] != "#END") {
                rows.add(
                    ModuleItem(
                        id = p[0].trim(),
                        name = p[1],
                        version = p[2],
                        author = p[3],
                        sizeKb = p[4].trim().toLongOrNull() ?: 0L,
                        state = p[5].trim(),
                        mounted = p[6].trim() == "1",
                        updatable = p[7].trim() == "1",
                    ),
                )
            }
        }
        return rows
    }

    /** update / remove for one module. */
    private fun moduleOp(action: String, item: ModuleItem) {
        if (moduleActing) {
            return
        }
        moduleActing = true
        Thread({
            val out = Root.run(moduleCommand(action, item.id), 120_000)
            logLine(out.trim())
            val ok = when (action) {
                "update" -> out.contains("updated")
                "remove" -> out.contains("removed")
                else -> false
            }
            val text = when (action) {
                "update" -> if (ok) "已更新 ${item.name}" else "更新失败：${out.trim().take(80)}"
                "remove" -> if (ok) "已卸载 ${item.name}" else "卸载失败：${out.trim().take(80)}"
                else -> out.trim()
            }
            ui.post {
                moduleActing = false
                moduleMessage = text
                loadModules()
            }
        }, "kagerou-module-op").start()
    }

    // ---- module actions ---------------------------------------------------

    /**
     * Refreshes the scripts next to the assets and returns the shell command
     * for one mode of ksu_modules.sh.
     *
     * The script is run with `sh <path>` from the external files dir: root can
     * read it there, and the file does not need an execute bit.
     */
    private fun moduleCommand(mode: String, arg: String? = null): String {
        val script = moduleScript()
        val suffix = if (arg.isNullOrBlank()) "" else " " + arg
        return "/system/bin/sh $script $mode$suffix"
    }

    /** Refreshes the script from the assets and returns its on-device path. */
    private fun moduleScript(): String {
        val dir = Loader.shellBin(this)
        Loader.stageOne(assets, dir, "ksu_modules.sh")
        return File(dir, "ksu_modules.sh").absolutePath
    }

    /**
     * Runs one mode of ksu_modules.sh as root.
     *
     * The script is started detached (`setsid … > log 2>&1 &`) and the app
     * tails the log: tying it to our stdout pipe breaks it halfway, because the
     * zygote restart takes the pipe (and sometimes the app) with it.  Manual
     * runs work for exactly that reason.
     */
    private fun moduleAction(mode: String, title: String) {
        if (phase == BootPhase.RUNNING) {
            return
        }
        phase = BootPhase.RUNNING
        status = if (ShizukuRunner.available()) {
            "正在$title…结束时会热重启，界面会短暂消失"
        } else {
            "正在请求root，然后$title…"
        }
        clearLog()

        Thread({
            val log = "$TMP_DIR/$mode.log"
            var noRoot = false
            try {
                // Double fork: the outer sh exits at once, so the script is
                // reparented to init and the zygote restart cannot take it (or
                // the Shizuku/ksu cleanup) out with it.
                val script = moduleScript()
                val start = Root.run(
                    "/system/bin/rm -f $log; " +
                            "/system/bin/setsid /system/bin/sh -c " +
                            "'/system/bin/sh $script $mode >$log 2>&1 </dev/null &' </dev/null",
                    15_000,
                )
                logLine(start.trim())
                noRoot = start.contains("No root shell") || start.trim() == "no root"
                if (start.contains("setsid")) {
                    // No setsid at all: fall back to a plain background run.
                    logLine(Root.run(
                        "/system/bin/sh ${moduleScript()} $mode >$log 2>&1 </dev/null &",
                        15_000,
                    ).trim())
                }

                var shown = 0
                val deadline = System.currentTimeMillis() + 240_000
                while (!noRoot && System.currentTimeMillis() < deadline) {
                    Thread.sleep(2500)
                    val text = Root.run("/system/bin/cat $log", 8_000)
                    val lines = text.lines().filter { it.isNotBlank() }
                    for (i in shown until lines.size) {
                        logLine(lines[i])
                    }
                    shown = lines.size
                    if (text.contains("bridge=") || text.contains("lspd failed")
                        || text.contains("crashed") || text.contains("no zygote64")
                    ) {
                        break
                    }
                }
            } catch (t: Throwable) {
                logLine("脚本执行异常：$t")
            }

            ui.post {
                phase = if (noRoot) BootPhase.FAILURE else BootPhase.SUCCESS
                status = when {
                    noRoot -> "没有 root 权限：请在KSU中给与Shell与本应用root权限"
                    else -> "$title 已执行（日志：$log）"
                }
                if (noRoot) {
                    rootGuide = true
                }
                refresh()
            }
        }, "kagerou-module").start()
    }

    // ---- self-check -------------------------------------------------------

    private fun selfCheck() {
        if (phase == BootPhase.RUNNING) {
            return
        }
        phase = BootPhase.RUNNING
        status = "正在自检…"
        clearLog()

        Thread({
            try {
                // Resolve the channel first so the header lines show live data
                // instead of whatever the last refresh happened to leave.
                val canRoot = Root.prepare()
                val enforce = if (canRoot) {
                    Root.run("/system/bin/getenforce", 10_000).trim()
                } else {
                    ShizukuRunner.capture(arrayOf("/system/bin/getenforce"), TMP_DIR, 5000).trim()
                }

                logLine("=== 环境自检 ===")
                logLine("设备：" + Build.MODEL + " · " + Build.DISPLAY)
                logLine("内核：" + Probe.kernel())
                logLine("SELinux：" + enforce.ifBlank { selinux })
                logLine("KSU状态：" + if (canRoot || moduleLoaded) "已加载" else "未加载")
                logLine("Shizuku：" + shizukuLabel())

                if (canRoot) {
                    logLine("")
                    logLine("[root] id")
                    logLine(Root.run("/system/bin/id", 15_000).trim())
                    logLine("")
                    logLine("[root] ls -l $TMP_DIR")
                    logLine(Root.run("/system/bin/ls -l $TMP_DIR", 15_000).trim())
                    logLine("")
                    logLine("[root] getenforce")
                    logLine(enforce)
                } else if (ShizukuRunner.available() && ShizukuRunner.permitted()) {
                    logLine("")
                    logLine("[shell] id（无 root 权限）")
                    logLine(ShizukuRunner.capture(arrayOf("/system/bin/id"), TMP_DIR, 8000).trim())
                    logLine("")
                    logLine("[shell] ls -l $TMP_DIR")
                    logLine(
                        ShizukuRunner.capture(
                            arrayOf("/system/bin/ls", "-l", TMP_DIR),
                            TMP_DIR,
                            8000,
                        ).trim(),
                    )
                } else {
                    logLine("")
                    logLine("没有 root 权限, 且 Shizuku 未就绪, 跳过检查")
                }

                ui.post {
                    if (enforce.contains("Enforcing")) {
                        selinux = "Enforcing"
                    } else if (enforce.contains("Permissive")) {
                        selinux = "Permissive"
                    }
                    if (canRoot) {
                        moduleLoaded = true
                    }
                }
            } catch (t: Throwable) {
                logLine("自检异常：$t")
            }

            ui.post {
                val loaded = moduleLoaded
                phase = if (loaded) BootPhase.SUCCESS else BootPhase.IDLE
                status = if (loaded) {
                    "KSU已加载"
                } else {
                    "未知状态, 点击「获取临时 Root」开始"
                }
                selinuxChecked = false
                refresh()
            }
        }, "kagerou-check").start()
    }

    // ---- state ------------------------------------------------------------

    private fun refresh() {
        needsShizukuGrant = ShizukuRunner.available() && !ShizukuRunner.permitted()
        showShizuku = !ShizukuRunner.available() || needsShizukuGrant
        rows = listOf(
            "设备型号" to Build.MODEL,
            "系统版本" to "Android ${Build.VERSION.RELEASE}（API ${Build.VERSION.SDK_INT}）· ${Build.DISPLAY}",
            "内核版本" to Probe.kernel(),
            "SELinux" to selinux,
            "KSU状态" to if (moduleLoaded) "已加载" else "未加载",
            "Shizuku" to shizukuLabel(),
        )
        querySelinux()
    }

    /**
     * Apps cannot read selinuxfs here, so ask whichever channel we have:
     * root first (works when Shizuku is down), shell/Shizuku second.
     * A working root also means the KernelSU driver is up, which is the only
     * way to tell from an app (the LKM hides itself from /proc/modules).
     */
    private fun querySelinux() {
        if (selinuxChecked) {
            return
        }
        selinuxChecked = true
        Thread({
            var raw = ""
            var rooted = false
            try {
                rooted = Root.prepare()
                raw = if (rooted) {
                    Root.run("/system/bin/getenforce", 10_000)
                } else if (ShizukuRunner.available() && ShizukuRunner.permitted()) {
                    ShizukuRunner.capture(arrayOf("/system/bin/getenforce"), "/data/local/tmp", 5000)
                } else {
                    ""
                }
            } catch (t: Throwable) {
                android.util.Log.w("r5gk.boot", "selinux query failed", t)
            }
            val value = when {
                raw.contains("Enforcing") -> "Enforcing"
                raw.contains("Permissive") -> "Permissive"
                else -> selinux
            }
            ui.post {
                if (value != selinux) {
                    selinux = value
                }
                if (rooted && !moduleLoaded) {
                    moduleLoaded = true
                }
                refresh()
            }
        }, "kagerou-selinux").start()
    }

    private fun shizukuLabel(): String = when {
        !ShizukuRunner.available() -> "未运行"
        ShizukuRunner.permitted() -> "已连接 · 已授权"
        else -> "已连接 · 等待授权"
    }

    // ---- logging ----------------------------------------------------------

    private fun logLine(line: String) {
        android.util.Log.i("r5gk.boot", line)
        val snapshot: String
        synchronized(logBuffer) {
            logBuffer.append(line).append('\n')
            snapshot = logBuffer.toString()
        }
        val recent = synchronized(logBuffer) {
            logBuffer.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toList()
                .takeLast(3)
        }
        ui.post {
            log = snapshot
            ticker = recent
        }
    }

    private fun clearLog() {
        synchronized(logBuffer) { logBuffer.setLength(0) }
        log = ""
        ticker = emptyList()
    }

    // ---- shortcuts --------------------------------------------------------

    private fun openManager() = openPackage(MANAGER, "未安装 KernelSU 管理器（$MANAGER）")

    private fun openShizuku() = openPackage(SHIZUKU, "未安装 Shizuku（$SHIZUKU）")

    private fun openPackage(pkg: String, missing: String) {
        val launch: Intent? = packageManager.getLaunchIntentForPackage(pkg)
        if (launch == null) {
            status = missing
            logLine(missing)
            return
        }
        startActivity(launch)
    }
}
