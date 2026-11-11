#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/workqueue.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/hook_manager.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "feature/sulog.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "feature/selinux_hide.h"
#include "feature/adb_root.h"

extern void __init ksu_lsm_hook_init(void);
/* selinux/rules.c */
extern bool ksu_r5g_selinux_ready(void);
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
					void *argv, void *envp, int *flags);
extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
				    void *argv, void *envp, int *flags);
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, ksu lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                          \
    (defined(CONFIG_ARM64) && defined(MODULE) &&                               \
     !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init
    __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;

#ifdef CONFIG_KSU_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

bool ksu_no_custom_rc = false;
module_param_named(norc, ksu_no_custom_rc, bool, 0);

#ifdef MODULE
bool ksu_bundled = false;
module_param_named(bundled, ksu_bundled, bool, 0);
#endif

/*
 * R5G bring-up aid.  A crash inside kernelsu_init() would otherwise leave no
 * trace: the kernel panics and dmesg is gone.  Write each completed step to
 * /data/local/tmp/ksu_boot.log with O_SYNC so the last line survives.
 */
static struct file *ksu_r5g_log_fp;

void ksu_r5g_log(const char *msg)
{
	if (!ksu_r5g_log_fp)
		ksu_r5g_log_fp = filp_open("/data/local/tmp/ksu_boot.log",
					   O_WRONLY | O_CREAT | O_APPEND | O_SYNC,
					   0644);
	if (IS_ERR_OR_NULL(ksu_r5g_log_fp))
		return;

	kernel_write(ksu_r5g_log_fp, msg, strlen(msg), &ksu_r5g_log_fp->f_pos);
}

static void ksu_r5g_stage(const char *stage)
{
	char buf[160];
	int len;

	len = snprintf(buf, sizeof(buf), "%s pid=%d comm=%s\n", stage,
		       current->pid, current->comm);
	if (len > 0)
		ksu_r5g_log(buf);
}

int __init kernelsu_init(void)
{
	ksu_r5g_stage("start");

#ifdef MODULE
	ksu_late_loaded = (current->pid != 1);
#else
	ksu_late_loaded = false;
#endif

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

	if (allow_shell) {
		pr_alert("shell is allowed at init!");
	}

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        return -ENOSYS;
    }
	ksu_r5g_stage("prepare_creds");

	ksu_feature_init();
	ksu_r5g_stage("feature_init");

	ksu_sulog_init();
	ksu_r5g_stage("sulog_init");

	ksu_adb_root_init();
	ksu_r5g_stage("adb_root_init");

	ksu_lsm_hook_init();
	ksu_r5g_stage("lsm_hook_init");

	ksu_selinux_hide_init();
	ksu_r5g_stage("selinux_hide_init");

	ksu_supercalls_init();
	ksu_r5g_stage("supercalls_init");

	ksu_app_profile_init();
	ksu_r5g_stage("app_profile_init");

	if (ksu_late_loaded) {
		pr_info("late load mode, skipping kprobe hooks\n");

		apply_kernelsu_rules();
		ksu_r5g_stage("apply_rules");
		cache_sid();
		ksu_r5g_stage("cache_sid");
		setup_ksu_cred();
		ksu_r5g_stage("setup_ksu_cred");

		// Grant current process (ksud late-load) root
		// with KSU SELinux domain before enforcing SELinux, so it
		// can continue to access /data/app etc. after enforcement.
		escape_to_root_for_init();
		ksu_r5g_stage("escape_to_root");

		ksu_allowlist_init();
		ksu_r5g_stage("allowlist_init");
		ksu_load_allow_list();
		ksu_r5g_stage("load_allow_list");

		ksu_syscall_hook_manager_init();
		ksu_r5g_stage("hook_manager_init");

		ksu_throne_tracker_init();
		ksu_r5g_stage("throne_tracker_init");
		ksu_observer_init();
		ksu_r5g_stage("observer_init");
		ksu_file_wrapper_init();
		ksu_r5g_stage("file_wrapper_init");

		ksu_boot_completed = true;
		track_throne(false);
		ksu_r5g_stage("track_throne");

		if (!getenforce()) {
#ifdef KSU_R5G_ENFORCE_IF_READY
			/*
			 * Stock policy has no su domain, so enforcing with the rules
			 * unapplied would deny su/ksud everything under /data/adb.
			 * Only flip the switch once the injected domain is live.
			 */
			if (ksu_r5g_selinux_ready()) {
				pr_info("r5g: su domain live, enforcing\n");
				ksu_r5g_log("enforce: on");
				setenforce(true);
			} else {
				pr_info("r5g: su domain missing, staying permissive\n");
				ksu_r5g_log("enforce: skipped");
			}
#else
			pr_info("Permissive SELinux, enforcing\n");
			setenforce(true);
#endif
		}
		ksu_r5g_stage("setenforce");

	} else {
		ksu_syscall_hook_manager_init();
		ksu_r5g_stage("hook_manager_init");

		ksu_allowlist_init();
		ksu_r5g_stage("allowlist_init");

		ksu_throne_tracker_init();

		ksu_ksud_init();

		ksu_file_wrapper_init();
	}

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#ifdef KSU_R5G_HIDE_MODULE
	/*
	 * Detectors read /proc/modules and /proc/kallsyms; both enumerate the
	 * global module list, so unlink ourselves from it.  The module keeps
	 * running (hooks are already installed); we just cannot be unloaded,
	 * which is fine for a RAM-only late load.
	 */
	if (!list_empty(&THIS_MODULE->list)) {
		list_del_rcu(&THIS_MODULE->list);
		synchronize_rcu();
		pr_info("r5g: module unlinked from module list\n");
	}
#endif
#endif
	ksu_r5g_stage("done");
	return 0;
}

void __exit kernelsu_exit(void)
{
	// Phase 1: Stop all hooks first to prevent new callbacks
	ksu_syscall_hook_manager_exit();

	ksu_supercalls_exit();

	if (!ksu_late_loaded)
		ksu_ksud_exit();

	// Wait for any in-flight RCU readers (e.g. handler traversing allow_list)
	synchronize_rcu();

	// Phase 2: Now safe to release data structures
	ksu_observer_exit();

	ksu_throne_tracker_exit();

	ksu_allowlist_exit();

	ksu_selinux_hide_exit();

	ksu_sulog_exit();

	ksu_adb_root_exit();

	ksu_feature_exit();

	if (ksu_cred) {
		put_cred(ksu_cred);
	}
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
