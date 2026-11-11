#ifdef KSU_SYSCALL_TABLE_HOOK

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <asm/ptrace.h>
#if defined(__aarch64__)
#include <asm/memory.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "compat/kernel_compat.h"
#include "hook/syscall_table_hook.h"
#include "hook/patch_memory.h"
#include "infra/symbol_resolver.h"
#include "policy/app_profile.h"
#include "selinux/selinux.h"
#include "feature/sucompat.h"
#include "feature/adb_root.h"
#include "runtime/ksud.h"
#include "policy/allowlist.h"
#include "manager/manager_identity.h"
#include "uapi/supercall.h"

/*
 * Implemented in supercall/supercall.c.  The kprobe build calls it from a
 * reboot kprobe; with the syscall-table scheme we have to route __NR_reboot
 * here ourselves, otherwise the manager never gets its supercall fd.
 */
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg);

/* bring-up log, survives a panic (see core/init.c) */
extern void ksu_r5g_log(const char *msg);

/* supercall/supercall.c */
extern int ksu_install_fd(void);
extern bool ksu_has_driver_fd(void);


// The pt_regs-based syscall ABI (__arm64_sys_*/__x64_sys_*) exists since 4.17
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#error "syscall table hook requires kernel >= 4.17 (pt_regs syscall ABI)"
#endif

typedef long (*ksu_syscall_fn_t)(const struct pt_regs *regs);

static ksu_syscall_fn_t *ksu_sth_syscall_table = NULL;

#define KSU_STH_MAX_HOOKS 16

struct ksu_sth_entry {
	int nr;
	ksu_syscall_fn_t orig;
	ksu_syscall_fn_t wrapper;
};

static DEFINE_MUTEX(ksu_sth_lock);
static struct ksu_sth_entry ksu_sth_entries[KSU_STH_MAX_HOOKS];
static int ksu_sth_count = 0;

// Some architectures (e.g. x86_64) do not provide untagged_addr()
#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

static ksu_syscall_fn_t ksu_sth_get_orig(int nr)
{
	int i;
	for (i = 0; i < ksu_sth_count; i++) {
		if (ksu_sth_entries[i].nr == nr)
			return ksu_sth_entries[i].orig;
	}
	return NULL;
}

static inline long ksu_sth_call_orig(int nr, const struct pt_regs *regs)
{
	ksu_syscall_fn_t orig = ksu_sth_get_orig(nr);
	if (unlikely(!orig))
		return -ENOSYS;
	return orig(regs);
}

/* defined below; used by the faccessat/newfstatat wrappers */
static bool ksu_r5g_path_hidden(const char __user *path_user);

/* defined below; used by the reboot/prctl supercall wrappers */
static bool ksu_sth_prctl_is_manager(void);

static int ksu_sth_patch(int nr, ksu_syscall_fn_t fn)
{
	if (!ksu_sth_syscall_table)
		return -ENOENT;

	pr_info("sth: patch syscall %d: 0x%lx -> 0x%lx\n", nr,
		(unsigned long)READ_ONCE(ksu_sth_syscall_table[nr]),
		(unsigned long)fn);

	if (ksu_patch_text(&ksu_sth_syscall_table[nr], &fn, sizeof(fn),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("sth: patch syscall %d failed\n", nr);
		return -EIO;
	}
	return 0;
}

static void ksu_sth_record(int nr, ksu_syscall_fn_t orig)
{
	int i;
	for (i = 0; i < ksu_sth_count; i++) {
		if (ksu_sth_entries[i].nr == nr)
			return;
	}
	if (ksu_sth_count >= KSU_STH_MAX_HOOKS) {
		pr_err("sth: entry table full, cannot track syscall %d\n", nr);
		return;
	}
	ksu_sth_entries[ksu_sth_count].nr = nr;
	ksu_sth_entries[ksu_sth_count].orig = orig;
	ksu_sth_entries[ksu_sth_count].wrapper = NULL;
	ksu_sth_count++;
}

// init exec tracker for the table hook scheme: escape when init executes ksud.
// The tracepoint-based unmark logic does not apply here (no task marking).
static void ksu_sth_init_exec_tracker(const char __user *filename_user)
{
	char path[64];
	unsigned long addr;
	const char __user *fn;
	long ret;

	addr = untagged_addr((unsigned long)filename_user);
	fn = (const char __user *)addr;

	memset(path, 0, sizeof(path));
	ret = strncpy_from_user_nofault(path, fn, sizeof(path));
	if (ret < 0 && preempt_count()) {
		preempt_enable_no_resched_notrace();
		ret = strncpy_from_user(path, fn, sizeof(path));
		preempt_disable_notrace();
	}

	if (ret < 0)
		return;

	if (unlikely(strcmp(path, KSUD_PATH) == 0)) {
		pr_info("sth: escape to root for init executing ksud: %d\n",
			current->pid);
		escape_to_root_for_init();
	}
}

#ifdef __NR_execve
static long ksu_sth_execve(const struct pt_regs *regs)
{
	const char __user **filename_user =
		(const char __user **)&PT_REGS_PARM1(regs);
	long adb_ret = 0;

	if (current->pid != 1 && is_init(current_cred())) {
		ksu_sth_init_exec_tracker(*filename_user);
		adb_ret = ksu_adb_root_handle_execve((struct pt_regs *)regs);
		if (adb_ret)
			pr_err("sth: adb root failed: %ld\n", adb_ret);
	} else {
		ksu_handle_execve_sucompat(filename_user, __NR_execve, regs);
	}

	return ksu_sth_call_orig(__NR_execve, regs);
}
#endif

#ifdef __NR_execveat
static long ksu_sth_execveat(const struct pt_regs *regs)
{
	const char __user **filename_user =
		(const char __user **)&PT_REGS_PARM2(regs);
	long adb_ret = 0;

	// New bionic maps execve to execveat(AT_FDCWD, path, argv, envp, 0)
	if ((int)PT_REGS_PARM1(regs) == AT_FDCWD &&
	    (int)PT_REGS_SYSCALL_PARM4(regs) == 0) {
		if (current->pid != 1 && is_init(current_cred())) {
			ksu_sth_init_exec_tracker(*filename_user);
			adb_ret = ksu_adb_root_handle_execveat(
				(struct pt_regs *)regs);
			if (adb_ret)
				pr_err("sth: adb root failed: %ld\n", adb_ret);
		} else {
			ksu_handle_execveat_sucompat_user(filename_user,
							  __NR_execveat, regs);
		}
	}

	return ksu_sth_call_orig(__NR_execveat, regs);
}
#endif

#ifdef __NR_faccessat
static long ksu_sth_faccessat(const struct pt_regs *regs)
{
	int *dfd = (int *)&PT_REGS_PARM1(regs);
	const char __user **filename_user =
		(const char __user **)&PT_REGS_PARM2(regs);
	int *mode = (int *)&PT_REGS_PARM3(regs);

	if (ksu_r5g_path_hidden(*filename_user))
		return -ENOENT;

	ksu_handle_faccessat(dfd, filename_user, mode, NULL);

	return ksu_sth_call_orig(__NR_faccessat, regs);
}
#endif

#ifdef __NR_newfstatat
static long ksu_sth_newfstatat(const struct pt_regs *regs)
{
	int *dfd = (int *)&PT_REGS_PARM1(regs);
	const char __user **filename_user =
		(const char __user **)&PT_REGS_PARM2(regs);
	int *flags = (int *)&PT_REGS_SYSCALL_PARM4(regs);

	if (ksu_r5g_path_hidden(*filename_user))
		return -ENOENT;

	ksu_handle_stat(dfd, filename_user, flags);

	return ksu_sth_call_orig(__NR_newfstatat, regs);
}
#endif

/* ---------------- R5G: selinuxfs context hiding ---------------- */

/*
 * SELinux exposes /sys/fs/selinux/context: write "u:r:ksu:s0" and the kernel
 * answers with a SID (or EINVAL for an unknown type).  That makes the su
 * domain we inject visible to any app.  A stock policy has no ksu type, so
 * denying ksu contexts there is indistinguishable from "not installed".
 *
 * The inode is cached at init so the hot path is a single pointer compare.
 */
static struct file *ksu_r5g_ctx_file;
static struct inode *ksu_r5g_ctx_inode;

static void ksu_r5g_selinux_ctx_init(void)
{
	struct file *fp;

	fp = filp_open("/sys/fs/selinux/context", O_RDONLY, 0);
	if (IS_ERR_OR_NULL(fp)) {
		pr_warn("sth: selinuxfs context node unavailable\n");
		return;
	}
	/* keep the file open so the inode cannot be freed under us */
	ksu_r5g_ctx_file = fp;
	ksu_r5g_ctx_inode = fp->f_inode;
	pr_info("sth: selinux context hiding active\n");
}

static bool ksu_r5g_selinux_ctx_hidden(unsigned int fd,
				       const char __user *buf, size_t count)
{
	struct fd f;
	char tmp[128];
	uid_t uid;
	size_t n;

	if (!ksu_r5g_ctx_inode || !count)
		return false;

	uid = current_uid().val;
	if (uid < 10000 || ksu_is_allow_uid_for_current(uid))
		return false;

	f = fdget(fd);
	if (!f.file)
		return false;

	if (f.file->f_inode != ksu_r5g_ctx_inode) {
		fdput(f);
		return false;
	}

	n = count < sizeof(tmp) - 1 ? count : sizeof(tmp) - 1;
	memset(tmp, 0, sizeof(tmp));
	if (strncpy_from_user_nofault(tmp, buf, n) < 0) {
		fdput(f);
		return false;
	}
	fdput(f);

	if (strstr(tmp, "ksu")) {
		pr_info("sth: denied selinux context probe for uid %d\n", uid);
		return true;
	}
	return false;
}

#ifdef __NR_write
static long ksu_sth_write(const struct pt_regs *regs)
{
	if (ksu_r5g_selinux_ctx_hidden((unsigned int)PT_REGS_PARM1(regs),
				       (const char __user *)PT_REGS_PARM2(regs),
				       (size_t)PT_REGS_PARM3(regs)))
		return -EINVAL;

	return ksu_sth_call_orig(__NR_write, regs);
}
#endif

/* ---------------- R5G: path / uname hiding ---------------- */

/*
 * Everything below is hidden from processes that are neither root-allowed nor
 * the manager: apps that probe for root should see a clean system.  Authorized
 * uids (and the manager app) keep full visibility, so su/ksud still work.
 */
static const char *const ksu_r5g_hidden_paths[] = {
	"/data/adb",
	"/data/local/tmp/ksu",
	"/system/bin/su",
	"/system/xbin/su",
	"/sbin/su",
};

static bool ksu_r5g_path_hidden(const char __user *path_user)
{
	char path[128];
	long n;
	uid_t uid;
	int i;

	if (!path_user)
		return false;

	/*
	 * Root and system uids must always see the real filesystem: hiding
	 * /data/adb from uid 0 breaks ksud, the manager and su itself.
	 * Only apps (uid >= 10000) are filtered.
	 */
	uid = current_uid().val;
	if (uid < 10000)
		return false;

	if (ksu_is_allow_uid_for_current(uid))
		return false;

	n = strncpy_from_user_nofault(path, path_user, sizeof(path) - 1);
	if (n <= 0)
		return false;
	path[sizeof(path) - 1] = '\0';

	for (i = 0; i < ARRAY_SIZE(ksu_r5g_hidden_paths); i++) {
		size_t len = strlen(ksu_r5g_hidden_paths[i]);

		if (!strncmp(path, ksu_r5g_hidden_paths[i], len))
			return true;
	}

	return false;
}

#ifdef __NR_openat
static long ksu_sth_openat(const struct pt_regs *regs)
{
	if (ksu_r5g_path_hidden((const char __user *)PT_REGS_PARM2(regs)))
		return -ENOENT;

	return ksu_sth_call_orig(__NR_openat, regs);
}
#endif

#ifdef __NR_readlinkat
static long ksu_sth_readlinkat(const struct pt_regs *regs)
{
	if (ksu_r5g_path_hidden((const char __user *)PT_REGS_PARM2(regs)))
		return -ENOENT;

	return ksu_sth_call_orig(__NR_readlinkat, regs);
}
#endif

/*
 * reboot(2) is the manager's supercall entry point: it calls
 * reboot(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, ...) and receives the
 * driver fd through arg4.  Everything else must go to the real syscall.
 */
#ifdef __NR_reboot
static long ksu_sth_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)PT_REGS_PARM1(regs);
	int magic2 = (int)PT_REGS_PARM2(regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(regs);
	void __user **arg = (void __user **)&PT_REGS_SYSCALL_PARM4(regs);

	if (magic1 != KSU_INSTALL_MAGIC1)
		return ksu_sth_call_orig(__NR_reboot, regs);

	/* only the manager may open a supercall channel this way */
	if (!ksu_sth_prctl_is_manager())
		return ksu_sth_call_orig(__NR_reboot, regs);

	return ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
}
#endif

/*
 * Legacy supercall: the v3.x manager's C++ side falls back to
 *   prctl(0xDEADBEEF, 2, &version, &flags, &result)
 * when the newer fd interface is unavailable.  A positive version with the
 * LKM flag is what makes the manager treat the driver as installed.
 */
#define KSU_PRCTL_MAGIC 0xDEADBEEF
#define KSU_PRCTL_CMD_GET_INFO 2

/*
 * The supercall magic is itself a KernelSU signature: a stock kernel answers
 * EINVAL for an unknown prctl option.  Answering the manager is required, but
 * answering every other probe leaks both the driver and its tail (the probe
 * app gets a live [ksu_driver] fd and an EFAULT instead of EINVAL).
 */
static bool ksu_sth_prctl_is_manager(void)
{
	/*
	 * Root already owns the machine and cannot be reached by an app, so
	 * answering uid 0 leaks nothing -- and ksud (which runs as root) needs
	 * the channel to install its driver fd.
	 */
	if (current_uid().val == 0)
		return true;

	if (ksu_is_manager_appid_valid() && is_manager())
		return true;

	/*
	 * track_throne() may not have crowned the manager yet (the APK lives
	 * on /data/app, and crowning needs a package scan).  Fall back to the
	 * process name Android gives the manager: ART truncates the package
	 * name to TASK_COMM_LEN - 1, so com.rifsxd.ksunext shows up as
	 * ".rifsxd.ksunext".
	 */
	return strstr(current->comm, "ksunext") != NULL;
}

#ifdef __NR_prctl
static long ksu_sth_prctl(const struct pt_regs *regs)
{
	int option = (int)PT_REGS_PARM1(regs);
	unsigned long cmd = PT_REGS_PARM2(regs);
	unsigned long a3 = PT_REGS_PARM3(regs);
	unsigned long a4 = PT_REGS_SYSCALL_PARM4(regs);
	unsigned long a5 = PT_REGS_PARM5(regs);

	if (option != KSU_PRCTL_MAGIC)
		return ksu_sth_call_orig(__NR_prctl, regs);

	if (!ksu_sth_prctl_is_manager())
		return ksu_sth_call_orig(__NR_prctl, regs);

	if (cmd == KSU_PRCTL_CMD_GET_INFO) {
		int32_t version = KSU_VERSION;
		int32_t flags = KSU_GET_INFO_FLAG_LKM |
				KSU_GET_INFO_FLAG_LATE_LOAD;
		int32_t result = 0;

		pr_info("sth: legacy prctl get_info v=%d flags=%#x\n", version,
			flags);
		/*
		 * Hand the caller a driver fd the first time it looks for the
		 * version: the manager app only scans /proc/self/fd and would
		 * otherwise be stuck with fd == -1 for every ioctl.
		 */
		if (!ksu_has_driver_fd()) {
			int fd = ksu_install_fd();

			pr_info("sth: installed driver fd %d for pid %d\n", fd,
				current->pid);
		}
		if (copy_to_user((void __user *)a3, &version, sizeof(version)) ||
		    copy_to_user((void __user *)a4, &flags, sizeof(flags)) ||
		    copy_to_user((void __user *)a5, &result, sizeof(result)))
			return -EFAULT;
		return 0;
	}

	pr_info("sth: legacy prctl cmd=%lu (unsupported)\n", cmd);
	return -EINVAL;
}
#endif

void __init ksu_syscall_table_hook_init(void)
{
	struct {
		int nr;
		ksu_syscall_fn_t wrapper;
	} hooks[] = {
#ifdef __NR_execve
		{ __NR_execve, ksu_sth_execve },
#endif
#ifdef __NR_execveat
		{ __NR_execveat, ksu_sth_execveat },
#endif
#ifdef __NR_faccessat
		{ __NR_faccessat, ksu_sth_faccessat },
#endif
#ifdef __NR_newfstatat
		{ __NR_newfstatat, ksu_sth_newfstatat },
#endif
#ifdef __NR_reboot
		{ __NR_reboot, ksu_sth_reboot },
#endif
#ifdef __NR_prctl
		{ __NR_prctl, ksu_sth_prctl },
#endif
#ifdef __NR_openat
		{ __NR_openat, ksu_sth_openat },
#endif
#ifdef __NR_readlinkat
		{ __NR_readlinkat, ksu_sth_readlinkat },
#endif
#ifdef __NR_write
		{ __NR_write, ksu_sth_write },
#endif
	};
	int i, patched = 0;

	ksu_init_symbol_resolver();

	ksu_sth_syscall_table =
		(ksu_syscall_fn_t *)ksu_resolve_symbol_for_functable_hook(
			"sys_call_table");
	pr_info("sth: sys_call_table=0x%lx\n",
		(unsigned long)ksu_sth_syscall_table);

	if (!ksu_sth_syscall_table) {
		pr_err("sth: sys_call_table not found, table hook disabled\n");
		ksu_r5g_log("sth: sys_call_table NOT FOUND\n");
		return;
	}
	{
		char b[128];
		snprintf(b, sizeof(b), "sth: table=%#lx\n",
			 (unsigned long)ksu_sth_syscall_table);
		ksu_r5g_log(b);
	}

	mutex_lock(&ksu_sth_lock);

	ksu_r5g_selinux_ctx_init();

	for (i = 0; i < ARRAY_SIZE(hooks); i++) {
		ksu_syscall_fn_t orig =
			READ_ONCE(ksu_sth_syscall_table[hooks[i].nr]);
		if (!orig) {
			pr_warn("sth: syscall %d has no original, skip\n",
				hooks[i].nr);
			continue;
		}
		ksu_sth_record(hooks[i].nr, orig);
		if (!ksu_sth_patch(hooks[i].nr, hooks[i].wrapper))
			patched++;
		else {
			char b[64];
			snprintf(b, sizeof(b), "sth: patch %d FAILED\n",
				 hooks[i].nr);
			ksu_r5g_log(b);
		}
	}

	mutex_unlock(&ksu_sth_lock);

	pr_info("sth: %d/%ld syscalls hooked\n", patched,
		(long)ARRAY_SIZE(hooks));
	{
		char b[128];
		snprintf(b, sizeof(b), "sth: hooked=%d/%d\n", patched,
			 (int)ARRAY_SIZE(hooks));
		ksu_r5g_log(b);
	}
}

void __exit ksu_syscall_table_hook_exit(void)
{
	int i;

	if (!ksu_sth_syscall_table)
		return;

	mutex_lock(&ksu_sth_lock);

	for (i = 0; i < ksu_sth_count; i++) {
		int nr = ksu_sth_entries[i].nr;
		ksu_syscall_fn_t orig = ksu_sth_entries[i].orig;

		pr_info("sth: restore syscall %d to 0x%lx\n", nr,
			(unsigned long)orig);
		if (ksu_patch_text(&ksu_sth_syscall_table[nr], &orig,
				   sizeof(orig),
				   KSU_PATCH_TEXT_FLUSH_DCACHE))
			pr_err("sth: restore syscall %d failed\n", nr);
	}
	ksu_sth_count = 0;

	mutex_unlock(&ksu_sth_lock);
}

#else // !KSU_SYSCALL_TABLE_HOOK

#include "hook/syscall_table_hook.h"

void __init ksu_syscall_table_hook_init(void)
{
}

void __exit ksu_syscall_table_hook_exit(void)
{
}

#endif // KSU_SYSCALL_TABLE_HOOK
