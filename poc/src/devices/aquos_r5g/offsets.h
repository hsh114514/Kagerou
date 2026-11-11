#define STRUCT_OFFSETS_4_19_R5G \
  .task_prio=0xac, .task_normal_prio=0xb4, .task_sched_task_group=0x3c0, \
  .task_pi_lock=0x8a4, .task_pi_waiters=0x8b0, \
  .task_pi_top_task=0x8c0, .task_pi_blocked_on=0x8c8, \
  .task_pid=0x628, .task_tgid=0x62c, .task_real_parent=0x638, \
  .task_atomic_flags=0x5f0, .task_real_cred=0x7d0, .task_cred=0x7d8, \
  .task_comm=0x7e0, .task_tasks=0x528, .task_seccomp=0x880, \
  .mm_owner=0x328, .waiter_compact=1

OFFSETS_ENTRY("4.19.125-perf",
  .kernel_phys_load=0x80080000ULL,
  .kimage_text_base=0xffffff8008080000ULL,
  STRUCT_OFFSETS_4_19_R5G,
  .off_init_task=0x279bec0,
  .off_init_cred=0x27ab4d0,
  .off_init_uts_ns=0x279bc68,
  .off_empty_zero_page=0x2a0f000,
  .off_root_task_group=0x2a15d40,
  /* selinux_state + 1: CONFIG_SECURITY_SELINUX_DISABLE is on, so the
   * struct starts with `bool disabled` and `bool enforcing` follows it
   * (verified: sel_write_enforce does strb [state,#1], max=0x1). */
  .off_selinux_enforcing=0x31b6001,
  .off_kptr_restrict=0x279b790,
  .off_selinux_blob_sizes=0,
  .off_security_hook_heads=0x1f4f298,
  .off_kmalloc_caches=0x1f4ed98,
  .off_anon_pipe_buf_ops=0x18e3ec0,
  .off_ashmem_misc_fops=0x29302b0,
  .off_ashmem_fops=0x19b2790,
  .off_ashmem_ioctl=0xc09400,
  .off_ashmem_compat_ioctl=0xc09d30,
  .off_ashmem_mmap=0xc09d80,
  .off_ashmem_open=0xc09ee8,
  .off_ashmem_release=0xc09f60,
  .off_ashmem_show_fdinfo=0xc0a078,
  .off_configfs_read_iter=0x2dd488,
  .off_configfs_bin_write_iter=0x2dd978,
  .off_copy_splice_read=0x2702f8,
  .off_noop_llseek=0x22d7e0,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x2792270,
  .off_slide_loggers_0_1=0x27921a8,
  .off_slide_boot_id=0x2aa9a4c,
  .off_system_unbound_wq=0,
  .off_call_usermodehelper_exec_work=0,
),
