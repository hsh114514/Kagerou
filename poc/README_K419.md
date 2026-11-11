# GhostLock Adapter for 4.19.152-perf+ Kernel

基于 [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) 的 CVE-2026-43499 (GhostLock) 漏洞利用适配。

## 目标内核

```
Linux version 4.19.152-perf+ (compiler@comdg01146232)
(clang version 10.0.5 for Android NDK, GNU ld (binutils-2.27-bd24d23f) 2.27.0.20170315)
#1 SMP PREEMPT Mon Mar 31 16:22:45 CST 2025
```

## 构建

### 本地构建（需要 Android NDK）

```bash
NDK=/path/to/android-ndk-r26d
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang \
  -O2 -Wall -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"target.h\" \
  src/core/main.c src/core/util.c src/core/slide.c \
  src/core/fops.c src/core/pipe_physrw.c src/core/root.c \
  src/core/miniadb.c src/core/umh_root.c \
  -o ghostlock -fPIE -pie -pthread
```

### 云端编译（GitHub Actions）

推送到 main 分支后自动触发 GitHub Actions 构建。
前往 [Actions](https://github.com/XiaoBaiLovesStirring/ghostlock-k419-adapter/actions) 页面下载编译产物。

## 使用

```bash
adb push ghostlock /data/local/tmp/a/e
adb shell chmod 755 /data/local/tmp/a/e
adb shell /data/local/tmp/a/e
```

## 偏移量来源

所有偏移量从目标内核的 `kernel.elf` 中提取：
- 全局符号偏移：通过 `nm` 从 ELF 中直接提取
- 结构体偏移：通过反汇编分析验证
- 缺失符号：通过 `kallsyms_lookup_name` 在运行时动态解析

## 注意

1. 首次运行后可能触发内核崩溃（kernel panic），这是正常现象
2. 使用 `PSELECT_SHIFT` 环境变量调整栈布局偏移
3. 需要 `ksud` 二进制文件来持久化 KernelSU 安装