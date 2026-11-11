#!/bin/bash
# Build kernelsu.ko in WSL against the R5G 4.19 tree.
set -o pipefail
export PATH="$HOME/kb/tc/gcc/bin:$PATH"
SRC="$HOME/r5g-full/AQUOS_R5G_S2005/LINUX/android/kernel/msm-4.19"
OUT="$HOME/r5g-vmlinux-out"
M="/mnt/d/Project/R5G/ksu/ksun-legacy/kernel"
make -C "$SRC" O="$OUT" M="$M" \
     CONFIG_KSU=m CONFIG_KSU_SYSCALL_TABLE_HOOK=y \
     ARCH=arm64 CROSS_COMPILE=aarch64-linux-androidkernel- \
     CLANG_TRIPLE=aarch64-linux-gnu- CC="$HOME/bin/clang-kernel" \
     modules 2>&1 | tail -40
