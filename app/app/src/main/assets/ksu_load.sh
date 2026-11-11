#!/system/bin/sh
# Run as root (the exploit's --root-write child): load the module, install the
# userspace half of KernelSU, then turn enforcing SELinux back on.
#
# The kernel treats an insmod from anything but pid 1 as a late load: it grants
# root to the insmod process and skips the boot-time init.rc work.  Everything
# userspace therefore has to happen here:
#
#   * the ksu/ksu_file SELinux types, without which the su redirect target
#     cannot be opened and the kernel silently falls back to /system/bin/sh;
#   * /data/adb/ksud itself, which /system/bin/su is redirected to and which
#     the manager drives its root shell through.
#
# ksud's own `late-load` is deliberately not used: it rescans /data and remounts
# modules, which on this device ends in a printk deadlock.

DIR=$(dirname "$0")

# The exploit's parent can return before this script is done, which closes the
# stdout pipe.  Without this a single echo would SIGPIPE the shell halfway
# through the policy patch and leave SELinux permissive.
trap '' PIPE

insmod "$DIR/kernelsu_r5g.ko" allow_shell=1
echo "insmod rc=$?"

# A late load flips enforcing on by itself.  Drop it again while the policy and
# the userspace files are written; the last ksu_enforce.sh puts it back.
echo 0 > /sys/fs/selinux/enforce

# Cheap evidence for "the manager cannot get root": what the module crowned and
# what is actually installed.
echo "--- crown ---"
stat -c "manager uid=%u" /data/data/com.rifsxd.ksunext 2>&1
dmesg 2>/dev/null | grep -iE "crown|manager pkg|su domain|transive" | tail -8

# Inject the types first: ksu_file has to exist before anything can be labelled
# with it, and labelling needs the permissive window we are still in.
#
# Both policy runs send their own output to /dev/null: if the exploit's parent
# exits early the stdout pipe is gone, and a write there would SIGPIPE the whole
# script halfway through the policy patch.
if "$DIR/ksu_enforce.sh" apply >/dev/null 2>&1; then
	echo "rules applied"
else
	echo "rules apply failed"
fi

if [ -x "$DIR/ksud" ]; then
	echo "--- ksud install ---"
	# From /data/local/tmp, never /data/adb/ksud: install() unlinks the daemon
	# path before copying itself there, so running it from that path deletes
	# the running binary and fails with ENOENT.
	"$DIR/ksud" install >/dev/null 2>&1
	echo "install rc=$?"
fi

# install() can bail halfway; su only needs the file and its label.
if [ ! -x /data/adb/ksud ] && [ -x "$DIR/ksud" ]; then
	cp "$DIR/ksud" /data/adb/ksud
	chmod 755 /data/adb/ksud
	echo "ksud copied by fallback"
fi
chcon u:object_r:ksu_file:s0 /data/adb/ksud 2>/dev/null

if "$DIR/ksu_enforce.sh" >/dev/null 2>&1; then
	echo "enforcing enabled"
else
	echo "enforcing failed"
fi

echo "--- state ---"
id
ls -lZ /data/adb/ksud 2>&1
if [ -x /data/adb/ksud ]; then
	echo "ksud present"
else
	echo "ksud missing"
fi
