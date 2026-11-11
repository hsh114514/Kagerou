#!/system/bin/sh
# Apply KernelSU's SELinux rules to the *live* policy and switch to enforcing.
#
# Run as root after loading kernelsu.ko: without the su domain, enforcing
# locks root out of /data/adb.  Safe to run more than once.

DIR=$(dirname "$0")
MP="$DIR/magiskpolicy"
[ -x "$MP" ] || MP=/data/adb/ksu/bin/magiskpolicy
[ -x "$MP" ] || MP=/data/local/tmp/magiskpolicy
if [ ! -x "$MP" ]; then
	echo "ksu_enforce: magiskpolicy not found" >&2
	exit 1
fi

# Essentials: create the domain, mark it permissive, give it the attributes
# the rest of the policy keys on.
"$MP" --live \
	"type ksu domain" \
	"permissive ksu" \
	"typeattribute ksu mlstrustedsubject" \
	"typeattribute ksu netdomain" \
	"typeattribute ksu bluetoothdomain"
if [ $? -ne 0 ]; then
	echo "ksu_enforce: essential rules failed" >&2
	exit 1
fi

# Everything else: let the rest of the system interoperate with su.
"$MP" --live \
	"type ksu_file file_type" \
	"typeattribute ksu_file mlstrustedobject" \
	"allow domain ksu_file file *" \
	"allow domain ksu process sigchld" \
	"allow domain ksu fd use" \
	"allow domain ksu fifo_file { read write open getattr }" \
	"allow domain ksu unix_stream_socket { read write connectto getopt getattr }" \
	"allow domain ksu binder *" \
	"allow domain ksu memfd_file { execute getattr map read write }" \
	"allow logd ksu dir search" \
	"allow logd ksu file { read open getattr }" \
	"allow servicemanager ksu dir search" \
	"allow servicemanager ksu file { read open }" \
	"allow servicemanager ksu process getattr" \
	"allow hwservicemanager ksu dir search" \
	"allow hwservicemanager ksu file { read open }" \
	"allow hwservicemanager ksu process getattr" \
	"allow system_server ksu process { getpgid sigkill }" \
	"allow init ksu * *" \
	"allow zygote adb_data_file dir search" 2>/dev/null

# `apply` stops after injecting the rules: the caller still has to write files
# with ksu_file labels, which needs the permissive window.
if [ "$1" = "apply" ]; then
	echo "ksu_enforce: rules applied, enforce untouched"
	exit 0
fi

if [ "$(getenforce)" = "Enforcing" ]; then
	echo "ksu_enforce: already enforcing"
	exit 0
fi
if echo 1 > /sys/fs/selinux/enforce 2>/dev/null; then
	echo "ksu_enforce: enforcing enabled"
else
	echo "ksu_enforce: could not switch to enforcing" >&2
	exit 1
fi
