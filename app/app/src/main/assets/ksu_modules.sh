#!/system/bin/sh
# Module bootstrap and management for the late-loaded KernelSU LKM.
#
#   merge        - move modules_update/<id> into modules/ (what post-fs-data does)
#   zygote       - restart zygote64 only
#   lsposed      - the "fix" sequence: zygiskd, sepolicy, lspd in init's mount
#                  namespace, zygote restart, wait for the bridge
#   list         - one tab-separated line per module:
#                  id, name, version, author, size_kb, state, mounted, updatable
#   remove <id>  - delete the module
#   update <id>  - move modules_update/<id> into modules/ (its "update")
#
# This is the userspace work ksud's post-fs-data would have done.  That stage
# cannot run here: the module is loaded late, and ksud's full late-load path
# deadlocks on this device.  Run as root.

PATH=/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin:$PATH
export PATH

MODE="$1"
ARG="$2"

# If anything kills this shell mid-way (the zygote restart has been seen to
# take out the launcher), leave a marker instead of a log that just stops.
# INT/HUP are ignored: the restart has been observed to deliver them to the
# detached script, which used to cut it off right after the bridge.
trap 'echo "[end] rc=$? at $(date +%H:%M:%S)"' EXIT
trap '' INT HUP TERM

# Module ids are copied back from `list`, but keep them to the character set
# KernelSU allows so nothing else can be smuggled into a path.
case "$ARG" in
"") ;;
*[!A-Za-z0-9._-]*)
	echo "invalid module id"
	exit 3
	;;
esac

merge() {
	[ -d /data/adb/modules_update ] || return 0
	for d in /data/adb/modules_update/*; do
		[ -d "$d" ] || continue
		id=${d##*/}
		# The installer leaves module.prop + update in modules/<id>, so the
		# old dir has to go before the staged one can take its place.
		rm -rf "/data/adb/modules/$id"
		if mv "$d" "/data/adb/modules/$id"; then
			echo "merged $id"
		else
			echo "merge failed $id"
		fi
	done
}

list() {
	# Markers let the app tell a complete list from a truncated capture.
	echo "#BEGIN"
	for d in /data/adb/modules/*; do
		[ -d "$d" ] || continue
		id=${d##*/}
		name=$(sed -n 's/^name=//p' "$d/module.prop" 2>/dev/null | head -1)
		ver=$(sed -n 's/^version=//p' "$d/module.prop" 2>/dev/null | head -1)
		author=$(sed -n 's/^author=//p' "$d/module.prop" 2>/dev/null | head -1)
		[ -n "$name" ] || name=$id
		size=$(du -sk "$d" 2>/dev/null | awk '{print $1}')
		[ -n "$size" ] || size=0
		state=ok
		[ -f "$d/remove" ] && state=remove
		[ -f "$d/disable" ] && state=disabled
		[ -f "$d/update" ] && state=pending
		mounted=0
		if grep -q "$id" /proc/self/mountinfo 2>/dev/null; then
			mounted=1
		fi
		updatable=0
		[ -d "/data/adb/modules_update/$id" ] && updatable=1
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$id" "$name" "$ver" "$author" "$size" "$state" "$mounted" "$updatable"
	done
	echo "#END"
}

remove_one() {
	id="$1"
	[ -n "$id" ] || { echo "missing id"; return 1; }
	rm -rf "/data/adb/modules/$id" "/data/adb/modules_update/$id"
	if [ -d "/data/adb/modules/$id" ]; then
		echo "remove failed $id"
		return 1
	fi
	echo "removed $id"
}

# "更新" is the merge step for a single module: the installer staged it in
# modules_update, and moving it into modules/ is what makes it take effect.
update_one() {
	id="$1"
	[ -n "$id" ] || { echo "missing id"; return 1; }
	src="/data/adb/modules_update/$id"
	[ -d "$src" ] || { echo "no update for $id"; return 1; }
	rm -rf "/data/adb/modules/$id"
	if mv "$src" "/data/adb/modules/$id"; then
		echo "updated $id"
	else
		echo "update failed $id"
		return 1
	fi
}

# LSPosed: a straight port of the user's fix_lspd.sh.  In particular it does
# NOT apply any sepolicy: doing so upsets the environment and is unnecessary.
# The module's own post-fs-data.sh only does `./lspd &`, which starts lspd in
# the wrong mount namespace and never gets the system_server bridge.
lsposed() {
	MODDIR=/data/adb/modules/zygisk_lsposed
	LOGDIR=/data/adb/lspd/log
	ZYGISKDIR=/data/adb/modules/zygisksu
	[ -d "$MODDIR" ] || { echo "no lsposed module"; return 1; }

	echo "[1] kill old lspd"
	for p in $(pidof lspd); do
		kill -9 "$p" 2>/dev/null
	done
	sleep 1

	echo "[2] zygote env"
	ZPID=$(pidof zygote64)
	[ -n "$ZPID" ] || { echo "no zygote64"; return 1; }
	BOOTCP=$(cat /proc/$ZPID/environ 2>/dev/null | tr '\0' '\n' | grep '^BOOTCLASSPATH=' | head -1)
	DEX2OAT=$(cat /proc/$ZPID/environ 2>/dev/null | tr '\0' '\n' | grep '^DEX2OATBOOTCLASSPATH=' | head -1)
	[ -n "$BOOTCP" ] || { echo "no BOOTCLASSPATH"; return 1; }
	echo "  zygote64=$ZPID"

	echo "[3] zygiskd daemon"
	cd "$ZYGISKDIR" || return 1
	./bin/zygiskd daemon 2>&1 &
	sleep 3
	echo "[4] zygiskd service-stage"
	./bin/zygiskd service-stage 2>&1 &
	sleep 2

	echo "[5] clean lspd state"
	rm -f /data/adb/lspd/monitor /data/adb/lspd/lock

	OLD_SS=$(pidof system_server)
	echo "[6] old system_server=${OLD_SS:-none}"

	echo "[7] start lspd"
	java_options="-Djava.class.path=$MODDIR/daemon.apk -Xnoimage-dex2oat"
	: >/data/local/tmp/r5gk/lspd-start.log
	/system/bin/setsid /system/bin/nsenter -t 1 -m -- /system/bin/sh -c "
		cd $MODDIR
		export ANDROID_ROOT=/system
		export ANDROID_DATA=/data
		export ANDROID_ART_ROOT=/apex/com.android.art
		export ANDROID_I18N_ROOT=/apex/com.android.i18n
		export ANDROID_TZDATA_ROOT=/apex/com.android.tzdata
		export $BOOTCP
		export $DEX2OAT
		export PATH=$PATH
		exec /system/bin/app_process $java_options /system/bin --nice-name=lspd org.lsposed.lspd.Main
	" </dev/null >>/data/local/tmp/r5gk/lspd-start.log 2>&1 &
	# app_process can take a moment to show up as `lspd`; poll instead of
	# trusting a single 3 s check.
	i=0
	LSPD=
	while [ $i -lt 12 ]; do
		i=$((i + 1))
		sleep 1
		LSPD=$(pidof lspd)
		[ -n "$LSPD" ] && break
	done
	if [ -z "$LSPD" ]; then
		echo "lspd failed to start (${i}s)"
		cat /data/local/tmp/r5gk/lspd-start.log 2>/dev/null
		return 1
	fi
	echo "  lspd=$LSPD"
	sleep 5
	[ -n "$(pidof lspd)" ] || { echo "lspd crashed"; return 1; }
	echo "  lspd alive"

	echo "[8] kill zygote64"
	kill -9 $(pidof zygote64)

	echo "[9] wait old system_server"
	i=0
	while [ $i -lt 15 ]; do
		i=$((i + 1))
		sleep 1
		kill -0 "$OLD_SS" 2>/dev/null || break
	done

	echo "[10] wait new system_server"
	NEW_SS=
	i=0
	while [ $i -lt 30 ]; do
		i=$((i + 1))
		sleep 1
		NEW_SS=$(pidof system_server)
		[ -n "$NEW_SS" ] && [ "$NEW_SS" != "$OLD_SS" ] && break
	done
	[ -n "$NEW_SS" ] || { echo "no new system_server"; return 1; }
	echo "  system_server=$NEW_SS"

	echo "[11] wait bridge"
	i=0
	BRIDGE=no
	while [ $i -lt 90 ]; do
		i=$((i + 1))
		sleep 1
		L=$(ls -t $LOGDIR/verbose_*.log 2>/dev/null | head -1)
		# Only a line for *this* system_server counts; the log also holds
		# entries from earlier instances.
		if [ -n "$L" ] && grep "binder received" "$L" 2>/dev/null | grep -q "$NEW_SS"; then
			BRIDGE=yes
			echo "  bridge at ${i}s"
			break
		fi
		[ $((i % 10)) -eq 0 ] && echo "  still waiting (${i}s)"
	done

	sleep 15
	chmod 644 /data/adb/lspd/monitor 2>/dev/null

	# The notification LSPosed posts opens org.lsposed.manager; without it the
	# tap does nothing.
	if ! pm list packages 2>/dev/null | grep -q "org.lsposed.manager"; then
		cp "$MODDIR/manager.apk" /data/local/tmp/lsp-manager.apk 2>/dev/null &&
			chmod 644 /data/local/tmp/lsp-manager.apk 2>/dev/null &&
			pm install -r /data/local/tmp/lsp-manager.apk >/dev/null 2>&1 &&
			echo "  manager installed"
	fi
	echo "lspd=$(pidof lspd) bridge=$BRIDGE"
}

restart_zygote() {
	pid=$(pidof zygote64)
	if [ -z "$pid" ]; then
		echo "no zygote64"
		return 1
	fi
	# init treats zygote as critical and restarts it, which brings up a new
	# system_server.  Do not use stop/start: that hangs this device.
	kill -9 $pid
	echo "zygote64 killed ($pid)"
}

case "$MODE" in
merge) merge ;;
zygote) restart_zygote ;;
lsposed) lsposed ;;
list) list ;;
remove) remove_one "$ARG" ;;
update) update_one "$ARG" ;;
*)
	echo "usage: $0 merge|zygote|lsposed|list|remove <id>|update <id>"
	exit 2
	;;
esac
