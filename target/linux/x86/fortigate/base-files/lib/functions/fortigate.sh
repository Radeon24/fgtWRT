# SPDX-License-Identifier: GPL-2.0-only
#
# Persistent overlay of the FortiGate x86 boards: without a device tree,
# the kernel command line built into the image describes where the
# rootfs_data of the overlay lies on a disk (the rest of the firmware
# slot, after the container):
#
#	fortinet.rootfs_data=<vendor>,<model>,<disk sectors>,<start>+<count>
#
# vendor and model are the device/vendor and device/model sysfs strings
# of the disk, '_' standing for a space; sectors are 512 bytes, absolute
# on the disk. fstools reads the same parameter, checks the range and
# claims it. A device tree node "fortinet,disk-rootfs-data" keeps the
# priority: the parameter is then ignored, as fstools does. Without the
# parameter, the system runs from its initramfs as before, with a RAM
# root. The paths below can be set beforehand, for a test outside the
# target.

: "${FORTIGATE_PROC_CMDLINE:=/proc/cmdline}"
: "${FORTIGATE_DT_BASE:=/sys/firmware/devicetree/base}"
: "${FORTIGATE_SYS_BLOCK:=/sys/block}"
: "${FORTIGATE_DEV:=/dev}"

# True when a device tree node, direct child of the root, is compatible
# with "fortinet,disk-rootfs-data" (a list of NUL-terminated strings).
fortigate_dt_rootfs_data() {
	local f

	for f in "$FORTIGATE_DT_BASE"/*/compatible; do
		[ -f "$f" ] || continue
		tr '\0' '\n' < "$f" | grep -qx 'fortinet,disk-rootfs-data' &&
			return 0
	done
	return 1
}

# Print the value of the fortinet.rootfs_data parameter of the command
# line. Returns 0 when given once with a value, 1 when absent (or when
# a device tree node describes the range), 2 when repeated or without a
# value: present, but no description (said on stderr).
fortigate_rootfs_data_value() {
	local words n

	fortigate_dt_rootfs_data && return 1
	words="$(tr ' \t' '\n\n' < "$FORTIGATE_PROC_CMDLINE" 2>/dev/null |
		grep -E '^fortinet\.rootfs_data(=|$)')"
	[ -n "$words" ] || return 1
	n="$(echo "$words" | wc -l)"
	[ "$n" = 1 ] || {
		echo "- rootfs_data: fortinet.rootfs_data given $n times, no overlay -" >&2
		return 2
	}
	case "$words" in
	fortinet.rootfs_data=?*) ;;
	*)
		echo "- rootfs_data: fortinet.rootfs_data without a value, no overlay -" >&2
		return 2
		;;
	esac
	echo "${words#fortinet.rootfs_data=}"
}

# Vendor or model field $1: non-empty, at most 64 bytes, '_' for a
# space, trailing blanks dropped (as fstools compares them). Printed;
# fails when blank.
fortigate_rootfs_data_string() {
	local s

	[ -n "$1" ] && [ "${#1}" -le 64 ] || return 1
	s="$(printf '%s' "$1" | tr '_' ' ' | sed 's/[[:space:]]*$//')"
	[ -n "$s" ] || return 1
	echo "$s"
}

# Decimal field $1, digits only; printed without its leading zeros.
fortigate_rootfs_data_number() {
	case "$1" in
	''|*[!0-9]*) return 1 ;;
	esac
	echo "$1" | sed 's/^0*//; s/^$/0/'
}

# Parse the value $1 of fortinet.rootfs_data into FGT_RD_VENDOR,
# FGT_RD_MODEL, FGT_RD_SECTORS, FGT_RD_START and FGT_RD_COUNT. The
# syntax only: the range rules (alignment, bounds) are fstools'.
fortigate_rootfs_data_parse() {
	local val="$1" rest range

	FGT_RD_VENDOR= FGT_RD_MODEL= FGT_RD_SECTORS= FGT_RD_START= FGT_RD_COUNT=
	[ "$(printf '%s' "$val" | tr -cd ',' | wc -c)" = 3 ] || return 1
	rest="${val#*,}"
	FGT_RD_VENDOR="$(fortigate_rootfs_data_string "${val%%,*}")" || return 1
	FGT_RD_MODEL="$(fortigate_rootfs_data_string "${rest%%,*}")" || return 1
	rest="${rest#*,}"
	FGT_RD_SECTORS="$(fortigate_rootfs_data_number "${rest%%,*}")" || return 1
	range="${rest#*,}"
	case "$range" in
	*+*+*|+*|*+) return 1 ;;
	*+*) ;;
	*) return 1 ;;
	esac
	FGT_RD_START="$(fortigate_rootfs_data_number "${range%+*}")" || return 1
	FGT_RD_COUNT="$(fortigate_rootfs_data_number "${range#*+}")" || return 1
}

# Create the block node of the whole disk $1 from its sysfs major:minor,
# unless it exists. In preinit, procd only made the nodes of the devices
# present when it started; mknod here is synchronous, right before
# mount_root, whatever the order of the hotplug events.
fortigate_disk_node() {
	local name="$1" mm

	[ -e "$FORTIGATE_DEV/$name" ] && return 0
	mm="$(cat "$FORTIGATE_SYS_BLOCK/$name/dev" 2>/dev/null)"
	case "$mm" in
	[0-9]*:[0-9]*)
		mknod -m 0600 "$FORTIGATE_DEV/$name" b "${mm%%:*}" "${mm#*:}" &&
			return 0
		;;
	esac
	echo "- rootfs_data: cannot create $FORTIGATE_DEV/$name (${mm:-no dev}) -"
	return 1
}

# True when the sysfs attribute $1 (SCSI pads vendor and model with
# spaces, which read drops) equals $2.
fortigate_sys_string_is() {
	local got

	read -r got < "$1" 2>/dev/null || return 1
	[ "$got" = "$2" ]
}

# Wait, at most $2 seconds (default 15), for a whole disk of the size,
# vendor and model given by the value $1 of fortinet.rootfs_data, and
# make sure the /dev node of each such disk exists (fstools picks the
# one disk among them). A SATA disk is normally probed before preinit;
# the wait is a bound, not a delay. Returns 0 when one shows up, 1 when
# none does, 2 when the value is malformed (no wait).
fortigate_rootfs_data_wait() {
	local timeout="${2:-15}" dev found n=0

	fortigate_rootfs_data_parse "$1" || {
		echo "- rootfs_data: malformed fortinet.rootfs_data=$1, no overlay -"
		return 2
	}

	while :; do
		found=0
		for dev in "$FORTIGATE_SYS_BLOCK"/*; do
			case "${dev##*/}" in
			loop*|ram*|mtdblock*|zram*) continue ;;
			esac
			[ -e "$dev/partition" ] && continue
			[ "$(cat "$dev/size" 2>/dev/null)" = "$FGT_RD_SECTORS" ] ||
				continue
			fortigate_sys_string_is "$dev/device/vendor" "$FGT_RD_VENDOR" &&
				fortigate_sys_string_is "$dev/device/model" \
					"$FGT_RD_MODEL" || continue
			fortigate_disk_node "${dev##*/}"
			found=1
		done
		[ "$found" = 1 ] && return 0
		[ "$n" -ge "$timeout" ] && return 1
		sleep 1
		n=$((n + 1))
	done
}
