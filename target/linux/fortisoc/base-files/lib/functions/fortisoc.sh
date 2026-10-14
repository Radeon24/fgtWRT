# SPDX-License-Identifier: GPL-2.0-only
#
# Persistent overlay of the FortiSOC targets: a device tree node
# "fortinet,disk-rootfs-data", a direct child of the root, describes
# where the rootfs_data of the overlay lies on a disk (the rest of the
# firmware slot, after the container). Without it, the system runs from
# its initramfs as before, with a RAM root. The paths below can be set
# beforehand, for a test outside the target.

: "${FORTISOC_DT_BASE:=/sys/firmware/devicetree/base}"
: "${FORTISOC_SYS_BLOCK:=/sys/block}"
: "${FORTISOC_DEV:=/dev}"

# Print the directory of the rootfs_data node; fail without one. The
# compatible property is a list of NUL-terminated strings.
fortisoc_rootfs_data_node() {
	local f

	for f in "$FORTISOC_DT_BASE"/*/compatible; do
		[ -f "$f" ] || continue
		tr '\0' '\n' < "$f" | grep -qx 'fortinet,disk-rootfs-data' || continue
		echo "${f%/compatible}"
		return 0
	done
	return 1
}

# Create the block node of the whole disk $1 from its sysfs major:minor,
# unless it exists. In preinit, procd only made the nodes of the devices
# present when it started, and a USB disk shows up later. mknod here is
# synchronous, right before mount_root, whatever the order of the hotplug
# events; a makedev rule in hotplug-preinit.json would race with it.
fortisoc_disk_node() {
	local name="$1" mm

	[ -e "$FORTISOC_DEV/$name" ] && return 0
	mm="$(cat "$FORTISOC_SYS_BLOCK/$name/dev" 2>/dev/null)"
	case "$mm" in
	[0-9]*:[0-9]*)
		mknod -m 0600 "$FORTISOC_DEV/$name" b "${mm%%:*}" "${mm#*:}" &&
			return 0
		;;
	esac
	echo "- rootfs_data: cannot create $FORTISOC_DEV/$name (${mm:-no dev}) -"
	return 1
}

# Wait, at most $2 seconds (default 15), for a disk of the size given by
# the node $1 (fortinet,disk-sectors, a big-endian 64-bit cell pair), as
# USB storage is probed asynchronously, and make sure the /dev node of
# each disk of that size exists (fstools picks among them by vendor and
# model). Fail if none shows up.
fortisoc_rootfs_data_wait() {
	local node="$1" timeout="${2:-15}" hex sectors dev found n=0

	hex="$(hexdump -v -e '1/1 "%02x"' "$node/fortinet,disk-sectors" 2>/dev/null)"
	[ "${#hex}" = 16 ] || return 1
	sectors=$((0x$hex))

	while :; do
		found=0
		for dev in "$FORTISOC_SYS_BLOCK"/*; do
			case "${dev##*/}" in
			loop*|ram*|mtdblock*|zram*) continue ;;
			esac
			[ "$(cat "$dev/size" 2>/dev/null)" = "$sectors" ] || continue
			fortisoc_disk_node "${dev##*/}"
			found=1
		done
		[ "$found" = 1 ] && return 0
		[ "$n" -ge "$timeout" ] && return 1
		sleep 1
		n=$((n + 1))
	done
}
