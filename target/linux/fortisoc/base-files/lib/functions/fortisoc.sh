# SPDX-License-Identifier: GPL-2.0-only
#
# Persistent overlay of the FortiSOC targets: a device tree node
# "fortinet,disk-rootfs-data", a direct child of the root, describes
# where the rootfs_data of the overlay lies on a disk (the rest of the
# firmware slot, after the container). Without it, the system runs from
# its initramfs as before, with a RAM root. Both paths below can be set
# beforehand, for a test outside the target.

: "${FORTISOC_DT_BASE:=/sys/firmware/devicetree/base}"
: "${FORTISOC_SYS_BLOCK:=/sys/block}"

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

# Wait, at most $2 seconds (default 15), for a disk of the size given by
# the node $1 (fortinet,disk-sectors, a big-endian 64-bit cell pair), as
# USB storage is probed asynchronously. Fail if none shows up.
fortisoc_rootfs_data_wait() {
	local node="$1" timeout="${2:-15}" hex sectors dev n=0

	hex="$(hexdump -v -e '1/1 "%02x"' "$node/fortinet,disk-sectors" 2>/dev/null)"
	[ "${#hex}" = 16 ] || return 1
	sectors=$((0x$hex))

	while :; do
		for dev in "$FORTISOC_SYS_BLOCK"/*; do
			case "${dev##*/}" in
			loop*|ram*|mtdblock*|zram*) continue ;;
			esac
			[ "$(cat "$dev/size" 2>/dev/null)" = "$sectors" ] && return 0
		done
		[ "$n" -ge "$timeout" ] && return 1
		sleep 1
		n=$((n + 1))
	done
}
