# SPDX-License-Identifier: GPL-2.0-only
#
# fortigate.sh: install OpenWrt into a firmware slot of the boot disk of
# a dual-slot FortiGate, through the write windows of the kernel.
#
# Layout of the boot disk (an internal USB stick, or the eMMC), as left
# by the stock firmware:
#
#   sector 0     boot sector: a Fortinet header (bytes 0x000-0x1bd)
#                merged with an MBR partition table (0x1be-0x1fd,
#                55 aa at 0x1fe)
#   partition 1  firmware slot of image 0, an ext file system with the
#                files of a firmware ("flatkc", "rootfs.gz"...)
#   partition 2  firmware slot of image 1, same form
#   partition 3  data shared by both slots
#
# The header holds the name of each image: image 0 (partition 1) at
# 0x10, image 1 (partition 2) at 0x30, 32 bytes each, padded with
# zeros; the build numbers of images 0 and 1 are at 0x128 and 0x12c
# (4 bytes). The boot loader picks the default slot from the boot flag
# of MBR entries 1 and 2; its menu option [B] switches it (and only
# writes 0x1be/0x1ce). By default nothing here changes the default
# slot: OpenWrt goes to the slot that is not the default one, and the
# switch is left to the boot loader. A board may ask instead that the
# target slot become the default one (FGT_SLOT_MAKE_DEFAULT): the boot
# flags are then switched (target 0x80, other 0x00) in the same write
# of sector 0 as the name and the build number, and [B] in the boot
# menu brings the stock firmware back. The target slot must then be
# the one that is not the default one, or already the default one with
# an OpenWrt image (its name in the header is FGT_IMAGE_NAME or
# FGT_IMAGE_NAME_ENV): a default slot holding anything else is the
# stock firmware in use, never overwritten. The other image must have
# a name (the stock firmware [B] brings back).
#
# Persistence (FGT_PERSIST): the slot then holds two areas,
#
#   start of the slot   the container: the ext file system the boot
#                       loader reads (flatkc...), never mounted by
#                       OpenWrt; its size is the one of the ext file
#                       system of the image, smaller than the slot
#   rest of the slot    rootfs_data: the upper layer of the overlay,
#                       an ext4 file system made by fstools at boot
#
# The place of rootfs_data is never set here nor in platform.sh: it is
# read from the device tree, node "fortinet,disk-rootfs-data", a child
# of the root (properties fortinet,disk-sectors, 64-bit, the size of
# the disk, and fortinet,rootfs-data, <start count>, in sectors of the
# whole disk). The kernel keeps that area writable at all times (a
# persistent write window, see fgt_ww_read); the installer requires it
# to be exactly that window, inside the slot and after the container.
# fstools reaches it through a loop device backed by the whole disk,
# whose page cache writes back whole 4 KiB pages aligned on the disk:
# start and count must be multiples of 8 sectors (a page across its
# start or end would write out of the window), and the container must
# end before it, its last 4 KiB page of the slot device included.
#
# The platform.sh of the target sets, for the board named by
# board_name (the fgt_board() case there):
#
#   FGT_BOARD             label of the board, for the messages
#   FGT_DISK_KIND         usb (an internal stick) or mmc (the eMMC)
#   FGT_SLOT_PART         partition to write: 1 or 2 (its MBR entry)
#   FGT_SLOT_LBA          expected start of that partition (sectors)
#   FGT_SLOT_SIZE         expected size of that partition (sectors)
#   FGT_SLOT_IMAGE        image written in the header: 0 or 1
#   FGT_IMAGE_NAME        name of the image written in the header
#   FGT_WW_EXPECTED       expected witness of the write windows, after
#                         the state word (see fgt_ww_read)
#   FGT_HEADER_FORBIDDEN  header bytes never to change, on top of the
#                         boot flags, the magic and the other image
#   FGT_SLOT_NONDEFAULT   1: refuse unless the target slot is not the
#                         default one
#   FGT_SLOT_MAKE_DEFAULT 1: make the target slot the default one (the
#                         boot flags 0x1be/0x1ce become writable for
#                         this board only); never with
#                         FGT_SLOT_NONDEFAULT
#   FGT_PERSIST           1: persistence, rootfs_data in the rest of
#                         the slot (needs FGT_DISK_SECTORS, the device
#                         tree node and a persistent window)
#
#   usb: FGT_USB_PATH (USB host controller), FGT_USB_PORT (port of the
#        stick), FGT_DISK_VENDOR, FGT_DISK_MODEL, FGT_DISK_SECTORS (the
#        stick is never chosen by its sdX name, which depends on the
#        other disks plugged in)
#   mmc: FGT_MMC_DISK (device of the eMMC), FGT_MMC_SLOT (partition
#        to write)
#
# The kernel guards the boot disk and refuses every write except the
# windows it declares itself (they come from the device tree): this
# script reads them from the witness, /sys/module/block/parameters/
# write_windows (USB guard) or /sys/module/mmc_core/parameters/
# write_windows (eMMC guard), and refuses unless they are exactly the
# expected ones (FGT_WW_EXPECTED), cover sector 0 and the target slot,
# and allow the bytes of sector 0 it changes (USB guard). The target
# partition must also be the expected one (FGT_SLOT_LBA, FGT_SLOT_SIZE).
# The closed list of header bytes is enforced here as well.
# The windows are disarmed at boot: this script arms them, once per
# boot and for 10 minutes at most, right before writing, and turns
# them off when done or on failure (the persistent window of
# rootfs_data does not depend on it). A USB stick may also be kept
# read-only by user space (blockdev --setro): the stick alone is made
# writable while the windows are armed, and read-only again
# afterwards.
#
# Upgrade image: the TFTP image itself (a gzip stream holding a disk
# image whose partition 0 is the file system of a slot), so that the
# file booted from RAM by option [R] is the one installed. Its MBR
# entry always gives the size of the slot; the length copied into the
# target slot is the size of the ext file system of partition 0 (from
# its superblock, never a 64bit one), the whole slot or only the
# container.
#
# Configuration, without FGT_PERSIST: nothing of the RAM system is
# kept, and sysupgrade without -n is refused (SAVE_CONFIG=1 at the
# image check, a backup archive, UPGRADE_BACKUP, in stage2): use
# sysupgrade -n. With FGT_PERSIST, the order is: container,
# then rootfs_data, then sector 0. sysupgrade (keep the configuration)
# hands over its backup archive (UPGRADE_BACKUP, /tmp/sysupgrade.tgz,
# set by procd, visible in platform_do_upgrade): it is written at the
# head of rootfs_data, and at the next boot fstools extracts it,
# formats rootfs_data and the configuration is restored (as
# emmc_copy_config does); with -c or -o the archive merely holds more
# files (the changed files of /etc, or of / but the packages: they
# need /overlay/upper/etc, there with persistence). sysupgrade -n (no
# UPGRADE_BACKUP): the marker 0xdeadc0de is written at the head of
# rootfs_data, and fstools formats it at the next boot. rootfs_data is
# never formatted here.
#
# The name of the image written in the header can be overridden without
# touching platform.sh: set FGT_IMAGE_NAME_ENV in the environment.
#
# The paths of sysfs, /dev, /proc and of the device tree may be
# overridden from the environment, for a test harness on a PC only:
# FGT_SYS_BLOCK, FGT_SYS_CLASS_BLOCK, FGT_SYS_MODULE, FGT_DEV,
# FGT_PROC_MOUNTS, FGT_DT_BASE, FGT_DROP_CACHES, FGT_SECTOR0, and the
# directory of the temporary files: FGT_TMP.

# Kill switch: set to 0 to refuse every upgrade (not forceable).
FGT_DUALSLOT_CONFIRMED=1

# Format of the boot sector (independent of the board)
FGT_MAGIC_OFS=0x0e
FGT_MAGIC=aa55
FGT_NAME_LEN=32
FGT_BUILD_LEN=4
# Direct I/O on sector 0 (never busybox dd: not direct at bs=512)
FGT_SECTOR0="${FGT_SECTOR0:-fgt-sector0}"
# Description of rootfs_data in the device tree
FGT_DT_COMPAT=fortinet,disk-rootfs-data
# Marker that makes fstools format rootfs_data at the next boot
FGT_DEADCODE=deadc0de
# Head of the backup archive fstools recognizes (gzip, deflate, no flag)
FGT_TARGZ=1f8b0800

# Paths of the running system (overridable for a test harness only)
FGT_SYS_BLOCK="${FGT_SYS_BLOCK:-/sys/block}"
FGT_SYS_CLASS_BLOCK="${FGT_SYS_CLASS_BLOCK:-/sys/class/block}"
FGT_SYS_MODULE="${FGT_SYS_MODULE:-/sys/module}"
FGT_DEV="${FGT_DEV:-/dev}"
FGT_PROC_MOUNTS="${FGT_PROC_MOUNTS:-/proc/mounts}"
FGT_DT_BASE="${FGT_DT_BASE:-/sys/firmware/devicetree/base}"
FGT_DROP_CACHES="${FGT_DROP_CACHES:-/proc/sys/vm/drop_caches}"
FGT_TMP="${FGT_TMP:-/tmp}"

# Hexadecimal dump of <count> bytes at <offset> of a file or a stream
fgt_hex() { # <offset> <count> [<file>]
	if [ -n "$3" ]; then
		dd if="$3" bs=1 skip=$(($1)) count=$(($2)) 2>/dev/null
	else
		dd bs=1 skip=$(($1)) count=$(($2)) 2>/dev/null
	fi | hexdump -v -e '1/1 "%02x"'
}

# Little-endian 32-bit value at <offset> of a file
fgt_le32() { # <offset> <file>
	local h="$(fgt_hex "$1" 4 "$2")"

	[ ${#h} -eq 8 ] || return 1
	echo $((0x${h:6:2}${h:4:2}${h:2:2}${h:0:2}))
}

# Big-endian 32-bit value at <offset> of a file (device tree cells)
fgt_be32() { # <offset> <file>
	local h="$(fgt_hex "$1" 4 "$2")"

	[ ${#h} -eq 8 ] || return 1
	echo $((0x$h))
}

# Bytes of a whole file, or of the standard input, as " xx xx ..."
# (one word per byte, so that a match never straddles two bytes)
fgt_hexw() { # [<file>]
	hexdump -v -e '1/1 " %02x"' ${1:+"$1"}
}

fgt_refuse() {
	echo "${FGT_BOARD:-FortiGate}: $*" >&2
	return 1
}

# Name and build number of image <0 or 1> in the header
fgt_image_offsets() { # <image>
	case "$1" in
	0) echo "0x10 0x128" ;;
	1) echo "0x30 0x12c" ;;
	*) return 1 ;;
	esac
}

# True when the name of the image at <offset> of the header <file> is
# exactly <name> (cut to 32 bytes, padded with zeros); never for an
# empty <name>
fgt_name_is() { # <file> <offset> <name>
	local n="${3:0:$FGT_NAME_LEN}" want

	[ -n "$n" ] || return 1
	want="$(printf '%s' "$n" | fgt_hex 0 $FGT_NAME_LEN)"
	while [ ${#want} -lt $((2 * FGT_NAME_LEN)) ]; do
		want="${want}00"
	done
	[ "$(fgt_hex "$2" $FGT_NAME_LEN "$1")" = "$want" ]
}

# First offset of the MBR entry of partition <1 or 2>: the boot flag is
# there, the partition type 4 bytes further, the start (little-endian
# 32-bit) 8 bytes further, the size 12 bytes further
fgt_mbr() { # <partition> <0|4|8|12>
	echo $((0x1be + 16 * ($1 - 1) + $2))
}

# Checks the settings given by platform.sh and derives the header
# offsets and the lists of writable and forbidden header bytes. Runs
# before every image check and every upgrade.
fgt_check_settings() {
	local o

	case "$FGT_DISK_KIND" in
	usb) FGT_WW="$FGT_SYS_MODULE/block/parameters/write_windows" ;;
	mmc) FGT_WW="$FGT_SYS_MODULE/mmc_core/parameters/write_windows" ;;
	*) return 1 ;;
	esac
	case "$FGT_SLOT_PART" in
	1|2) ;;
	*) return 1 ;;
	esac
	case "$FGT_SLOT_IMAGE" in
	0|1) ;;
	*) return 1 ;;
	esac
	case "$FGT_SLOT_NONDEFAULT:$FGT_SLOT_MAKE_DEFAULT:$FGT_PERSIST" in
	*[!01:]*) return 1 ;;
	1:1:*) return 1 ;;
	esac
	[ -n "$FGT_BOARD" ] && [ -n "$FGT_IMAGE_NAME" ] &&
		[ -n "$FGT_WW_EXPECTED" ] || return 1
	case "$FGT_SLOT_LBA$FGT_SLOT_SIZE$FGT_DISK_SECTORS" in
	*[!0-9]*) return 1 ;;
	esac
	[ -n "$FGT_SLOT_LBA" ] && [ "$FGT_SLOT_LBA" -ge 1 ] &&
		[ -n "$FGT_SLOT_SIZE" ] && [ "$FGT_SLOT_SIZE" -ge 1 ] || return 1
	if [ "$FGT_DISK_KIND" = usb ]; then
		[ -n "$FGT_USB_PATH" ] && [ -n "$FGT_USB_PORT" ] &&
			[ -n "$FGT_DISK_VENDOR" ] && [ -n "$FGT_DISK_MODEL" ] &&
			[ -n "$FGT_DISK_SECTORS" ] || return 1
	else
		[ -n "$FGT_MMC_DISK" ] && [ -n "$FGT_MMC_SLOT" ] || return 1
	fi
	# Persistence: the size of the disk is checked against the device
	# tree, on the eMMC as well
	if [ "$FGT_PERSIST" = 1 ]; then
		[ -n "$FGT_DISK_SECTORS" ] || return 1
	fi
	o="$(fgt_image_offsets "$FGT_SLOT_IMAGE")" || return 1
	FGT_NAME_OFS="${o% *}"; FGT_BUILD_OFS="${o#* }"
	o="$(fgt_image_offsets "$((1 - FGT_SLOT_IMAGE))")" || return 1
	FGT_OTHER_NAME_OFS="${o% *}"; FGT_OTHER_BUILD_OFS="${o#* }"
	# Boot flags of the target partition and of the other one
	FGT_FLAG_OFS=$(fgt_mbr $FGT_SLOT_PART 0)
	FGT_OTHER_FLAG_OFS=$(fgt_mbr $((3 - FGT_SLOT_PART)) 0)
	# The closed list of header bytes this script may change (first
	# offset, length): name and build number of the image it writes,
	# and the boot flags of MBR entries 1 and 2 when the board makes
	# the target slot the default one.
	FGT_WRITABLE="$FGT_NAME_OFS:$FGT_NAME_LEN $FGT_BUILD_OFS:$FGT_BUILD_LEN"
	# Header bytes never to be changed, whatever the list above says:
	# boot flags of MBR entries 1 and 2 (unless the board makes the
	# target slot the default one), magic, name and build number of
	# the other image, and the bytes listed by the board.
	if [ "$FGT_SLOT_MAKE_DEFAULT" = 1 ]; then
		FGT_WRITABLE="$FGT_WRITABLE 0x1be:1 0x1ce:1"
		FGT_FORBIDDEN=""
	else
		FGT_FORBIDDEN="0x1be:1 0x1ce:1 "
	fi
	FGT_FORBIDDEN="${FGT_FORBIDDEN}0x0e:2 \
$FGT_OTHER_NAME_OFS:$FGT_NAME_LEN $FGT_OTHER_BUILD_OFS:$FGT_BUILD_LEN \
$FGT_HEADER_FORBIDDEN"
}

# Every range of FGT_WRITABLE must lie in the header (before the
# partition table), or be the boot flag of MBR entry 1 or 2 when the
# board makes the target slot the default one, and lie out of
# FGT_FORBIDDEN
fgt_check_writable_list() {
	local w f wo wl fo fl

	for w in $FGT_WRITABLE; do
		wo=$((${w%%:*})); wl=$((${w##*:}))
		if [ "$FGT_SLOT_MAKE_DEFAULT" = 1 ] && [ $wl = 1 ] &&
			{ [ $wo = $(fgt_mbr 1 0) ] || [ $wo = $(fgt_mbr 2 0) ]; }; then
			:
		else
			[ $wl -gt 0 ] && [ $((wo + wl)) -le $((0x1be)) ] ||
				return 1
		fi
		for f in $FGT_FORBIDDEN; do
			fo=$((${f%%:*})); fl=$((${f##*:}))
			[ $((wo + wl)) -le $fo ] || [ $((fo + fl)) -le $wo ] ||
				return 1
		done
	done
}

# The one disk that is the boot stick: USB port, vendor, model and
# size. Prints its name (sdX); fails unless exactly one disk matches.
fgt_disk_usb() {
	local b d real v m n found=""

	for b in "$FGT_SYS_BLOCK"/sd*; do
		[ -e "$b" ] || continue
		d="${b##*/}"
		real="$(readlink -f "$b")" || continue
		case "$real" in
		*"$FGT_USB_PATH"*"$FGT_USB_PORT"*) ;;
		*) continue ;;
		esac
		read v < "$b/device/vendor" 2>/dev/null || continue
		read m < "$b/device/model" 2>/dev/null || continue
		read n < "$b/size" 2>/dev/null || continue
		[ "$v" = "$FGT_DISK_VENDOR" ] &&
			[ "$m" = "$FGT_DISK_MODEL" ] &&
			[ "$n" = "$FGT_DISK_SECTORS" ] || continue
		[ -z "$found" ] || return 1
		found="$d"
	done
	[ -n "$found" ] && echo "$found"
}

# True when <path> is a block device (the one test of the kind of a
# device, redefined by a test harness on a PC only)
fgt_is_block() { # <path>
	[ -b "$1" ]
}

# The eMMC: the devices given by the board must exist
fgt_disk_mmc() {
	fgt_is_block "$FGT_MMC_DISK" && fgt_is_block "$FGT_MMC_SLOT"
}

# Witness of the write windows, read at every check, one line:
#
#   <state> <windows...> [persistent <windows...>] [sector0 <bytes...>]
#
# The state is "inactive", "off", "disarmed" or "armed"; then the
# session windows ("<start>+<count>", in sectors of the whole disk, or
# "none"), armed by this script; then, on boards with persistence
# only, "persistent" followed by the windows the kernel keeps writable
# at all times (rootfs_data); then, for the USB guard, "sector0"
# followed by the bytes of sector 0 that may change ("<offset
# hex>+<count>", or "none"). Sets FGT_WW_LINE (the witness),
# FGT_WW_STATE, FGT_WW_WINDOWS, FGT_WW_PERSISTENT and FGT_WW_BYTES in
# the calling shell: never call it from a command substitution. Any
# other shape (unknown word, state word not first or repeated,
# "persistent" or "sector0" repeated, out of order or not expected on
# this board) gives the state "unknown".
fgt_ww_read() {
	local w n=0 part=session

	FGT_WW_LINE=""
	FGT_WW_STATE=unknown
	FGT_WW_WINDOWS=""
	FGT_WW_PERSISTENT=""
	FGT_WW_BYTES=""
	[ -r "$FGT_WW" ] || return 1
	read -r FGT_WW_LINE < "$FGT_WW" || return 1
	for w in $FGT_WW_LINE; do
		n=$((n + 1))
		case "$w" in
		inactive|off|disarmed|armed)
			[ $n = 1 ] || { FGT_WW_STATE=unknown; return 0; }
			FGT_WW_STATE="$w"
			;;
		persistent)
			[ $part = session ] && [ "$FGT_PERSIST" = 1 ] ||
				{ FGT_WW_STATE=unknown; return 0; }
			part=persistent
			;;
		sector0)
			[ $part != sector0 ] && [ "$FGT_DISK_KIND" = usb ] ||
				{ FGT_WW_STATE=unknown; return 0; }
			part=sector0
			;;
		none)
			;;
		[0-9]*+[0-9]*)
			case $part in
			session) FGT_WW_WINDOWS="$FGT_WW_WINDOWS $w" ;;
			persistent) FGT_WW_PERSISTENT="$FGT_WW_PERSISTENT $w" ;;
			sector0) FGT_WW_BYTES="$FGT_WW_BYTES $w" ;;
			esac
			;;
		*)
			FGT_WW_STATE=unknown
			return 0
			;;
		esac
	done
	[ $n = 1 ] || case "$FGT_WW_STATE" in
		disarmed|armed) ;;
		*) FGT_WW_STATE=unknown ;;
	esac
	return 0
}

# True when the witness is exactly "<state> FGT_WW_EXPECTED" (state
# "disarmed" or "armed"); also loads the windows for fgt_ww_covers and
# fgt_ww_bytes_cover
fgt_ww_is() { # <state>
	fgt_ww_read || return 1
	[ "$FGT_WW_STATE" = "$1" ] &&
		[ "$FGT_WW_LINE" = "$1 $FGT_WW_EXPECTED" ]
}

# True when the session windows cover <start>+<count> sectors of the
# disk
fgt_ww_covers() { # <start> <count>
	local w ws wc

	for w in $FGT_WW_WINDOWS; do
		ws=$((${w%+*})); wc=$((${w#*+}))
		[ "$1" -ge "$ws" ] && [ $(($1 + $2)) -le $((ws + wc)) ] &&
			return 0
	done
	return 1
}

# True when the bytes of sector 0 the kernel allows cover
# <offset>+<count> bytes of the header
fgt_ww_bytes_cover() { # <offset> <count>
	local w ws wc

	for w in $FGT_WW_BYTES; do
		ws=$((${w%+*})); wc=$((${w#*+}))
		[ $(($1)) -ge "$ws" ] && [ $(($1 + $2)) -le $((ws + wc)) ] &&
			return 0
	done
	return 1
}

fgt_ww_arm() {
	echo arm > "$FGT_WW" 2>/dev/null
}

# Windows off; a USB stick is made read-only again as well (both always
# attempted)
fgt_ww_off() { # [<disk>]
	echo off > "$FGT_WW" 2>/dev/null
	echo "Write windows: $(cat "$FGT_WW" 2>/dev/null)"
	if [ -n "$1" ]; then
		blockdev --setro "$1" 2>/dev/null &&
			echo "$1 read-only: $(blockdev --getro "$1" 2>/dev/null)"
	fi
	return 0
}

# Windows off at the end of the work, or on failure
fgt_ww_done() {
	if [ "$FGT_DISK_KIND" = usb ]; then
		fgt_ww_off "$FGT_DISK"
	else
		fgt_ww_off
	fi
}

# Drop the page cache, so that a read back reaches the disk
fgt_drop_caches() {
	sync
	echo 3 > "$FGT_DROP_CACHES"
}

# The one node of the device tree, child of the root, compatible with
# FGT_DT_COMPAT. Prints its path; fails unless exactly one matches.
fgt_dt_node() {
	local c want found=""

	want=" 00$(printf '%s' "$FGT_DT_COMPAT" | fgt_hexw) 00 "
	for c in "$FGT_DT_BASE"/*/compatible; do
		[ -f "$c" ] || continue
		case " 00$(fgt_hexw "$c") " in
		*"$want"*) ;;
		*) continue ;;
		esac
		[ -z "$found" ] || return 1
		found="${c%/compatible}"
	done
	[ -n "$found" ] && echo "$found"
}

# True when the string property <file> of the device tree is absent or
# holds exactly <string>
fgt_dt_string_is() { # <file> <string>
	[ -e "$1" ] || return 0
	[ "$(fgt_hexw "$1")" = "$(printf '%s' "$2" | fgt_hexw) 00" ]
}

# rootfs_data as described by the device tree (never by platform.sh):
# the size of the disk must be FGT_DISK_SECTORS and the one of the
# disk found, the area must lie inside the target slot (a container
# before it) and be exactly the one persistent window of the witness
# (fgt_ww_read first). Sets FGT_RD_START and FGT_RD_COUNT (sectors of
# the whole disk).
fgt_check_rootfs_data() {
	local node hi lo size=""

	FGT_RD_START=""; FGT_RD_COUNT=""
	node="$(fgt_dt_node)" ||
		{ fgt_refuse "no device tree node $FGT_DT_COMPAT (or more than one)"; return 1; }
	[ "$(wc -c < "$node/fortinet,disk-sectors" 2>/dev/null)" = 8 ] &&
		[ "$(wc -c < "$node/fortinet,rootfs-data" 2>/dev/null)" = 8 ] ||
		{ fgt_refuse "malformed device tree node $node"; return 1; }
	# 64-bit size of the disk: a high cell of 0 (2 TiB at most)
	hi="$(fgt_be32 0 "$node/fortinet,disk-sectors")" &&
		lo="$(fgt_be32 4 "$node/fortinet,disk-sectors")" &&
		[ "$hi" = 0 ] && [ "$lo" = "$FGT_DISK_SECTORS" ] ||
		{ fgt_refuse "device tree disk size ($hi:$lo) is not $FGT_DISK_SECTORS sectors"; return 1; }
	read size < "$FGT_SYS_CLASS_BLOCK/${FGT_DISK##*/}/size" 2>/dev/null
	[ "$size" = "$FGT_DISK_SECTORS" ] ||
		{ fgt_refuse "$FGT_DISK is not $FGT_DISK_SECTORS sectors ($size)"; return 1; }
	if [ "$FGT_DISK_KIND" = usb ]; then
		fgt_dt_string_is "$node/fortinet,disk-vendor" "$FGT_DISK_VENDOR" &&
			fgt_dt_string_is "$node/fortinet,disk-model" "$FGT_DISK_MODEL" ||
			{ fgt_refuse "device tree disk vendor or model is not $FGT_DISK_VENDOR $FGT_DISK_MODEL"; return 1; }
	fi
	FGT_RD_START="$(fgt_be32 0 "$node/fortinet,rootfs-data")" &&
		FGT_RD_COUNT="$(fgt_be32 4 "$node/fortinet,rootfs-data")" ||
		{ fgt_refuse "cannot read rootfs_data from $node"; return 1; }
	# Aligned on the 4 KiB pages of the disk (see the top of this file)
	[ $((FGT_RD_START % 8)) = 0 ] && [ $((FGT_RD_COUNT % 8)) = 0 ] ||
		{ fgt_refuse "rootfs_data ($FGT_RD_START+$FGT_RD_COUNT) is not aligned on 8 sectors (4 KiB)"; return 1; }
	# Inside the slot, at least one sector of container before it
	[ "$FGT_RD_COUNT" -ge 1 ] &&
		[ "$FGT_RD_START" -gt "$FGT_SLOT_START" ] &&
		[ $((FGT_RD_START + FGT_RD_COUNT)) -le $((FGT_SLOT_START + FGT_SLOT_SECTORS)) ] ||
		{ fgt_refuse "rootfs_data ($FGT_RD_START+$FGT_RD_COUNT) is not inside partition $FGT_SLOT_PART after its start"; return 1; }
	[ "$FGT_WW_PERSISTENT" = " $FGT_RD_START+$FGT_RD_COUNT" ] ||
		{ fgt_refuse "the persistent write window ($FGT_WW_PERSISTENT) is not rootfs_data ($FGT_RD_START+$FGT_RD_COUNT)"; return 1; }
}

# Checks of the disk and its boot sector, shared by the image check and
# the upgrade itself. Sets FGT_DISK, FGT_SLOT, FGT_SLOT_START and
# FGT_SLOT_SECTORS (and FGT_RD_START, FGT_RD_COUNT with persistence);
# the target partition must lie inside the write windows of the
# kernel, and the bytes of the header this script changes must be
# among those the kernel allows (USB guard).
fgt_check_disk() { # <sector 0 file>
	local s0="$1" disk part start size flags

	if [ "$FGT_DISK_KIND" = usb ]; then
		command -v blockdev > /dev/null ||
			{ fgt_refuse "blockdev is missing"; return 1; }
		disk="$(fgt_disk_usb)" ||
			{ fgt_refuse "boot stick not found (or more than one)"; return 1; }
		FGT_DISK="$FGT_DEV/$disk"
		FGT_SLOT="$FGT_DEV/$disk$FGT_SLOT_PART"
		part="$disk$FGT_SLOT_PART"
	else
		fgt_disk_mmc ||
			{ fgt_refuse "no eMMC slot $FGT_MMC_SLOT"; return 1; }
		FGT_DISK="$FGT_MMC_DISK"
		FGT_SLOT="$FGT_MMC_SLOT"
		part="${FGT_MMC_SLOT##*/}"
	fi
	command -v "$FGT_SECTOR0" > /dev/null ||
		{ fgt_refuse "$FGT_SECTOR0 is missing"; return 1; }
	fgt_is_block "$FGT_DISK" && fgt_is_block "$FGT_SLOT" ||
		{ fgt_refuse "no slot $FGT_SLOT"; return 1; }
	if [ "$FGT_DISK_KIND" = usb ]; then
		grep -qs "^$FGT_DISK" "$FGT_PROC_MOUNTS" &&
			{ fgt_refuse "$FGT_DISK is mounted"; return 1; }
	else
		grep -qs "^$FGT_SLOT " "$FGT_PROC_MOUNTS" &&
			{ fgt_refuse "$FGT_SLOT is mounted"; return 1; }
	fi
	rm -f "$s0"
	"$FGT_SECTOR0" read "$FGT_DISK" "$s0" &&
		[ "$(wc -c < "$s0")" -eq 512 ] ||
		{ fgt_refuse "cannot read the boot sector"; return 1; }
	[ "$(fgt_hex 0x1fe 2 "$s0")" = 55aa ] &&
		[ "$(fgt_hex $FGT_MAGIC_OFS 2 "$s0")" = "$FGT_MAGIC" ] ||
		{ fgt_refuse "boot sector without the stock header"; return 1; }

	# The other partition (the stock firmware) must be the default
	# slot, when the board asks for it
	flags="$(fgt_hex $FGT_FLAG_OFS 1 "$s0")$(fgt_hex $FGT_OTHER_FLAG_OFS 1 "$s0")"
	if [ "$FGT_SLOT_NONDEFAULT" = 1 ]; then
		[ "$flags" = 0080 ] ||
			{ fgt_refuse "partition $FGT_SLOT_PART is the default slot (or no default): switch to partition $((3 - FGT_SLOT_PART)) with [B] first"; return 1; }
	fi
	# Exactly one default slot before the switch, when the board makes
	# the target slot the default one. The target slot may already be
	# the default one only when its image is OpenWrt (a name this
	# installer writes): any other image there is the stock firmware in
	# use. The other image must have a name: the stock firmware that
	# [B] brings back.
	if [ "$FGT_SLOT_MAKE_DEFAULT" = 1 ]; then
		case "$flags" in
		0080) ;;
		8000)
			fgt_name_is "$s0" "$FGT_NAME_OFS" "$FGT_IMAGE_NAME" ||
				fgt_name_is "$s0" "$FGT_NAME_OFS" "$FGT_IMAGE_NAME_ENV" ||
				{ fgt_refuse "partition $FGT_SLOT_PART is the default slot and image $FGT_SLOT_IMAGE is not OpenWrt: switch to partition $((3 - FGT_SLOT_PART)) with [B] first"; return 1; }
			;;
		*) fgt_refuse "boot flags of partitions $FGT_SLOT_PART and $((3 - FGT_SLOT_PART)) are $flags, neither 8000 nor 0080: switch with [B] first"; return 1 ;;
		esac
		case "$(fgt_hex $FGT_OTHER_NAME_OFS 1 "$s0")" in
		""|00) fgt_refuse "image $((1 - FGT_SLOT_IMAGE)) has no name: no stock firmware for [B] to bring back"; return 1 ;;
		esac
	fi

	# The target partition as seen by the kernel and by its MBR entry
	start="$(cat "$FGT_SYS_CLASS_BLOCK/$part/start")"
	size="$(cat "$FGT_SYS_CLASS_BLOCK/$part/size")"
	[ -n "$start" ] && [ -n "$size" ] ||
		{ fgt_refuse "no partition $part"; return 1; }
	[ "$start" = "$(fgt_le32 $(fgt_mbr $FGT_SLOT_PART 8) "$s0")" ] &&
		[ "$size" = "$(fgt_le32 $(fgt_mbr $FGT_SLOT_PART 12) "$s0")" ] ||
		{ fgt_refuse "partition $FGT_SLOT_PART differs from its MBR entry ($start+$size)"; return 1; }
	[ "$start" = "$FGT_SLOT_LBA" ] && [ "$size" = "$FGT_SLOT_SIZE" ] ||
		{ fgt_refuse "unexpected partition $FGT_SLOT_PART ($start+$size, expected $FGT_SLOT_LBA+$FGT_SLOT_SIZE)"; return 1; }
	if [ "$FGT_DISK_KIND" = usb ]; then
		[ "$(fgt_hex $(fgt_mbr $FGT_SLOT_PART 4) 1 "$s0")" = 83 ] ||
			{ fgt_refuse "partition $FGT_SLOT_PART is not an ext partition"; return 1; }
	fi
	FGT_SLOT_START=$start
	FGT_SLOT_SECTORS=$size

	# Windows of the kernel: the expected ones, not armed yet in this
	# boot, and wide enough for what this script writes
	fgt_ww_is disarmed ||
		{ fgt_refuse "no disarmed write windows, or not the expected ones ($(cat "$FGT_WW" 2>/dev/null)): reboot"; return 1; }
	fgt_ww_covers 0 1 ||
		{ fgt_refuse "no write window over sector 0"; return 1; }
	fgt_ww_covers "$FGT_SLOT_START" "$FGT_SLOT_SECTORS" ||
		{ fgt_refuse "no write window over partition $FGT_SLOT_PART ($FGT_SLOT_START+$FGT_SLOT_SECTORS)"; return 1; }
	if [ "$FGT_DISK_KIND" = usb ]; then
		fgt_ww_bytes_cover "$FGT_NAME_OFS" $FGT_NAME_LEN &&
			fgt_ww_bytes_cover "$FGT_BUILD_OFS" $FGT_BUILD_LEN ||
			{ fgt_refuse "the kernel does not allow the name or the build number of image $FGT_SLOT_IMAGE to change"; return 1; }
		if [ "$FGT_SLOT_MAKE_DEFAULT" = 1 ]; then
			fgt_ww_bytes_cover "$FGT_FLAG_OFS" 1 &&
				fgt_ww_bytes_cover "$FGT_OTHER_FLAG_OFS" 1 ||
				{ fgt_refuse "the kernel does not allow the boot flags to change"; return 1; }
		fi
	fi

	# rootfs_data: from the device tree, the persistent window
	if [ "$FGT_PERSIST" = 1 ]; then
		fgt_check_rootfs_data || return 1
	fi
}

# Checks the TFTP image: gzip stream, MBR, partition 0 of the size of
# the target slot holding an ext file system (not 64bit), no larger
# than the slot (with persistence: than the room before rootfs_data,
# counted in whole 4 KiB pages of the slot device), and the image long
# enough to hold it. Prints "<offset> <length>": offset of partition 0,
# size of its file system (from the superblock).
fgt_check_container() { # <image>
	local img="$1" mbr="$FGT_TMP/fortigate-image.mbr"
	local sb="$FGT_TMP/fortigate-image.sb" lba sectors blocks logbs len room
	local incompat

	get_image "$img" | head -c 512 > "$mbr"
	[ "$(fgt_hex 0 2 "$img")" = 1f8b ] &&
		[ "$(fgt_hex 0x1fe 2 "$mbr")" = 55aa ] &&
		[ "$(fgt_hex 0x1c2 1 "$mbr")" = 83 ] ||
		{ fgt_refuse "not a $FGT_BOARD TFTP image"; return 1; }
	lba="$(fgt_le32 0x1c6 "$mbr")"
	sectors="$(fgt_le32 0x1ca "$mbr")"
	[ -n "$lba" ] && [ "$lba" -ge 1 ] &&
		[ "$sectors" = "$FGT_SLOT_SIZE" ] &&
		[ "$sectors" = "$FGT_SLOT_SECTORS" ] ||
		{ fgt_refuse "partition 0 is not the size of a slot"; return 1; }
	# Superblock of the ext2/3/4 file system of partition 0: magic
	# (0xef53), s_blocks_count_lo and s_log_block_size; without the
	# 64bit feature (s_feature_incompat 0x80), whose high half of the
	# block count is not read here
	get_image "$img" | tail -c +$((lba * 512 + 1)) | head -c 2048 > "$sb"
	[ "$(fgt_hex 0x438 2 "$sb")" = 53ef ] ||
		{ fgt_refuse "partition 0 holds no ext file system"; return 1; }
	incompat="$(fgt_le32 0x460 "$sb")" && [ $((incompat & 0x80)) = 0 ] ||
		{ fgt_refuse "the file system of partition 0 is 64bit"; return 1; }
	blocks="$(fgt_le32 0x404 "$sb")" && logbs="$(fgt_le32 0x418 "$sb")" &&
		[ "$blocks" -ge 1 ] && [ "$logbs" -le 6 ] ||
		{ fgt_refuse "bad superblock in partition 0"; return 1; }
	len=$((blocks * (1024 << logbs)))
	[ $((len / 512)) -le "$FGT_SLOT_SECTORS" ] ||
		{ fgt_refuse "the file system of partition 0 ($len bytes) is larger than the slot"; return 1; }
	# The slot device writes back whole 4 KiB pages (from the start of
	# the slot): the last page of the container must end before
	# rootfs_data
	if [ "$FGT_PERSIST" = 1 ]; then
		room=$((FGT_RD_START - FGT_SLOT_START))
		[ $((((len + 4095) / 4096) * 8)) -le $room ] ||
			{ fgt_refuse "the file system of partition 0 ($len bytes) overlaps rootfs_data (at sector $room of the slot)"; return 1; }
	fi
	# The image holds the whole file system
	[ "$(get_image "$img" | tail -c +$((lba * 512 + len)) | head -c 1 |
		wc -c)" -eq 1 ] ||
		{ fgt_refuse "the image is shorter than the file system of partition 0"; return 1; }
	echo "$((lba * 512)) $len"
}

# New header in <new> from <s0>: name of the image at its offset, its
# build number at 0, and the target slot made the default one when the
# board asks for it; every changed byte must lie in the closed list.
fgt_new_header() { # <s0> <new> <name>
	local s0="$1" new="$2" name="$3" diff

	rm -f "$new"
	cp "$s0" "$new" &&
		printf '%s' "${name:0:$FGT_NAME_LEN}" |
		dd of="$new" bs=$FGT_NAME_LEN count=1 conv=sync,notrunc \
			oflag=seek_bytes seek=$(($FGT_NAME_OFS)) 2>/dev/null &&
		dd if=/dev/zero of="$new" bs=$FGT_BUILD_LEN count=1 conv=notrunc \
			oflag=seek_bytes seek=$(($FGT_BUILD_OFS)) 2>/dev/null ||
		{ fgt_refuse "cannot prepare the header buffer"; return 1; }
	if [ "$FGT_SLOT_MAKE_DEFAULT" = 1 ]; then
		printf '\200' | dd of="$new" bs=1 count=1 conv=notrunc \
			seek=$FGT_FLAG_OFS 2>/dev/null &&
			dd if=/dev/zero of="$new" bs=1 count=1 conv=notrunc \
				seek=$FGT_OTHER_FLAG_OFS 2>/dev/null ||
			{ fgt_refuse "cannot prepare the header buffer"; return 1; }
		[ "$(fgt_hex $FGT_FLAG_OFS 1 "$new")$(fgt_hex $FGT_OTHER_FLAG_OFS 1 "$new")" = 8000 ] ||
			{ fgt_refuse "boot flags not set in the header buffer"; return 1; }
	fi
	[ "$(wc -c < "$new")" -eq 512 ] ||
		{ fgt_refuse "header buffer of a wrong size"; return 1; }
	diff="$(cmp -l "$s0" "$new" | while read w _; do
		ok=0
		w=$((w - 1))
		for f in $FGT_WRITABLE; do
			[ $w -ge $((${f%%:*})) ] &&
				[ $w -lt $((${f%%:*} + ${f##*:})) ] && ok=1
		done
		[ $ok = 1 ] || printf "0x%x " $w
	done)"
	[ -z "$diff" ] ||
		{ fgt_refuse "header bytes out of the list: $diff"; return 1; }
}

# Name of the image written in the header (overridable from the
# environment)
fgt_image_name() {
	echo "${FGT_IMAGE_NAME_ENV:-$FGT_IMAGE_NAME}"
}

# Prints the loop devices bound to the boot disk or to one of its
# partitions (backing file, by name: the path the kernel shows may lie
# under another root after stage2 pivots); fails when there is none.
# The one of rootfs_data (fstools, autoclear) is no longer in
# FGT_PROC_MOUNTS once stage2 lazily unmounts the overlay, but it stays
# bound, and its page cache may still write back, until the last user
# is gone.
fgt_loop_bound() {
	local l b d="${FGT_DISK##*/}" found=""

	for l in "$FGT_SYS_BLOCK"/loop*; do
		[ -r "$l/loop/backing_file" ] || continue
		read -r b < "$l/loop/backing_file" || continue
		case "$b" in
		"$FGT_DISK"|"$FGT_DISK"[0-9p]*|"$FGT_SLOT"|*/"$d"|*/"$d"[0-9p]*) ;;
		*) continue ;;
		esac
		found="$found${found:+ }${l##*/}"
	done
	[ -n "$found" ] && echo "$found"
}

# Waits up to 10 seconds, by steps of 1 second (busybox sleep), until no
# loop device is bound to the boot disk; fails if one still is
fgt_loop_wait() {
	local n=0 loops

	while loops="$(fgt_loop_bound)"; do
		[ $n -lt 10 ] || { echo "$loops"; return 1; }
		[ $n = 0 ] && echo "Waiting for $loops on $FGT_DISK to be released" >&2
		n=$((n + 1))
		sleep 1
	done
	return 0
}

# Backup archive of sysupgrade to write at the head of rootfs_data
# (prints its path), or nothing for the 0xdeadc0de marker; it must be
# a gzip stream fstools recognizes and fit in rootfs_data
fgt_rootfs_data_backup() {
	local size

	[ -n "$UPGRADE_BACKUP" ] || return 0
	[ -f "$UPGRADE_BACKUP" ] ||
		{ echo "Backup $UPGRADE_BACKUP not found: rootfs_data will be erased" >&2; return 0; }
	size="$(wc -c < "$UPGRADE_BACKUP")"
	[ -n "$size" ] && [ "$size" -ge 4 ] &&
		[ "$(fgt_hex 0 4 "$UPGRADE_BACKUP")" = "$FGT_TARGZ" ] ||
		{ fgt_refuse "the backup $UPGRADE_BACKUP is not a gzip archive: use sysupgrade -n"; return 1; }
	[ $(((size + 511) / 512)) -le "$FGT_RD_COUNT" ] ||
		{ fgt_refuse "the backup $UPGRADE_BACKUP ($size bytes) is larger than rootfs_data"; return 1; }
	echo "$UPGRADE_BACKUP"
}

# Head of rootfs_data, through the target slot (offset relative to its
# start): the backup archive <backup>, or the marker 0xdeadc0de when
# empty; read back from the disk. The pages of the slot device start at
# the slot: the first one written may also cover the end of the room
# before rootfs_data (rewritten as read), all inside the slot, which
# the armed session window covers.
fgt_write_rootfs_data() { # [<backup>]
	local rel=$((FGT_RD_START - FGT_SLOT_START)) size

	if [ -n "$1" ]; then
		size="$(wc -c < "$1")"
		echo "Writing the configuration backup at the head of rootfs_data ($size bytes)"
		dd if="$1" of="$FGT_SLOT" bs=512 seek=$rel conv=notrunc,fsync 2>/dev/null ||
			{ fgt_refuse "writing rootfs_data failed"; return 1; }
		fgt_drop_caches
		dd if="$FGT_SLOT" bs=512 skip=$rel count=$(((size + 511) / 512)) 2>/dev/null |
			head -c $size | cmp -s - "$1" ||
			{ fgt_refuse "rootfs_data does not read back as written"; return 1; }
	else
		echo "Writing the marker $FGT_DEADCODE at the head of rootfs_data (formatted at the next boot)"
		printf '\336\255\300\336' |
			dd of="$FGT_SLOT" bs=512 seek=$rel conv=notrunc,fsync 2>/dev/null ||
			{ fgt_refuse "writing rootfs_data failed"; return 1; }
		fgt_drop_caches
		[ "$(dd if="$FGT_SLOT" bs=512 skip=$rel count=1 2>/dev/null |
			fgt_hex 0 4)" = "$FGT_DEADCODE" ] ||
			{ fgt_refuse "rootfs_data does not read back as written"; return 1; }
	fi
}

# Right before each write: the boot disk is still the one checked (an
# USB stick found again by its port, vendor, model and size), nothing
# of it is mounted, and the write windows are still the expected armed
# ones
fgt_recheck_disk() {
	if [ "$FGT_DISK_KIND" = usb ]; then
		[ "$FGT_DEV/$(fgt_disk_usb)" = "$FGT_DISK" ] ||
			{ fgt_refuse "the boot stick changed since the checks"; return 1; }
		grep -qs "^$FGT_DISK" "$FGT_PROC_MOUNTS" &&
			{ fgt_refuse "$FGT_DISK is mounted"; return 1; }
	else
		fgt_disk_mmc ||
			{ fgt_refuse "no eMMC slot $FGT_MMC_SLOT"; return 1; }
		grep -qs "^$FGT_SLOT " "$FGT_PROC_MOUNTS" &&
			{ fgt_refuse "$FGT_SLOT is mounted"; return 1; }
	fi
	fgt_is_block "$FGT_DISK" && fgt_is_block "$FGT_SLOT" ||
		{ fgt_refuse "no slot $FGT_SLOT"; return 1; }
	fgt_ww_is armed ||
		{ fgt_refuse "write windows no longer armed ($(cat "$FGT_WW" 2>/dev/null))"; return 1; }
}

# After a failed write of sector 0, the windows off: reads it back and
# tells what the disk holds, the saved copy <s0> or the header <new>
fgt_s0_state() { # <s0> <new> <read>
	rm -f "$3"
	fgt_drop_caches
	if ! "$FGT_SECTOR0" read "$FGT_DISK" "$3"; then
		echo "Boot sector: cannot read it back (saved copy $1)" >&2
	elif cmp -s "$3" "$1"; then
		echo "Boot sector unchanged" >&2
	elif cmp -s "$3" "$2"; then
		echo "Boot sector holds the new header" >&2
	else
		echo "Boot sector differs from the saved copy and from the new header: keep the saved copy $1 ($(sha256sum < "$1" | cut -c1-64))" >&2
	fi
}

fgt_check_image() { # <image>
	local s0="$FGT_TMP/fortigate-s0.check"

	if [ "$FGT_DUALSLOT_CONFIRMED" != 1 ]; then
		echo "$FGT_BOARD: installing to the boot disk is disabled."
		# Not forceable by sysupgrade -F
		return 74
	fi
	fgt_check_settings ||
		{ echo "${FGT_BOARD:-FortiGate}: bad installer settings (platform.sh)."
		  return 74; }
	fgt_check_writable_list ||
		{ fgt_refuse "bad list of writable header bytes"; return 74; }
	# Without persistence nothing is kept: sysupgrade -n only
	if [ "$FGT_PERSIST" != 1 ]; then
		command -v notify_firmware_no_backup > /dev/null &&
			notify_firmware_no_backup
		[ "$SAVE_CONFIG" != 1 ] ||
			{ fgt_refuse "no configuration is kept on this board: use sysupgrade -n"; return 74; }
	fi
	fgt_check_disk "$s0" || return 74
	fgt_check_container "$1" > /dev/null || return 1
}

fgt_do_upgrade() { # <image>
	local img="$1"
	local s0="$FGT_TMP/fortigate-s0.bak" new="$FGT_TMP/fortigate-s0.new"
	local rb="$FGT_TMP/fortigate-s0.read"
	local name part ofs len sum loop backup=""

	[ "$FGT_DUALSLOT_CONFIRMED" = 1 ] ||
		{ fgt_refuse "installing to the boot disk is disabled"; return 74; }
	fgt_check_settings ||
		{ fgt_refuse "bad installer settings (platform.sh)"; return 74; }
	fgt_check_writable_list ||
		{ fgt_refuse "bad list of writable header bytes"; return 74; }
	[ "$FGT_PERSIST" = 1 ] || [ -z "$UPGRADE_BACKUP" ] ||
		{ fgt_refuse "no configuration is kept on this board: use sysupgrade -n"; return 74; }
	fgt_check_disk "$s0" || return 74
	name="$(fgt_image_name)"
	part="$(fgt_check_container "$img")" || return 1
	ofs="${part% *}"; len="${part#* }"
	# rootfs_data: no loop device left on the disk (stage2 unmounts
	# the overlay, the loop device then frees itself), and what to
	# write at its head
	if [ "$FGT_PERSIST" = 1 ]; then
		loop="$(fgt_loop_wait)" ||
			{ fgt_refuse "$loop still bound to $FGT_DISK"; return 74; }
		backup="$(fgt_rootfs_data_backup)" || return 1
	fi
	echo "Boot disk: $FGT_DISK, target slot $FGT_SLOT"
	echo "Boot sector saved to $s0: $(sha256sum < "$s0" | cut -c1-64)"
	# Header prepared and checked before anything is written
	fgt_new_header "$s0" "$new" "$name" || return 1
	sum="$(get_image "$img" | tail -c +$((ofs + 1)) | head -c $len |
		sha256sum | cut -c1-64)"

	# Arm the write windows (once per boot), then the stick alone
	# writable (it may be read-only by user space as well). What is
	# dirty is written back first: nothing queued before goes out while
	# the windows are armed.
	sync
	fgt_ww_arm
	fgt_ww_is armed ||
		{ fgt_refuse "the write windows do not arm ($(cat "$FGT_WW" 2>/dev/null))"; fgt_ww_done; return 74; }
	echo "Write windows armed: $(cat "$FGT_WW")"
	if [ "$FGT_DISK_KIND" = usb ]; then
		blockdev --setrw "$FGT_DISK" &&
			[ "$(blockdev --getro "$FGT_DISK")" = 0 ] ||
			{ fgt_refuse "$FGT_DISK stays read-only"; fgt_ww_done; return 1; }
	fi

	# 1. Target slot: the file system of partition 0 of the image (the
	# container only, with persistence), then read back from the disk
	fgt_recheck_disk || { fgt_ww_done; return 1; }
	echo "Writing the target slot ($FGT_SLOT, $len bytes)"
	get_image "$img" | tail -c +$((ofs + 1)) | head -c $len |
		dd of="$FGT_SLOT" bs=1M conv=fsync,notrunc 2>/dev/null ||
		{ fgt_refuse "writing the target slot failed"; fgt_ww_done; return 1; }
	fgt_drop_caches
	[ "$(head -c $len "$FGT_SLOT" | sha256sum | cut -c1-64)" = "$sum" ] ||
		{ fgt_refuse "the target slot does not read back as written"; fgt_ww_done; return 1; }

	# 2. rootfs_data: the backup archive or the marker at its head
	if [ "$FGT_PERSIST" = 1 ]; then
		fgt_recheck_disk && fgt_write_rootfs_data "$backup" ||
			{ fgt_ww_done; return 1; }
	fi

	# 3. Header (read-modify-write of sector 0, direct I/O), read
	# back from the disk; sector 0 must still be the one saved
	fgt_recheck_disk ||
		{ fgt_refuse "header unchanged"; fgt_ww_done; return 1; }
	rm -f "$rb"
	"$FGT_SECTOR0" read "$FGT_DISK" "$rb" && cmp -s "$rb" "$s0" ||
		{ fgt_refuse "the boot sector changed since it was saved, header unchanged"; fgt_ww_done; return 1; }
	"$FGT_SECTOR0" write "$FGT_DISK" "$new" ||
		{ fgt_refuse "writing the boot sector failed"; fgt_ww_done
		  fgt_s0_state "$s0" "$new" "$rb"; return 1; }
	fgt_ww_done
	fgt_drop_caches
	rm -f "$rb"
	"$FGT_SECTOR0" read "$FGT_DISK" "$rb" &&
		cmp -s "$rb" "$new" ||
		{ fgt_refuse "boot sector does not read back as written"
		  fgt_s0_state "$s0" "$new" "$rb"; return 1; }

	echo "Partition $FGT_SLOT_PART written ($sum), image $FGT_SLOT_IMAGE named \"${name:0:$FGT_NAME_LEN}\", build 0."
	if [ "$FGT_PERSIST" = 1 ]; then
		if [ -n "$backup" ]; then
			echo "rootfs_data holds the configuration backup: restored at the next boot."
		else
			echo "rootfs_data erased: formatted at the next boot."
		fi
	fi
	if [ "$FGT_SLOT_MAKE_DEFAULT" = 1 ]; then
		echo "Partition $FGT_SLOT_PART is now the default slot: [B] in the boot menu brings the stock firmware back."
	else
		echo "The default slot is unchanged: switch with [B] in the boot menu."
	fi
}
