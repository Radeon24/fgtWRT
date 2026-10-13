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
# writes 0x1be/0x1ce). Nothing here changes the default slot: OpenWrt
# goes to the slot that is not the default one, and the switch is left
# to the boot loader.
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
# them off when done or on failure. A USB stick may also be kept
# read-only by user space (blockdev --setro): the stick alone is made
# writable while the windows are armed, and read-only again
# afterwards.
#
# Upgrade image: the TFTP image itself (a gzip stream holding a disk
# image whose partition 0 is the file system of a slot), so that the
# file booted from RAM by option [R] is the one installed. Partition 0
# is copied as is into the target slot. Use sysupgrade -n: nothing of
# the RAM system is kept.
#
# The name of the image written in the header can be overridden without
# touching platform.sh: set FGT_IMAGE_NAME_ENV in the environment.

# Kill switch: set to 0 to refuse every upgrade (not forceable).
FGT_DUALSLOT_CONFIRMED=1

# Format of the boot sector (independent of the board)
FGT_MAGIC_OFS=0x0e
FGT_MAGIC=aa55
FGT_NAME_LEN=32
FGT_BUILD_LEN=4
# Direct I/O on sector 0 (never busybox dd: not direct at bs=512)
FGT_SECTOR0=fgt-sector0
FGT_DROP_CACHES=/proc/sys/vm/drop_caches

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
	usb) FGT_WW=/sys/module/block/parameters/write_windows ;;
	mmc) FGT_WW=/sys/module/mmc_core/parameters/write_windows ;;
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
	[ -n "$FGT_BOARD" ] && [ -n "$FGT_IMAGE_NAME" ] &&
		[ -n "$FGT_WW_EXPECTED" ] || return 1
	case "$FGT_SLOT_LBA$FGT_SLOT_SIZE" in
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
	o="$(fgt_image_offsets "$FGT_SLOT_IMAGE")" || return 1
	FGT_NAME_OFS="${o% *}"; FGT_BUILD_OFS="${o#* }"
	o="$(fgt_image_offsets "$((1 - FGT_SLOT_IMAGE))")" || return 1
	FGT_OTHER_NAME_OFS="${o% *}"; FGT_OTHER_BUILD_OFS="${o#* }"
	# The closed list of header bytes this script may change (first
	# offset, length): name and build number of the image it writes.
	FGT_WRITABLE="$FGT_NAME_OFS:$FGT_NAME_LEN $FGT_BUILD_OFS:$FGT_BUILD_LEN"
	# Header bytes never to be changed, whatever the list above says:
	# boot flags of MBR entries 1 and 2, magic, name and build number
	# of the other image, and the bytes listed by the board.
	FGT_FORBIDDEN="0x1be:1 0x1ce:1 0x0e:2 \
$FGT_OTHER_NAME_OFS:$FGT_NAME_LEN $FGT_OTHER_BUILD_OFS:$FGT_BUILD_LEN \
$FGT_HEADER_FORBIDDEN"
}

# Every range of FGT_WRITABLE must lie in the header (before the
# partition table) and out of FGT_FORBIDDEN
fgt_check_writable_list() {
	local w f wo wl fo fl

	for w in $FGT_WRITABLE; do
		wo=$((${w%%:*})); wl=$((${w##*:}))
		[ $wl -gt 0 ] && [ $((wo + wl)) -le $((0x1be)) ] ||
			return 1
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

	for b in /sys/block/sd*; do
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

# The eMMC: the devices given by the board must exist
fgt_disk_mmc() {
	[ -b "$FGT_MMC_DISK" ] && [ -b "$FGT_MMC_SLOT" ]
}

# Witness of the write windows, read at every check: the first word is
# "inactive", "off", "disarmed" or "armed"; then the windows
# ("<start>+<count>", in sectors of the whole disk, or "none"), and,
# for the USB guard, "sector0" followed by the bytes of sector 0 that
# may change ("<offset hex>+<count>", or "none"). Sets FGT_WW_LINE (the
# witness), FGT_WW_STATE, FGT_WW_WINDOWS and FGT_WW_BYTES in the calling
# shell: never call it from a command substitution. Any other shape
# (unknown word, state word not first or repeated) gives the state
# "unknown".
fgt_ww_read() {
	local w n=0 s0=0

	FGT_WW_LINE=""
	FGT_WW_STATE=unknown
	FGT_WW_WINDOWS=""
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
		sector0)
			[ $s0 = 0 ] && [ "$FGT_DISK_KIND" = usb ] ||
				{ FGT_WW_STATE=unknown; return 0; }
			s0=1
			;;
		none)
			;;
		[0-9]*+[0-9]*)
			if [ "$s0" = 1 ]; then
				FGT_WW_BYTES="$FGT_WW_BYTES $w"
			else
				FGT_WW_WINDOWS="$FGT_WW_WINDOWS $w"
			fi
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

# True when the windows cover <start>+<count> sectors of the disk
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

# Checks of the disk and its boot sector, shared by the image check and
# the upgrade itself. Sets FGT_DISK, FGT_SLOT, FGT_SLOT_START and
# FGT_SLOT_SECTORS; the target partition must lie inside the write
# windows of the kernel, and the bytes of the header this script
# changes must be among those the kernel allows (USB guard).
fgt_check_disk() { # <sector 0 file>
	local s0="$1" disk part start size

	if [ "$FGT_DISK_KIND" = usb ]; then
		command -v blockdev > /dev/null ||
			{ fgt_refuse "blockdev is missing"; return 1; }
		disk="$(fgt_disk_usb)" ||
			{ fgt_refuse "boot stick not found (or more than one)"; return 1; }
		FGT_DISK="/dev/$disk"
		FGT_SLOT="/dev/$disk$FGT_SLOT_PART"
		part="$disk$FGT_SLOT_PART"
	else
		fgt_disk_mmc ||
			{ fgt_refuse "no eMMC slot $FGT_MMC_SLOT"; return 1; }
		FGT_DISK="$FGT_MMC_DISK"
		FGT_SLOT="$FGT_MMC_SLOT"
		part="${FGT_MMC_SLOT#/dev/}"
	fi
	command -v "$FGT_SECTOR0" > /dev/null ||
		{ fgt_refuse "$FGT_SECTOR0 is missing"; return 1; }
	[ -b "$FGT_DISK" ] && [ -b "$FGT_SLOT" ] ||
		{ fgt_refuse "no slot $FGT_SLOT"; return 1; }
	if [ "$FGT_DISK_KIND" = usb ]; then
		grep -qs "^$FGT_DISK" /proc/mounts &&
			{ fgt_refuse "$FGT_DISK is mounted"; return 1; }
	else
		grep -qs "^$FGT_SLOT " /proc/mounts &&
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
	if [ "$FGT_SLOT_NONDEFAULT" = 1 ]; then
		[ "$(fgt_hex $(fgt_mbr $FGT_SLOT_PART 0) 1 "$s0")" = 00 ] &&
			[ "$(fgt_hex $(fgt_mbr $((3 - FGT_SLOT_PART)) 0) 1 "$s0")" = 80 ] ||
			{ fgt_refuse "partition $FGT_SLOT_PART is the default slot (or no default): switch to partition $((3 - FGT_SLOT_PART)) with [B] first"; return 1; }
	fi

	# The target partition as seen by the kernel and by its MBR entry
	start="$(cat /sys/class/block/$part/start)"
	size="$(cat /sys/class/block/$part/size)"
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
	fi
}

# Checks the TFTP image: gzip stream, MBR, partition 0 of the size of
# the target slot holding an ext file system. Prints "<offset>
# <length>" of partition 0.
fgt_check_container() { # <image>
	local img="$1" mbr="/tmp/fortigate-image.mbr" lba sectors

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
	# ext2/3/4 magic (0xef53) of partition 0
	[ "$(get_image "$img" | tail -c +$((lba * 512 + 1080 + 1)) |
		fgt_hex 0 2)" = 53ef ] ||
		{ fgt_refuse "partition 0 holds no ext file system"; return 1; }
	echo "$((lba * 512)) $((sectors * 512))"
}

# New header in <new> from <s0>: name of the image at its offset, its
# build number at 0; every changed byte must lie in the closed list.
fgt_new_header() { # <s0> <new> <name>
	local s0="$1" new="$2" name="$3" diff

	cp "$s0" "$new"
	printf '%s' "${name:0:$FGT_NAME_LEN}" |
		dd of="$new" bs=$FGT_NAME_LEN count=1 conv=sync,notrunc \
			oflag=seek_bytes seek=$(($FGT_NAME_OFS)) 2>/dev/null
	dd if=/dev/zero of="$new" bs=$FGT_BUILD_LEN count=1 conv=notrunc \
		oflag=seek_bytes seek=$(($FGT_BUILD_OFS)) 2>/dev/null
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

fgt_check_image() { # <image>
	local s0="/tmp/fortigate-s0.check"

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
	fgt_check_disk "$s0" || return 74
	fgt_check_container "$1" > /dev/null || return 1
}

fgt_do_upgrade() { # <image>
	local img="$1"
	local s0="/tmp/fortigate-s0.bak" new="/tmp/fortigate-s0.new"
	local rb="/tmp/fortigate-s0.read"
	local name part ofs len sum

	[ "$FGT_DUALSLOT_CONFIRMED" = 1 ] ||
		{ fgt_refuse "installing to the boot disk is disabled"; return 74; }
	fgt_check_settings ||
		{ fgt_refuse "bad installer settings (platform.sh)"; return 74; }
	fgt_check_writable_list ||
		{ fgt_refuse "bad list of writable header bytes"; return 74; }
	fgt_check_disk "$s0" || return 74
	name="$(fgt_image_name)"
	part="$(fgt_check_container "$img")" || return 1
	ofs="${part% *}"; len="${part#* }"
	echo "Boot disk: $FGT_DISK, target slot $FGT_SLOT"
	echo "Boot sector saved to $s0: $(sha256sum < "$s0" | cut -c1-64)"
	# Header prepared and checked before anything is written
	fgt_new_header "$s0" "$new" "$name" || return 1
	sum="$(get_image "$img" | tail -c +$((ofs + 1)) | head -c $len |
		sha256sum | cut -c1-64)"

	# Arm the write windows (once per boot), then the stick alone
	# writable (it may be read-only by user space as well)
	fgt_ww_arm
	fgt_ww_is armed ||
		{ fgt_refuse "the write windows do not arm ($(cat "$FGT_WW" 2>/dev/null))"; fgt_ww_done; return 74; }
	echo "Write windows armed: $(cat "$FGT_WW")"
	if [ "$FGT_DISK_KIND" = usb ]; then
		blockdev --setrw "$FGT_DISK" &&
			[ "$(blockdev --getro "$FGT_DISK")" = 0 ] ||
			{ fgt_refuse "$FGT_DISK stays read-only"; fgt_ww_done; return 1; }
	fi

	# 1. Target slot: partition 0 of the image, then read back from
	# the disk
	echo "Writing the target slot ($FGT_SLOT, $len bytes)"
	get_image "$img" | tail -c +$((ofs + 1)) | head -c $len |
		dd of="$FGT_SLOT" bs=1M conv=fsync 2>/dev/null ||
		{ fgt_refuse "writing the target slot failed"; fgt_ww_done; return 1; }
	fgt_drop_caches
	[ "$(head -c $len "$FGT_SLOT" | sha256sum | cut -c1-64)" = "$sum" ] ||
		{ fgt_refuse "the target slot does not read back as written"; fgt_ww_done; return 1; }

	# 2. Header (read-modify-write of sector 0, direct I/O), read
	# back from the disk
	fgt_ww_is armed ||
		{ fgt_refuse "write windows no longer armed, header unchanged"; fgt_ww_done; return 1; }
	"$FGT_SECTOR0" write "$FGT_DISK" "$new" ||
		{ fgt_refuse "writing the boot sector failed"; fgt_ww_done; return 1; }
	fgt_ww_done
	fgt_drop_caches
	rm -f "$rb"
	"$FGT_SECTOR0" read "$FGT_DISK" "$rb" &&
		cmp -s "$rb" "$new" ||
		{ fgt_refuse "boot sector does not read back as written"; return 1; }

	echo "Partition $FGT_SLOT_PART written ($sum), image $FGT_SLOT_IMAGE named \"${name:0:$FGT_NAME_LEN}\", build 0."
	echo "The default slot is unchanged: switch with [B] in the boot menu."
}
