# SPDX-License-Identifier: GPL-2.0-only
#
# These images boot from RAM through the stock boot loader. On the board
# below, the installer (the fgt_* functions of fortigate.sh, package
# fortigate-dualslot) writes the second firmware slot of the internal
# SATA disk through the write windows of the kernel; every other board
# installs nothing. Never a fallback to the generic x86 upgrade: it
# writes the whole disk and mounts its partition 1, which hold the stock
# firmware.
#
# 100D: persistence (FGT_PERSIST), as on the 90D. The slot (partition 2,
# sectors 524289-1048576 of the disk) holds the container (the ext file
# system the boot loader reads, smaller than the slot) followed by
# rootfs_data, the upper layer of the overlay. There is no device tree:
# the place of rootfs_data is read from the kernel command line
# (fortinet.rootfs_data=), never set here; the expected witness below
# only repeats what the kernel reports from the same command line, and
# rootfs_data must be its persistent window. The slot is made the
# default one (FGT_SLOT_MAKE_DEFAULT: boot flags 0x1be/0x1ce, allowed by
# the witness); [B] in the boot menu brings the stock firmware back.
# sysupgrade keeps the configuration (its backup archive at the head of
# rootfs_data), sysupgrade -n erases it.

# Sets the disk, the target slot and the image name of the board named
# by board_name, for the fgt_* functions of fortigate.sh. Fails on any
# other board.
fgt_board() {
	case "$(board_name)" in
	fortinet,fg100d)
		FGT_BOARD="FortiGate 100D"
		FGT_DISK_KIND=ata
		# The SSD on port 1 of the SATA controller: never chosen by
		# its sdX name, which depends on the other disks plugged in
		FGT_ATA_PATH="/0000:00:1f.2/ata1/"
		FGT_DISK_VENDOR=ATA
		FGT_DISK_MODEL="SATA SSD"
		FGT_DISK_SECTORS=31277232
		FGT_SLOT_PART=2
		FGT_SLOT_LBA=524289
		FGT_SLOT_SIZE=524288
		FGT_SLOT_IMAGE=1
		FGT_IMAGE_NAME=FGT100D-OpenWrt
		# OpenWrt becomes the default slot, rootfs_data persistent
		# (its place comes from the kernel command line)
		FGT_SLOT_MAKE_DEFAULT=1
		FGT_PERSIST=1
		FGT_HEADER_FORBIDDEN="0xdc:1"
		FGT_WW_EXPECTED="0+1 524289+524288 persistent 589824+458752 sector0 0x30+32 0x12c+4 0x1be+1 0x1ce+1"
		;;
	*)
		return 1
		;;
	esac
}

platform_check_image() {
	fgt_board || {
		echo "This board runs from RAM only and installs nothing."
		# Not forceable by sysupgrade -F
		return 74
	}
	command -v fgt_check_image > /dev/null || {
		echo "$FGT_BOARD: fortigate-dualslot is missing, no installer."
		# Not forceable by sysupgrade -F
		return 74
	}
	fgt_check_image "$1"
}

platform_do_upgrade() {
	fgt_board || {
		echo "This board runs from RAM only and installs nothing."
		return 74
	}
	command -v fgt_do_upgrade > /dev/null || {
		echo "$FGT_BOARD: fortigate-dualslot is missing, no installer."
		return 74
	}
	fgt_do_upgrade "$1"
}

# The configuration goes to rootfs_data (fgt_do_upgrade writes the backup
# archive at its head): nothing to copy, and never the generic x86 copy
# into partition 1
platform_copy_config() {
	return 0
}

# Binaries copied into the upgrade ramdisk, on top of the default ones
# (fortigate.sh needs them there; dd, hexdump, tail, wc, grep, cut and
# printf, also used for rootfs_data and the kernel command line, are
# among the default ones of stage2)
case "$(board_name)" in
fortinet,fg100d)
	RAMFS_COPY_BIN="$RAMFS_COPY_BIN blockdev cmp head readlink sha256sum fgt-sector0"
	;;
esac
