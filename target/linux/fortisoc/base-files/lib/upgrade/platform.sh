# SPDX-License-Identifier: GPL-2.0-only
#
# These images run from RAM only: nothing is installed, except on the
# boards below, whose installer (the fgt_* functions of fortigate.sh,
# package fortigate-dualslot) writes a firmware slot of the boot disk
# through the write windows of the kernel: an internal USB stick, or
# the eMMC.
#
# 90D and 60E: the slot that is not the default one; the default slot
# is left unchanged ([B] in the boot menu switches to OpenWrt), and
# nothing of the system is kept (sysupgrade -n).
#
# 60D: persistence (FGT_PERSIST). Its slot (partition 1, sectors
# 1-524288 of the stick) holds the container (the ext file system the
# boot loader reads, smaller than the slot) followed by rootfs_data,
# the upper layer of the overlay. The place of rootfs_data is read
# from the device tree (node fortinet,disk-rootfs-data), never set
# here: the expected witness below only repeats what the kernel
# reports from the same device tree, and rootfs_data must be its
# persistent window. The slot is made the default one
# (FGT_SLOT_MAKE_DEFAULT: boot flags 0x1be/0x1ce, allowed by the
# witness); [B] in the boot menu brings the stock firmware back. sysupgrade
# keeps the configuration (its backup archive at the head of
# rootfs_data), sysupgrade -n erases it.

# Sets the disk, the target slot and the image name of the board named
# by board_name, for the fgt_* functions of fortigate.sh. Fails on any
# other board.
fgt_board() {
	case "$(board_name)" in
	fortinet,fg60d)
		FGT_BOARD="FortiGate 60D"
		FGT_DISK_KIND=usb
		# The stick: never chosen by its sdX name, which depends on
		# the other disks plugged in
		FGT_USB_PATH="/f0200000.usb/"
		FGT_USB_PORT="/2-1/2-1.2/"
		FGT_DISK_VENDOR=FORTINET
		FGT_DISK_MODEL=S01_V140320_004
		FGT_DISK_SECTORS=7913472
		FGT_SLOT_PART=1
		FGT_SLOT_LBA=1
		FGT_SLOT_SIZE=524288
		FGT_SLOT_IMAGE=0
		FGT_IMAGE_NAME=FGT60D-OpenWrt
		# OpenWrt becomes the default slot, rootfs_data persistent
		# (its place comes from the device tree)
		FGT_SLOT_MAKE_DEFAULT=1
		FGT_PERSIST=1
		FGT_HEADER_FORBIDDEN="0xdc:1"
		FGT_WW_EXPECTED="0+1 1+524288 persistent 32768+491520 sector0 0x10+32 0x128+4 0x1be+1 0x1ce+1"
		;;
	fortinet,fg90d)
		FGT_BOARD="FortiGate 90D"
		FGT_DISK_KIND=usb
		FGT_USB_PATH="/f0100000.usb/"
		FGT_USB_PORT="/1-1/1-1:1.0/"
		FGT_DISK_VENDOR=FORTINET
		FGT_DISK_MODEL=61_V030910_008
		FGT_DISK_SECTORS=15654912
		FGT_SLOT_PART=2
		FGT_SLOT_LBA=524289
		FGT_SLOT_SIZE=524288
		FGT_SLOT_IMAGE=1
		FGT_IMAGE_NAME=FGT90D-OpenWrt
		FGT_SLOT_NONDEFAULT=1
		FGT_HEADER_FORBIDDEN="0xdc:1"
		FGT_WW_EXPECTED="0+1 524289+524288 sector0 0x30+32 0x12c+4"
		;;
	fortinet,fg60e)
		FGT_BOARD="FortiGate 60E"
		FGT_DISK_KIND=mmc
		FGT_MMC_DISK=/dev/mmcblk0
		FGT_MMC_SLOT=/dev/mmcblk0p2
		FGT_SLOT_PART=2
		FGT_SLOT_LBA=786440
		FGT_SLOT_SIZE=524288
		FGT_SLOT_IMAGE=1
		FGT_IMAGE_NAME=FGT60E-OpenWrt
		FGT_HEADER_FORBIDDEN="0xdc:1 0x170:1"
		FGT_WW_EXPECTED="0+1 786440+524288"
		;;
	*)
		return 1
		;;
	esac
}

platform_check_image() {
	fgt_board || {
		echo "This target runs from RAM only and installs nothing."
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
	fgt_board || return 1
	fgt_do_upgrade "$1"
}

# Binaries copied into the upgrade ramdisk, on top of the default ones
# (fortigate.sh needs them there; dd, hexdump, tail, wc, grep, cut and
# printf, also used for rootfs_data and the device tree, are among the
# default ones of stage2)
case "$(board_name)" in
fortinet,fg60d|fortinet,fg90d)
	RAMFS_COPY_BIN="$RAMFS_COPY_BIN blockdev cmp head readlink sha256sum fgt-sector0"
	;;
fortinet,fg60e)
	RAMFS_COPY_BIN="$RAMFS_COPY_BIN cmp head sha256sum fgt-sector0"
	;;
esac
