# SPDX-License-Identifier: GPL-2.0-only

BOARDNAME:=FortiSOC3
CPU_TYPE:=cortex-a9
CPU_SUBTYPE:=vfpv3-d16
FEATURES+=fpu
# The kernel takes its initramfs from the rootfs.gz of the container
# (option "separate ramdisk", see image/Makefile)
FEATURES+=separate_ramdisk

define Target/Description
	Build images for the FortiSOC3 (four ARM Cortex-A9 r4p1 cores,
	VFPv3-D16 without NEON), with an eMMC holding the firmware slots.
endef
