# SPDX-License-Identifier: GPL-2.0-only

BOARDNAME:=FortiSOC2
CPU_TYPE:=arm926ej-s
# The kernel may also take its initramfs from the rootfs.gz of the
# container (option "separate ramdisk", see image/Makefile)
FEATURES+=separate_ramdisk

define Target/Description
	Build images for the FortiSOC2 (Faraday FA726TE, ARMv5TE):
	a network processor, one or two BCM53128 switches behind its
	links, and the firmware slots of the internal storage.
endef
