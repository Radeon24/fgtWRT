# SPDX-License-Identifier: GPL-2.0-only

ARCH:=x86_64
BOARDNAME:=Fortinet FortiGate (x86)
# Booted from RAM by the stock boot loader (no GRUB, no disk image). The
# kernel may take its initramfs from the rootfs.gz of the container
# (option "separate ramdisk", see image/fortigate.mk) or embed it.
FEATURES:=fpu pci usb usbgadget ramdisk separate_ramdisk

define Target/Description
	Build images for Fortinet FortiGate appliances built around an
	x86 processor (FortiGate 100D: Intel Atom D525, ICH8M). The stock
	boot loader runs a "flatkc" kernel file from a firmware container:
	no GRUB, no ACPI tables, no DMI. The kernel never writes the CMOS
	clock, which the boot loader and the stock firmware share.
endef
