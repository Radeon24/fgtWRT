# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

DEVICE_VARS += FORTIGATE_CMDLINE FORTIGATE_MODEL
DEVICE_VARS += FORTIGATE_PART_LBA FORTIGATE_PART_SECTORS FORTIGATE_CONTAINER_DTB
DEVICE_VARS += FORTIGATE_CONTAINER_SECTORS

FORTIGATE_EPOCH := $(if $(SOURCE_DATE_EPOCH),$(SOURCE_DATE_EPOCH),0)

# Shell code writing the 32-bit value $(1) in little endian
fortigate-le32 = v=$$(printf "%08x" $(1)); printf "\x$${v:6:2}\x$${v:4:2}\x$${v:2:2}\x$${v:0:2}"

# flatkc, the kernel file the boot loader runs: a 512-byte header followed
# by a gzip stream (here the zImage with its DTB, which relocates and
# inflates itself). Header, little endian, all zero but for:
#
#   0x000  55 aa aa 55   magic
#   0x004  0x000000ce
#   0x008  0x00000200    offset of the gzip stream
#   0x00c  0x55aae517    tag
#   0x030  0x00100000    load address
#   0x058  length        of the command line, terminator included
#   0x05c  command line  terminated by "\n\0" (ignored by the kernel, which
#                        is built with CONFIG_CMDLINE_FORCE)
#
# A copy is kept next to the images.
define Build/fortigate-flatkc
	$(STAGING_DIR_HOST)/bin/gzip -9 -n -c $@ > $@.gz
	( \
		cmdline="$(FORTIGATE_CMDLINE)"; \
		len=$$(($$(printf "%s" "$$cmdline" | wc -c) + 2)); \
		[ $$len -le 420 ] || { echo "command line too long" >&2; exit 1; }; \
		$(call fortigate-le32,0x55aaaa55); \
		$(call fortigate-le32,0xce); \
		$(call fortigate-le32,0x200); \
		$(call fortigate-le32,0x55aae517); \
		head -c 32 /dev/zero; \
		$(call fortigate-le32,0x100000); \
		head -c 36 /dev/zero; \
		$(call fortigate-le32,$$len); \
		printf "%s\n\0" "$$cmdline"; \
		head -c $$((420 - len)) /dev/zero; \
		cat $@.gz; \
	) > $@.new
	mv $@.new $@
	rm -f $@.gz
	mkdir -p $(BIN_DIR)
	cp $@ $(BIN_DIR)/$(DEVICE_IMG_PREFIX)-initramfs-flatkc.bin
endef

# Firmware container for a TFTP boot to RAM (boot menu option [R]): a disk
# image whose MBR partition table has a single entry, an ext2 holding the
# "flatkc" file and a "rootfs.gz" (an empty gzip stream: loaded by the boot
# loader, then ignored by a kernel built with CONFIG_INITRAMFS_FORCE). The
# boot loader wants both files and the partition table; it checks neither
# the rest of the MBR nor the file system geometry. With
# FORTIGATE_CONTAINER_DTB, the ext2 also holds the device tree as
# "devicetree.dtb", like the stock containers of the FortiSOC3 models
# (the kernel uses the copy appended to the zImage). The container is then
# compressed by gzip-filename with the model as name, which the boot loader
# checks too. The output only depends on SOURCE_DATE_EPOCH, which e2fsprogs
# also prefers to E2FSPROGS_FAKE_TIME. The ext2 spans
# FORTIGATE_CONTAINER_SECTORS (default: the whole partition), while the
# partition entry always gives FORTIGATE_PART_SECTORS, the size of the
# firmware slot; the end of the slot then stays out of the container.
define Build/fortigate-container
	rm -rf $@.root $@.ext2
	mkdir -p $@.root
	cp $@ $@.root/flatkc
	$(STAGING_DIR_HOST)/bin/gzip -9 -n -c < /dev/null > $@.root/rootfs.gz
	$(if $(FORTIGATE_CONTAINER_DTB), \
		cp $(KDIR)/image-$(firstword $(DEVICE_DTS)).dtb \
			$@.root/devicetree.dtb)
	E2FSPROGS_FAKE_TIME=$(FORTIGATE_EPOCH) \
	SOURCE_DATE_EPOCH=$(FORTIGATE_EPOCH) \
	$(STAGING_DIR_HOST)/bin/mke2fs -q -F -t ext2 -r 1 -b 1024 -I 128 \
		-i 4096 -m 5 \
		-O none,ext_attr,resize_inode,dir_index,filetype,sparse_super \
		-U clear \
		-E root_owner=0:0,hash_seed=66727469-7772-7400-0000-000000000309 \
		-d $@.root $@.ext2 \
		$$(($(or $(FORTIGATE_CONTAINER_SECTORS),$(FORTIGATE_PART_SECTORS)) / 2))
	for f in flatkc rootfs.gz $(if $(FORTIGATE_CONTAINER_DTB),devicetree.dtb); do \
		echo "sif /$$f uid 0"; \
		echo "sif /$$f gid 0"; \
		for t in atime mtime ctime; do \
			echo "sif /$$f $$t @$(FORTIGATE_EPOCH)"; \
		done; \
	done > $@.cmds
	E2FSPROGS_FAKE_TIME=$(FORTIGATE_EPOCH) \
	SOURCE_DATE_EPOCH=$(FORTIGATE_EPOCH) \
	$(STAGING_DIR_HOST)/bin/debugfs -w -f $@.cmds $@.ext2 > /dev/null
	$(STAGING_DIR_HOST)/bin/e2fsck -fn $@.ext2 > /dev/null
	( \
		head -c 446 /dev/zero; \
		printf "\x80\x00\x00\x00\x83\x00\x00\x00"; \
		$(call fortigate-le32,$(FORTIGATE_PART_LBA)); \
		$(call fortigate-le32,$(FORTIGATE_PART_SECTORS)); \
		head -c 48 /dev/zero; \
		printf "\x55\xaa"; \
		head -c $$((($(FORTIGATE_PART_LBA) - 1) * 512)) /dev/zero; \
		cat $@.ext2; \
	) > $@.new
	mv $@.new $@
	rm -rf $@.root $@.ext2 $@.cmds
endef

define Device/Default
  PROFILES := Default
  DEVICE_DTS_DIR := ../dts
  KERNEL_NAME := zImage
  KERNEL := kernel-bin | append-dtb
  KERNEL_INITRAMFS = kernel-bin | append-dtb | fortigate-flatkc | \
	fortigate-container | gzip-filename $$(FORTIGATE_MODEL)
  FORTIGATE_CMDLINE := console=ttyS0,9600n8
  # Name of the gzip member of the TFTP image, checked by the boot loader
  FORTIGATE_MODEL :=
  # Partition 0 of the container, in 512-byte sectors: start (LBA) and
  # size, the size of the firmware slot (16 MiB here, each device sets
  # its own)
  FORTIGATE_PART_LBA := 1
  FORTIGATE_PART_SECTORS := 32768
  # Size of the ext2 of the container, in 512-byte sectors, at most
  # FORTIGATE_PART_SECTORS; empty: FORTIGATE_PART_SECTORS
  FORTIGATE_CONTAINER_SECTORS :=
  # Also put the device tree in the container (FortiSOC3)
  FORTIGATE_CONTAINER_DTB :=
  # No OpenWrt-style sysupgrade image is defined here: the container
  # built above is also the image the installer package writes to a
  # firmware slot.
  IMAGES :=
endef

include $(SUBTARGET).mk

$(eval $(call BuildImage))
