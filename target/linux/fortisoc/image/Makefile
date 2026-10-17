# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

DEVICE_VARS += FORTIGATE_CMDLINE FORTIGATE_MODEL
DEVICE_VARS += FORTIGATE_PART_LBA FORTIGATE_PART_SECTORS FORTIGATE_CONTAINER_DTB
DEVICE_VARS += FORTIGATE_CONTAINER_SECTORS FORTIGATE_FLATKC_MAX
DEVICE_VARS += FORTIGATE_INITRD_ADDR

FORTIGATE_EPOCH := $(if $(SOURCE_DATE_EPOCH),$(SOURCE_DATE_EPOCH),0)

# Shell code writing the 32-bit value $(1) in little endian
fortigate-le32 = v=$$(printf "%08x" $(1)); printf "\x$${v:6:2}\x$${v:4:2}\x$${v:2:2}\x$${v:0:2}"

# Shell function rd32 <file> <offset>: the 32-bit little endian value there
fortigate-rd32 = rd32() { set -- $$(od -An -v -tu1 -j $$(($$2)) -N 4 $$1); \
	echo $$(($$1 | $$2 << 8 | $$3 << 16 | $$4 << 24)); }

# The separate ramdisk (target option "separate ramdisk", gzip only): it
# becomes the rootfs.gz of the container
fortigate-initrd = $(KERNEL_BUILD_DIR)/initrd$(if $(TARGET_PER_DEVICE_ROOTFS),.$(ROOTFS_ID/$(DEVICE_NAME))).cpio.gzip

# Device tree appended to the zImage. Without a separate ramdisk, the one
# of the device as is. With it (the rootfs.gz of the container, which the
# boot loader loads at FORTIGATE_INITRD_ADDR without telling the kernel:
# it passes no initrd tag), /chosen gets linux,initrd-start and
# linux,initrd-end, from the exact size of the ramdisk. The build then
# fails if the kernel or the zImage decompressor may reach that address:
# the decompressor writes the kernel at TEXT_OFFSET of the RAM (at 0
# here), up to its end with .bss, then may move itself right after it
# (its code, appended device tree grown by half, at least 32 KiB, stack
# and malloc area). The sizes come from the zImage header and its table
# (magic 0x016f2818 at 0x24, end at 0x2c, table at 0x38: "KLSZ", offset
# of the inflated size, .bss size, TEXT_OFFSET, malloc size); 64 KiB
# cover the relocation code, its .bss, stack and alignments.
define Build/fortigate-dtb
	$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE), \
		$(call Build/fortigate-dtb-initrd), \
		$(call Build/append-dtb))
endef

define Build/fortigate-dtb-initrd
	[ -n "$(CONFIG_TARGET_INITRAMFS_COMPRESSION_GZIP)" ] || { \
		echo "rootfs.gz: the separate ramdisk must be gzip compressed" >&2; \
		exit 1; }
	[ -n "$(FORTIGATE_INITRD_ADDR)" ] || { \
		echo "FORTIGATE_INITRD_ADDR: not set for $(DEVICE_NAME)" >&2; \
		exit 1; }
	[ -s $(fortigate-initrd) ] || { \
		echo "$(fortigate-initrd): missing or empty" >&2; exit 1; }
	addr=$$(($(FORTIGATE_INITRD_ADDR))); \
	size=$$(stat -c %s $(fortigate-initrd)); \
	{ $(LINUX_DIR)/scripts/dtc/dtc -q -I dtb -O dts \
		$(KDIR)/image-$(firstword $(DEVICE_DTS)).dtb; \
	  printf '/ { chosen { linux,initrd-start = <0x%x>; linux,initrd-end = <0x%x>; }; };\n' \
		$$addr $$((addr + size)); \
	} | $(LINUX_DIR)/scripts/dtc/dtc -q -I dts -O dtb -o $@.dtb -
	$(fortigate-rd32); \
	[ $$(rd32 $@ 0x24) = $$((0x016f2818)) ] || { \
		echo "$@: not a zImage" >&2; rm -f $@.dtb; exit 1; }; \
	zsize=$$(rd32 $@ 0x2c); tab=$$(rd32 $@ 0x38); \
	[ $$(rd32 $@ $$((tab + 4))) = $$((0x5a534c4b)) ] || { \
		echo "$@: no size table in the zImage" >&2; rm -f $@.dtb; exit 1; }; \
	inflated=$$(rd32 $@ $$(rd32 $@ $$((tab + 8)))); \
	bss=$$(rd32 $@ $$((tab + 12))); \
	tofs=$$(rd32 $@ $$((tab + 16))); \
	malloc=$$(rd32 $@ $$((tab + 20))); \
	dtb=$$(stat -c %s $@.dtb); \
	grow=$$(((dtb + dtb / 2 + 7) & ~7)); \
	[ $$grow -ge 32768 ] || grow=32768; \
	[ $$grow -le 1048576 ] || grow=1048576; \
	kend=$$((tofs + inflated + bss)); \
	top=$$((kend + zsize + grow + malloc + 65536)); \
	addr=$$(($(FORTIGATE_INITRD_ADDR))); \
	printf "fortigate: kernel end 0x%x, decompressor up to 0x%x, initrd 0x%x-0x%x\n" \
		$$kend $$top $$addr $$((addr + $$(stat -c %s $(fortigate-initrd)))); \
	[ $$top -le $$addr ] || { \
		echo "the kernel or its decompressor would overwrite the initrd at" \
			"$(FORTIGATE_INITRD_ADDR) (up to $$(printf 0x%x $$top))" >&2; \
		rm -f $@.dtb; exit 1; }
	cat $@.dtb >> $@
	rm -f $@.dtb
endef

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
# A copy is kept next to the images. With FORTIGATE_FLATKC_MAX, both the
# flatkc and its inflated payload must not exceed that many bytes: the
# build fails otherwise (the boot loader of some models crashes on a
# larger kernel, see the device definitions).
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
	max="$(FORTIGATE_FLATKC_MAX)"; [ -z "$$max" ] || { \
		k=$$(stat -c %s $@); f=$$(stat -c %s $@.new); \
		if [ $$k -gt $$max ] || [ $$f -gt $$max ]; then \
			echo "flatkc too large for the boot loader: $$f bytes" \
				"($$k inflated), at most $$max" >&2; \
			rm -f $@.new $@.gz; exit 1; \
		fi; \
	}
	mv $@.new $@
	rm -f $@.gz
	mkdir -p $(BIN_DIR)
	cp $@ $(BIN_DIR)/$(DEVICE_IMG_PREFIX)-initramfs-flatkc.bin
endef

# Firmware container for a TFTP boot to RAM (boot menu option [R]): a disk
# image whose MBR partition table has a single entry, an ext2 holding the
# "flatkc" file and a "rootfs.gz" (an empty gzip stream: loaded by the boot
# loader, then ignored by a kernel built with CONFIG_INITRAMFS_FORCE; with
# a separate ramdisk, the ramdisk itself, which the kernel finds through
# the device tree, see Build/fortigate-dtb). The
# boot loader wants both files and the partition table; it checks neither
# the rest of the MBR nor the file system geometry. With
# FORTIGATE_CONTAINER_DTB, the ext2 also holds the device tree as
# "devicetree.dtb", like the stock containers of the FortiSOC3 models
# (the kernel uses the copy appended to the zImage). The container is then
# compressed by gzip-filename with the model as name, which the boot loader
# checks too. The output only depends on SOURCE_DATE_EPOCH, which e2fsprogs
# also prefers to E2FSPROGS_FAKE_TIME: modes are set (not left to the umask
# of the build host), extended attributes of the host are not copied. The
# ext2 spans FORTIGATE_CONTAINER_SECTORS (default: the whole partition),
# while the partition entry always gives FORTIGATE_PART_SECTORS, the size
# of the firmware slot; the end of the slot then stays out of the
# container.
define Build/fortigate-container
	rm -rf $@.root $@.ext2
	mkdir -p $@.root
	cp $@ $@.root/flatkc
	$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE), \
		cp $(fortigate-initrd) $@.root/rootfs.gz, \
		$(STAGING_DIR_HOST)/bin/gzip -9 -n -c < /dev/null > $@.root/rootfs.gz)
	$(if $(FORTIGATE_CONTAINER_DTB), \
		cp $(KDIR)/image-$(firstword $(DEVICE_DTS)).dtb \
			$@.root/devicetree.dtb)
	chmod 0644 $@.root/*
	chmod 0755 $@.root
	E2FSPROGS_FAKE_TIME=$(FORTIGATE_EPOCH) \
	SOURCE_DATE_EPOCH=$(FORTIGATE_EPOCH) \
	$(STAGING_DIR_HOST)/bin/mke2fs -q -F -t ext2 -r 1 -b 1024 -I 128 \
		-i 4096 -m 5 \
		-O none,ext_attr,resize_inode,dir_index,filetype,sparse_super \
		-U clear \
		-E root_owner=0:0,hash_seed=66727469-7772-7400-0000-000000000309,no_copy_xattrs \
		-d $@.root $@.ext2 \
		$$(($(or $(FORTIGATE_CONTAINER_SECTORS),$(FORTIGATE_PART_SECTORS)) / 2)) || { \
		echo "the container files do not fit in" \
			"$(or $(FORTIGATE_CONTAINER_SECTORS),$(FORTIGATE_PART_SECTORS)) sectors:" \
			"$$(du -cb $@.root/* | tail -n 1 | cut -f 1) bytes" >&2; \
		rm -rf $@.root $@.ext2; exit 1; }
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
  KERNEL_INITRAMFS = kernel-bin | fortigate-dtb | fortigate-flatkc | \
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
  # Largest flatkc (and inflated payload) the boot loader is known to
  # take, in bytes; empty: no check
  FORTIGATE_FLATKC_MAX :=
  # Physical address where the boot loader loads the rootfs.gz of the
  # container, needed with a separate ramdisk only; empty: unknown
  FORTIGATE_INITRD_ADDR :=
  # No OpenWrt-style sysupgrade image is defined here: the container
  # built above is also the image the installer package writes to a
  # firmware slot.
  IMAGES :=
endef

include $(SUBTARGET).mk

$(eval $(call BuildImage))
