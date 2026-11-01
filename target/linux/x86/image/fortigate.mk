# SPDX-License-Identifier: GPL-2.0-only
#
# Fortinet FortiGate appliances built around an x86 processor. The stock
# boot loader loads a firmware container (TFTP boot to RAM, boot menu
# option [R]), inflates the "flatkc" file of its first partition to
# 0x100000 and jumps there in 32-bit protected mode. No GRUB, no disk
# image. With the target option "separate ramdisk", the flatkc holds the
# kernel only and the initramfs is the "rootfs.gz" file of the container,
# which the boot loader loads at FORTIGATE_INITRD_ADDR and the entry stub
# hands to the kernel (RELAY_RD); otherwise the kernel embeds its
# initramfs and the rootfs.gz is an empty gzip stream.

DEVICE_VARS += FORTIGATE_MODEL FORTIGATE_CMDLINE FORTIGATE_PART_LBA
DEVICE_VARS += FORTIGATE_PART_SECTORS FORTIGATE_PAYLOAD_END_MAX
DEVICE_VARS += FORTIGATE_STUB_CMDLINE FORTIGATE_CONTAINER_SECTORS
DEVICE_VARS += FORTIGATE_STUB_DEFS FORTIGATE_INITRD_ADDR
DEVICE_VARS += FORTIGATE_INITRD_SIZE_MAX FORTIGATE_INITRD_END_MAX

FORTIGATE_EPOCH := $(if $(SOURCE_DATE_EPOCH),$(SOURCE_DATE_EPOCH),0)

# Shell code writing the 32-bit value $(1) in little endian
fortigate-le32 = v=$$(printf "%08x" $(1)); printf "\x$${v:6:2}\x$${v:4:2}\x$${v:2:2}\x$${v:0:2}"

# Shell function rd32 <file> <offset>: the 32-bit little endian value there
fortigate-x86-rd32 = rd32() { set -- $$(od -An -v -tu1 -j $$(($$2)) -N 4 $$1); \
	echo $$(($$1 | $$2 << 8 | $$3 << 16 | $$4 << 24)); }

# The separate ramdisk (target option "separate ramdisk", gzip only): it
# becomes the rootfs.gz of the container
fortigate-x86-initrd = $(KERNEL_BUILD_DIR)/initrd$(if $(TARGET_PER_DEVICE_ROOTFS),.$(ROOTFS_ID/$(DEVICE_NAME))).cpio.gzip

# With a separate ramdisk, checks the bzImage and the ramdisk against what
# the entry stub does with them (see fortigate-stub.S, RELAY_RD): the boot
# loader loads the rootfs.gz at FORTIGATE_INITRD_ADDR, where the
# decompressor of the kernel runs ([pref_address, pref_address +
# init_size) of the setup header); the stub then moves it to the first
# 2 MiB boundary above both. The build fails unless the stub relays the
# ramdisk, the kernel unpacks it (BLK_DEV_INITRD, RD_GZIP), the ramdisk
# is at most FORTIGATE_INITRD_SIZE_MAX bytes and ends, once moved, at or
# below FORTIGATE_INITRD_END_MAX and initrd_addr_max. Without a separate
# ramdisk, nothing to check.
define Build/fortigate-x86-initrd-check
	$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE), \
		$(call Build/fortigate-x86-initrd-check/separate))
endef

define Build/fortigate-x86-initrd-check/separate
	[ -n "$(CONFIG_TARGET_INITRAMFS_COMPRESSION_GZIP)" ] || { \
		echo "rootfs.gz: the separate ramdisk must be gzip compressed" >&2; \
		exit 1; }
	case " $(FORTIGATE_STUB_DEFS) " in *" -DRELAY_RD "*) ;; *) \
		echo "FORTIGATE_STUB_DEFS: no -DRELAY_RD, the kernel would not get" \
			"the ramdisk" >&2; exit 1;; esac
	for v in "$(FORTIGATE_INITRD_ADDR)" "$(FORTIGATE_INITRD_SIZE_MAX)" \
			"$(FORTIGATE_INITRD_END_MAX)"; do \
		[ -n "$$v" ] || { echo "FORTIGATE_INITRD_*: not set for" \
			"$(DEVICE_NAME)" >&2; exit 1; }; \
	done
	[ -s $(fortigate-x86-initrd) ] || { \
		echo "$(fortigate-x86-initrd): missing or empty" >&2; exit 1; }
	[ "$$(od -An -tx1 -N 2 $(fortigate-x86-initrd) | tr -d ' ')" = 1f8b ] || { \
		echo "$(fortigate-x86-initrd): not a gzip stream" >&2; exit 1; }
	for sym in CONFIG_BLK_DEV_INITRD CONFIG_RD_GZIP; do \
		grep -qx "$$sym=y" $(LINUX_DIR)/.config || { \
			echo "$$sym=y missing from the kernel" >&2; exit 1; }; \
	done
	[ "$$(dd if=$@ bs=1 skip=$$((0x202)) count=4 status=none)" = HdrS ] || { \
		echo "$@: not a bzImage" >&2; exit 1; }
	$(fortigate-x86-rd32); \
	[ $$(rd32 $@ 0x25c) = 0 ] || { \
		echo "$@: pref_address above 4 GiB" >&2; exit 1; }; \
	pref=$$(rd32 $@ 0x258); kze=$$((pref + $$(rd32 $@ 0x260))); \
	amax=$$(rd32 $@ 0x22c); \
	src=$$(($(FORTIGATE_INITRD_ADDR))); \
	size=$$(stat -c %s $(fortigate-x86-initrd)); \
	end=$$((src + size)); \
	if [ $$end -le $$pref ] || [ $$src -ge $$kze ]; then dst=$$src; \
	else top=$$kze; [ $$end -le $$top ] || top=$$end; \
		dst=$$(((top + 0x1fffff) & ~0x1fffff)); fi; \
	printf "fortigate: initrd 0x%x -> 0x%x (%d bytes), kernel area 0x%x-0x%x\n" \
		$$src $$dst $$size $$pref $$kze; \
	[ $$size -le $$(($(FORTIGATE_INITRD_SIZE_MAX))) ] || { \
		echo "rootfs.gz: $$size bytes, at most $(FORTIGATE_INITRD_SIZE_MAX)" >&2; \
		exit 1; }; \
	[ $$((dst + size)) -le $$(($(FORTIGATE_INITRD_END_MAX))) ] || { \
		printf "the relayed initrd would end at 0x%x, at most %s\n" \
			$$((dst + size)) "$(FORTIGATE_INITRD_END_MAX)" >&2; exit 1; }; \
	[ $$((dst + size - 1)) -le $$amax ] || { \
		printf "the relayed initrd would end above initrd_addr_max 0x%x\n" \
			$$amax >&2; exit 1; }
endef

# Payload of the flatkc: the entry stub (fortigate-stub.S, at 0x100000)
# followed at 0x4000 by the protected-mode part of the bzImage, whose
# decompressor then moves the kernel to LOAD_PHYSICAL_ADDR. The setup
# header of the bzImage goes into the zero page built by the stub; the
# real-mode setup code is not used. The boot loader inflates the payload
# to 0x100000 from a buffer at 0x1000000: with
# FORTIGATE_PAYLOAD_END_MAX, the build fails if the payload would end
# above that address (the largest end known to boot). With a separate
# ramdisk, it also fails if the payload would end above
# FORTIGATE_INITRD_ADDR, where the boot loader loads the rootfs.gz.
define Build/fortigate-x86-payload
	rm -f $@.hdr $@.pm $@.o $@.elf $@.new
	# fstools mounts the overlay in preinit, before kmodloader loads the
	# modules that are not boot modules: the file system named by
	# fstools_overlay_fstype= must be built into the kernel
	for fs in $$(printf '%s\n' $(strip $(FORTIGATE_CMDLINE) $(FORTIGATE_STUB_CMDLINE)) | \
			sed -n 's/^fstools_overlay_fstype=//p'); do \
		sym=CONFIG_$$(printf '%s' "$$fs" | tr a-z A-Z)_FS; \
		grep -qx "$$sym=y" $(LINUX_DIR)/.config || { \
			echo "$@: overlay on $$fs, but $$sym=y missing from the kernel" >&2; \
			exit 1; }; \
	done
	[ "$$(dd if=$@ bs=1 skip=$$((0x202)) count=4 status=none)" = HdrS ] || { \
		echo "$@: not a bzImage" >&2; exit 1; }; \
	setup=$$(od -An -tu1 -j $$((0x1f1)) -N 1 $@ | tr -d ' '); \
	[ $$setup -ne 0 ] || setup=4; \
	hlen=$$((0x202 + $$(od -An -tu1 -j $$((0x201)) -N 1 $@ | tr -d ' ') - 0x1f1)); \
	dd if=$@ of=$@.hdr bs=1 skip=$$((0x1f1)) count=$$hlen status=none && \
	dd if=$@ of=$@.pm bs=512 skip=$$((setup + 1)) status=none
	$(TARGET_CROSS)gcc -m32 -c -o $@.o $(FORTIGATE_STUB_DEFS) \
		-DHDR_BIN='"$@.hdr"' -DPM_BIN='"$@.pm"' \
		-DCMDLINE_STR='"$(strip $(FORTIGATE_CMDLINE) $(FORTIGATE_STUB_CMDLINE))"' \
		./fortigate-stub.S
	$(TARGET_CROSS)ld -m elf_i386 -Ttext=0x100000 -o $@.elf $@.o
	# .text only: the assembler may add a .note.gnu.property section
	$(TARGET_CROSS)objcopy -O binary -j .text $@.elf $@.new
	tail -c +$$((0x4000 + 1)) $@.new | cmp -s - $@.pm || { \
		echo "$@: protected-mode part not at 0x4000" >&2; exit 1; }
	end=$$((0x100000 + $$(stat -c %s $@.new))); \
	printf "fortigate: payload 0x100000-0x%x (%d bytes)\n" $$end $$((end - 0x100000)); \
	max="$(FORTIGATE_PAYLOAD_END_MAX)"; [ -z "$$max" ] || [ $$end -le $$((max)) ] || { \
		printf "payload too large for the boot loader: ends at 0x%x, at most %s\n" \
			$$end "$$max" >&2; exit 1; }; \
	rd="$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE),$(FORTIGATE_INITRD_ADDR))"; \
	[ -z "$$rd" ] || [ $$end -le $$((rd)) ] || { \
		printf "payload ends at 0x%x, above the rootfs.gz loaded at %s\n" \
			$$end "$$rd" >&2; exit 1; }
	mv $@.new $@
	rm -f $@.hdr $@.pm $@.o $@.elf
	mkdir -p $(BIN_DIR)
	cp $@ $(BIN_DIR)/$(DEVICE_IMG_PREFIX)-initramfs-payload.bin
endef

# flatkc: a 512-byte header followed by the gzip stream of the payload,
# named "fortikernel.out" like in the stock flatkc files (which also have
# XFL 4). Header, little endian, all zero but for:
#
#   0x000  55 aa aa 55   magic
#   0x004  0x5c + length of the command line (as in the stock files)
#   0x008  0x00000200    offset of the gzip stream
#   0x00c  0x55aae517    tag
#   0x030  0x00100000    load address
#   0x058  length        of the command line, terminator included
#   0x05c  command line  terminated by "\n\0" (not used: the stub passes
#                        its own, FORTIGATE_CMDLINE followed by
#                        FORTIGATE_STUB_CMDLINE, which stays out of the
#                        header)
define Build/fortigate-x86-flatkc
	rm -rf $@.tmp
	mkdir -p $@.tmp
	cp $@ $@.tmp/fortikernel.out
	touch -hcd "@$(FORTIGATE_EPOCH)" $@.tmp/fortikernel.out
	$(STAGING_DIR_HOST)/bin/gzip -9 -N -c $@.tmp/fortikernel.out > $@.gz
	printf '\004' | dd of=$@.gz bs=1 seek=8 conv=notrunc status=none
	( \
		cmdline="$(FORTIGATE_CMDLINE)"; \
		len=$$(($$(printf "%s" "$$cmdline" | wc -c) + 2)); \
		[ $$len -le 420 ] || { echo "command line too long" >&2; exit 1; }; \
		$(call fortigate-le32,0x55aaaa55); \
		$(call fortigate-le32,$$((0x5c + len))); \
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
	rm -rf $@.tmp $@.gz
	cp $@ $(BIN_DIR)/$(DEVICE_IMG_PREFIX)-initramfs-flatkc.bin
endef

# Firmware container for a TFTP boot to RAM: a disk image whose MBR
# partition table has a single entry (active, type 0x83), an ext2 holding
# the "flatkc" file, a "rootfs.gz" (the separate ramdisk, or an empty gzip
# stream without one) and two 256-byte "flatkc.chk" and "rootfs.gz.chk" files
# (zeros: the boot loader of [R] does not check them), like the
# containers known to boot on these models. The output only depends on
# SOURCE_DATE_EPOCH. The container is then compressed by gzip-filename
# with the model as name, which the boot loader checks. The ext2 spans
# FORTIGATE_CONTAINER_SECTORS (default: the whole partition), while the
# partition entry always gives FORTIGATE_PART_SECTORS, the size of the
# firmware slot: the end of the slot then stays out of the container
# (rootfs_data, once installed). The same file is the image of the
# installer (sysupgrade).
define Build/fortigate-x86-container
	rm -rf $@.root $@.ext2
	mkdir -p $@.root
	cp $@ $@.root/flatkc
	$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE), \
		cp $(fortigate-x86-initrd) $@.root/rootfs.gz, \
		$(STAGING_DIR_HOST)/bin/gzip -9 -n -c < /dev/null > $@.root/rootfs.gz)
	head -c 256 /dev/zero > $@.root/flatkc.chk
	head -c 256 /dev/zero > $@.root/rootfs.gz.chk
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
	for f in flatkc rootfs.gz flatkc.chk rootfs.gz.chk; do \
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

define Device/fortigate-x86
  DEVICE_VENDOR := Fortinet
  KERNEL := kernel-bin
  KERNEL_NAME := bzImage
  KERNEL_INITRAMFS = kernel-bin | fortigate-x86-initrd-check | \
	fortigate-x86-payload | \
	fortigate-x86-flatkc | fortigate-x86-container | \
	gzip-filename $$(FORTIGATE_MODEL)
  # Appended by the kernel to its built-in command line (console), also
  # written in the flatkc header
  FORTIGATE_CMDLINE :=
  # Appended after FORTIGATE_CMDLINE by the stub only, not written in
  # the flatkc header: the description of the boot disk (no device tree)
  FORTIGATE_STUB_CMDLINE :=
  # Name of the gzip member of the TFTP image, checked by the boot loader
  FORTIGATE_MODEL :=
  # Size of the ext2 of the container, in sectors; empty: the partition
  FORTIGATE_CONTAINER_SECTORS :=
  # Partition 0 of the container, in 512-byte sectors
  FORTIGATE_PART_LBA := 1
  FORTIGATE_PART_SECTORS := 524288
  # Highest end address of the inflated payload known to boot; empty: no
  # check
  FORTIGATE_PAYLOAD_END_MAX :=
  # Options of the entry stub: with a separate ramdisk, relay it to the
  # kernel, and stop rather than boot a kernel without it
  FORTIGATE_STUB_DEFS := $(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE),-DRELAY_RD -DRELAY_STRICT)
  # Separate ramdisk only: physical address where the boot loader loads
  # the rootfs.gz of the container, largest rootfs.gz known to be relayed
  # and unpacked, highest end of the relayed ramdisk
  FORTIGATE_INITRD_ADDR :=
  FORTIGATE_INITRD_SIZE_MAX :=
  FORTIGATE_INITRD_END_MAX :=
  # No disk image: the TFTP image (KERNEL_INITRAMFS) is booted from RAM
  # and is also the image of the installer
  IMAGES :=
  ARTIFACTS :=
  KERNEL_INSTALL :=
endef

define Device/fortinet_fg-100d
  $(Device/fortigate-x86)
  DEVICE_MODEL := FortiGate 100D
  FORTIGATE_MODEL := FG100D
  FORTIGATE_CMDLINE := fgt.board=fg100d
  # Firmware slots of the SATA disk (31277232 sectors, behind port ata1
  # of the AHCI controller 00:1f.2): the stock firmware in partition 1,
  # OpenWrt in partition 2 (sectors 524289-1048576). The container fills
  # the first 32 MiB of the slot, but for its last 4 KiB page; the rest
  # of the slot holds rootfs_data, from sector 589824 (aligned on the
  # 4 KiB pages of the page cache of the disk), formatted with
  # mkfs.ext4 at the first boot. No device tree on this board: the
  # kernel command line describes the disk, the write windows of the
  # installer (sector 0, partition 2; bytes of the header of image 1 and
  # the boot flags) and rootfs_data, as the device tree does on the
  # other boards.
  FORTIGATE_CONTAINER_SECTORS := 65528
  FORTIGATE_STUB_CMDLINE := fstools_overlay_fstype=ext4 \
	fstools_overlay_nodiscard=1 fstools_ignore_partname=1 \
	fortinet.rootfs_data=ATA,SATA_SSD,31277232,589824+458752 \
	block.write_windows_disk=ata,0000:00:1f.2,ata1,ATA,SATA_SSD,31277232 \
	block.write_windows_ranges=0+1,524289+524288 \
	block.write_windows_sector0=0x30+32,0x12c+4,0x1be+1,0x1ce+1 \
	block.write_windows_persistent=589824+458752
  # Largest payload proved to boot ends at 0xcec400; the limit of the boot
  # loader above it is not known
  FORTIGATE_PAYLOAD_END_MAX := 0xcec400
  # The boot loader loads the rootfs.gz raw at 16 MiB (seen in a TFTP
  # boot to RAM; the boot from the disk is not checked yet), above the
  # end of the payload. A rootfs.gz of 25404233 bytes was relayed and
  # unpacked; 256 MiB keeps the ramdisk well below the buffers of the
  # boot loader.
  FORTIGATE_INITRD_ADDR := 0x1000000
  FORTIGATE_INITRD_SIZE_MAX := 25404233
  FORTIGATE_INITRD_END_MAX := 0x10000000
  # USB management port: NetChip NET2282 (17cc:2282), device side only;
  # installer of the second firmware slot, e2fsprogs for rootfs_data;
  # VFAT for a FAT32 stick in the USB host ports (the USB host and
  # storage drivers are built in); DSA driver of the BCM53314 switch,
  # set up at boot, and the bridge tool for its VLAN-aware bridges; tools
  # and tc modules of what the switch offloads (ets, tbf, flower, matchall,
  # police, pedit, mirred, skbedit, DCB, ntuple), bonding (hardware LAG),
  # lldpd and hostapd (full variant: EAP and RADIUS, driver=wired, for
  # 802.1X on the front ports), installed but not started at boot
  DEVICE_PACKAGES := blockdev kmod-hwmon-w83627ehf kmod-i2c-i801 \
	kmod-leds-fg100d kmod-usb-net2280 usbgadget-acm usbgadget-ncm \
	fortigate-dualslot e2fsprogs fgtwrt-base luci luci-app-fgtwrt \
	kmod-fs-vfat kmod-bcm5331x-dsa ip-bridge ip-full tc-full ethtool-full \
	dcb kmod-sched-core kmod-sched-ets kmod-sched-flower \
	kmod-sched-act-police kmod-sched-act-pedit kmod-bonding lldpd \
	hostapd-mbedtls
  SUPPORTED_DEVICES := fortinet,fg100d
endef
TARGET_DEVICES += fortinet_fg-100d
