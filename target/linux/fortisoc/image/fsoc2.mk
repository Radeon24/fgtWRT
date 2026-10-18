# SPDX-License-Identifier: GPL-2.0-only

define Device/fortinet_fg-60d
  DEVICE_VENDOR := Fortinet
  DEVICE_MODEL := FortiGate 60D
  SOC := fsoc2
  FORTIGATE_MODEL := FGT60D
  # Geometry of the firmware slots of the boot stick (256 MiB partition):
  # the container is also the image of the installer
  FORTIGATE_PART_SECTORS := 524288
  # The container only fills the first 16 380 KiB of the slot; the rest
  # of the slot holds the rootfs_data of the overlay (described by the
  # device tree: sectors 32768 to 524287 of the disk, aligned on the
  # 4 KiB pages of its page cache), formatted with mkfs.ext4 at the first
  # boot. The container (from sector 1) must end before it, page
  # included: 32760 sectors, 4095 pages of the slot
  FORTIGATE_CONTAINER_SECTORS := 32760
  # The boot loader inflates the flatkc into low memory, below its own
  # stack and data: a 9.0 MB flatkc makes it fault and reset in a loop,
  # flatkc files up to 7.5 MB boot. Keep a margin: 7 MiB at most
  FORTIGATE_FLATKC_MAX := 7340032
  # The boot loader loads the rootfs.gz of the container at 16 MiB: with
  # a separate ramdisk, the kernel and its decompressor must stay below
  FORTIGATE_INITRD_ADDR := 0x1000000
  # Kernel command line of the flatkc header: the one of the kernel
  # (CONFIG_CMDLINE, forced)
  FORTIGATE_CMDLINE := earlycon=uart8250,mmio32,0xe4100000 \
	console=ttyS0,9600n8 loglevel=6 panic=10 bonding.max_bonds=0 \
	fstools_overlay_fstype=ext4 fstools_overlay_nodiscard=1 \
	fstools_ignore_partname=1
  DEVICE_DTS := fortinet-fg60d
  DEVICE_PACKAGES := firewall4 kmod-nft-offload kmod-bonding proto-bonding \
	ethtool ip-full kmod-fortinet-np4lite kmod-fortinet-cp7 \
	kmod-ipsec kmod-ipsec4 kmod-ipsec6 kmod-crypto-seqiv \
	kmod-crypto-chacha20poly1305 kmod-fortinet-np4lite-ipsec fortigate-dualslot \
	e2fsprogs luci kmod-wireguard wireguard-tools openvpn-openssl \
	kmod-ovpn-backports openssl-util
  SUPPORTED_DEVICES := fortinet,fg60d
endef
TARGET_DEVICES += fortinet_fg-60d

define Device/fortinet_fg-90d
  DEVICE_VENDOR := Fortinet
  DEVICE_MODEL := FortiGate 90D
  SOC := fsoc2
  FORTIGATE_MODEL := FGT90D
  # Geometry of the firmware slots of the boot stick (256 MiB partition):
  # the container is also the image of the installer
  FORTIGATE_PART_SECTORS := 524288
  # As on the 60D, the container only fills the first 16 380 KiB of the
  # slot (partition 2, sectors 524289 to 557048 of the disk); the rest
  # of the slot holds the rootfs_data of the overlay (described by the
  # device tree: sectors 557056 to 1048575 of the disk, aligned on the
  # 4 KiB pages of its page cache), formatted with mkfs.ext4 at the first
  # boot
  FORTIGATE_CONTAINER_SECTORS := 32760
  # Same boot loader family as the 60D. The largest flatkc booted on the
  # 90D is 7.1 MB; its limit is not known: keep the one of the 60D
  FORTIGATE_FLATKC_MAX := 7340032
  # Same boot loader family as the 60D: rootfs.gz loaded at 16 MiB
  FORTIGATE_INITRD_ADDR := 0x1000000
  # Kernel command line of the flatkc header: the one of the kernel
  # (CONFIG_CMDLINE, forced)
  FORTIGATE_CMDLINE := earlycon=uart8250,mmio32,0xe4100000 \
	console=ttyS0,9600n8 loglevel=6 panic=10 bonding.max_bonds=0 \
	fstools_overlay_fstype=ext4 fstools_overlay_nodiscard=1 \
	fstools_ignore_partname=1
  DEVICE_DTS := fortinet-fg90d
  DEVICE_PACKAGES := firewall4 kmod-nft-offload kmod-bonding proto-bonding \
	ethtool ip-full kmod-fortinet-np4lite kmod-fortinet-cp7 \
	kmod-ipsec kmod-ipsec4 kmod-ipsec6 kmod-crypto-seqiv \
	kmod-crypto-chacha20poly1305 kmod-fortinet-np4lite-ipsec fortigate-dualslot \
	e2fsprogs luci kmod-wireguard wireguard-tools openvpn-openssl \
	kmod-ovpn-backports openssl-util
  SUPPORTED_DEVICES := fortinet,fg90d
endef
TARGET_DEVICES += fortinet_fg-90d
