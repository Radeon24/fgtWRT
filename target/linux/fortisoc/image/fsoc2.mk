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
  # Kernel command line of the flatkc header: the one of the kernel
  # (CONFIG_CMDLINE, forced)
  FORTIGATE_CMDLINE := earlycon=uart8250,mmio32,0xe4100000 \
	console=ttyS0,9600n8 loglevel=6 panic=10 bonding.max_bonds=0 \
	fstools_overlay_fstype=ext4 fstools_overlay_nodiscard=1 \
	fstools_ignore_partname=1
  DEVICE_DTS := fortinet-fg60d
  DEVICE_PACKAGES := firewall4 kmod-nft-offload kmod-bonding proto-bonding \
	ethtool ip-full kmod-fortinet-np4lite kmod-fortinet-cp7 \
	kmod-ipsec kmod-ipsec4 kmod-fortinet-np4lite-ipsec fortigate-dualslot e2fsprogs
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
  DEVICE_DTS := fortinet-fg90d
  DEVICE_PACKAGES := firewall4 kmod-nft-offload kmod-bonding proto-bonding \
	ethtool ip-full kmod-fortinet-np4lite kmod-fortinet-cp7 \
	kmod-ipsec kmod-ipsec4 kmod-fortinet-np4lite-ipsec fortigate-dualslot
  SUPPORTED_DEVICES := fortinet,fg90d
endef
TARGET_DEVICES += fortinet_fg-90d
