# SPDX-License-Identifier: GPL-2.0-only

define Device/fortinet_fg-60e
  DEVICE_VENDOR := Fortinet
  DEVICE_MODEL := FortiGate 60E
  SOC := fsoc3
  FORTIGATE_MODEL := FGT60E
  # The stock containers of the 60E carry their device tree next to the
  # kernel; ours carries the one appended to the zImage.
  FORTIGATE_CONTAINER_DTB := 1
  # Geometry of the firmware slots of the eMMC (256 MiB partition): the
  # container is also the image of the installer
  FORTIGATE_PART_SECTORS := 524288
  # The container only fills the first 16 380 KiB of the slot (partition
  # 2, sectors 786440 to 819199 of the eMMC); the rest of the slot holds
  # the rootfs_data of the overlay (described by the device tree: sectors
  # 819208 to 1310727 of the eMMC, the last sector of the slot, aligned
  # on the 4 KiB pages of its page cache), formatted with mkfs.ext4 at
  # the first boot. Sectors 819200 to 819207 stay unused
  FORTIGATE_CONTAINER_SECTORS := 32760
  # The boot loader loads the rootfs.gz of the container at 416 MiB, as
  # the initrd of the stock firmware: with a separate ramdisk, the kernel
  # and its decompressor must stay below
  FORTIGATE_INITRD_ADDR := 0x1A000000
  # Kernel command line of the flatkc header: the one of the kernel
  # (CONFIG_CMDLINE, forced)
  FORTIGATE_CMDLINE := earlycon=em_uart,mmio32,0xfb000000 \
	console=ttyS0,9600n8 loglevel=6 panic=10 bonding.max_bonds=0 \
	fstools_overlay_fstype=ext4 fstools_overlay_nodiscard=1 \
	fstools_ignore_partname=1
  DEVICE_DTS := fortinet-fg60e
  DEVICE_PACKAGES := firewall4 kmod-nft-offload kmod-bonding proto-bonding \
	ethtool ip-full kmod-fortinet-np6lite fortigate-dualslot \
	kmod-ipsec kmod-ipsec4 kmod-ipsec6 kmod-crypto-seqiv \
	kmod-crypto-chacha20poly1305 kmod-crypto-sha256 \
	e2fsprogs luci kmod-wireguard wireguard-tools openvpn-openssl \
	kmod-ovpn-backports openssl-util conntrack ip-bridge \
	kmod-gpio-button-hotplug r8a779x-usb3-firmware
  SUPPORTED_DEVICES := fortinet,fg60e
endef
TARGET_DEVICES += fortinet_fg-60e
