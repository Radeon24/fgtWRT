# SPDX-License-Identifier: GPL-2.0-only

define Device/fortinet_fg-60e
  DEVICE_VENDOR := Fortinet
  DEVICE_MODEL := FortiGate 60E
  SOC := fsoc3
  FORTIGATE_MODEL := FGT60E
  # The stock containers of the 60E carry their device tree next to the
  # kernel; ours carries the one appended to the zImage.
  FORTIGATE_CONTAINER_DTB := 1
  # Geometry of the stock containers of the 60E (256 MiB partition)
  FORTIGATE_PART_SECTORS := 524288
  DEVICE_DTS := fortinet-fg60e
  DEVICE_PACKAGES := firewall4 kmod-nft-offload kmod-bonding proto-bonding \
	ethtool ip-full kmod-fortinet-np6lite fortigate-dualslot
  SUPPORTED_DEVICES := fortinet,fg60e
endef
TARGET_DEVICES += fortinet_fg-60e
