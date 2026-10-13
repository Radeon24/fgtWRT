# SPDX-License-Identifier: GPL-2.0-only

define Device/fortinet_fg-60d
  DEVICE_VENDOR := Fortinet
  DEVICE_MODEL := FortiGate 60D
  SOC := fsoc2
  FORTIGATE_MODEL := FGT60D
  # Geometry of the firmware slots of the boot stick (256 MiB partition):
  # the container is also the image of the installer
  FORTIGATE_PART_SECTORS := 524288
  DEVICE_DTS := fortinet-fg60d
  DEVICE_PACKAGES := firewall4 kmod-nft-offload kmod-bonding proto-bonding \
	ethtool ip-full kmod-fortinet-np4lite kmod-fortinet-cp7 \
	fortigate-dualslot luci
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
	fortigate-dualslot luci
  SUPPORTED_DEVICES := fortinet,fg90d
endef
TARGET_DEVICES += fortinet_fg-90d
