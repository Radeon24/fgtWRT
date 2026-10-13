# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

ARCH:=arm
BOARD:=fortisoc
BOARDNAME:=Fortinet FortiSOC
FEATURES:=dt ramdisk
# fsoc1 is laid out but not enabled yet.
SUBTARGETS:=fsoc2 fsoc3

KERNEL_PATCHVER:=6.18

define Target/Description
	Build images for Fortinet FortiGate appliances built around
	the Fortinet FortiSOC (FortiSOC1: Faraday FA626TE, FortiSOC2:
	Faraday FA726TE, FortiSOC3: ARM Cortex-A9). The images boot from
	RAM through the stock boot loader; sysupgrade can then install
	one into a firmware slot of the internal storage, behind the
	write guards of the running kernel.
endef

KERNELNAME:=zImage

# Router packages (firewall, dnsmasq, odhcpd, PPPoE), as on other targets.
DEVICE_TYPE:=router

include $(INCLUDE_DIR)/target.mk

# No flash to manage at build time: the internal storage holds firmware
# slots behind write guards, not an OpenWrt flash layout.
DEFAULT_PACKAGES := $(filter-out mtd,$(DEFAULT_PACKAGES))

$(eval $(call BuildTarget))
