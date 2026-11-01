# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=leds-fg100d
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define KernelPackage/leds-fg100d
  SUBMENU:=LED modules
  TITLE:=Fortinet FortiGate 100D front LEDs
  FILES:=$(PKG_BUILD_DIR)/leds-fg100d.ko
  DEPENDS:=@TARGET_x86_fortigate
  # No modalias: the module creates its own platform device from the PCI
  # fingerprint of the board, so only /etc/modules.d can load it.
  AUTOLOAD:=$(call AutoProbe,leds-fg100d)
endef

define KernelPackage/leds-fg100d/description
  STATUS, HA and ALARM LEDs of the Fortinet FortiGate 100D, behind an
  addressable latch driven through GPIO lines of the ICH8M. Loaded at
  boot: nothing is written to the latch when the module is loaded; each
  change of a LED (LED service, triggers) writes its channel (parameters:
  channels, dry_run).
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef

$(eval $(call KernelPackage,leds-fg100d))
