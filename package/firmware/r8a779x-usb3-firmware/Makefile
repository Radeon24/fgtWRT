# SPDX-License-Identifier: GPL-2.0-only
#
# Renesas R-Car xHCI firmware, "v2" file as first published in linux-firmware
# (commit 98d922b9, 2015-10-05): the one the xHCI of the FortiGate 60E runs
# with (its device tree names it). The later "v2" of linux-firmware is a
# different binary. Installed unmodified, under a name of its own.

include $(TOPDIR)/rules.mk

PKG_NAME:=r8a779x-usb3-firmware
PKG_VERSION:=2015.10.05
PKG_RELEASE:=1

PKG_LICENSE:=LicenseRef-LICENCE.r8a779x_usb3
PKG_LICENSE_FILES:=LICENCE.r8a779x_usb3

include $(INCLUDE_DIR)/package.mk

LINUX_FIRMWARE_COMMIT:=98d922b9bc891f33efd04b9cf8efde22d7949213
LINUX_FIRMWARE_URL:=https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain

define Download/r8a779x-usb3-v2
  URL:=$(LINUX_FIRMWARE_URL)
  URL_FILE:=r8a779x_usb3_v2.dlmem?id=$(LINUX_FIRMWARE_COMMIT)
  FILE:=r8a779x_usb3_v2-98d922b9.dlmem
  HASH:=84078c431a33ed4d846e136f8f73c6eec7669df278b3ed49e2072ee207b5b36f
endef
$(eval $(call Download,r8a779x-usb3-v2))

define Download/r8a779x-usb3-licence
  URL:=$(LINUX_FIRMWARE_URL)
  URL_FILE:=LICENCE.r8a779x_usb3?id=$(LINUX_FIRMWARE_COMMIT)
  FILE:=LICENCE.r8a779x_usb3-98d922b9
  HASH:=794f8cda805228ea982b00c3b3041dcd955661c9dee0004538c8c01aceb33945
endef
$(eval $(call Download,r8a779x-usb3-licence))

define Package/r8a779x-usb3-firmware
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=Renesas R-Car xHCI firmware (v2 of 2015, FortiGate 60E)
  URL:=https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git
endef

define Package/r8a779x-usb3-firmware/description
 Firmware of the R-Car xHCI, "v2" file of linux-firmware commit 98d922b9,
 used by the xHCI of the FortiGate 60E.
endef

define Build/Prepare
	cp $(DL_DIR)/r8a779x_usb3_v2-98d922b9.dlmem $(PKG_BUILD_DIR)/
	cp $(DL_DIR)/LICENCE.r8a779x_usb3-98d922b9 $(PKG_BUILD_DIR)/LICENCE.r8a779x_usb3
endef

define Build/Compile
endef

define Package/r8a779x-usb3-firmware/install
	$(INSTALL_DIR) $(1)/lib/firmware
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/r8a779x_usb3_v2-98d922b9.dlmem $(1)/lib/firmware/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENCE.r8a779x_usb3 $(1)/lib/firmware/
endef

$(eval $(call BuildPackage,r8a779x-usb3-firmware))
