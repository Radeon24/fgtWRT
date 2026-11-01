# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=fgtwrt-base
PKG_RELEASE:=6

PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/fgtwrt-base
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:=FortiGate board detection, capabilities and settings service
  DEPENDS:=@(TARGET_fortisoc||TARGET_x86) +jsonfilter
  PKGARCH:=all
endef

define Package/fgtwrt-base/description
 Finds which FortiGate model OpenWrt runs on, describes what that model
 can do (fan, USB ports, LEDs, button, watchdog, network processor) and
 applies the settings of /etc/config/fgtwrt at boot: fan profiles on the
 models with a controllable fan, mode of the USB management port (off,
 serial console or network interface "usb") on the models that have one.
 The "default" fan profile leaves the chip as the firmware set it; the
 other profiles are undone when the service stops. The USB modes need
 the usbgadget-acm or usbgadget-ncm package and a kernel with the gadget
 support of the board.
endef

define Package/fgtwrt-base/conffiles
/etc/config/fgtwrt
endef

define Build/Compile
endef

define Package/fgtwrt-base/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/etc/uci-defaults
	$(INSTALL_CONF) ./files/etc/config/fgtwrt $(1)/etc/config/
	$(INSTALL_BIN) ./files/etc/init.d/fgtwrt $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/etc/uci-defaults/90-fgtwrt $(1)/etc/uci-defaults/
	$(INSTALL_DIR) $(1)/lib/functions
	$(INSTALL_DATA) ./files/lib/functions/fgtwrt.sh $(1)/lib/functions/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/fgtwrt-fan $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/usr/libexec/fgtwrt-usb-console $(1)/usr/libexec/
	$(INSTALL_DIR) $(1)/usr/share/fgtwrt/models
	$(INSTALL_DATA) ./files/usr/share/fgtwrt/boards $(1)/usr/share/fgtwrt/
	$(INSTALL_DATA) ./files/usr/share/fgtwrt/models/*.json $(1)/usr/share/fgtwrt/models/
endef

$(eval $(call BuildPackage,fgtwrt-base))
