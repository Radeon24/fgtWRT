# SPDX-License-Identifier: GPL-2.0-only
#
# Built from the LuCI feed (./scripts/feeds install -a): luci.mk is taken
# from there.

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for the FortiGate specific settings (fgtWRT)
LUCI_DEPENDS:=+luci-base +fgtwrt-base
LUCI_PKGARCH:=all

PKG_LICENSE:=GPL-2.0-only

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
