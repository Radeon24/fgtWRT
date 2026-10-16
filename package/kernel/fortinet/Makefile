#
# SPDX-License-Identifier: GPL-2.0-only
#
# Out-of-tree kernel modules for the Fortinet IP blocks: the NP4Lite and
# NP6Lite network processors and the CP7 crypto engine.
#
# src/ is generated from the kernel sources of the sub-targets; only this
# Makefile is maintained by hand.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=fortinet
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

# The network processors have no known reset: a driver takes the block over
# from the boot loader once and keeps it for good (no remove, no module_exit).
# They are loaded in the boot module set, before the network setup of preinit,
# so that their interfaces exist when the interfaces are named. The crypto
# engine comes after the network processor whose interrupt it needs.

define KernelPackage/fortinet-np4lite
  SUBMENU:=Network Devices
  TITLE:=Fortinet NP4Lite network processor
  DEPENDS:=@(TARGET_fortisoc_fsoc1||TARGET_fortisoc_fsoc2) \
	+kmod-nf-flow \
	+TARGET_fortisoc_fsoc2:kmod-crypto-md5 \
	+TARGET_fortisoc_fsoc2:kmod-crypto-sha1
  FILES:=$(PKG_BUILD_DIR)/fortinet-np4lite.ko
  AUTOLOAD:=$(call AutoLoad,20,fortinet-np4lite,1)
  KCONFIG:=
endef

define KernelPackage/fortinet-np4lite/description
 Ethernet driver for the NP4Lite network processor: one network interface
 per port, routed IPv4 flows offloaded through a netfilter flow table with
 the "offload" flag and, where the SoC has them, the ports of the switch
 behind the network processor's links. IPsec ESP offload is not part of
 this package.
 Once loaded, the module cannot be unloaded.
endef

define KernelPackage/fortinet-np6lite
  SUBMENU:=Network Devices
  TITLE:=Fortinet NP6Lite network processor
  DEPENDS:=@TARGET_fortisoc_fsoc3
  FILES:=$(PKG_BUILD_DIR)/fortinet-np6lite.ko
  AUTOLOAD:=$(call AutoLoad,20,fortinet-np6lite,1)
  KCONFIG:=
endef

define KernelPackage/fortinet-np6lite/description
 Host interface of the NP6Lite network processor: MDIO master, one network
 interface per directly attached port, and the offload of flow table flows
 to the session engine. Once loaded, the module cannot be unloaded.
endef

define KernelPackage/fortinet-cp7
  SUBMENU:=Cryptographic API modules
  TITLE:=Fortinet CP7 crypto engine
  DEPENDS:=@(TARGET_fortisoc_fsoc1||TARGET_fortisoc_fsoc2) \
	+TARGET_fortisoc_fsoc2:kmod-fortinet-np4lite \
	+kmod-crypto-authenc \
	+kmod-crypto-cbc \
	+kmod-crypto-des \
	+kmod-crypto-hmac \
	+kmod-crypto-md5 \
	+kmod-crypto-sha1 \
	+kmod-crypto-sha256 \
	+kmod-crypto-sha512
  FILES:=$(PKG_BUILD_DIR)/fortinet-cp7.ko
  AUTOLOAD:=$(call AutoLoad,21,fortinet-cp7,1)
  KCONFIG:=
endef

define KernelPackage/fortinet-cp7/description
 Crypto engine of the CP7 block: cbc(aes), cbc(des3_ede) and cbc(des), and
 the authenc() AEAD combinations used by IPsec ESP. Requests the engine
 cannot do go to the software implementations.
endef

FORTINET_MODS:= \
	$(if $(CONFIG_PACKAGE_kmod-fortinet-np4lite),FORTINET_NP4LITE=m) \
	$(if $(CONFIG_PACKAGE_kmod-fortinet-np6lite),FORTINET_NP6LITE=m) \
	$(if $(CONFIG_PACKAGE_kmod-fortinet-cp7),FORTINET_CP7=m)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" \
		FORTINET_SOC="$(SUBTARGET)" \
		$(FORTINET_MODS) \
		modules
endef

$(eval $(call KernelPackage,fortinet-np4lite))
$(eval $(call KernelPackage,fortinet-np6lite))
$(eval $(call KernelPackage,fortinet-cp7))
