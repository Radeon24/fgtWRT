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
PKG_RELEASE:=2
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
 behind the network processor's links. On the FortiSOC2, the IPsec ESP
 offload is built into the module only with kmod-fortinet-np4lite-ipsec.
 Once loaded, the module cannot be unloaded.
endef

# The IPsec engine glue (np4lite-ipsec.o) is linked into fortinet-np4lite.ko
# when the kernel has XFRM_OFFLOAD and INET_ESP_OFFLOAD (src/Kbuild).
# XFRM_OFFLOAD is only selected by INET_ESP_OFFLOAD, which kmod-ipsec4 sets
# to n. A "y" is the one value that package-metadata.pl keeps whatever the
# order of the packages, so this package asks for "y"; with INET_ESP built
# as a module, Kconfig turns it into "m": esp4_offload.ko, which the kernel
# needs for any ESP state offloaded to a device ("Type doesn't support
# offload" without it), is then shipped here.
define KernelPackage/fortinet-np4lite-ipsec
  SUBMENU:=Network Devices
  TITLE:=Fortinet NP4Lite IPsec ESP offload
  DEPENDS:=@TARGET_fortisoc_fsoc2 +kmod-fortinet-np4lite +kmod-ipsec4
  KCONFIG:= \
	CONFIG_INET_ESP_OFFLOAD=y \
	CONFIG_XFRM_OFFLOAD=y \
	CONFIG_NF_FLOW_TABLE_XFRM_OFFLOAD=y
  FILES:=$(LINUX_DIR)/net/ipv4/esp4_offload.ko
  AUTOLOAD:=$(call AutoLoad,33,esp4_offload)
endef

define KernelPackage/fortinet-np4lite-ipsec/description
 IPsec ESP offload of the NP4Lite network processor (FortiSOC2): IPv4 ESP
 states added with "offload packet" on a port of the network processor are
 handled by its IPsec engine, and flow table flows sent through such a
 state stay offloaded. Selecting this package builds the offload into
 kmod-fortinet-np4lite and turns on the kernel options it needs
 (INET_ESP_OFFLOAD, XFRM_OFFLOAD, NF_FLOW_TABLE_XFRM_OFFLOAD).
endef

# On the FortiSOC2, two fw4 chain includes clamp the TCP MSS of the flows
# carried by an IPsec SA (see the files). Their "meta secpath" and "rt ipsec"
# expressions only exist in a kernel built with CONFIG_XFRM, and fw4 loads
# its ruleset in one transaction: a single rule the kernel rejects ("Not
# supported") leaves the device with no firewall table at all, flow offload
# included. Install them only when the kernel this module is built against
# has XFRM, i.e. when an IPsec package (kmod-ipsec) is part of the build.
NP4LITE_NFT:=/usr/share/nftables.d/chain-pre

define KernelPackage/fortinet-np4lite/install
	if [ "$(SUBTARGET)" = fsoc2 ] && \
	   grep -qx 'CONFIG_XFRM=y' $(LINUX_DIR)/.config; then \
		$(INSTALL_DIR) $(1)$(NP4LITE_NFT)/mangle_prerouting \
			$(1)$(NP4LITE_NFT)/mangle_forward && \
		$(INSTALL_DATA) \
			./files/nftables.d/chain-pre/mangle_prerouting/10-ipsec-mss.nft \
			$(1)$(NP4LITE_NFT)/mangle_prerouting/ && \
		$(INSTALL_DATA) \
			./files/nftables.d/chain-pre/mangle_forward/10-ipsec-mss.nft \
			$(1)$(NP4LITE_NFT)/mangle_forward/; \
	fi
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
$(eval $(call KernelPackage,fortinet-np4lite-ipsec))
$(eval $(call KernelPackage,fortinet-np6lite))
$(eval $(call KernelPackage,fortinet-cp7))
