#
# SPDX-License-Identifier: GPL-2.0-only
#
# Crypto blocks of the Fortinet FortiSOC3 (FortiGate 100E): the true random
# number generator, the public key engine (RSA) and the symmetric crypto
# engine (AES/DES/3DES-CBC, HMAC, AES-GCM), as out-of-tree kernel modules.
#
# Standalone package: it does not touch package/kernel/fortinet. The
# drivers only bind to the device tree nodes of
# target/linux/fortisoc/dts/fsoc3-crypto.dtsi, which only the 100E device
# tree includes (see the README of this overlay).
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=fortinet-fsoc3
PKG_RELEASE:=2
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

# Loaded in the boot module set, for entropy early in preinit; kmodloader
# loads rng-core (kmod-random-core) first, as a dependency.
define KernelPackage/fortinet-fsoc3-trng
  SUBMENU:=Other modules
  TITLE:=Fortinet FortiSOC3 TRNG
  DEPENDS:=@TARGET_fortisoc_fsoc3 +kmod-random-core
  FILES:=$(PKG_BUILD_DIR)/fsoc3-trng.ko
  AUTOLOAD:=$(call AutoLoad,22,fsoc3-trng,1)
  KCONFIG:=
endef

define KernelPackage/fortinet-fsoc3-trng/description
 hwrng driver for the true random number generator of the miscellaneous
 block of the NP6Lite (FortiSOC3): /dev/hwrng, and entropy for the kernel
 pool (credited at 1 bit per 8). At probe the generator is set up to fill
 its host FIFO (the configuration of the vendor firmware).
endef

# RSA on the public key engine, for the crypto API (rsa-fsoc3, priority
# 300 over rsa-generic, which stays the fallback). kmod-crypto-rsa turns
# on the kernel RSA/MPI code: the kernel is rebuilt when it is selected.
define KernelPackage/fortinet-fsoc3-pkce
  SUBMENU:=Other modules
  TITLE:=Fortinet FortiSOC3 public key engine (RSA)
  DEPENDS:=@TARGET_fortisoc_fsoc3 +kmod-crypto-rsa
  FILES:=$(PKG_BUILD_DIR)/fsoc3-pkce.ko
  AUTOLOAD:=$(call AutoLoad,30,fsoc3-pkce)
  KCONFIG:=
endef

define KernelPackage/fortinet-fsoc3-pkce/description
 Crypto API driver of the public key engine (PKCE) of the FortiSOC3: raw
 RSA ("rsa", driver rsa-fsoc3) up to 4064-bit moduli, decryption by the
 CRT; larger keys go to rsa-generic. A known-answer test runs at probe.
endef

# Test tool, not needed in a release image: differential test of
# rsa-fsoc3 against rsa-generic, run by loading it (results in dmesg).
define KernelPackage/fortinet-fsoc3-pkce-test
  SUBMENU:=Other modules
  TITLE:=Fortinet FortiSOC3 RSA driver test
  DEPENDS:=@TARGET_fortisoc_fsoc3 +kmod-fortinet-fsoc3-pkce
  FILES:=$(PKG_BUILD_DIR)/fsoc3-pkce-test.ko
  KCONFIG:=
endef

define KernelPackage/fortinet-fsoc3-pkce-test/description
 Test module: compares rsa-fsoc3 with rsa-generic on the keys given as
 module parameters. Not loaded at boot.
endef

define KernelPackage/fortinet-fsoc3-cp
  SUBMENU:=Cryptographic API modules
  TITLE:=Fortinet FortiSOC3 symmetric crypto engine
  DEPENDS:=@TARGET_fortisoc_fsoc3 \
	+kmod-crypto-authenc \
	+kmod-crypto-cbc \
	+kmod-crypto-des \
	+kmod-crypto-gcm \
	+kmod-crypto-hmac \
	+kmod-crypto-md5 \
	+kmod-crypto-sha1 \
	+kmod-crypto-sha256 \
	+kmod-crypto-sha512
  FILES:=$(PKG_BUILD_DIR)/fsoc3-cp.ko
  AUTOLOAD:=$(call AutoLoad,30,fsoc3-cp)
  KCONFIG:=
endef

define KernelPackage/fortinet-fsoc3-cp/description
 Crypto API driver of the symmetric crypto engine of the FortiSOC3:
 cbc(aes), cbc(des), cbc(des3_ede), authenc(hmac(md5|sha1|sha256|sha384|
 sha512),cbc(aes|des3_ede)), rfc4106(gcm(aes)) (IPsec) and gcm(aes) (e.g.
 the OpenVPN data channel offload). Requests the engine cannot do go to
 the software implementations.
endef

# Test tool, not needed in a release image: differential test of fsoc3-cp
# against the software implementations, run by loading it.
define KernelPackage/fortinet-fsoc3-cp-test
  SUBMENU:=Cryptographic API modules
  TITLE:=Fortinet FortiSOC3 crypto engine test
  DEPENDS:=@TARGET_fortisoc_fsoc3 +kmod-fortinet-fsoc3-cp
  FILES:=$(PKG_BUILD_DIR)/fsoc3-cp-test.ko
  KCONFIG:=
endef

define KernelPackage/fortinet-fsoc3-cp-test/description
 Test module: compares every fsoc3-cp algorithm with the software (and
 tampered messages), or with speed=1 prints a time table. Not loaded at
 boot.
endef

FSOC3_MODS:= \
	$(if $(CONFIG_PACKAGE_kmod-fortinet-fsoc3-trng),FORTINET_FSOC3_TRNG=m) \
	$(if $(CONFIG_PACKAGE_kmod-fortinet-fsoc3-pkce),FORTINET_FSOC3_PKCE=m) \
	$(if $(CONFIG_PACKAGE_kmod-fortinet-fsoc3-pkce-test),FORTINET_FSOC3_PKCE_TEST=m) \
	$(if $(CONFIG_PACKAGE_kmod-fortinet-fsoc3-cp),FORTINET_FSOC3_CP=m) \
	$(if $(CONFIG_PACKAGE_kmod-fortinet-fsoc3-cp-test),FORTINET_FSOC3_CP_TEST=m)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" \
		$(FSOC3_MODS) \
		modules
endef

$(eval $(call KernelPackage,fortinet-fsoc3-trng))
$(eval $(call KernelPackage,fortinet-fsoc3-pkce))
$(eval $(call KernelPackage,fortinet-fsoc3-pkce-test))
$(eval $(call KernelPackage,fortinet-fsoc3-cp))
$(eval $(call KernelPackage,fortinet-fsoc3-cp-test))
