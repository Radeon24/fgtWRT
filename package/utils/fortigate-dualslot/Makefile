# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=fortigate-dualslot
PKG_RELEASE:=6

PKG_LICENSE:=GPL-2.0-only
PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk

# fortisoc: the 60D and the 90D (fsoc2, internal USB stick) and the 60E
# (fsoc3, eMMC). x86/fortigate: the 100D (internal SATA disk); never the
# other x86 subtargets, whose generic upgrade writes the whole disk.
# blockdev (util-linux, not in the default busybox) keeps the internal
# USB stick of the fsoc2 boards and the SATA disk of the 100D read-only
# outside an installation, and the partitions of the eMMC of the fsoc3
# boards the installer never writes.
define Package/fortigate-dualslot
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:=Installer for the second firmware slot of a dual-slot FortiGate
  DEPENDS:=@(TARGET_fortisoc||TARGET_x86_fortigate) \
	+TARGET_fortisoc_fsoc2:blockdev +TARGET_fortisoc_fsoc3:blockdev \
	+TARGET_x86_fortigate:blockdev
endef

define Package/fortigate-dualslot/description
 Installs OpenWrt into a firmware slot of the boot disk, through the
 write windows the kernel declares (an internal USB stick, the eMMC or
 an internal SATA disk, both slots guarded by the kernel): the slot
 that is not the default one, or, on boards that ask for it, a slot
 made the default one (the boot flags of the MBR switched, [B] in the
 boot menu brings the stock firmware back) whose rest holds
 rootfs_data, the persistent overlay described by the device tree, or
 by the kernel command line on a board without one. Ships fgt-sector0
 (real direct I/O on the boot sector) and the fgt_* helpers of
 /lib/upgrade/fortigate.sh, used by the platform.sh of the target.
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -Wall -Wextra \
		-o $(PKG_BUILD_DIR)/fgt-sector0 \
		$(PKG_BUILD_DIR)/fgt-sector0.c $(TARGET_LDFLAGS)
endef

define Package/fortigate-dualslot/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/lib/upgrade
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/fgt-sector0 $(1)/usr/sbin/
	$(INSTALL_DATA) ./files/lib/upgrade/fortigate.sh $(1)/lib/upgrade/
endef

$(eval $(call BuildPackage,fortigate-dualslot))
