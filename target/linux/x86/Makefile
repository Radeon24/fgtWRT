# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2006-2011 OpenWrt.org

include $(TOPDIR)/rules.mk

ARCH:=i386
BOARD:=x86
BOARDNAME:=x86
FEATURES:=squashfs ext4 legacy-sdcard vdi vmdk vhdx pcmcia targz fpu boot-part rootfs-part
SUBTARGETS:=generic legacy geode 64 fortigate

KERNEL_PATCHVER:=6.18

KERNELNAME:=bzImage

include $(INCLUDE_DIR)/target.mk

ifeq ($(SUBTARGET),fortigate)
# No GRUB, no display, no flash: the stock boot loader runs the kernel
# from RAM, the internal disk belongs to the stock firmware.
DEFAULT_PACKAGES := $(filter-out mtd,$(DEFAULT_PACKAGES))

# Kernel files and patches of this subtarget only (the write windows of
# the boot disk), copied and applied after those of the target: kept out
# of the kernels of the other subtargets.
SUBTARGET_FILES_DIR:=$(CURDIR)/$(SUBTARGET)/files-$(KERNEL_PATCHVER)
SUBTARGET_PATCH_DIR:=$(CURDIR)/$(SUBTARGET)/patches-$(KERNEL_PATCHVER)
FILES_DIR += "$(SUBTARGET_FILES_DIR)"
KERNEL_FILE_DEPENDS += $(SUBTARGET_FILES_DIR) $(SUBTARGET_PATCH_DIR)
define Kernel/Patch
	$(Kernel/Patch/Default)
	$(call PatchDir,$(LINUX_DIR),$(SUBTARGET_PATCH_DIR),platform-$(SUBTARGET)/)
endef
else
DEFAULT_PACKAGES += \
	mkf2fs \
	e2fsprogs kmod-button-hotplug \
	grub2-bios-setup
DEFAULT_PACKAGES += video-support
endif

$(eval $(call BuildTarget))

$(eval $(call $(if $(CONFIG_ISO_IMAGES),SetupHostCommand,Ignore),mkisofs, \
	Please install mkisofs. , \
	mkisofs -v 2>&1 , \
	genisoimage -v 2>&1 | grep genisoimage, \
	xorrisofs -v 2>&1 | grep xorriso \
))
