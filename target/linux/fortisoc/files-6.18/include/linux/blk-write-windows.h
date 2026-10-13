/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Write windows for the installer of a dual-slot USB boot disk, described
 * by the device tree, see block/blk-write-windows.c.
 */
#ifndef _LINUX_BLK_WRITE_WINDOWS_H
#define _LINUX_BLK_WRITE_WINDOWS_H

#include <linux/blkdev.h>

#ifdef CONFIG_BLK_WRITE_WINDOWS
bool blk_wrwin_match(const char *vendor, size_t vendor_len,
		     const char *model, size_t model_len);
void blk_wrwin_register(struct gendisk *disk);
void blk_wrwin_unregister(struct gendisk *disk);
bool blk_wrwin_refuse(struct bio *bio);

static inline bool blk_wrwin_guarded(struct gendisk *disk)
{
	return test_bit(GD_WRITE_WINDOWS, &disk->state);
}
#else
static inline bool blk_wrwin_match(const char *vendor, size_t vendor_len,
				   const char *model, size_t model_len)
{
	return false;
}
static inline void blk_wrwin_register(struct gendisk *disk) { }
static inline void blk_wrwin_unregister(struct gendisk *disk) { }
static inline bool blk_wrwin_refuse(struct bio *bio) { return false; }
static inline bool blk_wrwin_guarded(struct gendisk *disk) { return false; }
#endif

#endif /* _LINUX_BLK_WRITE_WINDOWS_H */
