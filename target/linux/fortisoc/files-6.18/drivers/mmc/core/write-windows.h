/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Write windows of the fortinet,force-ro read-only guard of the MMC core,
 * see write-windows.c.
 */
#ifndef _MMC_CORE_WRITE_WINDOWS_H
#define _MMC_CORE_WRITE_WINDOWS_H

#include <linux/types.h>

struct gendisk;
struct mmc_command;
struct mmc_host;
struct mmc_request;

#ifdef CONFIG_MMC_WRITE_WINDOWS
void mmc_write_windows_setup(struct mmc_host *host);
bool mmc_write_windows_on_host(struct mmc_host *host);
void mmc_write_windows_add_disk(struct mmc_host *host, struct gendisk *disk);
void mmc_write_windows_remove_disk(struct gendisk *disk);
bool mmc_write_window_ok(struct mmc_host *host,
			 const struct mmc_request *mrq);
void mmc_write_windows_note_refused(const struct mmc_command *cmd);
#else
static inline void mmc_write_windows_setup(struct mmc_host *host) { }
static inline bool mmc_write_windows_on_host(struct mmc_host *host)
{
	return false;
}
static inline void mmc_write_windows_add_disk(struct mmc_host *host,
					      struct gendisk *disk) { }
static inline void mmc_write_windows_remove_disk(struct gendisk *disk) { }
static inline bool mmc_write_window_ok(struct mmc_host *host,
				       const struct mmc_request *mrq)
{
	return false;
}
static inline void mmc_write_windows_note_refused(const struct mmc_command *cmd) { }
#endif

#endif /* _MMC_CORE_WRITE_WINDOWS_H */
