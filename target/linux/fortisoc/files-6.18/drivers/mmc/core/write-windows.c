// SPDX-License-Identifier: GPL-2.0-only
/*
 * Write windows of the fortinet,force-ro read-only guard of the MMC core
 *
 * The read-only guard (MMC_CAP2_FORCE_RO, core.c) refuses every data write
 * to a guarded host. For an installer writing one firmware slot of an eMMC,
 * and for a file system kept in that slot, this option (MMC_WRITE_WINDOWS,
 * default n) lets plain CMD24/CMD25 writes of 512-byte blocks to the user
 * area of a sector-addressed eMMC through, when the whole request lies
 * inside one window given by the device tree node of the guarded host:
 *
 *	mmc@... {
 *		fortinet,force-ro;
 *		fortinet,write-windows = <0 1>, <786440 524288>;
 *		fortinet,sector0-bytes = <0x30 32>, <0x12c 4>;
 *		fortinet,persistent-windows = <819208 491520>;
 *	};
 *
 *  - Windows: fortinet,write-windows, <start count> pairs of absolute
 *    512-byte sectors of the user area, read once when the host is added
 *    (nothing can change them at run time). Only one guarded host may have
 *    windows. A guarded host with neither windows nor persistent windows
 *    stays strictly read-only.
 *  - Arming: the windows are disarmed at boot. Writing "arm" to
 *    /sys/module/mmc_core/parameters/write_windows arms them, once per
 *    boot, for MMC_WRITE_WINDOWS_ARM_SECS at most; "off" (end of the
 *    installation), the end of the armed time, the removal of the disk, a
 *    second host with windows, a bad configuration or a refused
 *    PARTITION_CONFIG switch (the cached part_config could then say "user
 *    area" while another partition is selected) turn them off until the
 *    next boot. Arming needs the disk of the user area of the host.
 *  - Sector 0: a write starting at sector 0 may only change the bytes of
 *    sector 0 listed in fortinet,sector0-bytes (<offset length> pairs),
 *    compared with a copy of sector 0 read at arming time; a write of
 *    sector 0 that cannot be compared is refused. Absent: the content of
 *    sector 0 may not change at all.
 *  - Persistent windows (optional): fortinet,persistent-windows, <start
 *    count> pairs as above, never covering sector 0 (refused: bad
 *    configuration). Plain writes lying entirely inside one of them are
 *    accepted without arming, from the registration of the host
 *    ("disarmed") until "off", for a file system kept in that area. With
 *    them, the end of the armed time only closes the other windows: the
 *    state becomes "expired" (persistent windows still open, "arm" refused
 *    until the next boot) instead of "off". "off", from user space or for
 *    any of the reasons above, closes every window, the persistent ones
 *    too. A window written through the page cache of the whole disk (a
 *    loop device backed by it) must be aligned on its pages (8 sectors).
 *  - Capacity: a window beyond the user area turns the windows off when
 *    the disk is registered; a request beyond it is refused anyway.
 *  - Witness: the parameter reads "inactive" (no guarded host with
 *    windows), "off", or the state ("disarmed", "armed", "expired"), the
 *    windows ("none" without), the persistent windows after the word
 *    "persistent" (when there are some) and the bytes of sector 0 that may
 *    change after the word "sector0" ("none" without), e.g.
 *    "disarmed 0+1 786440+524288 persistent 819208+491520 sector0 0x30+32".
 *
 * Refused whatever the state: reliable writes, tagged or forced
 * programming, open-ended or one-block CMD25, erase, discard, EXT_CSD
 * writes, boot/GP/RPMB partitions, the command queue engine and ioctl
 * writes (core.c, block.c). The data of a sector 0 write is checked when
 * the request is started: a writer changing its own buffer while the
 * request is in flight is not defended against (this guards against
 * mistakes, not against root).
 */
#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mmc/card.h>
#include <linux/mmc/core.h>
#include <linux/mmc/host.h>
#include <linux/mmc/mmc.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/property.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "card.h"
#include "write-windows.h"

#define MMC_WRITE_WINDOWS_SECTOR	512
#define MMC_WRITE_WINDOWS_MAX		4
#define MMC_WRITE_WINDOWS_MAX_BYTES	8
/* Lifetime of an armed window, from the arming (one installation) */
#define MMC_WRITE_WINDOWS_ARM_SECS	600

struct mmc_write_windows_range {
	u32 start;
	u32 count;
};

static struct mmc_write_windows_range mmc_write_windows[MMC_WRITE_WINDOWS_MAX];
static unsigned int mmc_write_windows_nr;
/* Windows open without arming (none: no fortinet,persistent-windows) */
static struct mmc_write_windows_range mmc_write_windows_persistent[MMC_WRITE_WINDOWS_MAX];
static unsigned int mmc_write_windows_nr_persistent;
/* Bytes of sector 0 that a write may change (offset, length) */
static struct mmc_write_windows_range mmc_write_windows_bytes[MMC_WRITE_WINDOWS_MAX_BYTES];
static unsigned int mmc_write_windows_nr_bytes;

/* The guarded host the windows belong to, set once */
static struct mmc_host *mmc_write_windows_host;

/*
 * State, one way only within a boot (never back to a more permissive one):
 *  INACTIVE  no guarded host with windows registered;
 *  DISARMED  guarded host registered, every write refused except in the
 *            persistent windows (boot default);
 *  ARMED     armed by user space ("arm"), once per boot,
 *            MMC_WRITE_WINDOWS_ARM_SECS at most;
 *  EXPIRED   armed time over with persistent windows: those stay open, every
 *            other write refused, "arm" refused (never without them: OFF);
 *  OFF       every write refused until the next boot.
 */
enum {
	MMC_WRWIN_INACTIVE,
	MMC_WRWIN_DISARMED,
	MMC_WRWIN_ARMED,
	MMC_WRWIN_EXPIRED,
	MMC_WRWIN_OFF,
};

static atomic_t mmc_write_windows_state = ATOMIC_INIT(MMC_WRWIN_INACTIVE);
static unsigned long mmc_write_windows_until;	/* jiffies, valid when ARMED */
static DEFINE_MUTEX(mmc_write_windows_lock);	/* setup, disk and arming */
static unsigned int mmc_write_windows_disks;	/* disks registered since boot */
static struct gendisk *mmc_write_windows_disk;	/* under mmc_write_windows_lock */
/* Sector 0 read at arming time, the reference of the sector 0 check */
static u8 mmc_write_windows_sector0[MMC_WRITE_WINDOWS_SECTOR];
/* Data of a sector 0 write, copied from the request (any context) */
static u8 mmc_write_windows_buf[MMC_WRITE_WINDOWS_SECTOR];
static DEFINE_SPINLOCK(mmc_write_windows_buf_lock);

static void mmc_write_windows_disable(const char *why)
{
	if (atomic_xchg(&mmc_write_windows_state, MMC_WRWIN_OFF) != MMC_WRWIN_OFF)
		pr_warn("force-ro: write windows off (%s)\n", why);
}

/*
 * End of the armed time: off without persistent windows; with them, only
 * from ARMED to EXPIRED (never back from OFF).
 */
static void mmc_write_windows_expire(void)
{
	if (!mmc_write_windows_nr_persistent) {
		mmc_write_windows_disable("armed time over");
		return;
	}
	if (atomic_cmpxchg(&mmc_write_windows_state, MMC_WRWIN_ARMED,
			   MMC_WRWIN_EXPIRED) == MMC_WRWIN_ARMED)
		pr_warn("force-ro: write windows expired (armed time over), persistent windows open\n");
}

/* Current state; ends an armed time that is over */
static int mmc_write_windows_state_now(void)
{
	int state = atomic_read(&mmc_write_windows_state);

	if (state != MMC_WRWIN_ARMED)
		return state;
	/* pairs with the full barrier of the arming cmpxchg */
	smp_rmb();
	if (time_before(jiffies, READ_ONCE(mmc_write_windows_until)))
		return MMC_WRWIN_ARMED;
	mmc_write_windows_expire();
	return atomic_read(&mmc_write_windows_state);
}

/* Sectors start..end - 1 entirely inside one of the nr windows w */
static bool mmc_write_windows_inside(const struct mmc_write_windows_range *w,
				     unsigned int nr, u64 start, u64 end)
{
	unsigned int i;

	for (i = 0; i < nr; i++)
		if (start >= w[i].start && end <= (u64)w[i].start + w[i].count)
			return true;
	return false;
}

static bool mmc_write_windows_byte_may_change(unsigned int off)
{
	unsigned int i;

	for (i = 0; i < mmc_write_windows_nr_bytes; i++)
		if (off >= mmc_write_windows_bytes[i].start &&
		    off < mmc_write_windows_bytes[i].start +
			  mmc_write_windows_bytes[i].count)
			return true;
	return false;
}

/* First 512 bytes of a write starting at sector 0, against the copy */
static bool mmc_write_windows_sector0_ok(const struct mmc_data *data)
{
	unsigned long flags;
	unsigned int i, bad = 0;
	bool ok = true;

	spin_lock_irqsave(&mmc_write_windows_buf_lock, flags);
	if (sg_copy_to_buffer(data->sg, data->sg_len, mmc_write_windows_buf,
			      MMC_WRITE_WINDOWS_SECTOR) !=
	    MMC_WRITE_WINDOWS_SECTOR)
		ok = false;
	for (i = 0; ok && i < MMC_WRITE_WINDOWS_SECTOR; i++)
		if (mmc_write_windows_buf[i] != mmc_write_windows_sector0[i] &&
		    !mmc_write_windows_byte_may_change(i)) {
			bad = i;
			ok = false;
		}
	spin_unlock_irqrestore(&mmc_write_windows_buf_lock, flags);
	if (!ok)
		pr_warn_ratelimited("force-ro: sector 0 byte %#x may not change\n",
				    bad);
	return ok;
}

/*
 * Data request on the guarded host that is not a plain read: true lets it
 * through (core.c refuses it otherwise).
 */
bool mmc_write_window_ok(struct mmc_host *host, const struct mmc_request *mrq)
{
	const struct mmc_card *card = host->card;
	const struct mmc_command *cmd = mrq->cmd;
	const struct mmc_data *data = mrq->data;
	u64 start, end;
	int state;

	/* pairs with the release of mmc_write_windows_setup() */
	if (host != smp_load_acquire(&mmc_write_windows_host))
		return false;
	/* Sector-addressed eMMC, user area selected (no boot, GP, RPMB) */
	if (!card || !mmc_card_mmc(card) || !mmc_card_blockaddr(card))
		return false;
	if (card->ext_csd.part_config & EXT_CSD_PART_CONFIG_ACC_MASK)
		return false;
	if (!cmd || !data || mrq->cap_cmd_during_tfr)
		return false;
	/* Plain write: no reliable write, tag, forced programming, CQE flags */
	if (data->flags != MMC_DATA_WRITE)
		return false;
	if (data->blksz != MMC_WRITE_WINDOWS_SECTOR || !data->blocks)
		return false;
	/* CMD12 is the only stop command */
	if (mrq->stop && (mrq->stop->opcode != MMC_STOP_TRANSMISSION ||
			  mrq->stop->arg != 0))
		return false;

	switch (cmd->opcode) {
	case MMC_WRITE_BLOCK:
		if (data->blocks != 1 || mrq->sbc)
			return false;
		break;
	case MMC_WRITE_MULTIPLE_BLOCK:
		/*
		 * At least 2 blocks: tmio sends its automatic CMD12 only for
		 * more than one block, a 1-block CMD25 would stay open-ended.
		 */
		if (data->blocks < 2)
			return false;
		if (mrq->sbc) {
			/* block count only, exactly the data length */
			if (mrq->sbc->opcode != MMC_SET_BLOCK_COUNT ||
			    mrq->sbc->arg != data->blocks)
				return false;
		} else if (!mrq->stop) {
			return false;	/* open-ended write */
		}
		break;
	default:
		return false;
	}

	start = cmd->arg;
	end = start + data->blocks;
	if (end > card->ext_csd.sectors)
		return false;

	state = mmc_write_windows_state_now();
	/* persistent windows: open from the registration of the host to "off" */
	if ((state == MMC_WRWIN_DISARMED || state == MMC_WRWIN_ARMED ||
	     state == MMC_WRWIN_EXPIRED) &&
	    mmc_write_windows_inside(mmc_write_windows_persistent,
				     mmc_write_windows_nr_persistent, start, end))
		return true;
	if (state != MMC_WRWIN_ARMED)
		return false;
	if (!mmc_write_windows_inside(mmc_write_windows, mmc_write_windows_nr,
				      start, end))
		return false;
	if (start == 0 && !mmc_write_windows_sector0_ok(data))
		return false;
	return true;
}

/* A command refused by the guard: a PARTITION_CONFIG switch closes all */
void mmc_write_windows_note_refused(const struct mmc_command *cmd)
{
	if (cmd->opcode == MMC_SWITCH &&
	    ((cmd->arg >> 16) & 0xff) == EXT_CSD_PART_CONFIG)
		mmc_write_windows_disable("PARTITION_CONFIG switch refused");
}

/* Copy of sector 0 through the disk (mmc_write_windows_lock held) */
static int mmc_write_windows_read_sector0(struct gendisk *disk)
{
	struct page *page;
	struct bio *bio;
	int err;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	bio = bio_alloc(disk->part0, 1, REQ_OP_READ | REQ_SYNC, GFP_KERNEL);
	__bio_add_page(bio, page, MMC_WRITE_WINDOWS_SECTOR, 0);
	bio->bi_iter.bi_sector = 0;
	err = submit_bio_wait(bio);
	if (!err)
		memcpy(mmc_write_windows_sector0, page_address(page),
		       MMC_WRITE_WINDOWS_SECTOR);
	bio_put(bio);
	__free_page(page);
	return err;
}

static int mmc_write_windows_get(char *buf, const struct kernel_param *kp)
{
	static const char * const names[] = {
		[MMC_WRWIN_DISARMED] = "disarmed",
		[MMC_WRWIN_ARMED] = "armed",
		[MMC_WRWIN_EXPIRED] = "expired",
	};
	unsigned int i;
	int n, state;

	state = mmc_write_windows_state_now();	/* ends an armed time over */
	if (state == MMC_WRWIN_OFF)
		return sysfs_emit(buf, "off\n");
	if (state == MMC_WRWIN_INACTIVE)
		return sysfs_emit(buf, "inactive\n");
	n = sysfs_emit(buf, "%s", names[state]);
	for (i = 0; i < mmc_write_windows_nr; i++)
		n += sysfs_emit_at(buf, n, " %u+%u", mmc_write_windows[i].start,
				   mmc_write_windows[i].count);
	if (!mmc_write_windows_nr)
		n += sysfs_emit_at(buf, n, " none");
	if (mmc_write_windows_nr_persistent)
		n += sysfs_emit_at(buf, n, " persistent");
	for (i = 0; i < mmc_write_windows_nr_persistent; i++)
		n += sysfs_emit_at(buf, n, " %u+%u",
				   mmc_write_windows_persistent[i].start,
				   mmc_write_windows_persistent[i].count);
	n += sysfs_emit_at(buf, n, " sector0");
	for (i = 0; i < mmc_write_windows_nr_bytes; i++)
		n += sysfs_emit_at(buf, n, " %#x+%u",
				   mmc_write_windows_bytes[i].start,
				   mmc_write_windows_bytes[i].count);
	if (!mmc_write_windows_nr_bytes)
		n += sysfs_emit_at(buf, n, " none");
	return n + sysfs_emit_at(buf, n, "\n");
}

static int mmc_write_windows_set(const char *val, const struct kernel_param *kp)
{
	int err;

	/* Never from the kernel command line: at run time only */
	if (system_state != SYSTEM_RUNNING)
		return -EPERM;
	/* "off": less permissive than any state, always accepted */
	if (sysfs_streq(val, "off")) {
		mmc_write_windows_disable("turned off by user space");
		return 0;
	}
	if (!sysfs_streq(val, "arm"))
		return -EINVAL;

	/*
	 * Only DISARMED can be armed, and the state never comes back to it:
	 * the deadline is written once per boot, never pushed back.
	 */
	guard(mutex)(&mmc_write_windows_lock);
	if (atomic_read(&mmc_write_windows_state) != MMC_WRWIN_DISARMED ||
	    !mmc_write_windows_disk)
		return -EPERM;
	if (!mmc_write_windows_nr)
		return -EPERM;	/* nothing to arm */
	err = mmc_write_windows_read_sector0(mmc_write_windows_disk);
	if (err) {
		pr_err("force-ro: sector 0 unreadable (%d), not armed\n", err);
		return err;
	}
	WRITE_ONCE(mmc_write_windows_until,
		   jiffies + MMC_WRITE_WINDOWS_ARM_SECS * HZ);
	/* full barrier on success: deadline and copy seen before the state */
	if (atomic_cmpxchg(&mmc_write_windows_state, MMC_WRWIN_DISARMED,
			   MMC_WRWIN_ARMED) != MMC_WRWIN_DISARMED)
		return -EPERM;	/* turned off meanwhile */

	pr_warn("force-ro: write windows armed for %u s by %s[%d]\n",
		MMC_WRITE_WINDOWS_ARM_SECS, current->comm,
		task_pid_nr(current));
	return 0;
}

static const struct kernel_param_ops mmc_write_windows_ops = {
	.set = mmc_write_windows_set,
	.get = mmc_write_windows_get,
};
module_param_cb(write_windows, &mmc_write_windows_ops, NULL, 0644);
MODULE_PARM_DESC(write_windows,
		 "Write windows of the fortinet,force-ro guard (\"arm\" once per boot, \"off\")");

/* <a b>, <c d>...: u32 pairs, at most max of them, b > 0; absent: none */
static int mmc_write_windows_read_pairs(struct device *dev, const char *name,
					struct mmc_write_windows_range *r,
					unsigned int max, unsigned int *nr)
{
	u32 cells[2 * MMC_WRITE_WINDOWS_MAX_BYTES];
	int n, i;

	static_assert(MMC_WRITE_WINDOWS_MAX <= MMC_WRITE_WINDOWS_MAX_BYTES);

	*nr = 0;
	n = device_property_count_u32(dev, name);
	if (n == -EINVAL)
		return 0;		/* absent */
	if (n <= 0 || n % 2 || n > 2 * max)
		return -EINVAL;
	if (device_property_read_u32_array(dev, name, cells, n))
		return -EINVAL;
	for (i = 0; i < n / 2; i++) {
		r[i].start = cells[2 * i];
		r[i].count = cells[2 * i + 1];
		if (!r[i].count)
			return -EINVAL;
	}
	*nr = n / 2;
	return 0;
}

/* Every property of the host read and checked; false = bad configuration */
static bool mmc_write_windows_read_config(struct mmc_host *host)
{
	struct device *dev = mmc_dev(host);
	unsigned int i;
	bool ok = true;

	if (mmc_write_windows_read_pairs(dev, "fortinet,write-windows",
					 mmc_write_windows,
					 MMC_WRITE_WINDOWS_MAX,
					 &mmc_write_windows_nr)) {
		pr_err("%s: force-ro: bad fortinet,write-windows\n",
		       mmc_hostname(host));
		ok = false;
	}
	if (mmc_write_windows_read_pairs(dev, "fortinet,persistent-windows",
					 mmc_write_windows_persistent,
					 MMC_WRITE_WINDOWS_MAX,
					 &mmc_write_windows_nr_persistent)) {
		pr_err("%s: force-ro: bad fortinet,persistent-windows\n",
		       mmc_hostname(host));
		ok = false;
	}
	for (i = 0; i < mmc_write_windows_nr_persistent; i++)
		if (!mmc_write_windows_persistent[i].start) {
			pr_err("%s: force-ro: persistent window over sector 0\n",
			       mmc_hostname(host));
			ok = false;
		}
	if (mmc_write_windows_read_pairs(dev, "fortinet,sector0-bytes",
					 mmc_write_windows_bytes,
					 MMC_WRITE_WINDOWS_MAX_BYTES,
					 &mmc_write_windows_nr_bytes)) {
		pr_err("%s: force-ro: bad fortinet,sector0-bytes\n",
		       mmc_hostname(host));
		ok = false;
	}
	for (i = 0; i < mmc_write_windows_nr_bytes; i++)
		if ((u64)mmc_write_windows_bytes[i].start +
		    mmc_write_windows_bytes[i].count > MMC_WRITE_WINDOWS_SECTOR) {
			pr_err("%s: force-ro: sector 0 bytes beyond 512\n",
			       mmc_hostname(host));
			ok = false;
		}
	if (ok && mmc_write_windows_nr_bytes) {
		for (i = 0; i < mmc_write_windows_nr; i++)
			if (!mmc_write_windows[i].start)
				break;
		if (i == mmc_write_windows_nr)
			pr_warn("%s: force-ro: sector 0 bytes given, but no window starts at sector 0\n",
				mmc_hostname(host));
	}
	return ok;
}

/*
 * Called for a guarded host when it is added, before its card: read its
 * windows, if any. A second host with windows, or a bad property, turns
 * them off for good.
 */
void mmc_write_windows_setup(struct mmc_host *host)
{
	struct device *dev = mmc_dev(host);
	unsigned int i;

	if (!device_property_present(dev, "fortinet,write-windows") &&
	    !device_property_present(dev, "fortinet,persistent-windows"))
		return;		/* no window: strictly read-only */

	guard(mutex)(&mmc_write_windows_lock);
	if (mmc_write_windows_host) {
		pr_err("%s: force-ro: write windows of another host already\n",
		       mmc_hostname(host));
		mmc_write_windows_disable("more than one host with windows");
		return;
	}
	if (!mmc_write_windows_read_config(host)) {
		mmc_write_windows_nr = 0;
		mmc_write_windows_nr_persistent = 0;
		mmc_write_windows_nr_bytes = 0;
		mmc_write_windows_disable("bad configuration");
		return;
	}

	for (i = 0; i < mmc_write_windows_nr; i++)
		pr_warn("%s: force-ro: write window LBA %u..%llu (%u sectors), disarmed\n",
			mmc_hostname(host), mmc_write_windows[i].start,
			(u64)mmc_write_windows[i].start +
			mmc_write_windows[i].count - 1,
			mmc_write_windows[i].count);
	for (i = 0; i < mmc_write_windows_nr_persistent; i++)
		pr_warn("%s: force-ro: persistent window LBA %u..%llu (%u sectors), open\n",
			mmc_hostname(host), mmc_write_windows_persistent[i].start,
			(u64)mmc_write_windows_persistent[i].start +
			mmc_write_windows_persistent[i].count - 1,
			mmc_write_windows_persistent[i].count);
	for (i = 0; i < mmc_write_windows_nr_bytes; i++)
		pr_warn("%s: force-ro: sector 0 bytes %#x..%#x may change\n",
			mmc_hostname(host), mmc_write_windows_bytes[i].start,
			mmc_write_windows_bytes[i].start +
			mmc_write_windows_bytes[i].count - 1);
	/* the windows are seen before the host, see mmc_write_window_ok() */
	smp_store_release(&mmc_write_windows_host, host);
	atomic_cmpxchg(&mmc_write_windows_state, MMC_WRWIN_INACTIVE,
		       MMC_WRWIN_DISARMED);
}

/* The block device of this host may be opened for writing */
bool mmc_write_windows_on_host(struct mmc_host *host)
{
	/* pairs with the release of mmc_write_windows_setup() */
	return host == smp_load_acquire(&mmc_write_windows_host);
}
EXPORT_SYMBOL_GPL(mmc_write_windows_on_host);

/*
 * Called by the block driver for the disk of the user area of a card, once
 * its capacity is known: the disk of the guarded host is the one sector 0
 * is read from at arming time. A window beyond it, or a second disk, turns
 * the windows off.
 */
void mmc_write_windows_add_disk(struct mmc_host *host, struct gendisk *disk)
{
	u64 cap = get_capacity(disk);
	unsigned int i;

	guard(mutex)(&mmc_write_windows_lock);
	if (host != mmc_write_windows_host)
		return;
	if (mmc_write_windows_disks++) {
		pr_err("%s: force-ro: another disk on the guarded host\n",
		       disk->disk_name);
		mmc_write_windows_disable("more than one disk");
		return;
	}
	for (i = 0; i < mmc_write_windows_nr; i++)
		if ((u64)mmc_write_windows[i].start +
		    mmc_write_windows[i].count > cap) {
			pr_err("%s: force-ro: window %u+%u beyond the disk (%llu sectors)\n",
			       disk->disk_name, mmc_write_windows[i].start,
			       mmc_write_windows[i].count, cap);
			mmc_write_windows_disable("window beyond the disk");
			return;
		}
	for (i = 0; i < mmc_write_windows_nr_persistent; i++)
		if ((u64)mmc_write_windows_persistent[i].start +
		    mmc_write_windows_persistent[i].count > cap) {
			pr_err("%s: force-ro: persistent window %u+%u beyond the disk (%llu sectors)\n",
			       disk->disk_name,
			       mmc_write_windows_persistent[i].start,
			       mmc_write_windows_persistent[i].count, cap);
			mmc_write_windows_disable("window beyond the disk");
			return;
		}
	mmc_write_windows_disk = disk;
	pr_info("%s: force-ro: guarded disk, %llu sectors\n",
		disk->disk_name, cap);
}
EXPORT_SYMBOL_GPL(mmc_write_windows_add_disk);

/* Called by the block driver before a disk goes away */
void mmc_write_windows_remove_disk(struct gendisk *disk)
{
	guard(mutex)(&mmc_write_windows_lock);
	if (disk != mmc_write_windows_disk)
		return;
	mmc_write_windows_disk = NULL;
	mmc_write_windows_disable("guarded disk removed");
}
EXPORT_SYMBOL_GPL(mmc_write_windows_remove_disk);
