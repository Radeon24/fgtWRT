// SPDX-License-Identifier: GPL-2.0-only
/*
 * Write windows for the installer of a dual-slot USB boot disk
 *
 * Some appliances boot from an internal USB disk holding two firmware slots
 * and a data partition. To let an installer write one slot from Linux, this
 * option (default n) guards the one disk matched by sd (usb-storage
 * transport, SCSI vendor and model given by the device tree, optionally its
 * exact size): every bio that may change its medium is refused, except
 * plain REQ_OP_WRITE bios lying entirely inside one of the windows given by
 * the device tree, while the windows are armed, or entirely inside one of
 * its persistent windows (a data area written at any time, see below).
 *
 * The board describes the disk and its windows in one node, found by its
 * compatible (no driver, no probe order):
 *
 *	write-windows {
 *		compatible = "fortinet,usb-disk-write-windows";
 *		fortinet,disk-vendor = "VENDOR";
 *		fortinet,disk-model = "MODEL";
 *		fortinet,disk-sectors = /bits/ 64 <7913472>;
 *		fortinet,write-windows = <0 1>, <1 524288>;
 *		fortinet,sector0-bytes = <0x10 32>, <0x128 4>;
 *		fortinet,persistent-windows = <32768 491520>;
 *	};
 *
 *  - No such node: no disk is guarded, the parameter reads "inactive" and
 *    "arm" is refused.
 *  - fortinet,disk-sectors (optional): exact size of the disk, in 512-byte
 *    sectors; another size turns the windows off.
 *  - Windows: fortinet,write-windows, <start count> pairs in absolute
 *    512-byte sectors of the whole disk. Absent: no window, every write to
 *    the guarded disk is refused, armed or not.
 *  - Sector 0: a write starting at sector 0 may only change the bytes of
 *    sector 0 listed in fortinet,sector0-bytes (<offset length> pairs),
 *    compared with a copy of sector 0 read at arming time. Absent: the
 *    content of sector 0 may not change at all.
 *  - Arming: the windows are disarmed at boot. Writing "arm" to
 *    /sys/module/block/parameters/write_windows arms them, once per
 *    boot, for WRWIN_ARM_SECS at most; "off" (end of the work), the end of the
 *    armed time, the removal of the disk, a second matching disk or a bad
 *    configuration turn them off until the next boot. The parameter reads
 *    "inactive" (no matching disk yet), "disarmed ...", "armed ..." or "off".
 *  - Persistent windows (optional): fortinet,persistent-windows, <start
 *    count> pairs as above, never covering sector 0 (refused: bad
 *    configuration). Plain writes lying entirely inside one of them are
 *    accepted without arming, from the registration of the disk ("disarmed")
 *    until "off", the removal of the disk or a second matching disk, for a
 *    file system mounted on that area. With them, the end of the armed time
 *    only closes the other windows: the state becomes "expired" (persistent
 *    windows still open, "arm" refused until the next boot) instead of
 *    "off". "off" from user space still closes every window. The parameter
 *    then lists them after the word "persistent", e.g.
 *    "disarmed 0+1 1+524288 persistent 32768+491520 sector0 0x10+32 0x128+4".
 *    A window written through the page cache of the whole disk (a loop
 *    device backed by it) must be aligned on its pages, 8 sectors here:
 *    the page cache writes back whole pages, and a page across the edge
 *    of the window would be refused.
 *    Absent: no persistent window, the behaviour and the parameter are those
 *    described above.
 *
 * Refused whatever the state: discard, secure erase, write zeroes, zone
 * operations on the guarded disk (bios), and SCSI pass-through through its
 * block device (SG_IO and friends, see sd_ioctl()). Only the sd block
 * device refuses them: the SCSI generic and bsg character devices
 * (CHR_DEV_SG, BLK_DEV_BSG) reach the disk without a bio and are not
 * guarded; the configurations that use the guard leave them out. Other
 * disks are not affected at all.
 *
 * PERSISTENT RESERVE OUT (IOC_PR_* ioctls) is refused as well.
 * Not covered (no medium data): MODE SELECT issued by the sd sysfs
 * attributes (cache_type...), SYNCHRONIZE CACHE, START STOP UNIT. A buffered
 * write to sector 0 reaches the disk as a whole page (sectors 0-7): with a
 * one-sector window it is refused, and the page cache may then hold data
 * that is not on the disk; sector 0 is written by real 512-byte direct I/O
 * only, and read back after dropping the caches. The data of
 * a sector 0 write is checked when the bio is submitted: a writer that
 * changes its own O_DIRECT buffer while the write is in flight is not
 * defended against (this guards against mistakes, not against root).
 */
#define pr_fmt(fmt) "write_windows: " fmt

#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-write-windows.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "block."

#define WRWIN_SECTOR		512
#define WRWIN_MAX_WINDOWS		4
#define WRWIN_MAX_BYTES		8
/* Lifetime of an armed window, from the arming (one write session) */
#define WRWIN_ARM_SECS		600
#define WRWIN_COMPATIBLE	"fortinet,usb-disk-write-windows"
/* Sizes of the vendor and model fields of the SCSI INQUIRY data */
#define WRWIN_VENDOR_LEN	8
#define WRWIN_MODEL_LEN		16

struct wrwin_range {
	u64 start;
	u64 count;
};

static struct wrwin_range wrwin_windows[WRWIN_MAX_WINDOWS];
static unsigned int wrwin_nr_windows;
/* Windows open without arming (none: no fortinet,persistent-windows) */
static struct wrwin_range wrwin_persistent[WRWIN_MAX_WINDOWS];
static unsigned int wrwin_nr_persistent;
/* Bytes of sector 0 that a write may change (offset, length) */
static struct wrwin_range wrwin_bytes[WRWIN_MAX_BYTES];
static unsigned int wrwin_nr_bytes;

/* Identity of the guarded disk, from the device tree (NULL: no node) */
static const char *wrwin_vendor;
static const char *wrwin_model;
static u64 wrwin_sectors;			/* 0: size not checked */
static bool wrwin_bad;				/* bad node: windows off */

/*
 * State, one way only within a boot (never back to a more permissive one):
 *  INACTIVE  no matching disk registered yet;
 *  DISARMED  one matching disk registered, every write refused except in the
 *            persistent windows (default);
 *  ARMED     armed by user space ("arm"), once per boot, WRWIN_ARM_SECS at most;
 *  EXPIRED   armed time over with persistent windows: those stay open, every
 *            other write refused, "arm" refused (never without them: OFF);
 *  OFF       every write to a guarded disk refused until the next boot.
 */
enum {
	WRWIN_INACTIVE,
	WRWIN_DISARMED,
	WRWIN_ARMED,
	WRWIN_EXPIRED,
	WRWIN_OFF,
};

static atomic_t wrwin_state = ATOMIC_INIT(WRWIN_INACTIVE);
static unsigned long wrwin_until;			/* jiffies, valid when ARMED */
static DEFINE_MUTEX(wrwin_lock);			/* registration and arming */
static unsigned int wrwin_matched;		/* disks matched since boot */
static struct gendisk *wrwin_disk;		/* the guarded disk, under wrwin_lock */
static u8 wrwin_sector0[WRWIN_SECTOR];		/* sector 0 read at arming time */

static void wrwin_disable(const char *why)
{
	if (atomic_xchg(&wrwin_state, WRWIN_OFF) != WRWIN_OFF)
		pr_warn("write windows off (%s)\n", why);
}

/*
 * End of the armed time: off without persistent windows; with them, only
 * from ARMED to EXPIRED (never back from OFF).
 */
static void wrwin_expire(void)
{
	if (!wrwin_nr_persistent) {
		wrwin_disable("armed time over");
		return;
	}
	if (atomic_cmpxchg(&wrwin_state, WRWIN_ARMED, WRWIN_EXPIRED) ==
	    WRWIN_ARMED)
		pr_warn("write windows expired (armed time over), persistent windows open\n");
}

/* Current state; ends an armed time that is over */
static int wrwin_state_now(void)
{
	int state = atomic_read(&wrwin_state);

	if (state != WRWIN_ARMED)
		return state;
	/* pairs with the full barrier of the arming cmpxchg */
	smp_rmb();
	if (time_before(jiffies, READ_ONCE(wrwin_until)))
		return WRWIN_ARMED;
	wrwin_expire();
	return atomic_read(&wrwin_state);
}

/* Sectors start..end - 1 entirely inside one of the nr windows w */
static bool wrwin_inside(const struct wrwin_range *w, unsigned int nr,
			 u64 start, u64 end)
{
	unsigned int i;

	for (i = 0; i < nr; i++)
		if (start >= w[i].start && end <= w[i].start + w[i].count)
			return true;
	return false;
}

/* <a b>, <c d>...: u32 pairs, at most max of them, b > 0; absent: none */
static int __init wrwin_read_pairs(struct device_node *np, const char *name,
				   struct wrwin_range *r, unsigned int max,
				   unsigned int *nr)
{
	u32 cells[2 * WRWIN_MAX_BYTES];
	int n, i;

	static_assert(WRWIN_MAX_WINDOWS <= WRWIN_MAX_BYTES);

	*nr = 0;
	n = of_property_count_u32_elems(np, name);
	if (n == -EINVAL)
		return 0;		/* absent */
	if (n <= 0 || n % 2 || n > 2 * max)
		return -EINVAL;
	if (of_property_read_u32_array(np, name, cells, n))
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

/* Disk identity: a string of 1 to len characters */
static const char * __init wrwin_read_id(struct device_node *np,
					 const char *name, size_t len)
{
	const char *str;

	if (of_property_read_string(np, name, &str) || !*str ||
	    strlen(str) > len) {
		pr_err("%pOF: bad or missing %s\n", np, name);
		return NULL;
	}
	return str;
}

/*
 * Configuration of the board, read once before any disk is probed. Without
 * an identity no disk is matched (inactive); a matched disk with any other
 * error is guarded with its windows off.
 */
static int __init wrwin_init(void)
{
	struct device_node *np;
	unsigned int i;

	np = of_find_compatible_node(NULL, NULL, WRWIN_COMPATIBLE);
	if (!np)
		return 0;
	if (!of_device_is_available(np))
		goto out;
	wrwin_vendor = wrwin_read_id(np, "fortinet,disk-vendor",
				     WRWIN_VENDOR_LEN);
	wrwin_model = wrwin_read_id(np, "fortinet,disk-model",
				    WRWIN_MODEL_LEN);
	if (!wrwin_vendor || !wrwin_model) {
		wrwin_vendor = wrwin_model = NULL;
		goto out;
	}
	/* the strings stay valid: the node is never released */
	of_node_get(np);

	if (of_property_present(np, "fortinet,disk-sectors") &&
	    (of_property_read_u64(np, "fortinet,disk-sectors", &wrwin_sectors) ||
	     !wrwin_sectors)) {
		pr_err("%pOF: bad fortinet,disk-sectors\n", np);
		wrwin_bad = true;
	}
	if (wrwin_read_pairs(np, "fortinet,write-windows", wrwin_windows,
			     WRWIN_MAX_WINDOWS, &wrwin_nr_windows)) {
		pr_err("%pOF: bad fortinet,write-windows\n", np);
		wrwin_bad = true;
	}
	if (wrwin_read_pairs(np, "fortinet,persistent-windows",
			     wrwin_persistent, WRWIN_MAX_WINDOWS,
			     &wrwin_nr_persistent)) {
		pr_err("%pOF: bad fortinet,persistent-windows\n", np);
		wrwin_bad = true;
	}
	for (i = 0; i < wrwin_nr_persistent; i++)
		if (!wrwin_persistent[i].start) {
			pr_err("persistent window over sector 0\n");
			wrwin_bad = true;
		}
	if (wrwin_read_pairs(np, "fortinet,sector0-bytes", wrwin_bytes,
			     WRWIN_MAX_BYTES, &wrwin_nr_bytes)) {
		pr_err("%pOF: bad fortinet,sector0-bytes\n", np);
		wrwin_bad = true;
	}
	for (i = 0; i < wrwin_nr_bytes; i++)
		if (wrwin_bytes[i].start + wrwin_bytes[i].count > WRWIN_SECTOR) {
			pr_err("sector 0 bytes beyond 512\n");
			wrwin_bad = true;
		}
	if (wrwin_nr_bytes) {
		for (i = 0; i < wrwin_nr_windows; i++)
			if (!wrwin_windows[i].start)
				break;
		if (i == wrwin_nr_windows)
			pr_warn("sector 0 bytes given, but no window starts at sector 0\n");
	}
	pr_info("USB disk to guard: \"%s\" \"%s\"%s\n", wrwin_vendor,
		wrwin_model, wrwin_bad ? ", windows off (bad configuration)" : "");
out:
	of_node_put(np);
	return 0;
}
subsys_initcall(wrwin_init);

/* INQUIRY field (space or NUL padded) equal to a configured string */
static bool wrwin_field_eq(const char *field, size_t size, const char *want)
{
	size_t n = strlen(want), i;

	if (!n || n > size || memcmp(field, want, n))
		return false;
	for (i = n; i < size && field[i]; i++)
		if (field[i] != ' ')
			return false;
	return true;
}

/* Called by sd for a usb-storage disk: is it the disk to guard? */
bool blk_wrwin_match(const char *vendor, size_t vendor_len,
		     const char *model, size_t model_len)
{
	return wrwin_vendor && wrwin_model &&
	       wrwin_field_eq(vendor, vendor_len, wrwin_vendor) &&
	       wrwin_field_eq(model, model_len, wrwin_model);
}

/* Configuration checked against the disk; false = refuse all */
static bool wrwin_config_ok(struct gendisk *disk)
{
	u64 cap = get_capacity(disk);
	unsigned int i;

	if (wrwin_bad)
		return false;
	for (i = 0; i < wrwin_nr_windows; i++)
		if (wrwin_windows[i].start + wrwin_windows[i].count > cap) {
			pr_err("window %llu+%llu beyond the disk (%llu sectors)\n",
			       wrwin_windows[i].start, wrwin_windows[i].count, cap);
			return false;
		}
	for (i = 0; i < wrwin_nr_persistent; i++)
		if (wrwin_persistent[i].start + wrwin_persistent[i].count > cap) {
			pr_err("persistent window %llu+%llu beyond the disk (%llu sectors)\n",
			       wrwin_persistent[i].start,
			       wrwin_persistent[i].count, cap);
			return false;
		}
	return true;
}

/*
 * Called by sd for a disk matching the configured identity, after its
 * capacity is known and before it is added (no I/O from user space yet).
 * The disk is guarded from here on, whatever happens next.
 */
void blk_wrwin_register(struct gendisk *disk)
{
	unsigned int i;

	guard(mutex)(&wrwin_lock);
	set_bit(GD_WRITE_WINDOWS, &disk->state);
	if (wrwin_matched++) {
		pr_err("%s: another disk matches already\n",
		       disk->disk_name);
		wrwin_disable("more than one matching disk");
		return;
	}
	if (queue_logical_block_size(disk->queue) != WRWIN_SECTOR) {
		pr_err("%s: logical block size %u, not 512\n",
		       disk->disk_name, queue_logical_block_size(disk->queue));
		wrwin_disable("logical block size");
		return;
	}
	if (wrwin_sectors && get_capacity(disk) != wrwin_sectors) {
		pr_err("%s: %llu sectors, %llu expected\n",
		       disk->disk_name, (u64)get_capacity(disk), wrwin_sectors);
		wrwin_disable("unexpected size");
		return;
	}
	if (!wrwin_config_ok(disk)) {
		wrwin_disable("bad configuration");
		return;
	}
	wrwin_disk = disk;
	pr_warn("%s guarded, %u write window(s), disarmed\n",
		disk->disk_name, wrwin_nr_windows);
	for (i = 0; i < wrwin_nr_windows; i++)
		pr_warn("%s: window sectors %llu..%llu (%llu)\n",
			disk->disk_name, wrwin_windows[i].start,
			wrwin_windows[i].start + wrwin_windows[i].count - 1,
			wrwin_windows[i].count);
	for (i = 0; i < wrwin_nr_persistent; i++)
		pr_warn("%s: persistent window sectors %llu..%llu (%llu), open\n",
			disk->disk_name, wrwin_persistent[i].start,
			wrwin_persistent[i].start + wrwin_persistent[i].count - 1,
			wrwin_persistent[i].count);
	for (i = 0; i < wrwin_nr_bytes; i++)
		pr_warn("%s: sector 0 bytes %#llx..%#llx may change\n",
			disk->disk_name, wrwin_bytes[i].start,
			wrwin_bytes[i].start + wrwin_bytes[i].count - 1);
	atomic_cmpxchg(&wrwin_state, WRWIN_INACTIVE, WRWIN_DISARMED);
}

/* Called by sd before a guarded disk goes away: off until the next boot */
void blk_wrwin_unregister(struct gendisk *disk)
{
	if (!test_bit(GD_WRITE_WINDOWS, &disk->state))
		return;
	guard(mutex)(&wrwin_lock);
	if (wrwin_disk == disk)
		wrwin_disk = NULL;
	wrwin_disable("guarded disk removed");
}

static bool wrwin_byte_may_change(unsigned int off)
{
	unsigned int i;

	for (i = 0; i < wrwin_nr_bytes; i++)
		if (off >= wrwin_bytes[i].start &&
		    off < wrwin_bytes[i].start + wrwin_bytes[i].count)
			return true;
	return false;
}

/* First 512 bytes of a write starting at sector 0, against the copy */
static bool wrwin_sector0_ok(struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned int done = 0, i;
	bool ok = true;
	u8 *buf;

	buf = kmalloc(WRWIN_SECTOR, GFP_NOIO);
	if (!buf)
		return false;
	bio_for_each_segment(bv, bio, iter) {
		bv.bv_len = min(bv.bv_len, WRWIN_SECTOR - done);
		memcpy_from_bvec(buf + done, &bv);
		done += bv.bv_len;
		if (done == WRWIN_SECTOR)
			break;
	}
	if (done != WRWIN_SECTOR)
		ok = false;
	for (i = 0; ok && i < WRWIN_SECTOR; i++)
		if (buf[i] != wrwin_sector0[i] && !wrwin_byte_may_change(i)) {
			pr_warn_ratelimited("sector 0 byte %#x may not change\n",
					    i);
			ok = false;
		}
	kfree(buf);
	return ok;
}

/*
 * Bio on a guarded disk (GD_WRITE_WINDOWS), sector already absolute (after the
 * partition remap). True: refuse it.
 */
bool blk_wrwin_refuse(struct bio *bio)
{
	u64 start = bio->bi_iter.bi_sector, end;
	unsigned int nr = bio_sectors(bio);
	const char *why;
	int state;

	if (!op_is_write(bio_op(bio)))
		return false;
	/* an empty flush carries no data (no byte, not "under a sector") */
	if (bio_op(bio) == REQ_OP_WRITE && !bio->bi_iter.bi_size)
		return false;
	end = start + nr;

	why = "not a plain write";
	if (bio_op(bio) != REQ_OP_WRITE)
		goto refuse;
	why = "not whole sectors";
	if (bio->bi_iter.bi_size & (WRWIN_SECTOR - 1))
		goto refuse;
	why = "logical block size not 512";
	if (bdev_logical_block_size(bio->bi_bdev) != WRWIN_SECTOR)
		goto refuse;
	state = wrwin_state_now();
	/* persistent windows: open from the registration of the disk to "off" */
	if ((state == WRWIN_DISARMED || state == WRWIN_ARMED ||
	     state == WRWIN_EXPIRED) &&
	    wrwin_inside(wrwin_persistent, wrwin_nr_persistent, start, end))
		return false;
	why = "windows not armed";
	if (state != WRWIN_ARMED)
		goto refuse;
	why = "outside the windows";
	if (!wrwin_inside(wrwin_windows, wrwin_nr_windows, start, end))
		goto refuse;
	why = "sector 0 content";
	if (start == 0 && !wrwin_sector0_ok(bio))
		goto refuse;
	return false;

refuse:
	pr_warn_ratelimited("%pg: write op %u of sectors %llu+%u refused (%s)\n",
			    bio->bi_bdev, bio_op(bio), start, nr, why);
	return true;
}

/* Copy of sector 0, the reference of the sector 0 check (wrwin_lock held) */
static int wrwin_read_sector0(struct gendisk *disk)
{
	struct page *page;
	struct bio *bio;
	int err;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	bio = bio_alloc(disk->part0, 1, REQ_OP_READ | REQ_SYNC, GFP_KERNEL);
	__bio_add_page(bio, page, WRWIN_SECTOR, 0);
	bio->bi_iter.bi_sector = 0;
	err = submit_bio_wait(bio);
	if (!err)
		memcpy(wrwin_sector0, page_address(page), WRWIN_SECTOR);
	bio_put(bio);
	__free_page(page);
	return err;
}

static int wrwin_get(char *buf, const struct kernel_param *kp)
{
	static const char * const names[] = {
		[WRWIN_DISARMED] = "disarmed",
		[WRWIN_ARMED] = "armed",
		[WRWIN_EXPIRED] = "expired",
	};
	unsigned int i;
	int n, state;

	state = wrwin_state_now();	/* ends an armed time that is over */
	if (state == WRWIN_OFF)
		return sysfs_emit(buf, "off\n");
	if (state == WRWIN_INACTIVE)
		return sysfs_emit(buf, "inactive\n");
	n = sysfs_emit(buf, "%s", names[state]);
	for (i = 0; i < wrwin_nr_windows; i++)
		n += sysfs_emit_at(buf, n, " %llu+%llu", wrwin_windows[i].start,
				   wrwin_windows[i].count);
	if (!wrwin_nr_windows)
		n += sysfs_emit_at(buf, n, " none");
	if (wrwin_nr_persistent)
		n += sysfs_emit_at(buf, n, " persistent");
	for (i = 0; i < wrwin_nr_persistent; i++)
		n += sysfs_emit_at(buf, n, " %llu+%llu",
				   wrwin_persistent[i].start,
				   wrwin_persistent[i].count);
	n += sysfs_emit_at(buf, n, " sector0");
	for (i = 0; i < wrwin_nr_bytes; i++)
		n += sysfs_emit_at(buf, n, " %#llx+%llu", wrwin_bytes[i].start,
				   wrwin_bytes[i].count);
	if (!wrwin_nr_bytes)
		n += sysfs_emit_at(buf, n, " none");
	return n + sysfs_emit_at(buf, n, "\n");
}

static int wrwin_set(const char *val, const struct kernel_param *kp)
{
	int err;

	/* Never from the kernel command line: at run time only */
	if (system_state != SYSTEM_RUNNING)
		return -EPERM;
	/* "off": less permissive than any state, always accepted */
	if (sysfs_streq(val, "off")) {
		wrwin_disable("turned off by user space");
		return 0;
	}
	if (!sysfs_streq(val, "arm"))
		return -EINVAL;

	guard(mutex)(&wrwin_lock);
	/* Only DISARMED can be armed: once per boot, never pushed back (not EXPIRED) */
	if (atomic_read(&wrwin_state) != WRWIN_DISARMED || !wrwin_disk)
		return -EPERM;
	if (!wrwin_nr_windows)
		return -EPERM;	/* nothing to arm */
	err = wrwin_read_sector0(wrwin_disk);
	if (err) {
		pr_err("sector 0 unreadable (%d), not armed\n",
		       err);
		return err;
	}
	WRITE_ONCE(wrwin_until, jiffies + WRWIN_ARM_SECS * HZ);
	/* full barrier on success: the deadline is seen before the state */
	if (atomic_cmpxchg(&wrwin_state, WRWIN_DISARMED, WRWIN_ARMED) !=
	    WRWIN_DISARMED)
		return -EPERM;	/* turned off meanwhile */
	pr_warn("%s: write windows armed for %u s by %s[%d]\n",
		wrwin_disk->disk_name, WRWIN_ARM_SECS, current->comm,
		task_pid_nr(current));
	return 0;
}

static const struct kernel_param_ops wrwin_ops = {
	.set = wrwin_set,
	.get = wrwin_get,
};
module_param_cb(write_windows, &wrwin_ops, NULL, 0644);
MODULE_PARM_DESC(write_windows,
		 "Write windows of the guarded USB disk (\"arm\" once per boot, \"off\")");
