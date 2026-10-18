// SPDX-License-Identifier: GPL-2.0-only
/*
 * L2 cache controllers of the Fortinet FortiSOC1 and FortiSOC2
 *
 * The FortiSOC1 (FortiGate 60C) has a 256 KiB, 8-way, physically addressed
 * outer cache with 32-byte lines, behind the FA626TE core: the FortiSOC1 L2
 * cache controller. The FortiSOC2 (FortiGate 60D) has one of the same
 * geometry at the same address, behind the FA726TE core (a Faraday
 * FTL2CC031). Neither has public documentation: register layout and values
 * established by observation, for interoperability; only the registers
 * below are touched.
 *
 * Both share the control register:
 *
 *   0x00 CTRL    0: off, 1: on, 2: invalidate all (bit 1 busy)
 *
 * FortiSOC1 ("fortinet,fsoc1-l2cc"):
 *
 *   0x04 AUXCTRL bits 11:9 and 1:0 set to 0b001 and 0b00 before enabling
 *   0x30 SYNC    write 1, then wait for bit 0 to clear
 *   0x34 MAINT   whole cache maintenance, one way at a time: operation in
 *                the low bits, way in bits 10:8, busy while the operation
 *                bits are set
 *   0x38 RANGE_ADDR range maintenance: physical start address (32-byte
 *                aligned) ORed with the operation, busy while bits 2:0 of
 *                the operation are set
 *   0x3c RANGE_LINES number of lines of the range operation; the field
 *                width is unknown
 *   0x90         written with 1 before enabling, purpose unknown
 *
 * FortiSOC2 ("fortinet,fsoc2-l2cc"), where this driver touches only the
 * registers at 0x00, 0x08, 0x40, 0x44, 0x4c and 0x50:
 *
 *   0x08 AUXCTRL written with a board specific value before enabling (not
 *                a read-modify-write): 0x00012023 by default (FortiGate
 *                60D), or the "fortinet,auxiliary-control" property of the
 *                node (FortiGate 90D: 0x00012033, bit 4 in addition, its
 *                effect not known)
 *   0x40 RANGE_ADDR range maintenance: physical start address, 32-byte
 *                aligned
 *   0x44 RANGE_LINES number of lines of the range operation minus one
 *                (0x3ff at most here)
 *   0x4c WAYS    mask of the ways of a whole cache operation
 *   0x50 CMD     command, busy while the bits of the command are set:
 *                1 sync, 2 invalidate range, 5 clean range, 8 clean and
 *                invalidate range, 7 clean ways, 0xa clean and invalidate
 *                ways
 *
 * FortiSOC2: the range invalidate command (2) has not been validated, and
 * is not used: range invalidation is done with command 8, which is also
 * correct for DMA, since the lines of a buffer being received into
 * cannot be dirty (the edges are cleaned first anyway).
 *
 * The range operations take physical addresses, like the outer_cache
 * callbacks.
 *
 * The boot loader may or may not leave the cache enabled. If it is on, it
 * is taken over and flushed; if it is off, it is enabled
 * (fsoc1_l2_enable_fsoc1(), fsoc1_l2_enable_fsoc2()). It is flushed and
 * turned off again on restart.
 */

#define pr_fmt(fmt) "fsoc1-l2: " fmt

#include <linux/init.h>
#include <linux/io.h>
#include <linux/irqflags.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/reboot.h>
#include <linux/sizes.h>
#include <linux/spinlock.h>
#include <asm/cacheflush.h>
#include <asm/outercache.h>

#define FSOC1_L2_CTRL		0x00
#define FSOC1_L2_CTRL_OFF	0
#define FSOC1_L2_CTRL_ON	BIT(0)
#define FSOC1_L2_CTRL_INV	BIT(1)
#define FSOC1_L2_AUXCTRL	0x04
#define FSOC1_L2_AUXCTRL_MASK	(GENMASK(11, 9) | GENMASK(1, 0))
#define FSOC1_L2_AUXCTRL_VAL	BIT(9)
#define FSOC1_L2_SYNC		0x30
#define FSOC1_L2_SYNC_BUSY	BIT(0)
#define FSOC1_L2_MAINT		0x34
#define FSOC1_L2_MAINT_FLUSH	BIT(1)
#define FSOC1_L2_MAINT_CLEAN	BIT(3)
#define FSOC1_L2_MAINT_WAY_SHIFT 8
#define FSOC1_L2_RANGE_ADDR		0x38
#define FSOC1_L2_RANGE_ADDR_FLUSH	(BIT(4) | BIT(0))
#define FSOC1_L2_RANGE_ADDR_CLEAN	(BIT(4) | BIT(1))
#define FSOC1_L2_RANGE_ADDR_INV	(BIT(4) | BIT(2))
#define FSOC1_L2_RANGE_ADDR_BUSY	GENMASK(2, 0)
#define FSOC1_L2_RANGE_LINES		0x3c
/* Below 8192, which a 13-bit field would read as 0. */
#define FSOC1_L2_RANGE_LINES_MAX	4096
#define FSOC1_L2_INIT		0x90

#define FSOC2_L2_AUXCTRL	0x08
/* Default auxiliary control value, see "fortinet,auxiliary-control" */
#define FSOC2_L2_AUXCTRL_VAL	0x00012023
#define FSOC2_L2_RANGE_ADDR		0x40
#define FSOC2_L2_RANGE_LINES		0x44
#define FSOC2_L2_RANGE_LINES_MAX	1024
#define FSOC2_L2_WAYS		0x4c
#define FSOC2_L2_CMD		0x50
#define FSOC2_L2_CMD_SYNC	0x1
#define FSOC2_L2_CMD_INV	0x2	/* not used, see above */
#define FSOC2_L2_CMD_CLEAN	0x5
#define FSOC2_L2_CMD_FLUSH	0x8
#define FSOC2_L2_CMD_CLEAN_WAYS	0x7
#define FSOC2_L2_CMD_FLUSH_WAYS	0xa

#define FSOC1_L2_LINE_SIZE	32
#define FSOC1_L2_WAYS		8
#define FSOC1_L2_SIZE		SZ_256K

/*
 * Busy polls before giving up.
 */
#define FSOC1_L2_POLLS		5000000

/**
 * struct fsoc1_l2_variant - differences between the controllers
 * @auxctrl: offset of the auxiliary control register
 * @max_lines: largest line count of one range operation
 * @inv: range invalidate operation, for @range_op
 * @clean: range clean operation, for @range_op
 * @flush: range clean and invalidate operation, for @range_op
 * @clean_all: whole cache clean operation, for @all_op
 * @flush_all: whole cache clean and invalidate operation, for @all_op
 * @enable: enable sequence, from off
 * @enable_writes: registers written by @enable before it can fail
 * @sync: wait for the previous operations to complete
 * @range_op: start and wait for a range operation, no sync after it
 * @all_op: whole cache operation, synced
 */
struct fsoc1_l2_variant {
	unsigned int auxctrl;
	unsigned int max_lines;
	u32 inv;
	u32 clean;
	u32 flush;
	u32 clean_all;
	u32 flush_all;
	int (*enable)(void);
	const char *enable_writes;
	void (*sync)(void);
	void (*range_op)(unsigned long start, unsigned int lines, u32 op);
	void (*all_op)(u32 op);
};

static const struct fsoc1_l2_variant *fsoc1_l2_v;
static u32 fsoc2_l2_aux = FSOC2_L2_AUXCTRL_VAL;
static void __iomem *fsoc1_l2_base;
static DEFINE_RAW_SPINLOCK(fsoc1_l2_lock);
static bool fsoc1_l2_on;

static bool fsoc1_l2_wait(unsigned int reg, u32 mask)
{
	unsigned int i;

	for (i = 0; i < FSOC1_L2_POLLS; i++)
		if (!(readl_relaxed(fsoc1_l2_base + reg) & mask))
			return true;

	return false;
}

static void fsoc1_l2_sync(void)
{
	writel_relaxed(1, fsoc1_l2_base + FSOC1_L2_SYNC);
	if (!fsoc1_l2_wait(FSOC1_L2_SYNC, FSOC1_L2_SYNC_BUSY))
		pr_err_ratelimited("sync timeout\n");
}

/* Lines [start, start + lines * 32), lines <= FSOC1_L2_RANGE_LINES_MAX. */
static void fsoc1_l2_range_op(unsigned long start, unsigned int lines, u32 op)
{
	fsoc1_l2_sync();
	writel_relaxed(lines, fsoc1_l2_base + FSOC1_L2_RANGE_LINES);
	writel_relaxed(start | op, fsoc1_l2_base + FSOC1_L2_RANGE_ADDR);
	if (!fsoc1_l2_wait(FSOC1_L2_RANGE_ADDR, op & FSOC1_L2_RANGE_ADDR_BUSY))
		pr_err_ratelimited("range op %#x timeout\n", op);
}

static void fsoc1_l2_range(unsigned long start, unsigned long end, u32 op)
{
	unsigned long flags;
	unsigned int lines;

	while (start < end) {
		lines = min_t(unsigned long, (end - start) / FSOC1_L2_LINE_SIZE,
			      fsoc1_l2_v->max_lines);
		/* Callers pass whole lines; never loop, nor write -1 lines. */
		if (WARN_ON_ONCE(!lines))
			break;

		raw_spin_lock_irqsave(&fsoc1_l2_lock, flags);
		if (fsoc1_l2_on) {
			fsoc1_l2_v->range_op(start, lines, op);
			fsoc1_l2_v->sync();
		}
		raw_spin_unlock_irqrestore(&fsoc1_l2_lock, flags);

		start += lines * FSOC1_L2_LINE_SIZE;
	}
}

static void __fsoc1_l2_way_op(u32 op)
{
	unsigned int way;

	fsoc1_l2_sync();
	for (way = 0; way < FSOC1_L2_WAYS; way++) {
		writel_relaxed(op | way << FSOC1_L2_MAINT_WAY_SHIFT,
			       fsoc1_l2_base + FSOC1_L2_MAINT);
		if (!fsoc1_l2_wait(FSOC1_L2_MAINT, op))
			pr_err_ratelimited("way %u op %#x timeout\n", way, op);
	}
	fsoc1_l2_sync();
}

static void fsoc2_l2_cmd(u32 cmd)
{
	writel_relaxed(cmd, fsoc1_l2_base + FSOC2_L2_CMD);
	if (!fsoc1_l2_wait(FSOC2_L2_CMD, cmd))
		pr_err_ratelimited("command %#x timeout\n", cmd);
}

static void fsoc2_l2_sync(void)
{
	fsoc2_l2_cmd(FSOC2_L2_CMD_SYNC);
}

/* Lines [start, start + lines * 32), 1 <= lines <= FSOC2_L2_RANGE_LINES_MAX. */
static void fsoc2_l2_range_op(unsigned long start, unsigned int lines, u32 op)
{
	writel_relaxed(lines - 1, fsoc1_l2_base + FSOC2_L2_RANGE_LINES);
	writel_relaxed(start, fsoc1_l2_base + FSOC2_L2_RANGE_ADDR);
	fsoc2_l2_cmd(op);
}

/* All the ways at once. */
static void fsoc2_l2_all_op(u32 op)
{
	writel_relaxed(GENMASK(FSOC1_L2_WAYS - 1, 0),
		       fsoc1_l2_base + FSOC2_L2_WAYS);
	fsoc2_l2_cmd(op);
	fsoc2_l2_sync();
}

static void fsoc1_l2_all_op(u32 op)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&fsoc1_l2_lock, flags);
	if (fsoc1_l2_on)
		fsoc1_l2_v->all_op(op);
	raw_spin_unlock_irqrestore(&fsoc1_l2_lock, flags);
}

static void fsoc1_l2_inv_range(unsigned long start, unsigned long end)
{
	/*
	 * Lines only partly covered also hold data outside the buffer:
	 * write them back instead of dropping them.
	 */
	if (start & (FSOC1_L2_LINE_SIZE - 1)) {
		start &= ~(FSOC1_L2_LINE_SIZE - 1);
		fsoc1_l2_range(start, start + FSOC1_L2_LINE_SIZE,
			       fsoc1_l2_v->flush);
		start += FSOC1_L2_LINE_SIZE;
	}

	if (end & (FSOC1_L2_LINE_SIZE - 1)) {
		end &= ~(FSOC1_L2_LINE_SIZE - 1);
		if (end >= start)
			fsoc1_l2_range(end, end + FSOC1_L2_LINE_SIZE,
				       fsoc1_l2_v->flush);
	}

	fsoc1_l2_range(start, end, fsoc1_l2_v->inv);
}

static void fsoc1_l2_clean_range(unsigned long start, unsigned long end)
{
	if (end - start >= FSOC1_L2_SIZE) {
		fsoc1_l2_all_op(fsoc1_l2_v->clean_all);
		return;
	}

	start &= ~(FSOC1_L2_LINE_SIZE - 1);
	end = ALIGN(end, FSOC1_L2_LINE_SIZE);
	fsoc1_l2_range(start, end, fsoc1_l2_v->clean);
}

static void fsoc1_l2_flush_all(void)
{
	fsoc1_l2_all_op(fsoc1_l2_v->flush_all);
}

static void fsoc1_l2_flush_range(unsigned long start, unsigned long end)
{
	if (end - start >= FSOC1_L2_SIZE) {
		fsoc1_l2_flush_all();
		return;
	}

	start &= ~(FSOC1_L2_LINE_SIZE - 1);
	end = ALIGN(end, FSOC1_L2_LINE_SIZE);
	fsoc1_l2_range(start, end, fsoc1_l2_v->flush);
}

/* Write back every dirty line, then turn the cache off. */
static void fsoc1_l2_disable(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&fsoc1_l2_lock, flags);
	if (fsoc1_l2_on) {
		/*
		 * Empty the L1 first, with interrupts off: nothing can then
		 * be written back into the L2 between its flush and its
		 * disabling, and be lost.
		 */
		flush_cache_all();
		fsoc1_l2_v->all_op(fsoc1_l2_v->flush_all);
		writel_relaxed(FSOC1_L2_CTRL_OFF, fsoc1_l2_base + FSOC1_L2_CTRL);
		fsoc1_l2_on = false;
	}
	raw_spin_unlock_irqrestore(&fsoc1_l2_lock, flags);
}

/*
 * Runs before the watchdog restart handler: leave the boot loader a clean
 * and disabled cache, as found when it did not enable it.
 */
static int fsoc1_l2_restart(struct notifier_block *nb, unsigned long action,
			    void *data)
{
	fsoc1_l2_disable();
	return NOTIFY_DONE;
}

static struct notifier_block fsoc1_l2_restart_nb = {
	.notifier_call = fsoc1_l2_restart,
	.priority = 192,
};

static int fsoc1_l2_enable_fsoc1(void)
{
	u32 aux;

	writel_relaxed(FSOC1_L2_CTRL_OFF, fsoc1_l2_base + FSOC1_L2_CTRL);
	writel_relaxed(1, fsoc1_l2_base + FSOC1_L2_INIT);

	aux = readl_relaxed(fsoc1_l2_base + FSOC1_L2_AUXCTRL);
	aux &= ~FSOC1_L2_AUXCTRL_MASK;
	aux |= FSOC1_L2_AUXCTRL_VAL;
	writel_relaxed(aux, fsoc1_l2_base + FSOC1_L2_AUXCTRL);

	writel_relaxed(FSOC1_L2_CTRL_INV, fsoc1_l2_base + FSOC1_L2_CTRL);
	if (!fsoc1_l2_wait(FSOC1_L2_CTRL, FSOC1_L2_CTRL_INV)) {
		writel_relaxed(FSOC1_L2_CTRL_OFF, fsoc1_l2_base + FSOC1_L2_CTRL);
		return -ETIMEDOUT;
	}

	writel_relaxed(FSOC1_L2_CTRL_ON, fsoc1_l2_base + FSOC1_L2_CTRL);

	return 0;
}

static int fsoc1_l2_enable_fsoc2(void)
{
	writel_relaxed(FSOC1_L2_CTRL_OFF, fsoc1_l2_base + FSOC1_L2_CTRL);
	writel_relaxed(fsoc2_l2_aux, fsoc1_l2_base + FSOC2_L2_AUXCTRL);

	writel_relaxed(FSOC1_L2_CTRL_INV, fsoc1_l2_base + FSOC1_L2_CTRL);
	if (!fsoc1_l2_wait(FSOC1_L2_CTRL, FSOC1_L2_CTRL_INV)) {
		writel_relaxed(FSOC1_L2_CTRL_OFF, fsoc1_l2_base + FSOC1_L2_CTRL);
		return -ETIMEDOUT;
	}

	writel_relaxed(FSOC1_L2_CTRL_ON, fsoc1_l2_base + FSOC1_L2_CTRL);

	return 0;
}

static const struct fsoc1_l2_variant fsoc1_l2_fsoc1 = {
	.auxctrl = FSOC1_L2_AUXCTRL,
	.max_lines = FSOC1_L2_RANGE_LINES_MAX,
	.inv = FSOC1_L2_RANGE_ADDR_INV,
	.clean = FSOC1_L2_RANGE_ADDR_CLEAN,
	.flush = FSOC1_L2_RANGE_ADDR_FLUSH,
	.clean_all = FSOC1_L2_MAINT_CLEAN,
	.flush_all = FSOC1_L2_MAINT_FLUSH,
	.enable = fsoc1_l2_enable_fsoc1,
	.enable_writes = "AUXCTRL and register 0x90",
	.sync = fsoc1_l2_sync,
	.range_op = fsoc1_l2_range_op,
	.all_op = __fsoc1_l2_way_op,
};

/*
 * Syncing after each slice of a range operation (rather than once at the
 * end) keeps the lock held per slice.
 * Range invalidation uses command 8, see the top of this file.
 */
static const struct fsoc1_l2_variant fsoc1_l2_fsoc2 = {
	.auxctrl = FSOC2_L2_AUXCTRL,
	.max_lines = FSOC2_L2_RANGE_LINES_MAX,
	.inv = FSOC2_L2_CMD_FLUSH,
	.clean = FSOC2_L2_CMD_CLEAN,
	.flush = FSOC2_L2_CMD_FLUSH,
	.clean_all = FSOC2_L2_CMD_CLEAN_WAYS,
	.flush_all = FSOC2_L2_CMD_FLUSH_WAYS,
	.enable = fsoc1_l2_enable_fsoc2,
	.enable_writes = "AUXCTRL",
	.sync = fsoc2_l2_sync,
	.range_op = fsoc2_l2_range_op,
	.all_op = fsoc2_l2_all_op,
};

static const struct of_device_id fsoc1_l2_ids[] __initconst = {
	{ .compatible = "fortinet,fsoc1-l2cc", .data = &fsoc1_l2_fsoc1 },
	{ .compatible = "fortinet,fsoc2-l2cc", .data = &fsoc1_l2_fsoc2 },
	{ }
};

static int __init fsoc1_l2_init(void)
{
	const struct of_device_id *match;
	struct device_node *np;
	u32 ctrl, aux;
	bool was_on;
	int ret;

	np = of_find_matching_node_and_match(NULL, fsoc1_l2_ids, &match);
	if (!np)
		return 0;

	/* Disabled in the device tree: do not touch the hardware at all. */
	if (!of_device_is_available(np)) {
		of_node_put(np);
		return 0;
	}

	fsoc1_l2_v = match->data;

	/*
	 * FortiSOC2: auxiliary control value of the board, if it differs
	 * from the default. Ignored when the boot loader left the cache on.
	 */
	if (fsoc1_l2_v == &fsoc1_l2_fsoc2)
		of_property_read_u32(np, "fortinet,auxiliary-control",
				     &fsoc2_l2_aux);

	fsoc1_l2_base = of_iomap(np, 0);
	of_node_put(np);
	if (!fsoc1_l2_base) {
		pr_err("cannot map registers\n");
		return -ENOMEM;
	}

	ctrl = readl_relaxed(fsoc1_l2_base + FSOC1_L2_CTRL);
	aux = readl_relaxed(fsoc1_l2_base + fsoc1_l2_v->auxctrl);
	was_on = ctrl & FSOC1_L2_CTRL_ON;
	if (was_on)
		pr_warn("found enabled by the boot loader, taking it over as is: CTRL %#010x AUXCTRL %#010x\n",
			ctrl, aux);
	else
		pr_info("found disabled, CTRL %#010x AUXCTRL %#010x\n",
			ctrl, aux);

	if (!was_on) {
		ret = fsoc1_l2_v->enable();
		if (ret) {
			pr_err("invalidate all timed out: cache left off, but %s already written (AUXCTRL %#010x)\n",
			       fsoc1_l2_v->enable_writes,
			       readl_relaxed(fsoc1_l2_base + fsoc1_l2_v->auxctrl));
			iounmap(fsoc1_l2_base);
			fsoc1_l2_base = NULL;
			return ret;
		}
	}

	fsoc1_l2_on = true;

	/* The value written must read back, or the board value is wrong. */
	if (!was_on && fsoc1_l2_v == &fsoc1_l2_fsoc2) {
		aux = readl_relaxed(fsoc1_l2_base + FSOC2_L2_AUXCTRL);
		if (aux != fsoc2_l2_aux)
			pr_warn("AUXCTRL reads back %#010x, %#010x written\n",
				aux, fsoc2_l2_aux);
	}

	/*
	 * Taken over: everything written so far, page tables included, may
	 * sit in the cache. Write it back so that memory is up to date, as
	 * when the cache is enabled here.
	 */
	if (was_on)
		fsoc1_l2_flush_all();

	outer_cache.inv_range = fsoc1_l2_inv_range;
	outer_cache.clean_range = fsoc1_l2_clean_range;
	outer_cache.flush_range = fsoc1_l2_flush_range;
	outer_cache.flush_all = fsoc1_l2_flush_all;
	outer_cache.disable = fsoc1_l2_disable;

	register_restart_handler(&fsoc1_l2_restart_nb);

	pr_info("%u KiB, %u ways, %u B lines, %s, AUXCTRL %#010x\n",
		FSOC1_L2_SIZE / SZ_1K, FSOC1_L2_WAYS, FSOC1_L2_LINE_SIZE,
		was_on ? "taken over" : "enabled",
		readl_relaxed(fsoc1_l2_base + fsoc1_l2_v->auxctrl));

	return 0;
}
early_initcall(fsoc1_l2_init);
