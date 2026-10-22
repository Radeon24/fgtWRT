// SPDX-License-Identifier: GPL-2.0-only
/*
 * Watchdog driver for the Fortinet FortiSOC3 (FortiGate 60E and 100E)
 *
 * Register layout established by observation for interoperability; the
 * input clock (about 48 MHz) and the effect of an expiry were measured;
 * the effect of clearing the enable bit on a running block is unknown.
 *
 * Registers (32 bits, window of 0x100 bytes):
 *   0x00 CTRL     bit 0 = enable; no other bit is ever set
 *   0x04 LOAD     delay of each expiry, in periods of the input clock
 *   0x08 COUNT    current value, read only (never read by this driver)
 *   0x0c RESTART  write 1 to reload the counter from LOAD; never read
 * No other offset of the window is accessed.
 *
 * Choices:
 * - the block is never armed at probe; a block found enabled is reported
 *   as running (WDOG_HW_RUNNING) and is only reloaded, never reprogrammed;
 * - the block is never stopped unless allow_stop=1: stopping a running
 *   block has not been demonstrated, so the watchdog core keeps reloading
 *   it after /dev/watchdog is closed;
 * - the block raises its interrupt at the first expiry, LOAD periods after
 *   a reload, and resets the SoC by itself at the second one, 2 x LOAD
 *   periods after it (measured); that reset leaves
 *   the SoC in a state no kernel boots from (the boot freezes until a
 *   power cycle), while the software restart of fsoc3-reboot is clean.
 *   LOAD is therefore the requested delay: the first expiry is the
 *   watchdog event, and the interrupt turns it into a software
 *   restart; the reset of the block stays a last resort for a
 *   CPU that does not take the interrupt;
 * - the input clock comes from the "clock-frequency" property (no clock
 *   is described for this block); a value above the real one only makes
 *   the hardware delay longer than requested, never shorter;
 * - the interrupt, raised on expiry, restarts the SoC at once by the
 *   software restart (on_expiry=1, the default: emergency_restart, the
 *   end of the panic path without its "panic=" delay, which left only
 *   1.2 s before the reset of the block in a measurement),
 *   panics (on_expiry=2: trace, then "panic=") or is only logged
 *   (on_expiry=0); before a restart or a panic it reloads the counter
 *   once, so that the reset of the block comes 2 x LOAD after the
 *   interrupt (a panic restart wins while "panic=" stays below twice
 *   the delay: min_timeout covers panic=10);
 * - a running block is reprogrammed without being disabled first (LOAD,
 *   then reload, then enable), as the board firmware does; LOAD is read
 *   back and logged at each programming;
 * - an optional restart handler (restart_handler=1, off by default)
 *   restarts the SoC by a rising edge of bit 1 of the system manager
 *   register at offset 0x68, as fsoc3-reboot does; the system manager
 *   register at offset 0x64 is read once at probe and never written.
 */

#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/mfd/syscon.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/panic.h>
#include <linux/platform_device.h>
#include <linux/reboot.h>
#include <linux/regmap.h>
#include <linux/watchdog.h>

#define FSOC3_WDT_CTRL		0x00
#define FSOC3_WDT_LOAD		0x04
#define FSOC3_WDT_RESTART	0x0c
#define FSOC3_WDT_EN		BIT(0)

/* Writes to the block are spaced by 100 us; shorter spacing is untested. */
#define FSOC3_WDT_DELAY_US	100

#define FSOC3_SYSMGR_WDT	0x64	/* read only, logged at probe */
#define FSOC3_SYSMGR_RESET	0x68
#define FSOC3_SYSMGR_RESET_REQ	BIT(1)

#define FSOC3_WDT_DEFAULT_TIMEOUT	30
/* Above half of the panic timeout of the board (panic=10), see above. */
#define FSOC3_WDT_MIN_TIMEOUT		6

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, 0);
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started");

static unsigned int timeout;
module_param(timeout, uint, 0);
MODULE_PARM_DESC(timeout, "Timeout in seconds (default: DT timeout-sec, else 30)");

static bool allow_stop;
module_param(allow_stop, bool, 0444);
MODULE_PARM_DESC(allow_stop, "Stop the block by clearing its enable bit (default: never stop it)");

static unsigned int on_expiry = 1;
module_param(on_expiry, uint, 0644);
MODULE_PARM_DESC(on_expiry, "On the expiry interrupt: 0 log, 1 restart at once (default), 2 panic");

static bool restart_handler;
module_param(restart_handler, bool, 0444);
MODULE_PARM_DESC(restart_handler, "Register a restart handler (sysmgr+0x68 bit 1 edge, default: N)");

struct fsoc3_wdt {
	struct watchdog_device wdd;
	struct watchdog_ops ops;
	void __iomem *base;
	struct regmap *sysmgr;
	u32 rate;
	unsigned int expiries;
};

static void fsoc3_wdt_writel(struct fsoc3_wdt *wdt, u32 val, unsigned int reg)
{
	writel(val, wdt->base + reg);
	udelay(FSOC3_WDT_DELAY_US);
}

static u32 fsoc3_wdt_ticks(struct fsoc3_wdt *wdt, unsigned int secs)
{
	/* The first expiry, which raises the interrupt, ends the delay. */
	u64 ticks = (u64)secs * wdt->rate;

	return ticks > U32_MAX ? U32_MAX : (u32)ticks;
}

/*
 * Program the delay: a stopped block is kept disabled while LOAD is set; a
 * running one is reprogrammed in place (LOAD, reload, enable), as the
 * board firmware does on a running block.
 */
static void fsoc3_wdt_program(struct fsoc3_wdt *wdt, unsigned int secs)
{
	u32 load = fsoc3_wdt_ticks(wdt, secs);
	u32 ctrl = readl(wdt->base + FSOC3_WDT_CTRL);

	if (!(ctrl & FSOC3_WDT_EN))
		fsoc3_wdt_writel(wdt, 0, FSOC3_WDT_CTRL);
	fsoc3_wdt_writel(wdt, load, FSOC3_WDT_LOAD);
	fsoc3_wdt_writel(wdt, 1, FSOC3_WDT_RESTART);
	fsoc3_wdt_writel(wdt, ctrl | FSOC3_WDT_EN, FSOC3_WDT_CTRL);
	dev_info(wdt->wdd.parent, "%u s: LOAD %#010x, read back %#010x, CTRL %#010x\n",
		 secs, load, readl(wdt->base + FSOC3_WDT_LOAD),
		 readl(wdt->base + FSOC3_WDT_CTRL));
}

/* Delay given to the hardware: the core reloads it every half of it. */
static unsigned int fsoc3_wdt_hw_secs(struct watchdog_device *wdd)
{
	unsigned int max = wdd->max_hw_heartbeat_ms / 1000;

	return min(wdd->timeout, max ? max : 1);
}

static int fsoc3_wdt_start(struct watchdog_device *wdd)
{
	struct fsoc3_wdt *wdt = watchdog_get_drvdata(wdd);

	fsoc3_wdt_program(wdt, fsoc3_wdt_hw_secs(wdd));
	return 0;
}

static int fsoc3_wdt_stop(struct watchdog_device *wdd)
{
	struct fsoc3_wdt *wdt = watchdog_get_drvdata(wdd);

	/* Only reachable with allow_stop=1. */
	fsoc3_wdt_writel(wdt, 0, FSOC3_WDT_CTRL);
	return 0;
}

static int fsoc3_wdt_ping(struct watchdog_device *wdd)
{
	struct fsoc3_wdt *wdt = watchdog_get_drvdata(wdd);

	fsoc3_wdt_writel(wdt, 1, FSOC3_WDT_RESTART);
	return 0;
}

static int fsoc3_wdt_set_timeout(struct watchdog_device *wdd, unsigned int t)
{
	struct fsoc3_wdt *wdt = watchdog_get_drvdata(wdd);

	wdd->timeout = t;
	if (watchdog_active(wdd))
		fsoc3_wdt_program(wdt, fsoc3_wdt_hw_secs(wdd));
	return 0;
}

static int fsoc3_wdt_restart(struct watchdog_device *wdd, unsigned long action,
			     void *data)
{
	struct fsoc3_wdt *wdt = watchdog_get_drvdata(wdd);
	unsigned int val;

	if (regmap_read(wdt->sysmgr, FSOC3_SYSMGR_RESET, &val))
		return -EIO;

	/* Rising edge of the reset request: bit 1 low, then high. */
	regmap_write(wdt->sysmgr, FSOC3_SYSMGR_RESET, val & ~FSOC3_SYSMGR_RESET_REQ);
	regmap_write(wdt->sysmgr, FSOC3_SYSMGR_RESET, val | FSOC3_SYSMGR_RESET_REQ);
	mdelay(1000);
	return 0;
}

static irqreturn_t fsoc3_wdt_irq(int irq, void *dev_id)
{
	struct fsoc3_wdt *wdt = dev_id;

	wdt->expiries++;
	if (on_expiry == 1 || on_expiry == 2) {
		/* Push the reset of the block behind the software restart. */
		writel(1, wdt->base + FSOC3_WDT_RESTART);
		if (on_expiry == 2)
			panic("fsoc3-wdt: watchdog expired");
		pr_emerg("fsoc3-wdt: watchdog expired, restarting\n");
		emergency_restart();
	}
	pr_crit("fsoc3-wdt: expiry interrupt %u (logged only)\n", wdt->expiries);
	return IRQ_HANDLED;
}

static const struct watchdog_info fsoc3_wdt_info = {
	.options = WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING | WDIOF_MAGICCLOSE,
	.identity = "FortiSOC3 watchdog",
};

static int fsoc3_wdt_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fsoc3_wdt *wdt;
	unsigned int val;
	int irq, ret;

	wdt = devm_kzalloc(dev, sizeof(*wdt), GFP_KERNEL);
	if (!wdt)
		return -ENOMEM;

	if (of_property_read_u32(dev->of_node, "clock-frequency", &wdt->rate) ||
	    !wdt->rate)
		return dev_err_probe(dev, -EINVAL, "no clock-frequency\n");

	wdt->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(wdt->base))
		return PTR_ERR(wdt->base);

	wdt->sysmgr = syscon_regmap_lookup_by_phandle_optional(dev->of_node,
								"fortinet,sysmgr");
	if (IS_ERR(wdt->sysmgr))
		return dev_err_probe(dev, PTR_ERR(wdt->sysmgr), "bad system manager\n");
	if (restart_handler && !wdt->sysmgr)
		return dev_err_probe(dev, -EINVAL, "restart_handler needs fortinet,sysmgr\n");
	if (wdt->sysmgr && !regmap_read(wdt->sysmgr, FSOC3_SYSMGR_WDT, &val))
		dev_info(dev, "sysmgr+0x%02x = 0x%08x\n", FSOC3_SYSMGR_WDT, val);

	wdt->ops = (struct watchdog_ops) {
		.owner = THIS_MODULE,
		.start = fsoc3_wdt_start,
		.ping = fsoc3_wdt_ping,
		.set_timeout = fsoc3_wdt_set_timeout,
	};
	if (allow_stop)
		wdt->ops.stop = fsoc3_wdt_stop;
	if (restart_handler)
		wdt->ops.restart = fsoc3_wdt_restart;

	wdt->wdd.info = &fsoc3_wdt_info;
	wdt->wdd.ops = &wdt->ops;
	wdt->wdd.parent = dev;
	wdt->wdd.min_timeout = FSOC3_WDT_MIN_TIMEOUT;
	/* Largest delay whose LOAD still fits in 32 bits. */
	wdt->wdd.max_hw_heartbeat_ms = div_u64((u64)U32_MAX * 1000, wdt->rate);
	if (wdt->wdd.max_hw_heartbeat_ms < FSOC3_WDT_MIN_TIMEOUT * 1000)
		return dev_err_probe(dev, -EINVAL, "clock-frequency too high\n");
	wdt->wdd.timeout = FSOC3_WDT_DEFAULT_TIMEOUT;
	watchdog_init_timeout(&wdt->wdd, timeout, dev);
	watchdog_set_nowayout(&wdt->wdd, nowayout);
	watchdog_set_drvdata(&wdt->wdd, wdt);
	if (restart_handler)
		watchdog_set_restart_priority(&wdt->wdd, 128);

	/* The only read of the block at probe. */
	if (readl(wdt->base + FSOC3_WDT_CTRL) & FSOC3_WDT_EN)
		set_bit(WDOG_HW_RUNNING, &wdt->wdd.status);

	irq = platform_get_irq_optional(pdev, 0);
	if (irq > 0) {
		ret = devm_request_irq(dev, irq, fsoc3_wdt_irq, 0, "fsoc3-wdt", wdt);
		if (ret)
			return dev_err_probe(dev, ret, "cannot request the interrupt\n");
	}

	ret = devm_watchdog_register_device(dev, &wdt->wdd);
	if (ret)
		return ret;

	dev_info(dev, "%u Hz, max hw %u ms, timeout %u s, %s%s%s\n", wdt->rate,
		 wdt->wdd.max_hw_heartbeat_ms, wdt->wdd.timeout,
		 watchdog_hw_running(&wdt->wdd) ? "found running" : "stopped",
		 allow_stop ? ", stoppable" : ", never stopped",
		 restart_handler ? ", restart handler" : "");
	return 0;
}

static const struct of_device_id fsoc3_wdt_of_match[] = {
	{ .compatible = "fortinet,fsoc3-wdt" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc3_wdt_of_match);

static struct platform_driver fsoc3_wdt_driver = {
	.probe = fsoc3_wdt_probe,
	.driver = {
		.name = "fsoc3-wdt",
		.of_match_table = fsoc3_wdt_of_match,
	},
};
module_platform_driver(fsoc3_wdt_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC3 watchdog driver");
MODULE_LICENSE("GPL");
