// SPDX-License-Identifier: GPL-2.0-only
/*
 * Real-time clock of the Fortinet FortiSOC2
 *
 * The battery-backed clock is three registers of the system control unit
 * (SCU) at 0xe5100200, binary coded, with no alarm and no interrupt known.
 * Offsets below are from the start of the RTC resource:
 *
 *   0x00 time     seconds [6:0], minutes [14:8], hours [21:16]
 *   0x04 date     day [5:0], month [12:8] (1-12), year of the century
 *                 [23:16], century [31:24]
 *   0x10 control  bit 0 runs the clock, and is cleared while the time is
 *                 written; bit 8 follows bit 0 once the clock has taken
 *                 the change, and is clear if the clock was never set
 *
 * This is the layout and the write sequence of the boot loader (U-Boot
 * "date" command). The control register is left alone when reading: the time is read until it is seen unchanged
 * around the date.
 *
 * The register at 0x0c, between the date and the control register, holds
 * the console baud rate of the boot loader.
 * This driver never accesses it: it only reads and writes the three
 * registers above, one whole register at a time. How the clock handles
 * leap years and centuries is not known: the range is kept to 2000-2099.
 */

#include <linux/bitfield.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/rtc.h>

#define FSOC2_RTC_TIME		0x00
#define FSOC2_RTC_DATE		0x04
#define FSOC2_RTC_CTRL		0x10

#define FSOC2_RTC_TIME_SEC	GENMASK(6, 0)
#define FSOC2_RTC_TIME_MIN	GENMASK(14, 8)
#define FSOC2_RTC_TIME_HOUR	GENMASK(21, 16)

#define FSOC2_RTC_DATE_DAY	GENMASK(5, 0)
#define FSOC2_RTC_DATE_MON	GENMASK(12, 8)
#define FSOC2_RTC_DATE_YEAR	GENMASK(23, 16)
#define FSOC2_RTC_DATE_CENTURY	GENMASK(31, 24)

#define FSOC2_RTC_CTRL_EN	BIT(0)
#define FSOC2_RTC_CTRL_RUNNING	BIT(8)

/* How long bit 8 of the control register may take to follow bit 0 */
#define FSOC2_RTC_POLL_US	1000
#define FSOC2_RTC_TIMEOUT_US	2000000

struct fsoc2_rtc {
	void __iomem *base;
	struct rtc_device *rtc;
};

static int fsoc2_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct fsoc2_rtc *rtc = dev_get_drvdata(dev);
	u32 time, date, again;
	int i;

	if (!(readl(rtc->base + FSOC2_RTC_CTRL) & FSOC2_RTC_CTRL_RUNNING))
		return -EINVAL;

	/* Without the latch, a date read across midnight would not match */
	for (i = 0; i < 3; i++) {
		time = readl(rtc->base + FSOC2_RTC_TIME);
		date = readl(rtc->base + FSOC2_RTC_DATE);
		again = readl(rtc->base + FSOC2_RTC_TIME);
		if (time == again)
			break;
	}
	if (time != again)
		return -EBUSY;

	tm->tm_sec = FIELD_GET(FSOC2_RTC_TIME_SEC, time);
	tm->tm_min = FIELD_GET(FSOC2_RTC_TIME_MIN, time);
	tm->tm_hour = FIELD_GET(FSOC2_RTC_TIME_HOUR, time);
	tm->tm_mday = FIELD_GET(FSOC2_RTC_DATE_DAY, date);
	tm->tm_mon = FIELD_GET(FSOC2_RTC_DATE_MON, date) - 1;
	tm->tm_year = FIELD_GET(FSOC2_RTC_DATE_CENTURY, date) * 100 +
		      FIELD_GET(FSOC2_RTC_DATE_YEAR, date) - 1900;

	return 0;
}

static int fsoc2_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct fsoc2_rtc *rtc = dev_get_drvdata(dev);
	unsigned int year = tm->tm_year + 1900;
	u32 ctrl, val, time, date;
	int ret, err;

	time = FIELD_PREP(FSOC2_RTC_TIME_SEC, tm->tm_sec) |
	       FIELD_PREP(FSOC2_RTC_TIME_MIN, tm->tm_min) |
	       FIELD_PREP(FSOC2_RTC_TIME_HOUR, tm->tm_hour);
	date = FIELD_PREP(FSOC2_RTC_DATE_DAY, tm->tm_mday) |
	       FIELD_PREP(FSOC2_RTC_DATE_MON, tm->tm_mon + 1) |
	       FIELD_PREP(FSOC2_RTC_DATE_YEAR, year % 100) |
	       FIELD_PREP(FSOC2_RTC_DATE_CENTURY, year / 100);

	ctrl = readl(rtc->base + FSOC2_RTC_CTRL);

	/* Stop the clock, and wait for it to have stopped */
	writel(ctrl & ~FSOC2_RTC_CTRL_EN, rtc->base + FSOC2_RTC_CTRL);
	ret = readl_poll_timeout(rtc->base + FSOC2_RTC_CTRL, val,
				 !(val & FSOC2_RTC_CTRL_RUNNING),
				 FSOC2_RTC_POLL_US, FSOC2_RTC_TIMEOUT_US);
	if (!ret) {
		writel(time, rtc->base + FSOC2_RTC_TIME);
		writel(date, rtc->base + FSOC2_RTC_DATE);
	}

	/* Run it again in any case, then wait for it to have started */
	writel(ctrl | FSOC2_RTC_CTRL_EN, rtc->base + FSOC2_RTC_CTRL);
	err = readl_poll_timeout(rtc->base + FSOC2_RTC_CTRL, val,
				 val & FSOC2_RTC_CTRL_RUNNING,
				 FSOC2_RTC_POLL_US, FSOC2_RTC_TIMEOUT_US);

	return ret ?: err;
}

static const struct rtc_class_ops fsoc2_rtc_ops = {
	.read_time = fsoc2_rtc_read_time,
	.set_time = fsoc2_rtc_set_time,
};

static int fsoc2_rtc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fsoc2_rtc *rtc;

	rtc = devm_kzalloc(dev, sizeof(*rtc), GFP_KERNEL);
	if (!rtc)
		return -ENOMEM;

	rtc->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(rtc->base))
		return PTR_ERR(rtc->base);

	if (!(readl(rtc->base + FSOC2_RTC_CTRL) & FSOC2_RTC_CTRL_RUNNING))
		dev_warn(dev, "clock not running, time not valid\n");

	platform_set_drvdata(pdev, rtc);

	rtc->rtc = devm_rtc_allocate_device(dev);
	if (IS_ERR(rtc->rtc))
		return PTR_ERR(rtc->rtc);

	rtc->rtc->ops = &fsoc2_rtc_ops;
	rtc->rtc->range_min = RTC_TIMESTAMP_BEGIN_2000;
	rtc->rtc->range_max = RTC_TIMESTAMP_END_2099;

	return devm_rtc_register_device(rtc->rtc);
}

static const struct of_device_id fsoc2_rtc_of_match[] = {
	{ .compatible = "fortinet,fsoc2-rtc" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc2_rtc_of_match);

static struct platform_driver fsoc2_rtc_driver = {
	.driver = {
		.name = "fsoc2-rtc",
		.of_match_table = fsoc2_rtc_of_match,
	},
	.probe = fsoc2_rtc_probe,
};
module_platform_driver(fsoc2_rtc_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC2 RTC driver");
MODULE_LICENSE("GPL");
