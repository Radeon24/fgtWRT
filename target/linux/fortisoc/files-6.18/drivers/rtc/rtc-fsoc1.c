// SPDX-License-Identifier: GPL-2.0-only
/*
 * Real-time clock of the Fortinet FortiSOC1 (FortiGate 60C)
 *
 * A battery-backed Faraday block. The time reads from a single register:
 * a day count since 1970-01-01 in bits 31:17, then the hour, the minute
 * and the second of that day. Nothing else is read to get the time.
 *
 * Setting the time goes through other registers, loaded by a command in
 * the control register, whose meaning is not fully known: this driver does
 * not set the time. Nor does it ever
 * access the register at 0x10, where the boot loader keeps the speed of
 * its console across power cycles.
 */

#include <linux/bitfield.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/rtc.h>

#define FSOC1_RTC_STATUS	0x40
#define FSOC1_RTC_COUNT		0x44
#define  FSOC1_RTC_DAY		GENMASK(31, 17)
#define  FSOC1_RTC_HOUR		GENMASK(16, 12)
#define  FSOC1_RTC_MIN		GENMASK(11, 6)
#define  FSOC1_RTC_SEC		GENMASK(5, 0)

/* 15 bits of days: up to 2059-09-18 */
#define FSOC1_RTC_MAX		((time64_t)(FIELD_MAX(FSOC1_RTC_DAY) + 1) * \
				 86400 - 1)

struct fsoc1_rtc {
	void __iomem *base;
};

static int fsoc1_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct fsoc1_rtc *rtc = dev_get_drvdata(dev);
	unsigned int hour, min, sec;
	u32 v, prev;
	int tries = 3;

	/* Two equal reads in a row: no carry between the fields in flight */
	v = readl(rtc->base + FSOC1_RTC_COUNT);
	do {
		prev = v;
		v = readl(rtc->base + FSOC1_RTC_COUNT);
	} while (v != prev && --tries);
	if (v != prev)
		return -EIO;

	hour = FIELD_GET(FSOC1_RTC_HOUR, v);
	min = FIELD_GET(FSOC1_RTC_MIN, v);
	sec = FIELD_GET(FSOC1_RTC_SEC, v);
	if (hour > 23 || min > 59 || sec > 59)
		return -EINVAL;

	rtc_time64_to_tm((time64_t)FIELD_GET(FSOC1_RTC_DAY, v) * 86400 +
			 hour * 3600 + min * 60 + sec, tm);

	return 0;
}

static const struct rtc_class_ops fsoc1_rtc_ops = {
	.read_time = fsoc1_rtc_read_time,
};

static int fsoc1_rtc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rtc_device *rtc_dev;
	struct fsoc1_rtc *rtc;

	rtc = devm_kzalloc(dev, sizeof(*rtc), GFP_KERNEL);
	if (!rtc)
		return -ENOMEM;

	rtc->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(rtc->base))
		return PTR_ERR(rtc->base);

	platform_set_drvdata(pdev, rtc);

	dev_dbg(dev, "status %#x, count %#x\n",
		readl(rtc->base + FSOC1_RTC_STATUS),
		readl(rtc->base + FSOC1_RTC_COUNT));

	rtc_dev = devm_rtc_allocate_device(dev);
	if (IS_ERR(rtc_dev))
		return PTR_ERR(rtc_dev);

	rtc_dev->ops = &fsoc1_rtc_ops;
	rtc_dev->range_min = 0;
	rtc_dev->range_max = FSOC1_RTC_MAX;
	clear_bit(RTC_FEATURE_ALARM, rtc_dev->features);
	clear_bit(RTC_FEATURE_UPDATE_INTERRUPT, rtc_dev->features);

	return devm_rtc_register_device(rtc_dev);
}

static const struct of_device_id fsoc1_rtc_of_match[] = {
	{ .compatible = "fortinet,fsoc1-rtc" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc1_rtc_of_match);

static struct platform_driver fsoc1_rtc_driver = {
	.driver = {
		.name = "rtc-fsoc1",
		.of_match_table = fsoc1_rtc_of_match,
	},
	.probe = fsoc1_rtc_probe,
};
module_platform_driver(fsoc1_rtc_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC1 real-time clock driver");
MODULE_LICENSE("GPL");
