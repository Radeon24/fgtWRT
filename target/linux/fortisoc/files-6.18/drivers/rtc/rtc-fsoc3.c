// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet FortiSOC3 internal RTC, read-only by design: the block keeps
 * time on battery and is left as it was set
 *
 * Register layout established by observation, for interoperability: byte
 * registers 4 bytes apart, BCD.
 *
 *   +0x00 control (bit 7 = running, bit 6 = busy stopping, bit 5 = load;
 *         not written here)
 *   +0x08 status, bit 1 = update in progress (polled before reading)
 *   +0x14..+0x2c  time to load (the time-set registers, not written)
 *   +0x4c sec, +0x50 min, +0x54 hour, +0x58 wday, +0x5c mday,
 *   +0x60 month (1-12), +0x64 year (00-99, < 70 means 20xx)
 *
 * The block keeps time on battery: it is NEVER written here. No set_time,
 * no alarm, no ioctl; with RTC_HCTOSYS the system clock is read from it,
 * RTC_SYSTOHC must stay off (it needs set_time anyway).
 */

#include <linux/bcd.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/rtc.h>

#define FSOC3_RTC_CTRL		0x00
#define FSOC3_RTC_STATUS	0x08
#define FSOC3_RTC_STATUS_BUSY	BIT(1)
#define FSOC3_RTC_SEC		0x4c
#define FSOC3_RTC_MIN		0x50
#define FSOC3_RTC_HOUR		0x54
#define FSOC3_RTC_WDAY		0x58
#define FSOC3_RTC_MDAY		0x5c
#define FSOC3_RTC_MON		0x60
#define FSOC3_RTC_YEAR		0x64

#define FSOC3_RTC_TRIES		10000

struct fsoc3_rtc {
	struct rtc_device *rtc;
	void __iomem *base;
};

static int fsoc3_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct fsoc3_rtc *r = dev_get_drvdata(dev);
	void __iomem *b = r->base;
	u8 sec, min, hour, wday, mday, mon, year;
	int tries;

	for (tries = FSOC3_RTC_TRIES; tries; tries--) {
		if (!(readb(b + FSOC3_RTC_STATUS) & FSOC3_RTC_STATUS_BUSY))
			break;
		cpu_relax();
	}
	if (!tries)
		return -EBUSY;

	/* Seconds read before and after: retry if they changed in between */
	for (tries = FSOC3_RTC_TRIES; tries; tries--) {
		sec = readb(b + FSOC3_RTC_SEC);
		min = readb(b + FSOC3_RTC_MIN);
		hour = readb(b + FSOC3_RTC_HOUR);
		wday = readb(b + FSOC3_RTC_WDAY);
		mday = readb(b + FSOC3_RTC_MDAY);
		mon = readb(b + FSOC3_RTC_MON);
		year = readb(b + FSOC3_RTC_YEAR);
		if (readb(b + FSOC3_RTC_SEC) == sec)
			break;
	}
	if (!tries)
		return -EBUSY;

	tm->tm_sec = bcd2bin(sec & 0x7f);
	tm->tm_min = bcd2bin(min & 0x7f);
	tm->tm_hour = bcd2bin(hour & 0x3f);
	tm->tm_mday = bcd2bin(mday & 0x3f);
	tm->tm_mon = bcd2bin(mon & 0x1f) - 1;
	tm->tm_wday = bcd2bin(wday & 0x07);
	tm->tm_year = bcd2bin(year);
	if (tm->tm_year < 70)
		tm->tm_year += 100;

	return 0;
}

static const struct rtc_class_ops fsoc3_rtc_ops = {
	.read_time = fsoc3_rtc_read_time,
};

static int fsoc3_rtc_probe(struct platform_device *pdev)
{
	struct fsoc3_rtc *r;

	r = devm_kzalloc(&pdev->dev, sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	r->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(r->base))
		return PTR_ERR(r->base);

	platform_set_drvdata(pdev, r);

	dev_info(&pdev->dev, "read-only: control %#04x status %#04x\n",
		 readb(r->base + FSOC3_RTC_CTRL),
		 readb(r->base + FSOC3_RTC_STATUS));

	r->rtc = devm_rtc_allocate_device(&pdev->dev);
	if (IS_ERR(r->rtc))
		return PTR_ERR(r->rtc);

	r->rtc->ops = &fsoc3_rtc_ops;
	r->rtc->range_min = RTC_TIMESTAMP_BEGIN_2000;
	r->rtc->range_max = mktime64(2069, 12, 31, 23, 59, 59);

	return devm_rtc_register_device(r->rtc);
}

static const struct of_device_id fsoc3_rtc_of_match[] = {
	{ .compatible = "fortinet,fsoc3-rtc" },
	{ }
};

static struct platform_driver fsoc3_rtc_driver = {
	.driver = {
		.name = "fsoc3-rtc",
		.of_match_table = fsoc3_rtc_of_match,
	},
	.probe = fsoc3_rtc_probe,
};
builtin_platform_driver(fsoc3_rtc_driver);
