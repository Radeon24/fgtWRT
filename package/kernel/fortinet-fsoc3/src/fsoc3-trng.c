// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet FortiSOC3 true random number generator
 *
 * The generator sits in the miscellaneous block of the NP6Lite window
 * (0xf5000000 + 0xff80, established on the FortiGate 100E). That window is
 * requested by the NP6Lite driver: this driver maps its 64 bytes without
 * requesting them, as the GPIO driver does for its own block.
 *
 * The registers are 64 bits apart (bit 2 of the offset is ignored); the
 * names are those of the vendor firmware (FortiOS 6.4 "diagnose cp soc3
 * reg"). Registers used (32 bits, offsets from the start of the node's
 * window), as measured on the 100E:
 *   0x00 trng_cfg   configuration. The boot loader leaves 0x08000cbe: the
 *                   generator runs for the other engines but the host FIFO
 *                   stays empty. The value of the vendor firmware,
 *                   0x09fe0082, fills it; it reads back as 0x09fe00be (bits
 *                   2-5 cannot be cleared), as in the vendor firmware.
 *   0x28 wr_to_rd   a write (of 0) pops one word from the FIFO into the
 *                   latch, a read returns the latch
 *   0x30 fifo_rnum  number of words in the FIFO, read only: 0x10 within
 *                   100 ms of the trng_cfg write, one less per pop
 * Register only read for a debug message at probe: 0x18 tf_cnt (always 0
 * here). The other registers of the window (PLL, interrupt timer, debug)
 * are never accessed.
 *
 * About 770 bytes per second come out (limited by the refill of the FIFO,
 * not by the CPU). The output passes the FIPS 140-2 tests of rngtest, which
 * says nothing of its entropy: whether it is raw or conditioned is unknown,
 * so it is credited as 1 bit per 8 (quality 128), which
 * /sys/class/misc/hw_random/rng_quality can change.
 */

#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#define FSOC3_TRNG_CFG		0x00
#define FSOC3_TRNG_TF_CNT	0x18
#define FSOC3_TRNG_WR_TO_RD	0x28
#define FSOC3_TRNG_FIFO_RNUM	0x30
#define FSOC3_TRNG_SIZE		0x40

#define FSOC3_TRNG_CFG_HOST	0x09fe0082

/* Longest wait for one word when the caller may sleep */
#define FSOC3_TRNG_TIMEOUT_US	20000
/* Longest wait for the first words after the trng_cfg write (seen: < 100 ms) */
#define FSOC3_TRNG_START_US	1000000

struct fsoc3_trng {
	void __iomem *base;
	struct hwrng rng;
};

static int fsoc3_trng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	struct fsoc3_trng *t = container_of(rng, struct fsoc3_trng, rng);
	size_t done = 0, n;
	u32 level, word;
	int ret;

	while (done < max) {
		level = readl(t->base + FSOC3_TRNG_FIFO_RNUM);
		if (!level) {
			if (!wait || done)
				break;
			ret = readl_poll_timeout(t->base + FSOC3_TRNG_FIFO_RNUM,
						 level, level,
						 10, FSOC3_TRNG_TIMEOUT_US);
			if (ret)
				return ret;
		}

		writel(0, t->base + FSOC3_TRNG_WR_TO_RD);
		/*
		 * The time the pop takes to reach the latch is unknown: 1 us
		 * is far more than any number of cycles it could take.
		 */
		udelay(1);
		word = readl(t->base + FSOC3_TRNG_WR_TO_RD);

		n = min(max - done, sizeof(word));
		memcpy(buf + done, &word, n);
		done += n;
	}

	return done;
}

static int fsoc3_trng_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fsoc3_trng *t;
	struct resource *res;
	u32 cfg, level;
	int ret;

	t = devm_kzalloc(dev, sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res || resource_size(res) < FSOC3_TRNG_SIZE)
		return dev_err_probe(dev, -EINVAL, "no window of 0x%x bytes\n",
				     FSOC3_TRNG_SIZE);
	/* Inside the NP6Lite window, requested by its driver: not requested */
	t->base = devm_ioremap(dev, res->start, FSOC3_TRNG_SIZE);
	if (!t->base)
		return -ENOMEM;

	cfg = readl(t->base + FSOC3_TRNG_CFG);
	dev_dbg(dev, "tf_cnt 0x%08x fifo_rnum 0x%08x\n",
		readl(t->base + FSOC3_TRNG_TF_CNT),
		readl(t->base + FSOC3_TRNG_FIFO_RNUM));

	writel(FSOC3_TRNG_CFG_HOST, t->base + FSOC3_TRNG_CFG);
	dev_info(dev, "cfg 0x%08x, wrote 0x%08x, reads 0x%08x\n", cfg,
		 FSOC3_TRNG_CFG_HOST, readl(t->base + FSOC3_TRNG_CFG));

	ret = readl_poll_timeout(t->base + FSOC3_TRNG_FIFO_RNUM, level, level,
				 1000, FSOC3_TRNG_START_US);
	if (ret)
		return dev_err_probe(dev, ret, "FIFO still empty after %u ms\n",
				     FSOC3_TRNG_START_US / 1000);

	t->rng.name = dev_name(dev);
	t->rng.read = fsoc3_trng_read;
	t->rng.quality = 128;

	ret = devm_hwrng_register(dev, &t->rng);
	if (ret)
		return dev_err_probe(dev, ret, "cannot register the hwrng\n");

	dev_info(dev, "hwrng registered, FIFO level %u\n", level);
	return 0;
}

static const struct of_device_id fsoc3_trng_of_match[] = {
	{ .compatible = "fortinet,fsoc3-trng" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc3_trng_of_match);

static struct platform_driver fsoc3_trng_driver = {
	.probe = fsoc3_trng_probe,
	.driver = {
		.name = "fsoc3-trng",
		.of_match_table = fsoc3_trng_of_match,
	},
};
module_platform_driver(fsoc3_trng_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC3 true random number generator");
MODULE_LICENSE("GPL");
