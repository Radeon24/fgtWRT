// SPDX-License-Identifier: GPL-2.0-only
/*
 * I2C master driver for the Fortinet FortiSOC3
 *
 * The FortiSOC3 (FortiGate 60E, 100E) has two I2C controllers of the
 * NEC/Renesas IICA family, at 0xfb004000 and 0xfb005000. The control bits
 * are those of the IICA (and of i2c-emev2), but the register map differs:
 * the control register is split in two, the status is a 16-bit register
 * and there is no separate enable register. Register layout established by
 * observation, for interoperability:
 *
 *   +0x00  data (8 bits)
 *   +0x08  control 0: bit 7 enable, bit 2 stop interrupt enable,
 *          bit 1 wait timing (1: 9th clock), bit 0 acknowledge enable
 *   +0x0c  control 1: bit 2 wait release, bit 1 start, bit 0 stop
 *   +0x10  status (16 bits): bit 8 acknowledge detected, bit 6 bus busy,
 *          bit 0 arbitration lost
 *   +0x20  flags: bit 1 start without stop detection
 *   +0x24  SCL low width, +0x28 SCL high width (16 bits)
 *
 * Two edge interrupts: transfer interrupt (index 0) and stop interrupt
 * (index 1). Neither needs to be acknowledged.
 *
 * The meaning of control 0 bits 0-2 is deduced from observed sequences
 * (initial value 0x86, set 0x03 before a start, clear bit 1 before a read).
 * A multi-byte read acknowledges every byte but the last.
 *
 * Only master mode, 7-bit addresses. By default the driver refuses any
 * write but the one-byte register pointer of a combined write-then-read
 * transfer, and zero-length messages (no SMBus quick command): the bus can
 * be scanned with "i2cdetect -r" and registers read with i2cget, nothing
 * can be written to a device (module parameter "allow_write" to lift it).
 */

#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#define FSOC3_I2C_DATA		0x00
#define FSOC3_I2C_CTL0		0x08
#define FSOC3_I2C_CTL1		0x0c
#define FSOC3_I2C_STAT		0x10
#define FSOC3_I2C_FLAG		0x20
#define FSOC3_I2C_WL		0x24
#define FSOC3_I2C_WH		0x28

#define FSOC3_I2C_CTL0_IICE	BIT(7)
#define FSOC3_I2C_CTL0_SPIE	BIT(2)
#define FSOC3_I2C_CTL0_WTIM	BIT(1)
#define FSOC3_I2C_CTL0_ACKE	BIT(0)

#define FSOC3_I2C_CTL1_WREL	BIT(2)
#define FSOC3_I2C_CTL1_STT	BIT(1)
#define FSOC3_I2C_CTL1_SPT	BIT(0)

#define FSOC3_I2C_STAT_ACKD	BIT(8)
#define FSOC3_I2C_STAT_BSY	BIT(6)
#define FSOC3_I2C_STAT_ALD	BIT(0)

#define FSOC3_I2C_FLAG_STCEN	BIT(1)

/* Initial control 0 (enable, stop interrupt, 9th clock wait), SCL widths */
#define FSOC3_I2C_CTL0_INIT	(FSOC3_I2C_CTL0_IICE | FSOC3_I2C_CTL0_SPIE | \
				 FSOC3_I2C_CTL0_WTIM)
#define FSOC3_I2C_WL_VAL	0x29c
#define FSOC3_I2C_WH_VAL	0x2f2

static bool allow_write;
module_param(allow_write, bool, 0444);
MODULE_PARM_DESC(allow_write, "Allow writes to I2C devices (default: register pointer of a read only)");

struct fsoc3_i2c {
	struct device *dev;
	void __iomem *base;
	struct i2c_adapter adap;
	struct completion xfer_done;
	struct completion stop_done;
};

static void fsoc3_i2c_set8(struct fsoc3_i2c *priv, unsigned int reg, u8 clr, u8 set)
{
	writeb((readb(priv->base + reg) & ~clr) | set, priv->base + reg);
}

/* Returns the status register, or a negative error */
static int fsoc3_i2c_wait(struct fsoc3_i2c *priv, struct completion *c)
{
	u16 st;

	if (!wait_for_completion_timeout(c, priv->adap.timeout)) {
		dev_dbg(priv->dev, "timeout, status %#06x\n",
			readw(priv->base + FSOC3_I2C_STAT));
		return -ETIMEDOUT;
	}

	st = readw(priv->base + FSOC3_I2C_STAT);
	return st & FSOC3_I2C_STAT_ALD ? -EAGAIN : st;
}

static void fsoc3_i2c_reset(struct fsoc3_i2c *priv)
{
	int retries;

	if (readb(priv->base + FSOC3_I2C_CTL0) & FSOC3_I2C_CTL0_IICE) {
		writeb(0, priv->base + FSOC3_I2C_CTL0);
		retries = 1000;
		while ((readb(priv->base + FSOC3_I2C_CTL0) & FSOC3_I2C_CTL0_IICE) &&
		       --retries)
			;
		WARN_ON(!retries);
	}

	writeb(FSOC3_I2C_FLAG_STCEN, priv->base + FSOC3_I2C_FLAG);
	writeb(FSOC3_I2C_CTL0_INIT, priv->base + FSOC3_I2C_CTL0);
	retries = 1000;
	while (!(readb(priv->base + FSOC3_I2C_CTL0) & FSOC3_I2C_CTL0_IICE) &&
	       --retries)
		;
	WARN_ON(!retries);

	writew(FSOC3_I2C_WL_VAL, priv->base + FSOC3_I2C_WL);
	writew(FSOC3_I2C_WH_VAL, priv->base + FSOC3_I2C_WH);
}

static void fsoc3_i2c_stop(struct fsoc3_i2c *priv)
{
	int ret;

	reinit_completion(&priv->stop_done);
	fsoc3_i2c_set8(priv, FSOC3_I2C_CTL1, 0, FSOC3_I2C_CTL1_SPT);
	ret = fsoc3_i2c_wait(priv, &priv->stop_done);
	if (ret < 0)
		dev_dbg(priv->dev, "stop: %d\n", ret);
}

static int fsoc3_i2c_xfer_msg(struct fsoc3_i2c *priv, struct i2c_msg *msg,
			      bool last)
{
	bool read = msg->flags & I2C_M_RD;
	int i, st;

	/* Start condition, address and direction, 9th clock wait */
	reinit_completion(&priv->xfer_done);
	fsoc3_i2c_set8(priv, FSOC3_I2C_CTL0, 0,
		       FSOC3_I2C_CTL0_ACKE | FSOC3_I2C_CTL0_WTIM);
	fsoc3_i2c_set8(priv, FSOC3_I2C_CTL1, 0, FSOC3_I2C_CTL1_STT);
	writeb(i2c_8bit_addr_from_msg(msg), priv->base + FSOC3_I2C_DATA);
	st = fsoc3_i2c_wait(priv, &priv->xfer_done);
	if (st < 0)
		goto out_reset;
	if (!(st & FSOC3_I2C_STAT_ACKD)) {
		fsoc3_i2c_stop(priv);
		return -ENXIO;
	}

	if (read) {
		/* 8th clock wait: data available before the acknowledge */
		reinit_completion(&priv->xfer_done);
		fsoc3_i2c_set8(priv, FSOC3_I2C_CTL0, FSOC3_I2C_CTL0_WTIM, 0);
		fsoc3_i2c_set8(priv, FSOC3_I2C_CTL1, 0, FSOC3_I2C_CTL1_WREL);
		st = fsoc3_i2c_wait(priv, &priv->xfer_done);
		if (st < 0)
			goto out_reset;

		for (i = 0; i < msg->len; i++) {
			msg->buf[i] = readb(priv->base + FSOC3_I2C_DATA);
			reinit_completion(&priv->xfer_done);
			/* Last byte: no acknowledge, 9th clock wait */
			if (i == msg->len - 1)
				fsoc3_i2c_set8(priv, FSOC3_I2C_CTL0,
					       FSOC3_I2C_CTL0_ACKE,
					       FSOC3_I2C_CTL0_WTIM);
			fsoc3_i2c_set8(priv, FSOC3_I2C_CTL1, 0,
				       FSOC3_I2C_CTL1_WREL);
			st = fsoc3_i2c_wait(priv, &priv->xfer_done);
			if (st < 0)
				goto out_reset;
		}
	} else {
		for (i = 0; i < msg->len; i++) {
			reinit_completion(&priv->xfer_done);
			writeb(msg->buf[i], priv->base + FSOC3_I2C_DATA);
			st = fsoc3_i2c_wait(priv, &priv->xfer_done);
			if (st < 0)
				goto out_reset;
			if (!(st & FSOC3_I2C_STAT_ACKD)) {
				fsoc3_i2c_stop(priv);
				return -EIO;
			}
		}
	}

	if (last)
		fsoc3_i2c_stop(priv);

	return 0;

out_reset:
	dev_dbg(priv->dev, "addr %#04x: %d, resetting\n", msg->addr, st);
	fsoc3_i2c_reset(priv);
	return st;
}

static int fsoc3_i2c_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs,
			  int num)
{
	struct fsoc3_i2c *priv = i2c_get_adapdata(adap);
	int i, ret;

	/* Read-only guard: a write only as the register pointer of a read */
	for (i = 0; i < num && !allow_write; i++) {
		if (msgs[i].flags & I2C_M_RD)
			continue;
		if (msgs[i].len != 1 || i + 1 >= num ||
		    !(msgs[i + 1].flags & I2C_M_RD)) {
			dev_warn_ratelimited(priv->dev,
					     "write to %#04x refused (read-only)\n",
					     msgs[i].addr);
			return -EPERM;
		}
	}

	if (readw(priv->base + FSOC3_I2C_STAT) & FSOC3_I2C_STAT_BSY)
		return -EAGAIN;

	for (i = 0; i < num; i++) {
		ret = fsoc3_i2c_xfer_msg(priv, &msgs[i], i == num - 1);
		if (ret < 0)
			return ret;
	}

	return num;
}

static u32 fsoc3_i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | (I2C_FUNC_SMBUS_EMUL & ~I2C_FUNC_SMBUS_QUICK);
}

static const struct i2c_algorithm fsoc3_i2c_algo = {
	.xfer = fsoc3_i2c_xfer,
	.functionality = fsoc3_i2c_func,
};

static const struct i2c_adapter_quirks fsoc3_i2c_quirks = {
	.flags = I2C_AQ_NO_ZERO_LEN,
};

static irqreturn_t fsoc3_i2c_xfer_irq(int irq, void *dev_id)
{
	struct fsoc3_i2c *priv = dev_id;

	complete(&priv->xfer_done);
	return IRQ_HANDLED;
}

static irqreturn_t fsoc3_i2c_stop_irq(int irq, void *dev_id)
{
	struct fsoc3_i2c *priv = dev_id;

	complete(&priv->stop_done);
	return IRQ_HANDLED;
}

static int fsoc3_i2c_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fsoc3_i2c *priv;
	struct clk *clk;
	int irq, ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->dev = dev;

	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	clk = devm_clk_get_optional_enabled(dev, NULL);
	if (IS_ERR(clk))
		return PTR_ERR(clk);

	init_completion(&priv->xfer_done);
	init_completion(&priv->stop_done);

	dev_info(dev, "before reset: ctl0 %#04x ctl1 %#04x stat %#06x flag %#04x wl %#06x wh %#06x\n",
		 readb(priv->base + FSOC3_I2C_CTL0),
		 readb(priv->base + FSOC3_I2C_CTL1),
		 readw(priv->base + FSOC3_I2C_STAT),
		 readb(priv->base + FSOC3_I2C_FLAG),
		 readw(priv->base + FSOC3_I2C_WL),
		 readw(priv->base + FSOC3_I2C_WH));

	fsoc3_i2c_reset(priv);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;
	ret = devm_request_irq(dev, irq, fsoc3_i2c_xfer_irq, 0,
			       dev_name(dev), priv);
	if (ret)
		return ret;

	irq = platform_get_irq(pdev, 1);
	if (irq < 0)
		return irq;
	ret = devm_request_irq(dev, irq, fsoc3_i2c_stop_irq, 0,
			       dev_name(dev), priv);
	if (ret)
		return ret;

	strscpy(priv->adap.name, "FortiSOC3 I2C", sizeof(priv->adap.name));
	priv->adap.owner = THIS_MODULE;
	priv->adap.algo = &fsoc3_i2c_algo;
	priv->adap.quirks = &fsoc3_i2c_quirks;
	priv->adap.timeout = msecs_to_jiffies(200);
	priv->adap.retries = 0;
	priv->adap.dev.parent = dev;
	priv->adap.dev.of_node = dev->of_node;
	i2c_set_adapdata(&priv->adap, priv);
	platform_set_drvdata(pdev, priv);

	ret = i2c_add_adapter(&priv->adap);
	if (ret)
		return ret;

	dev_info(dev, "ctl0 %#04x stat %#06x, %s\n",
		 readb(priv->base + FSOC3_I2C_CTL0),
		 readw(priv->base + FSOC3_I2C_STAT),
		 allow_write ? "writes allowed" : "read-only");
	return 0;
}

static void fsoc3_i2c_remove(struct platform_device *pdev)
{
	struct fsoc3_i2c *priv = platform_get_drvdata(pdev);

	i2c_del_adapter(&priv->adap);
	writeb(0, priv->base + FSOC3_I2C_CTL0);
}

static const struct of_device_id fsoc3_i2c_of_match[] = {
	{ .compatible = "fortinet,fsoc3-i2c" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc3_i2c_of_match);

static struct platform_driver fsoc3_i2c_driver = {
	.probe = fsoc3_i2c_probe,
	.remove = fsoc3_i2c_remove,
	.driver = {
		.name = "fsoc3-i2c",
		.of_match_table = fsoc3_i2c_of_match,
	},
};
module_platform_driver(fsoc3_i2c_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC3 I2C master driver");
MODULE_LICENSE("GPL");
