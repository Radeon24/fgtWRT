// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet FortiSOC3 GPIO lines: the GPIO block of the network processor
 * and the output lines of the system manager
 *
 * fortinet,fsoc3-gpio: 32 lines in the "msc" block of the NP6Lite
 * (physical 0xf500fc00, inside the network processor window that its own
 * driver maps: the window is mapped here without being requested). GPIO
 * block registers, layout established by observation, for
 * interoperability:
 *
 *   +0x00 IN       input level           +0x48 OUT_CLR  output clear (write 1)
 *   +0x08 OUT      output set (write 1)  +0x50 OE_CLR   direction clear (write 1)
 *                  / output latch (read)
 *   +0x10 OE       direction set (write 1) / direction (read, 1 = output)
 *   +0x30 INT_ENABLE, +0x38 INT_STATUS (interrupts, never written)
 *
 * Every write sets or clears the bits written as 1 and leaves the others
 * alone, so no read-modify-write is needed and the lines driven by the
 * network processor driver (PHY and switch resets, MDC), kept from being
 * requested here by gpio-reserved-ranges, are never touched. get() reads
 * the output latch for an output line and the input level for an input
 * line. A line is made an output with its level already set, as the
 * board firmware does. Some front panel LEDs of the FortiGate 60E are
 * bicolour LEDs between two lines of this block: both lines must be
 * outputs for either colour to light.
 *
 * fortinet,fsoc3-sysmgr-gpio: output lines of the system manager
 * (fortinet,fsoc3-sysmgr, through its syscon regmap), bit n of three of
 * its registers for line n:
 *
 *   +0xc0 SEL      1 = the pin is a general purpose line
 *   +0xc8 DATA     output level
 *   +0xd0 OE       1 = the output is driven
 *
 * The boot loader leaves some lines set up. Lines are output only; the
 * device tree lists the usable ones (gpio-reserved-ranges covers the
 * others, which are never written). A line is set up when it is made an
 * output, in the order SEL, DATA, OE; a register whose bit already holds
 * the value is not written.
 */

#include <linux/bits.h>
#include <linux/gpio/driver.h>
#include <linux/io.h>
#include <linux/mfd/syscon.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/seq_file.h>

#define FSOC3_GPIO_IN		0x00
#define FSOC3_GPIO_OUT		0x08
#define FSOC3_GPIO_OE		0x10
#define FSOC3_GPIO_INT_ENABLE	0x30
#define FSOC3_GPIO_INT_STATUS	0x38
#define FSOC3_GPIO_OUT_CLR	0x48
#define FSOC3_GPIO_OE_CLR	0x50

#define FSOC3_SYSMGR_GPIO_SEL	0xc0
#define FSOC3_SYSMGR_GPIO_DATA	0xc8
#define FSOC3_SYSMGR_GPIO_OE	0xd0

struct fsoc3_gpio {
	struct gpio_chip gc;
	void __iomem *base;
};

struct fsoc3_sysmgr_gpio {
	struct gpio_chip gc;
	struct regmap *sysmgr;
};

static int fsoc3_gpio_get_direction(struct gpio_chip *gc, unsigned int offset)
{
	struct fsoc3_gpio *g = gpiochip_get_data(gc);

	return readl(g->base + FSOC3_GPIO_OE) & BIT(offset) ?
		GPIO_LINE_DIRECTION_OUT : GPIO_LINE_DIRECTION_IN;
}

static int fsoc3_gpio_get(struct gpio_chip *gc, unsigned int offset)
{
	struct fsoc3_gpio *g = gpiochip_get_data(gc);
	u32 reg = readl(g->base + FSOC3_GPIO_OE) & BIT(offset) ?
		  FSOC3_GPIO_OUT : FSOC3_GPIO_IN;

	return !!(readl(g->base + reg) & BIT(offset));
}

static int fsoc3_gpio_set(struct gpio_chip *gc, unsigned int offset, int value)
{
	struct fsoc3_gpio *g = gpiochip_get_data(gc);

	writel(BIT(offset), g->base + (value ? FSOC3_GPIO_OUT : FSOC3_GPIO_OUT_CLR));
	return 0;
}

static int fsoc3_gpio_direction_output(struct gpio_chip *gc, unsigned int offset,
				       int value)
{
	struct fsoc3_gpio *g = gpiochip_get_data(gc);

	fsoc3_gpio_set(gc, offset, value);
	writel(BIT(offset), g->base + FSOC3_GPIO_OE);
	return 0;
}

static int fsoc3_gpio_direction_input(struct gpio_chip *gc, unsigned int offset)
{
	struct fsoc3_gpio *g = gpiochip_get_data(gc);

	writel(BIT(offset), g->base + FSOC3_GPIO_OE_CLR);
	return 0;
}

/* All 32 lines, reserved ones included (reading never changes them). */
static void fsoc3_gpio_dbg_show(struct seq_file *s, struct gpio_chip *gc)
{
	struct fsoc3_gpio *g = gpiochip_get_data(gc);
	u32 in = readl(g->base + FSOC3_GPIO_IN);
	u32 latch = readl(g->base + FSOC3_GPIO_OUT);
	u32 oe = readl(g->base + FSOC3_GPIO_OE);
	u32 inten = readl(g->base + FSOC3_GPIO_INT_ENABLE);
	u32 intst = readl(g->base + FSOC3_GPIO_INT_STATUS);
	unsigned int i;

	seq_printf(s, " in %08x out %08x oe %08x int_enable %08x int_status %08x\n",
		   in, latch, oe, inten, intst);
	for (i = 0; i < gc->ngpio; i++) {
		bool out = oe & BIT(i);

		seq_printf(s, " line %2u: %-3s %s in=%u%s%s\n", i,
			   out ? "out" : "in",
			   ((out ? latch : in) & BIT(i)) ? "hi" : "lo",
			   !!(in & BIT(i)),
			   inten & BIT(i) ? " irq" : "",
			   gpiochip_line_is_valid(gc, i) ? "" : " reserved");
	}
}

static int fsoc3_gpio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fsoc3_gpio *g;
	struct resource *res;

	g = devm_kzalloc(dev, sizeof(*g), GFP_KERNEL);
	if (!g)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -EINVAL;
	/* Inside the NP6Lite window: map, do not request */
	g->base = devm_ioremap(dev, res->start, resource_size(res));
	if (!g->base)
		return -ENOMEM;

	g->gc.label = dev_name(dev);
	g->gc.parent = dev;
	g->gc.owner = THIS_MODULE;
	g->gc.base = -1;
	g->gc.ngpio = 32;
	g->gc.get_direction = fsoc3_gpio_get_direction;
	g->gc.get = fsoc3_gpio_get;
	g->gc.set = fsoc3_gpio_set;
	g->gc.direction_output = fsoc3_gpio_direction_output;
	g->gc.direction_input = fsoc3_gpio_direction_input;
	g->gc.dbg_show = fsoc3_gpio_dbg_show;

	dev_info(dev, "in %#010x out %#010x oe %#010x int_enable %#010x\n",
		 readl(g->base + FSOC3_GPIO_IN), readl(g->base + FSOC3_GPIO_OUT),
		 readl(g->base + FSOC3_GPIO_OE),
		 readl(g->base + FSOC3_GPIO_INT_ENABLE));

	return devm_gpiochip_add_data(dev, &g->gc, g);
}

static int fsoc3_sysmgr_gpio_get_direction(struct gpio_chip *gc, unsigned int offset)
{
	return GPIO_LINE_DIRECTION_OUT;
}

static int fsoc3_sysmgr_gpio_get(struct gpio_chip *gc, unsigned int offset)
{
	struct fsoc3_sysmgr_gpio *g = gpiochip_get_data(gc);
	unsigned int val;
	int ret;

	ret = regmap_read(g->sysmgr, FSOC3_SYSMGR_GPIO_DATA, &val);
	if (ret)
		return ret;
	return !!(val & BIT(offset));
}

static int fsoc3_sysmgr_gpio_set(struct gpio_chip *gc, unsigned int offset,
				 int value)
{
	struct fsoc3_sysmgr_gpio *g = gpiochip_get_data(gc);

	return regmap_update_bits(g->sysmgr, FSOC3_SYSMGR_GPIO_DATA, BIT(offset),
				  value ? BIT(offset) : 0);
}

static int fsoc3_sysmgr_gpio_direction_output(struct gpio_chip *gc,
					      unsigned int offset, int value)
{
	struct fsoc3_sysmgr_gpio *g = gpiochip_get_data(gc);
	int ret;

	ret = regmap_update_bits(g->sysmgr, FSOC3_SYSMGR_GPIO_SEL, BIT(offset),
				 BIT(offset));
	if (!ret)
		ret = fsoc3_sysmgr_gpio_set(gc, offset, value);
	if (!ret)
		ret = regmap_update_bits(g->sysmgr, FSOC3_SYSMGR_GPIO_OE,
					 BIT(offset), BIT(offset));
	return ret;
}

static int fsoc3_sysmgr_gpio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fsoc3_sysmgr_gpio *g;
	unsigned int sel, data, oe;

	g = devm_kzalloc(dev, sizeof(*g), GFP_KERNEL);
	if (!g)
		return -ENOMEM;

	g->sysmgr = syscon_regmap_lookup_by_phandle(dev->of_node, "fortinet,sysmgr");
	if (IS_ERR(g->sysmgr))
		return dev_err_probe(dev, PTR_ERR(g->sysmgr), "no system manager\n");

	g->gc.label = dev_name(dev);
	g->gc.parent = dev;
	g->gc.owner = THIS_MODULE;
	g->gc.base = -1;
	g->gc.ngpio = 32;
	g->gc.can_sleep = true;
	g->gc.get_direction = fsoc3_sysmgr_gpio_get_direction;
	g->gc.get = fsoc3_sysmgr_gpio_get;
	g->gc.set = fsoc3_sysmgr_gpio_set;
	g->gc.direction_output = fsoc3_sysmgr_gpio_direction_output;

	if (!regmap_read(g->sysmgr, FSOC3_SYSMGR_GPIO_SEL, &sel) &&
	    !regmap_read(g->sysmgr, FSOC3_SYSMGR_GPIO_DATA, &data) &&
	    !regmap_read(g->sysmgr, FSOC3_SYSMGR_GPIO_OE, &oe))
		dev_info(dev, "sel %#010x data %#010x oe %#010x\n", sel, data, oe);

	return devm_gpiochip_add_data(dev, &g->gc, g);
}

static const struct of_device_id fsoc3_gpio_of_match[] = {
	{ .compatible = "fortinet,fsoc3-gpio", .data = fsoc3_gpio_probe },
	{ .compatible = "fortinet,fsoc3-sysmgr-gpio", .data = fsoc3_sysmgr_gpio_probe },
	{ }
};

static int fsoc3_gpio_dispatch(struct platform_device *pdev)
{
	int (*probe)(struct platform_device *pdev) = device_get_match_data(&pdev->dev);

	return probe ? probe(pdev) : -ENODEV;
}

static struct platform_driver fsoc3_gpio_driver = {
	.driver = {
		.name = "fsoc3-gpio",
		.of_match_table = fsoc3_gpio_of_match,
	},
	.probe = fsoc3_gpio_dispatch,
};
builtin_platform_driver(fsoc3_gpio_driver);
