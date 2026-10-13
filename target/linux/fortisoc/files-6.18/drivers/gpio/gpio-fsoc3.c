// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet FortiSOC3 GPIO block, read-only by design: the network processor
 * driver owns the lines it drives
 *
 * 32 lines in the "msc" block of the NP6Lite (physical 0xf500fc00, inside the
 * network processor window that its own driver maps: the window is mapped
 * here without being requested). GPIO block registers, layout established
 * by observation, for interoperability:
 *
 *   +0x00 IN       input level           +0x48 OUT_CLR  output clear (write 1)
 *   +0x08 OUT      output latch / set    +0x50 OE_CLR   direction clear = input
 *   +0x10 OE       direction (1 = output)
 *   +0x30 INT_ENABLE, +0x38 INT_STATUS (interrupts)
 *
 * get() reads the output latch for an output line and the input level for
 * an input line. It has no set(), direction_input() nor
 * direction_output() and never writes a register: the lines driven by the
 * network processor driver (PHY and switch resets, MDC) stay its business,
 * and gpio-reserved-ranges keeps them from being requested here.
 */

#include <linux/bits.h>
#include <linux/gpio/driver.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>

#define FSOC3_GPIO_IN		0x00
#define FSOC3_GPIO_OUT		0x08
#define FSOC3_GPIO_OE		0x10
#define FSOC3_GPIO_INT_ENABLE	0x30
#define FSOC3_GPIO_INT_STATUS	0x38

struct fsoc3_gpio {
	struct gpio_chip gc;
	void __iomem *base;
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
	g->gc.dbg_show = fsoc3_gpio_dbg_show;

	dev_info(dev, "read-only: in %#010x out %#010x oe %#010x int_enable %#010x\n",
		 readl(g->base + FSOC3_GPIO_IN), readl(g->base + FSOC3_GPIO_OUT),
		 readl(g->base + FSOC3_GPIO_OE),
		 readl(g->base + FSOC3_GPIO_INT_ENABLE));

	return devm_gpiochip_add_data(dev, &g->gc, g);
}

static const struct of_device_id fsoc3_gpio_of_match[] = {
	{ .compatible = "fortinet,fsoc3-gpio" },
	{ }
};

static struct platform_driver fsoc3_gpio_driver = {
	.driver = {
		.name = "fsoc3-gpio",
		.of_match_table = fsoc3_gpio_of_match,
	},
	.probe = fsoc3_gpio_probe,
};
builtin_platform_driver(fsoc3_gpio_driver);
