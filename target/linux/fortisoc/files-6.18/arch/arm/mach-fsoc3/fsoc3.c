// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet FortiSOC3 (FortiGate 60E and 100E)
 *
 * The generic DT machine would do, except for the PL310 L2 cache
 * controller: it is only set up for a machine that gives L2C auxiliary
 * control values. This machine keeps the auxiliary control value left by
 * the boot loader (value 0, mask ~0); latencies, prefetch and power control
 * are not set either (the device tree has no such property), so the boot
 * loader values are kept.
 *
 * The accelerator coherency port (ACP) is fronted by a block of eleven
 * profiles, 0x20 apart (node "fortinet,fsoc3-acp"). The boot loader leaves
 * profiles 1-10 unvalidated: masters that rely on the ACP (the NP6Lite
 * with bits 39:32 of its DMA addresses at 0x27) then see stale lines. They
 * are programmed in the init_irq hook, before the L2 cache controller is
 * set up, with the values below; their meaning is not documented (ID
 * ranges and AXI attributes, presumably).
 */

#include <linux/init.h>
#include <linux/io.h>
#include <linux/irqchip.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include <asm/mach/arch.h>

static const u32 fsoc3_acp_profile[][2] __initconst = {
	{ 0x003f0020, 0x0003 }, { 0x001f0000, 0x1302 }, { 0x005f0040, 0x1302 },
	{ 0x007f0060, 0x1302 }, { 0x011f0100, 0x1302 }, { 0x009f0080, 0x1302 },
	{ 0x00bf00a0, 0x1302 }, { 0x00df00c0, 0x1302 }, { 0x013f0120, 0x1302 },
	{ 0x021f0200, 0x1302 }, { 0x023f0220, 0x1302 },
};

static void __init fsoc3_acp_init(void)
{
	struct device_node *np;
	void __iomem *acp;
	unsigned int i;

	np = of_find_compatible_node(NULL, NULL, "fortinet,fsoc3-acp");
	if (!np)
		return;
	acp = of_iomap(np, 0);
	of_node_put(np);
	if (!acp) {
		pr_err("fsoc3: cannot map the ACP profiles\n");
		return;
	}
	for (i = 0; i < ARRAY_SIZE(fsoc3_acp_profile); i++) {
		void __iomem *b = acp + 0x20 * i;
		u32 range = fsoc3_acp_profile[i][0], attr = fsoc3_acp_profile[i][1];

		writel(range, b + 0x00);
		writel(range, b + 0x10);
		writel(attr, b + 0x08);
		writel(attr, b + 0x18);
		writel(3, b + 0x04);
		writel(1, b + 0x14);
	}
	iounmap(acp);
	pr_info("fsoc3: %u ACP profiles programmed\n", i);
}

static void __init fsoc3_init_irq(void)
{
	fsoc3_acp_init();
	irqchip_init();
}

static const char *const fsoc3_dt_compat[] __initconst = {
	"fortinet,fsoc3",
	NULL
};

DT_MACHINE_START(FSOC3_DT, "Fortinet FortiSOC3")
	.l2c_aux_val	= 0,
	.l2c_aux_mask	= ~0,
	.init_irq	= fsoc3_init_irq,
	.dt_compat	= fsoc3_dt_compat,
MACHINE_END
