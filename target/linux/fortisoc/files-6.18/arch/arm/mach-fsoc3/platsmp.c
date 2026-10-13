// SPDX-License-Identifier: GPL-2.0-only
/*
 * Secondary CPU bring-up for the Fortinet FortiSOC3 (FortiGate 60E/100E)
 *
 * The four Cortex-A9 cores are started through the system manager:
 *  - bit 16 + n of the register at offset 0x74 is set (read-modify-
 *    write: the other bits of this register are left unchanged);
 *  - the physical address of the entry point, with bit 0 set, is then
 *    written to the register at offset 0xf0 + 4 * n.
 * These are the only system manager registers written here; no
 * cpuN-start-addr property is used. The SCU is enabled first.
 */

#include <linux/bits.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/printk.h>
#include <linux/smp.h>

#include <asm/smp_plat.h>
#include <asm/smp_scu.h>

#define FSOC3_SYSMGR_CPU_RELEASE	0x74
#define FSOC3_SYSMGR_CPU_RELEASE_BIT(n)	BIT(16 + (n))
#define FSOC3_SYSMGR_CPU_ENTRY(n)	(0xf0 + 4 * (n))
#define FSOC3_SYSMGR_CPU_ENTRY_VALID	BIT(0)

static void __iomem *fsoc3_sysmgr_base;

static void __init fsoc3_smp_prepare_cpus(unsigned int max_cpus)
{
	struct device_node *np;
	void __iomem *scu_base;

	np = of_find_compatible_node(NULL, NULL, "arm,cortex-a9-scu");
	scu_base = of_iomap(np, 0);
	of_node_put(np);
	if (!scu_base) {
		pr_err("fsoc3: no SCU, secondary CPUs left off\n");
		return;
	}
	scu_enable(scu_base);
	iounmap(scu_base);

	np = of_find_compatible_node(NULL, NULL, "fortinet,fsoc3-sysmgr");
	fsoc3_sysmgr_base = of_iomap(np, 0);
	of_node_put(np);
	if (!fsoc3_sysmgr_base)
		pr_err("fsoc3: no system manager, secondary CPUs left off\n");
}

static int fsoc3_boot_secondary(unsigned int cpu, struct task_struct *idle)
{
	u32 hwcpu = cpu_logical_map(cpu);
	u32 val;

	if (!fsoc3_sysmgr_base)
		return -ENODEV;
	if (hwcpu < 1 || hwcpu > 3)
		return -EINVAL;

	/* Release, then entry point: the core starts as soon as it is released. */
	val = readl(fsoc3_sysmgr_base + FSOC3_SYSMGR_CPU_RELEASE);
	writel(val | FSOC3_SYSMGR_CPU_RELEASE_BIT(hwcpu),
	       fsoc3_sysmgr_base + FSOC3_SYSMGR_CPU_RELEASE);
	writel(__pa_symbol(secondary_startup) | FSOC3_SYSMGR_CPU_ENTRY_VALID,
	       fsoc3_sysmgr_base + FSOC3_SYSMGR_CPU_ENTRY(hwcpu));

	return 0;
}

static const struct smp_operations fsoc3_smp_ops __initconst = {
	.smp_prepare_cpus	= fsoc3_smp_prepare_cpus,
	.smp_boot_secondary	= fsoc3_boot_secondary,
};
CPU_METHOD_OF_DECLARE(fsoc3_smp, "fortinet,fsoc3-smp", &fsoc3_smp_ops);
