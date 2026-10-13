// SPDX-License-Identifier: GPL-2.0-only
/*
 * Restart driver for the Fortinet FortiSOC3 (FortiGate 60E and 100E)
 *
 * The SoC is restarted by reading the system manager register at offset
 * 0x68, writing it back with bit 1 cleared, then with bit 1 set: the reset
 * is requested by the rising edge of that bit. A single masked write (syscon-reboot) would not produce the edge
 * if the bit were already set, hence this driver.
 *
 * This is the only system manager register written here, and only on
 * restart. The other bits of the register are written back unchanged.
 */

#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/mfd/syscon.h>
#include <linux/mod_devicetable.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/reboot.h>
#include <linux/regmap.h>

#define FSOC3_SYSMGR_RESET		0x68
#define FSOC3_SYSMGR_RESET_REQ		BIT(1)

static int fsoc3_restart(struct sys_off_data *data)
{
	struct regmap *map = data->cb_data;
	unsigned int val;

	if (regmap_read(map, FSOC3_SYSMGR_RESET, &val))
		return NOTIFY_DONE;

	/* Rising edge of the reset request: bit 1 low, then high. */
	regmap_write(map, FSOC3_SYSMGR_RESET, val & ~FSOC3_SYSMGR_RESET_REQ);
	regmap_write(map, FSOC3_SYSMGR_RESET, val | FSOC3_SYSMGR_RESET_REQ);

	mdelay(1000);
	pr_emerg("fsoc3-reboot: still running after the reset request\n");

	return NOTIFY_DONE;
}

static int fsoc3_reboot_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct regmap *map;
	unsigned int val;
	int ret;

	map = syscon_regmap_lookup_by_phandle(dev->of_node, "fortinet,sysmgr");
	if (IS_ERR(map))
		return dev_err_probe(dev, PTR_ERR(map), "no system manager\n");

	/* Read only: logged to check the state of the bit before a restart. */
	ret = regmap_read(map, FSOC3_SYSMGR_RESET, &val);
	if (ret)
		return dev_err_probe(dev, ret, "cannot read the reset register\n");
	dev_info(dev, "sysmgr+0x%02x = 0x%08x\n", FSOC3_SYSMGR_RESET, val);

	return devm_register_sys_off_handler(dev, SYS_OFF_MODE_RESTART,
					     SYS_OFF_PRIO_DEFAULT,
					     fsoc3_restart, map);
}

static const struct of_device_id fsoc3_reboot_of_match[] = {
	{ .compatible = "fortinet,fsoc3-reboot" },
	{ }
};

static struct platform_driver fsoc3_reboot_driver = {
	.probe = fsoc3_reboot_probe,
	.driver = {
		.name = "fsoc3-reboot",
		.of_match_table = fsoc3_reboot_of_match,
	},
};
builtin_platform_driver(fsoc3_reboot_driver);
