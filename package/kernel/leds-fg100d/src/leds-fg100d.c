// SPDX-License-Identifier: GPL-2.0-only
/*
 * Front LEDs of the Fortinet FortiGate 100D
 *
 * STATUS, HA and ALARM are two-colour LEDs behind a write-only
 * addressable latch, driven bit by bit through six GPIO lines of the
 * ICH8M (gpio-ich):
 *
 *   GPIO38       bank select, 0 = LEDs (never set to 1 here: the other
 *                bank drives bypass/PHY commands)
 *   GPIO29/7/6   address of the LED channel (A2/A1/A0)
 *   GPIO1        data, 1 = channel on
 *   GPIO17       strobe, the latch takes the data on a 0-1-0 pulse
 *
 * A change of one channel is written as: GPIO38 <- 0, address, data,
 * GPIO17 <- 1, GPIO17 <- 0, the strobe at rest before and after. The
 * latch cannot be read back: the brightness shown is the last one
 * written.
 *
 * The board has no DMI table and no ACPI: it is recognised from its PCI
 * fingerprint (ICH8M LPC bridge, BCM53314 switch, NET2282 USB device
 * controller). The lines are taken as they are (GPIOD_ASIS): nothing is
 * written when the module is loaded or removed, only when the brightness
 * of a LED is changed. A line found configured as an input means this is
 * not the expected board: the driver then gives up without writing.
 *
 * Module parameters:
 *   channels  bitmap of the LEDs to register (bit 0 green:status, 1
 *             red:status, 2 green:ha, 3 red:ha, 4 red:alarm, 5
 *             amber:alarm), all by default
 *   dry_run   log the writes instead of doing them
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio/machine.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/platform_device.h>

#define DRV_NAME	"leds-fg100d"
#define FG100D_GPIO_CHIP "gpio_ich"
/* NET2282 USB device controller: legacy NetChip vendor ID */
#define FG100D_PCI_VENDOR_NETCHIP	0x17cc

enum {
	FG100D_SEL,
	FG100D_A2,
	FG100D_A1,
	FG100D_A0,
	FG100D_DATA,
	FG100D_STROBE,
	FG100D_NUM_LINES,
};

static const char *const fg100d_line_name[FG100D_NUM_LINES] = {
	[FG100D_SEL] = "sel",
	[FG100D_A2] = "a2",
	[FG100D_A1] = "a1",
	[FG100D_A0] = "a0",
	[FG100D_DATA] = "data",
	[FG100D_STROBE] = "strobe",
};

static struct gpiod_lookup_table fg100d_gpio_lookup = {
	.dev_id = DRV_NAME,
	.table = {
		GPIO_LOOKUP(FG100D_GPIO_CHIP, 38, "sel", GPIO_ACTIVE_HIGH),
		GPIO_LOOKUP(FG100D_GPIO_CHIP, 29, "a2", GPIO_ACTIVE_HIGH),
		GPIO_LOOKUP(FG100D_GPIO_CHIP, 7, "a1", GPIO_ACTIVE_HIGH),
		GPIO_LOOKUP(FG100D_GPIO_CHIP, 6, "a0", GPIO_ACTIVE_HIGH),
		GPIO_LOOKUP(FG100D_GPIO_CHIP, 1, "data", GPIO_ACTIVE_HIGH),
		GPIO_LOOKUP(FG100D_GPIO_CHIP, 17, "strobe", GPIO_ACTIVE_HIGH),
		{ }
	},
};

/* Latch address of each channel: A2 (GPIO29), A1 (GPIO7), A0 (GPIO6) */
static const struct {
	const char *name;
	u8 addr;
} fg100d_led_desc[] = {
	{ "green:status", 0x5 },
	{ "red:status", 0x4 },
	{ "green:ha", 0x3 },
	{ "red:ha", 0x2 },
	{ "red:alarm", 0x0 },
	{ "amber:alarm", 0x1 },
};

#define FG100D_ALL_CHANNELS	GENMASK(ARRAY_SIZE(fg100d_led_desc) - 1, 0)

static uint channels = FG100D_ALL_CHANNELS;
module_param(channels, uint, 0444);
MODULE_PARM_DESC(channels,
		 "LEDs to register, bit 0 green:status, 1 red:status, 2 green:ha, 3 red:ha, 4 red:alarm, 5 amber:alarm (default: all)");

static bool dry_run;
module_param(dry_run, bool, 0444);
MODULE_PARM_DESC(dry_run, "Log the writes to the LED latch instead of doing them");

struct fg100d_leds;

struct fg100d_led {
	struct led_classdev cdev;
	struct fg100d_leds *priv;
	u8 addr;
};

struct fg100d_leds {
	struct device *dev;
	struct gpio_desc *line[FG100D_NUM_LINES];
	struct mutex lock;	/* one latch write at a time */
	bool removing;
	struct fg100d_led led[];
};

static int fg100d_set(struct fg100d_leds *priv, int line, int value)
{
	int err;

	/* never select the other bank of the latch */
	if (WARN_ON(line == FG100D_SEL && value))
		return -EINVAL;

	err = gpiod_set_raw_value(priv->line[line], value);
	if (err)
		dev_err(priv->dev, "cannot set %s to %d: %d\n",
			fg100d_line_name[line], value, err);
	return err;
}

static int fg100d_led_set(struct led_classdev *cdev,
			  enum led_brightness brightness)
{
	struct fg100d_led *led = container_of(cdev, struct fg100d_led, cdev);
	struct fg100d_leds *priv = led->priv;
	int data = brightness ? 1 : 0;
	int err;

	mutex_lock(&priv->lock);

	/* No write while the LEDs are being unregistered */
	if (priv->removing) {
		err = 0;
		goto out;
	}

	if (dry_run) {
		dev_info(priv->dev, "%s: would write address %u data %d\n",
			 cdev->name, led->addr, data);
		err = 0;
		goto out;
	}

	err = fg100d_set(priv, FG100D_SEL, 0);
	if (!err)
		err = fg100d_set(priv, FG100D_A2, !!(led->addr & 0x4));
	if (!err)
		err = fg100d_set(priv, FG100D_A1, !!(led->addr & 0x2));
	if (!err)
		err = fg100d_set(priv, FG100D_A0, !!(led->addr & 0x1));
	if (!err)
		err = fg100d_set(priv, FG100D_DATA, data);
	if (err)
		goto out;

	udelay(1);
	err = fg100d_set(priv, FG100D_STROBE, 1);
	udelay(1);
	/* back to rest even if raising the strobe failed */
	if (fg100d_set(priv, FG100D_STROBE, 0) && !err)
		err = -EIO;

out:
	mutex_unlock(&priv->lock);
	return err;
}

static int fg100d_leds_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fg100d_leds *priv;
	unsigned int i, n = 0;
	int err;

	priv = devm_kzalloc(dev, struct_size(priv, led,
					     ARRAY_SIZE(fg100d_led_desc)),
			    GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->dev = dev;
	mutex_init(&priv->lock);

	/*
	 * Lines taken as they are: requesting them reads the use and
	 * direction registers of the ICH8M, nothing is written.
	 */
	for (i = 0; i < FG100D_NUM_LINES; i++) {
		priv->line[i] = devm_gpiod_get(dev, fg100d_line_name[i],
					       GPIOD_ASIS);
		if (IS_ERR(priv->line[i]))
			return dev_err_probe(dev, PTR_ERR(priv->line[i]),
					     "no GPIO line %s\n",
					     fg100d_line_name[i]);

		err = gpiod_get_direction(priv->line[i]);
		if (err < 0)
			return dev_err_probe(dev, err,
					     "direction of %s unknown\n",
					     fg100d_line_name[i]);
		/* gpiod_get_direction(): 0 output, 1 input */
		if (err) {
			dev_err(dev, "line %s is an input: not the expected board, nothing written\n",
				fg100d_line_name[i]);
			return -ENODEV;
		}
	}

	dev_info(dev, "latch lines: sel %d address %d%d%d data %d strobe %d%s\n",
		 gpiod_get_raw_value(priv->line[FG100D_SEL]),
		 gpiod_get_raw_value(priv->line[FG100D_A2]),
		 gpiod_get_raw_value(priv->line[FG100D_A1]),
		 gpiod_get_raw_value(priv->line[FG100D_A0]),
		 gpiod_get_raw_value(priv->line[FG100D_DATA]),
		 gpiod_get_raw_value(priv->line[FG100D_STROBE]),
		 dry_run ? " (dry run)" : "");

	for (i = 0; i < ARRAY_SIZE(fg100d_led_desc); i++) {
		struct fg100d_led *led = &priv->led[n];

		if (!(channels & BIT(i)))
			continue;

		led->priv = priv;
		led->addr = fg100d_led_desc[i].addr;
		led->cdev.name = fg100d_led_desc[i].name;
		led->cdev.max_brightness = 1;
		led->cdev.brightness = LED_OFF;
		led->cdev.brightness_set_blocking = fg100d_led_set;
		/* no write when unregistered */
		led->cdev.flags = LED_RETAIN_AT_SHUTDOWN;

		err = devm_led_classdev_register(dev, &led->cdev);
		if (err)
			return dev_err_probe(dev, err, "cannot register %s\n",
					     led->cdev.name);
		n++;
	}

	platform_set_drvdata(pdev, priv);
	dev_info(dev, "%u LEDs registered, state unknown until written\n", n);
	return 0;
}

static void fg100d_leds_remove(struct platform_device *pdev)
{
	struct fg100d_leds *priv = platform_get_drvdata(pdev);

	/*
	 * Unregistering a LED with a trigger turns it off: the LEDs are
	 * left as they are instead.
	 */
	mutex_lock(&priv->lock);
	priv->removing = true;
	mutex_unlock(&priv->lock);
}

static struct platform_driver fg100d_leds_driver = {
	.driver = {
		.name = DRV_NAME,
	},
	.probe = fg100d_leds_probe,
	.remove = fg100d_leds_remove,
};

static struct platform_device *fg100d_leds_pdev;

static bool __init fg100d_pci_has(unsigned int vendor, unsigned int device)
{
	struct pci_dev *pdev = pci_get_device(vendor, device, NULL);

	pci_dev_put(pdev);
	return pdev != NULL;
}

static int __init fg100d_leds_init(void)
{
	int err;

	/* ICH8M LPC bridge, BCM53314 switch, NET2282 USB device controller */
	if (!fg100d_pci_has(PCI_VENDOR_ID_INTEL, 0x2815) ||
	    !fg100d_pci_has(PCI_VENDOR_ID_BROADCOM, 0xc314) ||
	    !fg100d_pci_has(FG100D_PCI_VENDOR_NETCHIP, 0x2282)) {
		pr_info("not a FortiGate 100D\n");
		return -ENODEV;
	}

	if (!(channels & FG100D_ALL_CHANNELS)) {
		pr_info("no LED selected\n");
		return -EINVAL;
	}

	gpiod_add_lookup_table(&fg100d_gpio_lookup);

	err = platform_driver_register(&fg100d_leds_driver);
	if (err)
		goto err_lookup;

	fg100d_leds_pdev = platform_device_register_simple(DRV_NAME,
							   PLATFORM_DEVID_NONE,
							   NULL, 0);
	if (IS_ERR(fg100d_leds_pdev)) {
		err = PTR_ERR(fg100d_leds_pdev);
		goto err_driver;
	}

	return 0;

err_driver:
	platform_driver_unregister(&fg100d_leds_driver);
err_lookup:
	gpiod_remove_lookup_table(&fg100d_gpio_lookup);
	return err;
}
module_init(fg100d_leds_init);

static void __exit fg100d_leds_exit(void)
{
	platform_device_unregister(fg100d_leds_pdev);
	platform_driver_unregister(&fg100d_leds_driver);
	gpiod_remove_lookup_table(&fg100d_gpio_lookup);
}
module_exit(fg100d_leds_exit);

MODULE_DESCRIPTION("Fortinet FortiGate 100D front LEDs");
MODULE_LICENSE("GPL");
