// SPDX-License-Identifier: GPL-2.0-only
/*
 * Read-only access to the factory block of the Fortinet FortiSOC3 boot flash
 *
 * The FortiGate 60E keeps its boot loader, and its factory data (base MAC
 * address, serial number), in a SPI NOR
 * flash (a Macronix 16 Mbit part, JEDEC c2 20 15, on the unit examined) behind
 * a small command port of the SoC at 0xfd300000, driven one byte at a time:
 *  - +0x14 <- 1 ends a transaction (chip select released); the next access
 *    to +0x10 starts one;
 *  - +0x10 written: one byte sent (command, address); +0x18 bit 0 is set
 *    until it is out;
 *  - +0x10 read: one byte clocked in and returned;
 *  - +0x08 is left by the boot loader; bit 3 enables the command port;
 *    +0x00, +0x04 and +0x0c are not touched.
 * The factory block is the 32 KiB at 0x1f8000 of the 2 MiB boot loader area
 * at offset 0 of the flash, whatever the size of the flash.
 * The base MAC address is the 6 bytes at 0x5880 into that block, port i
 * getting the base + i.
 *
 * This driver exposes that block as a read-only NVMEM device and nothing
 * more. Three commands may reach the flash, each checked against a fixed
 * list before any register is accessed: read identification (0x9f), read
 * status (0x05) and read (0x03, 3-byte address), its address bounded to
 * the factory block. No command that writes or changes a state of the
 * flash (write enable, status write, program, erase, reset, power down)
 * can be sent: there is no other path to the port. The driver keeps away
 * from a flash it does not know: a few manufacturers and families of
 * 2 to 16 MiB whose identification gives the size as a power of two.
 *
 * Only the bytes of the base MAC address are ever read from the block (the
 * rest is kept out of the NVMEM device: the serial number is not read). A
 * "mac-base" cell gets its index added, so that the ports can take the
 * base + their rank from the device tree; a base that is not a unicast
 * address is refused, and the ports then fall back to random addresses.
 * No failure of this driver stops the boot.
 *
 * Experimental, tested on the FortiGate 60E only.
 */

#include <linux/bits.h>
#include <linux/etherdevice.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nvmem-provider.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/sizes.h>

#define FB_CTRL			0x08	/* left by the boot loader */
#define FB_CTRL_EN		BIT(3)	/* enables the command port */
#define FB_DATA			0x10	/* write: byte out; read: byte in */
#define FB_END			0x14	/* 1: end of transaction */
#define FB_STATUS		0x18
#define FB_STATUS_BUSY		BIT(0)	/* byte being sent */

/* Polled after each byte sent, for 50 ms at most */
#define FB_POLL_US		1
#define FB_TIMEOUT_US		50000

/*
 * Factory block: 0x1f8000 into the 2 MiB boot loader area,
 * at offset 0 of the flash, whatever its size (the last 32 KiB of a 2 MiB
 * part)
 */
#define FB_BLOCK		0x1f8000
#define FB_BLOCK_SIZE		SZ_32K
/* Base MAC address in the block: the only bytes read from it */
#define FB_MAC			0x5880

/* Capacity byte of the identification: log2 of the size, 2 to 16 MiB */
#define FB_CAP_MIN		0x15
#define FB_CAP_MAX		0x18

#define SPINOR_RDID		0x9f
#define SPINOR_RDSR		0x05
#define SPINOR_READ		0x03	/* 3-byte address */

struct fsoc3_bf {
	struct device *dev;
	void __iomem *base;
	struct mutex lock;	/* one transaction at a time */
};

/* The only commands that reach the flash: reads, data in */
static const struct fsoc3_bf_cmd {
	u8 opcode;
	u8 addr_nbytes;
	u8 max_len;		/* 0: no limit but the block */
} fsoc3_bf_cmds[] = {
	{ SPINOR_RDID, 0, 6 },
	{ SPINOR_RDSR, 0, 2 },
	{ SPINOR_READ, 3, 0 },
};

/*
 * Flashes taken: manufacturer and memory type of the identification, for
 * families whose third byte is log2 of the size (2 to 16 MiB here). Other
 * encodings are left out, e.g. the Spansion S25FL-A/P parts (type 0x02,
 * 01 02 15 = 4 MiB), the other Spansion parts of type 0x20 but the
 * 16 MiB ones, and the other memory types of manufacturer 0x20 (also used
 * by XMC).
 */
static const struct fsoc3_bf_part {
	u8 mfr;
	u8 type;
	u8 cap_min;
	u8 cap_max;
	const char *name;
} fsoc3_bf_parts[] = {
	{ 0xc2, 0x20, FB_CAP_MIN, FB_CAP_MAX, "Macronix MX25L" },
	{ 0xc2, 0x23, FB_CAP_MIN, FB_CAP_MAX, "Macronix MX25V" },
	{ 0xc2, 0x25, FB_CAP_MIN, FB_CAP_MAX, "Macronix MX25U" },
	{ 0xc2, 0x28, FB_CAP_MIN, FB_CAP_MAX, "Macronix MX25R" },
	{ 0xef, 0x30, FB_CAP_MIN, FB_CAP_MAX, "Winbond W25X" },
	{ 0xef, 0x40, FB_CAP_MIN, FB_CAP_MAX, "Winbond W25Q" },
	{ 0xef, 0x60, FB_CAP_MIN, FB_CAP_MAX, "Winbond W25Q (1.8 V)" },
	{ 0xef, 0x70, FB_CAP_MIN, FB_CAP_MAX, "Winbond W25Q (JV-M)" },
	{ 0xc8, 0x40, FB_CAP_MIN, FB_CAP_MAX, "GigaDevice GD25Q" },
	{ 0xc8, 0x60, FB_CAP_MIN, FB_CAP_MAX, "GigaDevice GD25LQ" },
	{ 0x01, 0x40, FB_CAP_MIN, FB_CAP_MAX, "Spansion S25FL1-K" },
	{ 0x01, 0x60, FB_CAP_MIN, FB_CAP_MAX, "Spansion S25FL-L" },
	{ 0x01, 0x20, 0x18, 0x18, "Spansion S25FL128S/P" },
	{ 0x9d, 0x40, FB_CAP_MIN, FB_CAP_MAX, "ISSI IS25LQ" },
	{ 0x9d, 0x60, FB_CAP_MIN, FB_CAP_MAX, "ISSI IS25LP" },
	{ 0x9d, 0x70, FB_CAP_MIN, FB_CAP_MAX, "ISSI IS25WP" },
	{ 0x20, 0x20, FB_CAP_MIN, FB_CAP_MAX, "Micron M25P" },
	{ 0x20, 0x71, FB_CAP_MIN, FB_CAP_MAX, "Micron M25PX" },
	{ 0x20, 0x80, FB_CAP_MIN, FB_CAP_MAX, "Micron M25PE" },
	{ 0x20, 0xba, FB_CAP_MIN, FB_CAP_MAX, "Micron N25Q/MT25QL" },
	{ 0x20, 0xbb, FB_CAP_MIN, FB_CAP_MAX, "Micron N25Q/MT25QU" },
};

/* Fortinet, Inc. MA-L assignments (IEEE registry): only warned about */
static const u8 fsoc3_bf_ouis[][3] = {
	{ 0x00, 0x09, 0x0f }, { 0x00, 0x0c, 0xe6 }, { 0x04, 0x01, 0xa1 },
	{ 0x04, 0xd5, 0x90 }, { 0x08, 0x5b, 0x0e }, { 0x1c, 0xd1, 0x1a },
	{ 0x38, 0xc0, 0xea }, { 0x48, 0x3a, 0x02 }, { 0x5c, 0x63, 0xb0 },
	{ 0x68, 0xcc, 0xae }, { 0x70, 0x4c, 0xa5 }, { 0x74, 0x78, 0xa6 },
	{ 0x78, 0x18, 0xec }, { 0x80, 0x5a, 0x70 }, { 0x80, 0x80, 0x2c },
	{ 0x84, 0x39, 0x8f }, { 0x90, 0x6c, 0xac }, { 0x94, 0xf3, 0x92 },
	{ 0x94, 0xff, 0x3c }, { 0xac, 0x71, 0x2e }, { 0xb4, 0xb2, 0xe9 },
	{ 0xd4, 0x76, 0xa0 }, { 0xd4, 0xb4, 0xc0 }, { 0xe0, 0x23, 0xff },
	{ 0xe8, 0x1c, 0xba }, { 0xe8, 0xed, 0xd6 },
};

static const struct fsoc3_bf_cmd *fsoc3_bf_allowed(u8 opcode, u32 addr,
						   size_t len)
{
	unsigned int i;

	if (!len)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(fsoc3_bf_cmds); i++) {
		const struct fsoc3_bf_cmd *c = &fsoc3_bf_cmds[i];

		if (c->opcode != opcode)
			continue;
		if (c->max_len && len > c->max_len)
			return NULL;
		/* data reads: the factory block only */
		if (c->addr_nbytes &&
		    (addr < FB_BLOCK || len > FB_BLOCK_SIZE ||
		     addr - FB_BLOCK > FB_BLOCK_SIZE - len))
			return NULL;
		return c;
	}

	return NULL;
}

static int fsoc3_bf_out(struct fsoc3_bf *bf, u8 byte)
{
	u32 status;

	writel(byte, bf->base + FB_DATA);
	return readl_poll_timeout_atomic(bf->base + FB_STATUS, status,
					 !(status & FB_STATUS_BUSY),
					 FB_POLL_US, FB_TIMEOUT_US);
}

/* One command, its address (big endian), then len bytes in. Under bf->lock. */
static int fsoc3_bf_cmd(struct fsoc3_bf *bf, u8 opcode, u32 addr, u8 *buf,
			size_t len)
{
	const struct fsoc3_bf_cmd *c;
	unsigned int i;
	int ret;

	/* Before any access: nothing but one of the reads reaches the flash */
	c = fsoc3_bf_allowed(opcode, addr, len);
	if (!c) {
		dev_warn_ratelimited(bf->dev, "command %#x (%#x, %zu bytes) refused\n",
				     opcode, addr, len);
		return -EPERM;
	}

	writel(1, bf->base + FB_END);
	ret = fsoc3_bf_out(bf, opcode);
	for (i = 0; !ret && i < c->addr_nbytes; i++)
		ret = fsoc3_bf_out(bf, addr >> (8 * (c->addr_nbytes - 1 - i)));
	for (i = 0; !ret && i < len; i++) {
		buf[i] = readl(bf->base + FB_DATA);
		if (!((i + 1) & (SZ_4K - 1)))
			cond_resched();
	}
	writel(1, bf->base + FB_END);

	if (ret)
		dev_err_ratelimited(bf->dev, "command %#x timed out\n", opcode);

	return ret;
}

static int fsoc3_bf_reg_read(void *priv, unsigned int offset, void *val,
			     size_t bytes)
{
	struct fsoc3_bf *bf = priv;
	int ret;

	mutex_lock(&bf->lock);
	ret = fsoc3_bf_cmd(bf, SPINOR_READ, FB_BLOCK + offset, val, bytes);
	mutex_unlock(&bf->lock);

	return ret;
}

/*
 * "mac-base" cell: the base + the index the consumer gives (port rank). A
 * base that is not a unicast address (multicast, all ones, all zeros) is
 * refused: the consumer then takes a random address.
 */
static int fsoc3_bf_mac_base(void *context, const char *id, int index,
			     unsigned int offset, void *buf, size_t bytes)
{
	if (bytes != ETH_ALEN || !is_valid_ether_addr(buf))
		return -EINVAL;

	if (index)
		eth_addr_add(buf, index);

	return 0;
}

static void fsoc3_bf_fixup_cell(struct nvmem_device *nvmem,
				struct nvmem_cell_info *cell)
{
	if (of_device_is_compatible(cell->np, "mac-base") &&
	    cell->bytes == ETH_ALEN)
		cell->read_post_process = fsoc3_bf_mac_base;
}

/* Everything but the base MAC address is kept out: never read */
static const struct nvmem_keepout fsoc3_bf_keepout[] = {
	{ .start = 0, .end = FB_MAC, .value = 0xff },
	{ .start = FB_MAC + ETH_ALEN, .end = FB_BLOCK_SIZE, .value = 0xff },
};

static const struct fsoc3_bf_part *fsoc3_bf_part(const u8 *id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fsoc3_bf_parts); i++) {
		const struct fsoc3_bf_part *p = &fsoc3_bf_parts[i];

		if (id[0] == p->mfr && id[1] == p->type &&
		    id[2] >= p->cap_min && id[2] <= p->cap_max)
			return p;
	}

	return NULL;
}

/*
 * The base MAC address, checked once at probe for the log (the address
 * itself is not logged): a refused base leaves the ports to random
 * addresses, a base outside the Fortinet OUIs is only warned about.
 */
static void fsoc3_bf_check_mac(struct fsoc3_bf *bf)
{
	u8 mac[ETH_ALEN];
	unsigned int i;
	int ret;

	mutex_lock(&bf->lock);
	ret = fsoc3_bf_cmd(bf, SPINOR_READ, FB_BLOCK + FB_MAC, mac, ETH_ALEN);
	mutex_unlock(&bf->lock);
	if (ret) {
		dev_warn(bf->dev, "base MAC address unreadable: %pe\n",
			 ERR_PTR(ret));
		return;
	}

	if (!is_valid_ether_addr(mac)) {
		dev_warn(bf->dev, "base MAC address refused (%s): random addresses\n",
			 is_zero_ether_addr(mac) ? "all zeros" :
			 is_broadcast_ether_addr(mac) ? "all ones" :
			 "multicast");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(fsoc3_bf_ouis); i++)
		if (!memcmp(mac, fsoc3_bf_ouis[i], 3))
			break;
	if (i == ARRAY_SIZE(fsoc3_bf_ouis))
		dev_warn(bf->dev, "base MAC address outside the known Fortinet OUIs\n");
	else
		dev_info(bf->dev, "base MAC address in a Fortinet OUI\n");
}

static int fsoc3_bf_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct fsoc3_bf_part *part;
	struct nvmem_config config = {};
	struct nvmem_device *nvmem;
	struct fsoc3_bf *bf;
	u32 ctrl, status;
	u8 id[3], sr;
	int ret;

	/* The base MAC address lies within the block */
	BUILD_BUG_ON(FB_MAC + ETH_ALEN > FB_BLOCK_SIZE);
	/* and the block within the smallest flash taken */
	BUILD_BUG_ON(FB_BLOCK + FB_BLOCK_SIZE > BIT(FB_CAP_MIN));

	bf = devm_kzalloc(dev, sizeof(*bf), GFP_KERNEL);
	if (!bf)
		return -ENOMEM;
	bf->dev = dev;
	ret = devm_mutex_init(dev, &bf->lock);
	if (ret)
		return ret;

	bf->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(bf->base))
		return PTR_ERR(bf->base);

	ctrl = readl(bf->base + FB_CTRL);
	status = readl(bf->base + FB_STATUS);
	if (!(ctrl & FB_CTRL_EN))
		writel(ctrl | FB_CTRL_EN, bf->base + FB_CTRL);

	mutex_lock(&bf->lock);
	ret = fsoc3_bf_cmd(bf, SPINOR_RDID, 0, id, sizeof(id));
	if (!ret)
		ret = fsoc3_bf_cmd(bf, SPINOR_RDSR, 0, &sr, 1);
	mutex_unlock(&bf->lock);
	if (ret)
		return dev_err_probe(dev, ret, "no answer (ctrl %#x, status %#x)\n",
				     ctrl, status);

	/* Only a flash of a known family and size, or keep away */
	part = fsoc3_bf_part(id);
	dev_info(dev, "ctrl %#x%s, status %#x; JEDEC %02x %02x %02x (%s), SR %#04x\n",
		 ctrl, ctrl & FB_CTRL_EN ? "" : " (bit 3 set)", status,
		 id[0], id[1], id[2], part ? part->name : "unknown", sr);
	if (!part)
		return dev_err_probe(dev, -ENODEV,
				     "flash not taken: random MAC addresses\n");
	dev_info(dev, "%s, %lu KiB\n", part->name, BIT(id[2]) / SZ_1K);

	fsoc3_bf_check_mac(bf);

	config.dev = dev;
	config.name = "fsoc3-factory";
	config.id = NVMEM_DEVID_NONE;
	config.owner = THIS_MODULE;
	config.type = NVMEM_TYPE_UNKNOWN;
	config.read_only = true;
	config.root_only = true;
	config.size = FB_BLOCK_SIZE;
	config.word_size = 1;
	config.stride = 1;
	config.keepout = fsoc3_bf_keepout;
	config.nkeepout = ARRAY_SIZE(fsoc3_bf_keepout);
	config.reg_read = fsoc3_bf_reg_read;
	config.fixup_dt_cell_info = fsoc3_bf_fixup_cell;
	config.priv = bf;

	nvmem = devm_nvmem_register(dev, &config);
	if (IS_ERR(nvmem))
		return dev_err_probe(dev, PTR_ERR(nvmem), "cannot register\n");

	return 0;
}

static const struct of_device_id fsoc3_bf_of_match[] = {
	{ .compatible = "fortinet,fsoc3-boot-flash" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc3_bf_of_match);

static struct platform_driver fsoc3_bf_driver = {
	.probe = fsoc3_bf_probe,
	.driver = {
		.name = "fsoc3-boot-flash",
		.of_match_table = fsoc3_bf_of_match,
	},
};
module_platform_driver(fsoc3_bf_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC3 boot flash factory block (read-only)");
MODULE_LICENSE("GPL");
