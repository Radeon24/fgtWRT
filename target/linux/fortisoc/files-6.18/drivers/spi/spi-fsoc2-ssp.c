// SPDX-License-Identifier: GPL-2.0-only
/*
 * Read-only access to the boot flash of the Fortinet FortiSOC2
 *
 * The FortiGate 60D keeps its boot loader, and its factory data (base MAC
 * address, serial number), in a SPI NOR
 * flash behind the first Faraday FTSSP010 port of the SoC, whose chip
 * select is a line of a GPIO block. The boot loader sets the port up
 * (master, SPI format, clock, 32-bit frames). Reading the flash then takes:
 * chip select low, one 32-bit frame with the READ command and the address,
 * one 32-bit frame of zeros per word read, waiting for each frame in the
 * receive FIFO, chip select high.
 *
 * This driver reads it so, as a SPI memory controller:
 *  - an operation runs only when it is one of a few read commands (READ,
 *    read identification, read status, read SFDP), single wire, its data
 *    phase coming in. Any other operation is refused with -EROFS before
 *    the bus is touched. The controller still claims to support the
 *    single wire operations that write (page program, erase, write
 *    enable...): the SPI NOR core only takes a flash it could write, and
 *    sets up the page program and its direct mapping when it probes,
 *    without running them; the MTD on top is read-only. There are no
 *    regular SPI transfers, so there is no other path to the bus:
 *    nothing can be written to the flash;
 *  - the whole operation is clocked in 32-bit frames, the frame length the
 *    boot loader leaves: the command, address and dummy bytes, then zeros,
 *    the flash answering in the same frames; a few more bytes than asked
 *    may be read at the end. The configuration of the port is never
 *    written: probe fails when it is not the expected one.
 * The registers written are the FIFO clear bits of CR2 (before each
 * transfer), the data register, and the data
 * set and data clear registers of the GPIO block, for the chip select
 * line only.
 *
 * SPI_FSOC2_SSP_BUS (test, FortiGate 90D): the second FTSSP010 port reaches
 * the two BCM53128 switches of the 90D, behind a multiplexer driven by a
 * board GPIO line. This port, "fortinet,fsoc2-ssp-bus", takes regular SPI
 * messages, but never near the boot flash:
 *  - its chip select is another line of the same GPIO block (19 on the
 *    90D), driven as a GPIO around each frame,
 *    and probe refuses a port whose registers or chip select line are
 *    those of any read-only flash port of the device tree, enabled or
 *    not: the code that runs those messages has no way to the chip select
 *    of the flash;
 *  - the flash port and this port are serialised by one lock, so that the
 *    two FTSSP010 never clock at the same time, whatever their pads share;
 *  - the port runs as the boot loader left it (SPI master, mode 3,
 *    enabled), only its frame length is set (8-bit frames), for each
 *    frame; probe fails otherwise;
 *  - at probe, the SSP is set up as a SPI master with its chip select pad
 *    muxed to GPIO: chip select line high, then bit
 *    31 of the pad control register of the system control unit
 *    (0xe5100328: the line becomes a GPIO on its pad, the boot loader
 *    leaves it clear), then the line an output. Nothing else of the
 *    system control unit or of the GPIO block is written.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/mutex.h>
#include <linux/of_address.h>
#include <linux/spi/spi.h>
#include <linux/spi/spi-mem.h>

#define SSP_CR0			0x00
#define SSP_CR0_FFMT		GENMASK(14, 12)	/* frame format */
#define SSP_CR0_FFMT_SPI	1
#define SSP_CR0_OPM		GENMASK(3, 2)	/* operation mode */
#define SSP_CR0_OPM_MASTER	BIT(3)
#define SSP_CR0_SCLKPO		BIT(1)	/* clock polarity */
#define SSP_CR0_SCLKPH		BIT(0)	/* clock phase */
#define SSP_CR1			0x04
#define SSP_CR1_SDL		GENMASK(20, 16)	/* frame length - 1 */
#define SSP_CR2			0x08
#define SSP_CR2_TXFCLR		BIT(3)
#define SSP_CR2_RXFCLR		BIT(2)
#define SSP_CR2_SSPEN		BIT(0)
#define SSP_STATUS		0x0c
#define SSP_STATUS_RFVE		GENMASK(8, 4)	/* words in the RX FIFO */
#define SSP_DATA		0x18

/* GPIO block of the chip select, from its data set register */
#define CS_DATASET		0x00
#define CS_DATACLR		0x04

#define SSP_FRAME_BYTES		4
/*
 * 32-bit frame: at 64 KiB in 0.27 s, some 20 us. Polled every microsecond
 * for 1 ms at most.
 */
#define SSP_FRAME_POLL_US	1
#define SSP_FRAME_TIMEOUT_US	1000
#define SSP_HDR_MAX		5	/* command, 3 address bytes, 1 dummy byte */

struct fsoc2_ssp {
	struct device *dev;
	void __iomem *base;
	void __iomem *cs;
	u32 cs_mask;
};

/*
 * One lock for every port of the driver: an operation on the boot flash
 * and a message on the switch bus never run at the same time.
 */
static DEFINE_MUTEX(fsoc2_ssp_lock);

enum fsoc2_ssp_kind {
	FSOC2_SSP_FLASH,	/* boot flash, read commands only */
	FSOC2_SSP_BUS,		/* regular SPI messages (SPI_FSOC2_SSP_BUS) */
};

/* The only operations that reach the bus: reads, single wire. */
static const struct fsoc2_ssp_read_op {
	u8 opcode;
	u8 addr_nbytes;
	u8 dummy_nbytes;
} fsoc2_ssp_read_ops[] = {
	{ 0x03, 3, 0 },		/* READ */
	{ 0x05, 0, 0 },		/* read status register */
	{ 0x5a, 3, 1 },		/* read SFDP */
	{ 0x9f, 0, 0 },		/* read identification */
};

static bool fsoc2_ssp_single_wire(const struct spi_mem_op *op)
{
	if (op->cmd.nbytes != 1 || op->cmd.buswidth != 1 || op->cmd.dtr)
		return false;
	if (op->addr.nbytes && (op->addr.buswidth != 1 || op->addr.dtr))
		return false;
	if (op->dummy.nbytes && (op->dummy.buswidth != 1 || op->dummy.dtr))
		return false;
	if (op->data.dir != SPI_MEM_NO_DATA &&
	    (op->data.buswidth != 1 || op->data.dtr || op->data.ecc ||
	     op->data.swap16))
		return false;

	return true;
}

/* One of the read commands, whatever its length (a direct mapping has none) */
static bool fsoc2_ssp_read_shape(const struct spi_mem_op *op)
{
	unsigned int i;

	if (!fsoc2_ssp_single_wire(op) || op->data.dir != SPI_MEM_DATA_IN)
		return false;

	for (i = 0; i < ARRAY_SIZE(fsoc2_ssp_read_ops); i++) {
		const struct fsoc2_ssp_read_op *r = &fsoc2_ssp_read_ops[i];

		if (op->cmd.opcode == r->opcode &&
		    op->addr.nbytes == r->addr_nbytes &&
		    op->dummy.nbytes == r->dummy_nbytes)
			return true;
	}

	return false;
}

/* What may reach the bus: a read command with data to read */
static bool fsoc2_ssp_read_allowed(const struct spi_mem_op *op)
{
	return fsoc2_ssp_read_shape(op) && op->data.nbytes;
}

/*
 * The read commands, and the single wire operations that write: the SPI
 * NOR core wants a page program it could run, and the erase, write enable
 * and status register writes go with it. Those are claimed so that the
 * flash is taken, but refused when run. The other reads (fast read,
 * configuration register...) are not supported, so that the core keeps
 * to the plain READ.
 */
static bool fsoc2_ssp_supports_op(struct spi_mem *mem,
				  const struct spi_mem_op *op)
{
	if (op->data.dir == SPI_MEM_DATA_IN)
		return fsoc2_ssp_read_shape(op);

	return fsoc2_ssp_single_wire(op);
}

/* One 32-bit frame out, one in; the first byte on the wire is bits 31-24. */
static int fsoc2_ssp_frame(struct fsoc2_ssp *ssp, u32 out, u32 *in)
{
	u32 status;
	int ret;

	writel(out, ssp->base + SSP_DATA);
	ret = readl_poll_timeout_atomic(ssp->base + SSP_STATUS, status,
					status & SSP_STATUS_RFVE,
					SSP_FRAME_POLL_US,
					SSP_FRAME_TIMEOUT_US);
	if (ret)
		return ret;
	*in = readl(ssp->base + SSP_DATA);

	return 0;
}

static int fsoc2_ssp_exec_op(struct spi_mem *mem, const struct spi_mem_op *op)
{
	struct fsoc2_ssp *ssp = spi_controller_get_devdata(mem->spi->controller);
	unsigned int hdr_len, len, pos, i;
	u8 hdr[SSP_HDR_MAX] = {};
	u8 *buf = op->data.buf.in;
	u32 out, in, cr2;
	int ret = 0;

	/*
	 * Before any access: nothing but a read reaches the flash. -EROFS,
	 * not -EOPNOTSUPP, so that the SPI memory core does not try regular
	 * SPI transfers instead (there are none, but this does not rely on it).
	 */
	if (!fsoc2_ssp_read_allowed(op)) {
		dev_warn_ratelimited(ssp->dev, "operation %#x refused\n",
				     op->cmd.opcode);
		return -EROFS;
	}

	/* Command, address (big endian), dummy bytes (zeros) */
	hdr[0] = op->cmd.opcode;
	for (i = 0; i < op->addr.nbytes; i++)
		hdr[1 + i] = op->addr.val >> (8 * (op->addr.nbytes - 1 - i));
	hdr_len = 1 + op->addr.nbytes + op->dummy.nbytes;
	len = hdr_len + op->data.nbytes;

	mutex_lock(&fsoc2_ssp_lock);

	/* Both FIFOs cleared before each transfer */
	cr2 = readl(ssp->base + SSP_CR2);
	writel(cr2 | SSP_CR2_TXFCLR, ssp->base + SSP_CR2);
	cr2 = readl(ssp->base + SSP_CR2);
	writel(cr2 | SSP_CR2_RXFCLR, ssp->base + SSP_CR2);

	writel(ssp->cs_mask, ssp->cs + CS_DATACLR);	/* selected */
	for (pos = 0; pos < len; pos += SSP_FRAME_BYTES) {
		out = 0;
		for (i = 0; i < SSP_FRAME_BYTES; i++)
			if (pos + i < hdr_len)
				out |= (u32)hdr[pos + i] << (24 - 8 * i);

		ret = fsoc2_ssp_frame(ssp, out, &in);
		if (ret)
			break;

		for (i = 0; i < SSP_FRAME_BYTES; i++)
			if (pos + i >= hdr_len && pos + i < len)
				buf[pos + i - hdr_len] = in >> (24 - 8 * i);

		if (!(pos & (SZ_4K - 1)))
			cond_resched();
	}
	writel(ssp->cs_mask, ssp->cs + CS_DATASET);	/* released */

	mutex_unlock(&fsoc2_ssp_lock);

	if (ret)
		dev_err_ratelimited(ssp->dev, "operation %#x timed out at byte %u\n",
				    op->cmd.opcode, pos);

	return ret;
}

static const struct spi_controller_mem_ops fsoc2_ssp_mem_ops = {
	.supports_op = fsoc2_ssp_supports_op,
	.exec_op = fsoc2_ssp_exec_op,
};

static int fsoc2_ssp_flash_probe(struct platform_device *pdev,
				 struct spi_controller *ctlr,
				 struct fsoc2_ssp *ssp)
{
	struct device *dev = &pdev->dev;
	u32 cr0, cr1, cr2;
	int ret;

	ssp->cs = devm_platform_ioremap_resource_byname(pdev, "cs");
	if (IS_ERR(ssp->cs))
		return PTR_ERR(ssp->cs);

	/*
	 * The port runs as the boot loader left it: enabled SPI master with
	 * 32-bit frames. Anything else, and the driver keeps away.
	 */
	cr0 = readl(ssp->base + SSP_CR0);
	cr1 = readl(ssp->base + SSP_CR1);
	cr2 = readl(ssp->base + SSP_CR2);
	if (FIELD_GET(SSP_CR0_FFMT, cr0) != SSP_CR0_FFMT_SPI ||
	    !(cr0 & SSP_CR0_OPM_MASTER) ||
	    FIELD_GET(SSP_CR1_SDL, cr1) != 8 * SSP_FRAME_BYTES - 1 ||
	    !(cr2 & SSP_CR2_SSPEN))
		return dev_err_probe(dev, -ENODEV,
				     "port not set up by the boot loader (CR0 %#x CR1 %#x CR2 %#x)\n",
				     cr0, cr1, cr2);

	ctlr->dev.of_node = dev->of_node;
	ctlr->bus_num = -1;
	ctlr->num_chipselect = 1;
	ctlr->mode_bits = 0;
	ctlr->mem_ops = &fsoc2_ssp_mem_ops;

	ret = devm_spi_register_controller(dev, ctlr);
	if (ret)
		return dev_err_probe(dev, ret, "cannot register the controller\n");

	dev_info(dev, "read-only, CR0 %#x CR1 %#x CR2 %#x\n", cr0, cr1, cr2);

	return 0;
}

#ifdef CONFIG_SPI_FSOC2_SSP_BUS
/* Pad control register of the system control unit (bit 31: SSP1 CS as GPIO) */
#define FSOC2_SCU_PADCTL	0xe5100328
#define FSOC2_SCU_PADCTL_SSP1	BIT(31)
/* Direction register of the chip select GPIO block: 8 bytes below data set */
#define CS_DIR_BELOW		0x08

/*
 * Whether the resource @res of this port overlaps the resource @name of
 * the flash port @fnp. A flash node whose resource cannot be read counts
 * as overlapping: nothing proves this port keeps away from it.
 */
static bool fsoc2_ssp_overlaps(struct device_node *fnp, const char *name,
			       const struct resource *res)
{
	struct resource fres;
	int i;

	i = of_property_match_string(fnp, "reg-names", name);
	if (i < 0 || of_address_to_resource(fnp, i, &fres))
		return true;

	return resource_overlaps(&fres, res);
}

/*
 * The boot flash keeps away from this port: no read-only flash port of
 * the device tree, enabled or not, has its registers, or its chip select
 * line in the same GPIO block. At least one flash port must be found.
 */
static int fsoc2_ssp_bus_check(struct device *dev, const struct resource *rssp,
			       const struct resource *rcs, u32 line)
{
	struct device_node *fnp;
	unsigned int n = 0;
	u32 fline;

	for_each_compatible_node(fnp, NULL, "fortinet,fsoc2-ssp") {
		n++;
		if (fsoc2_ssp_overlaps(fnp, "ssp", rssp)) {
			of_node_put(fnp);
			return dev_err_probe(dev, -EINVAL,
					     "registers of the boot flash port %pOF\n",
					     fnp);
		}
		if (of_property_read_u32(fnp, "fortinet,cs-line", &fline) ||
		    (fline == line && fsoc2_ssp_overlaps(fnp, "cs", rcs))) {
			of_node_put(fnp);
			return dev_err_probe(dev, -EINVAL,
					     "chip select of the boot flash port %pOF\n",
					     fnp);
		}
	}
	if (!n)
		return dev_err_probe(dev, -ENODEV, "no boot flash port to keep away from\n");

	return 0;
}

/* One 8-bit frame out, one in (the frame is in the low bits). */
static int fsoc2_ssp_bus_byte(struct fsoc2_ssp *ssp, u8 out, u8 *in)
{
	u32 val;
	int ret;

	ret = fsoc2_ssp_frame(ssp, out, &val);
	if (!ret && in)
		*in = val;

	return ret;
}

static int fsoc2_ssp_bus_transfer(struct spi_controller *ctlr,
				  struct spi_message *msg)
{
	struct fsoc2_ssp *ssp = spi_controller_get_devdata(ctlr);
	struct spi_transfer *t;
	unsigned int i;
	u32 cr1, cr2;
	int ret = 0;

	mutex_lock(&fsoc2_ssp_lock);

	/* 8-bit frames; both FIFOs cleared */
	cr1 = readl(ssp->base + SSP_CR1);
	cr1 = (cr1 & ~SSP_CR1_SDL) | FIELD_PREP(SSP_CR1_SDL, 7);
	writel(cr1, ssp->base + SSP_CR1);
	cr2 = readl(ssp->base + SSP_CR2);
	writel(cr2 | SSP_CR2_TXFCLR, ssp->base + SSP_CR2);
	cr2 = readl(ssp->base + SSP_CR2);
	writel(cr2 | SSP_CR2_RXFCLR, ssp->base + SSP_CR2);

	writel(ssp->cs_mask, ssp->cs + CS_DATACLR);	/* selected */
	list_for_each_entry(t, &msg->transfers, transfer_list) {
		const u8 *tx = t->tx_buf;
		u8 *rx = t->rx_buf;

		for (i = 0; i < t->len; i++) {
			ret = fsoc2_ssp_bus_byte(ssp, tx ? tx[i] : 0,
						 rx ? &rx[i] : NULL);
			if (ret)
				goto out;
		}
		msg->actual_length += t->len;
		spi_transfer_delay_exec(t);

		if (t->cs_change &&
		    !list_is_last(&t->transfer_list, &msg->transfers)) {
			writel(ssp->cs_mask, ssp->cs + CS_DATASET);
			udelay(1);
			writel(ssp->cs_mask, ssp->cs + CS_DATACLR);
		}
	}
out:
	writel(ssp->cs_mask, ssp->cs + CS_DATASET);	/* released */

	mutex_unlock(&fsoc2_ssp_lock);

	if (ret)
		dev_err_ratelimited(ssp->dev, "message timed out after %u bytes\n",
				    msg->actual_length);
	msg->status = ret;
	spi_finalize_current_message(ctlr);

	return ret;
}

/* The port keeps the mode the boot loader set: mode 3 only. */
static int fsoc2_ssp_bus_setup(struct spi_device *spi)
{
	if ((spi->mode & SPI_MODE_X_MASK) != SPI_MODE_3)
		return -EINVAL;

	return 0;
}

static int fsoc2_ssp_bus_probe(struct platform_device *pdev,
			       struct spi_controller *ctlr,
			       struct fsoc2_ssp *ssp)
{
	struct device *dev = &pdev->dev;
	struct resource *rssp, *rcs, *rpad;
	void __iomem *pad, *dir;
	u32 cr0, cr2, line;
	int ret;

	rssp = platform_get_resource_byname(pdev, IORESOURCE_MEM, "ssp");
	rcs = platform_get_resource_byname(pdev, IORESOURCE_MEM, "cs");
	rpad = platform_get_resource_byname(pdev, IORESOURCE_MEM, "pad");
	if (!rssp || !rcs || resource_size(rcs) < 8)
		return dev_err_probe(dev, -EINVAL, "missing registers\n");
	if (rpad && (rpad->start != FSOC2_SCU_PADCTL || resource_size(rpad) != 4))
		return dev_err_probe(dev, -EINVAL, "pad control register not at %#x\n",
				     FSOC2_SCU_PADCTL);

	ret = of_property_read_u32(dev->of_node, "fortinet,cs-line", &line);
	if (ret || line > 31)
		return dev_err_probe(dev, -EINVAL, "no valid chip select line\n");

	/* Before anything is written: away from the boot flash */
	ret = fsoc2_ssp_bus_check(dev, rssp, rcs, line);
	if (ret)
		return ret;
	ssp->cs_mask = BIT(line);

	/*
	 * The data set and data clear registers are those the flash port
	 * holds: mapped, not requested. The direction register lies 8 bytes
	 * below them.
	 */
	ssp->cs = devm_ioremap(dev, rcs->start, 8);
	dir = devm_ioremap(dev, rcs->start - CS_DIR_BELOW, 4);
	if (!ssp->cs || !dir)
		return -ENOMEM;

	cr0 = readl(ssp->base + SSP_CR0);
	cr2 = readl(ssp->base + SSP_CR2);
	if (FIELD_GET(SSP_CR0_FFMT, cr0) != SSP_CR0_FFMT_SPI ||
	    !(cr0 & SSP_CR0_OPM_MASTER) ||
	    (cr0 & (SSP_CR0_SCLKPO | SSP_CR0_SCLKPH)) !=
	    (SSP_CR0_SCLKPO | SSP_CR0_SCLKPH) ||
	    !(cr2 & SSP_CR2_SSPEN))
		return dev_err_probe(dev, -ENODEV,
				     "port not set up by the boot loader (CR0 %#x CR2 %#x)\n",
				     cr0, cr2);

	/* Line high, pad to GPIO, line an output */
	writel(ssp->cs_mask, ssp->cs + CS_DATASET);
	if (rpad) {
		pad = devm_ioremap_resource(dev, rpad);
		if (IS_ERR(pad))
			return PTR_ERR(pad);
		writel(readl(pad) | FSOC2_SCU_PADCTL_SSP1, pad);
	}
	writel(readl(dir) | ssp->cs_mask, dir);

	ctlr->dev.of_node = dev->of_node;
	ctlr->bus_num = -1;
	ctlr->num_chipselect = 1;
	ctlr->mode_bits = SPI_CPOL | SPI_CPHA;
	ctlr->bits_per_word_mask = SPI_BPW_MASK(8);
	ctlr->setup = fsoc2_ssp_bus_setup;
	ctlr->transfer_one_message = fsoc2_ssp_bus_transfer;

	ret = devm_spi_register_controller(dev, ctlr);
	if (ret)
		return dev_err_probe(dev, ret, "cannot register the controller\n");

	dev_info(dev, "bus, chip select line %u, CR0 %#x CR2 %#x%s\n", line,
		 cr0, cr2, rpad ? ", pad set" : "");

	return 0;
}
#endif /* CONFIG_SPI_FSOC2_SSP_BUS */

static int fsoc2_ssp_probe(struct platform_device *pdev)
{
	enum fsoc2_ssp_kind kind = (uintptr_t)device_get_match_data(&pdev->dev);
	struct device *dev = &pdev->dev;
	struct spi_controller *ctlr;
	struct fsoc2_ssp *ssp;

	ctlr = devm_spi_alloc_host(dev, sizeof(*ssp));
	if (!ctlr)
		return -ENOMEM;

	ssp = spi_controller_get_devdata(ctlr);
	ssp->dev = dev;

	ssp->base = devm_platform_ioremap_resource_byname(pdev, "ssp");
	if (IS_ERR(ssp->base))
		return PTR_ERR(ssp->base);

	if (kind == FSOC2_SSP_FLASH) {
		u32 line;
		int ret;

		ret = of_property_read_u32(dev->of_node, "fortinet,cs-line", &line);
		if (ret || line > 31)
			return dev_err_probe(dev, -EINVAL, "no valid chip select line\n");
		ssp->cs_mask = BIT(line);

		return fsoc2_ssp_flash_probe(pdev, ctlr, ssp);
	}

#ifdef CONFIG_SPI_FSOC2_SSP_BUS
	return fsoc2_ssp_bus_probe(pdev, ctlr, ssp);
#else
	return -ENODEV;
#endif
}

static const struct of_device_id fsoc2_ssp_of_match[] = {
	{ .compatible = "fortinet,fsoc2-ssp", .data = (void *)FSOC2_SSP_FLASH },
#ifdef CONFIG_SPI_FSOC2_SSP_BUS
	{ .compatible = "fortinet,fsoc2-ssp-bus", .data = (void *)FSOC2_SSP_BUS },
#endif
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc2_ssp_of_match);

static struct platform_driver fsoc2_ssp_driver = {
	.probe = fsoc2_ssp_probe,
	.driver = {
		.name = "fsoc2-ssp",
		.of_match_table = fsoc2_ssp_of_match,
	},
};
module_platform_driver(fsoc2_ssp_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC2 boot flash controller (read-only)");
MODULE_LICENSE("GPL");
