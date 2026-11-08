// SPDX-License-Identifier: GPL-2.0-only
/*
 * PCIe root port of the Fortinet FortiSOC3
 *
 * The FortiSOC3 has one PCIe root port (vendor 0x1a29, device 0x5333) behind
 * a small register block of the SoC ("p2ab" under the board firmware), at
 * 0xf3000000 on the FortiGate 100E, with the memory window of the link at
 * 0xf0000000. The FortiGate 100E has its Broadcom BCM53344 switch on it
 * (01:00.0 and 01:00.1, 14e4:8344). Established from the boot loader of
 * that board (fsoc3_p2ab_init, p2ab_read_config, p2ab_write_config) and
 * measured on it:
 *  - +0x94 bits 4:0: link state, 0xf once the link is up; the link trains
 *    by itself after reset;
 *  - +0x04: written 1 after link up; until then a configuration access
 *    never completes and leaves the command register busy;
 *  - +0x8c: written 0xf after link up (read 0xf before: kept as the loader
 *    writes it);
 *  - configuration accesses, one at a time: +0x6c address (bus << 20 |
 *    devfn << 12 | register), +0x74 data to write, +0x64 command: bit 15
 *    start, bits 3:0 byte enables, bit 4 write, bit 5 for the bus behind
 *    the root port; read back, bit 31 is busy, bit 30 done, bits 29:27 an
 *    error; +0x7c the data read.
 * Bus 0 holds the root port alone; on the link, only device 0 answers.
 *
 * No MSI: the legacy interrupts of the link come on one SPI of the GIC
 * (interrupt-map in the device tree).
 *
 * The memory window of the link is small (16 MiB on the 100E) next to
 * what an endpoint may ask for: the BCM53344 has a 16 MiB BAR on each of
 * its two functions besides its register BARs. A BAR as large as the whole
 * window is left unassigned, as the board firmware does: otherwise the
 * window of the root port cannot be sized and no BAR at all gets an
 * address.
 *
 * Experimental, tested on the FortiGate 100E only.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/platform_device.h>

#define FSOC3_PCIE_ENABLE		0x04	/* 1 after link up */
#define FSOC3_PCIE_CFG_CMD		0x64
#define  FSOC3_PCIE_CFG_BUSY		BIT(31)
#define  FSOC3_PCIE_CFG_DONE		BIT(30)
#define  FSOC3_PCIE_CFG_ERR		GENMASK(29, 27)
#define  FSOC3_PCIE_CFG_START		BIT(15)
#define  FSOC3_PCIE_CFG_LINK_BUS	BIT(5)	/* access behind the root port */
#define  FSOC3_PCIE_CFG_WRITE		BIT(4)
#define  FSOC3_PCIE_CFG_BE		GENMASK(3, 0)
#define FSOC3_PCIE_CFG_ADDR		0x6c
#define FSOC3_PCIE_CFG_WDATA		0x74
#define FSOC3_PCIE_CFG_RDATA		0x7c
#define FSOC3_PCIE_CTRL_8C		0x8c	/* 0xf after link up */
#define FSOC3_PCIE_LINK			0x94
#define  FSOC3_PCIE_LINK_STATE		GENMASK(4, 0)
#define  FSOC3_PCIE_LINK_UP		0xf

/* Polled with the PCI config lock held: no sleep */
#define FSOC3_PCIE_CFG_TIMEOUT_US	10000
/* Link up after reset: the boot loader waits for about 100 ms */
#define FSOC3_PCIE_LINK_TIMEOUT_US	200000

struct fsoc3_pcie {
	struct device *dev;
	void __iomem *base;
};

static bool fsoc3_pcie_link_up(struct fsoc3_pcie *pcie)
{
	return FIELD_GET(FSOC3_PCIE_LINK_STATE,
			 readl(pcie->base + FSOC3_PCIE_LINK)) == FSOC3_PCIE_LINK_UP;
}

/* Bus 0: the root port alone; bus 1 (the link): device 0 only */
static bool fsoc3_pcie_valid(struct pci_bus *bus, unsigned int devfn)
{
	if (pci_is_root_bus(bus))
		return devfn == 0;
	return bus->number == bus->primary + 1 && PCI_SLOT(devfn) == 0;
}

/* One configuration access, register aligned to 4 bytes */
static int fsoc3_pcie_cfg(struct fsoc3_pcie *pcie, struct pci_bus *bus,
			  unsigned int devfn, int where, u32 cmd, u32 wdata,
			  u32 *rdata)
{
	bool link = !pci_is_root_bus(bus);
	u32 v;

	if (readl_poll_timeout_atomic(pcie->base + FSOC3_PCIE_CFG_CMD, v,
				      !(v & FSOC3_PCIE_CFG_BUSY), 1,
				      FSOC3_PCIE_CFG_TIMEOUT_US))
		return PCIBIOS_SET_FAILED;

	writel((link ? bus->number : 0) << 20 | devfn << 12 | (where & 0xffc),
	       pcie->base + FSOC3_PCIE_CFG_ADDR);
	if (cmd & FSOC3_PCIE_CFG_WRITE)
		writel(wdata, pcie->base + FSOC3_PCIE_CFG_WDATA);
	writel(cmd | FSOC3_PCIE_CFG_START | (link ? FSOC3_PCIE_CFG_LINK_BUS : 0),
	       pcie->base + FSOC3_PCIE_CFG_CMD);

	if (readl_poll_timeout_atomic(pcie->base + FSOC3_PCIE_CFG_CMD, v,
				      v & FSOC3_PCIE_CFG_DONE, 1,
				      FSOC3_PCIE_CFG_TIMEOUT_US)) {
		dev_err_ratelimited(pcie->dev, "config access %02x:%02x.%u %#x timed out (%#x)\n",
				    bus->number, PCI_SLOT(devfn), PCI_FUNC(devfn),
				    where, v);
		return PCIBIOS_SET_FAILED;
	}
	if (v & FSOC3_PCIE_CFG_ERR)
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (rdata)
		*rdata = readl(pcie->base + FSOC3_PCIE_CFG_RDATA);
	return PCIBIOS_SUCCESSFUL;
}

static int fsoc3_pcie_read(struct pci_bus *bus, unsigned int devfn, int where,
			   int size, u32 *val)
{
	struct fsoc3_pcie *pcie = bus->sysdata;
	u32 v;
	int ret;

	if (!fsoc3_pcie_valid(bus, devfn) ||
	    (!pci_is_root_bus(bus) && !fsoc3_pcie_link_up(pcie))) {
		PCI_SET_ERROR_RESPONSE(val);
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	ret = fsoc3_pcie_cfg(pcie, bus, devfn, where, FSOC3_PCIE_CFG_BE, 0, &v);
	if (ret) {
		PCI_SET_ERROR_RESPONSE(val);
		return ret;
	}

	v >>= 8 * (where & 3);
	if (size == 1)
		v &= 0xff;
	else if (size == 2)
		v &= 0xffff;
	*val = v;
	return PCIBIOS_SUCCESSFUL;
}

static int fsoc3_pcie_write(struct pci_bus *bus, unsigned int devfn, int where,
			    int size, u32 val)
{
	struct fsoc3_pcie *pcie = bus->sysdata;
	unsigned int shift = 8 * (where & 3);
	u32 be = (BIT(size) - 1) << (where & 3);

	if (!fsoc3_pcie_valid(bus, devfn) ||
	    (!pci_is_root_bus(bus) && !fsoc3_pcie_link_up(pcie)))
		return PCIBIOS_DEVICE_NOT_FOUND;

	return fsoc3_pcie_cfg(pcie, bus, devfn, where,
			      FSOC3_PCIE_CFG_WRITE | (be & FSOC3_PCIE_CFG_BE),
			      val << shift, NULL);
}

static struct pci_ops fsoc3_pcie_ops = {
	.read	= fsoc3_pcie_read,
	.write	= fsoc3_pcie_write,
};

/* Leave out the memory BARs as large as the window (see above) */
static void fsoc3_pcie_drop_large_bars(struct pci_bus *bus, resource_size_t win)
{
	struct pci_dev *pdev;
	int i;

	list_for_each_entry(pdev, &bus->devices, bus_list) {
		for (i = 0; i < PCI_STD_NUM_BARS; i++) {
			struct resource *r = &pdev->resource[i];

			if (resource_type(r) != IORESOURCE_MEM || resource_size(r) < win)
				continue;
			pci_info(pdev, "BAR %d %pR: as large as the memory window, left unassigned\n",
				 i, r);
			r->flags = 0;
		}
		if (pdev->subordinate)
			fsoc3_pcie_drop_large_bars(pdev->subordinate, win);
	}
}

/* pci_host_probe(), with the large BARs left out before the assignment */
static int fsoc3_pcie_host_probe(struct pci_host_bridge *host)
{
	struct resource_entry *entry;
	resource_size_t win = 0;
	struct pci_bus *bus, *child;
	int ret;

	resource_list_for_each_entry(entry, &host->windows)
		if (resource_type(entry->res) == IORESOURCE_MEM)
			win = max(win, resource_size(entry->res));

	pci_lock_rescan_remove();
	ret = pci_scan_root_bus_bridge(host);
	pci_unlock_rescan_remove();
	if (ret < 0)
		return ret;

	bus = host->bus;
	if (win)
		fsoc3_pcie_drop_large_bars(bus, win);
	pci_assign_unassigned_root_bus_resources(bus);
	list_for_each_entry(child, &bus->children, node)
		pcie_bus_configure_settings(child);

	pci_lock_rescan_remove();
	pci_bus_add_devices(bus);
	pci_unlock_rescan_remove();
	return 0;
}

static int fsoc3_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_host_bridge *host;
	struct fsoc3_pcie *pcie;
	u32 v;

	host = devm_pci_alloc_host_bridge(dev, sizeof(*pcie));
	if (!host)
		return -ENOMEM;
	pcie = pci_host_bridge_priv(host);
	pcie->dev = dev;

	pcie->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(pcie->base))
		return PTR_ERR(pcie->base);

	if (readl_poll_timeout(pcie->base + FSOC3_PCIE_LINK, v,
			       FIELD_GET(FSOC3_PCIE_LINK_STATE, v) == FSOC3_PCIE_LINK_UP,
			       1000, FSOC3_PCIE_LINK_TIMEOUT_US))
		dev_info(dev, "link down (state %#lx): root port only\n",
			 FIELD_GET(FSOC3_PCIE_LINK_STATE, v));
	else
		dev_info(dev, "link up\n");

	/* as the boot loader, before the first configuration access */
	writel(1, pcie->base + FSOC3_PCIE_ENABLE);
	writel(0xf, pcie->base + FSOC3_PCIE_CTRL_8C);

	host->ops = &fsoc3_pcie_ops;
	host->sysdata = pcie;

	return fsoc3_pcie_host_probe(host);
}

static const struct of_device_id fsoc3_pcie_of_match[] = {
	{ .compatible = "fortinet,fsoc3-pcie" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc3_pcie_of_match);

static struct platform_driver fsoc3_pcie_driver = {
	.probe = fsoc3_pcie_probe,
	.driver = {
		.name = "fsoc3-pcie",
		.of_match_table = fsoc3_pcie_of_match,
		.suppress_bind_attrs = true,
	},
};
builtin_platform_driver(fsoc3_pcie_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC3 PCIe root port");
MODULE_LICENSE("GPL");
