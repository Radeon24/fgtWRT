// SPDX-License-Identifier: GPL-2.0-only
/*
 * Broadcom BCM53344 (Hurricane 2) of the FortiGate 100E
 *
 * On the Fortinet FortiGate 100E the BCM53344 sits behind the PCIe root
 * port of the FortiSOC3. Its front ports reach the NP6Lite of the SoC over
 * the QSGMII uplinks (ports 18-25); the CMIC (port 0) carries no traffic.
 * This driver brings the switch out of reset and sets it up: wan1 (port 8)
 * and wan2 (port 9) are bridged to an uplink each (ports 18, 19: NP6Lite
 * MAC 2, 3); the other front ports are DSA user ports of two instances
 * (child nodes of the PCI device) with tag_8021q over uplink 20 or 21.
 *
 * Access: the CMIC is in the BAR named by the vendor-specific capability
 * (+8 bit 8: BAR 2); the blocks of the switch are reached over the
 * S-Channel of CMC0, the PHYs over the MDIO master of CMC0.
 *
 * The egress masks keep zones and DSA instances apart; VLANs are a second
 * layer. The QGPHY, TSC and MAC speeds follow the PHYs (polled for the
 * zones, phylink for DSA ports). Tested on the FortiGate 100E only.
 */

#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/iopoll.h>
#include <linux/mii.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/dsa/8021q.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/of_mdio.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/phylink.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <net/dsa.h>
#include <net/switchdev.h>
#include <linux/workqueue.h>


static bool led_chase = true;
module_param(led_chase, bool, 0444);
MODULE_PARM_DESC(led_chase, "run a chase light over the front LEDs once at probe");
static int mac_limit = 1024;
module_param(mac_limit, int, 0444);
MODULE_PARM_DESC(mac_limit, "learned MAC addresses per front port, frames with a new source beyond are dropped (0: no limit)");

static int led_chase_ms = 150;
module_param(led_chase_ms, int, 0444);
MODULE_PARM_DESC(led_chase_ms, "chase light: time per jack in ms");

/* CMIC (BAR) */
#define CMIC_SBUS_TIMEOUT	0x10094
#define CMIC_SBUS_RING_MAP(n)	(0x10098 + 4 * (n))
#define CMIC_DEV_REV_ID		0x10224
#define CMC0_SCHAN_CTRL		0x31000
#define  SCHAN_MSG_START	BIT(0)
#define  SCHAN_MSG_DONE		BIT(1)
#define  SCHAN_ABORT		BIT(2)
#define  SCHAN_NAK		BIT(21)
#define CMC0_SCHAN_ERR		0x31008
#define CMC0_SCHAN_MESSAGE(n)	(0x3100c + 4 * (n))
#define CMC0_MIIM_PARAM		0x31080
#define  MIIM_INTERNAL		BIT(25)
#define  MIIM_BUS		GENMASK(24, 22)
#define  MIIM_PHY		GENMASK(20, 16)
#define  MIIM_DATA		GENMASK(15, 0)
#define CMC0_MIIM_READ_DATA	0x31084
#define CMC0_MIIM_ADDRESS	0x31088
#define CMC0_MIIM_CTRL		0x3108c
#define  MIIM_WR_START		BIT(0)
#define  MIIM_RD_START		BIT(1)
#define CMC0_MIIM_STAT		0x31090
#define  MIIM_OPN_DONE		BIT(0)

/* S-Channel opcodes and header (new SBUS format) */
#define SCHAN_READ_MEMORY	0x07
#define SCHAN_WRITE_MEMORY	0x09
#define SCHAN_READ_REGISTER	0x0b
#define SCHAN_WRITE_REGISTER	0x0d
#define SCHAN_HDR(op, blk, len)	((op) << 26 | (blk) << 20 | (len) << 7)
#define SCHAN_WORDS		22

/* S-Channel block numbers */
#define BLK_GPORT(n)		(2 + (n))
#define BLK_XLPORT(n)		(5 + (n))
#define BLK_IPIPE		10
#define BLK_EPIPE		11
#define BLK_MMU			12
#define BLK_TOP			16

/* TOP */
#define TOP_SOFT_RESET_REG	0x02030400
#define  TOP_IP_RST_L		BIT(0)
#define  TOP_EP_RST_L		BIT(1)
#define  TOP_MMU_RST_L		BIT(2)
#define  TOP_SPARE_RST_L	BIT(5)
#define  TOP_TS_RST_L		BIT(15)
/* XLP0/1, GP0-2, QSGMII2X0-2 and their FIFOs, QGPHY 3:0 */
#define  TOP_PORT_BLOCKS_RST_L	0x000f7fd8
#define TOP_SOFT_RESET_REG_2	0x02030800
#define  TOP_TS_PLL_RST_L	BIT(8)
#define  TOP_TS_PLL_POST_RST_L	BIT(9)

/* IPIPE / EPIPE */
#define ING_HW_RESET_CONTROL_1	0x02000200
#define ING_HW_RESET_CONTROL_2	0x02000300
#define EGR_HW_RESET_CONTROL_0	0x02000000
#define EGR_HW_RESET_CONTROL_1	0x02000100
#define  HW_RESET_COUNT		GENMASK(15, 0)
#define  HW_RESET_ALL		BIT(16)
#define  HW_RESET_VALID		BIT(17)
#define  HW_RESET_DONE		BIT(18)

/* IPIPE: port mapping, TDM, credits */
#define ING_PHYS_TO_LOGIC_MAP	0x000c0000	/* memory, by physical port */
#define  INVALID_LOGIC_PORT	0x1f
#define IARB_TDM_CONTROL	0x02000900
#define  IARB_TDM_DISABLE	BIT(0)
#define  IARB_TDM_WRAP_PTR	GENMASK(7, 1)
#define IARB_TDM_TABLE		0x00080000	/* memory */
#define IP_TO_CMICM_CREDIT_TRANSFER 0x02002300
#define  CREDIT_TRANSFER_ENABLE	BIT(6)
#define  CREDIT_NUM		GENMASK(5, 0)

/* EPIPE */
#define EGR_LOGIC_TO_PHYS_MAP	0x34001b00	/* port register */
#define  INVALID_PHYS_PORT	0x3f
#define EGR_ENABLE		0x345c0000	/* memory, by physical port */
#define  EGR_PRT_ENABLE		BIT(0)
#define EGR_VLAN_CONTROL_1	0x04000b00	/* port register */
#define ING_CONFIG_64		0x06000000	/* IPIPE, 64 bit */
#define  APPLY_EGR_MASK_ON_L2	BIT_ULL(12)
#define  APPLY_EGR_MASK_ON_L3	BIT_ULL(13)
#define EGR_MASK		0x44000000	/* IPIPE memory, by source port */
/* copy-to-CPU controls (IPIPE); the CMIC takes no frames: all must stay 0 */
#define CPU_CONTROL_0		0x1e000600
#define CPU_CONTROL_1		0x3a000300
#define CPU_CONTROL_M		0x3a000400
#define PROTOCOL_PKT_CONTROL	0x1c000400	/* port register */
#define IGMP_MLD_PKT_CONTROL	0x1c000500	/* port register */
/* learn limits (IPIPE): LIMIT 16:2, OVER_LIMIT_DROP 1, OVER_LIMIT_TOCPU 0 */
#define SYS_MAC_LIMIT_CONTROL	0x1e000300
#define  SYS_MAC_LIMIT_ENABLE	BIT(17)
#define PORT_OR_TRUNK_MAC_LIMIT	0x1c240000	/* 158: 128 trunks, then ports */
#define PORT_OR_TRUNK_MAC_COUNT	0x1c200000	/* same index, COUNT 14:0 */
#define  MAC_LIMIT_PORT(p)	(128 + (p))
#define VLAN_OR_VFI_MAC_LIMIT	0x1c2c0000	/* 4096 entries, index = VID */
#define  MAC_LIMIT		GENMASK(16, 2)
#define  MAC_LIMIT_DROP		BIT(1)
#define  MAC_LIMIT_MAX		16383		/* L2X entries - 1: no limit */
#define EGR_PORT_REQUESTS	0x34040000	/* memory, by physical port, RO */
#define  REMARK_OUTER_DOT1P	BIT(12)

/* GPORT */
#define GPORT_CONFIG		0x02020000
#define  GPORT_EN		BIT(0)
#define  GPORT_CLR_CNT		BIT(1)

/* GPORT UniMAC (port registers, index in block) */
#define UMAC_COMMAND_CONFIG	0x00010200
#define  UMAC_TX_ENA		BIT(0)
#define  UMAC_RX_ENA		BIT(1)
#define  UMAC_ETH_SPEED		GENMASK(3, 2)
#define  UMAC_SPEED_1000	2
#define  UMAC_SW_RESET		BIT(13)
#define  UMAC_SW_OVERRIDE_TX	BIT(17)
#define  UMAC_SW_OVERRIDE_RX	BIT(18)
#define UMAC_FRM_LENGTH		0x00010500
#define UMAC_MAX_FRAME		9220	/* jumbo frames */
#define UMAC_MAC_MODE		0x00011100	/* read only */
#define GPORT_GRPKT		0x00001b00
#define GPORT_GTPKT		0x00003800

/* IPIPE VLAN/STG/port tables (memories) and link bitmap */
#define VLAN_TAB		0x14000000	/* 4 words */
#define STG_TAB			0x14040000	/* 2 words */
#define PORT_TAB		0x04000000	/* 8 words */
#define  CML_LEARN_FWD		8	/* CML_FLAGS: learn in hardware, forward */
#define ING_VLAN_TAG_ACTION_PROFILE 0x102c0000	/* 1 word, 64 entries */
#define  TAG_ACTION_ADD		1
#define  TAG_ACTION_REPLACE	2
#define L2X			0x1c000000	/* 4 words, 16384 entries */
#define L2X_ENTRIES		16384
#define L2_AGE_TIMER		0x02000400	/* IPIPE */
#define  L2_AGE_VAL		GENMASK(19, 0)	/* seconds */
#define  L2_AGE_ENA		BIT(20)
#define EPC_LINK_BMAP		0x46002700	/* 64 bit register */
#define EGR_VLAN		0x100c0000	/* EPIPE, 3 words */
#define L2MC			0x24000000	/* IPIPE, 2 words: flood groups */
#define  L2MC_ENTRIES		1024
#define  L2MC_ZONE		1020		/* + zone index */
#define  L2MC_DEAD		1023
/* flood groups of VLAN-aware bridge VIDs: unused by the tag_8021q VIDs */
#define  L2MC_USER		128
#define  L2MC_USER_N		384
/*
 * Internal VIDs stay in the tag_8021q range (3072-4095), which VLAN-aware
 * bridges cannot use, at a switch number DSA does not hand out here.
 */
#define VID_ZONE_BASE		3520	/* + uplink port */
#define VID_DEAD		3583	/* valid, no member: PVID of unused ports */
#define EGR_VLAN_STG		0x10100000	/* EPIPE, 2 words */
#define STP_FORWARD		3
#define BCM53344_STG		1

/* QSGMII2X_2 SerDes of the uplink ports 18-25: internal bus 1 address 0x11 */
#define SERDES_BUS		1
#define SERDES_PHY		0x11
#define SERDES_BLOCK		0x1f
#define SERDES_AER_BLOCK	0xffd0
#define SERDES_AER		0x1e

/* MMU (port registers indexed by MMU port = logical port here) */
#define MMU_ARB_TDM_TABLE	0x2c078000	/* memory */
#define  MMU_TDM_WRAP_EN	BIT(6)
#define MISCCONFIG		0x02025a00
#define  SKIDMARKER		GENMASK(3, 2)
#define  METERING_CLK_EN	BIT(5)
#define HOLCOSPKTSETLIMIT	0x00000800	/* + cos << 8 */
#define HOLCOSPKTRESETLIMIT	0x00002800
#define HOLCOSMINXQCNT		0x00004800
#define LWMCOSCELLSETLIMIT	0x0000cd00
#define HOLCOSCELLMAXLIMIT	0x0000ed00
#define DYNXQCNTPORT		0x0000ca00
#define MMU_DYNPKTCNTPORT	0x0000cc00	/* read only */
#define MMU_LOG_TO_PHY_PORT_MAPPING 0x00086000	/* port register, reset 0x3f */
#define XQEMPTY			0x00012f00	/* MMU port register, RO */
#define DYNRESETLIMPORT		0x0000cb00
#define IBPDISCARDSETLIMIT	0x00000300
#define DYNCELLLIMIT		0x00012d00
#define IBPPKTSETLIMIT		0x00000000
#define IBPCELLSETLIMIT		0x00000200
#define E2EFC_CNT_SET_LIMIT	0x02056000	/* + port << 8 */
#define E2EFC_CNT_RESET_LIMIT	0x02076000
#define E2EFC_CNT_DISC_LIMIT	0x02066000
#define  E2EFC_PARITY		BIT(29)
#define TOTALDYNCELLSETLIMIT	0x02025b00
#define TOTALDYNCELLRESETLIMIT	0x02030400
#define LIMIT2(lo, hi)		((lo) | (hi) << 14)

/*
 * MMU of the BCM53344: 1.5 MiB of 128 byte cells
 * (12288), 8 COS, minimum 8 XQs / 12 cells per COS, skid marker 3
 */
#define MMU_TOTAL_CELLS		12288
#define MMU_DYN_XQ_PER_PORT	(1536 - 8 * 8 - (3 + 4) - 9)	/* 1456 */
#define MMU_XQ_LIMIT		(MMU_DYN_XQ_PER_PORT + 8)
#define MMU_COS_MIN_XQS		8
#define MMU_COS_MIN_CELLS	12
#define MMU_CELL_MAX_PRI_0	5704
#define MMU_CELL_MAX_PRI_1_7	48
#define MMU_DYN_CELL_LIMIT	(MMU_CELL_MAX_PRI_0 + 7 * MMU_CELL_MAX_PRI_1_7)
#define MMU_XOFF_CELL_LIMIT	(9728 / 128 + 4)
#define MMU_TOTAL_DYN_CELLS	(MMU_TOTAL_CELLS - 29 * 8 * MMU_COS_MIN_CELLS)

#define NUM_PORTS		30	/* logical ports 0..29, 1 unused */
#define NUM_PHYS_PORTS		34

/* MMU arbiter TDM calendar of the BCM53344; 63 = idle slot */
static const u8 bcm53344_tdm[] = {
	2, 10, 18, 26, 63, 0,	3, 11, 19, 63, 63, 63,
	4, 12, 20, 27, 63, 63,	5, 13, 21, 63, 63, 63,
	6, 14, 22, 28, 63, 63,	7, 15, 23, 63, 63, 63,
	8, 16, 24, 29, 63, 63,	9, 17, 25, 63, 63, 63,
};

/* SBUS ring map of blocks 0..31 */
static const u32 bcm53344_ring_map[] = { 0x11122200, 0x00430000, 0x00005004, 0 };

struct bcm53344 {
	struct pci_dev *pdev;
	void __iomem *cmic;
	struct mutex schan_lock;
	struct mutex miim_lock;
	struct dentry *debugfs;
	struct delayed_work led_work;
	struct delayed_work led_link_work;
	struct delayed_work b50220_led_work;
	int b50220_step;
	int led_step;
	u8 umac_speed[NUM_PORTS];	/* UMAC ETH_SPEED of the front ports */
	u8 tsc_speed[4];		/* ports 26-29: 2 1000, 1 100, 0 10 */
	struct mii_bus *mii_int;	/* internal MDIO bus 0: QGPHYs */
	struct mii_bus *mii_ext;	/* external MDIO bus 1: B50220 */
	struct mutex cfg_lock;		/* VLANs, link bitmap, port table */
	u32 link_bmap;			/* EPC_LINK_BMAP */
	u32 dsa_ports;			/* ports owned by a DSA instance */
	struct bcm53344_vlan {
		u32 members;
		u32 untagged;
		/* VLANs of user VIDs as bridges ask for them, applied to the
		 * ports of the VLAN-aware bridge only */
		u32 want, want_ut;
		u16 l2mc;
	} *vlan;			/* VLAN_TAB/EGR_VLAN of the DSA VIDs */
	u32 aware_ports;		/* VLAN-aware bridge ports and their CPU port */
	struct net_device *aware_br;	/* the one VLAN-aware bridge */
	DECLARE_BITMAP(l2mc_user, L2MC_USER_N);
	u16 pvid[NUM_PORTS];		/* PORT_VID set by a DSA instance */
	u32 egr_mask[NUM_PORTS];	/* EGR_MASK as it must be in hardware */
	struct bcm53344_dsa *dsa[2];	/* DSA instances, by switch index */
};

/*
 * Front ports with an internal QGPHY (internal MDIO bus 0) used here:
 * port and PHY address
 */
static const struct {
	const char *name;
	int port;
	int phy;
	int uplink;
} bcm53344_front[] = {
	{ "wan1", 8, 8, 18 },	/* NP6Lite MAC 2 */
	{ "wan2", 9, 9, 19 },	/* NP6Lite MAC 3 */
};

/*
 * One S-Channel operation, polled: nwr words
 * (header, address, data) out, nrd words back (header, data)
 */
static int bcm53344_schan_op(struct bcm53344 *sw, const u32 *wr, int nwr,
			     u32 *rd, int nrd)
{
	void __iomem *ctrl = sw->cmic + CMC0_SCHAN_CTRL;
	u32 v;
	int i, ret;

	mutex_lock(&sw->schan_lock);
	for (i = 0; i < nwr; i++)
		writel(wr[i], sw->cmic + CMC0_SCHAN_MESSAGE(i));
	writel(SCHAN_MSG_START, ctrl);
	ret = readl_poll_timeout(ctrl, v, v & SCHAN_MSG_DONE, 10, 100000);
	if (ret) {
		/* abort the operation */
		writel(v | SCHAN_ABORT, ctrl);
		writel(v, ctrl);
		dev_err(&sw->pdev->dev, "schan %#010x %#010x: timeout, ctrl %#x err %#x\n",
			wr[0], wr[1], v, readl(sw->cmic + CMC0_SCHAN_ERR));
	} else if (v & SCHAN_NAK) {
		dev_err(&sw->pdev->dev, "schan %#010x %#010x: NAK\n", wr[0], wr[1]);
		ret = -EIO;
	} else {
		for (i = 0; i < nrd; i++)
			rd[i] = readl(sw->cmic + CMC0_SCHAN_MESSAGE(i));
	}
	writel(0, ctrl);	/* MSG_CLR */
	mutex_unlock(&sw->schan_lock);
	return ret;
}

static int bcm53344_reg_read(struct bcm53344 *sw, int blk, u32 addr, u32 *val)
{
	u32 wr[2] = { SCHAN_HDR(SCHAN_READ_REGISTER, blk, 4), addr }, rd[2];
	int ret;

	ret = bcm53344_schan_op(sw, wr, 2, rd, 2);
	if (!ret)
		*val = rd[1];
	return ret;
}

static int bcm53344_reg_write(struct bcm53344 *sw, int blk, u32 addr, u32 val)
{
	u32 wr[3] = { SCHAN_HDR(SCHAN_WRITE_REGISTER, blk, 4), addr, val };

	return bcm53344_schan_op(sw, wr, 3, NULL, 0);
}

static int bcm53344_mem_read(struct bcm53344 *sw, int blk, u32 addr,
			     u32 *val, int nwords)
{
	u32 wr[2] = { SCHAN_HDR(SCHAN_READ_MEMORY, blk, 4), addr };
	u32 rd[SCHAN_WORDS];
	int ret;

	ret = bcm53344_schan_op(sw, wr, 2, rd, nwords + 1);
	if (!ret)
		memcpy(val, &rd[1], nwords * 4);
	return ret;
}

static int bcm53344_mem_write(struct bcm53344 *sw, int blk, u32 addr,
			      const u32 *val, int nwords)
{
	u32 wr[SCHAN_WORDS];

	wr[0] = SCHAN_HDR(SCHAN_WRITE_MEMORY, blk, nwords * 4);
	wr[1] = addr;
	memcpy(&wr[2], val, nwords * 4);
	return bcm53344_schan_op(sw, wr, nwords + 2, NULL, 0);
}

/* Clause 22 access over the MDIO master of CMC0 */
static int bcm53344_miim(struct bcm53344 *sw, bool internal, int bus, int phy,
			 int reg, bool write, u16 data)
{
	u32 param = FIELD_PREP(MIIM_BUS, bus) | FIELD_PREP(MIIM_PHY, phy);
	u32 v;
	int ret;

	if (internal)
		param |= MIIM_INTERNAL;
	if (write)
		param |= FIELD_PREP(MIIM_DATA, data);

	mutex_lock(&sw->miim_lock);
	writel(reg, sw->cmic + CMC0_MIIM_ADDRESS);
	writel(param, sw->cmic + CMC0_MIIM_PARAM);
	writel(write ? MIIM_WR_START : MIIM_RD_START, sw->cmic + CMC0_MIIM_CTRL);
	ret = readl_poll_timeout(sw->cmic + CMC0_MIIM_STAT, v, v & MIIM_OPN_DONE,
				 10, 10000);
	v = readl(sw->cmic + CMC0_MIIM_READ_DATA) & 0xffff;
	writel(0, sw->cmic + CMC0_MIIM_CTRL);
	mutex_unlock(&sw->miim_lock);
	return ret ? ret : (write ? 0 : v);
}

static int bcm53344_qgphy_read(struct bcm53344 *sw, int phy, int reg)
{
	return bcm53344_miim(sw, true, 0, phy, reg, false, 0);
}

static int bcm53344_qgphy_write(struct bcm53344 *sw, int phy, int reg, u16 val)
{
	return bcm53344_miim(sw, true, 0, phy, reg, true, val);
}

static int bcm53344_reg64_read(struct bcm53344 *sw, int blk, u32 addr, u64 *val)
{
	u32 wr[2] = { SCHAN_HDR(SCHAN_READ_REGISTER, blk, 8), addr }, rd[3];
	int ret;

	ret = bcm53344_schan_op(sw, wr, 2, rd, 3);
	if (!ret)
		*val = (u64)rd[2] << 32 | rd[1];
	return ret;
}

static int bcm53344_reg64_write(struct bcm53344 *sw, int blk, u32 addr, u64 val)
{
	u32 wr[4] = { SCHAN_HDR(SCHAN_WRITE_REGISTER, blk, 8), addr,
		      lower_32_bits(val), upper_32_bits(val) };

	return bcm53344_schan_op(sw, wr, 4, NULL, 0);
}

/* Set a field of a table entry given as little endian words */
static void bcm53344_field_set(u32 *e, int lsb, int width, u32 val)
{
	int i;

	for (i = 0; i < width; i++) {
		int b = lsb + i;

		if (val & BIT(i))
			e[b / 32] |= BIT(b % 32);
		else
			e[b / 32] &= ~BIT(b % 32);
	}
}

static u32 bcm53344_field_get(const u32 *e, int lsb, int width)
{
	u32 v = 0;
	int i;

	for (i = 0; i < width; i++) {
		int b = lsb + i;

		if (e[b / 32] & BIT(b % 32))
			v |= BIT(i);
	}
	return v;
}

/* Write a table entry; debug log with the read back value */
/* PORT_TAB (8 words): one field of one port, read-modify-write */
static int bcm53344_port_tab_set(struct bcm53344 *sw, int port, int lsb,
				 int width, u32 val)
{
	u32 pt[8];
	int ret;

	ret = bcm53344_mem_read(sw, BLK_IPIPE, PORT_TAB + port, pt, 8);
	if (ret)
		return ret;
	bcm53344_field_set(pt, lsb, width, val);
	return bcm53344_mem_write(sw, BLK_IPIPE, PORT_TAB + port, pt, 8);
}

static int bcm53344_mem_set(struct bcm53344 *sw, int blk, u32 addr,
			    const u32 *e, int n)
{
	u32 now[8] = { };
	int ret;

	ret = bcm53344_mem_write(sw, blk, addr, e, n);
	if (!ret)
		ret = bcm53344_mem_read(sw, blk, addr, now, n);
	dev_dbg(&sw->pdev->dev, "blk %2d mem %#010x: wrote %*ph, read back %*ph%s\n",
		 blk, addr, n * 4, e, n * 4, now,
		 ret ? " (failed)" : (memcmp(e, now, n * 4) ? " (differs)" : ""));
	return ret;
}

/* Write a register; debug log with old value, new value and read back */
static int bcm53344_reg_set(struct bcm53344 *sw, int blk, u32 addr, u32 val)
{
	u32 old = 0, now = 0;
	int ret;

	ret = bcm53344_reg_read(sw, blk, addr, &old);
	if (!ret)
		ret = bcm53344_reg_write(sw, blk, addr, val);
	if (!ret)
		ret = bcm53344_reg_read(sw, blk, addr, &now);
	dev_dbg(&sw->pdev->dev, "blk %2d %#010x: %#010x -> %#010x, read back %#010x%s\n",
		 blk, addr, old, val, now, ret ? " (failed)" : "");
	return ret;
}

static int bcm53344_reg_setbits(struct bcm53344 *sw, int blk, u32 addr, u32 bits)
{
	u32 v;
	int ret;

	ret = bcm53344_reg_read(sw, blk, addr, &v);
	if (ret)
		return ret;
	return bcm53344_reg_set(sw, blk, addr, v | bits);
}

/*
 * Bulk writes (many ports/COS): each one read back; only mismatches are
 * logged, plus a summary
 */
struct bcm53344_bulk {
	int writes;
	int bad;
};

static void bcm53344_bulk_reg_mask(struct bcm53344 *sw, struct bcm53344_bulk *b,
				   int blk, u32 addr, u32 val, u32 mask)
{
	u32 now = 0;
	int ret;

	ret = bcm53344_reg_write(sw, blk, addr, val);
	if (!ret)
		ret = bcm53344_reg_read(sw, blk, addr, &now);
	b->writes++;
	if (ret || (now & mask) != val) {
		b->bad++;
		dev_dbg(&sw->pdev->dev, "blk %2d %#010x: wrote %#010x, read back %#010x%s\n",
			 blk, addr, val, now, ret ? " (failed)" : "");
	}
}

static void bcm53344_bulk_reg(struct bcm53344 *sw, struct bcm53344_bulk *b,
			      int blk, u32 addr, u32 val)
{
	bcm53344_bulk_reg_mask(sw, b, blk, addr, val, ~0);
}

static void bcm53344_bulk_mem(struct bcm53344 *sw, struct bcm53344_bulk *b,
			      int blk, u32 addr, u32 val)
{
	u32 now = 0;
	int ret;

	ret = bcm53344_mem_write(sw, blk, addr, &val, 1);
	if (!ret)
		ret = bcm53344_mem_read(sw, blk, addr, &now, 1);
	b->writes++;
	if (ret || now != val) {
		b->bad++;
		dev_dbg(&sw->pdev->dev, "blk %2d mem %#010x: wrote %#010x, read back %#010x%s\n",
			 blk, addr, val, now, ret ? " (failed)" : "");
	}
}

static bool bcm53344_port_valid(int port)
{
	return port == 0 || (port >= 2 && port < NUM_PORTS);
}

/* Wait up to 50 ms for a bit of a register to be set */
static int bcm53344_reg_poll(struct bcm53344 *sw, int blk, u32 addr, u32 bit,
			     u32 *val)
{
	int i, ret;

	for (i = 0; i < 50; i++) {
		ret = bcm53344_reg_read(sw, blk, addr, val);
		if (ret || (*val & bit))
			return ret;
		usleep_range(1000, 2000);
	}
	return -ETIMEDOUT;
}

/* SBUS ring map, port blocks and QGPHYs out of reset */
/* all blocks of the switch in reset (the power-on state): nothing forwards */
static int bcm53344_quiesce(struct bcm53344 *sw)
{
	int ret;

	ret = bcm53344_reg_write(sw, BLK_TOP, TOP_SOFT_RESET_REG, 0);
	if (!ret)
		ret = bcm53344_reg_write(sw, BLK_TOP, TOP_SOFT_RESET_REG_2, 0);
	msleep(10);
	if (ret)
		dev_crit(&sw->pdev->dev, "switch not put into reset: %d\n", ret);
	return ret;
}

static int bcm53344_reset_ports(struct bcm53344 *sw)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(bcm53344_ring_map); i++)
		writel(bcm53344_ring_map[i], sw->cmic + CMIC_SBUS_RING_MAP(i));

	/*
	 * Whatever ran before (a driver reload without a reset of the chip),
	 * every block goes into reset first, as after power-on: no port
	 * forwards while the tables are rebuilt.
	 */
	ret = bcm53344_quiesce(sw);
	if (ret)
		return ret;
	ret = bcm53344_reg_setbits(sw, BLK_TOP, TOP_SOFT_RESET_REG,
				   TOP_PORT_BLOCKS_RST_L);
	msleep(10);
	return ret;
}

/* time sync, SBUS timeout, IP/EP/MMU out of reset */
static int bcm53344_reset_core(struct bcm53344 *sw)
{
	int ret;

	ret = bcm53344_reg_setbits(sw, BLK_TOP, TOP_SOFT_RESET_REG,
				   TOP_TS_RST_L | TOP_SPARE_RST_L);
	if (!ret)
		ret = bcm53344_reg_setbits(sw, BLK_TOP, TOP_SOFT_RESET_REG_2,
					   TOP_TS_PLL_RST_L);
	if (!ret)
		ret = bcm53344_reg_setbits(sw, BLK_TOP, TOP_SOFT_RESET_REG_2,
					   TOP_TS_PLL_POST_RST_L);
	msleep(10);
	if (ret)
		return ret;

	writel(0x7d0, sw->cmic + CMIC_SBUS_TIMEOUT);
	dev_dbg(&sw->pdev->dev, "CMIC_SBUS_TIMEOUT -> 0x7d0, read back %#x\n",
		 readl(sw->cmic + CMIC_SBUS_TIMEOUT));

	/*
	 * IP and MMU out of reset first; the MMU port mapping and the
	 * MMU arbiter TDM before the EP leaves reset, since the EP makes its
	 * first cell requests to the MMU then (with the reset mapping 0x3f
	 * they go unanswered and the MMU never grants)
	 */
	ret = bcm53344_reg_setbits(sw, BLK_TOP, TOP_SOFT_RESET_REG,
				   TOP_IP_RST_L | TOP_MMU_RST_L);
	msleep(10);
	if (ret)
		return ret;
	{
		struct bcm53344_bulk b = { };
		int port, i, n = ARRAY_SIZE(bcm53344_tdm);

		for (port = 0; port < NUM_PORTS; port++)
			if (bcm53344_port_valid(port))
				bcm53344_bulk_reg(sw, &b, BLK_MMU,
						  MMU_LOG_TO_PHY_PORT_MAPPING | port, port);
		for (i = 0; i < n; i++)
			bcm53344_bulk_mem(sw, &b, BLK_MMU, MMU_ARB_TDM_TABLE + i,
					  bcm53344_tdm[i] |
					  (i == n - 1 ? MMU_TDM_WRAP_EN : 0));
		dev_dbg(&sw->pdev->dev, "mmu before ep reset release: %d writes, %d bad\n",
			 b.writes, b.bad);
	}
	ret = bcm53344_reg_setbits(sw, BLK_TOP, TOP_SOFT_RESET_REG, TOP_EP_RST_L);
	msleep(10);
	return ret;
}

/* hardware clear of the IPIPE and EPIPE memories */
static int bcm53344_clear_pipes(struct bcm53344 *sw)
{
	u32 ing = 0, egr = 0;
	int ret;

	ret = bcm53344_reg_set(sw, BLK_IPIPE, ING_HW_RESET_CONTROL_1, 0);
	if (!ret)
		ret = bcm53344_reg_set(sw, BLK_IPIPE, ING_HW_RESET_CONTROL_2,
				       HW_RESET_ALL | HW_RESET_VALID |
				       FIELD_PREP(HW_RESET_COUNT, 0x8000));
	if (!ret)
		ret = bcm53344_reg_set(sw, BLK_EPIPE, EGR_HW_RESET_CONTROL_0, 0);
	if (!ret)
		ret = bcm53344_reg_set(sw, BLK_EPIPE, EGR_HW_RESET_CONTROL_1,
				       HW_RESET_ALL | HW_RESET_VALID |
				       FIELD_PREP(HW_RESET_COUNT, 0x4000));
	if (ret)
		return ret;

	ret = bcm53344_reg_poll(sw, BLK_IPIPE, ING_HW_RESET_CONTROL_2,
				HW_RESET_DONE, &ing);
	if (!ret)
		ret = bcm53344_reg_poll(sw, BLK_EPIPE, EGR_HW_RESET_CONTROL_1,
					HW_RESET_DONE, &egr);
	dev_dbg(&sw->pdev->dev, "pipe clear: ING %#x EGR %#x%s\n", ing, egr,
		 ret ? " (timeout)" : "");
	if (ret)
		return ret;

	ret = bcm53344_reg_set(sw, BLK_IPIPE, ING_HW_RESET_CONTROL_2, 0);
	if (!ret)
		ret = bcm53344_reg_set(sw, BLK_EPIPE, EGR_HW_RESET_CONTROL_1, 0);
	return ret;
}

/* XLPORT (ports 26-29, TSC4_0 SerDes to the B50220 PHYs) */
#define XLPORT_MODE_REG		0x02020a00
#define XLPORT_ENABLE_REG	0x02020b00
#define XLPORT_SOFT_RESET	0x02020c00
#define XLPORT_MIB_RESET	0x02022c00
#define XLPORT_MAC_CONTROL	0x02021000
#define  XMAC0_RESET		BIT(0)
#define XLPORT_XGXS0_CTRL_REG	0x02021400
#define  XGXS_RSTB_PLL		BIT(1)
#define  XGXS_RSTB_HW		BIT(2)
#define  XGXS_RSTB_REFCLK	BIT(3)
#define  XGXS_REFIN_EN		BIT(5)
#define  XGXS_PWRDWN		BIT(6)
#define  XGXS_IDDQ		BIT(8)
#define TSC_BUS			1	/* internal bus 1, address 1 (port 26) */

/*
 * XLPORT0 and its TSC out of reset (LCPLL reference), quad mode with all
 * four ports enabled. The MACs stay off until the zones are set up.
 */
static int bcm53344_setup_xlport(struct bcm53344 *sw)
{
	int blk = BLK_XLPORT(0);
	u32 v = 0;
	int ret;

	ret = bcm53344_reg_read(sw, blk, XLPORT_XGXS0_CTRL_REG, &v);
	if (ret)
		return ret;
	v = (v | XGXS_REFIN_EN) & ~(XGXS_PWRDWN | XGXS_IDDQ);
	ret = bcm53344_reg_set(sw, blk, XLPORT_XGXS0_CTRL_REG, v);
	usleep_range(1100, 2000);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_XGXS0_CTRL_REG, v & ~XGXS_RSTB_HW);
	usleep_range(11100, 12000);
	v |= XGXS_RSTB_HW;
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_XGXS0_CTRL_REG, v);
	usleep_range(1100, 2000);
	v |= XGXS_RSTB_REFCLK;
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_XGXS0_CTRL_REG, v);
	v |= XGXS_RSTB_PLL;
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_XGXS0_CTRL_REG, v);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_MAC_CONTROL, XMAC0_RESET);
	udelay(10);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_MAC_CONTROL, 0);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_SOFT_RESET, 0xf);
	if (!ret)	/* XPORT0 core and PHY port mode quad (0) */
		ret = bcm53344_reg_set(sw, blk, XLPORT_MODE_REG, 0);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_SOFT_RESET, 0);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_ENABLE_REG, 0xf);
	/* MIB counters live in memory: clear them */
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_MIB_RESET, 0xf);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, XLPORT_MIB_RESET, 0);
	return ret;
}

/*
 * TSC4 SerDes of ports 26-29. A register is a 16-bit
 * address; it is reached over clause 22 at internal bus 1, address
 * 1 + lane: the AER (block 0xffd0, register 0x1e) selects the lane
 * (0-3, 6 = broadcast), register 0x1f the block (address & 0xfff0), and
 * registers 0x00-0x0f / 0x10-0x1f the low nibble (bit 15 of the address
 * selects the upper half).
 */
#define TSC_AER_BCST		6
#define TSC_PLL_STATUS		0x9010
#define  TSC_PLLSEQPASS		BIT(11)
#define TSC_PMD_LIVE		0xc150	/* per lane: bit 3 PMD lock, bit 0 signal ok */
#define TSC_PCS_LIVE		0xc154	/* per lane: bit 1 link, bit 0 sync */

static int bcm53344_tsc(struct bcm53344 *sw, int lane, int aer, u16 addr,
			bool write, u16 val)
{
	int phy = 1 + lane;
	int reg = (addr & 0xf) | ((addr & 0x8000) ? 0x10 : 0);
	int ret;

	ret = bcm53344_miim(sw, true, TSC_BUS, phy, SERDES_BLOCK, true,
			    SERDES_AER_BLOCK);
	if (!ret)
		ret = bcm53344_miim(sw, true, TSC_BUS, phy, SERDES_AER, true, aer);
	if (!ret)
		ret = bcm53344_miim(sw, true, TSC_BUS, phy, SERDES_BLOCK, true,
				    addr & 0xfff0);
	if (!ret)
		ret = bcm53344_miim(sw, true, TSC_BUS, phy, reg, write, val);
	return ret;
}

/*
 * One step of the TSC set-up: read-modify-write of addr (mask 0xffff:
 * plain write). TSC_OP_BCST writes all four lanes; the old value is read
 * from the lane itself (lane 0 for broadcast).
 */
#define TSC_OP_BCST	BIT(0)
#define TSC_OP_SLEEP	BIT(1)	/* sleep val microseconds, no access */
#define TSC_OP_POLL	BIT(2)	/* wait until (addr & mask) == val */

struct bcm53344_tsc_op {
	u8 flags;
	u16 addr, val, mask;
};

#define TB(a, v, m)	{ TSC_OP_BCST, a, v, m }
#define TL(a, v, m)	{ 0, a, v, m }
#define TSLEEP(us)	{ TSC_OP_SLEEP, 0, us, 0 }

/*
 * Core set-up of the TSC through lane 0: forced speed, no microcode,
 * reference clock 156.25 MHz, PLL divider 40 for 1G SGMII. Each entry
 * changes only the bits under its mask.
 */
static const struct bcm53344_tsc_op bcm53344_tsc_core[] = {
	TB(0x9003, 0xe4e4, 0xffff),	/* LANE_SWAP: none */
	TL(0xc017, 0x8000, 0x8000),	/* lane 0 TX electrical idle */
	TB(0x9001, 0x0000, 0x0080),	/* MISC_CONTROL: enable PLL */
	TB(0x9002, 0x0010, 0x0010),	/* enable power timer */
	TB(0x9002, 0x0000, 0xff00),	/* POWER_CONTROL: all lanes on */
	TSLEEP(1000),
	TB(0xc21e, 0x0800, 0x0800),	/* rxSeqStart_AN_disable */
	TB(0xf014, 0x22a6, 0xffff),	/* temperature default */
	TB(0x9001, 0xff00, 0xff00),	/* tx/rx analog reset, all lanes */
	TB(0xc21e, 0x8000, 0x8000),	/* DSC state machine hold */
	TSLEEP(1000),
	TL(0x9000, 0x0000, 0x0080),	/* PLL sequencer stop */
	TB(0x9000, 0x6000, 0xe000),	/* refclk 156.25 MHz */
	TSLEEP(2000),
	TB(0x909a, 0x0000, 0x0020),	/* LFCK bypass off */
	TB(0x9012, 0x0100, 0xff00),	/* CORE_RESET: SW defaults */
	TB(0x9253, 0x10ed, 0xffff),
	TB(0x9250, 0x0350, 0xffff),
	TB(0x9251, 0x0350, 0xffff),
	TB(0x9254, 0x1a10, 0xffff),
	TB(0x9255, 0x14d4, 0xffff),
	TB(0x925c, 0x07d0, 0xffff),
	TB(0x9257, 0x8236, 0xffff),
	TB(0x9258, 0x1a10, 0xffff),
	TB(0x9259, 0x029a, 0xffff),
	TB(0x9256, 0x0350, 0xffff),
	TB(0x925a, 0x8236, 0xffff),
	TB(0x925b, 0x01fe, 0xffff),
	TB(0xc031, 0x0808, 0x0808),
	TB(0x9248, 0x0ee0, 0xffff),	/* credit table address (HR2) */
	TB(0xc253, 0x3f00, 0x3f00),	/* TX taps KX/OS/BR/KR/2p5 */
	TB(0x9111, 0x03f0, 0x7fff),
	TB(0x9112, 0x5a54, 0x7fff),
	TB(0xc110, 0x5a54, 0x7fff),
	TB(0x9113, 0x03f0, 0x7fff),
	TB(0xc017, 0x0600, 0x0f00),	/* TX amplitude (idriver 6) */
	TB(0x9000, 0x0000, 0x0078),	/* port mode select: quad */
	TB(0x9000, 0x7200, 0xff00),	/* SET_PORT_MODE: plldiv 40 */
	TSLEEP(1000),
	TB(0xc100, 0x0000, 0xffff),	/* PORT_CLEAN_UP: credits */
	TB(0xc104, 0x0000, 0xffff),
	TL(0x9000, 0x0080, 0x0080),	/* PLL sequencer start */
	{ TSC_OP_POLL, TSC_PLL_STATUS, TSC_PLLSEQPASS, TSC_PLLSEQPASS },
};

/*
 * Per-lane set-up for one 1G SGMII port, forced speed. The analog reset
 * release of 0x9001 is done separately (one bit pair per lane).
 */
static const struct bcm53344_tsc_op bcm53344_tsc_lane[] = {
	TL(0xc021, 0x0000, 0x8000),	/* RX polarity: no flip */
	TL(0xc011, 0x0000, 0x0020),	/* TX polarity: no flip */
	TL(0xc104, 0x0000, 0x4000),	/* CREDIT_CONTROL off */
	TL(0xc100, 0x0000, 0x4000),
	TL(0xc113, 0x0000, 0x0001),	/* TX_LANE_CONTROL */
	TL(0xc113, 0x0000, 0x0002),
	TL(0xc137, 0x0000, 0x0001),	/* RX path off */
	TL(0x9000, 0x0000, 0x0078),	/* SET_SPD_INTF 1G SGMII */
	TL(0xc254, 0x0200, 0x3f00),	/* actual speed 1000M */
	TL(0xc260, 0x0000, 0xffff),	/* firmware mode 0 */
	TL(0xc100, 0x0019, 0x3fff),	/* CREDIT_SET */
	TL(0xc101, 0x8200, 0xffff),
	TL(0xc102, 0x0040, 0x3fff),
	TL(0xc103, 0x0018, 0x1fff),
	TL(0xc104, 0x0000, 0xbfff),
	TL(0xc105, 0x0000, 0x1fff),
	TL(0xc100, 0x0000, 0x8000),
	TL(0xc111, 0x000c, 0x1e1c),	/* ENCODE_SET */
	TL(0xc113, 0x0000, 0xc000),
	TL(0xc114, 0x0004, 0x0004),
	TL(0xa003, 0x0002, 0x00ff),
	TL(0xc130, 0x2cb0, 0xfffa),	/* DECODE_SET */
	TL(0xc136, 0x0001, 0x0007),
	TL(0xc134, 0x0003, 0xbe07),
	TL(0xc137, 0x002a, 0x007a),
	TL(0xa023, 0x0400, 0x0400),
	TL(0xc253, 0x0080, 0x00f0),
	TL(0xc113, 0x01c0, 0x01c0),
	TL(0xc134, 0x0070, 0x0070),
	TL(0xa001, 0x0070, 0x0070),
	TL(0xa024, 0x010c, 0x010c),
	TL(0xa002, 0x0070, 0x0070),
	TL(0xa024, 0x0203, 0x0203),
};

/* Tail per lane: DSC start, RX path on, TX out of electrical idle */
static const struct bcm53344_tsc_op bcm53344_tsc_lane_up[] = {
	TL(0xc21e, 0x0000, 0x8000),	/* DSC state machine run */
	TSLEEP(1000),
	TL(0xc137, 0x0001, 0x0001),	/* RX path on */
	TL(0xc138, 0x0000, 0x0006),	/* RX signal detect: normal */
	TL(0xc01a, 0x0000, 0x0001),	/* ANATX input enabled */
	TL(0xc017, 0x0000, 0x8000),	/* TX electrical idle off */
	TSLEEP(1000),
	/* lane enabled: TX lane and credits on */
	TL(0xc113, 0x0002, 0x0002),	/* TX_LANE_CONTROL: lane out of reset */
	TL(0xc113, 0x0001, 0x0001),	/* TX lane enabled */
	TL(0xc100, 0x4000, 0x4000),	/* CREDIT_CONTROL: credits on */
};

static int bcm53344_tsc_run(struct bcm53344 *sw, int lane,
			    const struct bcm53344_tsc_op *op, int n)
{
	struct device *dev = &sw->pdev->dev;
	int i, old, now, ret;

	for (i = 0; i < n; i++, op++) {
		int aer = (op->flags & TSC_OP_BCST) ? TSC_AER_BCST : lane;
		int rd = (op->flags & TSC_OP_BCST) ? 0 : lane;
		u16 nv;

		if (op->flags & TSC_OP_SLEEP) {
			usleep_range(op->val, op->val + 500);
			continue;
		}
		if (op->flags & TSC_OP_POLL) {
			unsigned long end = jiffies + msecs_to_jiffies(500);

			do {
				now = bcm53344_tsc(sw, lane, rd, op->addr, false, 0);
				if (now < 0 || (now & op->mask) == op->val)
					break;
				usleep_range(1000, 2000);
			} while (time_before(jiffies, end));
			dev_dbg(dev, "tsc lane %d poll %#06x: %#06x%s\n", lane,
				 op->addr, now,
				 now >= 0 && (now & op->mask) == op->val ? "" : " (timeout)");
			if (now < 0)
				return now;
			continue;
		}
		old = 0;
		if (op->mask != 0xffff) {
			old = bcm53344_tsc(sw, lane, rd, op->addr, false, 0);
			if (old < 0)
				return old;
		}
		nv = (old & ~op->mask) | (op->val & op->mask);
		ret = bcm53344_tsc(sw, lane, aer, op->addr, true, nv);
		now = bcm53344_tsc(sw, lane, rd, op->addr, false, 0);
		dev_dbg(dev, "tsc aer %d %#06x: %#06x -> %#06x, read back %#06x%s\n",
			 aer, op->addr, old, nv, now, ret ? " (failed)" : "");
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * TSC4_0 for ports 26-29 as 1G SGMII towards the B50220 PHYs, without
 * microcode. The MACs stay off until the zones are set up.
 */
static int bcm53344_setup_tsc(struct bcm53344 *sw)
{
	int lane, ret;

	ret = bcm53344_tsc_run(sw, 0, bcm53344_tsc_core,
			       ARRAY_SIZE(bcm53344_tsc_core));
	for (lane = 0; lane < 4 && !ret; lane++) {
		/* MAIN0_RESET: release tx/rx analog reset of this lane */
		const struct bcm53344_tsc_op rel = TL(0x9001, 0x0000,
						      0x1100 << lane);

		ret = bcm53344_tsc_run(sw, lane, bcm53344_tsc_lane,
				       ARRAY_SIZE(bcm53344_tsc_lane));
		if (!ret)
			ret = bcm53344_tsc_run(sw, lane, &rel, 1);
		if (!ret)
			ret = bcm53344_tsc_run(sw, lane, bcm53344_tsc_lane_up,
					       ARRAY_SIZE(bcm53344_tsc_lane_up));
	}
	msleep(100);
	return ret;
}

/*
 * B50220 of ports 26-29 (external bus 1, addresses 31, 0, 15, 16), board
 * setting: expansion register 0x7e = 0 (RDB access), then RDB
 * read-modify-writes (value/mask). The first one only on ports 26/27;
 * the LED set-up (spare control 0x012: link speed LED mode; LED control
 * 0x019) on all four, else the link LED of the automedium ports 28/29
 * stays dark at 1000 Mb/s.
 */
static int bcm53344_setup_b50220(struct bcm53344 *sw)
{
	static const u8 addr[] = { 31, 0, 15, 16 };
	static const struct { u16 reg, val, mask; } rdb[] = {
		{ 0x000, 0x0000, 0x0020 },
		{ 0x012, 0x0004, 0x0005 },
		{ 0x019, 0x0008, 0x011b },
	};
	struct device *dev = &sw->pdev->dev;
	int i, j, ret;

	for (i = 0; i < ARRAY_SIZE(addr); i++) {
		int a = addr[i];

		ret = bcm53344_miim(sw, false, 1, a, 0x17, true, 0x0f7e);
		if (!ret)
			ret = bcm53344_miim(sw, false, 1, a, 0x15, true, 0x0000);
		if (ret)
			return ret;
		for (j = a == 15 || a == 16 ? 1 : 0; j < ARRAY_SIZE(rdb); j++) {
			int old, now;
			u16 nv;

			ret = bcm53344_miim(sw, false, 1, a, 0x1e, true, rdb[j].reg);
			old = ret ? ret : bcm53344_miim(sw, false, 1, a, 0x1f, false, 0);
			if (old < 0)
				return old;
			nv = (old & ~rdb[j].mask) | rdb[j].val;
			ret = bcm53344_miim(sw, false, 1, a, 0x1f, true, nv);
			bcm53344_miim(sw, false, 1, a, 0x1e, true, rdb[j].reg);
			now = bcm53344_miim(sw, false, 1, a, 0x1f, false, 0);
			dev_dbg(dev, "b50220 ext addr %d rdb %#05x: %#06x -> %#06x, read back %#06x%s\n",
				 a, rdb[j].reg, old, nv, now, ret ? " (failed)" : "");
			if (ret)
				return ret;
		}
	}
	return 0;
}

/* 1:1 port mapping, egress enable, GPORT blocks */
static int bcm53344_setup_ports(struct bcm53344 *sw)
{
	struct bcm53344_bulk b = { };
	int port, i, ret;

	for (port = 0; port < NUM_PHYS_PORTS; port++)
		bcm53344_bulk_mem(sw, &b, BLK_IPIPE, ING_PHYS_TO_LOGIC_MAP + port,
				  bcm53344_port_valid(port) ? port : INVALID_LOGIC_PORT);
	for (port = 0; port < NUM_PORTS; port++) {
		bcm53344_bulk_reg(sw, &b, BLK_EPIPE, EGR_LOGIC_TO_PHYS_MAP | port,
				  bcm53344_port_valid(port) ? port : INVALID_PHYS_PORT);
		if (!bcm53344_port_valid(port))
			continue;
		bcm53344_bulk_mem(sw, &b, BLK_EPIPE, EGR_ENABLE + port,
				  EGR_PRT_ENABLE);
		bcm53344_bulk_reg(sw, &b, BLK_EPIPE, EGR_VLAN_CONTROL_1 | port,
				  REMARK_OUTER_DOT1P);
		/*
		 * MMU logical to physical port: the
		 * reset value 0x3f is no port, and the MMU never hands a
		 * queued frame to the egress pipeline
		 */
		bcm53344_bulk_reg(sw, &b, BLK_MMU, MMU_LOG_TO_PHY_PORT_MAPPING | port,
				  port);
	}
	dev_dbg(&sw->pdev->dev, "port mapping: %d writes, %d bad\n", b.writes, b.bad);
	if (b.bad)
		return -EIO;

	for (i = 0; i < 3; i++) {
		ret = bcm53344_reg_set(sw, BLK_GPORT(i), GPORT_CONFIG,
				       GPORT_EN | GPORT_CLR_CNT);
		if (!ret)
			ret = bcm53344_reg_set(sw, BLK_GPORT(i), GPORT_CONFIG, GPORT_EN);
		if (ret)
			return ret;
	}
	return 0;
}

/* TDM calendar and MMU thresholds */
static int bcm53344_setup_mmu(struct bcm53344 *sw)
{
	struct bcm53344_bulk b = { };
	int n = ARRAY_SIZE(bcm53344_tdm);
	int port, cos, i, ret;
	u32 v;

	ret = bcm53344_reg_read(sw, BLK_IPIPE, IARB_TDM_CONTROL, &v);
	if (ret)
		return ret;
	v |= IARB_TDM_DISABLE;
	v = (v & ~IARB_TDM_WRAP_PTR) | FIELD_PREP(IARB_TDM_WRAP_PTR, 83);
	ret = bcm53344_reg_set(sw, BLK_IPIPE, IARB_TDM_CONTROL, v);
	if (ret)
		return ret;
	for (i = 0; i < n; i++) {
		bcm53344_bulk_mem(sw, &b, BLK_IPIPE, IARB_TDM_TABLE + i,
				  bcm53344_tdm[i]);
		bcm53344_bulk_mem(sw, &b, BLK_MMU, MMU_ARB_TDM_TABLE + i,
				  bcm53344_tdm[i] |
				  (i == n - 1 ? MMU_TDM_WRAP_EN : 0));
	}
	ret = bcm53344_reg_set(sw, BLK_IPIPE, IARB_TDM_CONTROL,
			       FIELD_PREP(IARB_TDM_WRAP_PTR, n - 1));
	if (ret)
		return ret;

	ret = bcm53344_reg_read(sw, BLK_MMU, MISCCONFIG, &v);
	if (!ret)
		ret = bcm53344_reg_set(sw, BLK_MMU, MISCCONFIG,
				       (v & ~SKIDMARKER) | FIELD_PREP(SKIDMARKER, 3) |
				       METERING_CLK_EN);
	if (!ret)
		ret = bcm53344_reg_set(sw, BLK_IPIPE, IP_TO_CMICM_CREDIT_TRANSFER,
				       CREDIT_TRANSFER_ENABLE |
				       FIELD_PREP(CREDIT_NUM, 32));
	if (ret)
		return ret;

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bcm53344_port_valid(port))
			continue;
		for (cos = 0; cos < 8; cos++) {
			u32 c = cos << 8 | port;
			u32 max = cos ? MMU_CELL_MAX_PRI_1_7 : MMU_CELL_MAX_PRI_0;

			bcm53344_bulk_reg(sw, &b, BLK_MMU, HOLCOSPKTSETLIMIT + c,
					  MMU_XQ_LIMIT);
			bcm53344_bulk_reg(sw, &b, BLK_MMU, HOLCOSPKTRESETLIMIT + c,
					  MMU_XQ_LIMIT - 4);
			bcm53344_bulk_reg(sw, &b, BLK_MMU, HOLCOSMINXQCNT + c,
					  MMU_COS_MIN_XQS);
			bcm53344_bulk_reg(sw, &b, BLK_MMU, LWMCOSCELLSETLIMIT + c,
					  LIMIT2(MMU_COS_MIN_CELLS, MMU_COS_MIN_CELLS));
			bcm53344_bulk_reg(sw, &b, BLK_MMU, HOLCOSCELLMAXLIMIT + c,
					  LIMIT2(max, max - 12));
		}
		bcm53344_bulk_reg(sw, &b, BLK_MMU, DYNXQCNTPORT | port,
				  MMU_DYN_XQ_PER_PORT);
		bcm53344_bulk_reg(sw, &b, BLK_MMU, DYNRESETLIMPORT | port,
				  MMU_DYN_XQ_PER_PORT - 4);
		bcm53344_bulk_reg(sw, &b, BLK_MMU, IBPDISCARDSETLIMIT | port,
				  MMU_TOTAL_CELLS - 1);
		bcm53344_bulk_reg(sw, &b, BLK_MMU, DYNCELLLIMIT | port,
				  LIMIT2(MMU_DYN_CELL_LIMIT, MMU_DYN_CELL_LIMIT - 24));
		bcm53344_bulk_reg(sw, &b, BLK_MMU, IBPPKTSETLIMIT | port,
				  MMU_COS_MIN_CELLS);
		bcm53344_bulk_reg(sw, &b, BLK_MMU, IBPCELLSETLIMIT | port,
				  MMU_XOFF_CELL_LIMIT);
		/* not HiGig: E2EFC limits; PARITY (bit 29) is kept by hardware */
		bcm53344_bulk_reg_mask(sw, &b, BLK_MMU, E2EFC_CNT_SET_LIMIT + (port << 8),
				       LIMIT2(80, 12), ~E2EFC_PARITY);
		bcm53344_bulk_reg_mask(sw, &b, BLK_MMU, E2EFC_CNT_RESET_LIMIT + (port << 8),
				       LIMIT2(60, 9), ~E2EFC_PARITY);
		bcm53344_bulk_reg_mask(sw, &b, BLK_MMU, E2EFC_CNT_DISC_LIMIT + (port << 8),
				       LIMIT2(9504, 1456), ~E2EFC_PARITY);
	}
	dev_dbg(&sw->pdev->dev, "TDM + MMU: %d writes, %d bad\n", b.writes, b.bad);

	ret = bcm53344_reg_set(sw, BLK_MMU, TOTALDYNCELLSETLIMIT, MMU_TOTAL_DYN_CELLS);
	if (!ret)
		ret = bcm53344_reg_set(sw, BLK_MMU, TOTALDYNCELLRESETLIMIT,
				       MMU_TOTAL_DYN_CELLS - 24);
	return ret ? ret : (b.bad ? -EIO : 0);
}

/*
 * The QGPHYs of the front ports: powered up with autonegotiation
 * on (all abilities left at their reset values), then the link state
 */
static int bcm53344_setup_phys(struct bcm53344 *sw)
{
	struct device *dev = &sw->pdev->dev;
	int i, t, bmcr, bmsr, ret;

	for (i = 0; i < ARRAY_SIZE(bcm53344_front); i++) {
		int phy = bcm53344_front[i].phy;
		int id1 = bcm53344_qgphy_read(sw, phy, MII_PHYSID1);
		int id2 = bcm53344_qgphy_read(sw, phy, MII_PHYSID2);

		bmcr = bcm53344_qgphy_read(sw, phy, MII_BMCR);
		bmsr = bcm53344_qgphy_read(sw, phy, MII_BMSR);
		dev_dbg(dev, "%s: port %d phy %d id %04x:%04x bmcr %#06x bmsr %#06x adv %#06x ctrl1000 %#06x\n",
			 bcm53344_front[i].name, bcm53344_front[i].port, phy,
			 id1, id2, bmcr, bmsr,
			 bcm53344_qgphy_read(sw, phy, MII_ADVERTISE),
			 bcm53344_qgphy_read(sw, phy, MII_CTRL1000));
		if (bmcr < 0)
			return bmcr;
		if ((bmcr & (BMCR_PDOWN | BMCR_ISOLATE)) || !(bmcr & BMCR_ANENABLE)) {
			u16 val = (bmcr & ~(BMCR_PDOWN | BMCR_ISOLATE)) |
				  BMCR_ANENABLE | BMCR_ANRESTART;

			ret = bcm53344_qgphy_write(sw, phy, MII_BMCR, val);
			dev_dbg(dev, "%s: bmcr %#06x -> %#06x, read back %#06x%s\n",
				 bcm53344_front[i].name, bmcr, val,
				 bcm53344_qgphy_read(sw, phy, MII_BMCR),
				 ret ? " (failed)" : "");
			if (ret)
				return ret;
		}
	}

	/* autonegotiation takes a few seconds */
	for (t = 0; t < 50; t++) {
		msleep(100);
		bmsr = bcm53344_qgphy_read(sw, bcm53344_front[0].phy, MII_BMSR);
		bmsr = bcm53344_qgphy_read(sw, bcm53344_front[0].phy, MII_BMSR);
		if (bmsr >= 0 && (bmsr & BMSR_LSTATUS))
			break;
	}
	for (i = 0; i < ARRAY_SIZE(bcm53344_front); i++) {
		int phy = bcm53344_front[i].phy;

		bcm53344_qgphy_read(sw, phy, MII_BMSR);	/* latched */
		dev_dbg(dev, "%s: after %d ms bmsr %#06x lpa %#06x stat1000 %#06x\n",
			 bcm53344_front[i].name, (t + 1) * 100,
			 bcm53344_qgphy_read(sw, phy, MII_BMSR),
			 bcm53344_qgphy_read(sw, phy, MII_LPA),
			 bcm53344_qgphy_read(sw, phy, MII_STAT1000));
	}
	return 0;
}

/* GPORT block and index of a GE port (2-25) */
#define GPORT_BLK(port)		BLK_GPORT(((port) - 2) / 8)
#define GPORT_IDX(port)		(((port) - 2) % 8)

/*
 * Clause 22 access to one lane of the uplink SerDes, through its AER block,
 * in register block blk (registers 0x10-0x1f of a block; block 0 for the
 * IEEE registers 0-0xf)
 */
static int bcm53344_serdes_blk(struct bcm53344 *sw, int lane, u16 blk, int reg,
			       bool write, u16 val)
{
	int ret;

	ret = bcm53344_miim(sw, true, SERDES_BUS, SERDES_PHY, SERDES_BLOCK, true,
			    SERDES_AER_BLOCK);
	if (!ret)
		ret = bcm53344_miim(sw, true, SERDES_BUS, SERDES_PHY, SERDES_AER,
				    true, lane);
	if (!ret)
		ret = bcm53344_miim(sw, true, SERDES_BUS, SERDES_PHY, SERDES_BLOCK,
				    true, blk);
	if (!ret)
		ret = bcm53344_miim(sw, true, SERDES_BUS, SERDES_PHY, reg, write,
				    val);
	return ret;
}

static int bcm53344_serdes(struct bcm53344 *sw, int lane, int reg, bool write,
			   u16 val)
{
	return bcm53344_serdes_blk(sw, lane, 0, reg, write, val);
}


/* Digital block: 1000X control 1 / status 1 (xgxs register map) */
#define SERDES_DIG_BLOCK	0x8300
#define SERDES_1000X_CTRL1	0x10
#define  SERDES_FIBER_MODE	0x0001

/* TX driver of the two QSGMII lanes (AER 0 and 4), board setting */
#define SERDES_TX0_BLOCK	0x8060
#define SERDES_TX_DRIVER	0x17
#define SERDES_TX_DRIVER_VAL	0x0b92

/*
 * UniMAC of a GE port: reset, 1000 Mb/s, frame length, then enabled. The
 * MACs of the QGPHY ports see no link from their PHY: TX/RX are enabled
 * by software override there, and the speed follows the PHY.
 */
/* XLMAC of ports 26-29 (64-bit port registers of XLPORT0, index = lane) */
#define XLMAC_CTRL		0x00060000
#define  XLMAC_TX_EN		BIT_ULL(0)
#define  XLMAC_RX_EN		BIT_ULL(1)
#define  XLMAC_LOCAL_LPBK	BIT_ULL(2)
#define  XLMAC_SOFT_RESET	BIT_ULL(6)
#define  XLMAC_IPG_CHECK_DIS	BIT_ULL(11)
#define XLMAC_MODE		0x00060100
#define  XLMAC_SPEED_1000	(2 << 4)	/* SPEED_MODE */
#define XLMAC_TX_CTRL		0x00060400
#define  XLMAC_CRC_MODE		GENMASK_ULL(1, 0)
#define  XLMAC_CRC_PER_PKT	3
#define  XLMAC_AVERAGE_IPG	GENMASK_ULL(18, 12)
#define XLMAC_RX_CTRL		0x00060600
#define  XLMAC_STRIP_CRC	BIT_ULL(2)
#define  XLMAC_STRICT_PREAMBLE	BIT_ULL(3)
#define  XLMAC_RUNT_THRESHOLD	GENMASK_ULL(10, 4)
#define XLMAC_RX_MAX_SIZE	0x00060800
#define XLMAC_RX_LSS_CTRL	0x00060a00
#define  XLMAC_DROP_TX_ON_FAULT	GENMASK_ULL(6, 4)	/* local, remote, link int. */
#define XLPORT_RPKT		0x00000b00	/* counters */
#define XLPORT_TPKT		0x00004c00
#define XLPORT_RFCS		0x00000f00
#define XLPORT_RERPKT		0x00001800
#define XLMAC_TXFIFO_CELL_CNT	0x00062b00

/*
 * XLMAC of a GE port: 1000 Mb/s, IEEE, CRC per packet, average IPG 96
 * bits, runt threshold 64, then TX/RX enabled. No EP credit reset: the EP
 * leaves reset after the MMU mapping, and pulses on running ports lose
 * the credits.
 */
static int bcm53344_xlmac_enable(struct bcm53344 *sw, int port)
{
	int blk = BLK_XLPORT(0), idx = port - 26;
	u64 ctrl, v;
	int ret;

	ret = bcm53344_reg64_read(sw, blk, XLMAC_CTRL | idx, &ctrl);
	if (ret)
		return ret;
	v = ctrl & ~(XLMAC_SOFT_RESET | XLMAC_RX_EN | XLMAC_TX_EN |
		     XLMAC_IPG_CHECK_DIS | XLMAC_LOCAL_LPBK);
	ret = bcm53344_reg64_write(sw, blk, XLMAC_CTRL | idx, v);
	if (!ret)
		ret = bcm53344_reg64_write(sw, blk, XLMAC_RX_MAX_SIZE | idx,
					   UMAC_MAX_FRAME);
	if (!ret)
		ret = bcm53344_reg64_write(sw, blk, XLMAC_MODE | idx,
					   XLMAC_SPEED_1000);
	if (!ret)
		ret = bcm53344_reg64_read(sw, blk, XLMAC_TX_CTRL | idx, &v);
	if (!ret) {
		v &= ~(XLMAC_CRC_MODE | XLMAC_AVERAGE_IPG);
		v |= FIELD_PREP(XLMAC_CRC_MODE, XLMAC_CRC_PER_PKT) |
		     FIELD_PREP(XLMAC_AVERAGE_IPG, 96 / 8);
		ret = bcm53344_reg64_write(sw, blk, XLMAC_TX_CTRL | idx, v);
	}
	if (!ret)
		ret = bcm53344_reg64_read(sw, blk, XLMAC_RX_CTRL | idx, &v);
	if (!ret) {
		v &= ~(XLMAC_STRIP_CRC | XLMAC_STRICT_PREAMBLE |
		       XLMAC_RUNT_THRESHOLD);
		v |= FIELD_PREP(XLMAC_RUNT_THRESHOLD, 64);
		ret = bcm53344_reg64_write(sw, blk, XLMAC_RX_CTRL | idx, v);
	}
	if (!ret)
		ret = bcm53344_reg64_read(sw, blk, XLMAC_RX_LSS_CTRL | idx, &v);
	if (!ret)
		ret = bcm53344_reg64_write(sw, blk, XLMAC_RX_LSS_CTRL | idx,
					   v | XLMAC_DROP_TX_ON_FAULT);
	if (!ret) {
		v = (ctrl & ~(XLMAC_SOFT_RESET | XLMAC_IPG_CHECK_DIS |
			      XLMAC_LOCAL_LPBK)) | XLMAC_RX_EN | XLMAC_TX_EN;
		ret = bcm53344_reg64_write(sw, blk, XLMAC_CTRL | idx, v);
	}
	{
		u64 c = 0, m = 0, t = 0, r = 0;

		bcm53344_reg64_read(sw, blk, XLMAC_CTRL | idx, &c);
		bcm53344_reg64_read(sw, blk, XLMAC_MODE | idx, &m);
		bcm53344_reg64_read(sw, blk, XLMAC_TX_CTRL | idx, &t);
		bcm53344_reg64_read(sw, blk, XLMAC_RX_CTRL | idx, &r);
		dev_dbg(&sw->pdev->dev, "xlmac port %d: ctrl %#llx -> %#llx mode %#llx tx_ctrl %#llx rx_ctrl %#llx%s\n",
			 port, ctrl, c, m, t, r, ret ? " (failed)" : "");
	}
	return ret;
}

static int bcm53344_mac_enable(struct bcm53344 *sw, int port)
{
	int blk = GPORT_BLK(port), idx = GPORT_IDX(port);
	u32 cfg;
	int ret;

	if (port >= 26)
		return bcm53344_xlmac_enable(sw, port);

	ret = bcm53344_reg_read(sw, blk, UMAC_COMMAND_CONFIG | idx, &cfg);
	if (ret)
		return ret;
	cfg &= ~(UMAC_TX_ENA | UMAC_RX_ENA | UMAC_ETH_SPEED);
	cfg |= FIELD_PREP(UMAC_ETH_SPEED, UMAC_SPEED_1000);
	if (port < 18)
		cfg |= UMAC_SW_OVERRIDE_TX | UMAC_SW_OVERRIDE_RX;
	ret = bcm53344_reg_set(sw, blk, UMAC_COMMAND_CONFIG | idx,
			       cfg | UMAC_SW_RESET);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, UMAC_FRM_LENGTH | idx,
				       UMAC_MAX_FRAME);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, UMAC_COMMAND_CONFIG | idx, cfg);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, UMAC_COMMAND_CONFIG | idx,
				       cfg | UMAC_TX_ENA | UMAC_RX_ENA);
	return ret;
}


/*
 * Zones: a set of front ports and the one uplink port (QSGMII to an NP6Lite
 * MAC) they share. Frames of a zone never reach another zone: EGR_MASK
 * blocks every other egress port, independent of the VLAN lookup (which
 * floods to the whole VLAN). Front ports by jack: port1 4, port2 5, port3 2, port4 3, port5 11, port6 10,
 * port7 13, port8 12, port9 15, port10 14, port11 17, port12 16; ha1 6,
 * ha2 7; wan1 8, wan2 9; port13 27, port14 26, port15 29, port16 28
 * (B50220 behind the TSC).
 */
static const struct bcm53344_zone {
	const char *name;
	int uplink;		/* 18-21: NP6Lite MAC 2-5 */
	u32 members;
} bcm53344_zones[] = {
	{ "wan1", 18, BIT(8) },
	{ "wan2", 19, BIT(9) },
};

/* VLAN_TAB, EGR_VLAN and its L2MC flood group (members, untagged) */
static int bcm53344_vlan_write(struct bcm53344 *sw, u16 vid, u32 pbm, u32 ut,
			       int l2mc, bool valid)
{
	u32 vlan[4] = { }, egr[3] = { }, mc[2] = { };
	int ret;

	if (valid) {
		bcm53344_field_set(vlan, 0, 30, pbm);			/* PORT_BITMAP */
		bcm53344_field_set(vlan, 38, 1, 1);			/* VALID */
		bcm53344_field_set(vlan, 39, 9, BCM53344_STG);		/* STG */
		bcm53344_field_set(vlan, 89, 12, l2mc);			/* BC_IDX */
		bcm53344_field_set(vlan, 101, 12, l2mc);		/* UUC_IDX */
		bcm53344_field_set(vlan, 113, 12, l2mc);		/* UMC_IDX */
		bcm53344_field_set(egr, 0, 30, ut);			/* UT_BITMAP */
		bcm53344_field_set(egr, 30, 30, pbm);			/* PORT_BITMAP */
		bcm53344_field_set(egr, 60, 8, BCM53344_STG);		/* STG */
		bcm53344_field_set(egr, 68, 1, 1);			/* VALID */
		bcm53344_field_set(mc, 8, 30, pbm);			/* PORT_BITMAP */
		bcm53344_field_set(mc, 38, 1, 1);			/* VALID */
	}
	ret = bcm53344_mem_write(sw, BLK_IPIPE, L2MC + l2mc, mc, 2);
	if (!ret)
		ret = bcm53344_mem_write(sw, BLK_IPIPE, VLAN_TAB + vid, vlan, 4);
	if (!ret)
		ret = bcm53344_mem_write(sw, BLK_EPIPE, EGR_VLAN + vid, egr, 3);
	return ret;
}

/*
 * Egress masks are the hard border between zones and DSA instances: every
 * write goes through the soft copy, and bcm53344_masks_verify reads all of
 * them back. A mismatch closes every mask (fail-closed).
 */
static void bcm53344_mask_set(struct bcm53344 *sw, struct bcm53344_bulk *b,
			      int port, u32 val)
{
	sw->egr_mask[port] = val;
	bcm53344_bulk_mem(sw, b, BLK_IPIPE, EGR_MASK + port, val);
}

static int bcm53344_masks_verify(struct bcm53344 *sw)
{
	u32 all = GENMASK(NUM_PORTS - 1, 0);
	struct bcm53344_bulk b = { };
	int port, bad = 0;

	for (port = 0; port < NUM_PORTS; port++) {
		u32 v = 0;

		if (bcm53344_mem_read(sw, BLK_IPIPE, EGR_MASK + port, &v, 1) ||
		    (v & all) != sw->egr_mask[port] || !(v & BIT(0))) {
			dev_crit(&sw->pdev->dev, "egr_mask %d: %#x, expected %#x\n",
				 port, v, sw->egr_mask[port]);
			bad++;
		}
	}
	if (!bad)
		return 0;
	for (port = 0; port < NUM_PORTS; port++)
		bcm53344_mask_set(sw, &b, port, all);
	return -EIO;
}

/*
 * Port table baseline of every port, read back: the VLAN of a frame is the
 * port VID, whatever tag it carries. No outer or inner tag is parsed (a tag
 * stays payload; DSA CPU ports parse theirs later), no VLAN translation, no
 * MAC, subnet or protocol based VLAN, no VFP; ingress filtering on (a port
 * that is not a member of its frame's VLAN drops it); PVID VID_DEAD.
 */
static const struct { u8 lsb, width; u16 val; } bcm53344_port_base[] = {
	{ 2, 1, 0 },		/* VT_ENABLE */
	{ 5, 1, 1 },		/* EN_IFILTER */
	{ 22, 1, 0 },		/* SUBNET_BASED_VID_ENABLE */
	{ 23, 1, 0 },		/* MAC_BASED_VID_ENABLE */
	{ 24, 12, VID_DEAD },	/* PORT_VID */
	{ 48, 1, 0 },		/* PORT_BRIDGE */
	{ 68, 1, 0 },		/* VFP_ENABLE */
	{ 85, 4, 0 },		/* OUTER_TPID_ENABLE */
	{ 92, 6, 0 },		/* TAG_ACTION_PROFILE_PTR */
	{ 110, 1, 0 },		/* TRUST_INCOMING_VID */
	{ 190, 5, 0 },		/* VLAN_PROTOCOL_DATA_INDEX */
	{ 215, 1, 0 },		/* INNER_TPID_ENABLE */
};

static int bcm53344_port_baseline(struct bcm53344 *sw)
{
	int port, i, ret;

	for (port = 0; port < NUM_PORTS; port++) {
		u32 pt[8];

		if (!bcm53344_port_valid(port))
			continue;
		ret = bcm53344_mem_read(sw, BLK_IPIPE, PORT_TAB + port, pt, 8);
		if (ret)
			return ret;
		for (i = 0; i < ARRAY_SIZE(bcm53344_port_base); i++)
			bcm53344_field_set(pt, bcm53344_port_base[i].lsb,
					   bcm53344_port_base[i].width,
					   bcm53344_port_base[i].val);
		ret = bcm53344_mem_write(sw, BLK_IPIPE, PORT_TAB + port, pt, 8);
		if (!ret)
			ret = bcm53344_mem_read(sw, BLK_IPIPE, PORT_TAB + port, pt, 8);
		if (ret)
			return ret;
		for (i = 0; i < ARRAY_SIZE(bcm53344_port_base); i++)
			if (bcm53344_field_get(pt, bcm53344_port_base[i].lsb,
					       bcm53344_port_base[i].width) !=
			    bcm53344_port_base[i].val) {
				dev_crit(&sw->pdev->dev, "port %d: port table bit %u not set\n",
					 port, bcm53344_port_base[i].lsb);
				return -EIO;
			}
		sw->pvid[port] = VID_DEAD;
	}
	return 0;
}

/*
 * No frame may be copied to the CMIC: without its packet DMA nobody takes
 * it, and it stalls the egress of every port. The reset values are 0;
 * written and read back anyway.
 */
static int bcm53344_cpu_paths_off(struct bcm53344 *sw)
{
	static const u32 regs[] = { CPU_CONTROL_0, CPU_CONTROL_1, CPU_CONTROL_M };
	int i, port, ret = 0;
	u32 v;

	for (i = 0; i < ARRAY_SIZE(regs) && !ret; i++) {
		ret = bcm53344_reg_write(sw, BLK_IPIPE, regs[i], 0);
		if (!ret)
			ret = bcm53344_reg_read(sw, BLK_IPIPE, regs[i], &v);
		if (!ret && v)
			ret = -EIO;
	}
	for (port = 0; port < NUM_PORTS && !ret; port++) {
		ret = bcm53344_reg_write(sw, BLK_IPIPE, PROTOCOL_PKT_CONTROL | port, 0);
		if (!ret)
			ret = bcm53344_reg_write(sw, BLK_IPIPE, IGMP_MLD_PKT_CONTROL | port, 0);
		if (!ret)
			ret = bcm53344_reg_read(sw, BLK_IPIPE, PROTOCOL_PKT_CONTROL | port, &v);
		if (!ret && v)
			ret = -EIO;
	}
	if (ret)
		dev_crit(&sw->pdev->dev, "copy-to-CPU controls not cleared: %d\n", ret);
	return ret;
}

/*
 * Learn limit per front port: a port may fill its share of the shared L2
 * table, no more; a frame with a new source address beyond the limit is
 * dropped (never copied to the CPU). System, VLAN and other ports without
 * limit (the maximum).
 */
static int bcm53344_mac_limits(struct bcm53344 *sw)
{
	u32 nolimit = FIELD_PREP(MAC_LIMIT, MAC_LIMIT_MAX), v = 0;
	int i, ret = 0;

	if (mac_limit <= 0)
		return bcm53344_reg_write(sw, BLK_IPIPE, SYS_MAC_LIMIT_CONTROL,
					  FIELD_PREP(MAC_LIMIT, MAC_LIMIT_MAX));
	for (i = 0; i < 4096 && !ret; i++)
		ret = bcm53344_mem_write(sw, BLK_IPIPE, VLAN_OR_VFI_MAC_LIMIT + i,
					 &nolimit, 1);
	for (i = 0; i < 158 && !ret; i++) {
		int port = i - MAC_LIMIT_PORT(0);
		bool front = (port >= 2 && port <= 17) || (port >= 26 && port <= 29);

		v = front ? FIELD_PREP(MAC_LIMIT, min(mac_limit, MAC_LIMIT_MAX)) |
			    MAC_LIMIT_DROP : nolimit;
		ret = bcm53344_mem_write(sw, BLK_IPIPE, PORT_OR_TRUNK_MAC_LIMIT + i,
					 &v, 1);
	}
	if (!ret)
		ret = bcm53344_reg_write(sw, BLK_IPIPE, SYS_MAC_LIMIT_CONTROL,
					 SYS_MAC_LIMIT_ENABLE | nolimit);
	if (!ret)
		ret = bcm53344_reg_read(sw, BLK_IPIPE, SYS_MAC_LIMIT_CONTROL, &v);
	dev_dbg(&sw->pdev->dev, "mac limit %d per front port, sys %#x: %d\n",
		mac_limit, v, ret);
	return ret;
}

/*
 * VLAN 1: valid without members, the PVID of every port no zone or DSA
 * instance uses (and of the CPU ports: untagged frames from the host are
 * dropped). A valid VLAN, so nothing is sent to the unconnected CMIC.
 */
static int bcm53344_vlan_dead(struct bcm53344 *sw)
{
	return bcm53344_vlan_write(sw, VID_DEAD, 0, 0, L2MC_DEAD, true);
}

/*
 * Zones. Order: uplink SerDes, then all masks and tables, the MACs
 * last, so that no front port forwards before its zone is closed.
 */
static int bcm53344_setup_passthrough(struct bcm53344 *sw)
{
	struct device *dev = &sw->pdev->dev;
	/*
	 * Not the CPU port: nothing takes frames from the CMIC without its
	 * packet DMA, and a frame for it blocks the egress of all ports
	 */
	u32 stg[2] = { }, link = 0, all = GENMASK(NUM_PORTS - 1, 0);
	u32 mask[NUM_PORTS];
	int i, port, ret;
	u64 bmap;

	/*
	 * Uplink SerDes: TX driver of both QSGMII lanes (board setting), and
	 * the uplink ports forced to 1000/full without autonegotiation
	 */
	for (i = 0; i <= 4; i += 4) {
		int old = bcm53344_serdes_blk(sw, i, SERDES_TX0_BLOCK,
					      SERDES_TX_DRIVER, false, 0);

		ret = bcm53344_serdes_blk(sw, i, SERDES_TX0_BLOCK, SERDES_TX_DRIVER,
					  true, SERDES_TX_DRIVER_VAL);
		dev_dbg(dev, "serdes aer %d tx driver %#06x -> %#06x, read back %#06x%s\n",
			 i, old, SERDES_TX_DRIVER_VAL,
			 bcm53344_serdes_blk(sw, i, SERDES_TX0_BLOCK,
					     SERDES_TX_DRIVER, false, 0),
			 ret ? " (failed)" : "");
		if (ret)
			return ret;
	}
	for (i = 18; i <= 21; i++) {
		int lane = i - 18;
		int old = bcm53344_serdes_blk(sw, lane, SERDES_DIG_BLOCK,
					      SERDES_1000X_CTRL1, false, 0);

		/* no PHY behind the uplink: fiber (1000BASE-X) mode */
		ret = bcm53344_serdes_blk(sw, lane, SERDES_DIG_BLOCK, SERDES_1000X_CTRL1,
					  true, old | SERDES_FIBER_MODE);
		if (!ret)
			ret = bcm53344_serdes(sw, lane, MII_BMCR, true,
					      BMCR_SPEED1000 | BMCR_FULLDPLX);
		dev_dbg(dev, "uplink %d: serdes lane %d 1000x_ctrl1 %#06x, bmcr %#06x%s\n",
			 i, lane,
			 bcm53344_serdes_blk(sw, lane, SERDES_DIG_BLOCK,
					     SERDES_1000X_CTRL1, false, 0),
			 bcm53344_serdes(sw, lane, MII_BMCR, false, 0),
			 ret ? " (failed)" : "");
		if (ret || old < 0)
			return ret ? ret : old;
	}

	ret = bcm53344_port_baseline(sw);
	if (!ret)
		ret = bcm53344_cpu_paths_off(sw);
	if (!ret)
		ret = bcm53344_mac_limits(sw);
	if (ret)
		return ret;

	/*
	 * Egress masks of every port first (index = source port with module
	 * id 0, set bits = blocked egress ports), applied to L2 and L3 in
	 * ING_CONFIG_64. A port outside the zones may send nowhere until a
	 * DSA instance takes it.
	 */
	for (port = 0; port < NUM_PORTS; port++)
		mask[port] = all;
	for (i = 0; i < ARRAY_SIZE(bcm53344_zones); i++) {
		u32 mem = bcm53344_zones[i].members;
		int up = bcm53344_zones[i].uplink;

		for (port = 0; port < NUM_PORTS; port++)
			if (mem & BIT(port))
				mask[port] = all & ~(mem | BIT(up));
		mask[up] = all & ~mem;
		link |= mem | BIT(up);
	}
	{
		struct bcm53344_bulk b = { };
		u64 cfg = 0;

		for (port = 0; port < NUM_PORTS; port++)
			bcm53344_mask_set(sw, &b, port, mask[port]);
		dev_dbg(dev, "egr_mask: %d writes, %d bad\n", b.writes, b.bad);
		if (b.bad)
			return -EIO;
		ret = bcm53344_masks_verify(sw);
		if (ret)
			return ret;
		ret = bcm53344_reg64_read(sw, BLK_IPIPE, ING_CONFIG_64, &cfg);
		if (!ret)
			ret = bcm53344_reg64_write(sw, BLK_IPIPE, ING_CONFIG_64,
						   cfg | APPLY_EGR_MASK_ON_L2 |
						   APPLY_EGR_MASK_ON_L3);
		if (ret)
			return ret;
		bcm53344_reg64_read(sw, BLK_IPIPE, ING_CONFIG_64, &bmap);
		dev_dbg(dev, "ING_CONFIG_64 %#llx -> %#llx\n", cfg, bmap);
	}

	for (port = 0; port < NUM_PORTS; port++)
		if (bcm53344_port_valid(port))
			bcm53344_field_set(stg, 2 * port, 2, STP_FORWARD);
	ret = bcm53344_mem_set(sw, BLK_IPIPE, STG_TAB + BCM53344_STG, stg, 2);
	if (!ret)
		ret = bcm53344_mem_set(sw, BLK_EPIPE, EGR_VLAN_STG + BCM53344_STG,
				       stg, 2);
	if (ret)
		return ret;

	/*
	 * Ingress VLAN tag action profile 0:
	 * untagged and inner-tagged frames get an outer tag with the port VID,
	 * outer-tagged ones keep it. Empty (the reset value) the frames get no
	 * VID and the flood ignores the VLAN.
	 */
	{
		u32 prof[1] = { };

		bcm53344_field_set(prof, 2, 2, TAG_ACTION_ADD);		/* UT_OTAG */
		bcm53344_field_set(prof, 8, 2, TAG_ACTION_ADD);		/* SIT_OTAG */
		bcm53344_field_set(prof, 12, 2, TAG_ACTION_REPLACE);	/* SOT_POTAG */
		bcm53344_field_set(prof, 20, 2, TAG_ACTION_REPLACE);	/* DT_POTAG */
		ret = bcm53344_mem_set(sw, BLK_IPIPE, ING_VLAN_TAG_ACTION_PROFILE,
				       prof, 1);
		if (ret)
			return ret;
	}

	ret = bcm53344_vlan_dead(sw);
	if (ret)
		return ret;

	/* one VLAN per zone (VID = uplink port), all untagged, PVID of all */
	for (i = 0; i < ARRAY_SIZE(bcm53344_zones); i++) {
		int up = bcm53344_zones[i].uplink;
		u32 pbm = bcm53344_zones[i].members | BIT(up);
		u32 vid = VID_ZONE_BASE + up;
		u32 vlan[4] = { }, egr[3] = { }, mc[2] = { };

		bcm53344_field_set(vlan, 0, 30, pbm);			/* PORT_BITMAP */
		bcm53344_field_set(vlan, 38, 1, 1);			/* VALID */
		bcm53344_field_set(vlan, 39, 9, BCM53344_STG);		/* STG */
		/* broadcast, unknown multicast/unicast flood to L2MC[idx] */
		bcm53344_field_set(vlan, 89, 12, L2MC_ZONE + i);	/* BC_IDX */
		bcm53344_field_set(vlan, 101, 12, L2MC_ZONE + i);	/* UUC_IDX */
		bcm53344_field_set(vlan, 113, 12, L2MC_ZONE + i);	/* UMC_IDX */
		bcm53344_field_set(egr, 0, 30, pbm);			/* UT_BITMAP */
		bcm53344_field_set(egr, 30, 30, pbm);			/* PORT_BITMAP */
		bcm53344_field_set(egr, 60, 8, BCM53344_STG);		/* STG */
		bcm53344_field_set(egr, 68, 1, 1);			/* VALID */
		bcm53344_field_set(mc, 8, 30, pbm);			/* PORT_BITMAP */
		bcm53344_field_set(mc, 38, 1, 1);			/* VALID */
		ret = bcm53344_mem_set(sw, BLK_IPIPE, L2MC + L2MC_ZONE + i, mc, 2);
		if (!ret)
			ret = bcm53344_mem_set(sw, BLK_IPIPE, VLAN_TAB + vid, vlan, 4);
		if (!ret)
			ret = bcm53344_mem_set(sw, BLK_EPIPE, EGR_VLAN + vid, egr, 3);
		if (ret)
			return ret;

		for (port = 0; port < NUM_PORTS; port++) {
			u32 pt[8] = { };

			if (!(pbm & BIT(port)))
				continue;
			ret = bcm53344_mem_read(sw, BLK_IPIPE, PORT_TAB + port, pt, 8);
			if (ret)
				return ret;
			bcm53344_field_set(pt, 24, 12, vid);		/* PORT_VID */
			bcm53344_field_set(pt, 92, 6, 0);		/* TAG_ACTION_PROFILE_PTR */
			/* hardware learning, forward (CML 8 = ARL | FWD) */
			bcm53344_field_set(pt, 121, 4, CML_LEARN_FWD);	/* CML_FLAGS_NEW */
			bcm53344_field_set(pt, 125, 4, CML_LEARN_FWD);	/* CML_FLAGS_MOVE */
			ret = bcm53344_mem_write(sw, BLK_IPIPE, PORT_TAB + port, pt, 8);
			if (ret)
				return ret;
		}
	}

	/* L2 aging of the learned entries */
	ret = bcm53344_reg_set(sw, BLK_IPIPE, L2_AGE_TIMER,
			       L2_AGE_ENA | FIELD_PREP(L2_AGE_VAL, 300));
	if (ret)
		return ret;

	ret = bcm53344_reg64_read(sw, BLK_IPIPE, EPC_LINK_BMAP, &bmap);
	if (!ret)
		ret = bcm53344_reg64_write(sw, BLK_IPIPE, EPC_LINK_BMAP, link);
	dev_dbg(dev, "EPC_LINK_BMAP %#llx -> %#x%s\n", bmap, link,
		 ret ? " (failed)" : "");
	if (ret)
		return ret;

	/* the MACs last: zones closed, masks as they must be */
	ret = bcm53344_masks_verify(sw);
	if (ret)
		return ret;
	for (port = 0; port < NUM_PORTS; port++) {
		if (!(link & BIT(port)))
			continue;
		ret = bcm53344_mac_enable(sw, port);
		if (ret)
			return ret;
	}
	dev_dbg(dev, "MACs enabled: %#x\n", link);
	sw->link_bmap = link;
	return 0;
}


/* debugfs: MAC state and counters of the front and uplink ports, read only */
static int bcm53344_ports_show(struct seq_file *m, void *unused)
{
	struct bcm53344 *sw = m->private;
	int port;

	for (port = 2; port <= 25; port++) {
		int blk = GPORT_BLK(port), idx = GPORT_IDX(port);
		u32 cfg = 0, mode = 0, rx = 0, tx = 0, q = 0, e = 0;

		bcm53344_reg_read(sw, blk, UMAC_COMMAND_CONFIG | idx, &cfg);
		bcm53344_reg_read(sw, blk, UMAC_MAC_MODE | idx, &mode);
		bcm53344_reg_read(sw, blk, GPORT_GRPKT | idx, &rx);
		bcm53344_reg_read(sw, blk, GPORT_GTPKT | idx, &tx);
		bcm53344_reg_read(sw, BLK_MMU, MMU_DYNPKTCNTPORT | port, &q);
		bcm53344_reg_read(sw, BLK_MMU, XQEMPTY | port, &e);
		seq_printf(m, "port %2d: command_config %#010x mac_mode %#06x rx %u tx %u mmu_pkts %u xqempty %#x\n",
			   port, cfg, mode, rx, tx, q, e);
	}
	for (port = 26; port <= 29; port++) {
		int blk = BLK_XLPORT(0), idx = port - 26, lane = idx;
		u64 ctrl = 0, rx = 0, tx = 0, fcs = 0, err = 0, cells = 0;
		u32 q = 0, e = 0, req = 0;

		bcm53344_reg64_read(sw, blk, XLMAC_CTRL | idx, &ctrl);
		bcm53344_reg64_read(sw, blk, XLPORT_RPKT | idx, &rx);
		bcm53344_reg64_read(sw, blk, XLPORT_TPKT | idx, &tx);
		bcm53344_reg64_read(sw, blk, XLPORT_RFCS | idx, &fcs);
		bcm53344_reg64_read(sw, blk, XLPORT_RERPKT | idx, &err);
		bcm53344_reg64_read(sw, blk, XLMAC_TXFIFO_CELL_CNT | idx, &cells);
		bcm53344_reg_read(sw, BLK_MMU, MMU_DYNPKTCNTPORT | port, &q);
		bcm53344_reg_read(sw, BLK_MMU, XQEMPTY | port, &e);
		bcm53344_mem_read(sw, BLK_EPIPE, EGR_PORT_REQUESTS + port, &req, 1);
		seq_printf(m, "port %2d: xlmac_ctrl %#llx rx %llu tx %llu rfcs %llu rerpkt %llu txfifo_cells %llu egr_req %u mmu_pkts %u xqempty %#x tsc pmd %#06x pcs %#06x\n",
			   port, ctrl, rx, tx, fcs, err, cells, req, q, e,
			   bcm53344_tsc(sw, lane, lane, TSC_PMD_LIVE, false, 0),
			   bcm53344_tsc(sw, lane, lane, TSC_PCS_LIVE, false, 0));
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(bcm53344_ports);

/* QGPHY addresses of ports 2-17 */
static const u8 bcm53344_gphy_addr[] = { 1, 2, 3, 4, 6, 7, 8, 9,
					 11, 12, 13, 14, 16, 17, 18, 19 };

/* debugfs: all PHYs on the switch MDIO, read only */
static int bcm53344_phys_show(struct seq_file *m, void *unused)
{
	static const u8 ext[] = { 31, 0, 15, 16 };	/* B50220, ports 26-29 */
	const int ng = ARRAY_SIZE(bcm53344_gphy_addr);
	struct bcm53344 *sw = m->private;
	int i;

	for (i = 0; i < ng + ARRAY_SIZE(ext); i++) {
		bool in = i < ng;
		int bus = in ? 0 : 1;
		int a = in ? bcm53344_gphy_addr[i] : ext[i - ng];

		bcm53344_miim(sw, in, bus, a, MII_BMSR, false, 0);	/* latched */
		seq_printf(m, "port %2d %s bus %d addr %2d: id %04x:%04x bmcr %#06x bmsr %#06x lpa %#06x stat1000 %#06x aux %#06x\n",
			   in ? i + 2 : 26 + i - ng,
			   in ? "int" : "ext", bus, a,
			   bcm53344_miim(sw, in, bus, a, MII_PHYSID1, false, 0),
			   bcm53344_miim(sw, in, bus, a, MII_PHYSID2, false, 0),
			   bcm53344_miim(sw, in, bus, a, MII_BMCR, false, 0),
			   bcm53344_miim(sw, in, bus, a, MII_BMSR, false, 0),
			   bcm53344_miim(sw, in, bus, a, MII_LPA, false, 0),
			   bcm53344_miim(sw, in, bus, a, MII_STAT1000, false, 0),
			   bcm53344_miim(sw, in, bus, a, 0x19 /* aux status */, false, 0));
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(bcm53344_phys);


static int bcm53344_init(struct bcm53344 *sw)
{
	int ret;

	dev_info(&sw->pdev->dev, "BCM53344 switch, device id %#06x rev %#x\n",
		 readl(sw->cmic + CMIC_DEV_REV_ID) & 0xffff,
		 readl(sw->cmic + CMIC_DEV_REV_ID) >> 16 & 0xff);

	ret = bcm53344_reset_ports(sw);
	if (ret)
		return ret;
	ret = bcm53344_reset_core(sw);
	if (!ret)
		ret = bcm53344_clear_pipes(sw);
	if (ret)
		return ret;
	ret = bcm53344_setup_ports(sw);
	if (!ret)
		ret = bcm53344_setup_xlport(sw);
	if (!ret) {
		/* ports 26-29 only; a failure must not stop the other ports */
		int err = bcm53344_setup_tsc(sw);

		if (err)
			dev_warn(&sw->pdev->dev, "tsc setup failed: %d\n", err);
		err = bcm53344_setup_b50220(sw);
		if (err)
			dev_warn(&sw->pdev->dev, "b50220 setup failed: %d\n", err);
	}
	if (!ret)
		ret = bcm53344_setup_mmu(sw);
	if (ret)
		return ret;
	ret = bcm53344_setup_phys(sw);
	if (ret)
		return ret;
	return bcm53344_setup_passthrough(sw);
}

/*
 * Front port LEDs: CMIC LED processor 0 (CMICm LEDUP0), the serial chain
 * converted to parallel outputs in TOP. Program: tools/led/fg100e.asm.
 */
#define CMIC_LEDUP0_CTRL	0x20000
#define  LEDUP_EN		BIT(0)
#define  LEDUP_INTRA_PORT_DELAY	GENMASK(3, 1)
#define  LEDUP_START_DELAY	GENMASK(9, 4)
#define CMIC_LEDUP0_STATUS	0x20004
#define CMIC_LEDUP0_REMAP(i)	(0x20010 + 4 * (i))	/* ports 4i..4i+3 */
#define CMIC_LEDUP0_DATA_RAM(i)	(0x20400 + 4 * (i))
#define CMIC_LEDUP0_PROG_RAM(i)	(0x20800 + 4 * (i))
#define XLPORT_LED_CHAIN_CONFIG	0x02022b00
#define TOP_PARALLEL_LED_CTRL	0x02035000
#define  LED_FAULTDET_PDWN_L	GENMASK(16, 11)
#define  LED_SER2PAR_SEL	BIT(17)
#define LED_MODE		0xf0	/* data RAM, see fg100e.asm */
#define LED_CHASE		0xf1
#define LED_LINK(port)		(0xc0 + (port))
#define  LED_LINK_UP		BIT(0)
#define  LED_LINK_1000		BIT(1)	/* link LED colour */
#define  LED_LINK_100		BIT(2)
#define QGPHY_AUX_STATUS	0x19	/* bits 10:8 resolved speed/duplex */
#define  QGPHY_HCD		GENMASK(10, 8)

/* tools/led/fg100e.asm, assembled */
static const u8 bcm53344_led_prog[] = {
	0x02, 0x0A, 0x67, 0x18, 0x06, 0xE0, 0x80, 0xD2, 0x12, 0x74, 0x02, 0x02, 0x09, 0x67, 0x18, 0x06,
	0xE0, 0x90, 0xD2, 0x01, 0x74, 0x0D, 0x3A, 0x40, 0x60, 0xE0, 0x28, 0x16, 0xF0, 0xDA, 0x00, 0x70,
	0x3F, 0xD6, 0xF1, 0x70, 0x32, 0x22, 0x01, 0x87, 0x22, 0x01, 0x87, 0x22, 0x01, 0x87, 0x22, 0x01,
	0x87, 0x57, 0x22, 0x01, 0x87, 0x22, 0x00, 0x87, 0x22, 0x00, 0x87, 0x22, 0x00, 0x87, 0x57, 0x12,
	0xC0, 0xFE, 0xE0, 0x5A, 0x00, 0x75, 0x25, 0x5A, 0x01, 0x27, 0x87, 0x5A, 0x02, 0x27, 0x87, 0x12,
	0xA0, 0xFE, 0xE0, 0x32, 0x00, 0x32, 0x01, 0xB7, 0x97, 0x75, 0x61, 0x05, 0xA2, 0x01, 0x50, 0x77,
	0x63, 0x52, 0x01, 0x5A, 0x00, 0x27, 0x87, 0x22, 0x00, 0x87, 0x57,
};

/* chase order: front labels wan1 wan2 ha1 ha2 port1..port12 (switch ports) */
static const u8 bcm53344_led_chase_order[] = {
	8, 9, 6, 7, 4, 5, 2, 3, 11, 10, 13, 12, 15, 14, 17, 16,
};

static void bcm53344_led_work(struct work_struct *work)
{
	struct bcm53344 *sw = container_of(to_delayed_work(work),
					   struct bcm53344, led_work);
	int n = ARRAY_SIZE(bcm53344_led_chase_order);

	if (sw->led_step < n) {
		writel(bcm53344_led_chase_order[sw->led_step],
		       sw->cmic + CMIC_LEDUP0_DATA_RAM(LED_CHASE));
		writel(1, sw->cmic + CMIC_LEDUP0_DATA_RAM(LED_MODE));
		sw->led_step++;
		schedule_delayed_work(&sw->led_work, msecs_to_jiffies(led_chase_ms));
	} else {
		/* the QGPHY jacks back to status, go on with port13-16 */
		writel(0, sw->cmic + CMIC_LEDUP0_DATA_RAM(LED_MODE));
		sw->b50220_step = 0;
		schedule_delayed_work(&sw->b50220_led_work, 0);
	}
}

/*
 * The UniMACs of the front ports run with a forced link (SW override), so
 * the LED processor sees every port up: the link LEDs follow the PHYs,
 * polled here, and written to the LED data RAM.
 */
/*
 * The UniMAC of a QGPHY port runs with a forced link (SW override): its
 * speed must follow the PHY. Changed under SW_RESET, TX/RX enables kept.
 */
static void bcm53344_umac_speed(struct bcm53344 *sw, int port, int speed)
{
	int blk = GPORT_BLK(port), idx = GPORT_IDX(port);
	u32 cfg = 0, now = 0;
	int ret;

	ret = bcm53344_reg_read(sw, blk, UMAC_COMMAND_CONFIG | idx, &cfg);
	if (ret)
		return;
	cfg = (cfg & ~UMAC_ETH_SPEED) | FIELD_PREP(UMAC_ETH_SPEED, speed);
	ret = bcm53344_reg_set(sw, blk, UMAC_COMMAND_CONFIG | idx, cfg | UMAC_SW_RESET);
	udelay(10);
	if (!ret)
		ret = bcm53344_reg_set(sw, blk, UMAC_COMMAND_CONFIG | idx, cfg);
	bcm53344_reg_read(sw, blk, UMAC_COMMAND_CONFIG | idx, &now);
	dev_info(&sw->pdev->dev, "port %d: umac speed %s, command_config %#x%s\n",
		 port, speed == 2 ? "1000" : speed == 1 ? "100" : "10", now,
		 ret ? " (failed)" : "");
	if (!ret)
		sw->umac_speed[port] = speed;
}

/*
 * TSC lane speed for 1G/100M/10M SGMII (ports 26-29): actual speed 0xc254, credits 0xc100-0xc105, decoder
 * 0xc130; 10/100 also enable the PCS credits (0xc104 bit 14) and the
 * SGMII speed switch (0xc100 bit 15). TX/RX/credits off around it.
 */
static const struct {
	u16 aspd, c100, c101, c103, c104, c105, c130;
} bcm53344_tsc_spd[3] = {
	[0] = { 0x0000, 0x09c4, 0x8000, 0x09c3, 0x4019 | 0x8000, 0x0018, 0x2ca8 },
	[1] = { 0x0100, 0x00fa, 0x8100, 0x00f9, 0x4019, 0x0018, 0x2ca0 },
	[2] = { 0x0200, 0x0019, 0x8200, 0x0018, 0x0000, 0x0000, 0x2cb0 },
};

static int bcm53344_tsc_speed(struct bcm53344 *sw, int lane, int speed)
{
	const typeof(bcm53344_tsc_spd[0]) *v = &bcm53344_tsc_spd[speed];
	u16 sgmii_sw = speed < 2 ? 0x8000 : 0;
	const struct bcm53344_tsc_op op[] = {
		TL(0xc100, 0x0000, 0x4000),	/* credits off */
		TL(0xc104, 0x0000, 0x4000),
		TL(0xc113, 0x0000, 0x0001),	/* TX lane off, reset */
		TL(0xc113, 0x0000, 0x0002),
		TL(0xc137, 0x0000, 0x0001),	/* RX path off */
		TL(0xc254, v->aspd, 0x3f00),
		TL(0xc100, v->c100 | sgmii_sw, 0xbfff),
		TL(0xc101, v->c101, 0xffff),
		TL(0xc102, 0x0040, 0x3fff),
		TL(0xc103, v->c103, 0x1fff),
		TL(0xc104, v->c104, 0xffff),
		TL(0xc105, v->c105, 0x1fff),
		TL(0xc130, v->c130, 0xfffa),
		TL(0xc137, 0x0001, 0x0001),	/* RX path on */
		TL(0xc113, 0x0002, 0x0002),	/* TX lane out of reset, on */
		TL(0xc113, 0x0001, 0x0001),
		TL(0xc100, 0x4000, 0x4000),	/* credits on */
	};
	int ret = bcm53344_tsc_run(sw, lane, op, ARRAY_SIZE(op));

	if (!ret)	/* XLMAC SPEED_MODE: 0 10, 1 100, 2 1000 */
		ret = bcm53344_reg64_write(sw, BLK_XLPORT(0), XLMAC_MODE | lane,
					   speed << 4);
	dev_info(&sw->pdev->dev, "port %d: tsc/xlmac speed %s%s\n", 26 + lane,
		 speed == 2 ? "1000" : speed == 1 ? "100" : "10",
		 ret ? " (failed)" : "");
	if (!ret)
		sw->tsc_speed[lane] = speed;
	return ret;
}

/*
 * Resolved speed of a copper PHY with link: 2 = 1000, 1 = 100, 0 = 10.
 * Aux status HCD only when it says autonegotiation is complete (bit 15),
 * else (parallel detection, downshift) from the standard registers as
 * genphy_read_lpa: own abilities and partner abilities intersected
 * (the HCD bits are stale without AN complete, e.g. after a 100 FD
 * partner without autonegotiation).
 */
static int bcm53344_phy_speed(struct bcm53344 *sw, bool internal, int bus,
			      int a)
{
	int aux = bcm53344_miim(sw, internal, bus, a, QGPHY_AUX_STATUS, false, 0);
	int adv, lpa, c1000, s1000;

	if (aux >= 0 && (aux & BIT(15))) {
		int hcd = FIELD_GET(QGPHY_HCD, aux);

		if (hcd)
			return hcd >= 6 ? 2 : hcd >= 3 ? 1 : 0;
	}
	adv = bcm53344_miim(sw, internal, bus, a, MII_ADVERTISE, false, 0);
	lpa = bcm53344_miim(sw, internal, bus, a, MII_LPA, false, 0);
	c1000 = bcm53344_miim(sw, internal, bus, a, MII_CTRL1000, false, 0);
	s1000 = bcm53344_miim(sw, internal, bus, a, MII_STAT1000, false, 0);
	if (adv < 0 || lpa < 0 || c1000 < 0 || s1000 < 0)
		return 2;
	if ((c1000 & (ADVERTISE_1000FULL | ADVERTISE_1000HALF)) &
	    (s1000 >> 2) & (ADVERTISE_1000FULL | ADVERTISE_1000HALF))
		return 2;
	if (adv & lpa & (ADVERTISE_100FULL | ADVERTISE_100HALF))
		return 1;
	if (adv & lpa & (ADVERTISE_10FULL | ADVERTISE_10HALF))
		return 0;
	return 1;	/* no common mode reported: parallel detection, 100 */
}

static void bcm53344_led_link_work(struct work_struct *work)
{
	struct bcm53344 *sw = container_of(to_delayed_work(work),
					   struct bcm53344, led_link_work);
	int i;

	for (i = 0; i < ARRAY_SIZE(bcm53344_gphy_addr); i++) {
		int a = bcm53344_gphy_addr[i], bmsr;
		u32 v = 0;

		/* DSA ports: phylink reports the link (bcm53344_dsa_link) */
		if (READ_ONCE(sw->dsa_ports) & BIT(i + 2))
			continue;
		bcm53344_qgphy_read(sw, a, MII_BMSR);	/* latched low */
		bmsr = bcm53344_qgphy_read(sw, a, MII_BMSR);
		if (bmsr >= 0 && (bmsr & BMSR_LSTATUS)) {
			int speed = bcm53344_phy_speed(sw, true, 0, a);

			v = LED_LINK_UP | (speed == 2 ? LED_LINK_1000 : LED_LINK_100);
			if (speed != sw->umac_speed[i + 2])
				bcm53344_umac_speed(sw, i + 2, speed);
		}
		writel(v, sw->cmic + CMIC_LEDUP0_DATA_RAM(LED_LINK(i + 2)));
	}
	/* B50220 copper ports 26-29 (ext. bus 1): TSC lane and XLMAC follow */
	for (i = 0; i < 4; i++) {
		static const u8 ext[4] = { 31, 0, 15, 16 };
		int a = ext[i], bmsr, speed;

		if (READ_ONCE(sw->dsa_ports) & BIT(26 + i))
			continue;
		bcm53344_miim(sw, false, 1, a, MII_BMSR, false, 0);
		bmsr = bcm53344_miim(sw, false, 1, a, MII_BMSR, false, 0);
		if (bmsr < 0 || !(bmsr & BMSR_LSTATUS))
			continue;
		speed = bcm53344_phy_speed(sw, false, 1, a);
		if (speed != sw->tsc_speed[i])
			bcm53344_tsc_speed(sw, i, speed);
	}
	schedule_delayed_work(&sw->led_link_work, msecs_to_jiffies(500));
}

/*
 * B50220 of ports 26-29 (front port14, port13, port16, port15): four LED
 * pins per port, mode per pin in RDB 0x01d (LED1/LED2) and 0x01e
 * (LED3/LED4), 4 bits each.
 */
#define B50220_RDB_LED_SEL1	0x01d
#define B50220_RDB_LED_SEL2	0x01e
#define B50220_LED_OFF		0xe
#define B50220_LED_ON		0xf

/* front order port13, port14, port15, port16: ext. bus 1 addresses */
static const struct { const char *name; u8 addr; } bcm53344_b50220_front[] = {
	{ "port13", 0 }, { "port14", 31 }, { "port15", 16 }, { "port16", 15 },
};

static int bcm53344_b50220_rdb(struct bcm53344 *sw, int addr, u16 reg,
			       bool write, u16 val)
{
	int ret;

	ret = bcm53344_miim(sw, false, 1, addr, 0x1e, true, reg);
	if (ret)
		return ret;
	return bcm53344_miim(sw, false, 1, addr, 0x1f, write, val);
}

/* LED1..LED4 modes (4 bits each); bits 15:8 of the selectors kept */
static void bcm53344_b50220_led_modes(struct bcm53344 *sw, int addr,
				      const u8 *m)
{
	static const u16 reg[2] = { B50220_RDB_LED_SEL1, B50220_RDB_LED_SEL2 };
	int i, v;

	for (i = 0; i < 2; i++) {
		v = bcm53344_b50220_rdb(sw, addr, reg[i], false, 0);
		if (v < 0)
			continue;
		bcm53344_b50220_rdb(sw, addr, reg[i], true,
				    (v & 0xff00) | m[2 * i + 1] << 4 | m[2 * i]);
	}
}

/*
 * Pins: LED1 link green (1000, mode 0), LED2 link red (10/100, mode 1),
 * LED3 activity green (mode 3), LED4 unused (mode 6).
 */
static const u8 bcm53344_b50220_led_dark[4] = {
	B50220_LED_OFF, B50220_LED_OFF, B50220_LED_OFF, B50220_LED_OFF };
static const u8 bcm53344_b50220_led_lit[4] = {
	B50220_LED_ON, B50220_LED_OFF, B50220_LED_ON, B50220_LED_OFF };
static const u8 bcm53344_b50220_led_status[4] = { 0, 1, 3, 6 };

/* chase light part 2: port13-16 after the jacks of the LED processor */
static void bcm53344_b50220_led_work(struct work_struct *work)
{
	struct bcm53344 *sw = container_of(to_delayed_work(work),
					   struct bcm53344, b50220_led_work);
	int n = ARRAY_SIZE(bcm53344_b50220_front), i, step = sw->b50220_step;

	for (i = 0; i < n; i++)
		bcm53344_b50220_led_modes(sw, bcm53344_b50220_front[i].addr,
					  i == step ? bcm53344_b50220_led_lit :
					  step < n ? bcm53344_b50220_led_dark :
					  bcm53344_b50220_led_status);
	if (step < n) {
		sw->b50220_step++;
		schedule_delayed_work(&sw->b50220_led_work,
				      msecs_to_jiffies(led_chase_ms));
	} else {
		dev_dbg(&sw->pdev->dev, "leds: chase done, status display\n");
	}
}

static int bcm53344_setup_leds(struct bcm53344 *sw)
{
	struct device *dev = &sw->pdev->dev;
	u32 top = 0, v;
	int i, ret;

	writel(0, sw->cmic + CMIC_LEDUP0_CTRL);
	/* LED port i scans physical port i; the XLPORT block reversed */
	for (i = 0; i < 8; i++) {
		int p[4], j;

		for (j = 0; j < 4; j++)
			p[j] = 4 * i + 2 + j;
		if (p[0] == 26 || p[0] == 30)
			for (j = 0; j < 4; j++)
				p[j] = 4 * i + 2 + 3 - j;
		writel(p[0] | p[1] << 6 | p[2] << 12 | p[3] << 18,
		       sw->cmic + CMIC_LEDUP0_REMAP(i));
	}
	ret = bcm53344_reg_set(sw, BLK_XLPORT(0), XLPORT_LED_CHAIN_CONFIG, 6);
	if (ret)
		return ret;
	/* XLPORT1 too; its ports are not bonded out on the BCM53344 */
	if (bcm53344_reg_set(sw, BLK_XLPORT(1), XLPORT_LED_CHAIN_CONFIG, 6))
		dev_dbg(dev, "leds: xlport1 led chain config not written\n");
	for (i = 0; i < 256; i++) {
		writel(0, sw->cmic + CMIC_LEDUP0_DATA_RAM(i));
		writel(i < ARRAY_SIZE(bcm53344_led_prog) ? bcm53344_led_prog[i] : 0,
		       sw->cmic + CMIC_LEDUP0_PROG_RAM(i));
	}
	ret = bcm53344_reg_read(sw, BLK_TOP, TOP_PARALLEL_LED_CTRL, &top);
	if (!ret)
		ret = bcm53344_reg_set(sw, BLK_TOP, TOP_PARALLEL_LED_CTRL,
				       LED_SER2PAR_SEL | LED_FAULTDET_PDWN_L);
	bcm53344_reg_read(sw, BLK_TOP, TOP_PARALLEL_LED_CTRL, &v);
	dev_dbg(dev, "leds: top_parallel_led_ctrl %#x -> %#lx, read back %#x%s\n",
		 top, LED_SER2PAR_SEL | LED_FAULTDET_PDWN_L, v, ret ? " (failed)" : "");
	if (ret)
		return ret;
	if (led_chase) {
		writel(bcm53344_led_chase_order[0],
		       sw->cmic + CMIC_LEDUP0_DATA_RAM(LED_CHASE));
		writel(1, sw->cmic + CMIC_LEDUP0_DATA_RAM(LED_MODE));
	}
	writel(FIELD_PREP(LEDUP_START_DELAY, 6) |
	       FIELD_PREP(LEDUP_INTRA_PORT_DELAY, 5) | LEDUP_EN,
	       sw->cmic + CMIC_LEDUP0_CTRL);
	msleep(20);
	dev_dbg(dev, "leds: program %zu bytes, ctrl %#x status %#x\n",
		 ARRAY_SIZE(bcm53344_led_prog), readl(sw->cmic + CMIC_LEDUP0_CTRL),
		 readl(sw->cmic + CMIC_LEDUP0_STATUS));
	if (led_chase) {
		sw->led_step = 0;
		schedule_delayed_work(&sw->led_work, 0);
	}
	schedule_delayed_work(&sw->led_link_work, 0);
	{
		int i;

		for (i = 0; i < ARRAY_SIZE(bcm53344_b50220_front); i++) {
			int a = bcm53344_b50220_front[i].addr;

			/* expansion 0x7e = 0: RDB access */
			bcm53344_miim(sw, false, 1, a, 0x17, true, 0x0f7e);
			bcm53344_miim(sw, false, 1, a, 0x15, true, 0x0000);
			dev_dbg(dev, "leds: b50220 %s addr %d led_sel %#06x %#06x led_ctrl %#06x\n",
				 bcm53344_b50220_front[i].name, a,
				 bcm53344_b50220_rdb(sw, a, B50220_RDB_LED_SEL1, false, 0),
				 bcm53344_b50220_rdb(sw, a, B50220_RDB_LED_SEL2, false, 0),
				 bcm53344_b50220_rdb(sw, a, 0x019, false, 0));
		}
		/* dark until the chase light reaches them, else status */
		for (i = 0; i < ARRAY_SIZE(bcm53344_b50220_front); i++)
			bcm53344_b50220_led_modes(sw, bcm53344_b50220_front[i].addr,
						  led_chase ? bcm53344_b50220_led_dark :
						  bcm53344_b50220_led_status);
	}
	return 0;
}


/*
 * debugfs: valid L2 entries (VLAN, port, flags); the MAC is shown with
 * its last two bytes only.
 */
/* debugfs: learn limits and counters, read only */
static int bcm53344_limits_show(struct seq_file *m, void *unused)
{
	struct bcm53344 *sw = m->private;
	u32 v = 0;
	int i;

	bcm53344_reg_read(sw, BLK_IPIPE, SYS_MAC_LIMIT_CONTROL, &v);
	seq_printf(m, "sys %#x (limit param %d)\n", v, mac_limit);
	for (i = 0; i < 158; i++) {
		u32 c = 0, l = 0;

		bcm53344_mem_read(sw, BLK_IPIPE, PORT_OR_TRUNK_MAC_COUNT + i, &c, 1);
		bcm53344_mem_read(sw, BLK_IPIPE, PORT_OR_TRUNK_MAC_LIMIT + i, &l, 1);
		if ((c & 0x7fff) || (l & MAC_LIMIT_DROP))
			seq_printf(m, "index %3d: count %u limit %lu drop %u\n", i,
				   c & 0x7fff, FIELD_GET(MAC_LIMIT, l),
				   !!(l & MAC_LIMIT_DROP));
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(bcm53344_limits);

static int bcm53344_l2_show(struct seq_file *m, void *unused)
{
	struct bcm53344 *sw = m->private;
	int i, n = 0;

	for (i = 0; i < L2X_ENTRIES; i++) {
		u32 e[4] = { };

		if (bcm53344_mem_read(sw, BLK_IPIPE, L2X + i, e, 4))
			break;
		if (!bcm53344_field_get(e, 99, 1))		/* VALID */
			continue;
		n++;
		seq_printf(m, "%5d: key %u vlan %u mac ..:%02x:%02x port %u static %u hit da/sa %u/%u counted %u\n",
			   i, bcm53344_field_get(e, 0, 2), bcm53344_field_get(e, 2, 12),
			   bcm53344_field_get(e, 22, 8), bcm53344_field_get(e, 14, 8),
			   bcm53344_field_get(e, 62, 6), bcm53344_field_get(e, 97, 1),
			   bcm53344_field_get(e, 101, 1), bcm53344_field_get(e, 102, 1),
			   bcm53344_field_get(e, 95, 1));
	}
	seq_printf(m, "%d valid entries\n", n);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(bcm53344_l2);


/* ------------------------------------------------------------ MDIO buses */

static int bcm53344_mdio_read(struct mii_bus *bus, int addr, int reg)
{
	struct bcm53344 *sw = bus->priv;
	bool in = bus == sw->mii_int;

	return bcm53344_miim(sw, in, in ? 0 : 1, addr, reg, false, 0);
}

static int bcm53344_mdio_write(struct mii_bus *bus, int addr, int reg,
			       u16 val)
{
	struct bcm53344 *sw = bus->priv;
	bool in = bus == sw->mii_int;

	return bcm53344_miim(sw, in, in ? 0 : 1, addr, reg, true, val);
}

/* the internal (QGPHY) or external (B50220) bus, if the device tree has it */
static int bcm53344_mdio_register(struct bcm53344 *sw, struct mii_bus **busp,
				  const char *node)
{
	struct device *dev = &sw->pdev->dev;
	struct device_node *np;
	struct mii_bus *bus;
	int ret;

	np = of_get_child_by_name(dev->of_node, node);
	if (!np)
		return 0;
	bus = devm_mdiobus_alloc(dev);
	if (!bus) {
		of_node_put(np);
		return -ENOMEM;
	}
	bus->name = node;
	snprintf(bus->id, MII_BUS_ID_SIZE, "%s-%s", dev_name(dev), node);
	bus->priv = sw;
	bus->parent = dev;
	bus->read = bcm53344_mdio_read;
	bus->write = bcm53344_mdio_write;
	*busp = bus;	/* the read callback tells the buses apart by it */
	ret = devm_of_mdiobus_register(dev, bus, np);
	of_node_put(np);
	if (ret)
		*busp = NULL;
	return ret;
}

/* ------------------------------------------------------------ DSA instances */

/*
 * Two DSA instances on one chip, each with its own uplink as the CPU port
 * and its own NP6Lite MAC as the conduit: tag_8021q encodes 16 user ports
 * per switch at most. User port i is DSA port i, the CPU port follows.
 * The instance is the switch index of "dsa,member" (each in a tree of its
 * own, so that their standalone VIDs differ in the switch ID bits).
 */
static const struct bcm53344_dsa_layout {
	int n;		/* user ports */
	u8 hw[16];	/* switch port of each */
	u8 cpu;		/* uplink port */
} bcm53344_dsa_layouts[] = {
	/* port1 .. port16 */
	{ 16, { 4, 5, 2, 3, 11, 10, 13, 12, 15, 14, 17, 16, 27, 26, 29, 28 }, 20 },
	/* ha1, ha2 */
	{ 2, { 6, 7 }, 21 },
};

struct bcm53344_dsa {
	struct dsa_switch ds;
	struct bcm53344 *sw;
	const struct bcm53344_dsa_layout *lay;
	u32 users;	/* switch ports of the used user ports */
	struct net_device *br[16];	/* bridge of each user port */
	u16 upvid[16];			/* PVID the VLAN-aware bridge asks for */
	u16 aware_vid[16];		/* bridge VLAN left by a VLAN-aware port */
};

static int bcm53344_dsa_hw(struct bcm53344_dsa *d, int port)
{
	return port == d->lay->n ? d->lay->cpu : d->lay->hw[port];
}

static enum dsa_tag_protocol
bcm53344_dsa_get_tag_protocol(struct dsa_switch *ds, int port,
			      enum dsa_tag_protocol mprot)
{
	return DSA_TAG_PROTO_BCM53344_8021Q;
}

/* the flood group of a tag_8021q VID: VIDs 3072-4095 -> 0-1023 */
static int bcm53344_dsa_l2mc(u16 vid)
{
	if (vid < 3072 || vid - 3072 >= L2MC_ZONE)
		return -EINVAL;
	return vid - 3072;
}

static int bcm53344_dsa_vlan_add(struct dsa_switch *ds, int port, u16 vid,
				 u16 flags)
{
	struct bcm53344_dsa *d = ds->priv;
	struct bcm53344 *sw = d->sw;
	int hw = bcm53344_dsa_hw(d, port), l2mc = bcm53344_dsa_l2mc(vid);
	struct bcm53344_vlan *v = &sw->vlan[vid];
	int ret;

	if (l2mc < 0)
		return l2mc;
	mutex_lock(&sw->cfg_lock);
	v->members |= BIT(hw);
	if (flags & BRIDGE_VLAN_INFO_UNTAGGED)
		v->untagged |= BIT(hw);
	else
		v->untagged &= ~BIT(hw);
	ret = bcm53344_vlan_write(sw, vid, v->members, v->untagged, l2mc, true);
	if (!ret && (flags & BRIDGE_VLAN_INFO_PVID)) {
		ret = bcm53344_port_tab_set(sw, hw, 24, 12, vid);	/* PORT_VID */
		if (!ret)
			sw->pvid[hw] = vid;
	}
	mutex_unlock(&sw->cfg_lock);
	dev_dbg(ds->dev, "vlan %u add port %d (switch port %d) flags %#x: members %#x untagged %#x: %d\n",
		vid, port, hw, flags, v->members, v->untagged, ret);
	return ret;
}

static int bcm53344_dsa_vlan_del(struct dsa_switch *ds, int port, u16 vid)
{
	struct bcm53344_dsa *d = ds->priv;
	struct bcm53344 *sw = d->sw;
	int hw = bcm53344_dsa_hw(d, port), l2mc = bcm53344_dsa_l2mc(vid);
	struct bcm53344_vlan *v = &sw->vlan[vid];
	int i, ret = 0;

	if (l2mc < 0)
		return l2mc;
	mutex_lock(&sw->cfg_lock);
	/*
	 * A port joining a bridge leaves its standalone VLAN, yet the host
	 * still sends to that one port (not forwarded by the bridge: the
	 * software flow table, BPDUs), and only this VLAN reaches a single
	 * port. It stays a member: the port does not parse tags and its PVID
	 * is the bridge VLAN, so none of its frames gets this VID (the tagger
	 * also drops them from a bridged port).
	 */
	for (i = 0; i < ds->num_ports; i++) {
		if (dsa_is_user_port(ds, i) &&
		    vid == dsa_tag_8021q_standalone_vid(dsa_to_port(ds, i))) {
			mutex_unlock(&sw->cfg_lock);
			return 0;
		}
	}
	if (sw->pvid[hw] == vid) {
		ret = bcm53344_port_tab_set(sw, hw, 24, 12, VID_DEAD);
		if (!ret)
			sw->pvid[hw] = VID_DEAD;
	}
	v->members &= ~BIT(hw);
	v->untagged &= ~BIT(hw);
	if (!ret)
		ret = bcm53344_vlan_write(sw, vid, v->members, v->untagged,
					  l2mc, v->members);
	mutex_unlock(&sw->cfg_lock);
	return ret;
}

/*
 * VLANs of a VLAN-aware bridge. Only its ports parse tags and only they (and
 * their CPU port) enter these VLANs: the VLAN table is shared, and a port
 * outside would get the floods of a VID it merely asked for. cfg_lock held.
 */
static int bcm53344_user_vlan_sync(struct bcm53344 *sw, u16 vid)
{
	struct bcm53344_vlan *v = &sw->vlan[vid];
	u32 mem = v->want & sw->aware_ports;
	int bit, ret;

	if (!mem) {
		if (!v->l2mc)
			return 0;
		ret = bcm53344_vlan_write(sw, vid, 0, 0, v->l2mc, false);
		clear_bit(v->l2mc - L2MC_USER, sw->l2mc_user);
		v->l2mc = 0;
		v->members = 0;
		v->untagged = 0;
		return ret;
	}
	if (!v->l2mc) {
		bit = find_first_zero_bit(sw->l2mc_user, L2MC_USER_N);
		if (bit >= L2MC_USER_N)
			return -ENOSPC;
		set_bit(bit, sw->l2mc_user);
		v->l2mc = L2MC_USER + bit;
	}
	v->members = mem;
	v->untagged = v->want_ut & mem;
	return bcm53344_vlan_write(sw, vid, v->members, v->untagged, v->l2mc,
				   true);
}

static int bcm53344_dsa_port_vlan_add(struct dsa_switch *ds, int port,
				      const struct switchdev_obj_port_vlan *vlan,
				      struct netlink_ext_ack *extack)
{
	struct bcm53344_dsa *d = ds->priv;
	struct bcm53344 *sw = d->sw;
	int hw = bcm53344_dsa_hw(d, port), ret;
	struct bcm53344_vlan *v;
	u16 vid = vlan->vid;

	if (vid_is_dsa_8021q(vid)) {
		NL_SET_ERR_MSG_MOD(extack, "VIDs 3072-4095 are reserved");
		return -EBUSY;
	}
	v = &sw->vlan[vid];
	mutex_lock(&sw->cfg_lock);
	v->want |= BIT(hw);
	/* the CPU port always sees the tag: it tells the VLAN to the host */
	if ((vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED) && !dsa_is_cpu_port(ds, port))
		v->want_ut |= BIT(hw);
	else
		v->want_ut &= ~BIT(hw);
	ret = bcm53344_user_vlan_sync(sw, vid);
	if (!ret && !dsa_is_cpu_port(ds, port)) {
		if (vlan->flags & BRIDGE_VLAN_INFO_PVID)
			d->upvid[port] = vid;
		else if (d->upvid[port] == vid)
			d->upvid[port] = 0;
		if (sw->aware_ports & BIT(hw))
			ret = bcm53344_port_tab_set(sw, hw, 24, 12,
						    d->upvid[port] ?: VID_DEAD);
	}
	mutex_unlock(&sw->cfg_lock);
	return ret;
}

static int bcm53344_dsa_port_vlan_del(struct dsa_switch *ds, int port,
				      const struct switchdev_obj_port_vlan *vlan)
{
	struct bcm53344_dsa *d = ds->priv;
	struct bcm53344 *sw = d->sw;
	int hw = bcm53344_dsa_hw(d, port), ret = 0;
	struct bcm53344_vlan *v;
	u16 vid = vlan->vid;

	if (vid_is_dsa_8021q(vid))
		return 0;
	v = &sw->vlan[vid];
	mutex_lock(&sw->cfg_lock);
	if (!dsa_is_cpu_port(ds, port) && d->upvid[port] == vid) {
		d->upvid[port] = 0;
		if (sw->aware_ports & BIT(hw))
			ret = bcm53344_port_tab_set(sw, hw, 24, 12, VID_DEAD);
	}
	v->want &= ~BIT(hw);
	v->want_ut &= ~BIT(hw);
	if (!ret)
		ret = bcm53344_user_vlan_sync(sw, vid);
	mutex_unlock(&sw->cfg_lock);
	return ret;
}

static int bcm53344_dsa_setup(struct dsa_switch *ds)
{
	struct bcm53344_dsa *d = ds->priv;
	const struct bcm53344_dsa_layout *l = d->lay;
	struct bcm53344 *sw = d->sw;
	u32 all = GENMASK(NUM_PORTS - 1, 0);
	struct bcm53344_bulk b = { };
	int i, ret;

	if (!dsa_is_cpu_port(ds, l->n)) {
		dev_err(ds->dev, "port %d must be the CPU port\n", l->n);
		return -EINVAL;
	}
	for (i = 0; i < l->n; i++)
		if (dsa_is_user_port(ds, i))
			d->users |= BIT(l->hw[i]);
	if (d->users & (sw->link_bmap | READ_ONCE(sw->dsa_ports)) ||
	    sw->dsa[ds->index]) {
		dev_err(ds->dev, "ports %#x already in use\n", d->users);
		return -EBUSY;
	}
	sw->dsa[ds->index] = d;

	mutex_lock(&sw->cfg_lock);
	/* a user port reaches its CPU port only, the CPU port its user ports */
	for (i = 0; i < NUM_PORTS; i++)
		if (d->users & BIT(i))
			bcm53344_mask_set(sw, &b, i, all & ~BIT(l->cpu));
	bcm53344_mask_set(sw, &b, l->cpu, all & ~d->users);
	ret = b.bad ? -EIO : bcm53344_masks_verify(sw);
	/*
	 * User ports take every frame as untagged (a tag stays payload) and
	 * add their PVID; the CPU port parses the tag_8021q tag (outer TPID
	 * 0, 0x8100). Hardware learning on all of them.
	 */
	for (i = 0; i < NUM_PORTS && !ret; i++) {
		if (!(d->users & BIT(i)) && i != l->cpu)
			continue;
		ret = bcm53344_port_tab_set(sw, i, 85, 4, i == l->cpu);	/* OUTER_TPID_ENABLE */
		if (!ret)
			ret = bcm53344_port_tab_set(sw, i, 121, 4, CML_LEARN_FWD);	/* CML_FLAGS_NEW */
		if (!ret)
			ret = bcm53344_port_tab_set(sw, i, 125, 4, CML_LEARN_FWD);	/* CML_FLAGS_MOVE */
	}
	if (!ret) {
		sw->link_bmap |= d->users | BIT(l->cpu);
		ret = bcm53344_reg64_write(sw, BLK_IPIPE, EPC_LINK_BMAP,
					   sw->link_bmap);
	}
	if (!ret)
		WRITE_ONCE(sw->dsa_ports, sw->dsa_ports | d->users);
	mutex_unlock(&sw->cfg_lock);
	if (ret)
		return ret;

	rtnl_lock();
	ret = dsa_tag_8021q_register(ds, htons(ETH_P_8021Q));
	rtnl_unlock();
	if (ret)
		return ret;

	/* the MACs last: masks and VLANs are in place */
	for (i = 0; i < NUM_PORTS && !ret; i++)
		if ((d->users & BIT(i)) || i == l->cpu)
			ret = bcm53344_mac_enable(sw, i);
	dev_info(ds->dev, "switch %d: user ports %#x, cpu port %d: %d\n",
		 ds->index, d->users, l->cpu, ret);
	return ret;
}

static int bcm53344_dsa_aware_set(struct bcm53344_dsa *d, int port, bool on);

/*
 * Egress masks of the user ports: the CPU port, and the other user ports
 * of the same bridge (same instance; between instances the CPU forwards)
 */
static int bcm53344_dsa_masks(struct bcm53344_dsa *d)
{
	const struct bcm53344_dsa_layout *l = d->lay;
	struct bcm53344 *sw = d->sw;
	u32 all = GENMASK(NUM_PORTS - 1, 0);
	struct bcm53344_bulk b = { };
	int i, j, ret;

	mutex_lock(&sw->cfg_lock);
	for (i = 0; i < l->n; i++) {
		u32 m = all & ~BIT(l->cpu);

		if (!(d->users & BIT(l->hw[i])))
			continue;
		for (j = 0; j < l->n && d->br[i]; j++)
			if (j != i && d->br[j] == d->br[i])
				m &= ~BIT(l->hw[j]);
		bcm53344_mask_set(sw, &b, l->hw[i], m);
	}
	ret = b.bad ? -EIO : bcm53344_masks_verify(sw);
	mutex_unlock(&sw->cfg_lock);
	return ret;
}

static int bcm53344_dsa_bridge_join(struct dsa_switch *ds, int port,
				    struct dsa_bridge bridge,
				    bool *tx_fwd_offload,
				    struct netlink_ext_ack *extack)
{
	struct bcm53344_dsa *d = ds->priv, *o = d->sw->dsa[!ds->index];
	int j, ret;

	/*
	 * A bridge over both instances: each would learn the host on its own
	 * CPU port and its mask drops the other's frames. Bridged in software
	 * (through the CPU) instead.
	 */
	for (j = 0; o && j < o->lay->n; j++)
		if (o->br[j] == bridge.dev) {
			NL_SET_ERR_MSG_MOD(extack,
					   "bridge spans both switch instances: bridged in software");
			return -EOPNOTSUPP;
		}

	/* the bridge VLAN first, then the masks open */
	ret = dsa_tag_8021q_bridge_join(ds, port, bridge, tx_fwd_offload,
					extack);
	if (ret)
		return ret;
	d->br[port] = bridge.dev;
	ret = bcm53344_dsa_masks(d);
	if (ret) {
		d->br[port] = NULL;
		bcm53344_dsa_masks(d);
		dsa_tag_8021q_bridge_leave(ds, port, bridge);
	}
	return ret;
}

static void bcm53344_dsa_bridge_leave(struct dsa_switch *ds, int port,
				      struct dsa_bridge bridge)
{
	struct bcm53344_dsa *d = ds->priv;

	/* the masks close first, then the standalone VLAN comes back */
	bcm53344_dsa_aware_set(d, port, false);
	d->br[port] = NULL;
	bcm53344_dsa_masks(d);
	dsa_tag_8021q_bridge_leave(ds, port, bridge);
}

/*
 * Spanning tree state of a user port in the one STG all VLANs use, ingress
 * and egress (0 disabled, 1 blocking, 2 learning, 3 forwarding). DSA also
 * needs it for the receive path: a bridge VLAN frame goes to a port in
 * learning or forwarding state.
 */
static void bcm53344_dsa_stp_state(struct dsa_switch *ds, int port, u8 state)
{
	struct bcm53344_dsa *d = ds->priv;
	struct bcm53344 *sw = d->sw;
	int hw = bcm53344_dsa_hw(d, port), ret;
	u32 stg[2], v;

	switch (state) {
	case BR_STATE_DISABLED:
		v = 0;
		break;
	case BR_STATE_LEARNING:
		v = 2;
		break;
	case BR_STATE_FORWARDING:
		v = STP_FORWARD;
		break;
	default:	/* blocking, listening */
		v = 1;
		break;
	}
	mutex_lock(&sw->cfg_lock);
	ret = bcm53344_mem_read(sw, BLK_IPIPE, STG_TAB + BCM53344_STG, stg, 2);
	if (!ret) {
		bcm53344_field_set(stg, 2 * hw, 2, v);
		ret = bcm53344_mem_write(sw, BLK_IPIPE, STG_TAB + BCM53344_STG, stg, 2);
	}
	if (!ret)
		ret = bcm53344_mem_read(sw, BLK_EPIPE, EGR_VLAN_STG + BCM53344_STG, stg, 2);
	if (!ret) {
		bcm53344_field_set(stg, 2 * hw, 2, v);
		ret = bcm53344_mem_write(sw, BLK_EPIPE, EGR_VLAN_STG + BCM53344_STG, stg, 2);
	}
	mutex_unlock(&sw->cfg_lock);
	if (ret)
		dev_err(ds->dev, "port %d: stp state %u: %d\n", port, state, ret);
}

/*
 * Fast ageing: the learned (not static) L2 entries of a user port go, e.g.
 * when it leaves a bridge or stops forwarding. A walk over the whole hash
 * table (16384 entries); entries are cleared by index.
 */
static void bcm53344_dsa_fast_age(struct dsa_switch *ds, int port)
{
	struct bcm53344_dsa *d = ds->priv;
	struct bcm53344 *sw = d->sw;
	int hw = bcm53344_dsa_hw(d, port), i, n = 0, ret = 0;
	static const u32 zero[4];

	mutex_lock(&sw->cfg_lock);
	for (i = 0; i < L2X_ENTRIES && !ret; i++) {
		u32 e[4];

		ret = bcm53344_mem_read(sw, BLK_IPIPE, L2X + i, e, 4);
		if (ret || !bcm53344_field_get(e, 99, 1) ||	/* VALID */
		    bcm53344_field_get(e, 0, 2) ||		/* KEY_TYPE: bridge */
		    bcm53344_field_get(e, 97, 1) ||		/* STATIC_BIT */
		    bcm53344_field_get(e, 62, 6) != hw)		/* PORT_NUM */
			continue;
		ret = bcm53344_mem_write(sw, BLK_IPIPE, L2X + i, zero, 4);
		n++;
	}
	mutex_unlock(&sw->cfg_lock);
	dev_dbg(ds->dev, "port %d: fast age, %d entries cleared: %d\n", port, n, ret);
}

/*
 * Port in or out of VLAN-aware operation. In: it leaves the bridge VLAN (a
 * tag with that VID would pass the VLAN filter otherwise), takes the PVID of
 * the bridge, then starts to parse tags; out in the reverse order. Its
 * standalone VLAN stays for what the host sends, and the tagger ignores it on
 * receive. The filter of the port (EN_IFILTER) stays on.
 */
static int bcm53344_dsa_aware_set(struct bcm53344_dsa *d, int port, bool on)
{
	struct bcm53344 *sw = d->sw;
	int hw = bcm53344_dsa_hw(d, port), cpu = d->lay->cpu, ret, i;
	u16 bvid = d->aware_vid[port];
	struct bcm53344_vlan *v;
	bool was = sw->aware_ports & BIT(hw);
	u32 ports;

	if (was == on)
		return 0;
	if (on)
		bvid = dsa_tag_8021q_bridge_vid(dsa_port_bridge_num_get(dsa_to_port(&d->ds, port)));
	v = &sw->vlan[bvid];

	mutex_lock(&sw->cfg_lock);
	ports = sw->aware_ports;
	if (on) {
		ports |= BIT(hw) | BIT(cpu);
		v->members &= ~BIT(hw);
		v->untagged &= ~BIT(hw);
		ret = bcm53344_vlan_write(sw, bvid, v->members, v->untagged,
					  bcm53344_dsa_l2mc(bvid), true);
		if (!ret)
			ret = bcm53344_port_tab_set(sw, hw, 24, 12,
						    d->upvid[port] ?: VID_DEAD);
		if (!ret)
			ret = bcm53344_port_tab_set(sw, hw, 85, 4, 1);	/* OUTER_TPID_ENABLE */
		d->aware_vid[port] = bvid;
	} else {
		ports &= ~BIT(hw);
		if (!(ports & d->users))
			ports &= ~BIT(cpu);
		ret = bcm53344_port_tab_set(sw, hw, 85, 4, 0);
		if (!ret)
			ret = bcm53344_port_tab_set(sw, hw, 24, 12, sw->pvid[hw]);
		v->members |= BIT(hw);
		v->untagged |= BIT(hw);
		if (!ret)
			ret = bcm53344_vlan_write(sw, bvid, v->members, v->untagged,
						  bcm53344_dsa_l2mc(bvid), true);
		d->aware_vid[port] = 0;
	}
	sw->aware_ports = ports;
	if (!ports)
		sw->aware_br = NULL;
	/* user VLANs follow the membership */
	for (i = 1; i < 3072 && !ret; i++)
		if (sw->vlan[i].want & (BIT(hw) | BIT(cpu)))
			ret = bcm53344_user_vlan_sync(sw, i);
	mutex_unlock(&sw->cfg_lock);
	return ret;
}

static int bcm53344_dsa_vlan_filtering(struct dsa_switch *ds, int port,
				       bool filtering,
				       struct netlink_ext_ack *extack)
{
	struct bcm53344_dsa *d = ds->priv;
	struct bcm53344 *sw = d->sw;
	struct net_device *br = dsa_port_bridge_dev_get(dsa_to_port(ds, port));
	int ret;

	if (dsa_is_cpu_port(ds, port))
		return 0;
	if (filtering) {
		if (!br) {
			NL_SET_ERR_MSG_MOD(extack, "VLAN filtering needs a bridge");
			return -EOPNOTSUPP;
		}
		/* one VLAN table: a second bridge would share its VIDs */
		mutex_lock(&sw->cfg_lock);
		if (sw->aware_br && sw->aware_br != br) {
			mutex_unlock(&sw->cfg_lock);
			NL_SET_ERR_MSG_MOD(extack, "only one VLAN-aware bridge is supported");
			return -EBUSY;
		}
		sw->aware_br = br;
		mutex_unlock(&sw->cfg_lock);
	}
	ret = bcm53344_dsa_aware_set(d, port, filtering);
	if (!ret)
		bcm53344_dsa_fast_age(ds, port);
	return ret;
}

static void bcm53344_dsa_teardown(struct dsa_switch *ds)
{
	struct bcm53344_dsa *d = ds->priv;
	struct bcm53344 *sw = d->sw;
	struct bcm53344_bulk b = { };
	int i;

	rtnl_lock();
	dsa_tag_8021q_unregister(ds);
	rtnl_unlock();
	mutex_lock(&sw->cfg_lock);
	for (i = 0; i < NUM_PORTS; i++)
		if ((d->users & BIT(i)) || i == d->lay->cpu)
			bcm53344_mask_set(sw, &b, i, GENMASK(NUM_PORTS - 1, 0));
	bcm53344_masks_verify(sw);
	WRITE_ONCE(sw->dsa_ports, sw->dsa_ports & ~d->users);
	sw->dsa[ds->index] = NULL;
	mutex_unlock(&sw->cfg_lock);
}

static void bcm53344_dsa_get_caps(struct dsa_switch *ds, int port,
				  struct phylink_config *config)
{
	struct bcm53344_dsa *d = ds->priv;
	int hw = bcm53344_dsa_hw(d, port);

	if (hw >= 18 && hw <= 25) {
		/* uplink to the NP6Lite: QSGMII lane forced to 1000/full */
		__set_bit(PHY_INTERFACE_MODE_INTERNAL, config->supported_interfaces);
		config->mac_capabilities = MAC_1000FD;
		return;
	}
	if (hw >= 26) {
		/* TSC lane, SGMII to a B50220 */
		__set_bit(PHY_INTERFACE_MODE_SGMII, config->supported_interfaces);
	} else {
		/* UniMAC with an internal QGPHY */
		__set_bit(PHY_INTERFACE_MODE_INTERNAL, config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_GMII, config->supported_interfaces);
	}
	config->mac_capabilities = MAC_10 | MAC_100 | MAC_1000FD;
}

/* link of a DSA port from phylink: MAC/TSC speed and the LED data */
static void bcm53344_dsa_link(struct phylink_config *config, bool up,
			      int speed)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct bcm53344_dsa *d = dp->ds->priv;
	struct bcm53344 *sw = d->sw;
	int hw = bcm53344_dsa_hw(d, dp->index);
	int code = speed == SPEED_1000 ? 2 : speed == SPEED_100 ? 1 : 0;

	if (hw >= 18 && hw <= 25)
		return;
	if (hw >= 26) {
		if (up && code != sw->tsc_speed[hw - 26])
			bcm53344_tsc_speed(sw, hw - 26, code);
		return;	/* the B50220 drives its LEDs itself */
	}
	if (up && code != sw->umac_speed[hw])
		bcm53344_umac_speed(sw, hw, code);
	writel(up ? LED_LINK_UP | (code == 2 ? LED_LINK_1000 : LED_LINK_100) : 0,
	       sw->cmic + CMIC_LEDUP0_DATA_RAM(LED_LINK(hw)));
}

static void bcm53344_dsa_mac_config(struct phylink_config *config,
				    unsigned int mode,
				    const struct phylink_link_state *state)
{
}

static void bcm53344_dsa_mac_link_down(struct phylink_config *config,
				       unsigned int mode,
				       phy_interface_t interface)
{
	bcm53344_dsa_link(config, false, 0);
}

static void bcm53344_dsa_mac_link_up(struct phylink_config *config,
				     struct phy_device *phy, unsigned int mode,
				     phy_interface_t interface, int speed,
				     int duplex, bool tx_pause, bool rx_pause)
{
	bcm53344_dsa_link(config, true, speed);
}

static const struct phylink_mac_ops bcm53344_phylink_mac_ops = {
	.mac_config	= bcm53344_dsa_mac_config,
	.mac_link_down	= bcm53344_dsa_mac_link_down,
	.mac_link_up	= bcm53344_dsa_mac_link_up,
};

static const struct dsa_switch_ops bcm53344_dsa_ops = {
	.get_tag_protocol	= bcm53344_dsa_get_tag_protocol,
	.setup			= bcm53344_dsa_setup,
	.teardown		= bcm53344_dsa_teardown,
	.phylink_get_caps	= bcm53344_dsa_get_caps,
	.tag_8021q_vlan_add	= bcm53344_dsa_vlan_add,
	.tag_8021q_vlan_del	= bcm53344_dsa_vlan_del,
	.port_bridge_join	= bcm53344_dsa_bridge_join,
	.port_bridge_leave	= bcm53344_dsa_bridge_leave,
	.port_vlan_filtering	= bcm53344_dsa_vlan_filtering,
	.port_vlan_add		= bcm53344_dsa_port_vlan_add,
	.port_vlan_del		= bcm53344_dsa_port_vlan_del,
	.port_stp_state_set	= bcm53344_dsa_stp_state,
	.port_fast_age		= bcm53344_dsa_fast_age,
};

static int bcm53344_dsa_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct bcm53344 *sw = dev_get_drvdata(dev->parent);
	struct bcm53344_dsa *d;
	u32 idx;

	if (!sw)
		return -EPROBE_DEFER;
	if (of_property_read_u32_index(dev->of_node, "dsa,member", 1, &idx) ||
	    idx >= ARRAY_SIZE(bcm53344_dsa_layouts)) {
		dev_err(dev, "bad dsa,member\n");
		return -EINVAL;
	}
	d = devm_kzalloc(dev, sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	d->sw = sw;
	d->lay = &bcm53344_dsa_layouts[idx];
	d->ds.dev = dev;
	d->ds.num_ports = d->lay->n + 1;
	d->ds.ops = &bcm53344_dsa_ops;
	d->ds.phylink_mac_ops = &bcm53344_phylink_mac_ops;
	d->ds.priv = d;
	d->ds.max_num_bridges = DSA_TAG_8021Q_MAX_NUM_BRIDGES;
	platform_set_drvdata(pdev, d);
	return dsa_register_switch(&d->ds);
}

static void bcm53344_dsa_remove(struct platform_device *pdev)
{
	struct bcm53344_dsa *d = platform_get_drvdata(pdev);

	if (d)
		dsa_unregister_switch(&d->ds);
}

static void bcm53344_dsa_shutdown(struct platform_device *pdev)
{
	struct bcm53344_dsa *d = platform_get_drvdata(pdev);

	if (d)
		dsa_switch_shutdown(&d->ds);
	platform_set_drvdata(pdev, NULL);
}

static const struct of_device_id bcm53344_dsa_of_match[] = {
	{ .compatible = "brcm,bcm53344-dsa" },
	{ }
};
MODULE_DEVICE_TABLE(of, bcm53344_dsa_of_match);

static struct platform_driver bcm53344_dsa_driver = {
	.driver = {
		.name = "bcm53344-dsa",
		.of_match_table = bcm53344_dsa_of_match,
	},
	.probe = bcm53344_dsa_probe,
	.remove = bcm53344_dsa_remove,
	.shutdown = bcm53344_dsa_shutdown,
};

static int bcm53344_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct bcm53344 *sw;
	int cap, bar, ret;
	u32 vsec;

	/* function 1 has no CMIC */
	if (PCI_FUNC(pdev->devfn) != 0)
		return -ENODEV;

	cap = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_VNDR);
	if (!cap)
		return -ENODEV;
	pci_read_config_dword(pdev, cap + 8, &vsec);
	bar = (vsec & BIT(8)) ? 2 : 0;

	sw = devm_kzalloc(&pdev->dev, sizeof(*sw), GFP_KERNEL);
	if (!sw)
		return -ENOMEM;
	sw->pdev = pdev;
	mutex_init(&sw->schan_lock);
	mutex_init(&sw->miim_lock);
	mutex_init(&sw->cfg_lock);
	sw->vlan = devm_kcalloc(&pdev->dev, VLAN_N_VID, sizeof(*sw->vlan),
				GFP_KERNEL);
	if (!sw->vlan)
		return -ENOMEM;
	INIT_DELAYED_WORK(&sw->led_work, bcm53344_led_work);
	memset(sw->umac_speed, UMAC_SPEED_1000, sizeof(sw->umac_speed));
	memset(sw->tsc_speed, 2, sizeof(sw->tsc_speed));
	INIT_DELAYED_WORK(&sw->led_link_work, bcm53344_led_link_work);
	INIT_DELAYED_WORK(&sw->b50220_led_work, bcm53344_b50220_led_work);

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;
	sw->cmic = pcim_iomap(pdev, bar, 0);
	if (!sw->cmic)
		return -ENOMEM;
	pci_set_drvdata(pdev, sw);

	ret = bcm53344_init(sw);
	if (ret) {
		/* fail-closed: a half set-up switch must not forward */
		dev_err(&pdev->dev, "init failed: %d, switch held in reset\n", ret);
		bcm53344_quiesce(sw);
	} else {
		/* LEDs are cosmetic: a failure must not stop the switch */
		int err = bcm53344_setup_leds(sw);

		if (err)
			dev_warn(&pdev->dev, "led setup failed: %d\n", err);
		sw->debugfs = debugfs_create_dir("bcm53344", NULL);
		debugfs_create_file("ports", 0400, sw->debugfs, sw,
				    &bcm53344_ports_fops);
		debugfs_create_file("phys", 0400, sw->debugfs, sw,
				    &bcm53344_phys_fops);
		debugfs_create_file("l2", 0400, sw->debugfs, sw,
				    &bcm53344_l2_fops);
		debugfs_create_file("limits", 0400, sw->debugfs, sw,
				    &bcm53344_limits_fops);
		/*
		 * PHY buses and the DSA instances (child nodes); without a
		 * device tree node only the zones work
		 */
		ret = bcm53344_mdio_register(sw, &sw->mii_int, "mdio-int");
		if (!ret)
			ret = bcm53344_mdio_register(sw, &sw->mii_ext, "mdio-ext");
		if (!ret && pdev->dev.of_node)
			ret = of_platform_populate(pdev->dev.of_node, NULL, NULL,
						   &pdev->dev);
		if (ret)
			dev_err(&pdev->dev, "mdio/dsa set-up failed: %d\n", ret);
	}
	return 0;
}

static void bcm53344_remove(struct pci_dev *pdev)
{
	struct bcm53344 *sw = pci_get_drvdata(pdev);

	/* DSA instances first, then the switch goes into reset (no driver: no forwarding) */
	of_platform_depopulate(&pdev->dev);
	cancel_delayed_work_sync(&sw->led_work);
	cancel_delayed_work_sync(&sw->led_link_work);
	cancel_delayed_work_sync(&sw->b50220_led_work);
	debugfs_remove_recursive(sw->debugfs);
	bcm53344_quiesce(sw);
}

static void bcm53344_shutdown(struct pci_dev *pdev)
{
	struct bcm53344 *sw = pci_get_drvdata(pdev);

	if (!sw)
		return;
	cancel_delayed_work_sync(&sw->led_work);
	cancel_delayed_work_sync(&sw->led_link_work);
	cancel_delayed_work_sync(&sw->b50220_led_work);
	bcm53344_quiesce(sw);
}

static const struct pci_device_id bcm53344_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, 0x8344) },
	{ }
};
MODULE_DEVICE_TABLE(pci, bcm53344_ids);

static struct pci_driver bcm53344_driver = {
	.name = "bcm53344",
	.id_table = bcm53344_ids,
	.probe = bcm53344_probe,
	.remove = bcm53344_remove,
	.shutdown = bcm53344_shutdown,
};
static int __init bcm53344_module_init(void)
{
	int ret;

	ret = platform_driver_register(&bcm53344_dsa_driver);
	if (ret)
		return ret;
	ret = pci_register_driver(&bcm53344_driver);
	if (ret)
		platform_driver_unregister(&bcm53344_dsa_driver);
	return ret;
}
module_init(bcm53344_module_init);

static void __exit bcm53344_module_exit(void)
{
	pci_unregister_driver(&bcm53344_driver);
	platform_driver_unregister(&bcm53344_dsa_driver);
}
module_exit(bcm53344_module_exit);

MODULE_DESCRIPTION("Broadcom BCM53344 of the FortiGate 100E: pass-through zones and DSA");
MODULE_LICENSE("GPL");
