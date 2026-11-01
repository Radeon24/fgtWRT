// SPDX-License-Identifier: GPL-2.0-only
/*
 * Port-based VLANs on the BCM53314 switch of the Fortinet FortiGate 100D
 *
 * The board carries a Broadcom StrataXGS BCM53314 (B0, "Hawkeye" family,
 * PCI 14e4:c314). It is not a RoboSwitch: no b53 support, no DSA tag on
 * its Ethernet ports. Its registers and tables are reached through the
 * CMIC window in BAR0 (64 KiB): S-channel messages for the switch core,
 * MIIM for the PHYs. Ports: 0 = CMIC (packet DMA: bcm5331x-cmic.c only),
 * 1-24 = gigabit ports in three blocks of eight. Port 3 (ge2) is wired to
 * an Intel 82574L of the host and is the CPU trunk; port 4 (ge3) goes to a
 * second 82574L and is left alone unless step "ge3" is requested; ports
 * 5-24 are the front ports.
 *
 * This prototype gives each selected front port its own VLAN, shared only
 * with the trunk: untagged on the front port, tagged on the trunk. The
 * host then sees each front port as an 802.1Q interface on top of the
 * trunk netdev (e.g. eth0.101). It is the first step towards a DSA driver
 * with a VLAN-based tagger; see the design note of the project.
 *
 * The boot firmware resets and sets up the switch only when it loads an
 * image over the network (TFTP through the MGMT port). After a start from
 * the local disk the switch blocks are left as the power-on reset left
 * them, and every S-channel request times out (status DONE + TIMEOUT).
 * The block reset register is therefore read at load (plain MMIO read)
 * and S-channel/MIIM access is refused unless it holds the value the boot
 * firmware leaves after its set-up. Every write below is volatile: a
 * reboot undoes it. Nothing is written when the module is loaded with its
 * default parameters, nor when it is removed (but for the LED link bits of
 * "leds", cleared again), nor when the switch is found not set up.
 *
 * Register offsets, table layouts, field positions and reset values come
 * from the public OpenBCM SDK (src/soc/mcm/bcm53314_a0.c and the
 * allregs/allmems/fields tables it points to, resolved by position);
 * sequences follow the SDK functions named in the comments.
 *
 * Module parameters (all read-only after load):
 *   access     0 = identify the chip with plain MMIO reads only (default);
 *              1 = also allow S-channel and MIIM reads (debugfs files);
 *              2 = also allow the configuration writes listed in "steps"
 *   steps      comma-separated list run at load, in this order, when
 *              access=2: counters, learning, trunk, isolate, ports, ifilter, ge3, trunk2,
 *              mgmt
 *              (MGMT port in VID 20, untagged, with the trunk)
 *   isolate    "<port>:<vid>[,<port>:<vid>...]", switch port 5-24 and VID
 *              100-199, e.g. "10:101,9:102"
 *   trunk_autoneg  let the trunk PHY auto-negotiate (it is left forced
 *              at 1000 Mb/s without auto-negotiation by the boot firmware)
 *   dry_run    compute and log the write plan, write nothing (default Y)
 *   init_phy   step "init" only: also reset and set up the internal PHYs
 *              of ports 1-8 (default Y); N = no MIIM access at all
 *   init_ledram  step "init" only: line R17 sets SEL_LEDRAM_SERIAL_DATA
 *              (CMIC_QGPHY_QSGMII_CONTROL bit 3), so that the LEDs of
 *              ports 1-8 (wan2, MGMT, ha1, ha2) take the serial stream of
 *              the LED processor (default Y, as the boot firmware); N =
 *              R17 left out of the plan (one write less, nothing else
 *              changed): these LEDs stay driven by the internal PHYs,
 *              whose LED selectors the step sets (P14-P16). Started from
 *              the disk, the LED processor is stopped (no program loaded):
 *              with R17, these four LEDs then stay lit whatever the link
 *   monitor    0 = nothing runs after load (default); 1 = a work item, once
 *              a second, reads the link status of the front ports and,
 *              every ten seconds, accumulates their MIB counters (reads
 *              only); 2 = also keeps the forwarding link bitmap of the front
 *              ports in step with their link (needs step "ports", access=2,
 *              dry_run=N)
 *
 * Step "ports" (instead of "isolate", never with it) isolates every front
 * port but MGMT with the fixed VID of its front panel label: portN gets VID
 * 100 + N (101-116), wan2, ha1 and ha2 get 120, 121 and 122. The internal
 * PHYs of wan2, ha1 and ha2 are switched from forced 1000 Mb/s to
 * auto-negotiation (MII control 0x0140 -> 0x1340), as for the trunk. The
 * same write rules as step "isolate" apply. Step "isolate" is never
 * combined with "mgmt", nor step "ports" without step "ifilter": a front
 * port that does not filter tagged frames on ingress would switch a frame
 * tagged with VID 20 to MGMT.
 * On the host, VLAN interfaces of
 * the trunk netdev may then take the name of the label (e.g. "port1" for
 * VID 101). debugfs "ports" (access >= 1) lists, per front port, the MAC
 * link status, the port VID, the MAC control and two MIB counters.
 *
 * Step "ifilter" (with step "ports" only) turns on the ingress VLAN
 * membership filter of the same front ports: a frame received tagged with a
 * VID whose VLAN does not hold the port is dropped, so that the isolation
 * also holds for tagged frames. Untagged frames still get the port VID.
 *
 * debugfs "mib" (access >= 1) gives, per port, MIB and drop counters summed
 * on 64 bits since the first read (32-bit hardware counters, never cleared
 * here; with monitor=0 the sums hold only if two reads are less than 34 s
 * apart, the time a byte counter takes to wrap at 1 Gb/s); "mtu" gives the maximum frame length of each MAC and the egress MTU
 * limit. With monitor >= 1, "link" gives the link status seen by the work
 * item. With monitor=2 a front port is removed from the forwarding link
 * bitmap after two consecutive samples without link and put back after two
 * with link: the hardware never updates that bitmap itself. At most one
 * bitmap write per second, at most ten per minute (beyond: the work item
 * stops writing for good and keeps reading; a port then out of the bitmap
 * stays out until the next load); the first fault stops it. Nothing is
 * written at removal: the bitmap keeps its last value until the next reboot.
 *
 * Parameter "linksrc" (used with monitor >= 1 only, inert otherwise):
 * "bmsr" (default) takes the link of a front port from bit 2 of
 * the MII status register of the port PHY, as the hardware link scan of the
 * SDK does; "mac" takes it from MAC_MODE.LINK_STATUS, which is set when the
 * MAC is brought up but does not fall when the link is lost. With
 * "bmsr": one MIIM read of register 1 per front port and pass (19 a
 * second at most), internal PHYs 0x85, 0x87, 0x88 for wan2, ha1, ha2 and
 * external PHYs 0x09-0x10 (ports 9-16) and 0x12-0x19 (ports 17-24); 0x11
 * serves no port (it answers an ID of its own) and is never read, nor is the trunk SerDes or the MGMT PHY
 * (MGMT keeps MAC_MODE). The bit latches low: a short loss reads 0 once and
 * is dropped by the two-sample debounce. MIIM reads only, no PHY register
 * or page is ever written; the medium of the combo port (port 15) is not
 * selected. MAC_MODE is still read and shown in "link". A busy MIIM (link
 * scan on), no answer or a read of 0xffff stops the module.
 *
 * Steps "ge3" and "trunk2" (with step "ports" only, never with "isolate"
 * or "mgmt") add the second CPU link, in two loads. Step "ge3" brings up
 * ge3 (port 4): auto-negotiation of its PHY (0x84, left forced at 1000
 * Mb/s), MAC enable, link bitmap; ge3 is then only in VID 1, as after the
 * set-up. Step "trunk2" runs only once ge3 is up with its PHY link read
 * up: a trunk group has no fallback, a member without link would lose the
 * unicast hashed to it and half of the flooded frames. It joins ge3 to ge2
 * in hardware trunk group 7, hashed on source and destination IP (RTAG 6),
 * as the SDK function _bcm_xgs3_trunk_set lays it out: group entry
 * (members 3, 4 repeated over the eight slots), trunk bitmap, ge3 tagged in
 * every VLAN of step "ports", non-unicast block mask (one member left per
 * entry, alternately), flood hash on source and destination, and last the
 * source trunk map of ports 3 and 4 (frames from the host learnt on the
 * group). Nothing removes a member that loses its link afterwards. On the
 * host, eth0 and eth1 then form one balance-xor bond. debugfs "trunk2"
 * (access >= 1) shows the group and the counters of both links.
 *
 * Port LEDs. The LEDs of the switch ports are driven by the LED processor
 * of the CMIC (LEDUP), loaded and started by the boot firmware. Its public
 * reference program for this chip reads the link of port p from bit 0 of
 * byte 0xa0 + p of its data RAM (one byte per 32-bit word), which the host
 * has to keep current; speed and activity come from the hardware scan.
 * debugfs "led" (any access level, plain MMIO reads only, nothing written):
 * LEDUP control and status (status read twice, 50 ms apart), a fingerprint
 * of the program RAM (non-zero bytes, sum, CRC-32, whether its first eight
 * bytes are those of the public reference program; the program bytes
 * themselves are never shown) and data bytes 0xa0-0xbf. Parameter "leds"
 * (0 = off, default): 1 = once the link state of the work item is
 * debounced, each pass reads byte 0xa0 + p for p = 5-24 (MGMT is port 6)
 * and, only when it differs, writes (value read & ~0x81) | link (bit 7,
 * turbo, cleared as the SDK does). It needs monitor >= 1, access=2 and
 * dry_run=N; nothing is written unless the LED processor is found enabled
 * with a program that starts as the public reference one. At most 60
 * writes per 60 s (beyond: the LED writes stop for good, reads go on);
 * a read back that differs stops them too. At removal the link bits of the
 * ports written are cleared again (bounded: 20 writes at most), unless the
 * LED processor then reads stopped or a fault occurred. No other
 * LED processor word is ever written.
 *
 * The LEDs of port1-16 (switch ports 9-24) do not follow that data RAM
 * (tried: bits set, LEDs unchanged): they hang on the LED pins of
 * their BCM54684 PHYs, left at their hardware defaults (LED3 = activity in
 * traffic mode: a flash on activity only). Parameter "phyled" (0 = off,
 * default): 1 = at load, the LED set-up of the SDK with the properties of
 * FortiOS (phy_led1_mode=1, phy_led2_mode=0, phy_led_ctrl=0x18; OpenBCM
 * phy54684.c, OpenMDK bcm54684_drv.c) on the 16 external PHYs (MIIM 0x09-
 * 0x10, 0x12-0x19), each read back: spare control 1 (shadow 0x02) |= 6
 * (link speed LED mode), LED selector 1 (shadow 0x0d) = 0x01 (LED1
 * LINKSPD[2], LED2 LINKSPD[1]), LED control (shadow 0x09) = 0x018 (LED3
 * link/activity), extended control (register 0x10) bit 5 (traffic LED
 * mode) cleared. LED selector 2 keeps its default (LED3 activity, LED4
 * INTR). Only MIIM registers 0x10 and 0x1c of these PHYs, only these values
 * (and shadow read selections); the PHY identifier is checked first, then
 * the four registers are read and only those that differ are written (the
 * exact value computed from the value read); the first deviation stops it.
 * Volatile, not undone at removal. It needs access=2, not with step init;
 * with dry_run=Y, reads only (the shadow selections excepted), logging per
 * PHY the four values read and the number of writes a run would make.
 *
 * Step "init" (steps=init, access=2, alone in its load) brings the switch
 * out of the power-on reset left after a start from the local disk and
 * sets it up as the boot firmware does before a network load: CMIC reset
 * and block resets, pipeline reset, VLAN/STG tables cleared, per-port MAC
 * set-up, VID 1 on every port, spanning-tree forwarding, then every port
 * disabled (RX off). The sequence follows the reset/init functions of the
 * public OpenMDK SDK for this chip (bcm53314_a0); values come from the
 * OpenBCM/OpenMDK register descriptions. It runs only when the block reset
 * register reads 0. All its lines form one table: with dry_run=Y the table
 * is only printed (debugfs "plan"), nothing is accessed beyond the three
 * identification reads; with dry_run=N each line is played and logged
 * (debugfs "log"), and the first fault stops the run without any abort or
 * error-clear write. Its CMIC writes are allowed for the duration of the
 * run, one by one, with the exact value of the table.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mii.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

/* ---------------------------------------------------------------------- */
/* CMIC window (BAR0)                                                      */

#define CMIC_BAR_SIZE		0x10000
#define CMIC_SCHAN_CTRL		0x050	/* S-channel and MIIM control */
#define CMIC_SCHAN_ERR		0x05c	/* never read nor written */
#define CMIC_CONFIG		0x10c	/* written by step "init" only */
#define CMIC_IRQ_MASK		0x148	/* step "init" only */
#define CMIC_QGPHY_QSGMII_CONTROL 0x14c	/* step "init" only */
#define CMIC_ENDIANESS_SEL	0x174	/* step "init" only */
#define CMIC_CHIP_MODE_CONTROL	0x198	/* step "init" only */
#define CMIC_SBUS_RING_MAP	0x400	/* step "init" only */
#define CMIC_XGXS_PLL_STATUS	0x594	/* step "init" only */
#define CMIC_INTR_WAIT_CYCLES	0xd48	/* step "init" only */
#define CMIC_MIIM_PARAM		0x158
#define CMIC_MIIM_READ_DATA	0x15c
#define CMIC_DEV_REV_ID		0x178
#define CMIC_MIIM_ADDRESS	0x4a0
#define CMIC_SOFT_RESET		0x580	/* block reset, active low; written by step "init" only */
#define CMIC_SCHAN_MSG		0x800	/* message words 0..21 */
#define CMIC_SCHAN_MSG_END	0x858
/*
 * Data words of one S-channel write: 3 for every table of the steps, 5 for
 * L2_USER_ENTRY (156 bits); 14 for FP_TCAM (422 bits, IPIPE 0x0d720000,
 * 512 entries), written by the DSA driver with fp=1 only: a write of more
 * than 5 words to any other address is refused (fault).
 */
#define SCHAN_WRITE_WORDS	14
#define SCHAN_WRITE_WORDS_STD	5
#define SCHAN_FP_TCAM_FIRST	0x0d720000
#define SCHAN_FP_TCAM_LAST	0x0d7201ff

#define CHIP_ID_B0		0x0011c314	/* device 0xc314, revision 0x11 */
/*
 * CMIC_SOFT_RESET after the boot firmware has set the switch up: GP, MMU,
 * IP, EP, XG_PLL, QGPHY0/1 and QSGMII2X0/1 out of reset; FP, GX12, G2P5x
 * and BSAFE held in reset (fields of CMIC_SOFT_RESET_REG for this chip).
 * Measured identical after a cold start and after a warm one.
 */
#define SOFT_RESET_SET_UP	0x0001e3c1
#define SOFT_RESET_DISK		0x00000000	/* every block in reset: power-on value */

/* CMIC_CONFIG */
#define CFG_BURST		(BIT(0) | BIT(1))	/* RD_BRST_EN, WR_BRST_EN */
#define CFG_RESET_CPS		BIT(5)		/* S-bus reset pulse, clears itself */
#define CFG_SCHAN_ABORT		BIT(7)
#define CFG_I2C_EN		BIT(11)
#define CFG_SET_UP		0x08000043	/* reset value, measured after the set-up */
#define PLL_LOCK		BIT(31)		/* CMIC_XGXS_PLL_STATUS */
#define SBUS_RING_MAP		0x0ad42aaa	/* reset value of CMIC_SBUS_RING_MAP */

/* CMIC_SCHAN_CTRL: set/clear commands written, status bits read */
#define SC_MSG_START_SET	0x80
#define SC_MSG_DONE_CLR		0x01
#define SC_MIIM_RD_START_SET	0x90
#define SC_MIIM_WR_START_SET	0x91
#define SC_MIIM_OP_DONE_CLR	0x12
#define SC_MSG_START		BIT(0)
#define SC_MSG_DONE		BIT(1)
#define SC_MIIM_SCAN_BUSY	BIT(14)
#define SC_MIIM_RD_START	BIT(16)
#define SC_MIIM_WR_START	BIT(17)
#define SC_MIIM_OP_DONE		BIT(18)
#define SC_MIIM_LINK_SCAN_EN	BIT(19)
#define SC_MSG_NAK		BIT(21)
#define SC_MSG_TIMEOUT		BIT(22)
#define SC_MSG_BUSY		(SC_MSG_START | SC_MSG_DONE | SC_MSG_NAK | SC_MSG_TIMEOUT)
#define SC_MIIM_BUSY		(SC_MIIM_SCAN_BUSY | SC_MIIM_LINK_SCAN_EN | \
				 SC_MIIM_RD_START | SC_MIIM_WR_START | SC_MIIM_OP_DONE)

#define SCHAN_TIMEOUT_US	300000
#define MIIM_TIMEOUT_US		1000000

/* S-channel opcodes */
#define OP_READ_MEM		0x07
#define OP_READ_MEM_ACK		0x08
#define OP_WRITE_MEM		0x09
#define OP_READ_REG		0x0b
#define OP_READ_REG_ACK		0x0c
#define OP_WRITE_REG		0x0d
/*
 * L2 table (L2X) insert and delete by the switch itself (OpenMDK xgs_schan.h,
 * OpenBCM schanmsg.h l. 382-385): header and the three words of an L2X
 * entry, no address word; never used by this module, only by the DSA driver
 * (fdb=1), each message armed with its exact words (cmic_write_allowed).
 */
#define OP_ARL_INSERT		0x0f
#define OP_ARL_INSERT_DONE	0x10
#define OP_ARL_DELETE		0x11
#define OP_ARL_DELETE_DONE	0x12
#define ARL_MSG_WORDS		4	/* header + L2X entry (3 words) */

/* Block numbers on the S-channel */
#define BLK_MMU			6
#define BLK_IPIPE		7
#define BLK_EPIPE		9

/* Ports */
#define NUM_PORTS		25
#define PORT_TRUNK		3			/* ge2 */
#define PBM_TRUNK		BIT(PORT_TRUNK)
#define PBM_FRONT		GENMASK(24, 5)		/* ge4-ge23 */
#define TRUNK_PHY		0x83			/* internal bus, address 3 */
#define PORT_TRUNK2		4			/* ge3, second link to the host (steps ge3, trunk2) */
#define PBM_TRUNK2		BIT(PORT_TRUNK2)
#define TRUNK2_PHY		0x84			/* internal bus, address 4 */
#define PORT_MGMT		6			/* ge5, front port labelled MGMT */
#define MGMT_VID		20			/* VID of the network behind MGMT */

/* VIDs this prototype may create */
/* block of the front-port VIDs: vid_base .. vid_base + 99 (module parameter, default 100) */
#define VID_BASE_DEF		100
#define VID_MIN			vid_base
#define VID_MAX			(vid_base + 99)
#define VID_DEFAULT		1			/* every port at reset */
#define STG_DEFAULT		1			/* spanning-tree group of VID 1 */

#define PHY_INT_LAST		8			/* ports 1-8: internal PHY, MIIM 0x80 | port */

/* MII control register */
#define BMCR_FORCED_1000	0x0140			/* left by the boot firmware */
#define BMCR_AUTONEG_RESTART	0x1340

/* ---------------------------------------------------------------------- */
/* Switch objects                                                          */

enum obj_kind {
	K_GEN,		/* general register of a pipeline block */
	K_PIPE_PORT,	/* per-port register of a pipeline block: port << 12 */
	K_GPORT_PORT,	/* per-port register of a GPORT block */
	K_MEM,		/* table: base + block << 20 + index */
};

struct sw_obj {
	const char *name;
	enum obj_kind kind;
	u32 base;
	u8 blk;
	u8 words;
	u16 max;	/* last index (tables) */
	u32 parity;	/* bit kept by the hardware, ignored on read-back (0 = none) */
};

enum {
	O_COMMAND_CONFIG, O_FRM_LENGTH, O_EPC_LINK_BMAP, O_ING_CONFIG, O_VLAN_CTRL,
	O_EGR_CONFIG, O_ING_OUTER_TPID_0, O_EGR_OUTER_TPID_0, O_EGR_PORT,
	O_EGR_VLAN_CONTROL_1, O_ING_EGRMSKBMAP, O_PORT_TAB, O_VLAN_TAB, O_EGR_VLAN,
	O_STG_TAB, O_EGR_VLAN_STG, O_VLAN_PROTOCOL, O_SOURCE_TRUNK_MAP,
	O_TDBGC0, O_TDBGC1, O_TDBGC2, O_RDBGC0, O_RDBGC1,
	O_TDBGC0_SELECT, O_TDBGC1_SELECT, O_TDBGC2_SELECT,
	O_RDBGC0_SELECT, O_RDBGC1_SELECT,
	O_GT1518, O_GTMGV, O_GT2047, O_GTPKT, O_GRPKT,
	O_MIRROR_CONTROL, O_EMIRROR_CONTROL, O_MAC_MODE,
	O_GRBYT, O_GRUC, O_GRMCA, O_GRBCA, O_GRFCS, O_GROVR, O_GRJBR, O_GRMTUE,
	O_GRUND, O_GRFRG, O_GR9216, O_GTBYT, O_GTUC, O_GTMCA, O_GTBCA, O_GTFCS,
	O_GTOVR, O_GT9216, O_RDISC, O_HOLD, O_EGRDROPPKTCOUNT, O_EGR_MTU_SIZE,
	O_TRUNK_GROUP, O_TRUNK_BITMAP, O_NONUCAST_TRUNK_BLOCK_MASK, O_HASH_CONTROL,
	O_NUM
};

static const struct sw_obj objs[O_NUM] = {
	[O_COMMAND_CONFIG]	= { "COMMAND_CONFIG", K_GPORT_PORT, 0x00000102, 0, 1 },
	[O_FRM_LENGTH]		= { "FRM_LENGTH", K_GPORT_PORT, 0x00000105, 0, 1 },
	[O_EPC_LINK_BMAP]	= { "EPC_LINK_BMAP", K_GEN, 0x0f080110, BLK_IPIPE, 1 },
	[O_ING_CONFIG]		= { "ING_CONFIG", K_GEN, 0x01080000, BLK_IPIPE, 1 },
	[O_VLAN_CTRL]		= { "VLAN_CTRL", K_GEN, 0x01080003, BLK_IPIPE, 1 },
	[O_EGR_CONFIG]		= { "EGR_CONFIG", K_GEN, 0x01080000, BLK_EPIPE, 1 },
	[O_ING_OUTER_TPID_0]	= { "ING_OUTER_TPID_0", K_GEN, 0x0208000c, BLK_IPIPE, 1 },
	[O_EGR_OUTER_TPID_0]	= { "EGR_OUTER_TPID_0", K_GEN, 0x04080000, BLK_EPIPE, 1 },
	[O_EGR_PORT]		= { "EGR_PORT", K_PIPE_PORT, 0x01000002, BLK_EPIPE, 1 },
	[O_EGR_VLAN_CONTROL_1]	= { "EGR_VLAN_CONTROL_1", K_PIPE_PORT, 0x01000003, BLK_EPIPE, 1 },
	[O_ING_EGRMSKBMAP]	= { "ING_EGRMSKBMAP", K_PIPE_PORT, 0x0f000135, BLK_IPIPE, 1 },
	[O_PORT_TAB]		= { "PORT_TAB", K_MEM, 0x01000000, BLK_IPIPE, 3, 24 },
	[O_VLAN_TAB]		= { "VLAN_TAB", K_MEM, 0x05000000, BLK_IPIPE, 2, 4095, BIT(43 - 32) },
	[O_EGR_VLAN]		= { "EGR_VLAN", K_MEM, 0x04010000, BLK_EPIPE, 2, 4095, BIT(59 - 32) },
	[O_STG_TAB]		= { "STG_TAB", K_MEM, 0x05010000, BLK_IPIPE, 2, 63 },
	[O_EGR_VLAN_STG]	= { "EGR_VLAN_STG", K_MEM, 0x04020000, BLK_EPIPE, 2, 63 },
	[O_VLAN_PROTOCOL]	= { "VLAN_PROTOCOL", K_MEM, 0x04000000, BLK_IPIPE, 1, 15 },
	[O_SOURCE_TRUNK_MAP]	= { "SOURCE_TRUNK_MAP_TABLE", K_MEM, 0x02010000, BLK_IPIPE, 1, 63 },
	[O_TDBGC0]		= { "TDBGC0", K_PIPE_PORT, 0x0a000000, BLK_EPIPE, 1 },
	[O_TDBGC1]		= { "TDBGC1", K_PIPE_PORT, 0x0a000001, BLK_EPIPE, 1 },
	[O_TDBGC2]		= { "TDBGC2", K_PIPE_PORT, 0x0a000002, BLK_EPIPE, 1 },
	[O_RDBGC0]		= { "RDBGC0", K_PIPE_PORT, 0x0f00000b, BLK_IPIPE, 1 },
	[O_RDBGC1]		= { "RDBGC1", K_PIPE_PORT, 0x0f00000c, BLK_IPIPE, 1 },
	[O_TDBGC0_SELECT]	= { "TDBGC0_SELECT", K_GEN, 0x0a080020, BLK_EPIPE, 1 },
	[O_TDBGC1_SELECT]	= { "TDBGC1_SELECT", K_GEN, 0x0a080021, BLK_EPIPE, 1 },
	[O_TDBGC2_SELECT]	= { "TDBGC2_SELECT", K_GEN, 0x0a080022, BLK_EPIPE, 1 },
	[O_RDBGC0_SELECT]	= { "RDBGC0_SELECT", K_GEN, 0x0f080020, BLK_IPIPE, 1 },
	[O_RDBGC1_SELECT]	= { "RDBGC1_SELECT", K_GEN, 0x0f080021, BLK_IPIPE, 1 },
	/* transmit MIB of a GE port: 1024-1518 bytes, 1519-1522 bytes VLAN-tagged, 1519-2047 bytes, all */
	[O_GT1518]		= { "GT1518", K_GPORT_PORT, 0x00000033, 0, 1 },
	[O_GTMGV]		= { "GTMGV", K_GPORT_PORT, 0x00000034, 0, 1 },
	[O_GT2047]		= { "GT2047", K_GPORT_PORT, 0x00000035, 0, 1 },
	[O_GTPKT]		= { "GTPKT", K_GPORT_PORT, 0x00000038, 0, 1 },
	[O_GRPKT]		= { "GRPKT", K_GPORT_PORT, 0x0000001b, 0, 1 },	/* received, all */
	/* mirroring, per ingress port: M_ENABLE bit 0; egress ports mirrored */
	[O_MIRROR_CONTROL]	= { "MIRROR_CONTROL", K_PIPE_PORT, 0x0f000108, BLK_IPIPE, 1 },
	[O_EMIRROR_CONTROL]	= { "EMIRROR_CONTROL", K_PIPE_PORT, 0x0f000109, BLK_IPIPE, 1 },
	/* read only: MAC_SPEED 1:0, MAC_DUPLEX 2, MAC_RX_PAUSE 3, MAC_TX_PAUSE 4, LINK_STATUS 5 */
	[O_MAC_MODE]		= { "MAC_MODE", K_GPORT_PORT, 0x00000111, 0, 1 },
	/* MIB of a GE port, 32 bits, not cleared on read */
	[O_GRBYT]		= { "GRBYT", K_GPORT_PORT, 0x0000001c, 0, 1 },
	[O_GRUC]		= { "GRUC", K_GPORT_PORT, 0x0000001d, 0, 1 },
	[O_GRMCA]		= { "GRMCA", K_GPORT_PORT, 0x0000000f, 0, 1 },
	[O_GRBCA]		= { "GRBCA", K_GPORT_PORT, 0x00000010, 0, 1 },
	[O_GRFCS]		= { "GRFCS", K_GPORT_PORT, 0x00000000, 0, 1 },
	[O_GROVR]		= { "GROVR", K_GPORT_PORT, 0x00000008, 0, 1 },
	[O_GRJBR]		= { "GRJBR", K_GPORT_PORT, 0x00000009, 0, 1 },
	[O_GRMTUE]		= { "GRMTUE", K_GPORT_PORT, 0x0000000a, 0, 1 },
	[O_GRUND]		= { "GRUND", K_GPORT_PORT, 0x0000000c, 0, 1 },
	[O_GRFRG]		= { "GRFRG", K_GPORT_PORT, 0x0000000d, 0, 1 },
	[O_GR9216]		= { "GR9216", K_GPORT_PORT, 0x0000001a, 0, 1 },
	[O_GTBYT]		= { "GTBYT", K_GPORT_PORT, 0x00000039, 0, 1 },
	[O_GTUC]		= { "GTUC", K_GPORT_PORT, 0x0000003a, 0, 1 },
	[O_GTMCA]		= { "GTMCA", K_GPORT_PORT, 0x0000002c, 0, 1 },
	[O_GTBCA]		= { "GTBCA", K_GPORT_PORT, 0x0000002d, 0, 1 },
	[O_GTFCS]		= { "GTFCS", K_GPORT_PORT, 0x00000021, 0, 1 },
	[O_GTOVR]		= { "GTOVR", K_GPORT_PORT, 0x00000023, 0, 1 },
	[O_GT9216]		= { "GT9216", K_GPORT_PORT, 0x00000037, 0, 1 },
	/* drops: ingress discards, egress head-of-line, MMU egress */
	[O_RDISC]		= { "RDISC", K_PIPE_PORT, 0x0f000008, BLK_IPIPE, 1 },
	[O_HOLD]		= { "HOLD", K_PIPE_PORT, 0x0f000014, BLK_IPIPE, 1 },
	[O_EGRDROPPKTCOUNT]	= { "EGRDROPPKTCOUNT", K_PIPE_PORT, 0x0000006a, BLK_MMU, 1 },
	/* egress MTU limit of a port, MTU_SIZE 13:0 (read only here) */
	[O_EGR_MTU_SIZE]	= { "EGR_MTU_SIZE", K_PIPE_PORT, 0x0f000124, BLK_IPIPE, 1 },
	/*
	 * Step trunk2. TRUNK_GROUP: PORTi 10i+5:10i, MODULEi 10i+9:10i+6 (i = 0-7), RTAG 82:80;
	 * TRUNK_BITMAP 24:0; NONUCAST_TRUNK_BLOCK_MASK 24:0 (one entry per hash index of a
	 * flooded frame); HASH_CONTROL NON_UC_TRUNK_HASH_SRC_ENABLE 1, _DST_ENABLE 2.
	 * SOURCE_TRUNK_MAP_TABLE above: PORT_TYPE 1:0, TGID 6:2, index = module id << 5 | port.
	 */
	[O_TRUNK_GROUP]		= { "TRUNK_GROUP", K_MEM, 0x0f020000, BLK_IPIPE, 3, 7 },
	[O_TRUNK_BITMAP]	= { "TRUNK_BITMAP", K_MEM, 0x0f030000, BLK_IPIPE, 1, 7 },
	[O_NONUCAST_TRUNK_BLOCK_MASK] = { "NONUCAST_TRUNK_BLOCK_MASK", K_MEM, 0x0f090000, BLK_IPIPE, 1, 15 },
	[O_HASH_CONTROL]	= { "HASH_CONTROL", K_GEN, 0x01080004, BLK_IPIPE, 1 },
};
#define MAC_MODE_LINK		BIT(5)

/*
 * LED processor of the CMIC (CMIC_LEDUP_*, OpenMDK bcm53314_a0_defs.h and
 * bmdi/xgs_led.h; OpenBCM src/appl/diag/ledproc.c, include/soc/cmic.h):
 * program and data RAM hold one byte per 32-bit word. Data byte 0xa0 + port:
 * bit 0 = link, kept current by the host (OpenMDK xgs_led_update), bit 7 = turbo.
 */
#define LEDUP_CTRL		0x1000	/* LEDUP_EN bit 0, scan delays 7:1 */
#define LEDUP_STATUS		0x1004	/* PROGRAM_COUNTER 7:0, RUNNING 8, INITIALISING 9 */
#define LEDUP_PROGRAM_RAM	0x1800
#define LEDUP_DATA_RAM		0x1c00
#define LEDUP_EN		BIT(0)
#define LED_LINK_BASE		0xa0
#define LED_DATA(i)		(LEDUP_DATA_RAM + 4 * (i))
#define LED_PORT_LO		5	/* wan2 */
#define LED_PORT_HI		24	/* MGMT = port 6 (PORT_MGMT) */
#define LED_BITS		0x81	/* link (0) and turbo (7) */
#define LED_SHOWN_LO		LED_DATA(0xa0)	/* data bytes shown by debugfs "led" */
#define LED_SHOWN_HI		LED_DATA(0xbf)
#define LED_WR_BUDGET		60	/* data RAM writes allowed ... */
#define LED_WR_WINDOW		60	/* ... per this many seconds */
#define LED_CLEAR_MAX		(LED_PORT_HI - LED_PORT_LO + 1)

/* "phyled": LED set-up of the external BCM54684 PHYs of ports 9-24 */
#define PHYLED_ID1		0x0143
#define PHYLED_ID2		0xbef0	/* & 0xfff0: BCM54684 (0x0143bef3) */
#define PHYLED_SHD(s)		((u16)((s) << 10))		/* register 0x1c: shadow select (read) */
#define PHYLED_SHD_WR(s, d)	((u16)(0x8000 | (s) << 10 | (d)))	/* register 0x1c: shadow write */
#define PHYLED_SPARE		0x02	/* spare control 1 */
#define PHYLED_SPARE_BITS	0x0006	/* timing, link speed LED mode (phy54684.c) */
#define PHYLED_SEL1		0x0d	/* LED selector 1: LED2 7:4, LED1 3:0 */
#define PHYLED_SEL1_VAL		0x01	/* LED1 = LINKSPD[2] (1), LED2 = LINKSPD[1] (0) */
#define PHYLED_CTRL		0x09	/* LED control */
#define PHYLED_CTRL_VAL		0x018	/* bit 4 = LED3 link/activity */
#define PHYLED_ECR		0x10	/* extended control */
#define PHYLED_ECR_TRAFFIC	0x0020	/* traffic LED mode, off with link/activity */
#define PHYLED_RD_SPARE		0x01	/* sw->phyled_rd_ok: spare read on this PHY, not yet written */
#define PHYLED_RD_ECR		0x02	/* sw->phyled_rd_ok: ECR read on this PHY, not yet written */

/* First eight bytes of the public reference program bcm953314p24ref (OpenBCM tools/led/example, public ledasm) */
static const u8 led_ref_head[8] = { 0x02, 0x01, 0x28, 0x60, 0xe3, 0x67, 0x43, 0x67 };

/* Step trunk2: group 7 = {ge2, ge3}, hash on source and destination IP (SDK BCM_TRUNK_PSC_SRCDSTIP) */
#define TRUNK2_TGID		7
#define TRUNK2_RTAG		6
#define STM_TRUNK2		(1 | TRUNK2_TGID << 2)	/* PORT_TYPE 1 (trunk member), TGID 7 */
#define HASH_CONTROL_RESET	0x01014000
#define HC_NUC_SRC		BIT(1)
#define HC_NUC_DST		BIT(2)
#define NUM_NUC			16

/*
 * Step "ports": front panel label, switch port, VID. Switch ports of the
 * labels: measured for MGMT, port1 and port2; the others follow the same
 * pairing (port 2k-1 on switch port 2k+8, port 2k on 2k+7).
 */
static const struct {
	const char *label;
	u8 port;
	u8 vid;
} front_ports[] = {
	{ "port1", 10, 101 }, { "port2", 9, 102 }, { "port3", 12, 103 }, { "port4", 11, 104 },
	{ "port5", 14, 105 }, { "port6", 13, 106 }, { "port7", 16, 107 }, { "port8", 15, 108 },
	{ "port9", 18, 109 }, { "port10", 17, 110 }, { "port11", 20, 111 }, { "port12", 19, 112 },
	{ "port13", 22, 113 }, { "port14", 21, 114 }, { "port15", 24, 115 }, { "port16", 23, 116 },
	{ "wan2", 5, 120 }, { "ha1", 7, 121 }, { "ha2", 8, 122 },
};

/* COMMAND_CONFIG */
#define CC_TX_ENA		BIT(0)
#define CC_RX_ENA		BIT(1)
#define CC_SW_RESET		BIT(13)
#define CC_LATE_COL_FIX		BIT(31)	/* read-only, self-clearing */

/* EGR_CONFIG / VLAN_CTRL: shared VLAN learning */
#define EGR_CONFIG_USE_LEARN_VID	BIT(1)
#define EGR_CONFIG_LEARN_VID		GENMASK(13, 2)
#define VLAN_CTRL_LEARN_VID		GENMASK(11, 0)
#define VLAN_CTRL_USE_LEARN_VID		BIT(12)

/* Debug counter selections: one drop cause per counter */
#define TDBG_VLAN_DROP		BIT(13)	/* egress VLAN membership check */
#define TDBG_STG_DROP		BIT(15)	/* egress spanning-tree state */
#define TDBG_ANY_DROP		BIT(18)	/* any egress drop */
#define RDBG_PBM_ZERO		BIT(15)	/* empty destination bitmap */
#define RDBG_VLAN_DROP		BIT(26)	/* ingress VLAN drop */

static const struct {
	int obj;
	u32 val;
} dbg_select[] = {
	{ O_TDBGC0_SELECT, TDBG_VLAN_DROP },
	{ O_TDBGC1_SELECT, TDBG_STG_DROP },
	{ O_TDBGC2_SELECT, TDBG_ANY_DROP },
	{ O_RDBGC0_SELECT, RDBG_VLAN_DROP },
	{ O_RDBGC1_SELECT, RDBG_PBM_ZERO },
};

/* ---------------------------------------------------------------------- */
/* Parameters                                                              */

static int access;
module_param(access, int, 0444);
MODULE_PARM_DESC(access, "0 = MMIO identification only (default), 1 = + S-channel/MIIM reads, 2 = + configuration writes");

static char *steps = "";
module_param(steps, charp, 0444);
MODULE_PARM_DESC(steps, "Steps run at load with access=2: counters,learning,trunk,isolate|ports[,ifilter][,ge3][,trunk2],mgmt; or init alone");

static char *isolate = "";
module_param(isolate, charp, 0444);
MODULE_PARM_DESC(isolate, "Front ports to isolate: <port 5-24>:<vid vid_base..vid_base+99>[,...]");

/*
 * vid_base: first VID of the block of the front-port VLANs.
 * Port VID of a front port = vid_base + (its VID in front_ports[] - 100),
 * i.e. 101-122 at the default 100 (nothing else changes); the DSA driver
 * puts its bridge VIDs at vid_base + 41 .. + 48. The block vid_base ..
 * vid_base + 99 must stay clear of VID 1, of VID 20 (MGMT) and of
 * 4076-4095 (VLAN-aware pool of the DSA driver): 21 <= vid_base <= 3976.
 */
static int vid_base = VID_BASE_DEF;
module_param(vid_base, int, 0444);
MODULE_PARM_DESC(vid_base, "First VID of the front-port VLAN block (21-3976, default 100: port VIDs 101-122)");

/* port VID of front_ports[@i] under vid_base */
static int fp_vid(int i)
{
	return vid_base - VID_BASE_DEF + front_ports[i].vid;
}

static bool trunk_autoneg;
module_param(trunk_autoneg, bool, 0444);
MODULE_PARM_DESC(trunk_autoneg, "Let the trunk PHY auto-negotiate (step trunk)");

static bool dry_run = true;
module_param(dry_run, bool, 0444);
MODULE_PARM_DESC(dry_run, "Log the write plan without writing (default Y)");

static bool init_phy = true;
module_param(init_phy, bool, 0444);
MODULE_PARM_DESC(init_phy, "Step init: also set up the internal PHYs of ports 1-8 (default Y; N = no MIIM access)");

static bool init_ledram = true;
module_param(init_ledram, bool, 0444);
MODULE_PARM_DESC(init_ledram, "Step init: R17 hands the LEDs of ports 1-8 to the LED processor (default Y); N = R17 left out, these LEDs stay with the internal PHYs (one write less)");

static int monitor;
module_param(monitor, int, 0444);
MODULE_PARM_DESC(monitor, "0 = off (default), 1 = link and MIB reads once a second, 2 = also keep the link bitmap of the front ports (step ports)");

static int leds;
module_param(leds, int, 0444);
MODULE_PARM_DESC(leds, "0 = off (default), 1 = the work item keeps the link bit of ports 5-24 in the LED processor data RAM (monitor >= 1, access=2, dry_run=N)");

static int phyled;
module_param(phyled, int, 0444);
MODULE_PARM_DESC(phyled, "0 = off (default), 1 = at load, LED set-up of the external PHYs of ports 9-24 as FortiOS (link speed LEDs, link/activity), read back (access=2, not with init; dry_run=Y: reads only, shadow selections excepted)");

static char *linksrc = "bmsr";
module_param(linksrc, charp, 0444);
MODULE_PARM_DESC(linksrc, "Link source of the work item (monitor >= 1, inert otherwise): bmsr (default, MII status of the port PHY, MIIM reads only) or mac (MAC_MODE link bit, does not fall on a link loss)");
static bool link_bmsr;	/* linksrc=bmsr, set at load */

/*
 * Step "mgmt" without link on MGMT: false (always, for this module on its
 * own) = the plan is refused (-ENOLINK) unless the MGMT PHY has a link;
 * true = the plan is built whatever the link. Not a parameter of this
 * module: only a driver that includes this file sets it (the DSA driver,
 * whose MGMT user port may have no cable and whose PHY may still be at
 * forced 1000 Mb/s after step "init"). The writes are the same either way.
 */
static bool mgmt_link_optional;

/* ---------------------------------------------------------------------- */
/* State                                                                   */

#define MAX_ISOLATE		20
static_assert(ARRAY_SIZE(front_ports) <= MAX_ISOLATE);
#define MAX_OPS			400	/* steps counters to ports: 246; to ifilter: 265; to ge3: 273; to ifilter and mgmt: 277 */
/* step mgmt goes with step ports only together with step ifilter (front ports filter tagged frames on ingress) */
#define MGMT_NEEDS_IFILTER	1
/* step mgmt may be planned without link on MGMT (mgmt_link_optional, set by an including driver) */
#define MGMT_LINK_OPTIONAL	1
#define SHADOW_SLOTS		320

/* Work item of "monitor" */
#define MON_PERIOD_MS		1000
#define MON_MIB_TICKS		10	/* MIB every 10 s: a byte counter wraps in 34 s at 1 Gb/s */
#define LINK_DEBOUNCE		2	/* samples in a row before a link change is taken */
#define LINK_WR_BUDGET		10	/* bitmap writes allowed ... */
#define LINK_WR_WINDOW		60	/* ... per this many seconds */
#define LINK_LOG_MAX		20	/* link lines logged per window */
#define BMSR_GAP_ADDR		0x11	/* external MIIM address of no port (answers 0x0143bff0): never read */
#define NUM_SHOWN		(ARRAY_SIZE(front_ports) + 2)	/* front ports, MGMT, trunk */

static const int mib_objs[] = {
	O_GRPKT, O_GRBYT, O_GRUC, O_GRMCA, O_GRBCA, O_GRFCS, O_GROVR, O_GRJBR, O_GRMTUE,
	O_GRUND, O_GRFRG, O_GR9216, O_GTPKT, O_GTBYT, O_GTUC, O_GTMCA, O_GTBCA, O_GTFCS,
	O_GTOVR, O_GT9216, O_RDISC, O_RDBGC0, O_HOLD, O_TDBGC2, O_EGRDROPPKTCOUNT,
};
#define NUM_MIB			ARRAY_SIZE(mib_objs)

/* One line of the step "init" table: printed as one line of "plan" */
enum { V_MMIO, V_SREG, V_SMEM, V_MIIM };
enum {
	L_RD,		/* isolated read */
	L_WR,		/* write of the value of the table */
	L_RMW,		/* read, (value & m) | v, write */
	L_WRD,		/* write of (value read by the previous line & m) | v, no read */
	L_WWR,		/* write of the entry written by the previous line */
};
enum { P_NONE, P_WAIT, P_PLL, P_PIPE, P_COSLC, P_PHYRST };
enum { R_NONE, R_IDX, R_GPORT };	/* compact loop over table indexes or GPORT blocks */
enum { G_NONE, G_CFG, G_CFG_SET_UP, G_PHYID };

#define INIT_MAX_LINES		1100
#define INIT_LINE		192	/* longest formatted line, with margin */
#define INIT_VALS		96	/* values read, appended to a "log" line */
#define INIT_LOG_EXTRA		(INIT_VALS + 112)

struct iline {
	char id[20];
	u8 voie, op, post, loop, guard, words;
	u8 phy, reg;
	bool check;
	u16 lo, hi;
	u32 addr;
	u32 aux;		/* address of the poll (P_COSLC) or of the source line */
	u32 m[3], v[3];
	u32 wait_us;
	u32 chk;
	const char *src;	/* L_WRD, L_WWR: id of the source line */
};

struct plan_op {
	bool miim;
	int obj;
	int idx;
	u32 old[3];
	u32 val[3];
	u32 pre_mask[3];	/* bits compared before the write */
	u32 post_mask[3];	/* bits compared after the write */
	u8 phy, reg;
	unsigned int delay_us;
	const char *what;
};

struct bcm53314 {
	struct pci_dev *pdev;
	void __iomem *bar;
	struct mutex lock;
	struct dentry *dbg;
	bool halted;		/* first fault: no further access */
	/* write authorisation of the operation in progress */
	bool schan_write_armed;
	u32 schan_write_addr;
	u32 schan_write_data[SCHAN_WRITE_WORDS];
	int schan_write_words;
	bool arl_armed;		/* one L2X insert/delete message: exact header and entry */
	u32 arl_msg[ARL_MSG_WORDS];
	bool miim_write_armed;
	u8 miim_arm_phy, miim_arm_reg;
	/*
	 * One MIIM write of an advertisement register (4 or 9) of a front-port
	 * PHY, armed by the DSA driver only (link=2); never set by this module.
	 */
	bool miim_adv_armed;
	/*
	 * One MIIM write of the expansion register select (0x17) or data (0x15)
	 * of an external port PHY (BCM54684, 0x09-0x10, 0x12-0x19), armed by the
	 * DSA driver only; never set by this module. The
	 * value must be the armed one and one of miim_exp_val_ok(); miim_exp_cur
	 * is the last select written that way (PHY << 16 | value).
	 */
	bool miim_exp_armed;
	u16 miim_exp_val;
	u32 miim_exp_cur;
	/*
	 * Reads of CMIC_TIMESYNC_CONTROL and CMIC_TIMESYNC_TIMER (0xd4c, 0xd50:
	 * outside the CMIC reads of this module), armed by the DSA driver only
	 * around each read (ptp>=1); never set by this module.
	 */
	bool timesync_rd_armed;
	/* "phyled": one MIIM write of an external PHY, register 0x10/0x1c, exact value */
	bool phyled_active;
	u16 phyled_val;
	u8 phyled_phy, phyled_rd_ok;	/* current PHY; PHYLED_RD_*: values read on it */
	u16 phyled_spare, phyled_ecr;	/* last values read (spare data 9:0, ECR) */
	int phyled_nw, phyled_nsel, phyled_nplan;
	/* step "init": refusals lifted for the duration of its run only */
	bool init_active;
	bool init_mmio_armed;	/* one CMIC write of the table, exact value */
	u32 arm_off, arm_val;
	bool cfg_rd_valid, mode_rd_valid, qg_rd_valid;
	u32 cfg_rd, mode_rd, qg_rd;	/* last reads of 0x10c, 0x198, 0x14c */
	bool cps_pending;	/* RESET_CPS written, dummy read not done yet */
	int rst_step;		/* writes of CMIC_SOFT_RESET done */
	char cause[96];		/* first fault of the run */
	struct iline *il;
	struct iline il_spare;
	int nil;
	bool il_overflow;
	u32 prev_rd[3], prev_rd_addr;
	u32 prev_wr[3], prev_wr_addr;
	int tot_mmio, tot_schan, tot_miim;
	char *plan, *log;
	size_t plan_len, log_len, log_cap;
	/* plan */
	struct plan_op ops[MAX_OPS];
	int nops;
	int nwritten;
	struct {
		int obj, idx;
		u32 w[3];
	} shadow[SHADOW_SLOTS];
	int nshadow;
	/* configuration */
	int iso_port[MAX_ISOLATE];
	int iso_vid[MAX_ISOLATE];
	int niso;
	bool ports;		/* step "ports" requested: iso_* filled from front_ports[] */
	bool ifilter;		/* step "ifilter" requested */
	bool mgmt;		/* step "mgmt" requested */
	bool ge3;		/* step "ge3" requested */
	bool trunk2;		/* step "trunk2" requested */
	/* monitor */
	struct delayed_work mon_work;
	bool mon_started;
	u32 tick;
	u32 link_raw;		/* link bits of the last sample (MAC_MODE, or BMSR with linksrc=bmsr) */
	u32 link_mac;		/* MAC_MODE link bits of the last sample */
	u32 bmsr_reads;		/* MIIM reads of the work item (linksrc=bmsr) */
	u32 link_up;		/* debounced link bits */
	u8 link_cnt[NUM_PORTS];
	u32 link_trans[NUM_PORTS];
	u32 epc_expect;		/* link bitmap as last read or written */
	int link_writes;
	u32 link_wr_tick[LINK_WR_BUDGET];
	bool link_wr_stopped;
	char link_stop[80];
	int log_win, log_supp;
	u32 log_win_tick;
	/* leds */
	bool led_armed;		/* LED processor enabled, reference program layout */
	bool led_wr_armed;	/* one data RAM write: exact address, value and value read */
	u32 led_arm_off, led_arm_val, led_arm_old;
	bool led_stopped;	/* no further link bit set */
	bool led_fault;		/* no further LED write at all, removal included */
	char led_why[80];
	int led_writes;
	u32 led_wr_tick[LED_WR_BUDGET];
	u32 led_touched;	/* ports whose data byte was written */
	int led_cleared;	/* link bits cleared at removal */
	bool mib_valid;
	u32 mib_last[NUM_SHOWN][NUM_MIB];
	u64 mib_sum[NUM_SHOWN][NUM_MIB];
};

static struct bcm53314 *sw_dev;

/* ---------------------------------------------------------------------- */
/* CMIC access: deny list first, then allow list                           */

static bool cmic_denied(u32 off)
{
	static const struct { u32 lo, hi; } deny[] = {
		{ 0x05c, 0x05c },	/* CMIC_SCHAN_ERR */
		{ 0x100, 0x11c },	/* packet DMA: bcm5331x-cmic.c, its own list */
		{ 0x10c, 0x10c },	/* CMIC_CONFIG: S-channel abort, I2C enable */
		{ 0x120, 0x13c },	/* I2C controller */
		{ 0x164, 0x170 },	/* statistics DMA */
		{ 0x420, 0x49c },	/* table, SLAM and statistics DMA */
		{ 0x580, 0x580 },	/* block soft reset */
		{ 0x5c0, 0x5fc },	/* DMA */
		{ 0x780, 0x784 },	/* DMA */
		{ 0x864, 0x864 },	/* MIIM auto-scan address */
		{ 0x900, CMIC_BAR_SIZE - 1 },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(deny); i++)
		if (off >= deny[i].lo && off <= deny[i].hi)
			return true;
	return false;
}

/*
 * DSA driver (miim_exp_armed): expansion register select values a
 * write may take: 0 (no expansion register, as step "init" and Linux leave
 * it), or 0x0F00 | e for the expansion registers 0x10-0x13 (cable
 * diagnostics results of the BCM54684, OpenMDK bcm54684_defs.h) and
 * 0xC0-0xC5 (ECD control, fault type, pair lengths, brcmphy.h); data
 * register: only 0x8000 (ECD run, nothing else set) and only while the
 * select of that PHY is 0x0FC0.
 */
#define MIIM_EXP_SEL		0x17
#define MIIM_EXP_DATA		0x15
#define MIIM_EXP_ER		0x0f00
#define MIIM_EXP_ECD_CTRL	0x0fc0
#define MIIM_EXP_ECD_RUN	0x8000

static bool miim_exp_phy_ok(u8 phy)
{
	return phy >= 0x09 && phy <= 0x19 && phy != BMSR_GAP_ADDR;
}

static bool miim_exp_sel_ok(u16 v)
{
	u16 e = v & 0xff;

	return !v || ((v & 0xff00) == MIIM_EXP_ER && ((e >= 0x10 && e <= 0x13) || (e >= 0xc0 && e <= 0xc5)));
}

static bool miim_exp_val_ok(const struct bcm53314 *sw, u8 reg, u16 v)
{
	if (!miim_exp_phy_ok(sw->miim_arm_phy) || v != sw->miim_exp_val)
		return false;
	if (reg == MIIM_EXP_SEL)
		return miim_exp_sel_ok(v);
	return reg == MIIM_EXP_DATA && v == MIIM_EXP_ECD_RUN &&
	       sw->miim_exp_cur == ((u32)sw->miim_arm_phy << 16 | MIIM_EXP_ECD_CTRL);
}

/*
 * Step "init", CMIC writes: only the write armed by the current line of its
 * table, with the value of the line, and only these registers. Within the
 * deny list, only CMIC_CONFIG, CMIC_SOFT_RESET and CMIC_INTR_WAIT_CYCLES are
 * lifted; the rest of 0x100-0x11c, I2C, DMA, LED, CMIC_SCHAN_ERR stay refused.
 */
static bool init_mmio_allowed(struct bcm53314 *sw, u32 off, u32 val)
{
	static const u32 rst_seq[] = { SOFT_RESET_DISK, 0x00000200, 0x0001e200, SOFT_RESET_SET_UP };

	if (!sw->init_active || off != sw->arm_off || val != sw->arm_val)
		return false;
	if (cmic_denied(off) && off != CMIC_CONFIG && off != CMIC_SOFT_RESET &&
	    off != CMIC_INTR_WAIT_CYCLES)
		return false;
	switch (off) {
	case CMIC_CONFIG:	/* read | burst enables, or read | RESET_CPS, never abort/I2C */
		if (!sw->cfg_rd_valid || ((sw->cfg_rd | val) & (CFG_SCHAN_ABORT | CFG_I2C_EN)))
			return false;
		return val == (sw->cfg_rd | CFG_BURST) || val == (sw->cfg_rd | CFG_RESET_CPS);
	case CMIC_SOFT_RESET:	/* fixed sequence, each value once */
		return sw->rst_step < ARRAY_SIZE(rst_seq) && val == rst_seq[sw->rst_step];
	case CMIC_IRQ_MASK:
	case CMIC_ENDIANESS_SEL:
	case CMIC_INTR_WAIT_CYCLES:
		return val == 0;
	case CMIC_SBUS_RING_MAP:
		return val == SBUS_RING_MAP;
	case CMIC_CHIP_MODE_CONTROL:	/* UNMANAGED_MODE cleared */
		return sw->mode_rd_valid && val == (sw->mode_rd & ~BIT(0));
	case CMIC_QGPHY_QSGMII_CONTROL:	/* SEL_LEDRAM_SERIAL_DATA set */
		return sw->qg_rd_valid && val == (sw->qg_rd | BIT(3));
	}
	return false;
}

/* MIIM registers written by step "init" on the internal PHYs of ports 1-8 */
static bool init_phy_reg_ok(u32 reg)
{
	switch (reg) {
	case 0x00: case 0x09: case 0x10: case 0x15: case 0x17: case 0x18: case 0x1c: case 0x1e:
		return true;
	}
	return false;
}

/* "phyled": external PHYs of ports 9-24 only (0x11 is no port) */
static bool phyled_phy_ok(u8 phy)
{
	return (phy >= 0x09 && phy <= 0x10) || (phy >= 0x12 && phy <= 0x19);
}

/* LED processor words read by debugfs "led" and by "leds": these only */
static bool led_read_ok(u32 off)
{
	return off == LEDUP_CTRL || off == LEDUP_STATUS ||
	       (off >= LEDUP_PROGRAM_RAM && off <= LEDUP_PROGRAM_RAM + 4 * 255) ||
	       (off >= LED_SHOWN_LO && off <= LED_SHOWN_HI);
}

/*
 * "leds", one data RAM write: only the write armed for it, at the address,
 * with the value and from the value read that were armed; only the link
 * byte of ports 5-24; only bits 0 and 7 changed, bit 7 always left clear;
 * setting bit 0 refused once the LED writes are stopped (clearing it stays
 * allowed: removal). Checked before the deny list, which keeps refusing
 * every other LED processor word, in writes as in reads.
 */
static bool led_write_allowed(struct bcm53314 *sw, u32 off, u32 val)
{
	u32 old = sw->led_arm_old;

	if (leds != 1 || monitor < 1 || access != 2 || dry_run || !sw->led_armed || sw->led_fault)
		return false;
	if (off != sw->led_arm_off || val != sw->led_arm_val || off < LED_DATA(LED_LINK_BASE + LED_PORT_LO) ||
	    off > LED_DATA(LED_LINK_BASE + LED_PORT_HI) || old > 0xff)
		return false;
	if (val == (old & ~LED_BITS))
		return true;
	return val == ((old & ~LED_BITS) | 1) && !sw->led_stopped;
}

static u32 schan_header(u32 opcode, u32 addr, u32 bytes);

static bool cmic_write_allowed(struct bcm53314 *sw, u32 off, u32 val)
{
	if (off & 3)
		return false;
	if (sw->init_mmio_armed)
		return access == 2 && init_mmio_allowed(sw, off, val);
	if (sw->led_wr_armed)
		return led_write_allowed(sw, off, val);
	if (cmic_denied(off) || access < 1)
		return false;
	/*
	 * L2X insert/delete (DSA driver, fdb=1): the message words are exactly
	 * the armed ones, an insert or delete header to the IPIPE with the
	 * length of one L2X entry; the start bit is the usual SC_MSG_START_SET.
	 */
	if (sw->arl_armed && off >= CMIC_SCHAN_MSG && off < CMIC_SCHAN_MSG + 4 * ARL_MSG_WORDS) {
		u32 h = sw->arl_msg[0];

		if (access != 2 ||
		    (h != schan_header(OP_ARL_INSERT, BLK_IPIPE << 20, 12) &&
		     h != schan_header(OP_ARL_DELETE, BLK_IPIPE << 20, 12)))
			return false;
		return val == sw->arl_msg[(off - CMIC_SCHAN_MSG) / 4];
	}
	switch (off) {
	case CMIC_SCHAN_CTRL:
		if (val == SC_MSG_START_SET || val == SC_MSG_DONE_CLR ||
		    val == SC_MIIM_RD_START_SET || val == SC_MIIM_OP_DONE_CLR)
			return true;
		return val == SC_MIIM_WR_START_SET && sw->miim_write_armed;
	case CMIC_MIIM_PARAM:	/* PHY id + internal bus select, data on writes */
		if (!(val & ~0x009f0000))
			return true;
		if (!sw->miim_write_armed || (val & ~0x009fffff) || val >> 16 != sw->miim_arm_phy)
			return false;
		if (sw->phyled_active)
			return phyled_phy_ok(sw->miim_arm_phy) && (val & 0xffff) == sw->phyled_val;
		if (sw->miim_exp_armed)
			return !sw->init_active && miim_exp_val_ok(sw, sw->miim_arm_reg, val & 0xffff);
		return !sw->init_active || (sw->miim_arm_phy >= 0x81 && sw->miim_arm_phy <= 0x88);
	case CMIC_MIIM_ADDRESS:	/* clause 22 register */
		if (val > 0x1f)
			return false;
		if (!sw->miim_write_armed)
			return true;
		if (sw->phyled_active)
			return val == sw->miim_arm_reg && (val == 0x1c || val == PHYLED_ECR);
		if (sw->init_active)
			return val == sw->miim_arm_reg && init_phy_reg_ok(val);
		if (sw->miim_exp_armed)
			return val == sw->miim_arm_reg && (val == MIIM_EXP_SEL || val == MIIM_EXP_DATA);
		if (sw->miim_adv_armed)
			return val == sw->miim_arm_reg && (val == MII_ADVERTISE || val == MII_CTRL1000);
		return val == MII_BMCR;
	case CMIC_SCHAN_MSG: {
		u32 opc = val >> 26;

		if (opc == OP_READ_MEM || opc == OP_READ_REG)
			return true;
		return (opc == OP_WRITE_MEM || opc == OP_WRITE_REG) &&
		       sw->schan_write_armed;
	}
	case CMIC_SCHAN_MSG + 4:
		return !sw->schan_write_armed || val == sw->schan_write_addr;
	}
	if (off > CMIC_SCHAN_MSG + 4 && off < CMIC_SCHAN_MSG_END && sw->schan_write_armed) {
		int i = (off - CMIC_SCHAN_MSG - 8) / 4;

		return i < sw->schan_write_words && val == sw->schan_write_data[i];
	}
	return false;
}

#define CMIC_TIMESYNC_CONTROL	0xd4c	/* OpenMDK bcm53314_a0_defs.h */
#define CMIC_TIMESYNC_TIMER	0xd50

static bool cmic_read_allowed(struct bcm53314 *sw, u32 off)
{
	if ((off & 3) || off >= CMIC_BAR_SIZE)
		return false;
	if (sw->timesync_rd_armed && (off == CMIC_TIMESYNC_CONTROL || off == CMIC_TIMESYNC_TIMER))
		return true;
	/* the first read after a CPS reset may return invalid data: never CMIC_CONFIG */
	if (sw->cps_pending && off == CMIC_CONFIG)
		return false;
	if (off >= CMIC_SCHAN_MSG && off < CMIC_SCHAN_MSG_END)
		return true;
	if (sw->init_active && (off == CMIC_IRQ_MASK || off == CMIC_CHIP_MODE_CONTROL ||
				off == CMIC_QGPHY_QSGMII_CONTROL || off == CMIC_XGXS_PLL_STATUS))
		return true;
	if (led_read_ok(off))
		return true;
	return off == CMIC_SCHAN_CTRL || off == CMIC_CONFIG ||
	       off == CMIC_MIIM_PARAM || off == CMIC_MIIM_READ_DATA ||
	       off == CMIC_DEV_REV_ID || off == CMIC_MIIM_ADDRESS ||
	       off == CMIC_SOFT_RESET;
}

/*
 * First fault: no further access. During step "init" the cause is kept for
 * the end line and the "log" file, not written to the kernel log.
 */
static __printf(2, 3) void sw_fault(struct bcm53314 *sw, const char *fmt, ...)
{
	char buf[sizeof(sw->cause)];
	va_list ap;

	va_start(ap, fmt);
	vscnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	sw->halted = true;
	if (!sw->init_active)
		dev_err(&sw->pdev->dev, "%s, halting\n", buf);
	else if (!sw->cause[0])
		strscpy(sw->cause, buf, sizeof(sw->cause));
}

static int cmic_rd(struct bcm53314 *sw, u32 off, u32 *val)
{
	if (sw->halted)
		return -EIO;
	if (!cmic_read_allowed(sw, off)) {
		sw_fault(sw, "read 0x%03x refused", off);
		return -EPERM;
	}
	*val = ioread32(sw->bar + off);
	if (sw->init_active) {
		switch (off) {
		case CMIC_CONFIG:
			sw->cfg_rd = *val;
			sw->cfg_rd_valid = true;
			break;
		case CMIC_CHIP_MODE_CONTROL:
			sw->mode_rd = *val;
			sw->mode_rd_valid = true;
			break;
		case CMIC_QGPHY_QSGMII_CONTROL:
			sw->qg_rd = *val;
			sw->qg_rd_valid = true;
			break;
		case CMIC_IRQ_MASK:	/* the dummy read after a CPS reset */
			sw->cps_pending = false;
			break;
		}
	}
	return 0;
}

static int cmic_wr(struct bcm53314 *sw, u32 off, u32 val)
{
	if (sw->halted)
		return -EIO;
	if (!cmic_write_allowed(sw, off, val)) {
		sw->led_wr_armed = false;
		sw_fault(sw, "write 0x%03x <- 0x%08x refused", off, val);
		return -EPERM;
	}
	iowrite32(val, sw->bar + off);
	sw->led_wr_armed = false;	/* one write per arming */
	if (sw->init_mmio_armed) {
		sw->init_mmio_armed = false;	/* one write per arming */
		if (off == CMIC_SOFT_RESET)
			sw->rst_step++;
		if (off == CMIC_CONFIG) {
			sw->cfg_rd_valid = false;
			if (val & CFG_RESET_CPS)
				sw->cps_pending = true;
		}
		if (off == CMIC_CHIP_MODE_CONTROL)
			sw->mode_rd_valid = false;
		if (off == CMIC_QGPHY_QSGMII_CONTROL)
			sw->qg_rd_valid = false;
	}
	return 0;
}

static int cmic_wait(struct bcm53314 *sw, u32 bit, u32 timeout_us, u32 *ctrl)
{
	ktime_t end = ktime_add_us(ktime_get(), timeout_us);
	int err;

	for (;;) {
		err = cmic_rd(sw, CMIC_SCHAN_CTRL, ctrl);
		if (err)
			return err;
		if (*ctrl & bit)
			return 0;
		if (ktime_after(ktime_get(), end))
			return -ETIMEDOUT;
		usleep_range(10, 20);
	}
}

/* ---------------------------------------------------------------------- */
/* S-channel                                                               */

static int obj_idx_valid(const struct sw_obj *o, int idx)
{
	switch (o->kind) {
	case K_GEN:
		return idx == 0;
	case K_PIPE_PORT:
		return idx >= 0 && idx < NUM_PORTS;
	case K_GPORT_PORT:
		return idx >= 1 && idx < NUM_PORTS;
	case K_MEM:
		return idx >= 0 && idx <= o->max;
	}
	return 0;
}

static u32 obj_addr(const struct sw_obj *o, int idx)
{
	switch (o->kind) {
	case K_GPORT_PORT:	/* GPORT0/1/2 = blocks 2/3/4, eight ports each */
		return o->base | (2 + (idx - 1) / 8) << 20 | ((idx - 1) % 8) << 12;
	case K_PIPE_PORT:
		return o->base | o->blk << 20 | idx << 12;
	case K_MEM:
		return o->base + (o->blk << 20) + idx;
	default:
		return o->base | o->blk << 20;
	}
}

static u32 schan_header(u32 opcode, u32 addr, u32 bytes)
{
	u32 dst = ((addr >> 20) & 0xf) | ((addr >> 30) & 3) << 4;

	return opcode << 26 | dst << 20 | bytes << 7;	/* source block 0 = CMIC */
}

/* One S-channel request on a full address; name/idx only label a fault */
static int schan_xfer(struct bcm53314 *sw, bool write, bool mem, u32 addr, int words,
		      u32 *w, const char *name, int idx)
{
	char lbl[40];
	u32 ctrl, r0;
	int err, i, werr = 0;

	if (access < 1)
		return -EPERM;
	if (name)
		scnprintf(lbl, sizeof(lbl), "%s[%d]", name, idx);
	else
		scnprintf(lbl, sizeof(lbl), "0x%08x", addr);
	err = cmic_rd(sw, CMIC_SCHAN_CTRL, &ctrl);
	if (err)
		return err;
	if (ctrl & SC_MSG_BUSY) {
		sw_fault(sw, "S-channel busy (0x%08x)", ctrl);
		return -EBUSY;
	}

	if (write && (words < 1 || words > SCHAN_WRITE_WORDS ||
		      (words > SCHAN_WRITE_WORDS_STD &&
		       (!mem || addr < SCHAN_FP_TCAM_FIRST || addr > SCHAN_FP_TCAM_LAST)))) {
		sw_fault(sw, "write %s: %d words", lbl, words);
		return -EINVAL;
	}
	if (write) {
		sw->schan_write_armed = true;
		sw->schan_write_addr = addr;
		sw->schan_write_words = words;
		memcpy(sw->schan_write_data, w, 4 * words);
		err = cmic_wr(sw, CMIC_SCHAN_MSG,
			      schan_header(mem ? OP_WRITE_MEM : OP_WRITE_REG, addr, 4 * words));
	} else {
		err = cmic_wr(sw, CMIC_SCHAN_MSG,
			      schan_header(mem ? OP_READ_MEM : OP_READ_REG, addr, 4));
	}
	if (!err)
		err = cmic_wr(sw, CMIC_SCHAN_MSG + 4, addr);
	for (i = 0; write && !err && i < words; i++)
		err = cmic_wr(sw, CMIC_SCHAN_MSG + 8 + 4 * i, w[i]);
	if (!err)
		err = cmic_wr(sw, CMIC_SCHAN_CTRL, SC_MSG_START_SET);
	sw->schan_write_armed = false;
	sw->schan_write_words = 0;
	if (err)
		return err;

	werr = cmic_wait(sw, SC_MSG_DONE, SCHAN_TIMEOUT_US, &ctrl);
	err = cmic_wr(sw, CMIC_SCHAN_CTRL, SC_MSG_DONE_CLR);	/* always; no error clear, no abort */
	if (werr || err || (ctrl & (SC_MSG_NAK | SC_MSG_TIMEOUT))) {
		sw_fault(sw, "%s %s: %s (0x%08x)", write ? "write" : "read", lbl,
			 werr ? "no answer" : (ctrl & SC_MSG_NAK) ? "NAK" :
			 "timeout, target block did not answer", ctrl);
		return -EIO;
	}

	if (!write) {
		err = cmic_rd(sw, CMIC_SCHAN_MSG, &r0);
		if (err)
			return err;
		if (r0 >> 26 != (mem ? OP_READ_MEM_ACK : OP_READ_REG_ACK) || (r0 & 0x41)) {
			sw_fault(sw, "read %s: bad answer 0x%08x", lbl, r0);
			return -EIO;
		}
		for (i = 0; i < words; i++) {
			err = cmic_rd(sw, CMIC_SCHAN_MSG + 4 + 4 * i, &w[i]);
			if (err)
				return err;
		}
	}

	err = cmic_rd(sw, CMIC_SCHAN_CTRL, &ctrl);
	if (err)
		return err;
	if (ctrl & SC_MSG_BUSY) {
		sw_fault(sw, "S-channel status 0x%08x after completion", ctrl);
		return -EIO;
	}
	return 0;
}

static int schan_op(struct bcm53314 *sw, bool write, int obj, int idx, u32 *w)
{
	const struct sw_obj *o = &objs[obj];

	if (access < 1)
		return -EPERM;
	if (!obj_idx_valid(o, idx)) {
		sw->halted = true;
		return -EINVAL;
	}
	return schan_xfer(sw, write, o->kind == K_MEM, obj_addr(o, idx), o->words, w,
			  o->name, idx);
}

static int sw_read(struct bcm53314 *sw, int obj, int idx, u32 *w)
{
	memset(w, 0, 3 * sizeof(*w));
	return schan_op(sw, false, obj, idx, w);
}

/* ---------------------------------------------------------------------- */
/* MIIM (clause 22 through CMIC_MIIM_ADDRESS); hardware link scan must be off */

static int miim_op(struct bcm53314 *sw, bool write, u8 phy, u8 reg, u16 *val)
{
	u32 ctrl, data;
	int err, werr;

	if (access < 1)
		return -EPERM;
	err = cmic_rd(sw, CMIC_SCHAN_CTRL, &ctrl);
	if (err)
		return err;
	if (ctrl & SC_MIIM_BUSY) {
		sw_fault(sw, "MIIM busy or link scan on (0x%08x)", ctrl);
		return -EBUSY;
	}
	if (write) {
		sw->miim_write_armed = true;
		sw->miim_arm_phy = phy;
		sw->miim_arm_reg = reg;
	}
	err = cmic_wr(sw, CMIC_MIIM_ADDRESS, reg);
	if (!err)
		err = cmic_wr(sw, CMIC_MIIM_PARAM, (u32)phy << 16 | (write ? *val : 0));
	if (!err)
		err = cmic_wr(sw, CMIC_SCHAN_CTRL,
			      write ? SC_MIIM_WR_START_SET : SC_MIIM_RD_START_SET);
	sw->miim_write_armed = false;
	if (err)
		return err;
	werr = cmic_wait(sw, SC_MIIM_OP_DONE, MIIM_TIMEOUT_US, &ctrl);
	err = cmic_wr(sw, CMIC_SCHAN_CTRL, SC_MIIM_OP_DONE_CLR);
	if (werr || err) {
		sw_fault(sw, "MIIM phy 0x%02x reg %u: no answer", phy, reg);
		return -EIO;
	}
	if (write && reg == MIIM_EXP_SEL)
		sw->miim_exp_cur = sw->miim_exp_armed ? (u32)phy << 16 | *val : 0;
	if (!write) {
		err = cmic_rd(sw, CMIC_MIIM_READ_DATA, &data);
		if (err)
			return err;
		*val = data;
	}
	return 0;
}

/* ---------------------------------------------------------------------- */
/* Bit fields of multi-word entries                                        */

static u32 ent_get(const u32 *w, int bp, int len)
{
	u32 v = 0;
	int i;

	for (i = 0; i < len; i++)
		if (w[(bp + i) / 32] & BIT((bp + i) % 32))
			v |= BIT(i);
	return v;
}

static void ent_set(u32 *w, int bp, int len, u32 v)
{
	int i;

	for (i = 0; i < len; i++) {
		int b = bp + i;

		if (v & BIT(i))
			w[b / 32] |= BIT(b % 32);
		else
			w[b / 32] &= ~BIT(b % 32);
	}
}

/* VLAN_TAB: PORT_BITMAP 24:0, VALID 25, STG 31:26, VLAN_PROFILE_PTR 34:32 */
#define VT_PBM(w)	ent_get(w, 0, 25)
#define VT_VALID(w)	ent_get(w, 25, 1)
#define VT_STG(w)	ent_get(w, 26, 6)
/* EGR_VLAN: UT_BITMAP 24:0, PORT_BITMAP 49:25, STG 55:50, VALID 56, OUTER_TPID_INDEX 58:57 */
#define EV_UT(w)	ent_get(w, 0, 25)
#define EV_PBM(w)	ent_get(w, 25, 25)
#define EV_STG(w)	ent_get(w, 50, 6)
#define EV_VALID(w)	ent_get(w, 56, 1)
/* PORT_TAB: EN_IFILTER 3, PORT_DIS_TAG 14, PORT_DIS_UNTAG 15, MAC/SUBNET VID 18/17, PORT_VID 30:19,
 * OUTER_TPID_ENABLE 53:50, TRUST_INCOMING_VID 56, VT_ENABLE 58 */
#define PT_VID(w)	ent_get(w, 19, 12)

static void vlan_tab_build(u32 *w, u32 pbm)
{
	w[0] = w[1] = w[2] = 0;
	ent_set(w, 0, 25, pbm);
	ent_set(w, 25, 1, 1);
	ent_set(w, 26, 6, STG_DEFAULT);
}

static void egr_vlan_build(u32 *w, u32 pbm, u32 untagged)
{
	w[0] = w[1] = w[2] = 0;
	ent_set(w, 0, 25, untagged);
	ent_set(w, 25, 25, pbm);
	ent_set(w, 50, 6, STG_DEFAULT);
	ent_set(w, 56, 1, 1);
}

/* ---------------------------------------------------------------------- */
/* Plan: computed on a read-through shadow, validated, then executed       */

static int shadow_get(struct bcm53314 *sw, int obj, int idx, u32 *w)
{
	int i, err;

	for (i = 0; i < sw->nshadow; i++)
		if (sw->shadow[i].obj == obj && sw->shadow[i].idx == idx) {
			memcpy(w, sw->shadow[i].w, sizeof(sw->shadow[i].w));
			return 0;
		}
	if (sw->nshadow >= SHADOW_SLOTS)
		return -ENOSPC;
	err = sw_read(sw, obj, idx, w);
	if (err)
		return err;
	sw->shadow[sw->nshadow].obj = obj;
	sw->shadow[sw->nshadow].idx = idx;
	memcpy(sw->shadow[sw->nshadow].w, w, sizeof(sw->shadow[0].w));
	sw->nshadow++;
	return 0;
}

static void shadow_set(struct bcm53314 *sw, int obj, int idx, const u32 *w)
{
	int i;

	for (i = 0; i < sw->nshadow; i++)
		if (sw->shadow[i].obj == obj && sw->shadow[i].idx == idx) {
			memcpy(sw->shadow[i].w, w, sizeof(sw->shadow[i].w));
			return;
		}
}

/* Queue a write of obj[idx]: old = shadow, ignore = bits not compared */
static int plan_write(struct bcm53314 *sw, int obj, int idx, const u32 *val,
		      u32 pre_ignore, u32 post_ignore, const char *what)
{
	const struct sw_obj *o = &objs[obj];
	struct plan_op *op;
	u32 old[3];
	int err, i;

	err = shadow_get(sw, obj, idx, old);
	if (err)
		return err;
	if (!memcmp(old, val, 4 * o->words))
		return 0;	/* already in place */
	if (sw->nops >= MAX_OPS)
		return -ENOSPC;
	op = &sw->ops[sw->nops++];
	memset(op, 0, sizeof(*op));
	op->obj = obj;
	op->idx = idx;
	op->what = what;
	for (i = 0; i < o->words; i++) {
		op->old[i] = old[i];
		op->val[i] = val[i];
		op->pre_mask[i] = ~0u;
		op->post_mask[i] = ~0u;
	}
	op->pre_mask[0] &= ~pre_ignore;
	op->post_mask[0] &= ~post_ignore;
	if (o->parity) {	/* parity bit of the second word, kept by the hardware */
		op->pre_mask[1] &= ~o->parity;
		op->post_mask[1] &= ~o->parity;
	}
	shadow_set(sw, obj, idx, val);
	return 0;
}

static bool in_isolation(struct bcm53314 *sw, int port)
{
	int i;

	for (i = 0; i < sw->niso; i++)
		if (sw->iso_port[i] == port)
			return true;
	return false;
}

static bool port_managed(struct bcm53314 *sw, int port)
{
	return in_isolation(sw, port) || (sw->mgmt && port == PORT_MGMT);
}

static bool pbm_managed(struct bcm53314 *sw, u32 pbm)
{
	int p;

	for (p = 0; p < NUM_PORTS; p++)
		if ((pbm & BIT(p)) && !port_managed(sw, p))
			return false;
	return true;
}

/*
 * Step trunk2. Group entry: members ge2, ge3 repeated over the eight slots
 * (slot i = member i % 2), module id 0 everywhere, RTAG 6. Block mask entry
 * i: the other member blocked, so that one copy of a flooded frame leaves by
 * ge2 for even hash indexes and by ge3 for odd ones (SDK
 * _bcm_xgs3_trunk_block_mask with two local members).
 */
static void trunk2_group(u32 *w)
{
	int i;

	w[0] = w[1] = w[2] = 0;
	for (i = 0; i < 8; i++)
		ent_set(w, 10 * i, 6, i % 2 ? PORT_TRUNK2 : PORT_TRUNK);
	ent_set(w, 80, 3, TRUNK2_RTAG);
}

static u32 trunk2_nuc_block(int idx)
{
	return idx % 2 ? PBM_TRUNK : PBM_TRUNK2;
}

/* PORT_TAB fields set on MGMT: drop every tagged frame, filter ingress VLAN membership */
#define PT_EN_IFILTER		BIT(3)
#define PT_PORT_DIS_TAG		BIT(14)

/*
 * Write rules, checked on the whole plan before the first write: each
 * object may only change in the way its step needs.
 */
static bool op_allowed(struct bcm53314 *sw, const struct plan_op *op, const char **why)
{
	const u32 *a = op->old, *n = op->val;
	u32 changed = a[0] ^ n[0];

	*why = "object not writable";
	if (op->miim) {
		*why = "MIIM: BMCR 0x0140 -> 0x1340 of the trunk PHY, of the ge3 PHY under step ge3 or of the internal PHY of a port of step ports only";
		if (op->reg != MII_BMCR || a[0] != BMCR_FORCED_1000 || n[0] != BMCR_AUTONEG_RESTART)
			return false;
		return op->phy == TRUNK_PHY || (sw->ge3 && op->phy == TRUNK2_PHY) ||
		       (sw->ports && op->phy >= 0x80 + 5 && op->phy <= 0x80 + PHY_INT_LAST &&
			op->phy != (0x80 | PORT_MGMT) && in_isolation(sw, op->phy & 0x7f));
	}
	switch (op->obj) {
	case O_EGR_CONFIG:
		*why = "EGR_CONFIG: shared VLAN learning fields only, cleared";
		return !(changed & ~(EGR_CONFIG_USE_LEARN_VID | EGR_CONFIG_LEARN_VID)) &&
		       !(n[0] & (EGR_CONFIG_USE_LEARN_VID | EGR_CONFIG_LEARN_VID));
	case O_VLAN_CTRL:
		*why = "VLAN_CTRL: LEARN_VID cleared, USE_LEARN_VID already 0";
		return !(changed & ~VLAN_CTRL_LEARN_VID) && !(n[0] & VLAN_CTRL_LEARN_VID) &&
		       !(a[0] & VLAN_CTRL_USE_LEARN_VID);
	case O_TDBGC0_SELECT ... O_RDBGC1_SELECT: {
		int i;

		*why = "debug counter selection outside the fixed list";
		for (i = 0; i < ARRAY_SIZE(dbg_select); i++)
			if (dbg_select[i].obj == op->obj)
				return n[0] == dbg_select[i].val;
		return false;
	}
	case O_COMMAND_CONFIG:
		*why = "COMMAND_CONFIG: TX/RX enable and soft reset of trunk, ge3 (step ge3), isolated or MGMT ports only";
		return (op->idx == PORT_TRUNK || port_managed(sw, op->idx) ||
			(sw->ge3 && op->idx == PORT_TRUNK2)) &&
		       !(changed & ~(CC_TX_ENA | CC_RX_ENA | CC_SW_RESET | CC_LATE_COL_FIX));
	case O_EPC_LINK_BMAP:
		*why = "EPC_LINK_BMAP: only adding the trunk, ge3 (step ge3) or isolated ports";
		if (changed & a[0])
			return false;
		for (int p = 0; p < NUM_PORTS; p++)
			if ((changed & BIT(p)) && p != PORT_TRUNK && !port_managed(sw, p) &&
			    !(sw->ge3 && p == PORT_TRUNK2))
				return false;
		return true;
	case O_PORT_TAB:
		if (sw->mgmt && op->idx == PORT_MGMT) {
			*why = "PORT_TAB[MGMT]: PORT_VID 20, tagged frames dropped, ingress filter on";
			return !(changed & ~(GENMASK(30, 19) | PT_EN_IFILTER | PT_PORT_DIS_TAG)) &&
			       a[1] == n[1] && a[2] == n[2] && PT_VID(n) == MGMT_VID &&
			       (n[0] & PT_EN_IFILTER) && (n[0] & PT_PORT_DIS_TAG) &&
			       !(n[0] & BIT(15));
		}
		*why = "PORT_TAB: PORT_VID of an isolated front port, ingress filter set under step ifilter";
		return in_isolation(sw, op->idx) &&
		       !(changed & ~(GENMASK(30, 19) | (sw->ifilter ? PT_EN_IFILTER : 0))) &&
		       !((a[0] & PT_EN_IFILTER) && !(n[0] & PT_EN_IFILTER)) &&
		       a[1] == n[1] && a[2] == n[2] &&
		       PT_VID(n) >= VID_MIN && PT_VID(n) <= VID_MAX;
	case O_VLAN_TAB:
		if (op->idx == VID_DEFAULT) {
			*why = "VLAN_TAB[1]: only removing isolated or MGMT front ports";
			return !((a[1] ^ n[1]) & ~objs[O_VLAN_TAB].parity) &&
			       !(changed & ~PBM_FRONT) && !(n[0] & changed) &&
			       pbm_managed(sw, changed);
		}
		if (sw->mgmt && op->idx == MGMT_VID) {
			*why = "VLAN_TAB[20]: {MGMT, trunk}, STG 1, nothing else";
			return VT_VALID(n) && VT_STG(n) == STG_DEFAULT &&
			       VT_PBM(n) == (BIT(PORT_MGMT) | PBM_TRUNK) && !ent_get(n, 32, 11);
		}
		*why = "VLAN_TAB: VID 100-199, {front ports but MGMT, trunk[, ge3 under step trunk2]}, STG 1";
		return op->idx >= VID_MIN && op->idx <= VID_MAX && VT_VALID(n) &&
		       VT_STG(n) == STG_DEFAULT && (VT_PBM(n) & PBM_TRUNK) &&
		       !(VT_PBM(n) & ~(PBM_FRONT | PBM_TRUNK | (sw->trunk2 ? PBM_TRUNK2 : 0))) &&
		       !(VT_PBM(n) & BIT(PORT_MGMT)) &&
		       !ent_get(n, 32, 11);
	case O_EGR_VLAN:
		if (op->idx == VID_DEFAULT) {
			*why = "EGR_VLAN[1]: only removing isolated or MGMT front ports";
			return !((EV_PBM(a) ^ EV_PBM(n)) & ~PBM_FRONT) &&
			       pbm_managed(sw, EV_PBM(a) ^ EV_PBM(n)) &&
			       !((EV_UT(a) ^ EV_UT(n)) & ~PBM_FRONT) &&
			       !(EV_PBM(n) & ~EV_PBM(a)) && !(EV_UT(n) & ~EV_UT(a)) &&
			       ent_get(a, 50, 9) == ent_get(n, 50, 9);
		}
		if (sw->mgmt && op->idx == MGMT_VID) {
			*why = "EGR_VLAN[20]: MGMT untagged, trunk tagged, nothing else";
			return EV_VALID(n) && EV_STG(n) == STG_DEFAULT &&
			       EV_PBM(n) == (BIT(PORT_MGMT) | PBM_TRUNK) &&
			       EV_UT(n) == BIT(PORT_MGMT) && !ent_get(n, 57, 3);
		}
		*why = "EGR_VLAN: VID 100-199, trunk[ and ge3 under step trunk2] tagged, front ports but MGMT untagged";
		return op->idx >= VID_MIN && op->idx <= VID_MAX && EV_VALID(n) &&
		       EV_STG(n) == STG_DEFAULT && (EV_PBM(n) & PBM_TRUNK) &&
		       !(EV_PBM(n) & ~(PBM_FRONT | PBM_TRUNK | (sw->trunk2 ? PBM_TRUNK2 : 0))) &&
		       !(EV_PBM(n) & BIT(PORT_MGMT)) &&
		       EV_UT(n) == (EV_PBM(n) & PBM_FRONT) && !ent_get(n, 57, 3);
	case O_TRUNK_GROUP: {
		u32 g[3];

		trunk2_group(g);
		*why = "TRUNK_GROUP: entry 7 only, from empty to {ge2, ge3} RTAG 6, under step trunk2";
		return sw->trunk2 && op->idx == TRUNK2_TGID && !a[0] && !a[1] && !a[2] &&
		       !memcmp(n, g, sizeof(g));
	}
	case O_TRUNK_BITMAP:
		*why = "TRUNK_BITMAP: entry 7 only, from empty to {ge2, ge3}, under step trunk2";
		return sw->trunk2 && op->idx == TRUNK2_TGID && !a[0] && n[0] == (PBM_TRUNK | PBM_TRUNK2);
	case O_SOURCE_TRUNK_MAP:
		*why = "SOURCE_TRUNK_MAP_TABLE: ge2 and ge3 (module 0) only, from 0 to group 7, under step trunk2";
		return sw->trunk2 && (op->idx == PORT_TRUNK || op->idx == PORT_TRUNK2) && !a[0] &&
		       n[0] == STM_TRUNK2;
	case O_NONUCAST_TRUNK_BLOCK_MASK:
		*why = "NONUCAST_TRUNK_BLOCK_MASK: one of ge2/ge3 added, alternately, nothing else, under step trunk2";
		return sw->trunk2 && !(a[0] & (PBM_TRUNK | PBM_TRUNK2)) &&
		       n[0] == (a[0] | trunk2_nuc_block(op->idx));
	case O_HASH_CONTROL:
		*why = "HASH_CONTROL: flood hash on source and destination added to the reset value, under step trunk2";
		return sw->trunk2 && a[0] == HASH_CONTROL_RESET &&
		       n[0] == (HASH_CONTROL_RESET | HC_NUC_SRC | HC_NUC_DST);
	}
	return false;
}

/* Step "counters": one drop cause per debug counter (all counters count nothing at reset) */
static int plan_counters(struct bcm53314 *sw)
{
	int i, err;

	for (i = 0; i < ARRAY_SIZE(dbg_select); i++) {
		u32 w[3] = { dbg_select[i].val };

		err = plan_write(sw, dbg_select[i].obj, 0, w, 0, 0, "select one drop cause");
		if (err)
			return err;
	}
	return 0;
}

/*
 * Step "learning": independent VLAN learning on both pipelines. At reset
 * the egress pipeline works in shared learning mode on VID 1; the boot
 * firmware turns it off on ingress only. Leaving it on makes the egress
 * side process every frame as if it belonged to VID 1.
 */
static int plan_learning(struct bcm53314 *sw)
{
	u32 w[3];
	int err;

	err = shadow_get(sw, O_EGR_CONFIG, 0, w);
	if (err)
		return err;
	w[0] &= ~(EGR_CONFIG_USE_LEARN_VID | EGR_CONFIG_LEARN_VID);
	err = plan_write(sw, O_EGR_CONFIG, 0, w, 0, 0, "egress: independent VLAN learning");
	if (err)
		return err;
	err = shadow_get(sw, O_VLAN_CTRL, 0, w);
	if (err)
		return err;
	if (w[0] & VLAN_CTRL_USE_LEARN_VID)
		return -EINVAL;	/* not the state left by the boot firmware */
	w[0] &= ~VLAN_CTRL_LEARN_VID;
	return plan_write(sw, O_VLAN_CTRL, 0, w, 0, 0, "ingress: learning VID 0");
}

/*
 * MAC enable of one port, UniMAC sequence (SDK mac_uni_enable_set): soft
 * reset, enable TX and RX, add the port to the link bitmap used for
 * forwarding (ING_MISC_CONFIG.USE_EPC_LINK_BMP is set by the boot
 * firmware), soft reset pulse.
 */
static int plan_port_on(struct bcm53314 *sw, int p)
{
	u32 cc[3], epc[3], w[3] = { 0 }, c, rw;
	int err;

	err = shadow_get(sw, O_COMMAND_CONFIG, p, cc);
	if (!err)
		err = shadow_get(sw, O_EPC_LINK_BMAP, 0, epc);
	if (err)
		return err;
	c = cc[0];
	rw = CC_LATE_COL_FIX | CC_TX_ENA | CC_RX_ENA;	/* not reliable while in reset */
	if ((c & CC_TX_ENA) && (c & CC_RX_ENA) && !(c & CC_SW_RESET)) {
		if (epc[0] & BIT(p))
			return 0;
		w[0] = epc[0] | BIT(p);
		return plan_write(sw, O_EPC_LINK_BMAP, 0, w, 0, 0, "port forwards");
	}
	c |= CC_SW_RESET;
	w[0] = c;
	err = plan_write(sw, O_COMMAND_CONFIG, p, w, CC_LATE_COL_FIX, rw, "MAC soft reset");
	c &= ~(CC_TX_ENA | CC_RX_ENA);
	w[0] = c;
	if (!err)
		err = plan_write(sw, O_COMMAND_CONFIG, p, w, rw, rw, "MAC disabled in reset");
	c &= ~CC_SW_RESET;
	w[0] = c;
	if (!err)
		err = plan_write(sw, O_COMMAND_CONFIG, p, w, rw, rw, "MAC out of reset");
	c |= CC_TX_ENA | CC_RX_ENA;
	w[0] = c;
	if (!err)
		err = plan_write(sw, O_COMMAND_CONFIG, p, w, rw, CC_LATE_COL_FIX, "MAC TX and RX enabled");
	if (!err && !(epc[0] & BIT(p))) {
		u32 e[3] = { epc[0] | BIT(p) };

		err = plan_write(sw, O_EPC_LINK_BMAP, 0, e, 0, 0, "port forwards");
	}
	w[0] = c | CC_SW_RESET;
	if (!err)
		err = plan_write(sw, O_COMMAND_CONFIG, p, w, CC_LATE_COL_FIX, rw, "MAC soft reset pulse");
	w[0] = c;
	if (!err)
		err = plan_write(sw, O_COMMAND_CONFIG, p, w, rw, CC_LATE_COL_FIX, "MAC soft reset released");
	return err;
}

static int plan_check_globals(struct bcm53314 *sw)
{
	u32 w[3];
	int err;

	err = shadow_get(sw, O_ING_CONFIG, 0, w);
	if (err)
		return err;
	if (w[0] & BIT(0))	/* DT_MODE: double tagging on */
		return -EINVAL;
	err = shadow_get(sw, O_ING_OUTER_TPID_0, 0, w);
	if (err)
		return err;
	if ((w[0] & 0xffff) != ETH_P_8021Q)
		return -EINVAL;
	err = shadow_get(sw, O_EGR_OUTER_TPID_0, 0, w);
	if (err)
		return err;
	return (w[0] & 0xffff) == ETH_P_8021Q ? 0 : -EINVAL;
}

/* Spanning-tree group 1 forwarding (state 3) on ingress and egress for each port of pbm */
static int plan_check_stg(struct bcm53314 *sw, u32 pbm)
{
	u32 in[3], eg[3];
	int err, p;

	err = shadow_get(sw, O_STG_TAB, STG_DEFAULT, in);
	if (!err)
		err = shadow_get(sw, O_EGR_VLAN_STG, STG_DEFAULT, eg);
	if (err)
		return err;
	for (p = 0; p < NUM_PORTS; p++)
		if ((pbm & BIT(p)) && (ent_get(in, 2 * p, 2) != 3 || ent_get(eg, 2 * p, 2) != 3))
			return -EINVAL;
	return 0;
}

/* MII control 0x0140 -> 0x1340 of a PHY, value read now (forced 1000 Mb/s left by the set-up) */
static int plan_phy_an(struct bcm53314 *sw, u8 phy, const char *what)
{
	struct plan_op *op;
	u16 bmcr;
	int err;

	err = miim_op(sw, false, phy, MII_BMCR, &bmcr);
	if (err)
		return err;
	if (bmcr & BMCR_ANENABLE)
		return 0;	/* already auto-negotiating */
	if (bmcr != BMCR_FORCED_1000)
		return -EINVAL;	/* not the state left by the set-up */
	if (sw->nops >= MAX_OPS)
		return -ENOSPC;
	op = &sw->ops[sw->nops++];
	memset(op, 0, sizeof(*op));
	op->miim = true;
	op->phy = phy;
	op->reg = MII_BMCR;
	op->old[0] = bmcr;
	op->val[0] = BMCR_AUTONEG_RESTART;
	op->what = what;
	return 0;
}

/* Step "trunk": optional PHY auto-negotiation, then MAC enable of ge2 */
static int plan_trunk(struct bcm53314 *sw)
{
	u32 w[3];
	int err;

	err = plan_check_globals(sw);
	if (!err)
		err = plan_check_stg(sw, PBM_TRUNK);
	if (!err)
		err = shadow_get(sw, O_PORT_TAB, PORT_TRUNK, w);
	if (err)
		return err;
	/* PORT_VID 1, outer TPID 0 recognised, tagged frames accepted */
	if (PT_VID(w) != VID_DEFAULT || !(ent_get(w, 50, 4) & 1) || ent_get(w, 14, 1))
		return -EINVAL;
	err = shadow_get(sw, O_FRM_LENGTH, PORT_TRUNK, w);
	if (err)
		return err;
	if ((w[0] & 0x3fff) < ETH_FRAME_LEN + ETH_FCS_LEN + VLAN_HLEN)
		return -EINVAL;
	if (trunk_autoneg) {
		err = plan_phy_an(sw, TRUNK_PHY, "trunk PHY: auto-negotiation enabled and restarted");
		if (err)
			return err;
	}
	return plan_port_on(sw, PORT_TRUNK);
}

/* Step "isolate": one VLAN per listed front port, shared with the trunk only */
static int plan_isolate(struct bcm53314 *sw)
{
	u32 pt[3], vt[3], ev[3], w[3], cc[3], epc[3];
	int i, err;

	err = plan_check_globals(sw);
	if (err)
		return err;
	err = shadow_get(sw, O_COMMAND_CONFIG, PORT_TRUNK, cc);
	if (!err)
		err = shadow_get(sw, O_EPC_LINK_BMAP, 0, epc);
	if (err)
		return err;
	if (!(cc[0] & CC_TX_ENA) || !(cc[0] & CC_RX_ENA) || (cc[0] & CC_SW_RESET) ||
	    !(epc[0] & PBM_TRUNK))
		return -EINVAL;		/* step trunk first */

	for (i = 0; i < sw->niso; i++) {
		int p = sw->iso_port[i], vid = sw->iso_vid[i], v0, q;
		u32 mask;

		err = plan_check_stg(sw, BIT(p) | PBM_TRUNK);
		if (!err)
			err = shadow_get(sw, O_ING_EGRMSKBMAP, p, w);
		if (err)
			return err;
		if (w[0] & PBM_TRUNK)
			return -EINVAL;	/* flooding towards the trunk blocked */
		err = shadow_get(sw, O_ING_EGRMSKBMAP, PORT_TRUNK, w);
		if (err)
			return err;
		if (w[0] & BIT(p))
			return -EINVAL;
		err = shadow_get(sw, O_PORT_TAB, p, pt);
		if (!err)
			err = shadow_get(sw, O_VLAN_TAB, vid, vt);
		if (!err)
			err = shadow_get(sw, O_EGR_VLAN, vid, ev);
		if (err)
			return err;
		v0 = PT_VID(pt);
		if (ent_get(pt, 15, 1) || (v0 != VID_DEFAULT && v0 != vid))
			return -EINVAL;
		/*
		 * The VID must be free, or already exactly ours; under step
		 * trunk2, ours may already hold ge3 (tagged), which is kept.
		 */
		mask = BIT(p) | PBM_TRUNK;
		if (sw->trunk2 && (VT_PBM(vt) & PBM_TRUNK2))
			mask |= PBM_TRUNK2;
		if ((vt[0] || (vt[1] & ~objs[O_VLAN_TAB].parity)) &&
		    !(VT_PBM(vt) == mask && VT_VALID(vt) && VT_STG(vt) == STG_DEFAULT))
			return -EBUSY;
		if ((ev[0] || (ev[1] & ~objs[O_EGR_VLAN].parity)) &&
		    !(EV_PBM(ev) == mask && EV_UT(ev) == BIT(p) && EV_VALID(ev) &&
		      EV_STG(ev) == STG_DEFAULT))
			return -EBUSY;
		for (q = 0; q < i; q++)
			if (sw->iso_vid[q] == vid)
				return -EINVAL;

		err = plan_port_on(sw, p);
		if (err)
			return err;
		vlan_tab_build(w, mask);
		err = plan_write(sw, O_VLAN_TAB, vid, w, 0, 0, "VLAN: front port + trunk");
		if (err)
			return err;
		egr_vlan_build(w, mask, BIT(p));
		err = plan_write(sw, O_EGR_VLAN, vid, w, 0, 0,
				 "egress VLAN: front port untagged, trunk tagged");
		if (err)
			return err;
		if (v0 == vid)
			continue;
		memcpy(w, pt, sizeof(w));
		ent_set(w, 19, 12, vid);
		err = plan_write(sw, O_PORT_TAB, p, w, 0, 0, "port VID");
		if (err)
			return err;
		/* only then leave VID 1, so that the port always has a VLAN */
		err = shadow_get(sw, O_VLAN_TAB, VID_DEFAULT, w);
		if (err)
			return err;
		ent_set(w, 0, 25, VT_PBM(w) & ~BIT(p));
		err = plan_write(sw, O_VLAN_TAB, VID_DEFAULT, w, 0, 0, "VID 1 without the port");
		if (err)
			return err;
		err = shadow_get(sw, O_EGR_VLAN, VID_DEFAULT, w);
		if (err)
			return err;
		ent_set(w, 0, 25, EV_UT(w) & ~BIT(p));
		ent_set(w, 25, 25, EV_PBM(w) & ~BIT(p));
		err = plan_write(sw, O_EGR_VLAN, VID_DEFAULT, w, 0, 0, "egress VID 1 without the port");
		if (err)
			return err;
	}
	return 0;
}

/*
 * Step "ports": every front port but MGMT in its own VLAN (plan of step
 * "isolate" on front_ports[]), then auto-negotiation on the internal PHYs
 * of these ports.
 */
static int plan_ports(struct bcm53314 *sw)
{
	int i, err;

	err = plan_isolate(sw);
	for (i = 0; !err && i < sw->niso; i++)
		if (sw->iso_port[i] <= PHY_INT_LAST)
			err = plan_phy_an(sw, 0x80 | sw->iso_port[i],
					  "front port PHY: auto-negotiation enabled and restarted");
	return err;
}

/*
 * Step "ifilter": ingress VLAN membership filter on every port of step
 * "ports", once the port has its own VLAN. Each VLAN 100-199 of the step
 * holds only its port and the trunk, VID 1 no longer holds the port: a
 * frame tagged with any VID but the port VID (or 0) is then dropped on
 * ingress instead of entering that VLAN (SDK: ingress VLAN membership of a
 * port = PORT_TAB.EN_IFILTER on this family).
 */
static int plan_ifilter(struct bcm53314 *sw)
{
	u32 pt[3], vt[3], w[3];
	int i, err;

	if (!sw->ports)
		return -EINVAL;
	for (i = 0; i < sw->niso; i++) {
		int p = sw->iso_port[i], vid = sw->iso_vid[i];

		err = shadow_get(sw, O_PORT_TAB, p, pt);
		if (!err)
			err = shadow_get(sw, O_VLAN_TAB, vid, vt);
		if (!err)
			err = shadow_get(sw, O_VLAN_TAB, VID_DEFAULT, w);
		if (err)
			return err;
		/* the state step "ports" leaves (planned in this load or found) */
		if (PT_VID(pt) != vid || (pt[0] & (PT_PORT_DIS_TAG | BIT(15))) ||
		    (VT_PBM(vt) & ~(sw->trunk2 ? PBM_TRUNK2 : 0)) != (BIT(p) | PBM_TRUNK) ||
		    !VT_VALID(vt) || (VT_PBM(w) & BIT(p)))
			return -EINVAL;
		if (pt[0] & PT_EN_IFILTER)
			continue;
		w[0] = pt[0] | PT_EN_IFILTER;
		w[1] = pt[1];
		w[2] = pt[2];
		err = plan_write(sw, O_PORT_TAB, p, w, 0, 0, "ingress VLAN membership filter");
		if (err)
			return err;
	}
	return 0;
}

/*
 * Steps ge3 and trunk2, common checks: ge2 up (step trunk) and forwarding,
 * ge3 set up as ge2 on ingress and egress, module id 0 (the source trunk
 * map is indexed by module id << 5 | port), no flooding mask on ge3 nor
 * towards it from ge2 or a port of step ports.
 */
static int plan_check_ge3(struct bcm53314 *sw)
{
	u32 w[3], x[3], cc[3], epc[3];
	int i, err;

	if (!sw->ports || sw->mgmt)
		return -EINVAL;
	err = plan_check_globals(sw);
	if (!err)
		err = shadow_get(sw, O_COMMAND_CONFIG, PORT_TRUNK, cc);
	if (!err)
		err = shadow_get(sw, O_EPC_LINK_BMAP, 0, epc);
	if (err)
		return err;
	if (!(cc[0] & CC_TX_ENA) || !(cc[0] & CC_RX_ENA) || (cc[0] & CC_SW_RESET) ||
	    !(epc[0] & PBM_TRUNK))
		return -EINVAL;		/* step trunk first */
	err = plan_check_stg(sw, PBM_TRUNK | PBM_TRUNK2);
	if (err)
		return err;
	err = shadow_get(sw, O_PORT_TAB, PORT_TRUNK, w);
	if (!err)
		err = shadow_get(sw, O_PORT_TAB, PORT_TRUNK2, x);
	if (err)
		return err;
	if (memcmp(w, x, sizeof(w)) || ent_get(w, 32 + 2, 4))
		return -EINVAL;
	err = shadow_get(sw, O_FRM_LENGTH, PORT_TRUNK, w);
	if (!err)
		err = shadow_get(sw, O_FRM_LENGTH, PORT_TRUNK2, x);
	if (err)
		return err;
	if ((w[0] ^ x[0]) & 0x3fff)
		return -EINVAL;
	err = sw_read(sw, O_EGR_PORT, PORT_TRUNK, w);
	if (!err)
		err = sw_read(sw, O_EGR_PORT, PORT_TRUNK2, x);
	if (err)
		return err;
	if (w[0] != x[0])
		return -EINVAL;
	err = sw_read(sw, O_EGR_VLAN_CONTROL_1, PORT_TRUNK, w);
	if (!err)
		err = sw_read(sw, O_EGR_VLAN_CONTROL_1, PORT_TRUNK2, x);
	if (err)
		return err;
	if (w[0] != x[0])
		return -EINVAL;
	err = shadow_get(sw, O_ING_EGRMSKBMAP, PORT_TRUNK2, w);
	if (err)
		return err;
	if (w[0] & (PBM_TRUNK | PBM_FRONT))
		return -EINVAL;
	err = shadow_get(sw, O_ING_EGRMSKBMAP, PORT_TRUNK, w);
	if (err)
		return err;
	if (w[0] & PBM_TRUNK2)
		return -EINVAL;
	for (i = 0; i < sw->niso; i++) {
		err = shadow_get(sw, O_ING_EGRMSKBMAP, sw->iso_port[i], w);
		if (err)
			return err;
		if (w[0] & PBM_TRUNK2)
			return -EINVAL;
	}
	return 0;
}

/*
 * Step ge3 (with step "ports", after it and after "ifilter"): ge3 PHY
 * auto-negotiation, then MAC enable and link bitmap. ge3 stays in VID 1
 * only (untagged, as every port after the set-up): it carries nothing of
 * the VLANs of step "ports" until step trunk2.
 */
static int plan_ge3(struct bcm53314 *sw)
{
	int err = plan_check_ge3(sw);

	if (!err)
		err = plan_phy_an(sw, TRUNK2_PHY, "ge3 PHY: auto-negotiation enabled and restarted");
	if (!err)
		err = plan_port_on(sw, PORT_TRUNK2);
	return err;
}

/*
 * Step trunk2: ge3 joins ge2 in trunk group 7, in a load after step ge3 has
 * run and the ge3 PHY has found its link (refused otherwise: a member
 * without link would lose what the group hashes to it). Every check below
 * is made before the first write. Order of the writes:
 *  1. group entry and trunk bitmap (unused while no source maps to them);
 *  2. ge3 tagged in each VLAN of step "ports";
 *  3. non-unicast block mask: one copy of a flooded frame per group;
 *  4. flood hash on source and destination;
 *  5. last, the source trunk map of ge2 and ge3: from then on, frames of the
 *     host are learnt on the group and unicast towards it is hashed.
 */
static int plan_trunk2(struct bcm53314 *sw)
{
	u32 w[3], x[3], g[3], cc[3], epc[3];
	u16 bmcr, bmsr;
	int i, err;

	err = plan_check_ge3(sw);
	if (err)
		return err;
	/* ge3 up, forwarding, PHY auto-negotiated with its link up (latched bit: read twice) */
	err = shadow_get(sw, O_COMMAND_CONFIG, PORT_TRUNK2, cc);
	if (!err)
		err = shadow_get(sw, O_EPC_LINK_BMAP, 0, epc);
	if (!err)
		err = miim_op(sw, false, TRUNK2_PHY, MII_BMCR, &bmcr);
	if (!err)
		err = miim_op(sw, false, TRUNK2_PHY, MII_BMSR, &bmsr);
	if (!err)
		err = miim_op(sw, false, TRUNK2_PHY, MII_BMSR, &bmsr);
	if (err)
		return err;
	if (!(cc[0] & CC_TX_ENA) || !(cc[0] & CC_RX_ENA) || (cc[0] & CC_SW_RESET) ||
	    !(epc[0] & PBM_TRUNK2) || !(bmcr & BMCR_ANENABLE) || !(bmsr & BMSR_LSTATUS))
		return -ENOLINK;	/* step ge3 first, in a previous load, and a link */

	/* no other trunk group anywhere; group 7 empty or exactly ours */
	trunk2_group(g);
	for (i = 0; i <= objs[O_TRUNK_BITMAP].max; i++) {
		err = shadow_get(sw, O_TRUNK_BITMAP, i, w);
		if (err)
			return err;
		if (w[0] && !(i == TRUNK2_TGID && w[0] == (PBM_TRUNK | PBM_TRUNK2)))
			return -EBUSY;
	}
	err = shadow_get(sw, O_TRUNK_GROUP, TRUNK2_TGID, w);
	if (err)
		return err;
	if ((w[0] || w[1] || w[2]) && memcmp(w, g, sizeof(g)))
		return -EBUSY;
	/* no port of this module mapped to a trunk, but ge2/ge3 to ours */
	for (i = 0; i < NUM_PORTS; i++) {
		err = shadow_get(sw, O_SOURCE_TRUNK_MAP, i, w);
		if (err)
			return err;
		if (w[0] && !((i == PORT_TRUNK || i == PORT_TRUNK2) && w[0] == STM_TRUNK2))
			return -EBUSY;
	}
	for (i = 0; i < NUM_NUC; i++) {
		err = shadow_get(sw, O_NONUCAST_TRUNK_BLOCK_MASK, i, w);
		if (err)
			return err;
		if ((w[0] & (PBM_TRUNK | PBM_TRUNK2)) &&
		    (w[0] & (PBM_TRUNK | PBM_TRUNK2)) != trunk2_nuc_block(i))
			return -EBUSY;
	}
	err = shadow_get(sw, O_HASH_CONTROL, 0, w);
	if (err)
		return err;
	if (w[0] != HASH_CONTROL_RESET && w[0] != (HASH_CONTROL_RESET | HC_NUC_SRC | HC_NUC_DST))
		return -EINVAL;
	/* each VLAN of step ports: {port, ge2} or {port, ge2, ge3}, ge3 tagged */
	for (i = 0; i < sw->niso; i++) {
		int p = sw->iso_port[i], vid = sw->iso_vid[i];
		u32 m = BIT(p) | PBM_TRUNK;

		err = shadow_get(sw, O_VLAN_TAB, vid, w);
		if (!err)
			err = shadow_get(sw, O_EGR_VLAN, vid, x);
		if (err)
			return err;
		if ((VT_PBM(w) != m && VT_PBM(w) != (m | PBM_TRUNK2)) || EV_PBM(x) != VT_PBM(w) ||
		    EV_UT(x) != BIT(p))
			return -EINVAL;
	}

	/* 1. group entry and trunk bitmap */
	err = plan_write(sw, O_TRUNK_GROUP, TRUNK2_TGID, g, 0, 0, "group 7: ge2, ge3, hash on IP source + destination");
	if (err)
		return err;
	w[0] = PBM_TRUNK | PBM_TRUNK2;
	w[1] = w[2] = 0;
	err = plan_write(sw, O_TRUNK_BITMAP, TRUNK2_TGID, w, 0, 0, "group 7 members");
	if (err)
		return err;
	/* 2. ge3 tagged in the VLANs of step ports */
	for (i = 0; i < sw->niso; i++) {
		u32 m = BIT(sw->iso_port[i]) | PBM_TRUNK | PBM_TRUNK2;

		vlan_tab_build(w, m);
		err = plan_write(sw, O_VLAN_TAB, sw->iso_vid[i], w, 0, 0, "VLAN: + ge3");
		if (err)
			return err;
		egr_vlan_build(w, m, BIT(sw->iso_port[i]));
		err = plan_write(sw, O_EGR_VLAN, sw->iso_vid[i], w, 0, 0, "egress VLAN: + ge3 tagged");
		if (err)
			return err;
	}
	/* 3. non-unicast block mask */
	for (i = 0; i < NUM_NUC; i++) {
		err = shadow_get(sw, O_NONUCAST_TRUNK_BLOCK_MASK, i, w);
		if (err)
			return err;
		w[0] |= trunk2_nuc_block(i);
		err = plan_write(sw, O_NONUCAST_TRUNK_BLOCK_MASK, i, w, 0, 0,
				 i % 2 ? "flood copy by ge3" : "flood copy by ge2");
		if (err)
			return err;
	}
	/* 4. flood hash */
	err = shadow_get(sw, O_HASH_CONTROL, 0, w);
	if (err)
		return err;
	w[0] |= HC_NUC_SRC | HC_NUC_DST;
	err = plan_write(sw, O_HASH_CONTROL, 0, w, 0, 0, "flood hash on source and destination");
	if (err)
		return err;
	/* 5. source trunk map, last */
	w[0] = STM_TRUNK2;
	err = plan_write(sw, O_SOURCE_TRUNK_MAP, PORT_TRUNK, w, 0, 0, "ge2 member of group 7");
	if (!err)
		err = plan_write(sw, O_SOURCE_TRUNK_MAP, PORT_TRUNK2, w, 0, 0, "ge3 member of group 7");
	return err;
}

/*
 * Step "mgmt": the MGMT port joins the trunk in VID 20, untagged on MGMT and
 * tagged on the trunk, so that the host reaches the network behind MGMT
 * through the switch. That network may also carry tagged traffic of other
 * VLANs on the same cable. Guarantees, all checked before the first write:
 *  - MGMT never transmits a tagged frame: egress VLAN filtering already on
 *    for MGMT, no egress VLAN translation, no double tagging, no mirroring
 *    on any port, and no VLAN entry other than VID
 *    1 (MGMT removed from it) and VID 20 (MGMT untagged) holds the port
 *    (all 4096 entries read);
 *  - nothing tagged received on MGMT is switched anywhere: tagged frames are
 *    dropped on ingress, VLAN membership is filtered on ingress, no
 *    protocol-based VLAN entry exists;
 *  - MGMT receives only once all this is in place (MAC enabled last).
 */
static int plan_mgmt(struct bcm53314 *sw)
{
	const u32 mask = BIT(PORT_MGMT) | PBM_TRUNK;
	u32 w[3], pt[3], vt[3], ev[3], cc[3], epc[3];
	u16 bmsr;
	int err, vid;

	err = plan_check_globals(sw);
	if (!err)
		err = shadow_get(sw, O_COMMAND_CONFIG, PORT_TRUNK, cc);
	if (!err)
		err = shadow_get(sw, O_EPC_LINK_BMAP, 0, epc);
	if (err)
		return err;
	if (!(cc[0] & CC_TX_ENA) || !(cc[0] & CC_RX_ENA) || (cc[0] & CC_SW_RESET) ||
	    !(epc[0] & PBM_TRUNK))
		return -EINVAL;		/* step trunk first */
	/*
	 * With step ports: every front port of the list filters VLAN membership
	 * on ingress (step ifilter planned before), keeps its own VID and stays
	 * out of VID 20, so that no frame received on a front port, tagged with
	 * VID 20 or not, may reach MGMT.
	 */
	if (sw->ports) {
		int i;

		if (!sw->ifilter)
			return -EINVAL;
		for (i = 0; i < sw->niso; i++) {
			err = shadow_get(sw, O_PORT_TAB, sw->iso_port[i], pt);
			if (err)
				return err;
			if (!(pt[0] & PT_EN_IFILTER) || PT_VID(pt) == MGMT_VID)
				return -EINVAL;
		}
	}
	err = plan_check_stg(sw, mask);
	if (err)
		return err;

	/* egress side of MGMT: VLAN filter on, plain port, no translation */
	err = sw_read(sw, O_EGR_PORT, PORT_MGMT, w);
	if (err)
		return err;
	if ((w[0] & 0xf) != BIT(2))	/* EN_EFILTER 1, NNI/HiGig 0, PRESERVE_CPU_TAG 0 */
		return -EINVAL;
	err = shadow_get(sw, O_EGR_CONFIG, 0, w);
	if (err)
		return err;
	if (w[0] & BIT(0))		/* egress double tagging */
		return -EINVAL;
	/* no mirroring anywhere: a mirrored copy is not subject to the VLAN tables */
	for (vid = 0; vid < NUM_PORTS; vid++) {
		err = sw_read(sw, O_MIRROR_CONTROL, vid, w);
		if (!err && (w[0] & BIT(0)))
			err = -EBUSY;
		if (!err)
			err = sw_read(sw, O_EMIRROR_CONTROL, vid, w);
		if (!err && (w[0] & GENMASK(24, 0)))
			err = -EBUSY;
		if (err)
			return err;
	}
	err = sw_read(sw, O_EGR_VLAN_CONTROL_1, PORT_MGMT, w);
	if (err)
		return err;
	if (w[0] & (BIT(0) | BIT(11)))	/* VT_ENABLE, REMOVE_INNER_TAG */
		return -EINVAL;
	/* ingress side: no flooding mask towards/from the trunk, plain port */
	err = shadow_get(sw, O_ING_EGRMSKBMAP, PORT_MGMT, w);
	if (err)
		return err;
	if (w[0] & PBM_TRUNK)
		return -EINVAL;
	err = shadow_get(sw, O_ING_EGRMSKBMAP, PORT_TRUNK, w);
	if (err)
		return err;
	if (w[0] & BIT(PORT_MGMT))
		return -EINVAL;
	err = shadow_get(sw, O_PORT_TAB, PORT_MGMT, pt);
	if (err)
		return err;
	if ((PT_VID(pt) != VID_DEFAULT && PT_VID(pt) != MGMT_VID) || ent_get(pt, 15, 1) ||
	    ent_get(pt, 17, 2) || ent_get(pt, 31, 2) || ent_get(pt, 57, 2))
		return -EINVAL;		/* untag drop, MAC/subnet VID, HiGig/NNI, translation */
	for (vid = 0; vid <= objs[O_VLAN_PROTOCOL].max; vid++) {
		err = sw_read(sw, O_VLAN_PROTOCOL, vid, w);
		if (err)
			return err;
		if (w[0])
			return -EBUSY;
	}
	/* every VLAN: MGMT only in VID 1 and VID 20, untagged wherever it is */
	for (vid = 0; vid <= objs[O_VLAN_TAB].max; vid++) {
		bool in_vt, in_ev;

		err = sw_read(sw, O_VLAN_TAB, vid, vt);
		if (!err)
			err = sw_read(sw, O_EGR_VLAN, vid, ev);
		if (err)
			return err;
		in_vt = VT_PBM(vt) & BIT(PORT_MGMT);
		in_ev = (EV_PBM(ev) | EV_UT(ev)) & BIT(PORT_MGMT);
		if (vid == VID_DEFAULT) {
			if (in_ev && !(EV_UT(ev) & BIT(PORT_MGMT)))
				return -EBUSY;
			continue;
		}
		if (vid == MGMT_VID) {
			bool empty = !vt[0] && !(vt[1] & ~objs[O_VLAN_TAB].parity) &&
				     !ev[0] && !(ev[1] & ~objs[O_EGR_VLAN].parity);
			bool ours = VT_PBM(vt) == mask && VT_VALID(vt) &&
				    VT_STG(vt) == STG_DEFAULT && EV_PBM(ev) == mask &&
				    EV_UT(ev) == BIT(PORT_MGMT) && EV_VALID(ev) &&
				    EV_STG(ev) == STG_DEFAULT && !ent_get(ev, 57, 2);

			if (!empty && !ours)
				return -EBUSY;
			continue;
		}
		if (in_vt || in_ev)
			return -EBUSY;
	}
	/* link of the MGMT PHY (latched bit: read twice) */
	err = miim_op(sw, false, 0x80 | PORT_MGMT, MII_BMSR, &bmsr);
	if (!err)
		err = miim_op(sw, false, 0x80 | PORT_MGMT, MII_BMSR, &bmsr);
	if (err)
		return err;
	if (!(bmsr & BMSR_LSTATUS)) {
		if (!mgmt_link_optional)
			return -ENOLINK;
		dev_info(&sw->pdev->dev, "mgmt: no link on MGMT (MII status 0x%04x), planned all the same\n",
			 bmsr);
	}

	vlan_tab_build(w, mask);
	err = plan_write(sw, O_VLAN_TAB, MGMT_VID, w, 0, 0, "VLAN 20: MGMT + trunk");
	if (err)
		return err;
	egr_vlan_build(w, mask, BIT(PORT_MGMT));
	err = plan_write(sw, O_EGR_VLAN, MGMT_VID, w, 0, 0,
			 "egress VLAN 20: MGMT untagged, trunk tagged");
	if (err)
		return err;
	memcpy(w, pt, sizeof(w));
	ent_set(w, 19, 12, MGMT_VID);
	w[0] |= PT_EN_IFILTER | PT_PORT_DIS_TAG;
	err = plan_write(sw, O_PORT_TAB, PORT_MGMT, w, 0, 0,
			 "MGMT: VID 20, tagged frames dropped, ingress VLAN filter");
	if (err)
		return err;
	err = shadow_get(sw, O_VLAN_TAB, VID_DEFAULT, w);
	if (err)
		return err;
	ent_set(w, 0, 25, VT_PBM(w) & ~BIT(PORT_MGMT));
	err = plan_write(sw, O_VLAN_TAB, VID_DEFAULT, w, 0, 0, "VID 1 without MGMT");
	if (err)
		return err;
	err = shadow_get(sw, O_EGR_VLAN, VID_DEFAULT, w);
	if (err)
		return err;
	ent_set(w, 0, 25, EV_UT(w) & ~BIT(PORT_MGMT));
	ent_set(w, 25, 25, EV_PBM(w) & ~BIT(PORT_MGMT));
	err = plan_write(sw, O_EGR_VLAN, VID_DEFAULT, w, 0, 0, "egress VID 1 without MGMT");
	if (err)
		return err;
	return plan_port_on(sw, PORT_MGMT);
}

static void op_log(struct bcm53314 *sw, const char *tag, int i, const struct plan_op *op)
{
	if (op->miim) {
		dev_info(&sw->pdev->dev, "%s %d/%d MIIM phy 0x%02x reg %u: 0x%04x -> 0x%04x (%s)\n",
			 tag, i + 1, sw->nops, op->phy, op->reg, op->old[0], op->val[0], op->what);
		return;
	}
	dev_info(&sw->pdev->dev, "%s %d/%d %s[%d] addr 0x%08x: %08x %08x %08x -> %08x %08x %08x (%s)\n",
		 tag, i + 1, sw->nops, objs[op->obj].name, op->idx,
		 obj_addr(&objs[op->obj], op->idx), op->old[0], op->old[1], op->old[2],
		 op->val[0], op->val[1], op->val[2], op->what);
}

static bool masked_equal(const u32 *x, const u32 *y, const u32 *m, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if ((x[i] ^ y[i]) & m[i])
			return false;
	return true;
}

static int plan_execute(struct bcm53314 *sw)
{
	const char *why;
	int i, err;

	for (i = 0; i < sw->nops; i++)
		if (!op_allowed(sw, &sw->ops[i], &why)) {
			op_log(sw, "REFUSED", i, &sw->ops[i]);
			dev_err(&sw->pdev->dev, "plan refused (%s): nothing written\n", why);
			return -EPERM;
		}
	for (i = 0; i < sw->nops; i++)
		op_log(sw, "PLAN", i, &sw->ops[i]);
	if (!sw->nops) {
		dev_info(&sw->pdev->dev, "nothing to write\n");
		return 0;
	}
	if (dry_run || access < 2) {
		dev_info(&sw->pdev->dev, "dry run: %d write(s) planned, none done\n", sw->nops);
		return 0;
	}

	for (i = 0; i < sw->nops; i++) {
		struct plan_op *op = &sw->ops[i];
		int words = op->miim ? 1 : objs[op->obj].words;
		u32 cur[3], rb[3];

		if (op->miim) {
			u16 v, nv = op->val[0];

			err = miim_op(sw, false, op->phy, op->reg, &v);
			if (!err && v != op->old[0])
				err = -ESTALE;
			if (!err)
				err = miim_op(sw, true, op->phy, op->reg, &nv);
			if (!err)
				err = miim_op(sw, false, op->phy, op->reg, &v);
			/* the restart bit clears itself */
			if (!err && (v & ~BMCR_ANRESTART) != (op->val[0] & ~BMCR_ANRESTART))
				err = -EIO;
			if (err) {
				dev_err(&sw->pdev->dev, "step %d: MIIM check failed (%d), halting\n",
					i + 1, err);
				sw->halted = true;
				return err;
			}
			sw->nwritten++;
			continue;
		}
		err = sw_read(sw, op->obj, op->idx, cur);
		if (err)
			return err;
		if (!masked_equal(cur, op->old, op->pre_mask, words)) {
			dev_err(&sw->pdev->dev, "step %d: %s[%d] is %08x, expected %08x, halting\n",
				i + 1, objs[op->obj].name, op->idx, cur[0], op->old[0]);
			sw->halted = true;
			return -ESTALE;
		}
		err = schan_op(sw, true, op->obj, op->idx, op->val);
		if (err)
			return err;
		udelay(10);
		err = sw_read(sw, op->obj, op->idx, rb);
		if (err)
			return err;
		sw->nwritten++;
		if (!masked_equal(rb, op->val, op->post_mask, words)) {
			dev_err(&sw->pdev->dev, "step %d: %s[%d] read back %08x %08x, wrote %08x %08x, halting\n",
				i + 1, objs[op->obj].name, op->idx, rb[0], rb[1], op->val[0], op->val[1]);
			sw->halted = true;
			return -EIO;
		}
		if (op->delay_us)
			fsleep(op->delay_us);
	}
	dev_info(&sw->pdev->dev, "%d write(s) done and read back\n", sw->nwritten);
	return 0;
}

/* ---------------------------------------------------------------------- */
/* Step "init": the switch set up from its power-on reset                  */
/*
 * Addresses: full S-channel addresses (block in bits 23:20); per-port
 * registers of the IPIPE/EPIPE/MMU blocks take the port in bits 19:12,
 * those of a GPORT block take the rank of the port in its block.
 */
#define A_ING_HW_RESET_CONTROL_1	0x00780001
#define A_ING_HW_RESET_CONTROL_2	0x00780002	/* RESET_ALL 16, VALID 17, DONE 18 */
#define A_EGR_HW_RESET_CONTROL_0	0x00980000
#define A_EGR_HW_RESET_CONTROL_1	0x00980001
#define PIPE_RESET_GO			0x00034000	/* RESET_ALL, VALID, COUNT 0x4000 */
#define PIPE_RESET_DONE			BIT(18)
#define A_EGR_ENABLE_SELECT		0x0a980105
#define A_RDBGC0_SELECT			0x0f780020
#define RDBGC0_SELECT_SET_UP		0x0400ad11
#define A_VLAN_TAB			0x05700000	/* 4096 entries, 2 words */
#define A_EGR_VLAN			0x04910000	/* 4096 entries, 2 words */
#define A_STG_TAB			0x05710000	/* 64 entries, 2 words */
#define A_EGR_VLAN_STG			0x04920000	/* 64 entries, 2 words */
#define A_VLAN_PROFILE_TAB		0x05720000	/* 1 word */
#define A_VLAN_CTRL			0x01780003
#define A_ING_MISC_CONFIG		0x0f78012d	/* USE_EPC_LINK_BMP 6 */
#define A_GPORT_CONFIG			0x00080000	/* + GPORT block */
#define A_ING_OUTER_TPID_0		0x0278000c
#define A_EGR_VLAN_CONTROL_1		0x01900003	/* per port */
#define A_PORT_TAB			0x01700000	/* 25 entries, 3 words */
#define A_EGR_PORT			0x01900002	/* per port */
#define A_ING_EN_EFILTER_BITMAP		0x0c78000d
#define A_EGR_ENABLE			0x0a900100	/* per port */
#define A_EPC_LINK_BMAP			0x0f780110
#define A_COSLCCOUNT			0x00600044	/* per port, COS 0, read only */
#define G_COMMAND_CONFIG		0x102		/* GPORT registers */
#define G_PAUSE_QUANT			0x106
#define G_TX_IPG_LENGTH			0x117
#define G_FLUSH_CONTROL			0x1cd

#define PHY_ID1				0x0143		/* internal PHYs of ports 1-8 */
#define PHY_ID2				0xbd20		/* & 0xfff0 */
#define INIT_PHY_PORTS			8
#define PORT_MASK_GE			GENMASK(24, 1)

static u32 pipe_port(u32 base, int p)
{
	return base | p << 12;
}

static u32 gport_port(u32 off, int p)
{
	return off | (2 + (p - 1) / 8) << 20 | ((p - 1) % 8) << 12;
}

static struct iline *il_add(struct bcm53314 *sw, const char *pre, const char *name, int p,
			    int voie, int op, u32 addr)
{
	struct iline *l;
	int n;

	if (sw->nil >= INIT_MAX_LINES) {
		sw->il_overflow = true;
		l = &sw->il_spare;
	} else {
		l = &sw->il[sw->nil++];
	}
	memset(l, 0, sizeof(*l));
	n = scnprintf(l->id, sizeof(l->id), "%s%s%s", pre ? pre : "", pre ? "." : "", name);
	if (p > 0)
		scnprintf(l->id + n, sizeof(l->id) - n, "(%d)", p);
	l->voie = voie;
	l->op = op;
	l->addr = addr;
	l->words = 1;
	return l;
}

static struct iline *mm(struct bcm53314 *sw, const char *name, int op, u32 off, u32 m, u32 v)
{
	struct iline *l = il_add(sw, NULL, name, 0, V_MMIO, op, off);

	l->m[0] = m;
	l->v[0] = v;
	return l;
}

static struct iline *sr(struct bcm53314 *sw, const char *pre, const char *name, int p, int op,
			u32 addr, u32 m, u32 v)
{
	struct iline *l = il_add(sw, pre, name, p, V_SREG, op, addr);

	l->m[0] = m;
	l->v[0] = v;
	return l;
}

static struct iline *sm(struct bcm53314 *sw, const char *name, int p, int op, u32 addr, int words,
			const u32 *m, const u32 *v)
{
	struct iline *l = il_add(sw, NULL, name, p, V_SMEM, op, addr);
	int i;

	l->words = words;
	for (i = 0; i < words; i++) {
		l->m[i] = m ? m[i] : ~0u;
		l->v[i] = v ? v[i] : 0;
	}
	return l;
}

static struct iline *mi(struct bcm53314 *sw, const char *pre, const char *name, int p, int op,
			u8 reg, u16 m, u16 v)
{
	struct iline *l = il_add(sw, pre, name, p, V_MIIM, op, 0);

	l->phy = 0x80 | p;	/* internal bus */
	l->reg = reg;
	l->m[0] = m;
	l->v[0] = v;
	return l;
}

static struct iline *il_wait(struct iline *l, u32 us)
{
	l->post = P_WAIT;
	l->wait_us = us;
	return l;
}

static struct iline *il_check(struct iline *l, u32 v)
{
	l->check = true;
	l->chk = v;
	return l;
}

static struct iline *il_loop(struct iline *l, int kind, int lo, int hi)
{
	l->loop = kind;
	l->lo = lo;
	l->hi = hi;
	return l;
}

/* Port mode: purge, PHY (ports 1-8), MAC; on = auto-negotiation and RX/TX enabled */
static void init_port_mode(struct bcm53314 *sw, const char *pre, int p, bool on)
{
	u32 cc = gport_port(G_COMMAND_CONFIG, p), fl = gport_port(G_FLUSH_CONTROL, p);
	struct iline *l;

	sr(sw, pre, "S1", p, L_RMW, A_EPC_LINK_BMAP, ~(u32)BIT(p), 0);
	l = sr(sw, pre, "S2", p, L_RMW, fl, ~0u, BIT(0));		/* FLUSH */
	l->post = P_COSLC;
	l->aux = pipe_port(A_COSLCCOUNT, p);
	l = sr(sw, pre, "S3", p, L_WRD, fl, ~(u32)BIT(0), 0);		/* value read by S2, FLUSH 0 */
	l->aux = fl;
	l->src = "S2";
	if (init_phy && p <= INIT_PHY_PORTS) {
		if (on)	/* auto-negotiation on and restarted */
			mi(sw, pre, "Q1", p, L_RMW, MII_BMCR, 0xffff, 0x1200);
		else	/* auto-negotiation off */
			mi(sw, pre, "Q1", p, L_RMW, MII_BMCR, 0xefff, 0);
		mi(sw, pre, "Q2", p, L_RMW, 0x1e, 0xefff, 0);		/* no PHY loopback */
		mi(sw, pre, "Q3", p, L_RMW, MII_BMCR, 0xbfff, 0);	/* loopback off */
		mi(sw, pre, "Q4", p, L_WR, 0x18, 0, 0x0004);		/* no remote loopback */
		if (on) {
			mi(sw, pre, "Qg", p, L_RD, MII_BMCR, 0, 0);
		} else {
			mi(sw, pre, "Q5", p, L_RMW, MII_BMCR, 0x9fbf, 0x0040);	/* 1000 Mb/s */
			mi(sw, pre, "Q6", p, L_RMW, MII_BMCR, 0xffff, 0x0100);	/* full duplex */
		}
	}
	sr(sw, pre, "C1", p, L_RMW, cc, ~0u, CC_SW_RESET);
	sr(sw, pre, "C2", p, L_RMW, cc, 0xfffffbf1, 0x8);	/* RX off, 1 Gb/s, full duplex */
	sr(sw, pre, "C3", p, L_RMW, cc, ~(u32)CC_SW_RESET, 0);
	sr(sw, pre, "C4", p, L_RMW, cc, ~(u32)BIT(15), 0);		/* LOOP_ENA 0 */
	if (on) {
		sr(sw, pre, "C5", p, L_RMW, cc, ~0u, CC_SW_RESET);
		sr(sw, pre, "C6", p, L_RMW, cc, ~0u, CC_TX_ENA | CC_RX_ENA);
		sr(sw, pre, "C7", p, L_RMW, cc, ~(u32)CC_SW_RESET, 0);
	}
}

/* Internal PHY of port p: reset, then its set-up */
static void init_phy_port(struct bcm53314 *sw, int p)
{
	mi(sw, NULL, "PID", p, L_RD, 2, 0, 0)->guard = G_PHYID;
	mi(sw, NULL, "P1", p, L_WR, MII_BMCR, 0, 0x8000)->post = P_PHYRST;
	mi(sw, NULL, "P2", p, L_RMW, 0x09, 0xffff, 0x0400);	/* 1000BASE-T: repeater/switch */
	mi(sw, NULL, "P3", p, L_WR, 0x1c, 0, 0xfc01);		/* fibre registers */
	mi(sw, NULL, "P4", p, L_RMW, MII_BMCR, 0xefff, 0x0800);	/* fibre: power down, AN off */
	mi(sw, NULL, "P5", p, L_WR, 0x1c, 0, 0xfc00);		/* copper registers */
	mi(sw, NULL, "P6", p, L_RMW, MII_BMCR, 0xf7ff, 0);	/* copper: power up */
	mi(sw, NULL, "P7", p, L_WR, 0x1c, 0, 0x7800);		/* shadow 0x1e */
	mi(sw, NULL, "P8", p, L_RMW, 0x1c, 0xffe0, 0xf800);	/* auto-medium detect off */
	mi(sw, NULL, "P9", p, L_WR, 0x1c, 0, 0x6c00);		/* shadow 0x1b */
	mi(sw, NULL, "P10", p, L_RMW, 0x1c, 0xffff, 0xec40);	/* carrier extension off */
	mi(sw, NULL, "P11", p, L_RMW, 0x10, 0xffff, 0x0021);	/* traffic LEDs, FIFO elasticity */
	mi(sw, NULL, "P12", p, L_WR, 0x18, 0, 0x0007);		/* shadow 7 */
	mi(sw, NULL, "P13", p, L_RMW, 0x18, 0xffff, 0x4000);	/* extended packet length */
	mi(sw, NULL, "P14", p, L_WR, 0x1c, 0, 0xb410);		/* LED selectors */
	mi(sw, NULL, "P15", p, L_WR, 0x1c, 0, 0xb863);
	mi(sw, NULL, "P16", p, L_WR, 0x1c, 0, 0xa408);
	mi(sw, NULL, "P17", p, L_WR, 0x17, 0, 0x0f04);		/* expansion register 4 */
	mi(sw, NULL, "P18", p, L_WR, 0x15, 0, 0x0000);
	mi(sw, NULL, "P19", p, L_WR, 0x17, 0, 0x0000);
}

static void init_build(struct bcm53314 *sw)
{
	static const u32 vt1_m[2] = { 0x07ffffff, 0xfffffff8 }, vt1_v[2] = { 0x06000000, 0 };
	static const u32 ev1_m[2] = { 0xfe000000, 0xff07ffff }, ev1_v[2] = { 0, 0x01040000 };
	static const u32 pt_v[3] = { 0x00080001, 0x01040000, 0 };
	struct iline *l;
	u32 v[3], m[3];
	int p;

	sw->nil = 0;
	sw->il_overflow = false;

	/* R: CMIC, block resets */
	mm(sw, "R1", L_RD, CMIC_IRQ_MASK, 0, 0);		/* dummy read */
	mm(sw, "R2", L_WR, CMIC_ENDIANESS_SEL, 0, 0);
	mm(sw, "R3", L_RMW, CMIC_CONFIG, ~0u, CFG_BURST)->guard = G_CFG;
	mm(sw, "R4", L_WR, CMIC_IRQ_MASK, 0, 0);
	l = mm(sw, "R5", L_RMW, CMIC_CONFIG, ~0u, CFG_RESET_CPS);
	l->guard = G_CFG;
	il_wait(l, 10000);
	mm(sw, "R6a", L_RD, CMIC_IRQ_MASK, 0, 0);		/* first read after the CPS reset */
	mm(sw, "R6b", L_WR, CMIC_ENDIANESS_SEL, 0, 0);
	mm(sw, "R7", L_RMW, CMIC_CONFIG, ~0u, CFG_BURST)->guard = G_CFG_SET_UP;
	mm(sw, "R8", L_WR, CMIC_IRQ_MASK, 0, 0);
	mm(sw, "R9", L_WR, CMIC_SOFT_RESET, 0, SOFT_RESET_DISK);
	mm(sw, "R10", L_WR, CMIC_SOFT_RESET, 0, 0x00000200)->post = P_PLL;	/* XG PLL */
	il_wait(mm(sw, "R12", L_WR, CMIC_SOFT_RESET, 0, 0x0001e200), 50);	/* + QGPHY, QSGMII */
	il_check(il_wait(mm(sw, "R13", L_WR, CMIC_SOFT_RESET, 0, SOFT_RESET_SET_UP), 10000),
		 SOFT_RESET_SET_UP);					/* + GP, MMU, IP, EP */
	mm(sw, "R14", L_WR, CMIC_SBUS_RING_MAP, 0, SBUS_RING_MAP);
	mm(sw, "R15", L_RMW, CMIC_CHIP_MODE_CONTROL, ~(u32)BIT(0), 0);
	mm(sw, "R16", L_WR, CMIC_INTR_WAIT_CYCLES, 0, 0);
	if (init_ledram)	/* LEDs of ports 1-8 from the LED processor */
		mm(sw, "R17", L_RMW, CMIC_QGPHY_QSGMII_CONTROL, ~0u, BIT(3));
	il_check(mm(sw, "RFa", L_RD, CMIC_CONFIG, 0, 0), CFG_SET_UP)->guard = G_CFG;
	il_check(mm(sw, "RFb", L_RD, CMIC_SOFT_RESET, 0, 0), SOFT_RESET_SET_UP);

	/* I: pipelines, tables, globals */
	sr(sw, NULL, "I1", 0, L_WR, A_ING_HW_RESET_CONTROL_1, 0, 0);
	sr(sw, NULL, "I2", 0, L_WR, A_ING_HW_RESET_CONTROL_2, 0, PIPE_RESET_GO);
	sr(sw, NULL, "I3", 0, L_WR, A_EGR_HW_RESET_CONTROL_0, 0, 0);
	sr(sw, NULL, "I4", 0, L_WR, A_EGR_HW_RESET_CONTROL_1, 0, PIPE_RESET_GO)->post = P_PIPE;
	sr(sw, NULL, "I7", 0, L_WR, A_ING_HW_RESET_CONTROL_2, 0, 0);
	sr(sw, NULL, "I8", 0, L_WR, A_EGR_HW_RESET_CONTROL_1, 0, 0);
	sr(sw, NULL, "I9", 0, L_RMW, A_EGR_ENABLE_SELECT, ~0u, BIT(0));
	sr(sw, NULL, "I10", 0, L_WR, A_RDBGC0_SELECT, 0, RDBGC0_SELECT_SET_UP);
	il_loop(sm(sw, "I11", 0, L_WR, A_VLAN_TAB, 2, NULL, NULL), R_IDX, 0, 4095);
	il_loop(sm(sw, "I12", 0, L_WR, A_EGR_VLAN, 2, NULL, NULL), R_IDX, 0, 4095);
	il_loop(sm(sw, "I13", 0, L_WR, A_STG_TAB, 2, NULL, NULL), R_IDX, 0, 63);
	il_loop(sm(sw, "I14", 0, L_WR, A_EGR_VLAN_STG, 2, NULL, NULL), R_IDX, 0, 63);
	m[0] = 0xffffaff9;
	v[0] = 0x2fe1;
	il_check(sm(sw, "I15", 0, L_RMW, A_VLAN_PROFILE_TAB, 1, m, v), 0x2fe1);
	il_check(sr(sw, NULL, "I16", 0, L_RMW, A_VLAN_CTRL, ~(u32)BIT(12), 0), 0x10200001);
	il_check(sr(sw, NULL, "I17", 0, L_RMW, A_ING_MISC_CONFIG, ~0u, BIT(6)), 0x440);
	il_loop(sr(sw, NULL, "I18", 0, L_WR, A_GPORT_CONFIG, 0, 3), R_GPORT, 0, 2);
	il_loop(sr(sw, NULL, "I19", 0, L_WR, A_GPORT_CONFIG, 0, 1), R_GPORT, 0, 2);

	/* I20: per port MAC and tables, then P: internal PHY of ports 1-8 */
	for (p = 1; p < NUM_PORTS; p++) {
		sr(sw, NULL, "I20a", p, L_RMW, A_ING_OUTER_TPID_0, 0xffff0000, ETH_P_8021Q);
		sr(sw, NULL, "I20b", p, L_RMW, pipe_port(A_EGR_VLAN_CONTROL_1, p), ~0x70u, 0);
		sm(sw, "I20c", p, L_WR, A_PORT_TAB + p, 3, NULL, pt_v);
		sr(sw, NULL, "I20d", p, L_RMW, pipe_port(A_EGR_PORT, p), ~0u, BIT(2));
		sr(sw, NULL, "I20e", p, L_RMW, A_ING_EN_EFILTER_BITMAP, ~0u, BIT(p));
		sr(sw, NULL, "I20f", p, L_RMW, pipe_port(A_EGR_ENABLE, p), ~0u, BIT(0));
		il_wait(sr(sw, NULL, "I20g", p, L_RMW, gport_port(G_COMMAND_CONFIG, p), ~0u,
			   CC_SW_RESET), 10);
		/* 1 Gb/s; RX_ENA, LOOP_ENA, LINE_LOOPBACK 0; TX_ENA kept */
		sr(sw, NULL, "I20h", p, L_RMW, gport_port(G_COMMAND_CONFIG, p), 0xfdff7ff1, 0x8);
		sr(sw, NULL, "I20i", p, L_RMW, gport_port(G_COMMAND_CONFIG, p), ~(u32)CC_SW_RESET, 0);
		sr(sw, NULL, "I20j", p, L_RMW, gport_port(G_PAUSE_QUANT, p), ~0u, 0xffff);
		sr(sw, NULL, "I20k", p, L_RMW, gport_port(G_TX_IPG_LENGTH, p), ~0x7fu, 12);
		if (init_phy && p <= INIT_PHY_PORTS)
			init_phy_port(sw, p);
	}

	/* I21-I24: VID 1 untagged on every port, CMIC tagged, forwarding */
	sm(sw, "I21a", 0, L_RMW, A_VLAN_TAB + VID_DEFAULT, 2, vt1_m, vt1_v);
	sm(sw, "I21b", 0, L_RMW, A_EGR_VLAN + VID_DEFAULT, 2, ev1_m, ev1_v);
	for (p = 1; p < NUM_PORTS; p++) {
		memset(v, 0, sizeof(v));
		ent_set(v, 0, 25, BIT(p));
		sm(sw, "I22a", p, L_RMW, A_VLAN_TAB + VID_DEFAULT, 2, NULL, v);
		memset(v, 0, sizeof(v));
		ent_set(v, 0, 25, BIT(p));		/* UT_BITMAP */
		ent_set(v, 25, 25, BIT(p));		/* PORT_BITMAP */
		sm(sw, "I22b", p, L_RMW, A_EGR_VLAN + VID_DEFAULT, 2, NULL, v);
		m[0] = m[1] = ~0u;
		memset(v, 0, sizeof(v));
		ent_set(m, 2 * p, 2, 0);
		ent_set(v, 2 * p, 2, 3);		/* forwarding */
		sm(sw, "I22c", p, L_RMW, A_STG_TAB + STG_DEFAULT, 2, m, v);
		l = sm(sw, "I22d", p, L_WWR, A_EGR_VLAN_STG + STG_DEFAULT, 2, NULL, NULL);
		l->aux = A_STG_TAB + STG_DEFAULT;
		l->src = "I22c";
		init_port_mode(sw, "I22e", p, true);
	}
	memset(v, 0, sizeof(v));
	ent_set(v, 0, 25, BIT(0));
	sm(sw, "I23a", 0, L_RMW, A_VLAN_TAB + VID_DEFAULT, 2, NULL, v);
	memset(v, 0, sizeof(v));
	ent_set(v, 25, 25, BIT(0));			/* CMIC tagged: PORT_BITMAP only */
	sm(sw, "I23b", 0, L_RMW, A_EGR_VLAN + VID_DEFAULT, 2, NULL, v);
	sr(sw, NULL, "I24", 0, L_WR, A_EPC_LINK_BMAP, 0, PORT_MASK_GE);

	/* F: every port disabled, trunk and MGMT last */
	for (p = 1; p < NUM_PORTS; p++)
		if (p != PORT_TRUNK && p != PORT_MGMT)
			init_port_mode(sw, "F2", p, false);
	init_port_mode(sw, "F4", PORT_TRUNK, false);
	init_port_mode(sw, "F4", PORT_MGMT, false);
}

/* Formatting: one function, used for "plan", "log" and tests */
static size_t fmt_val(char *b, size_t n, int voie, u32 v)
{
	if (voie == V_MMIO)
		return scnprintf(b, n, "0x%08X", v);
	if (voie == V_MIIM)
		return scnprintf(b, n, "0x%04X", v);
	return v ? scnprintf(b, n, "0x%X", v) : scnprintf(b, n, "0");
}

static size_t fmt_words(char *b, size_t n, int voie, int words, const u32 *w)
{
	size_t len = 0;
	int i, nz = 0;

	for (i = 0; i < words; i++)
		nz |= w[i] != 0;
	if (words > 1 && !nz)
		return scnprintf(b, n, "0");
	for (i = 0; i < words; i++) {
		if (i)
			len += scnprintf(b + len, n - len, ",");
		len += fmt_val(b + len, n - len, voie, w[i]);
	}
	return len;
}

static size_t fmt_dur(char *b, size_t n, u32 us)
{
	if (us && !(us % 1000))
		return scnprintf(b, n, "%ums", us / 1000);
	return scnprintf(b, n, "%uus", us);
}

static size_t il_format(const struct iline *l, char *b, size_t n)
{
	static const char *const voie[] = { "MMIO", "S-reg", "S-mem", "MIIM" };
	size_t len;

	len = scnprintf(b, n, "%s %s ", l->id, voie[l->voie]);
	switch (l->voie) {
	case V_MMIO:
		len += scnprintf(b + len, n - len, "0x%03X", l->addr);
		break;
	case V_MIIM:
		if (l->guard == G_PHYID)
			len += scnprintf(b + len, n - len, "phy 0x%02X reg 0x02/0x03", l->phy);
		else
			len += scnprintf(b + len, n - len, "phy 0x%02X reg 0x%02X", l->phy, l->reg);
		break;
	default:
		len += scnprintf(b + len, n - len, "0x%08X", l->addr);
		if (l->loop == R_IDX)
			len += scnprintf(b + len, n - len, "[%u..%u]", l->lo, l->hi);
		else if (l->loop == R_GPORT)
			len += scnprintf(b + len, n - len, "[gport %u..%u]", l->lo, l->hi);
	}
	switch (l->op) {
	case L_RD:
		len += scnprintf(b + len, n - len, " R");
		break;
	case L_WR:
		len += scnprintf(b + len, n - len, " W ");
		len += fmt_words(b + len, n - len, l->voie, l->words, l->v);
		break;
	case L_RMW:
		len += scnprintf(b + len, n - len, " RMW &");
		len += fmt_words(b + len, n - len, l->voie, l->words, l->m);
		len += scnprintf(b + len, n - len, " |");
		len += fmt_words(b + len, n - len, l->voie, l->words, l->v);
		break;
	case L_WRD:
		len += scnprintf(b + len, n - len, " W =%s &", l->src);
		len += fmt_words(b + len, n - len, l->voie, l->words, l->m);
		break;
	case L_WWR:
		len += scnprintf(b + len, n - len, " W =%s", l->src);
		break;
	}
	if (l->loop)
		len += scnprintf(b + len, n - len, " x%u", l->hi - l->lo + 1);
	switch (l->post) {
	case P_WAIT:
		len += scnprintf(b + len, n - len, " ; WAIT ");
		len += fmt_dur(b + len, n - len, l->wait_us);
		break;
	case P_PLL:
		len += scnprintf(b + len, n - len, " ; POLL 0x%03X[31]=1 <=500x1ms",
				 CMIC_XGXS_PLL_STATUS);
		break;
	case P_PIPE:
		len += scnprintf(b + len, n - len, " ; POLL 0x%08X[18]=1,0x%08X[18]=1 <=5x1ms",
				 A_ING_HW_RESET_CONTROL_2, A_EGR_HW_RESET_CONTROL_1);
		break;
	case P_COSLC:
		len += scnprintf(b + len, n - len, " ; POLL 0x%08X=0 <=50x10ms", l->aux);
		break;
	case P_PHYRST:
		len += scnprintf(b + len, n - len, " ; POLL reg 0x00[15]=0 <=10x0us");
		break;
	}
	if (l->check) {
		len += scnprintf(b + len, n - len, " ; CHECK ");
		len += fmt_val(b + len, n - len, l->voie, l->chk);
	}
	if (l->guard == G_PHYID)
		len += scnprintf(b + len, n - len, " ; CHECK 0x%04X,0x%04X/0xFFF0", PHY_ID1, PHY_ID2);
	return len;
}

/* Execution of one line; values read are appended to x (the "log" line) */
struct xbuf {
	char b[INIT_VALS];
	size_t len;
};

static __printf(2, 3) void xbuf_add(struct xbuf *x, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	x->len += vscnprintf(x->b + x->len, sizeof(x->b) - x->len, fmt, ap);
	va_end(ap);
}

static __printf(2, 3) int init_halt(struct bcm53314 *sw, const char *fmt, ...)
{
	va_list ap;

	if (!sw->cause[0]) {
		va_start(ap, fmt);
		vscnprintf(sw->cause, sizeof(sw->cause), fmt, ap);
		va_end(ap);
	}
	sw->halted = true;
	return -EIO;
}

static int init_mmio_wr(struct bcm53314 *sw, u32 off, u32 val)
{
	int err;

	sw->init_mmio_armed = true;
	sw->arm_off = off;
	sw->arm_val = val;
	err = cmic_wr(sw, off, val);
	sw->init_mmio_armed = false;
	if (!err)
		sw->tot_mmio++;
	return err;
}

static int il_exec_mmio(struct bcm53314 *sw, const struct iline *l, struct xbuf *x)
{
	u32 r = 0, nv;
	int err, n;

	if (l->op == L_RD || l->op == L_RMW) {
		err = cmic_rd(sw, l->addr, &r);
		if (err)
			return err;
		xbuf_add(x, " r=0x%08X", r);
		if (l->guard && (r & (CFG_SCHAN_ABORT | CFG_I2C_EN)))
			return init_halt(sw, "CMIC_CONFIG 0x%08X: SCHAN_ABORT or I2C_EN set", r);
		if (l->guard == G_CFG_SET_UP && (r & CFG_RESET_CPS))
			return init_halt(sw, "CMIC_CONFIG 0x%08X: RESET_CPS not cleared", r);
		if (l->guard == G_CFG_SET_UP && r != CFG_SET_UP)
			return init_halt(sw, "CMIC_CONFIG 0x%08X, expected 0x%08X", r, CFG_SET_UP);
	}
	if (l->op == L_RD) {
		if (l->check && r != l->chk)
			return init_halt(sw, "0x%03X read 0x%08X, expected 0x%08X", l->addr, r, l->chk);
		return 0;
	}
	nv = l->op == L_RMW ? (r & l->m[0]) | l->v[0] : l->v[0];
	err = init_mmio_wr(sw, l->addr, nv);
	if (err)
		return err;
	if (l->post == P_WAIT)
		fsleep(l->wait_us);
	if (l->post == P_PLL) {
		for (n = 1; ; n++) {
			err = cmic_rd(sw, CMIC_XGXS_PLL_STATUS, &r);
			if (err)
				return err;
			if (r & PLL_LOCK)
				break;
			if (n >= 500) {
				xbuf_add(x, " n=%d", n);
				return init_halt(sw, "PLL not locked after %d reads (0x%08X)", n, r);
			}
			fsleep(1000);
		}
		xbuf_add(x, " n=%d", n);
	}
	if (l->check) {
		err = cmic_rd(sw, l->addr, &r);
		if (err)
			return err;
		xbuf_add(x, " c=0x%08X", r);
		if (r != l->chk)
			return init_halt(sw, "0x%03X read back 0x%08X, expected 0x%08X", l->addr, r, l->chk);
	}
	return 0;
}

static int s_write(struct bcm53314 *sw, bool mem, u32 addr, int words, u32 *w)
{
	int err = schan_xfer(sw, true, mem, addr, words, w, NULL, 0);

	if (!err)
		sw->tot_schan++;
	return err;
}

static int il_exec_schan(struct bcm53314 *sw, const struct iline *l, struct xbuf *x)
{
	bool mem = l->voie == V_SMEM;
	u32 r[3] = { 0 }, nv[3] = { 0 };
	int err = 0, i, k, n = 0;

	if (l->loop) {
		for (k = l->lo; k <= l->hi; k++) {
			u32 a = l->loop == R_IDX ? l->addr + k : l->addr | (2 + k) << 20;

			memcpy(nv, l->v, sizeof(nv));
			err = s_write(sw, mem, a, l->words, nv);
			if (err)
				break;
			n++;
		}
		xbuf_add(x, " w=%d", n);
		return err;
	}
	switch (l->op) {
	case L_WR:
		memcpy(nv, l->v, sizeof(nv));
		break;
	case L_RMW:
		err = schan_xfer(sw, false, mem, l->addr, l->words, r, NULL, 0);
		if (err)
			return err;
		xbuf_add(x, " r=");
		for (i = 0; i < l->words; i++) {
			xbuf_add(x, "%s0x%X", i ? "," : "", r[i]);
			nv[i] = (r[i] & l->m[i]) | l->v[i];
		}
		memcpy(sw->prev_rd, r, sizeof(r));
		sw->prev_rd_addr = l->addr;
		break;
	case L_WRD:
		if (sw->prev_rd_addr != l->aux)
			return init_halt(sw, "no value read from 0x%08X", l->aux);
		nv[0] = (sw->prev_rd[0] & l->m[0]) | l->v[0];
		break;
	case L_WWR:
		if (sw->prev_wr_addr != l->aux)
			return init_halt(sw, "no entry written at 0x%08X", l->aux);
		memcpy(nv, sw->prev_wr, sizeof(nv));
		break;
	default:
		return init_halt(sw, "bad line");
	}
	err = s_write(sw, mem, l->addr, l->words, nv);
	if (err)
		return err;
	memcpy(sw->prev_wr, nv, sizeof(nv));
	sw->prev_wr_addr = l->addr;
	sw->prev_rd_addr = l->op == L_RMW ? l->addr : 0;

	if (l->post == P_WAIT)
		fsleep(l->wait_us);
	if (l->post == P_PIPE) {	/* one budget of 5 reads for both pipelines */
		static const u32 pa[2] = { A_ING_HW_RESET_CONTROL_2, A_EGR_HW_RESET_CONTROL_1 };
		int st = 0;

		while (st < 2) {
			if (n >= 5) {
				xbuf_add(x, " n=%d", n);
				return init_halt(sw, "%s pipeline reset not done after %d reads",
						 st ? "egress" : "ingress", n);
			}
			err = schan_xfer(sw, false, false, pa[st], 1, r, NULL, 0);
			if (err)
				return err;
			n++;
			if (r[0] & PIPE_RESET_DONE)
				st++;
			else if (n < 5)
				fsleep(1000);
		}
		xbuf_add(x, " n=%d", n);
	}
	if (l->post == P_COSLC) {
		for (n = 1; ; n++) {
			err = schan_xfer(sw, false, false, l->aux, 1, r, NULL, 0);
			if (err)
				return err;
			if (!r[0])
				break;
			if (n >= 50) {
				xbuf_add(x, " n=%d", n);
				return init_halt(sw, "COSLCCOUNT 0x%X after %d reads", r[0], n);
			}
			fsleep(10000);
		}
		xbuf_add(x, " n=%d", n);
	}
	if (l->check) {
		err = schan_xfer(sw, false, mem, l->addr, l->words, r, NULL, 0);
		if (err)
			return err;
		xbuf_add(x, " c=0x%X", r[0]);
		if (r[0] != l->chk)
			return init_halt(sw, "0x%08X read back 0x%X, expected 0x%X", l->addr, r[0], l->chk);
	}
	return 0;
}

static int il_exec_miim(struct bcm53314 *sw, const struct iline *l, struct xbuf *x)
{
	u16 r = 0, id2 = 0, nv;
	int err, n;

	if (l->guard == G_PHYID) {
		err = miim_op(sw, false, l->phy, 2, &r);
		if (!err)
			err = miim_op(sw, false, l->phy, 3, &id2);
		if (err)
			return err;
		xbuf_add(x, " r=0x%04X,0x%04X", r, id2);
		if (r != PHY_ID1 || (id2 & 0xfff0) != PHY_ID2)
			return init_halt(sw, "PHY 0x%02X id 0x%04X%04X, expected 0x%04X%04X/0xFFFFFFF0",
					 l->phy, r, id2, PHY_ID1, PHY_ID2);
		return 0;
	}
	if (l->op == L_RD || l->op == L_RMW) {
		err = miim_op(sw, false, l->phy, l->reg, &r);
		if (err)
			return err;
		xbuf_add(x, " r=0x%04X", r);
		if (l->op == L_RD)
			return 0;
	}
	nv = l->op == L_RMW ? (r & l->m[0]) | l->v[0] : l->v[0];
	err = miim_op(sw, true, l->phy, l->reg, &nv);
	if (err)
		return err;
	sw->tot_miim++;
	if (l->post == P_PHYRST) {
		for (n = 1; ; n++) {
			err = miim_op(sw, false, l->phy, MII_BMCR, &r);
			if (err)
				return err;
			if (!(r & BMCR_RESET))
				break;
			if (n >= 10) {
				xbuf_add(x, " n=%d", n);
				return init_halt(sw, "PHY 0x%02X still in reset after %d reads", l->phy, n);
			}
		}
		xbuf_add(x, " n=%d", n);
	}
	return 0;
}

static int il_exec(struct bcm53314 *sw, const struct iline *l, struct xbuf *x)
{
	switch (l->voie) {
	case V_MMIO:
		return il_exec_mmio(sw, l, x);
	case V_MIIM:
		return il_exec_miim(sw, l, x);
	}
	return il_exec_schan(sw, l, x);
}

static __printf(2, 3) void log_add(struct bcm53314 *sw, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sw->log_len += vscnprintf(sw->log + sw->log_len, sw->log_cap - sw->log_len, fmt, ap);
	va_end(ap);
}

/*
 * The table is built, printed into "plan" (sized from the table), then, with
 * dry_run=N, played line by line into "log". The kernel log gets a start
 * line, an end line and the TOTAL line only (plus the two lines of the
 * identification). The switch is left as the run left it.
 */
static int run_init(struct bcm53314 *sw)
{
	const char *halted_at = NULL;
	struct xbuf *x = NULL;
	char *line;
	size_t cap, len;
	int i, err = -ENOMEM;

	line = kmalloc(INIT_LINE, GFP_KERNEL);
	x = kzalloc(sizeof(*x), GFP_KERNEL);
	sw->il = vzalloc(sizeof(*sw->il) * INIT_MAX_LINES);
	if (!line || !x || !sw->il)
		goto out;
	init_build(sw);
	err = -ENOSPC;
	if (sw->il_overflow)
		goto out;
	for (cap = 1, i = 0; i < sw->nil; i++)
		cap += il_format(&sw->il[i], line, INIT_LINE) + 1;
	err = -ENOMEM;
	sw->plan = vmalloc(cap);
	sw->log_cap = cap + (size_t)sw->nil * INIT_LOG_EXTRA + 64;
	sw->log = vmalloc(sw->log_cap);
	if (!sw->plan || !sw->log)
		goto out;
	for (sw->plan_len = 0, i = 0; i < sw->nil; i++) {
		len = il_format(&sw->il[i], line, INIT_LINE);
		memcpy(sw->plan + sw->plan_len, line, len);
		sw->plan_len += len;
		sw->plan[sw->plan_len++] = '\n';
	}
	sw->log_len = 0;
	sw->log[0] = 0;
	dev_info(&sw->pdev->dev, "init: %s, %d lines, %s%s\n",
		 dry_run ? "plan only (dry run), nothing accessed" : "replay",
		 sw->nil, init_phy ? "full variant" : "variant P0 (no PHY access)",
		 init_ledram ? "" : ", R17 left out (LEDs of ports 1-8 kept by their PHYs)");

	if (!dry_run) {
		sw->init_active = true;
		for (i = 0; i < sw->nil; i++) {
			const struct iline *l = &sw->il[i];

			len = il_format(l, line, INIT_LINE);
			if (sw->log_len + len + INIT_LOG_EXTRA > sw->log_cap - 64) {
				init_halt(sw, "log buffer full");
				halted_at = l->id;
				break;
			}
			x->len = 0;
			x->b[0] = 0;
			err = il_exec(sw, l, x);
			if (err && !sw->cause[0])
				init_halt(sw, "error %d", err);
			log_add(sw, "%s ->%s %s%s\n", line, x->b, err ? "HALT " : "ok",
				err ? sw->cause : "");
			if (err) {
				halted_at = l->id;
				break;
			}
		}
		sw->init_active = false;
	}
	log_add(sw, "TOTAL mmio %d schan %d miim %d\n", sw->tot_mmio, sw->tot_schan, sw->tot_miim);
	if (halted_at)
		dev_err(&sw->pdev->dev, "init: halted at %s (%s)\n", halted_at, sw->cause);
	else
		dev_info(&sw->pdev->dev, "init: done\n");
	dev_info(&sw->pdev->dev, "TOTAL mmio %d schan %d miim %d\n",
		 sw->tot_mmio, sw->tot_schan, sw->tot_miim);
	/* nothing else reaches the switch through this load */
	sw->halted = true;
	err = 0;
out:
	vfree(sw->il);
	sw->il = NULL;
	kfree(x);
	kfree(line);
	return err;
}

static int plan_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;

	seq_write(m, sw->plan, sw->plan_len);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(plan);

static int log_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;

	seq_write(m, sw->log, sw->log_len);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(log);

/* ---------------------------------------------------------------------- */
/* Parameters                                                              */

static int parse_isolate(struct bcm53314 *sw)
{
	char *buf, *s, *tok;
	int err = 0;

	sw->niso = 0;
	if (!isolate || !*isolate)
		return 0;
	buf = kstrdup(isolate, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	s = buf;
	while ((tok = strsep(&s, ",")) && !err) {
		char *colon = strchr(tok, ':');
		int port, vid, i;

		if (!colon) {
			err = -EINVAL;
			break;
		}
		*colon = 0;
		if (kstrtoint(tok, 10, &port) || kstrtoint(colon + 1, 10, &vid) ||
		    port < 5 || port > 24 || vid < VID_MIN || vid > VID_MAX ||
		    sw->niso >= MAX_ISOLATE) {
			err = -EINVAL;
			break;
		}
		for (i = 0; i < sw->niso; i++)
			if (sw->iso_port[i] == port || sw->iso_vid[i] == vid)
				err = -EINVAL;
		sw->iso_port[sw->niso] = port;
		sw->iso_vid[sw->niso] = vid;
		sw->niso++;
	}
	kfree(buf);
	return err;
}

static bool step_wanted(const char *name)
{
	const char *p = steps;
	size_t n = strlen(name);

	while (p && *p) {
		if (!strncmp(p, name, n) && (p[n] == ',' || !p[n]))
			return true;
		p = strchr(p, ',');
		if (p)
			p++;
	}
	return false;
}

static int steps_valid(void)
{
	static const char *const known[] = { "counters", "learning", "trunk", "isolate", "ports",
					     "ifilter", "ge3", "trunk2", "mgmt", "init" };
	const char *p = steps;

	while (p && *p) {
		size_t n = strcspn(p, ",");
		bool ok = false;
		int i;

		for (i = 0; i < ARRAY_SIZE(known); i++)
			if (n == strlen(known[i]) && !strncmp(p, known[i], n))
				ok = true;
		if (!ok)
			return -EINVAL;
		p += n;
		if (*p)
			p++;
	}
	return 0;
}

/* ---------------------------------------------------------------------- */
/* debugfs (reads only; each S-channel read writes the CMIC message window) */

static void show_obj(struct seq_file *m, struct bcm53314 *sw, int obj, int idx)
{
	u32 w[3];
	int i;

	if (sw_read(sw, obj, idx, w)) {
		seq_printf(m, "%s[%d] read error\n", objs[obj].name, idx);
		return;
	}
	seq_printf(m, "%s[%d]", objs[obj].name, idx);
	for (i = 0; i < objs[obj].words; i++)
		seq_printf(m, " %08x", w[i]);
	seq_putc(m, '\n');
}

static int state_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;
	static const int ports[] = { 0, PORT_TRUNK, PORT_MGMT, 9, 10 };
	int i, p;
	u16 bmcr, bmsr;

	if (access < 1)
		return -EPERM;
	mutex_lock(&sw->lock);
	if (sw->halted) {
		mutex_unlock(&sw->lock);
		return -EIO;
	}
	show_obj(m, sw, O_ING_CONFIG, 0);
	show_obj(m, sw, O_VLAN_CTRL, 0);
	show_obj(m, sw, O_EGR_CONFIG, 0);
	show_obj(m, sw, O_ING_OUTER_TPID_0, 0);
	show_obj(m, sw, O_EGR_OUTER_TPID_0, 0);
	show_obj(m, sw, O_EPC_LINK_BMAP, 0);
	for (i = 0; i < ARRAY_SIZE(ports); i++) {
		p = ports[i];
		show_obj(m, sw, O_PORT_TAB, p);
		show_obj(m, sw, O_EGR_PORT, p);
		show_obj(m, sw, O_EGR_VLAN_CONTROL_1, p);
		show_obj(m, sw, O_SOURCE_TRUNK_MAP, p);
		if (p)
			show_obj(m, sw, O_COMMAND_CONFIG, p);
	}
	for (i = 0; i < sw->niso; i++) {
		show_obj(m, sw, O_PORT_TAB, sw->iso_port[i]);
		show_obj(m, sw, O_COMMAND_CONFIG, sw->iso_port[i]);
		show_obj(m, sw, O_VLAN_TAB, sw->iso_vid[i]);
		show_obj(m, sw, O_EGR_VLAN, sw->iso_vid[i]);
	}
	show_obj(m, sw, O_VLAN_TAB, VID_DEFAULT);
	show_obj(m, sw, O_EGR_VLAN, VID_DEFAULT);
	for (i = 0; i <= objs[O_VLAN_PROTOCOL].max; i++)
		show_obj(m, sw, O_VLAN_PROTOCOL, i);
	if (!miim_op(sw, false, TRUNK_PHY, MII_BMCR, &bmcr) &&
	    !miim_op(sw, false, TRUNK_PHY, MII_BMSR, &bmsr) &&
	    !miim_op(sw, false, TRUNK_PHY, MII_BMSR, &bmsr))
		seq_printf(m, "trunk PHY 0x%02x BMCR %04x BMSR %04x\n", TRUNK_PHY, bmcr, bmsr);
	mutex_unlock(&sw->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(state);

static int counters_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;
	static const int ports[] = { PORT_TRUNK, PORT_MGMT, 9, 10 };
	static const int cnt[] = { O_TDBGC0, O_TDBGC1, O_TDBGC2, O_RDBGC0, O_RDBGC1,
				   O_GT1518, O_GTMGV, O_GT2047, O_GTPKT, O_GRPKT };
	int i, j;

	if (access < 1)
		return -EPERM;
	mutex_lock(&sw->lock);
	if (sw->halted) {
		mutex_unlock(&sw->lock);
		return -EIO;
	}
	for (i = 0; i < ARRAY_SIZE(dbg_select); i++)
		show_obj(m, sw, dbg_select[i].obj, 0);
	for (j = 0; j < ARRAY_SIZE(cnt); j++)
		for (i = 0; i < ARRAY_SIZE(ports); i++)
			show_obj(m, sw, cnt[j], ports[i]);
	mutex_unlock(&sw->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(counters);

/* One line per front port, then MGMT and trunk: label, switch port, MAC_MODE, port VID, MAC control, MIB */
static int ports_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;
	u32 mm[3], pt[3], cc[3], rx[3], tx[3];
	int i;

	if (access < 1)
		return -EPERM;
	mutex_lock(&sw->lock);
	if (sw->halted) {
		mutex_unlock(&sw->lock);
		return -EIO;
	}
	for (i = 0; i <= ARRAY_SIZE(front_ports) + 1; i++) {
		const char *label = i < ARRAY_SIZE(front_ports) ? front_ports[i].label :
				    i == ARRAY_SIZE(front_ports) ? "mgmt" : "trunk";
		int p = i < ARRAY_SIZE(front_ports) ? front_ports[i].port :
			i == ARRAY_SIZE(front_ports) ? PORT_MGMT : PORT_TRUNK;

		if (sw_read(sw, O_MAC_MODE, p, mm) || sw_read(sw, O_PORT_TAB, p, pt) ||
		    sw_read(sw, O_COMMAND_CONFIG, p, cc) || sw_read(sw, O_GRPKT, p, rx) ||
		    sw_read(sw, O_GTPKT, p, tx)) {
			seq_printf(m, "%s p%d read error\n", label, p);
			break;
		}
		/* MAC_MODE fields printed raw: speed 0-2 = 10/100/1000 Mb/s, MAC_DUPLEX bit as read (0 on full-duplex gigabit links) */
		seq_printf(m, "%-6s p%-2d link %d speed %u duplex_raw %u vid %u cc %08x rx %u tx %u\n", label, p,
			   !!(mm[0] & MAC_MODE_LINK), mm[0] & 3, !!(mm[0] & BIT(2)), PT_VID(pt), cc[0],
			   rx[0], tx[0]);
	}
	mutex_unlock(&sw->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(ports);

/* Port shown on line i of "ports", "mib", "mtu": front ports, then MGMT, then trunk */
static int shown_port(int i, const char **label)
{
	if (i < ARRAY_SIZE(front_ports)) {
		*label = front_ports[i].label;
		return front_ports[i].port;
	}
	*label = i == ARRAY_SIZE(front_ports) ? "mgmt" : "trunk";
	return i == ARRAY_SIZE(front_ports) ? PORT_MGMT : PORT_TRUNK;
}

/* MIB sums: 32-bit counters read, differences summed on 64 bits (reads only) */
static int mib_update(struct bcm53314 *sw)
{
	const char *label;
	u32 w[3];
	int i, j, err;

	for (i = 0; i < NUM_SHOWN; i++) {
		int p = shown_port(i, &label);

		for (j = 0; j < NUM_MIB; j++) {
			err = sw_read(sw, mib_objs[j], p, w);
			if (err)
				return err;
			if (sw->mib_valid)
				sw->mib_sum[i][j] += (u32)(w[0] - sw->mib_last[i][j]);
			sw->mib_last[i][j] = w[0];
		}
	}
	sw->mib_valid = true;
	return 0;
}

static int mib_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;
	const char *label;
	int i, j, err;

	if (access < 1)
		return -EPERM;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : mib_update(sw);
	if (err) {
		mutex_unlock(&sw->lock);
		return err;
	}
	for (i = 0; i < NUM_SHOWN; i++) {
		int p = shown_port(i, &label);

		seq_printf(m, "%-6s p%-2d", label, p);
		for (j = 0; j < NUM_MIB; j++)
			seq_printf(m, " %s %llu", objs[mib_objs[j]].name,
				   (unsigned long long)sw->mib_sum[i][j]);
		seq_putc(m, '\n');
	}
	mutex_unlock(&sw->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(mib);

/* Maximum frame length of each MAC (MAXFR 13:0) and egress MTU limit (13:0), raw */
static int mtu_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;
	const char *label;
	u32 f[3], e[3];
	int i;

	if (access < 1)
		return -EPERM;
	mutex_lock(&sw->lock);
	if (sw->halted) {
		mutex_unlock(&sw->lock);
		return -EIO;
	}
	for (i = 0; i < NUM_SHOWN; i++) {
		int p = shown_port(i, &label);

		if (sw_read(sw, O_FRM_LENGTH, p, f) || sw_read(sw, O_EGR_MTU_SIZE, p, e)) {
			mutex_unlock(&sw->lock);
			return -EIO;
		}
		seq_printf(m, "%-6s p%-2d frm_length %08x maxfr %u egr_mtu_size %08x mtu %u\n", label, p,
			   f[0], f[0] & 0x3fff, e[0], e[0] & 0x3fff);
	}
	mutex_unlock(&sw->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(mtu);

/*
 * Step trunk2, reads only: group 7, source trunk map of ge2/ge3, block mask,
 * flood hash; then, for ge2 and ge3, MAC link and control and four raw 32-bit
 * MIB counters (packets and bytes received and sent: the share of each link
 * is read from their differences), and the ge3 PHY (link bit read twice).
 */
static int trunk2_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;
	static const int cnt[] = { O_GRPKT, O_GTPKT, O_GRBYT, O_GTBYT };
	u32 w[3], c[4][3], mm[3], cc[3];
	u16 bmcr, bmsr;
	int i, j;

	if (access < 1)
		return -EPERM;
	mutex_lock(&sw->lock);
	if (sw->halted) {
		mutex_unlock(&sw->lock);
		return -EIO;
	}
	show_obj(m, sw, O_TRUNK_GROUP, TRUNK2_TGID);
	show_obj(m, sw, O_TRUNK_BITMAP, TRUNK2_TGID);
	show_obj(m, sw, O_SOURCE_TRUNK_MAP, PORT_TRUNK);
	show_obj(m, sw, O_SOURCE_TRUNK_MAP, PORT_TRUNK2);
	show_obj(m, sw, O_HASH_CONTROL, 0);
	seq_puts(m, "NONUCAST_TRUNK_BLOCK_MASK");
	for (i = 0; i < NUM_NUC; i++) {
		if (sw_read(sw, O_NONUCAST_TRUNK_BLOCK_MASK, i, w)) {
			seq_puts(m, " read error\n");
			goto out;
		}
		seq_printf(m, " %07x", w[0]);
	}
	seq_putc(m, '\n');
	for (i = 0; i < 2; i++) {
		int p = i ? PORT_TRUNK2 : PORT_TRUNK;

		if (sw_read(sw, O_MAC_MODE, p, mm) || sw_read(sw, O_COMMAND_CONFIG, p, cc))
			goto err;
		for (j = 0; j < ARRAY_SIZE(cnt); j++)
			if (sw_read(sw, cnt[j], p, c[j]))
				goto err;
		seq_printf(m, "%s p%d link %d cc %08x GRPKT %u GTPKT %u GRBYT %u GTBYT %u\n",
			   i ? "ge3" : "ge2", p, !!(mm[0] & MAC_MODE_LINK), cc[0],
			   c[0][0], c[1][0], c[2][0], c[3][0]);
	}
	if (!miim_op(sw, false, TRUNK2_PHY, MII_BMCR, &bmcr) &&
	    !miim_op(sw, false, TRUNK2_PHY, MII_BMSR, &bmsr) &&
	    !miim_op(sw, false, TRUNK2_PHY, MII_BMSR, &bmsr))
		seq_printf(m, "ge3 PHY 0x%02x BMCR %04x BMSR %04x\n", TRUNK2_PHY, bmcr, bmsr);
	goto out;
err:
	seq_puts(m, "read error\n");
out:
	mutex_unlock(&sw->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(trunk2);

/* Front ports of the link bitmap handled by the work item */
static u32 front_pbm(void)
{
	u32 pbm = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(front_ports); i++)
		pbm |= BIT(front_ports[i].port);
	return pbm;
}

static __printf(2, 3) void link_log(struct bcm53314 *sw, const char *fmt, ...)
{
	char buf[128];
	va_list ap;

	if (sw->tick - sw->log_win_tick >= LINK_WR_WINDOW) {
		if (sw->log_supp)
			dev_info(&sw->pdev->dev, "monitor: %d line(s) not logged\n", sw->log_supp);
		sw->log_win_tick = sw->tick;
		sw->log_win = 0;
		sw->log_supp = 0;
	}
	if (sw->log_win >= LINK_LOG_MAX) {
		sw->log_supp++;
		return;
	}
	sw->log_win++;
	va_start(ap, fmt);
	vscnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	dev_info(&sw->pdev->dev, "monitor: %s\n", buf);
}

static void link_stop(struct bcm53314 *sw, const char *why)
{
	sw->link_wr_stopped = true;
	strscpy(sw->link_stop, why, sizeof(sw->link_stop));
	dev_warn(&sw->pdev->dev, "monitor: link bitmap writes stopped (%s), reads go on\n", why);
}

/*
 * Write rule of the work item, checked before each write: only bits of the
 * front ports of step "ports" change, the trunk stays in, nothing else.
 */
static bool link_write_allowed(struct bcm53314 *sw, u32 old, u32 new)
{
	return monitor == 2 && sw->ports && !dry_run && access == 2 &&
	       !((old ^ new) & ~front_pbm()) && (old & PBM_TRUNK) && (new & PBM_TRUNK);
}

static void link_apply(struct bcm53314 *sw)
{
	u32 want = (sw->epc_expect & ~front_pbm()) | (sw->link_up & front_pbm());
	u32 cur[3], w[3] = { 0 };
	int slot = sw->link_writes % LINK_WR_BUDGET;

	if (want == sw->epc_expect)
		return;
	if (sw->link_writes >= LINK_WR_BUDGET &&
	    sw->tick - sw->link_wr_tick[slot] < LINK_WR_WINDOW) {
		link_stop(sw, "more than 10 writes in 60 s");
		return;
	}
	if (sw_read(sw, O_EPC_LINK_BMAP, 0, cur))
		return;
	if (cur[0] != sw->epc_expect) {
		link_stop(sw, "EPC_LINK_BMAP changed outside the work item");
		return;
	}
	if (!link_write_allowed(sw, cur[0], want)) {
		link_stop(sw, "write rule");
		return;
	}
	w[0] = want;
	if (schan_op(sw, true, O_EPC_LINK_BMAP, 0, w))
		return;
	udelay(10);
	if (sw_read(sw, O_EPC_LINK_BMAP, 0, cur))
		return;
	if (cur[0] != want) {
		sw_fault(sw, "EPC_LINK_BMAP read back 0x%08x, wrote 0x%08x", cur[0], want);
		return;
	}
	/* not under the line budget of link_log(): at most ten per minute already */
	dev_info(&sw->pdev->dev, "monitor: EPC_LINK_BMAP 0x%08x -> 0x%08x (tick %u)\n",
		 sw->epc_expect, want, sw->tick);
	sw->epc_expect = want;
	sw->link_wr_tick[slot] = sw->tick;
	sw->link_writes++;
}

/* ---------------------------------------------------------------------- */
/* Port LEDs: link bit of the LED processor data RAM ("led", "leds")       */

static u32 led_crc32(u32 crc, u8 b)
{
	int i;

	crc ^= b;
	for (i = 0; i < 8; i++)
		crc = (crc >> 1) ^ (crc & 1 ? 0xedb88320 : 0);
	return crc;
}

/* fault: nothing more written, not even at removal */
static void led_stop(struct bcm53314 *sw, bool fault, const char *why)
{
	if (sw->led_stopped && (!fault || sw->led_fault))
		return;
	sw->led_stopped = true;
	sw->led_fault |= fault;
	strscpy(sw->led_why, why, sizeof(sw->led_why));
	dev_warn(&sw->pdev->dev, "leds: LED writes stopped (%s)%s\n", why,
		 fault ? ", nothing more written" : ", reads go on");
}

/* One data RAM write, armed with its address, value and the value read just before; read back */
static int led_write(struct bcm53314 *sw, int p, u32 old, u32 val)
{
	u32 off = LED_DATA(LED_LINK_BASE + p), rd;
	char why[80];
	int err;

	sw->led_arm_off = off;
	sw->led_arm_val = val;
	sw->led_arm_old = old;
	sw->led_wr_armed = true;
	err = cmic_wr(sw, off, val);
	sw->led_wr_armed = false;
	if (err)
		return err;
	sw->led_touched |= BIT(p);
	err = cmic_rd(sw, off, &rd);
	if (err)
		return err;
	if (rd != val) {
		scnprintf(why, sizeof(why), "port %d read back 0x%08x, wrote 0x%02x", p, rd, val);
		led_stop(sw, true, why);
		return -EIO;
	}
	return 0;
}

/* Start of "leds": the LED processor must be enabled with a program of the reference layout */
static void led_start(struct bcm53314 *sw)
{
	bool head = true;
	u32 ctrl, v;
	int k;

	if (cmic_rd(sw, LEDUP_CTRL, &ctrl))
		return;
	for (k = 0; k < ARRAY_SIZE(led_ref_head); k++) {
		if (cmic_rd(sw, LEDUP_PROGRAM_RAM + 4 * k, &v))
			return;
		if (v != led_ref_head[k])
			head = false;
	}
	if (!(ctrl & LEDUP_EN) || !head) {
		dev_warn(&sw->pdev->dev, "leds: LED processor %s (CTRL 0x%08x): link bits not written\n",
			 !(ctrl & LEDUP_EN) ? "stopped" : "not running a program of the reference layout", ctrl);
		return;
	}
	sw->led_armed = true;
	dev_info(&sw->pdev->dev, "leds: LED processor enabled (CTRL 0x%08x), link bit of ports %d-%d kept by the work item\n",
		 ctrl, LED_PORT_LO, LED_PORT_HI);
}

/* One pass: data byte of each port read, written only when its link bit (or bit 7) differs */
static void led_update(struct bcm53314 *sw)
{
	char why[80];
	u32 ctrl, old, val;
	int p;

	if (leds != 1 || !sw->led_armed || sw->led_stopped || sw->tick < LINK_DEBOUNCE)
		return;
	if (cmic_rd(sw, LEDUP_CTRL, &ctrl))
		return;
	if (!(ctrl & LEDUP_EN)) {
		scnprintf(why, sizeof(why), "LED processor stopped, CTRL 0x%08x", ctrl);
		led_stop(sw, false, why);
		return;
	}
	for (p = LED_PORT_LO; p <= LED_PORT_HI; p++) {
		int slot = sw->led_writes % LED_WR_BUDGET;

		if (cmic_rd(sw, LED_DATA(LED_LINK_BASE + p), &old))
			return;
		if (old > 0xff) {
			scnprintf(why, sizeof(why), "port %d data word 0x%08x above 0xff", p, old);
			led_stop(sw, true, why);
			return;
		}
		val = (old & ~LED_BITS) | !!(sw->link_up & BIT(p));
		if (val == old)
			continue;
		if (sw->led_writes >= LED_WR_BUDGET &&
		    sw->tick - sw->led_wr_tick[slot] < LED_WR_WINDOW) {
			led_stop(sw, false, "more than 60 writes in 60 s");
			return;
		}
		if (led_write(sw, p, old, val))
			return;
		sw->led_wr_tick[slot] = sw->tick;
		sw->led_writes++;
		link_log(sw, "led p%d 0x%02x -> 0x%02x", p, old, val);
	}
}

/*
 * Removal: link (and turbo) bits cleared on the ports written, at most 20
 * writes, outside the 60 s budget; nothing when the LED processor reads
 * stopped, after a LED fault or after a fault of the module.
 */
static void led_clear(struct bcm53314 *sw)
{
	u32 old, ctrl;
	int p, n = 0;

	if (leds != 1 || !sw->led_armed)
		return;
	if (sw->led_fault || sw->halted || cmic_rd(sw, LEDUP_CTRL, &ctrl) || !(ctrl & LEDUP_EN)) {
		dev_warn(&sw->pdev->dev, "leds: %s, link bits left as they are (touched %08x)\n",
			 sw->led_fault ? "LED fault" : sw->halted ? "module halted" : "LED processor stopped",
			 sw->led_touched);
		return;
	}
	for (p = LED_PORT_LO; p <= LED_PORT_HI && n < LED_CLEAR_MAX; p++) {
		if (!(sw->led_touched & BIT(p)))
			continue;
		if (cmic_rd(sw, LED_DATA(LED_LINK_BASE + p), &old))
			break;
		if (old > 0xff || !(old & LED_BITS))
			continue;
		if (led_write(sw, p, old, old & ~LED_BITS))
			break;
		n++;
	}
	sw->led_cleared = n;
	dev_info(&sw->pdev->dev, "leds: %d link bit(s) cleared at removal\n", n);
}

static int led_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;
	u32 ctrl, st[2], v, sum = 0, crc = ~0u, nz = 0, high = 0;
	bool head = true;
	int k;

	mutex_lock(&sw->lock);
	if (cmic_rd(sw, CMIC_SOFT_RESET, &v))
		goto err;
	seq_printf(m, "block_reset %08x\n", v);
	if (cmic_rd(sw, LEDUP_CTRL, &ctrl) || cmic_rd(sw, LEDUP_STATUS, &st[0]))
		goto err;
	msleep(50);
	if (cmic_rd(sw, LEDUP_STATUS, &st[1]))
		goto err;
	/* program RAM: a fingerprint only, its bytes are never shown */
	for (k = 0; k < 256; k++) {
		if (cmic_rd(sw, LEDUP_PROGRAM_RAM + 4 * k, &v))
			goto err;
		high += v > 0xff;
		nz += (v & 0xff) != 0;
		sum += v & 0xff;
		crc = led_crc32(crc, v & 0xff);
		if (k < ARRAY_SIZE(led_ref_head) && v != led_ref_head[k])
			head = false;
	}
	seq_printf(m, "ctrl %08x enable %u scan_intra_port_delay %u scan_start_delay %u\n",
		   ctrl, ctrl & 1, (ctrl >> 1) & 7, (ctrl >> 4) & 0xf);
	for (k = 0; k < 2; k++)
		seq_printf(m, "status%s %08x pc %02x running %u initialising %u\n", k ? " +50ms" : "",
			   st[k], st[k] & 0xff, !!(st[k] & BIT(8)), !!(st[k] & BIT(9)));
	seq_printf(m, "program nonzero %u/256 above_0xff %u sum %05x crc32 %08x reference_header %s\n",
		   nz, high, sum, ~crc, head ? "yes" : "no");
	for (k = 0; k < 32; k++) {
		if (cmic_rd(sw, LED_DATA(LED_LINK_BASE + k), &v))
			goto err;
		if (!(k % 8))
			seq_printf(m, "data %02x:", LED_LINK_BASE + k);
		if (v > 0xff)
			seq_printf(m, " %08x", v);
		else
			seq_printf(m, " %02x", v);
		if (k % 8 == 7)
			seq_putc(m, '\n');
	}
	seq_printf(m, "leds %d armed %d writes %d stopped %d fault %d touched %08x cleared %d%s%s%s\n", leds,
		   sw->led_armed, sw->led_writes, sw->led_stopped, sw->led_fault, sw->led_touched,
		   sw->led_cleared, sw->led_stopped ? " (" : "", sw->led_why, sw->led_stopped ? ")" : "");
	seq_printf(m, "halted %d\n", sw->halted);
	goto out;
err:
	seq_puts(m, "read error\n");
out:
	mutex_unlock(&sw->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(led);

/* Ports sampled by the work item: the front ports, and MGMT with "leds" */
static int link_nports(void)
{
	return ARRAY_SIZE(front_ports) + (leds == 1);
}

/*
 * PHY read for the link of front port p with linksrc=bmsr (phy_addr table of
 * the SDK): internal 0x85, 0x87, 0x88; external 0x09-0x10, 0x12-0x19.
 * 0 = none (trunk, ge3, MGMT: never read).
 */
static u8 link_phy(int p)
{
	if (p == 5 || p == 7 || p == 8)
		return 0x80 | p;
	if (p >= 9 && p <= 16)
		return p;
	if (p >= 17 && p <= 24)
		return p + 1;
	return 0;
}

/* One sample: link of each front port (and MGMT with "leds"), debounced */
static void link_sample(struct bcm53314 *sw)
{
	const char *label;
	u32 raw = 0, mac = 0, w[3];
	u16 bmsr;
	int i;

	for (i = 0; i < link_nports(); i++) {
		int p = shown_port(i, &label);
		u8 a = link_bmsr && i < ARRAY_SIZE(front_ports) ? link_phy(p) : 0;

		if (sw_read(sw, O_MAC_MODE, p, w))
			return;
		if (w[0] & MAC_MODE_LINK)
			mac |= BIT(p);
		if (!a) {
			raw |= mac & BIT(p);
			continue;
		}
		if (a == BMSR_GAP_ADDR) {
			sw_fault(sw, "monitor: PHY 0x%02x is not read", a);
			return;
		}
		if (miim_op(sw, false, a, MII_BMSR, &bmsr))
			return;
		sw->bmsr_reads++;
		if (bmsr == 0xffff) {
			sw_fault(sw, "monitor: BMSR of PHY 0x%02x reads 0xffff", a);
			return;
		}
		if (bmsr & BMSR_LSTATUS)
			raw |= BIT(p);
	}
	sw->link_raw = raw;
	sw->link_mac = mac;
	for (i = 0; i < link_nports(); i++) {
		int p = shown_port(i, &label);

		if (!!(raw & BIT(p)) == !!(sw->link_up & BIT(p))) {
			sw->link_cnt[p] = 0;
			continue;
		}
		if (++sw->link_cnt[p] < LINK_DEBOUNCE)
			continue;
		sw->link_cnt[p] = 0;
		sw->link_up ^= BIT(p);
		sw->link_trans[p]++;
		link_log(sw, "%s (p%d) link %s", label, p,
			 sw->link_up & BIT(p) ? "up" : "down");
	}
	if (monitor == 2 && !sw->link_wr_stopped)
		link_apply(sw);
	if (!sw->halted)
		led_update(sw);
}

static void mon_work_fn(struct work_struct *work)
{
	struct bcm53314 *sw = container_of(to_delayed_work(work), struct bcm53314, mon_work);
	bool again;

	mutex_lock(&sw->lock);
	sw->tick++;
	if (!sw->halted)
		link_sample(sw);
	if (!sw->halted && sw->tick % MON_MIB_TICKS == 1)
		mib_update(sw);
	again = !sw->halted;
	mutex_unlock(&sw->lock);
	if (again)
		schedule_delayed_work(&sw->mon_work, msecs_to_jiffies(MON_PERIOD_MS));
	else
		dev_err(&sw->pdev->dev, "monitor: stopped after a fault\n");
}

/* Start of the work item: the link bitmap as found is the debounced state */
static int mon_start(struct bcm53314 *sw)
{
	u32 w[3];
	int err;

	mutex_lock(&sw->lock);
	err = sw_read(sw, O_EPC_LINK_BMAP, 0, w);
	if (!err && monitor == 2 && !(w[0] & PBM_TRUNK))
		err = -EINVAL;
	if (!err) {
		sw->epc_expect = w[0];
		sw->link_up = w[0] & front_pbm();
		if (leds == 1)
			led_start(sw);
	}
	mutex_unlock(&sw->lock);
	if (err)
		return err;
	INIT_DELAYED_WORK(&sw->mon_work, mon_work_fn);
	sw->mon_started = true;
	schedule_delayed_work(&sw->mon_work, msecs_to_jiffies(MON_PERIOD_MS));
	dev_info(&sw->pdev->dev, "monitor %d: link bitmap 0x%08x%s%s\n", monitor, w[0],
		 monitor == 2 ? ", front ports kept in step with their link" : ", reads only",
		 link_bmsr ? ", link from the PHY status (linksrc=bmsr)" : "");
	return 0;
}

static int link_show(struct seq_file *m, void *unused)
{
	struct bcm53314 *sw = m->private;
	int i;

	mutex_lock(&sw->lock);
	seq_printf(m, "monitor %d tick %u epc %08x want %08x writes %d stopped %d%s%s%s\n", monitor,
		   sw->tick, sw->epc_expect,
		   (sw->epc_expect & ~front_pbm()) | (sw->link_up & front_pbm()), sw->link_writes,
		   sw->link_wr_stopped, sw->link_wr_stopped ? " (" : "", sw->link_stop,
		   sw->link_wr_stopped ? ")" : "");
	if (link_bmsr)
		seq_printf(m, "linksrc bmsr miim %u\n", sw->bmsr_reads);
	for (i = 0; i < ARRAY_SIZE(front_ports); i++) {
		int p = front_ports[i].port;

		seq_printf(m, "%-6s p%-2d raw %d up %d epc %d changes %u", front_ports[i].label, p,
			   !!(sw->link_raw & BIT(p)), !!(sw->link_up & BIT(p)),
			   !!(sw->epc_expect & BIT(p)), sw->link_trans[p]);
		if (link_bmsr)
			seq_printf(m, " mac %d phy 0x%02x", !!(sw->link_mac & BIT(p)), link_phy(p));
		seq_putc(m, '\n');
	}
	if (leds == 1) {
		seq_printf(m, "mgmt   p%-2d raw %d up %d changes %u\n", PORT_MGMT, !!(sw->link_raw & BIT(PORT_MGMT)),
			   !!(sw->link_up & BIT(PORT_MGMT)), sw->link_trans[PORT_MGMT]);
		seq_printf(m, "leds armed %d writes %d stopped %d fault %d touched %08x%s%s%s\n", sw->led_armed,
			   sw->led_writes, sw->led_stopped, sw->led_fault, sw->led_touched,
			   sw->led_stopped ? " (" : "", sw->led_why, sw->led_stopped ? ")" : "");
	}
	seq_printf(m, "halted %d\n", sw->halted);
	mutex_unlock(&sw->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(link);

/* ---------------------------------------------------------------------- */
/* "phyled": LED set-up of the external PHYs of ports 9-24                 */

/*
 * One PHY at a time (sw->phyled_phy): the shadows 0x02, 0x0d and 0x09 of
 * register 0x1c and the extended control (0x10) are read first; a shadow
 * read needs a selection write (bit 15 clear, data 0), the only writes made
 * with dry_run=Y. Then only the registers that differ from the values of
 * FortiOS are written, each with the one value computed here from the value
 * read on this PHY (one write per read): spare = read | 6, selector 1 =
 * 0x01, LED control = 0x018, ECR = read & ~0x20 (bit 5 found set). The
 * value is armed exactly for the second check (cmic_write_allowed).
 */
static bool phyled_val_ok(struct bcm53314 *sw, u8 phy, u8 reg, u16 v)
{
	u16 s = (v >> 10) & 0x1f, d = v & 0x3ff;

	if (phy != sw->phyled_phy || !phyled_phy_ok(phy))
		return false;
	if (reg == 0x1c && !(v & 0x8000))	/* selection of a shadow for a read */
		return (s == PHYLED_SPARE || s == PHYLED_SEL1 || s == PHYLED_CTRL) && d == 0;
	if (dry_run)
		return false;
	if (reg == PHYLED_ECR)
		return (sw->phyled_rd_ok & PHYLED_RD_ECR) && (sw->phyled_ecr & PHYLED_ECR_TRAFFIC) &&
		       v == (sw->phyled_ecr & ~PHYLED_ECR_TRAFFIC);
	if (reg != 0x1c)
		return false;
	if (s == PHYLED_SPARE)
		return (sw->phyled_rd_ok & PHYLED_RD_SPARE) &&
		       (sw->phyled_spare & PHYLED_SPARE_BITS) != PHYLED_SPARE_BITS &&
		       v == PHYLED_SHD_WR(PHYLED_SPARE, sw->phyled_spare | PHYLED_SPARE_BITS);
	return v == PHYLED_SHD_WR(PHYLED_SEL1, PHYLED_SEL1_VAL) || v == PHYLED_SHD_WR(PHYLED_CTRL, PHYLED_CTRL_VAL);
}

/* one write of register 0x10 or 0x1c of the current external PHY */
static int phyled_wr(struct bcm53314 *sw, u8 phy, u8 reg, u16 v)
{
	bool data = reg != 0x1c || (v & 0x8000);
	int err;

	if (!phyled_val_ok(sw, phy, reg, v))
		return -EPERM;
	sw->phyled_active = true;
	sw->phyled_val = v;
	err = miim_op(sw, true, phy, reg, &v);
	sw->phyled_active = false;
	if (data)	/* one write per read of spare or ECR */
		sw->phyled_rd_ok &= reg == PHYLED_ECR ? ~PHYLED_RD_ECR :
				    ((v >> 10) & 0x1f) == PHYLED_SPARE ? ~PHYLED_RD_SPARE : 0xff;
	if (err)
		return err;
	sw->tot_miim++;
	if (data)
		sw->phyled_nw++;
	else
		sw->phyled_nsel++;
	return 0;
}

/* data (9:0) of shadow s of register 0x1c: selection, read, shadow field checked */
static int phyled_shd_rd(struct bcm53314 *sw, int p, u8 phy, u8 s, u16 *d)
{
	u16 r;
	int err = phyled_wr(sw, phy, 0x1c, PHYLED_SHD(s));

	if (!err)
		err = miim_op(sw, false, phy, 0x1c, &r);
	if (err)
		return err;
	if (((r >> 10) & 0x1f) != s) {
		dev_err(&sw->pdev->dev, "phyled: p%d PHY 0x%02x read back 0x%04x for shadow 0x%02x\n", p, phy, r, s);
		return -EIO;
	}
	*d = r & 0x3ff;
	if (s == PHYLED_SPARE) {
		sw->phyled_spare = *d;
		sw->phyled_rd_ok |= PHYLED_RD_SPARE;
	}
	return 0;
}

static int phyled_ecr_rd(struct bcm53314 *sw, u8 phy, u16 *ecr)
{
	int err = miim_op(sw, false, phy, PHYLED_ECR, ecr);

	if (!err) {
		sw->phyled_ecr = *ecr;
		sw->phyled_rd_ok |= PHYLED_RD_ECR;
	}
	return err;
}

/* the four LED registers of one PHY: spare, selector 1, LED control, ECR */
static int phyled_rd4(struct bcm53314 *sw, int p, u8 phy, u16 *spare, u16 *sel1, u16 *ctrl, u16 *ecr)
{
	int err = phyled_ecr_rd(sw, phy, ecr);

	if (!err)
		err = phyled_shd_rd(sw, p, phy, PHYLED_SPARE, spare);
	if (!err)
		err = phyled_shd_rd(sw, p, phy, PHYLED_SEL1, sel1);
	if (!err)
		err = phyled_shd_rd(sw, p, phy, PHYLED_CTRL, ctrl);
	return err;
}

static int phyled_one(struct bcm53314 *sw, int p, u8 phy)
{
	u16 id1, id2, spare, spare0, sel1, ctrl, ecr;
	bool w_spare, w_sel1, w_ctrl, w_ecr;
	int err;

	sw->phyled_phy = phy;
	sw->phyled_rd_ok = 0;
	err = miim_op(sw, false, phy, 2, &id1);
	if (!err)
		err = miim_op(sw, false, phy, 3, &id2);
	if (err)
		return err;
	if (id1 != PHYLED_ID1 || (id2 & 0xfff0) != PHYLED_ID2) {
		dev_err(&sw->pdev->dev, "phyled: p%d PHY 0x%02x id 0x%04x%04x, expected 0x%04x%04x/0xfffffff0\n",
			p, phy, id1, id2, PHYLED_ID1, PHYLED_ID2);
		return -ENODEV;
	}
	err = phyled_rd4(sw, p, phy, &spare, &sel1, &ctrl, &ecr);
	if (err)
		return err;
	w_spare = (spare & PHYLED_SPARE_BITS) != PHYLED_SPARE_BITS;
	w_sel1 = sel1 != PHYLED_SEL1_VAL;
	w_ctrl = ctrl != PHYLED_CTRL_VAL;
	w_ecr = ecr & PHYLED_ECR_TRAFFIC;
	if (dry_run) {
		sw->phyled_nplan += w_spare + w_sel1 + w_ctrl + w_ecr;
		dev_info(&sw->pdev->dev, "phyled: p%d PHY 0x%02x spare 0x%03x sel1 0x%03x ctrl 0x%03x ecr 0x%04x, %d write(s) planned\n",
			 p, phy, spare, sel1, ctrl, ecr, w_spare + w_sel1 + w_ctrl + w_ecr);
		return 0;
	}
	if (w_spare)
		err = phyled_wr(sw, phy, 0x1c, PHYLED_SHD_WR(PHYLED_SPARE, spare | PHYLED_SPARE_BITS));
	if (!err && w_sel1)
		err = phyled_wr(sw, phy, 0x1c, PHYLED_SHD_WR(PHYLED_SEL1, PHYLED_SEL1_VAL));
	if (!err && w_ctrl)
		err = phyled_wr(sw, phy, 0x1c, PHYLED_SHD_WR(PHYLED_CTRL, PHYLED_CTRL_VAL));
	if (!err && w_ecr)
		err = phyled_wr(sw, phy, PHYLED_ECR, ecr & ~PHYLED_ECR_TRAFFIC);
	if (err)
		return err;
	/* read back */
	spare0 = spare;
	err = phyled_rd4(sw, p, phy, &spare, &sel1, &ctrl, &ecr);
	if (err)
		return err;
	if (spare != (spare0 | PHYLED_SPARE_BITS) || sel1 != PHYLED_SEL1_VAL || ctrl != PHYLED_CTRL_VAL ||
	    (ecr & PHYLED_ECR_TRAFFIC)) {
		dev_err(&sw->pdev->dev, "phyled: p%d PHY 0x%02x read back spare 0x%03x sel1 0x%03x ctrl 0x%03x ecr 0x%04x\n",
			p, phy, spare, sel1, ctrl, ecr);
		return -EIO;
	}
	return 0;
}

/* ports 9-24 in order; the first deviation stops (the PHYs already set keep it: volatile) */
static int phyled_run(struct bcm53314 *sw)
{
	int p, err = 0;

	sw->phyled_nw = sw->phyled_nsel = sw->phyled_nplan = 0;
	for (p = 9; p <= 24 && !err; p++)
		err = phyled_one(sw, p, link_phy(p));
	sw->phyled_phy = 0;
	sw->phyled_rd_ok = 0;
	if (err)
		dev_err(&sw->pdev->dev, "phyled: stopped at p%d (%d), %d write(s) done (and %d shadow selection(s))\n",
			p - 1, err, sw->phyled_nw, sw->phyled_nsel);
	else if (dry_run)
		dev_info(&sw->pdev->dev, "phyled: dry run, 16 PHYs, %d write(s) planned, none done (%d shadow selection(s) for the reads)\n",
			 sw->phyled_nplan, sw->phyled_nsel);
	else
		dev_info(&sw->pdev->dev, "phyled: LED set-up done, 16 PHYs, %d write(s) read back (and %d shadow selection(s) for the reads)\n",
			 sw->phyled_nw, sw->phyled_nsel);
	return err;
}

/* ---------------------------------------------------------------------- */
/* Load                                                                    */

static int run_steps(struct bcm53314 *sw)
{
	int err = 0;

	sw->nops = 0;
	sw->nshadow = 0;
	if (step_wanted("counters"))
		err = plan_counters(sw);
	if (!err && step_wanted("learning"))
		err = plan_learning(sw);
	if (!err && step_wanted("trunk"))
		err = plan_trunk(sw);
	if (!err && step_wanted("isolate"))
		err = plan_isolate(sw);
	if (!err && sw->ports)
		err = plan_ports(sw);
	if (!err && sw->ifilter)
		err = plan_ifilter(sw);
	if (!err && sw->ge3)
		err = plan_ge3(sw);
	if (!err && sw->trunk2)
		err = plan_trunk2(sw);
	if (!err && sw->mgmt)
		err = plan_mgmt(sw);
	if (err) {
		dev_err(&sw->pdev->dev, "plan not built (%d): state not as expected, nothing written\n", err);
		return err;
	}
	return plan_execute(sw);
}

static int __init bcm53314_init(void)
{
	struct pci_dev *pdev, *other;
	struct bcm53314 *sw;
	resource_size_t start;
	u16 cmd;
	u32 id, rst;
	bool init;
	int err;

	if (access < 0 || access > 2 || steps_valid())
		return -EINVAL;
	if (vid_base < 21 || vid_base > 3976) {
		pr_err("vid_base: 21-3976 (block clear of VID 1, 20 and 4076-4095)\n");
		return -EINVAL;
	}
	if (*steps && access < 2) {
		pr_err("steps need access=2\n");
		return -EINVAL;
	}
	init = step_wanted("init");
	if (init && (strcmp(steps, "init") || (isolate && *isolate) || trunk_autoneg || monitor)) {
		pr_err("step init runs alone\n");
		return -EINVAL;
	}
	/* monitor 2 writes the link bitmap: only over step ports, writes on */
	if (monitor < 0 || monitor > 2 || (monitor && access < 1) ||
	    (monitor == 2 && (access < 2 || dry_run || !step_wanted("ports")))) {
		pr_err("monitor: 1 needs access >= 1; 2 needs access=2, dry_run=N and step ports\n");
		return -EINVAL;
	}
	/*
	 * linksrc: MIIM reads of the PHY status (bmsr, default) or MAC_MODE
	 * (mac), taken by the work item only: without monitor no link is
	 * sampled, so the source is inert (no MIIM read at all).
	 */
	if (!linksrc || (strcmp(linksrc, "mac") && strcmp(linksrc, "bmsr"))) {
		pr_err("linksrc: mac or bmsr\n");
		return -EINVAL;
	}
	link_bmsr = !strcmp(linksrc, "bmsr") && monitor >= 1 && access >= 1;
	/* leds 1 writes the LED processor data RAM from the work item */
	if (leds < 0 || leds > 1 || (leds && (monitor < 1 || access != 2 || dry_run))) {
		pr_err("leds: 1 needs monitor >= 1, access=2 and dry_run=N\n");
		return -EINVAL;
	}
	/* phyled 1: MIIM of the external PHYs, at load, never with the step init */
	if (phyled < 0 || phyled > 1 || (phyled && (access != 2 || step_wanted("init")))) {
		pr_err("phyled: 1 needs access=2, never with step init\n");
		return -EINVAL;
	}
	if (step_wanted("ifilter") && !step_wanted("ports")) {
		pr_err("step ifilter needs step ports\n");
		return -EINVAL;
	}
	if ((step_wanted("ge3") || step_wanted("trunk2")) &&
	    (!step_wanted("ports") || step_wanted("isolate") || step_wanted("mgmt") || (isolate && *isolate))) {
		pr_err("steps ge3 and trunk2 need step ports, never with isolate or mgmt\n");
		return -EINVAL;
	}

	pdev = pci_get_device(PCI_VENDOR_ID_BROADCOM, 0xc314, NULL);
	if (!pdev)
		return -ENODEV;
	/* pci_get_device() drops the reference of its "from" argument: give it one of its own */
	other = pci_get_device(PCI_VENDOR_ID_BROADCOM, 0xc314, pci_dev_get(pdev));
	if (other) {	/* exactly one switch on this board */
		pci_dev_put(other);
		err = -ENODEV;
		goto put;
	}
	/* no driver bound, memory decoding already enabled: nothing is written to the device */
	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	if (pdev->dev.driver || !(cmd & PCI_COMMAND_MEMORY) ||
	    !(pci_resource_flags(pdev, 0) & IORESOURCE_MEM) ||
	    pci_resource_len(pdev, 0) < CMIC_BAR_SIZE) {
		err = -ENODEV;
		goto put;
	}

	sw = kvzalloc(sizeof(*sw), GFP_KERNEL);
	if (!sw) {
		err = -ENOMEM;
		goto put;
	}
	sw->pdev = pdev;
	mutex_init(&sw->lock);
	sw->mgmt = step_wanted("mgmt");
	sw->ports = step_wanted("ports");
	sw->ifilter = step_wanted("ifilter");
	sw->ge3 = step_wanted("ge3");
	sw->trunk2 = step_wanted("trunk2");
	err = parse_isolate(sw);
	if (!err && sw->ports) {
		int i;

		if (sw->niso || step_wanted("isolate")) {
			err = -EINVAL;	/* "ports" replaces "isolate" */
			goto free;
		}

		for (i = 0; i < ARRAY_SIZE(front_ports); i++) {
			sw->iso_port[i] = front_ports[i].port;
			sw->iso_vid[i] = fp_vid(i);
		}
		sw->niso = i;
	}
	/*
	 * Not with "isolate", nor with "ports" without "ifilter": their front
	 * ports would keep the ingress VLAN filter off, so a frame tagged with
	 * VID 20 received on one of them would be switched to MGMT.
	 */
	if (!err && sw->mgmt && (step_wanted("isolate") || (sw->niso && !sw->ports) ||
				 (sw->ports && !sw->ifilter)))
		err = -EINVAL;
	if (err)
		goto free;
	start = pci_resource_start(pdev, 0);
	if (!request_mem_region(start, CMIC_BAR_SIZE, KBUILD_MODNAME)) {
		err = -EBUSY;
		goto free;
	}
	sw->bar = ioremap(start, CMIC_BAR_SIZE);
	if (!sw->bar) {
		err = -ENOMEM;
		goto release;
	}
	id = ioread32(sw->bar + CMIC_DEV_REV_ID);
	if (id != CHIP_ID_B0) {
		dev_err(&pdev->dev, "chip id 0x%08x, expected 0x%08x\n", id, CHIP_ID_B0);
		err = -ENODEV;
		goto unmap;
	}
	rst = ioread32(sw->bar + CMIC_SOFT_RESET);
	dev_info(&pdev->dev, "BCM53314 B0, access level %d%s, block reset 0x%08x, config 0x%08x\n",
		 access, access == 2 && !init ? (dry_run ? ", dry run" : ", writes enabled") : "",
		 rst, ioread32(sw->bar + CMIC_CONFIG));
	if (rst != SOFT_RESET_SET_UP)
		dev_warn(&pdev->dev,
			 "switch not set up by the boot firmware (block reset 0x%08x, expected 0x%08x): it does so only when it loads an image over the network\n",
			 rst, SOFT_RESET_SET_UP);
	if (init) {
		/* only from the power-on reset of a start from the disk */
		if (rst != SOFT_RESET_DISK) {
			dev_err(&pdev->dev, "init: block reset 0x%08x, expected 0x%08x: %s, nothing done\n",
				rst, SOFT_RESET_DISK, rst == SOFT_RESET_SET_UP ?
				"already set up by the boot firmware" : "unknown state");
			err = -EIO;
			goto unmap;
		}
		mutex_lock(&sw->lock);
		err = run_init(sw);
		mutex_unlock(&sw->lock);
		if (err)
			goto unmap;
		sw->dbg = debugfs_create_dir(KBUILD_MODNAME, NULL);
		debugfs_create_file("plan", 0400, sw->dbg, sw, &plan_fops);
		debugfs_create_file("log", 0400, sw->dbg, sw, &log_fops);
		debugfs_create_file("led", 0400, sw->dbg, sw, &led_fops);
		sw_dev = sw;
		return 0;
	}
	if (rst != SOFT_RESET_SET_UP && access >= 1) {
		dev_err(&pdev->dev, "S-channel and MIIM access refused, nothing written\n");
		err = -EIO;
		goto unmap;
	}

	if (*steps) {
		mutex_lock(&sw->lock);
		err = run_steps(sw);
		mutex_unlock(&sw->lock);
		if (err)
			goto unmap;
	}
	if (phyled) {
		mutex_lock(&sw->lock);
		err = phyled_run(sw);
		mutex_unlock(&sw->lock);
		if (err)
			goto unmap;
	}
	if (access >= 1) {
		sw->dbg = debugfs_create_dir(KBUILD_MODNAME, NULL);
		debugfs_create_file("state", 0400, sw->dbg, sw, &state_fops);
		debugfs_create_file("counters", 0400, sw->dbg, sw, &counters_fops);
		debugfs_create_file("ports", 0400, sw->dbg, sw, &ports_fops);
		debugfs_create_file("mib", 0400, sw->dbg, sw, &mib_fops);
		debugfs_create_file("mtu", 0400, sw->dbg, sw, &mtu_fops);
		debugfs_create_file("trunk2", 0400, sw->dbg, sw, &trunk2_fops);
	}
	/* plain MMIO reads of the LED processor: at any access level */
	if (!sw->dbg)
		sw->dbg = debugfs_create_dir(KBUILD_MODNAME, NULL);
	debugfs_create_file("led", 0400, sw->dbg, sw, &led_fops);
	if (monitor) {
		err = mon_start(sw);
		if (err) {
			debugfs_remove(sw->dbg);
			goto unmap;
		}
		debugfs_create_file("link", 0400, sw->dbg, sw, &link_fops);
	}
	sw_dev = sw;
	return 0;

unmap:
	vfree(sw->plan);
	vfree(sw->log);
	iounmap(sw->bar);
release:
	release_mem_region(start, CMIC_BAR_SIZE);
free:
	kvfree(sw);
put:
	pci_dev_put(pdev);
	return err;
}

/*
 * Removal writes nothing but, with "leds", the link bits it set in the LED
 * processor data RAM, cleared again: the switch keeps its state (link
 * bitmap included) until the next reboot.
 */
static void __exit bcm53314_exit(void)
{
	struct bcm53314 *sw = sw_dev;

	/* the work item may requeue itself: cancel_delayed_work_sync() waits for it and stops it */
	if (sw->mon_started)
		cancel_delayed_work_sync(&sw->mon_work);
	debugfs_remove(sw->dbg);
	mutex_lock(&sw->lock);
	led_clear(sw);
	mutex_unlock(&sw->lock);
	vfree(sw->plan);
	vfree(sw->log);
	iounmap(sw->bar);
	release_mem_region(pci_resource_start(sw->pdev, 0), CMIC_BAR_SIZE);
	pci_dev_put(sw->pdev);
	kvfree(sw);
}

module_init(bcm53314_init);
module_exit(bcm53314_exit);

MODULE_DESCRIPTION("Port-based VLANs on the BCM53314 switch of the FortiGate 100D");
MODULE_LICENSE("GPL");
