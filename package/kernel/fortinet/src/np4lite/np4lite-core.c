// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet NP4Lite network processor (NP) Ethernet driver
 *
 * NP4Lite: network processor of the FortiSOC1/FortiSOC2: four ports, flow
 * engine, host interface, IPsec engine (FortiSOC2).
 * HIF: host interface, the DMA rings between the NP and the host.
 * HRX / HTX: host receive / host transmit engines of the HIF.
 * LIF: logical interface, the index a received frame is classified to,
 * and that a flow entry or a transmit descriptor targets.
 * IGR / EGR: ingress / egress port processing (classification, tags).
 * IHP / XHP / EHP: ingress / extensible / egress header processing.
 * SSE: session search engine, the flow engine.
 * TCE / TAE / DCE: traffic (per-LIF), traffic accounting (per-flow) and
 * drop (per-cause) counter engines. TPE: traffic shaping and accounting
 * engine. PBA: packet buffer allocator. PDQ: packet buffer queue between
 * two engines of the NP.
 *
 * The NP of the FortiSOC1 (e.g. the FortiGate 60C) has four RGMII ports,
 * numbered 0 to 3, and exchanges frames with the host through a single
 * pair of descriptor rings, the HIF: HRX towards the host, HTX from it.
 * Every frame on the rings is preceded by a 10-byte "host tag" header that
 * carries a LIF number; port N uses LIF N. Each port described in the
 * device tree gets its own net_device. The rings, the interrupt and NAPI
 * are shared, and received frames are dispatched on the source LIF of
 * their host tag.
 *
 * Register layout and values established by observation, for
 * interoperability. Registers below 0x400 are global (the 4 KiB window
 * repeats every 0x400), except for the per-port blocks, which are
 * replicated at port * 0x400.
 *
 * No reset or clock control is known for the NP: the driver takes over
 * the state left by the boot loader (HIF running out of memory of its own,
 * MAC address in the entry of LIF 0, reception of the ports cut) and
 * reprograms what it needs. For the same reason it cannot be unbound, and
 * as a module it cannot be unloaded.
 *
 * The MDIO controller of the board PHYs and switch also lives in the NP
 * register window. It is registered as the bus of the "mdio" child node.
 *
 * Received frames land in pages of a page pool, which go up the stack
 * with them (short frames are copied). Transmitted frames are copied to
 * coherent bounce buffers, or, with the "tx-zerocopy" private flag (on by
 * default), mapped where they are: host tag pushed into the headroom, one
 * descriptor for the linear part and one per page fragment.
 *
 * The flow engine of the NP forwards known flows between its ports without
 * the host. It offloads the netfilter flow tables the ports are bound to.
 *
 * The NP of the FortiSOC2 (e.g. the FortiGate 60D) keeps most of this
 * layout. It differs in what struct fnp4l_soc describes: RX descriptors
 * are completed in a separate write-back ring, the interrupt is routed by a
 * block of its own (IRQ map), the header check values are not the same,
 * and the flow engine has neither command ring nor message queue of its
 * own: it takes its commands on the TX ring and hands its messages over on
 * the RX ring, and its control register has moved. Its ingress lookup
 * windows hold noise after a power cycle and are rewritten at probe.
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/hashtable.h>
#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/kfifo.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/nvmem-consumer.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/of_reserved_mem.h>
#include <linux/phy.h>
#include <linux/phylink.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/rtnetlink.h>
#include <linux/sizes.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/u64_stats_sync.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>
#include <net/bonding.h>
#include <net/dsa.h>
#include <net/flow_offload.h>
#include <net/ip.h>
#include <net/page_pool/helpers.h>
#include <net/pkt_cls.h>
#ifdef CONFIG_FORTINET_NP4LITE_DSA
#include <linux/if_bridge.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/switchdev.h>
#endif

#include "np4lite.h"

#define DRV_NAME		"fortinet-np4lite"

static bool napi_threaded = true;
module_param(napi_threaded, bool, 0444);
MODULE_PARM_DESC(napi_threaded,
		 "Run the NAPI of the NP in a kernel thread instead of softirq (default 1; 0 on the kernel command line, fortinet_np4lite.napi_threaded=0, restores softirq NAPI)");

/* HRX: host receive ring */
#define NP4L_HRX_RING_BASE	0x000	/* ring base address */
#define NP4L_HRX_RING_BASE_HI	0x004	/* high part, always 0 */
#define NP4L_HRX_RING_SIZE	0x010	/* number of descriptors */
#define NP4L_HRX_RING_HEAD	0x014	/* written by the host */
#define NP4L_HRX_RING_FETCH	0x018	/* fetched by the NP */
#define NP4L_HRX_RING_DONE	0x01c	/* completed by the NP */
#define NP4L_HRX_CTRL		0x03c	/* run control */
#define NP4L_HRX_INT_STATUS	0x040	/* events, write back to acknowledge */
#define NP4L_HRX_INT_ENABLE	0x044	/* event mask, 1 = enabled */
/*
 * FortiSOC2: base of the write-back ring, where the NP completes the RX
 * descriptors, and a write-back configuration register set to 0x60000
 * once the HIF runs.
 */
#define NP4L_HRX_WB_BASE	0x008
#define NP4L_HRX_WB_BASE_HI	0x00c
#define NP4L_HRX_WB_CFG		0x058
#define NP4L_HRX_WB_CFG_INIT	0x00060000
/*
 * FortiSOC2: messages of the flow engine on the RX ring (bit 0), enabled
 * once the HIF is set up.
 */
#define NP4L_HRX_MSG_CTRL	0x07c
#define NP4L_HRX_MSG_EN		BIT(0)

/* HTX: host transmit ring, same layout */
#define NP4L_HTX_RING_BASE	0x080
#define NP4L_HTX_RING_BASE_HI	0x084
#define NP4L_HTX_RING_SIZE	0x090
#define NP4L_HTX_RING_HEAD	0x094
#define NP4L_HTX_RING_FETCH	0x098
#define NP4L_HTX_RING_DONE	0x09c
#define NP4L_HTX_CTRL		0x0bc
#define NP4L_HTX_INT_STATUS	0x0c0
#define NP4L_HTX_INT_ENABLE	0x0c4

#define NP4L_HIF_CTRL_RUN	3
#define NP4L_HIF_CTRL_STOP	0
#define NP4L_HIF_INT_ALL	0xf
#define NP4L_HIF_INT_FATAL	GENMASK(3, 2)

/* Per-port GMII block */
#define NP4L_PORT_STRIDE	0x400
#define NP4L_GMII_TX(port)	((port) * NP4L_PORT_STRIDE + 0x150)
#define NP4L_GMII_RX(port)	((port) * NP4L_PORT_STRIDE + 0x154)
/*
 * GMII_TX: bit 20 is always set, bits 19..18 hold the speed, bits 29..26
 * are set in full duplex; half duplex clears bits 31..24 and sets bits
 * 22..21.
 * GMII_RX: bit 0 selects the gigabit receive mode and must match the
 * speed of the link (set at 100 Mbit/s, no frame gets in; clear at 1000
 * Mbit/s, every frame has a CRC error), bit 1 cuts reception, bits 8..3
 * are an RX delay that is always left at 0. The boot loader leaves its
 * port with GMII_RX = 3, which lets no frame in.
 */
#define NP4L_GMII_TX_CLR	0x00cc0000
#define NP4L_GMII_TX_BIT20	BIT(20)
#define NP4L_GMII_TX_1000	BIT(19)
#define NP4L_GMII_TX_100	BIT(18)
#define NP4L_GMII_TX_FULL	GENMASK(29, 26)
#define NP4L_GMII_TX_HALF_CLR	GENMASK(31, 24)
#define NP4L_GMII_TX_HALF	GENMASK(22, 21)
#define NP4L_GMII_RX_CLR	GENMASK(8, 0)
#define NP4L_GMII_RX_1000	BIT(0)
#define NP4L_GMII_RX_CUT	BIT(1)

/*
 * Default LIF: bit 12 = enable, bits 11..10 = port, bits 9..0 = LIF given
 * to the frames of the port that the class table does not claim.
 * The boot loader leaves LIF 0 on every port (and the table empty), so
 * every port would reach the host as LIF 0.
 */
#define NP4L_IGR_DEFAULT_LIF(port)	((port) * NP4L_PORT_STRIDE + 0x118)
#define NP4L_IGR_DEFLIF_EN	BIT(12)
#define NP4L_IGR_DEFLIF_PORT	GENMASK(11, 10)
#define NP4L_IGR_DEFLIF_LIF	GENMASK(9, 0)

/*
 * 802.1Q recognition by the IGR: bit 16 = enable, bits 15..0 = TPID as the
 * NP reads it (0x81 for 81 00). When enabled, the IGR takes the tag off the
 * frame and hands its TCI to the host in the host tag, and the flow engine
 * keys on its VID: enabled on every port. The boot loader leaves 0, the
 * tag then stays in the frame. Insertion needs nothing but the TPID of the
 * EGR (+0x120), which the FortiSOC1 boot loader sets and which is written
 * on each port of the FortiSOC2.
 */
#define NP4L_IGR_VLAN_TPID(port)	((port) * NP4L_PORT_STRIDE + 0x110)
#define NP4L_IGR_TPID_EN	BIT(16)
#define NP4L_TPID_8021Q		0x81
#define NP4L_EGR_VLAN_TPID(port)	((port) * NP4L_PORT_STRIDE + 0x120)
/*
 * The other tag extractions of the IGR, same layout: second tag, port tag
 * and host tag. The boot loader leaves them at 0 (off), and so does the
 * driver, but for the port tag on the link to the switch of the FortiSOC2
 * (FORTINET_NP4LITE_DSA): with the "TPID" 0x0000, it matches the Broadcom
 * tag of the frames the switch sends to the host, whose first two bytes
 * (opcode 0) are 0. The IGR takes the tag off, and the low 12 bits of its
 * last two bytes (reason code, traffic class, source port) key the class
 * table, as port tag.
 */
#define NP4L_IGR_TAG2_TPID(port)	((port) * NP4L_PORT_STRIDE + 0x108)
#define NP4L_IGR_PORT_TAG_TPID(port)	((port) * NP4L_PORT_STRIDE + 0x10c)
#define NP4L_IGR_HTAG_TPID(port)	((port) * NP4L_PORT_STRIDE + 0x114)
/*
 * Port tag the EGR inserts after the source address of a frame sent on a
 * LIF whose egress tag has a port tag (entry B), none otherwise: this TPID,
 * then the port tag. The boot loader of the FortiSOC2 leaves 0x82 (82 00),
 * unused.
 */
#define NP4L_EGR_PORT_TAG_TPID(port)	((port) * NP4L_PORT_STRIDE + 0x128)

/*
 * Per-port ingress header checks. The boot loader leaves the whole block
 * at its reset value 0xffff: every check enabled with its "drop" action.
 * The TCP and UDP checks then drop every valid TCP or UDP frame, while ARP
 * and ICMP get through.
 */
#define NP4L_IHP_L3_ANOMALY_EN(port)	((port) * NP4L_PORT_STRIDE + 0x180)
#define NP4L_IHP_L3_ANOMALY_ACT(port)	((port) * NP4L_PORT_STRIDE + 0x184)
#define NP4L_IHP_L4_ANOMALY_EN(port)	((port) * NP4L_PORT_STRIDE + 0x188)
#define NP4L_IHP_L4_ANOMALY_ACT(port)	((port) * NP4L_PORT_STRIDE + 0x18c)
#define NP4L_IHP_L3_CHECK_EN(port)	((port) * NP4L_PORT_STRIDE + 0x190)
#define NP4L_IHP_L3_CHECK_ACT(port)	((port) * NP4L_PORT_STRIDE + 0x194)
/*
 * The L3 header checks enabled on every port (enable and action both
 * 0x1f). Bit 4 of the action is the one that drops the IPv4 frames with
 * options entering through the switch once the port tag extraction takes
 * its tag off (FORTINET_NP4LITE_DSA only).
 */
#define NP4L_IHP_L3_CHECK_ALL	0x1f
#define NP4L_IHP_L3_CHECK_DSA_HOST	BIT(4)
#define NP4L_IHP_TCP_CHECK_EN(port)	((port) * NP4L_PORT_STRIDE + 0x198)
#define NP4L_IHP_TCP_CHECK_ACT(port)	((port) * NP4L_PORT_STRIDE + 0x19c)
#define NP4L_IHP_UDP_CHECK_EN(port)	((port) * NP4L_PORT_STRIDE + 0x1a0)
#define NP4L_IHP_UDP_CHECK_ACT(port)	((port) * NP4L_PORT_STRIDE + 0x1a4)
#define NP4L_IHP_L4_CHECK_EN(port)	((port) * NP4L_PORT_STRIDE + 0x1a8)
#define NP4L_IHP_L4_CHECK_ACT(port)	((port) * NP4L_PORT_STRIDE + 0x1ac)
#define NP4L_IHP_CTRL(port)	((port) * NP4L_PORT_STRIDE + 0x1b8)
#define NP4L_IHP_UDP_ESP_MIN_LEN(port) ((port) * NP4L_PORT_STRIDE + 0x1bc)
#define NP4L_IHP_L4_MIN_LEN(port)	((port) * NP4L_PORT_STRIDE + 0x1c4)
#define NP4L_IHP_UDP_ESP_PROTO0(port) ((port) * NP4L_PORT_STRIDE + 0x1cc)

/*
 * FortiSOC2: header checks of the frames that come from no port (the host,
 * IPsec), a single block with the layout of the per-port one, programmed
 * like it.
 */
#define NP4L_XHP_BASE		0xb00

/*
 * L3 anomaly checks of the IHP, one bit per IPv4 option in both the
 * enable and the action register. Enabled with action 0, a frame with the
 * option leaves the flow engine path and goes to the host, marked in its
 * RX descriptor (NP4L_RX_ANOMALY); with the action bit set, as at reset, it
 * is dropped. Only the options the IP layer acts on when forwarding.
 */
#define NP4L_ANOMALY_L3_RR	BIT(2)	/* record route */
#define NP4L_ANOMALY_L3_SSRR	BIT(3)	/* strict source route */
#define NP4L_ANOMALY_L3_LSRR	BIT(4)	/* loose source route */
#define NP4L_ANOMALY_L3_TS	BIT(7)	/* timestamp */
#define NP4L_ANOMALY_L3_IPOPT	(NP4L_ANOMALY_L3_RR | NP4L_ANOMALY_L3_SSRR | \
					 NP4L_ANOMALY_L3_LSRR | NP4L_ANOMALY_L3_TS)

/*
 * Indirect table access ports: a command word (entry index, bit 30 =
 * write, bit 31 = busy) followed by the 64-bit entry.
 */
#define NP4L_TBL_LIF		0x300	/* LIF table */
#define NP4L_TBL_CLASS		0x320	/* sorted tables: class, VLAN action */
#define NP4L_TBL_TRAFFIC_CNT	0x280	/* TCE and TAE counters, clear on read */
#define NP4L_TBL_DROP_CNT	0x2a0	/* DCE counters, clear on read */
#define NP4L_TBL_CMD		0x0
#define NP4L_TBL_DATA_LO	0x4
#define NP4L_TBL_DATA_HI	0x8
#define NP4L_TBL_CMD_WRITE	BIT(30)
#define NP4L_TBL_CMD_BUSY	BIT(31)
#define NP4L_LIF_ENTRY_B	64	/* entry B of LIF i is at i + 64 */
/* Entry A (MAC filter): lo = MAC bytes 0..3, hi[15:0] = MAC bytes 4..5 */
#define NP4L_LIFA_PROMISC	BIT(16)
#define NP4L_LIFA_BCAST		BIT(17)
#define NP4L_LIFA_VALID		BIT(18)
#define NP4L_LIFA_EGR_CNT	GENMASK(31, 25)	/* egress counter (TCE) */
/* Entry B */
#define NP4L_LIFB_MTU		GENMASK(13, 0)
#define NP4L_LIFB_PORT		GENMASK(15, 14)	/* port */
#define NP4L_LIFB_EGR_TAG_LO	GENMASK(31, 16)	/* egress tag, low part */
#define NP4L_LIFB_EGR_PORT_TAG	GENMASK(27, 16)	/* of it, the port tag TCI */
#define NP4L_LIFB_EGR_TAG_HI	GENMASK(8, 0)	/* egress tag, high part */
#define NP4L_LIFB_RX_ACTION	GENMASK(20, 19)	/* 0 = LIF shut down */
#define NP4L_LIFB_TX_ACTION	GENMASK(24, 23)
#define NP4L_LIFB_IGR_CNT	GENMASK(31, 25)	/* ingress counter (TCE) */
/*
 * Values the boot loader programs in LIF 0, used for every LIF: ingress
 * counter 1, egress counter 2, shared by every LIF that uses them.
 */
#define NP4L_TCE_LOADER_IGR	1
#define NP4L_TCE_LOADER_EGR	2
#define NP4L_LIFA_HI_INIT	NP4L_LIFA_VALID
/*
 * Value of the FortiSOC1 boot loader. On the FortiSOC2 only the layout of
 * the entry is known to be the same; this value works there.
 */
#define NP4L_LIFB_HI_INIT	0x01980000
/*
 * MTU field of a LIF (entry B): the largest IP packet, IP header included
 * and link header excluded, the NP sends out whole on the LIF. A larger
 * packet it builds itself (ESP from the IPsec engine) leaves in IP
 * fragments that fit: with 1536, ESP packets of 1560 bytes left with
 * their last fragment at offset 1512, after a first one of 1532 bytes
 * that a 1500-byte link drops. Established by observation. Received
 * frames are bounded by the IGR length window (fnp4l_loader_regs).
 *  - the LIF of a port holds the MTU of its net_device, kept by
 *    fnp4l_change_mtu();
 *  - a DSA conduit and the LIFs of its switch ports keep the value the
 *    boot loader programs in LIF 0, NP4L_LIF_MTU, room for the switch tag.
 */
#define NP4L_LIF_MTU		1536

/* Offset of the lookup windows of port 0..3: +0, +4, +0x20, +0x24 */
static u32 fnp4l_igr_win(u32 port)
{
	return (port >> 1) * 0x20 + (port & 1) * 4;
}

/*
 * Lookup windows of the IGR, one pair per port, outside the per-port banks:
 * "bit 31 | n << 16 | base" covers entries base..base + n - 1 of
 * NP4L_TBL_CLASS, 0 an empty table. The width of n and base is not known;
 * the driver uses small values only.
 *  - class table: classifies the frames of the port to a LIF. The boot
 *    loader leaves bit 31 clear on every port, the default LIF then
 *    classifies them, and the VLAN action table is never looked up. It
 *    covers entries 0..5 on port 0 (the switch tags) and entry 5 + k on
 *    port k: the LIF of the port, for frames without tags.
 *  - VLAN action: what to do with the frames of a (LIF, VID) pair, looked
 *    up in class mode only. A VID without an entry, or an empty window,
 *    sends the frame to the host.
 */
#define NP4L_IGR_CLASS_WIN(port)	(0x340 + fnp4l_igr_win(port))
#define NP4L_IGR_VLAN_WIN(port)	(0x350 + fnp4l_igr_win(port))
/*
 * EtherType table of the port, looked up in class mode (hw 1, like the
 * two others). Neither the driver nor the FortiSOC1 boot loader uses it;
 * 0 is an empty table. On the FortiSOC2 the window holds noise after a
 * power cycle, bit 31 possibly set.
 */
#define NP4L_IGR_ETYPE_WIN(port)	(0x348 + fnp4l_igr_win(port))
#define NP4L_IGR_WIN_EN		BIT(31)
#define NP4L_IGR_WIN_COUNT	GENMASK(30, 16)
#define NP4L_IGR_WIN_BASE	GENMASK(15, 0)
/* Class entry of a port without tags, as the boot loader writes it */
#define NP4L_CLASS_IDX(port)	(5 + (port))
#define NP4L_CLASS_LIF_LO	GENMASK(31, 24)	/* LIF, low part */
#define NP4L_CLASS_LIF_HI	GENMASK(1, 0)	/* LIF, high part */
/* Key of a class entry, the table sorted by increasing key */
#define NP4L_CLASS_PORT_TAG	GENMASK(23, 12)
#define NP4L_CLASS_TAG2		GENMASK(11, 0)
/*
 * VLAN action entry. The table is sorted by increasing lo[21:0], LIF << 12
 * | VID, and searched by halves. Op 0 drops the frames, 1 looks the flow
 * table up. The forward LIF and VID serve relaying from VLAN to VLAN; the
 * driver sets them to the LIF and VID of the entry, as tested on hardware.
 */
#define NP4L_VLAN_ACT_VID	GENMASK(11, 0)
#define NP4L_VLAN_ACT_LIF	GENMASK(21, 12)
#define NP4L_VLAN_ACT_FWD_VID_LO	GENMASK(31, 24)	/* forward VID, low part */
#define NP4L_VLAN_ACT_FWD_VID_HI	GENMASK(3, 0)	/* forward VID, high part */
#define NP4L_VLAN_ACT_FWD_LIF	GENMASK(13, 4)
#define NP4L_VLAN_ACT_OP	GENMASK(15, 14)
#define NP4L_VLAN_ACT_OP_FLOW	1
/* Area of NP4L_TBL_CLASS given to the VLAN action table of each port */
#define NP4L_VLAN_ACT_MAX	32
#define NP4L_VLAN_ACT_BASE(port)	(16 + NP4L_VLAN_ACT_MAX * (port))

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/*
 * FORTINET_NP4LITE_DSA: a LIF per user port of a BCM53128 switch (ports
 * 0 to 7, the IMP being port 8), given by the
 * "fortinet,switch-logical-interfaces" of its conduit, which keeps its
 * "fortinet,logical-interface" for the frames of the switch that are not
 * classified by port. Their class entries, one per port and per value of
 * the reason code and traffic class of the tag the driver expects
 * (NP4L_DSA_RC_MASK_DEFAULT, switch_tc_mask), sit past the VLAN action
 * tables of the ports, in a table of 512 entries: the whole area for the
 * conduit alone on its NP, a window of NP4L_DSA_CLASS_WIN entries per link
 * otherwise.
 */
#define NP4L_DSA_NR_PORTS	8
#define NP4L_DSA_NONE		0xff
#define NP4L_DSA_CLASS_BASE	NP4L_VLAN_ACT_BASE(NP4L_NR_PORTS)
#define NP4L_DSA_CLASS_MAX	256
#define NP4L_DSA_CLASS_WIN	(NP4L_DSA_CLASS_MAX / NP4L_NR_PORTS)
static_assert(NP4L_DSA_CLASS_BASE + NP4L_DSA_CLASS_MAX <= 512);
/*
 * Last LIF of a switch port or a conduit: 20 LIFs (0 to 19) cover the
 * FortiGate 90D. The LIF bitmaps of the switch ports are unsigned longs.
 */
#define NP4L_DSA_LIF_LAST	19
static_assert(NP4L_DSA_LIF_LAST < BITS_PER_LONG);
/*
 * Copies of the first class entry written ahead of it (tested on
 * hardware): with the entry of dmz (key 0) at the base of the window, the
 * frames of dmz all missed the class table while those of internal1 (key
 * 7, the last entry) were classified. The engine either never matches the
 * first entry of a window, or never matches key 0. With a copy of the
 * first entry at the base (same key, same LIF, the table stays sorted),
 * the first reading finds the copy at base + 1; under the second, dmz
 * still misses. Tests settled it: key 0 is never matched, other keys
 * anywhere in the window are. The copy stays, harmless: under class 7 the first
 * entry is key 0 still (class 0 kept in switch_tc_mask), never matched.
 */
#define NP4L_DSA_CLASS_PAD	1
/* Port tag of a frame of the switch: bits 11..0 of tag bytes 2 and 3 */
#define NP4L_DSA_PORT_TAG(rc, tc, p)	(((rc) & 0xf) << 8 | ((tc) & 7) << 5 | (p))
#define NP4L_DSA_TAG_LEN	4
/*
 * Port tag "TPID" of the EGR of the link of a conduit, 20 00: with the port
 * tag BIT(port) of the LIF of a switch port, the EGR inserts the tag
 * 20 00 00 BIT(port),
 * the one tag_brcm puts on the frames it sends through that port (opcode 1,
 * forwarded to the ports of the map whatever the tables of the switch).
 */
#define NP4L_DSA_EGR_PORT_TAG	0x20

/*
 * Not validated on hardware yet: default off. Offload the flows
 * between two different LIFs of one conduit (two ports of one switch, a
 * port and a slave of a bond on that switch...), into and out of the
 * same link of the NP, as it does for a bond of NP ports (on the 60D, the
 * NP sends a frame back through its link and LIF of entry).
 * Read at each insertion; never a flow back to its own LIF.
 */
static bool same_switch_offload;
module_param(same_switch_offload, bool, 0644);
MODULE_PARM_DESC(same_switch_offload,
		 "FortiSOC2 switch ports: offload flows between two ports of one switch (default off: through the host)");
/*
 * Low nibbles of the reason code of the switch tag in the class table,
 * one bit each: 0, 2, 4 and 6. The BCM53128 gives the frames of a
 * standalone port the reason 0x20 and those of a bridged port the
 * reason 0x04 (measured), which a class table of nibble 0 alone misses
 * (to the LIF of the conduit). Nibbles 2 and 6, never seen, only cost
 * class entries.
 */
#define NP4L_DSA_RC_MASK_DEFAULT	(BIT(0) | BIT(2) | BIT(4) | BIT(6))
/*
 * Classes 0 and 7: 0 is the class of every frame under b53 as is
 * (measured), 7 the one of every frame with brcm,port-traffic-class = <7>
 * (port-based QoS). Key 0, that of dmz in class 0, is never matched
 * (measured): dmz needs class 7. Both keep one image good for a switch
 * with or without that property.
 */
static unsigned int switch_tc_mask = BIT(0) | BIT(7);
module_param(switch_tc_mask, uint, 0444);
MODULE_PARM_DESC(switch_tc_mask,
		 "FortiSOC2 switch ports: traffic classes in the class table, one bit each (0x81: classes 0 and 7; 0xff: all)");
/*
 * Flows routed through a bridge of switch ports offloaded when the bridge
 * is offloaded to the switches of one DSA tree (one switch, or both
 * switches of the 90D joined by their cascade), not VLAN filtering
 * (fnp4l_dsa_bridged()). The LIF of such a port takes the address of
 * the bridge and is not promiscuous. 0: such ports refused, routed by
 * the host.
 * Live: a change re-reads the ports, flows of the ports that change are
 * torn down.
 */
static bool bridge_offload = true;
static int fnp4l_bridge_param(const char *val,
			      const struct kernel_param *kp);
static const struct kernel_param_ops fnp4l_bridge_ops = {
	.set = fnp4l_bridge_param,
	.get = param_get_bool,
};
module_param_cb(bridge_offload, &fnp4l_bridge_ops, &bridge_offload,
		0644);
MODULE_PARM_DESC(bridge_offload,
		 "FortiSOC2 switch ports: offload flows routed through a bridge of ports of the switches of one DSA tree (0: such ports refused, routed by the host)");
#endif /* CONFIG_FORTINET_NP4LITE_DSA */

/*
 * Traffic counters (TCE): entries of table NP4L_TBL_TRAFFIC_CNT, 128
 * entries shared with the per-flow counters (TAE), the first 8 taken by
 * the boot loader. Each LIF points at an ingress and an egress counter. They
 * count every frame of the LIF, those the flow engine forwards and those
 * of the host alike, the frame length without FCS in bytes. A read clears
 * the entry: each has a single reader, the counter work for those of the
 * ports, which folds them into 64-bit totals, the flow statistics for the
 * per-flow ones. LIF N gets the entries 8 + 2N and 9 + 2N.
 *
 * Entry: bit 63 set for a counter (clear: a rate limiter), bytes in bits
 * 62..29 (34 bits), packets in bits 28..0. At 1 Gbit/s, the byte count
 * wraps after about 137 seconds.
 */
#define NP4L_TCE_IGR(lif)	(8 + 2 * (lif))
#define NP4L_TCE_EGR(lif)	(9 + 2 * (lif))
#define NP4L_TCE_HI_CNT		BIT(31)
#define NP4L_TCE_HI_BYTES	GENMASK(30, 0)	/* bytes, bits 33..3 */
#define NP4L_TCE_LO_BYTES	GENMASK(31, 29)	/* bytes, bits 2..0 */
#define NP4L_TCE_LO_PKTS	GENMASK(28, 0)
#define NP4L_TCE_PERIOD		HZ
#define NP4L_TCE_ENTRIES	128
/*
 * TPE configuration: with it the flow engine updates the flow state,
 * per-flow counters included; without it, it does not update the
 * per-flow counters an entry points at (the port counters count anyway).
 * The low bits are a refresh period of 266 MHz / 512 for the rate
 * limiters, which no entry used here is.
 */
#define NP4L_TPE_CONFIG		0x2c0
#define NP4L_TPE_CONFIG_INIT	0xc007ed6b
/*
 * Last LIF a previous system may have left programmed (LIF 1 to 8). After
 * a watchdog reset, those LIF entries are still valid in the table SRAM
 * and point at their traffic counters, up to entry 25. Frames reaching
 * such a leftover LIF (through a leftover class entry) would be counted
 * there: those
 * entries are never used as per-flow counters. The leftover LIF entries
 * themselves are left alone, no LIF past those of the ports being written.
 * With FORTINET_NP4LITE_DSA, the switch ports and their conduits take
 * LIFs up to NP4L_DSA_LIF_LAST (19), whose entries go up to 47 (the LIFs
 * of the switch ports share those of their conduit): per-flow counters
 * start past them.
 */
#ifdef CONFIG_FORTINET_NP4LITE_DSA
#define NP4L_LIF_FW_LAST	NP4L_DSA_LIF_LAST
#else
#define NP4L_LIF_FW_LAST	8
#endif
static_assert(NP4L_NR_PORTS - 1 <= NP4L_LIF_FW_LAST);
/* First entry past all of these, for per-flow counters (TAE) */
#define NP4L_TCE_FIRST_FREE	(NP4L_TCE_EGR(NP4L_LIF_FW_LAST) + 1)
static_assert(NP4L_TCE_FIRST_FREE <= NP4L_TCE_ENTRIES);

/*
 * Flow engine (SSE) of the NP. It looks the 5-tuple of the frames of a LIF
 * up in a hash table and forwards the hits itself, with the MAC header
 * rewritten; the misses go to the host. Its tables live in system memory
 * (hash table, then overflow table, 64-byte entries) and the host never
 * accesses them: it posts commands (insert, delete, flush) to a ring the
 * engine reads by DMA. There is no per-command acknowledgment, only the
 * fetch index, global counters and failure bits in the control register.
 *
 * Writing the reset bit alone holds the engine in reset with its
 * interrupts disabled, which is the state the boot loader leaves.
 */
#define NP4L_SSE_CTRL		0x200	/* control and status */
#define NP4L_SSE_CTRL_RESET	BIT(31)
#define NP4L_SSE_CTRL_RUN	BIT(28)
#define NP4L_SSE_CTRL_DEL_FAIL	BIT(5)	/* a delete failed */
#define NP4L_SSE_CTRL_INS_FAIL	BIT(3)	/* an insertion failed */
#define NP4L_SSE_CTRL_FATAL	(BIT(1) | BIT(0)) /* DMA error, bad command */
#define NP4L_SSE_RING_BASE	0x204	/* command ring base address */
#define NP4L_SSE_RING_SIZE	0x20c	/* command ring length, in 64-bit words */
#define NP4L_SSE_RING_HEAD	0x210	/* written by the host, doorbell */
#define NP4L_SSE_RING_FETCH	0x214	/* fetched by the engine */
#define NP4L_SSE_FAIL_IRQ_CTRL	0x224
#define NP4L_SSE_SEARCH_CTRL	0x22c
#define NP4L_SSE_PHT_CFG	0x230	/* hash table */
#define NP4L_SSE_OFT_CFG	0x234	/* overflow table */
#define NP4L_SSE_INSERTS	0x244	/* insertions processed */
#define NP4L_SSE_INSERTS_OK	0x248	/* insertions that succeeded */
#define NP4L_SSE_DELETES	0x24c	/* deletions processed */
#define NP4L_SSE_DELETES_OK	0x250	/* deletions that succeeded */
#define NP4L_SSE_ENTRIES	0x254	/* entries in the tables */
#define NP4L_SSE_HASH_CTRL	0x264
/*
 * Entry ageing: the engine counts ticks of AGE_TICK core clock cycles (one
 * second with the value of the boot loader) and, every AGE_CTRL[15:0] ticks,
 * queues a message for each entry frames hit during that period. It never
 * removes an entry by itself. The driver only reads them.
 */
#define NP4L_SSE_AGE_TICK	0x268
#define NP4L_SSE_AGE_CTRL	0x26c
#define NP4L_SSE_AGE_CTRL_PERIOD	GENMASK(15, 0)
#define NP4L_SSE_AGE_DEFAULT	40	/* seconds, period of the ageing messages */

/*
 * Initial values. Table registers: bits 31..24 hold the
 * base address in 4 MiB units, the low bits the size in 128-byte units
 * (overflow table: minus 64 entries). The hash control value matches a
 * 16 MiB hash table.
 */
#define NP4L_SSE_FAIL_IRQ_CTRL_INIT	0x00100100
#define NP4L_SSE_SEARCH_CTRL_INIT	0x3f
#define NP4L_SSE_HASH_CTRL_INIT	0x88ffff80
#define NP4L_SSE_TBL_BASE	GENMASK(31, 24)
#define NP4L_SSE_TBL_BASE_SHIFT	22
#define NP4L_SSE_PHT_SIZE	SZ_16M
#define NP4L_SSE_OFT_SIZE	(SZ_32M + SZ_8M)
#define NP4L_SSE_TBL_SIZE	(NP4L_SSE_PHT_SIZE + NP4L_SSE_OFT_SIZE)
#define NP4L_SSE_RING_WORDS	8192	/* ring length, power of 2 */
#define NP4L_SSE_RING_BYTES	((NP4L_SSE_RING_WORDS + 1) * 8)	/* + guard word */

/*
 * Message queue, from the NP to the host: a ring of 64-bit words the NP
 * fills (head) and the host empties (fetch index), both counted
 * in words. The engine is only started with this queue pointing at memory
 * of the driver. Its interrupts stay disabled: the driver reads the queue
 * when the flow table asks for the activity of its flows.
 */
#define NP4L_MSG_CTRL		0x3a0
#define NP4L_MSG_CTRL_RUN	BIT(31)
#define NP4L_MSG_CTRL_OFF	GENMASK(26, 24)
#define NP4L_MSG_CTRL_IRQ_EN	GENMASK(17, 16)
#define NP4L_MSG_RING_BASE	0x3a4
#define NP4L_MSG_RING_SIZE	0x3a8	/* in 64-bit words */
#define NP4L_MSG_RING_HEAD	0x3ac	/* written by the NP */
#define NP4L_MSG_RING_FETCH	0x3b0	/* written by the host */
#define NP4L_MSG_WIN_CTRL	0x3b4
#define NP4L_MSG_INT_CTRL	0x3b8
#define NP4L_MSG_SIZE		SZ_32K
#define NP4L_MSG_RING_WORDS	(NP4L_MSG_SIZE / 8 - 32)
#define NP4L_MSG_WIN_CTRL_INIT	0x003f0008
#define NP4L_MSG_INT_CTRL_INIT	0x007f0040

/*
 * The command ring and the message queue live in a reserved region
 * outside of the memory of the kernel, as the flow tables do: after a
 * panic or an emergency restart, the engine and its message queue may
 * still run while the next kernel boots.
 */
#define NP4L_SSE_QMEM_RING	0
#define NP4L_SSE_QMEM_MSG	0x20000
#define NP4L_SSE_QMEM_SIZE	(NP4L_SSE_QMEM_MSG + NP4L_MSG_SIZE)

/*
 * FortiSOC2 (NP4Lite) flow engine. The tables and the counters are those
 * of the FortiSOC1, the rest differs:
 *  - the control register (reset, run) is at 0x20c; 0x200..0x208 is the
 *    access port of the port-to-trunk table (NP4L_TBL_* layout, 64
 *    entries), which must hold the identity: the boot loader does not fill
 *    it, and the table does not survive a power cycle (only a warm
 *    restart): the driver fills it at each start of the engine;
 *  - commands go on the TX ring, one descriptor each (NP4L_TX_CMD), without
 *    host tag;
 *  - messages come on the RX ring, several in a buffer, without host tag,
 *    marked in the completion (NP4L_RX_MSG), once enabled by
 *    NP4L_HRX_MSG_CTRL.
 * No interrupt of the engine is used, and its control register is never
 * read back.
 */
#define NP4L_SSE_FSOC2_PORT_TRUNK	0x200
#define NP4L_SSE_FSOC2_PORT_TRUNK_ENTRIES	64
#define NP4L_SSE_FSOC2_CTRL	0x20c
#define NP4L_SSE_FSOC2_HOSTQ_MAP0	0x21c
#define NP4L_SSE_FSOC2_HOSTQ_MAP1	0x220
/*
 * One tick a second at 333 MHz; only written if 0. The boot loader leaves
 * 0x0fe502aa, measured to tick once a second too: kept.
 */
#define NP4L_SSE_FSOC2_AGE_TICK_INIT	0x13d92d40
/* Bits set in AGE_CTRL besides the period */
#define NP4L_SSE_FSOC2_AGE_CTRL_INIT	0x010f0000
/* Ageing keys between the RX path and the flow table, power of 2 */
#define NP4L_MSG_FIFO_LEN	1024

/*
 * Commands of the flow engine: a header word (bit 7 of the first byte
 * always set, opcode in bits 4..0, then the length of the command in
 * 64-bit words), followed by the flow key for an insertion or a deletion.
 * The engine reads them as a byte image, in the layout below.
 */
#define NP4L_SSE_CMD_VALID	BIT(7)
#define NP4L_SSE_OP_INSERT	1
#define NP4L_SSE_OP_DELETE	2
#define NP4L_SSE_OP_FLUSH	15

struct fnp4l_sse_hdr {
	u8 op;
	u8 len;
	u8 rsvd[6];
} __packed;

/*
 * Flow key, bytes 8..23 of an insertion or a deletion: addresses and ports
 * in network order, then the IP protocol, the VLAN ID of the frame as the
 * IGR extracted it (bits 19..8 of the little endian word at byte 20: byte
 * 21 and the low nibble of byte 22, 0 = untagged) and the input LIF (bits
 * 13..4 of the little endian half-word at byte 22).
 */
struct fnp4l_sse_key {
	__be32 saddr;
	__be32 daddr;
	/* Ports, or the SPI of an inbound SA (fnp4l_sse_spi()) */
	struct_group(ports, __be16 sport; __be16 dport;);
	u8 proto;
	u8 vid_lo;
	__le16 lif;
} __packed;

#define NP4L_SSE_KEY_LIF	GENMASK(13, 4)
#define NP4L_SSE_KEY_VID_HI	GENMASK(3, 0)

/*
 * Message header, first word: source, type, length of the message in
 * 64-bit words (header included), then fields the driver does not use.
 * An ageing message carries the key of the entry, as inserted except for
 * bit 15 of the LIF half-word, which the NP sets.
 */
#define NP4L_MSG_TYPE_TIMEOUT	2
#define NP4L_MSG_MAX_WORDS	8

struct fnp4l_msg_hdr {
	u8 src;
	u8 type;
	u8 len;
	u8 rsvd[5];
} __packed;

struct fnp4l_msg_timeout {
	struct fnp4l_msg_hdr hdr;
	struct fnp4l_sse_key key;
} __packed;

/*
 * FortiSOC2: an ageing message is one word longer, with two more words.
 * They are not counts since the previous message: measured, the second
 * one is always 1 and the first one the length of the last frame (without
 * FCS) only. They are kept for the debug, and never counted.
 */
struct fnp4l_msg_timeout2 {
	struct fnp4l_msg_timeout timeout;
	__le32 last_len;
	__le32 one;
} __packed;

/* What the RX path keeps of an ageing message, words 0 if none */
struct fnp4l_age {
	struct fnp4l_sse_key key;
	u32 last_len;
	u32 one;
};

struct fnp4l_sse_del {
	struct fnp4l_sse_hdr hdr;
	struct fnp4l_sse_key key;
} __packed;

/*
 * Insertion. After the key: action flags, a fourth action byte and the
 * index of an IPsec SA (little endian), both set for IPsec only, output
 * LIF, largest IP packet of the output, 802.1Q tag
 * to push (big endian, 0 = none), next-hop MAC address, the tuple after
 * translation (the key without NAT), and an accounting entry (0 = none).
 * The source MAC address is the one of the output LIF. Bytes 32 to 37
 * hold counts the engine keeps, 0 on insertion.
 */
struct fnp4l_sse_ins {
	struct fnp4l_sse_hdr hdr;
	struct fnp4l_sse_key key;
	u8 rsvd0[4];
	u8 act[3];
	u8 act3;
	u8 rsvd2[6];
	__le16 sa;
	u8 rsvd3[4];
	u8 out_lif;
	u8 tos;
	__le16 mtu;
	__be16 tci;
	u8 h_dest[ETH_ALEN];
	__be32 xsaddr;
	__be32 xdaddr;
	__be16 xsport;
	__be16 xdport;
	__le32 acct;
} __packed;

static_assert(sizeof(struct fnp4l_sse_del) == 24);
static_assert(sizeof(struct fnp4l_sse_ins) == 72);
static_assert(offsetof(struct fnp4l_sse_ins, act) == 28);
static_assert(offsetof(struct fnp4l_sse_ins, act3) == 31);
static_assert(offsetof(struct fnp4l_sse_ins, sa) == 38);
static_assert(offsetof(struct fnp4l_sse_ins, out_lif) == 44);
static_assert(offsetof(struct fnp4l_sse_ins, h_dest) == 50);
static_assert(offsetof(struct fnp4l_sse_ins, acct) == 68);
static_assert(sizeof(struct fnp4l_msg_timeout) == 24);
static_assert(sizeof(struct fnp4l_msg_timeout2) == 32);

/*
 * Accounting word of an insertion: counter entry (TAE) the engine adds the
 * frames of the entry to, in the table of the traffic counters.
 */
#define NP4L_SSE_ACCT_EN	BIT(30)
#define NP4L_SSE_ACCT_IDX	GENMASK(26, 16)

/*
 * First action byte of a routed flow without NAT: rewrite the MAC header
 * (bit 3), routed (bit 2), and bit 7, of unknown meaning.
 */
#define NP4L_SSE_ACT_ROUTED	(BIT(7) | BIT(3) | BIT(2))
#define NP4L_SSE_ACT_VLAN	BIT(4)	/* push the 802.1Q tag of "tci" */
#define NP4L_SSE_ACT_SNAT	BIT(5)	/* source address translated */
#define NP4L_SSE_ACT_DNAT	BIT(6)	/* destination address translated */
/*
 * Second and fourth action bytes of a flow the flow engine sends to the
 * IPsec engine, with the index of its outbound SA in "sa" and the MTU
 * of the tunnel: enough to chain the flow to the IPsec engine without any
 * other write; meaning not known otherwise (FIXME: their exact semantics).
 */
#define NP4L_SSE_ACT1_IPSEC	BIT(5)
#define NP4L_SSE_ACT3_IPSEC	BIT(0)
/* Third action byte */
#define NP4L_SSE_ACT_SPAT	BIT(5)	/* source port translated */
#define NP4L_SSE_ACT_DPAT	BIT(6)	/* destination port translated */

/* Engine state, under sse_lock */
enum fnp4l_sse_state {
	NP4L_SSE_DOWN,		/* in reset, can be started */
	NP4L_SSE_UP,
	NP4L_SSE_FAILED,	/* in reset after an error, until every port unbinds */
	NP4L_SSE_SHUTDOWN,	/* in reset for good */
};

/* RX action of a LIF: 1 = look the flow table up, 3 = everything to the host */
#define NP4L_RX_ACTION_FLOW	1
#define NP4L_RX_ACTION_HOST	3

#define NP4L_FT_MAX_FLOWS	8192
#define NP4L_FT_HASH_BITS	10

/* Flow engine commands take microseconds: spin, then sleep. */
#define NP4L_SSE_SPIN_US	1000
#define NP4L_SSE_SLEEP_US	1000
#define NP4L_SSE_TIMEOUT_US	200000

#define NP4L_TOP_STAT		0x380	/* OR of the enabled sources, read only */
#define NP4L_TOP_STAT_HIF	(BIT(0) | BIT(4))
#define NP4L_TOP_PBUF_BLOCKS	0x390	/* size of the packet buffer, in blocks */
#define NP4L_TOP_PBUF_BASE	0x394	/* physical address of the packet buffer */
/*
 * Size of a packet buffer block: 0x80 blocks fill an 8 MiB packet buffer
 * on the FortiSOC1. Taken to be the same on the FortiSOC2, whose boot
 * loader sets 0x100 blocks.
 */
#define NP4L_PBA_BLOCK		SZ_64K

/*
 * FortiSOC2: routing of the NP sources to the SoC interrupt controller
 * ("irq-map" register block). Output k of the AXI map drives SoC line
 * 8 + k and carries the sources set in NP4L_IRQMAP_OUT(k); the device tree
 * line of the NP, 20, is output 12. The status gathers the sources: bits
 * 16 and 20 are the HIF, bit 24 the board pins (not used,
 * NP4L_PERIPH_INT_ENABLE stays 0).
 */
#define NP4L_IRQMAP_STATUS	0x080
#define NP4L_IRQMAP_ENABLE	0x084	/* 1 = enabled */
#define NP4L_IRQMAP_OUT(k)	(0x0c0 + 4 * (k))
#define NP4L_IRQMAP_OUT_NP	12
#define NP4L_IRQMAP_SRC_HIF	(BIT(16) | BIT(20))
/*
 * Output 0 (SoC line 8) carries source 8, the crypto engine at NP + 0x1900:
 * routed here for the fortinet,fsoc2-crypto driver, which cannot map this
 * block.
 */
#define NP4L_IRQMAP_OUT_CRYPTO	0
#define NP4L_IRQMAP_SRC_CRYPTO	BIT(8)

/*
 * Memory regions of the node: packet buffer, memory of the boot loader
 * (not used by the driver), then, for flow offload, flow tables and, on
 * the FortiSOC1 only, command and message queues
 */
#define NP4L_MEM_PBUF		0
#define NP4L_MEM_FLOW		2
#define NP4L_MEM_QUEUES		3	/* FortiSOC1 */
#define NP4L_MEM_SA		3	/* FortiSOC2, IPsec security associations */
#define NP4L_MEM_NR		4

/* MDIO controller */
#define NP4L_MDIO_CMD		0x398
#define NP4L_MDIO_CFG		0x39c
#define NP4L_MDIO_BUSY		BIT(31)
#define NP4L_MDIO_START		BIT(28)
#define NP4L_MDIO_OP_READ	BIT(27)
#define NP4L_MDIO_OP_WRITE	BIT(26)
#define NP4L_MDIO_PHY		GENMASK(25, 21)
#define NP4L_MDIO_REG		GENMASK(20, 16)
#define NP4L_MDIO_DATA		GENMASK(15, 0)
/* MDC clock and mode, as programmed by the boot loader */
#define NP4L_MDIO_CFG_INIT	0x38306300
#define NP4L_MDIO_TIMEOUT_US	10000

/*
 * GPIO pins of the NP (FortiSOC2 board: reset of the switch link on pin 0,
 * of the wan1 PHY on pin 2, of the wan2 PHY on pin 4, all active low; pins
 * 1, 3, 5 are their interrupts). Plain registers, read-modify-write.
 */
#define NP4L_GPIO_IN		0x3e0	/* input level */
#define NP4L_GPIO_OUT		0x3e4	/* output level */
#define NP4L_GPIO_OE		0x3e8	/* output enable */
#define NP4L_GPIO_RESET_LOW_MS	100
#define NP4L_GPIO_RESET_WAIT_MS	100

/* Board interrupt pins (switch and PHYs), also routed to the NP interrupt */
#define NP4L_PERIPH_INT_ENABLE	0x3f8
#define NP4L_PERIPH_INT_STATUS	0x3fc

/* Rings */
/*
 * Powers of 2. RX is the reservoir of a burst to the host: a full RX ring holds
 * the HIF back, and the queue from SSE to HRX, a dozen entries, overflows
 * (DCE 0x12). 64 descriptors cap a back-to-back burst at 74 frames.
 * TX is shared by every port, and a scatter-gather frame takes two or
 * three descriptors: 64 would leave some 20 frames in flight.
 *
 * The RX length is FORTINET_NP4LITE_RX_RING_LEN: 256 carries steady
 * traffic, 4096 (the default) rides out the bursts above on the FortiGate
 * 90D. The width of the ring size field is only known to hold 4096 on the
 * FortiSOC2: the probe reads the ring size back and fails if the NP did
 * not keep it.
 */
#define NP4L_RX_RING_LEN	CONFIG_FORTINET_NP4LITE_RX_RING_LEN
#define NP4L_RX_RING_MASK	(NP4L_RX_RING_LEN - 1)
/* The ring indexes are masked down, not wrapped: a power of 2 only. */
static_assert(!(NP4L_RX_RING_LEN & (NP4L_RX_RING_LEN - 1)));
#define NP4L_TX_RING_LEN	256
#define NP4L_TX_RING_MASK	(NP4L_TX_RING_LEN - 1)
#define NP4L_RING_EXTRA		32	/* slack after each ring */
#define NP4L_BUF_SIZE		2048	/* LEN armed in RX descriptors */
/*
 * The NP may write a little past the LEN armed in an RX descriptor: leave
 * a 64-byte margin between buffers and a guard slot after the last one.
 */
#define NP4L_BUF_STRIDE		(NP4L_BUF_SIZE + 64)
/* TX bounce buffers, one per TX descriptor */
#define NP4L_BUF_AREA		((NP4L_TX_RING_LEN + 1) * NP4L_BUF_STRIDE)
#define NP4L_RX_HEAD_BATCH	16

/*
 * RX buffers: one page per descriptor. The NP writes the host tag at the
 * address of the descriptor, NP4L_RX_PAD bytes into the page, and the frame
 * right after it; its IP header then lands 4-byte aligned. The area the
 * NP may write, margin included (NP4L_RX_DMA_LEN), starts and ends on a
 * cache line: the cache is not coherent, and a line shared with the
 * headroom or the skb_shared_info that build_skb() puts at the end of the
 * page would be lost to the invalidation before the NP writes.
 *
 * The headroom is sized for forwarding, not for NET_SKB_PAD: the IP
 * header sits NP4L_RX_PAD + 24 bytes into the page, and a routed packet
 * gets pushed in front of it the headers of its output path, up to an
 * IPv6 ESP tunnel (40 + 8 + a 16-byte IV) and a DSA user port (48 bytes
 * of LL_RESERVED_SPACE with an EDSA tag), 112 bytes. The segments of a
 * GRO fraglist packet get these headers copied in front of them by
 * skb_segment_list(), which checks nothing. 128 leaves room for
 * MAX_HEADER on top of the IPv6 ESP tunnel, and fits the page with
 * plenty to spare.
 */
#define NP4L_RX_PAD		ALIGN(128, SMP_CACHE_BYTES)
#define NP4L_RX_DMA_LEN		ALIGN(NP4L_BUF_STRIDE, SMP_CACHE_BYTES)
static_assert(IS_ALIGNED(NP4L_RX_PAD, SMP_CACHE_BYTES));
static_assert(NP4L_RX_PAD + NP4L_RX_DMA_LEN +
	      SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) <= PAGE_SIZE);
/*
 * Frames up to this length are copied into a small skb and the page stays
 * in its descriptor: a page per ACK would inflate the socket memory
 * accounting 16-fold, and copying from cached memory costs less than a
 * page round trip through the pool.
 */
#define NP4L_RX_COPYBREAK	256

/* RX descriptor, 8 bytes */
struct fnp4l_rx_bd {
	__le32 addr;		/* physical address of the buffer */
	__le32 ctrl;
};

#define NP4L_RX_DONE		BIT(31)
#define NP4L_RX_OK		BIT(30)
#define NP4L_RX_LEN		GENMASK(29, 16)	/* host tag included */
/*
 * Header check results of the NP (bit 6, L3 checked, is not used: only an
 * L4 check says anything of the payload).
 */
#define NP4L_RX_L3_ERR		BIT(14)
#define NP4L_RX_L4_ERR		BIT(13)
#define NP4L_RX_L4_OK		BIT(5)
#define NP4L_RX_ANOMALY		BIT(4)	/* sent up by an L3 anomaly check */
/* FortiSOC2: a buffer of flow engine messages, not a frame */
#define NP4L_RX_MSG		BIT(7)

/*
 * TX descriptor, 16 bytes. A frame takes one descriptor per segment: the
 * first one carries the host tag and the linear part, the frame length, the
 * port and the checksum request; the following ones, one page fragment
 * each, only their address and length. EOP marks the last one.
 */
struct fnp4l_tx_bd {
	__le32 addr;		/* segment, host tag + frame for the first one */
	__le32 len;		/* frame length without host tag, first segment */
	__le32 ctrl;
	__le32 rsvd;
};

#define NP4L_TX_FRAME_LEN	GENMASK(31, 16)
#define NP4L_TX_PORT		GENMASK(31, 30)
/*
 * Checksum offload request, for CHECKSUM_PARTIAL frames, first segment
 * only. Nothing tells the NP where the checksum is: it parses the headers.
 */
#define NP4L_TX_CSUM		GENMASK(26, 25)
#define NP4L_TX_EOP		BIT(24)
/* FortiSOC2: a flow engine command, not a frame */
#define NP4L_TX_CMD		BIT(28)
/*
 * FortiSOC2: to be encrypted and encapsulated by the IPsec engine with
 * the security association whose index is in the last word, first
 * segment only. Bit 16, a test mode, is never set.
 */
#define NP4L_TX_IPSEC		BIT(17)
#define NP4L_TX_SEG_LEN		GENMASK(15, 0)	/* host tag included */
/* Descriptors kept free for the largest frame before a queue stops */
#define NP4L_TX_MAX_BDS		(MAX_SKB_FRAGS + 1)
static_assert((NP4L_TX_MAX_BDS) < NP4L_TX_RING_LEN - 1);
/*
 * Frames up to this length are copied even in zero-copy mode: the copy is
 * short, and the skb (an ACK, most of the time) is released at once.
 */
#define NP4L_TX_COPYBREAK	256

/* Software state of a TX descriptor */
struct fnp4l_tx_slot {
	struct sk_buff *skb;		/* mapped frame, last descriptor */
	struct fnp4l_port *port;	/* any frame, last descriptor */
	dma_addr_t dma;
	u16 dma_len;			/* 0: bounce buffer, nothing mapped */
	bool dma_page;			/* page fragment */
	bool cmd;			/* command, bounce buffer to wipe */
	/* Frame length, last descriptor; command length */
	u16 len;
};

/*
 * Private flags, per port. "ip-options-host" (FortiSOC2, not on a DSA
 * conduit) is last, and only offered where it applies.
 */
#define NP4L_PRIV_TX_ZEROCOPY	BIT(0)
#define NP4L_PRIV_IPOPT_HOST	BIT(1)

static const char fnp4l_priv_flags[][ETH_GSTRING_LEN] = {
	"tx-zerocopy",
	"ip-options-host",
};

/* Host tag, 10 bytes in front of every frame */
#define NP4L_HTAG_LEN		10
#define NP4L_HTAG_TX_VALID	0x80
#define NP4L_HTAG_RX_NOVLAN	0x40
#define NP4L_LIF_MAX		63
/*
 * FortiSOC2: LIF pattern 0x_F_, bits 7..4 of a 10-bit LIF all set. It
 * marks a frame the IPsec engine decrypted, the rest of the LIF and of the
 * host tag giving the index of its security association. For a LIF in
 * bytes 0 and 1 of the host tag, ((b0 & 3) << 8) | b1, these bits are all
 * in byte 1.
 */
#define NP4L_HTAG_LIF_MARK	GENMASK(7, 4)

#define NP4L_TX_MAX_FRAME	(NP4L_BUF_SIZE - NP4L_HTAG_LEN)
/* Room for a DSA tag (EDSA, 8 bytes) when the port is a DSA conduit */
#define NP4L_MAX_MTU		(ETH_DATA_LEN + 8)
#define NP4L_TX_TIMEOUT		(5 * HZ)

/*
 * DCE counters, clear on read. Per-port counters sit at port * 0x40 +
 * index, the others are global. Each has a single reader: ethtool for
 * the per-port ones, the counter work for the global ones.
 */
#define NP4L_DCE_PORT_STRIDE	0x40
/* The entries of the ports, cleared at probe; beyond, those listed only */
#define NP4L_DCE_ENTRIES	256
/* Frames for the host dropped for want of room, global */
#define NP4L_DCE_FLOW_TO_HOST_FULL	0x12	/* host queue of the flow engine */
#define NP4L_DCE_RX_NO_BUFFER	0x19	/* no free RX descriptor */

struct fnp4l_dce_desc {
	u8 idx;
	bool global;
	char name[ETH_GSTRING_LEN];
};

static const struct fnp4l_dce_desc fnp4l_dce_descs[] = {
	{ 0x00, false, "tx_fifo_errors" },
	{ 0x01, false, "rx_symbol_errors" },
	{ 0x02, false, "rx_fifo_errors" },
	{ 0x03, false, "rx_crc_errors" },
	{ 0x04, false, "rx_pause_frames" },
	{ 0x05, false, "rx_long_length_errors" },
	{ 0x06, false, "rx_short_length_errors" },
	{ 0x07, false, "rx_lif_disabled_drops" },
	{ 0x08, false, "rx_vlan_filter_drops" },
	{ 0x09, false, "rx_mac_filter_drops" },
	{ 0x0a, false, "rx_ethertype_drops" },
	{ 0x0b, false, "rx_target_drops" },
	{ 0x0c, false, "rx_frames_ok" },
	{ 0x0d, false, "tx_frames_ok" },
	{ 0x0e, false, "tx_late_collisions" },
	{ 0x10, false, "rx_flow_queue_full" },
	{ 0x11, false, "fwd_egress_queue_full" },
	{ 0x13, false, "tx_host_queue_full" },
	{ 0x1a, false, "rx_broadcast" },
	{ 0x1b, false, "rx_multicast" },
	{ 0x1c, false, "rx_unicast" },
	{ 0x1d, false, "tx_broadcast" },
	{ 0x1e, false, "tx_multicast" },
	{ 0x1f, false, "tx_unicast" },
	{ 0x33, false, "rx_anomaly_drops" },
	{ 0x34, false, "rx_header_check_drops" },
	{ 0x3a, false, "fwd_egress_queue_reads" },
	{ 0x3b, false, "fwd_egress_queue_writes" },
	{ 0x3c, false, "egress_queue_reads" },
	{ 0x3d, false, "egress_queue_writes" },
	{ 0x3e, false, "flow_queue_reads" },
	{ 0x3f, false, "flow_queue_writes" },
	{ 0x14, true,  "shaper_drops" },
	{ 0x15, true,  "shaper_resync_drops" },
	{ 0x56, true,  "flow_config_drops" },
	{ 0x57, true,  "flow_ttl_drops" },
	{ NP4L_DCE_FLOW_TO_HOST_FULL, true, "rx_host_queue_full" },
	{ 0x18, true,  "tx_host_frame_errors" },
	{ NP4L_DCE_RX_NO_BUFFER, true, "rx_no_buffer_count" },
	{ 0x36, true,  "host_queue_reads" },
	{ 0x37, true,  "host_queue_writes" },
};

#define NP4L_DCE_NR		ARRAY_SIZE(fnp4l_dce_descs)

#ifdef CONFIG_FORTINET_NP4LITE_IPSEC
/*
 * FortiSOC2: global DCE counters of the IPsec engine and of the header checks
 * of the packets it decrypts (XHP), above the entries of the table above
 * (NP4L_DCE_ENTRIES, which they do not follow the per-port layout of): drops of
 * its queues and of the engine, and the write and read commits of the queues
 * around it. The drops of the header checks of the XHP (0x114..0x134, every one
 * listed) are summed. Read by the counter work alone, as the other global ones,
 * when the IPsec offload is set up.
 */
enum {
	NP4L_IPSEC_DCE_IN_SHAPER_DROPS,
	NP4L_IPSEC_DCE_OUT_SHAPER_DROPS,
	NP4L_IPSEC_DCE_INPUT_QUEUE_DROPS,
	NP4L_IPSEC_DCE_ENGINE_DROPS,
	NP4L_IPSEC_DCE_DECAP_FLOW_DROPS,
	NP4L_IPSEC_DCE_DECAP_CHECK_DROPS,
	NP4L_IPSEC_DCE_TO_FLOW_WRITES,
	NP4L_IPSEC_DCE_TO_FLOW_READS,
	NP4L_IPSEC_DCE_TO_DECAP_WRITES,
	NP4L_IPSEC_DCE_TO_DECAP_READS,
	NP4L_IPSEC_DCE_DECAP_TO_FLOW_WRITES,
	NP4L_IPSEC_DCE_DECAP_TO_FLOW_READS,
	NP4L_IPSEC_DCE_FLOW_TO_IN_WRITES,
	NP4L_IPSEC_DCE_FLOW_TO_IN_READS,
	NP4L_IPSEC_DCE_FLOW_TO_OUT_WRITES,
	NP4L_IPSEC_DCE_FLOW_TO_OUT_READS,
	NP4L_IPSEC_DCE_NR
};

static const char fnp4l_ipsec_dce_names[NP4L_IPSEC_DCE_NR][ETH_GSTRING_LEN] = {
	[NP4L_IPSEC_DCE_IN_SHAPER_DROPS]	= "ipsec_in_shaper_drops",
	[NP4L_IPSEC_DCE_OUT_SHAPER_DROPS]	= "ipsec_out_shaper_drops",
	[NP4L_IPSEC_DCE_INPUT_QUEUE_DROPS]	= "ipsec_input_queue_drops",
	[NP4L_IPSEC_DCE_ENGINE_DROPS]	= "ipsec_engine_drops",
	[NP4L_IPSEC_DCE_DECAP_FLOW_DROPS]	= "ipsec_decap_flow_drops",
	[NP4L_IPSEC_DCE_DECAP_CHECK_DROPS]	= "ipsec_decap_check_drops",
	[NP4L_IPSEC_DCE_TO_FLOW_WRITES]	= "ipsec_to_flow_writes",
	[NP4L_IPSEC_DCE_TO_FLOW_READS]	= "ipsec_to_flow_reads",
	[NP4L_IPSEC_DCE_TO_DECAP_WRITES]	= "ipsec_to_decap_writes",
	[NP4L_IPSEC_DCE_TO_DECAP_READS]	= "ipsec_to_decap_reads",
	[NP4L_IPSEC_DCE_DECAP_TO_FLOW_WRITES]	= "decap_to_flow_writes",
	[NP4L_IPSEC_DCE_DECAP_TO_FLOW_READS]	= "decap_to_flow_reads",
	[NP4L_IPSEC_DCE_FLOW_TO_IN_WRITES]	= "flow_to_ipsec_in_writes",
	[NP4L_IPSEC_DCE_FLOW_TO_IN_READS]	= "flow_to_ipsec_in_reads",
	[NP4L_IPSEC_DCE_FLOW_TO_OUT_WRITES]	= "flow_to_ipsec_out_writes",
	[NP4L_IPSEC_DCE_FLOW_TO_OUT_READS]	= "flow_to_ipsec_out_reads",
};

struct fnp4l_ipsec_dce {
	u16 idx;	/* DCE entry */
	u8 stat;	/* NP4L_IPSEC_DCE_*, which it adds to */
};

#define NP4L_IPSEC_DCE_DECAP_CHECK(idx)	{ idx, NP4L_IPSEC_DCE_DECAP_CHECK_DROPS }

static const struct fnp4l_ipsec_dce fnp4l_ipsec_dces[] = {
	{ 0x100, NP4L_IPSEC_DCE_IN_SHAPER_DROPS },
	{ 0x101, NP4L_IPSEC_DCE_OUT_SHAPER_DROPS },
	{ 0x103, NP4L_IPSEC_DCE_INPUT_QUEUE_DROPS },
	{ 0x104, NP4L_IPSEC_DCE_ENGINE_DROPS },
	{ 0x105, NP4L_IPSEC_DCE_DECAP_FLOW_DROPS },
	{ 0x106, NP4L_IPSEC_DCE_TO_FLOW_WRITES },
	{ 0x107, NP4L_IPSEC_DCE_TO_FLOW_READS },
	{ 0x108, NP4L_IPSEC_DCE_TO_DECAP_WRITES },
	{ 0x109, NP4L_IPSEC_DCE_TO_DECAP_READS },
	{ 0x10a, NP4L_IPSEC_DCE_DECAP_TO_FLOW_WRITES },
	{ 0x10b, NP4L_IPSEC_DCE_DECAP_TO_FLOW_READS },
	{ 0x10c, NP4L_IPSEC_DCE_FLOW_TO_IN_WRITES },
	{ 0x10d, NP4L_IPSEC_DCE_FLOW_TO_IN_READS },
	{ 0x10e, NP4L_IPSEC_DCE_FLOW_TO_OUT_WRITES },
	{ 0x10f, NP4L_IPSEC_DCE_FLOW_TO_OUT_READS },
	NP4L_IPSEC_DCE_DECAP_CHECK(0x114), NP4L_IPSEC_DCE_DECAP_CHECK(0x115),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x116), NP4L_IPSEC_DCE_DECAP_CHECK(0x117),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x118), NP4L_IPSEC_DCE_DECAP_CHECK(0x119),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x11a), NP4L_IPSEC_DCE_DECAP_CHECK(0x11b),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x11c), NP4L_IPSEC_DCE_DECAP_CHECK(0x11d),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x11e), NP4L_IPSEC_DCE_DECAP_CHECK(0x11f),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x120), NP4L_IPSEC_DCE_DECAP_CHECK(0x121),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x122), NP4L_IPSEC_DCE_DECAP_CHECK(0x123),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x124), NP4L_IPSEC_DCE_DECAP_CHECK(0x125),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x126), NP4L_IPSEC_DCE_DECAP_CHECK(0x127),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x128), NP4L_IPSEC_DCE_DECAP_CHECK(0x129),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x12a), NP4L_IPSEC_DCE_DECAP_CHECK(0x12b),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x12c), NP4L_IPSEC_DCE_DECAP_CHECK(0x12d),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x12e), NP4L_IPSEC_DCE_DECAP_CHECK(0x12f),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x130), NP4L_IPSEC_DCE_DECAP_CHECK(0x131),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x132), NP4L_IPSEC_DCE_DECAP_CHECK(0x133),
	NP4L_IPSEC_DCE_DECAP_CHECK(0x134),
};
#endif /* CONFIG_FORTINET_NP4LITE_IPSEC */

/*
 * What differs between the NP4Lite of the FortiSOC1 and that of the
 * FortiSOC2
 */
struct fnp4l_soc {
	u32 pbuf_size;		/* packet buffer, at least */
	u32 ihp_ctrl;		/* per-port header check control */
	u32 ihp_l4minlen;	/* 0: left as the boot loader set it */
	u32 ihp_uesp_proto0;	/* 0: left as the boot loader set it */
	bool xhp;		/* header checks of the host frames (+0xb00) */
	bool rx_wb;		/* RX completions in a write-back ring */
	bool irqmap;		/* interrupt routed by the "irq-map" block */
	/* Flow engine and message queue at the offsets of the FortiSOC1 */
	bool sse;
	/*
	 * Flow engine of the FortiSOC2 (NP4L_SSE_FSOC2_*): commands on the TX
	 * ring, messages on the RX ring.
	 */
	bool sse_hif;
	bool gmii_tx_hi;	/* GMII_TX bits 31..24 follow the duplex */
	bool tx_port;		/* port number in the TX descriptors */
	/*
	 * Where the MAC addresses come from when the device tree has neither
	 * an address nor a "mac-base" NVMEM cell: LIF 0, which the boot
	 * loader sets up on the FortiSOC1, or the LIF entries of the boot
	 * loader (fnp4l_loader_mac()).
	 */
	bool loader_lifs_mac;
	/*
	 * 802.1Q extraction and insertion, and the VLAN action table of the
	 * ports for tagged flows (class mode).
	 */
	bool vlan;
	/*
	 * The lookup windows of the IGR hold noise after a power cycle: the
	 * driver rewrites them at probe rather than check them (FortiSOC2).
	 */
	bool igr_noise;
	/*
	 * The ports with a VLAN action table (all but a DSA conduit) stay in
	 * class mode, empty table included: the MAC filter of a LIF only
	 * applies to the frames of a port in class mode (FortiSOC2).
	 */
	bool wan_class;
	bool egr_tpid;		/* the driver sets the TPID of the EGR */
	/*
	 * IPv4 options to the host (NP4L_ANOMALY_L3_IPOPT) on every port,
	 * always (FortiSOC1), or under the "ip-options-host" private flag, on
	 * by default, on the ports but a DSA conduit (FortiSOC2).
	 */
	bool anomaly_priv;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	/* A LIF per port of the switch behind link 0 (FortiSOC2) */
	bool dsa_offload;
#endif
};

struct fnp4l;

/* One port of the NP, with its own net_device (its private data) */
struct fnp4l_port {
	struct fnp4l *np;
	struct net_device *ndev;
	struct device_node *of_node;
	u32 id;				/* port number, register bank */
	u32 lif;			/* LIF of the host tag, RX and TX */
	u64 dce[NP4L_DCE_NR];		/* per-port DCE totals, tbl_lock */
	bool tce;			/* own traffic counters */
	struct u64_stats_sync tce_syncp;	/* written under tbl_lock */
	u64_stats_t tce_rx_packets;	/* ingress counter totals */
	u64_stats_t tce_rx_bytes;
	u64_stats_t tce_tx_packets;	/* egress counter totals */
	u64_stats_t tce_tx_bytes;
	struct u64_stats_sync rx_syncp;	/* written by NAPI */
	u64_stats_t rx_anomaly_trapped;	/* frames sent up by an anomaly check */
	/*
	 * VLAN action table of the port, under sse_lock: the VIDs that
	 * offloaded flows enter the port with, in increasing order, and the
	 * number of flow directions using each. Class mode is on while
	 * the table is not empty, and always with wan_class
	 * (fnp4l_igr_idle()).
	 */
	bool vlan_act_avail;		/* class table as the boot loader left it */
	bool class_on;
	unsigned int vlan_act_nr;
	u16 vlan_act_vid[NP4L_VLAN_ACT_MAX];
	unsigned int vlan_act_refs[NP4L_VLAN_ACT_MAX];
	struct phylink *phylink;
	struct phylink_config phylink_config;
	u32 priv_flags;			/* NP4L_PRIV_*, read locklessly */
	bool ipopt_flag;		/* "ip-options-host" offered */
	bool lif_mtu_fixed;		/* DSA conduit: LIF MTU NP4L_LIF_MTU */
};

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/* FORTINET_NP4LITE_DSA: a DSA conduit and its switch, by link */
struct fnp4l_dsa_link {
	struct fnp4l_port *port;	/* the conduit, NULL: none */
	bool offload;			/* a LIF per switch port */
	u8 lif[NP4L_DSA_NR_PORTS];	/* LIF of switch port p, 0: none */
	u32 class_base, class_max;	/* its class table window */
};
#endif

struct fnp4l {
	struct device *dev;
	const struct fnp4l_soc *soc;
	void __iomem *base;
	void __iomem *irqmap;	/* FortiSOC2 */
	u32 loader_irqmap;	/* NP4L_IRQMAP_OUT(NP) left by the boot loader */
	u32 loader_irqmap_crypto;	/* NP4L_IRQMAP_OUT(CRYPTO), likewise */
	int irq;
	/*
	 * Base MAC address, from the "mac-base" NVMEM cell (mac_base_nvmem),
	 * else from the LIF entries of the boot loader
	 */
	u8 mac_base[ETH_ALEN];
	bool mac_base_valid;
	bool mac_base_nvmem;
	/* FortiSOC2, counted on the RX path */
	atomic_long_t rx_flow_msgs;	/* engine messages received */
	atomic_long_t msg_lost;		/* ageing keys lost, FIFO full */
	atomic_long_t msg_rx_bad;	/* malformed messages */
	atomic_long_t rx_flow_msgs_other; /* of other types, skipped */
	atomic_long_t rx_htag_mark_a;	/* frames, LIF 0x_F_ in bytes 0-1 */
	atomic_long_t rx_htag_mark_b;	/* frames, LIF 0x_F_ in bytes 4-5 */

	struct fnp4l_port *ports[NP4L_NR_PORTS];
	struct fnp4l_port *hif_port;	/* lowest port, global HIF drops */
	struct fnp4l_port *lif_port[NP4L_LIF_MAX + 1];	/* RX dispatch */
	unsigned int users;		/* open ports, under RTNL */

	spinlock_t tbl_lock;		/* indirect table access ports */
	struct u64_stats_sync drop_cnt_syncp;	/* written under tbl_lock */
	u64_stats_t dce[NP4L_DCE_NR];	/* global DCE totals */
#ifdef CONFIG_FORTINET_NP4LITE_IPSEC
	u64_stats_t ipsec_dce[NP4L_IPSEC_DCE_NR];	/* likewise, IPsec engine */
#endif
	/* Sole reader of the TCE counters and of the global DCE ones */
	struct delayed_work tce_work;
	u64 tce_errors;			/* failed TCE/TAE reads, under tbl_lock */
	u32 loader_rx_ring_base, loader_rx_ring_size, loader_rx_wb_base;
	u32 loader_tx_ring_base, loader_tx_ring_size;

	/* NAPI is shared by every port: it hangs off a dummy net_device. */
	struct net_device *napi_dev;
	struct napi_struct napi;

	struct fnp4l_rx_bd *rx_ring;
	dma_addr_t rx_ring_dma;
	/*
	 * Where the NP completes the RX descriptors: rx_ring itself on the
	 * FortiSOC1, a write-back ring of the same layout on the FortiSOC2,
	 * of which only the control word is used.
	 */
	struct fnp4l_rx_bd *rx_wb;
	dma_addr_t rx_wb_dma;
	/* Pages of the RX slots, while the HIF runs: the NP clears addr. */
	struct page_pool *rx_pool;
	struct page *rx_page[NP4L_RX_RING_LEN];
	/* Address of the RX descriptors without a page, never written */
	dma_addr_t rx_guard_dma;
	unsigned int rx_head;	/* next descriptor the NP completes */
	unsigned int rx_tail;	/* empty slot, value of the HRX head */

	spinlock_t tx_lock;	/* TX ring, shared by the ports */
	struct fnp4l_tx_bd *tx_ring;
	dma_addr_t tx_ring_dma;
	u8 *tx_buf;
	dma_addr_t tx_buf_dma;
	unsigned int tx_head;	/* oldest descriptor not yet released */
	unsigned int tx_tail;	/* next descriptor to fill, value of the HTX head */
	bool tx_stopped;	/* every port queue stopped on a full ring */
	bool hif_up;		/* the NP reads the TX ring */
	struct fnp4l_tx_slot tx_slot[NP4L_TX_RING_LEN];

	/* Flow offload */
	struct mutex sse_lock;	/* engine, command ring, flows, ft_ports */
	bool sse_avail;		/* flow tables usable */
	enum fnp4l_sse_state sse_state;
	u32 sse_phtconf, sse_oftconf;
	void __iomem *sseq;	/* command ring, then message queue */
	u32 sseq_phys;
	unsigned int sse_tail;	/* next free word of the ring, value of the head */
	unsigned long ft_ports;	/* ports bound to a flow table */
#ifdef CONFIG_FORTINET_NP4LITE_LAG
	/* Bonds of NP ports bound to a flow table, see fnp4l_lag_bind() */
	struct list_head lags;
	unsigned long lag_ports;	/* their slaves */
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	unsigned long lag_lifs;		/* their slaves of the switch, by LIF */
#endif
	DECLARE_HASHTABLE(lag_flows, NP4L_FT_HASH_BITS);	/* by cookie */
	struct delayed_work lag_work;	/* follows the changes of the bonds */
	struct notifier_block lag_nb;
#endif
	unsigned int ft_nr_flows;
	DECLARE_HASHTABLE(ft_flows, NP4L_FT_HASH_BITS);	/* by cookie */
	DECLARE_HASHTABLE(ft_keys, NP4L_FT_HASH_BITS);	/* by engine key */
	unsigned int msg_rp;	/* next word of the message queue to read */
	unsigned long sse_age;	/* ageing period of the engine, in jiffies */
	u64 msg_timeout, msg_unknown, msg_bad;
	/*
	 * FortiSOC2: keys and words of the ageing messages, from the RX path
	 * (the only writer) to the flow statistics (the only reader, under
	 * sse_lock)
	 */
	DECLARE_KFIFO(msg_fifo, struct fnp4l_age, NP4L_MSG_FIFO_LEN);
	DECLARE_BITMAP(tae_used, NP4L_TCE_ENTRIES);	/* per-flow counters */
	u64 tae_exhausted;	/* flow directions without a counter */
	/* FortiSOC2: IPsec offload (FORTINET_NP4LITE_IPSEC), NULL without it */
	struct fnp4l_ipsec *ipsec;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	/*
	 * Switch ports behind the DSA conduits, see fnp4l_dsa_probe();
	 * their state by LIF (two switches have the same port numbers)
	 */
	struct fnp4l_dsa_link dsa_link[NP4L_NR_PORTS];	/* by link */
	unsigned long dsa_links;		/* links of the conduits */
	/*
	 * Flows leave through the switch ports: from probe, unless the
	 * address notifier fails (fnp4l_dsa_init())
	 */
	bool dsa_out;
	unsigned long dsa_lifs;			/* LIFs of the switch ports */
	u8 dsa_lif_sw[NP4L_LIF_MAX + 1];	/* switch port of a LIF */
	u8 dsa_mac[NP4L_DSA_LIF_LAST + 1][ETH_ALEN]; /* by LIF, tbl_lock */
	atomic_long_t dsa_rx_retag;		/* tag put back, RX */
	atomic_long_t dsa_rx_tagged;		/* tag found in place */
	atomic_long_t dsa_rx_missed;		/* conduit LIF, class table missed */
	atomic_long_t dsa_rx_untagged;		/* conduit LIF, no tag: dropped */
	atomic_long_t dsa_rx_prio_tag;		/* 802.1Q VID 0 taken off, RX */
	atomic_long_t dsa_rx_vid_tag;		/* 802.1Q VID other than 0, RX */
	u16 dsa_rx_last_tci;			/* TCI of the last of them */
	struct notifier_block dsa_nb;		/* addresses of the user ports */
	struct net_device *dsa_user[NP4L_DSA_LIF_LAST + 1]; /* by LIF, RTNL */
	unsigned long dsa_promisc_need;		/* by LIF, tbl_lock */
	unsigned long dsa_promisc;		/* PROMISC set, tbl_lock */
	unsigned long dsa_mac_bad;		/* address not written, tbl_lock */
	unsigned long dsa_guard;		/* flows kept out, tbl_lock */
	unsigned long dsa_purge;		/* LIFs to purge, tbl_lock */
	struct work_struct dsa_purge_work;	/* fnp4l_dsa_purge() */
	atomic_long_t dsa_promisc_purged;	/* flow directions purged */
	/* bridge_offload: LIFs of offloadable bridged ports, RTNL */
	unsigned long dsa_bridged;
	/* Stations learnt on another port of such a bridge (fdb_work) */
	struct notifier_block dsa_fdb_nb;
	struct work_struct dsa_fdb_work;
	spinlock_t dsa_fdb_lock;
	struct net_device *dsa_fdb_dev[8];	/* held, with their address */
	u8 dsa_fdb_addr[8][ETH_ALEN];
	bool dsa_fdb_del[8];			/* entry forgets the station */
	unsigned int dsa_fdb_n;
	bool dsa_fdb_lost;			/* ring full: all of them */
	atomic_long_t dsa_fdb_moves;		/* torn down for a move */
#endif
};

/*
 * One direction of an offloaded flow, keyed by the flow_cls cookie and by
 * its engine key (ageing messages)
 */
struct fnp4l_flow {
	struct hlist_node node;
	struct hlist_node key_node;
	unsigned long cookie;
	unsigned long last_active;	/* jiffies of the last sign of activity */
	struct fnp4l_sse_key key;
	u8 in_port, out_port;
	u8 tae;				/* counter entry, 0 = none */
	bool vlan_act;			/* holds a VLAN action entry of in_port */
	u16 sa_idx;			/* IPsec SA it is chained to, 0 = none */
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	u8 dsa_out_lif;			/* switch port of the output, 0: none */
	u8 h_dest[ETH_ALEN];		/* next hop, for the bridge FDB */
#endif
};

static inline u32 fnp4l_rd(struct fnp4l *np, u32 reg)
{
	return readl(np->base + reg);
}

/*
 * Without ARM_DMA_MEM_BUFFERABLE (ARMv4/v5), writel() implies no barrier,
 * not even a compiler one: every descriptor update is followed by an
 * explicit dma_wmb() before the doorbell write.
 */
static inline void fnp4l_wr(struct fnp4l *np, u32 reg, u32 val)
{
	writel(val, np->base + reg);
}

static void fnp4l_irq_mask(struct fnp4l *np, u32 val)
{
	fnp4l_wr(np, NP4L_HRX_INT_ENABLE, val);
	fnp4l_wr(np, NP4L_HTX_INT_ENABLE, val);
}

static void fnp4l_ack(struct fnp4l *np, u32 rx, u32 tx)
{
	if (rx)
		fnp4l_wr(np, NP4L_HRX_INT_STATUS, rx);
	if (tx)
		fnp4l_wr(np, NP4L_HTX_INT_STATUS, tx);
}

/* Cut the receive side of one port, other bits kept. */
static void fnp4l_gmii_rx_cut(struct fnp4l *np, unsigned int id)
{
	fnp4l_wr(np, NP4L_GMII_RX(id), fnp4l_rd(np, NP4L_GMII_RX(id)) | NP4L_GMII_RX_CUT);
}

/*
 * Stop the HIF. The receive side of every port is cut first: clearing
 * GMII_RX alone does not stop reception at 100 Mbit/s.
 */
static void fnp4l_hif_stop(struct fnp4l *np)
{
	unsigned int id;

	fnp4l_irq_mask(np, 0);
	for (id = 0; id < NP4L_NR_PORTS; id++)
		fnp4l_gmii_rx_cut(np, id);

	fnp4l_wr(np, NP4L_HRX_CTRL, NP4L_HIF_CTRL_STOP);
	fnp4l_wr(np, NP4L_HTX_CTRL, NP4L_HIF_CTRL_STOP);
	usleep_range(1000, 2000);

	fnp4l_ack(np, fnp4l_rd(np, NP4L_HRX_INT_STATUS), fnp4l_rd(np, NP4L_HTX_INT_STATUS));
}

/* Make both rings empty from the NP point of view: head = done. */
static void fnp4l_hif_drain(struct fnp4l *np)
{
	fnp4l_wr(np, NP4L_HRX_RING_HEAD, fnp4l_rd(np, NP4L_HRX_RING_DONE));
	fnp4l_wr(np, NP4L_HTX_RING_HEAD, fnp4l_rd(np, NP4L_HTX_RING_DONE));
}

/*
 * Program base, size and head of both rings while the HIF is stopped.
 * Whether stopping the HIF or writing the ring base resets the hardware
 * indexes is not known: empty the rings (head = done) before switching
 * the base, read the done index back afterwards and empty them again. The
 * done indexes are returned as the starting indexes.
 */
static int fnp4l_hif_program(struct fnp4l *np, unsigned int *rx_start,
			     unsigned int *tx_start)
{
	u32 rdp, tdp, ring_size;

	fnp4l_hif_drain(np);

	fnp4l_wr(np, NP4L_HRX_RING_BASE, np->rx_ring_dma);
	fnp4l_wr(np, NP4L_HRX_RING_BASE_HI, 0);
	if (np->soc->rx_wb) {
		fnp4l_wr(np, NP4L_HRX_WB_BASE, np->rx_wb_dma);
		fnp4l_wr(np, NP4L_HRX_WB_BASE_HI, 0);
	}
	fnp4l_wr(np, NP4L_HRX_RING_SIZE, NP4L_RX_RING_LEN);
	/*
	 * Above 256 descriptors the NP may keep less than programmed (4096
	 * checked on the FortiSOC2 only).
	 */
	ring_size = fnp4l_rd(np, NP4L_HRX_RING_SIZE);
	if (ring_size != NP4L_RX_RING_LEN) {
		dev_err(np->dev, "HRX ring size %u not kept (read %#x)\n",
			NP4L_RX_RING_LEN, ring_size);
		return -EIO;
	}
	if (NP4L_RX_RING_LEN != 256)
		dev_info_once(np->dev, "host RX ring of %u descriptors\n",
			      NP4L_RX_RING_LEN);

	fnp4l_wr(np, NP4L_HTX_RING_BASE, np->tx_ring_dma);
	fnp4l_wr(np, NP4L_HTX_RING_BASE_HI, 0);
	fnp4l_wr(np, NP4L_HTX_RING_SIZE, NP4L_TX_RING_LEN);

	rdp = fnp4l_rd(np, NP4L_HRX_RING_DONE);
	tdp = fnp4l_rd(np, NP4L_HTX_RING_DONE);
	if (rdp >= NP4L_RX_RING_LEN || tdp >= NP4L_TX_RING_LEN) {
		dev_err(np->dev, "done indexes out of range (RX %#x, TX %#x)\n",
			rdp, tdp);
		return -EIO;
	}
	fnp4l_wr(np, NP4L_HRX_RING_HEAD, rdp);
	fnp4l_wr(np, NP4L_HTX_RING_HEAD, tdp);

	*rx_start = rdp;
	*tx_start = tdp;

	return 0;
}

/*
 * Leave the HIF stopped and pointed at the rings of the boot loader, in
 * memory reserved for them, so that our rings can be freed.
 */
static void fnp4l_hif_park(struct fnp4l *np)
{
	fnp4l_hif_drain(np);
	fnp4l_wr(np, NP4L_HRX_RING_BASE, np->loader_rx_ring_base);
	if (np->soc->rx_wb)
		fnp4l_wr(np, NP4L_HRX_WB_BASE, np->loader_rx_wb_base);
	fnp4l_wr(np, NP4L_HRX_RING_SIZE, np->loader_rx_ring_size);
	fnp4l_wr(np, NP4L_HTX_RING_BASE, np->loader_tx_ring_base);
	fnp4l_wr(np, NP4L_HTX_RING_SIZE, np->loader_tx_ring_size);
	fnp4l_hif_drain(np);
}

/*
 * The NP interrupt is the OR of every NP source, and this driver only
 * serves the HIF ones. Disable the others before requesting the line: the
 * board interrupt pins (switch and PHYs, left pending by the boot loader),
 * the flow engine being held in reset. The HIF masks were cleared by
 * fnp4l_hif_stop().
 *
 * Returns the non-HIF sources still active. On the FortiSOC2, the HIF
 * sources alone get routed to the line afterwards (fnp4l_irqmap_route()).
 */
static u32 fnp4l_irq_quiesce(struct fnp4l *np)
{
	fnp4l_wr(np, NP4L_PERIPH_INT_ENABLE, 0);
	fnp4l_wr(np, NP4L_PERIPH_INT_STATUS, fnp4l_rd(np, NP4L_PERIPH_INT_STATUS));

	/*
	 * FortiSOC2: the sources the boot loader routed to the line. The IRQ
	 * map enable is not restored: the boot loader leaves every source
	 * enabled, and fnp4l_irqmap_route() only ever adds the HIF ones.
	 */
	if (np->irqmap)
		return readl(np->irqmap + NP4L_IRQMAP_STATUS) & np->loader_irqmap &
		       ~NP4L_IRQMAP_SRC_HIF;

	return fnp4l_rd(np, NP4L_TOP_STAT) & ~NP4L_TOP_STAT_HIF;
}

/*
 * FortiSOC2: route the HIF sources, and them alone, to the NP line before
 * requesting it (the board pins, which this driver does not serve, stay
 * unrouted). The boot loader routes nothing.
 * The crypto engine source goes to its own line, 8, for its driver, and
 * only when its node is enabled (an unrequested line would stay masked in
 * the interrupt controller anyway).
 */
static void fnp4l_irqmap_route(struct fnp4l *np)
{
	u32 mask = readl(np->irqmap + NP4L_IRQMAP_ENABLE);
	u32 want = NP4L_IRQMAP_SRC_HIF;
	struct device_node *ce;

	ce = of_find_compatible_node(NULL, NULL, "fortinet,fsoc2-crypto");
	if (ce && of_device_is_available(ce))
		want |= NP4L_IRQMAP_SRC_CRYPTO;
	of_node_put(ce);

	writel(NP4L_IRQMAP_SRC_HIF, np->irqmap + NP4L_IRQMAP_OUT(NP4L_IRQMAP_OUT_NP));
	if (want & NP4L_IRQMAP_SRC_CRYPTO)
		writel(NP4L_IRQMAP_SRC_CRYPTO,
		       np->irqmap + NP4L_IRQMAP_OUT(NP4L_IRQMAP_OUT_CRYPTO));
	if ((mask & want) != want)
		writel(mask | want, np->irqmap + NP4L_IRQMAP_ENABLE);
}

/*
 * Hold the flow engine in reset and stop the message queue, as the boot
 * loader leaves them: at probe, so that no engine state survives into this
 * kernel (the NP is not reset by a watchdog reset), and whenever flow
 * offload stops. The table registers are left alone: they point at the
 * reserved flow tables once the driver has used the engine.
 */
static void fnp4l_sse_reset(struct fnp4l *np)
{
	u32 ctrl, msg;

	/*
	 * FortiSOC2: the engine reset, then no messages.
	 * The security associations of IPsec go with the flows.
	 */
	if (np->soc->sse_hif) {
		fnp4l_wr(np, NP4L_SSE_FSOC2_CTRL, NP4L_SSE_CTRL_RESET);
		usleep_range(1000, 2000);
		if (fnp4l_rd(np, NP4L_HRX_MSG_CTRL))
			fnp4l_wr(np, NP4L_HRX_MSG_CTRL, 0);
		fnp4l_ipsec_reset(np->ipsec);
		return;
	}

	fnp4l_wr(np, NP4L_SSE_CTRL, NP4L_SSE_CTRL_RESET);

	ctrl = fnp4l_rd(np, NP4L_MSG_CTRL);
	msg = (ctrl & ~(NP4L_MSG_CTRL_RUN | NP4L_MSG_CTRL_IRQ_EN)) | NP4L_MSG_CTRL_OFF;
	if (msg != ctrl)
		fnp4l_wr(np, NP4L_MSG_CTRL, msg);
}

/* Wait for the command of access port @tbl to complete. Under tbl_lock. */
static int fnp4l_tbl_wait(struct fnp4l *np, u32 tbl)
{
	u32 val;

	return readl_poll_timeout_atomic(np->base + tbl + NP4L_TBL_CMD, val,
					 !(val & NP4L_TBL_CMD_BUSY), 1, 1000);
}

/* Read one table entry. Under tbl_lock. */
static int fnp4l_tbl_read(struct fnp4l *np, u32 tbl, u32 idx,
			  u32 *lo, u32 *hi)
{
	int ret;

	fnp4l_wr(np, tbl + NP4L_TBL_CMD, idx);
	fnp4l_rd(np, tbl + NP4L_TBL_CMD);
	ret = fnp4l_tbl_wait(np, tbl);
	if (ret)
		return ret;

	*lo = fnp4l_rd(np, tbl + NP4L_TBL_DATA_LO);
	*hi = fnp4l_rd(np, tbl + NP4L_TBL_DATA_HI);

	return 0;
}

/* Write one table entry, then read it back and compare. Under tbl_lock. */
static int fnp4l_tbl_write(struct fnp4l *np, u32 tbl, u32 idx,
			   u32 lo, u32 hi)
{
	u32 rlo, rhi;
	int ret;

	fnp4l_wr(np, tbl + NP4L_TBL_DATA_LO, lo);
	fnp4l_wr(np, tbl + NP4L_TBL_DATA_HI, hi);
	fnp4l_wr(np, tbl + NP4L_TBL_CMD, idx | NP4L_TBL_CMD_WRITE);
	ret = fnp4l_tbl_wait(np, tbl);
	if (ret)
		return ret;

	ret = fnp4l_tbl_read(np, tbl, idx, &rlo, &rhi);
	if (ret)
		return ret;

	return (rlo == lo && rhi == hi) ? 0 : -EIO;
}

/* Packets and bytes held by a counter entry (TCE or TAE) */
static void fnp4l_tce_decode(u32 lo, u32 hi, u64 *packets, u64 *bytes)
{
	*packets = FIELD_GET(NP4L_TCE_LO_PKTS, lo);
	*bytes = (u64)FIELD_GET(NP4L_TCE_HI_BYTES, hi) << 3 |
		 FIELD_GET(NP4L_TCE_LO_BYTES, lo);
}

/* MAC address held by a MAC filter entry (entry A of a LIF). */
static void fnp4l_lif_mac_filter(u32 lo, u32 hi, u8 *addr)
{
	addr[0] = lo & 0xff;
	addr[1] = (lo >> 8) & 0xff;
	addr[2] = (lo >> 16) & 0xff;
	addr[3] = (lo >> 24) & 0xff;
	addr[4] = hi & 0xff;
	addr[5] = (hi >> 8) & 0xff;
}

/* LIF entries of the boot loader, as read at probe */
struct fnp4l_lif_entry {
	u32 alo, ahi, blo, bhi;
	int err;
};

/*
 * Whether @base explains the address of a candidate LIF: the boot loader
 * writes the base address itself in the LIF of its link (its console
 * shows it), this driver writes base + LIF number in every LIF of a port,
 * and the table survives a watchdog reset.
 */
static bool fnp4l_mac_explains(const u8 *base, const u8 *addr,
			       unsigned int lif)
{
	u8 own[ETH_ALEN];

	if (ether_addr_equal(addr, base))
		return true;

	ether_addr_copy(own, base);
	eth_addr_add(own, lif);

	return ether_addr_equal(addr, own);
}

static bool fnp4l_mac_base_ok(const u8 *base,
			      const u8 (*addr)[ETH_ALEN], unsigned long cand)
{
	bool loader = false;
	unsigned int j;

	for_each_set_bit(j, &cand, NP4L_NR_PORTS) {
		if (!fnp4l_mac_explains(base, addr[j], j))
			return false;
		loader |= ether_addr_equal(base, addr[j]);
	}

	return loader || hweight_long(cand) >= 2;
}

/*
 * FortiSOC2: base MAC address from the LIF table, before any LIF is
 * written. The boot loader classes link k on LIF k and, for the link it
 * uses (TFTP), writes the base address in entry A of that LIF; nothing
 * else in the table can be trusted (noise after a power cycle). The
 * address of LIF k is a candidate when
 *  - entry A is valid and holds a unicast, universally administered
 *    address: a factory address, not the random (locally administered)
 *    one a previous run may have written;
 *  - entry B sends to link k, as it must for the boot loader to transmit
 *    on that link.
 * A base is kept when it explains every candidate (fnp4l_mac_explains())
 * and is the address of one of them, or is backed by two candidates at
 * least; it must be the only one. Noise passes the checks of one LIF with
 * a probability of 1/32 and then makes the choice fail, rather than give
 * an arbitrary address.
 */
static bool fnp4l_loader_mac(struct fnp4l *np,
			     const struct fnp4l_lif_entry *e, u8 *mac_base)
{
	u8 addr[NP4L_NR_PORTS][ETH_ALEN], base[ETH_ALEN];
	unsigned long cand = 0;
	unsigned int k, h;
	bool found = false;

	for (k = 0; k < NP4L_NR_PORTS; k++) {
		if (e[k].err || !(e[k].ahi & NP4L_LIFA_VALID) ||
		    FIELD_GET(NP4L_LIFB_PORT, e[k].blo) != k)
			continue;
		fnp4l_lif_mac_filter(e[k].alo, e[k].ahi, addr[k]);
		if (is_valid_ether_addr(addr[k]) && !is_local_ether_addr(addr[k]))
			cand |= BIT(k);
	}
	if (!cand) {
		dev_warn(np->dev, "no MAC address in the LIF table of the boot loader\n");
		return false;
	}

	/* LIF k written by the boot loader (h = 0), or by this driver */
	for_each_set_bit(k, &cand, NP4L_NR_PORTS) {
		for (h = 0; h < 2; h++) {
			ether_addr_copy(base, addr[k]);
			if (h)
				eth_addr_add(base, -(long)k);
			if (!fnp4l_mac_base_ok(base, addr, cand))
				continue;
			if (found && !ether_addr_equal(base, mac_base)) {
				found = false;
				goto out;
			}
			ether_addr_copy(mac_base, base);
			found = true;
		}
	}

out:
	if (found && np->mac_base_nvmem)
		dev_dbg(np->dev, "MAC address base in the LIF table (LIFs %*pbl)\n",
			NP4L_NR_PORTS, &cand);
	else if (found)
		dev_info(np->dev, "MAC address base from the LIF table (LIFs %*pbl)\n",
			 NP4L_NR_PORTS, &cand);
	else
		dev_warn(np->dev, "LIF table of the boot loader: no single MAC address base (LIFs %*pbl)\n",
			 NP4L_NR_PORTS, &cand);
	return found;
}

/*
 * Base MAC address from the "mac-base" NVMEM cell of the device tree: on
 * the FortiGate 60D, the 6 bytes of the SPI flash of the boot loader that
 * hold the factory base address. Looked up before the
 * driver touches the hardware, as it may defer the probe. Without the
 * cell, when a node on its path is disabled, or when its provider does not
 * come up by the end of boot (driver not built, flash not found), the LIF
 * table is used. For the latter, the device tree lists the cell among the
 * post-init providers of the NP too, so that fw_devlink does not hold the
 * probe for good. Returns 0 or -EPROBE_DEFER.
 */
static int fnp4l_nvmem_mac(struct fnp4l *np)
{
	struct device_node *node = np->dev->of_node, *n;
	struct of_phandle_args cell_spec;
	struct nvmem_cell *cell;
	int idx, ret;
	size_t len;
	u8 *mac;

	idx = of_property_match_string(node, "nvmem-cell-names", "mac-base");
	if (idx < 0)
		return 0;
	if (of_parse_phandle_with_optional_args(node, "nvmem-cells",
						"#nvmem-cell-cells", idx,
						&cell_spec))
		return 0;
	for (n = cell_spec.np; n; n = of_get_next_parent(n)) {
		if (!of_device_is_available(n)) {
			of_node_put(n);
			dev_info(np->dev, "MAC address base: NVMEM cell disabled\n");
			return 0;
		}
	}

	cell = nvmem_cell_get(np->dev, "mac-base");
	if (IS_ERR(cell)) {
		ret = PTR_ERR(cell);
		/* Provider not there yet: wait for it until the end of boot */
		if (ret == -EPROBE_DEFER)
			ret = driver_deferred_probe_check_state(np->dev);
		if (ret == -EPROBE_DEFER)
			return dev_err_probe(np->dev, ret,
					     "MAC address base: NVMEM cell not ready\n");
		dev_warn(np->dev, "MAC address base: NVMEM cell unavailable: %pe\n",
			 ERR_PTR(ret));
		return 0;
	}

	mac = nvmem_cell_read(cell, &len);
	nvmem_cell_put(cell);
	if (IS_ERR(mac)) {
		dev_warn(np->dev, "MAC address base: NVMEM cell unreadable: %pe\n",
			 mac);
		return 0;
	}

	/* A factory address, as for the LIF table */
	if (len == ETH_ALEN && is_valid_ether_addr(mac) &&
	    !is_local_ether_addr(mac)) {
		ether_addr_copy(np->mac_base, mac);
		np->mac_base_valid = true;
		np->mac_base_nvmem = true;
	} else {
		dev_warn(np->dev, "MAC address base: NVMEM cell of %zu bytes without a factory address\n",
			 len);
	}
	kfree(mac);

	return 0;
}

/*
 * State the boot loader leaves the NP in, read before the driver changes
 * it: HIF, packet buffer, and the LIF entries it may have written (read
 * through the table port, not cleared by the read), with the switch LIF
 * of the FortiGate 60D (11). Then the base MAC address, when taken
 * from them.
 */
static void fnp4l_loader_state(struct fnp4l *np)
{
	static const u8 lifs[] = { 0, 1, 2, 3, 11 };
	struct fnp4l_lif_entry e[ARRAY_SIZE(lifs)] = {};
	unsigned int i;

	BUILD_BUG_ON(ARRAY_SIZE(lifs) < NP4L_NR_PORTS);

	dev_dbg(np->dev, "boot loader HIF: RX %#x/%#x write-back %#x, TX %#x/%#x, packet buffer %#x, %u blocks\n",
		np->loader_rx_ring_base, np->loader_rx_ring_size, np->loader_rx_wb_base,
		np->loader_tx_ring_base, np->loader_tx_ring_size,
		fnp4l_rd(np, NP4L_TOP_PBUF_BASE), fnp4l_rd(np, NP4L_TOP_PBUF_BLOCKS));

	spin_lock_bh(&np->tbl_lock);
	for (i = 0; i < ARRAY_SIZE(lifs); i++) {
		e[i].err = fnp4l_tbl_read(np, NP4L_TBL_LIF, lifs[i],
					  &e[i].alo, &e[i].ahi);
		if (!e[i].err)
			e[i].err = fnp4l_tbl_read(np, NP4L_TBL_LIF,
						  lifs[i] + NP4L_LIF_ENTRY_B,
						  &e[i].blo, &e[i].bhi);
	}
	spin_unlock_bh(&np->tbl_lock);

	for (i = 0; i < ARRAY_SIZE(lifs); i++)
		dev_dbg(np->dev, "boot loader LIF %u: A %08x %08x B %08x %08x (%d)\n",
			lifs[i], e[i].alo, e[i].ahi, e[i].blo, e[i].bhi,
			e[i].err);

	/*
	 * lifs[k] = k for the LIFs of the links. The base from the NVMEM
	 * cell comes first; the one of the LIF table is only compared with
	 * it (the addresses themselves are not logged).
	 */
	if (np->soc->loader_lifs_mac) {
		u8 base[ETH_ALEN];
		bool lif = fnp4l_loader_mac(np, e, base);

		if (np->mac_base_nvmem) {
			if (!lif)
				dev_info(np->dev, "MAC address base from NVMEM (none in the LIF table)\n");
			else if (ether_addr_equal(base, np->mac_base))
				dev_info(np->dev, "MAC address base from NVMEM (LIF table: same)\n");
			else
				dev_warn(np->dev, "MAC address base from NVMEM (LIF table: different)\n");
		} else if (lif) {
			ether_addr_copy(np->mac_base, base);
			np->mac_base_valid = true;
		} else {
			dev_warn(np->dev, "MAC address base: none, random addresses\n");
		}
	}
}

/*
 * Base MAC address of the ports: the one of the NVMEM cell, else entry A
 * of LIF 0 on the FortiSOC1 (read again, it may be ours), the one
 * fnp4l_loader_mac() found on the FortiSOC2. Under no lock.
 */
static int fnp4l_base_mac(struct fnp4l *np, u8 *addr)
{
	u32 lo = 0, hi = 0;
	int ret;

	if (np->mac_base_nvmem || np->soc->loader_lifs_mac) {
		if (!np->mac_base_valid)
			return -ENOENT;
		ether_addr_copy(addr, np->mac_base);
		return 0;
	}

	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, 0, &lo, &hi);
	spin_unlock_bh(&np->tbl_lock);
	if (ret)
		return ret;

	fnp4l_lif_mac_filter(lo, hi, addr);
	if (!(hi & NP4L_LIFA_VALID) || !is_valid_ether_addr(addr))
		return -ENOENT;

	return 0;
}

/*
 * LIF of the port node @child, on link @link (its "reg"):
 * "fortinet,logical-interface" where the board classes the link on another
 * LIF than its number, else the link number. On the FortiGate 90D, wan1
 * and wan2, links 0 and 1, are on LIFs 2 and 3. The link indexes the port
 * and every register bank of the NP; the LIF is what the host tag, the LIF
 * table,
 * the traffic counters and the flow keys carry.
 */
static u32 fnp4l_of_port_lif(const struct device_node *child, u32 link)
{
	u32 lif;

	if (of_property_read_u32(child, "fortinet,logical-interface", &lif))
		return link;

	return lif;
}

/* MTU field of the LIF of @port, see NP4L_LIF_MTU */
static u32 fnp4l_lif_mtu(const struct fnp4l_port *port, unsigned int mtu)
{
	return port->lif_mtu_fixed ? NP4L_LIF_MTU : mtu;
}

/*
 * Entries A (MAC filter) and B of the LIF of a port, at probe with the
 * HIF stopped. The FortiSOC1 boot loader only initialises LIF 0; the other
 * entries hold whatever survived in the table SRAM (leftovers of a
 * previous system after a watchdog reset, noise after a power cycle).
 * Only LIF 0 is trusted there. The FortiSOC2 boot loader sets up the LIF of
 * the link it uses instead, see fnp4l_loader_mac().
 *  - MAC address of the port: the one from the device tree, else the base
 *    address + port number (the link, not the LIF), as the labels of the
 *    FortiGate 60D number the interfaces of the NP links, else a random
 *    one. FIXME: on the FortiGate 90D, the factory addresses of wan1 and
 *    wan2 are the address of LIF 0 + 1 and + 2, neither their link nor
 *    their LIF. The base is the
 *    one of the "mac-base" NVMEM cell (fnp4l_nvmem_mac()), else the
 *    MAC address of LIF 0 (FortiSOC1) or the one fnp4l_loader_mac()
 *    found (FortiSOC2). The NP filters on the address of entry A.
 *  - both entries are built from scratch, nothing is kept from the table:
 *    the values of LIF 0, link = port, no egress tag, MTU as
 *    fnp4l_lif_mtu().
 *  - traffic counters of the LIF, cleared before the LIF points at them
 *    (the SRAM may hold anything there, even an entry that is not a
 *    counter). Should that fail, the LIF uses the shared counters of the
 *    boot loader and the port only has software statistics.
 */
static int fnp4l_lif_setup(struct fnp4l_port *port)
{
	struct net_device *ndev = port->ndev;
	struct fnp4l *np = port->np;
	u32 alo, ahi, blo, bhi, nalo, nahi, nblo, nbhi;
	u32 lif = port->lif;
	u32 igr, egr;
	u8 addr[ETH_ALEN];
	const u8 *m;
	int ret;

	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, lif, &alo, &ahi);
	if (!ret)
		ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, lif + NP4L_LIF_ENTRY_B,
				     &blo, &bhi);
	spin_unlock_bh(&np->tbl_lock);
	if (ret)
		return dev_err_probe(np->dev, ret, "LIF %u: table read failed\n",
				     lif);

	/*
	 * Address from the device tree, else the base address plus the port
	 * number (the LIF on the FortiSOC1), else a random one.
	 */
	ret = of_get_ethdev_address(port->of_node, ndev);
	if (ret == -EPROBE_DEFER)
		return ret;
	if (ret) {
		if (!fnp4l_base_mac(np, addr)) {
			eth_addr_add(addr, port->id);
			eth_hw_addr_set(ndev, addr);
		} else {
			eth_hw_addr_random(ndev);
			dev_warn(np->dev, "LIF %u: no usable MAC address, using a random one\n",
				 lif);
		}
	}

	/*
	 * No frame reaches the LIF yet (reception of every port cut), so the
	 * read back of the write sees an empty counter.
	 */
	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_write(np, NP4L_TBL_TRAFFIC_CNT, NP4L_TCE_IGR(lif), 0,
			      NP4L_TCE_HI_CNT);
	if (!ret)
		ret = fnp4l_tbl_write(np, NP4L_TBL_TRAFFIC_CNT, NP4L_TCE_EGR(lif), 0,
				      NP4L_TCE_HI_CNT);
	spin_unlock_bh(&np->tbl_lock);
	port->tce = !ret;
	if (port->tce) {
		igr = NP4L_TCE_IGR(lif);
		egr = NP4L_TCE_EGR(lif);
	} else {
		dev_warn(np->dev, "LIF %u: cannot clear traffic counters: %d\n",
			 lif, ret);
		igr = NP4L_TCE_LOADER_IGR;
		egr = NP4L_TCE_LOADER_EGR;
	}

	m = ndev->dev_addr;
	nalo = m[0] | m[1] << 8 | m[2] << 16 | (u32)m[3] << 24;
	nahi = m[4] | m[5] << 8 | NP4L_LIFA_HI_INIT |
	       FIELD_PREP(NP4L_LIFA_EGR_CNT, egr);

	nblo = FIELD_PREP(NP4L_LIFB_MTU, fnp4l_lif_mtu(port, ndev->mtu)) |
	       FIELD_PREP(NP4L_LIFB_PORT, port->id);
	nbhi = NP4L_LIFB_HI_INIT | FIELD_PREP(NP4L_LIFB_IGR_CNT, igr);

	ret = 0;
	spin_lock_bh(&np->tbl_lock);
	if (nalo != alo || nahi != ahi)
		ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, lif, nalo, nahi);
	if (!ret && (nblo != blo || nbhi != bhi))
		ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, lif + NP4L_LIF_ENTRY_B,
				      nblo, nbhi);
	spin_unlock_bh(&np->tbl_lock);
	if (ret)
		return dev_err_probe(np->dev, ret, "LIF %u: table write failed\n",
				     lif);

	return 0;
}

/*
 * @port is a DSA conduit giving a LIF to each port of its switch, flows
 * through them offloaded
 */
static bool fnp4l_dsa_offload(const struct fnp4l_port *port)
{
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	return port && test_bit(port->id, &port->np->dsa_links) &&
	       port->np->dsa_link[port->id].offload;
#else
	return false;
#endif
}

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/* @port is a DSA conduit handled by the driver, offloading or not */
static bool fnp4l_dsa_conduit(const struct fnp4l_port *port)
{
	return port && test_bit(port->id, &port->np->dsa_links);
}

/*
 * LIF @lif is a switch port's and the flows leaving through it are
 * offloaded
 */
static bool fnp4l_dsa_lif_out(const struct fnp4l *np, unsigned int lif)
{
	return lif <= NP4L_DSA_LIF_LAST && test_bit(lif, &np->dsa_lifs) &&
	       np->dsa_out;
}
#endif

/*
 * Default LIF of the port, written once at probe with the HIF stopped. It
 * only matters while the receive side of the port is open, which
 * mac_link_up alone does. A DSA conduit gets it too: the frames of the
 * switch its class table misses go to its LIF.
 */
static void fnp4l_igr_default_lif(struct fnp4l_port *port)
{
	u32 val = NP4L_IGR_DEFLIF_EN | FIELD_PREP(NP4L_IGR_DEFLIF_PORT, port->id) |
		  FIELD_PREP(NP4L_IGR_DEFLIF_LIF, port->lif);

	fnp4l_wr(port->np, NP4L_IGR_DEFAULT_LIF(port->id), val);
}

#ifdef CONFIG_FORTINET_NP4LITE_DSA
static int fnp4l_dsa_rx_action(struct fnp4l_port *port, u32 act);
#endif

/*
 * RX action of the LIF of a port: whether its frames are looked up in the
 * flow table. Only entry B is touched. Under sse_lock. A DSA conduit of
 * FORTINET_NP4LITE_DSA sets the LIFs of its switch ports instead, and
 * keeps its own LIF, the frames its class table misses, on the host.
 */
static int fnp4l_lif_rx_action(struct fnp4l_port *port, u32 act)
{
	struct fnp4l *np = port->np;
	u32 idx = port->lif + NP4L_LIF_ENTRY_B;
	u32 lo, hi, nhi;
	int ret;

#ifdef CONFIG_FORTINET_NP4LITE_DSA
	if (fnp4l_dsa_offload(port))
		return fnp4l_dsa_rx_action(port, act);
#endif

	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, idx, &lo, &hi);
	if (!ret) {
		nhi = (hi & ~NP4L_LIFB_RX_ACTION) |
		      FIELD_PREP(NP4L_LIFB_RX_ACTION, act);
		if (nhi != hi)
			ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, idx, lo, nhi);
	}
	spin_unlock_bh(&np->tbl_lock);

	if (ret)
		netdev_err(port->ndev, "cannot set RX action %u on LIF %u: %d\n",
			   act, port->lif, ret);

	return ret;
}

/*
 * Class mode off and VLAN action table empty: the state of the boot
 * loader, where the default LIF classifies every frame of the port.
 * Under tbl_lock, or before the ports are registered.
 */
static void fnp4l_igr_restore(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	u32 id = port->id;

	fnp4l_wr(np, NP4L_IGR_CLASS_WIN(id),
		 FIELD_PREP(NP4L_IGR_WIN_COUNT, 1) |
		 FIELD_PREP(NP4L_IGR_WIN_BASE, NP4L_CLASS_IDX(id)));
	fnp4l_wr(np, NP4L_IGR_VLAN_WIN(id), 0);
	port->class_on = false;
}

/*
 * Whether a port stays in class mode while its VLAN action table is
 * empty, with one class entry of key 0 to the LIF of the port: the ports
 * of a FortiSOC2 with a VLAN action table (wan1 and wan2 on the FortiGate
 * 60D). The MAC filter of a LIF, its "promisc" bit clear, drops unicast
 * frames to another address (rx_mac_filter_drops) only on a port in class
 * mode, never under the default LIF alone (measured on a FortiGate 60D):
 * without it, an offloaded flow also forwards a frame to a foreign address
 * (seen on wan1/wan2 too).
 */
static bool fnp4l_wan_class(const struct fnp4l_port *port)
{
	return port->np->soc->wan_class && port->vlan_act_avail;
}

/*
 * Class mode on: the class entry of the port written again first (the
 * table survives a watchdog reset, and who wrote it last is unknown), then
 * the window, valid. The entry has key 0, which the engine is not known to
 * match (on link 0, measured): a frame that misses it gets the default
 * LIF, the LIF of the port as well
 * (fnp4l_igr_default_lif()), and the MAC filter applies the same (measured
 * on a FortiGate 60D). Under tbl_lock.
 */
static int fnp4l_igr_class_on(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	u32 lif = port->lif;
	int ret;

	if (port->class_on)
		return 0;

	ret = fnp4l_tbl_write(np, NP4L_TBL_CLASS, NP4L_CLASS_IDX(port->id),
			      FIELD_PREP(NP4L_CLASS_LIF_LO, lif),
			      FIELD_PREP(NP4L_CLASS_LIF_HI, lif >> 8));
	if (ret)
		return ret;

	fnp4l_wr(np, NP4L_IGR_CLASS_WIN(port->id),
		 NP4L_IGR_WIN_EN | FIELD_PREP(NP4L_IGR_WIN_COUNT, 1) |
		 FIELD_PREP(NP4L_IGR_WIN_BASE, NP4L_CLASS_IDX(port->id)));
	port->class_on = true;

	return 0;
}

/*
 * A port with an empty VLAN action table: VLAN action window empty (a
 * tagged frame goes to the host, measured) and, with fnp4l_wan_class(),
 * class mode on; otherwise, or when the class entry cannot be written,
 * the state of the boot loader. Under tbl_lock, or before the ports are
 * registered.
 */
static int fnp4l_igr_idle(struct fnp4l_port *port)
{
	int ret;

	if (!fnp4l_wan_class(port)) {
		fnp4l_igr_restore(port);
		return 0;
	}

	fnp4l_wr(port->np, NP4L_IGR_VLAN_WIN(port->id), 0);
	ret = fnp4l_igr_class_on(port);
	if (ret)
		fnp4l_igr_restore(port);

	return ret;
}

/*
 * Check the class table of a port at probe, and restore the state of the
 * boot loader: a previous kernel may have left class mode on (a watchdog
 * reset does not reset the NP). The VLAN action table is only used on a
 * port whose class window is the one of the boot loader, and never on a
 * DSA conduit, whose class table covers the switch tags.
 */
static void fnp4l_igr_probe(struct fnp4l_port *port, bool conduit)
{
	struct fnp4l *np = port->np;
	u32 id = port->id;
	u32 class_win, vlan_win;
	int ret;

	/*
	 * FortiSOC2: the windows hold noise after a power cycle, class mode
	 * included. Leave every port to its default LIF, as on the FortiSOC1,
	 * DSA conduit included (the boot loader sets no class table for the
	 * switch tags). Before class mode may come on, the EtherType window
	 * of the port goes to 0, an empty table: with bit 31 left set, the NP
	 * would take VLAN action entries for EtherType ones.
	 */
	if (np->soc->igr_noise) {
		fnp4l_igr_restore(port);
		if (conduit || !np->soc->vlan)
			return;
		fnp4l_wr(np, NP4L_IGR_ETYPE_WIN(id), 0);
		port->vlan_act_avail = true;
		/* Then class mode, with fnp4l_wan_class() */
		if (fnp4l_wan_class(port)) {
			spin_lock_bh(&np->tbl_lock);
			ret = fnp4l_igr_idle(port);
			spin_unlock_bh(&np->tbl_lock);
			if (ret)
				dev_warn(np->dev, "port %u: class mode off (%d), no MAC filter\n",
					 id, ret);
		}
		return;
	}

	if (!np->soc->vlan)
		return;

	if (conduit)
		return;

	class_win = fnp4l_rd(np, NP4L_IGR_CLASS_WIN(id));
	vlan_win = fnp4l_rd(np, NP4L_IGR_VLAN_WIN(id));
	if ((class_win & ~NP4L_IGR_WIN_EN) !=
	    (FIELD_PREP(NP4L_IGR_WIN_COUNT, 1) |
	     FIELD_PREP(NP4L_IGR_WIN_BASE, NP4L_CLASS_IDX(id)))) {
		dev_info(np->dev, "port %u: class window %#x, no VLAN offload on input\n",
			 id, class_win);
		return;
	}

	if ((class_win & NP4L_IGR_WIN_EN) || vlan_win)
		dev_warn(np->dev, "port %u: class mode left on, VLAN action window %#x\n",
			 id, vlan_win);
	fnp4l_igr_restore(port);
	port->vlan_act_avail = true;
}

/*
 * TPID of the 802.1Q tags the EGR inserts. The FortiSOC1 boot loader sets
 * it; on the FortiSOC2, whose boot loader is not known to, the driver
 * writes it if it finds another value.
 */
static void fnp4l_egr_init(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	u32 val;

	if (!np->soc->egr_tpid)
		return;

	val = fnp4l_rd(np, NP4L_EGR_VLAN_TPID(port->id));
	if (val == NP4L_TPID_8021Q)
		return;

	dev_info(np->dev, "port %u: EGR TPID %#x, set to %#x\n", port->id, val,
		 NP4L_TPID_8021Q);
	fnp4l_wr(np, NP4L_EGR_VLAN_TPID(port->id), NP4L_TPID_8021Q);
}

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/*
 * FORTINET_NP4LITE_DSA: the ports of a BCM53128 switch, DSA user ports
 * behind a conduit of the NP, each on a LIF of its own: one switch per
 * conduit, one or more conduits per NP (state by conduit in dsa_link[],
 * by LIF for the switch ports: two switches have the same ports 0 to 7).
 *
 * The switch sends its frames to the host with a Broadcom tag after the
 * source address, 00 00 RC TC|port (tag_brcm), measured under b53 as
 * 00 00 20 0p: reason 0x20 for every frame, LACPDUs included, and traffic
 * class 0; 00 00 20 ep with the port-based class 7 of
 * brcm,port-traffic-class = <7>. The class table holds both classes
 * (switch_tc_mask), key 0 (port 0 in class 0) being never matched. The port
 * tag extraction of the IGR of the link of the conduit, with the "TPID"
 * 0x0000, takes that tag off; its low 12 bits (the low nibble of the
 * reason, the class and the port) key the class table of that link, which
 * gives the LIF of the port. The flow engine then keys the flows of each
 * port on its LIF. Frames the class table misses go to the LIF of the
 * conduit, the default LIF, with their tag.
 *
 * Towards the host, the frames of a port LIF arrive without their tag,
 * which the driver puts back before the DSA tagger (as 00 00 00 port);
 * those of the conduit LIF arrive with it (the NP strips the tag of
 * classified frames only). DSA sees no difference.
 * Frames from the host keep going out with the tag of tag_brcm, on the
 * conduit LIF.
 *
 * The device tree turns it on, conduit by conduit: the
 * "fortinet,switch-logical-interfaces" of the conduit gives the LIF of
 * each switch port (0: no port), the conduit keeping its
 * "fortinet,logical-interface"; checked at probe against every port of
 * the NP (fnp4l_dsa_of_lifs()). At probe, the HIF stopped: a LIF per
 * port, its class entries, the IPv4 options of the link to the host, the
 * flows entering through the switch ports offloaded, and those leaving
 * through them: the EGR of the link inserts the tag of tag_brcm, directed
 * to the port (fnp4l_dsa_out()). A conduit without the property, or
 * failing the check, stays as without this option: its frames reach the
 * host with their tag, on the LIF of the conduit.
 */

static bool fnp4l_port_is_conduit(const struct device_node *port_np);

/*
 * RX action of LIF @lif, as fnp4l_lif_rx_action() for the LIF of a port.
 * Under sse_lock.
 */
static int fnp4l_lif_nr_rx_action(struct fnp4l *np, u32 lif, u32 act)
{
	u32 idx = lif + NP4L_LIF_ENTRY_B;
	u32 lo, hi, nhi;
	int ret;

	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, idx, &lo, &hi);
	if (!ret) {
		nhi = (hi & ~NP4L_LIFB_RX_ACTION) |
		      FIELD_PREP(NP4L_LIFB_RX_ACTION, act);
		if (nhi != hi)
			ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, idx, lo, nhi);
	}
	spin_unlock_bh(&np->tbl_lock);

	if (ret)
		dev_err(np->dev, "cannot set RX action %u on LIF %u: %d\n", act, lif,
			ret);

	return ret;
}

/*
 * The conduit binds or unbinds: the LIFs of its switch ports look frames
 * up in the flow table, or send them all to the host, but those of the
 * slaves of a bound bond, which always look them up. The LIF of the
 * conduit stays with the host. Under sse_lock.
 */
static int fnp4l_dsa_rx_action(struct fnp4l_port *port, u32 act)
{
	struct fnp4l *np = port->np;
	const struct fnp4l_dsa_link *link = &np->dsa_link[port->id];
	unsigned int p, lif;
	int ret = 0;

	for (p = 0; p < NP4L_DSA_NR_PORTS; p++) {
		lif = link->lif[p];
		if (!lif)
			continue;
#ifdef CONFIG_FORTINET_NP4LITE_LAG
		/* A slave of a bound bond looks frames up anyway. */
		if (test_bit(lif, &np->lag_lifs))
			continue;
#endif
		if (fnp4l_lif_nr_rx_action(np, lif, act))
			ret = -EIO;
	}

	return ret;
}

/*
 * Entries A and B of the LIFs of the switch ports of the conduit @port,
 * at probe: the address of the conduit, which the user ports inherit,
 * counted with the conduit, frames to the host, the link of the conduit;
 * on output, the port tag of the directed tag of the port
 * (NP4L_DSA_EGR_PORT_TAG). Not promiscuous: the address of the LIF
 * follows that of its user port, see fnp4l_dsa_promisc_apply().
 */
static int fnp4l_dsa_lifs(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	const struct fnp4l_dsa_link *link = &np->dsa_link[port->id];
	const u8 *m = port->ndev->dev_addr;
	u32 igr = NP4L_TCE_LOADER_IGR, egr = NP4L_TCE_LOADER_EGR;
	u32 alo, ahi, blo, bhi;
	unsigned int p;
	int ret = 0;

	if (port->tce) {
		igr = NP4L_TCE_IGR(port->lif);
		egr = NP4L_TCE_EGR(port->lif);
	}
	alo = m[0] | m[1] << 8 | m[2] << 16 | (u32)m[3] << 24;
	ahi = m[4] | m[5] << 8 | NP4L_LIFA_HI_INIT |
	      FIELD_PREP(NP4L_LIFA_EGR_CNT, egr);
	bhi = NP4L_LIFB_HI_INIT | FIELD_PREP(NP4L_LIFB_IGR_CNT, igr);

	spin_lock_bh(&np->tbl_lock);
	for (p = 0; p < NP4L_DSA_NR_PORTS && !ret; p++) {
		u32 lif = link->lif[p];

		if (!lif)
			continue;
		blo = FIELD_PREP(NP4L_LIFB_MTU, NP4L_LIF_MTU) |
		      FIELD_PREP(NP4L_LIFB_PORT, port->id) |
		      FIELD_PREP(NP4L_LIFB_EGR_PORT_TAG, BIT(p));
		ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, lif, alo, ahi);
		if (!ret)
			ret = fnp4l_tbl_write(np, NP4L_TBL_LIF,
					      lif + NP4L_LIF_ENTRY_B, blo, bhi);
		ether_addr_copy(np->dsa_mac[lif], m);
	}
	spin_unlock_bh(&np->tbl_lock);

	return ret;
}

/*
 * Class table of the link of the conduit @port, in its window: an entry
 * per switch port and per reason and class of NP4L_DSA_RC_MASK_DEFAULT
 * and switch_tc_mask, in increasing key order, the first one written
 * NP4L_DSA_CLASS_PAD more times ahead of itself. Then the window, valid.
 */
static int fnp4l_dsa_class(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	const struct fnp4l_dsa_link *link = &np->dsa_link[port->id];
	unsigned long rcs = NP4L_DSA_RC_MASK_DEFAULT;
	unsigned long tcs = switch_tc_mask & GENMASK(7, 0);
	unsigned int rc, tc, p, n = 0, nr_ports = 0;
	u32 idx = link->class_base;
	int ret = 0;

	for (p = 0; p < NP4L_DSA_NR_PORTS; p++)
		nr_ports += !!link->lif[p];
	if (!tcs ||
	    hweight_long(rcs) * hweight_long(tcs) * nr_ports +
	    NP4L_DSA_CLASS_PAD > link->class_max) {
		dev_warn(np->dev, "reason codes %#lx, switch_tc_mask %#x: using 0x1, 0x1\n",
			 rcs, switch_tc_mask);
		rcs = BIT(0);
		tcs = BIT(0);
	}

	spin_lock_bh(&np->tbl_lock);
	for_each_set_bit(rc, &rcs, 16) {
		for_each_set_bit(tc, &tcs, 8) {
			for (p = 0; p < NP4L_DSA_NR_PORTS && !ret; p++) {
				u32 lif = link->lif[p];
				u32 lo = FIELD_PREP(NP4L_CLASS_LIF_LO, lif) |
					 FIELD_PREP(NP4L_CLASS_PORT_TAG,
						    NP4L_DSA_PORT_TAG(rc, tc, p));
				u32 hi = FIELD_PREP(NP4L_CLASS_LIF_HI, lif >> 8);
				unsigned int copies = n ? 1 : 1 + NP4L_DSA_CLASS_PAD;

				if (!lif)
					continue;
				while (copies-- && !ret)
					ret = fnp4l_tbl_write(np, NP4L_TBL_CLASS,
							      idx + n++, lo,
							      hi);
			}
		}
	}

	if (!ret)
		fnp4l_wr(np, NP4L_IGR_CLASS_WIN(port->id),
			 NP4L_IGR_WIN_EN | FIELD_PREP(NP4L_IGR_WIN_COUNT, n) |
			 FIELD_PREP(NP4L_IGR_WIN_BASE, link->class_base));
	spin_unlock_bh(&np->tbl_lock);
	if (!ret)
		dev_info(np->dev, "switch ports of link %u: %u class entries at %u (first one %u times), reasons %#lx, classes %#lx\n",
			 port->id, n, idx, 1 + NP4L_DSA_CLASS_PAD, rcs, tcs);

	return ret;
}

/* Number of DSA conduits among the available ports of the NP of @child */
static unsigned int fnp4l_dsa_nr_conduits(const struct device_node *child)
{
	struct device_node *ports_np = of_get_parent(child);
	unsigned int n = 0;

	for_each_available_child_of_node_scoped(ports_np, c)
		n += fnp4l_port_is_conduit(c);
	of_node_put(ports_np);

	return n;
}

/*
 * "fortinet,switch-logical-interfaces" of the conduit @port into @lifs: one LIF per
 * switch port, 0 for none, at most NP4L_DSA_LIF_LAST, each once, never the
 * LIF of the conduit; and none of them the LIF of another port of the NP
 * or of a switch port of another conduit, nor the LIF of the conduit a
 * switch port of another conduit (the device tree of every port, probed
 * or not). An error leaves the conduit without offload.
 */
static int fnp4l_dsa_of_lifs(struct fnp4l_port *port, u8 *lifs)
{
	struct fnp4l *np = port->np;
	u32 v[NP4L_DSA_NR_PORTS], w[NP4L_DSA_NR_PORTS], id, lif;
	struct device_node *ports_np;
	unsigned long seen = 0;
	unsigned int p, q;
	int n, ret = 0;

	n = of_property_count_u32_elems(port->of_node,
					 "fortinet,switch-logical-interfaces");
	if (n != NP4L_DSA_NR_PORTS ||
	    of_property_read_u32_array(port->of_node,
				       "fortinet,switch-logical-interfaces",
				       v, NP4L_DSA_NR_PORTS)) {
		dev_warn(np->dev, "port %u: fortinet,switch-logical-interfaces: %d values, %u expected\n",
			 port->id, n, NP4L_DSA_NR_PORTS);
		return -EINVAL;
	}

	for (p = 0; p < NP4L_DSA_NR_PORTS; p++) {
		lif = v[p];
		if (!lif)
			continue;
		if (lif > NP4L_DSA_LIF_LAST || lif == port->lif ||
		    test_bit(lif, &seen)) {
			dev_warn(np->dev, "port %u: switch port %u on LIF %u: above %u, the LIF of the conduit or twice\n",
				 port->id, p, lif, NP4L_DSA_LIF_LAST);
			return -EINVAL;
		}
		__set_bit(lif, &seen);
	}
	if (!seen) {
		dev_warn(np->dev, "port %u: fortinet,switch-logical-interfaces names no port\n",
			 port->id);
		return -EINVAL;
	}

	ports_np = of_get_parent(port->of_node);
	for_each_available_child_of_node_scoped(ports_np, child) {
		if (of_property_read_u32(child, "reg", &id) || id == port->id)
			continue;
		lif = fnp4l_of_port_lif(child, id);
		if (lif <= NP4L_DSA_LIF_LAST && test_bit(lif, &seen)) {
			dev_warn(np->dev, "port %u: LIF %u of a switch port is the LIF of port %u\n",
				 port->id, lif, id);
			ret = -EBUSY;
			break;
		}
		if (of_property_read_u32_array(child,
					       "fortinet,switch-logical-interfaces",
					       w, NP4L_DSA_NR_PORTS))
			continue;
		for (q = 0; q < NP4L_DSA_NR_PORTS && !ret; q++) {
			if (!w[q])
				continue;
			if (w[q] == port->lif ||
			    (w[q] <= NP4L_DSA_LIF_LAST && test_bit(w[q], &seen))) {
				dev_warn(np->dev, "port %u: LIF %u also a switch port of port %u\n",
					 port->id, w[q], id);
				ret = -EBUSY;
			}
		}
		if (ret)
			break;
	}
	of_node_put(ports_np);
	if (ret)
		return ret;

	for (p = 0; p < NP4L_DSA_NR_PORTS; p++)
		lifs[p] = v[p];

	return 0;
}

/*
 * 802.1Q recognition by the IGR of the link of a conduit: on (@on) while
 * its switch ports are offloaded, as on every other port, off otherwise,
 * also when a previous kernel left it on (a warm reset does not reset the
 * NP).
 *
 * The BCM53128 sends the frames of its user ports to the IMP with an
 * 802.1Q tag of VID 0 after the Broadcom tag when its 802.1Q mode is on: a
 * management port keeps the tag whatever its untag bit (a priority tag,
 * the priority of the port). Without the recognition, the IHP sees an
 * EtherType of 0x8100 once the IGR took the Broadcom tag off, and the
 * flow engine never finds the flow (measured: classified, inserted, all
 * to the host; 0x10081 written live: offloaded at once). The IGR takes
 * the tag off and the engine keys on its VID, 0 as the flows of a user
 * port (fnp4l_dsa_port(): neither bridged nor 802.1Q). The TCI reaches the
 * host in the host tag, see fnp4l_dsa_rx(). Frames without that tag are
 * not changed.
 */
static void fnp4l_dsa_igr_vid(struct fnp4l_port *port, bool on)
{
	struct fnp4l *np = port->np;
	u32 want = 0, val;

	if (on)
		want = NP4L_IGR_TPID_EN | NP4L_TPID_8021Q;
	val = fnp4l_rd(np, NP4L_IGR_VLAN_TPID(port->id));
	if (val == want)
		return;
	dev_info(np->dev, "port %u: IGR 802.1Q %#x, set to %#x\n", port->id,
		 val, want);
	fnp4l_wr(np, NP4L_IGR_VLAN_TPID(port->id), want);
}

/*
 * The DSA conduit @port, at probe with the HIF stopped, its LIF and
 * default LIF written. With "fortinet,switch-logical-interfaces": a LIF
 * per switch port, the class table, the IPv4 options of the link to the
 * host and the tags of the EGR, then port tag extraction last, once the
 * class table is complete. Without it, or on an error, the switch ports
 * are not offloaded: the class table off, the conduit on its LIF with the
 * default LIF enabled (bit 12), the frames of the switch reaching the
 * host as without this option.
 */
static void fnp4l_dsa_probe(struct fnp4l_port *port)
{
	const u32 regs[] = { NP4L_IGR_TAG2_TPID(port->id), NP4L_IGR_HTAG_TPID(port->id) };
	struct fnp4l *np = port->np;
	struct fnp4l_dsa_link *link = &np->dsa_link[port->id];
	unsigned int i, p, lif;
	u32 val;
	int ret;

	if (!np->soc->dsa_offload)
		return;
	link->port = port;
	__set_bit(port->id, &np->dsa_links);

	if (!of_property_present(port->of_node,
				 "fortinet,switch-logical-interfaces")) {
		dev_info(np->dev, "port %u: DSA conduit without fortinet,switch-logical-interfaces, switch ports not offloaded\n",
			 port->id);
		goto off;
	}
	/* The whole area for a conduit alone on its NP, else a window per link */
	if (fnp4l_dsa_nr_conduits(port->of_node) == 1) {
		link->class_base = NP4L_DSA_CLASS_BASE;
		link->class_max = NP4L_DSA_CLASS_MAX;
	} else {
		link->class_base = NP4L_DSA_CLASS_BASE + port->id * NP4L_DSA_CLASS_WIN;
		link->class_max = NP4L_DSA_CLASS_WIN;
	}
	if (fnp4l_dsa_of_lifs(port, link->lif)) {
		memset(link->lif, 0, sizeof(link->lif));
		dev_warn(np->dev, "port %u: switch ports not offloaded\n",
			 port->id);
		goto off;
	}

	/* Second tag and host tag: off, as the boot loader leaves them (0) */
	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		val = fnp4l_rd(np, regs[i]);
		if (!val)
			continue;
		dev_info(np->dev, "IGR register %#x = %#x, set to 0\n", regs[i],
			 val);
		fnp4l_wr(np, regs[i], 0);
	}

	/*
	 * EtherType window empty before class mode: after a power cycle it
	 * holds noise, bit 31 possibly set (fnp4l_igr_probe() leaves it on a
	 * conduit).
	 */
	spin_lock_bh(&np->tbl_lock);
	fnp4l_wr(np, NP4L_IGR_ETYPE_WIN(port->id), 0);
	spin_unlock_bh(&np->tbl_lock);

	ret = fnp4l_dsa_lifs(port);
	if (!ret)
		ret = fnp4l_dsa_class(port);
	if (ret) {
		dev_err(np->dev, "port %u: table write failed (%d), switch ports not offloaded\n",
			port->id, ret);
		spin_lock_bh(&np->tbl_lock);
		fnp4l_igr_restore(port);
		spin_unlock_bh(&np->tbl_lock);
		fnp4l_igr_default_lif(port);
		memset(link->lif, 0, sizeof(link->lif));
		goto off;
	}

	spin_lock_bh(&np->tbl_lock);
	for (p = 0; p < NP4L_DSA_NR_PORTS; p++) {
		lif = link->lif[p];
		if (!lif)
			continue;
		np->lif_port[lif] = port;
		np->dsa_lif_sw[lif] = p;
		__set_bit(lif, &np->dsa_lifs);
		/* Not promiscuous, see fnp4l_dsa_lifs() */
		__clear_bit(lif, &np->dsa_promisc);
	}
	spin_unlock_bh(&np->tbl_lock);

	val = fnp4l_rd(np, NP4L_EGR_PORT_TAG_TPID(port->id));
	dev_info(np->dev, "port %u: EGR port tag TPID %#x, set to %#x\n", port->id,
		 val, NP4L_DSA_EGR_PORT_TAG);
	fnp4l_wr(np, NP4L_EGR_PORT_TAG_TPID(port->id), NP4L_DSA_EGR_PORT_TAG);

	fnp4l_dsa_igr_vid(port, true);
	fnp4l_wr(np, NP4L_IGR_PORT_TAG_TPID(port->id), NP4L_IGR_TPID_EN);
	link->offload = true;
	dev_info(np->dev, "port %u: switch ports offloaded, conduit on LIF %u, switch port LIFs %*ph\n",
		 port->id, port->lif, NP4L_DSA_NR_PORTS, link->lif);
	return;

off:
	/*
	 * A previous kernel may have left port tag extraction on: a warm
	 * reset does not reset the NP. Back to the boot loader value.
	 */
	val = fnp4l_rd(np, NP4L_IGR_PORT_TAG_TPID(port->id));
	if (val) {
		dev_info(np->dev, "port %u: IGR port tag %#x left on, set to 0\n",
			 port->id, val);
		fnp4l_wr(np, NP4L_IGR_PORT_TAG_TPID(port->id), 0);
	}
	fnp4l_dsa_igr_vid(port, false);
}

static void fnp4l_dsa_promisc_apply(struct fnp4l *np);

/*
 * The LIF of the user port @dp, behind a conduit of this NP giving its
 * switch ports a LIF each, or 0
 */
static unsigned int fnp4l_dsa_dp_lif(struct fnp4l *np,
				     struct dsa_port *dp)
{
	const struct net_device *conduit = dsa_port_to_conduit(dp);
	unsigned int id;

	if (dp->index >= NP4L_DSA_NR_PORTS)
		return 0;
	for_each_set_bit(id, &np->dsa_links, NP4L_NR_PORTS) {
		const struct fnp4l_dsa_link *link = &np->dsa_link[id];

		if (link->port->ndev == conduit &&
		    fnp4l_dsa_offload(link->port))
			return link->lif[dp->index];
	}

	return 0;
}

struct fnp4l_dsa_br {
	struct fnp4l *np;
	struct net_device *br;
	struct dsa_switch_tree *dst;	/* tree of the port asked about */
};

/*
 * A device below the bridge, at any depth: a conduit (DSA links each user
 * port as an upper of its conduit, so the walk reaches it below the port),
 * or a user port of the same DSA tree, the bridge offloaded to it, with a
 * LIF behind a conduit of this NP (with one tree for the two
 * switches of the 90D, the ports of either switch, each routed through its
 * own link; ports of two trees are bridged by the host: refused), or stop
 */
static int fnp4l_dsa_br_lower(struct net_device *lower,
			      struct netdev_nested_priv *priv)
{
	const struct fnp4l_dsa_br *b = priv->data;
	struct dsa_port *dp;

	if (netdev_uses_dsa(lower))
		return 0;
	dp = dsa_port_from_netdev(lower);
	if (IS_ERR(dp)) {
		dev_dbg(b->np->dev, "bridge: %s below it, not a port of the switch\n",
			netdev_name(lower));
		return 1;
	}
	if (dp->ds->dst != b->dst || !dsa_port_offloads_bridge_dev(dp, b->br)) {
		dev_dbg(b->np->dev, "bridge: %s below it, in another tree\n",
			netdev_name(lower));
		return 1;
	}
	if (!fnp4l_dsa_dp_lif(b->np, dp)) {
		dev_dbg(b->np->dev, "bridge: %s below it, no LIF\n",
			netdev_name(lower));
		return 1;
	}

	return 0;
}

/*
 * bridge_offload: whether the user port @dev is in a bridge the
 * NP may route through: offloaded to the switch, not VLAN filtering (the
 * switch would tag the frames to the IMP with the VID), every port below
 * it a port of the tree of @dev with a LIF (fnp4l_dsa_br_lower(): one
 * switch of the 90D, or both under one tree; a bond refused). The switch
 * forwards within the bridge, the NP routes to and from its address, which
 * @addr then gets.
 */
static bool fnp4l_dsa_bridged(struct fnp4l *np, struct net_device *dev,
			      u8 *addr)
{
	struct fnp4l_dsa_br b = { .np = np };
	struct netdev_nested_priv priv = { .data = &b };
	struct net_device *br;
	struct dsa_port *dp;
	unsigned int lif;
	bool ok = false;

	if (!READ_ONCE(bridge_offload) || !dev)
		return false;

	rcu_read_lock();
	br = netdev_master_upper_dev_get_rcu(dev);
	dp = dsa_port_from_netdev(dev);
	if (!br || !netif_is_bridge_master(br) || IS_ERR(dp))
		goto out;
	if (br_vlan_enabled(br)) {
		dev_dbg(np->dev, "bridge %s of %s: VLAN filtering\n",
			netdev_name(br), netdev_name(dev));
		goto out;
	}
	if (!dsa_port_offloads_bridge_dev(dp, br)) {
		dev_dbg(np->dev, "bridge %s of %s: not offloaded to the switch\n",
			netdev_name(br), netdev_name(dev));
		goto out;
	}
	lif = fnp4l_dsa_dp_lif(np, dp);
	if (!lif) {
		dev_dbg(np->dev, "bridge %s of %s: no LIF\n", netdev_name(br),
			netdev_name(dev));
		goto out;
	}
	b.br = br;
	b.dst = dp->ds->dst;
	if (netdev_walk_all_lower_dev_rcu(br, fnp4l_dsa_br_lower, &priv))
		goto out;
	if (addr)
		ether_addr_copy(addr, br->dev_addr);
	ok = true;
out:
	rcu_read_unlock();

	return ok;
}

/* The address of the LIF of the user port @dev: its own, or its bridge's */
static const u8 *fnp4l_dsa_addr(struct fnp4l *np, struct net_device *dev,
				u8 *buf)
{
	return fnp4l_dsa_bridged(np, dev, buf) ? buf : dev->dev_addr;
}

/*
 * Entry A of the LIF @lif of a switch port takes @addr, the address of its
 * user port: the engine takes the source address of the frames it sends
 * there from it. Written while frames flow, as fnp4l_set_mac_address()
 * does. Not written, the filter of the LIF would drop the unicast frames
 * to the user port: the LIF stays promiscuous until it is (dsa_mac_bad).
 */
static void fnp4l_dsa_mac_sync(struct fnp4l *np, unsigned int lif,
			       const u8 *addr)
{
	bool was_bad;
	u32 lo, hi;
	int ret = 0;

	if (WARN_ON_ONCE(lif > NP4L_DSA_LIF_LAST))
		return;

	spin_lock_bh(&np->tbl_lock);
	was_bad = test_bit(lif, &np->dsa_mac_bad);
	if (ether_addr_equal(np->dsa_mac[lif], addr))
		goto out;
	ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, lif, &lo, &hi);
	if (ret)
		goto out;
	lo = addr[0] | addr[1] << 8 | addr[2] << 16 | (u32)addr[3] << 24;
	hi = (hi & ~GENMASK(15, 0)) | addr[4] | addr[5] << 8;
	ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, lif, lo, hi);
	if (!ret)
		ether_addr_copy(np->dsa_mac[lif], addr);
out:
	__assign_bit(lif, &np->dsa_mac_bad, ret);
	spin_unlock_bh(&np->tbl_lock);

	if (ret)
		dev_err(np->dev, "cannot write the address of LIF %u: %d\n", lif,
			ret);
	if (was_bad != !!ret)
		fnp4l_dsa_promisc_apply(np);
}

/*
 * Promiscuous LIFs of the switch ports. The MAC filter
 * of the LIF of a switch port holds the address of its user port (the
 * notifier follows it): a unicast frame to another address, which the
 * switch floods to its CPU port, stops there, where with the LIF
 * promiscuous the flow engine, whose key has no address, forwarded it
 * if its tuple was offloaded (measured: Linux drops it, as
 * PACKET_OTHERHOST). Broadcast gets through the filter; multicast,
 * LACPDUs included, is expected to.
 * A LIF goes promiscuous when its user port needs other addresses than
 * its own: a device above it, directly or not, that is neither a bond nor
 * an 802.1Q device with the address of the port (a bridge, a macvlan, a
 * VLAN or a bond with an address of its own). Its promiscuity alone (a
 * capture) has no notifier event and is not followed. Without the
 * address notifier (fnp4l_dsa_init()): all of them.
 * So does a LIF whose address could not follow that of its user port
 * (dsa_mac_bad). Everything by LIF.
 */
static struct fnp4l *fnp4l_dsa_np;		/* for bridge_offload */
static DEFINE_MUTEX(fnp4l_dsa_np_lock);

/* Write PROMISC in entry A of the LIFs where it changes. */
static void fnp4l_dsa_promisc_apply(struct fnp4l *np)
{
	unsigned long want, changed = 0, guard = 0, purge;
	u32 lif = 0, lo, hi, nhi;
	unsigned int l;
	int ret = 0;

	spin_lock_bh(&np->tbl_lock);
	want = np->dsa_promisc_need | np->dsa_mac_bad;
	for_each_set_bit(l, &np->dsa_lifs, NP4L_DSA_LIF_LAST + 1)
		if (!fnp4l_dsa_lif_out(np, l))
			__set_bit(l, &want);
	want &= np->dsa_lifs;
	for_each_set_bit(l, &np->dsa_lifs, NP4L_DSA_LIF_LAST + 1) {
		bool on = test_bit(l, &want);

		if (on == test_bit(l, &np->dsa_promisc))
			continue;
		lif = l;
		ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, lif, &lo, &hi);
		if (ret)
			break;
		nhi = on ? hi | NP4L_LIFA_PROMISC : hi & ~NP4L_LIFA_PROMISC;
		if (nhi != hi)
			ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, lif, lo, nhi);
		if (ret)
			break;
		__assign_bit(l, &np->dsa_promisc, on);
		__set_bit(l, &changed);
	}
	want = np->dsa_promisc;
	/*
	 * No flow enters the engine through a promiscuous LIF:
	 * those offloaded before it went promiscuous are purged,
	 * new ones refused (fnp4l_dsa_guarded()).
	 */
	for_each_set_bit(l, &want, NP4L_DSA_LIF_LAST + 1)
		if (fnp4l_dsa_lif_out(np, l))
			__set_bit(l, &guard);
	purge = guard & ~np->dsa_guard;
	np->dsa_guard = guard;
	np->dsa_purge |= purge;
	spin_unlock_bh(&np->tbl_lock);

	if (ret)
		dev_err(np->dev, "cannot set the MAC filter of LIF %u: %d\n",
			lif, ret);
	if (changed)
		dev_info(np->dev, "switch ports: promiscuous LIFs %#lx\n",
			 want);
	/* May run under the lock of the flow engine: the purge takes it. */
	if (purge)
		queue_work(system_wq, &np->dsa_purge_work);
}

/*
 * Whether the flows that enter through @lif, the LIF of a switch port,
 * are kept out of the flow engine: with the address notifier, while the LIF is
 * promiscuous (dsa_guard). Under sse_lock: a LIF goes promiscuous before
 * the purge that follows takes it, so an entry added in between is
 * purged, and none after.
 */
static bool fnp4l_dsa_guarded(struct fnp4l *np, unsigned int lif)
{
	return lif <= NP4L_DSA_LIF_LAST && test_bit(lif, &np->dsa_guard);
}

static unsigned int fnp4l_dsa_purge_lifs(struct fnp4l *np,
					 unsigned long lifs);

/*
 * LIFs of switch ports that have just gone promiscuous (dsa_purge): the
 * MAC filter of the LIF no longer stops the unicast frames to other
 * addresses, which the flow engine, whose key has no address, forwards if
 * their tuple is offloaded. The driver refuses the flows of a bridged
 * port, but an entry offloaded before the port joined a bridge (or got a
 * macvlan, a VLAN with an address of its own...) outlived it (seen on
 * hardware). Delete the engine entries of the flows entering through
 * these LIFs, under the lock of the flow engine; then have the flow
 * tables tear down the flows through the user port, and through its bond,
 * outside that lock: the cleanup waits for the work of the flow table,
 * whose callbacks take it (as fnp4l_ipsec_ft_work()). The flows go
 * back to the host, and to the slow path. Under RTNL (dsa_user).
 */
static void fnp4l_dsa_purge(struct fnp4l *np)
{
	struct net_device *dev, *bond, *last = NULL;
	unsigned int lif, n = 0;
	unsigned long lifs;

	ASSERT_RTNL();
	mutex_lock(&np->sse_lock);
	spin_lock_bh(&np->tbl_lock);
	lifs = np->dsa_purge;
	np->dsa_purge = 0;
	spin_unlock_bh(&np->tbl_lock);
	if (lifs)
		n = fnp4l_dsa_purge_lifs(np, lifs);
	mutex_unlock(&np->sse_lock);
	if (!lifs)
		return;

	atomic_long_add(n, &np->dsa_promisc_purged);
	dev_info(np->dev, "switch port LIFs %#lx promiscuous: %u offloaded flow directions back to the host\n",
		 lifs, n);

	if (!IS_ENABLED(CONFIG_NF_FLOW_TABLE))
		return;
	for_each_set_bit(lif, &lifs, NP4L_DSA_LIF_LAST + 1) {
		dev = np->dsa_user[lif];
		if (!dev)
			continue;
		nf_flow_table_cleanup(dev);
		bond = netdev_master_upper_dev_get(dev);
		if (bond && netif_is_bond_master(bond) && bond != last) {
			nf_flow_table_cleanup(bond);
			last = bond;
		}
	}
}

/* The purge of a LIF gone promiscuous outside the notifier */
static void fnp4l_dsa_purge_work(struct work_struct *work)
{
	struct fnp4l *np = container_of(work, struct fnp4l,
					dsa_purge_work);

	rtnl_lock();
	fnp4l_dsa_purge(np);
	rtnl_unlock();
}

static int fnp4l_dsa_upper(struct net_device *upper,
			   struct netdev_nested_priv *priv)
{
	const struct net_device *dev = priv->data;

	if ((netif_is_bond_master(upper) || is_vlan_dev(upper)) &&
	    ether_addr_equal(upper->dev_addr, dev->dev_addr))
		return 0;

	return 1;	/* stop: promiscuous */
}

/*
 * Which LIFs must be promiscuous, from the devices above, and the address
 * of each (its user port's, or with bridge_offload that of its bridge,
 * fnp4l_dsa_bridged(): then not promiscuous, the switch forwarding
 * within the bridge). A port that joins or leaves such a bridge has its
 * flows torn down: built for the other address. Under RTNL.
 */
static void fnp4l_dsa_promisc_update(struct fnp4l *np)
{
	unsigned long need = 0, bridged = 0, changed;
	struct netdev_nested_priv priv;
	u8 buf[ETH_ALEN];
	unsigned int lif;

	ASSERT_RTNL();
	for_each_set_bit(lif, &np->dsa_lifs, NP4L_DSA_LIF_LAST + 1) {
		struct net_device *dev = np->dsa_user[lif];

		if (!dev)
			continue;
		if (fnp4l_dsa_bridged(np, dev, buf)) {
			__set_bit(lif, &bridged);
			fnp4l_dsa_mac_sync(np, lif, buf);
			continue;
		}
		fnp4l_dsa_mac_sync(np, lif, dev->dev_addr);
		priv.data = dev;
		rcu_read_lock();
		if (netdev_walk_all_upper_dev_rcu(dev, fnp4l_dsa_upper,
						  &priv))
			__set_bit(lif, &need);
		rcu_read_unlock();
	}

	spin_lock_bh(&np->tbl_lock);
	np->dsa_promisc_need = need;
	spin_unlock_bh(&np->tbl_lock);
	fnp4l_dsa_promisc_apply(np);

	changed = bridged ^ np->dsa_bridged;
	WRITE_ONCE(np->dsa_bridged, bridged);
	if (changed)
		dev_info(np->dev, "switch ports: LIFs routed through a bridge %#lx\n",
			 bridged);
	if (!changed || !IS_ENABLED(CONFIG_NF_FLOW_TABLE))
		return;
	for_each_set_bit(lif, &changed, NP4L_DSA_LIF_LAST + 1)
		if (np->dsa_user[lif])
			nf_flow_table_cleanup(np->dsa_user[lif]);
}

/* bridge_offload changed: the ports read again */
static int fnp4l_bridge_param(const char *val,
			      const struct kernel_param *kp)
{
	int ret = param_set_bool(val, kp);

	if (ret)
		return ret;
	mutex_lock(&fnp4l_dsa_np_lock);
	if (fnp4l_dsa_np) {
		rtnl_lock();
		fnp4l_dsa_promisc_update(fnp4l_dsa_np);
		fnp4l_dsa_purge(fnp4l_dsa_np);
		rtnl_unlock();
	}
	mutex_unlock(&fnp4l_dsa_np_lock);

	return 0;
}

/*
 * A station learnt by a bridge on a port, or forgotten there
 * (bridge_offload): an offloaded flow towards it through another
 * port of the bridge would keep sending there, and a forgotten station
 * to a port the bridge no longer names (directed output). Queued for
 * fnp4l_dsa_fdb_work(). Atomic.
 */
static int fnp4l_dsa_fdb_event(struct notifier_block *nb,
			       unsigned long event, void *ptr)
{
	struct fnp4l *np = container_of(nb, struct fnp4l, dsa_fdb_nb);
	struct switchdev_notifier_fdb_info *fdb = ptr;
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	unsigned long flags;

	/* A deletion: an entry put by the user only, not an ageing one
	 * (offloaded stations are not seen by the bridge) */
	if ((event != SWITCHDEV_FDB_ADD_TO_DEVICE &&
	     (event != SWITCHDEV_FDB_DEL_TO_DEVICE || !fdb->added_by_user)) ||
	    fdb->is_local ||
	    !READ_ONCE(np->dsa_bridged) || IS_ERR(dsa_port_from_netdev(dev)))
		return NOTIFY_DONE;

	spin_lock_irqsave(&np->dsa_fdb_lock, flags);
	if (np->dsa_fdb_n < ARRAY_SIZE(np->dsa_fdb_dev)) {
		dev_hold(dev);
		np->dsa_fdb_dev[np->dsa_fdb_n] = dev;
		ether_addr_copy(np->dsa_fdb_addr[np->dsa_fdb_n], fdb->addr);
		np->dsa_fdb_del[np->dsa_fdb_n] =
			event == SWITCHDEV_FDB_DEL_TO_DEVICE;
		np->dsa_fdb_n++;
	} else {
		np->dsa_fdb_lost = true;
	}
	spin_unlock_irqrestore(&np->dsa_fdb_lock, flags);
	queue_work(system_wq, &np->dsa_fdb_work);

	return NOTIFY_DONE;
}

/*
 * Tear down the flows towards the stations learnt on another port than
 * the one of their output LIF, or towards stations the bridge has
 * forgotten, a stale static entry left behind (all of a bridge, past a
 * full ring): their packets go through the host, which offers them anew
 * once the flow table resolves the new port. Under no lock.
 */
static void fnp4l_dsa_fdb_work(struct work_struct *work)
{
	struct fnp4l *np = container_of(work, struct fnp4l,
					dsa_fdb_work);
	struct net_device *devs[ARRAY_SIZE(np->dsa_fdb_dev)];
	u8 addrs[ARRAY_SIZE(np->dsa_fdb_dev)][ETH_ALEN];
	bool dels[ARRAY_SIZE(np->dsa_fdb_dev)];
	struct fnp4l_flow *flow;
	unsigned int i, n, bkt, lif;
	unsigned long old = 0, flags;
	struct dsa_port *dp;
	bool lost;

	spin_lock_irqsave(&np->dsa_fdb_lock, flags);
	n = np->dsa_fdb_n;
	memcpy(devs, np->dsa_fdb_dev, n * sizeof(devs[0]));
	memcpy(addrs, np->dsa_fdb_addr, n * ETH_ALEN);
	memcpy(dels, np->dsa_fdb_del, n * sizeof(dels[0]));
	np->dsa_fdb_n = 0;
	lost = np->dsa_fdb_lost;
	np->dsa_fdb_lost = false;
	spin_unlock_irqrestore(&np->dsa_fdb_lock, flags);

	rtnl_lock();
	mutex_lock(&np->sse_lock);
	for (i = 0; i < n; i++) {
		dp = dsa_port_from_netdev(devs[i]);
		lif = IS_ERR(dp) ? 0 : fnp4l_dsa_dp_lif(np, dp);
		hash_for_each(np->ft_flows, bkt, flow, node) {
			if (!flow->dsa_out_lif ||
			    !ether_addr_equal(flow->h_dest, addrs[i]))
				continue;
			/* A forgotten station: whatever port the event
			 * names; a learnt one: another port than it. */
			if (dels[i] || flow->dsa_out_lif != lif)
				__set_bit(flow->dsa_out_lif, &old);
		}
	}
	mutex_unlock(&np->sse_lock);
	if (lost)
		old |= np->dsa_bridged;
	if (old && IS_ENABLED(CONFIG_NF_FLOW_TABLE)) {
		for_each_set_bit(lif, &old, NP4L_DSA_LIF_LAST + 1) {
			if (!np->dsa_user[lif])
				continue;
			nf_flow_table_cleanup(np->dsa_user[lif]);
			atomic_long_inc(&np->dsa_fdb_moves);
		}
		dev_info(np->dev, "switch ports: station moved or forgotten, flows through LIFs %#lx torn down\n",
			 old);
	}
	rtnl_unlock();

	for (i = 0; i < n; i++)
		dev_put(devs[i]);
}

/*
 * The LIF of the user port @dp, behind a conduit of this NP whose flows
 * leave through the switch ports
 * (the notifier follows those only), or 0
 */
static unsigned int fnp4l_dsa_user_lif(struct fnp4l *np,
				       struct dsa_port *dp)
{
	const struct net_device *conduit = dsa_port_to_conduit(dp);
	unsigned int id, lif;

	if (dp->index >= NP4L_DSA_NR_PORTS)
		return 0;
	for_each_set_bit(id, &np->dsa_links, NP4L_NR_PORTS) {
		if (np->dsa_link[id].port->ndev != conduit)
			continue;
		lif = np->dsa_link[id].lif[dp->index];
		if (!fnp4l_dsa_lif_out(np, lif))
			return 0;
		return lif;
	}

	return 0;
}

/*
 * The L2 aggregates of the 90D stay per switch. Its two
 * BCM53128, each behind its own conduit of this NP, are joined by a
 * cascade: bridging a bond whose slaves span both switches would loop
 * through it. Such a bond is allowed, routed only — refuse
 * here, before it happens, its enslavement to a bridge, or that of one
 * more of its ports.
 */
static int fnp4l_dsa_bond_bridge_check(struct fnp4l *np,
				       struct net_device *dev,
				       struct netdev_notifier_changeupper_info *info)
{
	const struct net_device *conduit, *seen = NULL;
	struct net_device *bond, *bridge, *lower;
	struct dsa_port *dp, *dev_dp = NULL;
	struct list_head *iter;

	if (!info->linking)
		return NOTIFY_DONE;

	if (netif_is_bond_master(dev) &&
	    netif_is_bridge_master(info->upper_dev)) {
		bond = dev;
		bridge = info->upper_dev;
	} else {
		dev_dp = dsa_port_from_netdev(dev);
		if (IS_ERR(dev_dp) || !netif_is_bond_master(info->upper_dev))
			return NOTIFY_DONE;
		bridge = netdev_master_upper_dev_get(info->upper_dev);
		if (!bridge || !netif_is_bridge_master(bridge))
			return NOTIFY_DONE;
		bond = info->upper_dev;
	}

	netdev_for_each_lower_dev(bond, lower, iter) {
		dp = dsa_port_from_netdev(lower);
		if (IS_ERR(dp) || !fnp4l_dsa_user_lif(np, dp))
			continue;
		conduit = dsa_port_to_conduit(dp);
		if (seen && seen != conduit)
			goto refuse;
		seen = conduit;
	}

	/* The joining port counts as one more slave of the bond */
	if (dev_dp && fnp4l_dsa_user_lif(np, dev_dp) &&
	    seen && seen != dsa_port_to_conduit(dev_dp))
		goto refuse;

	return NOTIFY_DONE;

refuse:
	NL_SET_ERR_MSG_MOD(info->info.extack,
			   "bond across the two switches: not a bridge port (loop through their cascade)");
	netdev_warn(dev, "%s into %s refused: bond across the two switches, not a bridge port (loop through their cascade)\n",
		    bond->name, bridge->name);
	return notifier_from_errno(-EOPNOTSUPP);
}

/*
 * A user port of a conduit registers, changes its address or goes away;
 * a device gets or loses an upper, or changes its address (above a user
 * port or not: all of them are checked again).
 */
static int fnp4l_dsa_event(struct notifier_block *nb, unsigned long event,
			   void *ptr)
{
	struct fnp4l *np = container_of(nb, struct fnp4l, dsa_nb);
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct dsa_port *dp;
	unsigned int lif;

	switch (event) {
	case NETDEV_PRECHANGEUPPER:
		return fnp4l_dsa_bond_bridge_check(np, dev, ptr);
	case NETDEV_REGISTER:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEUPPER:
	case NETDEV_UNREGISTER:
		break;
	default:
		return NOTIFY_DONE;
	}

	dp = dsa_port_from_netdev(dev);
	lif = IS_ERR(dp) ? 0 : fnp4l_dsa_user_lif(np, dp);
	/* Its address (or its bridge's): fnp4l_dsa_promisc_update() */
	if (lif)
		np->dsa_user[lif] = event == NETDEV_UNREGISTER ? NULL : dev;
	fnp4l_dsa_promisc_update(np);
	/* Before the work: no frame of another address forwarded meanwhile */
	fnp4l_dsa_purge(np);

	return NOTIFY_DONE;
}

static void fnp4l_dsa_exit(void *data)
{
	struct fnp4l *np = data;

	unsigned int i;

	mutex_lock(&fnp4l_dsa_np_lock);
	fnp4l_dsa_np = NULL;
	mutex_unlock(&fnp4l_dsa_np_lock);
	if (np->dsa_fdb_nb.notifier_call)
		unregister_switchdev_notifier(&np->dsa_fdb_nb);
	unregister_netdevice_notifier(&np->dsa_nb);
	cancel_work_sync(&np->dsa_purge_work);
	cancel_work_sync(&np->dsa_fdb_work);
	for (i = 0; i < np->dsa_fdb_n; i++)
		dev_put(np->dsa_fdb_dev[i]);
	np->dsa_fdb_n = 0;
}

/*
 * With a conduit offloading, follow the addresses of the user ports, and
 * the devices above them (fnp4l_dsa_promisc_apply()). Without the
 * notifier, no flow leaves through the switch ports, their LIFs
 * promiscuous, the flows entering through them still offloaded: the ports
 * of the NP stay, whatever happens here.
 */
static void fnp4l_dsa_init(struct fnp4l *np)
{
	unsigned int id;
	bool out = false;
	int ret;

	for_each_set_bit(id, &np->dsa_links, NP4L_NR_PORTS)
		out |= np->dsa_link[id].offload;
	if (!out)
		return;

	np->dsa_nb.notifier_call = fnp4l_dsa_event;
	ret = register_netdevice_notifier(&np->dsa_nb);
	if (!ret)
		ret = devm_add_action_or_reset(np->dev, fnp4l_dsa_exit, np);
	if (ret) {
		dev_warn(np->dev, "switch ports: no address notifier (%d), no flow leaves through them\n",
			 ret);
		np->dsa_out = false;
		/* The LIFs promiscuous */
		fnp4l_dsa_promisc_apply(np);
		return;
	}
	/* bridge_offload: stations moving between ports of a bridge */
	np->dsa_fdb_nb.notifier_call = fnp4l_dsa_fdb_event;
	ret = register_switchdev_notifier(&np->dsa_fdb_nb);
	if (ret) {
		dev_warn(np->dev, "switch ports: no FDB notifier (%d), bridges not followed\n",
			 ret);
		np->dsa_fdb_nb.notifier_call = NULL;
	}
	mutex_lock(&fnp4l_dsa_np_lock);
	fnp4l_dsa_np = np;
	mutex_unlock(&fnp4l_dsa_np_lock);
}

/*
 * A frame of the DSA conduit @port, before the tagger. From the LIF of a switch
 * port, the NP took the tag off: put it back after the source address, with the
 * port, as tag_brcm reads it; unless the tag is still there (the first two
 * bytes of a tag are 0, never those of an EtherType or a length), counted. From
 * the LIF of the conduit, or without the class table, the tag is in place:
 * logged (debug) and, when offloading, counted as a miss; with the port tag
 * extraction on, a frame whose tag is not there (taken off where it was not
 * expected) is dropped, counted, rather than handed to the tagger with its
 * EtherType for a tag. Returns false to drop the frame.
 */
static bool fnp4l_dsa_rx(struct fnp4l_port *port, struct sk_buff *skb,
			 unsigned int lif, u16 *tci)
{
	struct fnp4l *np = port->np;
	bool offload = np->dsa_link[port->id].offload;
	unsigned int sw = lif <= NP4L_LIF_MAX ? np->dsa_lif_sw[lif] : NP4L_DSA_NONE;
	u8 *tag = skb->data + 2 * ETH_ALEN;

	/*
	 * 802.1Q tag the IGR took off (fnp4l_dsa_igr_vid()): a priority
	 * tag, VID 0, is the one of the IMP, dropped as the stack would drop
	 * it; another VID goes up, counted.
	 */
	if (*tci) {
		WRITE_ONCE(np->dsa_rx_last_tci, *tci);
		if (*tci & VLAN_VID_MASK) {
			atomic_long_inc(&np->dsa_rx_vid_tag);
		} else {
			atomic_long_inc(&np->dsa_rx_prio_tag);
			*tci = 0;
		}
	}

	if (sw == NP4L_DSA_NONE) {
		if (skb->len < ETH_HLEN + NP4L_DSA_TAG_LEN)
			return true;
		if (offload && (tag[0] || tag[1])) {
			atomic_long_inc(&np->dsa_rx_untagged);
			dev_dbg_ratelimited(np->dev, "frame without switch tag on LIF %u, dropped: %*ph\n",
					    lif, NP4L_DSA_TAG_LEN, tag);
			return false;
		}
		if (offload)
			atomic_long_inc(&np->dsa_rx_missed);
		dev_dbg_ratelimited(np->dev, "switch frame on LIF %u, tag %*ph, EtherType %*ph\n",
				    lif, NP4L_DSA_TAG_LEN, tag, 2,
				    tag + NP4L_DSA_TAG_LEN);
		return true;
	}

	if (!tag[0] && !tag[1]) {
		atomic_long_inc(&np->dsa_rx_tagged);
		return true;
	}

	tag = skb_push(skb, NP4L_DSA_TAG_LEN);
	memmove(tag, tag + NP4L_DSA_TAG_LEN, 2 * ETH_ALEN);
	tag += 2 * ETH_ALEN;
	tag[0] = 0;
	tag[1] = 0;
	tag[2] = 0;
	tag[3] = sw;
	atomic_long_inc(&np->dsa_rx_retag);

	return true;
}
#endif /* CONFIG_FORTINET_NP4LITE_DSA */

/*
 * Write the VLAN action table of @port to the NP: class mode first, unless it
 * is on already (fnp4l_igr_class_on(), the VLAN action window still empty),
 * then its entries, then its window. An entry depends on its key alone and is
 * written in one command: while the table is rewritten, a lookup may miss (the
 * frame goes to the host), never find the entry of another VID. An empty table
 * leaves the port as fnp4l_igr_idle() does (class mode on with fnp4l_wan_class(),
 * else the state of the boot loader); an error restores the state of the boot
 * loader, class mode off, which marks the table as in memory only. Under
 * sse_lock.
 */
static int fnp4l_vlan_act_sync(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	u32 base = NP4L_VLAN_ACT_BASE(port->id);
	u32 lif = port->lif;
	unsigned int i;
	int ret;

	lockdep_assert_held(&np->sse_lock);
	spin_lock_bh(&np->tbl_lock);
	if (!port->vlan_act_nr) {
		ret = fnp4l_igr_idle(port);
		goto out;
	}

	ret = fnp4l_igr_class_on(port);
	if (ret)
		goto err;

	for (i = 0; i < port->vlan_act_nr; i++) {
		u16 vid = port->vlan_act_vid[i];

		ret = fnp4l_tbl_write(np, NP4L_TBL_CLASS, base + i,
				      FIELD_PREP(NP4L_VLAN_ACT_VID, vid) |
				      FIELD_PREP(NP4L_VLAN_ACT_LIF, lif) |
				      FIELD_PREP(NP4L_VLAN_ACT_FWD_VID_LO, vid),
				      FIELD_PREP(NP4L_VLAN_ACT_FWD_VID_HI, vid >> 8) |
				      FIELD_PREP(NP4L_VLAN_ACT_FWD_LIF, lif) |
				      FIELD_PREP(NP4L_VLAN_ACT_OP,
						    NP4L_VLAN_ACT_OP_FLOW));
		if (ret)
			goto err;
	}

	fnp4l_wr(np, NP4L_IGR_VLAN_WIN(port->id),
		 NP4L_IGR_WIN_EN | FIELD_PREP(NP4L_IGR_WIN_COUNT, port->vlan_act_nr) |
		 FIELD_PREP(NP4L_IGR_WIN_BASE, base));
	goto out;

err:
	fnp4l_igr_restore(port);
out:
	spin_unlock_bh(&np->tbl_lock);
	if (ret && !port->vlan_act_nr)
		netdev_err(port->ndev, "class mode off (%d), no MAC filter\n",
			   ret);
	else if (ret)
		netdev_err(port->ndev, "cannot write the VLAN action table: %d\n",
			   ret);

	return ret;
}

/* Position of @vid in the VLAN action table of @port, or where it goes */
static unsigned int fnp4l_vlan_act_pos(const struct fnp4l_port *port,
				       u16 vid)
{
	unsigned int i;

	for (i = 0; i < port->vlan_act_nr; i++)
		if (port->vlan_act_vid[i] >= vid)
			break;

	return i;
}

static void fnp4l_vlan_act_del(struct fnp4l_port *port, unsigned int i)
{
	unsigned int n = port->vlan_act_nr - i - 1;

	memmove(&port->vlan_act_vid[i], &port->vlan_act_vid[i + 1],
		n * sizeof(port->vlan_act_vid[0]));
	memmove(&port->vlan_act_refs[i], &port->vlan_act_refs[i + 1],
		n * sizeof(port->vlan_act_refs[0]));
	port->vlan_act_nr--;
}

/*
 * Take a reference on the VLAN action entry of @vid on @port, adding the
 * entry if needed: frames of the port with that VID are then looked up in
 * the flow table. -ENOSPC when the table is full. Under sse_lock.
 */
static int fnp4l_vlan_act_get(struct fnp4l_port *port, u16 vid)
{
	unsigned int i = fnp4l_vlan_act_pos(port, vid);
	unsigned int n = port->vlan_act_nr;
	int ret;

	lockdep_assert_held(&port->np->sse_lock);
	if (i < n && port->vlan_act_vid[i] == vid) {
		/*
		 * Class mode off with a table that is not empty: a write
		 * failed, and the table is in memory only. Try again.
		 */
		if (!port->class_on) {
			ret = fnp4l_vlan_act_sync(port);
			if (ret)
				return ret;
		}
		port->vlan_act_refs[i]++;
		return 0;
	}
	if (n == NP4L_VLAN_ACT_MAX)
		return -ENOSPC;

	memmove(&port->vlan_act_vid[i + 1], &port->vlan_act_vid[i],
		(n - i) * sizeof(port->vlan_act_vid[0]));
	memmove(&port->vlan_act_refs[i + 1], &port->vlan_act_refs[i],
		(n - i) * sizeof(port->vlan_act_refs[0]));
	port->vlan_act_vid[i] = vid;
	port->vlan_act_refs[i] = 1;
	port->vlan_act_nr++;

	ret = fnp4l_vlan_act_sync(port);
	if (ret)
		fnp4l_vlan_act_del(port, i);

	return ret;
}

/*
 * Drop a reference taken by fnp4l_vlan_act_get(), and the entry with the
 * last one. The entry is gone already when the table was emptied by
 * fnp4l_vlan_act_clear(). Under sse_lock.
 */
static void fnp4l_vlan_act_put(struct fnp4l_port *port, u16 vid)
{
	unsigned int i = fnp4l_vlan_act_pos(port, vid);

	lockdep_assert_held(&port->np->sse_lock);
	if (i == port->vlan_act_nr || port->vlan_act_vid[i] != vid)
		return;
	if (--port->vlan_act_refs[i])
		return;

	fnp4l_vlan_act_del(port, i);
	fnp4l_vlan_act_sync(port);
}

/*
 * Empty the VLAN action table of @port, whatever the references, and
 * leave class mode, unless fnp4l_wan_class() keeps it (fnp4l_igr_idle()).
 * Under sse_lock.
 */
static void fnp4l_vlan_act_clear(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	int ret;

	lockdep_assert_held(&np->sse_lock);
	if (!port->vlan_act_avail)
		return;

	port->vlan_act_nr = 0;
	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_igr_idle(port);
	spin_unlock_bh(&np->tbl_lock);
	if (ret)
		netdev_err(port->ndev, "class mode off (%d), no MAC filter\n",
			   ret);
}

#ifdef CONFIG_FORTINET_NP4LITE_LAG
/* Slaves of the bonds bound to a flow table, see struct fnp4l_lag */
static unsigned long fnp4l_lag_ports(const struct fnp4l *np)
{
	return np->lag_ports;
}

/*
 * Neither port nor bond bound to a flow table, nor IPsec security
 * association: the engine can stop.
 */
static bool fnp4l_ft_idle(const struct fnp4l *np)
{
	return !np->ft_ports && list_empty(&np->lags) &&
	       !fnp4l_ipsec_busy(np->ipsec);
}

static void fnp4l_lag_forget(struct fnp4l *np);
static void fnp4l_lag_unbind_port(struct fnp4l_port *port);
#ifdef CONFIG_FORTINET_NP4LITE_IPSEC
static unsigned int fnp4l_lag_purge(struct fnp4l *np, unsigned int id);
#endif
#ifdef CONFIG_FORTINET_NP4LITE_DSA
static unsigned int fnp4l_lag_purge_lifs(struct fnp4l *np,
					 unsigned long lifs);
#endif
#else
static inline unsigned long fnp4l_lag_ports(const struct fnp4l *np)
{
	return 0;
}

static inline bool fnp4l_ft_idle(const struct fnp4l *np)
{
	return !np->ft_ports && !fnp4l_ipsec_busy(np->ipsec);
}

static inline void fnp4l_lag_forget(struct fnp4l *np)
{
}

static inline void fnp4l_lag_unbind_port(struct fnp4l_port *port)
{
}

static inline unsigned int fnp4l_lag_purge(struct fnp4l *np,
					   unsigned int id)
{
	return 0;
}

#ifdef CONFIG_FORTINET_NP4LITE_DSA
static inline unsigned int fnp4l_lag_purge_lifs(struct fnp4l *np,
						unsigned long lifs)
{
	return 0;
}
#endif
#endif

/*
 * Send every frame of the bound ports, of the slaves of the bound bonds,
 * and of the ports with an inbound IPsec security association, to the
 * host again, tagged ones included. Under sse_lock.
 */
static void fnp4l_ft_rx_action_host(struct fnp4l *np)
{
	unsigned long ports = np->ft_ports | fnp4l_lag_ports(np) |
			      fnp4l_ipsec_ports(np->ipsec);
	unsigned int id;

	for_each_set_bit(id, &ports, NP4L_NR_PORTS) {
		fnp4l_lif_rx_action(np->ports[id], NP4L_RX_ACTION_HOST);
		fnp4l_vlan_act_clear(np->ports[id]);
	}
#if defined(CONFIG_FORTINET_NP4LITE_LAG) && defined(CONFIG_FORTINET_NP4LITE_DSA)
	/* And the switch ports enslaved to a bound bond */
	for_each_set_bit(id, &np->lag_lifs, NP4L_LIF_MAX + 1)
		fnp4l_lif_nr_rx_action(np, id, NP4L_RX_ACTION_HOST);
#endif
}

/*
 * Hash and comparison of engine keys, as the ageing messages carry them:
 * the LIF half-word is compared under its LIF and VLAN ID fields only.
 */
static u16 fnp4l_key_vid(const struct fnp4l_sse_key *key)
{
	return key->vid_lo |
	       FIELD_GET(NP4L_SSE_KEY_VID_HI, le16_to_cpu(key->lif)) << 8;
}

static u32 fnp4l_key_hash(const struct fnp4l_sse_key *key)
{
	u32 lif = FIELD_GET(NP4L_SSE_KEY_LIF, le16_to_cpu(key->lif));

	return jhash_3words((__force u32)key->saddr, (__force u32)key->daddr,
			    ((__force u32)key->sport << 16) |
			    (__force u32)key->dport,
			    ((u32)fnp4l_key_vid(key) << 18) | (lif << 8) |
			    key->proto);
}

static bool fnp4l_key_match(const struct fnp4l_sse_key *a,
			    const struct fnp4l_sse_key *b)
{
	return a->saddr == b->saddr && a->daddr == b->daddr &&
	       a->sport == b->sport && a->dport == b->dport &&
	       a->proto == b->proto && a->vid_lo == b->vid_lo &&
	       !((le16_to_cpu(a->lif) ^ le16_to_cpu(b->lif)) &
		 (NP4L_SSE_KEY_LIF | NP4L_SSE_KEY_VID_HI));
}

/* Track a flow, in both hash tables. */
static void fnp4l_ft_link(struct fnp4l *np, struct fnp4l_flow *flow)
{
	lockdep_assert_held(&np->sse_lock);
	hash_add(np->ft_flows, &flow->node, flow->cookie);
	hash_add(np->ft_keys, &flow->key_node, fnp4l_key_hash(&flow->key));
	np->ft_nr_flows++;
}

/* Stop tracking a flow, the caller frees it. */
static void fnp4l_ft_unlink(struct fnp4l *np, struct fnp4l_flow *flow)
{
	lockdep_assert_held(&np->sse_lock);
	hash_del(&flow->node);
	hash_del(&flow->key_node);
	np->ft_nr_flows--;
}

/*
 * Per-flow counters (TAE): entries of the traffic counter table past those
 * of the ports, one per offloaded direction while there are free ones; a
 * direction without one is offloaded all the same, without counts. Same
 * format as the traffic counters, cleared on read: the flow statistics are
 * the only reader of an entry, and the counter work never reads it.
 *
 * Locking: the bitmap and the flow an entry belongs to are under sse_lock;
 * the table itself under tbl_lock, which is taken inside sse_lock and
 * never the other way round (the counter work holds tbl_lock with bottom
 * halves disabled, and sse_lock is a mutex).
 *
 * An entry is made an empty counter before the insertion that points at
 * it: the table survives a watchdog reset, and an entry may hold a rate
 * limiter. It is read once more after the engine entry is deleted, which
 * clears it; what it counted since the last statistics is lost, the flow
 * table asks for none after a deletion.
 */
static u8 fnp4l_tae_get(struct fnp4l *np)
{
	unsigned int idx;
	int ret;

	lockdep_assert_held(&np->sse_lock);
	idx = find_next_zero_bit(np->tae_used, NP4L_TCE_ENTRIES,
				 NP4L_TCE_FIRST_FREE);
	if (idx >= NP4L_TCE_ENTRIES) {
		np->tae_exhausted++;
		return 0;
	}

	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_write(np, NP4L_TBL_TRAFFIC_CNT, idx, 0, NP4L_TCE_HI_CNT);
	if (ret)
		np->tce_errors++;
	spin_unlock_bh(&np->tbl_lock);
	if (ret)
		return 0;

	__set_bit(idx, np->tae_used);

	return idx;
}

/*
 * Read (and clear) the counter of @flow: packets and bytes since the last
 * read. A failed read, or an entry that is no counter (made one again),
 * gives nothing.
 */
static void fnp4l_tae_read(struct fnp4l *np, struct fnp4l_flow *flow,
			   u64 *packets, u64 *bytes)
{
	u32 lo = 0, hi = 0;
	int ret;

	lockdep_assert_held(&np->sse_lock);
	*packets = 0;
	*bytes = 0;
	if (!flow->tae)
		return;

	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_read(np, NP4L_TBL_TRAFFIC_CNT, flow->tae, &lo, &hi);
	if (!ret && !(hi & NP4L_TCE_HI_CNT)) {
		fnp4l_tbl_write(np, NP4L_TBL_TRAFFIC_CNT, flow->tae, 0, NP4L_TCE_HI_CNT);
		ret = -EBADMSG;
	}
	if (ret)
		np->tce_errors++;
	spin_unlock_bh(&np->tbl_lock);

	if (!ret)
		fnp4l_tce_decode(lo, hi, packets, bytes);
}

/* Release the counter of @flow, once no engine entry points at it. */
static void fnp4l_tae_put(struct fnp4l *np, struct fnp4l_flow *flow)
{
	u64 packets, bytes;

	if (!flow->tae)
		return;

	fnp4l_tae_read(np, flow, &packets, &bytes);
	__clear_bit(flow->tae, np->tae_used);
	flow->tae = 0;
}

/*
 * Release what @flow holds besides its engine entry: its counter and its
 * VLAN action entry. Under sse_lock.
 */
static void fnp4l_ft_release(struct fnp4l *np,
			     struct fnp4l_flow *flow)
{
	fnp4l_tae_put(np, flow);
	if (flow->vlan_act) {
		fnp4l_vlan_act_put(np->ports[flow->in_port],
				   fnp4l_key_vid(&flow->key));
		flow->vlan_act = false;
	}
}

/*
 * Drop the flows of @port (or all of them for NULL), without telling the
 * engine, which is in reset. Under sse_lock.
 */
static void fnp4l_ft_forget(struct fnp4l *np, struct fnp4l_port *port)
{
	struct fnp4l_flow *flow;
	struct hlist_node *tmp;
	unsigned int bkt;

	hash_for_each_safe(np->ft_flows, bkt, tmp, flow, node) {
		if (port && flow->in_port != port->id &&
		    flow->out_port != port->id)
			continue;
		fnp4l_ft_unlink(np, flow);
		fnp4l_ft_release(np, flow);
		kfree(flow);
	}
	if (!port)
		fnp4l_lag_forget(np);
}

/* Write a register of the engine and read it back. */
static int fnp4l_sse_set(struct fnp4l *np, u32 reg, u32 val)
{
	u32 rd;

	fnp4l_wr(np, reg, val);
	rd = fnp4l_rd(np, reg);
	if (rd == val)
		return 0;

	dev_err(np->dev, "flow engine register %#x reads %#x, wrote %#x\n",
		reg, rd, val);
	return -EIO;
}

/* Wait for register @reg to read @val. */
static int fnp4l_sse_poll(struct fnp4l *np, u32 reg, u32 val)
{
	u32 cur;

	/* Without high resolution timers, a sleep lasts a scheduler tick. */
	if (!readl_poll_timeout_atomic(np->base + reg, cur, cur == val, 1,
				       NP4L_SSE_SPIN_US))
		return 0;

	return readl_poll_timeout(np->base + reg, cur, cur == val,
				  NP4L_SSE_SLEEP_US, NP4L_SSE_TIMEOUT_US);
}

/*
 * Clear the status bits of the engine (write one to clear; the control
 * bits are written back as read). Returns the status before clearing.
 */
static u32 fnp4l_sse_ack(struct fnp4l *np)
{
	u32 ctrl = fnp4l_rd(np, NP4L_SSE_CTRL);

	fnp4l_wr(np, NP4L_SSE_CTRL, ctrl);

	return ctrl;
}

/*
 * Copy a command to the ring and ring the doorbell. The ring is mapped as
 * I/O memory, like the registers; the barrier orders the copy before the
 * doorbell. A command may wrap around the end of the ring: the engine
 * follows it. Under sse_lock.
 */
static int fnp4l_sse_post(struct fnp4l *np, const void *cmd,
			  unsigned int words)
{
	unsigned int fetch, used, first;

	fetch = fnp4l_rd(np, NP4L_SSE_RING_FETCH);
	if (fetch >= NP4L_SSE_RING_WORDS)
		return -EIO;

	used = (np->sse_tail - fetch) & (NP4L_SSE_RING_WORDS - 1);
	if (words > NP4L_SSE_RING_WORDS - 1 - used)
		return -EBUSY;

	first = min(words, NP4L_SSE_RING_WORDS - np->sse_tail);
	memcpy_toio(np->sseq + NP4L_SSE_QMEM_RING + np->sse_tail * 8, cmd,
		    first * 8);
	if (first < words)
		memcpy_toio(np->sseq + NP4L_SSE_QMEM_RING, cmd + first * 8,
			    (words - first) * 8);
	np->sse_tail = (np->sse_tail + words) & (NP4L_SSE_RING_WORDS - 1);

	/* Command in memory before the doorbell */
	wmb();
	fnp4l_wr(np, NP4L_SSE_RING_HEAD, np->sse_tail);

	return 0;
}

/*
 * Post one command and wait until the engine has consumed it. There is no
 * per-command acknowledgment, but only one command is ever in flight:
 * when @tot_reg (insertions or deletions processed) moves, the command
 * was processed, and @succ_reg tells whether it succeeded. A flush has no
 * counter (@tot_reg = 0): the fetch index alone is waited for.
 *
 * Returns 0 on success, -ENOENT if the engine reported a failure of the
 * command (table full, no such entry), any other error if the state of
 * the engine is unknown. Under sse_lock.
 */
static int fnp4l_sse_fsoc2_exec(struct fnp4l *np, const void *cmd,
				unsigned int words, u32 tot_reg, u32 succ_reg);

static int fnp4l_sse_exec(struct fnp4l *np, const void *cmd,
			  unsigned int words, u32 tot_reg, u32 succ_reg)
{
	u32 tot = 0, succ = 0, ctrl, val;
	int ret;

	if (np->soc->sse_hif)
		return fnp4l_sse_fsoc2_exec(np, cmd, words, tot_reg, succ_reg);

	if (tot_reg) {
		tot = fnp4l_rd(np, tot_reg);
		succ = fnp4l_rd(np, succ_reg);
	}

	ret = fnp4l_sse_post(np, cmd, words);
	if (ret)
		return ret;

	ret = fnp4l_sse_poll(np, NP4L_SSE_RING_FETCH, np->sse_tail);
	if (!ret && tot_reg)
		ret = fnp4l_sse_poll(np, tot_reg, tot + 1);

	ctrl = fnp4l_sse_ack(np);
	if (ret) {
		dev_err(np->dev, "flow engine command %#x timed out, status %#x fetch %#x\n",
			*(const u8 *)cmd, ctrl, fnp4l_rd(np, NP4L_SSE_RING_FETCH));
		return ret;
	}
	if ((ctrl & (NP4L_SSE_CTRL_FATAL | NP4L_SSE_CTRL_RESET)) ||
	    !(ctrl & NP4L_SSE_CTRL_RUN)) {
		dev_err(np->dev, "flow engine error, status %#x\n", ctrl);
		return -EIO;
	}

	if (tot_reg &&
	    readl_poll_timeout_atomic(np->base + succ_reg, val, val == succ + 1,
				      1, 100))
		return -ENOENT;

	return 0;
}

/*
 * On the FortiSOC2, where nothing else tells that the flush was carried
 * out, the table must be seen empty afterwards.
 */
static int fnp4l_sse_flush(struct fnp4l *np)
{
	struct fnp4l_sse_hdr cmd = {
		.op = NP4L_SSE_CMD_VALID | NP4L_SSE_OP_FLUSH,
		.len = sizeof(cmd) / 8,
	};
	int ret;

	ret = fnp4l_sse_exec(np, &cmd, cmd.len, 0, 0);
	if (ret || !np->soc->sse_hif)
		return ret;

	ret = fnp4l_sse_poll(np, NP4L_SSE_ENTRIES, 0);
	if (ret)
		dev_err(np->dev, "flow engine holds %u entries after a flush\n",
			fnp4l_rd(np, NP4L_SSE_ENTRIES));

	return ret;
}

static int fnp4l_sse_delete(struct fnp4l *np,
			    const struct fnp4l_sse_key *key)
{
	struct fnp4l_sse_del cmd = {
		.hdr.op = NP4L_SSE_CMD_VALID | NP4L_SSE_OP_DELETE,
		.hdr.len = sizeof(cmd) / 8,
		.key = *key,
	};

	return fnp4l_sse_exec(np, &cmd, cmd.hdr.len, NP4L_SSE_DELETES,
			      NP4L_SSE_DELETES_OK);
}

/*
 * Stop flow offload after an engine error: every frame to the host, the
 * engine in reset, the flows forgotten. Binding ports again is refused
 * until they have all been unbound. Under sse_lock.
 */
static void fnp4l_sse_fail(struct fnp4l *np)
{
	fnp4l_ft_rx_action_host(np);
	fnp4l_sse_reset(np);
	fnp4l_ft_forget(np, NULL);
	np->sse_state = NP4L_SSE_FAILED;
	dev_err(np->dev, "flow engine stopped, flow offload disabled\n");
}

/*
 * Start the engine, when the first port binds to a flow table. Every
 * register is programmed while the engine is held in reset and read back;
 * once it runs, the table and ring registers are checked again before the
 * first command (a flush) is posted. The engine would otherwise work on
 * the tables its reset values describe, which lie in memory of the
 * kernel. Any mismatch leaves it in reset. Under sse_lock.
 */
static int fnp4l_sse_fsoc2_start(struct fnp4l *np);

static int fnp4l_sse_start(struct fnp4l *np)
{
	static const u32 check[] = {
		NP4L_SSE_RING_BASE, NP4L_SSE_RING_SIZE, NP4L_SSE_FAIL_IRQ_CTRL,
		NP4L_SSE_SEARCH_CTRL, NP4L_SSE_PHT_CFG, NP4L_SSE_OFT_CFG,
		NP4L_SSE_HASH_CTRL,
	};
	struct device *dev = np->dev;
	u32 val[ARRAY_SIZE(check)];
	u32 ctrl, rd, period;
	unsigned int i;
	int ret;

	if (np->soc->sse_hif)
		return fnp4l_sse_fsoc2_start(np);

	fnp4l_sse_reset(np);
	/* Per-flow counters: before the first insertion, left set at stop */
	fnp4l_wr(np, NP4L_TPE_CONFIG,
		 fnp4l_rd(np, NP4L_TPE_CONFIG) | NP4L_TPE_CONFIG_INIT);
	/* Not read by a stopped engine: safe to clear. */
	usleep_range(1000, 2000);
	memset_io(np->sseq + NP4L_SSE_QMEM_RING, 0, NP4L_SSE_RING_BYTES);
	memset_io(np->sseq + NP4L_SSE_QMEM_MSG, 0, NP4L_MSG_SIZE);
	np->sse_tail = 0;

	/*
	 * Message queue, interrupts disabled. The head written by the NP is
	 * not writable and keeps its value across a reset of the engine: it
	 * must be in range, and the host index starts there, on an empty
	 * queue.
	 */
	rd = fnp4l_rd(np, NP4L_MSG_RING_HEAD);
	if (rd >= NP4L_MSG_RING_WORDS) {
		dev_err(dev, "flow engine message queue head %#x\n", rd);
		ret = -EIO;
		goto err;
	}
	dev_dbg(dev, "flow engine message queue head at %#x\n", rd);
	ctrl = fnp4l_rd(np, NP4L_MSG_CTRL) &
	       ~(NP4L_MSG_CTRL_RUN | NP4L_MSG_CTRL_OFF | NP4L_MSG_CTRL_IRQ_EN);
	fnp4l_wr(np, NP4L_MSG_CTRL, ctrl);
	ret = fnp4l_sse_set(np, NP4L_MSG_RING_BASE, np->sseq_phys + NP4L_SSE_QMEM_MSG);
	if (!ret)
		ret = fnp4l_sse_set(np, NP4L_MSG_RING_SIZE, NP4L_MSG_RING_WORDS);
	if (!ret)
		ret = fnp4l_sse_set(np, NP4L_MSG_RING_FETCH, rd);
	np->msg_rp = rd;
	if (!ret)
		ret = fnp4l_sse_set(np, NP4L_MSG_WIN_CTRL, NP4L_MSG_WIN_CTRL_INIT);
	if (!ret)
		ret = fnp4l_sse_set(np, NP4L_MSG_INT_CTRL, NP4L_MSG_INT_CTRL_INIT);
	if (ret)
		goto err;
	fnp4l_wr(np, NP4L_MSG_CTRL, ctrl | NP4L_MSG_CTRL_RUN);

	/* Command ring and tables, engine in reset */
	val[0] = np->sseq_phys + NP4L_SSE_QMEM_RING;
	val[1] = NP4L_SSE_RING_WORDS;
	val[2] = NP4L_SSE_FAIL_IRQ_CTRL_INIT;
	val[3] = NP4L_SSE_SEARCH_CTRL_INIT;
	val[4] = np->sse_phtconf;
	val[5] = np->sse_oftconf;
	val[6] = NP4L_SSE_HASH_CTRL_INIT;
	for (i = 0; i < ARRAY_SIZE(check) && !ret; i++)
		ret = fnp4l_sse_set(np, check[i], val[i]);
	if (!ret)
		ret = fnp4l_sse_set(np, NP4L_SSE_RING_HEAD, 0);
	if (ret)
		goto err;
	if (!(fnp4l_rd(np, NP4L_SSE_CTRL) & NP4L_SSE_CTRL_RESET)) {
		dev_err(dev, "flow engine left reset early\n");
		ret = -EIO;
		goto err;
	}

	/* Release, then check that nothing moved. */
	fnp4l_wr(np, NP4L_SSE_CTRL, 0);
	fnp4l_wr(np, NP4L_SSE_CTRL, NP4L_SSE_CTRL_RUN);
	for (i = 0; i < ARRAY_SIZE(check); i++) {
		rd = fnp4l_rd(np, check[i]);
		if (rd != val[i]) {
			dev_err(dev, "flow engine register %#x reads %#x after reset, expected %#x\n",
				check[i], rd, val[i]);
			ret = -EIO;
			goto err;
		}
	}
	rd = fnp4l_rd(np, NP4L_SSE_RING_FETCH);
	if (rd) {
		dev_err(dev, "flow engine fetch index at %#x after reset\n",
			rd);
		ret = -EIO;
		goto err;
	}

	fnp4l_sse_ack(np);
	ret = fnp4l_sse_flush(np);
	if (ret)
		goto err;

	/*
	 * Ageing period, as the boot loader or a previous kernel set it, in
	 * ticks. A tick was measured to last one second (AGE_TICK holds the
	 * core clock frequency): the period is taken in seconds.
	 */
	period = FIELD_GET(NP4L_SSE_AGE_CTRL_PERIOD, fnp4l_rd(np, NP4L_SSE_AGE_CTRL));
	if (!period) {
		dev_warn(dev, "flow engine entry ageing disabled, offloaded flows expire every %u s\n",
			 NP4L_SSE_AGE_DEFAULT);
		period = NP4L_SSE_AGE_DEFAULT;
	}
	np->sse_age = period * HZ;

	np->sse_state = NP4L_SSE_UP;
	dev_info(dev, "flow engine started, entry ageing every %u ticks of %u cycles\n",
		 period, fnp4l_rd(np, NP4L_SSE_AGE_TICK));

	return 0;

err:
	fnp4l_sse_reset(np);
	dev_err(dev, "cannot start the flow engine: %d\n", ret);
	return ret == -ENOENT ? -EIO : ret;
}

/*
 * FortiSOC2: fill the port-to-trunk table with the identity (entry i =
 * LIF i) at each start of the engine. The boot loader does not fill it and
 * it is lost on a power cycle: without it, after a cold boot, no flow is
 * offloaded.
 */
static int fnp4l_sse_port_trunk_init(struct fnp4l *np)
{
	unsigned int i;
	int ret;

	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_wait(np, NP4L_SSE_FSOC2_PORT_TRUNK);
	for (i = 0; i < NP4L_SSE_FSOC2_PORT_TRUNK_ENTRIES && !ret; i++)
		ret = fnp4l_tbl_write(np, NP4L_SSE_FSOC2_PORT_TRUNK, i, i, 0);
	spin_unlock_bh(&np->tbl_lock);

	if (ret && !i)
		dev_err(np->dev, "flow engine port-to-trunk table busy: %d\n", ret);
	else if (ret)
		dev_err(np->dev, "flow engine port-to-trunk entry %u: %d\n", i - 1, ret);

	return ret;
}

/* Clear a register the boot loader should have left at 0. */
static int fnp4l_sse_fsoc2_clear(struct fnp4l *np, u32 reg)
{
	if (!fnp4l_rd(np, reg))
		return 0;

	return fnp4l_sse_set(np, reg, 0);
}

/*
 * FortiSOC2: start the engine with the fewest writes: counters of the
 * flows (before the first insertion), tables, port-to-trunk table, host
 * queue map, ageing (the tick of the
 * boot loader is kept, the period too), run, then the messages on the RX
 * ring and a flush through the TX ring, which must leave the
 * tables empty. The boot loader leaves the engine neither in reset nor
 * running (control 0x20c): no reset first, unless it runs. The HIF must
 * run. Under sse_lock.
 *
 * The table registers are written before run and read back after it: the
 * boot loader leaves them pointing into system RAM (0x04000000,
 * 0x02000000), so the engine must never run on them.
 */
static int fnp4l_sse_fsoc2_start(struct fnp4l *np)
{
	static const u32 check[] = {
		NP4L_SSE_PHT_CFG, NP4L_SSE_OFT_CFG, NP4L_SSE_HASH_CTRL,
	};
	u32 val[ARRAY_SIZE(check)] = {
		np->sse_phtconf, np->sse_oftconf, NP4L_SSE_HASH_CTRL_INIT,
	};
	struct device *dev = np->dev;
	u32 ctrl, rd, period;
	bool started = false;
	unsigned int i;
	int ret = 0;

	ctrl = fnp4l_rd(np, NP4L_SSE_FSOC2_CTRL);
	dev_dbg(dev, "flow engine control %#x before start\n", ctrl);
	if (ctrl & NP4L_SSE_CTRL_RUN) {
		dev_warn(dev, "flow engine running before start (control %#x), reset\n",
			 ctrl);
		fnp4l_sse_reset(np);
	}
	/* Keys of a previous run: the RX path is the only writer. */
	kfifo_reset_out(&np->msg_fifo);

	fnp4l_wr(np, NP4L_TPE_CONFIG,
		 fnp4l_rd(np, NP4L_TPE_CONFIG) | NP4L_TPE_CONFIG_INIT);

	for (i = 0; i < ARRAY_SIZE(check) && !ret; i++)
		ret = fnp4l_sse_set(np, check[i], val[i]);
	if (!ret)
		ret = fnp4l_sse_port_trunk_init(np);
	if (!ret)
		ret = fnp4l_sse_fsoc2_clear(np, NP4L_SSE_FSOC2_HOSTQ_MAP0);
	if (!ret)
		ret = fnp4l_sse_fsoc2_clear(np, NP4L_SSE_FSOC2_HOSTQ_MAP1);
	if (!ret && !fnp4l_rd(np, NP4L_SSE_AGE_TICK))
		ret = fnp4l_sse_set(np, NP4L_SSE_AGE_TICK,
				    NP4L_SSE_FSOC2_AGE_TICK_INIT);
	if (ret)
		goto err;

	/* Ageing period, in ticks of one second */
	rd = fnp4l_rd(np, NP4L_SSE_AGE_CTRL);
	period = FIELD_GET(NP4L_SSE_AGE_CTRL_PERIOD, rd);
	if (!period) {
		dev_warn(dev, "flow engine entry ageing disabled, set to %u s\n",
			 NP4L_SSE_AGE_DEFAULT);
		period = NP4L_SSE_AGE_DEFAULT;
	}
	ret = fnp4l_sse_set(np, NP4L_SSE_AGE_CTRL,
			    NP4L_SSE_FSOC2_AGE_CTRL_INIT | period);
	if (ret)
		goto err;
	np->sse_age = period * HZ;

	/* IPsec engine: before the flow engine runs */
	fnp4l_ipsec_start(np->ipsec);

	fnp4l_wr(np, NP4L_SSE_FSOC2_CTRL, NP4L_SSE_CTRL_RUN);
	started = true;
	ctrl = fnp4l_rd(np, NP4L_SSE_FSOC2_CTRL);
	if ((ctrl & NP4L_SSE_CTRL_RESET) || !(ctrl & NP4L_SSE_CTRL_RUN)) {
		dev_err(dev, "flow engine not running, control %#x\n", ctrl);
		ret = -EIO;
		goto err;
	}
	for (i = 0; i < ARRAY_SIZE(check); i++) {
		rd = fnp4l_rd(np, check[i]);
		if (rd != val[i]) {
			dev_err(dev, "flow engine register %#x reads %#x once running, expected %#x\n",
				check[i], rd, val[i]);
			ret = -EIO;
			goto err;
		}
	}

	fnp4l_wr(np, NP4L_HRX_MSG_CTRL, NP4L_HRX_MSG_EN);

	ret = fnp4l_sse_flush(np);
	if (ret)
		goto err;

	np->sse_state = NP4L_SSE_UP;
	dev_info(dev, "flow engine started, control %#x, entry ageing every %u ticks of %u cycles\n",
		 fnp4l_rd(np, NP4L_SSE_FSOC2_CTRL), period,
		 fnp4l_rd(np, NP4L_SSE_AGE_TICK));

	return 0;

err:
	/* Never started: left as the boot loader leaves it */
	if (started)
		fnp4l_sse_reset(np);
	dev_err(dev, "cannot start the flow engine: %d\n", ret);
	return ret == -ENOENT ? -EIO : ret;
}

/*
 * FortiSOC2: the engine reads its commands on the TX ring. Before the HIF
 * stops, when the last port closes, empty and stop it, and send the frames
 * of the bound ports to the host: flow offload stays off until every port
 * has unbound. Commands are refused from then on, until the HIF runs
 * again. Under RTNL, HIF and NAPI still running.
 */
static void fnp4l_sse_hif_down(struct fnp4l *np)
{
	mutex_lock(&np->sse_lock);
	if (np->soc->sse_hif && np->sse_state == NP4L_SSE_UP) {
		fnp4l_ft_rx_action_host(np);
		fnp4l_sse_flush(np);
		fnp4l_sse_reset(np);
		fnp4l_ft_forget(np, NULL);
		np->sse_state = NP4L_SSE_FAILED;
		dev_warn(np->dev, "every port closed, flow offload stopped until every port unbinds\n");
	}

	spin_lock_bh(&np->tx_lock);
	np->hif_up = false;
	spin_unlock_bh(&np->tx_lock);
	mutex_unlock(&np->sse_lock);
}

/* Stop the engine once no port is bound. Under sse_lock. */
static void fnp4l_sse_stop(struct fnp4l *np)
{
	if (np->sse_state == NP4L_SSE_UP)
		fnp4l_sse_flush(np);

	/* FortiSOC2: an engine that does not run is left as it is. */
	if (!np->soc->sse_hif ||
	    (fnp4l_rd(np, NP4L_SSE_FSOC2_CTRL) & NP4L_SSE_CTRL_RUN))
		fnp4l_sse_reset(np);
	fnp4l_ft_forget(np, NULL);
	if (np->sse_state != NP4L_SSE_SHUTDOWN)
		np->sse_state = NP4L_SSE_DOWN;
}

/*
 * No flow table access for good: every frame to the host, engine in reset,
 * and no more binding.
 */
static void fnp4l_sse_shutdown(struct fnp4l *np)
{
	mutex_lock(&np->sse_lock);
	fnp4l_ft_rx_action_host(np);
	np->sse_state = NP4L_SSE_SHUTDOWN;
	fnp4l_sse_stop(np);
	mutex_unlock(&np->sse_lock);
}

/*
 * Report a flow engine or message queue a previous kernel left running (a
 * watchdog reset does not reset the NP), before stopping them.
 */
static void fnp4l_sse_check_left(struct fnp4l *np)
{
	u32 ctrl = fnp4l_rd(np, NP4L_SSE_CTRL);
	u32 msg = fnp4l_rd(np, NP4L_MSG_CTRL);
	u32 wp = fnp4l_rd(np, NP4L_MSG_RING_HEAD);

	if ((ctrl & NP4L_SSE_CTRL_RESET) && msg == NP4L_MSG_CTRL_OFF && !wp)
		return;

	dev_warn(np->dev, "flow engine left running: control %#x, messages control %#x base %#x head %#x\n",
		 ctrl, msg, fnp4l_rd(np, NP4L_MSG_RING_BASE), wp);
}

/*
 * FortiSOC2: whether a previous kernel left the engine running, or its
 * messages enabled. The boot loader leaves neither.
 */
static bool fnp4l_sse_fsoc2_left(struct fnp4l *np)
{
	u32 ctrl = fnp4l_rd(np, NP4L_SSE_FSOC2_CTRL);
	u32 msg = fnp4l_rd(np, NP4L_HRX_MSG_CTRL);

	if (!(ctrl & NP4L_SSE_CTRL_RUN) && !msg)
		return false;

	dev_warn(np->dev, "flow engine left running: control %#x, messages control %#x\n",
		 ctrl, msg);
	return true;
}

/* Leave the NP with no DMA running, the HIF parked on the loader rings. */
static void fnp4l_teardown(void *data)
{
	struct fnp4l *np = data;

	/*
	 * FortiSOC2: refuse flow engine commands before the HIF stops, so
	 * that no flush is posted once it is parked on the loader rings.
	 */
	if (np->soc->sse_hif)
		fnp4l_sse_hif_down(np);
	fnp4l_hif_stop(np);
	fnp4l_hif_park(np);
	if (np->soc->sse || np->soc->sse_hif)
		fnp4l_sse_shutdown(np);
	if (np->irqmap) {
		writel(np->loader_irqmap, np->irqmap + NP4L_IRQMAP_OUT(NP4L_IRQMAP_OUT_NP));
		writel(np->loader_irqmap_crypto,
		       np->irqmap + NP4L_IRQMAP_OUT(NP4L_IRQMAP_OUT_CRYPTO));
	}
}

/*
 * Reserved region @idx of the node, for memory the flow engine accesses by
 * DMA: it must lie outside of system RAM (a no-map reservation is not
 * system RAM) and overlap no other region of the node.
 */
static int fnp4l_sse_region(struct fnp4l *np, unsigned int idx,
			    struct resource *res)
{
	struct device *dev = np->dev;
	struct resource other;
	unsigned int i;

	if (of_reserved_mem_region_to_resource(dev->of_node, idx, res))
		return -ENODEV;

	if (region_intersects(res->start, resource_size(res),
			      IORESOURCE_SYSTEM_RAM,
			      IORES_DESC_NONE) != REGION_DISJOINT) {
		dev_err(dev, "%pR overlaps system RAM\n", res);
		return -EINVAL;
	}

	for (i = 0; i < NP4L_MEM_NR; i++) {
		if (i == idx ||
		    of_reserved_mem_region_to_resource(dev->of_node, i, &other))
			continue;
		if (resource_overlaps(res, &other)) {
			dev_err(dev, "%pR overlaps %pR\n", res, &other);
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * Flow offload needs two reserved regions:
 *  - the flow tables, NP4L_SSE_TBL_SIZE, 4 MiB aligned, below 1 GiB (the
 *    reach of the table registers): hash table, then overflow table;
 *  - the command ring and the message queue, NP4L_SSE_QMEM_SIZE at least,
 *    below 4 GiB, except on the FortiSOC2, which uses the HIF rings.
 */
static void fnp4l_sse_probe(struct fnp4l *np)
{
	struct device *dev = np->dev;
	struct resource tbl, q;
	u64 oft;

	if (fnp4l_sse_region(np, NP4L_MEM_FLOW, &tbl) ||
	    (!np->soc->sse_hif &&
	     fnp4l_sse_region(np, NP4L_MEM_QUEUES, &q))) {
		dev_info(dev, "no memory for the flow engine, no flow offload\n");
		return;
	}

	if (resource_size(&tbl) != NP4L_SSE_TBL_SIZE ||
	    !IS_ALIGNED(tbl.start, SZ_4M) || tbl.end >= SZ_1G) {
		dev_warn(dev, "flow tables %pR unusable, no flow offload\n",
			 &tbl);
		return;
	}

	if (!np->soc->sse_hif) {
		if (resource_size(&q) < NP4L_SSE_QMEM_SIZE ||
		    !IS_ALIGNED(q.start, SZ_4K) || upper_32_bits(q.end)) {
			dev_warn(dev, "flow engine queues %pR unusable, no flow offload\n",
				 &q);
			return;
		}

		np->sseq = devm_ioremap(dev, q.start, NP4L_SSE_QMEM_SIZE);
		if (!np->sseq) {
			dev_warn(dev, "cannot map %pR, no flow offload\n", &q);
			return;
		}
		np->sseq_phys = q.start;
	}

	oft = tbl.start + NP4L_SSE_PHT_SIZE;
	np->sse_phtconf = FIELD_PREP(NP4L_SSE_TBL_BASE,
				     tbl.start >> NP4L_SSE_TBL_BASE_SHIFT) |
			  NP4L_SSE_PHT_SIZE / 128;
	np->sse_oftconf = FIELD_PREP(NP4L_SSE_TBL_BASE,
				     oft >> NP4L_SSE_TBL_BASE_SHIFT) |
			  (NP4L_SSE_OFT_SIZE / 64 - 64) / 2;
	np->sse_avail = true;
}

/*
 * FortiSOC2: the IPsec engine reads its security associations from a
 * reserved region of its own. Without it, or should anything else fail,
 * the ports offer no IPsec offload, and work otherwise.
 */
static void fnp4l_ipsec_probe_region(struct fnp4l *np)
{
	struct resource sa;
	int ret;

	if (!IS_ENABLED(CONFIG_FORTINET_NP4LITE_IPSEC))
		return;

	if (fnp4l_sse_region(np, NP4L_MEM_SA, &sa)) {
		dev_info(np->dev, "no memory for the IPsec engine, no IPsec offload\n");
		return;
	}

	ret = fnp4l_ipsec_probe(np, np->dev, np->base, &sa, &np->ipsec);
	if (ret)
		dev_warn(np->dev, "no IPsec offload: %d\n", ret);
}

/* Address the NP writes the host tag of a frame at, in an RX page */
static dma_addr_t fnp4l_rx_dma(struct page *page)
{
	return page_pool_get_dma_addr(page) + NP4L_RX_PAD;
}

/*
 * Return the page of a slot, read by the CPU up to @len bytes, to the
 * device. Its cache lines are invalidated here and nowhere else: the sync
 * for the CPU does nothing on this cache, and a line the CPU still holds
 * would hide what the NP writes next.
 */
static void fnp4l_rx_sync_dev(struct fnp4l *np, struct page *page,
			      unsigned int len)
{
	dma_sync_single_range_for_device(np->dev, page_pool_get_dma_addr(page),
					 NP4L_RX_PAD, min(len, NP4L_RX_DMA_LEN),
					 DMA_FROM_DEVICE);
}

/*
 * Release the pages of the RX slots, with the HIF stopped and parked on
 * the rings of the boot loader: the NP no longer writes to them. Pages
 * still up the stack go back to the pool, which lives until the last one
 * is returned.
 */
static void fnp4l_rx_free(struct fnp4l *np)
{
	unsigned int i;

	for (i = 0; i < NP4L_RX_RING_LEN; i++) {
		np->rx_ring[i].addr = cpu_to_le32(np->rx_guard_dma);
		np->rx_ring[i].ctrl = 0;
		if (np->rx_page[i])
			page_pool_put_full_page(np->rx_pool, np->rx_page[i],
						false);
		np->rx_page[i] = NULL;
	}

	page_pool_destroy(np->rx_pool);
	np->rx_pool = NULL;
}

/* A page pool and a page for every RX slot, NAPI disabled */
static int fnp4l_rx_alloc(struct fnp4l *np)
{
	struct page_pool_params pp = {
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.order = 0,
		.pool_size = 2 * NP4L_RX_RING_LEN,
		.nid = NUMA_NO_NODE,
		.dev = np->dev,
		.napi = &np->napi,
		.dma_dir = DMA_FROM_DEVICE,
		.offset = NP4L_RX_PAD,
		.max_len = NP4L_RX_DMA_LEN,
	};
	struct page_pool *pool;
	unsigned int i;

	pool = page_pool_create(&pp);
	if (IS_ERR(pool))
		return PTR_ERR(pool);
	np->rx_pool = pool;

	for (i = 0; i < NP4L_RX_RING_LEN; i++) {
		np->rx_page[i] = page_pool_alloc_pages(pool, GFP_KERNEL);
		if (!np->rx_page[i]) {
			fnp4l_rx_free(np);
			return -ENOMEM;
		}
	}

	return 0;
}

/* Return every RX slot except the one at @start to the NP. */
static void fnp4l_rx_fill(struct fnp4l *np, unsigned int start)
{
	unsigned int i;

	if (np->rx_wb != np->rx_ring)
		memset(np->rx_wb, 0, NP4L_RX_RING_LEN * sizeof(*np->rx_wb));

	for (i = 0; i < NP4L_RX_RING_LEN; i++) {
		struct fnp4l_rx_bd *bd = &np->rx_ring[i];

		bd->addr = cpu_to_le32(fnp4l_rx_dma(np->rx_page[i]));
		bd->ctrl = cpu_to_le32(FIELD_PREP(NP4L_RX_LEN, NP4L_BUF_SIZE));
	}

	np->rx_head = start;
	np->rx_tail = (start + NP4L_RX_RING_LEN - 1) & NP4L_RX_RING_MASK;
	np->rx_ring[np->rx_tail].ctrl = 0;
}

/* Under tx_lock. */
static unsigned int fnp4l_tx_free(struct fnp4l *np)
{
	unsigned int used = (np->tx_tail - np->tx_head) & NP4L_TX_RING_MASK;

	return NP4L_TX_RING_LEN - 1 - used;
}

/* The TX ring is shared: a full ring stops every port. Under tx_lock. */
static void fnp4l_tx_stop_all(struct fnp4l *np)
{
	unsigned int i;

	for (i = 0; i < NP4L_NR_PORTS; i++)
		if (np->ports[i])
			netif_stop_queue(np->ports[i]->ndev);
	np->tx_stopped = true;
}

static void fnp4l_tx_unmap(struct fnp4l *np,
			   struct fnp4l_tx_slot *slot)
{
	if (!slot->dma_len)
		return;
	if (slot->dma_page)
		dma_unmap_page(np->dev, slot->dma, slot->dma_len,
			       DMA_TO_DEVICE);
	else
		dma_unmap_single(np->dev, slot->dma, slot->dma_len,
				 DMA_TO_DEVICE);
	slot->dma_len = 0;
}

/*
 * The bounce buffer of a command, once the NP has read it or will not: it
 * may hold the keys of an IPsec security association. Under tx_lock.
 */
static void fnp4l_tx_cmd_wipe(struct fnp4l *np, unsigned int t)
{
	struct fnp4l_tx_slot *slot = &np->tx_slot[t];

	if (!slot->cmd)
		return;

	memzero_explicit(np->tx_buf + t * NP4L_BUF_STRIDE, slot->len);
	slot->cmd = false;
	slot->len = 0;
}

/* Release every TX descriptor up to ring_done, excluded. */
static void fnp4l_tx_clean(struct fnp4l *np)
{
	unsigned int ring_done, used, done, i;

	spin_lock(&np->tx_lock);

	ring_done = fnp4l_rd(np, NP4L_HTX_RING_DONE);
	if (ring_done >= NP4L_TX_RING_LEN) {
		dev_warn_once(np->dev, "TX done index out of range: %#x\n", ring_done);
		goto out;
	}

	used = (np->tx_tail - np->tx_head) & NP4L_TX_RING_MASK;
	done = (ring_done - np->tx_head) & NP4L_TX_RING_MASK;
	if (done > used) {
		dev_warn_once(np->dev, "TX done index %#x outside [%#x, %#x]\n",
			      ring_done, np->tx_head, np->tx_tail);
		goto out;
	}

	while (np->tx_head != ring_done) {
		struct fnp4l_tx_slot *slot = &np->tx_slot[np->tx_head];

		fnp4l_tx_unmap(np, slot);
		fnp4l_tx_cmd_wipe(np, np->tx_head);
		if (slot->port) {
			DEV_STATS_INC(slot->port->ndev, tx_packets);
			DEV_STATS_ADD(slot->port->ndev, tx_bytes, slot->len);
			slot->port = NULL;
		}
		if (slot->skb) {
			dev_consume_skb_any(slot->skb);
			slot->skb = NULL;
		}
		np->tx_head = (np->tx_head + 1) & NP4L_TX_RING_MASK;
	}

	if (np->tx_stopped && fnp4l_tx_free(np) >= NP4L_TX_MAX_BDS) {
		np->tx_stopped = false;
		for (i = 0; i < NP4L_NR_PORTS; i++)
			if (np->ports[i] && netif_running(np->ports[i]->ndev))
				netif_wake_queue(np->ports[i]->ndev);
	}
out:
	spin_unlock(&np->tx_lock);
}

/*
 * FortiSOC2: count the frames whose host tag carries the LIF pattern
 * 0x_F_, the mark of frames of the IPsec engine. Without an IPsec
 * security association, none are expected. Where that LIF sits is not
 * settled: bytes 0 and 1 of the host tag, or bytes 4 and 5, where this
 * driver finds the source LIF; each place has its own count. The same
 * pattern in bytes 0 and 1 may also mark messages of the flow engine
 * that come without the message bit of the write-back word: the count of
 * bytes 0 and 1 may take such messages in. Counting only, the frame goes
 * on as any other.
 */
static void fnp4l_rx_htag_mark(struct fnp4l *np, const u8 *buf,
			       unsigned int lif)
{
	bool f01 = (buf[1] & NP4L_HTAG_LIF_MARK) == NP4L_HTAG_LIF_MARK;
	bool f45 = (lif & NP4L_HTAG_LIF_MARK) == NP4L_HTAG_LIF_MARK;

	if (!f01 && !f45)
		return;

	if (f01)
		atomic_long_inc(&np->rx_htag_mark_a);
	if (f45)
		atomic_long_inc(&np->rx_htag_mark_b);
	dev_warn_once(np->dev, "frame with LIF pattern 0x_f_, host tag %*ph\n",
		      NP4L_HTAG_LEN, buf);
}

/*
 * The source LIF of the host tag selects the port. Frames of a LIF without an
 * open port are dropped.
 */
static struct fnp4l_port *fnp4l_rx_port(struct fnp4l *np,
					const u8 *buf)
{
	unsigned int lif = ((buf[4] & 3) << 8) | buf[5];
	struct fnp4l_port *port = NULL;

	if (np->soc->sse_hif)
		fnp4l_rx_htag_mark(np, buf, lif);

	if (lif <= NP4L_LIF_MAX)
		port = np->lif_port[lif];
	if (port && netif_running(port->ndev))
		return port;

	dev_dbg_ratelimited(np->dev, "dropping frame from LIF %u (no open port), host tag %*ph\n",
			    lif, NP4L_HTAG_LEN, buf);

	return NULL;
}

/*
 * Checksum of the NP, when enabled: trusted for untagged IPv4 TCP and UDP
 * only, with the L4 check done and neither check failed. Anything else is
 * left to the stack, frames of a DSA conduit included (EDSA EtherType).
 */
static void fnp4l_rx_csum(struct sk_buff *skb, u32 ctrl)
{
	const struct iphdr *iph;

	if (!(skb->dev->features & NETIF_F_RXCSUM) ||
	    !(ctrl & NP4L_RX_L4_OK) || (ctrl & (NP4L_RX_L3_ERR | NP4L_RX_L4_ERR)) ||
	    skb_vlan_tag_present(skb) || skb->protocol != htons(ETH_P_IP) ||
	    !pskb_may_pull(skb, sizeof(*iph)))
		return;

	iph = (const struct iphdr *)skb->data;
	if (iph->version != 4 || ip_is_fragment(iph) ||
	    (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP))
		return;

	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/*
 * FortiSOC2: a buffer of messages of the engines of the NP, one after the
 * other, each as long as its header says. The keys and counts of the ageing
 * messages go to the flow table. Messages of other types (4 to 7 come from the
 * IPsec engine) and ageing messages too short to hold a key are skipped over,
 * so that the ageing messages after them are not lost; only a length that does
 * not fit ends the buffer, since the next header cannot be found then, and
 * bytes left over after the last message are counted as bad.
 */
static void fnp4l_rx_msg(struct fnp4l *np, const u8 *buf,
			 unsigned int len, u32 ctrl)
{
	const struct fnp4l_msg_timeout2 *msg2;
	const struct fnp4l_msg_timeout *msg;
	struct fnp4l_age age;
	unsigned int n;

	if (!(ctrl & NP4L_RX_OK)) {
		atomic_long_inc(&np->msg_rx_bad);
		dev_dbg_ratelimited(np->dev, "engine message buffer in error, completion %#x\n",
				    ctrl);
		return;
	}

	for (; len >= sizeof(struct fnp4l_msg_hdr); buf += n, len -= n) {
		msg = (const struct fnp4l_msg_timeout *)buf;
		n = msg->hdr.len * 8;
		if (!n || n > len)
			goto bad;
		atomic_long_inc(&np->rx_flow_msgs);
		if (msg->hdr.type != NP4L_MSG_TYPE_TIMEOUT) {
			if (fnp4l_ipsec_msg(np->ipsec, buf, n))
				continue;
			atomic_long_inc(&np->rx_flow_msgs_other);
			dev_dbg_ratelimited(np->dev, "engine message of type %u, %u bytes, skipped\n",
					    msg->hdr.type, n);
			continue;
		}
		if (n < sizeof(*msg)) {
			atomic_long_inc(&np->msg_rx_bad);
			dev_dbg_ratelimited(np->dev, "ageing message of %u bytes, skipped\n",
					    n);
			continue;
		}
		age.key = msg->key;
		age.last_len = 0;
		age.one = 0;
		if (n >= sizeof(*msg2)) {
			msg2 = (const struct fnp4l_msg_timeout2 *)buf;
			age.last_len = le32_to_cpu(msg2->last_len);
			age.one = le32_to_cpu(msg2->one);
		}
		if (!kfifo_put(&np->msg_fifo, age))
			atomic_long_inc(&np->msg_lost);
	}
	/* Bytes too few for a header: a format not understood */
	if (!len)
		return;

bad:
	atomic_long_inc(&np->msg_rx_bad);
	dev_dbg_ratelimited(np->dev, "engine message %*ph, %u bytes left, rest of the buffer dropped\n",
			    (int)min_t(unsigned int, len, 8), buf, len);
}

/*
 * FortiSOC2: a frame the IPsec engine decrypted goes to the port of its
 * security association, which @x is set to, with a reference.
 */
static struct fnp4l_port *fnp4l_rx_ipsec(struct fnp4l *np,
					 const u8 *buf, u32 wb0, u32 ctrl,
					 struct xfrm_state **x)
{
	struct fnp4l_port *port;
	int id;

	id = fnp4l_ipsec_rx(np->ipsec, buf, wb0, ctrl, x);
	if (id == -ENOENT)
		return fnp4l_rx_port(np, buf);
	if (id < 0)
		return NULL;

	port = np->ports[id];
	if (port && netif_running(port->ndev))
		return port;

	fnp4l_ipsec_rx_put(*x);
	*x = NULL;
	return NULL;
}

/*
 * Hand the frame of RX slot @i to the stack. Its page goes up with it when
 * a new one can take its place in the slot; a short frame is copied, and a
 * dropped one leaves the page where it is. Either way the slot has a page
 * ready for the device afterwards. @wb0 is the first word of the
 * completion (FortiSOC2).
 */
static void fnp4l_rx_frame(struct fnp4l *np, unsigned int i, u32 ctrl,
			   u32 wb0)
{
	unsigned int len = FIELD_GET(NP4L_RX_LEN, ctrl);
	struct page *page = np->rx_page[i], *new;
	struct xfrm_state *x = NULL;
	struct fnp4l_port *port;
	struct net_device *ndev;
	struct sk_buff *skb;
	u16 tci = 0;
	u8 *buf;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	unsigned int lif;
#endif

	/* FortiSOC2: messages of the flow engine, without host tag */
	if (np->soc->sse_hif && (ctrl & NP4L_RX_MSG)) {
		page_pool_dma_sync_for_cpu(np->rx_pool, page, 0,
					   min(len, NP4L_RX_DMA_LEN));
		fnp4l_rx_msg(np, page_address(page) + NP4L_RX_PAD,
			     min(len, NP4L_BUF_SIZE), ctrl);
		goto keep;
	}

	if (len < NP4L_HTAG_LEN)
		return;

	page_pool_dma_sync_for_cpu(np->rx_pool, page, 0,
				   min(len, NP4L_RX_DMA_LEN));
	buf = page_address(page) + NP4L_RX_PAD;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	lif = ((buf[4] & 3) << 8) | buf[5];
#endif

	port = fnp4l_rx_ipsec(np, buf, wb0, ctrl, &x);
	if (!port)
		goto keep;
	ndev = port->ndev;

	if (!(ctrl & NP4L_RX_OK)) {
		DEV_STATS_INC(ndev, rx_errors);
		goto keep;
	}

	if (ctrl & NP4L_RX_ANOMALY) {
		u64_stats_update_begin(&port->rx_syncp);
		u64_stats_inc(&port->rx_anomaly_trapped);
		u64_stats_update_end(&port->rx_syncp);
	}

	if (len < NP4L_HTAG_LEN + ETH_HLEN || len > NP4L_BUF_SIZE) {
		DEV_STATS_INC(ndev, rx_length_errors);
		DEV_STATS_INC(ndev, rx_errors);
		goto keep;
	}

	/*
	 * Tag taken off by the IGR (rx-vlan-offload on). A tag with a TCI
	 * of 0 is dropped altogether: it carries nothing.
	 */
	if (!(buf[4] & NP4L_HTAG_RX_NOVLAN))
		tci = (buf[6] << 8) | buf[7];

	len -= NP4L_HTAG_LEN;
	if (len <= NP4L_RX_COPYBREAK) {
		/* The same headroom as a page, for GRO fraglist */
		skb = napi_alloc_skb(&np->napi, NP4L_RX_PAD - NET_SKB_PAD + len);
		if (!skb)
			goto drop;
		skb_reserve(skb, NP4L_RX_PAD - NET_SKB_PAD);
		skb_put_data(skb, buf + NP4L_HTAG_LEN, len);
		fnp4l_rx_sync_dev(np, page, NP4L_HTAG_LEN + len);
	} else {
		/* No new page, no frame: the slot must never be left empty. */
		new = page_pool_dev_alloc_pages(np->rx_pool);
		if (!new)
			goto drop;
		skb = napi_build_skb(page_address(page), PAGE_SIZE);
		if (!skb) {
			page_pool_recycle_direct(np->rx_pool, new);
			goto drop;
		}
		skb_mark_for_recycle(skb);
		skb_reserve(skb, NP4L_RX_PAD + NP4L_HTAG_LEN);
		skb_put(skb, len);
		np->rx_page[i] = new;
	}

	/*
	 * The length is used as reported. Should it include the FCS, the
	 * IP layer trims the trailing bytes.
	 */
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	if (fnp4l_dsa_conduit(port) && !x &&
	    !fnp4l_dsa_rx(port, skb, lif, &tci)) {
		DEV_STATS_INC(ndev, rx_dropped);
		kfree_skb(skb);
		return;
	}
#endif
	if (tci)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), tci);
	skb->protocol = eth_type_trans(skb, ndev);
	fnp4l_rx_csum(skb, ctrl);
	/* The reference of @x goes with the frame, or is dropped */
	if (x && !fnp4l_ipsec_rx_skb(np->ipsec, skb, x)) {
		DEV_STATS_INC(ndev, rx_dropped);
		kfree_skb(skb);
		return;
	}

	DEV_STATS_INC(ndev, rx_packets);
	DEV_STATS_ADD(ndev, rx_bytes, len);
	/*
	 * Not a decrypted frame through GRO: GRO does not compare the
	 * sec_path, and would merge it with a plain one of the same flow.
	 */
	if (x)
		netif_receive_skb(skb);
	else
		napi_gro_receive(&np->napi, skb);
	return;

drop:
	DEV_STATS_INC(ndev, rx_dropped);
keep:
	fnp4l_ipsec_rx_put(x);
	fnp4l_rx_sync_dev(np, page, FIELD_GET(NP4L_RX_LEN, ctrl));
}

static int fnp4l_rx(struct fnp4l *np, int budget)
{
	unsigned int refilled = 0;
	int done = 0;

	while (done < budget) {
		struct fnp4l_rx_bd *wb = &np->rx_wb[np->rx_head];
		u32 ctrl = le32_to_cpu(READ_ONCE(wb->ctrl));

		if (!(ctrl & NP4L_RX_DONE))
			break;
		dma_rmb();

		fnp4l_rx_frame(np, np->rx_head, ctrl,
			       le32_to_cpu(READ_ONCE(wb->addr)));

		wb->ctrl = cpu_to_le32(ctrl & ~NP4L_RX_DONE);

		/*
		 * Re-arm the empty slot, the consumed one becomes the hole.
		 * The NP does not preserve the buffer address of a completed
		 * descriptor: write it again on every refill, or re-armed
		 * slots send frames to physical address 0. Bit 30 is kept.
		 * The page of the slot is ready for the device.
		 */
		np->rx_ring[np->rx_tail].addr =
			cpu_to_le32(fnp4l_rx_dma(np->rx_page[np->rx_tail]));
		ctrl = le32_to_cpu(np->rx_ring[np->rx_tail].ctrl);
		np->rx_ring[np->rx_tail].ctrl =
			cpu_to_le32((ctrl & NP4L_RX_OK) |
				    FIELD_PREP(NP4L_RX_LEN, NP4L_BUF_SIZE));
		np->rx_tail = np->rx_head;
		np->rx_head = (np->rx_head + 1) & NP4L_RX_RING_MASK;

		if (++refilled % NP4L_RX_HEAD_BATCH == 0) {
			dma_wmb();
			fnp4l_wr(np, NP4L_HRX_RING_HEAD, np->rx_tail);
		}
		done++;
	}

	if (refilled % NP4L_RX_HEAD_BATCH) {
		dma_wmb();
		fnp4l_wr(np, NP4L_HRX_RING_HEAD, np->rx_tail);
	}

	return done;
}

static int fnp4l_poll(struct napi_struct *napi, int budget)
{
	struct fnp4l *np = container_of(napi, struct fnp4l, napi);
	int done;

	fnp4l_tx_clean(np);
	done = fnp4l_rx(np, budget);

	/*
	 * Unmask only once NAPI is complete, without reading the status
	 * again: an event latched in the meantime raises the level-triggered
	 * line as soon as the enable register is written.
	 */
	if (done < budget && napi_complete_done(napi, done))
		fnp4l_irq_mask(np, NP4L_HIF_INT_ALL);

	return done;
}

/*
 * TOP stat (NP4L_IRQMAP_STATUS of the IRQ map on the FortiSOC2) is the OR
 * of the enabled NP sources. The non-HIF ones are disabled at probe; should one
 * show up anyway, IRQ_NONE lets the spurious interrupt detector deal with
 * it.
 */
static irqreturn_t fnp4l_isr(int irq, void *dev_id)
{
	struct fnp4l *np = dev_id;
	u32 rx, tx;

	if (np->irqmap) {
		if (!(readl(np->irqmap + NP4L_IRQMAP_STATUS) & NP4L_IRQMAP_SRC_HIF))
			return IRQ_NONE;
	} else if (!(fnp4l_rd(np, NP4L_TOP_STAT) & NP4L_TOP_STAT_HIF)) {
		return IRQ_NONE;
	}

	rx = fnp4l_rd(np, NP4L_HRX_INT_STATUS);
	tx = fnp4l_rd(np, NP4L_HTX_INT_STATUS);
	if (!(rx | tx))
		return IRQ_NONE;

	/* Mask first, then write the events back. */
	fnp4l_irq_mask(np, 0);
	fnp4l_ack(np, rx, tx);

	if ((rx | tx) & NP4L_HIF_INT_FATAL)
		dev_err_ratelimited(np->dev, "fatal HIF event, RX status %#x, TX status %#x\n",
				    rx, tx);

	/* Also after a fatal event alone: the end of NAPI unmasks the HIF. */
	napi_schedule(&np->napi);

	return IRQ_HANDLED;
}

/*
 * Program the ingress header checks of every port: failed L3 checks
 * dropped, failed L4 checks handed to the host, L4 attack filters off.
 *
 * The frames with IPv4 options the IP layer acts on go to the host: the
 * flow engine forwards those of an offloaded flow with their options left
 * as they are (a record route or timestamp option not filled in, a source
 * route not followed). With the L3 anomaly checks on them, the engine
 * hands them over and Linux forwards them; the flow stays offloaded, and
 * fragments and TTL handling do not change. The action goes to 0 first:
 * the boot loader leaves it at 0xffff, which drops every frame the check
 * flags. On the FortiSOC2 they follow the "ip-options-host" flag of the port (on by
 * default), never on a DSA conduit, whose switch tag comes before the IP
 * header (but under FORTINET_NP4LITE_DSA, which takes it off), nor for the
 * frames of the host (XHP).
 */
static u32 fnp4l_l3_anomaly_en(struct fnp4l *np, unsigned int id)
{
	struct fnp4l_port *port = np->ports[id];

	if (!np->soc->anomaly_priv)
		return NP4L_ANOMALY_L3_IPOPT;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	/* The IHP of the link sees the IP header once the tag is off. */
	if (fnp4l_dsa_offload(port))
		return NP4L_ANOMALY_L3_IPOPT;
#endif
	if (port && port->ipopt_flag &&
	    (READ_ONCE(port->priv_flags) & NP4L_PRIV_IPOPT_HOST))
		return NP4L_ANOMALY_L3_IPOPT;

	return 0;
}

/*
 * Action of the L3 header checks of a port. On the IHP of the link of a
 * DSA conduit with the switch tag taken off (FORTINET_NP4LITE_DSA), check 4 fails on every
 * unicast IPv4 frame with options (IHL above 5), which the "drop" action
 * then loses: the IHL and options check is thrown off by the tag
 * extraction, while the same frames pass it on wan1 and wan2. With its
 * action at 0, those frames go to the host instead, which checks the
 * header again in ip_rcv_core() and handles the options as on any other
 * port; the flows of their 5-tuple stay offloaded. The check stays enabled
 * and the other ones keep dropping, the header checksum among them.
 * Elsewhere, the action stays at its default.
 */
static u32 fnp4l_l3_check_act(struct fnp4l *np, unsigned int id)
{
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	struct fnp4l_port *port = np->ports[id];

	if (fnp4l_dsa_offload(port))
		return NP4L_IHP_L3_CHECK_ALL & ~NP4L_IHP_L3_CHECK_DSA_HOST;
#endif
	return NP4L_IHP_L3_CHECK_ALL;
}

static void fnp4l_ihp_init(struct fnp4l *np)
{
	const struct fnp4l_soc *soc = np->soc;
	u32 xhp = NP4L_XHP_BASE - NP4L_IHP_L3_ANOMALY_EN(0);
	unsigned int id;

	for (id = 0; id < NP4L_NR_PORTS; id++) {
		fnp4l_wr(np, NP4L_IHP_L3_ANOMALY_ACT(id), 0);
		fnp4l_wr(np, NP4L_IHP_L3_ANOMALY_EN(id), fnp4l_l3_anomaly_en(np, id));
		fnp4l_wr(np, NP4L_IHP_L4_ANOMALY_EN(id), 0);
		fnp4l_wr(np, NP4L_IHP_L4_ANOMALY_ACT(id), 0);
		fnp4l_wr(np, NP4L_IHP_L3_CHECK_EN(id), NP4L_IHP_L3_CHECK_ALL);
		fnp4l_wr(np, NP4L_IHP_L3_CHECK_ACT(id), fnp4l_l3_check_act(np, id));
		fnp4l_wr(np, NP4L_IHP_TCP_CHECK_EN(id), 0x3);
		fnp4l_wr(np, NP4L_IHP_TCP_CHECK_ACT(id), 0);
		fnp4l_wr(np, NP4L_IHP_UDP_CHECK_EN(id), 0x27);
		fnp4l_wr(np, NP4L_IHP_UDP_CHECK_ACT(id), 0);
		fnp4l_wr(np, NP4L_IHP_L4_CHECK_EN(id), 0xf);
		fnp4l_wr(np, NP4L_IHP_L4_CHECK_ACT(id), 0);
		fnp4l_wr(np, NP4L_IHP_CTRL(id), soc->ihp_ctrl);
		fnp4l_wr(np, NP4L_IHP_UDP_ESP_MIN_LEN(id), 8);
		if (soc->ihp_l4minlen)
			fnp4l_wr(np, NP4L_IHP_L4_MIN_LEN(id), soc->ihp_l4minlen);
		if (soc->ihp_uesp_proto0)
			fnp4l_wr(np, NP4L_IHP_UDP_ESP_PROTO0(id),
				 soc->ihp_uesp_proto0);
	}

	if (!soc->xhp)
		return;

	fnp4l_wr(np, xhp + NP4L_IHP_L3_ANOMALY_EN(0), 0);
	fnp4l_wr(np, xhp + NP4L_IHP_L4_ANOMALY_EN(0), 0);
	fnp4l_wr(np, xhp + NP4L_IHP_L3_CHECK_EN(0), 0x3f);
	fnp4l_wr(np, xhp + NP4L_IHP_L3_CHECK_ACT(0), 0x7f);
	fnp4l_wr(np, xhp + NP4L_IHP_TCP_CHECK_EN(0), 0x3);
	fnp4l_wr(np, xhp + NP4L_IHP_TCP_CHECK_ACT(0), 0);
	fnp4l_wr(np, xhp + NP4L_IHP_UDP_CHECK_EN(0), 0x27);
	fnp4l_wr(np, xhp + NP4L_IHP_UDP_CHECK_ACT(0), 0);
	fnp4l_wr(np, xhp + NP4L_IHP_L4_CHECK_EN(0), 0xf);
	fnp4l_wr(np, xhp + NP4L_IHP_L4_CHECK_ACT(0), 0);
	fnp4l_wr(np, xhp + NP4L_IHP_CTRL(0), 0xc);
}

/*
 * Start the shared HIF, when the first port opens. The receive side of
 * every port is still cut (fnp4l_hif_stop()): each port opens its own
 * on link up.
 */
static int fnp4l_hif_start(struct fnp4l *np)
{
	unsigned int rx_start, tx_start;
	int ret;

	ret = fnp4l_rx_alloc(np);
	if (ret)
		return ret;

	ret = fnp4l_hif_program(np, &rx_start, &tx_start);
	if (ret) {
		fnp4l_hif_park(np);
		fnp4l_rx_free(np);
		return ret;
	}

	fnp4l_rx_fill(np, rx_start);
	np->tx_head = tx_start;
	np->tx_tail = tx_start;
	np->tx_stopped = false;
	memset(np->tx_ring, 0, NP4L_TX_RING_LEN * sizeof(*np->tx_ring));

	dma_wmb();
	fnp4l_wr(np, NP4L_HRX_RING_HEAD, np->rx_tail);

	napi_enable(&np->napi);

	fnp4l_wr(np, NP4L_HRX_CTRL, NP4L_HIF_CTRL_RUN);
	fnp4l_wr(np, NP4L_HTX_CTRL, NP4L_HIF_CTRL_RUN);
	/* Once the HIF runs */
	if (np->soc->rx_wb)
		fnp4l_wr(np, NP4L_HRX_WB_CFG, NP4L_HRX_WB_CFG_INIT);

	/* Starting the HIF must not have moved the done indexes. */
	if (fnp4l_rd(np, NP4L_HRX_RING_DONE) != rx_start ||
	    fnp4l_rd(np, NP4L_HTX_RING_DONE) != tx_start) {
		dev_err(np->dev, "done indexes moved when starting the HIF\n");
		fnp4l_hif_stop(np);
		fnp4l_hif_park(np);
		napi_disable(&np->napi);
		fnp4l_rx_free(np);
		return -EIO;
	}

	fnp4l_ihp_init(np);

	/* Clear leftovers while the ports still receive nothing. */
	fnp4l_ack(np, fnp4l_rd(np, NP4L_HRX_INT_STATUS), fnp4l_rd(np, NP4L_HTX_INT_STATUS));
	fnp4l_irq_mask(np, NP4L_HIF_INT_ALL);

	spin_lock_bh(&np->tx_lock);
	np->hif_up = true;
	spin_unlock_bh(&np->tx_lock);

	return 0;
}

/*
 * Drop the frames still on the TX ring, once the NP no longer reads it:
 * the ones it completed were released by fnp4l_tx_clean() before, the
 * others were not sent. Under RTNL, every queue stopped.
 */
static void fnp4l_tx_release(struct fnp4l *np)
{
	spin_lock_bh(&np->tx_lock);
	while (np->tx_head != np->tx_tail) {
		struct fnp4l_tx_slot *slot = &np->tx_slot[np->tx_head];

		fnp4l_tx_unmap(np, slot);
		fnp4l_tx_cmd_wipe(np, np->tx_head);
		if (slot->port) {
			DEV_STATS_INC(slot->port->ndev, tx_dropped);
			slot->port = NULL;
		}
		if (slot->skb) {
			dev_kfree_skb_any(slot->skb);
			slot->skb = NULL;
		}
		np->tx_head = (np->tx_head + 1) & NP4L_TX_RING_MASK;
	}
	spin_unlock_bh(&np->tx_lock);
}

/* Stop the shared HIF, when the last port closes. */
static void fnp4l_hif_shutdown(struct fnp4l *np)
{
	fnp4l_sse_hif_down(np);
	fnp4l_hif_stop(np);
	synchronize_irq(np->irq);
	napi_disable(&np->napi);

	/*
	 * A poll that completed before napi_disable() may have unmasked the
	 * interrupt again.
	 */
	fnp4l_irq_mask(np, 0);
	fnp4l_ack(np, fnp4l_rd(np, NP4L_HRX_INT_STATUS), fnp4l_rd(np, NP4L_HTX_INT_STATUS));
	synchronize_irq(np->irq);

	/*
	 * Frames the NP completed before it stopped count as sent: release
	 * them while the done index still refers to our ring.
	 */
	local_bh_disable();
	fnp4l_tx_clean(np);
	local_bh_enable();

	/*
	 * The NP is off our rings before their pages are released and the
	 * frames still queued for transmission unmapped.
	 */
	fnp4l_hif_park(np);
	fnp4l_tx_release(np);
	fnp4l_rx_free(np);
}

static void fnp4l_mac_config(struct phylink_config *config,
			     unsigned int mode,
			     const struct phylink_link_state *state)
{
	/* RGMII only, nothing to switch. */
}

static void fnp4l_mac_link_down(struct phylink_config *config,
				unsigned int mode, phy_interface_t interface)
{
	struct fnp4l_port *port = netdev_priv(to_net_dev(config->dev));

	fnp4l_gmii_rx_cut(port->np, port->id);
}

/* The receive side is written last: it is what lets frames in. */
static void fnp4l_mac_link_up(struct phylink_config *config,
			      struct phy_device *phy, unsigned int mode,
			      phy_interface_t interface, int speed,
			      int duplex, bool tx_pause, bool rx_pause)
{
	struct fnp4l_port *port = netdev_priv(to_net_dev(config->dev));
	struct fnp4l *np = port->np;
	u32 id = port->id;
	u32 tx, rx;

	tx = fnp4l_rd(np, NP4L_GMII_TX(id)) & ~NP4L_GMII_TX_CLR;
	tx |= NP4L_GMII_TX_BIT20;
	if (speed == SPEED_1000)
		tx |= NP4L_GMII_TX_1000;
	else if (speed == SPEED_100)
		tx |= NP4L_GMII_TX_100;
	if (duplex != DUPLEX_FULL)
		tx |= NP4L_GMII_TX_HALF;
	if (np->soc->gmii_tx_hi) {
		if (duplex == DUPLEX_FULL)
			tx |= NP4L_GMII_TX_FULL;
		else
			tx &= ~NP4L_GMII_TX_HALF_CLR;
	}

	rx = fnp4l_rd(np, NP4L_GMII_RX(id)) & ~NP4L_GMII_RX_CLR;
	if (speed == SPEED_1000)
		rx |= NP4L_GMII_RX_1000;

	fnp4l_wr(np, NP4L_GMII_TX(id), tx);
	fnp4l_wr(np, NP4L_GMII_RX(id), rx);
}

static const struct phylink_mac_ops fnp4l_phylink_ops = {
	.mac_config	= fnp4l_mac_config,
	.mac_link_down	= fnp4l_mac_link_down,
	.mac_link_up	= fnp4l_mac_link_up,
};

/*
 * 802.1Q extraction on reception, for a port that offers rx-vlan-offload
 * (never a DSA conduit). Off is the state of the boot loader, restored
 * when the port closes. Frames already received keep the form they were
 * received in: the host tag tells which. Under RTNL.
 */
static void fnp4l_vlan_rx_set(struct fnp4l_port *port, bool on)
{
	ASSERT_RTNL();
	if (!(port->ndev->hw_features & NETIF_F_HW_VLAN_CTAG_RX))
		return;

	fnp4l_wr(port->np, NP4L_IGR_VLAN_TPID(port->id),
		 on ? NP4L_IGR_TPID_EN | NP4L_TPID_8021Q : 0);
}

static int fnp4l_set_features(struct net_device *ndev,
			      netdev_features_t features)
{
	struct fnp4l_port *port = netdev_priv(ndev);

	if (netif_running(ndev) &&
	    ((ndev->features ^ features) & NETIF_F_HW_VLAN_CTAG_RX))
		fnp4l_vlan_rx_set(port,
				  features & NETIF_F_HW_VLAN_CTAG_RX);

	return 0;
}

/*
 * Class mode again on a port with an empty VLAN action table, should it
 * be off with fnp4l_wan_class() (a table write failed, at probe or since):
 * before reception opens.
 */
static void fnp4l_igr_open(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	int ret = 0;

	if (!fnp4l_wan_class(port))
		return;

	mutex_lock(&np->sse_lock);
	if (!port->class_on && !port->vlan_act_nr) {
		spin_lock_bh(&np->tbl_lock);
		ret = fnp4l_igr_idle(port);
		spin_unlock_bh(&np->tbl_lock);
	}
	mutex_unlock(&np->sse_lock);
	if (ret)
		netdev_err(port->ndev, "class mode off (%d), no MAC filter\n",
			   ret);
}

static int fnp4l_open(struct net_device *ndev)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;
	int ret;

	ASSERT_RTNL();
	if (!np->users) {
		ret = fnp4l_hif_start(np);
		if (ret)
			return ret;
	}
	np->users++;

	/* Reception stays cut until phylink reports the link up. */
	ret = phylink_of_phy_connect(port->phylink, port->of_node, 0);
	if (ret) {
		netdev_err(ndev, "cannot connect PHY: %d\n", ret);
		if (!--np->users)
			fnp4l_hif_shutdown(np);
		return ret;
	}
	fnp4l_vlan_rx_set(port, ndev->features & NETIF_F_HW_VLAN_CTAG_RX);
	fnp4l_igr_open(port);

	phylink_start(port->phylink);
	netif_start_queue(ndev);

	return 0;
}

static int fnp4l_stop(struct net_device *ndev)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;

	ASSERT_RTNL();
	netif_stop_queue(ndev);
	phylink_stop(port->phylink);
	phylink_disconnect_phy(port->phylink);
	/* Already done by mac_link_down, unless the link never came up. */
	fnp4l_gmii_rx_cut(np, port->id);
	fnp4l_vlan_rx_set(port, false);

	/*
	 * The rings stay up while another port is open. Frames of this port
	 * still in flight are transmitted, or dropped on reception, and
	 * never touch the net_device afterwards but for its statistics: the
	 * net_device outlives the HIF.
	 */
	if (!--np->users)
		fnp4l_hif_shutdown(np);

	return 0;
}

/*
 * The NP parses the headers of a frame to fill in its checksum: plain
 * Ethernet, IPv4 without options, TCP or UDP, with the checksum where the
 * protocol puts it. Frames of a DSA conduit carry a switch tag before the
 * EtherType, VLAN frames a tag the NP is not known to skip or, when the
 * EGR inserts it, to account for.
 */
static bool fnp4l_tx_csum_ok(struct sk_buff *skb, struct net_device *ndev)
{
	const struct iphdr *iph;
	unsigned int off, hlen;

	if (netdev_uses_dsa(ndev) || skb_vlan_tag_present(skb) ||
	    skb->protocol != htons(ETH_P_IP) ||
	    skb_headlen(skb) < ETH_HLEN + sizeof(*iph) ||
	    ((const struct ethhdr *)skb->data)->h_proto != htons(ETH_P_IP) ||
	    skb_network_offset(skb) != ETH_HLEN)
		return false;

	iph = ip_hdr(skb);
	if (iph->ihl != 5 || ip_is_fragment(iph) ||
	    skb_checksum_start_offset(skb) != ETH_HLEN + sizeof(*iph))
		return false;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		off = offsetof(struct tcphdr, check);
		hlen = tcp_hdrlen(skb);
		break;
	case IPPROTO_UDP:
		off = offsetof(struct udphdr, check);
		hlen = sizeof(struct udphdr);
		break;
	default:
		return false;
	}

	/*
	 * The headers must be in the first segment; how the NP copes with
	 * them split is not known.
	 */
	return skb->csum_offset == off &&
	       skb_headlen(skb) >= skb_checksum_start_offset(skb) + hlen;
}

/* Frames the NP cannot checksum are checksummed by the stack. */
static netdev_features_t fnp4l_features_check(struct sk_buff *skb,
					      struct net_device *ndev,
					      netdev_features_t features)
{
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    !fnp4l_tx_csum_ok(skb, ndev))
		features &= ~NETIF_F_CSUM_MASK;

	return features;
}

/*
 * Host tag: valid, destination LIF, and the TCI of the 802.1Q tag the EGR
 * inserts (0 = none): the stack leaves the tag out of the frame when
 * tx-vlan-offload is on.
 */
static void fnp4l_tx_htag(const struct fnp4l_port *port,
			  const struct sk_buff *skb, u8 *buf)
{
	memset(buf, 0, NP4L_HTAG_LEN);
	buf[0] = NP4L_HTAG_TX_VALID | ((port->lif >> 8) & 3);
	buf[1] = port->lif & 0xff;
	if (skb_vlan_tag_present(skb))
		put_unaligned_be16(skb_vlan_tag_get(skb), buf + 2);
}

static void fnp4l_tx_bd_set(struct fnp4l *np, unsigned int t,
			    dma_addr_t addr, u32 len, u32 ctrl)
{
	struct fnp4l_tx_bd *bd = &np->tx_ring[t];

	bd->addr = cpu_to_le32(addr);
	bd->len = cpu_to_le32(len);
	bd->ctrl = cpu_to_le32(ctrl);
	bd->rsvd = 0;
}

/*
 * Copy the frame to the bounce buffer of descriptor @t, a single segment.
 * The skb is consumed. Under tx_lock.
 */
static void fnp4l_tx_bounce(struct fnp4l *np, struct fnp4l_port *port,
			    struct sk_buff *skb, unsigned int t, u32 ctrl)
{
	struct fnp4l_tx_slot *slot = &np->tx_slot[t];
	u8 *buf = np->tx_buf + t * NP4L_BUF_STRIDE;
	unsigned int len = skb->len;

	fnp4l_tx_htag(port, skb, buf);
	skb_copy_bits(skb, 0, buf + NP4L_HTAG_LEN, len);
	/*
	 * Not a frame to encrypt: a frame longer than its IP packet stalls
	 * the IPsec engine of the FortiSOC2 for good, from a single byte of
	 * padding on (FIXME: why; until then, never pad). The engine sends a
	 * frame of its own, longer than ETH_ZLEN.
	 */
	if (len < ETH_ZLEN && !(ctrl & NP4L_TX_IPSEC)) {
		memset(buf + NP4L_HTAG_LEN + len, 0, ETH_ZLEN - len);
		len = ETH_ZLEN;
	}
	dev_consume_skb_any(skb);

	slot->dma_len = 0;
	fnp4l_tx_bd_set(np, t, np->tx_buf_dma + t * NP4L_BUF_STRIDE,
			FIELD_PREP(NP4L_TX_FRAME_LEN, len),
			ctrl | NP4L_TX_EOP |
			FIELD_PREP(NP4L_TX_SEG_LEN, len + NP4L_HTAG_LEN));
	slot->skb = NULL;
	slot->port = port;
	slot->len = len;
}

/*
 * FortiSOC2: post a flow engine command of @len bytes on the TX ring:
 * copied to the bounce buffer of the descriptor, no host tag, no padding,
 * the command bit set. No statistics
 * are kept for it. -EBUSY when the ring is full, -ENETDOWN when the HIF
 * is stopped. The descriptor is returned in @t.
 */
static int fnp4l_tx_cmd_try(struct fnp4l *np, const void *cmd,
			    unsigned int len, unsigned int *t)
{
	struct fnp4l_tx_slot *slot;
	unsigned int i;
	int ret = 0;

	spin_lock_bh(&np->tx_lock);
	if (!np->hif_up) {
		ret = -ENETDOWN;
		goto out;
	}
	if (!fnp4l_tx_free(np)) {
		ret = -EBUSY;
		goto out;
	}

	i = np->tx_tail;
	slot = &np->tx_slot[i];
	memcpy(np->tx_buf + i * NP4L_BUF_STRIDE, cmd, len);
	slot->dma_len = 0;
	slot->skb = NULL;
	slot->port = NULL;
	/* Wiped once read: IPsec commands carry keys. */
	slot->cmd = true;
	slot->len = len;
	fnp4l_tx_bd_set(np, i, np->tx_buf_dma + i * NP4L_BUF_STRIDE,
			FIELD_PREP(NP4L_TX_FRAME_LEN, len),
			NP4L_TX_EOP | NP4L_TX_CMD | FIELD_PREP(NP4L_TX_SEG_LEN, len));

	dma_wmb();
	np->tx_tail = (i + 1) & NP4L_TX_RING_MASK;
	fnp4l_wr(np, NP4L_HTX_RING_HEAD, np->tx_tail);
	if (fnp4l_tx_free(np) < NP4L_TX_MAX_BDS)
		fnp4l_tx_stop_all(np);
	*t = i;
out:
	spin_unlock_bh(&np->tx_lock);

	return ret;
}

/*
 * Post a command, waiting for room on the ring as long as a command may
 * take. A ring still full then gives -ENOSPC: nothing was posted.
 */
static int fnp4l_tx_cmd(struct fnp4l *np, const void *cmd,
			unsigned int len, unsigned int *t)
{
	int ret;

	if (read_poll_timeout(fnp4l_tx_cmd_try, ret, ret != -EBUSY,
			      NP4L_SSE_SLEEP_US, NP4L_SSE_TIMEOUT_US, false,
			      np, cmd, len, t))
		return -ENOSPC;

	return ret;
}

/* Whether the NP has yet to read TX descriptor @t, posted by us. */
static bool fnp4l_tx_pending(struct fnp4l *np, unsigned int t)
{
	unsigned int used, pos, done;

	spin_lock_bh(&np->tx_lock);
	used = (np->tx_tail - np->tx_head) & NP4L_TX_RING_MASK;
	pos = (t - np->tx_head) & NP4L_TX_RING_MASK;
	done = (fnp4l_rd(np, NP4L_HTX_RING_DONE) - np->tx_head) & NP4L_TX_RING_MASK;
	spin_unlock_bh(&np->tx_lock);

	/* Released already, or behind the done index */
	return pos < used && pos >= done;
}

static int fnp4l_tx_wait(struct fnp4l *np, unsigned int t)
{
	bool pending;

	if (!read_poll_timeout_atomic(fnp4l_tx_pending, pending, !pending,
				      1, NP4L_SSE_SPIN_US, false, np, t))
		return 0;

	return read_poll_timeout(fnp4l_tx_pending, pending, !pending,
				 NP4L_SSE_SLEEP_US, NP4L_SSE_TIMEOUT_US, false,
				 np, t);
}

/*
 * FortiSOC2 counterpart of fnp4l_sse_exec(): the command is consumed
 * once the NP has read its descriptor, then @tot_reg tells it was
 * processed and @succ_reg whether it succeeded. The control register is
 * only checked for the
 * engine still running, and its other bits, whose meaning is not known
 * here, are reported. Under sse_lock.
 */
static int fnp4l_sse_fsoc2_exec(struct fnp4l *np, const void *cmd,
				unsigned int words, u32 tot_reg, u32 succ_reg)
{
	u32 tot = 0, succ = 0, ctrl, val;
	unsigned int t = 0;
	int ret;

	if (tot_reg) {
		tot = fnp4l_rd(np, tot_reg);
		succ = fnp4l_rd(np, succ_reg);
	}

	ret = fnp4l_tx_cmd(np, cmd, words * 8, &t);
	if (ret) {
		dev_err(np->dev, "cannot post flow engine command %#x: %d\n",
			*(const u8 *)cmd, ret);
		return ret;
	}

	ret = fnp4l_tx_wait(np, t);
	if (!ret && tot_reg)
		ret = fnp4l_sse_poll(np, tot_reg, tot + 1);

	ctrl = fnp4l_rd(np, NP4L_SSE_FSOC2_CTRL);
	if (ret) {
		dev_err(np->dev, "flow engine command %#x timed out, control %#x, descriptor %u, TX done %#x\n",
			*(const u8 *)cmd, ctrl, t, fnp4l_rd(np, NP4L_HTX_RING_DONE));
		return ret;
	}
	if ((ctrl & NP4L_SSE_CTRL_RESET) || !(ctrl & NP4L_SSE_CTRL_RUN)) {
		dev_err(np->dev, "flow engine stopped, control %#x\n", ctrl);
		return -EIO;
	}
	if (ctrl & (NP4L_SSE_CTRL_FATAL | NP4L_SSE_CTRL_INS_FAIL | NP4L_SSE_CTRL_DEL_FAIL))
		dev_warn_once(np->dev, "flow engine control %#x after command %#x\n",
			      ctrl, *(const u8 *)cmd);

	if (tot_reg &&
	    readl_poll_timeout_atomic(np->base + succ_reg, val, val == succ + 1,
				      1, 100))
		return -ENOENT;

	return 0;
}

/*
 * Map the frame where it is, from descriptor @t on: host tag pushed into the
 * headroom and linear part in the first descriptor, one descriptor per
 * page fragment, the skb kept on the last one until the NP is done with
 * it. The caller made sure of the headroom and of the free descriptors.
 * On failure nothing is left mapped and the skb is as it was. Under
 * tx_lock.
 *
 * No descriptor carries address 0, even for the NP to read: page 0 is
 * ordinary RAM on this board, but what the NP makes of a null address is
 * not known. Such a mapping is treated as a failure.
 */
static int fnp4l_tx_map(struct fnp4l *np, struct fnp4l_port *port,
			struct sk_buff *skb, unsigned int t, u32 ctrl)
{
	unsigned int nfrags = skb_shinfo(skb)->nr_frags;
	unsigned int len = skb->len, i, n;
	struct fnp4l_tx_slot *slot;
	dma_addr_t dma;

	fnp4l_tx_htag(port, skb, skb_push(skb, NP4L_HTAG_LEN));

	slot = &np->tx_slot[t];
	dma = dma_map_single(np->dev, skb->data, skb_headlen(skb),
			     DMA_TO_DEVICE);
	if (dma_mapping_error(np->dev, dma))
		goto err_pull;
	slot->dma = dma;
	slot->dma_len = skb_headlen(skb);
	slot->dma_page = false;
	slot->skb = NULL;
	slot->port = NULL;
	n = t;
	if (!dma)
		goto err_unmap;

	/* Frame length and checksum request in the first descriptor only */
	fnp4l_tx_bd_set(np, t, dma, FIELD_PREP(NP4L_TX_FRAME_LEN, len),
			ctrl | (nfrags ? 0 : NP4L_TX_EOP) |
			FIELD_PREP(NP4L_TX_SEG_LEN, skb_headlen(skb)));

	for (i = 0; i < nfrags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		unsigned int flen = skb_frag_size(frag);

		n = (n + 1) & NP4L_TX_RING_MASK;
		slot = &np->tx_slot[n];
		slot->skb = NULL;
		slot->port = NULL;
		slot->dma_len = 0;
		if (!flen)
			goto err_unmap;
		dma = skb_frag_dma_map(np->dev, frag, 0, flen, DMA_TO_DEVICE);
		if (dma_mapping_error(np->dev, dma))
			goto err_unmap;
		slot->dma = dma;
		slot->dma_len = flen;
		slot->dma_page = true;
		if (!dma)
			goto err_unmap;

		fnp4l_tx_bd_set(np, n, dma, 0,
				(i == nfrags - 1 ? NP4L_TX_EOP : 0) |
				FIELD_PREP(NP4L_TX_SEG_LEN, flen));
	}

	slot->skb = skb;
	slot->port = port;
	slot->len = len;

	return 0;

err_unmap:
	/* Slots t to n, the last one possibly not mapped */
	for (i = t;; i = (i + 1) & NP4L_TX_RING_MASK) {
		fnp4l_tx_unmap(np, &np->tx_slot[i]);
		if (i == n)
			break;
	}
err_pull:
	skb_pull(skb, NP4L_HTAG_LEN);
	return -ENOMEM;
}

static netdev_tx_t fnp4l_start_xmit(struct sk_buff *skb,
				    struct net_device *ndev)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;
	unsigned int nbd = 1;
	bool zc = false;
	int sa;
	u32 ctrl;

	if (unlikely(skb->len > NP4L_TX_MAX_FRAME))
		goto drop;

	/* FortiSOC2: the frames of an offloaded IPsec policy */
	sa = fnp4l_ipsec_xmit(np->ipsec, port->id, skb);
	if (sa < 0)
		goto drop;

	/* FortiSOC2: the port field is left 0, the LIF selects the port. */
	ctrl = np->soc->tx_port ? FIELD_PREP(NP4L_TX_PORT, port->id) : 0;
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		/*
		 * Checked by fnp4l_features_check(), unless bypassed.
		 * FIXME: whether the NP fills the checksum of a
		 * frame it encrypts is not known.
		 */
		if (likely(!sa && fnp4l_tx_csum_ok(skb, ndev)))
			ctrl |= NP4L_TX_CSUM;
		else if (skb_checksum_help(skb))
			goto drop;
	}
	if (sa)
		ctrl |= NP4L_TX_IPSEC;

	/*
	 * Zero copy needs the linear part to hold the Ethernet header and
	 * room in front of it for the host tag. Anything else is copied.
	 */
	if ((READ_ONCE(port->priv_flags) & NP4L_PRIV_TX_ZEROCOPY) &&
	    skb->len > NP4L_TX_COPYBREAK && skb_headlen(skb) >= ETH_HLEN &&
	    !skb_cow_head(skb, NP4L_HTAG_LEN)) {
		zc = true;
		nbd += skb_shinfo(skb)->nr_frags;
	}

	spin_lock(&np->tx_lock);

	/*
	 * The ring is shared by every port: another port may have filled it
	 * since this queue was last woken. Stop them all and let the stack
	 * requeue the frame.
	 */
	if (unlikely(fnp4l_tx_free(np) < nbd)) {
		fnp4l_tx_stop_all(np);
		spin_unlock(&np->tx_lock);
		return NETDEV_TX_BUSY;
	}

	/* Before the host tag is pushed: PHY timestamping parses the frame */
	skb_tx_timestamp(skb);

	if (!zc || fnp4l_tx_map(np, port, skb, np->tx_tail, ctrl)) {
		fnp4l_tx_bounce(np, port, skb, np->tx_tail, ctrl);
		nbd = 1;
	}
	if (sa)
		np->tx_ring[np->tx_tail].rsvd = cpu_to_le32(sa);

	dma_wmb();
	np->tx_tail = (np->tx_tail + nbd) & NP4L_TX_RING_MASK;
	fnp4l_wr(np, NP4L_HTX_RING_HEAD, np->tx_tail);

	if (fnp4l_tx_free(np) < NP4L_TX_MAX_BDS)
		fnp4l_tx_stop_all(np);

	spin_unlock(&np->tx_lock);

	return NETDEV_TX_OK;

drop:
	DEV_STATS_INC(ndev, tx_dropped);
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static void fnp4l_tx_timeout(struct net_device *ndev, unsigned int txqueue)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;

	DEV_STATS_INC(ndev, tx_errors);
	netdev_warn(ndev, "TX timeout, head %#x tail %#x, HTX head %#x fetch %#x done %#x\n",
		    np->tx_head, np->tx_tail, fnp4l_rd(np, NP4L_HTX_RING_HEAD),
		    fnp4l_rd(np, NP4L_HTX_RING_FETCH), fnp4l_rd(np, NP4L_HTX_RING_DONE));
	napi_schedule(&np->napi);
}

/*
 * Promiscuous mode is the "promisc" bit of the MAC filter entry of the
 * LIF. With the bit clear, unicast frames to the address of the entry and
 * broadcast frames get through, other unicast frames are dropped
 * (rx_mac_filter_drops). With it set, the flow engine, whose key has no
 * address, also forwards a unicast frame to another address when its
 * tuple is offloaded (measured, wan1/wan2 of a FortiGate 60D).
 * IFF_PROMISC, IFF_ALLMULTI and a secondary unicast address set it; a
 * multicast list alone (IPv6 neighbour discovery, IGMP, LACPDUs) no
 * longer does: the multicast filter of a LIF is all-multicast, group
 * frames are expected to get through with the bit clear, as broadcast
 * does.
 * The rest of the entry is written back unchanged, and only while it
 * still holds the address of the port.
 */
static void fnp4l_set_rx_mode(struct net_device *ndev)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;
	bool promisc = (ndev->flags & (IFF_PROMISC | IFF_ALLMULTI)) ||
		       !netdev_uc_empty(ndev);
	u8 addr[ETH_ALEN];
	u32 lo, hi, nhi;
	int ret;

	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, port->lif, &lo, &hi);
	if (ret)
		goto out;

	fnp4l_lif_mac_filter(lo, hi, addr);
	if (!(hi & NP4L_LIFA_VALID) || !ether_addr_equal(addr, ndev->dev_addr)) {
		ret = -ENOENT;
		goto out;
	}

	nhi = promisc ? hi | NP4L_LIFA_PROMISC : hi & ~NP4L_LIFA_PROMISC;
	if (nhi != hi)
		ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, port->lif, lo, nhi);
out:
	spin_unlock_bh(&np->tbl_lock);

	if (ret)
		netdev_warn(ndev, "cannot update the MAC filter of LIF %u: %d\n",
			    port->lif, ret);
}

/*
 * The NP filters on the address of the MAC filter entry of the LIF, and
 * offloaded flows leave with it as their source address: change it there
 * first, then in the net_device, both under tbl_lock, so that
 * fnp4l_set_rx_mode() never sees them apart. The rest of the entry
 * (promisc, broadcast, valid, egress counter) is written back unchanged
 * (MAC address entry of a LIF in the filter). The entry is written
 * while frames flow, as set_rx_mode does: the change is live.
 */
static int fnp4l_set_mac_address(struct net_device *ndev, void *p)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;
	struct sockaddr *sa = p;
	u8 addr[ETH_ALEN];
	const u8 *m;
	u32 lo, hi;
	int ret;

	ret = eth_prepare_mac_addr_change(ndev, p);
	if (ret)
		return ret;

	m = sa->sa_data;
	spin_lock_bh(&np->tbl_lock);
	ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, port->lif, &lo, &hi);
	if (ret)
		goto out;

	fnp4l_lif_mac_filter(lo, hi, addr);
	if (!(hi & NP4L_LIFA_VALID) || !ether_addr_equal(addr, ndev->dev_addr)) {
		ret = -EIO;
		goto out;
	}

	lo = m[0] | m[1] << 8 | m[2] << 16 | (u32)m[3] << 24;
	hi = (hi & ~GENMASK(15, 0)) | m[4] | m[5] << 8;
	ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, port->lif, lo, hi);
	if (!ret)
		eth_commit_mac_addr_change(ndev, p);
out:
	spin_unlock_bh(&np->tbl_lock);

	if (ret)
		netdev_err(ndev, "cannot write the address of LIF %u: %d\n",
			   port->lif, ret);

	return ret;
}

/*
 * The "label" of the port node (the marking of the front port), or "p<N>"
 * without one: lets user space give the interfaces stable names.
 */
static int fnp4l_get_phys_port_name(struct net_device *ndev, char *name,
				    size_t len)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	const char *label;
	int n;

	if (!of_property_read_string(port->of_node, "label", &label))
		n = snprintf(name, len, "%s", label);
	else
		n = snprintf(name, len, "p%u", port->id);

	return n >= len ? -EINVAL : 0;
}

static int fnp4l_eth_ioctl(struct net_device *ndev, struct ifreq *rq,
			   int cmd)
{
	struct fnp4l_port *port = netdev_priv(ndev);

	return phylink_mii_ioctl(port->phylink, rq, cmd);
}

/*
 * Flow offload: netfilter flow tables with the "offload" flag. Binding a
 * port starts the engine if needed, then makes its LIF look frames up in
 * the flow table (RX action). Each direction of a flow is one engine entry,
 * inserted when the flow table offloads it, deleted when it tears it down.
 *
 * First version: routed IPv4 TCP and UDP flows between two NP ports, with
 * source or destination translation, with at most one 802.1Q tag on
 * input (taken off: the port has rx-vlan-offload on) and one on output
 * (pushed: the port has tx-vlan-offload on); no QinQ, no PPPoE, no tunnel,
 * not through the switch (DSA: a flow table bound to a switch port reaches
 * the conduit, which refuses it). The MTU of the output is taken when the
 * flow is offloaded.
 *
 * The engine sends TCP segments with FIN or RST to the host, which
 * forwards them: the flow table sees the end of a connection, marks the
 * flow closing and tears it down, which deletes both entries.
 *
 * Activity: every ageing period (40 s), the engine queues a message for
 * each entry frames hit during that period, and removes none. The driver
 * reads these messages when the flow table asks for statistics
 * (FLOW_CLS_STATS, every tenth of the offload timeout per flow, 3 s by
 * default): a direction is taken as possibly active until one period
 * after its last message, and reported
 * as used until then (lastused). An active flow then never reaches its
 * offload timeout (30 s by default, less than a period after the last
 * report); an idle one is torn down at most two periods and the offload
 * timeout after its last frame.
 *
 * Counts: a direction with a per-flow counter (TAE, see
 * fnp4l_tae_get()) reports the packets and bytes since the previous
 * request, which the flow table adds to the connection tracking entry
 * (flow table "counter" flag), and frames counted also mark it active.
 * A direction without one reports no packets and no bytes, only its
 * last use: the words of the FortiSOC2 ageing messages are not counts
 * (struct fnp4l_msg_timeout2).
 */

static struct fnp4l_port *fnp4l_ft_port(struct fnp4l *np,
					const struct net_device *ndev)
{
	unsigned int id;

	for (id = 0; id < NP4L_NR_PORTS; id++)
		if (np->ports[id] && np->ports[id]->ndev == ndev)
			return np->ports[id];

	return NULL;
}

static struct fnp4l_flow *fnp4l_ft_find(struct fnp4l *np,
					unsigned long cookie)
{
	struct fnp4l_flow *flow;

	hash_for_each_possible(np->ft_flows, flow, node, cookie)
		if (flow->cookie == cookie)
			return flow;

	return NULL;
}

/*
 * Ageing message: every direction with this key was active. FortiSOC2:
 * @last_len and @one are the extra words of the message (0 on the
 * FortiSOC1), printed for the debug only.
 */
static void fnp4l_msg_timeout(struct fnp4l *np,
			      const struct fnp4l_sse_key *key,
			      u32 last_len, u32 one)
{
	struct fnp4l_flow *flow;
	bool found = false;

	lockdep_assert_held(&np->sse_lock);
	np->msg_timeout++;
	hash_for_each_possible(np->ft_keys, flow, key_node,
			       fnp4l_key_hash(key)) {
		if (!fnp4l_key_match(&flow->key, key))
			continue;
		flow->last_active = jiffies;
		found = true;
	}
	/* Not an error: the flow may have been torn down since. */
	if (!found)
		np->msg_unknown++;

	dev_dbg(np->dev, "active%s: %u %pI4:%u > %pI4:%u lif %#x vid %u, words %u %u\n",
		found ? "" : " (unknown)", key->proto, &key->saddr,
		ntohs(key->sport), &key->daddr, ntohs(key->dport),
		le16_to_cpu(key->lif), fnp4l_key_vid(key), last_len, one);
}

/*
 * Read the messages the NP queued since the last call: a message whose
 * last word is not written yet is left for the next call. A message of
 * another type is skipped; an invalid length drops the whole queue,
 * rather than stall on it. A head out of range stops the engine. Engine
 * running.
 *
 * TODO: the NP queues the messages of a period in a burst, and the queue
 * holds about 1350 of them; what the NP does with a full queue is not
 * known yet (measurement pending).
 */
static void fnp4l_msg_drain(struct fnp4l *np)
{
	void __iomem *q = np->sseq + NP4L_SSE_QMEM_MSG;
	unsigned int rp = np->msg_rp, pos = rp, wp, avail, first;
	union {
		struct fnp4l_msg_hdr hdr;
		struct fnp4l_msg_timeout timeout;
		u64 words[NP4L_MSG_MAX_WORDS];
	} msg;
	u8 len;

	lockdep_assert_held(&np->sse_lock);

	/* FortiSOC2: the keys the RX path took out of the messages */
	if (np->soc->sse_hif) {
		struct fnp4l_age age;

		while (kfifo_get(&np->msg_fifo, &age))
			fnp4l_msg_timeout(np, &age.key, age.last_len,
					  age.one);
		return;
	}

	wp = fnp4l_rd(np, NP4L_MSG_RING_HEAD);
	if (wp >= NP4L_MSG_RING_WORDS) {
		np->msg_bad++;
		dev_err(np->dev, "flow engine message queue head %#x\n",
			wp);
		fnp4l_sse_fail(np);
		return;
	}

	while (rp != wp) {
		pos = rp;
		memcpy_fromio(&msg.hdr, q + rp * 8, sizeof(msg.hdr));
		len = msg.hdr.len;
		if (!len || len > NP4L_MSG_MAX_WORDS)
			goto bad;

		avail = (wp >= rp ? wp : wp + NP4L_MSG_RING_WORDS) - rp;
		if (avail < len)
			break;

		first = min_t(unsigned int, len, NP4L_MSG_RING_WORDS - rp);
		memcpy_fromio(msg.words, q + rp * 8, first * 8);
		if (first < len)
			memcpy_fromio(&msg.words[first], q, (len - first) * 8);
		rp += len;
		if (rp >= NP4L_MSG_RING_WORDS)
			rp -= NP4L_MSG_RING_WORDS;

		if (msg.hdr.type != NP4L_MSG_TYPE_TIMEOUT ||
		    len * 8 < sizeof(msg.timeout)) {
			np->msg_bad++;
			dev_warn_ratelimited(np->dev, "flow engine message of type %u, length %u at %#x, skipped\n",
					     msg.hdr.type, len, pos);
			continue;
		}
		fnp4l_msg_timeout(np, &msg.timeout.key, 0, 0);
	}
	goto out;

bad:
	np->msg_bad++;
	dev_warn_ratelimited(np->dev, "flow engine message of length %u at %#x, queue dropped\n",
			     len, pos);
	rp = wp;
out:
	if (rp != np->msg_rp) {
		np->msg_rp = rp;
		fnp4l_wr(np, NP4L_MSG_RING_FETCH, rp);
	}
}

/*
 * Apply one header rewrite of a flow rule to @hdr, a copy of the fields
 * of the header the driver tracks: 32-bit word at the offset, bits of
 * the mask kept, value bits set (in memory order, as the rule stores
 * them).
 */
static int fnp4l_ft_mangle(u8 *hdr, unsigned int size,
			   const struct flow_action_entry *act)
{
	u32 off = act->mangle.offset, word;

	if (off % 4 || off > size - 4 || (act->mangle.val & act->mangle.mask))
		return -EOPNOTSUPP;

	memcpy(&word, hdr + off, 4);
	word = (word & act->mangle.mask) | act->mangle.val;
	memcpy(hdr + off, &word, 4);

	return 0;
}

#define NP4L_FT_KEYS	(BIT_ULL(FLOW_DISSECTOR_KEY_META) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |	\
			 BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_TCP) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_VLAN))

#define NP4L_FT_ENC_KEYS	(BIT_ULL(FLOW_DISSECTOR_KEY_ENC_KEYID) |	\
				 BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |	\
				 BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |	\
				 BIT_ULL(FLOW_DISSECTOR_KEY_ENC_CONTROL))

static int fnp4l_upper_is_8021ad(struct net_device *dev,
				 struct netdev_nested_priv *priv)
{
	return is_vlan_dev(dev) &&
	       vlan_dev_vlan_proto(dev) == htons(ETH_P_8021AD);
}

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/*
 * FORTINET_NP4LITE_DSA: the port of the switch @dev is, if it is a user
 * port of a DSA conduit of this NP giving its switch ports a LIF each,
 * with the Broadcom tag, and neither bridged nor
 * enslaved (@msg says why then), or with @slave the slave of a bond: its
 * frames reach the NP on the LIF returned, that of the port; the conduit
 * is np->lif_port[] of it. -ENODEV otherwise. Under RCU.
 */
static int fnp4l_dsa_port(struct fnp4l *np, struct net_device *dev,
			  bool slave, const char **msg)
{
	struct net_device *master;
	struct dsa_port *dp;
	unsigned int id, lif = 0;

	if (!np->dsa_lifs || !dev)
		return -ENODEV;
	dp = dsa_port_from_netdev(dev);
	if (IS_ERR(dp) || dp->cpu_dp->tag_ops->proto != DSA_TAG_PROTO_BRCM ||
	    dp->index >= NP4L_DSA_NR_PORTS)
		return -ENODEV;
	for_each_set_bit(id, &np->dsa_links, NP4L_NR_PORTS) {
		const struct fnp4l_dsa_link *link = &np->dsa_link[id];

		if (dsa_port_to_conduit(dp) == link->port->ndev &&
		    fnp4l_dsa_offload(link->port)) {
			lif = link->lif[dp->index];
			break;
		}
	}
	if (!lif)
		return -ENODEV;

	/*
	 * Traffic the switch bridges never reaches the NP; a bond has a
	 * callback of its own (FORTINET_NP4LITE_LAG).
	 */
	master = netdev_master_upper_dev_get_rcu(dev);
	if (master && netif_is_bridge_master(master)) {
		/* bridge_offload: routed through its bridge */
		if (!slave && fnp4l_dsa_bridged(np, dev, NULL))
			return lif;
		*msg = "port of the switch in a bridge";
		return -EOPNOTSUPP;
	}
	if (slave ? !master || !netif_is_bond_master(master) : !!master) {
		*msg = slave ? "port of the switch not in a bond" :
			       "port of the switch enslaved";
		return -EOPNOTSUPP;
	}

	return lif;
}

/*
 * FORTINET_NP4LITE_DSA: the DSA conduit bound to a flow table whose user
 * port has index @ifindex, for a flow entering through that port, and the
 * LIF of the port in @lif: NULL if it is none, with a reason in @msg if the
 * flow is to be refused. The flow engine keys the flow on that LIF: frames
 * of the same tuple from another port of the switch do not find it. An
 * 802.1Q tagged frame of the port does not either, taken to be no IPv4
 * frame to the IHP, which sees its tag after the switch tag is off (not
 * extracted on the link of the conduit).
 */
static struct fnp4l_port *fnp4l_dsa_in(struct fnp4l *np,
				       struct net *net, int ifindex,
				       u32 *lif, const char **msg)
{
	struct fnp4l_port *port = NULL;
	int l;

	rcu_read_lock();
	l = fnp4l_dsa_port(np, dev_get_by_index_rcu(net, ifindex), false,
			   msg);
	if (l > 0 && test_bit(np->lif_port[l]->id, &np->ft_ports)) {
		port = np->lif_port[l];
		*lif = l;
	}
	rcu_read_unlock();

	return port;
}

/*
 * FORTINET_NP4LITE_DSA: the DSA conduit for a flow leaving
 * through the switch port @dev, and the LIF of the port in @lif: NULL if
 * it is none, with a reason in @msg if the flow is to be refused. The EGR
 * tags the frames for that port alone (NP4L_DSA_EGR_PORT_TAG): a
 * destination the switch does not know is not flooded to the other ports.
 */
static struct fnp4l_port *fnp4l_dsa_out(struct fnp4l *np,
					struct net_device *dev,
					u32 *lif, const char **msg)
{
	u8 buf[ETH_ALEN];
	int l;

	rcu_read_lock();
	l = fnp4l_dsa_port(np, dev, false, msg);
	rcu_read_unlock();
	if (l <= 0 || !fnp4l_dsa_lif_out(np, l))
		return NULL;

	/* The notifier does; the port may have registered before it. */
	fnp4l_dsa_mac_sync(np, l, fnp4l_dsa_addr(np, dev, buf));
	*lif = l;

	return np->lif_port[l];
}
#endif /* CONFIG_FORTINET_NP4LITE_DSA */

/* Refuse a flow, telling why: flow tables do not report the message. */
static int fnp4l_ft_refuse(struct fnp4l_port *port,
			   struct netlink_ext_ack *extack, const char *msg)
{
	NL_SET_ERR_MSG_FMT_MOD(extack, "%s", msg);
	netdev_dbg(port->ndev, "flow not offloaded: %s\n", msg);

	return -EOPNOTSUPP;
}

/* Offsets in the IPv4 header copy of fnp4l_ft_parse() */
#define NP4L_FT_IP_SADDR	offsetof(struct iphdr, saddr)
#define NP4L_FT_IP_DADDR	offsetof(struct iphdr, daddr)
#define NP4L_FT_IP_LEN		sizeof(struct iphdr)

/*
 * Build the insertion of one direction of a flow entering on @port. The
 * TCP flags match (no FIN, no RST) cannot be expressed: see above.
 *
 * Translation is recognised by comparing the rewritten tuple with the
 * key. Source or destination
 * translation, of the address, the port or both, is supported, and both at
 * once (destination translation followed by masquerading).
 */
static int fnp4l_ft_parse(struct fnp4l_port *port,
			  struct flow_cls_offload *cls,
			  struct fnp4l_sse_ins *cmd,
			  struct fnp4l_port **out,
			  const struct xfrm_state **xs)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct netlink_ext_ack *extack = cls->common.extack;
	const struct flow_action_entry *act;
	struct flow_match_ipv4_addrs addrs;
	struct fnp4l_port *oport = NULL;
	struct flow_match_control control;
	struct flow_match_ports ports;
	struct flow_match_basic basic;
	struct flow_match_meta meta;
	u8 eth[2 * ETH_ALEN] = {};
	u8 ip[NP4L_FT_IP_LEN] = {};
	u16 in_vid = 0, out_tci = 0;
	struct net_device *vdev;
	const char *msg = NULL;
	bool pop = false;
	unsigned int mtu;
	__be16 l4[2];
	u64 used;
	int ret, i;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	struct net_device *odev = NULL;
	u32 in_lif = port->lif, out_lif = 0;
#endif

	*xs = NULL;
	/* Each port sees every flow: take those that enter through it. */
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META))
		return -EOPNOTSUPP;
	flow_rule_match_meta(rule, &meta);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	if (fnp4l_dsa_conduit(port)) {
		/* Through a user port of this conduit, on the LIF of the port */
		if (fnp4l_dsa_in(port->np, dev_net(port->ndev),
				 meta.key->ingress_ifindex, &in_lif,
				 &msg) != port)
			return msg ? fnp4l_ft_refuse(port, extack, msg) :
				     -ENOENT;
	} else
#endif
	if (meta.key->ingress_ifindex != port->ndev->ifindex)
		return -ENOENT;

	/*
	 * Tell a non-IPv4 flow apart first: its address key is not in
	 * NP4L_FT_KEYS and would otherwise be reported as an unsupported match.
	 */
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC))
		return fnp4l_ft_refuse(port, extack, "not IPv4");
	flow_rule_match_control(rule, &control);
	flow_rule_match_basic(rule, &basic);
	if (control.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS ||
	    basic.key->n_proto != htons(ETH_P_IP))
		return fnp4l_ft_refuse(port, extack, "not IPv4");

	used = rule->match.dissector->used_keys;
	if (used & BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN))
		return fnp4l_ft_refuse(port, extack, "stacked VLAN tags");
	if (used & NP4L_FT_ENC_KEYS)
		return fnp4l_ft_refuse(port, extack, "tunnel");
	if (used & ~NP4L_FT_KEYS)
		return fnp4l_ft_refuse(port, extack, "unsupported match");

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS))
		return fnp4l_ft_refuse(port, extack, "not IPv4 TCP or UDP");

	if (flow_rule_has_control_flags(control.mask->flags, extack))
		return fnp4l_ft_refuse(port, extack, "not IPv4");

	if (basic.key->ip_proto != IPPROTO_TCP &&
	    basic.key->ip_proto != IPPROTO_UDP)
		return fnp4l_ft_refuse(port, extack, "not IPv4 TCP or UDP");

	/*
	 * One 802.1Q tag on input: the engine keys on the VID the IGR
	 * extracted, hence rx-vlan-offload on. VID 0 is the key of an
	 * untagged frame.
	 */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan vlan;

		flow_rule_match_vlan(rule, &vlan);
		if (vlan.key->vlan_tpid != htons(ETH_P_8021Q))
			return fnp4l_ft_refuse(port, extack,
					       "input VLAN not 802.1Q");
		if (vlan.mask->vlan_id != VLAN_VID_MASK ||
		    vlan.mask->vlan_priority || vlan.mask->vlan_dei ||
		    vlan.mask->vlan_eth_type || !vlan.key->vlan_id ||
		    !(port->ndev->features & NETIF_F_HW_VLAN_CTAG_RX) ||
		    !port->vlan_act_avail)
			return fnp4l_ft_refuse(port, extack,
					       "unsupported input VLAN");
		in_vid = vlan.key->vlan_id;
	}

	/*
	 * The flow table may pass an 802.1ad tag over in silence: an S-tagged
	 * flow then looks untagged, a QinQ one tagged with its inner VID. The
	 * IGR extracts 802.1Q tags only, and such a flow would share its key
	 * with frames of another VLAN. Refuse every flow of a port with an
	 * 802.1ad device above it, and a VID without an 802.1Q device.
	 */
	rcu_read_lock();
	if (netdev_walk_all_upper_dev_rcu(port->ndev, fnp4l_upper_is_8021ad,
					  NULL))
		msg = "802.1ad VLAN on the input port";
	else if (in_vid && !__vlan_find_dev_deep_rcu(port->ndev,
						     htons(ETH_P_8021Q),
						     in_vid))
		msg = "no 802.1Q device for the input VLAN";
	rcu_read_unlock();
	if (msg)
		return fnp4l_ft_refuse(port, extack, msg);

	flow_rule_match_ipv4_addrs(rule, &addrs);
	flow_rule_match_ports(rule, &ports);

	memcpy(ip + NP4L_FT_IP_SADDR, &addrs.key->src, 4);
	memcpy(ip + NP4L_FT_IP_DADDR, &addrs.key->dst, 4);
	l4[0] = ports.key->src;
	l4[1] = ports.key->dst;

	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			switch (act->mangle.htype) {
			case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
				ret = fnp4l_ft_mangle(eth, sizeof(eth), act);
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
				ret = act->mangle.offset < NP4L_FT_IP_SADDR ? -EOPNOTSUPP :
				      fnp4l_ft_mangle(ip, sizeof(ip), act);
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
			case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
				ret = fnp4l_ft_mangle((u8 *)l4, sizeof(l4),
						      act);
				break;
			default:
				ret = -EOPNOTSUPP;
			}
			if (ret)
				return fnp4l_ft_refuse(port, extack,
						       "unsupported rewrite");
			break;
		case FLOW_ACTION_CSUM:
			/* The engine updates the checksums it has to. */
			break;
		case FLOW_ACTION_VLAN_POP:
			if (pop)
				return fnp4l_ft_refuse(port, extack,
						       "stacked VLAN tags");
			pop = true;
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (out_tci)
				return fnp4l_ft_refuse(port, extack,
						       "stacked VLAN tags");
			if (act->vlan.proto != htons(ETH_P_8021Q))
				return fnp4l_ft_refuse(port, extack,
						       "output VLAN not 802.1Q");
			if (!act->vlan.vid || act->vlan.vid >= VLAN_VID_MASK)
				return fnp4l_ft_refuse(port, extack,
						       "unsupported output VLAN");
			out_tci = act->vlan.vid |
				  (u16)act->vlan.prio << VLAN_PRIO_SHIFT;
			break;
		case FLOW_ACTION_REDIRECT:
			if (oport)
				return -EOPNOTSUPP;
			oport = fnp4l_ft_port(port->np, act->dev);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
			/* Or a port of the switch, but from the switch */
			if (!oport) {
				oport = fnp4l_dsa_out(port->np, act->dev,
						      &out_lif, &msg);
				if (msg)
					return fnp4l_ft_refuse(port, extack,
							       msg);
				if (oport && (oport != port ||
					      (READ_ONCE(same_switch_offload) &&
					       out_lif != in_lif))) {
					odev = act->dev;
					break;
				}
			}
#endif
			if (!oport || oport == port ||
			    netdev_uses_dsa(oport->ndev))
				return fnp4l_ft_refuse(port, extack,
						       "output is not another NP port");
			break;
#ifdef CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS
		case FLOW_ACTION_XFRM:
			/*
			 * Only the pointer is kept: the SA lives as long as
			 * the call, its offloaded state may not, and is only
			 * looked at under sse_lock (fnp4l_ipsec_ft_chain()).
			 */
			if (*xs || !act->xfrm)
				return -EOPNOTSUPP;
			*xs = act->xfrm;
			break;
#endif
		default:
			return fnp4l_ft_refuse(port, extack, "unsupported action");
		}
	}

#ifdef CONFIG_FORTINET_NP4LITE_DSA
	/*
	 * Through a port of the switch: the address and MTU of the user
	 * port, and no 802.1Q tag (the EGR would put it after the switch
	 * tag, not tried).
	 */
	if (odev) {
		u8 buf[ETH_ALEN];

		/* Through a bridge (bridge_offload): its address */
		if (!is_valid_ether_addr(eth) ||
		    !ether_addr_equal(eth + ETH_ALEN,
				      fnp4l_dsa_addr(port->np, odev, buf)))
			return fnp4l_ft_refuse(port, extack,
					       "unsupported MAC header");
		if (pop != !!in_vid)
			return fnp4l_ft_refuse(port, extack,
					       "unsupported input VLAN");
		if (out_tci)
			return fnp4l_ft_refuse(port, extack,
					       "output VLAN on a port of the switch");
		mtu = READ_ONCE(odev->mtu);
		goto check_mtu;
	}
#endif

	/* The engine takes the source MAC address from the output LIF. */
	if (!oport || !is_valid_ether_addr(eth) ||
	    !ether_addr_equal(eth + ETH_ALEN, oport->ndev->dev_addr))
		return fnp4l_ft_refuse(port, extack,
				       "unsupported MAC header");

	/* The tag matched is the tag taken off, and nothing else. */
	if (pop != !!in_vid)
		return fnp4l_ft_refuse(port, extack,
				       "unsupported input VLAN");

	/*
	 * The engine pushes the tag on output; tx-vlan-offload on stands
	 * for "802.1Q insertion tried on this port". The MTU is the one of
	 * the VLAN device, where there is one, if smaller.
	 */
	mtu = READ_ONCE(oport->ndev->mtu);
	if (out_tci) {
		if (!(oport->ndev->features & NETIF_F_HW_VLAN_CTAG_TX))
			return fnp4l_ft_refuse(port, extack,
					       "unsupported output VLAN");
		rcu_read_lock();
		vdev = __vlan_find_dev_deep_rcu(oport->ndev, htons(ETH_P_8021Q),
						out_tci & VLAN_VID_MASK);
		if (vdev)
			mtu = min(mtu, READ_ONCE(vdev->mtu));
		rcu_read_unlock();
	}

	/*
	 * The engine does not check the MTU of the entry: with 1400 on the
	 * output port, DF packets of 1500 bytes still went out. Frames
	 * come in with up to 1500 bytes of IP, so a smaller output MTU
	 * stays with the host, which fragments or answers with ICMP.
	 */
#ifdef CONFIG_FORTINET_NP4LITE_DSA
check_mtu:
#endif
	if (mtu < ETH_DATA_LEN)
		return fnp4l_ft_refuse(port, extack,
				       "output MTU below 1500");

	memset(cmd, 0, sizeof(*cmd));
	cmd->hdr.op = NP4L_SSE_CMD_VALID | NP4L_SSE_OP_INSERT;
	cmd->hdr.len = sizeof(*cmd) / 8;
	cmd->key.saddr = addrs.key->src;
	cmd->key.daddr = addrs.key->dst;
	cmd->key.sport = ports.key->src;
	cmd->key.dport = ports.key->dst;
	cmd->key.proto = basic.key->ip_proto;
	cmd->key.vid_lo = in_vid & 0xff;
	cmd->key.lif = cpu_to_le16(FIELD_PREP(NP4L_SSE_KEY_LIF, port->lif) |
				   FIELD_PREP(NP4L_SSE_KEY_VID_HI, in_vid >> 8));
	cmd->out_lif = oport->lif;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	cmd->key.lif = cpu_to_le16(FIELD_PREP(NP4L_SSE_KEY_LIF, in_lif) |
				   FIELD_PREP(NP4L_SSE_KEY_VID_HI, in_vid >> 8));
	if (odev)
		cmd->out_lif = out_lif;
#endif
	cmd->mtu = cpu_to_le16(mtu);
	cmd->tci = cpu_to_be16(out_tci);
	memcpy(cmd->h_dest, eth, ETH_ALEN);
	memcpy(&cmd->xsaddr, ip + NP4L_FT_IP_SADDR, 4);
	memcpy(&cmd->xdaddr, ip + NP4L_FT_IP_DADDR, 4);
	cmd->xsport = l4[0];
	cmd->xdport = l4[1];
	cmd->act[0] = NP4L_SSE_ACT_ROUTED;
	if (out_tci)
		cmd->act[0] |= NP4L_SSE_ACT_VLAN;
	if (cmd->xsaddr != cmd->key.saddr)
		cmd->act[0] |= NP4L_SSE_ACT_SNAT;
	if (cmd->xdaddr != cmd->key.daddr)
		cmd->act[0] |= NP4L_SSE_ACT_DNAT;
	if (cmd->xsport != cmd->key.sport)
		cmd->act[2] |= NP4L_SSE_ACT_SPAT;
	if (cmd->xdport != cmd->key.dport)
		cmd->act[2] |= NP4L_SSE_ACT_DPAT;

	*out = oport;

	return 0;
}

/*
 * Whether the IPsec offload leaves the direction of insertion @cmd, from
 * port @in to port @out, to the flow engine, which would otherwise forward
 * it past the IPsec policies, in the clear or around a "block" policy: 0,
 * or -EOPNOTSUPP with the reason in @why. Without
 * FORTINET_NP4LITE_IPSEC_FLOWS, any offloaded outbound policy on either
 * port refuses it. A direction the
 * flow table sends through the SA @xs may be sent to the IPsec engine:
 * @cmd is then made to, and @sa set to the index of the SA (0 otherwise).
 * Under sse_lock.
 */
static int fnp4l_ft_ipsec_admit(struct fnp4l *np, unsigned int in,
				unsigned int out,
				struct fnp4l_sse_ins *cmd,
				const struct xfrm_state *xs, u16 *sa,
				const char **why)
{
	const struct fnp4l_ft_tuple key = {
		.saddr = cmd->key.saddr,
		.daddr = cmd->key.daddr,
		.sport = cmd->key.sport,
		.dport = cmd->key.dport,
		.proto = cmd->key.proto,
	};
	const struct fnp4l_ft_tuple xlat = {
		.saddr = cmd->xsaddr,
		.daddr = cmd->xdaddr,
		.sport = cmd->xsport,
		.dport = cmd->xdport,
		.proto = cmd->key.proto,
	};
	u8 h_dest[ETH_ALEN];
	bool nat, vlan;
	u16 idx, mtu;

	*sa = 0;
	if (!IS_ENABLED(CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS)) {
		if (!fnp4l_ipsec_ft_refuse(np->ipsec, BIT(in) | BIT(out)))
			return 0;
		*why = "port with an offloaded IPsec policy";
		return -EOPNOTSUPP;
	}

	nat = (cmd->act[0] & (NP4L_SSE_ACT_SNAT | NP4L_SSE_ACT_DNAT)) ||
	      (cmd->act[2] & (NP4L_SSE_ACT_SPAT | NP4L_SSE_ACT_DPAT));
	vlan = fnp4l_key_vid(&cmd->key) || cmd->tci;

	switch (fnp4l_ipsec_ft_admit(np->ipsec, in, out, &key, &xlat, !!xs,
				     nat, vlan, why)) {
	case NP4L_ADMIT_PLAIN:
		return 0;
	case NP4L_ADMIT_CHAIN:
		/*
		 * FORTINET_NP4LITE_DSA: never chain a flow entering through
		 * the switch ports to the IPsec engine. That path was never
		 * tried, and the IPsec engine stalls on frames it does not
		 * expect: such a flow stays with the host, which
		 * encrypts it.
		 */
		if (IS_ENABLED(CONFIG_FORTINET_NP4LITE_DSA) &&
		    netdev_uses_dsa(np->ports[in]->ndev)) {
			*why = "IPsec flow from the switch ports";
			return -EOPNOTSUPP;
		}
		break;
	default:
		return -EOPNOTSUPP;
	}

	/*
	 * An ordinary entry towards the next hop of the tunnel, with the
	 * index of the SA, which the engine encrypts and encapsulates with,
	 * and the MTU of the tunnel. The engine keeps the counts of the SA.
	 */
	if (fnp4l_ipsec_ft_chain(np->ipsec, out, xs, &xlat, &idx, &mtu,
				 h_dest)) {
		*why = "IPsec SA not chainable";
		return -EOPNOTSUPP;
	}
	cmd->act[1] |= NP4L_SSE_ACT1_IPSEC;
	cmd->act3 |= NP4L_SSE_ACT3_IPSEC;
	cmd->sa = cpu_to_le16(idx);
	cmd->mtu = cpu_to_le16(mtu);
	ether_addr_copy(cmd->h_dest, h_dest);
	*sa = idx;

	return 0;
}

static int fnp4l_ft_replace(struct fnp4l_port *port,
			    struct flow_cls_offload *cls)
{
	struct fnp4l *np = port->np;
	const struct xfrm_state *xs;
	struct fnp4l_sse_ins cmd;
	struct fnp4l_port *oport;
	struct fnp4l_flow *flow;
	const char *why = NULL;
	unsigned int tae;
	u16 vid, sa;
	int ret;

	ret = fnp4l_ft_parse(port, cls, &cmd, &oport, &xs);
	if (ret)
		return ret;

	flow = kzalloc_obj(*flow);
	if (!flow)
		return -ENOMEM;
	flow->cookie = cls->cookie;
	flow->last_active = jiffies;
	flow->key = cmd.key;
	flow->in_port = port->id;
	flow->out_port = oport->id;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	/* Through a switch port: followed in the FDB of its bridge */
	if (cmd.out_lif <= NP4L_DSA_LIF_LAST &&
	    test_bit(cmd.out_lif, &np->dsa_lifs)) {
		flow->dsa_out_lif = cmd.out_lif;
		ether_addr_copy(flow->h_dest, cmd.h_dest);
	}
#endif

	mutex_lock(&np->sse_lock);
	if (np->sse_state != NP4L_SSE_UP || !test_bit(port->id, &np->ft_ports)) {
		ret = -EOPNOTSUPP;
		goto err;
	}
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	/* Through a port of a switch, while its conduit is bound */
	if (fnp4l_dsa_conduit(oport) &&
	    !test_bit(oport->id, &np->ft_ports)) {
		ret = -EOPNOTSUPP;
		goto err;
	}
	if (fnp4l_dsa_conduit(port) &&
	    fnp4l_dsa_guarded(np, FIELD_GET(NP4L_SSE_KEY_LIF,
					    le16_to_cpu(flow->key.lif)))) {
		ret = fnp4l_ft_refuse(port, cls->common.extack,
				      "LIF of the switch port promiscuous");
		goto err;
	}
#endif
	/*
	 * The engine would forward the flow past the IPsec policies, in the
	 * clear: each direction is judged on its own, the flow table
	 * offloading a flow as soon as one is taken.
	 */
	if (fnp4l_ft_ipsec_admit(np, port->id, oport->id, &cmd, xs, &sa,
				 &why)) {
		ret = fnp4l_ft_refuse(port, cls->common.extack, why);
		goto err;
	}
	if (fnp4l_ft_find(np, cls->cookie)) {
		ret = -EEXIST;
		goto err;
	}
	if (np->ft_nr_flows >= NP4L_FT_MAX_FLOWS) {
		ret = -ENOSPC;
		goto err;
	}

	/*
	 * A tagged frame is looked up in the flow table only if the VLAN
	 * action table has an entry for its VID: add it before the flow.
	 */
	vid = fnp4l_key_vid(&flow->key);
	if (vid) {
		ret = fnp4l_vlan_act_get(port, vid);
		if (ret) {
			netdev_dbg(port->ndev, "no VLAN action entry for VID %u: %d\n",
				   vid, ret);
			goto err;
		}
		flow->vlan_act = true;
	}

	flow->tae = fnp4l_tae_get(np);
	if (flow->tae)
		cmd.acct = cpu_to_le32(NP4L_SSE_ACCT_EN |
				       FIELD_PREP(NP4L_SSE_ACCT_IDX, flow->tae));

	ret = fnp4l_sse_exec(np, &cmd, cmd.hdr.len, NP4L_SSE_INSERTS,
			     NP4L_SSE_INSERTS_OK);
	if (ret == -ENOENT) {
		/*
		 * Table full or entry refused. Should the insertion have
		 * taken after all, an entry the driver does not track would
		 * forward the flow for good: delete the key to be sure.
		 */
		netdev_dbg(port->ndev, "flow engine refused an entry\n");
		ret = fnp4l_sse_delete(np, &flow->key);
		if (!ret || ret == -ENOENT)
			ret = -ENOSPC;
	}
	if (ret) {
		if (ret != -ENOSPC)
			fnp4l_sse_fail(np);
		goto err;
	}

	tae = flow->tae;
	flow->sa_idx = sa;
	fnp4l_ft_link(np, flow);
	if (sa)
		fnp4l_ipsec_ft_chained(np->ipsec);
	mutex_unlock(&np->sse_lock);

	netdev_dbg(port->ndev, "offloaded %u %pI4:%u > %pI4:%u to %s as %pI4:%u > %pI4:%u, actions %02x/%02x, counter %u, IPsec SA %u\n",
		   cmd.key.proto, &cmd.key.saddr, ntohs(cmd.key.sport),
		   &cmd.key.daddr, ntohs(cmd.key.dport),
		   netdev_name(oport->ndev), &cmd.xsaddr, ntohs(cmd.xsport),
		   &cmd.xdaddr, ntohs(cmd.xdport), cmd.act[0], cmd.act[2],
		   tae, sa);

	return 0;

err:
	/* No engine entry uses the counter or VLAN action entry any more. */
	fnp4l_ft_release(np, flow);
	mutex_unlock(&np->sse_lock);
	kfree(flow);
	return ret;
}

/* Called through every bound port: the port that inserted the flow acts. */
static int fnp4l_ft_destroy(struct fnp4l *np, unsigned long cookie)
{
	struct fnp4l_flow *flow;
	int ret = 0;

	mutex_lock(&np->sse_lock);
	flow = fnp4l_ft_find(np, cookie);
	if (!flow) {
		mutex_unlock(&np->sse_lock);
		return -ENOENT;
	}

	fnp4l_ft_unlink(np, flow);
	dev_dbg(np->dev, "removing %u %pI4:%u > %pI4:%u\n", flow->key.proto,
		&flow->key.saddr, ntohs(flow->key.sport), &flow->key.daddr,
		ntohs(flow->key.dport));
	if (np->sse_state == NP4L_SSE_UP) {
		ret = fnp4l_sse_delete(np, &flow->key);
		if (ret == -ENOENT) {
			dev_dbg(np->dev, "flow engine entry already gone\n");
			ret = 0;
		} else if (ret) {
			fnp4l_sse_fail(np);
		}
	}
	fnp4l_ft_release(np, flow);
	mutex_unlock(&np->sse_lock);
	kfree(flow);

	return ret;
}

/*
 * Called through every bound port, whose reports the flow table adds up.
 * Reports the flow as used until one ageing period after the last sign of
 * activity (message of the engine, frames counted), never later than now.
 *
 * Counts, from the port the flow enters through only: the counter entry
 * counts frames without FCS, like the traffic counters; connection
 * tracking counts IP packets (the flow table adds skb->len at the network
 * header). The Ethernet header is taken off, and the 802.1Q tag of a flow
 * that enters tagged, taken to be counted as on the wire. The flow table
 * passes the byte count on as 32 bits: it would wrap past 4 GiB between
 * two requests (more than 30 s at 1 Gbit/s, for requests every 3 s).
 */
static int fnp4l_ft_stats(struct fnp4l_port *port,
			  struct flow_cls_offload *cls)
{
	struct fnp4l *np = port->np;
	unsigned int hlen = ETH_HLEN;
	struct fnp4l_flow *flow;
	u64 packets = 0, bytes = 0;
	unsigned long lastused;

	mutex_lock(&np->sse_lock);
	if (np->sse_state == NP4L_SSE_UP)
		fnp4l_msg_drain(np);
	flow = fnp4l_ft_find(np, cls->cookie);
	if (!flow) {
		mutex_unlock(&np->sse_lock);
		return -ENOENT;
	}
	if (flow->in_port == port->id) {
		fnp4l_tae_read(np, flow, &packets, &bytes);
		if (packets)
			flow->last_active = jiffies;
		if (fnp4l_key_vid(&flow->key))
			hlen = VLAN_ETH_HLEN;
	}
	lastused = flow->last_active + np->sse_age;
	mutex_unlock(&np->sse_lock);

	if (time_after(lastused, jiffies))
		lastused = jiffies;
	bytes -= min(bytes, packets * hlen);
	flow_stats_update(&cls->stats, bytes, packets, 0, lastused,
			  FLOW_ACTION_HW_STATS_DELAYED);

	return 0;
}

static int fnp4l_ft_cb(enum tc_setup_type type, void *type_data,
		       void *cb_priv)
{
	struct fnp4l_port *port = cb_priv;
	struct flow_cls_offload *cls = type_data;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		if (!tc_can_offload(port->ndev))
			return -EOPNOTSUPP;
		return fnp4l_ft_replace(port, cls);
	case FLOW_CLS_DESTROY:
		return fnp4l_ft_destroy(port->np, cls->cookie);
	case FLOW_CLS_STATS:
		return fnp4l_ft_stats(port, cls);
	default:
		return -EOPNOTSUPP;
	}
}

static int fnp4l_ft_bind(struct fnp4l_port *port,
			 struct netlink_ext_ack *extack)
{
	struct fnp4l *np = port->np;
	int ret;

	mutex_lock(&np->sse_lock);
	/* Offloaded through its bond: no flow table of its own */
	if (fnp4l_lag_ports(np) & BIT(port->id)) {
		NL_SET_ERR_MSG_MOD(extack, "port offloaded through a bond");
		ret = -EBUSY;
		goto out;
	}

	switch (np->sse_state) {
	case NP4L_SSE_DOWN:
		ret = fnp4l_sse_start(np);
		if (ret) {
			NL_SET_ERR_MSG_MOD(extack, "cannot start the flow engine");
			goto out;
		}
		break;
	case NP4L_SSE_UP:
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack, "flow engine stopped");
		ret = -EIO;
		goto out;
	}

	ret = fnp4l_lif_rx_action(port, NP4L_RX_ACTION_FLOW);
	if (ret) {
		fnp4l_lif_rx_action(port, NP4L_RX_ACTION_HOST);
		if (fnp4l_ft_idle(np))
			fnp4l_sse_stop(np);
		goto out;
	}
	set_bit(port->id, &np->ft_ports);
out:
	mutex_unlock(&np->sse_lock);

	return ret;
}

/*
 * The flow table no longer reaches the callback of this port: send its
 * frames, tagged ones included, to the host again and delete the entries
 * that go through it.
 */
static void fnp4l_ft_unbind(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	struct fnp4l_flow *flow;
	struct hlist_node *tmp;
	bool failed = false;
	unsigned int bkt;

	mutex_lock(&np->sse_lock);
	/* The ESP of an inbound IPsec SA is looked up in the flow table. */
	if (!(fnp4l_ipsec_ports(np->ipsec) & BIT(port->id)))
		fnp4l_lif_rx_action(port, NP4L_RX_ACTION_HOST);
	fnp4l_vlan_act_clear(port);
	clear_bit(port->id, &np->ft_ports);

	hash_for_each_safe(np->ft_flows, bkt, tmp, flow, node) {
		if (flow->in_port != port->id && flow->out_port != port->id)
			continue;
		if (np->sse_state == NP4L_SSE_UP && !failed) {
			int ret = fnp4l_sse_delete(np, &flow->key);

			failed = ret && ret != -ENOENT;
		}
		fnp4l_ft_unlink(np, flow);
		fnp4l_ft_release(np, flow);
		kfree(flow);
	}
	if (failed)
		fnp4l_sse_fail(np);
	fnp4l_lag_unbind_port(port);

	if (fnp4l_ft_idle(np))
		fnp4l_sse_stop(np);
	mutex_unlock(&np->sse_lock);
}

static LIST_HEAD(fnp4l_block_cb_list);

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/*
 * A user port of the switch leaves the flow table, others stay: the
 * conduit cannot tell which one left (the flow table only passes its
 * block), so delete the engine entries of every flow through the
 * conduit. Their packets go through the host from then on: the flow
 * table keeps them as offloaded, and offers them anew only once they
 * have expired. Neither is anything torn down by the flow table while
 * the port stays up.
 */
static void fnp4l_ft_purge_conduit(struct fnp4l_port *port)
{
	struct fnp4l *np = port->np;
	struct fnp4l_flow *flow;
	struct hlist_node *tmp;
	bool failed = false;
	unsigned int bkt;

	mutex_lock(&np->sse_lock);
	hash_for_each_safe(np->ft_flows, bkt, tmp, flow, node) {
		if (flow->in_port != port->id && flow->out_port != port->id)
			continue;
		if (np->sse_state == NP4L_SSE_UP && !failed) {
			int ret = fnp4l_sse_delete(np, &flow->key);

			failed = ret && ret != -ENOENT;
		}
		fnp4l_ft_unlink(np, flow);
		fnp4l_ft_release(np, flow);
		kfree(flow);
	}
	if (failed)
		fnp4l_sse_fail(np);
	/* And those through it and a bond */
	fnp4l_lag_unbind_port(port);
	mutex_unlock(&np->sse_lock);
}

/*
 * Delete the engine entries of the flows that enter through the LIFs of
 * switch ports @lifs (by LIF number), through a bond or not: see
 * fnp4l_dsa_purge(). Their packets go to the host again. Returns the
 * number of directions deleted. Under sse_lock.
 */
static unsigned int fnp4l_dsa_purge_lifs(struct fnp4l *np,
					 unsigned long lifs)
{
	struct fnp4l_flow *flow;
	struct hlist_node *tmp;
	unsigned int bkt, n = 0;
	bool failed = false;

	lockdep_assert_held(&np->sse_lock);
	hash_for_each_safe(np->ft_flows, bkt, tmp, flow, node) {
		unsigned int lif = FIELD_GET(NP4L_SSE_KEY_LIF,
					     le16_to_cpu(flow->key.lif));

		/* Through the conduit of that LIF (lifs: switch port LIFs) */
		if (lif >= BITS_PER_LONG || !test_bit(lif, &lifs) ||
		    flow->in_port != np->lif_port[lif]->id)
			continue;
		if (np->sse_state == NP4L_SSE_UP && !failed) {
			int ret = fnp4l_sse_delete(np, &flow->key);

			failed = ret && ret != -ENOENT;
		}
		fnp4l_ft_unlink(np, flow);
		fnp4l_ft_release(np, flow);
		kfree(flow);
		n++;
	}
	if (failed)
		fnp4l_sse_fail(np);

	return n + fnp4l_lag_purge_lifs(np, lifs);
}

/*
 * FORTINET_NP4LITE_DSA: a flow table bound to user ports of the switch
 * reaches their conduit, once per user port (dsa_user_setup_ft_block()).
 * The conduit has a single callback per flow table, bound with the first
 * user port and unbound with the last, and takes the flows that enter
 * through any of them (fnp4l_dsa_in()). The LIFs of the switch ports
 * then look frames up in the flow table (fnp4l_dsa_rx_action()).
 */
static int fnp4l_setup_ft_conduit(struct fnp4l_port *port,
				  struct flow_block_offload *f)
{
	flow_setup_cb_t *cb = fnp4l_ft_cb;
	struct flow_block_cb *block_cb;
	int ret;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		block_cb = flow_block_cb_lookup(f->block, cb, port);
		if (block_cb) {
			flow_block_cb_incref(block_cb);
			return 0;
		}
		if (flow_block_cb_is_busy(cb, port, &fnp4l_block_cb_list))
			return -EBUSY;

		ret = fnp4l_ft_bind(port, f->extack);
		if (ret)
			return ret;

		block_cb = flow_block_cb_alloc(cb, port, port, NULL);
		if (IS_ERR(block_cb)) {
			fnp4l_ft_unbind(port);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_incref(block_cb);
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &fnp4l_block_cb_list);
		netdev_dbg(port->ndev, "flow table bound, through the switch ports\n");
		return 0;
	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block, cb, port);
		if (!block_cb)
			return -ENOENT;
		if (flow_block_cb_decref(block_cb)) {
			fnp4l_ft_purge_conduit(port);
			return 0;
		}

		flow_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		fnp4l_ft_unbind(port);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}
#else
static int fnp4l_setup_ft_conduit(struct fnp4l_port *port,
				  struct flow_block_offload *f)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_FORTINET_NP4LITE_DSA */

static int fnp4l_setup_ft(struct fnp4l_port *port,
			  struct flow_block_offload *f)
{
	flow_setup_cb_t *cb = fnp4l_ft_cb;
	struct flow_block_cb *block_cb;
	int ret;

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	f->driver_block_list = &fnp4l_block_cb_list;

	if (port->np->sse_avail && netdev_uses_dsa(port->ndev) &&
	    fnp4l_dsa_offload(port))
		return fnp4l_setup_ft_conduit(port, f);

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		if (!port->np->sse_avail || netdev_uses_dsa(port->ndev)) {
			NL_SET_ERR_MSG_MOD(f->extack,
					   "flow offload not available on this port");
			return -EOPNOTSUPP;
		}
		if (flow_block_cb_is_busy(cb, port, &fnp4l_block_cb_list))
			return -EBUSY;

		ret = fnp4l_ft_bind(port, f->extack);
		if (ret)
			return ret;

		block_cb = flow_block_cb_alloc(cb, port, port, NULL);
		if (IS_ERR(block_cb)) {
			fnp4l_ft_unbind(port);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &fnp4l_block_cb_list);
		return 0;
	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block, cb, port);
		if (!block_cb)
			return -ENOENT;

		flow_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		fnp4l_ft_unbind(port);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int fnp4l_setup_tc(struct net_device *ndev, enum tc_setup_type type,
			  void *type_data)
{
	switch (type) {
	case TC_SETUP_FT:
		return fnp4l_setup_ft(netdev_priv(ndev), type_data);
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef CONFIG_FORTINET_NP4LITE_IPSEC
/*
 * FortiSOC2, for the IPsec offload (np4lite-ipsec.c), which uses the
 * flow engine: it commands the IPsec engine through it, and the ESP of an
 * inbound security association is looked up in its table. The engine
 * runs while there are security associations.
 */
struct fnp4l_ipsec *fnp4l_port_info(const struct net_device *ndev,
				    unsigned int *id)
{
	const struct fnp4l_port *port = netdev_priv(ndev);

	*id = port->id;

	return port->np->ipsec;
}

void fnp4l_sse_lock(struct fnp4l *np)
{
	mutex_lock(&np->sse_lock);
}

void fnp4l_sse_unlock(struct fnp4l *np)
{
	mutex_unlock(&np->sse_lock);
}

/* Start the engine if it is down. Under sse_lock, the HIF running. */
int fnp4l_sse_ready(struct fnp4l *np)
{
	switch (np->sse_state) {
	case NP4L_SSE_DOWN:
		return fnp4l_sse_start(np);
	case NP4L_SSE_UP:
		return 0;
	default:
		return -EIO;
	}
}

/* Stop the engine once nothing uses it. Under sse_lock. */
void fnp4l_sse_idle(struct fnp4l *np)
{
	if (fnp4l_ft_idle(np))
		fnp4l_sse_stop(np);
}

/* After a command failed: see fnp4l_sse_fail(). Under sse_lock. */
void fnp4l_sse_error(struct fnp4l *np)
{
	if (np->sse_state == NP4L_SSE_UP)
		fnp4l_sse_fail(np);
}

/*
 * An IPsec policy has just been offloaded to port @id: delete the flows
 * through it, which the engine would forward past the policy, in the
 * clear. Their packets go to the host again, and the flow table offers
 * them anew, to be refused (fnp4l_ft_replace()). Returns the number of
 * directions deleted, each a flow of the table of its own. Under sse_lock.
 */
unsigned int fnp4l_ft_purge(struct fnp4l *np, unsigned int id)
{
	struct fnp4l_flow *flow;
	struct hlist_node *tmp;
	unsigned int bkt, n = 0;
	bool failed = false;

	lockdep_assert_held(&np->sse_lock);
	hash_for_each_safe(np->ft_flows, bkt, tmp, flow, node) {
		if (flow->in_port != id && flow->out_port != id)
			continue;
		if (np->sse_state == NP4L_SSE_UP && !failed) {
			int ret = fnp4l_sse_delete(np, &flow->key);

			failed = ret && ret != -ENOENT;
		}
		fnp4l_ft_unlink(np, flow);
		fnp4l_ft_release(np, flow);
		kfree(flow);
		n++;
	}
	if (failed)
		fnp4l_sse_fail(np);

	return n + fnp4l_lag_purge(np, id);
}

void fnp4l_sse_assert_held(struct fnp4l *np)
{
	lockdep_assert_held(&np->sse_lock);
}

/*
 * Delete the flows chained to the IPsec engine that @match takes, given
 * the index of their SA and their output port, before the SA leaves the
 * engine or no longer fits them. Their packets go to the host again, and
 * the flow table offers them anew. Returns the number of directions
 * deleted. Under sse_lock.
 */
unsigned int fnp4l_ft_purge_chained(struct fnp4l *np,
				    bool (*match)(void *data, u16 sa,
						     unsigned int out),
				    void *data)
{
	struct fnp4l_flow *flow;
	struct hlist_node *tmp;
	unsigned int bkt, n = 0;
	bool failed = false;

	lockdep_assert_held(&np->sse_lock);
	hash_for_each_safe(np->ft_flows, bkt, tmp, flow, node) {
		if (!flow->sa_idx || !match(data, flow->sa_idx, flow->out_port))
			continue;
		if (np->sse_state == NP4L_SSE_UP && !failed) {
			int ret = fnp4l_sse_delete(np, &flow->key);

			failed = ret && ret != -ENOENT;
		}
		fnp4l_ft_unlink(np, flow);
		fnp4l_ft_release(np, flow);
		kfree(flow);
		n++;
	}
	/* Engine reset: every flow is gone, and every SA out of service. */
	if (failed)
		fnp4l_sse_fail(np);

	return n;
}

/* A command of @words 64-bit words, without counter. Under sse_lock. */
int fnp4l_sse_cmd(struct fnp4l *np, const void *cmd, unsigned int words)
{
	if (np->sse_state != NP4L_SSE_UP)
		return -EIO;

	return fnp4l_sse_exec(np, cmd, words, 0, 0);
}

/*
 * Bytes of the "SPI entry" of an inbound security association: SA index
 * in "sa" and, big endian, in "tci" (where a flow has its 802.1Q tag), output LIF 0xf_ with the high bits
 * of the index, and IPsec bits in the second action byte.
 */
#define NP4L_SSE_ACT1_SPI	(BIT(6) | BIT(5) | BIT(1))
#define NP4L_SSE_SPI_LIF	0xf0
static_assert(offsetof(struct fnp4l_sse_ins, tci) == 48);

/*
 * Insert (@add) or delete the entry that sends the ESP of an inbound
 * security association to the IPsec engine: the flow key of the tunnel
 * as it enters port @id, the SPI in place of the ports.
 * FIXME: the first and third action bytes, the meaning of
 * the bits of the second one and the accounting word are not known (0).
 * Returns -ENOENT when the engine refused it. Under sse_lock.
 */
int fnp4l_sse_spi(struct fnp4l *np, unsigned int id, __be32 saddr,
		  __be32 daddr, __be32 spi, u16 sa, bool add)
{
	struct fnp4l_port *port = np->ports[id];
	struct fnp4l_sse_ins cmd = {};
	struct fnp4l_sse_key *key = &cmd.key;

	if (np->sse_state != NP4L_SSE_UP || !port)
		return -EIO;

	key->saddr = saddr;
	key->daddr = daddr;
	memcpy(&key->ports, &spi, sizeof(spi));
	key->proto = IPPROTO_ESP;
	key->lif = cpu_to_le16(FIELD_PREP(NP4L_SSE_KEY_LIF, port->lif));
	if (!add)
		return fnp4l_sse_delete(np, key);

	cmd.hdr.op = NP4L_SSE_CMD_VALID | NP4L_SSE_OP_INSERT;
	cmd.hdr.len = sizeof(cmd) / 8;
	cmd.act[1] = NP4L_SSE_ACT1_SPI;
	cmd.sa = cpu_to_le16(sa);
	cmd.out_lif = NP4L_SSE_SPI_LIF | sa >> 12;
	cmd.tci = cpu_to_be16(sa);

	return fnp4l_sse_exec(np, &cmd, cmd.hdr.len, NP4L_SSE_INSERTS,
			      NP4L_SSE_INSERTS_OK);
}

/*
 * Frames of port @id to the flow engine while it is bound to a flow
 * table, a bond is, or it has an inbound security association, to the
 * host otherwise. Under sse_lock.
 */
void fnp4l_sse_port_sync(struct fnp4l *np, unsigned int id)
{
	unsigned long ports = np->ft_ports | fnp4l_lag_ports(np) |
			      fnp4l_ipsec_ports(np->ipsec);
	struct fnp4l_port *port = np->ports[id];

	if (np->sse_state != NP4L_SSE_UP || !port)
		return;

	if (fnp4l_lif_rx_action(port, ports & BIT(id) ? NP4L_RX_ACTION_FLOW :
							NP4L_RX_ACTION_HOST))
		netdev_warn(port->ndev, "cannot set the source action of LIF %u\n",
			    port->lif);
}

/*
 * Wait until the NP has read every TX descriptor posted so far: before an
 * SA index is cleared, no frame to send may still carry it. May sleep.
 */
int fnp4l_tx_drain(struct fnp4l *np)
{
	unsigned int t;
	bool empty;
	int ret;

	spin_lock_bh(&np->tx_lock);
	empty = !np->hif_up || np->tx_head == np->tx_tail;
	t = (np->tx_tail - 1) & NP4L_TX_RING_MASK;
	spin_unlock_bh(&np->tx_lock);
	if (empty)
		return 0;

	ret = fnp4l_tx_wait(np, t);
	if (ret)
		dev_err(np->dev, "TX ring not drained: %d\n", ret);

	return ret;
}
#endif /* CONFIG_FORTINET_NP4LITE_IPSEC */

#ifdef CONFIG_FORTINET_NP4LITE_LAG
/*
 * Bonds (bonding driver) of NP ports.
 *
 * A bond is followed while a flow table is bound to it: which ports are
 * its slaves (members), and on which of them it sends and receives
 * (active: link up and, in 802.3ad mode, collecting and distributing; in
 * active-backup mode, the active slave), and to which of those a flow may
 * leave (ready: in 802.3ad mode, the LACP partner collects there too). It
 * is only usable if every slave
 * is a port of this NP that is neither a DSA conduit nor bound to a flow
 * table on its own, in a mode where the bond picks the slave of a packet
 * from the packet alone: active-backup, balance-xor or 802.3ad. With
 * FORTINET_NP4LITE_DSA, every slave may instead be a user port of the
 * switch behind the DSA conduit (never both kinds in one bond).
 *
 * The ends of a flow, and the slaves, are known by their LIF: that of an
 * NP port (its number), or of a switch port (the LIFs of its conduit),
 * whose link is that DSA conduit (np->lif_port[]).
 *
 * The netdev notifier marks a bond whose slaves or their state changed,
 * and a work item reads it again, after a short delay that lets the
 * bonding driver update its own state (it may do so in a work item of its
 * own). Under sse_lock, like the rest of flow offload; the notifier runs
 * under RTNL, which is taken before sse_lock.
 */
struct fnp4l_lag {
	struct list_head node;		/* np->lags */
	struct fnp4l *np;
	/*
	 * The bond, not held: the notifier sees it unregister, and marks
	 * the bond dead before it is freed.
	 */
	struct net_device *dev;
	unsigned long members;		/* LIFs of the slaves, if usable */
	unsigned long active;		/* members sent and received on */
	unsigned long ready;		/* active, the partner collecting */
	bool usable;
	bool dirty;			/* to read again */
	bool pending;			/* active & ~ready: polled */
	bool lacp;			/* 802.3ad: polled slowly */
	u8 polls;			/* fast polls, pending */
	bool dead;
	/*
	 * An 802.1Q device above a bond or a port (FORTINET_NP4LITE_VLAN_BOND),
	 * not followed, not on np->lags: its callback takes no flow.
	 */
	bool vlan;
};

#define NP4L_LAG_DELAY		msecs_to_jiffies(50)
/*
 * Polling of a slave whose partner does not collect yet: every 100 ms for
 * 5 s, then every second, as that of the partners of a ready slave, which
 * may stop collecting with no event (802.3ad bonds, with active slaves).
 */
#define NP4L_LAG_POLL		msecs_to_jiffies(100)
#define NP4L_LAG_FAST_POLLS	50
#define NP4L_LAG_SLOW_POLL	msecs_to_jiffies(1000)

/* LIFs of the ends of a flow through a bond */
#ifdef CONFIG_FORTINET_NP4LITE_DSA
#define NP4L_LAG_LIFS		(NP4L_DSA_LIF_LAST + 1)
#else
#define NP4L_LAG_LIFS		NP4L_NR_PORTS
#endif
static_assert(NP4L_LAG_LIFS <= BITS_PER_LONG);

/* The link of the end @lif: its NP port, or the DSA conduit */
static struct fnp4l_port *fnp4l_lag_link(struct fnp4l *np,
					 unsigned int lif)
{
	return np->lif_port[lif];
}

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/* Whether @lif is the LIF of a switch port */
static bool fnp4l_lag_sw(const struct fnp4l *np, unsigned int lif)
{
	return np->dsa_lif_sw[lif] != NP4L_DSA_NONE;
}

/*
 * Whether the LIFs @lifs are all switch ports behind one conduit: a flow
 * between them would go into and out of one switch through the NP, not
 * tried (as for a port, "output is not another NP port").
 */
static bool fnp4l_lag_one_switch(struct fnp4l *np, unsigned long lifs)
{
	struct fnp4l_port *link = NULL;
	unsigned int lif;

	/* same_switch_offload: two different LIFs, offloaded; one, never */
	if (READ_ONCE(same_switch_offload) && hweight_long(lifs) > 1)
		return false;

	for_each_set_bit(lif, &lifs, NP4L_LAG_LIFS) {
		if (!fnp4l_lag_sw(np, lif))
			return false;
		if (link && fnp4l_lag_link(np, lif) != link)
			return false;
		link = fnp4l_lag_link(np, lif);
	}

	return link;
}
#endif

/*
 * The source address of the frames the engine sends on the end @lif: the
 * address of the port, or the one written in the LIF of a switch port.
 */
static void fnp4l_lag_addr(struct fnp4l *np, unsigned int lif, u8 *addr)
{
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	if (fnp4l_lag_sw(np, lif)) {
		spin_lock_bh(&np->tbl_lock);
		ether_addr_copy(addr, np->dsa_mac[lif]);
		spin_unlock_bh(&np->tbl_lock);
		return;
	}
#endif
	ether_addr_copy(addr, np->lif_port[lif]->ndev->dev_addr);
}

/*
 * The LIF of @dev, a slave of a bond: an NP port neither DSA conduit nor
 * bound on its own, or (FORTINET_NP4LITE_DSA) a switch port; in @sw,
 * whether it is a switch port. -ENODEV otherwise. Under RCU, sse_lock.
 */
static int fnp4l_lag_slave_lif(struct fnp4l *np, struct net_device *dev,
			       bool *sw)
{
	struct fnp4l_port *port = fnp4l_ft_port(np, dev);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	const char *msg = NULL;
	int lif;

	if (!port) {
		lif = fnp4l_dsa_port(np, dev, true, &msg);
		*sw = true;
		return lif <= 0 ? -ENODEV : lif;
	}
#endif
	*sw = false;
	if (!port || netdev_uses_dsa(port->ndev) ||
	    test_bit(port->id, &np->ft_ports))
		return -ENODEV;

	return port->lif;
}

/* The bond @dev, if followed. Under sse_lock. */
static struct fnp4l_lag *fnp4l_lag_find(struct fnp4l *np,
					const struct net_device *dev)
{
	struct fnp4l_lag *lag;

	lockdep_assert_held(&np->sse_lock);
	list_for_each_entry(lag, &np->lags, node)
		if (!lag->dead && lag->dev == dev)
			return lag;

	return NULL;
}

/*
 * Whether the LACP partner of @slave, active in the 802.3ad bond @bond,
 * collects the frames sent there. With coupled control (the default), the
 * bond sends on a slave once the partner is in sync, maybe before it
 * collects: until it does, frames sent there are lost (measured: 2.5 s
 * when a slave comes back). Change of the partner state: no event.
 * Without a partner heard (individual port), as the bond: yes. In the
 * other modes: yes.
 */
static bool fnp4l_lag_collects(struct bonding *bond, struct slave *slave)
{
	const struct port *ad;

	if (BOND_MODE(bond) != BOND_MODE_8023AD)
		return true;

	ad = &SLAVE_AD_INFO(slave)->port;
	if (is_zero_ether_addr(ad->partner_oper.system.mac_addr_value))
		return true;

	return READ_ONCE(ad->partner_oper.port_state) & LACP_STATE_COLLECTING;
}

/*
 * Read the slaves of @lag and their state. Returns whether the bond is
 * usable. Under sse_lock, the bond not dead.
 */
static bool fnp4l_lag_read(struct fnp4l_lag *lag,
			   unsigned long *members, unsigned long *active,
			   unsigned long *ready)
{
	struct bonding *bond = netdev_priv(lag->dev);
	struct fnp4l *np = lag->np;
	unsigned int kinds = 0;
	struct list_head *iter;
	struct slave *slave;
	bool usable, sw;
	int lif;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	struct fnp4l_port *conduit = NULL;
	bool cross = false;
#endif

	lockdep_assert_held(&np->sse_lock);
	*members = 0;
	*active = 0;
	*ready = 0;
	lag->lacp = BOND_MODE(bond) == BOND_MODE_8023AD;
	switch (BOND_MODE(bond)) {
	case BOND_MODE_ACTIVEBACKUP:
	case BOND_MODE_XOR:
	case BOND_MODE_8023AD:
		usable = true;
		break;
	default:
		usable = false;
		break;
	}

	rcu_read_lock();
	bond_for_each_slave_rcu(bond, slave, iter) {
		lif = fnp4l_lag_slave_lif(np, slave->dev, &sw);
		if (lif < 0) {
			usable = false;
			continue;
		}
		kinds |= BIT(sw);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
		/*
		 * Ports of two switches (FortiGate 90D): no trunk between
		 * them, each slave on the link of its switch; the entries of
		 * the flows go by LIF, so the NP does not mind.
		 */
		if (sw) {
			struct fnp4l_port *link = fnp4l_lag_link(np, lif);

			if (conduit && link != conduit)
				cross = true;
			conduit = link;
		}
#endif
		__set_bit(lif, members);
		if (bond_slave_can_tx(slave)) {
			__set_bit(lif, active);
			if (fnp4l_lag_collects(bond, slave))
				__set_bit(lif, ready);
		}
	}
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	/*
	 * But never bridged: a bridge across the two switches (their
	 * cascade) would flood what one slave receives back to the partner
	 * through the other one.
	 */
	if (cross) {
		struct net_device *master =
			netdev_master_upper_dev_get_rcu(lag->dev);

		if (master && netif_is_bridge_master(master))
			usable = false;
	}
#endif
	rcu_read_unlock();

	/* Ports of the NP and of a switch: not one link */
	return usable && *members && kinds != (BIT(0) | BIT(1));
}

/*
 * Take the new slaves of @lag: those that join look frames up in the flow
 * table, as the LIF of a bound port does, those that leave send them all
 * to the host again. Only with the engine running: after an error, or
 * once flow offload is shut down, every LIF sends its frames to the host
 * already. Under sse_lock.
 */
static void fnp4l_lag_set_members(struct fnp4l_lag *lag,
				  unsigned long members,
				  unsigned long active)
{
	unsigned long gone = lag->members & ~members;
	unsigned long added = members & ~lag->members;
	struct fnp4l *np = lag->np;
	struct fnp4l_lag *l;
	bool was_pending = lag->pending;
	unsigned int lif;

	lag->members = members;
	lag->active = active;
	lag->ready &= active;
	lag->pending = !!(active & ~lag->ready);
	if (lag->pending && !was_pending)
		lag->polls = 0;
	np->lag_ports = 0;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	np->lag_lifs = 0;
#endif
	list_for_each_entry(l, &np->lags, node) {
		for_each_set_bit(lif, &l->members, NP4L_LAG_LIFS) {
#ifdef CONFIG_FORTINET_NP4LITE_DSA
			if (fnp4l_lag_sw(np, lif)) {
				__set_bit(lif, &np->lag_lifs);
				continue;
			}
#endif
			__set_bit(fnp4l_lag_link(np, lif)->id, &np->lag_ports);
		}
	}

	if (np->sse_state != NP4L_SSE_UP)
		return;

	for_each_set_bit(lif, &gone, NP4L_LAG_LIFS) {
#ifdef CONFIG_FORTINET_NP4LITE_DSA
		/* Still looked up while its conduit is bound */
		if (fnp4l_lag_sw(np, lif)) {
			if (!test_bit(fnp4l_lag_link(np, lif)->id,
				      &np->ft_ports))
				fnp4l_lif_nr_rx_action(np, lif, NP4L_RX_ACTION_HOST);
			continue;
		}
#endif
		fnp4l_lif_rx_action(fnp4l_lag_link(np, lif), NP4L_RX_ACTION_HOST);
		fnp4l_vlan_act_clear(fnp4l_lag_link(np, lif));
	}
	for_each_set_bit(lif, &added, NP4L_LAG_LIFS) {
#ifdef CONFIG_FORTINET_NP4LITE_DSA
		if (fnp4l_lag_sw(np, lif)) {
			fnp4l_lif_nr_rx_action(np, lif, NP4L_RX_ACTION_FLOW);
			continue;
		}
#endif
		fnp4l_lif_rx_action(fnp4l_lag_link(np, lif), NP4L_RX_ACTION_FLOW);
	}
}

/*
 * Flows through a bond.
 *
 * A flow table bound to a bond stops there (the bonding driver has no
 * ndo_fill_forward_path): the flows it offloads enter or leave through the
 * bond itself. The NP has no link aggregation of its own: an engine entry
 * has one input LIF in its key and one output LIF. So:
 *  - a flow that enters through a bond gets an engine entry per slave the
 *    bond receives on, all alike but for the input LIF: the partner picks
 *    the link of each conversation;
 *  - a flow that leaves through a bond goes out on the slave the bond
 *    would pick for its packets, found once, when the flow is offloaded:
 *    netdev_get_xmit_slave() on a dummy packet with the tuple after
 *    translation, which is what the transmit hash of the bond sees. A flow
 *    then keeps its link between the host and the NP (its first packets,
 *    the TCP segments with FIN or RST).
 * The NP takes the source address from the output LIF: the slaves must
 * carry the address of the bond, as 802.3ad and balance-xor make them do,
 * and active-backup without fail_over_mac.
 *
 * The callback of a bond takes the flows that enter through it, and those that
 * enter through a bound port and leave through it; the callbacks of the ports
 * never see these flows (struct fnp4l_lflow, apart from the flows between
 * ports). A flow is refused, and stays with the host, in the cases the ports
 * refuse, when a bond is not usable (see struct fnp4l_lag), when it enters and
 * leaves through the same bond (unless between two of its VLANs, or with
 * FORTINET_NP4LITE_VLAN_BOND between a VLAN and its untagged traffic), or when
 * the bond has no slave to send or receive on.
 */

/*
 * One direction of a flow through a bond, by the cookie of the flow table.
 * Its engine entries are struct fnp4l_flow, tracked by engine key only
 * (ageing messages), not by cookie.
 */
struct fnp4l_lflow {
	struct hlist_node node;		/* np->lag_flows */
	unsigned long cookie;
	struct fnp4l_lag *owner;	/* the callback that reports it */
	struct fnp4l_lag *in_lag;	/* NULL: enters through in_lif */
	struct fnp4l_lag *out_lag;	/* NULL: leaves through out_lif */
	u8 in_lif;
	u8 out_lif;			/* with out_lag, the slave picked */
	u16 in_vid;			/* 802.1Q tag on input, 0 = none */
	unsigned long last_active;	/* of the entries deleted since */
	/* Insertion, but for the input LIF of the key and the output LIF */
	struct fnp4l_sse_ins cmd;
	struct fnp4l_flow *ent[NP4L_LAG_LIFS];	/* by input LIF */
};

/*
 * The LIFs behind a device of a flow: a port (of the NP or of the switch),
 * or the slaves of a bond
 */
struct fnp4l_lag_end {
	struct net_device *dev;
	struct fnp4l_lag *lag;		/* NULL: a port */
	unsigned long ports;
};

static struct fnp4l_lflow *fnp4l_lag_flow_find(struct fnp4l *np,
					       unsigned long cookie)
{
	struct fnp4l_lflow *lf;

	hash_for_each_possible(np->lag_flows, lf, node, cookie)
		if (lf->cookie == cookie)
			return lf;

	return NULL;
}

/* Errors after which the engine is as it was: the flow stays with the host */
static bool fnp4l_lag_soft(int ret)
{
	return ret == -ENOSPC || ret == -ENOMEM;
}

/*
 * Insert the engine entry @flow of @lf, towards the output LIF of @lf,
 * with the counter of the entry. As in fnp4l_ft_replace(), a refused
 * insertion is followed by a deletion, and gives -ENOSPC. Under sse_lock.
 */
static int fnp4l_lag_ent_insert(struct fnp4l *np,
				struct fnp4l_lflow *lf,
				struct fnp4l_flow *flow)
{
	unsigned int out = fnp4l_lag_link(np, lf->out_lif)->id;
	struct fnp4l_sse_ins cmd = lf->cmd;
	const char *why = NULL;
	u16 sa;
	int ret;

	cmd.key = flow->key;
	/*
	 * As in fnp4l_ft_replace(), never sent to the IPsec engine; soft,
	 * the entry is left out.
	 */
	if (fnp4l_ft_ipsec_admit(np, flow->in_port, out, &cmd, NULL, &sa,
				 &why)) {
		dev_dbg(np->dev, "flow not offloaded: %s\n", why);
		return -ENOSPC;
	}

	cmd.out_lif = lf->out_lif;
	if (flow->tae)
		cmd.acct = cpu_to_le32(NP4L_SSE_ACCT_EN |
				       FIELD_PREP(NP4L_SSE_ACCT_IDX, flow->tae));

	ret = fnp4l_sse_exec(np, &cmd, cmd.hdr.len, NP4L_SSE_INSERTS,
			     NP4L_SSE_INSERTS_OK);
	if (ret == -ENOENT) {
		ret = fnp4l_sse_delete(np, &flow->key);
		if (!ret || ret == -ENOENT)
			ret = -ENOSPC;
	}
	if (!ret)
		flow->out_port = out;

	return ret;
}

/*
 * Add the engine entry of @lf for the frames that enter through LIF @lif:
 * VLAN action entry for its tag, counter if one is free, insertion. Under
 * sse_lock.
 */
static int fnp4l_lag_ent_add(struct fnp4l *np, struct fnp4l_lflow *lf,
			     unsigned int lif)
{
	struct fnp4l_port *port = fnp4l_lag_link(np, lif);
	struct fnp4l_flow *flow;
	int ret;

	if (np->ft_nr_flows >= NP4L_FT_MAX_FLOWS)
		return -ENOSPC;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	/* LIF of a switch port gone promiscuous: see fnp4l_dsa_purge() */
	if (fnp4l_dsa_guarded(np, lif))
		return -ENOSPC;
	/*
	 * Into and out of one switch (a slave of a bond across the two
	 * switches of the 90D): no entry, the frames of this slave go to
	 * the host; those of the others stay offloaded.
	 */
	if (fnp4l_lag_one_switch(np, BIT(lif) | BIT(lf->out_lif)))
		return 0;
#endif
	/* A slave that joined without them */
	if (lf->in_vid &&
	    (!(port->ndev->features & NETIF_F_HW_VLAN_CTAG_RX) ||
	     !port->vlan_act_avail))
		return -ENOSPC;

	flow = kzalloc_obj(*flow);
	if (!flow)
		return -ENOMEM;
	flow->cookie = lf->cookie;
	flow->last_active = jiffies;
	flow->key = lf->cmd.key;
	flow->key.lif = cpu_to_le16(FIELD_PREP(NP4L_SSE_KEY_LIF, lif) |
				    FIELD_PREP(NP4L_SSE_KEY_VID_HI,
					       lf->in_vid >> 8));
	flow->in_port = port->id;

	if (lf->in_vid) {
		ret = fnp4l_vlan_act_get(port, lf->in_vid);
		if (ret) {
			netdev_dbg(port->ndev, "no VLAN action entry for VID %u: %d\n",
				   lf->in_vid, ret);
			ret = -ENOSPC;
			goto err;
		}
		flow->vlan_act = true;
	}

	flow->tae = fnp4l_tae_get(np);
	ret = fnp4l_lag_ent_insert(np, lf, flow);
	if (ret)
		goto err;

	hash_add(np->ft_keys, &flow->key_node, fnp4l_key_hash(&flow->key));
	np->ft_nr_flows++;
	lf->ent[lif] = flow;

	return 0;

err:
	fnp4l_ft_release(np, flow);
	kfree(flow);
	return ret;
}

/*
 * Delete the engine entry of @lf for LIF @lif, with a command if @cmd and
 * the engine runs, and release what it holds; its activity stays with
 * @lf. Returns the error of the command. Under sse_lock.
 */
static int fnp4l_lag_ent_del(struct fnp4l *np, struct fnp4l_lflow *lf,
			     unsigned int lif, bool cmd)
{
	struct fnp4l_flow *flow = lf->ent[lif];
	int ret = 0;

	if (!flow)
		return 0;

	if (cmd && np->sse_state == NP4L_SSE_UP) {
		ret = fnp4l_sse_delete(np, &flow->key);
		if (ret == -ENOENT)
			ret = 0;
	}
	if (time_after(flow->last_active, lf->last_active))
		lf->last_active = flow->last_active;
	lf->ent[lif] = NULL;
	hash_del(&flow->key_node);
	np->ft_nr_flows--;
	fnp4l_ft_release(np, flow);
	kfree(flow);

	return ret;
}

/*
 * Delete @lf and its entries. Once a command has failed (@failed), no
 * other is sent: the caller stops flow offload. Under sse_lock.
 */
static void fnp4l_lag_flow_free(struct fnp4l *np,
				struct fnp4l_lflow *lf, bool *failed)
{
	unsigned int lif;

	for (lif = 0; lif < NP4L_LAG_LIFS; lif++)
		if (fnp4l_lag_ent_del(np, lf, lif, !*failed))
			*failed = true;
	hash_del(&lf->node);
	kfree(lf);
}

/* Forget the flows through bonds, the engine in reset. Under sse_lock. */
static void fnp4l_lag_forget(struct fnp4l *np)
{
	struct fnp4l_lflow *lf;
	struct hlist_node *tmp;
	bool failed = true;
	unsigned int bkt;

	hash_for_each_safe(np->lag_flows, bkt, tmp, lf, node)
		fnp4l_lag_flow_free(np, lf, &failed);
}

/*
 * Delete the flows through @lag or, for NULL, those through port @id
 * without a bond. Returns false after an engine error: flow offload is
 * stopped, and every flow forgotten. Under sse_lock.
 */
static bool fnp4l_lag_drop(struct fnp4l *np,
			   const struct fnp4l_lag *lag, unsigned int id)
{
	struct fnp4l_lflow *lf;
	struct hlist_node *tmp;
	bool failed = false;
	unsigned int bkt;

	hash_for_each_safe(np->lag_flows, bkt, tmp, lf, node) {
		if (lag ? lf->in_lag != lag && lf->out_lag != lag :
		    (lf->in_lag || fnp4l_lag_link(np, lf->in_lif)->id != id) &&
		    (lf->out_lag || fnp4l_lag_link(np, lf->out_lif)->id != id))
			continue;
		fnp4l_lag_flow_free(np, lf, &failed);
	}
	if (failed)
		fnp4l_sse_fail(np);

	return !failed;
}

/* @port is no longer bound: delete the flows through a bond it carries. */
static void fnp4l_lag_unbind_port(struct fnp4l_port *port)
{
	fnp4l_lag_drop(port->np, NULL, port->id);
}

#ifdef CONFIG_FORTINET_NP4LITE_IPSEC
/*
 * Delete the flows through bonds that enter or leave through port @id,
 * for fnp4l_ft_purge(). Returns the number of directions deleted. Under
 * sse_lock.
 */
static unsigned int fnp4l_lag_purge(struct fnp4l *np, unsigned int id)
{
	struct fnp4l_lflow *lf;
	struct hlist_node *tmp;
	unsigned int bkt, n = 0;
	bool failed = false;

	hash_for_each_safe(np->lag_flows, bkt, tmp, lf, node) {
		unsigned int lif;
		bool through = fnp4l_lag_link(np, lf->out_lif)->id == id;

		for (lif = 0; lif < NP4L_LAG_LIFS && !through; lif++)
			through = lf->ent[lif] && lf->ent[lif]->in_port == id;
		if (!through && (lf->in_lag ||
				 fnp4l_lag_link(np, lf->in_lif)->id != id))
			continue;
		fnp4l_lag_flow_free(np, lf, &failed);
		n++;
	}
	if (failed)
		fnp4l_sse_fail(np);

	return n;
}
#endif

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/*
 * Delete the flows through bonds with an engine entry on one of the LIFs
 * @lifs (by LIF number), for fnp4l_dsa_purge_lifs(). Returns the number
 * of directions deleted. Under sse_lock.
 */
static unsigned int fnp4l_lag_purge_lifs(struct fnp4l *np,
					 unsigned long lifs)
{
	struct fnp4l_lflow *lf;
	struct hlist_node *tmp;
	unsigned int bkt, n = 0;
	bool failed = false;

	hash_for_each_safe(np->lag_flows, bkt, tmp, lf, node) {
		unsigned int lif;
		bool in = false;

		for_each_set_bit(lif, &lifs, NP4L_LAG_LIFS)
			in |= !!lf->ent[lif];
		if (!in)
			continue;
		fnp4l_lag_flow_free(np, lf, &failed);
		n++;
	}
	if (failed)
		fnp4l_sse_fail(np);

	return n;
}
#endif

/*
 * Resolve @dev, a device of a flow, into a bound and usable bond, or a
 * port that is neither DSA conduit nor slave; with FORTINET_NP4LITE_DSA, a
 * user port of the switch while the conduit is bound, neither bridged nor
 * enslaved. Under sse_lock.
 */
static bool fnp4l_lag_end(struct fnp4l *np, struct net_device *dev,
			  struct fnp4l_lag_end *end)
{
	struct fnp4l_port *port;

	end->dev = dev;
	end->lag = fnp4l_lag_find(np, dev);
	if (end->lag) {
		end->ports = end->lag->members;
		return end->lag->usable && end->ports;
	}

	port = fnp4l_ft_port(np, dev);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	if (!port) {
		const char *msg = NULL;
		int lif;

		rcu_read_lock();
		lif = fnp4l_dsa_port(np, dev, false, &msg);
		rcu_read_unlock();
		if (lif <= 0 ||
		    !test_bit(fnp4l_lag_link(np, lif)->id, &np->ft_ports))
			return false;
		if (fnp4l_dsa_lif_out(np, lif)) {
			u8 buf[ETH_ALEN];

			fnp4l_dsa_mac_sync(np, lif,
					   fnp4l_dsa_addr(np, dev, buf));
		}
		end->ports = BIT(lif);
		return true;
	}
#endif
	if (!port || netdev_uses_dsa(dev) || netif_is_bond_slave(dev))
		return false;
	end->ports = BIT(port->lif);

	return true;
}

/* The bound port whose net_device has index @ifindex */
static struct fnp4l_port *fnp4l_lag_ifport(struct fnp4l *np,
					   int ifindex)
{
	unsigned int id;

	for_each_set_bit(id, &np->ft_ports, NP4L_NR_PORTS)
		if (np->ports[id]->ndev->ifindex == ifindex)
			return np->ports[id];

	return NULL;
}

/*
 * The slave of the output bond of @lf its packets would go out on: a
 * dummy packet as the NP sends it (addresses and ports after translation,
 * MAC header, 802.1Q tag in the metadata, as the bond gets it from a VLAN
 * device), through netdev_get_xmit_slave(). The slave must be active and
 * carry the address of the bond, and its LACP partner collect there: if
 * it does not yet, and @hold, the slave @lf leaves through now, if its
 * partner collects, until the next reading of the bond. Returns
 * the LIF, or -ENOENT. Under sse_lock.
 */
static int fnp4l_lag_pick(struct fnp4l *np,
			  const struct fnp4l_lflow *lf, bool hold)
{
	const struct fnp4l_sse_ins *cmd = &lf->cmd;
	struct net_device *bdev = lf->out_lag->dev;
	struct net_device *slave;
	unsigned int l4len;
	int lif = -ENOENT;
	bool sw;
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct iphdr *iph;
	int ret = -ENOENT;

	l4len = cmd->key.proto == IPPROTO_TCP ? sizeof(struct tcphdr) :
						sizeof(struct udphdr);
	skb = alloc_skb(ETH_HLEN + sizeof(*iph) + l4len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	eth = skb_put_zero(skb, ETH_HLEN);
	memcpy(eth->h_dest, cmd->h_dest, ETH_ALEN);
	memcpy(eth->h_source, bdev->dev_addr, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	skb_reset_mac_header(skb);

	iph = skb_put_zero(skb, sizeof(*iph));
	iph->version = 4;
	iph->ihl = sizeof(*iph) / 4;
	iph->ttl = 64;
	iph->tot_len = htons(sizeof(*iph) + l4len);
	iph->protocol = cmd->key.proto;
	iph->saddr = cmd->xsaddr;
	iph->daddr = cmd->xdaddr;
	skb_set_network_header(skb, ETH_HLEN);

	if (cmd->key.proto == IPPROTO_TCP) {
		struct tcphdr *th = skb_put_zero(skb, sizeof(*th));

		th->source = cmd->xsport;
		th->dest = cmd->xdport;
		th->doff = sizeof(*th) / 4;
		th->ack = 1;
	} else {
		struct udphdr *uh = skb_put_zero(skb, sizeof(*uh));

		uh->source = cmd->xsport;
		uh->dest = cmd->xdport;
		uh->len = htons(sizeof(*uh));
	}
	skb_set_transport_header(skb, ETH_HLEN + sizeof(*iph));
	skb->protocol = htons(ETH_P_IP);
	skb->dev = bdev;
	if (cmd->tci)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       be16_to_cpu(cmd->tci));

	rcu_read_lock();
	slave = netdev_get_xmit_slave(bdev, skb, false);
	if (slave)
		lif = fnp4l_lag_slave_lif(np, slave, &sw);
	if (lif >= 0 && test_bit(lif, &lf->out_lag->active) &&
	    ether_addr_equal(slave->dev_addr, bdev->dev_addr)) {
		if (test_bit(lif, &lf->out_lag->ready)) {
			ret = lif;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
			/* The notifier does; to be sure before an entry uses it */
			if (sw)
				fnp4l_dsa_mac_sync(np, lif, slave->dev_addr);
#endif
		} else if (hold && test_bit(lf->out_lif, &lf->out_lag->ready)) {
			/* Its partner does not collect yet: stay. */
			ret = lf->out_lif;
		}
	}
	rcu_read_unlock();
	consume_skb(skb);

	return ret;
}

static int fnp4l_lag_refuse(const struct fnp4l_lag *lag,
			    struct netlink_ext_ack *extack, const char *msg)
{
	NL_SET_ERR_MSG_FMT_MOD(extack, "%s", msg);
	netdev_dbg(lag->dev, "flow not offloaded: %s\n", msg);

	return -EOPNOTSUPP;
}

/*
 * Build @lf from a flow of the table of @lag, as fnp4l_ft_parse() does
 * for a port, either end being a port or a bond: the checks on a port of
 * that function hold for every slave. Returns -ENOENT for a flow that is
 * not for this callback. Under sse_lock.
 */
static int fnp4l_lag_parse(struct fnp4l_lag *lag,
			   struct flow_cls_offload *cls,
			   struct fnp4l_lflow *lf)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct netlink_ext_ack *extack = cls->common.extack;
	struct fnp4l_sse_ins *cmd = &lf->cmd;
	const struct flow_action_entry *act;
	struct flow_match_ipv4_addrs addrs;
	struct flow_match_control control;
	struct fnp4l *np = lag->np;
	struct fnp4l_lag_end in, out;
	struct flow_match_ports ports;
	struct flow_match_basic basic;
	struct flow_match_meta meta;
	struct net_device *odev = NULL;
	u8 eth[2 * ETH_ALEN] = {};
	u8 ip[NP4L_FT_IP_LEN] = {};
	u16 in_vid = 0, out_tci = 0;
	struct fnp4l_port *port;
	struct net_device *vdev;
	const char *msg = NULL;
	unsigned int mtu, id;
	u8 addr[ETH_ALEN];
	bool pop = false;
	__be16 l4[2];
	u64 used;
	int ret, i;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META))
		return -EOPNOTSUPP;
	flow_rule_match_meta(rule, &meta);
	flow_action_for_each(i, act, &rule->action) {
		if (act->id != FLOW_ACTION_REDIRECT)
			continue;
		if (odev)
			return -EOPNOTSUPP;
		odev = act->dev;
	}

	/* Through this bond, or from a bound port to it */
	if (meta.key->ingress_ifindex == lag->dev->ifindex) {
		if (!fnp4l_lag_end(np, lag->dev, &in))
			return fnp4l_lag_refuse(lag, extack,
						"bond not offloaded");
	} else {
		port = fnp4l_lag_ifport(np, meta.key->ingress_ifindex);
		in.ports = port ? BIT(port->lif) : 0;
#ifdef CONFIG_FORTINET_NP4LITE_DSA
		/* Or a user port of the bound conduit, on its LIF */
		if (!port && odev == lag->dev) {
			u32 lif;

			port = fnp4l_dsa_in(np, dev_net(lag->dev),
					    meta.key->ingress_ifindex, &lif,
					    &msg);
			if (msg)
				return fnp4l_lag_refuse(lag, extack, msg);
			in.ports = BIT(lif);
		}
#endif
		if (!port || odev != lag->dev)
			return -ENOENT;
		in.dev = port->ndev;
		in.lag = NULL;
	}

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC))
		return fnp4l_lag_refuse(lag, extack, "not IPv4");
	flow_rule_match_control(rule, &control);
	flow_rule_match_basic(rule, &basic);
	if (control.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS ||
	    basic.key->n_proto != htons(ETH_P_IP))
		return fnp4l_lag_refuse(lag, extack, "not IPv4");

	used = rule->match.dissector->used_keys;
	if (used & BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN))
		return fnp4l_lag_refuse(lag, extack, "stacked VLAN tags");
	if (used & NP4L_FT_ENC_KEYS)
		return fnp4l_lag_refuse(lag, extack, "tunnel");
	if (used & ~NP4L_FT_KEYS)
		return fnp4l_lag_refuse(lag, extack, "unsupported match");

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS))
		return fnp4l_lag_refuse(lag, extack, "not IPv4 TCP or UDP");

	if (flow_rule_has_control_flags(control.mask->flags, extack))
		return fnp4l_lag_refuse(lag, extack, "not IPv4");

	if (basic.key->ip_proto != IPPROTO_TCP &&
	    basic.key->ip_proto != IPPROTO_UDP)
		return fnp4l_lag_refuse(lag, extack, "not IPv4 TCP or UDP");

	/* One 802.1Q tag on input, extracted by every input port */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan vlan;

		flow_rule_match_vlan(rule, &vlan);
		if (vlan.key->vlan_tpid != htons(ETH_P_8021Q))
			return fnp4l_lag_refuse(lag, extack,
						"input VLAN not 802.1Q");
		if (vlan.mask->vlan_id != VLAN_VID_MASK ||
		    vlan.mask->vlan_priority || vlan.mask->vlan_dei ||
		    vlan.mask->vlan_eth_type || !vlan.key->vlan_id)
			return fnp4l_lag_refuse(lag, extack,
						"unsupported input VLAN");
		for_each_set_bit(id, &in.ports, NP4L_LAG_LIFS) {
			port = fnp4l_lag_link(np, id);
			if (!(port->ndev->features & NETIF_F_HW_VLAN_CTAG_RX) ||
			    !port->vlan_act_avail)
				return fnp4l_lag_refuse(lag, extack,
							"unsupported input VLAN");
		}
		in_vid = vlan.key->vlan_id;
	}

	/*
	 * As for a port: the upper devices of a slave include the bond's
	 * (those of the conduit, of every port of the switch).
	 */
	rcu_read_lock();
	for_each_set_bit(id, &in.ports, NP4L_LAG_LIFS)
		if (netdev_walk_all_upper_dev_rcu(fnp4l_lag_link(np, id)->ndev,
						  fnp4l_upper_is_8021ad,
						  NULL))
			msg = "802.1ad VLAN on the input";
	if (!msg && in_vid &&
	    !__vlan_find_dev_deep_rcu(in.dev, htons(ETH_P_8021Q), in_vid))
		msg = "no 802.1Q device for the input VLAN";
	rcu_read_unlock();
	if (msg)
		return fnp4l_lag_refuse(lag, extack, msg);

	for_each_set_bit(id, &in.ports, NP4L_LAG_LIFS)
		if (!tc_can_offload(fnp4l_lag_link(np, id)->ndev))
			return fnp4l_lag_refuse(lag, extack,
						"hw-tc-offload off on an input port");

	flow_rule_match_ipv4_addrs(rule, &addrs);
	flow_rule_match_ports(rule, &ports);

	memcpy(ip + NP4L_FT_IP_SADDR, &addrs.key->src, 4);
	memcpy(ip + NP4L_FT_IP_DADDR, &addrs.key->dst, 4);
	l4[0] = ports.key->src;
	l4[1] = ports.key->dst;

	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			switch (act->mangle.htype) {
			case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
				ret = fnp4l_ft_mangle(eth, sizeof(eth), act);
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
				ret = act->mangle.offset < NP4L_FT_IP_SADDR ? -EOPNOTSUPP :
				      fnp4l_ft_mangle(ip, sizeof(ip), act);
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
			case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
				ret = fnp4l_ft_mangle((u8 *)l4, sizeof(l4),
						      act);
				break;
			default:
				ret = -EOPNOTSUPP;
			}
			if (ret)
				return fnp4l_lag_refuse(lag, extack,
							"unsupported rewrite");
			break;
		case FLOW_ACTION_CSUM:
		case FLOW_ACTION_REDIRECT:
			break;
		case FLOW_ACTION_VLAN_POP:
			if (pop)
				return fnp4l_lag_refuse(lag, extack,
							"stacked VLAN tags");
			pop = true;
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (out_tci)
				return fnp4l_lag_refuse(lag, extack,
							"stacked VLAN tags");
			if (act->vlan.proto != htons(ETH_P_8021Q))
				return fnp4l_lag_refuse(lag, extack,
							"output VLAN not 802.1Q");
			if (!act->vlan.vid || act->vlan.vid >= VLAN_VID_MASK)
				return fnp4l_lag_refuse(lag, extack,
							"unsupported output VLAN");
			out_tci = act->vlan.vid |
				  (u16)act->vlan.prio << VLAN_PRIO_SHIFT;
			break;
		default:
			return fnp4l_lag_refuse(lag, extack,
						"unsupported action");
		}
	}

	if (!odev || !fnp4l_lag_end(np, odev, &out))
		return fnp4l_lag_refuse(lag, extack,
					"output is not an NP port or bond");
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	for_each_set_bit(id, &out.ports, NP4L_LAG_LIFS)
		if (fnp4l_lag_sw(np, id) &&
		    !fnp4l_dsa_lif_out(np, id))
			return fnp4l_lag_refuse(lag, extack,
						"output through the switch ports not enabled");
	/*
	 * Between two ports of one switch: not tried, as for a port. Between
	 * the two switches of the FortiGate 90D, through two conduits, as for
	 * a port (measured: 926-935 Mbit/s routed between internal3 and
	 * internal10).
	 */
	if (fnp4l_lag_one_switch(np, in.ports | out.ports))
		return fnp4l_lag_refuse(lag, extack,
					"input and output through one switch");
#endif
	/*
	 * Between two VLANs of the same bond ("router on a stick"), the only
	 * way to gain from the bond when its slaves are the only ports out of
	 * the switch (FortiGate 60D): an entry may then send frames out through
	 * the LIF they came in by. With FORTINET_NP4LITE_VLAN_BOND, between a
	 * VLAN and the untagged traffic of the bond too: the VID in the key (0
	 * untagged) still tells the two directions apart. Refused on a port, as
	 * before.
	 */
	if (out.dev == in.dev &&
	    (!in.lag || in_vid == (out_tci & VLAN_VID_MASK) ||
	     (!IS_ENABLED(CONFIG_FORTINET_NP4LITE_VLAN_BOND) &&
	      (!in_vid || !out_tci))))
		return fnp4l_lag_refuse(lag, extack,
					"output is the input");

	/* The engine takes the source MAC address from the output LIF. */
	if (!is_valid_ether_addr(eth) ||
	    !ether_addr_equal(eth + ETH_ALEN, out.dev->dev_addr))
		return fnp4l_lag_refuse(lag, extack,
					"unsupported MAC header");
	for_each_set_bit(id, &out.ports, NP4L_LAG_LIFS) {
		fnp4l_lag_addr(np, id, addr);
		if (!ether_addr_equal(addr, out.dev->dev_addr))
			return fnp4l_lag_refuse(lag, extack,
						"slave address not the one of the bond");
	}

	if (pop != !!in_vid)
		return fnp4l_lag_refuse(lag, extack,
					"unsupported input VLAN");

	mtu = READ_ONCE(out.dev->mtu);
	if (out_tci) {
		for_each_set_bit(id, &out.ports, NP4L_LAG_LIFS)
			if (!(fnp4l_lag_link(np, id)->ndev->features &
			      NETIF_F_HW_VLAN_CTAG_TX))
				return fnp4l_lag_refuse(lag, extack,
							"unsupported output VLAN");
		rcu_read_lock();
		vdev = __vlan_find_dev_deep_rcu(out.dev, htons(ETH_P_8021Q),
						out_tci & VLAN_VID_MASK);
		if (vdev)
			mtu = min(mtu, READ_ONCE(vdev->mtu));
		rcu_read_unlock();
	}
	if (mtu < ETH_DATA_LEN)
		return fnp4l_lag_refuse(lag, extack,
					"output MTU below 1500");

	memset(cmd, 0, sizeof(*cmd));
	cmd->hdr.op = NP4L_SSE_CMD_VALID | NP4L_SSE_OP_INSERT;
	cmd->hdr.len = sizeof(*cmd) / 8;
	cmd->key.saddr = addrs.key->src;
	cmd->key.daddr = addrs.key->dst;
	cmd->key.sport = ports.key->src;
	cmd->key.dport = ports.key->dst;
	cmd->key.proto = basic.key->ip_proto;
	cmd->key.vid_lo = in_vid & 0xff;
	cmd->mtu = cpu_to_le16(mtu);
	cmd->tci = cpu_to_be16(out_tci);
	memcpy(cmd->h_dest, eth, ETH_ALEN);
	memcpy(&cmd->xsaddr, ip + NP4L_FT_IP_SADDR, 4);
	memcpy(&cmd->xdaddr, ip + NP4L_FT_IP_DADDR, 4);
	cmd->xsport = l4[0];
	cmd->xdport = l4[1];
	cmd->act[0] = NP4L_SSE_ACT_ROUTED;
	if (out_tci)
		cmd->act[0] |= NP4L_SSE_ACT_VLAN;
	if (cmd->xsaddr != cmd->key.saddr)
		cmd->act[0] |= NP4L_SSE_ACT_SNAT;
	if (cmd->xdaddr != cmd->key.daddr)
		cmd->act[0] |= NP4L_SSE_ACT_DNAT;
	if (cmd->xsport != cmd->key.sport)
		cmd->act[2] |= NP4L_SSE_ACT_SPAT;
	if (cmd->xdport != cmd->key.dport)
		cmd->act[2] |= NP4L_SSE_ACT_DPAT;

	lf->in_vid = in_vid;
	lf->in_lag = in.lag;
	lf->in_lif = in.lag ? 0 : __ffs(in.ports);
	lf->out_lag = out.lag;
	if (!out.lag) {
		lf->out_lif = __ffs(out.ports);
		return 0;
	}

	ret = fnp4l_lag_pick(np, lf, false);
	if (ret == -ENOMEM)
		return ret;
	if (ret < 0)
		return fnp4l_lag_refuse(lag, extack,
					"no slave of the output bond to send on");
	lf->out_lif = ret;

	return 0;
}

static int fnp4l_lag_replace(struct fnp4l_lag *lag,
			     struct flow_cls_offload *cls)
{
	struct fnp4l *np = lag->np;
	struct fnp4l_lflow *lf;
	unsigned long ports = 0;
	bool failed = false;
	unsigned int id;
	int ret;

	lf = kzalloc_obj(*lf);
	if (!lf)
		return -ENOMEM;
	lf->cookie = cls->cookie;
	lf->owner = lag;
	lf->last_active = jiffies;

	mutex_lock(&np->sse_lock);
	if (lag->dead || np->sse_state != NP4L_SSE_UP) {
		ret = -EOPNOTSUPP;
		goto out_free;
	}
	ret = fnp4l_lag_parse(lag, cls, lf);
	if (ret)
		goto out_free;
	if (fnp4l_lag_flow_find(np, lf->cookie)) {
		ret = -EEXIST;
		goto out_free;
	}
	if (np->ft_nr_flows >= NP4L_FT_MAX_FLOWS) {
		ret = -ENOSPC;
		goto out_free;
	}

	ports = lf->in_lag ? lf->in_lag->active : BIT(lf->in_lif);
	if (!ports) {
		ret = fnp4l_lag_refuse(lag, cls->common.extack,
				       "no slave of the input bond to receive on");
		goto out_free;
	}

	hash_add(np->lag_flows, &lf->node, lf->cookie);
	for_each_set_bit(id, &ports, NP4L_LAG_LIFS) {
		ret = fnp4l_lag_ent_add(np, lf, id);
		if (ret)
			break;
	}
	if (ret) {
		/* After an engine error, no command: it is reset. */
		failed = !fnp4l_lag_soft(ret);
		fnp4l_lag_flow_free(np, lf, &failed);
		if (failed)
			fnp4l_sse_fail(np);
		mutex_unlock(&np->sse_lock);
		return ret;
	}

	netdev_dbg(lag->dev, "offloaded %u %pI4:%u > %pI4:%u as %pI4:%u > %pI4:%u, input LIFs %#lx, output LIF %u, actions %02x/%02x\n",
		   lf->cmd.key.proto, &lf->cmd.key.saddr,
		   ntohs(lf->cmd.key.sport), &lf->cmd.key.daddr,
		   ntohs(lf->cmd.key.dport), &lf->cmd.xsaddr,
		   ntohs(lf->cmd.xsport), &lf->cmd.xdaddr,
		   ntohs(lf->cmd.xdport), ports, lf->out_lif,
		   lf->cmd.act[0], lf->cmd.act[2]);
	mutex_unlock(&np->sse_lock);

	return 0;

out_free:
	mutex_unlock(&np->sse_lock);
	kfree(lf);
	return ret;
}

/* Called through every bound bond and port: the owner acts. */
static int fnp4l_lag_destroy(struct fnp4l_lag *lag, unsigned long cookie)
{
	struct fnp4l *np = lag->np;
	struct fnp4l_lflow *lf;
	bool failed = false;

	mutex_lock(&np->sse_lock);
	lf = fnp4l_lag_flow_find(np, cookie);
	if (!lf || lf->owner != lag) {
		mutex_unlock(&np->sse_lock);
		return -ENOENT;
	}

	dev_dbg(np->dev, "removing %u %pI4:%u > %pI4:%u\n", lf->cmd.key.proto,
		&lf->cmd.key.saddr, ntohs(lf->cmd.key.sport),
		&lf->cmd.key.daddr, ntohs(lf->cmd.key.dport));
	fnp4l_lag_flow_free(np, lf, &failed);
	if (failed)
		fnp4l_sse_fail(np);
	mutex_unlock(&np->sse_lock);

	return failed ? -EIO : 0;
}

/*
 * As fnp4l_ft_stats(), from the owner only, adding up the entries of
 * the flow: the latest activity of any of them, and their counters.
 */
static int fnp4l_lag_stats(struct fnp4l_lag *lag,
			   struct flow_cls_offload *cls)
{
	struct fnp4l *np = lag->np;
	u64 packets = 0, bytes = 0, p, b;
	unsigned int hlen = ETH_HLEN, id;
	struct fnp4l_lflow *lf;
	unsigned long lastused;

	mutex_lock(&np->sse_lock);
	if (np->sse_state == NP4L_SSE_UP)
		fnp4l_msg_drain(np);
	lf = fnp4l_lag_flow_find(np, cls->cookie);
	if (!lf || lf->owner != lag) {
		mutex_unlock(&np->sse_lock);
		return -ENOENT;
	}

	lastused = lf->last_active;
	for (id = 0; id < NP4L_LAG_LIFS; id++) {
		struct fnp4l_flow *flow = lf->ent[id];

		if (!flow)
			continue;
		fnp4l_tae_read(np, flow, &p, &b);
		if (p)
			flow->last_active = jiffies;
		packets += p;
		bytes += b;
		if (time_after(flow->last_active, lastused))
			lastused = flow->last_active;
	}
	if (lf->in_vid)
		hlen = VLAN_ETH_HLEN;
	lastused += np->sse_age;
	mutex_unlock(&np->sse_lock);

	if (time_after(lastused, jiffies))
		lastused = jiffies;
	bytes -= min(bytes, packets * hlen);
	flow_stats_update(&cls->stats, bytes, packets, 0, lastused,
			  FLOW_ACTION_HW_STATS_DELAYED);

	return 0;
}

/*
 * Follow a change of the bonds of @lf: entries for the slaves its input
 * bond now receives on, and only those; a new pick of the output slave,
 * and the entries steered there (deleted and inserted again, keeping
 * their counters). Returns 0, or an error: the caller deletes the flow,
 * which goes back to the host until the flow table offloads it again,
 * and stops flow offload if @failed is set. Under sse_lock.
 */
static int fnp4l_lag_steer(struct fnp4l *np, struct fnp4l_lflow *lf,
			   bool *failed)
{
	unsigned long want, have = 0;
	struct fnp4l_flow *flow;
	unsigned int id;
	int out, ret;

	for (id = 0; id < NP4L_LAG_LIFS; id++)
		if (lf->ent[id])
			__set_bit(id, &have);
	want = lf->in_lag ? lf->in_lag->active : BIT(lf->in_lif);
	if (!want)
		return -ENOENT;

	out = lf->out_lif;
	if (lf->out_lag) {
		out = fnp4l_lag_pick(np, lf, true);
		if (out < 0)
			return out;
	}

	for_each_set_bit(id, &have, NP4L_LAG_LIFS) {
		if (test_bit(id, &want))
			continue;
		ret = fnp4l_lag_ent_del(np, lf, id, true);
		if (ret) {
			*failed = true;
			return ret;
		}
		__clear_bit(id, &have);
	}

	if (out != lf->out_lif) {
		lf->out_lif = out;
		for_each_set_bit(id, &have, NP4L_LAG_LIFS) {
			flow = lf->ent[id];
			ret = fnp4l_sse_delete(np, &flow->key);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
			/* Now into and out of one switch: see ent_add() */
			if ((!ret || ret == -ENOENT) &&
			    fnp4l_lag_one_switch(np, BIT(id) | BIT(out))) {
				fnp4l_lag_ent_del(np, lf, id, false);
				continue;
			}
#endif
			if (!ret || ret == -ENOENT)
				ret = fnp4l_lag_ent_insert(np, lf, flow);
			if (ret) {
				/* Not in the engine any more */
				fnp4l_lag_ent_del(np, lf, id, false);
				*failed = !fnp4l_lag_soft(ret);
				return ret;
			}
		}
	}

	for_each_set_bit(id, &want, NP4L_LAG_LIFS) {
		if (lf->ent[id])
			continue;
		ret = fnp4l_lag_ent_add(np, lf, id);
		if (ret) {
			*failed = !fnp4l_lag_soft(ret);
			return ret;
		}
	}

	return 0;
}

/*
 * Read @lag again, and follow the change with its flows: those that
 * cannot follow go back to the host. @poll: only if a slave became ready
 * or anything else changed. Under sse_lock, the bond not dead.
 */
static void fnp4l_lag_sync(struct fnp4l_lag *lag, bool poll)
{
	unsigned long members, active, ready;
	struct fnp4l *np = lag->np;
	struct fnp4l_lflow *lf;
	struct hlist_node *tmp;
	bool failed = false;
	unsigned int bkt;
	int ret;

	lag->usable = fnp4l_lag_read(lag, &members, &active, &ready);
	if (!lag->usable) {
		members = 0;
		active = 0;
		ready = 0;
	}
	if (members != lag->members || active != lag->active ||
	    ready != lag->ready)
		netdev_dbg(lag->dev, "LIFs %#lx, active %#lx, ready %#lx%s\n",
			   members, active, ready,
			   lag->usable ? "" : ", not offloaded");
	else if (poll)
		return;
	lag->ready = ready;
	/* New slaves look frames up before their entries go in. */
	fnp4l_lag_set_members(lag, members, active);
	if (np->sse_state != NP4L_SSE_UP)
		return;

	hash_for_each_safe(np->lag_flows, bkt, tmp, lf, node) {
		if (lf->in_lag != lag && lf->out_lag != lag)
			continue;
		ret = lag->usable ? fnp4l_lag_steer(np, lf, &failed) :
				    -ENOENT;
		if (ret && !failed) {
			netdev_dbg(lag->dev, "flow %u %pI4:%u > %pI4:%u back to the host: %d\n",
				   lf->cmd.key.proto, &lf->cmd.key.saddr,
				   ntohs(lf->cmd.key.sport), &lf->cmd.key.daddr,
				   ntohs(lf->cmd.key.dport), ret);
			fnp4l_lag_flow_free(np, lf, &failed);
		}
		if (failed)
			break;
	}
	if (failed)
		fnp4l_sse_fail(np);
}

/* The bond is going away: forget its slaves. Under sse_lock. */
static void fnp4l_lag_kill(struct fnp4l_lag *lag)
{
	lag->dead = true;
	lag->usable = false;
	fnp4l_lag_drop(lag->np, lag, 0);
	fnp4l_lag_set_members(lag, 0, 0);
}

static void fnp4l_lag_work(struct work_struct *work)
{
	struct fnp4l *np = container_of(to_delayed_work(work),
					struct fnp4l, lag_work);
	struct fnp4l_lag *lag;
	bool fast = false, slow = false;

	mutex_lock(&np->sse_lock);
	list_for_each_entry(lag, &np->lags, node) {
		if (lag->dead)
			continue;
		if (lag->dirty) {
			lag->dirty = false;
			fnp4l_lag_sync(lag, false);
		} else if (lag->pending || (lag->lacp && lag->active)) {
			fnp4l_lag_sync(lag, true);
		}
		if (lag->pending && lag->polls < NP4L_LAG_FAST_POLLS) {
			lag->polls++;
			fast = true;
		} else if (lag->pending || (lag->lacp && lag->active)) {
			slow = true;
		}
	}
	mutex_unlock(&np->sse_lock);

	/* The state of an LACP partner changes with no event: poll it. */
	if (fast || slow)
		queue_delayed_work(system_wq, &np->lag_work,
				   fast ? NP4L_LAG_POLL : NP4L_LAG_SLOW_POLL);
}

/*
 * A followed bond changed: slave added or removed (CHANGEUPPER), state of
 * a slave (CHANGELOWERSTATE), options (CHANGEINFODATA), failover, address,
 * or the bond goes away.
 *
 * The bond refreshes its transmit slave array at NETDEV_DOWN and
 * NETDEV_CHANGE of a slave, but reports CHANGELOWERSTATE only at its next
 * miimon pass. Offloaded flows kept going out to the lost port for
 * 100-170 ms (measured), while host-routed traffic lost nearly nothing:
 * read the bond again at once, without the delay that gathers the other
 * events.
 */
static int fnp4l_lag_event(struct notifier_block *nb, unsigned long event,
			   void *ptr)
{
	struct fnp4l *np = container_of(nb, struct fnp4l, lag_nb);
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_notifier_changeupper_info *info;
	struct net_device *upper;
	struct fnp4l_lag *lag;
	bool kick = false;
	bool now = false;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		info = ptr;
		upper = info->upper_dev;
		break;
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
		if (netif_is_bond_master(dev))
			return NOTIFY_DONE;
		upper = netdev_master_upper_dev_get(dev);
		now = true;
		break;
	case NETDEV_CHANGELOWERSTATE:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEINFODATA:
	case NETDEV_BONDING_FAILOVER:
	case NETDEV_UNREGISTER:
		upper = netif_is_bond_master(dev) ? dev :
			netdev_master_upper_dev_get(dev);
		break;
	default:
		return NOTIFY_DONE;
	}
	if (!upper || !netif_is_bond_master(upper))
		return NOTIFY_DONE;

	mutex_lock(&np->sse_lock);
	lag = fnp4l_lag_find(np, upper);
	if (lag && event == NETDEV_UNREGISTER && dev == upper) {
		fnp4l_lag_kill(lag);
	} else if (lag) {
		lag->dirty = true;
		kick = true;
	}
	mutex_unlock(&np->sse_lock);

	if (kick)
		mod_delayed_work(system_wq, &np->lag_work,
				 now ? 0 : NP4L_LAG_DELAY);

	return NOTIFY_DONE;
}

/*
 * Flow table bound to a bond (indirect block): follow the bond, and make
 * its slaves look frames up in the flow table. The first binding starts
 * the engine, as for a port.
 */
static struct fnp4l_lag *fnp4l_lag_bind(struct fnp4l *np,
					struct net_device *dev,
					struct netlink_ext_ack *extack)
{
	unsigned long members, active, ready;
	struct fnp4l_lag *lag;
	int ret;

	lag = kzalloc_obj(*lag);
	if (!lag)
		return ERR_PTR(-ENOMEM);
	lag->np = np;
	lag->dev = dev;

	mutex_lock(&np->sse_lock);
	if (fnp4l_lag_find(np, dev)) {
		ret = -EBUSY;
		goto err;
	}
	if (!fnp4l_lag_read(lag, &members, &active, &ready)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "bond of other devices than network processor or switch ports, or mode not supported");
		ret = -EOPNOTSUPP;
		goto err;
	}

	switch (np->sse_state) {
	case NP4L_SSE_DOWN:
		ret = fnp4l_sse_start(np);
		if (ret) {
			NL_SET_ERR_MSG_MOD(extack, "cannot start the flow engine");
			goto err;
		}
		break;
	case NP4L_SSE_UP:
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack, "flow engine stopped");
		ret = -EIO;
		goto err;
	}

	list_add_tail(&lag->node, &np->lags);
	lag->usable = true;
	lag->ready = ready;
	fnp4l_lag_set_members(lag, members, active);
	mutex_unlock(&np->sse_lock);
	netdev_dbg(dev, "flow table bound, LIFs %#lx, active %#lx, ready %#lx\n",
		   members, active, ready);
	if ((active & ~ready) || (lag->lacp && active))
		queue_delayed_work(system_wq, &np->lag_work, NP4L_LAG_POLL);

	return lag;

err:
	mutex_unlock(&np->sse_lock);
	kfree(lag);
	return ERR_PTR(ret);
}

/*
 * The flow table no longer reaches the callback of this bond: send the
 * frames of its slaves to the host again, stop the engine if nothing else
 * is bound, and forget the bond.
 */
static void fnp4l_lag_release(void *cb_priv)
{
	struct fnp4l_lag *lag = cb_priv;
	struct fnp4l *np = lag->np;

	if (lag->vlan) {
		kfree(lag);
		return;
	}

	mutex_lock(&np->sse_lock);
	lag->usable = false;
	fnp4l_lag_drop(np, lag, 0);
	fnp4l_lag_set_members(lag, 0, 0);
	list_del(&lag->node);
	if (fnp4l_ft_idle(np))
		fnp4l_sse_stop(np);
	mutex_unlock(&np->sse_lock);

	kfree(lag);
}

static int fnp4l_lag_cb(enum tc_setup_type type, void *type_data,
			void *cb_priv)
{
	struct flow_cls_offload *cls = type_data;
	struct fnp4l_lag *lag = cb_priv;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		return fnp4l_lag_replace(lag, cls);
	case FLOW_CLS_DESTROY:
		return fnp4l_lag_destroy(lag, cls->cookie);
	case FLOW_CLS_STATS:
		return fnp4l_lag_stats(lag, cls);
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef CONFIG_FORTINET_NP4LITE_VLAN_BOND
/*
 * 802.1Q devices listed in a flow table. The flow table follows the path
 * of a flow down to the last device without ndo_fill_forward_path, a bond
 * or a port of the NP here, and gives that device as input and output of
 * the flow, with the tag as an encapsulation: no flow enters or leaves
 * through the 802.1Q device itself, and its flows reach the callbacks of
 * the bond or the port, which the flow table must list for them to be
 * offloaded at all. Without a callback of its own, the device would make
 * the whole flow table fail with the "offload" flag: it gets one, which
 * takes no flow.
 */
static bool fnp4l_vlan_dev(struct fnp4l *np, struct net_device *dev)
{
	struct net_device *real;
	struct fnp4l_port *port;

	if (!is_vlan_dev(dev) || vlan_dev_vlan_proto(dev) != htons(ETH_P_8021Q))
		return false;

	real = vlan_dev_priv(dev)->real_dev;
	if (netif_is_bond_master(real))
		return true;
	port = fnp4l_ft_port(np, real);

	return port && !netdev_uses_dsa(real);
}

static int fnp4l_vlan_cb(enum tc_setup_type type, void *type_data,
			 void *cb_priv)
{
	return -EOPNOTSUPP;
}

/*
 * Unbinding a device bound as an 802.1Q device, found by its callback
 * rather than by fnp4l_vlan_dev() again, which a bond going away could
 * make false.
 */
static bool fnp4l_vlan_bound(struct flow_block_offload *f,
			     struct net_device *dev)
{
	return f->command == FLOW_BLOCK_UNBIND &&
	       flow_block_cb_lookup(f->block, fnp4l_vlan_cb, dev);
}

static int fnp4l_vlan_setup(struct fnp4l *np, struct net_device *dev,
			    struct Qdisc *sch, struct flow_block_offload *f,
			    void *data,
			    void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct flow_block_cb *block_cb;
	struct fnp4l_lag *lag;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		if (flow_block_cb_lookup(f->block, fnp4l_vlan_cb, dev))
			return -EBUSY;
		lag = kzalloc_obj(*lag);
		if (!lag)
			return -ENOMEM;
		lag->np = np;
		lag->dev = dev;
		lag->vlan = true;

		/* Identified by the device, for the unbinding. */
		block_cb = flow_indr_block_cb_alloc(fnp4l_vlan_cb, dev, lag,
						    fnp4l_lag_release, f,
						    dev, sch, data, np,
						    cleanup);
		if (IS_ERR(block_cb)) {
			kfree(lag);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &fnp4l_block_cb_list);
		netdev_dbg(dev, "flow table bound, flows through %s\n",
			   netdev_name(vlan_dev_priv(dev)->real_dev));
		return 0;
	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block, fnp4l_vlan_cb, dev);
		if (!block_cb)
			return -ENOENT;

		flow_indr_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}
#else
static bool fnp4l_vlan_dev(struct fnp4l *np, struct net_device *dev)
{
	return false;
}

static bool fnp4l_vlan_bound(struct flow_block_offload *f,
			     struct net_device *dev)
{
	return false;
}

static int fnp4l_vlan_setup(struct fnp4l *np, struct net_device *dev,
			    struct Qdisc *sch, struct flow_block_offload *f,
			    void *data,
			    void (*cleanup)(struct flow_block_cb *block_cb))
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_FORTINET_NP4LITE_VLAN_BOND */

/*
 * Indirect block callback: the bonding driver has no ndo_setup_tc, and a
 * flow table bound to a bond with the "offload" flag reaches the drivers
 * this way. Every flow of the table then goes to every callback of the
 * table, those of the bound ports included.
 */
static int fnp4l_lag_setup(struct net_device *dev, struct Qdisc *sch,
			   void *cb_priv, enum tc_setup_type type,
			   void *type_data, void *data,
			   void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct flow_block_offload *f = type_data;
	struct flow_block_cb *block_cb = NULL;
	struct fnp4l *np = cb_priv;
	struct fnp4l_lag *lag;

	if (!dev || type != TC_SETUP_FT ||
	    f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	if (fnp4l_vlan_bound(f, dev) || fnp4l_vlan_dev(np, dev)) {
		f->driver_block_list = &fnp4l_block_cb_list;
		return fnp4l_vlan_setup(np, dev, sch, f, data, cleanup);
	}
	if (!netif_is_bond_master(dev))
		return -EOPNOTSUPP;

	f->driver_block_list = &fnp4l_block_cb_list;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		lag = fnp4l_lag_bind(np, dev, f->extack);
		if (IS_ERR(lag))
			return PTR_ERR(lag);

		block_cb = flow_indr_block_cb_alloc(fnp4l_lag_cb, lag, lag,
						    fnp4l_lag_release, f,
						    dev, sch, data, np,
						    cleanup);
		if (IS_ERR(block_cb)) {
			fnp4l_lag_release(lag);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &fnp4l_block_cb_list);
		return 0;
	case FLOW_BLOCK_UNBIND:
		/* The bond may be dead: look the record up by address. */
		mutex_lock(&np->sse_lock);
		list_for_each_entry(lag, &np->lags, node) {
			if (lag->dev != dev)
				continue;
			block_cb = flow_block_cb_lookup(f->block,
							fnp4l_lag_cb, lag);
			if (block_cb)
				break;
		}
		mutex_unlock(&np->sse_lock);
		if (!block_cb)
			return -ENOENT;

		/* fnp4l_lag_release() runs when the table frees it. */
		flow_indr_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static void fnp4l_lag_exit(void *data)
{
	struct fnp4l *np = data;

	flow_indr_dev_unregister(fnp4l_lag_setup, np, fnp4l_lag_release);
	unregister_netdevice_notifier(&np->lag_nb);
	cancel_delayed_work_sync(&np->lag_work);
}

static int fnp4l_lag_init(struct fnp4l *np)
{
	int ret;

	INIT_LIST_HEAD(&np->lags);
	hash_init(np->lag_flows);
	INIT_DELAYED_WORK(&np->lag_work, fnp4l_lag_work);
	if (!np->sse_avail)
		return 0;

	np->lag_nb.notifier_call = fnp4l_lag_event;
	ret = register_netdevice_notifier(&np->lag_nb);
	if (ret)
		return ret;

	ret = flow_indr_dev_register(fnp4l_lag_setup, np);
	if (ret) {
		unregister_netdevice_notifier(&np->lag_nb);
		return ret;
	}

	return devm_add_action_or_reset(np->dev, fnp4l_lag_exit, np);
}
#else
static inline int fnp4l_lag_init(struct fnp4l *np)
{
	return 0;
}
#endif /* CONFIG_FORTINET_NP4LITE_LAG */

/*
 * Read (and clear) TCE counter @idx, and add it to the totals @packets and
 * @bytes. A failed read may already have cleared the entry: up to one
 * period of traffic is lost. A counter that lost its type (@raw holds it)
 * is made an empty counter again; the read back of that write clears the
 * frames counted meanwhile, and a mismatch is ignored. Neither should
 * happen while nothing else writes the table.
 *
 * Returns 0, the error of the read, or -EBADMSG for an entry that was no
 * counter. Under tbl_lock, within an update of tce_syncp.
 */
static int fnp4l_tce_fold(struct fnp4l_port *port, u32 idx,
			  u64_stats_t *packets, u64_stats_t *bytes,
			  u32 raw[2])
{
	struct fnp4l *np = port->np;
	u64 p, n;
	u32 lo, hi;
	int ret;

	ret = fnp4l_tbl_read(np, NP4L_TBL_TRAFFIC_CNT, idx, &lo, &hi);
	if (ret)
		return ret;

	if (!(hi & NP4L_TCE_HI_CNT)) {
		raw[0] = hi;
		raw[1] = lo;
		fnp4l_tbl_write(np, NP4L_TBL_TRAFFIC_CNT, idx, 0, NP4L_TCE_HI_CNT);
		return -EBADMSG;
	}

	fnp4l_tce_decode(lo, hi, &p, &n);
	u64_stats_set(packets, u64_stats_read(packets) + p);
	u64_stats_set(bytes, u64_stats_read(bytes) + n);

	return 0;
}

/*
 * Read (and clear) DCE entry @idx. The counter is the low word. What the
 * high word holds is not known: report it once rather than fold a possibly
 * unrelated field into the totals. Under tbl_lock.
 */
static int fnp4l_dce_read(struct fnp4l *np, u32 idx, u32 *val)
{
	u32 lo, hi;
	int ret;

	ret = fnp4l_tbl_read(np, NP4L_TBL_DROP_CNT, idx, &lo, &hi);
	if (ret)
		return ret;
	if (hi)
		dev_warn_once(np->dev, "DCE %#x: high word %#x not accounted\n",
			      idx, hi);
	*val = lo;

	return 0;
}

#ifdef CONFIG_FORTINET_NP4LITE_IPSEC
/*
 * Fold the DCE counters of the IPsec engine into their totals, as the
 * other global ones. Under tbl_lock, drop_cnt_syncp being updated. Returns the
 * number of failed reads.
 */
static unsigned int fnp4l_ipsec_dce_update(struct fnp4l *np)
{
	unsigned int i, failed = 0;
	u32 val;

	if (!np->ipsec)
		return 0;

	for (i = 0; i < ARRAY_SIZE(fnp4l_ipsec_dces); i++) {
		const struct fnp4l_ipsec_dce *d = &fnp4l_ipsec_dces[i];

		if (fnp4l_dce_read(np, d->idx, &val))
			failed++;
		else
			u64_stats_add(&np->ipsec_dce[d->stat], val);
	}

	return failed;
}

/*
 * The entries of fnp4l_ipsec_dces, which fnp4l_dce_clear() does not
 * reach, cleared the same way (read once) once the IPsec offload is set
 * up. At probe, HIF stopped.
 */
static void fnp4l_ipsec_dce_clear(struct fnp4l *np)
{
	unsigned int i, failed = 0;
	u32 lo, hi;

	spin_lock_bh(&np->tbl_lock);
	for (i = 0; i < ARRAY_SIZE(fnp4l_ipsec_dces); i++)
		if (fnp4l_tbl_read(np, NP4L_TBL_DROP_CNT, fnp4l_ipsec_dces[i].idx,
				   &lo, &hi))
			failed++;
	spin_unlock_bh(&np->tbl_lock);

	if (failed)
		dev_warn(np->dev, "IPsec DCE clear: %u reads timed out\n",
			 failed);
}

static unsigned int fnp4l_nr_ipsec_dce(const struct fnp4l *np)
{
	return np->ipsec ? NP4L_IPSEC_DCE_NR : 0;
}

static void fnp4l_ipsec_dce_strings(const struct fnp4l *np, u8 **data)
{
	unsigned int i;

	for (i = 0; i < fnp4l_nr_ipsec_dce(np); i++)
		ethtool_puts(data, fnp4l_ipsec_dce_names[i]);
}

/* The totals, under tbl_lock. Returns the number of values written. */
static unsigned int fnp4l_ipsec_dce_stats(struct fnp4l *np, u64 *data)
{
	unsigned int i;

	for (i = 0; i < fnp4l_nr_ipsec_dce(np); i++)
		data[i] = u64_stats_read(&np->ipsec_dce[i]);

	return fnp4l_nr_ipsec_dce(np);
}
#else
static unsigned int fnp4l_ipsec_dce_update(struct fnp4l *np)
{
	return 0;
}

static void fnp4l_ipsec_dce_clear(struct fnp4l *np)
{
}

static unsigned int fnp4l_nr_ipsec_dce(const struct fnp4l *np)
{
	return 0;
}

static void fnp4l_ipsec_dce_strings(const struct fnp4l *np, u8 **data)
{
}

static unsigned int fnp4l_ipsec_dce_stats(struct fnp4l *np, u64 *data)
{
	return 0;
}
#endif /* CONFIG_FORTINET_NP4LITE_IPSEC */

/*
 * Fold the global DCE counters into their totals. A failed read may
 * already have cleared the entry: up to one period of drops is lost.
 * Under tbl_lock. Returns the number of failed reads.
 */
static unsigned int fnp4l_dce_update(struct fnp4l *np)
{
	unsigned int i, failed = 0;
	u32 val;

	u64_stats_update_begin(&np->drop_cnt_syncp);
	for (i = 0; i < NP4L_DCE_NR; i++) {
		if (!fnp4l_dce_descs[i].global)
			continue;
		if (fnp4l_dce_read(np, fnp4l_dce_descs[i].idx, &val))
			failed++;
		else
			u64_stats_add(&np->dce[i], val);
	}
	failed += fnp4l_ipsec_dce_update(np);
	u64_stats_update_end(&np->drop_cnt_syncp);

	return failed;
}

/*
 * Fold the traffic counters of every port into its totals, whether the
 * port is open or not: the flow engine may forward to and from a port the
 * host has closed, and the counters wrap within minutes. Fold the global
 * DCE counters too.
 */
static void fnp4l_tce_update(struct fnp4l *np)
{
	unsigned int id, i, failed = 0, drop_failed;
	u32 bad_idx = 0, raw[2];
	int ret[2];

	/* Warnings are printed after the lock: the console is slow. */
	spin_lock_bh(&np->tbl_lock);
	for (id = 0; id < NP4L_NR_PORTS; id++) {
		struct fnp4l_port *port = np->ports[id];

		if (!port || !port->tce)
			continue;
		u64_stats_update_begin(&port->tce_syncp);
		ret[0] = fnp4l_tce_fold(port, NP4L_TCE_IGR(port->lif),
					&port->tce_rx_packets,
					&port->tce_rx_bytes, raw);
		ret[1] = fnp4l_tce_fold(port, NP4L_TCE_EGR(port->lif),
					&port->tce_tx_packets,
					&port->tce_tx_bytes, raw);
		u64_stats_update_end(&port->tce_syncp);

		for (i = 0; i < ARRAY_SIZE(ret); i++) {
			if (!ret[i])
				continue;
			np->tce_errors++;
			if (ret[i] == -EBADMSG)
				bad_idx = i ? NP4L_TCE_EGR(port->lif) :
					      NP4L_TCE_IGR(port->lif);
			else
				failed++;
		}
	}
	drop_failed = fnp4l_dce_update(np);
	spin_unlock_bh(&np->tbl_lock);

	if (failed)
		dev_warn_ratelimited(np->dev, "%u TCE reads failed, counts lost\n",
				     failed);
	if (drop_failed)
		dev_warn_ratelimited(np->dev, "%u DCE reads failed, counts lost\n",
				     drop_failed);
	if (bad_idx)
		dev_warn_once(np->dev, "TCE %u was no counter (%#010x %#010x), cleared\n",
			      bad_idx, raw[0], raw[1]);
}

/* Total of the global DCE counter @idx */
static u64 fnp4l_dce_total(struct fnp4l *np, u32 idx)
{
	unsigned int start, i;
	u64 total;

	for (i = 0; i < NP4L_DCE_NR; i++)
		if (fnp4l_dce_descs[i].global &&
		    fnp4l_dce_descs[i].idx == idx)
			break;
	if (i == NP4L_DCE_NR)
		return 0;

	do {
		start = u64_stats_fetch_begin(&np->drop_cnt_syncp);
		total = u64_stats_read(&np->dce[i]);
	} while (u64_stats_fetch_retry(&np->drop_cnt_syncp, start));

	return total;
}

/*
 * The counter work also follows the status of the IPsec engine.
 *
 * TODO: system_power_efficient_wq is not freezable. Should the driver get
 * power management, stop and restart the work on suspend and resume.
 */
static void fnp4l_tce_work(struct work_struct *work)
{
	struct fnp4l *np = container_of(to_delayed_work(work),
					struct fnp4l, tce_work);

	fnp4l_tce_update(np);
	if (np->ipsec)
		fnp4l_ipsec_watch(np->ipsec,
				  fnp4l_dce_total(np, NP4L_DCE_FLOW_TO_HOST_FULL));
	queue_delayed_work(system_power_efficient_wq, &np->tce_work,
			   round_jiffies_relative(NP4L_TCE_PERIOD));
}

/* Stop the counter work, after a last update of the totals. */
static void fnp4l_tce_stop(void *data)
{
	struct fnp4l *np = data;

	cancel_delayed_work_sync(&np->tce_work);
	fnp4l_tce_update(np);
}

struct fnp4l_tce_totals {
	u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
};

static void fnp4l_tce_read(struct fnp4l_port *port,
			   struct fnp4l_tce_totals *t)
{
	unsigned int start;

	do {
		start = u64_stats_fetch_begin(&port->tce_syncp);
		t->rx_packets = u64_stats_read(&port->tce_rx_packets);
		t->rx_bytes = u64_stats_read(&port->tce_rx_bytes);
		t->tx_packets = u64_stats_read(&port->tce_tx_packets);
		t->tx_bytes = u64_stats_read(&port->tce_tx_bytes);
	} while (u64_stats_fetch_retry(&port->tce_syncp, start));
}

/* Frames for the host the NP dropped for want of room, global totals */
static u64 fnp4l_hif_missed(struct fnp4l *np)
{
	unsigned int start, i;
	u64 missed;

	do {
		start = u64_stats_fetch_begin(&np->drop_cnt_syncp);
		missed = 0;
		for (i = 0; i < NP4L_DCE_NR; i++) {
			u8 idx = fnp4l_dce_descs[i].idx;

			if (idx == NP4L_DCE_FLOW_TO_HOST_FULL ||
			    idx == NP4L_DCE_RX_NO_BUFFER)
				missed += u64_stats_read(&np->dce[i]);
		}
	} while (u64_stats_fetch_retry(&np->drop_cnt_syncp, start));

	return missed;
}

/*
 * Packets and bytes are those of the traffic counters of the LIF, updated
 * every second: they cover the flows the NP forwards by itself, and the
 * frames of the host too, which the software counters (dev->stats) only
 * see. Adding both would count the host twice. Errors and drops are the
 * software ones, plus, in rx_missed_errors, the frames for the host the
 * NP dropped for want of room: host queue of the flow engine full (DCE
 * 0x12) or no free RX descriptor (DCE 0x19). The HIF is shared by every
 * port and these two counters are global, with no port of their own: they
 * are added to one port only, the lowest numbered (hif_port), the DSA
 * conduit on the FG-60C. They are the totals of the counter work, their
 * sole reader, at most a second old; ethtool shows the same totals.
 *
 * TODO: the per-port drop counters of the DCE (header checks, full
 * queues) belong to rx_dropped and rx_missed_errors too. They clear on
 * read and ethtool reads them: the counter work would have to become their
 * sole reader first, like for the global ones.
 */
static void fnp4l_get_stats64(struct net_device *ndev,
			      struct rtnl_link_stats64 *s)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l_tce_totals t;

	netdev_stats_to_stats64(s, &ndev->stats);
	if (port == port->np->hif_port)
		s->rx_missed_errors += fnp4l_hif_missed(port->np);
	if (!port->tce)
		return;

	fnp4l_tce_read(port, &t);
	s->rx_packets = t.rx_packets;
	s->rx_bytes = t.rx_bytes;
	s->tx_packets = t.tx_packets;
	s->tx_bytes = t.tx_bytes;
}

static bool fnp4l_has_offload_stats(const struct net_device *ndev,
				    int attr_id)
{
	return attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT;
}

/* Traffic of the host: the software counters. */
static int fnp4l_get_offload_stats(int attr_id, const struct net_device *ndev,
				   void *sp)
{
	struct rtnl_link_stats64 *s = sp;

	if (attr_id != IFLA_OFFLOAD_XSTATS_CPU_HIT)
		return -EINVAL;

	s->rx_packets = DEV_STATS_READ(ndev, rx_packets);
	s->rx_bytes = DEV_STATS_READ(ndev, rx_bytes);
	s->tx_packets = DEV_STATS_READ(ndev, tx_packets);
	s->tx_bytes = DEV_STATS_READ(ndev, tx_bytes);

	return 0;
}

/*
 * The MTU field of the LIF follows the MTU of the port (NP4L_LIF_MTU),
 * written before the new MTU shows: a smaller one first cuts the packets
 * the NP builds, then the host sends smaller ones.
 */
static int fnp4l_change_mtu(struct net_device *ndev, int new_mtu)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;
	u32 idx = port->lif + NP4L_LIF_ENTRY_B;
	u32 lo, hi, nlo;
	int ret;

	if (!port->lif_mtu_fixed) {
		spin_lock_bh(&np->tbl_lock);
		ret = fnp4l_tbl_read(np, NP4L_TBL_LIF, idx, &lo, &hi);
		if (!ret) {
			nlo = (lo & ~NP4L_LIFB_MTU) |
			      FIELD_PREP(NP4L_LIFB_MTU,
					 fnp4l_lif_mtu(port, new_mtu));
			if (nlo != lo)
				ret = fnp4l_tbl_write(np, NP4L_TBL_LIF, idx,
						      nlo, hi);
		}
		spin_unlock_bh(&np->tbl_lock);
		if (ret) {
			netdev_err(ndev, "cannot set MTU %d on LIF %u: %d\n",
				   new_mtu, port->lif, ret);
			return ret;
		}
	}

	WRITE_ONCE(ndev->mtu, new_mtu);

	return 0;
}

static const struct net_device_ops fnp4l_netdev_ops = {
	.ndo_open		= fnp4l_open,
	.ndo_stop		= fnp4l_stop,
	.ndo_start_xmit		= fnp4l_start_xmit,
	.ndo_features_check	= fnp4l_features_check,
	.ndo_tx_timeout		= fnp4l_tx_timeout,
	.ndo_set_rx_mode	= fnp4l_set_rx_mode,
	.ndo_set_mac_address	= fnp4l_set_mac_address,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_change_mtu		= fnp4l_change_mtu,
	.ndo_set_features	= fnp4l_set_features,
	.ndo_eth_ioctl		= fnp4l_eth_ioctl,
	.ndo_get_phys_port_name	= fnp4l_get_phys_port_name,
	.ndo_setup_tc		= fnp4l_setup_tc,
	.ndo_get_stats64	= fnp4l_get_stats64,
	.ndo_has_offload_stats	= fnp4l_has_offload_stats,
	.ndo_get_offload_stats	= fnp4l_get_offload_stats,
};

static void fnp4l_get_drvinfo(struct net_device *ndev,
			      struct ethtool_drvinfo *info)
{
	struct fnp4l_port *port = netdev_priv(ndev);

	strscpy(info->driver, DRV_NAME, sizeof(info->driver));
	strscpy(info->bus_info, dev_name(port->np->dev),
		sizeof(info->bus_info));
}

/*
 * Counters of the flow engine, global. The last one, the message queue of
 * the FortiSOC1, does not exist on the FortiSOC2.
 */
static const struct {
	u32 reg;
	char name[ETH_GSTRING_LEN];
} fnp4l_sse_stats[] = {
	{ NP4L_SSE_INSERTS,	"flow_inserts" },
	{ NP4L_SSE_INSERTS_OK,	"flow_inserts_ok" },
	{ NP4L_SSE_DELETES,	"flow_deletes" },
	{ NP4L_SSE_DELETES_OK,	"flow_deletes_ok" },
	{ NP4L_SSE_ENTRIES,	"flow_entries" },
	{ NP4L_MSG_RING_HEAD,	"flow_msg_head" },	/* messages queued by the NP */
};

/* Messages of the NP, counted by the driver, global */
static const char fnp4l_msg_stats[][ETH_GSTRING_LEN] = {
	"flow_msg_expired",	/* ageing messages */
	"flow_msg_unknown",	/* of them, for no tracked flow */
	"flow_msg_bad",		/* message skipped or queue dropped */
	"flow_counters_exhausted",	/* flow directions without a counter */
};

/* Counted by the driver, global */
static const char fnp4l_global_stats[][ETH_GSTRING_LEN] = {
	"lif_counter_errors",	/* traffic counters lost or reset */
};

/* FortiSOC2: engine messages and LIF patterns, counted on the RX path */
static const char fnp4l_hif_msg_stats[][ETH_GSTRING_LEN] = {
	"rx_flow_msgs",		/* engine messages received */
	"flow_msg_lost",	/* ageing keys lost, FIFO full */
	"rx_flow_msgs_other",	/* of them, not ageing nor IPsec, skipped */
	"rx_htag_mark_a",	/* frames, LIF 0x_F_ in host tag bytes 0-1 */
	"rx_htag_mark_b",	/* frames, LIF 0x_F_ in host tag bytes 4-5 */
};

/* Counted by the driver, per port */
static const char fnp4l_port_stats[][ETH_GSTRING_LEN] = {
	"rx_anomaly_trapped",	/* frames an L3 anomaly check sent up */
};

#ifdef CONFIG_FORTINET_NP4LITE_DSA
/* FORTINET_NP4LITE_DSA, global, last */
static const char fnp4l_dsa_stats[][ETH_GSTRING_LEN] = {
	"dsa_rx_retag",		/* switch tags put back, RX */
	"dsa_rx_tagged",	/* of a port LIF, with the tag in place */
	"dsa_rx_missed",	/* conduit LIF, offloading: class table missed */
	"dsa_rx_untagged",	/* conduit LIF, offloading: no tag, dropped */
	"dsa_promisc_purged",	/* flow directions of a LIF gone promiscuous */
	"dsa_lifs",		/* LIFs of the switch ports, one bit each */
	"dsa_rx_prio_tag",	/* 802.1Q VID 0 taken off by the IGR, RX */
	"dsa_rx_vid_tag",	/* 802.1Q VID other than 0, RX */
	"dsa_rx_last_tci",	/* TCI of the last of them */
	"dsa_bridged_lifs",	/* LIFs routed through a bridge */
	"dsa_fdb_moves",	/* ports torn down for a station move */
};
#endif

/* Flow engine registers shown: no message queue on the FortiSOC2 */
static unsigned int fnp4l_nr_sse_stats(const struct fnp4l_soc *soc)
{
	if (soc->sse_hif)
		return ARRAY_SIZE(fnp4l_sse_stats) - 1;

	return soc->sse ? ARRAY_SIZE(fnp4l_sse_stats) : 0;
}

/*
 * Statistics of the flow engine, only where the driver knows its
 * registers; the engine messages of the FortiSOC2, only there.
 */
static unsigned int fnp4l_nr_stats(const struct fnp4l *np)
{
	const struct fnp4l_soc *soc = np->soc;
	unsigned int n = NP4L_DCE_NR + ARRAY_SIZE(fnp4l_global_stats) +
			 ARRAY_SIZE(fnp4l_port_stats);

	n += fnp4l_nr_ipsec_dce(np);
	n += fnp4l_nr_sse_stats(soc);
	if (soc->sse || soc->sse_hif)
		n += ARRAY_SIZE(fnp4l_msg_stats);
	if (soc->sse_hif)
		n += ARRAY_SIZE(fnp4l_hif_msg_stats);
	n += fnp4l_ipsec_nr_stats(np->ipsec);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	n += ARRAY_SIZE(fnp4l_dsa_stats);
#endif

	return n;
}

static unsigned int fnp4l_nr_priv_flags(const struct fnp4l_port *port)
{
	return ARRAY_SIZE(fnp4l_priv_flags) - !port->ipopt_flag;
}

static int fnp4l_get_sset_count(struct net_device *ndev, int sset)
{
	struct fnp4l_port *port = netdev_priv(ndev);

	switch (sset) {
	case ETH_SS_STATS:
		return fnp4l_nr_stats(port->np);
	case ETH_SS_PRIV_FLAGS:
		return fnp4l_nr_priv_flags(port);
	default:
		return -EOPNOTSUPP;
	}
}

static void fnp4l_get_strings(struct net_device *ndev, u32 sset, u8 *data)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	const struct fnp4l_soc *soc = port->np->soc;
	bool sse = soc->sse || soc->sse_hif;
	unsigned int i;

	if (sset == ETH_SS_PRIV_FLAGS) {
		for (i = 0; i < fnp4l_nr_priv_flags(port); i++)
			ethtool_puts(&data, fnp4l_priv_flags[i]);
		return;
	}
	if (sset != ETH_SS_STATS)
		return;

	for (i = 0; i < NP4L_DCE_NR; i++)
		ethtool_puts(&data, fnp4l_dce_descs[i].name);
	fnp4l_ipsec_dce_strings(port->np, &data);
	for (i = 0; i < fnp4l_nr_sse_stats(soc); i++)
		ethtool_puts(&data, fnp4l_sse_stats[i].name);
	for (i = 0; sse && i < ARRAY_SIZE(fnp4l_msg_stats); i++)
		ethtool_puts(&data, fnp4l_msg_stats[i]);
	for (i = 0; i < ARRAY_SIZE(fnp4l_global_stats); i++)
		ethtool_puts(&data, fnp4l_global_stats[i]);
	for (i = 0; soc->sse_hif && i < ARRAY_SIZE(fnp4l_hif_msg_stats); i++)
		ethtool_puts(&data, fnp4l_hif_msg_stats[i]);
	fnp4l_ipsec_get_strings(port->np->ipsec, &data);
	for (i = 0; i < ARRAY_SIZE(fnp4l_port_stats); i++)
		ethtool_puts(&data, fnp4l_port_stats[i]);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	for (i = 0; i < ARRAY_SIZE(fnp4l_dsa_stats); i++)
		ethtool_puts(&data, fnp4l_dsa_stats[i]);
#endif
}

/*
 * The DCE counters clear on read. The per-port ones are read here and
 * accumulated in the port. The global ones are the totals of the counter
 * work, their sole reader, at most a second old; every port shows the
 * same values. The writer of those holds tbl_lock: no retry loop.
 */
static void fnp4l_get_ethtool_stats(struct net_device *ndev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;
	const struct fnp4l_soc *soc = np->soc;
	unsigned int i, start;
	u32 val;

	spin_lock_bh(&np->tbl_lock);
	for (i = 0; i < NP4L_DCE_NR; i++) {
		const struct fnp4l_dce_desc *d = &fnp4l_dce_descs[i];

		if (d->global) {
			*data++ = u64_stats_read(&np->dce[i]);
			continue;
		}
		if (!fnp4l_dce_read(np, d->idx + port->id * NP4L_DCE_PORT_STRIDE,
				    &val))
			port->dce[i] += val;
		*data++ = port->dce[i];
	}
	data += fnp4l_ipsec_dce_stats(np, data);
	spin_unlock_bh(&np->tbl_lock);

	/* Plain registers, not cleared on read, also while in reset */
	for (i = 0; i < fnp4l_nr_sse_stats(soc); i++)
		*data++ = fnp4l_rd(np, fnp4l_sse_stats[i].reg);

	if (soc->sse || soc->sse_hif) {
		mutex_lock(&np->sse_lock);
		*data++ = np->msg_timeout;
		*data++ = np->msg_unknown;
		*data++ = np->msg_bad + atomic_long_read(&np->msg_rx_bad);
		*data++ = np->tae_exhausted;
		mutex_unlock(&np->sse_lock);
	}

	spin_lock_bh(&np->tbl_lock);
	*data++ = np->tce_errors;
	spin_unlock_bh(&np->tbl_lock);
	if (soc->sse_hif) {
		*data++ = atomic_long_read(&np->rx_flow_msgs);
		*data++ = atomic_long_read(&np->msg_lost);
		*data++ = atomic_long_read(&np->rx_flow_msgs_other);
		*data++ = atomic_long_read(&np->rx_htag_mark_a);
		*data++ = atomic_long_read(&np->rx_htag_mark_b);
	}
	data += fnp4l_ipsec_get_stats(np->ipsec, data);

	do {
		start = u64_stats_fetch_begin(&port->rx_syncp);
		data[0] = u64_stats_read(&port->rx_anomaly_trapped);
	} while (u64_stats_fetch_retry(&port->rx_syncp, start));
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	data[1] = atomic_long_read(&np->dsa_rx_retag);
	data[2] = atomic_long_read(&np->dsa_rx_tagged);
	data[3] = atomic_long_read(&np->dsa_rx_missed);
	data[4] = atomic_long_read(&np->dsa_rx_untagged);
	data[5] = atomic_long_read(&np->dsa_promisc_purged);
	data[6] = np->dsa_lifs;
	data[7] = atomic_long_read(&np->dsa_rx_prio_tag);
	data[8] = atomic_long_read(&np->dsa_rx_vid_tag);
	data[9] = READ_ONCE(np->dsa_rx_last_tci);
	data[10] = READ_ONCE(np->dsa_bridged);
	data[11] = atomic_long_read(&np->dsa_fdb_moves);
#endif
}

static int fnp4l_get_link_ksettings(struct net_device *ndev,
				    struct ethtool_link_ksettings *cmd)
{
	struct fnp4l_port *port = netdev_priv(ndev);

	return phylink_ethtool_ksettings_get(port->phylink, cmd);
}

static int fnp4l_set_link_ksettings(struct net_device *ndev,
				    const struct ethtool_link_ksettings *cmd)
{
	struct fnp4l_port *port = netdev_priv(ndev);

	return phylink_ethtool_ksettings_set(port->phylink, cmd);
}

static int fnp4l_nway_reset(struct net_device *ndev)
{
	struct fnp4l_port *port = netdev_priv(ndev);

	return phylink_ethtool_nway_reset(port->phylink);
}

static u32 fnp4l_get_priv_flags(struct net_device *ndev)
{
	struct fnp4l_port *port = netdev_priv(ndev);

	return READ_ONCE(port->priv_flags);
}

/*
 * tx-zerocopy takes effect from the next frame: each descriptor records
 * its mapping. ip-options-host at once if the HIF runs (the header checks
 * are programmed when it starts), action before enable. Under RTNL.
 */
static int fnp4l_set_priv_flags(struct net_device *ndev, u32 flags)
{
	struct fnp4l_port *port = netdev_priv(ndev);
	struct fnp4l *np = port->np;
	u32 valid = NP4L_PRIV_TX_ZEROCOPY;

	if (port->ipopt_flag)
		valid |= NP4L_PRIV_IPOPT_HOST;
	if (flags & ~valid)
		return -EINVAL;
	WRITE_ONCE(port->priv_flags, flags);

	if (port->ipopt_flag && np->users) {
		fnp4l_wr(np, NP4L_IHP_L3_ANOMALY_ACT(port->id), 0);
		fnp4l_wr(np, NP4L_IHP_L3_ANOMALY_EN(port->id),
			 fnp4l_l3_anomaly_en(np, port->id));
	}

	return 0;
}

static const struct ethtool_ops fnp4l_ethtool_ops = {
	.get_drvinfo		= fnp4l_get_drvinfo,
	.get_link_ksettings	= fnp4l_get_link_ksettings,
	.set_link_ksettings	= fnp4l_set_link_ksettings,
	.nway_reset		= fnp4l_nway_reset,
	.get_link		= ethtool_op_get_link,
	.get_sset_count		= fnp4l_get_sset_count,
	.get_strings		= fnp4l_get_strings,
	.get_ethtool_stats	= fnp4l_get_ethtool_stats,
	.get_priv_flags		= fnp4l_get_priv_flags,
	.set_priv_flags		= fnp4l_set_priv_flags,
};

/*
 * The DCE counters live in SRAM that holds noise after a power cycle, and
 * the counts of a previous system after a watchdog reset: read every
 * entry once, which clears it. At probe, HIF stopped.
 */
static void fnp4l_dce_clear(struct fnp4l *np)
{
	unsigned int idx, failed = 0;
	u32 lo, hi;

	spin_lock_bh(&np->tbl_lock);
	for (idx = 0; idx < NP4L_DCE_ENTRIES; idx++)
		if (fnp4l_tbl_read(np, NP4L_TBL_DROP_CNT, idx, &lo, &hi))
			failed++;
	spin_unlock_bh(&np->tbl_lock);

	if (failed)
		dev_warn(np->dev, "DCE clear: %u reads timed out\n", failed);
}

static int fnp4l_mdio_xfer(struct mii_bus *bus, u32 cmd)
{
	struct fnp4l *np = bus->priv;
	u32 val;
	int ret;

	fnp4l_wr(np, NP4L_MDIO_CMD, cmd | NP4L_MDIO_START);
	/*
	 * A frame takes about 30 us: spin rather than sleep. Without high
	 * resolution timers a sleeping poll costs a scheduler tick per
	 * access, and a switch in multi-chip mode needs several accesses
	 * per register.
	 */
	ret = readl_poll_timeout_atomic(np->base + NP4L_MDIO_CMD, val,
					!(val & NP4L_MDIO_BUSY), 1,
					NP4L_MDIO_TIMEOUT_US);
	if (ret)
		return ret;

	return FIELD_GET(NP4L_MDIO_DATA, val);
}

static int fnp4l_mdio_read(struct mii_bus *bus, int addr, int regnum)
{
	return fnp4l_mdio_xfer(bus, NP4L_MDIO_OP_READ |
			       FIELD_PREP(NP4L_MDIO_PHY, addr) |
			       FIELD_PREP(NP4L_MDIO_REG, regnum));
}

static int fnp4l_mdio_write(struct mii_bus *bus, int addr, int regnum,
			    u16 val)
{
	int ret;

	ret = fnp4l_mdio_xfer(bus, NP4L_MDIO_OP_WRITE |
			      FIELD_PREP(NP4L_MDIO_PHY, addr) |
			      FIELD_PREP(NP4L_MDIO_REG, regnum) |
			      FIELD_PREP(NP4L_MDIO_DATA, val));

	return ret < 0 ? ret : 0;
}

/*
 * The boot loader drives the reset pins of the switch and the WAN PHYs high
 * (outputs at 1) on its TFTP path only: booted from the boot device, they
 * stay inputs, read low, and the PHYs and the switch are held in reset
 * (measured): the RGMII PHYs are released from reset by a GPIO pulse.
 * Pulse the pins listed in
 * "fortinet,reset-pins" low, then leave them outputs at 1, before any MDIO
 * access; on both paths, so that the TFTP path exercises the state the
 * boot device path gets. No other pin is changed.
 */
static void fnp4l_release_resets(struct fnp4l *np)
{
	u32 mask = 0, v;

	of_property_for_each_u32(np->dev->of_node, "fortinet,reset-pins", v)
		if (v < 32)
			mask |= BIT(v);
	if (!mask)
		return;

	dev_info(np->dev, "GPIO resets %#x: in %#x out %#x oe %#x, low %u ms, then high\n",
		 mask, fnp4l_rd(np, NP4L_GPIO_IN), fnp4l_rd(np, NP4L_GPIO_OUT),
		 fnp4l_rd(np, NP4L_GPIO_OE), NP4L_GPIO_RESET_LOW_MS);
	/* Level first, so that a pin turning output never drives high */
	fnp4l_wr(np, NP4L_GPIO_OUT, fnp4l_rd(np, NP4L_GPIO_OUT) & ~mask);
	fnp4l_wr(np, NP4L_GPIO_OE, fnp4l_rd(np, NP4L_GPIO_OE) | mask);
	msleep(NP4L_GPIO_RESET_LOW_MS);
	fnp4l_wr(np, NP4L_GPIO_OUT, fnp4l_rd(np, NP4L_GPIO_OUT) | mask);
	msleep(NP4L_GPIO_RESET_WAIT_MS);
	dev_info(np->dev, "GPIO resets released: in %#x out %#x oe %#x\n",
		 fnp4l_rd(np, NP4L_GPIO_IN), fnp4l_rd(np, NP4L_GPIO_OUT),
		 fnp4l_rd(np, NP4L_GPIO_OE));
}

/*
 * Registers the boot loader of the FortiSOC2 sets on its TFTP path only
 * (its NP set-up), that this driver does not program itself: booted from
 * the boot device they hold their reset values, and the IGR length window
 * at 0 makes every frame "too long". Values of the TFTP path (registers
 * compared between both boot paths on a FortiGate 60D). Never the PDQ
 * control, the port-to-trunk table port at 0x200..0x20c, the message
 * control, MDIO or the NP GPIO.
 */
static const struct {
	u16 reg;
	u32 val;
} fnp4l_loader_regs[] = {
	{ 0 * NP4L_PORT_STRIDE + 0x100, 0x3c },	/* IGR minimum length, link 0 */
	{ 0 * NP4L_PORT_STRIDE + 0x104, 0x800 },	/* IGR maximum length */
	{ 1 * NP4L_PORT_STRIDE + 0x100, 0x3c },
	{ 1 * NP4L_PORT_STRIDE + 0x104, 0x800 },
	{ 1 * NP4L_PORT_STRIDE + 0x118, 0x1401 },	/* default LIF, link 1 (no PHY) */
	{ 2 * NP4L_PORT_STRIDE + 0x100, 0x3c },
	{ 2 * NP4L_PORT_STRIDE + 0x104, 0x800 },
	{ 3 * NP4L_PORT_STRIDE + 0x100, 0x3c },
	{ 3 * NP4L_PORT_STRIDE + 0x104, 0x800 },
	{ 0x21c, 0 },				/* SSE host queue map 0 */
	{ 0x220, 0 },				/* SSE host queue map 1 */
	{ 0x228, 0xf0000000 },			/* SSE map 1 */
};

/* Rewrite those that differ; nothing is written on the TFTP path. */
static void fnp4l_loader_init(struct fnp4l *np)
{
	unsigned int i, n = 0;

	if (!np->soc->rx_wb)
		return;
	for (i = 0; i < ARRAY_SIZE(fnp4l_loader_regs); i++) {
		u32 reg = fnp4l_loader_regs[i].reg;
		u32 val = fnp4l_loader_regs[i].val;
		u32 old = fnp4l_rd(np, reg);

		if (old == val)
			continue;
		dev_dbg(np->dev, "loader init: %#05x %#010x -> %#010x\n",
			reg, old, val);
		fnp4l_wr(np, reg, val);
		n++;
	}
	dev_info(np->dev, "loader init: %u of %zu registers rewritten\n", n,
		 ARRAY_SIZE(fnp4l_loader_regs));
}

static int fnp4l_mdio_register(struct fnp4l *np)
{
	struct device *dev = np->dev;
	struct mii_bus *bus;

	struct device_node *mdio_np __free(device_node) =
		of_get_available_child_by_name(dev->of_node, "mdio");
	if (!mdio_np)
		return 0;

	bus = devm_mdiobus_alloc(dev);
	if (!bus)
		return -ENOMEM;

	fnp4l_wr(np, NP4L_MDIO_CFG, NP4L_MDIO_CFG_INIT);

	bus->name = "Fortinet NP MDIO";
	bus->priv = np;
	bus->read = fnp4l_mdio_read;
	bus->write = fnp4l_mdio_write;
	bus->parent = dev;
	snprintf(bus->id, MII_BUS_ID_SIZE, "%s-mii", dev_name(dev));

	return devm_of_mdiobus_register(dev, bus, mdio_np);
}

static int fnp4l_alloc_rings(struct fnp4l *np)
{
	struct device *dev = np->dev;
	unsigned int i;
	void *guard;

	np->rx_ring = dmam_alloc_coherent(dev, NP4L_RX_RING_LEN * sizeof(*np->rx_ring) +
					  NP4L_RING_EXTRA, &np->rx_ring_dma,
					  GFP_KERNEL);
	np->tx_ring = dmam_alloc_coherent(dev, NP4L_TX_RING_LEN * sizeof(*np->tx_ring) +
					  NP4L_RING_EXTRA, &np->tx_ring_dma,
					  GFP_KERNEL);
	if (np->soc->rx_wb) {
		np->rx_wb = dmam_alloc_coherent(dev, NP4L_RX_RING_LEN * sizeof(*np->rx_wb) +
						NP4L_RING_EXTRA, &np->rx_wb_dma,
						GFP_KERNEL);
		if (!np->rx_wb)
			return -ENOMEM;
	} else {
		np->rx_wb = np->rx_ring;
		np->rx_wb_dma = np->rx_ring_dma;
	}
	guard = dmam_alloc_coherent(dev, NP4L_RX_DMA_LEN, &np->rx_guard_dma,
				    GFP_KERNEL);
	np->tx_buf = dmam_alloc_coherent(dev, NP4L_BUF_AREA, &np->tx_buf_dma,
					 GFP_KERNEL);
	if (!np->rx_ring || !np->tx_ring || !guard || !np->tx_buf)
		return -ENOMEM;

	/*
	 * No descriptor may ever carry address 0, even with LEN = 0. RX
	 * descriptors point at a guard buffer while they have no page.
	 */
	for (i = 0; i < NP4L_RX_RING_LEN; i++)
		np->rx_ring[i].addr = cpu_to_le32(np->rx_guard_dma);
	for (i = 0; i < NP4L_TX_RING_LEN; i++)
		np->tx_ring[i].addr =
			cpu_to_le32(np->tx_buf_dma + i * NP4L_BUF_STRIDE);

	return 0;
}

static void fnp4l_of_node_put(void *data)
{
	of_node_put(data);
}

static void fnp4l_phylink_destroy(void *data)
{
	phylink_destroy(data);
}

/*
 * phylink of one port: "phy-handle" or "fixed-link". The NP adds no RGMII
 * delay: any "rgmii*" mode is accepted, the delays being the business of
 * the other end.
 */
static int fnp4l_phylink_create(struct fnp4l_port *port)
{
	struct phylink_config *config = &port->phylink_config;
	struct device *dev = port->np->dev;
	struct phylink *phylink;
	phy_interface_t mode;
	int ret;

	ret = of_get_phy_mode(port->of_node, &mode);
	if (ret)
		return dev_err_probe(dev, ret, "%pOF: no phy-mode\n",
				     port->of_node);

	config->dev = &port->ndev->dev;
	config->type = PHYLINK_NETDEV;
	config->mac_capabilities = MAC_10 | MAC_100 | MAC_1000FD;
	phy_interface_set_rgmii(config->supported_interfaces);

	phylink = phylink_create(config, of_fwnode_handle(port->of_node),
				 mode, &fnp4l_phylink_ops);
	if (IS_ERR(phylink))
		return dev_err_probe(dev, PTR_ERR(phylink),
				     "%pOF: cannot create phylink\n",
				     port->of_node);
	port->phylink = phylink;

	return devm_add_action_or_reset(dev, fnp4l_phylink_destroy,
					phylink);
}

static void fnp4l_napi_free(void *data)
{
	struct fnp4l *np = data;

	netif_napi_del(&np->napi);
	free_netdev(np->napi_dev);
}

/*
 * Whether a DSA switch port names this port as its conduit ("ethernet"):
 * known before DSA takes the net_device, unlike netdev_uses_dsa().
 */
static bool fnp4l_port_is_conduit(const struct device_node *port_np)
{
	struct device_node *dn, *eth;

	for_each_node_with_property(dn, "ethernet") {
		eth = of_parse_phandle(dn, "ethernet", 0);
		of_node_put(eth);
		if (eth == port_np) {
			of_node_put(dn);
			return true;
		}
	}

	return false;
}

/* Create the net_device of one "ethernet-port@N" node. */
static int fnp4l_port_probe(struct fnp4l *np, struct device_node *child)
{
	struct device *dev = np->dev;
	struct fnp4l_port *port;
	struct net_device *ndev;
	bool conduit;
	u32 id, lif;
	int ret;

	ret = of_property_read_u32(child, "reg", &id);
	if (ret || id >= NP4L_NR_PORTS)
		return dev_err_probe(dev, -EINVAL, "%pOF: bad reg\n", child);
	if (np->ports[id])
		return dev_err_probe(dev, -EINVAL, "%pOF: port %u twice\n",
				     child, id);
	/*
	 * The LIF of a port keeps its traffic counters below those of the
	 * flows (NP4L_LIF_FW_LAST), and fits the LIF bitmaps of the bonds.
	 */
	lif = fnp4l_of_port_lif(child, id);
	if (lif > NP4L_LIF_FW_LAST)
		return dev_err_probe(dev, -EINVAL, "%pOF: LIF %u above %u\n",
				     child, lif, NP4L_LIF_FW_LAST);
#ifdef CONFIG_FORTINET_NP4LITE_LAG
	if (lif >= NP4L_LAG_LIFS)
		return dev_err_probe(dev, -EINVAL, "%pOF: LIF %u, %u at most with bonds\n",
				     child, lif, NP4L_LAG_LIFS - 1);
#endif

	ret = devm_add_action_or_reset(dev, fnp4l_of_node_put,
				       of_node_get(child));
	if (ret)
		return ret;

	ndev = devm_alloc_etherdev(dev, sizeof(*port));
	if (!ndev)
		return -ENOMEM;

	/* Found by DSA through this node, when the port is a DSA conduit. */
	SET_NETDEV_DEV(ndev, dev);
	ndev->dev.of_node = child;

	port = netdev_priv(ndev);
	port->np = np;
	port->ndev = ndev;
	port->of_node = child;
	port->id = id;
	port->lif = lif;
	u64_stats_init(&port->tce_syncp);
	u64_stats_init(&port->rx_syncp);
	if (np->lif_port[port->lif])
		return dev_err_probe(dev, -EINVAL, "%pOF: LIF %u twice\n",
				     child, port->lif);

	conduit = fnp4l_port_is_conduit(child);
	port->lif_mtu_fixed = conduit;
	ret = fnp4l_lif_setup(port);
	if (ret)
		return ret;
	fnp4l_igr_default_lif(port);
	fnp4l_igr_probe(port, conduit);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	if (conduit)
		fnp4l_dsa_probe(port);
#endif

	ret = fnp4l_phylink_create(port);
	if (ret)
		return ret;

	ndev->netdev_ops = &fnp4l_netdev_ops;
	ndev->ethtool_ops = &fnp4l_ethtool_ops;
	ndev->watchdog_timeo = NP4L_TX_TIMEOUT;
	ndev->max_mtu = NP4L_MAX_MTU;
	ndev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	/*
	 * Checksums and SG are offered but off by default: the RX checksum
	 * bits are known from observation only, and with the TX checksum and
	 * SG on, routed traffic is slower (169 against 197 Mbit/s, measured)
	 * for a small gain on local traffic. Zero-copy transmission, the
	 * "tx-zerocopy" private flag, is on: routing in software goes from
	 * 120 to 197 Mbit/s. The host tag goes into the
	 * headroom in zero-copy mode. VLAN and DSA user ports inherit
	 * nothing (vlan_features): the NP does not parse their headers.
	 *
	 * 802.1Q extraction and insertion are offered but off by default,
	 * and never on a DSA conduit: extraction would change the frames of
	 * the switch, and the switch tag comes before any 802.1Q tag.
	 */
	ndev->hw_features |= NETIF_F_RXCSUM | NETIF_F_IP_CSUM | NETIF_F_SG;
	if (!conduit && np->soc->vlan) {
		fnp4l_egr_init(port);
		ndev->hw_features |= NETIF_F_HW_VLAN_CTAG_RX |
				     NETIF_F_HW_VLAN_CTAG_TX;
	}
	ndev->needed_headroom = NP4L_HTAG_LEN;
	port->priv_flags = NP4L_PRIV_TX_ZEROCOPY;
	if (!conduit && np->soc->anomaly_priv) {
		port->ipopt_flag = true;
		port->priv_flags |= NP4L_PRIV_IPOPT_HOST;
	}
	if (np->sse_avail) {
		ndev->hw_features |= NETIF_F_HW_TC;
		ndev->features |= NETIF_F_HW_TC;
	}
	/* Not on a DSA conduit: the NP does not parse the frames of the switch. */
	if (!conduit)
		fnp4l_ipsec_port_init(np->ipsec, ndev);

	np->ports[id] = port;
	np->lif_port[port->lif] = port;

	return 0;
}

static int fnp4l_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	unsigned int rx_start, tx_start, id;
	struct device_node *ports_np;
	struct resource pbuf;
	struct fnp4l *np;
	u32 foreign, pba;
	int ret;

	np = devm_kzalloc(dev, sizeof(*np), GFP_KERNEL);
	if (!np)
		return -ENOMEM;

	np->dev = dev;
	np->soc = device_get_match_data(dev);
	if (!np->soc)
		return -ENODEV;
	spin_lock_init(&np->tbl_lock);
	u64_stats_init(&np->drop_cnt_syncp);
	spin_lock_init(&np->tx_lock);
	mutex_init(&np->sse_lock);
	INIT_DELAYED_WORK(&np->tce_work, fnp4l_tce_work);
	hash_init(np->ft_flows);
	hash_init(np->ft_keys);
	INIT_KFIFO(np->msg_fifo);
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	memset(np->dsa_lif_sw, NP4L_DSA_NONE, sizeof(np->dsa_lif_sw));
	np->dsa_out = true;
	INIT_WORK(&np->dsa_purge_work, fnp4l_dsa_purge_work);
	INIT_WORK(&np->dsa_fdb_work, fnp4l_dsa_fdb_work);
	spin_lock_init(&np->dsa_fdb_lock);
#endif
	platform_set_drvdata(pdev, np);

	/* Before anything is written: it may defer the probe */
	ret = fnp4l_nvmem_mac(np);
	if (ret)
		return ret;

	/* Named on the FortiSOC2, which has a second block */
	if (np->soc->irqmap)
		np->base = devm_platform_ioremap_resource_byname(pdev, "np");
	else
		np->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(np->base))
		return PTR_ERR(np->base);

	if (np->soc->irqmap) {
		np->irqmap = devm_platform_ioremap_resource_byname(pdev, "irq-map");
		if (IS_ERR(np->irqmap))
			return PTR_ERR(np->irqmap);
		np->loader_irqmap = readl(np->irqmap + NP4L_IRQMAP_OUT(NP4L_IRQMAP_OUT_NP));
		np->loader_irqmap_crypto =
			readl(np->irqmap + NP4L_IRQMAP_OUT(NP4L_IRQMAP_OUT_CRYPTO));
	}

	np->irq = platform_get_irq(pdev, 0);
	if (np->irq < 0)
		return np->irq;

	ret = of_reserved_mem_region_to_resource(dev->of_node, NP4L_MEM_PBUF,
						 &pbuf);
	if (ret)
		return dev_err_probe(dev, ret, "no packet buffer\n");
	/*
	 * The NP sizes its buffer by the number of blocks the boot loader
	 * set, which the driver keeps.
	 */
	pba = fnp4l_rd(np, NP4L_TOP_PBUF_BLOCKS);
	if (upper_32_bits(pbuf.start) || !IS_ALIGNED(pbuf.start, NP4L_PBA_BLOCK) ||
	    resource_size(&pbuf) < np->soc->pbuf_size ||
	    resource_size(&pbuf) < (u64)pba * NP4L_PBA_BLOCK)
		return dev_err_probe(dev, -EINVAL, "packet buffer %pR unusable for %u blocks\n",
				     &pbuf, pba);

	/*
	 * The boot loader leaves the HIF running, with its rings and packet
	 * buffer in memory that is only reserved until the driver takes
	 * over: stop it before anything else.
	 */
	np->loader_rx_ring_base = fnp4l_rd(np, NP4L_HRX_RING_BASE);
	np->loader_rx_ring_size = fnp4l_rd(np, NP4L_HRX_RING_SIZE);
	if (np->soc->rx_wb)
		np->loader_rx_wb_base = fnp4l_rd(np, NP4L_HRX_WB_BASE);
	np->loader_tx_ring_base = fnp4l_rd(np, NP4L_HTX_RING_BASE);
	np->loader_tx_ring_size = fnp4l_rd(np, NP4L_HTX_RING_SIZE);
	fnp4l_hif_stop(np);
	if (np->soc->sse) {
		fnp4l_sse_check_left(np);
		fnp4l_sse_reset(np);
	} else if (np->soc->sse_hif && fnp4l_sse_fsoc2_left(np)) {
		/* The state of the boot loader is left alone. */
		fnp4l_sse_reset(np);
	}
	fnp4l_loader_state(np);

	/* Before any total is accumulated. */
	fnp4l_dce_clear(np);

	/* Move the packet buffer to its reserved memory. */
	fnp4l_wr(np, NP4L_TOP_PBUF_BASE, lower_32_bits(pbuf.start));

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret)
		return dev_err_probe(dev, ret, "no 32-bit DMA\n");

	if (np->soc->sse || np->soc->sse_hif)
		fnp4l_sse_probe(np);
	if (np->soc->sse_hif && np->sse_avail)
		fnp4l_ipsec_probe_region(np);
	if (np->ipsec)
		fnp4l_ipsec_dce_clear(np);

	ret = fnp4l_alloc_rings(np);
	if (ret)
		return dev_err_probe(dev, ret, "cannot allocate rings\n");

	/* Runs before the rings are freed, on probe failure and on remove. */
	ret = devm_add_action_or_reset(dev, fnp4l_teardown, np);
	if (ret)
		return ret;

	/* The TFTP path setup of the boot loader, before any RX queue. */
	fnp4l_loader_init(np);

	/* Point the (stopped) HIF at our rings right away. */
	ret = fnp4l_hif_program(np, &rx_start, &tx_start);
	if (ret)
		return ret;

	fnp4l_release_resets(np);
	ret = fnp4l_mdio_register(np);
	if (ret)
		return dev_err_probe(dev, ret, "cannot register MDIO bus\n");

	ports_np = of_get_child_by_name(dev->of_node, "ethernet-ports");
	if (!ports_np)
		return dev_err_probe(dev, -ENODEV, "no ethernet-ports node\n");
	for_each_available_child_of_node_scoped(ports_np, child) {
		ret = fnp4l_port_probe(np, child);
		if (ret) {
			of_node_put(ports_np);
			return ret;
		}
	}
	of_node_put(ports_np);

	np->napi_dev = alloc_netdev_dummy(0);
	if (!np->napi_dev)
		return -ENOMEM;
	netif_napi_add_weight(np->napi_dev, &np->napi, fnp4l_poll,
			      CONFIG_FORTINET_NP4LITE_NAPI_WEIGHT);
	/*
	 * Single core (FortiSOC1/FortiSOC2): softirq processing of the host
	 * path starves the flow offload workers during a burst of new
	 * connections; run the NAPI of the NP in a schedulable kernel thread.
	 */
	if (napi_threaded)
		netif_threaded_enable(np->napi_dev);
	ret = devm_add_action_or_reset(dev, fnp4l_napi_free, np);
	if (ret)
		return ret;

	/*
	 * A source this driver cannot acknowledge would keep the level
	 * triggered line up.
	 */
	foreign = fnp4l_irq_quiesce(np);
	if (foreign)
		return dev_err_probe(dev, -EBUSY,
				     "unexpected NP interrupt sources %#x\n",
				     foreign);
	if (np->irqmap)
		fnp4l_irqmap_route(np);

	ret = devm_request_irq(dev, np->irq, fnp4l_isr, 0, dev_name(dev),
			       np);
	if (ret)
		return dev_err_probe(dev, ret, "cannot request IRQ\n");

	/* Registered in port order */
	for (id = 0; id < NP4L_NR_PORTS; id++) {
		struct fnp4l_port *port = np->ports[id];

		if (!port)
			continue;
		if (!np->hif_port)
			np->hif_port = port;
		ret = devm_register_netdev(dev, port->ndev);
		if (ret)
			return dev_err_probe(dev, ret, "cannot register port %u\n",
					     id);
	}

	/* Runs first on removal, before the ports go away. */
	ret = devm_add_action_or_reset(dev, fnp4l_tce_stop, np);
	if (ret)
		return ret;
	queue_delayed_work(system_power_efficient_wq, &np->tce_work,
			   NP4L_TCE_PERIOD);

	ret = fnp4l_lag_init(np);
	if (ret)
		return ret;

#ifdef CONFIG_FORTINET_NP4LITE_DSA
	fnp4l_dsa_init(np);
#endif

	return 0;
}

static const struct fnp4l_soc fnp4l_fsoc1_data = {
	.pbuf_size = SZ_8M,
	.ihp_ctrl = 0xf,
	.sse = true,
	.gmii_tx_hi = true,
	.tx_port = true,
	.vlan = true,
};

/*
 * FortiSOC2 (e.g. the FortiGate 60D). Its packet buffer is 0x100 blocks where
 * the FortiSOC1 has 0x80 (8 MiB): 16 MiB if the block size is the same
 * (NP4L_PBA_BLOCK, checked against the reservation).
 */
static const struct fnp4l_soc fnp4l_fsoc2_data = {
	.pbuf_size = SZ_16M,
	.ihp_ctrl = 0x2000f,
	.ihp_l4minlen = 0x14082828,
	.ihp_uesp_proto0 = 0x19411,
	.xhp = true,
	.rx_wb = true,
	.irqmap = true,
	.sse_hif = true,
	.loader_lifs_mac = true,
	.vlan = true,
	.igr_noise = true,
	.wan_class = true,
	.egr_tpid = true,
	.anomaly_priv = true,
#ifdef CONFIG_FORTINET_NP4LITE_DSA
	.dsa_offload = true,
#endif
};

static const struct of_device_id fnp4l_of_match[] = {
	{ .compatible = "fortinet,fsoc1-np", .data = &fnp4l_fsoc1_data },
	{ .compatible = "fortinet,fsoc2-np", .data = &fnp4l_fsoc2_data },
	{ }
};
MODULE_DEVICE_TABLE(of, fnp4l_of_match);

/*
 * Close every port and stop the HIF: no NP DMA may target memory the next
 * kernel or the boot loader owns.
 */
static void fnp4l_shutdown(struct platform_device *pdev)
{
	struct fnp4l *np = platform_get_drvdata(pdev);
	unsigned int id;

	fnp4l_tce_stop(np);

	rtnl_lock();
	for (id = 0; id < NP4L_NR_PORTS; id++) {
		struct fnp4l_port *port = np->ports[id];

		if (!port || port->ndev->reg_state != NETREG_REGISTERED)
			continue;
		netif_device_detach(port->ndev);
		dev_close(port->ndev);
	}
	rtnl_unlock();

	/*
	 * The ports back to the default LIF, as the boot loader left
	 * them (its TFTP transfer goes through wan1), and kept there: no
	 * VLAN action table any more.
	 */
	mutex_lock(&np->sse_lock);
	for (id = 0; id < NP4L_NR_PORTS; id++) {
		struct fnp4l_port *port = np->ports[id];

		if (!port || !port->vlan_act_avail)
			continue;
		port->vlan_act_avail = false;
		port->vlan_act_nr = 0;
		spin_lock_bh(&np->tbl_lock);
		fnp4l_igr_restore(port);
		spin_unlock_bh(&np->tbl_lock);
	}
	mutex_unlock(&np->sse_lock);

	fnp4l_teardown(np);
}

/*
 * No remove, no unbind through sysfs and no module_exit: the NP cannot be
 * reset, so once probed the driver stays (the module is permanent).
 */
static struct platform_driver fnp4l_driver = {
	.probe = fnp4l_probe,
	.shutdown = fnp4l_shutdown,
	.driver = {
		.name = DRV_NAME,
		.of_match_table = fnp4l_of_match,
		.suppress_bind_attrs = true,
	},
};

static int __init fnp4l_init(void)
{
	return platform_driver_register(&fnp4l_driver);
}
module_init(fnp4l_init);

MODULE_DESCRIPTION("Fortinet NP4Lite network processor Ethernet driver");
MODULE_LICENSE("GPL");
