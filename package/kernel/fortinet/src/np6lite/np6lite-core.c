// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet NP6Lite network processor: host interface and flow table offload
 *
 * NP6Lite: network processor of the FortiSOC3. This driver only uses what
 * is needed to move frames between the host and the ports directly attached
 * to the network processor:
 *
 *  - the MDIO master of the miscellaneous block (command register 0);
 *  - the host interface (HIF): one host transmit queue (HTX 0) and the host
 *    receive queues (HRX 0..15), with their descriptor rings in host memory;
 *  - the per port MAC and the QSGMII/SGMII PCS of the ports.
 *
 * With CONFIG_FORTINET_NP6LITE_FLOW_OFFLOAD the ports are classified in
 * hardware (class table) and the session search engine (SSE: the flow table
 * engine) forwards the flows of the Linux flow table: see those sections.
 * Everything else (IPsec, the other tables) is left as the boot loader set
 * it.
 *
 * Register layout and values established by observation, for
 * interoperability. Some fields are still inferred rather than documented.
 *
 * The driver cannot be unbound nor unloaded: no reset of the network
 * processor is known, so the state written at probe cannot be undone.
 *
 * Other abbreviations: LIF = logical interface, the index a received frame
 * is classified to and that a flow entry or a transmit descriptor targets;
 * PHT/OFT = primary hash table / overflow table of the SSE; PBA = packet
 * buffer allocator; PDQ = packet buffer queue between two engines; IHP =
 * ingress header processing; EHP = egress header processing; TCE = traffic
 * counter engine.
 *
 * Danger zones (never touched here): random number generator of the
 * miscellaneous block (+0xff80..), NP DDR controller (+0xfb00..), AXI master
 * window (+0xf900..), mailboxes, GPIO 20/22/24 (PHY and switch resets).
 */

#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/hash.h>
#include <linux/hex.h>
#include <linux/if_bridge.h>
#include <linux/iopoll.h>
#include <linux/jhash.h>
#include <linux/log2.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/nvmem-consumer.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/timer.h>
#include <linux/unaligned.h>
#include <linux/ipv6.h>
#include <net/dsa.h>
#include <net/flow_offload.h>
#include <net/ip.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/switchdev.h>
#include <net/pkt_cls.h>

#define DRV_NAME		"fortinet-np6lite"

/* top block */
#define NP6L_STRAP			0x0388
#define NP6L_EGR_SW_QUEUE_EN0		0x3208
#define NP6L_PBA_CTRL			0x3270
#define  NP6L_PBA_CTRL_THRESH		GENMASK(11, 0)
#define  NP6L_PBA_CTRL_XTHRESH		GENMASK(27, 16)
#define NP6L_XG_QUEUE_CTRL		0x7fb8	/* queue control of the 10G port */
#define  NP6L_XG_QUEUE_RX_PBA_MAX	GENMASK(17, 8)
#define  NP6L_XG_QUEUE_TX_PBA_MAX	GENMASK(27, 18)
#define NP6L_HRX_TUNNEL_PDQ		0xa720	/* PDQ from the tunnel engine to HRX */
/* traffic counter engine (TCE): 16 byte counters at base + 16 * index */
#define NP6L_TCE_CTRL			0x7398
#define  NP6L_TCE_CTRL_EN		BIT(4)
#define NP6L_TCE_BASE			0x73a8
/* HTX: parser of the frames sent by the host */
#define NP6L_TBL_HTX_L4_PARSE		0xa180	/* L4 parse table, index = IP protocol */

/* per port MAC, ports 0..9; port = NP link - 1 */
#define NP6L_MAC(p)			(0x9800 + (p) * 0x80)
#define NP6L_MAC_RX_CTRL		0x40
#define  NP6L_MAC_RX_CTRL_GIGA		BIT(0)
#define  NP6L_MAC_RX_CTRL_EN		BIT(1)
#define NP6L_MAC_TX_CTRL		0x48
#define  NP6L_MAC_TX_CTRL_SLOT		GENMASK(9, 0)
#define  NP6L_MAC_TX_CTRL_SPEED		GENMASK(19, 18)
#define  NP6L_MAC_TX_CTRL_EN		BIT(20)
#define  NP6L_MAC_TX_CTRL_FLOW_CTRL	BIT(21)
#define  NP6L_MAC_TX_CTRL_HALF		BIT(22)
#define  NP6L_MAC_TX_CTRL_SGMII		BIT(23)
#define  NP6L_MAC_TX_CTRL_NO_CRC	BIT(31)
#define NP6L_MAC_RX_MAX_LEN		0x50
#define NP6L_MAC_RX_TAG			0x58
#define  NP6L_MAC_RX_PORT_TAG		GENMASK(11, 0)
#define  NP6L_MAC_RX_TAG_RX_PBA_MAX	GENMASK(21, 12)
#define  NP6L_MAC_RX_TAG_TX_PBA_MAX	GENMASK(31, 22)
/* packet buffer queues (PDQ) of a port, of a host receive queue, of HRX */
#define NP6L_MAC_PDQ_BUF_CTRL		0x20
#define NP6L_MAC_PDQ_JUMBO_CTRL		0x28
#define NP6L_MAC_PDQ_QUEUE_CTRL		0x38
#define  NP6L_PDQ_BUF_LIMIT		GENMASK(11, 0)	/* buffer limit, jumbo buffer limit */
#define NP6L_HRXQ_PDQ(q)		(0xc820 + (q) * 0x80)
/* port tag the MAC inserts after the source address when rx_port_tag != 0 */
#define NP6L_PORT_TAG_TPID		0x8200
#define NP6L_NR_MACS			10

/* host queue DMA parameters (burst settings); _INIT: values for every host queue */
#define NP6L_HRXQ_DMA_PARAMS(q)		(0xc868 + (q) * 0x80)
#define NP6L_HRXQ_CTRL(q)		(0xc878 + (q) * 0x80)
#define NP6L_HTXQ_DMA_PARAMS(q)		(0xd068 + (q) * 0x80)
#define NP6L_HTXQ_CTRL(q)		(0xd078 + (q) * 0x80)
#define NP6L_HRXQ_DMA_PARAMS_INIT	0x01010601
#define NP6L_HTXQ_DMA_PARAMS_INIT	0x00010001

/* QSGMII PCS: two blocks of four lanes; port 2..5 = block 0, 6..9 = block 1 */
#define NP6L_QSGMII_PCS_CMD(b)		(0xb180 + (b) * 0x80)
#define  NP6L_QSGMII_PCS_ADDR		GENMASK(6, 0)	/* lane << 5 | register */
#define  NP6L_QSGMII_PCS_WRITE		BIT(8)
#define  NP6L_QSGMII_PCS_START		BIT(9)
#define  NP6L_QSGMII_PCS_DATA		GENMASK(31, 16)
#define NP6L_QSGMII_PCS_ERR_CNT(b)	(0xb188 + (b) * 0x80)
#define NP6L_PCS_STATUS(b, l)		(0xb190 + (b) * 0x80 + (l) * 8)

/* miscellaneous block: MDIO master, GPIO, pin multiplexing */
#define NP6L_MDIO_CFG			0xfbb0
#define NP6L_MDIO_CMD0			0xfbb8
#define NP6L_MDIO_CMD1			0xfbc0
#define  NP6L_MDIO_DATA			GENMASK(15, 0)
#define  NP6L_MDIO_REG			GENMASK(20, 16)
#define  NP6L_MDIO_PHY			GENMASK(25, 21)
#define  NP6L_MDIO_OP			GENMASK(27, 26)	/* 1 = write, 2 = read */
#define  NP6L_MDIO_C22			GENMASK(29, 28)	/* 1 = clause 22 */
#define  NP6L_MDIO_BUSY			BIT(31)
#define NP6L_GPIO_IN			0xfc00
#define NP6L_GPIO_OUT			0xfc08
#define NP6L_GPIO_OE			0xfc10
#define NP6L_GPIO_INT_ENABLE		0xfc30
#define NP6L_GPIO_INT_STATUS		0xfc38
#define NP6L_MAC_TOP_CTRL		0xfc90
#define NP6L_PIN_MUX			0xfca0

/* host queues: HRX queue (NP to host) and HTX queue (host to NP), 16 each */
#define NP6L_NR_QUEUES			16
#define NP6L_HRXQ(q)			(0x10000 + (q) * 0x400)
#define NP6L_HTXQ(q)			(0x14000 + (q) * 0x400)
#define NP6L_Q_RING_BASE		0x000
#define NP6L_Q_RING_BASE_HI		0x008
#define NP6L_Q_WB_BASE			0x010
#define NP6L_Q_WB_BASE_HI		0x018
#define NP6L_Q_RING_SIZE		0x038
#define NP6L_Q_RING_HEAD		0x040
#define NP6L_Q_RING_FETCH		0x048
#define NP6L_Q_RING_DONE		0x050
#define NP6L_Q_RING_PROC		0x058
#define NP6L_Q_CTRL			0x0b8
#define  NP6L_Q_CTRL_EN			BIT(0)
#define  NP6L_Q_CTRL_WB			BIT(1)
#define  NP6L_Q_CTRL_RESET		BIT(2)
#define NP6L_Q_IRQ_FRAMES		0x118
#define NP6L_Q_IRQ_TIMER		0x120
#define NP6L_Q_IRQ_ABS_TIMER		0x128
#define NP6L_Q_IRQ_IDLE_TIMER		0x130
#define NP6L_Q_IRQ_THROTTLE		0x138
/* interrupt moderation of a host queue: frame count 16, timers below */
#define  NP6L_Q_IRQ_FRAMES_INIT		0x00000010
#define  NP6L_Q_IRQ_TIMER_INIT		0x02000002
#define  NP6L_Q_IRQ_ABS_TIMER_INIT	0x02000008
#define  NP6L_Q_IRQ_IDLE_TIMER_INIT	0x02007530
#define  NP6L_Q_IRQ_THROTTLE_INIT	0x02000002
#define NP6L_Q_INT_STATUS		0x200
#define NP6L_Q_INT_ENABLE		0x208
#define NP6L_Q_INT_ENABLE_CLR		0x210
#define  NP6L_Q_INT_TIMER		BIT(0)
#define  NP6L_Q_INT_ABS_TIMER		BIT(1)
#define  NP6L_Q_INT_IDLE_TIMER		BIT(4)
#define  NP6L_Q_INT_FRAMES		BIT(5)
#define  NP6L_Q_INT_VEC_CLR		BIT(7)
#define  NP6L_Q_INT_FATAL		(BIT(10) | BIT(11))

/* descriptors */
#define NP6L_RXD_LEN			GENMASK(29, 16)	/* word 1 */
#define NP6L_TXD1_PORT			GENMASK(13, 8)
#define NP6L_TXD1_FRAME_LEN		GENMASK(31, 16)	/* frame length, tag excluded */
#define NP6L_TXD2_SEG_LEN		GENMASK(15, 0)	/* segment length, tag included */
#define NP6L_TXD2_EOP			BIT(16)
#define NP6L_TXD2_SSE_CMD		BIT(17)	/* command to the session engine, not a frame */
#define NP6L_TXD2_HOST_INIT		(FIELD_PREP(GENMASK(19, 18), 2) | GENMASK(31, 28))
/*
 * Transmit checksum: both bits set when ip_summed == CHECKSUM_PARTIAL,
 * nothing else (no checksum start or offset: the HTX parser finds the
 * headers), for IPv4 and IPv6. Bit 20 = IPv4 header checksum, bit 21 =
 * TCP/UDP checksum. Tested on hardware: bit 21 alone gives the L4 checksum,
 * bit 20 alone gets the frame dropped by the NP; a zero UDP checksum leaves
 * as 0xffff.
 */
#define NP6L_TXD2_CSUM_L3		BIT(20)
#define NP6L_TXD2_CSUM_L4		BIT(21)
#define NP6L_TXD2_CSUM			(NP6L_TXD2_CSUM_L3 | NP6L_TXD2_CSUM_L4)
#define NP6L_WB_DONE			BIT(31)		/* word 1 */
#define NP6L_WB_EOP			BIT(30)		/* word 1 */
#define NP6L_WB_MSG			BIT(0)		/* word 0 */
/*
 * Receive completion word 0: IP header checksum correct (bit 27), TCP/UDP
 * checksum correct (bit 31), IP fragment (bit 26); no error bit in the word.
 * Tested on hardware: bit 27 is never set on an IPv6 frame, bit 31 follows
 * the TCP/UDP checksum on IPv4 and IPv6.
 */
#define NP6L_RXW0_IP_FRAG		BIT(26)
#define NP6L_RXW0_IP_CSUM_OK		BIT(27)
#define NP6L_RXW0_L4_CSUM_OK		BIT(31)

#define NP6L_HTAG_LEN			10
#define NP6L_TX_BLEN_PAGE		BIT(31)
#define NP6L_TX_MAX_DESC		(MAX_SKB_FRAGS + 1)
#define NP6L_RX_BUF			2048
#define NP6L_RXQ_SIZE			128
#define NP6L_TXQ_SIZE			1024	/* room for a burst of frames between two polls */
#define NP6L_MAX_LIF			16
/*
 * LIFs of the boot loader, kept as it sets them (fnp6l_hw_init_tables):
 * LIF 0 is its port LIF and the default LIF of the IGR (a frame the IGR does
 * not classify lands there), LIF 1 its host queue 0, never a port.
 */
#define NP6L_LIF_LOADER			0
#define NP6L_LIF_HOST			1
/* most switch ports behind one conduit (Broadcom tag: ports 0 to 7) */
#define NP6L_SW_PORTS			8
/* class table cells of the switch ports, all conduits (fnp6l_sw_apply_conduit) */
#define NP6L_SW_CELLS			64
#define NP6L_NR_VEC			4	/* HIF vectors 0..3; vector 4 = "err" */

static unsigned int poll_ms = CONFIG_FORTINET_NP6LITE_POLL_MS;
module_param(poll_ms, uint, 0444);
MODULE_PARM_DESC(poll_ms, "poll period in ms (0 = interrupts, with a 100 ms safety poll)");

/*
 * Energy Efficient Ethernet on the PHY of a port. The MAC of the NP has no
 * known Low Power Idle control: it never asks its PHY for LPI, and phylib
 * then expects the MAC driver to keep EEE off (phy_disable_eee()).
 * Advertised, it still lets the link partner put its own transmit side to
 * sleep between bursts, adding its wake time to every burst a window
 * bound TCP flow sends. Off by default, read at each open;
 * "ethtool --set-eee <port> eee on" turns it back on until the next open.
 */
static bool phy_eee;
module_param(phy_eee, bool, 0644);
MODULE_PARM_DESC(phy_eee, "advertise EEE on the PHY of the ports (read at open, default N)");

/*
 * Flow table offload (CONFIG_FORTINET_NP6LITE_FLOW_OFFLOAD). At probe, after
 * the ports are registered and before any of them is opened, the ingress
 * classification posts one class table entry per port toward its own LIF
 * (the reg of its port node; 60E: wan1 -> 0, wan2 -> 2, switch conduit -> 3),
 * keyed by the port tag at the row*4+bank index, and turns the IGR port tag
 * parser on (port tag TPID): the NP6Lite then resolves the ingress port in
 * hardware and strips the port tag, so fnp6l_rx_deliver reads the LIF
 * straight from the host tag. Then the session engine is given its tables,
 * the offload state is applied and the switch ports are classified to their
 * own LIFs; nftables flow tables with "flags offload" over the ports (60E:
 * wan1, wan2), bonds of switch ports and bare switch ports are then
 * forwarded by the NP.
 * Without the Kconfig option the driver keeps the port tag path and
 * offloads nothing.
 */

struct fnp6l_ring {
	void __iomem *regs;
	unsigned int idx;
	unsigned int size;
	bool tx;
	__le32 *desc;		/* rx: 2 words, tx: 4 words per entry */
	dma_addr_t desc_dma;
	__le32 *wb;		/* write-back area, 2 words per entry */
	dma_addr_t wb_dma;
	struct sk_buff **skb;	/* tx: on the last descriptor of the frame */
	dma_addr_t *buf;
	u32 *blen;		/* tx: mapped length, NP6L_TX_BLEN_PAGE for a fragment */
	unsigned int head;	/* next entry to complete */
	unsigned int tail;	/* next entry to fill */
	bool drop_seg;		/* rx: discard until end of frame */
};

struct fnp6l;

/*
 * One per HIF interrupt vector v: the receive queues q with q mod 4 == v
 * (source to vector table) and, for vector 0, the transmit queue.
 */
struct fnp6l_vec {
	struct fnp6l *np;
	struct napi_struct napi;
	unsigned int idx;
	unsigned long qmask;	/* receive queues */
	bool tx;		/* transmit queue 0 completions */
	int irq;
	u64 rx_pkts, rx_unknown_lif, rx_msg, rx_seg_drop, rx_nomem;
	u64 rx_csum_ok4, rx_csum_ok6, rx_csum_none;	/* fnp6l_rx_csum */
};

struct fnp6l_port {
	struct fnp6l *np;
	struct net_device *ndev;
	struct device_node *dn;
	phy_interface_t phy_mode;
	u32 lif;
	u32 link;		/* NP link, 1-based; MAC port = link - 1 */
	int speed;
	int duplex;		/* with speed: the MAC follows both */
	bool conduit;		/* DSA conduit: a switch CPU port points at it */
	/*
	 * Conduit: LIF of each switch port, by port number, 0 = none
	 * ("fortinet,switch-logical-interfaces"); sw_nports entries, 0 when
	 * the switch ports are not classified.
	 */
	unsigned int sw_nports;
	u8 sw_lif[NP6L_SW_PORTS];
};

struct fnp6l_mdio {
	struct fnp6l *np;
	int mdc_pin;		/* pin mux bit and NP GPIO of its MDC, -1 = none */
};

#define NP6L_FT_MSGTYPES		16	/* NP messages counted by header byte 0, 3:0 */
#define NP6L_FT_MSGHDR			24	/* header + key of the last unmatched message */
#define NP6L_FT_DELKEYS			256	/* keys of the last sessions deleted */
#define NP6L_FT_DELKEY_LEN		16	/* = NP6L_SSE_KEY4_LEN */
#define NP6L_FT_DEAD_RETRY_MS		20	/* undeleted flows: next try */
/*
 * Indexes of the flows by cookie and of their sessions by key: 1 << bits
 * buckets each, sized at probe (ft_hash_bits). A lookup walks one bucket:
 * with a fixed 2048 buckets each, at 196608 flows, every STATS and every
 * query reply walked about a hundred entries.
 */
#define NP6L_FT_HBITS_DEF		16	/* 65536 buckets: 256 KiB each (32-bit) */
#define NP6L_FT_HBITS_MIN		11
#define NP6L_FT_HBITS_MAX		20
#define NP6L_FT_BHASH_BITS		10	/* flows given back, by cookie */
#define NP6L_FT_BACK_MS			1000	/* given back: first offer again after */
#define NP6L_FT_BACK_SHIFT_MAX		6	/* then doubled up to 64 s */

struct fnp6l {
	struct device *dev;
	void __iomem *base;
	struct mii_bus *mii;
	struct mii_bus *mii_sw;
	spinlock_t mdio_lock;	/* MDIO command register 0, pin mux */
	u32 loader_ring_hi, loader_qctrl;	/* host queue 0 as the loader left it */
	spinlock_t tx_lock;
	struct fnp6l_ring rx[NP6L_NR_QUEUES];
	struct fnp6l_ring tx;
	unsigned long rx_mask;
	u32 addr_hi;
	struct net_device *napi_dev;
	struct fnp6l_vec vec[NP6L_NR_VEC];
	unsigned int nvec;
	struct timer_list poll_timer;
	bool use_irq;
	unsigned int nports;
	struct fnp6l_port *port[NP6L_MAX_LIF];
	u64 tx_csum_hw, tx_csum_hw6, tx_csum_sw, tx_sg;
	bool htx_l4_parse_done;
	bool sse_done;
	/* ingress classification: each port to its own LIF via class table */
	bool ic_on;
	u8 ic_idx[NP6L_MAX_LIF];	/* class table indices to clear on failure */
	unsigned int ic_nidx;
	u32 ic_saved_port_tag_tpid;
	u64 ic_port_tag_fallback;	/* frames still carrying a port tag (classification miss) */
	struct fnp6l_ring cmdq;	/* session commands */
	u8 *cmd_buf;
	dma_addr_t cmd_dma;
	bool cmdq_on;		/* command queue started (buffers kept on failure) */
	/*
	 * fatal error interrupts of the host queues: seen, acknowledged by
	 * writing the status bits back, masked on a queue whose status stays
	 * set after the acknowledgement (no interrupt storm)
	 */
	u64 err_fatal;
	unsigned long fatal_masked;	/* bit q: HRX queue q; bit 16: HTX queue */
	/* done index last seen, since when (ns), and whether it is stuck */
	unsigned int cmd_seen;
	u64 cmd_seen_ns;
	bool cmd_stalled;
	/*
	 * session commands (fnp6l_sse_lock): posted; posts that found the
	 * queue full (waits, time spun, longest spin); sleeps (none since
	 * commands are never waited for); posts refused on a full queue;
	 * stalls of the done index and the longest one seen (upper bound);
	 * queries skipped on a nearly full queue
	 */
	unsigned long sse_cmds, sse_waits, sse_sleeps, sse_full, sse_tmo;
	u64 sse_wait_us;
	u32 sse_wait_max_us, sse_stall_max_ms;
	unsigned long sse_qskip;
	unsigned long sse_iskip;	/* inserts refused: room kept for deletes */
	/* session table: buckets of the PHT and the OFT (read at probe) */
	u32 sse_pht_n, sse_oft_n;
	/*
	 * Admission of new flows (see fnp6l_ft_admit): the OFT free count
	 * read at oft_j and the sessions posted since (fnp6l_sse_lock, read
	 * without it for the early refusal), refusals by cause.
	 */
	u32 oft_free;
	unsigned int oft_posted;
	unsigned long oft_j, oft_reads;
	bool oft_valid;
	atomic_long_t ft_ref_oft, ft_ref_guard, ft_ref_max;
	/*
	 * Inserts the engine refused (fnp6l_sse_lock): the gap INSERTS -
	 * INSERTS_OK at engine init; at the last sample (command queue
	 * drained) INSERTS and the gap; the refusals counted (np_refused,
	 * see fnp6l_ft_cap_read), those not yet matched to a flow
	 * (np_credit); flows given back to the software flow table.
	 */
	u32 ins_gap0, ins_last, ins_gap_last, np_refused, np_credit;
	unsigned long ins_gap_j;
	bool ins_gap_have;
	unsigned long ft_back, ft_back_sess;
	/*
	 * Flows given back, by cookie, until their DESTROY (ft_sess_lock;
	 * fnp6l_ft_back_*): how many, offers refused while the engine has no
	 * room, given-back flows admitted again; deletes not posted for
	 * sessions the engine refused; offers refused while a live flow held
	 * one of their keys (fnp6l_sse_lock).
	 */
	struct hlist_head ft_bhash[1 << NP6L_FT_BHASH_BITS];
	struct list_head ft_backl;
	unsigned int ft_nback;
	atomic_long_t ft_ref_back;
	unsigned long ft_back_again, ft_del_skip, ft_keybusy;
	/* query replies that found no session (ft_sess_lock) */
	unsigned long ft_qmiss;
	/* flow table offload: see its section */
	bool ft_on;			/* the offload state is applied */
	struct list_head ft_flows;	/* offloaded flows */
	struct hlist_head *ft_chash;	/* the same, by cookie (1 << ft_hbits) */
	unsigned int ft_hbits;		/* both indexes, fixed at probe */
	unsigned int ft_nflows;
	/* flows whose delete failed: still in the engine, deleted again later */
	struct list_head ft_dead;
	unsigned int ft_ndead;
	unsigned long ft_delfail, ft_dfree, ft_lagfail;
	struct delayed_work ft_dead_work;
	/* DESTROY and STATS of a cookie we do not track (ft_sess_lock) */
	unsigned long ft_unk_destroy, ft_unk_stats;
	/* per-flow activity by session query replies */
	spinlock_t ft_sess_lock;	/* ft_hash, session snapshots, lastused, q* */
	struct hlist_head *ft_hash;	/* sessions by key (1 << ft_hbits) */
	/* STATS answered under ft_sess_lock alone, or with the command lock */
	unsigned long ft_sfast, ft_sslow;
	unsigned long ft_qsent, ft_qreply, ft_qmatch, ft_qchange, ft_qdrop;
	int ft_qoff;			/* key offset in the replies, -1: unseen */
	/* NP messages that are no reply to a query of ours (ft_sess_lock) */
	unsigned long ft_qnomatch, ft_msgtype[NP6L_FT_MSGTYPES];
	u8 ft_msghdr[NP6L_FT_MSGHDR];
	unsigned int ft_msghdr_len;
	/* messages by header byte 1 (3:0); unmatched ones whose key is one of
	 * the last NP6L_FT_DELKEYS session keys deleted (ft_sess_lock) */
	unsigned long ft_msgop[NP6L_FT_MSGTYPES], ft_qnomatch_del;
	u8 ft_delkey[NP6L_FT_DELKEYS][NP6L_FT_DELKEY_LEN];
	unsigned int ft_ndelkey;
	struct notifier_block ft_nb;	/* bond member changes (switch ports) */
	struct delayed_work ft_lag_work;
	unsigned int ft_lag_again;
	/* bridge_offload: stations learnt or forgotten on a bridged port */
	struct notifier_block ft_fdb_nb;
	struct work_struct ft_fdb_work;
	spinlock_t ft_fdb_lock;
	struct net_device *ft_fdb_dev[8];	/* held, with their address */
	u8 ft_fdb_addr[8][ETH_ALEN];
	bool ft_fdb_del[8];			/* entry forgets the station */
	unsigned int ft_fdb_n;
	bool ft_fdb_lost;			/* ring full: every bridged LIF */
	unsigned long ft_fdb_moves;		/* LIFs whose flows were torn down */
	struct fnp6l_ft_save {
		u32 tbl, idx, d[4];	/* a saved table entry */
	} ft_save[32];
	unsigned int ft_nsave;
	/* switch-port classification: see its section */
	bool sw_on;
	u8 sw_idx[NP6L_SW_CELLS];	/* class table indices to clear on failure */
	unsigned int sw_nidx;
	struct fnp6l_ft_save sw_save[6 * NP6L_MAX_LIF];	/* 6 tables per switch-port LIF */
	unsigned int sw_nsave;
	unsigned int sw_rb_bad;		/* switch-port LIF entries read back different */
	u64 sw_rx_retag;		/* frames given back their Broadcom tag */
	/* switch-port LIF -> its conduit and switch port (fnp6l_sw_map) */
	struct fnp6l_port *sw_conduit[NP6L_MAX_LIF];
	u8 sw_port[NP6L_MAX_LIF];
};

static inline u32 fnp6l_rd(struct fnp6l *np, u32 off)
{
	return readl(np->base + off);
}

static inline void fnp6l_wr(struct fnp6l *np, u32 off, u32 val)
{
	writel(val, np->base + off);
}

/* ---------------------------------------------------------------- MDIO */

static int fnp6l_mdio_wait(struct fnp6l *np, u32 *val)
{
	return readl_poll_timeout_atomic(np->base + NP6L_MDIO_CMD0, *val,
					 !(*val & NP6L_MDIO_BUSY), 1, 10000);
}

/*
 * A board may have two MDC lines sharing the MDIO data line, each on an NP
 * GPIO (fortinet,mdc-pin of each MDIO bus). Bit <pin> of the pin mux gives
 * the pin to the MDIO master for one access; between accesses it is a GPIO
 * held high.
 */
static int fnp6l_mdio_op_pin(struct fnp6l *np, int pin, int op, int phy, int reg,
			     u16 data)
{
	unsigned long flags;
	u32 v;
	int ret;

	spin_lock_irqsave(&np->mdio_lock, flags);
	if (pin >= 0)
		fnp6l_wr(np, NP6L_PIN_MUX, fnp6l_rd(np, NP6L_PIN_MUX) | BIT(pin));
	ret = fnp6l_mdio_wait(np, &v);
	if (ret)
		goto out;
	writel(FIELD_PREP(NP6L_MDIO_C22, 1) | FIELD_PREP(NP6L_MDIO_OP, op) |
	       FIELD_PREP(NP6L_MDIO_PHY, phy) | FIELD_PREP(NP6L_MDIO_REG, reg) |
	       FIELD_PREP(NP6L_MDIO_DATA, data), np->base + NP6L_MDIO_CMD0);
	ret = fnp6l_mdio_wait(np, &v);
	if (!ret && op == 2)
		ret = FIELD_GET(NP6L_MDIO_DATA, v);
out:
	if (pin >= 0) {
		fnp6l_wr(np, NP6L_PIN_MUX, fnp6l_rd(np, NP6L_PIN_MUX) & ~BIT(pin));
		fnp6l_wr(np, NP6L_GPIO_OUT, BIT(pin));	/* set */
	}
	spin_unlock_irqrestore(&np->mdio_lock, flags);
	return ret;
}

static int fnp6l_mdio_read(struct mii_bus *bus, int phy, int reg)
{
	struct fnp6l_mdio *m = bus->priv;

	return fnp6l_mdio_op_pin(m->np, m->mdc_pin, 2, phy, reg, 0);
}

static int fnp6l_mdio_write(struct mii_bus *bus, int phy, int reg, u16 val)
{
	struct fnp6l_mdio *m = bus->priv;

	return fnp6l_mdio_op_pin(m->np, m->mdc_pin, 1, phy, reg, val);
}

/* BCM53128 register read through its pseudo-PHY (as b53_mdio does) */
static int fnp6l_b53_read32(struct fnp6l *np, int pin, u8 page, u8 reg, u32 *val)
{
	int i, v, lo, hi;

	if (fnp6l_mdio_op_pin(np, pin, 1, 30, 16, page << 8 | 1) ||
	    fnp6l_mdio_op_pin(np, pin, 1, 30, 17, reg << 8 | 2))
		return -EIO;
	for (i = 0; i < 5; i++) {
		v = fnp6l_mdio_op_pin(np, pin, 2, 30, 17, 0);
		if (v >= 0 && !(v & 3))
			break;
	}
	if (i == 5)
		return -ETIMEDOUT;
	lo = fnp6l_mdio_op_pin(np, pin, 2, 30, 24, 0);
	hi = fnp6l_mdio_op_pin(np, pin, 2, 30, 25, 0);
	if (lo < 0 || hi < 0)
		return -EIO;
	*val = hi << 16 | lo;
	return 0;
}

/* GPIO block of the NP: +0x08/+0x48 output set/clear, +0x10/+0x50 dir set/clear */
#define NP6L_GPIO_OUT_CLR		0xfc48

/*
 * PHY and switch reset lines (fortinet,reset-pins): GPIO outputs driven low
 * for 100 ms, then high, 40 ms to settle. The loader may leave some of them
 * low, holding a PHY or the switch in reset.
 */
static void fnp6l_release_resets(struct fnp6l *np, u32 mask)
{
	if (!mask)
		return;
	dev_info(np->dev, "GPIO resets %#x: low 100 ms, then high\n", mask);
	fnp6l_wr(np, NP6L_GPIO_OUT_CLR, mask);
	fnp6l_wr(np, NP6L_GPIO_OE, mask);
	msleep(100);
	fnp6l_wr(np, NP6L_GPIO_OUT, mask);
	msleep(40);
}

/* MDC pins as GPIO outputs held high, pin mux bits cleared */
static void fnp6l_mdc_pins_init(struct fnp6l *np, u32 mask)
{
	if (!mask)
		return;
	fnp6l_wr(np, NP6L_GPIO_OUT, mask);
	fnp6l_wr(np, NP6L_GPIO_OE, mask);
	fnp6l_wr(np, NP6L_PIN_MUX, fnp6l_rd(np, NP6L_PIN_MUX) & ~mask);
}

static void fnp6l_mdio_scan(struct fnp6l *np, const char *name, int pin)
{
	int a, i1, i2;
	u32 id;

	for (a = 0; a < PHY_MAX_ADDR; a++) {
		i1 = fnp6l_mdio_op_pin(np, pin, 2, a, MII_PHYSID1, 0);
		i2 = fnp6l_mdio_op_pin(np, pin, 2, a, MII_PHYSID2, 0);
		if (i1 < 0 || i2 < 0 || (i1 == 0xffff && i2 == 0xffff) ||
		    (!i1 && !i2))
			continue;
		dev_info(np->dev, "%s (MDC %d): addr %2d id %04x:%04x bmsr %#06x\n",
			 name, pin, a, i1, i2,
			 fnp6l_mdio_op_pin(np, pin, 2, a, MII_BMSR, 0));
	}
	if (!fnp6l_b53_read32(np, pin, 0x02, 0x30, &id))
		dev_info(np->dev, "%s (MDC %d): pseudo-PHY 30 page 02h reg 30h (device id) %#x\n",
			 name, pin, id);
}

/* ------------------------------------------------------- PCS and MAC port */

static int fnp6l_pcs_access(struct fnp6l *np, unsigned int blk, unsigned int lane,
			    unsigned int reg, bool wr, u16 data)
{
	u32 v = FIELD_PREP(NP6L_QSGMII_PCS_ADDR, lane << 5 | reg) | NP6L_QSGMII_PCS_START;

	if (wr)
		v |= NP6L_QSGMII_PCS_WRITE | FIELD_PREP(NP6L_QSGMII_PCS_DATA, data);
	fnp6l_wr(np, NP6L_QSGMII_PCS_CMD(blk), v);
	/* the start bit may or may not clear: data read back after a short poll */
	readl_poll_timeout_atomic(np->base + NP6L_QSGMII_PCS_CMD(blk), v,
				  !(v & NP6L_QSGMII_PCS_START), 1, 100);
	return FIELD_GET(NP6L_QSGMII_PCS_DATA, v);
}

/* SGMII set-up of the PCS lane of one port: reset, then SGMII and autonegotiation */
static int fnp6l_pcs_init(struct fnp6l *np, unsigned int port)
{
	unsigned int blk, lane, i;

	if (port < 2 || port >= NP6L_NR_MACS)
		return -EINVAL;
	blk = (port - 2) / 4;
	lane = (port - 2) % 4;

	fnp6l_pcs_access(np, blk, lane, 0,
			 true, fnp6l_pcs_access(np, blk, lane, 0, false, 0) | BIT(15));
	for (i = 0; i < 1000; i++) {
		if (!(fnp6l_pcs_access(np, blk, lane, 0, false, 0) & BIT(15)))
			break;
		udelay(10);
	}
	if (i == 1000)
		dev_warn(np->dev, "PCS %u.%u: reset does not complete\n", blk, lane);
	fnp6l_pcs_access(np, blk, lane, 0x12, true, 0x0d40);
	fnp6l_pcs_access(np, blk, lane, 0x13, true, 0x0003);
	fnp6l_pcs_access(np, blk, lane, 0x14, true, 0x0053);
	fnp6l_pcs_access(np, blk, lane, 0x04, true, 0x0001);	/* SGMII */
	fnp6l_pcs_access(np, blk, lane, 0x00, true, 0x1340);	/* AN restart */
	return 0;
}

/* RX/TX control and maximum length of the MAC of one port */
static void fnp6l_mac_init(struct fnp6l *np, unsigned int port)
{
	u32 rx, tx;

	rx = fnp6l_rd(np, NP6L_MAC(port) + NP6L_MAC_RX_CTRL);
	rx &= ~(GENMASK(3, 0) | GENMASK(26, 24) | BIT(31));
	rx |= NP6L_MAC_RX_CTRL_GIGA | NP6L_MAC_RX_CTRL_EN;
	if (port < 2)
		rx |= BIT(31);	/* receive enable of the RGMII ports */

	tx = fnp6l_rd(np, NP6L_MAC(port) + NP6L_MAC_TX_CTRL);
	tx &= ~(NP6L_MAC_TX_CTRL_SLOT | NP6L_MAC_TX_CTRL_SPEED | NP6L_MAC_TX_CTRL_FLOW_CTRL |
		NP6L_MAC_TX_CTRL_HALF | NP6L_MAC_TX_CTRL_SGMII | NP6L_MAC_TX_CTRL_NO_CRC);
	tx |= FIELD_PREP(NP6L_MAC_TX_CTRL_SLOT, 0x40) | FIELD_PREP(NP6L_MAC_TX_CTRL_SPEED, 2) |
	      NP6L_MAC_TX_CTRL_EN;
	if (port > 1)
		tx |= NP6L_MAC_TX_CTRL_SGMII;

	fnp6l_wr(np, NP6L_MAC(port) + NP6L_MAC_RX_CTRL, rx);
	fnp6l_wr(np, NP6L_MAC(port) + NP6L_MAC_TX_CTRL, tx);
	fnp6l_wr(np, NP6L_MAC(port) + NP6L_MAC_RX_MAX_LEN, 0x40000014);
	/*
	 * The loader classifies every port to LIF 0 (default LIF, no class
	 * table entry): frames of wan2 reached wan1. Give each port a port tag
	 * ((port + 1) << 4); the MAC then inserts 82 00 00 yy after the source
	 * address, and the host uses it to find the ingress port (or, with
	 * the flow offload, the IGR consumes it to classify the port).
	 */
	fnp6l_wr(np, NP6L_MAC(port) + NP6L_MAC_RX_TAG,
		 (fnp6l_rd(np, NP6L_MAC(port) + NP6L_MAC_RX_TAG) & ~NP6L_MAC_RX_PORT_TAG) |
		 FIELD_PREP(NP6L_MAC_RX_PORT_TAG, (port + 1) << 4));
}

static void fnp6l_adjust_link(struct net_device *ndev)
{
	struct fnp6l_port *p = netdev_priv(ndev);
	struct phy_device *phy = ndev->phydev;
	unsigned int port = p->link - 1;
	u32 rx, tx, spd;

	if (!phy->link || (phy->speed == p->speed && phy->duplex == p->duplex))
		goto out;
	p->speed = phy->speed;
	p->duplex = phy->duplex;
	/* inferred: 0 = 10, 1 = 100, 2 = 1000 (2 at init) */
	spd = phy->speed == SPEED_1000 ? 2 : phy->speed == SPEED_100 ? 1 : 0;
	rx = fnp6l_rd(p->np, NP6L_MAC(port) + NP6L_MAC_RX_CTRL);
	tx = fnp6l_rd(p->np, NP6L_MAC(port) + NP6L_MAC_TX_CTRL);
	rx = (rx & ~NP6L_MAC_RX_CTRL_GIGA) | (spd == 2 ? NP6L_MAC_RX_CTRL_GIGA : 0);
	tx = (tx & ~(NP6L_MAC_TX_CTRL_SPEED | NP6L_MAC_TX_CTRL_HALF)) |
	     FIELD_PREP(NP6L_MAC_TX_CTRL_SPEED, spd) |
	     (phy->duplex == DUPLEX_HALF ? NP6L_MAC_TX_CTRL_HALF : 0);
	fnp6l_wr(p->np, NP6L_MAC(port) + NP6L_MAC_RX_CTRL, rx);
	fnp6l_wr(p->np, NP6L_MAC(port) + NP6L_MAC_TX_CTRL, tx);
out:
	phy_print_status(phy);
}

/* ------------------------------------------ state left by the boot loader */

/* logged at probe, before anything is written (reads only) */

static void fnp6l_dump_ring_mem(struct fnp6l *np, const char *what, u64 addr,
				unsigned int words)
{
	void *va;
	unsigned int i;
	u32 w[8];

	if (!addr || addr >> 32 || words > ARRAY_SIZE(w))
		return;
	if (!pfn_valid(PHYS_PFN(addr))) {
		dev_info(np->dev, "  %s %#llx: outside Linux memory\n", what, addr);
		return;
	}
	dev_warn(np->dev, "  %s %#llx: INSIDE Linux memory (loader DMA target)\n",
		 what, addr);
	va = memremap(addr, words * 4, MEMREMAP_WB);
	if (!va)
		return;
	for (i = 0; i < words; i++)
		w[i] = READ_ONCE(((u32 *)va)[i]);
	memunmap(va);
	dev_info(np->dev, "  %s: %*ph\n", what, words * 4, w);
}

static void fnp6l_dump_queue(struct fnp6l *np, const char *name, unsigned int q,
			     u32 off)
{
	u32 ring_base = fnp6l_rd(np, off + NP6L_Q_RING_BASE),
	    ring_hi = fnp6l_rd(np, off + NP6L_Q_RING_BASE_HI);
	u32 wb_base = fnp6l_rd(np, off + NP6L_Q_WB_BASE),
	    wb_hi = fnp6l_rd(np, off + NP6L_Q_WB_BASE_HI);
	u32 dev = fnp6l_rd(np, off + NP6L_Q_CTRL);

	if (!ring_base && !wb_base && !dev && !fnp6l_rd(np, off + NP6L_Q_RING_SIZE))
		return;
	dev_info(np->dev,
		 "%s%u: ring %02x:%08x wb %02x:%08x size %u head %u fetch %u done %u proc %u ctrl %#x int_status %#x int_enable %#x irq_frames %#x irq_timer %#x\n",
		 name, q, ring_hi, ring_base, wb_hi, wb_base, fnp6l_rd(np, off + NP6L_Q_RING_SIZE),
		 fnp6l_rd(np, off + NP6L_Q_RING_HEAD), fnp6l_rd(np, off + NP6L_Q_RING_FETCH),
		 fnp6l_rd(np, off + NP6L_Q_RING_DONE), fnp6l_rd(np, off + NP6L_Q_RING_PROC), dev,
		 fnp6l_rd(np, off + NP6L_Q_INT_STATUS), fnp6l_rd(np, off + NP6L_Q_INT_ENABLE),
		 fnp6l_rd(np, off + NP6L_Q_IRQ_FRAMES), fnp6l_rd(np, off + NP6L_Q_IRQ_TIMER));
	if (dev & NP6L_Q_CTRL_EN) {
		/*
		 * Bits 39:32 are an attribute (0x01 loader, 0x27 through the
		 * ACP); any other value is a stale register, not a DMA target.
		 * The write-back area of a transmit queue is only used with its
		 * write-back enable bit.
		 */
		if (ring_hi == 0x01 || ring_hi == 0x27 || !ring_hi)
			fnp6l_dump_ring_mem(np, "ring", ring_base, 8);
		else
			dev_info(np->dev, "  ring %02x:%08x: unknown attribute, stale\n",
				 ring_hi, ring_base);
		if ((off < NP6L_HTXQ(0) || (dev & NP6L_Q_CTRL_WB)) &&
		    (wb_hi == 0x01 || wb_hi == 0x27 || !wb_hi))
			fnp6l_dump_ring_mem(np, "wb", wb_base, 4);
	}
}

static void fnp6l_probe_dump(struct fnp6l *np)
{
	unsigned int i;

	dev_info(np->dev,
		 "strap %#x pba_ctrl %#x mac_top_ctrl %#x pin_mux %#x egr_sw_queue_en0 %#x\n",
		 fnp6l_rd(np, NP6L_STRAP), fnp6l_rd(np, NP6L_PBA_CTRL),
		 fnp6l_rd(np, NP6L_MAC_TOP_CTRL), fnp6l_rd(np, NP6L_PIN_MUX),
		 fnp6l_rd(np, NP6L_EGR_SW_QUEUE_EN0));
	dev_info(np->dev, "mdio cfg %#x cmd0 %#x cmd1 %#x\n",
		 fnp6l_rd(np, NP6L_MDIO_CFG), fnp6l_rd(np, NP6L_MDIO_CMD0),
		 fnp6l_rd(np, NP6L_MDIO_CMD1));
	dev_info(np->dev, "gpio in %#x out %#x dir %#x int_enable %#x int_status %#x\n",
		 fnp6l_rd(np, NP6L_GPIO_IN), fnp6l_rd(np, NP6L_GPIO_OUT),
		 fnp6l_rd(np, NP6L_GPIO_OE), fnp6l_rd(np, NP6L_GPIO_INT_ENABLE),
		 fnp6l_rd(np, NP6L_GPIO_INT_STATUS));
	for (i = 0; i < NP6L_NR_MACS; i++)
		dev_info(np->dev, "mac%u rx_ctrl %#x tx_ctrl %#x rx_max_len %#x\n", i,
			 fnp6l_rd(np, NP6L_MAC(i) + NP6L_MAC_RX_CTRL),
			 fnp6l_rd(np, NP6L_MAC(i) + NP6L_MAC_TX_CTRL),
			 fnp6l_rd(np, NP6L_MAC(i) + NP6L_MAC_RX_MAX_LEN));
	for (i = 0; i < 2; i++)
		dev_info(np->dev,
			 "qsgmii_pcs%u cmd %#x err_cnt %#x status %#x %#x %#x %#x\n",
			 i, fnp6l_rd(np, NP6L_QSGMII_PCS_CMD(i)),
			 fnp6l_rd(np, NP6L_QSGMII_PCS_ERR_CNT(i)),
			 fnp6l_rd(np, NP6L_PCS_STATUS(i, 0)),
			 fnp6l_rd(np, NP6L_PCS_STATUS(i, 1)),
			 fnp6l_rd(np, NP6L_PCS_STATUS(i, 2)),
			 fnp6l_rd(np, NP6L_PCS_STATUS(i, 3)));
	for (i = 0; i < NP6L_NR_QUEUES; i++)
		dev_info(np->dev, "hostq%u rx dma_params %#x ctrl %#x tx dma_params %#x ctrl %#x\n",
			 i, fnp6l_rd(np, NP6L_HRXQ_DMA_PARAMS(i)), fnp6l_rd(np, NP6L_HRXQ_CTRL(i)),
			 fnp6l_rd(np, NP6L_HTXQ_DMA_PARAMS(i)), fnp6l_rd(np, NP6L_HTXQ_CTRL(i)));
	for (i = 0; i < NP6L_NR_QUEUES; i++)
		fnp6l_dump_queue(np, "hrxq", i, NP6L_HRXQ(i));
	for (i = 0; i < NP6L_NR_QUEUES; i++)
		fnp6l_dump_queue(np, "htxq", i, NP6L_HTXQ(i));
}

static int fnp6l_queue_reset(struct fnp6l *np, u32 off)
{
	u32 v;
	int ret;

	writel(NP6L_Q_CTRL_RESET, np->base + off + NP6L_Q_CTRL);
	ret = readl_poll_timeout(np->base + off + NP6L_Q_CTRL, v, !(v & NP6L_Q_CTRL_RESET),
				 10, 10000);
	if (ret)
		dev_warn(np->dev, "queue %#x: reset does not complete (%#x)\n",
			 off, v);
	return ret;
}

/*
 * The loader leaves the traffic counter engine enabled with its counter base
 * at 0: its counters (64-bit bytes and packets, added every 255 packets or
 * 64 KiB) land in the first page of Linux memory. Move them to the base given
 * by the device tree (outside Linux memory).
 */
static void fnp6l_tce_init(struct fnp6l *np)
{
	u32 ctrl = fnp6l_rd(np, NP6L_TCE_CTRL), base = fnp6l_rd(np, NP6L_TCE_BASE), v;

	if (of_property_read_u32(np->dev->of_node, "fortinet,tce-base", &v)) {
		if (ctrl & NP6L_TCE_CTRL_EN)
			dev_warn(np->dev, "TCE enabled, counter base %#x left as is\n",
				 base);
		return;
	}
	fnp6l_wr(np, NP6L_TCE_BASE, v);
	dev_info(np->dev, "TCE (ctrl %#x): counter base %#x -> %#x\n", ctrl,
		 base, fnp6l_rd(np, NP6L_TCE_BASE));
}

/* stop every host queue (and the loader's DMA into host memory) */
static void fnp6l_stop_all_queues(struct fnp6l *np)
{
	unsigned int q;

	for (q = 0; q < NP6L_NR_QUEUES; q++) {
		fnp6l_queue_reset(np, NP6L_HRXQ(q));
		fnp6l_queue_reset(np, NP6L_HTXQ(q));
	}
}

/* ---------------------------------------- indirect tables (table access) */

/*
 * Table access port of the NP: command register (index 29:0, write bit 30,
 * busy bit 31), then data words lo/hi/x/y at +8/+0x10/+0x18/+0x20. An
 * indirect table read or write goes through the data registers.
 */
#define NP6L_TBL_EGR_TAG		0x0c80	/* tags inserted on output, by LIF */
#define NP6L_TBL_PORT_ACTION		0x2000	/* source/target actions, by LIF */
#define NP6L_TBL_LIF_MAC		0x2400	/* MAC address entry, by LIF */
#define NP6L_TBL_TRUNK_CFG		0x3480	/* egress trunk config (MTU...) */
#define NP6L_TBL_LIF_CFG		0x3500	/* output config of a LIF (source MAC, port) */
#define NP6L_TBL_TRUNK_MEMBERS		0x3580	/* ports of a trunk */
#define NP6L_TBL_PORT_TRUNK		0x3600	/* trunk of a port */
#define NP6L_TBL_CMD_WRITE		BIT(30)
#define NP6L_TBL_CMD_BUSY		BIT(31)

/*
 * Class table: hashed table, accessed through the same table access layout
 * as the linear tables (entries at 0x800, chain pointers at 0xa00). The
 * cell is the 16 byte key {w0, w1, 0, 0}; LIF and valid bit live in the key
 * words (see fnp6l_class_key). Hash size 0x007f0040 => 64 buckets, mask 0x7f.
 */
#define NP6L_TBL_CLASS			0x0800	/* class table entries */
#define NP6L_TBL_CLASS_CHAIN		0x0a00	/* chain pointers */
/*
 * TCE map, VLAN action and (port, protocol) source tables, each with its
 * chain pointers: hashed tables cleared at boot
 */
#define NP6L_TBL_TCE_MAP		0x7080
#define NP6L_TBL_TCE_CHAIN		0x7280
#define NP6L_TBL_VLAN_ACT		0x2080
#define NP6L_TBL_VLAN_ACT_CHAIN		0x2280
#define NP6L_TBL_PROTO_SRC		0x2a00
#define NP6L_TBL_PROTO_SRC_CHAIN	0x2c00
#define NP6L_CLASS_HASH_SIZE		0x0a38
#define NP6L_CLASS_BUCKETS		64
#define NP6L_CLASS_BANKS		4	/* cells per hash row: idx = row*4 + bank */
#define NP6L_CLASS_IDX_MASK		0x7f
#define NP6L_CLASS_VALID		BIT(2)	/* w1 bit 2 */
#define NP6L_IGR_TAG2_TPID		0x0c00	/* second tag TPID, global */
#define  NP6L_IGR_TAG2_TPID_BRCM	0x00010000	/* TPID 0x0000 + valid = Broadcom tag */
/*
 * EGR egress tag (switch ports): egress tag control [LIF]
 * bit 30 inserts the second tag, TPID from NP6L_EGR_TAG2 (0xd08, byte << 8),
 * TCI bits 15:0 (0x40005fa2 with a TPID byte of 0x82 = 802.1Q 0x8200 VID
 * 0xfa2 to the switch). With a TPID byte of 0x20 and TCI = BIT(port) the EGR
 * inserts the Broadcom directed-egress tag 20 00 00 BIT(p) b53 expects on the
 * IMP. No other LIF of ours has the tag control set, so NP6L_EGR_TAG2 is
 * free. The MAC VLAN register 0x7fc0 is NOT this TPID (it carries the port
 * tag: changing it stops all output).
 */
#define NP6L_EGR_TAG2			0x0d08
#define  NP6L_EGR_TAG2_BRCM		0x00000020	/* TPID 0x2000: opcode 1, TC 0 */
#define NP6L_EGR_TAG_CTRL_TAG2		BIT(30)
#define NP6L_IGR_PORT_TAG_TPID		0x0c08	/* port tag TPID, global */
/*
 * 802.1Q TPID of the IGR, valid | EtherType>>8 (0x10081 for 802.1Q),
 * 0 under the loader: a tagged frame is then never parsed past its tag (no
 * SSE lookup). Set, the tag is pulled into in_vid of the key and handed to
 * the host in the descriptor.
 */
#define NP6L_IGR_VLAN_TPID		0x0c10
#define NP6L_IGR_VLAN_TPID_8021Q	0x00010081
#define NP6L_TBL_IHP_L4_PARSE		0x3980	/* IHP L4 parse table, by IP protocol */
#define  NP6L_IGR_PORT_TAG_TPID_INIT	0x00010082	/* TPID 0x8200 + valid */
/* default LIF, left at 0 (254 would divert unmatched wan1 frames) */
#define NP6L_IGR_DEFAULT_LIF		0x0c20

static int fnp6l_tbl_op(struct fnp6l *np, u32 tbl, u32 idx, u32 *d, bool wr)
{
	u32 v;
	int i, ret;

	if (wr)
		for (i = 0; i < 4; i++)
			fnp6l_wr(np, tbl + 8 + 8 * i, d[i]);
	fnp6l_wr(np, tbl, (idx & GENMASK(29, 0)) | (wr ? NP6L_TBL_CMD_WRITE : 0));
	ret = readl_poll_timeout_atomic(np->base + tbl, v, !(v & NP6L_TBL_CMD_BUSY), 1, 1000);
	if (ret) {
		dev_warn(np->dev, "table %#x[%u]: busy\n", tbl, idx);
		return ret;
	}
	if (!wr)
		for (i = 0; i < 4; i++)
			d[i] = fnp6l_rd(np, tbl + 8 + 8 * i);
	return 0;
}

static void fnp6l_tbl_dump(struct fnp6l *np, const char *name, u32 tbl, unsigned int n)
{
	unsigned int i;
	u32 d[4];

	for (i = 0; i < n; i++)
		if (!fnp6l_tbl_op(np, tbl, i, d, false))
			dev_info(np->dev, "%s[%u] %08x %08x %08x %08x\n", name, i,
				 d[0], d[1], d[2], d[3]);
}

/*
 * The loader uses LIF 0 = its port (60E: wan1, lif_cfg port 2) and LIF 1 = host queue 0
 * (lif_cfg 0x80, target of port_action[0]). A port with a LIF >= 2 gets the
 * LIF entries of a direct port (MAC zero, as the loader for LIF 0): egress
 * tag none, lif_cfg = MAC port << 2 | 1, port_trunk = LIF, trunk_cfg = the
 * loader's trunk_cfg[0], port_action toward trunk 255 with SSE lookup.
 */
static void fnp6l_lif_tables(struct fnp6l *np, struct fnp6l_port *p)
{
	u32 d[4] = { };
	u32 port = p->link - 1, tc[4];

	if (p->lif == NP6L_LIF_LOADER || p->lif == NP6L_LIF_HOST)
		return;
	fnp6l_tbl_op(np, NP6L_TBL_EGR_TAG, p->lif, d, true);
	d[1] = FIELD_PREP(GENMASK(22, 16), port << 2 | 1);
	fnp6l_tbl_op(np, NP6L_TBL_LIF_CFG, p->lif, d, true);
	d[1] = 0;
	d[0] = p->lif & GENMASK(9, 0);
	fnp6l_tbl_op(np, NP6L_TBL_PORT_TRUNK, p->lif, d, true);
	if (!fnp6l_tbl_op(np, NP6L_TBL_TRUNK_CFG, 0, tc, false))
		fnp6l_tbl_op(np, NP6L_TBL_TRUNK_CFG, p->lif, tc, true);
	if (IS_ENABLED(CONFIG_FORTINET_NP6LITE_FLOW_OFFLOAD)) {
		/*
		 * Ingress classification: keep the loader's port_action
		 * (forward target 1 = its host queue, source action 2 =
		 * direct, no SSE lookup).
		 * The value with SSE lookup (0x0ff00000 / 0x00020040) here
		 * would need the host queues and trunk 255 posted and would
		 * drop the LIF's non-IP frames (ARP), and it would turn SSE
		 * lookup on before the engine is up. fnp6l_ft_apply raises
		 * source action to 1 and posts the host queues once the engine
		 * is ready.
		 */
		d[0] = 0x00100000;	/* forward target 1 (loader host queue) */
		d[1] = 0x00040080;	/* source action 2: direct, no SSE lookup */
	} else {
		d[0] = 0x0ff00000;	/* bits 29:20 = 0xff (forward target 255) */
		d[1] = 0x00020040;	/* byte 4 bits 7:6 = 1, byte 6 bits 2:1 = 1 */
	}
	fnp6l_tbl_op(np, NP6L_TBL_PORT_ACTION, p->lif, d, true);
	netdev_info(p->ndev, "LIF %u tables written (MAC port %u)\n", p->lif, port);
}

/* ------------------------------------------------------------------ rings */

static int fnp6l_ring_alloc(struct fnp6l *np, struct fnp6l_ring *r, bool tx,
			    unsigned int idx, unsigned int size)
{
	r->tx = tx;
	r->idx = idx;
	r->size = size;
	r->regs = np->base + (tx ? NP6L_HTXQ(idx) : NP6L_HRXQ(idx));
	r->desc = dmam_alloc_coherent(np->dev, size * (tx ? 16 : 8),
				      &r->desc_dma, GFP_KERNEL);
	r->wb = dmam_alloc_coherent(np->dev, (size + 8) * 8, &r->wb_dma,
				    GFP_KERNEL);
	r->skb = devm_kcalloc(np->dev, size, sizeof(*r->skb), GFP_KERNEL);
	r->buf = devm_kcalloc(np->dev, size, sizeof(*r->buf), GFP_KERNEL);
	if (tx)
		r->blen = devm_kcalloc(np->dev, size, sizeof(*r->blen), GFP_KERNEL);
	if (!r->desc || !r->wb || !r->skb || !r->buf || (tx && !r->blen))
		return -ENOMEM;
	return 0;
}

static int fnp6l_rx_fill_one(struct fnp6l *np, struct fnp6l_ring *r)
{
	unsigned int i = r->tail;
	struct sk_buff *skb;
	dma_addr_t dma;

	skb = netdev_alloc_skb(np->napi_dev, NP6L_RX_BUF);
	if (!skb)
		return -ENOMEM;
	dma = dma_map_single(np->dev, skb->data, NP6L_RX_BUF, DMA_FROM_DEVICE);
	if (dma_mapping_error(np->dev, dma)) {
		dev_kfree_skb_any(skb);
		return -ENOMEM;
	}
	r->skb[i] = skb;
	r->buf[i] = dma;
	r->wb[2 * i] = 0;
	r->wb[2 * i + 1] = 0;
	r->desc[2 * i] = cpu_to_le32(lower_32_bits(dma));
	r->desc[2 * i + 1] = cpu_to_le32(np->addr_hi |
					 FIELD_PREP(NP6L_RXD_LEN, NP6L_RX_BUF));
	r->tail = (i + 1) % r->size;
	return 0;
}

/* host ring set-up: base, size, indexes, write-back and moderation */
static int fnp6l_ring_start(struct fnp6l *np, struct fnp6l_ring *r)
{
	u32 dev;
	int ret;

	ret = fnp6l_queue_reset(np, r->tx ? NP6L_HTXQ(r->idx) : NP6L_HRXQ(r->idx));
	if (ret)
		return ret;
	writel(lower_32_bits(r->desc_dma), r->regs + NP6L_Q_RING_BASE);
	writel(lower_32_bits(r->wb_dma), r->regs + NP6L_Q_WB_BASE);
	writel(np->addr_hi, r->regs + NP6L_Q_RING_BASE_HI);
	writel(np->addr_hi, r->regs + NP6L_Q_WB_BASE_HI);
	writel(r->size, r->regs + NP6L_Q_RING_SIZE);
	writel(r->tail, r->regs + NP6L_Q_RING_HEAD);
	dev = readl(r->regs + NP6L_Q_CTRL) | NP6L_Q_CTRL_EN;
	if (r->tx)
		dev |= NP6L_Q_CTRL_WB;
	else
		dev &= ~NP6L_Q_CTRL_WB;
	writel(dev, r->regs + NP6L_Q_CTRL);
	writel(NP6L_Q_IRQ_IDLE_TIMER_INIT, r->regs + NP6L_Q_IRQ_IDLE_TIMER);
	/* interrupt moderation: not written by ring_init_hw, values seen live */
	writel(NP6L_Q_IRQ_FRAMES_INIT, r->regs + NP6L_Q_IRQ_FRAMES);
	writel(NP6L_Q_IRQ_TIMER_INIT, r->regs + NP6L_Q_IRQ_TIMER);
	writel(NP6L_Q_IRQ_ABS_TIMER_INIT, r->regs + NP6L_Q_IRQ_ABS_TIMER);
	writel(NP6L_Q_IRQ_THROTTLE_INIT, r->regs + NP6L_Q_IRQ_THROTTLE);
	return 0;
}

static void fnp6l_tx_unmap(struct fnp6l *np, struct fnp6l_ring *r, unsigned int i)
{
	u32 l = r->blen[i];

	if (!l)
		return;
	if (l & NP6L_TX_BLEN_PAGE)
		dma_unmap_page(np->dev, r->buf[i], l & ~NP6L_TX_BLEN_PAGE,
			       DMA_TO_DEVICE);
	else
		dma_unmap_single(np->dev, r->buf[i], l, DMA_TO_DEVICE);
	r->blen[i] = 0;
}

/*
 * Receive checksum (NETIF_F_RXCSUM, on by default on the NP ports but the DSA
 * conduit): CHECKSUM_UNNECESSARY for IPv4 when the IP header checksum
 * (b27) and the L4 checksum (b31) are both correct, and only when not a
 * fragment (b26, our own caution); IPv6 on the L4 checksum alone (b27 is
 * never set on IPv6), not a fragment. Tested on hardware with frames of
 * good and bad UDP checksums, IPv4 and IPv6, and TCP: no frame with a bad
 * checksum trusted. The family is
 * the EtherType after the Ethernet header (after the Broadcom tag on the
 * switch conduit); an 802.1Q tag left in band or any other family stays
 * CHECKSUM_NONE (not counted).
 */
static void fnp6l_rx_csum(struct fnp6l_vec *v, struct fnp6l_port *p,
			  struct sk_buff *skb, u32 w0)
{
	__be16 proto = skb->protocol;

	if (!(p->ndev->features & NETIF_F_RXCSUM))
		return;
	if (netdev_uses_dsa(p->ndev))
		proto = skb->len >= 4 ?
			get_unaligned((__be16 *)(skb->data + 2)) : 0;
	switch (ntohs(proto)) {
	case ETH_P_IP:
		if ((w0 & (NP6L_RXW0_IP_CSUM_OK | NP6L_RXW0_L4_CSUM_OK | NP6L_RXW0_IP_FRAG)) ==
		    (NP6L_RXW0_IP_CSUM_OK | NP6L_RXW0_L4_CSUM_OK)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			v->rx_csum_ok4++;
			return;
		}
		break;
	case ETH_P_IPV6:
		if ((w0 & (NP6L_RXW0_L4_CSUM_OK | NP6L_RXW0_IP_FRAG)) == NP6L_RXW0_L4_CSUM_OK) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			v->rx_csum_ok6++;
			return;
		}
		break;
	default:
		return;
	}
	v->rx_csum_none++;
}

static void fnp6l_rx_deliver(struct fnp6l *np, struct fnp6l_vec *v,
			     struct sk_buff *skb, u32 w0)
{
	u8 *t = skb->data;
	unsigned int lif = (t[4] & 3) << 8 | t[5];
	u16 tci = t[6] << 8 | t[7];
	struct fnp6l_port *p = lif < NP6L_MAX_LIF ? np->port[lif] : NULL;
	unsigned int i;
	bool port_tag;
	u8 tag[NP6L_HTAG_LEN];

	memcpy(tag, t, NP6L_HTAG_LEN);
	skb_pull(skb, NP6L_HTAG_LEN);
	port_tag = skb->len >= ETH_HLEN + 4 &&
	       get_unaligned_be16(skb->data + 12) == NP6L_PORT_TAG_TPID;

	if (np->ic_on) {
		/*
		 * Ingress classification: the IGR resolves the ingress port
		 * to its own LIF (60E: wan1 -> 0, wan2 -> 2, switch -> 3) through
		 * the class table and consumes the port tag, so p =
		 * np->port[lif] (set above) is the ingress port. If a port
		 * tag is still on the wire the classification missed for this
		 * frame (default LIF): count it and resolve by the port tag so
		 * the frame still flows.
		 */
		if (port_tag) {
			u16 ptag = get_unaligned_be16(skb->data + 14);

			np->ic_port_tag_fallback++;
			if (net_ratelimit())
				dev_info(np->dev,
					 "ingress_class rx: lif %u, port tag still on the wire\n",
					 lif);
			p = NULL;
			for (i = 0; i < NP6L_MAX_LIF; i++)
				if (np->port[i] && (np->port[i]->link << 4) == ptag)
					p = np->port[i];
			memmove(skb->data + 4, skb->data, 12);
			skb_pull(skb, 4);
		} else if (np->sw_on && lif < NP6L_MAX_LIF &&
			   ((p && p->sw_nports) || np->sw_conduit[lif])) {
			/*
			 * Switch-port classification: the IGR consumed the
			 * Broadcom tag as a second tag (second tag TPID 0x0000)
			 * and classified the switch port to its own LIF (on the
			 * conduit LIF: its own cell, key VID 0, which no frame
			 * with a second tag matches (measured), taken as port 0;
			 * on its own LIF, p is NULL and sw_port[] gives the
			 * port, 0 included). Give the frame back a
			 * Broadcom egress tag (opcode 0, source port) so
			 * tag_brcm demultiplexes it.
			 */
			unsigned int sp = p ? 0 : np->sw_port[lif];

			if (skb_headroom(skb) < 4 || skb->len < 2 * ETH_ALEN) {
				v->rx_unknown_lif++;
				dev_kfree_skb_any(skb);
				return;
			}
			skb_push(skb, 4);
			memmove(skb->data, skb->data + 4, 2 * ETH_ALEN);
			skb->data[12] = 0;
			skb->data[13] = 0;
			skb->data[14] = 0;
			skb->data[15] = sp;
			np->sw_rx_retag++;
			if (!p)
				p = np->sw_conduit[lif];
		}
	} else if (port_tag) {
		/* Ingress port from the port tag left on the wire (see fnp6l_mac_init) */
		u16 ptag = get_unaligned_be16(skb->data + 14);

		p = NULL;
		for (i = 0; i < NP6L_MAX_LIF; i++)
			if (np->port[i] && (np->port[i]->link << 4) == ptag)
				p = np->port[i];
		memmove(skb->data + 4, skb->data, 12);
		skb_pull(skb, 4);
	}
	if (!p || !netif_running(p->ndev)) {
		v->rx_unknown_lif++;
		if (net_ratelimit())
			dev_info(np->dev, "rx: tag %*ph (lif %u) dropped\n",
				 NP6L_HTAG_LEN, tag, lif);
		dev_kfree_skb_any(skb);
		return;
	}
	skb->protocol = eth_type_trans(skb, p->ndev);
	fnp6l_rx_csum(v, p, skb, w0);
	if (tci)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), tci);
	/* several NAPI contexts may deliver to the same port */
	DEV_STATS_INC(p->ndev, rx_packets);
	DEV_STATS_ADD(p->ndev, rx_bytes, skb->len);
	v->rx_pkts++;
	napi_gro_receive(&v->napi, skb);
}

static void fnp6l_rx_msg(struct fnp6l *np, const u8 *data, unsigned int len);

static int fnp6l_rx_ring(struct fnp6l *np, struct fnp6l_vec *v, struct fnp6l_ring *r,
			 int budget)
{
	int done = 0;

	while (done < budget) {
		unsigned int i = r->head;
		u32 w0, w1, len;
		struct sk_buff *skb;

		w1 = le32_to_cpu(READ_ONCE(r->wb[2 * i + 1]));
		if (!(w1 & NP6L_WB_DONE))
			break;
		dma_rmb();
		w0 = le32_to_cpu(r->wb[2 * i]);
		len = FIELD_GET(NP6L_RXD_LEN, w1);
		skb = r->skb[i];
		r->skb[i] = NULL;
		r->wb[2 * i] = 0;
		r->wb[2 * i + 1] = 0;
		r->head = (i + 1) % r->size;
		done++;
		if (skb)
			dma_unmap_single(np->dev, r->buf[i], NP6L_RX_BUF,
					 DMA_FROM_DEVICE);

		if (!skb || (w0 & NP6L_WB_MSG) || r->drop_seg || !(w1 & NP6L_WB_EOP) ||
		    len <= NP6L_HTAG_LEN + ETH_HLEN || len > NP6L_RX_BUF) {
			/* messages and frames spread over several buffers: not yet */
			if (w0 & NP6L_WB_MSG) {
				v->rx_msg++;
				if (skb && (w1 & NP6L_WB_EOP))
					fnp6l_rx_msg(np, skb->data,
						     min_t(u32, len, NP6L_RX_BUF));
			} else
				v->rx_seg_drop++;
			r->drop_seg = !(w1 & NP6L_WB_EOP);
			dev_kfree_skb_any(skb);
		} else {
			skb_put(skb, len);
			fnp6l_rx_deliver(np, v, skb, w0);
		}
	}

	/* One entry always stays empty; buffers are handed back by eight */
	while (r->tail != (r->head + r->size - 1) % r->size) {
		if (fnp6l_rx_fill_one(np, r)) {
			v->rx_nomem++;
			break;
		}
		if (!(r->tail & 7)) {
			wmb();
			writel(r->tail, r->regs + NP6L_Q_RING_HEAD);
		}
	}
	return done;
}

static unsigned int fnp6l_tx_free(struct fnp6l_ring *r)
{
	return (r->head + r->size - r->tail - 1) % r->size;
}

static void fnp6l_tx_clean(struct fnp6l *np)
{
	struct fnp6l_ring *r = &np->tx;
	unsigned int hw, i;
	bool woke = false;

	spin_lock(&np->tx_lock);
	hw = le32_to_cpu(READ_ONCE(r->wb[0])) & 0xffff;
	if (hw >= r->size)
		goto out;
	while (r->head != hw) {
		struct sk_buff *skb = r->skb[r->head];

		fnp6l_tx_unmap(np, r, r->head);
		if (skb) {
			dev_consume_skb_any(skb);
			r->skb[r->head] = NULL;
		}
		r->head = (r->head + 1) % r->size;
		woke = true;
	}
	/* room for a frame with every fragment */
	woke = woke && fnp6l_tx_free(r) >= NP6L_TX_MAX_DESC;
out:
	spin_unlock(&np->tx_lock);
	if (woke)
		for (i = 0; i < NP6L_MAX_LIF; i++)
			if (np->port[i] && netif_queue_stopped(np->port[i]->ndev))
				netif_wake_queue(np->port[i]->ndev);
}

/* queues of one vector: mask (enable clear) and acknowledge (status) */
static void fnp6l_vec_mask_ack(struct fnp6l_vec *v)
{
	struct fnp6l *np = v->np;
	unsigned int q;

	for_each_set_bit(q, &v->qmask, NP6L_NR_QUEUES) {
		writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_IDLE_TIMER | NP6L_Q_INT_FRAMES,
		       np->rx[q].regs + NP6L_Q_INT_ENABLE_CLR);
		writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_FRAMES,
		       np->rx[q].regs + NP6L_Q_INT_STATUS);
	}
	if (v->tx) {
		writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_IDLE_TIMER | NP6L_Q_INT_FRAMES,
		       np->tx.regs + NP6L_Q_INT_ENABLE_CLR);
		writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_FRAMES,
		       np->tx.regs + NP6L_Q_INT_STATUS);
	}
}

static void fnp6l_vec_rearm(struct fnp6l_vec *v)
{
	struct fnp6l *np = v->np;
	unsigned int q;

	for_each_set_bit(q, &v->qmask, NP6L_NR_QUEUES) {
		writel(NP6L_Q_INT_VEC_CLR, np->rx[q].regs + NP6L_Q_INT_STATUS);
		writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_FRAMES,
		       np->rx[q].regs + NP6L_Q_INT_ENABLE);
	}
	if (v->tx) {
		writel(NP6L_Q_INT_VEC_CLR, np->tx.regs + NP6L_Q_INT_STATUS);
		writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_FRAMES,
		       np->tx.regs + NP6L_Q_INT_ENABLE);
	}
}

static int fnp6l_poll(struct napi_struct *napi, int budget)
{
	struct fnp6l_vec *v = container_of(napi, struct fnp6l_vec, napi);
	struct fnp6l *np = v->np;
	int done = 0;
	unsigned int q;

	if (v->tx)
		fnp6l_tx_clean(np);
	for_each_set_bit(q, &v->qmask, NP6L_NR_QUEUES)
		done += fnp6l_rx_ring(np, v, &np->rx[q], budget - done);

	if (done < budget && napi_complete_done(napi, done)) {
		if (np->use_irq)
			fnp6l_vec_rearm(v);
		else
			mod_timer(&np->poll_timer,
				  jiffies + msecs_to_jiffies(poll_ms));
	}
	return done;
}

static void fnp6l_poll_timer(struct timer_list *t)
{
	struct fnp6l *np = timer_container_of(np, t, poll_timer);
	unsigned int i;

	for (i = 0; i < np->nvec; i++)
		napi_schedule(&np->vec[i].napi);
	/* Interrupt mode: slow safety poll, should an interrupt be lost */
	if (np->use_irq)
		mod_timer(&np->poll_timer, jiffies + msecs_to_jiffies(100));
}

/*
 * Source to interrupt vector table: source 4q = HRX queue q, 4q + 1 = its
 * fatal errors, 0x40 + 4q = HTX queue q, 0x41 + 4q its errors; vector v =
 * HIF interrupt v (v < nrx), vector nrx = "err".
 */
#define NP6L_TBL_IRQ_VEC		0x0200

static void fnp6l_irq_vec_init(struct fnp6l *np)
{
	unsigned int q;
	u32 d[4] = { };

	for_each_set_bit(q, &np->rx_mask, NP6L_NR_QUEUES) {
		d[0] = q % 4;
		fnp6l_tbl_op(np, NP6L_TBL_IRQ_VEC, 4 * q, d, true);
		d[0] = 4;
		fnp6l_tbl_op(np, NP6L_TBL_IRQ_VEC, 4 * q + 1, d, true);
	}
	d[0] = 0;
	fnp6l_tbl_op(np, NP6L_TBL_IRQ_VEC, 0x40, d, true);
	d[0] = 4;
	fnp6l_tbl_op(np, NP6L_TBL_IRQ_VEC, 0x41, d, true);
}

/* HIF vector v: only the queues of its vector */
static irqreturn_t fnp6l_vec_irq(int irq, void *data)
{
	struct fnp6l_vec *v = data;

	fnp6l_vec_mask_ack(v);
	napi_schedule(&v->napi);
	return IRQ_HANDLED;
}

static DEFINE_RATELIMIT_STATE(fnp6l_fatal_rs, 5 * HZ, 4);

/*
 * Fatal error status of one host queue: counted, acknowledged by writing
 * the bits back (as the other status bits), and masked if they stay set:
 * the "err" interrupt is enabled for them at setup and would otherwise
 * fire again at once, for good. Returns whether the queue had one.
 */
static bool fnp6l_fatal_ack(struct fnp6l *np, void __iomem *regs,
			    unsigned int bit, const char *name, unsigned int q)
{
	u32 st = readl(regs + NP6L_Q_INT_STATUS) & NP6L_Q_INT_FATAL;

	if (!st)
		return false;
	np->err_fatal++;
	writel(st, regs + NP6L_Q_INT_STATUS);
	if (readl(regs + NP6L_Q_INT_STATUS) & NP6L_Q_INT_FATAL) {
		writel(NP6L_Q_INT_FATAL, regs + NP6L_Q_INT_ENABLE_CLR);
		if (!test_and_set_bit(bit, &np->fatal_masked))
			dev_err(np->dev, "%s%u: fatal error status %#x stays set, masked\n",
				name, q, st);
	} else if (__ratelimit(&fnp6l_fatal_rs)) {
		dev_warn(np->dev, "%s%u: fatal error status %#x (%llu)\n",
			 name, q, st, np->err_fatal);
	}
	return true;
}

/* "err" (fatal errors of every queue): acknowledged, then every vector */
static irqreturn_t fnp6l_err_irq(int irq, void *data)
{
	struct fnp6l *np = data;
	unsigned int i, q;

	for_each_set_bit(q, &np->rx_mask, NP6L_NR_QUEUES)
		fnp6l_fatal_ack(np, np->rx[q].regs, q, "hrxq", q);
	fnp6l_fatal_ack(np, np->tx.regs, NP6L_NR_QUEUES, "htxq", 0);
	for (i = 0; i < np->nvec; i++) {
		fnp6l_vec_mask_ack(&np->vec[i]);
		napi_schedule(&np->vec[i].napi);
	}
	return IRQ_HANDLED;
}

static void fnp6l_clear_affinity_hint(void *data)
{
	irq_update_affinity_hint((unsigned long)data, NULL);
}

/* --------------------------------------------------------------- netdev */

/*
 * Transmit checksum (NETIF_F_IP_CSUM and NETIF_F_IPV6_CSUM, on by default):
 * what is asked of the NP is a TCP or UDP frame right behind an Ethernet
 * header, IPv4 without options or IPv6 without extension headers. IPv6 frames
 * with extension headers (the HTX L4 parse table has entries for 0, 43, 44 and
 * 60) are left to the stack here. Anything else (802.1Q in band, IP options, a
 * DSA conduit whose frames carry the switch tag) is done by the stack. HW_CSUM
 * is not used: mainline refuses it together with IP_CSUM, and
 * fnp6l_features_check would narrow it the same way. Neither SG nor TSO is
 * offered: the NP loses frames of several descriptors.
 */
static bool fnp6l_tx_offload_ok6(struct sk_buff *skb)
{
	const struct ipv6hdr *ip6 = ipv6_hdr(skb);

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return true;
	if (skb_checksum_start_offset(skb) != ETH_HLEN + sizeof(*ip6))
		return false;
	switch (ip6->nexthdr) {
	case IPPROTO_TCP:
		return skb->csum_offset == offsetof(struct tcphdr, check);
	case IPPROTO_UDP:
		return skb->csum_offset == offsetof(struct udphdr, check);
	}
	return false;
}

static bool fnp6l_tx_offload_ok(struct sk_buff *skb, struct net_device *ndev)
{
	const struct iphdr *iph;

	if (netdev_uses_dsa(ndev) || skb_network_offset(skb) != ETH_HLEN)
		return false;
	if (skb->protocol == htons(ETH_P_IPV6))
		return fnp6l_tx_offload_ok6(skb);
	if (skb->protocol != htons(ETH_P_IP))
		return false;
	iph = ip_hdr(skb);
	if (iph->ihl != 5 || ip_is_fragment(iph))
		return false;
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return true;
	if (skb_checksum_start_offset(skb) != ETH_HLEN + sizeof(*iph))
		return false;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		return skb->csum_offset == offsetof(struct tcphdr, check);
	case IPPROTO_UDP:
		return skb->csum_offset == offsetof(struct udphdr, check);
	}
	return false;
}

static netdev_features_t fnp6l_features_check(struct sk_buff *skb,
					      struct net_device *ndev,
					      netdev_features_t features)
{
	if (!fnp6l_tx_offload_ok(skb, ndev))
		features &= ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
	return features;
}

/*
 * Default L4 parse entries, by IP protocol: data lo = parse flags, data hi
 * 9:3 = L4 header length. The loader leaves the HTX table with
 * 0x40000000/0, without the L4 header lengths. Only HTX is written here,
 * each entry straight to its final value.
 */
static const struct { u8 proto; u32 l, h; } fnp6l_l4_parse_tbl[] = {
	{ 0, 0x00000003, 0x400 }, { 1, 0x40000002, 0x020 },
	{ 4, 0x7ffffffe, 0x0a0 }, { 6, 0x40000002, 0x0a0 },
	{ 8, 0x00000000, 0x400 }, { 17, 0x40000002, 0x040 },
	{ 41, 0x7ffffffe, 0x0a0 }, { 43, 0x00000001, 0x000 },
	{ 44, 0x00000001, 0x000 }, { 47, 0x7ffffffe, 0x020 },
	{ 50, 0x40000002, 0x040 }, { 51, 0x7ffffffe, 0x040 },
	{ 58, 0x40000002, 0x020 }, { 60, 0x00000003, 0x000 },
	{ 128, 0x00000000, 0x800 }, { 129, 0x00000000, 0x800 },
	{ 132, 0x40000002, 0x060 }, { 136, 0x40000002, 0x040 },
};

static void fnp6l_htx_l4_parse_init(struct fnp6l *np)
{
	unsigned int i, k;
	u32 d[4];

	for (i = 0; i < 256; i++) {
		memset(d, 0, sizeof(d));
		for (k = 0; k < ARRAY_SIZE(fnp6l_l4_parse_tbl); k++)
			if (fnp6l_l4_parse_tbl[k].proto == i) {
				d[0] = fnp6l_l4_parse_tbl[k].l;
				d[1] = fnp6l_l4_parse_tbl[k].h;
			}
		if (fnp6l_tbl_op(np, NP6L_TBL_HTX_L4_PARSE, i, d, true))
			return;
	}
	np->htx_l4_parse_done = true;
	dev_info(np->dev, "HTX L4 parse table programmed\n");
}

static int fnp6l_set_features(struct net_device *ndev, netdev_features_t features)
{
	struct fnp6l_port *p = netdev_priv(ndev);
	struct fnp6l *np = p->np;

	if ((features & ~ndev->features &
	     (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM)) && !np->htx_l4_parse_done)
		fnp6l_htx_l4_parse_init(np);
	return 0;
}

static const char fnp6l_gstrings[][ETH_GSTRING_LEN] = {
	"tx_csum_hw", "tx_csum_sw", "tx_sg",
	"rx_unknown_lif", "rx_flow_msgs", "rx_seg_drop", "rx_nomem",
	"rx_vec0", "rx_vec1", "rx_vec2", "rx_vec3",
	"tx_csum_hw6", "rx_csum_ok_v4", "rx_csum_ok_v6", "rx_csum_none",
	"err_fatal",
};

static void fnp6l_get_strings(struct net_device *ndev, u32 sset, u8 *data)
{
	if (sset == ETH_SS_STATS)
		memcpy(data, fnp6l_gstrings, sizeof(fnp6l_gstrings));
}

static int fnp6l_get_sset_count(struct net_device *ndev, int sset)
{
	return sset == ETH_SS_STATS ? ARRAY_SIZE(fnp6l_gstrings) : -EOPNOTSUPP;
}

/* NP wide counters (all ports share the host queues) */
static void fnp6l_get_ethtool_stats(struct net_device *ndev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct fnp6l_port *p = netdev_priv(ndev);
	struct fnp6l *np = p->np;
	unsigned int i = 0, k;

	data[i++] = np->tx_csum_hw;
	data[i++] = np->tx_csum_sw;
	data[i++] = np->tx_sg;
	memset(data + i, 0, (4 + NP6L_NR_VEC) * sizeof(*data));
	for (k = 0; k < np->nvec; k++) {
		data[i] += np->vec[k].rx_unknown_lif;
		data[i + 1] += np->vec[k].rx_msg;
		data[i + 2] += np->vec[k].rx_seg_drop;
		data[i + 3] += np->vec[k].rx_nomem;
		data[i + 4 + k] = np->vec[k].rx_pkts;
	}
	i += 4 + NP6L_NR_VEC;
	data[i++] = np->tx_csum_hw6;
	memset(data + i, 0, 3 * sizeof(*data));
	for (k = 0; k < np->nvec; k++) {
		data[i] += np->vec[k].rx_csum_ok4;
		data[i + 1] += np->vec[k].rx_csum_ok6;
		data[i + 2] += np->vec[k].rx_csum_none;
	}
	data[i + 3] = np->err_fatal;
}

/* EEE of the PHY of a port (see phy_eee): state and advertisement only */
static int fnp6l_get_eee(struct net_device *ndev, struct ethtool_keee *e)
{
	if (!ndev->phydev)
		return -ENODEV;
	return phy_ethtool_get_eee(ndev->phydev, e);
}

static int fnp6l_set_eee(struct net_device *ndev, struct ethtool_keee *e)
{
	if (!ndev->phydev)
		return -ENODEV;
	return phy_ethtool_set_eee(ndev->phydev, e);
}

static const struct ethtool_ops fnp6l_ethtool_ops = {
	.get_link		= ethtool_op_get_link,
	.get_link_ksettings	= phy_ethtool_get_link_ksettings,
	.set_link_ksettings	= phy_ethtool_set_link_ksettings,
	.nway_reset		= phy_ethtool_nway_reset,
	.get_eee		= fnp6l_get_eee,
	.set_eee		= fnp6l_set_eee,
	.get_strings		= fnp6l_get_strings,
	.get_sset_count		= fnp6l_get_sset_count,
	.get_ethtool_stats	= fnp6l_get_ethtool_stats,
};

static netdev_tx_t fnp6l_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct fnp6l_port *p = netdev_priv(ndev);
	struct fnp6l *np = p->np;
	struct fnp6l_ring *r = &np->tx;
	dma_addr_t dma[NP6L_TX_MAX_DESC];
	u32 dlen[NP6L_TX_MAX_DESC];
	unsigned int i, k, n, len;
	bool hw_csum = false, sw_csum = false;
	__le32 *d;
	u8 *t;

	/*
	 * Completions are only seen at the next poll (10 ms) or interrupt:
	 * reclaim what the NP has already sent, and release the socket memory
	 * now, or TCP small queues throttle a sender to a few frames per poll
	 * (iperf3 -R: 2.4 Mbit/s under yall).
	 */
	fnp6l_tx_clean(np);
	skb_orphan(skb);
	if (skb_put_padto(skb, ETH_ZLEN))
		goto dropped;
	if (skb_cow_head(skb, NP6L_HTAG_LEN))
		goto drop;
	/* without NETIF_F_SG the stack hands linear frames only */
	if ((!(ndev->features & NETIF_F_SG) || skb_has_frag_list(skb)) &&
	    skb_linearize(skb))
		goto drop;
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (fnp6l_tx_offload_ok(skb, ndev)) {
			hw_csum = true;
			np->tx_csum_hw6 += skb->protocol == htons(ETH_P_IPV6);
		} else {
			if (skb_checksum_help(skb))
				goto drop;
			sw_csum = true;
		}
	}
	t = skb_push(skb, NP6L_HTAG_LEN);
	memset(t, 0, NP6L_HTAG_LEN);
	t[0] = 0x80 | ((p->lif >> 8) & 3);	/* destination LIF */
	t[1] = p->lif & 0xff;
	t[4] = (r->idx >> 8) & 3;		/* host queue */
	t[5] = r->idx & 0xff;
	len = skb->len;

	/*
	 * Scatter-gather transmit descriptors: the first
	 * descriptor carries the linear part and the frame wide fields, one
	 * descriptor per page fragment with its address, the link and its
	 * length, end of packet on the last one.
	 */
	n = 1 + skb_shinfo(skb)->nr_frags;
	dlen[0] = skb_headlen(skb);
	dma[0] = dma_map_single(np->dev, skb->data, dlen[0], DMA_TO_DEVICE);
	if (dma_mapping_error(np->dev, dma[0]))
		goto drop;
	for (k = 1; k < n; k++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[k - 1];

		dlen[k] = skb_frag_size(f);
		dma[k] = skb_frag_dma_map(np->dev, f, 0, dlen[k], DMA_TO_DEVICE);
		if (dma_mapping_error(np->dev, dma[k]))
			goto unmap;
	}

	spin_lock_bh(&np->tx_lock);
	if (fnp6l_tx_free(r) < n) {
		/*
		 * Stopped under tx_lock: fnp6l_tx_clean frees under it and
		 * tests the stopped queues after, so it sees this stop and
		 * wakes the queue once the ring has room (the ring is shared
		 * by every port, without a transmit timeout).
		 */
		netif_stop_queue(ndev);
		spin_unlock_bh(&np->tx_lock);
		while (--k)
			dma_unmap_page(np->dev, dma[k], dlen[k], DMA_TO_DEVICE);
		dma_unmap_single(np->dev, dma[0], dlen[0], DMA_TO_DEVICE);
		skb_pull(skb, NP6L_HTAG_LEN);
		return NETDEV_TX_BUSY;
	}
	for (k = 0; k < n; k++) {
		i = (r->tail + k) % r->size;
		d = &r->desc[4 * i];
		r->skb[i] = k == n - 1 ? skb : NULL;
		r->buf[i] = dma[k];
		r->blen[i] = dlen[k] | (k ? NP6L_TX_BLEN_PAGE : 0);
		d[0] = cpu_to_le32(lower_32_bits(dma[k]));
		if (k) {
			d[1] = cpu_to_le32(np->addr_hi |
					   FIELD_PREP(NP6L_TXD1_PORT, p->link));
			d[2] = cpu_to_le32(FIELD_PREP(NP6L_TXD2_SEG_LEN, dlen[k]) |
					   (k == n - 1 ? NP6L_TXD2_EOP : 0));
			d[3] = 0;
			continue;
		}
		d[1] = cpu_to_le32(np->addr_hi | FIELD_PREP(NP6L_TXD1_PORT, p->link) |
				   FIELD_PREP(NP6L_TXD1_FRAME_LEN, len - NP6L_HTAG_LEN));
		d[2] = cpu_to_le32(FIELD_PREP(NP6L_TXD2_SEG_LEN, dlen[0]) |
				   (n == 1 ? NP6L_TXD2_EOP : 0) | NP6L_TXD2_HOST_INIT |
				   (hw_csum ? NP6L_TXD2_CSUM : 0));
		d[3] = 0;
	}
	np->tx_csum_hw += hw_csum;
	np->tx_csum_sw += sw_csum;
	np->tx_sg += n > 1;
	r->tail = (r->tail + n) % r->size;
	wmb();
	writel(r->tail, r->regs + NP6L_Q_RING_HEAD);
	if (fnp6l_tx_free(r) < NP6L_TX_MAX_DESC)
		netif_stop_queue(ndev);
	spin_unlock_bh(&np->tx_lock);

	ndev->stats.tx_packets++;
	ndev->stats.tx_bytes += len - NP6L_HTAG_LEN;
	return NETDEV_TX_OK;

unmap:
	while (--k)
		dma_unmap_page(np->dev, dma[k], dlen[k], DMA_TO_DEVICE);
	dma_unmap_single(np->dev, dma[0], dlen[0], DMA_TO_DEVICE);
drop:
	dev_kfree_skb_any(skb);
dropped:
	ndev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static int fnp6l_open(struct net_device *ndev)
{
	struct fnp6l_port *p = netdev_priv(ndev);
	struct phy_device *phy;

	phy = of_phy_get_and_connect(ndev, p->dn, fnp6l_adjust_link);
	if (!phy) {
		/* a fixed link it registered stays otherwise */
		if (of_phy_is_fixed_link(p->dn))
			of_phy_deregister_fixed_link(p->dn);
		netdev_err(ndev, "no PHY\n");
		return -ENODEV;
	}
	if (!of_phy_is_fixed_link(p->dn) && !READ_ONCE(phy_eee)) {
		/* advertisement kept: ethtool --set-eee can turn it back on */
		phy->eee_cfg.eee_enabled = false;
		phy->eee_cfg.tx_lpi_enabled = false;
	}
	p->speed = 0;
	p->duplex = DUPLEX_UNKNOWN;
	fnp6l_pcs_init(p->np, p->link - 1);
	fnp6l_mac_init(p->np, p->link - 1);
	phy_start(phy);
	netif_start_queue(ndev);
	return 0;
}

static int fnp6l_stop(struct net_device *ndev)
{
	struct fnp6l_port *p = netdev_priv(ndev);

	netif_stop_queue(ndev);
	if (ndev->phydev) {
		phy_stop(ndev->phydev);
		phy_disconnect(ndev->phydev);
	}
	/*
	 * of_phy_get_and_connect() registers a new fixed PHY at each open
	 * (the conduit): without this, every down/up of the conduit leaves
	 * one behind, until the fixed MDIO bus has no address left.
	 */
	if (of_phy_is_fixed_link(p->dn))
		of_phy_deregister_fixed_link(p->dn);
	return 0;
}

/* flow table offload, defined with its section further down */
static int fnp6l_setup_tc(struct net_device *ndev, enum tc_setup_type type,
			  void *type_data);
static int fnp6l_set_mac_address(struct net_device *ndev, void *addr);

static const struct net_device_ops fnp6l_netdev_ops = {
	.ndo_open		= fnp6l_open,
	.ndo_stop		= fnp6l_stop,
	.ndo_start_xmit		= fnp6l_xmit,
	.ndo_features_check	= fnp6l_features_check,
	.ndo_set_features	= fnp6l_set_features,
	.ndo_set_mac_address	= fnp6l_set_mac_address,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_eth_ioctl		= phy_do_ioctl_running,
	.ndo_setup_tc		= fnp6l_setup_tc,
};

/* the DSA conduit: a switch CPU port points at it ("ethernet") */
static bool fnp6l_dt_is_conduit(struct device_node *dn)
{
	struct device_node *n, *c;

	for_each_node_with_property(n, "ethernet") {
		c = of_parse_phandle(n, "ethernet", 0);
		of_node_put(c);
		if (c == dn) {
			of_node_put(n);
			return true;
		}
	}
	return false;
}

/*
 * "fortinet,switch-logical-interfaces" of a conduit: the LIF of each switch
 * port, by port number, 0 for none (the frames of that port stay on the
 * conduit LIF). Switch port 0 in class 0 keys VID 0, never matched: with a
 * LIF of its own (never the conduit's) it is classified in the other
 * classes of switch_tc_mask only (class 7: brcm,port-traffic-class = <7>
 * on the switch), see fnp6l_sw_apply_conduit. The LIFs are checked
 * against each other and the port LIFs by fnp6l_sw_map, once every port is
 * known. A bad value leaves the switch ports of this conduit unclassified
 * (the conduit still works).
 */
static void fnp6l_dt_switch_lifs(struct fnp6l *np, struct fnp6l_port *p)
{
	u32 v[NP6L_SW_PORTS];
	int n, i;

	n = of_property_count_u32_elems(p->dn, "fortinet,switch-logical-interfaces");
	if (n == -EINVAL)
		return;		/* absent: switch ports not classified */
	if (!p->conduit || n < 1 || n > NP6L_SW_PORTS ||
	    of_property_read_u32_array(p->dn, "fortinet,switch-logical-interfaces", v, n) ||
	    (v[0] && v[0] == p->lif))
		goto bad;
	for (i = 0; i < n; i++)
		if (v[i] >= NP6L_MAX_LIF || v[i] == NP6L_LIF_HOST)
			goto bad;
	for (i = 0; i < n; i++)
		p->sw_lif[i] = v[i];
	/* no switch port on a LIF of its own: as if absent */
	if (memchr_inv(p->sw_lif, 0, sizeof(p->sw_lif)))
		p->sw_nports = n;
	return;
bad:
	dev_err(np->dev, "%pOF: bad fortinet,switch-logical-interfaces, switch ports not classified\n",
		p->dn);
}

static int fnp6l_add_port(struct fnp6l *np, struct device_node *dn)
{
	struct net_device *ndev;
	struct fnp6l_port *p;
	const char *label;
	u32 lif, link;
	int ret;

	if (of_property_read_u32(dn, "reg", &lif) || lif >= NP6L_MAX_LIF ||
	    lif == NP6L_LIF_HOST || np->port[lif] ||
	    of_property_read_u32(dn, "fortinet,np-link", &link) ||
	    link < 1 || link > NP6L_NR_MACS) {
		dev_err(np->dev, "%pOF: bad reg or fortinet,np-link\n", dn);
		return -EINVAL;
	}
	ndev = devm_alloc_etherdev(np->dev, sizeof(*p));
	if (!ndev)
		return -ENOMEM;
	SET_NETDEV_DEV(ndev, np->dev);
	p = netdev_priv(ndev);
	p->np = np;
	p->ndev = ndev;
	p->dn = dn;
	p->lif = lif;
	p->link = link;
	p->conduit = fnp6l_dt_is_conduit(dn);
	fnp6l_dt_switch_lifs(np, p);
	ret = of_get_phy_mode(dn, &p->phy_mode);
	if (ret)
		p->phy_mode = PHY_INTERFACE_MODE_SGMII;
	if (!of_property_read_string(dn, "label", &label))
		strscpy(ndev->name, label, IFNAMSIZ);
	ndev->dev.of_node = dn;
	ndev->netdev_ops = &fnp6l_netdev_ops;
	ndev->ethtool_ops = &fnp6l_ethtool_ops;
	/*
	 * Transmit checksum by the NP, IPv4 and IPv6, and receive checksum on
	 * by default (tested on hardware; neither SG nor TSO). The
	 * receive checksum stays off on the DSA conduit (never checked
	 * behind the Broadcom tag): ethtool -K sw0 rx on.
	 */
	ndev->hw_features = NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_RXCSUM;
	ndev->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
	if (!p->conduit)
		ndev->features |= NETIF_F_RXCSUM;
	/* flow table offload: accept TC_SETUP_FT on this port */
	if (IS_ENABLED(CONFIG_FORTINET_NP6LITE_FLOW_OFFLOAD)) {
		ndev->hw_features |= NETIF_F_HW_TC;
		ndev->features |= NETIF_F_HW_TC;
	}
	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = NP6L_RX_BUF - NP6L_HTAG_LEN - ETH_HLEN - VLAN_HLEN - 64;
	/*
	 * MAC: from the device tree (a "mac-address" NVMEM cell: the factory
	 * base of the boot flash + the rank of the port), else random.
	 * fnp6l_wait_mac_cells() made sure the cell is there, if it can be.
	 */
	ret = of_get_ethdev_address(dn, ndev);
	if (ret) {
		eth_hw_addr_random(ndev);
		dev_info(np->dev, "%pOFn %s: random MAC address (%pe)\n", dn,
			 ndev->name, ERR_PTR(ret));
	} else if (of_property_present(dn, "nvmem-cells")) {
		dev_info(np->dev, "%pOFn %s: MAC address from NVMEM\n", dn,
			 ndev->name);
	}
	np->port[lif] = p;
	if (of_property_read_bool(np->dev->of_node, "fortinet,init-logical-interfaces"))
		fnp6l_lif_tables(np, p);
	ret = devm_register_netdev(np->dev, ndev);
	if (ret) {
		np->port[lif] = NULL;
		return ret;
	}
	netdev_info(ndev, "LIF %u, NP link %u (MAC port %u), %s\n", lif, link,
		    link - 1, phy_modes(p->phy_mode));
	return 0;
}

/*
 * Buffer limits of the packet buffer queues (PDQ). The loader leaves each
 * port output queue at 64 buffers and a TX PBA quota of 24: a
 * train of host frames to a 1 Gbit/s port overflows it and the frames are
 * dropped between the EHP and the port queue (TCP sent by the host: ~4 % at
 * 600 Mbit/s; routed, 722-852 instead of 944 Mbit/s).
 */
static void fnp6l_rmw(struct fnp6l *np, u32 reg, u32 mask, u32 val)
{
	fnp6l_wr(np, reg, (fnp6l_rd(np, reg) & ~mask) | val);
}

/*
 * Queue control of a port queue: four admission thresholds of 6 bits (q0
 * 5:0 .. q3 29:24, unit of 4 buffers), one per priority class. The frames
 * sent by the host are class 0 (q0) and those the session engine forwards
 * a higher class: when an offloaded flow fills a port queue at line rate,
 * the host frames to that port are dropped first (measured, LIF 3 to the
 * switch: ping 68 % lost, LACPDUs ~1/3 lost, the partner removes the LAG
 * member): q0 is admitted up to a full queue (63; 35 would leave a margin
 * to the forwarded classes).
 *
 * Thresholds of the higher classes (q1..q3, the frames the session engine
 * forwards). Even admitted up to a full queue, the host frames are lost when
 * an offloaded TCP flow keeps the port queue full (measured, to the switch:
 * the Broadcom tag makes port 0 the bottleneck; ping 2-8 %, IMP
 * RxDiscarded). With the forwarded classes held at 31 the queue keeps a
 * margin the host alone may use (ping 0 %, RxDiscarded 0, 940 Mbit/s, fewer
 * retransmits).
 */
#define NP6L_PDQ_HOST_THRESH_INIT	63
#define NP6L_PDQ_FWD_THRESH_INIT	31
#define NP6L_PDQ_QUEUE_CTRL_INIT	(NP6L_PDQ_FWD_THRESH_INIT << 24 |	\
					 NP6L_PDQ_FWD_THRESH_INIT << 16 |	\
					 NP6L_PDQ_FWD_THRESH_INIT << 8 |	\
					 NP6L_PDQ_HOST_THRESH_INIT)

static void fnp6l_pdq_init(struct fnp6l *np)
{
	unsigned int i;

	dev_info(np->dev, "pdq: port queue_ctrl %#x (host threshold %u, forwarded %u)\n",
		 NP6L_PDQ_QUEUE_CTRL_INIT, NP6L_PDQ_HOST_THRESH_INIT,
		 NP6L_PDQ_FWD_THRESH_INIT);
	fnp6l_rmw(np, NP6L_PBA_CTRL, NP6L_PBA_CTRL_THRESH | NP6L_PBA_CTRL_XTHRESH,
		  FIELD_PREP(NP6L_PBA_CTRL_THRESH, 38) | FIELD_PREP(NP6L_PBA_CTRL_XTHRESH, 76));
	for (i = 0; i < NP6L_NR_QUEUES; i++) {
		fnp6l_rmw(np, NP6L_HRXQ_PDQ(i) + 0, NP6L_PDQ_BUF_LIMIT, 0xc0);
		fnp6l_rmw(np, NP6L_HRXQ_PDQ(i) + 8, NP6L_PDQ_BUF_LIMIT, 0xc0);
	}
	fnp6l_rmw(np, NP6L_HRX_TUNNEL_PDQ + 0, NP6L_PDQ_BUF_LIMIT, 0xc0);
	fnp6l_rmw(np, NP6L_HRX_TUNNEL_PDQ + 8, NP6L_PDQ_BUF_LIMIT, 0xc0);
	fnp6l_rmw(np, NP6L_XG_QUEUE_CTRL, NP6L_XG_QUEUE_RX_PBA_MAX | NP6L_XG_QUEUE_TX_PBA_MAX,
		  FIELD_PREP(NP6L_XG_QUEUE_RX_PBA_MAX, 144) |
		  FIELD_PREP(NP6L_XG_QUEUE_TX_PBA_MAX, 400));
	for (i = 0; i < NP6L_NR_MACS; i++) {
		fnp6l_rmw(np, NP6L_MAC(i) + NP6L_MAC_PDQ_BUF_CTRL, NP6L_PDQ_BUF_LIMIT, 0x100);
		fnp6l_rmw(np, NP6L_MAC(i) + NP6L_MAC_PDQ_JUMBO_CTRL, NP6L_PDQ_BUF_LIMIT, 0x100);
		fnp6l_wr(np, NP6L_MAC(i) + NP6L_MAC_PDQ_QUEUE_CTRL, NP6L_PDQ_QUEUE_CTRL_INIT);
		fnp6l_rmw(np, NP6L_MAC(i) + NP6L_MAC_RX_TAG,
			  NP6L_MAC_RX_TAG_RX_PBA_MAX | NP6L_MAC_RX_TAG_TX_PBA_MAX,
			  FIELD_PREP(NP6L_MAC_RX_TAG_RX_PBA_MAX, 36) |
			  FIELD_PREP(NP6L_MAC_RX_TAG_TX_PBA_MAX, 256));
	}
}

/* ------------------------------------------------- session engine (sse) */

/*
 * Session search engine (SSE). The engine is given a primary hash table
 * (PHT) and an overflow table (OFT) in the NP's own DDR at
 * 0x76000000-0x7fffffff, which must lie outside Linux memory (refused
 * otherwise), then the search is turned on. The loader leaves the PHT and
 * OFT configs at 0x10180000 and 0x08040000 (bases in Linux memory): both
 * are rewritten before the search control and the interrupt enables. The
 * CPU zeroes the two tables. Done at probe with the flow offload. Undone
 * only by a reset (the loader rewrites the block).
 */
#define NP6L_SSE_IRQ_CTRL		0x6400
#define  NP6L_SSE_IRQ_STATUS		GENMASK(12, 3)	/* insert/delete/query failed, OFT full, purge */
#define  NP6L_SSE_IRQ_EN		(BIT(28) | BIT(29))	/* engine enables 0/1 */
#define NP6L_SSE_SEARCH_CTRL		0x6408
/* _INIT: search depth, IPsec and multicast lookups, multicast depth */
#define  NP6L_SSE_SEARCH_CTRL_INIT	0x00802101
#define NP6L_SSE_PHT_CFG		0x6410
#define NP6L_SSE_OFT_CFG		0x6418
#define NP6L_SSE_OFT_FREE		0x6420
#define NP6L_SSE_OFT_HEAD		0x6428
#define NP6L_SSE_OFT_TAIL		0x6430
#define NP6L_SSE_INSERTS		0x6438
#define NP6L_SSE_INSERTS_OK		0x6440
#define NP6L_SSE_DELETES		0x6448
#define NP6L_SSE_DELETES_OK		0x6450
#define NP6L_SSE_ENTRIES		0x6468
#define NP6L_SSE_SEARCHES		0x6470
#define NP6L_SSE_SEARCH_HITS		0x6478
#define NP6L_SSE_HASH_CTRL		0x6488
#define NP6L_SSE_HASH_MASK		0x6490
#define NP6L_SSE_AGE_TICK		0x6498
#define  NP6L_SSE_AGE_TICK_UNIT		GENMASK(27, 0)
#define NP6L_SSE_AGE_CTRL		0x64a0
#define  NP6L_SSE_AGE_CLK_EN		BIT(24)
#define NP6L_SSE_PURGE_CTRL		0x64c0
#define NP6L_SSE_MAP_SEL0		0x6568
#define NP6L_SSE_MAP_SEL1		0x6570
#define NP6L_SSE_FLUSH_CTRL		0x6580
#define  NP6L_SSE_FLUSH			BIT(0)
#define NP6L_SSE_CMD_STATUS		0x6640	/* command queue status */
#define NP6L_SSE_CMD_DROPS		0x6648	/* dropped commands 15:0 */
#define NP6L_MSG_BASE			0xfa80	/* message channel, not used */
#define NP6L_MSG_BASE_HI		0xfa88
#define NP6L_MSG_CTRL			0xfab8

/* DDR of the NP: never Linux memory */
#define NP6L_DDR_BASE			0x76000000U
#define NP6L_DDR_SIZE			0x0a000000U
#define NP6L_OFT_BASE			0x77000000U
#define NP6L_OFT_SIZE			0x05000000U	/* 80 MiB, 128 byte entries */
#define NP6L_PHT_BASE			0x7c000000U
#define NP6L_PHT_SIZE			0x04000000U	/* 64 MiB */
/* ageing tick = clock / 50 */
#define NP6L_SSE_AGE_TICK_INIT		0x0659fa0

static DEFINE_MUTEX(fnp6l_sse_lock);

/*
 * Table sizes in 128-byte buckets, read once at probe: 0 = the whole region
 * (PHT 512 Ki buckets, OFT 640 Ki). A smaller power of two (at least
 * NP6L_SSE_MIN_BUCKETS) keeps the same bases and the same hash formula; it
 * only serves to fill the engine with few sessions. Built in, the driver
 * takes them from the kernel command line
 * (fortinet_np6lite.sse_pht_buckets=…).
 */
static unsigned int sse_pht_buckets;
module_param(sse_pht_buckets, uint, 0444);
MODULE_PARM_DESC(sse_pht_buckets, "PHT buckets (0: 524288; else a power of two from 1024), read at probe");
static unsigned int sse_oft_buckets;
module_param(sse_oft_buckets, uint, 0444);
MODULE_PARM_DESC(sse_oft_buckets, "OFT buckets (0: 655360; else a power of two from 1024), read at probe");
#define NP6L_SSE_MIN_BUCKETS		1024

static u32 fnp6l_sse_buckets(struct fnp6l *np, const char *name,
			     unsigned int want, u32 max)
{
	if (!want || want == max)
		return max;
	if (want < NP6L_SSE_MIN_BUCKETS || want > max || !is_power_of_2(want)) {
		dev_warn(np->dev, "sse: %s %u buckets ignored (a power of two, %u to %u)\n",
			 name, want, NP6L_SSE_MIN_BUCKETS, max);
		return max;
	}
	dev_info(np->dev, "sse: %s reduced to %u buckets\n", name, want);
	return want;
}

static void fnp6l_sse_log(struct fnp6l *np, const char *when)
{
	dev_info(np->dev,
		 "sse %s: irq_ctrl %#x search_ctrl %#x pht_cfg %#x oft_cfg %#x oft_free %#x head %#x tail %#x hash_ctrl %#x hash_mask %#x age_tick %#x age_ctrl %#x flush_ctrl %#x\n",
		 when, fnp6l_rd(np, NP6L_SSE_IRQ_CTRL), fnp6l_rd(np, NP6L_SSE_SEARCH_CTRL),
		 fnp6l_rd(np, NP6L_SSE_PHT_CFG), fnp6l_rd(np, NP6L_SSE_OFT_CFG),
		 fnp6l_rd(np, NP6L_SSE_OFT_FREE), fnp6l_rd(np, NP6L_SSE_OFT_HEAD),
		 fnp6l_rd(np, NP6L_SSE_OFT_TAIL), fnp6l_rd(np, NP6L_SSE_HASH_CTRL),
		 fnp6l_rd(np, NP6L_SSE_HASH_MASK), fnp6l_rd(np, NP6L_SSE_AGE_TICK),
		 fnp6l_rd(np, NP6L_SSE_AGE_CTRL), fnp6l_rd(np, NP6L_SSE_FLUSH_CTRL));
	dev_info(np->dev,
		 "sse %s: inserts %u ok %u deletes %u ok %u entries %u searches %u hits %u map_sel %#x %#x purge_ctrl %#x cmd_status %#x cmd_drops %#x msg %#x:%#x ctrl %#x\n",
		 when, fnp6l_rd(np, NP6L_SSE_INSERTS), fnp6l_rd(np, NP6L_SSE_INSERTS_OK),
		 fnp6l_rd(np, NP6L_SSE_DELETES), fnp6l_rd(np, NP6L_SSE_DELETES_OK),
		 fnp6l_rd(np, NP6L_SSE_ENTRIES), fnp6l_rd(np, NP6L_SSE_SEARCHES),
		 fnp6l_rd(np, NP6L_SSE_SEARCH_HITS), fnp6l_rd(np, NP6L_SSE_MAP_SEL0),
		 fnp6l_rd(np, NP6L_SSE_MAP_SEL1), fnp6l_rd(np, NP6L_SSE_PURGE_CTRL),
		 fnp6l_rd(np, NP6L_SSE_CMD_STATUS), fnp6l_rd(np, NP6L_SSE_CMD_DROPS),
		 fnp6l_rd(np, NP6L_MSG_BASE_HI), fnp6l_rd(np, NP6L_MSG_BASE),
		 fnp6l_rd(np, NP6L_MSG_CTRL));
}

/* zero a table of the NP DDR through write-combined mappings, 4 MiB at a time */
static int fnp6l_ddr_zero(struct fnp6l *np, phys_addr_t base, size_t size)
{
	size_t off;
	void *va;

	for (off = 0; off < size; off += SZ_4M) {
		va = memremap(base + off, SZ_4M, MEMREMAP_WC);
		if (!va) {
			dev_err(np->dev, "sse: cannot map %pa + %#zx\n", &base, off);
			return -ENOMEM;
		}
		memset(va, 0, SZ_4M);
		wmb();
		memunmap(va);
		cond_resched();
	}
	return 0;
}

static int fnp6l_sse_flush(struct fnp6l *np)
{
	u32 v;
	int ret;

	fnp6l_wr(np, NP6L_SSE_FLUSH_CTRL, fnp6l_rd(np, NP6L_SSE_FLUSH_CTRL) | NP6L_SSE_FLUSH);
	/* the flush may take up to 10 s, polled every 1 ms */
	ret = readl_poll_timeout(np->base + NP6L_SSE_FLUSH_CTRL, v, !(v & NP6L_SSE_FLUSH),
				 1000, 10 * USEC_PER_SEC);
	if (ret)
		dev_err(np->dev, "sse: flush does not complete (%#x)\n", v);
	return ret;
}

static int fnp6l_sse_init(struct fnp6l *np)
{
	u32 n, h, prctl, mask, irq_ctrl;
	struct resource *res;
	int ret;

	if (np->sse_done)
		return 0;
	/* the tables must never overlap memory Linux uses */
	if (region_intersects(NP6L_DDR_BASE, NP6L_DDR_SIZE, IORESOURCE_SYSTEM_RAM,
			      IORES_DESC_NONE) != REGION_DISJOINT) {
		dev_err(np->dev, "sse: %#x-%#x overlaps System RAM, refused\n",
			NP6L_DDR_BASE, NP6L_DDR_BASE + NP6L_DDR_SIZE - 1);
		return -EBUSY;
	}
	res = request_mem_region(NP6L_DDR_BASE, NP6L_DDR_SIZE, "fortinet-np6lite ddr");
	if (!res) {
		dev_err(np->dev, "sse: NP DDR region busy, refused\n");
		return -EBUSY;
	}

	fnp6l_sse_log(np, "before");
	ret = fnp6l_ddr_zero(np, NP6L_OFT_BASE, NP6L_OFT_SIZE);
	if (!ret)
		ret = fnp6l_ddr_zero(np, NP6L_PHT_BASE, NP6L_PHT_SIZE);
	if (ret) {
		release_mem_region(NP6L_DDR_BASE, NP6L_DDR_SIZE);
		return ret;
	}
	dev_info(np->dev, "sse: OFT %#x (%u MiB) and PHT %#x (%u MiB) zeroed\n",
		 NP6L_OFT_BASE, NP6L_OFT_SIZE >> 20, NP6L_PHT_BASE, NP6L_PHT_SIZE >> 20);

	np->sse_pht_n = fnp6l_sse_buckets(np, "PHT", READ_ONCE(sse_pht_buckets),
					  NP6L_PHT_SIZE >> 7);
	np->sse_oft_n = fnp6l_sse_buckets(np, "OFT", READ_ONCE(sse_oft_buckets),
					  NP6L_OFT_SIZE >> 7);
	/* tables first, search last */
	fnp6l_wr(np, NP6L_SSE_PHT_CFG, NP6L_PHT_BASE | np->sse_pht_n);
	fnp6l_wr(np, NP6L_SSE_OFT_CFG, NP6L_OFT_BASE | np->sse_oft_n);
	/* hash prime and seed from the PHT size */
	n = (np->sse_pht_n - 1) & GENMASK(23, 0);
	h = fls(n) - 1;
	prctl = (h + 1) << 27 | n << (23 - h);
	mask = (27 - h) | 0x1e0;
	fnp6l_wr(np, NP6L_SSE_HASH_CTRL, prctl);
	fnp6l_wr(np, NP6L_SSE_HASH_MASK, mask);
	/* ageing clock */
	fnp6l_rmw(np, NP6L_SSE_AGE_TICK, NP6L_SSE_AGE_TICK_UNIT, NP6L_SSE_AGE_TICK_INIT);
	fnp6l_wr(np, NP6L_SSE_AGE_CTRL, fnp6l_rd(np, NP6L_SSE_AGE_CTRL) | NP6L_SSE_AGE_CLK_EN);
	irq_ctrl = fnp6l_rd(np, NP6L_SSE_IRQ_CTRL);
	fnp6l_wr(np, NP6L_SSE_IRQ_CTRL, irq_ctrl | NP6L_SSE_IRQ_EN);
	fnp6l_wr(np, NP6L_SSE_SEARCH_CTRL, fnp6l_rd(np, NP6L_SSE_SEARCH_CTRL) | NP6L_SSE_SEARCH_CTRL_INIT);
	fnp6l_wr(np, NP6L_SSE_SEARCHES, 0);
	fnp6l_wr(np, NP6L_SSE_MAP_SEL0, 0);
	fnp6l_wr(np, NP6L_SSE_MAP_SEL1, 0);
	ret = fnp6l_sse_flush(np);
	fnp6l_sse_log(np, "after");
	np->sse_done = true;	/* tables handed over: keep the region */
	irq_ctrl = fnp6l_rd(np, NP6L_SSE_IRQ_CTRL);
	if ((irq_ctrl & NP6L_SSE_IRQ_STATUS) & ~BIT(9))
		dev_warn(np->dev, "sse: interrupt status %#lx\n",
			 irq_ctrl & NP6L_SSE_IRQ_STATUS);
	if (fnp6l_rd(np, NP6L_SSE_OFT_FREE) != np->sse_oft_n - 1)
		dev_warn(np->dev, "sse: OFT free count %#x, expected %#x\n",
			 fnp6l_rd(np, NP6L_SSE_OFT_FREE), np->sse_oft_n - 1);
	/* refusals are counted from here (INSERTS_OK read first) */
	np->ins_gap0 = fnp6l_rd(np, NP6L_SSE_INSERTS_OK);
	np->ins_gap0 = fnp6l_rd(np, NP6L_SSE_INSERTS) - np->ins_gap0;
	dev_info(np->dev, "sse: engine on (PHT %u OFT %u buckets, hash_ctrl %#x hash_mask %#x)%s\n",
		 np->sse_pht_n, np->sse_oft_n, prctl, mask,
		 ret ? ", flush timed out" : "");
	return ret;
}

/*
 * Session commands: an 8 byte header (byte 0 = 0x80 | command, byte 1 =
 * total length / 8, byte 3 = host transmit queue, word 1 = argument, 0 for
 * insert and an IPv4 delete) then the entry (insert: 128 bytes) or its key
 * (delete: 16 bytes), in a buffer posted on a host transmit queue with the
 * SSE command bit (bit 81) and end of packet, no tag. Entry fields:
 * addresses and ports copied as on the wire (no swapping), bits 177-179 for
 * TCP (byte 22: 0x00 for UDP, 0x0e for TCP), reserved pointers of bytes
 * 110-127 all ones. Bit 176 (byte 22 bit 0) makes the engine ignore the
 * action of a hit IPv4 session (observed). Without an output, ACT_OUT_VALID
 * stays 0 (meant for the host on queue act_hostq; unconfirmed, not tried
 * with bit 176 clear).
 *
 * Options of an entry (struct fnp6l_sse_opt):
 *   output         ACT_OUT_VALID (bit 155) and out_lif (bits 489:480, byte
 *                  60): trunk/LIF of the target; a host LIF selects the
 *                  host queue (act_hostq is then ignored), a port trunk
 *                  offloads to that port.
 *   dmac           ACT_SET_DMAC (bit 154) and the destination MAC (bytes
 *                  66-71).
 *   mtu            bits 479:464, bytes 58-59.
 *   full entry     a complete IPv4 entry: ACT_SET_SMAC and ACT_DEC_TTL
 *                  (bits 153, 158), multicast next and tail pointers =
 *                  0xffffff (bytes 32-34, 36-38), mtu 1500 unless given,
 *                  the tuple after NAT (bytes 72-83, the key without NAT),
 *                  bytes 104-121 = 0xff, 122 = 0x0f, 125 = 0x0c (UDP) or
 *                  0x0b (TCP).
 * The chain pointer (bytes 16-18) and the timestamp (28-31) are left to the
 * engine.
 */
#define NP6L_SSE_CMD_INSERT		1
#define NP6L_SSE_CMD_DELETE		2
#define NP6L_SSE_ENTRY_LEN		128
#define NP6L_SSE_KEY4_LEN		16
/*
 * Up to 64 descriptors (sse_slots): the ring size register takes the size
 * as a count, as for the host frame queue (1024); 16 left no room for a
 * burst of queries ahead of the deletes of short connections.
 */
#define NP6L_SSE_CMD_SLOTS		64
#define NP6L_SSE_CMD_MIN_SLOTS		8
#define NP6L_SSE_CMD_BUF		1024
#define NP6L_SSE_QUERY_ROOM(n)		((n) / 4)	/* kept for inserts and deletes */
#define NP6L_SSE_DEL_ROOM(n)		((n) / 8)	/* kept for deletes */
#define NP6L_SSE_TXQ			1	/* host transmit queue of the commands */

struct fnp6l_sse_opt {
	u32 out, mtu;
	u8 dmac[ETH_ALEN];
	bool has_out, has_mtu, has_dmac, full;
	u16 out_vid;		/* VID pushed on output (0: none), bytes 62-63 BE */
	/* NAT (full only): translated tuple, ACT_NAT_* bits when changed */
	bool has_nat;
	__be32 nsip, ndip;
	__be16 nsport, ndport;
};

static void fnp6l_sse_entry4(u8 *e, u8 proto, __be32 sip, __be16 sport,
			     __be32 dip, __be16 dport, u32 in_lif, u32 vid,
			     u32 hostq, u32 tmo, const struct fnp6l_sse_opt *o)
{
	u32 w;

	memcpy(e + 0, &sip, 4);
	memcpy(e + 4, &dip, 4);
	memcpy(e + 8, &sport, 2);
	memcpy(e + 10, &dport, 2);
	/* bits 103:96 protocol, 115:104 in_vid, 125:116 in_lif, 126 KEY_TAGGED, 127 KEY_VALID */
	w = proto | FIELD_PREP(GENMASK(19, 8), vid) |
	    FIELD_PREP(GENMASK(29, 20), in_lif) | BIT(31);
	put_unaligned_le32(w, e + 12);
	if (!o)
		return;
	/* bit 176 never set (inhibits the action) */
	if (proto == IPPROTO_TCP)
		e[22] |= GENMASK(3, 1);		/* bits 177-179 */
	e[23] = (e[23] & BIT(0)) | (hostq & 0x7f) << 1;	/* act_hostq 191:185 */
	put_unaligned_le16(tmo, e + 26);	/* entry_timeout 223:208 */
	if (o->full) {
		e[19] |= BIT(1) | BIT(6);	/* ACT_SET_SMAC, ACT_DEC_TTL */
		memset(e + 32, 0xff, 3);	/* mcast_next */
		memset(e + 36, 0xff, 3);	/* mcast_tail */
		put_unaligned_le16(o->has_mtu ? o->mtu : 1500, e + 58);
		if (o->has_nat) {
			/*
			 * ACT_NAT_SADDR/ACT_NAT_DADDR bits 156/157,
			 * ACT_NAT_SPORT/ACT_NAT_DPORT bits 169/170; the engine
			 * fixes the IP and L4 checksums (tested on hardware).
			 */
			if (o->nsip != sip)
				e[19] |= BIT(4);
			if (o->ndip != dip)
				e[19] |= BIT(5);
			if (o->nsport != sport)
				e[21] |= BIT(1);
			if (o->ndport != dport)
				e[21] |= BIT(2);
			sport = o->nsport;
			dport = o->ndport;
			sip = o->nsip;
			dip = o->ndip;
		}
		memcpy(e + 72, &sport, 2);	/* nat_sport */
		memcpy(e + 74, &dport, 2);	/* nat_dport */
		memcpy(e + 76, &sip, 4);	/* nat_saddr */
		memcpy(e + 80, &dip, 4);	/* nat_daddr */
		memset(e + 104, 0xff, 18);
		e[122] = 0x0f;
		e[125] = proto == IPPROTO_TCP ? 0x0b : 0x0c;
	} else {
		memset(e + 110, 0xff, NP6L_SSE_ENTRY_LEN - 110);	/* reserved, all ones */
		if (o->has_mtu)
			put_unaligned_le16(o->mtu, e + 58);
	}
	if (o->has_out) {
		e[19] |= BIT(3);		/* ACT_OUT_VALID */
		e[60] = o->out & 0xff;		/* out_lif 489:480 */
		e[61] = (e[61] & ~GENMASK(1, 0)) | (o->out >> 8 & 3);
	}
	/*
	 * out_vid, big-endian VID: the EGR inserts an 802.1Q tag of TPID
	 * 0x8100 after the second tag of the egress tag control [out_lif]
	 * if any; 0 = untagged, the ingress tag (in_vid) being always
	 * removed.
	 */
	if (o->out_vid)
		put_unaligned_be16(o->out_vid & 0xfff, e + 62);
	if (o->has_dmac) {
		e[19] |= BIT(2);		/* ACT_SET_DMAC */
		memcpy(e + 66, o->dmac, ETH_ALEN);	/* destination MAC */
	}
}

static unsigned int sse_slots = NP6L_SSE_CMD_SLOTS;
module_param(sse_slots, uint, 0644);
MODULE_PARM_DESC(sse_slots, "session command descriptors (8 to 64, default 64), read once, at the first command");

static int fnp6l_cmdq_up(struct fnp6l *np)
{
	struct fnp6l_ring *r = &np->cmdq;
	unsigned int n = clamp_t(unsigned int, READ_ONCE(sse_slots),
				 NP6L_SSE_CMD_MIN_SLOTS, NP6L_SSE_CMD_SLOTS);
	u32 d[4] = { };
	int ret;

	if (np->cmdq_on)
		return 0;
	/* managed buffers, allocated once: a failed start is tried again on them */
	if (!np->cmd_buf) {
		np->cmd_buf = dmam_alloc_coherent(np->dev,
						  NP6L_SSE_CMD_SLOTS * NP6L_SSE_CMD_BUF,
						  &np->cmd_dma, GFP_KERNEL);
		if (!np->cmd_buf)
			return -ENOMEM;
	}
	if (!r->desc) {
		ret = fnp6l_ring_alloc(np, r, true, NP6L_SSE_TXQ, n);
		if (ret) {
			r->desc = NULL;
			return ret;
		}
	}
	ret = fnp6l_ring_start(np, r);
	if (ret)
		return ret;
	np->cmdq_on = true;
	/* no interrupt from this queue; its sources to the vectors of queue 0 */
	writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_IDLE_TIMER |
	       NP6L_Q_INT_FRAMES | NP6L_Q_INT_FATAL,
	       r->regs + NP6L_Q_INT_ENABLE_CLR);
	fnp6l_tbl_op(np, NP6L_TBL_IRQ_VEC, 0x40 + 4 * NP6L_SSE_TXQ, d, true);
	d[0] = 4;
	fnp6l_tbl_op(np, NP6L_TBL_IRQ_VEC, 0x41 + 4 * NP6L_SSE_TXQ, d, true);
	dev_info(np->dev, "sse: command queue htxq%u started, %u descriptors\n",
		 NP6L_SSE_TXQ, n);
	return 0;
}

/*
 * Session commands, under fnp6l_sse_lock. The NP writes back the done index
 * of the command queue (wb[0]) once it has read a descriptor and its buffer;
 * descriptor i always carries buffer i, so a buffer is only written again
 * when the ring wraps onto it, which needs the done index past it, as for a
 * frame. The queue is read in order and the done index only says that a
 * command was read, not what the engine made of it: a command is posted and
 * never waited for (a delete posted before an insert of the same key is read
 * first). Only a full queue is waited for, by a short busy poll
 * (sse_spin_us), the engine reading a command in a few microseconds; still
 * full, the command is refused (-EBUSY) and its caller keeps its state (a
 * flow left to the software flow table, an undeleted flow tried again
 * later): nothing sleeps under the command lock, which every flow table
 * work takes. A done index that does not move for NP6L_SSE_TIMEOUT_US while
 * commands wait is reported once ("not taken"), then again when it moves. A
 * done index outside the ring (nothing written back yet) is ignored.
 */
static unsigned int sse_spin_us = 100;
module_param(sse_spin_us, uint, 0644);
MODULE_PARM_DESC(sse_spin_us, "busy wait (us, at most 1000) on a full session command queue before refusing a command");
#define NP6L_SSE_SPIN_MAX_US		1000
#define NP6L_SSE_TIMEOUT_US		200000

/* catch up with the done index (tx_lock) */
static void fnp6l_cmdq_reap(struct fnp6l_ring *r)
{
	unsigned int hw = le32_to_cpu(READ_ONCE(r->wb[0])) & 0xffff;

	if (hw < r->size)
		r->head = hw;
}

enum { FNP6L_CMDQ_OK, FNP6L_CMDQ_STALLED, FNP6L_CMDQ_RESUMED };
static DEFINE_RATELIMIT_STATE(fnp6l_cmdq_rs, 5 * HZ, 10);

/* follow the done index (tx_lock, after fnp6l_cmdq_reap) */
static int fnp6l_cmdq_watch(struct fnp6l *np, u64 now)
{
	struct fnp6l_ring *r = &np->cmdq;
	int ev = FNP6L_CMDQ_OK;
	u32 ms;

	if (r->head != np->cmd_seen || r->head == r->tail) {
		if (np->cmd_stalled) {
			ms = div_u64(now - np->cmd_seen_ns, NSEC_PER_MSEC);
			if (ms > np->sse_stall_max_ms)
				np->sse_stall_max_ms = ms;
			np->cmd_stalled = false;
			ev = FNP6L_CMDQ_RESUMED;
		}
		np->cmd_seen = r->head;
		np->cmd_seen_ns = now;
	} else if (!np->cmd_stalled &&
		   now - np->cmd_seen_ns > (u64)NP6L_SSE_TIMEOUT_US * NSEC_PER_USEC) {
		np->cmd_stalled = true;
		np->sse_tmo++;
		ev = FNP6L_CMDQ_STALLED;
	}
	return ev;
}

/* a stall of the done index, with the queues the NP writes to the host */
static void fnp6l_cmdq_report(struct fnp6l *np, int ev)
{
	struct fnp6l_ring *r = &np->cmdq;
	unsigned int q;

	if (ev == FNP6L_CMDQ_RESUMED) {
		dev_info_ratelimited(np->dev, "sse: htxq%u commands taken again (stall up to %u ms)\n",
				     NP6L_SSE_TXQ, np->sse_stall_max_ms);
		return;
	}
	if (ev != FNP6L_CMDQ_STALLED || !__ratelimit(&fnp6l_cmdq_rs))
		return;
	dev_warn(np->dev, "sse: htxq%u command %u not taken (head %u tail %u) for %u ms: fetch %u done %u cmd_status %#x cmd_drops %#x\n",
		 NP6L_SSE_TXQ, r->head, r->head, r->tail, NP6L_SSE_TIMEOUT_US / 1000,
		 readl(r->regs + NP6L_Q_RING_FETCH), readl(r->regs + NP6L_Q_RING_DONE),
		 fnp6l_rd(np, NP6L_SSE_CMD_STATUS), fnp6l_rd(np, NP6L_SSE_CMD_DROPS));
	for_each_set_bit(q, &np->rx_mask, NP6L_NR_QUEUES)
		dev_warn(np->dev, "sse: hrxq%u head %u fetch %u done %u, host at %u\n", q,
			 readl(np->rx[q].regs + NP6L_Q_RING_HEAD),
			 readl(np->rx[q].regs + NP6L_Q_RING_FETCH),
			 readl(np->rx[q].regs + NP6L_Q_RING_DONE), np->rx[q].head);
}

/* whether the NP has yet to read command descriptor @idx, posted by us */
static bool fnp6l_cmdq_pending(struct fnp6l *np, unsigned int idx)
{
	struct fnp6l_ring *r = &np->cmdq;
	unsigned int used, pos;

	spin_lock_bh(&np->tx_lock);
	fnp6l_cmdq_reap(r);
	used = (r->tail + r->size - r->head) % r->size;
	pos = (idx + r->size - r->head) % r->size;
	spin_unlock_bh(&np->tx_lock);
	return pos < used;
}

/* free command descriptors */
static unsigned int fnp6l_cmdq_room(struct fnp6l *np)
{
	unsigned int n;

	spin_lock_bh(&np->tx_lock);
	fnp6l_cmdq_reap(&np->cmdq);
	n = fnp6l_tx_free(&np->cmdq);
	spin_unlock_bh(&np->tx_lock);
	return n;
}

/* busy poll until the NP has read descriptor @idx: 0, or -EBUSY */
static int fnp6l_sse_spin(struct fnp6l *np, unsigned int idx)
{
	unsigned int spin = min_t(unsigned int, READ_ONCE(sse_spin_us),
				  NP6L_SSE_SPIN_MAX_US);
	u64 t0 = ktime_get_ns();
	bool pending;
	int ret = -EBUSY;
	u32 dt;

	/* a zero timeout would never end the busy poll */
	if (spin &&
	    !read_poll_timeout_atomic(fnp6l_cmdq_pending, pending, !pending,
				      1, spin, false, np, idx))
		ret = 0;
	dt = div_u64(ktime_get_ns() - t0, NSEC_PER_USEC);
	np->sse_waits++;
	np->sse_wait_us += dt;
	if (dt > np->sse_wait_max_us)
		np->sse_wait_max_us = dt;
	return ret;
}

/* post one command; a full queue is polled once for its oldest command */
static int fnp6l_sse_post(struct fnp6l *np, const u8 *msg, unsigned int len)
{
	struct fnp6l_ring *r = &np->cmdq;
	unsigned int i, oldest;
	bool spun = false;
	dma_addr_t dma;
	__le32 *d;
	int ev;

	if (WARN_ON_ONCE(r->size > NP6L_SSE_CMD_SLOTS || len > NP6L_SSE_CMD_BUF))
		return -EINVAL;
	for (;;) {
		spin_lock_bh(&np->tx_lock);
		fnp6l_cmdq_reap(r);
		ev = fnp6l_cmdq_watch(np, ktime_get_ns());
		if (fnp6l_tx_free(r) >= 1)
			break;
		oldest = r->head;
		spin_unlock_bh(&np->tx_lock);
		fnp6l_cmdq_report(np, ev);
		if (spun || fnp6l_sse_spin(np, oldest)) {
			np->sse_full++;
			return -EBUSY;
		}
		spun = true;
	}
	i = r->tail;
	dma = np->cmd_dma + i * NP6L_SSE_CMD_BUF;
	memcpy(np->cmd_buf + i * NP6L_SSE_CMD_BUF, msg, len);
	d = &r->desc[4 * i];
	r->skb[i] = NULL;
	r->blen[i] = 0;		/* coherent buffer: nothing to unmap */
	d[0] = cpu_to_le32(lower_32_bits(dma));
	d[1] = cpu_to_le32(np->addr_hi | FIELD_PREP(NP6L_TXD1_FRAME_LEN, len));
	d[2] = cpu_to_le32(FIELD_PREP(NP6L_TXD2_SEG_LEN, len) | NP6L_TXD2_EOP | NP6L_TXD2_SSE_CMD);
	d[3] = 0;
	r->tail = (i + 1) % r->size;
	wmb();
	writel(r->tail, r->regs + NP6L_Q_RING_HEAD);
	spin_unlock_bh(&np->tx_lock);
	fnp6l_cmdq_report(np, ev);
	np->sse_cmds++;
	return 0;
}

static void fnp6l_dbg_cap_show(struct seq_file *m, struct fnp6l *np);

static int fnp6l_dbg_sse_show(struct seq_file *m, void *unused)
{
	struct fnp6l *np = m->private;
	unsigned int t;
	u32 off;

	seq_printf(m, "initialised %d\n", np->sse_done);
	for (off = NP6L_SSE_IRQ_CTRL; off <= NP6L_SSE_CMD_DROPS; off += 8)
		seq_printf(m, "%#06x %08x\n", off, fnp6l_rd(np, off));
	seq_printf(m, "%#06x %08x\n%#06x %08x\n%#06x %08x\n",
		   NP6L_MSG_BASE, fnp6l_rd(np, NP6L_MSG_BASE),
		   NP6L_MSG_BASE_HI, fnp6l_rd(np, NP6L_MSG_BASE_HI),
		   NP6L_MSG_CTRL, fnp6l_rd(np, NP6L_MSG_CTRL));
	seq_printf(m, "ft flows %u qsent %lu qreply %lu qmatch %lu qchange %lu qdrop %lu qoff %d\n",
		   np->ft_nflows, np->ft_qsent, np->ft_qreply, np->ft_qmatch,
		   np->ft_qchange, np->ft_qdrop, np->ft_qoff);
	seq_printf(m, "sse cmds %lu waits %lu wait_us %llu max_us %u sleeps %lu full %lu tmo %lu spin_us %u stall_ms %u qskip %lu slots %u\n",
		   np->sse_cmds, np->sse_waits, np->sse_wait_us,
		   np->sse_wait_max_us, np->sse_sleeps, np->sse_full,
		   np->sse_tmo, READ_ONCE(sse_spin_us), np->sse_stall_max_ms,
		   np->sse_qskip, np->cmdq.size);
	seq_printf(m, "ft dead %u delfail %lu dfree %lu lagfail %lu\n",
		   np->ft_ndead, np->ft_delfail, np->ft_dfree, np->ft_lagfail);
	/* messages by header byte 0 (3:0); the last one no query matched */
	seq_printf(m, "ft msg nomatch %lu", np->ft_qnomatch);
	for (t = 0; t < NP6L_FT_MSGTYPES; t++)
		if (np->ft_msgtype[t])
			seq_printf(m, " t%x %lu", t, np->ft_msgtype[t]);
	seq_printf(m, " last %*phN\n", np->ft_msghdr_len, np->ft_msghdr);
	/* cookies answered without the command lock, inserts refused to keep
	 * room for deletes, unmatched messages carrying a deleted key, messages
	 * by header byte 1 */
	seq_printf(m, "ft gate unk_destroy %lu unk_stats %lu iskip %lu nomatch_del %lu",
		   np->ft_unk_destroy, np->ft_unk_stats, np->sse_iskip,
		   np->ft_qnomatch_del);
	for (t = 0; t < NP6L_FT_MSGTYPES; t++)
		if (np->ft_msgop[t])
			seq_printf(m, " op%x %lu", t, np->ft_msgop[t]);
	seq_putc(m, '\n');
	fnp6l_dbg_cap_show(m, np);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(fnp6l_dbg_sse);

/* ------------------------------------------------- ingress class table */

/*
 * Ingress resolution by the hashed class table: key {w0, w1} = {LIF in
 * w0[31:24] and w1[1:0], the port tag in w0[23:12], the VID in w0[11:0], valid
 * w1[2]}; the hash row is the CRC-16/CCITT of the 3 big-endian bytes of
 * w0[23:0] (24 key bits, hash type 3) masked to the 64 rows; the cell is one of
 * the 4 banks of the row, at table index row * 4 + bank (an entry written at
 * index = row is silently ignored).
 */
/* CRC-16/CCITT, table-less form */
static u16 fnp6l_crc16_ccitt(const u8 *data, unsigned int n)
{
	u32 crc = 0xffff;

	while (n--) {
		u8 x = (crc >> 8) ^ *data++;

		x ^= x >> 4;
		crc = ((crc << 8) ^ ((u32)x << 12) ^ ((u32)x << 5) ^ x) & 0xffff;
	}
	return crc;
}

/* hash row of a key: CRC-16/CCITT of w0[23:0], big-endian (type 3) */
static u32 fnp6l_class_bucket(u32 w0)
{
	u8 b[3] = { w0 >> 16, w0 >> 8, w0 };
	u32 bk = fnp6l_crc16_ccitt(b, sizeof(b)) & NP6L_CLASS_IDX_MASK;

	return bk >= NP6L_CLASS_BUCKETS ? bk - NP6L_CLASS_BUCKETS : bk;
}

static void fnp6l_class_key(unsigned int ptag, unsigned int vid,
			    unsigned int lif, u32 *w0, u32 *w1)
{
	*w0 = (vid & 0xfff) | ((ptag & 0xfff) << 12) | ((lif & 0xff) << 24);
	*w1 = ((lif >> 8) & 0x3) | NP6L_CLASS_VALID;
}

/*
 * Insert one lone entry (no chaining); returns the table index or < 0. Reuse
 * the bank already holding this key (idempotent) or the first free bank of
 * the row; -EBUSY only when the four banks hold other keys. Indices >= 128
 * (beyond the index mask 0x7f, e.g. the switch conduit at row 44 -> 176) are
 * distinct cells (tested on hardware).
 */
static int fnp6l_class_insert(struct fnp6l *np, unsigned int ptag,
			      unsigned int vid, unsigned int lif)
{
	u32 w0, w1, d[4], cur[4];
	unsigned int row, bank, idx, free_idx = ~0u;

	fnp6l_class_key(ptag, vid, lif, &w0, &w1);
	row = fnp6l_class_bucket(w0);

	for (bank = 0; bank < NP6L_CLASS_BANKS; bank++) {
		idx = row * NP6L_CLASS_BANKS + bank;
		if (fnp6l_tbl_op(np, NP6L_TBL_CLASS, idx, cur, false))
			return -EIO;
		if ((cur[1] & NP6L_CLASS_VALID) && cur[0] == w0 && cur[1] == w1)
			break;				/* same key: reuse it */
		if (free_idx == ~0u && !(cur[1] & NP6L_CLASS_VALID) &&
		    !cur[0] && !cur[1])
			free_idx = idx;
	}
	if (bank == NP6L_CLASS_BANKS) {			/* no identical key found */
		if (free_idx == ~0u) {
			dev_warn(np->dev,
				 "class table: row %u full (4 banks used), not inserted\n",
				 row);
			return -EBUSY;
		}
		idx = free_idx;
	}

	d[0] = w0;
	d[1] = w1;
	d[2] = 0;
	d[3] = 0;
	if (fnp6l_tbl_op(np, NP6L_TBL_CLASS, idx, d, true) ||
	    fnp6l_tbl_op(np, NP6L_TBL_CLASS, idx, cur, false))
		return -EIO;
	dev_dbg(np->dev,
		"class table: port tag %#x VID %#x -> LIF %u: row %u bank %u idx %u key %08x %08x\n",
		ptag, vid, lif, row, idx - row * NP6L_CLASS_BANKS, idx, w0, w1);
	if (cur[0] != w0 || cur[1] != w1) {
		u32 z[4] = { };

		fnp6l_tbl_op(np, NP6L_TBL_CLASS, idx, z, true);
		dev_err(np->dev, "class table: read back mismatch, entry cleared\n");
		return -EIO;
	}
	return idx;
}

/*
 * Cell of key {port tag, VID} (w0[23:0], whatever its LIF): the table index
 * and its entry in @cur, -ENOENT when no bank of the row holds the key.
 */
static int fnp6l_class_find(struct fnp6l *np, unsigned int ptag,
			    unsigned int vid, u32 *cur)
{
	unsigned int row, bank, idx;
	u32 w0, w1;

	fnp6l_class_key(ptag, vid, 0, &w0, &w1);
	row = fnp6l_class_bucket(w0);
	for (bank = 0; bank < NP6L_CLASS_BANKS; bank++) {
		idx = row * NP6L_CLASS_BANKS + bank;
		if (fnp6l_tbl_op(np, NP6L_TBL_CLASS, idx, cur, false))
			return -EIO;
		if ((cur[1] & NP6L_CLASS_VALID) &&
		    !((cur[0] ^ w0) & GENMASK(23, 0)))
			return idx;
	}
	return -ENOENT;
}

/*
 * Receive port tag of a MAC port: rx_port_tag read back from its MAC at
 * bring-up (fnp6l_mac_init set it to (port+1)<<4 = link<<4); fall back to
 * the per-port value link<<4 if the field reads 0. MAC port 2 = 0x030.
 */
static unsigned int fnp6l_port_tag(struct fnp6l *np, struct fnp6l_port *p)
{
	u32 ptag = fnp6l_rd(np, NP6L_MAC(p->link - 1) + NP6L_MAC_RX_TAG) & NP6L_MAC_RX_PORT_TAG;

	return ptag ? ptag : ((p->link & 0xff) << 4);
}

static int fnp6l_dbg_class_show(struct seq_file *m, void *unused)
{
	struct fnp6l *np = m->private;
	unsigned int b, nvalid = 0;
	u32 d[4], chain[4];

	seq_printf(m, "hash_size %08x port_tag_tpid %08x tag2_tpid %08x default_lif %08x\n",
		   fnp6l_rd(np, NP6L_CLASS_HASH_SIZE), fnp6l_rd(np, NP6L_IGR_PORT_TAG_TPID),
		   fnp6l_rd(np, NP6L_IGR_TAG2_TPID), fnp6l_rd(np, NP6L_IGR_DEFAULT_LIF));
	seq_printf(m, "ic_on %u ic_port_tag_fallback %llu sw_on %u sw_rx_retag %llu\n",
		   np->ic_on, np->ic_port_tag_fallback, np->sw_on, np->sw_rx_retag);
	for (b = 0; b < NP6L_CLASS_BUCKETS * NP6L_CLASS_BANKS; b++) {
		if (fnp6l_tbl_op(np, NP6L_TBL_CLASS, b, d, false) ||
		    fnp6l_tbl_op(np, NP6L_TBL_CLASS_CHAIN, b, chain, false))
			break;
		if (!(d[1] & NP6L_CLASS_VALID) && !d[0] && !d[1])
			continue;
		nvalid++;
		seq_printf(m, "idx %3u (row %2u bank %u) ent %08x %08x %08x %08x chain %08x\n",
			   b, b / NP6L_CLASS_BANKS, b % NP6L_CLASS_BANKS,
			   d[0], d[1], d[2], d[3], chain[0]);
	}
	seq_printf(m, "non-empty cells %u\n", nvalid);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(fnp6l_dbg_class);

/* ------------------------------------------------- flow table offload */

/*
 * Hardware offload of the Linux flow table to the session engine: IPv4 and
 * IPv6 TCP or UDP flows between the ports that are not DSA conduits (60E:
 * wan1, wan2), bonds of switch ports and bare switch ports (a user port
 * outside a bond, its own LIF: bare_ports), NAT and 802.1Q included,
 * forwarded by the NP at line rate with no CPU (measured). Needs the
 * ingress classification: the NP classifies each port to its LIF (60E:
 * wan1 -> 0, wan2 -> 2) in hardware (and strips the port tag), so a
 * session's in_lif is the ingress port LIF and out_lif the egress port LIF.
 * The offload state posts the host-queue LIF entries (LIFs 4-6,
 * trunk_members[64..67], trunk_cfg[255]), raises port_action of each
 * port LIF (60E: 0, 2, 3) to source action 1 (SSE lookup on) while keeping
 * the loader's forward target 1 so its non-IP frames are still delivered (a
 * mixed value), and gives each its own source MAC in lif_cfg, LIF 0
 * included. All of this is saved and restored should a step fail; a reset
 * also undoes it (the loader rewrites the block). The engine never ages a
 * session on its own: the driver follows the flow table (DESTROY = delete)
 * and reports activity from per-session accounting (STATS).
 */
#define NP6L_FT_HOSTQ			3		/* ignored with a port output */
#define NP6L_FT_ENTRY_TIMEOUT		2000		/* entry_timeout; the driver deletes entries itself */
/*
 * Limits of the offload; a flow refused stays in the software flow table,
 * which offers it again at its next refresh.
 *
 * The engine: it refuses an insert once its OFT has no free bucket left (a
 * session goes to the OFT when its PHT bucket is taken; measured: about
 * 1.13 million sessions with the full tables, IPv4 and IPv6 alike). A new
 * flow is admitted while the OFT free count, less the sessions posted since
 * it was read, stays at or above oft_min_free: 512 = the command queue (64)
 * times the sessions of a flow (up to 8), what may still be on its way when
 * the count is read. The count is read at most every oft_poll_ms, and again
 * at once (at most once a tick) when the estimate comes near the threshold.
 *
 * The host: every offloaded flow costs activity queries and their replies
 * (STATS); with the indexes sized at probe (ft_hash_bits), that cost grows
 * linearly with the number of flows (measured on the 60E: about a fifth of
 * the four cores at 131072 flows, where the software flow table spent a few
 * percent). host_guard_flows bounds the flows offloaded at once (one flow =
 * one direction of a connection, 131072 = 65536 connections); beyond it, new
 * flows stay in the software flow table; 0 removes the bound.
 *
 * max_flows: a fixed bound as well, offloaded plus undeleted flows; 0 (the
 * default) = none.
 */
static unsigned int max_flows;
module_param(max_flows, uint, 0644);
MODULE_PARM_DESC(max_flows, "most flows offloaded at once, undeleted ones included (0: no fixed bound, the default)");
static unsigned int oft_min_free = 512;
module_param(oft_min_free, uint, 0644);
MODULE_PARM_DESC(oft_min_free, "new flows admitted while this many OFT buckets stay free (default 512; 0: no check, refusals of the engine handled after the fact)");
static unsigned int oft_poll_ms = 100;
module_param(oft_poll_ms, uint, 0644);
MODULE_PARM_DESC(oft_poll_ms, "interval (ms) between two reads of the OFT free count and of the insert counters (default 100)");
static unsigned int host_guard_flows = 131072;
module_param(host_guard_flows, uint, 0644);
MODULE_PARM_DESC(host_guard_flows, "most flows (directions) offloaded at once, for the host cost of their activity queries (default 131072 = 65536 connections; 0: no bound)");

/*
 * debugfs sse, lines "cap". Admission: OFT free count last read, sessions
 * posted since, its age, the bounds, offers refused by cause (OFT, host
 * guard, max_flows). Engine: table sizes, insert gap at the last drained
 * sample, refusals counted (two samples), not yet matched to a flow, query
 * replies that found no session, flows (and their sessions) given back to
 * the software flow table; then the flows given back still remembered,
 * offers of them refused, admitted again, deletes not posted for refused
 * sessions, offers refused on a key still held by a live flow.
 */
static void fnp6l_dbg_cap_show(struct seq_file *m, struct fnp6l *np)
{
	seq_printf(m, "cap admit flows %u oft_free %u posted %u age_ms %u reads %lu min_free %u guard %u max %u ref_oft %ld ref_guard %ld ref_max %ld\n",
		   np->ft_nflows, READ_ONCE(np->oft_free), READ_ONCE(np->oft_posted),
		   np->oft_valid ? jiffies_to_msecs(jiffies - READ_ONCE(np->oft_j)) : 0,
		   np->oft_reads, READ_ONCE(oft_min_free), READ_ONCE(host_guard_flows),
		   READ_ONCE(max_flows), atomic_long_read(&np->ft_ref_oft),
		   atomic_long_read(&np->ft_ref_guard), atomic_long_read(&np->ft_ref_max));
	seq_printf(m, "cap np tables %u/%u gap %u refused %u credit %u qmiss %lu back %lu back_sess %lu back_live %u ref_back %ld back_again %lu del_skip %lu keybusy %lu\n",
		   np->sse_pht_n, np->sse_oft_n, np->ins_gap_last, np->np_refused,
		   np->np_credit, np->ft_qmiss, np->ft_back, np->ft_back_sess,
		   READ_ONCE(np->ft_nback), atomic_long_read(&np->ft_ref_back),
		   np->ft_back_again, np->ft_del_skip, np->ft_keybusy);
	seq_printf(m, "cap stats fast %lu slow %lu index %u\n",
		   READ_ONCE(np->ft_sfast), READ_ONCE(np->ft_sslow),
		   1U << np->ft_hbits);
}

/*
 * Activity queries: the sessions of a flow at most every ft_stats_ms. The
 * flow table asks for the stats of a flow at each pass (once a second) once
 * its timeout has run below nine tenths: a busy flow is seen at most
 * ft_stats_ms late, well within its timeout (30 s), an idle one expires at
 * most that much later.
 */
static unsigned int ft_stats_ms = 2000;
module_param(ft_stats_ms, uint, 0644);
MODULE_PARM_DESC(ft_stats_ms, "least interval (ms) between two activity queries of a flow (default 2000)");
/*
 * UDP flows: offloaded by default; 0 leaves new UDP flows to the software
 * flow table (fallback kept for a stall of the host delivery once seen
 * under offloaded UDP).
 */
static bool ft_udp = true;
module_param(ft_udp, bool, 0644);
MODULE_PARM_DESC(ft_udp, "offload UDP flows (default 1: offloaded; 0: new UDP flows stay in the software flow table; flows already offloaded stay)");
#define NP6L_FT_MSG_QUERY		1	/* header byte 1 of a query reply */
#define NP6L_FT_STATS_OFF		24	/* activity counters: what a hit moves */
#define NP6L_FT_STATS_LEN		32
#define NP6L_FT_KEYS			(BIT_ULL(FLOW_DISSECTOR_KEY_META) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |	\
			 BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |	\
			 BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_TCP) |		\
			 BIT_ULL(FLOW_DISSECTOR_KEY_VLAN))

struct fnp6l_ft_flow {
	struct list_head node;		/* np->ft_flows, or np->ft_dead */
	struct hlist_node cnode;	/* np->ft_chash, by cookie (live flows) */
	unsigned long cookie;
	bool hw_bad;		/* sessions not all in the engine: insert again */
	/* block of the flow table that offered it: compared, never followed */
	const struct flow_block *table;
	__be32 sip, dip;
	__be16 sport, dport;
	u8 proto;
	u16 vid;		/* in_vid of the keys (802.1Q VID, 0: untagged) */
	bool v6;		/* sip/dip = address words 0, a6 = words 1-3 */
	u8 a6[24];		/* source then destination words 1-3 */
	u8 n_in_lif;		/* sessions: one per ingress LIF (bond members) */
	u8 in_lif[NP6L_SW_PORTS];	/* ingress LIFs of the keys (a port or bond members) */
	/* output to a bond of switch ports: re-picked on member changes */
	struct net_device *obond;
	struct fnp6l_sse_opt opt;
	u8 eth[2 * ETH_ALEN], l3[8], l4[4];	/* output headers (after NAT) */
	/* activity from the query replies of each session */
	unsigned long lastused, qtime;
	struct fnp6l_ft_sess {
		struct hlist_node hn;		/* np->ft_hash, by key */
		struct fnp6l_ft_flow *flow;
		u8 key[NP6L_SSE_KEY4_LEN];
		u8 snap[NP6L_FT_STATS_LEN];
		bool snap_ok;
		bool missing;		/* a query found no such session */
		bool refused;		/* missing, matched to a refusal: never deleted */
	} s[NP6L_SW_PORTS];
	unsigned int nback;	/* times given back before (fnp6l_ft_back_take) */
};

/*
 * A flow given back to the software flow table (fnp6l_ft_stats): the flow
 * table goes on offering it (a REPLACE at each refresh, once a second while
 * it runs in software) until its DESTROY. Remembered by cookie until then,
 * so that it is offered to the engine again only once the engine has room
 * for it and not before @until: without that, with oft_min_free 0, every
 * flow given back was inserted again at once, refused, given back, in a
 * loop (about 1 000 refusals a second at 8 192 connections, as measured).
 */
struct fnp6l_ft_back {
	struct hlist_node cnode;	/* np->ft_bhash (ft_sess_lock) */
	struct list_head node;		/* np->ft_backl (ft_sess_lock) */
	unsigned long cookie;
	const struct flow_block *table;	/* compared, never followed */
	unsigned long until;		/* jiffies: no offer before */
	unsigned int n;			/* sessions of the flow */
	unsigned int nback;		/* times given back */
};

/*
 * Source MAC of the offloaded frames: lif_cfg[LIF of the output port] holds
 * it next to the port field (bits 22:16, kept). Only port and switch-port
 * LIFs, never LIF 1, the loader's host queue. The MAC is never logged.
 */
static void fnp6l_ft_set_smac(struct fnp6l *np, unsigned int lif, const u8 *mac)
{
	u32 d[4];

	if (fnp6l_tbl_op(np, NP6L_TBL_LIF_CFG, lif, d, false))
		return;
	d[0] = mac[0] | mac[1] << 8 | mac[2] << 16 | (u32)mac[3] << 24;
	d[1] = (d[1] & 0xffff0000) | mac[4] | mac[5] << 8;
	fnp6l_tbl_op(np, NP6L_TBL_LIF_CFG, lif, d, true);
}

/* save a table entry for fnp6l_ft_restore (SRAM residues: never assumed) */
static int fnp6l_ft_save(struct fnp6l *np, u32 tbl, u32 idx)
{
	struct fnp6l_ft_save *s = &np->ft_save[np->ft_nsave];

	if (np->ft_nsave >= ARRAY_SIZE(np->ft_save))
		return -ENOSPC;
	if (fnp6l_tbl_op(np, tbl, idx, s->d, false))
		return -EIO;
	s->tbl = tbl;
	s->idx = idx;
	np->ft_nsave++;
	return 0;
}

/* save the current entry, then write d to it */
static int fnp6l_ft_write(struct fnp6l *np, u32 tbl, u32 idx, u32 *d)
{
	int ret = fnp6l_ft_save(np, tbl, idx);

	return ret ? ret : fnp6l_tbl_op(np, tbl, idx, d, true);
}

/* undo a failed fnp6l_ft_apply: the tables saved so far */
static void fnp6l_ft_restore(struct fnp6l *np)
{
	unsigned int i;

	for (i = np->ft_nsave; i-- > 0; )
		fnp6l_tbl_op(np, np->ft_save[i].tbl, np->ft_save[i].idx,
			     np->ft_save[i].d, true);
	np->ft_nsave = 0;
	np->ft_on = false;
}

/*
 * Post the host-queue LIF entries a classified port needs: host trunk LIFs 4,
 * 5, 6 (q = 1, 2, 3; lif_cfg, lif_mac, trunk_cfg, port_trunk, port_action
 * toward trunk 255), trunk_members[64..67] and trunk_cfg[255]. Without them a
 * port LIF whose port_action forward target points at trunk 255 loses its
 * non-IP frames. Every write goes through fnp6l_ft_write so fnp6l_ft_restore
 * undoes it. Under fnp6l_sse_lock.
 */
static int fnp6l_ft_host_residues(struct fnp6l *np)
{
	static const u32 trunk_members[4] = { 0x401, 0x404, 0x405, 0x406 };
	unsigned int q, lif, i;
	u32 d[4];
	int ret;

	for (q = 1; q <= 3; q++) {
		lif = q + 3;
		d[0] = 0; d[1] = (0x80 | q) << 16; d[2] = 0; d[3] = 0;
		ret = fnp6l_ft_write(np, NP6L_TBL_LIF_CFG, lif, d);
		if (!ret) {
			d[1] = 0x10000;
			ret = fnp6l_ft_write(np, NP6L_TBL_LIF_MAC, lif, d);
		}
		if (!ret) {
			d[1] = 0x7fc00000;
			ret = fnp6l_ft_write(np, NP6L_TBL_TRUNK_CFG, lif, d);
		}
		if (!ret) {
			d[0] = lif; d[1] = 0;
			ret = fnp6l_ft_write(np, NP6L_TBL_PORT_TRUNK, lif, d);
		}
		if (!ret) {
			d[0] = 0x0ff00000; d[1] = 0x00020040;
			ret = fnp6l_ft_write(np, NP6L_TBL_PORT_ACTION, lif, d);
		}
		if (ret)
			return ret;
	}
	for (i = 0; i < 4; i++) {
		d[0] = trunk_members[i]; d[1] = 0; d[2] = 0; d[3] = 0;
		ret = fnp6l_ft_write(np, NP6L_TBL_TRUNK_MEMBERS, 64 + i, d);
		if (ret)
			return ret;
	}
	d[0] = 0xf03f703f; d[1] = 0x7fc11040; d[2] = 0; d[3] = 0;
	return fnp6l_ft_write(np, NP6L_TBL_TRUNK_CFG, 255, d);
}

/* a port that is not a DSA conduit (a flow end) is declared */
static bool fnp6l_has_net_port(struct fnp6l *np)
{
	unsigned int i;

	for (i = 0; i < NP6L_MAX_LIF; i++)
		if (np->port[i] && !np->port[i]->conduit)
			return true;
	return false;
}

/*
 * Apply the offload state (under fnp6l_sse_lock): the host-queue LIF entries
 * (fnp6l_ft_host_residues), then for each port LIF (60E: 0, 2, 3)
 * port_action at a mixed value -- loader forward target 1 (non-IP still
 * delivered) with source action 1 that turns SSE lookup on -- its own source
 * MAC in lif_cfg (LIF 0 included) and its IPv6 MTU, the IHP keys of TCP and
 * UDP, and the IGR 802.1Q parser. Every table write goes through
 * fnp6l_ft_write / fnp6l_ft_save, so fnp6l_ft_restore puts the loader values
 * back should a step fail; the IGR 802.1Q parser is turned on last.
 */
static int fnp6l_ft_apply(struct fnp6l *np)
{
	unsigned int lif;
	u32 d[4], vlan_tpid;
	int ret;

	if (!np->sse_done)
		return -EPERM;
	if (!np->ic_on || !fnp6l_has_net_port(np))
		return -ENODEV;
	np->ft_nsave = 0;

	ret = fnp6l_ft_host_residues(np);
	if (ret)
		goto fail;

	/* every port, by LIF (60E: wan1 0, wan2 2, conduit 3) */
	for (lif = 0; lif < NP6L_MAX_LIF; lif++) {
		struct fnp6l_port *p = np->port[lif];

		if (!p)
			continue;
		d[0] = 0x00100000;	/* forward target 1 (loader host queue) */
		d[1] = 0x00020040;	/* source action 1, target action 1 (SSE lookup on) */
		d[2] = 0; d[3] = 0;
		ret = fnp6l_ft_write(np, NP6L_TBL_PORT_ACTION, lif, d);
		if (ret)
			goto fail;
		ret = fnp6l_ft_save(np, NP6L_TBL_LIF_CFG, lif);
		if (ret)
			goto fail;
		fnp6l_ft_set_smac(np, lif, p->ndev->dev_addr);
		/*
		 * IPv6 egress MTU of the LIF (trunk_cfg bits 76:64, in units
		 * of 2 bytes; 761 = 1522-byte frames): the loader leaves 0
		 * there and the NP then sends every IPv6 frame of the LIF as
		 * an atomic fragment, which breaks neighbour discovery.
		 */
		ret = fnp6l_tbl_op(np, NP6L_TBL_TRUNK_CFG, lif, d, false) ? -EIO : 0;
		if (!ret && !(d[2] & GENMASK(12, 0))) {
			d[2] |= 761;
			ret = fnp6l_ft_write(np, NP6L_TBL_TRUNK_CFG, lif, d);
		}
		if (ret)
			goto fail;
		dev_info(np->dev,
			 "ft: LIF %u port_action 00100000 00020040, port MAC set, v6 MTU %u\n",
			 lif, 2 * (d[2] & 0x1fff));
	}
	/*
	 * IHP L4 parse entries of TCP and UDP (default entries: byte 0 = 2,
	 * byte 3 = 0x40, L4 key length << 3): left as residues by the loader,
	 * an IPv6 TCP/UDP frame is then flagged as a protocol error by the
	 * IPv6 anomaly checks and never looked up. ICMPv6 keeps its
	 * residue: neighbour discovery still goes to the host untouched.
	 */
	d[0] = 0x40000002; d[1] = 20 << 3; d[2] = 0; d[3] = 0;
	ret = fnp6l_ft_write(np, NP6L_TBL_IHP_L4_PARSE, IPPROTO_TCP, d);
	if (!ret) {
		d[1] = 8 << 3;
		ret = fnp6l_ft_write(np, NP6L_TBL_IHP_L4_PARSE, IPPROTO_UDP, d);
	}
	if (ret)
		goto fail;
	/* 802.1Q parsed by the IGR: VLAN flows are looked up (in_vid) */
	vlan_tpid = fnp6l_rd(np, NP6L_IGR_VLAN_TPID);
	fnp6l_wr(np, NP6L_IGR_VLAN_TPID, NP6L_IGR_VLAN_TPID_8021Q);
	np->ft_on = true;
	dev_info(np->dev,
		 "ft: offload state applied (host queues + port_action, %u entries saved, VLAN TPID %#x -> %#x)\n",
		 np->ft_nsave, vlan_tpid, NP6L_IGR_VLAN_TPID_8021Q);
	return 0;
fail:
	fnp6l_ft_restore(np);
	dev_err(np->dev, "ft: ic apply failed (%d), state restored\n", ret);
	return ret;
}

/*
 * Post an insert or delete command for one session of a flow: ingress LIF
 * in, host queue NP6L_FT_HOSTQ (ignored), in_vid, entry_timeout
 * NP6L_FT_ENTRY_TIMEOUT, full entry, output = egress LIF, dmac = next hop.
 * The next-hop MAC is never logged. Under fnp6l_sse_lock.
 */
static int fnp6l_ft_cmd6(struct fnp6l *np, bool insert, u8 proto, __be32 sip,
			 __be16 sport, __be32 dip, __be16 dport, u32 in_lif,
			 u32 vid, const struct fnp6l_sse_opt *opt, const u8 *a6)
{
	u8 msg[8 + NP6L_SSE_ENTRY_LEN] = { };
	unsigned int len = insert ? NP6L_SSE_ENTRY_LEN : NP6L_SSE_KEY4_LEN;
	int ret = fnp6l_cmdq_up(np);

	if (ret)
		return ret;
	fnp6l_sse_entry4(msg + 8, proto, sip, sport, dip, dport, in_lif, vid,
			 NP6L_FT_HOSTQ, NP6L_FT_ENTRY_TIMEOUT, insert ? opt : NULL);
	if (a6) {
		/*
		 * IPv6 session entry: KEY_TAGGED (bit 126) marks IPv6;
		 * address words 0 in the key, words 1-3 of the source at
		 * bytes 84-95 and of the destination at 96-107, 0xff from
		 * byte 116. A delete is the key without KEY_VALID plus those
		 * 24 bytes (40 bytes).
		 */
		if (insert) {
			msg[8 + 15] |= 0x40;
			/* needed for IPv6: without it the NP
			 * rewrites the frame as IPv4; in an IPv4 entry
			 * the same bit stops the action */
			msg[8 + 22] |= BIT(0);
			memcpy(msg + 8 + 84, a6, 24);
			memset(msg + 8 + 108, 0, 8);
			memset(msg + 8 + 116, 0xff, 12);
		} else {
			msg[8 + 15] = (msg[8 + 15] & ~0x80) | 0x40;
			memcpy(msg + 8 + 16, a6, 24);
			len = 40;
		}
	}
	/*
	 * ACT_COUNT (bit 171): the engine then keeps its accounting in the
	 * entry (bytes 24-55 move on every hit);
	 * without it a query reply never changes.
	 */
	if (insert)
		msg[8 + 21] |= BIT(3);
	msg[0] = 0x80 | (insert ? NP6L_SSE_CMD_INSERT : NP6L_SSE_CMD_DELETE);
	msg[1] = (8 + len) / 8;
	msg[3] = NP6L_SSE_TXQ;
	return fnp6l_sse_post(np, msg, 8 + len);
}

static int fnp6l_ft_fcmd(struct fnp6l *np, bool insert, struct fnp6l_ft_flow *f,
			 unsigned int i, const struct fnp6l_sse_opt *opt)
{
	return fnp6l_ft_cmd6(np, insert, f->proto, f->sip, f->sport, f->dip,
			     f->dport, f->in_lif[i], f->vid, opt,
			     f->v6 ? f->a6 : NULL);
}

/*
 * Delete every session of a tracked flow (one per ingress LIF): post the
 * deletes (fnp6l_sse_post: the queue is read in order and no buffer is
 * reused before it is read; a later insert of the same key is read after
 * them). A post refused means a full queue: the next ones are not tried.
 * A session the engine refused (refused, see fnp6l_ft_mark_refused) is
 * not in the engine: no delete, it would only fail. Non-zero: the
 * sessions may still be in the engine.
 */
static int fnp6l_ft_del(struct fnp6l *np, struct fnp6l_ft_flow *flow)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < flow->n_in_lif && !ret; i++)
		if (!flow->s[i].refused)
			ret = fnp6l_ft_fcmd(np, false, flow, i, NULL);
	return ret;
}

static struct fnp6l_ft_flow *fnp6l_ft_find(struct fnp6l *np, unsigned long cookie)
{
	struct fnp6l_ft_flow *flow;

	hlist_for_each_entry(flow, &np->ft_chash[hash_long(cookie, np->ft_hbits)],
			     cnode)
		if (flow->cookie == cookie)
			return flow;
	return NULL;
}

/*
 * A live flow: on the list and indexed by cookie (fnp6l_sse_lock). The
 * cookie index is changed under ft_sess_lock too: fnp6l_ft_known reads it
 * under that lock alone.
 */
static void fnp6l_ft_link(struct fnp6l *np, struct fnp6l_ft_flow *flow)
{
	spin_lock_bh(&np->ft_sess_lock);
	hlist_add_head(&flow->cnode,
		       &np->ft_chash[hash_long(flow->cookie, np->ft_hbits)]);
	spin_unlock_bh(&np->ft_sess_lock);
	list_add(&flow->node, &np->ft_flows);
	np->ft_nflows++;
}

static unsigned int fnp6l_ft_khash(const struct fnp6l *np, const u8 *key)
{
	return jhash(key, NP6L_SSE_KEY4_LEN, 0) & ((1U << np->ft_hbits) - 1);
}

static unsigned int ft_hash_bits = NP6L_FT_HBITS_DEF;
module_param(ft_hash_bits, uint, 0444);
MODULE_PARM_DESC(ft_hash_bits, "log2 of the buckets of the flow and session indexes, read at probe (11 to 20, default 16)");

static void fnp6l_ft_index_free(void *data)
{
	struct fnp6l *np = data;

	kvfree(np->ft_hash);
	kvfree(np->ft_chash);
	np->ft_hash = NULL;
	np->ft_chash = NULL;
}

/*
 * Both indexes, empty (a zeroed hlist_head is an empty bucket); a smaller
 * size is tried should memory be short. 0, or -ENOMEM.
 */
static int fnp6l_ft_index_alloc(struct fnp6l *np)
{
	unsigned int want = clamp_t(unsigned int, READ_ONCE(ft_hash_bits),
				    NP6L_FT_HBITS_MIN, NP6L_FT_HBITS_MAX);
	unsigned int bits;

	for (bits = want; bits >= NP6L_FT_HBITS_MIN; bits--) {
		np->ft_hash = kvcalloc(1U << bits, sizeof(*np->ft_hash), GFP_KERNEL);
		np->ft_chash = kvcalloc(1U << bits, sizeof(*np->ft_chash), GFP_KERNEL);
		if (np->ft_hash && np->ft_chash)
			break;
		fnp6l_ft_index_free(np);
	}
	if (!np->ft_hash)
		return -ENOMEM;
	np->ft_hbits = bits;
	if (bits != want)
		dev_warn(np->dev, "ft: indexes reduced to %u buckets\n", 1U << bits);
	return devm_add_action_or_reset(np->dev, fnp6l_ft_index_free, np);
}

/* the session keys of a flow, as a query reply carries them */
static void fnp6l_ft_keys(struct fnp6l_ft_flow *flow)
{
	unsigned int i;

	for (i = 0; i < flow->n_in_lif; i++) {
		struct fnp6l_ft_sess *s = &flow->s[i];

		memset(s->key, 0, sizeof(s->key));
		fnp6l_sse_entry4(s->key, flow->proto, flow->sip, flow->sport,
				 flow->dip, flow->dport, flow->in_lif[i], flow->vid,
				 0, 0, NULL);
		if (flow->v6)
			s->key[15] |= 0x40;	/* KEY_TAGGED: IPv6 session */
	}
}

/*
 * Index the session keys of a flow (fnp6l_ft_keys) for the query replies.
 * ft_sess_lock, not fnp6l_sse_lock, guards the index: fnp6l_rx_msg reads
 * it in NAPI context, and a flow is freed only once out of it.
 */
static void fnp6l_ft_hash_add(struct fnp6l *np, struct fnp6l_ft_flow *flow)
{
	unsigned int i;

	spin_lock_bh(&np->ft_sess_lock);
	for (i = 0; i < flow->n_in_lif; i++) {
		struct fnp6l_ft_sess *s = &flow->s[i];

		s->flow = flow;
		s->snap_ok = false;
		hlist_add_head(&s->hn, &np->ft_hash[fnp6l_ft_khash(np, s->key)]);
	}
	spin_unlock_bh(&np->ft_sess_lock);
}

/* off the key and cookie indexes; its session keys kept as deleted */
static void fnp6l_ft_unhash(struct fnp6l *np, struct fnp6l_ft_flow *flow)
{
	unsigned int i;

	spin_lock_bh(&np->ft_sess_lock);
	hlist_del_init(&flow->cnode);
	for (i = 0; i < NP6L_SW_PORTS; i++) {
		if (hlist_unhashed(&flow->s[i].hn))
			continue;
		hlist_del_init(&flow->s[i].hn);
		memcpy(np->ft_delkey[np->ft_ndelkey++ % NP6L_FT_DELKEYS],
		       flow->s[i].key, sizeof(np->ft_delkey[0]));
	}
	spin_unlock_bh(&np->ft_sess_lock);
}

/* a live flow leaves: off the list, the cookie index and the key index */
static void fnp6l_ft_unlink(struct fnp6l *np, struct fnp6l_ft_flow *flow)
{
	list_del(&flow->node);
	np->ft_nflows--;
	fnp6l_ft_unhash(np, flow);
}

/*
 * A flow whose sessions could not be deleted stays counted (it holds
 * engine entries) on ft_dead, deleted again by fnp6l_ft_dead_work, and no
 * new flow with one of its keys is inserted until then.
 */
static void fnp6l_ft_bury(struct fnp6l *np, struct fnp6l_ft_flow *flow)
{
	list_add_tail(&flow->node, &np->ft_dead);
	np->ft_ndead++;
	np->ft_delfail++;
	dev_warn_ratelimited(np->dev, "ft: %u flow(s) not deleted, retried\n",
			     np->ft_ndead);
	schedule_delayed_work(&np->ft_dead_work,
			      msecs_to_jiffies(NP6L_FT_DEAD_RETRY_MS));
}

/* delete then free a flow already unlinked, or bury it (fnp6l_sse_lock) */
static void fnp6l_ft_drop(struct fnp6l *np, struct fnp6l_ft_flow *flow)
{
	if (np->ft_on && np->sse_done && fnp6l_ft_del(np, flow)) {
		fnp6l_ft_bury(np, flow);
		return;
	}
	kfree(flow);
}

/* try the dead flows again; how many remain (fnp6l_sse_lock) */
static unsigned int fnp6l_ft_dead_retry(struct fnp6l *np)
{
	struct fnp6l_ft_flow *flow, *tmp;

	list_for_each_entry_safe(flow, tmp, &np->ft_dead, node) {
		if (np->ft_on && np->sse_done && fnp6l_ft_del(np, flow))
			break;		/* queue still full: later */
		list_del(&flow->node);
		np->ft_ndead--;
		np->ft_dfree++;
		kfree(flow);
	}
	return np->ft_ndead;
}

/* whether a dead flow still holds one of the keys of @fl */
static bool fnp6l_ft_dead_key(struct fnp6l *np, const struct fnp6l_ft_flow *fl)
{
	const struct fnp6l_ft_flow *d;
	unsigned int i, j;

	list_for_each_entry(d, &np->ft_dead, node)
		for (i = 0; i < d->n_in_lif; i++)
			for (j = 0; j < fl->n_in_lif && !d->s[i].refused; j++)
				if (!memcmp(d->s[i].key, fl->s[j].key,
					    NP6L_SSE_KEY4_LEN) &&
				    (!fl->v6 || !memcmp(d->a6, fl->a6, sizeof(fl->a6))))
					return true;
	return false;
}

static void fnp6l_ft_dead_work(struct work_struct *work)
{
	struct fnp6l *np = container_of(to_delayed_work(work), struct fnp6l,
					ft_dead_work);
	unsigned int left;

	mutex_lock(&fnp6l_sse_lock);
	left = fnp6l_ft_dead_retry(np);
	mutex_unlock(&fnp6l_sse_lock);
	if (left)
		schedule_delayed_work(&np->ft_dead_work,
				      msecs_to_jiffies(NP6L_FT_DEAD_RETRY_MS));
}

/*
 * Whether @cookie is one of our flows, under ft_sess_lock alone; counted in
 * *unknown otherwise. Every flow of a flow table with the offload flag gets
 * DESTROY (and STATS) work, also those we refused: answered here without
 * taking fnp6l_sse_lock. A REPLACE and a DESTROY of one flow never run at
 * the same time (the flow table's pending bit), so a cookie unknown here is
 * not being inserted.
 */
static bool fnp6l_ft_known(struct fnp6l *np, unsigned long cookie,
			   unsigned long *unknown)
{
	bool known;

	spin_lock_bh(&np->ft_sess_lock);
	known = fnp6l_ft_find(np, cookie);
	if (!known)
		(*unknown)++;
	spin_unlock_bh(&np->ft_sess_lock);
	return known;
}

/* whether the NP has read every command posted (or none was ever posted) */
static bool fnp6l_cmdq_idle(struct fnp6l *np)
{
	struct fnp6l_ring *r = &np->cmdq;
	bool idle;

	if (!np->cmdq_on)
		return true;
	spin_lock_bh(&np->tx_lock);
	fnp6l_cmdq_reap(r);
	idle = r->head == r->tail;
	spin_unlock_bh(&np->tx_lock);
	return idle;
}

static unsigned long fnp6l_ft_poll_jiffies(void)
{
	return max_t(unsigned long, 1, msecs_to_jiffies(READ_ONCE(oft_poll_ms)));
}

/*
 * Read the OFT free count (fnp6l_sse_lock): every oft_poll_ms, or at once
 * when @force (at most once a tick). Then, every oft_poll_ms and only with
 * the command queue drained, the insert counters. The gap INSERTS -
 * INSERTS_OK at one instant also holds the inserts the engine has taken
 * but not completed: never read as refusals. An insert counted in INSERTS
 * at one sample is completed by the next, at least oft_poll_ms later (the
 * engine takes microseconds): the inserts refused are at least INSERTS at
 * the previous sample less INSERTS_OK now (less the gap at engine init),
 * exactly that once no insert came in between; np_refused only grows to
 * that bound. The interrupt status bits are not used.
 */
static void fnp6l_ft_cap_read(struct fnp6l *np, bool force)
{
	unsigned long now = jiffies, poll = fnp6l_ft_poll_jiffies();
	u32 ok, ins, gap, sure;

	if (!np->sse_done)
		return;
	if (!np->oft_valid || time_after_eq(now, np->oft_j + poll) ||
	    (force && np->oft_j != now)) {
		WRITE_ONCE(np->oft_free, fnp6l_rd(np, NP6L_SSE_OFT_FREE));
		WRITE_ONCE(np->oft_posted, 0);
		WRITE_ONCE(np->oft_j, now);
		WRITE_ONCE(np->oft_valid, true);
		np->oft_reads++;
	}
	if (np->ins_gap_have && time_before(now, np->ins_gap_j + poll))
		return;
	if (!fnp6l_cmdq_idle(np))
		return;		/* commands on their way: at the next call */
	ok = fnp6l_rd(np, NP6L_SSE_INSERTS_OK);	/* first: never ahead of INSERTS */
	ins = fnp6l_rd(np, NP6L_SSE_INSERTS);
	gap = ins - ok - np->ins_gap0;
	if (np->ins_gap_have) {
		sure = np->ins_last - ok - np->ins_gap0;
		if ((s32)sure > (s32)np->np_refused) {
			np->np_credit += sure - np->np_refused;
			np->np_refused = sure;
		}
	}
	np->ins_last = ins;
	np->ins_gap_last = (s32)gap > 0 ? gap : 0;
	np->ins_gap_j = now;
	np->ins_gap_have = true;
}

/* whether @n more sessions would leave fewer than @min_free OFT buckets */
static bool fnp6l_ft_oft_short(struct fnp6l *np, unsigned int n,
			       unsigned int min_free)
{
	return READ_ONCE(np->oft_free) <
	       (u64)READ_ONCE(np->oft_posted) + n + min_free;
}

/*
 * Whether a new flow of @n sessions may be offloaded: 0, or -ENOSPC counted
 * by cause (each offer refused counts: a flow is offered again at each
 * refresh). Under fnp6l_sse_lock, or @early: without it, before the flow is
 * parsed, on values read once; the OFT is then only judged on a count read
 * less than oft_poll_ms ago (an older one is read again under the lock).
 */
static int fnp6l_ft_admit(struct fnp6l *np, unsigned int n, bool early)
{
	unsigned int flows = READ_ONCE(np->ft_nflows);
	unsigned int max = READ_ONCE(max_flows);
	unsigned int guard = READ_ONCE(host_guard_flows);
	unsigned int min_free = READ_ONCE(oft_min_free);

	if (max && flows + READ_ONCE(np->ft_ndead) >= max) {
		atomic_long_inc(&np->ft_ref_max);
		return -ENOSPC;
	}
	if (guard && flows >= guard) {
		atomic_long_inc(&np->ft_ref_guard);
		return -ENOSPC;
	}
	if (!min_free || !READ_ONCE(np->sse_done))
		return 0;
	if (early) {
		if (!READ_ONCE(np->oft_valid) ||
		    time_after_eq(jiffies, READ_ONCE(np->oft_j) + fnp6l_ft_poll_jiffies()))
			return 0;
	} else {
		fnp6l_ft_cap_read(np, false);
		if (fnp6l_ft_oft_short(np, n, min_free))
			fnp6l_ft_cap_read(np, true);	/* the estimate only falls */
	}
	if (fnp6l_ft_oft_short(np, n, min_free)) {
		atomic_long_inc(&np->ft_ref_oft);
		return -ENOSPC;
	}
	return 0;
}

/* sessions of @flow a query found missing from the engine */
static unsigned int fnp6l_ft_missing(const struct fnp6l_ft_flow *flow)
{
	unsigned int i, n = 0;

	for (i = 0; i < flow->n_in_lif; i++)
		n += READ_ONCE(flow->s[i].missing);
	return n;
}

/*
 * Sessions of @flow a query found missing, matched to the refusals counted
 * from the insert counters (np_credit), at most np_credit of them: marked
 * refused, so that no delete is posted for them (fnp6l_ft_del): the engine
 * never held them, a delete would only fail (DELETES - DELETES_OK). A
 * session found missing with no refusal left to match is deleted as
 * before. How many were marked (fnp6l_sse_lock).
 */
static unsigned int fnp6l_ft_mark_refused(struct fnp6l *np,
					  struct fnp6l_ft_flow *flow)
{
	unsigned int i, n = 0;

	for (i = 0; i < flow->n_in_lif && n < np->np_credit; i++) {
		if (!READ_ONCE(flow->s[i].missing) || flow->s[i].refused)
			continue;
		flow->s[i].refused = true;
		n++;
	}
	np->np_credit -= n;
	np->ft_del_skip += n;
	return n;
}

/*
 * Whether a live flow already holds one of the session keys of @fl (keys
 * set by fnp6l_ft_keys), IPv6 address words 1-3 compared too: see
 * fnp6l_ft_replace (fnp6l_sse_lock).
 */
static bool fnp6l_ft_key_busy(struct fnp6l *np, const struct fnp6l_ft_flow *fl)
{
	const struct fnp6l_ft_sess *s;
	bool busy = false;
	unsigned int i;

	spin_lock_bh(&np->ft_sess_lock);
	for (i = 0; i < fl->n_in_lif && !busy; i++)
		hlist_for_each_entry(s, &np->ft_hash[fnp6l_ft_khash(np, fl->s[i].key)], hn)
			if (!memcmp(s->key, fl->s[i].key, NP6L_SSE_KEY4_LEN) &&
			    (!fl->v6 || !memcmp(s->flow->a6, fl->a6, sizeof(fl->a6)))) {
				busy = true;
				break;
			}
	spin_unlock_bh(&np->ft_sess_lock);
	return busy;
}

static struct hlist_head *fnp6l_ft_bhead(struct fnp6l *np, unsigned long cookie)
{
	return &np->ft_bhash[hash_long(cookie, NP6L_FT_BHASH_BITS)];
}

/* the flow given back with @cookie, or NULL (ft_sess_lock) */
static struct fnp6l_ft_back *fnp6l_ft_back_find(struct fnp6l *np,
						unsigned long cookie)
{
	struct fnp6l_ft_back *b;

	hlist_for_each_entry(b, fnp6l_ft_bhead(np, cookie), cnode)
		if (b->cookie == cookie)
			return b;
	return NULL;
}

/* delay before the next offer of a flow given back @nback times */
static unsigned long fnp6l_ft_back_delay(unsigned int nback)
{
	return msecs_to_jiffies(NP6L_FT_BACK_MS <<
				min_t(unsigned int, nback ? nback - 1 : 0,
				      NP6L_FT_BACK_SHIFT_MAX));
}

/* off the index (ft_sess_lock); the caller frees it */
static void fnp6l_ft_back_unlink(struct fnp6l *np, struct fnp6l_ft_back *b)
{
	hlist_del_init(&b->cnode);
	list_del(&b->node);
	WRITE_ONCE(np->ft_nback, np->ft_nback - 1);
}

/*
 * @flow (unlinked, cookie set) given back to the software flow table:
 * remembered until its DESTROY, its next offer not before NP6L_FT_BACK_MS,
 * doubled at each give-back of the same flow up to 64 s (the flow table
 * offers it once a second: a refusal there costs one look-up). Without
 * memory for it, it is offered again as any new flow (fnp6l_sse_lock).
 */
static void fnp6l_ft_back_add(struct fnp6l *np, const struct fnp6l_ft_flow *flow)
{
	struct fnp6l_ft_back *b = kzalloc(sizeof(*b), GFP_KERNEL);

	if (!b)
		return;
	b->cookie = flow->cookie;
	b->table = flow->table;
	b->n = flow->n_in_lif;
	b->nback = flow->nback + 1;
	b->until = jiffies + fnp6l_ft_back_delay(b->nback);
	spin_lock_bh(&np->ft_sess_lock);
	hlist_add_head(&b->cnode, fnp6l_ft_bhead(np, b->cookie));
	list_add(&b->node, &np->ft_backl);
	WRITE_ONCE(np->ft_nback, np->ft_nback + 1);
	spin_unlock_bh(&np->ft_sess_lock);
}

/*
 * Whether the flow of @cookie, if given back, may be offered to the engine
 * again now: 0, or -ENOSPC (counted) before its delay, or while the OFT
 * free count, less the sessions posted since its read, leaves no room for
 * its sessions, whatever oft_min_free (0 included: what stops the loop of
 * a flow inserted, refused and given back). @early: without
 * fnp6l_sse_lock, before the parse, the OFT judged on a count read less
 * than oft_poll_ms ago only; under the lock the count is read again when
 * short, and a refusal on it puts the next offer one delay later.
 */
static int fnp6l_ft_back_check(struct fnp6l *np, unsigned long cookie,
			       bool early)
{
	struct fnp6l_ft_back *b;
	unsigned int n = 0;
	int ret = 0;

	if (!READ_ONCE(np->ft_nback))
		return 0;
	spin_lock_bh(&np->ft_sess_lock);
	b = fnp6l_ft_back_find(np, cookie);
	if (b) {
		n = b->n;
		if (time_before(jiffies, b->until))
			ret = -ENOSPC;
	}
	spin_unlock_bh(&np->ft_sess_lock);
	if (!b)
		return 0;
	if (!ret && READ_ONCE(np->sse_done)) {
		if (early) {
			if (READ_ONCE(np->oft_valid) &&
			    time_before(jiffies, READ_ONCE(np->oft_j) +
					fnp6l_ft_poll_jiffies()) &&
			    fnp6l_ft_oft_short(np, n, 0))
				ret = -ENOSPC;
		} else {
			fnp6l_ft_cap_read(np, false);
			if (fnp6l_ft_oft_short(np, n, 0))
				fnp6l_ft_cap_read(np, true);
			if (fnp6l_ft_oft_short(np, n, 0)) {
				ret = -ENOSPC;
				spin_lock_bh(&np->ft_sess_lock);
				b = fnp6l_ft_back_find(np, cookie);
				if (b)
					b->until = jiffies + fnp6l_ft_back_delay(b->nback);
				spin_unlock_bh(&np->ft_sess_lock);
			}
		}
	}
	if (ret)
		atomic_long_inc(&np->ft_ref_back);
	return ret;
}

/* @flow (cookie set) inserted: no longer a flow given back (fnp6l_sse_lock) */
static void fnp6l_ft_back_take(struct fnp6l *np, struct fnp6l_ft_flow *flow)
{
	struct fnp6l_ft_back *b;

	if (!READ_ONCE(np->ft_nback))
		return;
	spin_lock_bh(&np->ft_sess_lock);
	b = fnp6l_ft_back_find(np, flow->cookie);
	if (b) {
		flow->nback = b->nback;
		fnp6l_ft_back_unlink(np, b);
	}
	spin_unlock_bh(&np->ft_sess_lock);
	if (b) {
		np->ft_back_again++;
		kfree(b);
	}
}

/* DESTROY of a flow given back: forgotten; whether it was one */
static bool fnp6l_ft_back_forget(struct fnp6l *np, unsigned long cookie)
{
	struct fnp6l_ft_back *b;

	if (!READ_ONCE(np->ft_nback))
		return false;
	spin_lock_bh(&np->ft_sess_lock);
	b = fnp6l_ft_back_find(np, cookie);
	if (b)
		fnp6l_ft_back_unlink(np, b);
	spin_unlock_bh(&np->ft_sess_lock);
	if (!b)
		return false;
	kfree(b);
	return true;
}

/* the flows given back by flow table @table: forgotten (it leaves the port) */
static void fnp6l_ft_back_forget_table(struct fnp6l *np,
				       const struct flow_block *table)
{
	struct fnp6l_ft_back *b, *tmp;
	LIST_HEAD(gone);

	spin_lock_bh(&np->ft_sess_lock);
	list_for_each_entry_safe(b, tmp, &np->ft_backl, node) {
		if (b->table != table)
			continue;
		fnp6l_ft_back_unlink(np, b);
		list_add(&b->node, &gone);
	}
	spin_unlock_bh(&np->ft_sess_lock);
	list_for_each_entry_safe(b, tmp, &gone, node)
		kfree(b);
}

static struct fnp6l_ft_sess *fnp6l_ft_sess_find(struct fnp6l *np, const u8 *key)
{
	struct fnp6l_ft_sess *s;

	hlist_for_each_entry(s, &np->ft_hash[fnp6l_ft_khash(np, key)], hn)
		if (!memcmp(s->key, key, NP6L_SSE_KEY4_LEN))
			return s;
	return NULL;
}

/*
 * Ask the engine for one session: the reply comes back as an RX message.
 * IPv6: the same 40-byte form as a delete (a query has the length of a
 * delete: 16 bytes, or 40 when KEY_TAGGED is set): key with KEY_TAGGED and
 * without KEY_VALID, then the words 1-3 of the source and destination
 * addresses.
 */
static int fnp6l_ft_query(struct fnp6l *np, const struct fnp6l_ft_sess *s)
{
	u8 msg[8 + 40] = { };
	unsigned int len = NP6L_SSE_KEY4_LEN;
	int ret = fnp6l_cmdq_up(np);

	if (ret)
		return ret;
	memcpy(msg + 8, s->key, NP6L_SSE_KEY4_LEN);
	if (s->flow->v6) {
		msg[8 + 15] = (msg[8 + 15] & ~0x80) | 0x40;
		memcpy(msg + 8 + 16, s->flow->a6, 24);
		len = 40;
	}
	msg[0] = 0x80 | 3;		/* query */
	msg[1] = (8 + len) / 8;
	msg[3] = NP6L_SSE_TXQ;
	np->ft_qsent++;
	return fnp6l_sse_post(np, msg, 8 + len);
}

/*
 * Session of a query reply whose entry starts at @off, or NULL (ft_sess_lock).
 */
static struct fnp6l_ft_sess *fnp6l_ft_reply_sess(struct fnp6l *np, const u8 *buf,
						 unsigned int len, unsigned int off)
{
	struct fnp6l_ft_sess *s;
	u8 key[NP6L_SSE_KEY4_LEN];

	if (off + NP6L_FT_STATS_OFF + NP6L_FT_STATS_LEN > len)
		return NULL;
	memcpy(key, buf + off, NP6L_SSE_KEY4_LEN);
	key[15] |= 0x80;
	s = fnp6l_ft_sess_find(np, key);
	/* IPv6: words 1-3 of the addresses at +84 too */
	if (s && s->flow->v6 && off + 108 <= len &&
	    memcmp(buf + off + 84, s->flow->a6, 24))
		return NULL;
	return s;
}

/*
 * Session of a query reply that found nothing, or NULL (ft_sess_lock): the
 * header (byte 1 = NP6L_FT_MSG_QUERY, byte 2 = length / 8) then the key
 * alone, without the entry (24 bytes for an IPv4 key).
 */
static struct fnp6l_ft_sess *fnp6l_ft_miss_sess(struct fnp6l *np, const u8 *buf,
						unsigned int len)
{
	unsigned int off = np->ft_qoff >= 0 ? np->ft_qoff : 8;
	u8 key[NP6L_SSE_KEY4_LEN];

	if (len < 2 || buf[1] != NP6L_FT_MSG_QUERY ||
	    off + NP6L_SSE_KEY4_LEN > len ||
	    off + NP6L_FT_STATS_OFF + NP6L_FT_STATS_LEN <= len)
		return NULL;
	memcpy(key, buf + off, NP6L_SSE_KEY4_LEN);
	key[15] |= 0x80;
	return fnp6l_ft_sess_find(np, key);
}

/*
 * Whether @k (KEY_VALID as sent) is one of the last session keys deleted
 * (ft_sess_lock): tells the reports of our deletes among the messages no
 * query matched.
 */
static bool fnp6l_ft_deleted_key(struct fnp6l *np, const u8 *k)
{
	unsigned int i, n = min_t(unsigned int, np->ft_ndelkey, NP6L_FT_DELKEYS);
	u8 key[NP6L_FT_DELKEY_LEN];

	memcpy(key, k, sizeof(key));
	key[NP6L_FT_DELKEY_LEN - 1] |= 0x80;
	for (i = 0; i < n; i++)
		if (!memcmp(np->ft_delkey[i], key, sizeof(key)))
			return true;
	return false;
}

/*
 * An NP message (NP6L_WB_MSG), in NAPI context. A query reply carries the
 * stored entry; where it starts in the message is found by its key, searched
 * until a first match (ft_qoff), then only there. A session whose service
 * bytes 24-55 (timestamp, counters) moved since its last reply was hit in
 * between: its flow is used now.
 *
 * Handled here rather than queued for a work: the NP also sends messages
 * that answer no query, in proportion to the sessions it holds, faster than
 * a work drained a queue of 64 (qdrop). Only ft_sess_lock is taken (_bh
 * elsewhere): what is read and written here (the key index, the session
 * snapshots, lastused, the q* counters) is under it, a flow being unhashed
 * under it before it is freed. Messages no query matched are counted by
 * header byte 0, the last one kept (header and key only).
 */
static void fnp6l_rx_msg(struct fnp6l *np, const u8 *buf, unsigned int len)
{
	struct fnp6l_ft_sess *s = NULL;
	unsigned int off;

	if (!READ_ONCE(np->ft_on) || !len)
		return;
	/* reply: 8-byte header (byte 2 = length / 8), then the entry with
	 * its KEY_VALID bit cleared; a miss returns the key alone */
	spin_lock(&np->ft_sess_lock);
	np->ft_qreply++;
	np->ft_msgtype[buf[0] % NP6L_FT_MSGTYPES]++;
	if (len > 1)
		np->ft_msgop[buf[1] % NP6L_FT_MSGTYPES]++;
	off = np->ft_qoff;
	if (np->ft_qoff >= 0) {
		s = fnp6l_ft_reply_sess(np, buf, len, off);
	} else {
		for (off = 0; off <= 64; off += 4) {
			s = fnp6l_ft_reply_sess(np, buf, len, off);
			if (s)
				break;
		}
	}
	if (s) {
		if (np->ft_qoff != off) {
			dev_info(np->dev, "ft: query reply: entry at +%u\n", off);
			np->ft_qoff = off;
		}
		np->ft_qmatch++;
		if (s->snap_ok &&
		    memcmp(s->snap, buf + off + NP6L_FT_STATS_OFF, NP6L_FT_STATS_LEN)) {
			WRITE_ONCE(s->flow->lastused, jiffies);
			np->ft_qchange++;
		}
		memcpy(s->snap, buf + off + NP6L_FT_STATS_OFF, NP6L_FT_STATS_LEN);
		s->snap_ok = true;
		WRITE_ONCE(s->missing, false);
	} else if ((s = fnp6l_ft_miss_sess(np, buf, len))) {
		/* given back to the software flow table by fnp6l_ft_stats */
		np->ft_qmiss++;
		WRITE_ONCE(s->missing, true);
	} else {
		np->ft_qnomatch++;
		np->ft_msghdr_len = min_t(unsigned int, len, NP6L_FT_MSGHDR);
		memcpy(np->ft_msghdr, buf, np->ft_msghdr_len);
		if (np->ft_qoff >= 0 &&
		    np->ft_qoff + NP6L_FT_DELKEY_LEN <= len &&
		    fnp6l_ft_deleted_key(np, buf + np->ft_qoff))
			np->ft_qnomatch_del++;
	}
	spin_unlock(&np->ft_sess_lock);
}

/* ------------------------------------------- switch-port classification */

/*
 * Needs the ingress classification: the b53 DSA conduit gets
 * every switch frame with a 4-byte Broadcom tag between the source address and
 * the EtherType, so the IHP never finds the IP header and the session engine
 * never looks a switch frame up (measured: search count flat for 500
 * switch frames, +1 per frame on wan1). A TPID-0x0000 tag matches the
 * Broadcom tag; on the NP6Lite the port tag TPID holds the port tag
 * (0x8200), so the Broadcom tag is declared as the second tag (second tag
 * TPID 0x10000): its 12 low bits (the low nibble of the reason code, the
 * traffic class and the source port: 00 00 RC TC<<5|port) then key the
 * class table {port tag of the conduit, VID = (RC & 0xf) << 8 | TC << 5 |
 * port} -> one LIF per switch port. The BCM53128 gives the frames of a
 * standalone port the reason 0x20 and those of a bridged port 0x04
 * (measured on the 90D), class 0 under b53 as is and class 7 with
 * brcm,port-traffic-class = <7>: each switch port gets one cell per reason
 * nibble of switch_rc_mask and class of switch_tc_mask. Key VID 0 (port 0,
 * reason nibble 0, class 0) is never matched (measured on the 60E: every
 * frame of port 0 takes the default LIF with both tags; same as key 0 on
 * the NP4Lite of the 60D): that key is never inserted, the conduit's own
 * ingress classification cell (VID 0, LIF 3) is left as it is, and switch
 * port 0 (dmz) is classified in class 7 only, which needs the switch
 * property. Switch port p gets the
 * LIF "fortinet,switch-logical-interfaces" of its conduit gives it (60E:
 * 8 + p) with copies of the conduit LIF tables (lif_cfg,
 * trunk_cfg, port_action: applied after the offload state to copy its
 * raised source action); a port without a LIF stays on the conduit LIF.
 * Every entry written is
 * read back (LIFs >= 4 hold SRAM residue). The second tag TPID is global:
 * every conduit of the NP needs the property. A classified frame reaches the
 * host without its Broadcom tag:
 * fnp6l_rx_deliver puts back an egress tag (opcode 0, source port) for
 * tag_brcm. A miss (a reason or a class without a cell, port 0 in class 0)
 * keeps both tags, lands on the IGR default LIF and takes the port tag
 * fallback.
 * Everything is saved and restored should a step fail; a reset undoes it.
 * Host transmission is unchanged (tag_brcm still tags it).
 */
/*
 * Reason nibbles 0 (0x20, standalone port) and 4 (0x04, bridged port);
 * classes 0 (b53 as is) and 7 (brcm,port-traffic-class = <7>): one image
 * good with or without the switch property, standalone or bridged ports.
 */
static unsigned int switch_rc_mask = BIT(0) | BIT(4);
module_param(switch_rc_mask, uint, 0444);
MODULE_PARM_DESC(switch_rc_mask,
		 "switch ports: low nibbles of the Broadcom reason code in the class table, one bit each (0x11: 0 and 4)");
static unsigned int switch_tc_mask = BIT(0) | BIT(7);
module_param(switch_tc_mask, uint, 0444);
MODULE_PARM_DESC(switch_tc_mask,
		 "switch ports: traffic classes in the class table, one bit each (0x81: classes 0 and 7)");

/* words of a table entry read back different from @d, as a bit mask */
static unsigned int fnp6l_sw_check(struct fnp6l *np, u32 tbl, u32 idx,
				   const u32 *d)
{
	unsigned int i, bad = 0;
	u32 rb[4];

	if (fnp6l_tbl_op(np, tbl, idx, rb, false))
		return 0xf;
	for (i = 0; i < 4; i++)
		if (rb[i] != d[i])
			bad |= BIT(i);
	return bad;
}

/*
 * Save the entry, write @d and read it back; an entry read back different is
 * written once more, then counted (sw_rb_bad) and logged by table, index and
 * word, never by value (lif_cfg holds a MAC): the classification goes on.
 */
static int fnp6l_sw_write(struct fnp6l *np, u32 tbl, u32 idx, u32 *d)
{
	struct fnp6l_ft_save *s = &np->sw_save[np->sw_nsave];
	unsigned int bad;
	int ret;

	if (np->sw_nsave >= ARRAY_SIZE(np->sw_save))
		return -ENOSPC;
	if (fnp6l_tbl_op(np, tbl, idx, s->d, false))
		return -EIO;
	s->tbl = tbl;
	s->idx = idx;
	np->sw_nsave++;
	ret = fnp6l_tbl_op(np, tbl, idx, d, true);
	if (ret)
		return ret;
	bad = fnp6l_sw_check(np, tbl, idx, d);
	if (bad) {
		ret = fnp6l_tbl_op(np, tbl, idx, d, true);
		if (ret)
			return ret;
		bad = fnp6l_sw_check(np, tbl, idx, d);
	}
	if (bad) {
		np->sw_rb_bad++;
		dev_warn(np->dev, "sw_class: table %#x[%u] read back different (words %#x)\n",
			 tbl, idx, bad);
	}
	return 0;
}

/*
 * Undo a failed fnp6l_sw_apply: class table cells inserted (the conduit's
 * own cell is never written), saved tables.
 */
static void fnp6l_sw_restore(struct fnp6l *np)
{
	unsigned int i;

	for (i = 0; i < np->sw_nidx; i++) {
		u32 z[4] = { };

		fnp6l_tbl_op(np, NP6L_TBL_CLASS, np->sw_idx[i], z, true);
	}
	np->sw_nidx = 0;
	for (i = np->sw_nsave; i-- > 0; )
		fnp6l_tbl_op(np, np->sw_save[i].tbl, np->sw_save[i].idx,
			     np->sw_save[i].d, true);
	np->sw_nsave = 0;
	np->sw_on = false;
}

/*
 * Switch-port LIF map from the conduits (under fnp6l_sse_lock): each LIF of
 * a "fortinet,switch-logical-interfaces" used once, apart from the port
 * LIFs. -ENODEV when no conduit classifies its switch ports, -EINVAL when a
 * conduit lacks the property or a LIF is used twice.
 */
static int fnp6l_sw_map(struct fnp6l *np)
{
	struct fnp6l_port *c;
	unsigned int i, sp, lif, n = 0;

	memset(np->sw_conduit, 0, sizeof(np->sw_conduit));
	for (i = 0; i < NP6L_MAX_LIF; i++) {
		c = np->port[i];
		if (!c || !c->conduit)
			continue;
		if (!c->sw_nports) {
			netdev_warn(c->ndev, "sw_class: conduit without switch-port LIFs\n");
			goto bad;
		}
		for (sp = 0; sp < c->sw_nports; sp++) {
			lif = c->sw_lif[sp];
			if (!lif)
				continue;
			if (np->port[lif] || np->sw_conduit[lif]) {
				netdev_warn(c->ndev, "sw_class: switch port %u: LIF %u already used\n",
					    sp, lif);
				goto bad;
			}
			np->sw_conduit[lif] = c;
			np->sw_port[lif] = sp;
		}
		n++;
	}
	return n ? 0 : -ENODEV;
bad:
	memset(np->sw_conduit, 0, sizeof(np->sw_conduit));
	return -EINVAL;
}

/* the switch ports of one conduit @sw to their own LIFs */
static int fnp6l_sw_apply_conduit(struct fnp6l *np, struct fnp6l_port *sw)
{
	u32 pc[4], tc[4], sa[4], im[4], d[4], cell[4];
	unsigned int sp, lif, ptag, rc, cl, vid, n;
	int idx, first, ret;

	if (fnp6l_tbl_op(np, NP6L_TBL_LIF_CFG, sw->lif, pc, false) ||
	    fnp6l_tbl_op(np, NP6L_TBL_TRUNK_CFG, sw->lif, tc, false) ||
	    fnp6l_tbl_op(np, NP6L_TBL_PORT_ACTION, sw->lif, sa, false) ||
	    fnp6l_tbl_op(np, NP6L_TBL_LIF_MAC, sw->lif, im, false))
		return -EIO;
	ptag = fnp6l_port_tag(np, sw);
	/*
	 * Where a frame of switch port 0 goes today, read only: the
	 * conduit's class cell (key VID 0) and the IGR default LIF, where a
	 * frame missing the class table lands.
	 */
	idx = fnp6l_class_find(np, ptag, 0, cell);
	if (idx >= 0)
		dev_info(np->dev,
			 "sw_class: conduit LIF %u cell idx %d ent %08x %08x %08x %08x, IGR default LIF %#x\n",
			 sw->lif, idx, cell[0], cell[1], cell[2], cell[3],
			 fnp6l_rd(np, NP6L_IGR_DEFAULT_LIF));
	else
		dev_info(np->dev,
			 "sw_class: conduit LIF %u cell not found (%d), IGR default LIF %#x\n",
			 sw->lif, idx, fnp6l_rd(np, NP6L_IGR_DEFAULT_LIF));
	for (sp = 0; sp < sw->sw_nports; sp++) {
		lif = sw->sw_lif[sp];
		if (!lif)
			continue;
		memset(d, 0, sizeof(d));
		d[0] = NP6L_EGR_TAG_CTRL_TAG2 | BIT(sp);	/* 20 00 00 BIT(p) on output */
		ret = fnp6l_sw_write(np, NP6L_TBL_EGR_TAG, lif, d);
		if (!ret)
			ret = fnp6l_sw_write(np, NP6L_TBL_LIF_CFG, lif, pc);
		if (!ret) {
			d[0] = lif;
			ret = fnp6l_sw_write(np, NP6L_TBL_PORT_TRUNK, lif, d);
		}
		if (!ret)
			ret = fnp6l_sw_write(np, NP6L_TBL_TRUNK_CFG, lif, tc);
		if (!ret)
			ret = fnp6l_sw_write(np, NP6L_TBL_PORT_ACTION, lif, sa);
		/*
		 * lif_mac[LIF] of a switch-port LIF is SRAM residue: with the
		 * wrong bits there the host never gets the LIF's unicast IP
		 * frames (LACP still passes; on the 60E port 7 / LIF 15 lost
		 * every TCP SYN as observed). Copy the conduit's entry.
		 */
		if (!ret)
			ret = fnp6l_sw_write(np, NP6L_TBL_LIF_MAC, lif, im);
		if (ret)
			return ret;
		/*
		 * One cell per reason nibble and class: key port tag << 12 |
		 * (RC & 0xf) << 8 | TC << 5 | port. VID 0 (port 0, nibble 0,
		 * class 0) is never matched and is the conduit's own cell: never
		 * inserted, the conduit's cell keeps its LIF.
		 */
		n = 0;
		first = -1;
		for (rc = 0; rc < 16; rc++) {
			if (!(switch_rc_mask & BIT(rc)))
				continue;
			for (cl = 0; cl < 8; cl++) {
				if (!(switch_tc_mask & BIT(cl)))
					continue;
				vid = rc << 8 | cl << 5 | sp;
				if (!vid)
					continue;
				if (np->sw_nidx >= ARRAY_SIZE(np->sw_idx))
					return -ENOSPC;
				idx = fnp6l_class_insert(np, ptag, vid, lif);
				if (idx < 0)
					return idx;
				np->sw_idx[np->sw_nidx++] = idx;
				if (first < 0)
					first = idx;
				n++;
			}
		}
		if (!n) {
			netdev_warn(sw->ndev,
				    "sw_class: switch port %u: no class table key (rc mask %#x, tc mask %#x)\n",
				    sp, switch_rc_mask, switch_tc_mask);
			return -EINVAL;
		}
		dev_info(np->dev,
			 "sw_class: switch port %u -> LIF %u, %u class table cells (first idx %d)\n",
			 sp, lif, n, first);
	}
	dev_info(np->dev, "sw_class: port_action %08x %08x copied from LIF %u\n",
		 sa[0], sa[1], sw->lif);
	return 0;
}

static int fnp6l_sw_apply(struct fnp6l *np)
{
	u32 tag2_tpid, egr_tag2;
	unsigned int i;
	int ret;

	if (!np->ic_on)
		return -EINVAL;
	ret = fnp6l_sw_map(np);
	if (ret)
		return ret;
	np->sw_nsave = 0;
	np->sw_nidx = 0;
	np->sw_rb_bad = 0;
	for (i = 0; i < NP6L_MAX_LIF; i++) {
		if (!np->port[i] || !np->port[i]->conduit)
			continue;
		ret = fnp6l_sw_apply_conduit(np, np->port[i]);
		if (ret)
			goto fail;
	}
	tag2_tpid = fnp6l_rd(np, NP6L_IGR_TAG2_TPID);
	egr_tag2 = fnp6l_rd(np, NP6L_EGR_TAG2);
	fnp6l_wr(np, NP6L_EGR_TAG2, NP6L_EGR_TAG2_BRCM);
	fnp6l_wr(np, NP6L_IGR_TAG2_TPID, NP6L_IGR_TAG2_TPID_BRCM);
	np->sw_on = true;
	dev_info(np->dev,
		 "sw_class: on, tag2 TPID %#x -> %#x, egress tag2 %#x -> %#x (%u entries saved, %u read back different, %u class cells, rc mask %#x, tc mask %#x)\n",
		 tag2_tpid, fnp6l_rd(np, NP6L_IGR_TAG2_TPID), egr_tag2,
		 fnp6l_rd(np, NP6L_EGR_TAG2), np->sw_nsave, np->sw_rb_bad,
		 np->sw_nidx, switch_rc_mask, switch_tc_mask);
	return 0;
fail:
	fnp6l_sw_restore(np);
	memset(np->sw_conduit, 0, sizeof(np->sw_conduit));
	dev_warn(np->dev, "sw_class: apply failed (%d), restored\n", ret);
	return ret;
}

/*
 * debugfs "sw_class", read only: per switch-port LIF its tables as read now
 * (lif_cfg: port field only, the rest is a MAC; lif_mac: compared with the
 * conduit's), the conduits' class cells, the switch-port cells and the IGR
 * default LIF.
 */
static int fnp6l_dbg_sw_show(struct seq_file *m, void *unused)
{
	struct fnp6l *np = m->private;
	u32 eg[4], lc[4], pt[4], tc[4], pa[4], im[4], cim[4], cell[4];
	struct fnp6l_port *c;
	unsigned int lif, i;
	int idx;

	mutex_lock(&fnp6l_sse_lock);
	seq_printf(m, "sw_on %u read_back_different %u default_lif %08x bridge_moves %lu rc_mask %#x tc_mask %#x cells %u\n",
		   np->sw_on, np->sw_rb_bad, fnp6l_rd(np, NP6L_IGR_DEFAULT_LIF),
		   np->ft_fdb_moves, switch_rc_mask, switch_tc_mask, np->sw_nidx);
	/* the conduits' own cells (key VID 0), never written by sw_class */
	for (lif = 0; lif < NP6L_MAX_LIF; lif++) {
		c = np->port[lif];
		if (!c || !c->conduit)
			continue;
		idx = fnp6l_class_find(np, fnp6l_port_tag(np, c), 0, cell);
		if (idx >= 0)
			seq_printf(m, "conduit LIF %u cell idx %d ent %08x %08x %08x %08x\n",
				   lif, idx, cell[0], cell[1], cell[2], cell[3]);
		else
			seq_printf(m, "conduit LIF %u cell not found (%d)\n", lif, idx);
	}
	for (i = 0; i < np->sw_nidx; i++)
		if (!fnp6l_tbl_op(np, NP6L_TBL_CLASS, np->sw_idx[i], cell, false))
			seq_printf(m, "cell idx %3u ent %08x %08x (LIF %u, port tag %#x, VID %#05x)\n",
				   np->sw_idx[i], cell[0], cell[1], cell[0] >> 24,
				   (cell[0] >> 12) & 0xfff, cell[0] & 0xfff);
	for (lif = 0; lif < NP6L_MAX_LIF; lif++) {
		c = np->sw_conduit[lif];
		if (!c)
			continue;
		if (fnp6l_tbl_op(np, NP6L_TBL_EGR_TAG, lif, eg, false) ||
		    fnp6l_tbl_op(np, NP6L_TBL_LIF_CFG, lif, lc, false) ||
		    fnp6l_tbl_op(np, NP6L_TBL_PORT_TRUNK, lif, pt, false) ||
		    fnp6l_tbl_op(np, NP6L_TBL_TRUNK_CFG, lif, tc, false) ||
		    fnp6l_tbl_op(np, NP6L_TBL_PORT_ACTION, lif, pa, false) ||
		    fnp6l_tbl_op(np, NP6L_TBL_LIF_MAC, lif, im, false) ||
		    fnp6l_tbl_op(np, NP6L_TBL_LIF_MAC, c->lif, cim, false))
			break;
		seq_printf(m, "LIF %2u port %u conduit LIF %u egr_tag %08x lif_cfg port %02lx port_trunk %08x trunk_cfg %08x %08x %08x %08x port_action %08x %08x lif_mac %s\n",
			   lif, np->sw_port[lif], c->lif, eg[0],
			   FIELD_GET(GENMASK(22, 16), lc[1]), pt[0],
			   tc[0], tc[1], tc[2], tc[3], pa[0], pa[1],
			   memcmp(im, cim, sizeof(im)) ? "differs" : "= conduit");
	}
	mutex_unlock(&fnp6l_sse_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(fnp6l_dbg_sw);

static int fnp6l_set_mac_address(struct net_device *ndev, void *addr)
{
	struct fnp6l_port *p = netdev_priv(ndev);
	struct fnp6l *np = p->np;
	int ret = eth_mac_addr(ndev, addr);

	if (ret)
		return ret;
	/*
	 * Keep the offloaded source MAC in step. Never LIF 1 (the loader's
	 * host queue, never a port); the loader's LIF 0 only with the
	 * ingress classification, where its port is a session output.
	 */
	if (p->lif != NP6L_LIF_LOADER || np->ic_on) {
		mutex_lock(&fnp6l_sse_lock);
		if (np->ft_on)
			fnp6l_ft_set_smac(np, p->lif, ndev->dev_addr);
		mutex_unlock(&fnp6l_sse_lock);
	}
	return 0;
}

/* Apply one header rewrite to @hdr (a copy of the fields tracked) at @off. */
static int fnp6l_ft_mangle(u8 *hdr, unsigned int size, u32 off,
			   const struct flow_action_entry *act)
{
	u32 word;

	if (off % 4 || off > size - 4 || (act->mangle.val & act->mangle.mask))
		return -EOPNOTSUPP;
	memcpy(&word, hdr + off, 4);
	word = (word & act->mangle.mask) | act->mangle.val;
	memcpy(hdr + off, &word, 4);
	return 0;
}

/* a switch-port LIF (fnp6l_sw_map) */
static bool fnp6l_lif_is_sw(struct fnp6l *np, unsigned int lif)
{
	return lif < NP6L_MAX_LIF && np->sw_conduit[lif];
}

static struct fnp6l_port *fnp6l_ft_port(struct fnp6l *np,
					const struct net_device *ndev)
{
	unsigned int i;

	for (i = 0; i < NP6L_MAX_LIF; i++)
		if (np->port[i] && np->port[i]->ndev == ndev)
			return np->port[i];
	return NULL;
}

/*
 * Flow ends on the switch: a bond whose members are switch ports with a LIF
 * of their own (fortinet,switch-logical-interfaces of their conduit; 60E:
 * ports 1..7 on LIF 8 + p) stands for the LIFs of its members.
 * The walk sees the DSA conduit below each member (linked as lower): skipped.
 */
struct fnp6l_ft_lowers {
	struct fnp6l *np;
	u8 *lifs;
	unsigned int n;
	bool all, bad;
};

/* DSA port of a switch user port; none when DSA is not reachable from here */
static struct dsa_port *fnp6l_dsa_port(struct net_device *dev)
{
	if (!IS_REACHABLE(CONFIG_NET_DSA))
		return NULL;
	return dsa_port_from_netdev(dev);
}

/* LIF of a switch port behind one of our conduits, 0 for any other device */
static unsigned int fnp6l_ft_sw_lif(struct fnp6l *np, struct net_device *dev)
{
	struct fnp6l_port *c;
	struct dsa_port *dp;
	unsigned int i, lif;

	if (!dev)
		return 0;
	dp = fnp6l_dsa_port(dev);
	if (IS_ERR_OR_NULL(dp) || !dp->cpu_dp)
		return 0;
	for (i = 0; i < NP6L_MAX_LIF; i++) {
		c = np->port[i];
		if (!c || !c->conduit || dp->cpu_dp->conduit != c->ndev)
			continue;
		if (dp->index >= c->sw_nports)
			return 0;
		lif = c->sw_lif[dp->index];
		/* only once classified (fnp6l_sw_map) */
		return fnp6l_lif_is_sw(np, lif) && np->sw_conduit[lif] == c ? lif : 0;
	}
	return 0;
}

static int fnp6l_ft_lower(struct net_device *ldev,
			  struct netdev_nested_priv *priv)
{
	struct fnp6l_ft_lowers *l = priv->data;
	struct fnp6l_port *c = fnp6l_ft_port(l->np, ldev);
	unsigned int i, lif;

	if (c && c->conduit)
		return 0;
	lif = fnp6l_ft_sw_lif(l->np, ldev);
	if (!lif) {
		l->bad = true;
		return 1;
	}
	/* output: the first running member (the bond hash is not followed) */
	if (!l->all && (l->n || !netif_running(ldev) ||
			!netif_carrier_ok(ldev)))
		return 0;
	/* the walk may reach a member more than once: one LIF each */
	for (i = 0; i < l->n; i++)
		if (l->lifs[i] == lif)
			return 0;
	if (l->n >= NP6L_SW_PORTS) {	/* members of more than one conduit */
		l->bad = true;
		return 1;
	}
	l->lifs[l->n++] = lif;
	return 0;
}

static bool bare_ports = true;
module_param(bare_ports, bool, 0644);
MODULE_PARM_DESC(bare_ports, "switch user ports outside a bond as flow ends (N: refused, as a conduit)");

static bool sw_routed;
module_param(sw_routed, bool, 0644);
MODULE_PARM_DESC(sw_routed, "offload flows routed between two switch LIFs, through the conduit link both ways (read per flow)");

static bool bridge_offload = true;
module_param(bridge_offload, bool, 0644);
MODULE_PARM_DESC(bridge_offload, "switch user ports of a bridge offloaded to the switch as flow ends (needs bare_ports for the conduit callback; read per flow)");

struct fnp6l_ft_br {
	struct fnp6l *np;
	struct net_device *br;
	struct dsa_switch_tree *dst;
};

/*
 * A device below the bridge, at any depth: a conduit (DSA links each user
 * port as an upper of its conduit), or a user port of the same DSA tree,
 * the bridge offloaded to it, with a LIF behind one of our conduits; any
 * other stops the walk (a bond, a port of the NP, a port of another tree:
 * bridged by the host).
 */
static int fnp6l_ft_br_lower(struct net_device *lower,
			     struct netdev_nested_priv *priv)
{
	const struct fnp6l_ft_br *b = priv->data;
	struct dsa_port *dp;

	if (netdev_uses_dsa(lower))
		return 0;
	dp = fnp6l_dsa_port(lower);
	if (IS_ERR_OR_NULL(dp) || dp->ds->dst != b->dst ||
	    !dsa_port_offloads_bridge_dev(dp, b->br) ||
	    !fnp6l_ft_sw_lif(b->np, lower))
		return 1;
	return 0;
}

/*
 * bridge_offload: whether the user port @dev, below the bridge @br, may be
 * a flow end. The bridge offloaded to the switch (it forwards within the
 * bridge), not VLAN filtering (the switch would tag the frames to the IMP
 * with the VID), every port below it a port of the tree of @dev with a LIF
 * (fnp6l_ft_br_lower). The NP routes to and from the bridge's address: the
 * source MAC of the output LIF is taken from the rule (h_source, the
 * bridge's address), the ingress classification keys on the source port
 * only. Same rule as the 60D (fnp4l_dsa_bridged); FortiOS offloads a
 * software switch only with an explicit intra-switch policy, never the
 * bridging itself. Under RCU.
 */
static bool fnp6l_ft_bridged(struct fnp6l *np, struct net_device *dev,
			     struct net_device *br)
{
	struct fnp6l_ft_br b = { .np = np, .br = br };
	struct netdev_nested_priv priv = { .data = &b };
	struct dsa_port *dp;

	if (!IS_REACHABLE(CONFIG_BRIDGE) || !READ_ONCE(bridge_offload) ||
	    br_vlan_enabled(br))
		return false;
	dp = fnp6l_dsa_port(dev);
	if (IS_ERR_OR_NULL(dp) || !dsa_port_offloads_bridge_dev(dp, br))
		return false;
	b.dst = dp->ds->dst;
	return !netdev_walk_all_lower_dev_rcu(br, fnp6l_ft_br_lower, &priv);
}

/*
 * LIF of a switch user port as a flow end: a user port with a LIF of its
 * own and either no master (bare_ports) or a bridge offloaded to the
 * switch (bridge_offload, fnp6l_ft_bridged). A bond member's flows come
 * through the bond. 0 for any other device. Any context (RCU for the
 * master).
 */
static unsigned int fnp6l_ft_bare_lif(struct fnp6l *np, struct net_device *dev)
{
	struct net_device *master;
	unsigned int lif;
	bool ok;

	lif = fnp6l_ft_sw_lif(np, dev);
	if (!lif)
		return 0;
	rcu_read_lock();
	master = netdev_master_upper_dev_get_rcu(dev);
	if (!master)
		ok = READ_ONCE(bare_ports);
	else
		ok = netif_is_bridge_master(master) &&
		     fnp6l_ft_bridged(np, dev, master);
	rcu_read_unlock();
	return ok ? lif : 0;
}

/*
 * LIFs of one end of a flow: a port that is not a DSA conduit -> its port
 * LIF (60E: wan1 0, wan2 2); with the switch ports classified, a bare or
 * bridged switch port -> its LIF (fnp6l_ft_bare_lif), a bond of switch ports -> the LIF of
 * every member (@all, the ingress: one session per member) or of the first
 * running one (output).
 * 0 when the end is not ours.
 */
static unsigned int fnp6l_ft_end(struct fnp6l *np, struct net_device *dev,
				 u8 *lifs, bool all)
{
	struct fnp6l_port *p = fnp6l_ft_port(np, dev);
	struct fnp6l_ft_lowers l = { .np = np, .lifs = lifs, .all = all };
	struct netdev_nested_priv priv = { .data = &l };

	if (p) {
		if (p->conduit)
			return 0;
		lifs[0] = p->lif;
		return 1;
	}
	if (!np->sw_on)
		return 0;
	if (!netif_is_bond_master(dev)) {
		lifs[0] = fnp6l_ft_bare_lif(np, dev);
		return lifs[0] ? 1 : 0;
	}
	rcu_read_lock();
	netdev_walk_all_lower_dev_rcu(dev, fnp6l_ft_lower, &priv);
	rcu_read_unlock();
	return l.bad ? 0 : l.n;
}

/*
 * Output member of a bond of switch ports, as the bond itself picks it:
 * ndo_get_xmit_slave on a frame built from the output headers of the flow
 * (MACs, IPv4 addresses and ports after NAT), so xmit_hash_policy (layer2,
 * layer2+3, layer3+4) is followed. When the bond's pick is not usable (its
 * slave array lags a link loss), the first running member; 0 if none.
 */
static unsigned int fnp6l_ft_bond_out(struct fnp6l *np, struct net_device *bond,
				      const u8 *eth, const u8 *l3, const u8 *l4,
				      u8 proto, const u8 *a6)
{
	struct net_device *slave;
	struct sk_buff *skb;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	struct ethhdr *eh;
	unsigned int lif = 0, nh;
	u8 lifs[NP6L_SW_PORTS];

	/* a header like the flow's first frame, for the bond's own hash */
	nh = a6 ? sizeof(*ip6h) : sizeof(*iph);
	skb = alloc_skb(NET_IP_ALIGN + ETH_HLEN + nh + 8, GFP_KERNEL);
	if (skb) {
		skb_reserve(skb, NET_IP_ALIGN);
		eh = skb_put_zero(skb, ETH_HLEN);
		memcpy(eh->h_dest, eth, ETH_ALEN);
		memcpy(eh->h_source, eth + ETH_ALEN, ETH_ALEN);
		if (a6) {
			/* IPv6: words 0 in l3, words 1-3 in a6 (fnp6l_ft_flow) */
			eh->h_proto = htons(ETH_P_IPV6);
			ip6h = skb_put_zero(skb, sizeof(*ip6h));
			ip6h->version = 6;
			ip6h->nexthdr = proto;
			ip6h->hop_limit = 64;
			ip6h->payload_len = htons(8);
			memcpy(&ip6h->saddr.s6_addr32[0], l3, 4);
			memcpy(&ip6h->saddr.s6_addr32[1], a6, 12);
			memcpy(&ip6h->daddr.s6_addr32[0], l3 + 4, 4);
			memcpy(&ip6h->daddr.s6_addr32[1], a6 + 12, 12);
			skb->protocol = htons(ETH_P_IPV6);
		} else {
			eh->h_proto = htons(ETH_P_IP);
			iph = skb_put_zero(skb, sizeof(*iph));
			iph->version = 4;
			iph->ihl = 5;
			iph->ttl = 64;
			iph->protocol = proto;
			iph->tot_len = htons(sizeof(*iph) + 8);
			memcpy(&iph->saddr, l3, 4);
			memcpy(&iph->daddr, l3 + 4, 4);
			skb->protocol = htons(ETH_P_IP);
		}
		memcpy(skb_put_zero(skb, 8), l4, 4);
		skb_reset_mac_header(skb);
		skb_set_network_header(skb, ETH_HLEN);
		skb_set_transport_header(skb, ETH_HLEN + nh);
		skb->dev = bond;
		rcu_read_lock();
		slave = netdev_get_xmit_slave(bond, skb, false);
		if (slave && netif_running(slave) && netif_carrier_ok(slave))
			lif = fnp6l_ft_sw_lif(np, slave);
		rcu_read_unlock();
		kfree_skb(skb);
	}
	if (!lif && fnp6l_ft_end(np, bond, lifs, false) == 1)
		lif = lifs[0];
	return lif;
}

static int fnp6l_ft_refuse_dev(struct net_device *dev,
			       struct netlink_ext_ack *extack, const char *msg)
{
	NL_SET_ERR_MSG_FMT_MOD(extack, "%s", msg);
	netdev_dbg(dev, "flow not offloaded: %s\n", msg);
	return -EOPNOTSUPP;
}

/*
 * Parse one flow offered to a block, IPv4 TCP or UDP, destination MAC from the
 * rule. Both directions between two ports (60E: wan1 <-> wan2) are kept, each
 * port being classified to
 * its own LIF, and with the switch ports classified a bond of switch ports is
 * an end too (ingress: one session per member LIF; output: the first running
 * member, the EGR adding the Broadcom tag). NAT (IPv4 address and port
 * rewrites of the flow table) goes to the nat_* fields of the entry. Every
 * other case returns -EOPNOTSUPP, so the software flow table keeps it. @idev
 * is the device the block belongs to; on success @fl holds the key and the
 * ingress LIFs, @opt the action and @smac the source MAC of the rule.
 */
static int fnp6l_ft_parse(struct fnp6l *np, struct net_device *idev,
			  struct flow_cls_offload *cls, struct fnp6l_ft_flow *fl,
			  struct fnp6l_sse_opt *opt, u8 *smac)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct netlink_ext_ack *extack = cls->common.extack;
	struct fnp6l_port *op;
	struct flow_match_ipv4_addrs addrs;
	struct flow_match_control control;
	struct flow_match_ports ports;
	struct flow_match_basic basic;
	struct flow_match_meta meta;
	const struct flow_action_entry *act;
	u8 eth[2 * ETH_ALEN] = { }, l3[8], l4[4], olif[NP6L_SW_PORTS];
	unsigned int nout = 0, i, j;
	struct net_device *odev = NULL;
	bool redirect = false, pop = false;
	__be32 osip, odip;
	u16 push = 0;
	u64 used;
	int k;

	fl->n_in_lif = fnp6l_ft_end(np, idev, fl->in_lif, true);
	if (!fl->n_in_lif)
		return fnp6l_ft_refuse_dev(idev, extack, "ingress is not an NP end");
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META))
		return -EOPNOTSUPP;
	flow_rule_match_meta(rule, &meta);
	if (meta.key->ingress_ifindex != idev->ifindex)
		return -ENOENT;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC))
		return fnp6l_ft_refuse_dev(idev, extack, "not IP");
	flow_rule_match_control(rule, &control);
	flow_rule_match_basic(rule, &basic);
	fl->v6 = control.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS &&
		 basic.key->n_proto == htons(ETH_P_IPV6);
	if (!fl->v6 &&
	    (control.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS ||
	     basic.key->n_proto != htons(ETH_P_IP)))
		return fnp6l_ft_refuse_dev(idev, extack, "not IPv4 or IPv6");

	used = rule->match.dissector->used_keys;
	if (used & BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN))
		return fnp6l_ft_refuse_dev(idev, extack, "stacked VLAN tags");
	if (used & ~NP6L_FT_KEYS)
		return fnp6l_ft_refuse_dev(idev, extack, "unsupported match");
	if (!flow_rule_match_key(rule, fl->v6 ? FLOW_DISSECTOR_KEY_IPV6_ADDRS :
					    FLOW_DISSECTOR_KEY_IPV4_ADDRS) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS))
		return fnp6l_ft_refuse_dev(idev, extack, "not TCP or UDP");
	if (flow_rule_has_control_flags(control.mask->flags, extack))
		return -EOPNOTSUPP;
	if (basic.key->ip_proto != IPPROTO_TCP &&
	    basic.key->ip_proto != IPPROTO_UDP)
		return fnp6l_ft_refuse_dev(idev, extack, "not IPv4 TCP or UDP");
	if (basic.key->ip_proto == IPPROTO_UDP && !READ_ONCE(ft_udp))
		return fnp6l_ft_refuse_dev(idev, extack, "UDP not offloaded (ft_udp)");

	if (fl->v6) {
		struct flow_match_ipv6_addrs a6;

		flow_rule_match_ipv6_addrs(rule, &a6);
		memcpy(l3, &a6.key->src.s6_addr32[0], 4);
		memcpy(l3 + 4, &a6.key->dst.s6_addr32[0], 4);
		memcpy(fl->a6, &a6.key->src.s6_addr32[1], 12);
		memcpy(fl->a6 + 12, &a6.key->dst.s6_addr32[1], 12);
	} else {
		flow_rule_match_ipv4_addrs(rule, &addrs);
		memcpy(l3, &addrs.key->src, 4);
		memcpy(l3 + 4, &addrs.key->dst, 4);
	}
	flow_rule_match_ports(rule, &ports);
	memcpy(&osip, l3, 4);		/* before any NAT rewrite */
	memcpy(&odip, l3 + 4, 4);
	memcpy(l4, &ports.key->src, 2);
	memcpy(l4 + 2, &ports.key->dst, 2);

	flow_action_for_each(k, act, &rule->action) {
		u32 off = act->mangle.offset;

		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			switch (act->mangle.htype) {
			case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
				if (fnp6l_ft_mangle(eth, sizeof(eth), off, act))
					return fnp6l_ft_refuse_dev(idev, extack,
						"unsupported MAC rewrite");
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_IP4:	/* saddr, daddr */
				if ((off != 12 && off != 16) ||
				    fnp6l_ft_mangle(l3, sizeof(l3), off - 12, act))
					return fnp6l_ft_refuse_dev(idev, extack,
						"unsupported IPv4 rewrite");
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_TCP:	/* ports word */
			case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
				if (off || fnp6l_ft_mangle(l4, sizeof(l4), 0, act))
					return fnp6l_ft_refuse_dev(idev, extack,
						"unsupported port rewrite");
				break;
			default:
				return fnp6l_ft_refuse_dev(idev, extack,
							   "unsupported rewrite");
			}
			break;
		case FLOW_ACTION_CSUM:
			break;
		case FLOW_ACTION_VLAN_POP:	/* the NP always drops in_vid */
			if (pop)
				return fnp6l_ft_refuse_dev(idev, extack,
							   "stacked VLAN");
			pop = true;
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (push || act->vlan.proto != htons(ETH_P_8021Q) ||
			    !act->vlan.vid || act->vlan.vid > VLAN_VID_MASK)
				return fnp6l_ft_refuse_dev(idev, extack,
							   "unsupported VLAN push");
			push = act->vlan.vid;
			break;
		case FLOW_ACTION_REDIRECT:
			if (redirect)
				return -EOPNOTSUPP;
			redirect = true;
			odev = act->dev;
			if (np->ic_on) {
				nout = fnp6l_ft_end(np, act->dev, olif, false);
				break;
			}
			/* unclassified, the ingress is the loader's LIF */
			op = fnp6l_ft_port(np, act->dev);
			if (op && !op->conduit && op->lif != NP6L_LIF_LOADER)
				nout = 1, olif[0] = op->lif;
			break;
		default:
			return fnp6l_ft_refuse_dev(idev, extack,
						   "unsupported action");
		}
	}
	if (nout != 1)
		return fnp6l_ft_refuse_dev(idev, extack, "output is not an NP end");
	/*
	 * The session MTU is 1500 (fnp6l_sse_entry4): the NP would send frames
	 * of up to 1500 bytes out of a smaller MTU, without an ICMP error.
	 */
	if (odev && READ_ONCE(odev->mtu) < ETH_DATA_LEN)
		return fnp6l_ft_refuse_dev(idev, extack, "output MTU under 1500");
	/*
	 * The VLAN match of nf_flow_table_offload: in used_keys with our
	 * flowtable fix, left out of it by mainline (dissector offset set
	 * only), so a VLAN_POP of the tuple tells it is there and it is read
	 * through the offset either way. A tagged match without a pop would
	 * be taken for an untagged flow: refused.
	 */
	fl->vid = 0;
	if (!pop && (used & BIT_ULL(FLOW_DISSECTOR_KEY_VLAN)))
		return fnp6l_ft_refuse_dev(idev, extack, "VLAN match without pop");
	if (pop) {
		struct flow_match_vlan vlan;

		if (!np->ic_on ||
		    !rule->match.dissector->offset[FLOW_DISSECTOR_KEY_VLAN])
			return fnp6l_ft_refuse_dev(idev, extack,
						   "VLAN pop without match");
		flow_rule_match_vlan(rule, &vlan);
		if (vlan.key->vlan_tpid != htons(ETH_P_8021Q) ||
		    vlan.mask->vlan_id != VLAN_VID_MASK || !vlan.key->vlan_id)
			return fnp6l_ft_refuse_dev(idev, extack,
						   "unsupported VLAN match");
		fl->vid = vlan.key->vlan_id;
	}
	for (i = 0; i < fl->n_in_lif; i++)
		if (fl->in_lif[i] == olif[0])
			return fnp6l_ft_refuse_dev(idev, extack, "hairpin");
	/*
	 * One port end at least, unless sw_routed: a flow routed between two
	 * switch LIFs (dmz <-> internal3, a bond <-> a bare port) enters and
	 * leaves through the conduit link, the NP turning it round between
	 * two LIFs of the same MAC port (never measured: off by default).
	 * The same LIF both ways stays refused above (hairpin).
	 */
	for (i = j = 0; i < fl->n_in_lif; i++)
		j += fnp6l_lif_is_sw(np, fl->in_lif[i]);
	if (j && fnp6l_lif_is_sw(np, olif[0]) && !READ_ONCE(sw_routed))
		return fnp6l_ft_refuse_dev(idev, extack, "switch to switch");
	if (!is_valid_ether_addr(eth))
		return fnp6l_ft_refuse_dev(idev, extack, "no destination MAC");
	fl->obond = NULL;
	if (fnp6l_lif_is_sw(np, olif[0]) && netif_is_bond_master(odev)) {
		olif[0] = fnp6l_ft_bond_out(np, odev, eth, l3, l4,
					    basic.key->ip_proto,
					    fl->v6 ? fl->a6 : NULL);
		if (!olif[0])
			return fnp6l_ft_refuse_dev(idev, extack,
						   "no usable bond member");
		fl->obond = odev;
	}
	memcpy(fl->eth, eth, sizeof(fl->eth));
	memcpy(fl->l3, l3, sizeof(fl->l3));
	memcpy(fl->l4, l4, sizeof(fl->l4));

	fl->proto = basic.key->ip_proto;
	fl->sip = osip;
	fl->dip = odip;
	fl->sport = ports.key->src;
	fl->dport = ports.key->dst;
	memset(opt, 0, sizeof(*opt));
	opt->full = true;
	opt->has_out = true;
	opt->out = olif[0];
	opt->has_dmac = true;
	opt->out_vid = push;
	ether_addr_copy(opt->dmac, eth);
	ether_addr_copy(smac, eth + ETH_ALEN);
	memcpy(&opt->nsip, l3, 4);
	memcpy(&opt->ndip, l3 + 4, 4);
	memcpy(&opt->nsport, l4, 2);
	memcpy(&opt->ndport, l4 + 2, 2);
	opt->has_nat = opt->nsip != fl->sip || opt->ndip != fl->dip ||
		       opt->nsport != fl->sport || opt->ndport != fl->dport;
	return 0;
}

static int fnp6l_ft_replace(struct fnp6l *np, struct net_device *idev,
			    const struct flow_block *table,
			    struct flow_cls_offload *cls)
{
	struct fnp6l_ft_flow fl = { }, *flow;
	struct fnp6l_sse_opt opt;
	u8 smac[ETH_ALEN];
	unsigned int i;
	int ret;

	/*
	 * Full: refused before the parse and the lock. The flow table offers
	 * a flow left in software again at each refresh (once a second per
	 * flow): taking the command lock for each refusal queued the works.
	 */
	ret = fnp6l_ft_admit(np, 1, true);
	if (!ret)
		ret = fnp6l_ft_back_check(np, cls->cookie, true);
	if (ret)
		return ret;
	ret = fnp6l_ft_parse(np, idev, cls, &fl, &opt, smac);
	if (ret)
		return ret;

	mutex_lock(&fnp6l_sse_lock);
	if (!np->ft_on) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (fnp6l_ft_find(np, cls->cookie)) {	/* repeated REPLACE: idempotent */
		ret = 0;
		goto out;
	}
	if (np->ft_ndead)
		fnp6l_ft_dead_retry(np);
	ret = fnp6l_ft_admit(np, fl.n_in_lif, false);
	if (!ret)
		ret = fnp6l_ft_back_check(np, cls->cookie, false);
	if (ret)
		goto out;
	fnp6l_ft_keys(&fl);
	/* a dead flow still holds this key: inserting it now, the retried
	 * delete would remove the new session */
	if (np->ft_ndead && fnp6l_ft_dead_key(np, &fl)) {
		ret = -EBUSY;
		goto out;
	}
	/*
	 * A live flow with another cookie still holds one of these keys: the
	 * flow table has torn it down (its tuple used again, its conntrack
	 * entry back from the flow table, flow_offload_teardown) and added a
	 * new flow for the same tuple before the DESTROY of the old one
	 * reached us. That DESTROY is queued at the next garbage collection
	 * pass only, on another work queue than this REPLACE. Inserted now,
	 * the new sessions would take the place of the old ones in the
	 * engine (counted as inserted) and the delete of the old flow would
	 * remove them: a flow tracked without a session, its own delete
	 * refused later (as measured). Refused until the old flow is
	 * gone; the flow table offers it again at its next refresh.
	 */
	if (fnp6l_ft_key_busy(np, &fl)) {
		np->ft_keybusy++;
		ret = -EBUSY;
		goto out;
	}
	/*
	 * The inserts never take the last eighth of the queue: a burst of
	 * them refused the deletes of short connections (full, then a flow
	 * kept on ft_dead). Offered again at the next refresh.
	 */
	if (np->cmdq_on &&
	    fnp6l_cmdq_room(np) < fl.n_in_lif + NP6L_SSE_DEL_ROOM(np->cmdq.size)) {
		np->sse_iskip++;
		ret = -EBUSY;
		goto out;
	}
	fl.opt = opt;
	flow = kmemdup(&fl, sizeof(fl), GFP_KERNEL);
	if (!flow) {
		ret = -ENOMEM;
		goto out;
	}
	/* switch LIFs: source MAC of the rule (lif_cfg saved by fnp6l_sw_apply) */
	if (fnp6l_lif_is_sw(np, opt.out) && is_valid_ether_addr(smac))
		fnp6l_ft_set_smac(np, opt.out, smac);
	/* post the inserts, never waited for (see fnp6l_ft_del) */
	for (i = 0; i < fl.n_in_lif; i++) {
		ret = fnp6l_ft_fcmd(np, true, &fl, i, &opt);
		if (ret)
			break;
	}
	if (ret) {
		/* posted sessions may be in the engine: delete them, or keep
		 * the flow until they are */
		flow->n_in_lif = i < fl.n_in_lif ? i : fl.n_in_lif;
		fnp6l_ft_drop(np, flow);
		goto out;
	}
	WRITE_ONCE(np->oft_posted, np->oft_posted + fl.n_in_lif);
	flow->cookie = cls->cookie;
	flow->table = table;
	flow->lastused = jiffies;
	flow->qtime = jiffies;
	fnp6l_ft_hash_add(np, flow);
	fnp6l_ft_link(np, flow);
	fnp6l_ft_back_take(np, flow);
	dev_dbg(np->dev,
		"offloaded %u %pI4:%u > %pI4:%u (%u session(s), in_lif %u vid %u -> %u vid %u, nat %d)\n",
		fl.proto, &fl.sip, ntohs(fl.sport), &fl.dip, ntohs(fl.dport),
		fl.n_in_lif, fl.in_lif[0], fl.vid, opt.out, opt.out_vid, opt.has_nat);
out:
	mutex_unlock(&fnp6l_sse_lock);
	return ret;
}

/*
 * The flow table has let the flow go (its cookie may come back for another
 * flow): out of the indexes now; freed once its sessions are deleted, kept
 * on ft_dead (still counted against max_flows) otherwise. Its sessions the
 * engine refused get no delete (fnp6l_ft_mark_refused). A flow given back
 * is only forgotten.
 */
static int fnp6l_ft_destroy(struct fnp6l *np, unsigned long cookie)
{
	struct fnp6l_ft_flow *flow;

	if (fnp6l_ft_back_forget(np, cookie))
		return 0;
	if (!fnp6l_ft_known(np, cookie, &np->ft_unk_destroy))
		return -ENOENT;
	mutex_lock(&fnp6l_sse_lock);
	flow = fnp6l_ft_find(np, cookie);
	if (!flow) {
		mutex_unlock(&fnp6l_sse_lock);
		return -ENOENT;
	}
	fnp6l_ft_unlink(np, flow);
	if (np->np_credit && fnp6l_ft_missing(flow))
		fnp6l_ft_mark_refused(np, flow);
	fnp6l_ft_drop(np, flow);
	mutex_unlock(&fnp6l_sse_lock);
	return 0;
}

/*
 * Activity of a flow: query each session of the flow (at most every
 * ft_stats_ms) and report the time its entry last moved (fnp6l_rx_msg).
 * The queries are posted, never waited for: the reply comes as a message.
 * They never take the last quarter of the descriptors, left to the
 * inserts and deletes; a query skipped is asked again at the next pass.
 *
 * The flow table asks once a second per flow, a query is due every
 * ft_stats_ms: most calls only read the activity, under ft_sess_lock
 * alone (the lock the replies write it under, a flow being unhashed under
 * it before it is freed). The command lock only when a query is due or a
 * session was found missing.
 */
static int fnp6l_ft_stats(struct fnp6l *np, struct flow_cls_offload *cls)
{
	struct fnp6l_ft_flow *flow;
	unsigned long lastused;
	unsigned int i;
	bool due;

	spin_lock_bh(&np->ft_sess_lock);
	flow = fnp6l_ft_find(np, cls->cookie);
	if (!flow) {
		np->ft_unk_stats++;
		spin_unlock_bh(&np->ft_sess_lock);
		return -ENOENT;
	}
	due = fnp6l_ft_missing(flow) ||
	      (READ_ONCE(np->sse_done) &&
	       time_after_eq(jiffies, READ_ONCE(flow->qtime) +
			     msecs_to_jiffies(READ_ONCE(ft_stats_ms))));
	lastused = READ_ONCE(flow->lastused);
	if (!due)
		np->ft_sfast++;
	spin_unlock_bh(&np->ft_sess_lock);
	if (!due)
		goto report;

	mutex_lock(&fnp6l_sse_lock);
	flow = fnp6l_ft_find(np, cls->cookie);
	if (!flow) {
		mutex_unlock(&fnp6l_sse_lock);
		return -ENOENT;
	}
	np->ft_sslow++;
	fnp6l_ft_cap_read(np, false);
	/*
	 * A session the engine refused (a query found it missing, and the
	 * insert counters showed refusals not yet matched to a flow): the
	 * flow is no longer counted nor queried, its other sessions are
	 * deleted (never the refused ones), and it goes on in the software
	 * flow table, which offers it again at each refresh: remembered as
	 * given back, it is offered to the engine again only once the engine
	 * has room for it (fnp6l_ft_back_check).
	 */
	if (fnp6l_ft_missing(flow) && np->np_credit) {
		i = fnp6l_ft_mark_refused(np, flow);
		np->ft_back++;
		np->ft_back_sess += i;
		fnp6l_ft_unlink(np, flow);
		fnp6l_ft_back_add(np, flow);
		fnp6l_ft_drop(np, flow);
		mutex_unlock(&fnp6l_sse_lock);
		return -ENOENT;
	}
	if (np->sse_done &&
	    time_after_eq(jiffies, flow->qtime +
			  msecs_to_jiffies(READ_ONCE(ft_stats_ms)))) {
		if (fnp6l_cmdq_room(np) <
		    NP6L_SSE_QUERY_ROOM(np->cmdq.size) + flow->n_in_lif) {
			np->sse_qskip++;
		} else {
			WRITE_ONCE(flow->qtime, jiffies);
			for (i = 0; i < flow->n_in_lif; i++)
				fnp6l_ft_query(np, &flow->s[i]);
		}
	}
	lastused = READ_ONCE(flow->lastused);
	mutex_unlock(&fnp6l_sse_lock);
report:
	if (time_after(lastused, jiffies))
		lastused = jiffies;
	flow_stats_update(&cls->stats, 0, 0, 0, lastused,
			  FLOW_ACTION_HW_STATS_DELAYED);
	return 0;
}

/*
 * LAG (switch ports): re-pick the output member of every flow sent to a
 * bond of switch ports, as the bond would now (member lost, back, or slave
 * array updated); a flow whose member changed gets its sessions deleted and
 * inserted again with the new out_lif (posted in that order, read in that
 * order). A flow whose delete was refused keeps its member; one whose insert
 * was refused is marked hw_bad and done again on the next pass; *failed
 * counts both. Under fnp6l_sse_lock.
 */
static unsigned int fnp6l_ft_lag_rebalance(struct fnp6l *np, unsigned int *failed)
{
	struct fnp6l_ft_flow *flow;
	unsigned int lif, i, moved = 0;
	int ret;

	list_for_each_entry(flow, &np->ft_flows, node) {
		if (!flow->obond)
			continue;
		lif = fnp6l_ft_bond_out(np, flow->obond, flow->eth, flow->l3,
					flow->l4, flow->proto,
					flow->v6 ? flow->a6 : NULL);
		if (!lif || (lif == flow->opt.out && !flow->hw_bad))
			continue;
		if (fnp6l_ft_del(np, flow)) {
			flow->hw_bad = true;
			(*failed)++;
			continue;
		}
		flow->opt.out = lif;
		fnp6l_ft_set_smac(np, lif, flow->eth + ETH_ALEN);
		for (ret = 0, i = 0; i < flow->n_in_lif && !ret; i++) {
			ret = fnp6l_ft_fcmd(np, true, flow, i, &flow->opt);
			/* inserted again: an earlier miss no longer holds */
			if (!ret)
				WRITE_ONCE(flow->s[i].missing, false);
		}
		flow->hw_bad = ret;
		if (flow->hw_bad)
			(*failed)++;
		else
			moved++;
	}
	return moved;
}

static unsigned int lag_repick_ms;	/* 0: re-pick at once */
module_param(lag_repick_ms, uint, 0644);
MODULE_PARM_DESC(lag_repick_ms, "delay (ms) before re-picking bond members after a member change (again 300 ms later)");

static void fnp6l_ft_lag_work(struct work_struct *work)
{
	struct fnp6l *np = container_of(to_delayed_work(work), struct fnp6l,
					ft_lag_work);
	unsigned int moved = 0, failed = 0;

	rtnl_lock();		/* bond lowers and slave state stable */
	mutex_lock(&fnp6l_sse_lock);
	if (np->ft_on && np->sse_done)
		moved = fnp6l_ft_lag_rebalance(np, &failed);
	np->ft_lagfail += failed;
	mutex_unlock(&fnp6l_sse_lock);
	rtnl_unlock();
	if (moved)
		dev_info(np->dev, "ft: lag: %u flow(s) moved to another member\n",
			 moved);
	if (failed)
		dev_warn_ratelimited(np->dev, "ft: lag: %u flow(s) not moved, retried\n",
				     failed);
	if (np->ft_lag_again) {
		np->ft_lag_again = 0;
		schedule_delayed_work(&np->ft_lag_work, msecs_to_jiffies(300));
	} else if (failed) {
		schedule_delayed_work(&np->ft_lag_work, HZ);
	}
}

static int fnp6l_ft_netdev_event(struct notifier_block *nb, unsigned long event,
				 void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct fnp6l *np = container_of(nb, struct fnp6l, ft_nb);

	switch (event) {
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
	case NETDEV_CHANGELOWERSTATE:
		break;
	case NETDEV_CHANGEUPPER:
		/*
		 * A switch port joins or leaves a bridge (or a bond): its
		 * flows were offloaded with the source MAC and the end of
		 * before; torn down, offered anew. Under RTNL, as the flow
		 * table does itself on NETDEV_DOWN.
		 */
		if (IS_ENABLED(CONFIG_NF_FLOW_TABLE) &&
		    READ_ONCE(np->ft_on) && READ_ONCE(np->sw_on) &&
		    fnp6l_ft_sw_lif(np, dev))
			nf_flow_table_cleanup(dev);
		return NOTIFY_DONE;
	default:
		return NOTIFY_DONE;
	}
	if (!READ_ONCE(np->ft_on) || !READ_ONCE(np->sw_on))
		return NOTIFY_DONE;
	if (!fnp6l_ft_sw_lif(np, dev) && !netif_is_bond_master(dev))
		return NOTIFY_DONE;
	np->ft_lag_again = 1;
	mod_delayed_work(system_wq, &np->ft_lag_work,
			 msecs_to_jiffies(lag_repick_ms));
	return NOTIFY_DONE;
}

/* The user port of the switch LIF @lif, or NULL. RTNL. */
static struct net_device *fnp6l_sw_user(struct fnp6l *np, unsigned int lif)
{
#if IS_REACHABLE(CONFIG_NET_DSA)
	struct fnp6l_port *c = lif < NP6L_MAX_LIF ? np->sw_conduit[lif] : NULL;
	struct dsa_port *cpu, *dp;

	if (!c)
		return NULL;
	cpu = c->ndev->dsa_ptr;
	if (!cpu)
		return NULL;
	dp = dsa_to_port(cpu->ds, np->sw_port[lif]);
	return dp ? dp->user : NULL;
#else
	return NULL;
#endif
}

/*
 * A station learnt by a bridge on one of our switch ports, or forgotten
 * there (an entry put by the user only: offloaded stations are not seen
 * ageing by the bridge): an offloaded flow towards it through another
 * port of the bridge would keep sending there. Queued for
 * fnp6l_ft_fdb_work (60D: fnp4l_dsa_fdb_event). Atomic.
 */
static int fnp6l_ft_fdb_event(struct notifier_block *nb, unsigned long event,
			      void *ptr)
{
	struct fnp6l *np = container_of(nb, struct fnp6l, ft_fdb_nb);
	struct switchdev_notifier_fdb_info *fdb = ptr;
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	struct net_device *master;
	unsigned long flags;
	bool ours;

	if ((event != SWITCHDEV_FDB_ADD_TO_DEVICE &&
	     (event != SWITCHDEV_FDB_DEL_TO_DEVICE || !fdb->added_by_user)) ||
	    fdb->is_local || !READ_ONCE(bridge_offload) ||
	    !READ_ONCE(np->ft_on) || !READ_ONCE(np->sw_on))
		return NOTIFY_DONE;
	rcu_read_lock();
	master = netdev_master_upper_dev_get_rcu(dev);
	ours = master && netif_is_bridge_master(master) &&
	       fnp6l_ft_sw_lif(np, dev);
	rcu_read_unlock();
	if (!ours)
		return NOTIFY_DONE;

	spin_lock_irqsave(&np->ft_fdb_lock, flags);
	if (np->ft_fdb_n < ARRAY_SIZE(np->ft_fdb_dev)) {
		dev_hold(dev);
		np->ft_fdb_dev[np->ft_fdb_n] = dev;
		ether_addr_copy(np->ft_fdb_addr[np->ft_fdb_n], fdb->addr);
		np->ft_fdb_del[np->ft_fdb_n] =
			event == SWITCHDEV_FDB_DEL_TO_DEVICE;
		np->ft_fdb_n++;
	} else {
		np->ft_fdb_lost = true;
	}
	spin_unlock_irqrestore(&np->ft_fdb_lock, flags);
	queue_work(system_wq, &np->ft_fdb_work);
	return NOTIFY_DONE;
}

/*
 * Tear down the flows towards a station learnt on another port than the one
 * of their output LIF, or forgotten (all the bridged LIFs past a full
 * ring): the flow table tears down every flow through that port
 * (nf_flow_table_cleanup), whose packets then go through the host, which
 * offers them anew once the path resolves the new port. The flow list under
 * fnp6l_sse_lock, the cleanup outside it (it flushes the offload work,
 * whose callbacks take that lock).
 */
static void fnp6l_ft_fdb_work(struct work_struct *work)
{
	struct fnp6l *np = container_of(work, struct fnp6l, ft_fdb_work);
	struct net_device *devs[ARRAY_SIZE(np->ft_fdb_dev)];
	u8 addrs[ARRAY_SIZE(np->ft_fdb_dev)][ETH_ALEN];
	bool dels[ARRAY_SIZE(np->ft_fdb_dev)];
	struct fnp6l_ft_flow *flow;
	unsigned long old = 0, flags;
	struct net_device *udev;
	unsigned int i, n, lif, out;
	bool lost;

	spin_lock_irqsave(&np->ft_fdb_lock, flags);
	n = np->ft_fdb_n;
	memcpy(devs, np->ft_fdb_dev, n * sizeof(devs[0]));
	memcpy(addrs, np->ft_fdb_addr, n * ETH_ALEN);
	memcpy(dels, np->ft_fdb_del, n * sizeof(dels[0]));
	np->ft_fdb_n = 0;
	lost = np->ft_fdb_lost;
	np->ft_fdb_lost = false;
	spin_unlock_irqrestore(&np->ft_fdb_lock, flags);

	rtnl_lock();
	mutex_lock(&fnp6l_sse_lock);
	list_for_each_entry(flow, &np->ft_flows, node) {
		out = flow->opt.out;
		if (flow->obond || !fnp6l_lif_is_sw(np, out))
			continue;
		if (lost) {
			__set_bit(out, &old);
			continue;
		}
		for (i = 0; i < n; i++) {
			if (!ether_addr_equal(flow->eth, addrs[i]))
				continue;
			lif = fnp6l_ft_sw_lif(np, devs[i]);
			/* forgotten: whatever port; learnt: another port */
			if (dels[i] || out != lif)
				__set_bit(out, &old);
		}
	}
	mutex_unlock(&fnp6l_sse_lock);
	if (old && IS_ENABLED(CONFIG_NF_FLOW_TABLE)) {
		for_each_set_bit(lif, &old, NP6L_MAX_LIF) {
			udev = fnp6l_sw_user(np, lif);
			if (!udev)
				continue;
			nf_flow_table_cleanup(udev);
			np->ft_fdb_moves++;
		}
		dev_info(np->dev, "ft: bridge: station moved or forgotten, flows through LIFs %#lx torn down\n",
			 old);
	}
	rtnl_unlock();

	for (i = 0; i < n; i++)
		dev_put(devs[i]);
}

/*
 * A port or a bond leaves flow table @table: delete every flow that table
 * offered, through any port. The flows of the other tables bound at the
 * same time (a reload binds the new table before it unbinds the old one,
 * a check-only transaction binds and unbinds a table of its own) stay.
 */
static void fnp6l_ft_forget_table(struct fnp6l *np,
				  const struct flow_block *table)
{
	struct fnp6l_ft_flow *flow, *tmp;

	mutex_lock(&fnp6l_sse_lock);
	list_for_each_entry_safe(flow, tmp, &np->ft_flows, node) {
		if (flow->table != table)
			continue;
		fnp6l_ft_unlink(np, flow);
		fnp6l_ft_drop(np, flow);
	}
	fnp6l_ft_back_forget_table(np, table);
	mutex_unlock(&fnp6l_sse_lock);
}

/*
 * Several flow tables may be bound to a port at a time: each binding of a
 * table to a port has its callback, whose data says which table its flows
 * come from.
 */
struct fnp6l_ft_block {
	struct fnp6l_port *port;
	const struct flow_block *table;
};

static void fnp6l_ft_block_free(void *cb_priv)
{
	kfree(cb_priv);
}

static int fnp6l_ft_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	const struct fnp6l_ft_block *blk = cb_priv;
	struct fnp6l_port *port = blk->port;
	struct flow_cls_offload *cls = type_data;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;
	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		if (!tc_can_offload(port->ndev))
			return -EOPNOTSUPP;
		return fnp6l_ft_replace(port->np, port->ndev, blk->table, cls);
	case FLOW_CLS_DESTROY:
		return fnp6l_ft_destroy(port->np, cls->cookie);
	case FLOW_CLS_STATS:
		return fnp6l_ft_stats(port->np, cls);
	default:
		return -EOPNOTSUPP;
	}
}

static LIST_HEAD(fnp6l_block_cb_list);

static void fnp6l_ft_priv_release(void *cb_priv)
{
	kfree(cb_priv);
}

/*
 * Bare switch ports: a flow table listing a DSA user port reaches its
 * conduit's ndo_setup_tc with the table's block, once per user port listed
 * (dsa_user_setup_ft_block), the user port unnamed. One callback per table
 * and conduit, counted (flow_block_cb_incref/decref), bound with the first
 * user port and unbound with the last (several tables may be bound at a
 * time, as for a port: a reload binds the new table before it unbinds the
 * old one); the ingress device of each flow is
 * found by meta.ingress_ifindex. Only a flow entering through a user port of
 * this conduit is parsed (fnp6l_ft_end: a bare port with a LIF of its own),
 * any other is left to the callback of its own device. STATS and DESTROY
 * go by cookie, as for every callback of the table: the activity reported
 * is a time, never packets or bytes, so a flow seen by several callbacks
 * is not counted twice.
 */
struct fnp6l_ft_dsa {
	struct fnp6l_port *port;	/* the conduit */
	struct net *net;		/* of the flow table */
	const struct flow_block *table;	/* one callback per table */
};

static int fnp6l_ft_dsa_cb(enum tc_setup_type type, void *type_data,
			   void *cb_priv)
{
	struct fnp6l_ft_dsa *b = cb_priv;
	struct fnp6l *np = b->port->np;
	struct flow_cls_offload *cls = type_data;
	struct flow_match_meta meta;
	struct net_device *idev;
	struct dsa_port *dp;
	int ret;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;
	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		if (!flow_rule_match_key(flow_cls_offload_flow_rule(cls),
					 FLOW_DISSECTOR_KEY_META))
			return -EOPNOTSUPP;
		flow_rule_match_meta(flow_cls_offload_flow_rule(cls), &meta);
		idev = dev_get_by_index(b->net, meta.key->ingress_ifindex);
		if (!idev)
			return -ENOENT;
		dp = fnp6l_dsa_port(idev);
		if (IS_ERR_OR_NULL(dp) || !dp->cpu_dp ||
		    dp->cpu_dp->conduit != b->port->ndev || !tc_can_offload(idev))
			ret = -EOPNOTSUPP;	/* not entering through our user ports */
		else
			ret = fnp6l_ft_replace(np, idev, b->table, cls);
		dev_put(idev);
		return ret;
	case FLOW_CLS_DESTROY:
		return fnp6l_ft_destroy(np, cls->cookie);
	case FLOW_CLS_STATS:
		return fnp6l_ft_stats(np, cls);
	default:
		return -EOPNOTSUPP;
	}
}

static int fnp6l_setup_ft_conduit(struct fnp6l_port *port,
				  struct flow_block_offload *f)
{
	struct fnp6l *np = port->np;
	struct flow_block_cb *block_cb;
	struct fnp6l_ft_dsa *b;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		block_cb = flow_block_cb_lookup(f->block, fnp6l_ft_dsa_cb, port);
		if (block_cb) {		/* another user port of the same table */
			flow_block_cb_incref(block_cb);
			return 0;
		}
		if (!READ_ONCE(bare_ports) || !READ_ONCE(np->ft_on) ||
		    !READ_ONCE(np->sw_on)) {
			NL_SET_ERR_MSG_MOD(f->extack, "flow offload not enabled");
			return -EOPNOTSUPP;
		}
		/* one callback per table, others bound or not */
		b = kzalloc(sizeof(*b), GFP_KERNEL);
		if (!b)
			return -ENOMEM;
		b->port = port;
		b->net = f->net;
		b->table = f->block;
		block_cb = flow_block_cb_alloc(fnp6l_ft_dsa_cb, port, b,
					       fnp6l_ft_priv_release);
		if (IS_ERR(block_cb)) {
			kfree(b);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_incref(block_cb);
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &fnp6l_block_cb_list);
		netdev_info(port->ndev, "ft: bound (bare switch ports)\n");
		return 0;
	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block, fnp6l_ft_dsa_cb, port);
		if (!block_cb)
			return -ENOENT;
		if (flow_block_cb_decref(block_cb))
			return 0;	/* other user ports still listed */
		flow_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		fnp6l_ft_forget_table(np, f->block);
		netdev_info(port->ndev, "ft: unbound (bare switch ports)\n");
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int fnp6l_setup_ft(struct fnp6l_port *port, struct flow_block_offload *f)
{
	flow_setup_cb_t *cb = fnp6l_ft_cb;
	struct flow_block_cb *block_cb;
	struct fnp6l_ft_block *blk;

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;
	f->driver_block_list = &fnp6l_block_cb_list;
	/* a DSA conduit: reached through user ports of the switch only */
	if (netdev_uses_dsa(port->ndev))
		return fnp6l_setup_ft_conduit(port, f);

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		if (!READ_ONCE(port->np->ft_on)) {
			NL_SET_ERR_MSG_MOD(f->extack,
					   "flow offload not enabled");
			return -EOPNOTSUPP;
		}
		/* bound twice to this port by the same table */
		block_cb = flow_block_cb_lookup(f->block, cb, port);
		if (block_cb) {
			flow_block_cb_incref(block_cb);
			return 0;
		}
		/* one callback per table, others bound or not */
		blk = kzalloc(sizeof(*blk), GFP_KERNEL);
		if (!blk)
			return -ENOMEM;
		blk->port = port;
		blk->table = f->block;
		block_cb = flow_block_cb_alloc(cb, port, blk, fnp6l_ft_block_free);
		if (IS_ERR(block_cb)) {
			kfree(blk);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_incref(block_cb);
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &fnp6l_block_cb_list);
		return 0;
	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block, cb, port);
		if (!block_cb)
			return -ENOENT;
		if (flow_block_cb_decref(block_cb))
			return 0;
		flow_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		fnp6l_ft_forget_table(port->np, f->block);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Indirect block (switch ports): the bonding driver has no ndo_setup_tc,
 * so a flow table listing a bond with the "offload" flag reaches us here.
 * Only a bond of our switch ports, with the offload state applied and the
 * switch ports classified; the bond's flows then come to fnp6l_ft_bond_cb
 * (and, as for any block of the table, to the wan callbacks, which ignore
 * them).
 */
struct fnp6l_ft_bond {
	struct fnp6l *np;
	struct net_device *dev;
	const struct flow_block *table;	/* one callback per table */
};

static int fnp6l_ft_bond_cb(enum tc_setup_type type, void *type_data,
			    void *cb_priv)
{
	struct fnp6l_ft_bond *b = cb_priv;
	struct flow_cls_offload *cls = type_data;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;
	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		return fnp6l_ft_replace(b->np, b->dev, b->table, cls);
	case FLOW_CLS_DESTROY:
		return fnp6l_ft_destroy(b->np, cls->cookie);
	case FLOW_CLS_STATS:
		return fnp6l_ft_stats(b->np, cls);
	default:
		return -EOPNOTSUPP;
	}
}

static int fnp6l_ft_indr_setup(struct net_device *dev, struct Qdisc *sch,
			       void *cb_priv, enum tc_setup_type type,
			       void *type_data, void *data,
			       void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct flow_block_offload *f = type_data;
	struct fnp6l *np = cb_priv;
	struct flow_block_cb *block_cb;
	struct fnp6l_ft_bond *b;
	u8 lifs[NP6L_SW_PORTS];

	if (!dev || type != TC_SETUP_FT || !netif_is_bond_master(dev) ||
	    f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;
	f->driver_block_list = &fnp6l_block_cb_list;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		mutex_lock(&fnp6l_sse_lock);
		if (!np->ft_on || !np->ic_on ||
		    !fnp6l_ft_end(np, dev, lifs, true)) {
			mutex_unlock(&fnp6l_sse_lock);
			NL_SET_ERR_MSG_MOD(f->extack,
					   "bond offload needs the flow offload and switch ports only");
			return -EOPNOTSUPP;
		}
		mutex_unlock(&fnp6l_sse_lock);
		/* bound twice to this bond by the same table */
		block_cb = flow_block_cb_lookup(f->block, fnp6l_ft_bond_cb, dev);
		if (block_cb) {
			flow_block_cb_incref(block_cb);
			return 0;
		}
		b = kzalloc(sizeof(*b), GFP_KERNEL);
		if (!b)
			return -ENOMEM;
		b->np = np;
		b->dev = dev;
		b->table = f->block;
		block_cb = flow_indr_block_cb_alloc(fnp6l_ft_bond_cb, dev, b,
						    fnp6l_ft_priv_release, f, dev,
						    sch, data, np, cleanup);
		if (IS_ERR(block_cb)) {
			kfree(b);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_incref(block_cb);
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &fnp6l_block_cb_list);
		dev_info(np->dev, "ft: bond %s bound (switch ports)\n", dev->name);
		return 0;
	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block, fnp6l_ft_bond_cb, dev);
		if (!block_cb)
			return -ENOENT;
		if (flow_block_cb_decref(block_cb))
			return 0;
		flow_indr_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		fnp6l_ft_forget_table(np, f->block);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int fnp6l_setup_tc(struct net_device *ndev, enum tc_setup_type type,
			  void *type_data)
{
	if (type != TC_SETUP_FT)
		return -EOPNOTSUPP;
	return fnp6l_setup_ft(netdev_priv(ndev), type_data);
}

/* ------------------------------------------ ingress classification */

/*
 * Undo a failed fnp6l_igr_class_init: put the IGR port tag TPID back and clear
 * the class table cells posted so far. The ports keep their LIF, so without
 * the IGR the port tag on the wire classifies them again (fnp6l_rx_deliver,
 * port tag path).
 */
static void fnp6l_igr_class_teardown(struct fnp6l *np)
{
	unsigned int i;

	if (!np->ic_on && !np->ic_nidx)
		return;
	fnp6l_wr(np, NP6L_IGR_PORT_TAG_TPID, np->ic_saved_port_tag_tpid);
	for (i = 0; i < np->ic_nidx; i++) {
		u32 z[4] = { };

		fnp6l_tbl_op(np, NP6L_TBL_CLASS, np->ic_idx[i], z, true);
	}
	np->ic_nidx = 0;
	np->ic_on = false;
	dev_info(np->dev, "ingress_class: torn down (class table cleared, port tag TPID restored)\n");
}

/*
 * Ingress classification: post one class table entry per managed port toward
 * its own LIF (key = port tag, VID 0) at the row*4+bank index, then turn the
 * IGR port tag parser on. The ports are not open yet, so fnp6l_port_tag
 * returns the link<<4 port tag even before fnp6l_mac_init runs. Called at
 * probe under fnp6l_sse_lock. The port on the loader's LIF 0 keeps it, so
 * no port table is rewritten here. Every port, by LIF (60E: wan1 0, wan2 2,
 * conduit 3).
 */
static int fnp6l_igr_class_init(struct fnp6l *np)
{
	unsigned int i, n = 0;

	np->ic_nidx = 0;
	np->ic_saved_port_tag_tpid = fnp6l_rd(np, NP6L_IGR_PORT_TAG_TPID);
	for (i = 0; i < NP6L_MAX_LIF; i++) {
		struct fnp6l_port *p = np->port[i];
		unsigned int ptag;
		int idx;

		if (!p)
			continue;
		ptag = fnp6l_port_tag(np, p);
		idx = fnp6l_class_insert(np, ptag, 0, p->lif);	/* key port tag << 12, vid 0 */
		if (idx < 0) {
			/*
			 * A DSA conduit may hash to the unverified idx >= 128
			 * zone (60E: LIF 3, row 44 -> idx 176): do not let its
			 * failure abort the classification of the other
			 * ports (the goal).
			 */
			if (p->conduit) {
				netdev_warn(p->ndev,
					    "ingress_class: switch LIF %u class table insert failed (%d), skipped\n",
					    p->lif, idx);
				continue;
			}
			netdev_err(p->ndev,
				   "ingress_class: class table insert LIF %u failed (%d)\n",
				   p->lif, idx);
			fnp6l_igr_class_teardown(np);
			return idx;
		}
		if (np->ic_nidx < ARRAY_SIZE(np->ic_idx))
			np->ic_idx[np->ic_nidx++] = idx;
		netdev_info(p->ndev, "ingress_class: LIF %u port tag %#x class table idx %d\n",
			    p->lif, ptag, idx);
		n++;
	}
	if (!n)
		return 0;
	fnp6l_wr(np, NP6L_IGR_PORT_TAG_TPID, NP6L_IGR_PORT_TAG_TPID_INIT);
	np->ic_on = true;
	dev_info(np->dev,
		 "ingress_class: %u class table entries, port tag TPID %#x -> %#x (port tag parsed in hardware)\n",
		 n, np->ic_saved_port_tag_tpid, fnp6l_rd(np, NP6L_IGR_PORT_TAG_TPID));
	return 0;
}

/*
 * IPv6 egress MTU of the port LIFs (trunk_cfg bits 76:64, units of 2 bytes;
 * 761 = 1522-byte frames): the
 * loader leaves 0 there, and the NP then sends every IPv6 frame of the LIF
 * -- the host's own included, neighbour discovery first -- as an atomic
 * fragment that the peers ignore. Set at probe for every port LIF
 * (the loader's LIF 0 included: only these 13 bits of its trunk_cfg, word 2) so the
 * host's IPv6 works without the flow offload; the switch-port LIFs copy
 * their conduit's and inherit it. Only a zero field is written. Without IPv6 the
 * loader value is left.
 */
static void fnp6l_v6_mtu_init(struct fnp6l *np)
{
	unsigned int lif;
	u32 d[4];

	if (!IS_ENABLED(CONFIG_IPV6))
		return;
	for (lif = 0; lif < NP6L_MAX_LIF; lif++) {
		if (!np->port[lif] || np->port[lif]->lif != lif)
			continue;
		if (fnp6l_tbl_op(np, NP6L_TBL_TRUNK_CFG, lif, d, false))
			continue;
		if (d[2] & GENMASK(12, 0))
			continue;
		d[2] |= 761;
		if (fnp6l_tbl_op(np, NP6L_TBL_TRUNK_CFG, lif, d, true))
			continue;
		netdev_info(np->port[lif]->ndev, "LIF %u IPv6 MTU %u (loader 0)\n",
			    lif, 2 * 761);
	}
}

/*
 * Flow offload at probe (under fnp6l_sse_lock, ports registered, none open),
 * in order: the session engine, the offload state, then the switch-port
 * classification (which copies the raised source action of the conduit LIF).
 * A failed step leaves the earlier ones and is logged.
 */
static void fnp6l_flow_offload_init(struct fnp6l *np)
{
	int ret;

	if (!np->ic_on) {
		dev_warn(np->dev, "flow offload: no ingress classification, off\n");
		return;
	}
	ret = fnp6l_sse_init(np);
	if (ret && !np->sse_done) {
		dev_err(np->dev, "flow offload: session engine not on (%d)\n", ret);
		return;
	}
	ret = fnp6l_ft_apply(np);
	if (ret) {
		dev_err(np->dev, "flow offload: state not applied (%d)\n", ret);
		return;
	}
	ret = fnp6l_sw_apply(np);
	if (ret && ret != -ENODEV)	/* -ENODEV: no switch ports to classify */
		dev_warn(np->dev, "flow offload: switch ports not classified (%d)\n",
			 ret);
}

static void fnp6l_debugfs_init(struct fnp6l *np)
{
	struct dentry *dir = debugfs_create_dir(DRV_NAME, NULL);

	debugfs_create_file("sse", 0400, dir, np, &fnp6l_dbg_sse_fops);
	debugfs_create_file("class_table", 0400, dir, np, &fnp6l_dbg_class_fops);
	debugfs_create_file("sw_class", 0400, dir, np, &fnp6l_dbg_sw_fops);
}

/*
 * Initial state of the NP tables. The boot loader only initialises the NP
 * when its own network stack runs (TFTP boot): after a cold boot from the
 * eMMC the NP SRAM tables hold noise and no frame crosses the NP. Written
 * at every probe, the TFTP path included: MDIO configuration, the hashed
 * tables cleared (with their chain pointers), default L4 parse entries,
 * the LIF 0/1 entries, and the SSE interrupt control. Enabling the host
 * queues on the NP side and the default LIF is not needed (found by
 * bisection). Not written here either: DMA descriptors (this driver has
 * its own rings), PHY reset GPIOs (fortinet,reset-pins), the MACs
 * (fnp6l_mac_init at open) and the MDIO.
 */
struct fnp6l_tbl_init_stats {
	unsigned int ok, fail;
};

static void fnp6l_tbl_init_wr(struct fnp6l_tbl_init_stats *st, struct fnp6l *np, u32 tbl,
			      u32 idx, u32 *d)
{
	if (fnp6l_tbl_op(np, tbl, idx, d, true))
		st->fail++;
	else
		st->ok++;
}

static void fnp6l_tbl_fill(struct fnp6l_tbl_init_stats *st, struct fnp6l *np, u32 tbl,
			   unsigned int entries, u32 *d)
{
	unsigned int i;

	for (i = 0; i < entries; i++)
		fnp6l_tbl_init_wr(st, np, tbl, i, d);
}

/* registers cleared at init (function not identified) */
#define NP6L_INIT_ZERO_2330		0x2330
#define NP6L_INIT_ZERO_3880		0x3880
#define NP6L_INIT_ZERO_3898		0x3898
#define NP6L_INIT_ZERO_38B0		0x38b0

static void fnp6l_hw_init_tables(struct fnp6l *np)
{
	struct fnp6l_tbl_init_stats st = { };
	/* partial initializers zero the words the loader leaves at 0 (d3 too) */
	u32 z[4] = { };
	u32 chain_7f[4] = { 0x7f };
	u32 chain_1ff[4] = { 0x1ff };
	u32 l4_parse_in[4] = { 0xc0000000 };
	u32 l4_parse_out[4] = { 0x40000000 };
	u32 lif_mac[4] = { 0, 0x00010000 };
	u32 port_action[4] = { 0x00100000, 0x00040080 };
	u32 port_trunk1[4] = { 1 };
	/*
	 * trunk_cfg as read after a TFTP boot: w1 = 0x7fc00000 (0x3fe0 in
	 * bits 30:17), w2 = 0x2f9 for LIF 0 and 0 for LIF 1
	 */
	u32 trunk0[4] = { 0, 0x7fc00000, 0x2f9 };
	u32 trunk1[4] = { 0, 0x7fc00000 };
	/* LIF 0 output on MAC port 2 (wan1): w1[23:16] = port * 4 + 1; LIF 1 = host queue 0 */
	u32 pc_wan1[4] = { 0, (2 * 4 + 1) << 16 };
	u32 pc_host[4] = { 0, 0x00800000 };

	fnp6l_wr(np, NP6L_MDIO_CFG, 0x38306300);

	fnp6l_tbl_fill(&st, np, NP6L_TBL_CLASS, 384, z);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_CLASS_CHAIN, 96, chain_7f);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_TCE_MAP, 1536, z);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_TCE_CHAIN, 384, chain_1ff);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_IHP_L4_PARSE, 256, l4_parse_in);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_HTX_L4_PARSE, 256, l4_parse_out);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_LIF_MAC, 0, lif_mac);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_PORT_ACTION, 0, port_action);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_VLAN_ACT, 1536, z);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_VLAN_ACT_CHAIN, 384, chain_1ff);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_PROTO_SRC, 384, z);
	fnp6l_tbl_fill(&st, np, NP6L_TBL_PROTO_SRC_CHAIN, 96, chain_7f);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_PORT_TRUNK, 0, z);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_PORT_TRUNK, 1, port_trunk1);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_TRUNK_CFG, 0, trunk0);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_TRUNK_CFG, 1, trunk1);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_LIF_CFG, 0, pc_wan1);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_LIF_CFG, 1, pc_host);
	fnp6l_tbl_init_wr(&st, np, NP6L_TBL_EGR_TAG, 0, z);

	fnp6l_wr(np, NP6L_SSE_IRQ_CTRL, 0);
	fnp6l_wr(np, NP6L_INIT_ZERO_2330, 0);
	fnp6l_wr(np, NP6L_INIT_ZERO_38B0, 0);
	fnp6l_wr(np, NP6L_INIT_ZERO_3880, 0);
	fnp6l_wr(np, NP6L_INIT_ZERO_3898, 0);

	dev_info(np->dev, "table init: %u entries written, %u failed\n",
		 st.ok, st.fail);
}

static int fnp6l_setup_net(struct platform_device *pdev, struct fnp6l *np)
{
	struct device_node *ports, *dn;
	unsigned int q;
	u32 hi;
	int ret, irq;

	/*
	 * DMA address bits 39:32: 0x27 sends the accesses through
	 * the ACP (cache coherent, once its profiles are programmed by the
	 * machine code: dma-coherent node); otherwise the loader's value.
	 */
	hi = np->loader_ring_hi;
	if (dev_is_dma_coherent(np->dev))
		np->addr_hi = 0x27;
	else if ((np->loader_qctrl & NP6L_Q_CTRL_EN) && hi)
		np->addr_hi = hi & 0xff;
	else
		np->addr_hi = 0x27;
	dev_info(np->dev, "DMA address bits 39:32 = %#x\n", np->addr_hi);

	ret = dma_set_mask_and_coherent(np->dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	np->napi_dev = alloc_netdev_dummy(0);
	if (!np->napi_dev)
		return -ENOMEM;

	for (q = 0; q < NP6L_NR_QUEUES; q++) {
		fnp6l_wr(np, NP6L_HRXQ_DMA_PARAMS(q), NP6L_HRXQ_DMA_PARAMS_INIT);
		fnp6l_wr(np, NP6L_HTXQ_DMA_PARAMS(q), NP6L_HTXQ_DMA_PARAMS_INIT);
	}
	fnp6l_pdq_init(np);

	np->rx_mask = GENMASK(NP6L_NR_QUEUES - 1, 0);
	/* host queue q goes to vector q mod 4 (fnp6l_irq_vec_init) */
	np->nvec = NP6L_NR_VEC;
	for (q = 0; q < np->nvec; q++) {
		np->vec[q].np = np;
		np->vec[q].idx = q;
		np->vec[q].irq = -1;
		netif_napi_add(np->napi_dev, &np->vec[q].napi, fnp6l_poll);
	}
	np->vec[0].tx = true;
	for_each_set_bit(q, &np->rx_mask, NP6L_NR_QUEUES)
		__set_bit(q, &np->vec[q % NP6L_NR_VEC].qmask);
	for_each_set_bit(q, &np->rx_mask, NP6L_NR_QUEUES) {
		struct fnp6l_ring *r = &np->rx[q];

		ret = fnp6l_ring_alloc(np, r, false, q, NP6L_RXQ_SIZE);
		if (ret)
			goto err;
		while (r->tail < r->size - 1) {
			ret = fnp6l_rx_fill_one(np, r);
			if (ret)
				goto err;
		}
		ret = fnp6l_ring_start(np, r);
		if (ret)
			goto err;
	}
	ret = fnp6l_ring_alloc(np, &np->tx, true, 0, NP6L_TXQ_SIZE);
	if (ret)
		goto err;
	ret = fnp6l_ring_start(np, &np->tx);
	if (ret)
		goto err;
	/* host queues the NP may deliver to ((1 << nrx) - 1) */
	fnp6l_wr(np, NP6L_EGR_SW_QUEUE_EN0, np->rx_mask);

	np->use_irq = !poll_ms;
	if (np->use_irq) {
		fnp6l_irq_vec_init(np);
		for (q = 0; q <= NP6L_NR_VEC; q++) {
			struct fnp6l_vec *v = &np->vec[q % NP6L_NR_VEC];

			irq = platform_get_irq(pdev, q);
			if (irq < 0) {
				ret = irq;
				goto err;
			}
			if (q == NP6L_NR_VEC)
				ret = devm_request_irq(np->dev, irq, fnp6l_err_irq,
						       IRQF_SHARED, dev_name(np->dev), np);
			else
				ret = devm_request_irq(np->dev, irq, fnp6l_vec_irq,
						       IRQF_SHARED, dev_name(np->dev), v);
			if (ret)
				goto err;
			if (q == NP6L_NR_VEC)
				continue;
			/*
			 * IRQ affinity: HIF vector i -> CPU i mod CPUs online,
			 * so that the NAPI of queue i runs there. Cleared
			 * before the interrupt is freed (devm order).
			 */
			v->irq = irq;
			if (irq_set_affinity_and_hint(irq,
					cpumask_of(q % num_online_cpus())))
				dev_warn(np->dev, "hif%u: affinity not set\n", q);
			ret = devm_add_action_or_reset(np->dev, fnp6l_clear_affinity_hint,
						       (void *)(unsigned long)irq);
			if (ret)
				goto err;
		}
	}
	timer_setup(&np->poll_timer, fnp6l_poll_timer, 0);
	for (q = 0; q < np->nvec; q++)
		napi_enable(&np->vec[q].napi);
	if (np->use_irq) {
		for_each_set_bit(q, &np->rx_mask, NP6L_NR_QUEUES)
			writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_FRAMES | NP6L_Q_INT_FATAL,
			       np->rx[q].regs + NP6L_Q_INT_ENABLE);
		writel(NP6L_Q_INT_TIMER | NP6L_Q_INT_ABS_TIMER | NP6L_Q_INT_FRAMES | NP6L_Q_INT_FATAL,
		       np->tx.regs + NP6L_Q_INT_ENABLE);
		mod_timer(&np->poll_timer, jiffies + msecs_to_jiffies(100));
	} else {
		mod_timer(&np->poll_timer, jiffies + 1);
	}

	if (of_property_read_bool(np->dev->of_node, "fortinet,init-logical-interfaces")) {
		fnp6l_tbl_dump(np, "egr_tag", NP6L_TBL_EGR_TAG, 4);
		fnp6l_tbl_dump(np, "port_action", NP6L_TBL_PORT_ACTION, 4);
		fnp6l_tbl_dump(np, "lif_mac", NP6L_TBL_LIF_MAC, 4);
		fnp6l_tbl_dump(np, "trunk_cfg", NP6L_TBL_TRUNK_CFG, 4);
		fnp6l_tbl_dump(np, "lif_cfg", NP6L_TBL_LIF_CFG, 4);
		fnp6l_tbl_dump(np, "port_trunk", NP6L_TBL_PORT_TRUNK, 4);
	}
	ports = of_get_child_by_name(np->dev->of_node, "ethernet-ports");
	for_each_available_child_of_node(ports, dn) {
		ret = fnp6l_add_port(np, dn);
		if (ret) {
			of_node_put(dn);
			break;
		}
		np->nports++;
	}
	of_node_put(ports);
	dev_info(np->dev, "%u port(s), rx queues %#lx, tx queue 0, %s, %u NAPI\n",
		 np->nports, np->rx_mask,
		 np->use_irq ? "interrupts" : "polled", np->nvec);
	fnp6l_debugfs_init(np);
	INIT_LIST_HEAD(&np->ft_flows);
	INIT_LIST_HEAD(&np->ft_dead);
	INIT_LIST_HEAD(&np->ft_backl);
	for (q = 0; q < ARRAY_SIZE(np->ft_bhash); q++)
		INIT_HLIST_HEAD(&np->ft_bhash[q]);
	spin_lock_init(&np->ft_sess_lock);
	INIT_DELAYED_WORK(&np->ft_dead_work, fnp6l_ft_dead_work);
	np->ft_qoff = -1;
	INIT_DELAYED_WORK(&np->ft_lag_work, fnp6l_ft_lag_work);
	np->ft_nb.notifier_call = fnp6l_ft_netdev_event;
	spin_lock_init(&np->ft_fdb_lock);
	INIT_WORK(&np->ft_fdb_work, fnp6l_ft_fdb_work);
	np->ft_fdb_nb.notifier_call = fnp6l_ft_fdb_event;
	if (IS_ENABLED(CONFIG_FORTINET_NP6LITE_FLOW_OFFLOAD)) {
		if (flow_indr_dev_register(fnp6l_ft_indr_setup, np))
			dev_warn(np->dev, "ft: indirect block (bond) not registered\n");
		if (register_netdevice_notifier(&np->ft_nb))
			dev_warn(np->dev, "ft: netdevice notifier not registered\n");
		if (register_switchdev_notifier(&np->ft_fdb_nb))
			dev_warn(np->dev, "ft: switchdev notifier (bridge stations) not registered\n");
	}
	mutex_lock(&fnp6l_sse_lock);
	fnp6l_v6_mtu_init(np);
	if (IS_ENABLED(CONFIG_FORTINET_NP6LITE_FLOW_OFFLOAD)) {
		if (fnp6l_igr_class_init(np))
			dev_warn(np->dev, "ingress_class: not applied\n");
		fnp6l_flow_offload_init(np);
	}
	mutex_unlock(&fnp6l_sse_lock);
	return 0;
err:
	fnp6l_stop_all_queues(np);
	return ret;
}

/*
 * The ports may take their MAC address from a "mac-address" NVMEM cell (the
 * factory base in the boot flash, plus the rank of the port). Its
 * provider may come up after this driver: of_get_ethdev_address() would
 * then fail with -EPROBE_DEFER and the port get a random address, in
 * silence. Wait for the cells before anything is written, until the end of
 * boot (driver_deferred_probe_check_state()); a cell on a disabled node,
 * or still missing then, leaves its port to a random address. The device
 * tree lists the provider among the post-init providers of the ports too,
 * so that fw_devlink does not hold this probe for good if the flash fails.
 * Returns 0 or -EPROBE_DEFER.
 */
static int fnp6l_wait_mac_cells(struct fnp6l *np)
{
	struct device_node *ports, *dn, *n;
	struct of_phandle_args spec;
	struct nvmem_cell *cell;
	int idx, ret = 0;

	ports = of_get_child_by_name(np->dev->of_node, "ethernet-ports");
	for_each_available_child_of_node(ports, dn) {
		idx = of_property_match_string(dn, "nvmem-cell-names",
					       "mac-address");
		if (idx < 0)
			continue;
		if (of_parse_phandle_with_optional_args(dn, "nvmem-cells",
							"#nvmem-cell-cells",
							idx, &spec))
			continue;
		for (n = spec.np; n; n = of_get_next_parent(n))
			if (!of_device_is_available(n))
				break;
		if (n) {
			of_node_put(n);
			dev_info(np->dev, "%pOFn: MAC address cell disabled\n", dn);
			continue;
		}
		cell = of_nvmem_cell_get(dn, "mac-address");
		if (!IS_ERR(cell)) {
			nvmem_cell_put(cell);
			continue;
		}
		ret = PTR_ERR(cell);
		if (ret == -EPROBE_DEFER)
			ret = driver_deferred_probe_check_state(np->dev);
		if (ret == -EPROBE_DEFER) {
			of_node_put(dn);
			break;
		}
		dev_warn(np->dev, "%pOFn: MAC address cell unavailable: %pe\n",
			 dn, ERR_PTR(ret));
		ret = 0;
	}
	of_node_put(ports);

	return ret == -EPROBE_DEFER ?
	       dev_err_probe(np->dev, ret, "MAC address cells not ready\n") : 0;
}

static int fnp6l_probe(struct platform_device *pdev)
{
	struct device_node *mdio;
	u32 v, mdc_mask, resets;
	int ret, i, pin[2];
	struct fnp6l *np;

	np = devm_kzalloc(&pdev->dev, sizeof(*np), GFP_KERNEL);
	if (!np)
		return -ENOMEM;
	np->dev = &pdev->dev;
	spin_lock_init(&np->mdio_lock);
	spin_lock_init(&np->tx_lock);
	platform_set_drvdata(pdev, np);
	ret = fnp6l_ft_index_alloc(np);
	if (ret)
		return ret;

	/* Before anything is written: it may defer the probe */
	ret = fnp6l_wait_mac_cells(np);
	if (ret)
		return ret;

	np->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(np->base))
		return PTR_ERR(np->base);

	fnp6l_probe_dump(np);

	/* Loader's DMA into host memory: stopped before anything else */
	np->loader_ring_hi = fnp6l_rd(np, NP6L_HRXQ(0) + NP6L_Q_RING_BASE_HI);
	np->loader_qctrl = fnp6l_rd(np, NP6L_HRXQ(0) + NP6L_Q_CTRL);
	fnp6l_stop_all_queues(np);
	fnp6l_tce_init(np);
	/*
	 * Initial state of the NP tables before this driver writes any NP table
	 * (fnp6l_lif_tables) or sets its rings up, once the loader's DMA into
	 * host memory is stopped and the TCE base is safe.
	 */
	fnp6l_hw_init_tables(np);
	/*
	 * The ports start with the transmit checksum on: program the HTX L4
	 * parse entries now (the table init above leaves defaults there).
	 */
	fnp6l_htx_l4_parse_init(np);

	mdc_mask = 0;
	for (i = 0; i < 2; i++) {
		mdio = of_get_child_by_name(np->dev->of_node, i ? "mdio-switch" : "mdio");
		pin[i] = -1;
		if (mdio && !of_property_read_u32(mdio, "fortinet,mdc-pin", &v) && v < 32) {
			pin[i] = v;
			mdc_mask |= BIT(v);
		}
		of_node_put(mdio);
	}
	fnp6l_mdc_pins_init(np, mdc_mask);
	resets = 0;
	of_property_for_each_u32(np->dev->of_node, "fortinet,reset-pins", v)
		if (v < 32)
			resets |= BIT(v);
	fnp6l_release_resets(np, resets);

	if (mdc_mask) {
		fnp6l_mdio_scan(np, "mdio", pin[0]);
		fnp6l_mdio_scan(np, "mdio-switch", pin[1]);
	}

	for (i = 0; i < 2; i++) {
		struct mii_bus *bus;
		struct fnp6l_mdio *m;

		mdio = of_get_child_by_name(np->dev->of_node, i ? "mdio-switch" : "mdio");
		if (!mdio || !of_device_is_available(mdio)) {
			of_node_put(mdio);
			continue;
		}
		bus = devm_mdiobus_alloc_size(np->dev, sizeof(*m));
		if (!bus) {
			of_node_put(mdio);
			return -ENOMEM;
		}
		m = bus->priv;
		m->np = np;
		m->mdc_pin = pin[i];
		bus->name = i ? "NP6Lite MDIO (switch)" : "NP6Lite MDIO";
		bus->read = fnp6l_mdio_read;
		bus->write = fnp6l_mdio_write;
		bus->parent = np->dev;
		snprintf(bus->id, MII_BUS_ID_SIZE, "%s-mii%d", dev_name(np->dev), i);
		ret = devm_of_mdiobus_register(np->dev, bus, mdio);
		of_node_put(mdio);
		if (ret)
			return dev_err_probe(np->dev, ret, "MDIO bus %d\n", i);
		if (i)
			np->mii_sw = bus;
		else
			np->mii = bus;
	}

	return fnp6l_setup_net(pdev, np);
}

static const struct of_device_id fnp6l_of_match[] = {
	{ .compatible = "fortinet,fsoc3-np6lite" },
	{ }
};
MODULE_DEVICE_TABLE(of, fnp6l_of_match);

/*
 * No remove and no module exit: the state written at probe cannot be undone
 * without a reset of the network processor, and none is known.
 */
static struct platform_driver fnp6l_driver = {
	.probe = fnp6l_probe,
	.driver = {
		.name = DRV_NAME,
		.of_match_table = fnp6l_of_match,
		.suppress_bind_attrs = true,
	},
};
builtin_platform_driver(fnp6l_driver);

MODULE_DESCRIPTION("Fortinet NP6Lite network processor driver");
MODULE_LICENSE("GPL");
