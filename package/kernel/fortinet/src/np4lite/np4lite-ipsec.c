// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet NP4Lite network processor (FortiSOC2): IPsec ESP offload
 *
 * The NP4Lite has an IPsec engine behind its flow engine. It reads its
 * security associations (SA) from a region of system memory, one 512-byte
 * slot per SA index, which it fills itself from commands the host posts
 * on the TX ring. Received ESP whose SPI has an entry in the flow engine
 * goes through the engine and comes to the host decrypted, without its
 * outer header, marked with the index of its SA; a frame the host sends
 * with an SA index goes out encrypted and encapsulated. The engine keeps
 * the sequence numbers and the lifetime in bytes itself, and reports
 * them in messages on the RX ring. This matches the "packet" offload of
 * xfrm.
 *
 * Register layout and values established by observation, for
 * interoperability; what is still guessed or open is marked FIXME.
 */

#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/bits.h>
#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/icmp.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ioport.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/soc/fortinet/cp-hmac.h>
#include <linux/spinlock.h>
#include <linux/u64_stats_sync.h>
#include <linux/workqueue.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/neighbour.h>
#include <net/netevent.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/route.h>
#include <net/xfrm.h>

#include "np4lite.h"

/*
 * Registers of the IPsec engine, in the register window of the NP. The
 * base of the SA region goes to the flow engine too. The status (0x3cc)
 * is only read, and the queue control (0x3d4, which has the layout of the
 * EHP one, whose blocking field cannot be undone) never touched.
 */
#define NP4L_SSE_SA_BASE	0x218
#define NP4L_IPSEC_STATUS	0x3cc
/*
 * Status of the engine at reset and while it processes frames: bit 16
 * alone. FIXME: the engine stopped processing frames with
 * bits 1, 3, 7 and 8 set too, latched until a reboot, maybe errors in the
 * layout of the status of the lookaside crypto engine.
 */
#define NP4L_IPSEC_STATUS_OK	0x00010000
/*
 * Bits that come and go under load, the engine working (observed on the
 * hardware): bit 1 too under 3DES, seconds in a row
 */
#define NP4L_IPSEC_STATUS_BUSY	(BIT(16) | BIT(1) | BIT(0))
#define NP4L_IPSEC_SA_BASE	0x3d0
#define NP4L_IPSEC_CTRL0	0x3d8
#define NP4L_IPSEC_CTRL1	0x3dc
/*
 * Set up once, whatever the tunnels: both control words with their low bits
 * set, then those cleared, bit 0 of the first one (taken to be "run") excepted.
 */
#define NP4L_IPSEC_CTRL0_INIT	0x7fa000cf
#define NP4L_IPSEC_CTRL1_INIT	0x002000cf
#define NP4L_IPSEC_CTRL0_PULSE	GENMASK(3, 1)
#define NP4L_IPSEC_CTRL1_PULSE	GENMASK(3, 0)
#define NP4L_IPSEC_CTRL0_VAL	0x7fa000c1
#define NP4L_IPSEC_CTRL1_VAL	0x002000c0

#ifdef CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS
/* Read when a flow direction may be sent to the IPsec engine */
static bool ipsec_chain_udp;
module_param(ipsec_chain_udp, bool, 0644);
MODULE_PARM_DESC(ipsec_chain_udp,
		 "Send UDP flows through an offloaded IPsec tunnel to the IPsec engine from the flow engine, not TCP ones only (default off: a UDP datagram longer than the MTU of the tunnel is lost)");
#endif

/*
 * SA region: 4 MiB, one 512-byte slot per index; index 0 means "no SA". An SA takes three 64-byte sub-blocks
 * of its slot, from sub-block 0 when outbound, from 4 when inbound.
 */
#define NP4L_SA_AREA_SIZE	SZ_4M
#define NP4L_SA_SLOT		512
#define NP4L_SA_NR		(NP4L_SA_AREA_SIZE / NP4L_SA_SLOT)
#define NP4L_SA_SUB		64
#define NP4L_SA_SUB_OUT		0
#define NP4L_SA_SUB_IN		4

/*
 * SA descriptor: the first 128 bytes of a 192-byte layout, the only ones
 * sent to the engine. Multi-byte fields as the engine reads them.
 */
struct fnp4l_sa_desc {
	u8 algs;		/* NP4L_SA_ENC_* | NP4L_SA_AUTH_* */
	u8 flags;		/* NP4L_SA_F_* */
	__le16 vol_lo;		/* byte lifetime, bits 15..0 */
	__be32 spi;
	__le32 seq;		/* kept by the engine */
	__le32 vol_hi;		/* byte lifetime, bits 46..16 */
	u8 key[32];		/* cipher key, then the start of the HMAC key */
	u8 hmac[40];		/* inner then outer HMAC state */
	__be32 saddr;		/* outer IP header */
	__be32 daddr;
	__be16 natt_sport;	/* NAT-T (not offloaded) */
	__be16 natt_dport;
	u8 rsvd0;
	u8 ttl;
	u8 rsvd1[2];
	u8 hmac2[24];		/* SHA-256: end of the outer state */
} __packed;

static_assert(sizeof(struct fnp4l_sa_desc) == 2 * NP4L_SA_SUB);
static_assert(offsetof(struct fnp4l_sa_desc, hmac) == 48);
static_assert(offsetof(struct fnp4l_sa_desc, saddr) == 88);
static_assert(offsetof(struct fnp4l_sa_desc, hmac2) == 104);

/* Byte 0: cipher in bits 2..0, authentication in bits 7..3 */
#define NP4L_SA_ENC_3DES	3
#define NP4L_SA_ENC_AES128	5
#define NP4L_SA_ENC_AES192	6
#define NP4L_SA_ENC_AES256	7
#define NP4L_SA_AUTH_MD5	0x10
#define NP4L_SA_AUTH_SHA1	0x18
#define NP4L_SA_AUTH_SHA256	0xd0
#define NP4L_SA_AUTH		GENMASK(7, 3)
/*
 * Byte 1: valid; reports of the byte lifetime and of the sequence numbers
 * (bits 5..3, FIXME: which is which); bit 1, of unknown meaning, set.
 * Anti-replay (bit 6) and ESN (bit 2) stay clear.
 */
#define NP4L_SA_F_VALID		BIT(7)
#define NP4L_SA_F_DEFAULT	(BIT(5) | BIT(4) | BIT(3) | BIT(1))
/* Byte lifetime of the engine, 47 bits: the largest, xfrm keeps its own */
#define NP4L_SA_VOL_MAX		GENMASK_ULL(46, 0)
/*
 * Byte 101: TTL of the outer IPv4 header, 64 in both directions; the
 * engine rewrites it while running (0xff and 0x3f read back afterwards).
 */
#define NP4L_SA_TTL		64

/*
 * Command 0xc of the flow engine, "write SA", in one TX descriptor: four
 * 72-byte records, each with 64 bytes of descriptor for a sub-block of
 * the slot: the first sub-block with the valid bit clear, the second one,
 * the third one (zeroes), then the first one again, valid. The engine
 * writes them to the slot itself. An SA is cleared by the same command
 * with a descriptor of zeroes.
 */
#define NP4L_SA_OP		0x8c

struct fnp4l_sa_rec {
	u8 op;
	u8 len;			/* in 64-bit words */
	u8 rsvd0[2];
	u8 sub;			/* sub-block, bits 2..0 */
	u8 rsvd1;
	__le16 idx;		/* FIXME: byte order */
	u8 data[NP4L_SA_SUB];
} __packed;

struct fnp4l_sa_cmd {
	struct fnp4l_sa_rec rec[4];
};

static_assert(sizeof(struct fnp4l_sa_rec) == 72);
static_assert(sizeof(struct fnp4l_sa_cmd) % 8 == 0);

/* The engine fills the slot after reading the command */
#define NP4L_SA_WRITE_US	10000

/*
 * RX completion of a frame of the IPsec engine: type in bits 1..0 of the
 * control word, SA index in bits 15..0 of the first word, which the NP
 * rewrites. LIF 0x_F_ in bytes 0 and 1 of the host tag also marks a
 * decrypted frame, the SA index in the low bits of the LIF and in bytes 2
 * and 3.
 */
#define NP4L_RX_IPSEC		GENMASK(1, 0)
#define NP4L_RX_IPSEC_DEC	1	/* decrypted */
#define NP4L_RX_IPSEC_REPLAY_F	2	/* anti-replay: failed? */
#define NP4L_RX_IPSEC_REPLAY_P	3	/* anti-replay: passed? */
#define NP4L_RX_IPSEC_IDX	GENMASK(15, 0)
#define NP4L_HTAG_LIF_MARK	GENMASK(7, 4)

/*
 * Messages of the IPsec engine, among those of the flow engine on the RX
 * ring: header (type in byte 1, length in 64-bit words in byte 2), SA
 * index, then a 16-bit and a 32-bit value.
 *  - NP4L_MSG_SA_LIFETIME: byte lifetime left, 47 bits (the 31 low bits
 *    of the 32-bit value, then the 16-bit one), every 50 packets or so;
 *  - NP4L_MSG_SA_SEQ_EXHAUSTED: sequence number exhausted;
 *  - NP4L_MSG_SA_SEQ: sequence number (32-bit value), every 130 packets
 *    or so, usable as the packet count;
 *  - NP4L_MSG_SA_REPLAY_WIN: sequence number of the anti-replay window,
 *    inbound.
 * FIXME: the length of each type is not known, nor what
 * the byte lifetime counts (ESP or inner packets, headers).
 */
#define NP4L_MSG_SA_LIFETIME	4
#define NP4L_MSG_SA_SEQ_EXHAUSTED	5
#define NP4L_MSG_SA_SEQ		6
#define NP4L_MSG_SA_REPLAY_WIN	7
#define NP4L_MSG_VOL_HI		GENMASK(30, 0)
/*
 * FIXME: now and then, a byte lifetime message that makes
 * the count jump by far more than the traffic, then the next one is right
 * again; enough to expire an SA with a byte limit. The lifetime left only
 * goes down, and a message comes every 50 packets or so: take neither a
 * count going back nor one jumping by more than this.
 */
#define NP4L_SA_BYTES_JUMP	SZ_256M
/* Renegotiation before the sequence number runs out (soft limit) */
#define NP4L_SA_SN_SOFT		0xfffe0000

struct fnp4l_ipsec_msg {
	u8 src;
	u8 type;
	u8 len;
	u8 rsvd[5];
	__le16 idx;
	__le16 lo;
	__le32 hi;
} __packed;

/* An offloaded SA, x->xso.offload_handle */
struct fnp4l_sa {
	struct fnp4l_ipsec *ips;
	struct xfrm_state *x;
	struct net_device *ndev;	/* its port */
	struct list_head node;		/* ips->sas, under the engine lock */
	struct rcu_head rcu;
	unsigned int port;		/* port id */
	u16 idx;
	bool in;
	/* In the engine: cleared by a reset of the engine, engine lock */
	bool hw;
	bool deleted;			/* by xfrm, no longer used */
	__be32 saddr, daddr, spi;	/* outer header, SPI */
	/*
	 * Counts of the messages of the engine, written under x->lock;
	 * xfrm may read them under another lock.
	 */
	struct u64_stats_sync syncp;
	u64_stats_t bytes, packets;
	u32 sn;				/* last sequence number reported */
	/* Outbound */
	u32 seq;			/* order of creation */
	struct list_head tx_node;	/* ips->tx_sas[port], RCU, tx_lock */
	bool tx_linked;			/* tx_lock */
	__be32 nh;			/* next hop of the outer header */
	seqlock_t mac_lock;
	u8 h_dest[ETH_ALEN];		/* its MAC address, 0 if unknown */
};

/*
 * An outbound policy offloaded to a port: its frames are looked up in
 * the policies of the port, by priority, as xfrm would. Inbound and
 * forward policies have nothing to set up.
 */
struct fnp4l_pol {
	struct fnp4l_ipsec *ips;
	struct xfrm_policy *xp;
	struct list_head node;		/* ips->tx_pols[port], RCU, tx_lock */
	struct rcu_head rcu;
	unsigned int port;
	bool linked;			/* tx_lock */
};

struct fnp4l_ipsec {
	struct fnp4l *np;
	struct device *dev;
	void __iomem *base;		/* registers of the NP */
	void __iomem *sa_mem;		/* SA region, uncached */
	u32 sa_phys;
	/* SAs by index, for the RX path and the messages of the engine */
	struct fnp4l_sa __rcu **sa_by_idx;
	/* The rest under the lock of the flow engine */
	bool hw_ok;			/* engine set up since the last reset */
	bool ctrl_done;			/* control words set up (once) */
	unsigned int nr_sa;		/* SAs, set up in the engine or not */
	unsigned long *sa_used;		/* SA indexes, 0 reserved */
	unsigned int next_idx;		/* where the next index is looked for */
	struct list_head sas;
	/* Inbound SAs in the engine, per port */
	unsigned int nr_in[NP4L_NR_PORTS];
	u32 seq;			/* of the last outbound SA */
	/* Counted on the RX path */
	atomic_long_t rx_dec;		/* decrypted frames to the host */
	atomic_long_t rx_nosa;		/* of them, for no SA in service */
	atomic_long_t rx_replay;	/* anti-replay verdicts, dropped */
	atomic_long_t rx_lif_f;		/* frames with the second encoding */
	atomic_long_t rx_sel;		/* dropped: not covered by the selector */
	/* TX path: outbound policies and SAs of each port */
	spinlock_t tx_lock;		/* writers */
	struct list_head tx_pols[NP4L_NR_PORTS];
	struct list_head tx_sas[NP4L_NR_PORTS];
	unsigned int nr_pols[NP4L_NR_PORTS];
	atomic_long_t tx_enc;		/* frames sent to be encrypted */
	atomic_long_t tx_nosa;		/* dropped: no SA in service */
	atomic_long_t tx_nomac;		/* dropped: next hop not resolved */
	atomic_long_t tx_block;		/* dropped: "block" policy */
	/* Flows kept off the flow engine by the policies */
	atomic_long_t ft_refused;	/* directions refused */
	atomic_long_t sse_purged;	/* deleted on a policy or inbound SA added */
	/* Flows sent to the IPsec engine by the flow engine */
	atomic_long_t sse_chained;	/* directions chained */
	atomic_long_t sse_purged_sa;	/* deleted for their SA */
	/* Chained flows to delete, by fnp4l_ipsec_purge_work() */
	struct work_struct purge_work;
	spinlock_t purge_lock;		/* the three below */
	unsigned long *purge_sas;	/* SA indexes, purge_lock */
	unsigned long purge_ports;	/* output ports, purge_lock */
	bool purge_all;			/* purge_lock */
	/* What the work deletes, taken from the above */
	unsigned long *purge_run_sas;
	unsigned long purge_run_ports;
	bool purge_run_all;
	/* Flows of the flow table torn down once a policy is in place */
	struct xfrm_mgr km;
	struct work_struct ft_work;
	spinlock_t ft_lock;		/* ft_dev, ft_pending */
	struct net_device *ft_dev[NP4L_NR_PORTS];	/* held, ft_lock */
	netdevice_tracker ft_tracker[NP4L_NR_PORTS];
	unsigned long ft_pending;	/* ports, ft_lock */
	struct notifier_block netevent_nb;
	/* Messages of the engine, by type, then for no SA */
	atomic_long_t msg[4];
	atomic_long_t msg_nosa;
	atomic_long_t msg_bad;		/* byte lifetime not taken */
	/*
	 * The status of the engine left its normal value, SAs out of
	 * service: written by the counter work (fnp4l_ipsec_watch())
	 * alone, like the time of the last normal status (0: none).
	 */
	bool stalled;
	u8 bad;				/* odd status reads in a row */
	ktime_t status_ok_time;
};

/*
 * The SA region survives a reboot, and holds whatever the previous
 * system left there, keys included: clear it at
 * probe and whenever the engine stops.
 */
static void fnp4l_ipsec_clear(struct fnp4l_ipsec *ips)
{
	memset_io(ips->sa_mem, 0, NP4L_SA_AREA_SIZE);
	/* In memory before the engine is told about it */
	wmb();
}

static int fnp4l_ipsec_set(struct fnp4l_ipsec *ips, u32 reg, u32 val)
{
	u32 rd;

	writel(val, ips->base + reg);
	rd = readl(ips->base + reg);
	if (rd == val)
		return 0;

	dev_err(ips->dev, "IPsec engine register %#x reads %#x, wrote %#x\n",
		reg, rd, val);
	return -EIO;
}

/*
 * Set the IPsec engine up, before the flow engine runs, in that order: SA
 * region, then the control words. The control words are set once per
 * boot, and the engine is never stopped: the driver only checks them at
 * the next starts (the meaning of the bits it clears is not known). Should a
 * register not read back as expected, the ports refuse to offload SAs
 * until the next start. Under the lock of the flow engine.
 */
void fnp4l_ipsec_start(struct fnp4l_ipsec *ips)
{
	u32 ctrl0, ctrl1;
	int ret;

	if (!ips)
		return;

	WRITE_ONCE(ips->hw_ok, false);
	fnp4l_ipsec_clear(ips);

	ret = fnp4l_ipsec_set(ips, NP4L_SSE_SA_BASE, ips->sa_phys);
	if (!ret)
		ret = fnp4l_ipsec_set(ips, NP4L_IPSEC_SA_BASE, ips->sa_phys);
	if (ret)
		goto err;

	if (!ips->ctrl_done) {
		ips->ctrl_done = true;
		writel(NP4L_IPSEC_CTRL0_INIT, ips->base + NP4L_IPSEC_CTRL0);
		writel(NP4L_IPSEC_CTRL1_INIT, ips->base + NP4L_IPSEC_CTRL1);
		ctrl0 = readl(ips->base + NP4L_IPSEC_CTRL0);
		writel(ctrl0 & ~NP4L_IPSEC_CTRL0_PULSE,
		       ips->base + NP4L_IPSEC_CTRL0);
		ctrl1 = readl(ips->base + NP4L_IPSEC_CTRL1);
		writel(ctrl1 & ~NP4L_IPSEC_CTRL1_PULSE,
		       ips->base + NP4L_IPSEC_CTRL1);
	}

	ctrl0 = readl(ips->base + NP4L_IPSEC_CTRL0);
	ctrl1 = readl(ips->base + NP4L_IPSEC_CTRL1);
	if (ctrl0 != NP4L_IPSEC_CTRL0_VAL || ctrl1 != NP4L_IPSEC_CTRL1_VAL) {
		dev_err(ips->dev, "IPsec engine control %#x %#x, expected %#x %#x\n",
			ctrl0, ctrl1, NP4L_IPSEC_CTRL0_VAL, NP4L_IPSEC_CTRL1_VAL);
		goto err;
	}

	WRITE_ONCE(ips->hw_ok, true);
	dev_dbg(ips->dev, "IPsec engine set up, SA region at %#x\n",
		ips->sa_phys);
	return;

err:
	dev_err(ips->dev, "cannot set the IPsec engine up, no IPsec offload until the flow engine restarts\n");
}

/*
 * The flow engine was reset: the SPI entries of the inbound SAs are gone.
 * The IPsec engine is left running, never stopped, but its SAs are
 * cleared. Under the lock of the flow engine, or at
 * probe.
 */
void fnp4l_ipsec_reset(struct fnp4l_ipsec *ips)
{
	struct fnp4l_sa *sa;
	bool hw = false;

	if (!ips)
		return;

	/*
	 * FIXME: the SAs stay out of service until xfrm deletes
	 * them, as the flows do until their ports unbind.
	 */
	list_for_each_entry(sa, &ips->sas, node) {
		hw |= sa->hw;
		WRITE_ONCE(sa->hw, false);
	}
	memset(ips->nr_in, 0, sizeof(ips->nr_in));
	if (hw) {
		dev_warn(ips->dev, "IPsec SAs out of service until deleted\n");
		/* No frame may still carry an index when the slots go */
		synchronize_net();
		fnp4l_tx_drain(ips->np);
	}

	WRITE_ONCE(ips->hw_ok, false);
	fnp4l_ipsec_clear(ips);

	/* Every slot is clear: only the indexes of the SAs left are taken. */
	bitmap_zero(ips->sa_used, NP4L_SA_NR);
	__set_bit(0, ips->sa_used);
	list_for_each_entry(sa, &ips->sas, node)
		__set_bit(sa->idx, ips->sa_used);
}

/* Whether SAs keep the flow engine running. Under its lock. */
bool fnp4l_ipsec_busy(const struct fnp4l_ipsec *ips)
{
	return ips && ips->nr_sa;
}

/*
 * Ports whose frames the flow engine must look up, for the SPI entries of
 * their inbound SAs. Under its lock.
 */
unsigned long fnp4l_ipsec_ports(const struct fnp4l_ipsec *ips)
{
	unsigned long ports = 0;
	unsigned int id;

	for (id = 0; ips && id < NP4L_NR_PORTS; id++)
		if (ips->nr_in[id])
			ports |= BIT(id);

	return ports;
}

static void __iomem *fnp4l_sa_slot(const struct fnp4l_ipsec *ips,
				   const struct fnp4l_sa *sa)
{
	return ips->sa_mem + sa->idx * NP4L_SA_SLOT +
	       (sa->in ? NP4L_SA_SUB_IN : NP4L_SA_SUB_OUT) * NP4L_SA_SUB;
}

/*
 * Write the descriptor @desc of @sa (NULL: clear it) with command 0xc.
 * Under the lock of the flow engine; an error leaves the state of the
 * engine unknown.
 */
static int fnp4l_sa_post(struct fnp4l_ipsec *ips,
			 const struct fnp4l_sa *sa,
			 const struct fnp4l_sa_desc *desc)
{
	static const u8 order[] = { 0, 1, 2, 0 };
	struct fnp4l_sa_cmd *cmd;
	unsigned int sub, i;
	int ret;

	cmd = kzalloc_obj(*cmd);
	if (!cmd)
		return -ENOMEM;

	sub = sa->in ? NP4L_SA_SUB_IN : NP4L_SA_SUB_OUT;
	for (i = 0; i < ARRAY_SIZE(cmd->rec); i++) {
		struct fnp4l_sa_rec *rec = &cmd->rec[i];

		rec->op = NP4L_SA_OP;
		rec->len = sizeof(*rec) / 8;
		rec->sub = sub + order[i];
		rec->idx = cpu_to_le16(sa->idx);
		if (desc && order[i] < 2)
			memcpy(rec->data, (const u8 *)desc + order[i] * NP4L_SA_SUB,
			       NP4L_SA_SUB);
	}
	/* Invalid, until the last record makes it valid */
	cmd->rec[0].data[offsetof(struct fnp4l_sa_desc, flags)] &=
		~NP4L_SA_F_VALID;

	ret = fnp4l_sse_cmd(ips->np, cmd, sizeof(*cmd) / 8);
	kfree_sensitive(cmd);
	if (ret)
		dev_err(ips->dev, "IPsec SA %u: command failed: %d\n", sa->idx,
			ret);

	return ret;
}

/* Whether the slot of @sa holds it, valid, or nothing valid. */
static bool fnp4l_sa_in_slot(const struct fnp4l_ipsec *ips,
			     const struct fnp4l_sa *sa, bool valid)
{
	void __iomem *slot = fnp4l_sa_slot(ips, sa);
	u8 flags = readb(slot + offsetof(struct fnp4l_sa_desc, flags));

	if (!valid)
		return !(flags & NP4L_SA_F_VALID);

	return (flags & NP4L_SA_F_VALID) &&
	       ioread32be(slot + offsetof(struct fnp4l_sa_desc, spi)) ==
	       be32_to_cpu(sa->spi);
}

/*
 * No acknowledgment of command 0xc is known: the slot the engine writes
 * is read back, without the key bytes.
 */
static int fnp4l_sa_verify(const struct fnp4l_ipsec *ips,
			   const struct fnp4l_sa *sa, bool valid)
{
	bool ok;
	int ret;

	ret = read_poll_timeout(fnp4l_sa_in_slot, ok, ok, 10, NP4L_SA_WRITE_US,
				false, ips, sa, valid);
	if (ret)
		dev_err(ips->dev, "IPsec SA %u: slot not %s by the engine\n",
			sa->idx, valid ? "written" : "cleared");

	return ret;
}

/*
 * HMAC states, as the crypto engine takes them: inner state at 48, outer
 * one at 68 (MD5, SHA-1: 20 bytes each, MD5 zero padded); SHA-256: inner
 * state at 48, outer one at 80..87, then 104..127.
 */
static void fnp4l_sa_hmac(struct fnp4l_sa_desc *desc, u8 auth,
			  const u8 *key, unsigned int keylen)
{
	u8 kb[FCP_HMAC_KB_SIZE] = {};

	switch (auth) {
	case NP4L_SA_AUTH_MD5:
		fcp_hmac_md5_states(kb, key, keylen);
		break;
	case NP4L_SA_AUTH_SHA1:
		fcp_hmac_sha1_states(kb, key, keylen);
		break;
	default:
		fcp_hmac_sha256_states(kb, key, keylen);
		memcpy(desc->hmac, kb + FCP_HMAC_KB_IN, 32);
		memcpy(desc->hmac + 32, kb + FCP_HMAC_KB_SHA256_OUT, 8);
		memcpy(desc->hmac2, kb + FCP_HMAC_KB_SHA256_OUT + 8, 24);
		goto out;
	}
	memcpy(desc->hmac, kb + FCP_HMAC_KB_IN, 20);
	memcpy(desc->hmac + 20, kb + FCP_HMAC_KB_OUT, 20);
out:
	memzero_explicit(kb, sizeof(kb));
}

/*
 * The descriptor of @x. The raw keys
 * come first, the HMAC key cut at byte 47 (what the engine makes of them
 * is not known), the HMAC states after them. The sequence number is left
 * to the engine.
 */
static void fnp4l_sa_desc_fill(struct fnp4l_sa_desc *desc,
			       const struct xfrm_state *x, u8 algs)
{
	unsigned int klen = x->ealg->alg_key_len / 8;
	unsigned int alen = x->aalg->alg_key_len / 8;

	desc->algs = algs;
	desc->flags = NP4L_SA_F_VALID | NP4L_SA_F_DEFAULT;
	desc->vol_lo = cpu_to_le16(lower_16_bits(NP4L_SA_VOL_MAX));
	desc->vol_hi = cpu_to_le32(NP4L_SA_VOL_MAX >> 16);
	desc->spi = x->id.spi;
	memcpy(desc->key, x->ealg->alg_key, klen);
	memcpy(desc->key + klen, x->aalg->alg_key,
	       min(alen, (unsigned int)sizeof(desc->key) - klen));
	fnp4l_sa_hmac(desc, algs & NP4L_SA_AUTH, x->aalg->alg_key, alen);
	desc->saddr = x->props.saddr.a4;
	desc->daddr = x->id.daddr.a4;
	desc->ttl = NP4L_SA_TTL;
}

/*
 * What the engine offloads, as tested on hardware: IPv4 ESP tunnels,
 * without ESN, NAT-T nor anti-replay (FIXME: never tried), AES-CBC or
 * 3DES-CBC with HMAC-MD5-96, HMAC-SHA1-96 or HMAC-SHA256-128.
 * FIXME: AES-192 was never seen offloaded. The local end of the tunnel
 * must be an address of the port.
 */
static int fnp4l_sa_check(struct net_device *ndev, struct xfrm_state *x,
			  struct netlink_ext_ack *extack, u8 *algs)
{
	bool in = x->xso.dir == XFRM_DEV_OFFLOAD_IN;
	unsigned int klen, trunc;
	struct net_device *ldev;
	u8 enc, auth;
	__be32 local;

	/* Crypto offload: xfrm falls back to software on -EOPNOTSUPP. */
	if (x->xso.type != XFRM_DEV_OFFLOAD_PACKET) {
		NL_SET_ERR_MSG_MOD(extack, "only packet offload is supported");
		return -EOPNOTSUPP;
	}
	if (x->props.family != AF_INET || x->sel.family == AF_INET6) {
		NL_SET_ERR_MSG_MOD(extack, "only IPv4 in IPv4 is supported");
		return -EINVAL;
	}
	if (x->props.mode != XFRM_MODE_TUNNEL || x->id.proto != IPPROTO_ESP) {
		NL_SET_ERR_MSG_MOD(extack, "only ESP in tunnel mode is supported");
		return -EINVAL;
	}
	if (x->props.flags & XFRM_STATE_ESN) {
		NL_SET_ERR_MSG_MOD(extack, "ESN is not supported");
		return -EINVAL;
	}
	if (x->encap) {
		NL_SET_ERR_MSG_MOD(extack, "encapsulation (NAT-T) is not supported");
		return -EINVAL;
	}
	if (in && (x->props.replay_window ||
		   (x->replay_esn && x->replay_esn->replay_window))) {
		NL_SET_ERR_MSG_MOD(extack, "anti-replay is not supported, set replay-window 0");
		return -EINVAL;
	}
	if (x->aead || x->calg || !x->ealg || !x->aalg) {
		NL_SET_ERR_MSG_MOD(extack, "only a cipher with an HMAC is supported");
		return -EINVAL;
	}

	klen = x->ealg->alg_key_len;
	if (!strcmp(x->ealg->alg_name, "cbc(aes)") && klen == 128)
		enc = NP4L_SA_ENC_AES128;
	else if (!strcmp(x->ealg->alg_name, "cbc(aes)") && klen == 192)
		enc = NP4L_SA_ENC_AES192;
	else if (!strcmp(x->ealg->alg_name, "cbc(aes)") && klen == 256)
		enc = NP4L_SA_ENC_AES256;
	else if (!strcmp(x->ealg->alg_name, "cbc(des3_ede)") && klen == 192)
		enc = NP4L_SA_ENC_3DES;
	else
		enc = 0;

	trunc = x->aalg->alg_trunc_len;
	if (!strcmp(x->aalg->alg_name, "hmac(md5)") && trunc == 96)
		auth = NP4L_SA_AUTH_MD5;
	else if (!strcmp(x->aalg->alg_name, "hmac(sha1)") && trunc == 96)
		auth = NP4L_SA_AUTH_SHA1;
	else if (!strcmp(x->aalg->alg_name, "hmac(sha256)") && trunc == 128)
		auth = NP4L_SA_AUTH_SHA256;
	else
		auth = 0;

	if (!enc || !auth) {
		NL_SET_ERR_MSG_MOD(extack, "unsupported algorithm or key length");
		return -EINVAL;
	}
	*algs = enc | auth;

	if (netif_is_lag_port(ndev)) {
		NL_SET_ERR_MSG_MOD(extack, "port is in a bond");
		return -EINVAL;
	}
	if (!netif_running(ndev)) {
		NL_SET_ERR_MSG_MOD(extack, "port is down");
		return -ENETDOWN;
	}

	local = in ? x->id.daddr.a4 : x->props.saddr.a4;
	rcu_read_lock();
	ldev = __ip_dev_find(dev_net(ndev), local, false);
	rcu_read_unlock();
	if (ldev != ndev) {
		NL_SET_ERR_MSG_MOD(extack, "local tunnel address is not on the port");
		return -EINVAL;
	}

	return 0;
}

/* MAC address of the next hop of @sa, from neighbour @n */
static void fnp4l_ipsec_purge(struct fnp4l_ipsec *ips, u16 idx,
			      unsigned long ports, bool all);

static void fnp4l_sa_mac_set(struct fnp4l_sa *sa, struct neighbour *n)
{
	u8 ha[ETH_ALEN] = {};
	bool changed;

	if (READ_ONCE(n->nud_state) & NUD_VALID)
		neigh_ha_snapshot(ha, n, sa->ndev);

	write_seqlock_bh(&sa->mac_lock);
	changed = !is_zero_ether_addr(sa->h_dest) &&
		  !ether_addr_equal(sa->h_dest, ha);
	ether_addr_copy(sa->h_dest, ha);
	write_sequnlock_bh(&sa->mac_lock);

	/* The flows chained to the SA go to the former address. */
	if (changed && !sa->in)
		fnp4l_ipsec_purge(sa->ips, sa->idx, 0, false);
}

/*
 * The engine sends the MAC header the host gives it, and xfrm leaves it
 * to the device on the forwarding path (xfrm_dev_direct_output()): keep
 * the address of the next hop towards the remote end of an outbound SA,
 * and follow its neighbour entry. The route must go through the port.
 */
static int fnp4l_sa_route(struct fnp4l_sa *sa,
			  struct netlink_ext_ack *extack)
{
	struct flowi4 fl4 = {
		.daddr = sa->daddr,
		.saddr = sa->saddr,
		.flowi4_proto = IPPROTO_ESP,
	};
	struct net_device *ndev = sa->ndev;
	struct rtable *rt;

	rt = ip_route_output_key(dev_net(ndev), &fl4);
	if (IS_ERR(rt)) {
		NL_SET_ERR_MSG_MOD(extack, "no route to the remote end");
		return PTR_ERR(rt);
	}
	if (rt->dst.dev != ndev || rt->rt_type != RTN_UNICAST) {
		ip_rt_put(rt);
		NL_SET_ERR_MSG_MOD(extack, "route to the remote end not through the port");
		return -EINVAL;
	}
	sa->nh = rt_nexthop(rt, sa->daddr);
	ip_rt_put(rt);

	return 0;
}

/*
 * Once @sa is on the list the notifier walks, so that no update of the
 * neighbour goes unseen: take its address, or have it resolved.
 */
static void fnp4l_sa_neigh(struct fnp4l_sa *sa)
{
	struct neighbour *n;

	n = neigh_lookup(&arp_tbl, &sa->nh, sa->ndev);
	if (!n) {
		n = neigh_create(&arp_tbl, &sa->nh, sa->ndev);
		if (IS_ERR(n))
			return;
	}
	fnp4l_sa_mac_set(sa, n);
	if (!(READ_ONCE(n->nud_state) & NUD_VALID))
		neigh_event_send(n, NULL);
	neigh_release(n);
}

static void fnp4l_sa_tx_unlink(struct fnp4l_sa *sa)
{
	struct fnp4l_ipsec *ips = sa->ips;

	spin_lock_bh(&ips->tx_lock);
	if (sa->tx_linked)
		list_del_rcu(&sa->tx_node);
	sa->tx_linked = false;
	spin_unlock_bh(&ips->tx_lock);
}

/*
 * Have the flows of the flow table through port @id, @ndev, torn down by
 * fnp4l_ipsec_ft_work(), outside the locks of the caller. The port is
 * held until then.
 */
static void fnp4l_ipsec_ft_teardown(struct fnp4l_ipsec *ips,
				    struct net_device *ndev,
				    unsigned int id)
{
	if (!IS_ENABLED(CONFIG_NF_FLOW_TABLE))
		return;

	spin_lock_bh(&ips->ft_lock);
	if (!ips->ft_dev[id]) {
		netdev_hold(ndev, &ips->ft_tracker[id], GFP_ATOMIC);
		ips->ft_dev[id] = ndev;
	}
	__set_bit(id, &ips->ft_pending);
	spin_unlock_bh(&ips->ft_lock);

	schedule_work(&ips->ft_work);
}

/*
 * Have the flows chained to the SA of index @idx (0: none), to an SA
 * through the ports @ports, or to any SA (@all) deleted from the flow
 * engine by fnp4l_ipsec_purge_work(), under its lock. Any context.
 */
static void fnp4l_ipsec_purge(struct fnp4l_ipsec *ips, u16 idx,
			      unsigned long ports, bool all)
{
	unsigned long flags;

	if (!IS_ENABLED(CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS))
		return;

	spin_lock_irqsave(&ips->purge_lock, flags);
	if (idx)
		__set_bit(idx, ips->purge_sas);
	ips->purge_ports |= ports;
	ips->purge_all |= all;
	spin_unlock_irqrestore(&ips->purge_lock, flags);

	schedule_work(&ips->purge_work);
}

static bool fnp4l_ipsec_purge_match(void *data, u16 sa, unsigned int out)
{
	struct fnp4l_ipsec *ips = data;

	return ips->purge_run_all || test_bit(sa, ips->purge_run_sas) ||
	       (ips->purge_run_ports & BIT(out));
}

/*
 * Delete the chained flows fnp4l_ipsec_purge() asked for. Deleting a
 * flow too many costs a round through the host only: an index freed and
 * taken again by another SA in between loses the flows of that SA, which
 * the flow table offers anew. Commands of the flow engine only, nothing
 * is written to the IPsec engine.
 */
static void fnp4l_ipsec_purge_work(struct work_struct *work)
{
	struct fnp4l_ipsec *ips = container_of(work, struct fnp4l_ipsec,
					       purge_work);
	unsigned int n;

	spin_lock_irq(&ips->purge_lock);
	bitmap_copy(ips->purge_run_sas, ips->purge_sas, NP4L_SA_NR);
	bitmap_zero(ips->purge_sas, NP4L_SA_NR);
	ips->purge_run_ports = ips->purge_ports;
	ips->purge_ports = 0;
	ips->purge_run_all = ips->purge_all;
	ips->purge_all = false;
	spin_unlock_irq(&ips->purge_lock);

	fnp4l_sse_lock(ips->np);
	n = fnp4l_ft_purge_chained(ips->np, fnp4l_ipsec_purge_match, ips);
	fnp4l_sse_unlock(ips->np);

	if (n) {
		atomic_long_add(n, &ips->sse_purged_sa);
		dev_dbg(ips->dev, "%u flow directions no longer chained to the IPsec engine\n",
			n);
	}
}

static void fnp4l_ipsec_purge_stop(void *data)
{
	struct fnp4l_ipsec *ips = data;

	cancel_work_sync(&ips->purge_work);
}

static int fnp4l_xdo_state_add(struct net_device *ndev,
			       struct xfrm_state *x,
			       struct netlink_ext_ack *extack)
{
	struct fnp4l_sa_desc *desc;
	struct fnp4l_ipsec *ips;
	unsigned int id, idx, n = 0;
	struct fnp4l_sa *sa;
	struct fnp4l *np;
	u8 algs;
	int ret;

	x->xso.offload_handle = 0;
	/* Larval SA of an acquire, in atomic context: nothing to set up */
	if (x->xso.flags & XFRM_DEV_OFFLOAD_FLAG_ACQ)
		return 0;

	ips = fnp4l_port_info(ndev, &id);
	np = ips->np;
	ret = fnp4l_sa_check(ndev, x, extack, &algs);
	if (ret)
		return ret;

	sa = kzalloc_obj(*sa);
	desc = kzalloc_obj(*desc);
	if (!sa || !desc) {
		ret = -ENOMEM;
		goto out;
	}
	sa->ips = ips;
	sa->x = x;
	sa->ndev = ndev;
	sa->port = id;
	sa->in = x->xso.dir == XFRM_DEV_OFFLOAD_IN;
	sa->saddr = x->props.saddr.a4;
	sa->daddr = x->id.daddr.a4;
	sa->spi = x->id.spi;
	seqlock_init(&sa->mac_lock);
	u64_stats_init(&sa->syncp);
	if (!sa->in) {
		ret = fnp4l_sa_route(sa, extack);
		if (ret)
			goto out;
	}
	fnp4l_sa_desc_fill(desc, x, algs);

	fnp4l_sse_lock(np);
	ret = fnp4l_sse_ready(np);
	if (!ret && (!READ_ONCE(ips->hw_ok) || READ_ONCE(ips->stalled)))
		ret = -EIO;
	if (ret) {
		NL_SET_ERR_MSG_MOD(extack, "IPsec engine not available");
		goto idle;
	}
	/*
	 * Next fit: an index freed is taken again as late as possible, the
	 * engine may cache SAs (FIXME: not known).
	 */
	idx = find_next_zero_bit(ips->sa_used, NP4L_SA_NR, ips->next_idx);
	if (idx >= NP4L_SA_NR)
		idx = find_next_zero_bit(ips->sa_used, NP4L_SA_NR, 1);
	if (idx >= NP4L_SA_NR) {
		NL_SET_ERR_MSG_MOD(extack, "no free SA index");
		ret = -ENOSPC;
		goto idle;
	}
	sa->idx = idx;

	ret = fnp4l_sa_post(ips, sa, desc);
	if (ret)
		goto fail;
	ret = fnp4l_sa_verify(ips, sa, true);
	if (ret) {
		/* The slot, should the engine have written it late */
		if (fnp4l_sa_post(ips, sa, NULL))
			goto fail;
		NL_SET_ERR_MSG_MOD(extack, "IPsec engine did not take the SA");
		goto idle;
	}

	/* Inbound: the ESP of the SPI to the IPsec engine, SA first */
	if (sa->in) {
		ret = fnp4l_sse_spi(np, id, sa->saddr, sa->daddr, sa->spi,
				    idx, true);
		if (ret == -ENOENT) {
			/* Refused: make sure, as for a flow */
			ret = fnp4l_sse_spi(np, id, sa->saddr, sa->daddr,
					    sa->spi, idx, false);
			if (ret == -ENOENT)
				ret = 0;
			if (!ret)
				ret = fnp4l_sa_post(ips, sa, NULL);
			if (ret)
				goto fail;
			NL_SET_ERR_MSG_MOD(extack, "flow engine refused the SPI entry");
			ret = -ENOSPC;
			goto idle;
		}
		if (ret)
			goto fail;
	}

	__set_bit(idx, ips->sa_used);
	ips->next_idx = idx + 1;
	WRITE_ONCE(ips->nr_sa, ips->nr_sa + 1);
	sa->hw = true;
	list_add(&sa->node, &ips->sas);
	if (sa->in) {
		ips->nr_in[id]++;
		fnp4l_sse_port_sync(np, id);
		/*
		 * A flow offloaded before, that enters through the port with
		 * a tuple the SA covers, would forward frames in the clear of
		 * the tunnel traffic: delete the flows through the port, as
		 * for a policy. The SA is on the list that
		 * fnp4l_ipsec_in_protected() reads under the same lock.
		 * An update of an SA comes this way too, with a new one.
		 */
		if (IS_ENABLED(CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS))
			n = fnp4l_ft_purge(np, id);
	} else {
		sa->seq = ++ips->seq;
		spin_lock_bh(&ips->tx_lock);
		list_add_tail_rcu(&sa->tx_node, &ips->tx_sas[id]);
		sa->tx_linked = true;
		spin_unlock_bh(&ips->tx_lock);
	}
	rcu_assign_pointer(ips->sa_by_idx[idx], sa);
	fnp4l_sse_unlock(np);
	if (!sa->in)
		fnp4l_sa_neigh(sa);
	if (IS_ENABLED(CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS) && sa->in) {
		if (n) {
			atomic_long_add(n, &ips->sse_purged);
			netdev_dbg(ndev, "%u flow directions no longer offloaded: inbound IPsec SA\n",
				   n);
		}
		/*
		 * And from the flow table, for the next packet to set them
		 * up again: an inbound flow does not depend on the SA being
		 * in the database yet, the driver sees it already.
		 */
		fnp4l_ipsec_ft_teardown(ips, ndev, id);
	}

	x->xso.offload_handle = (unsigned long)sa;
	netdev_dbg(ndev, "IPsec SA %u %s, SPI %#x, %pI4 > %pI4, algorithms %#x\n",
		   idx, sa->in ? "in" : "out", be32_to_cpu(sa->spi), &sa->saddr,
		   &sa->daddr, algs);
	kfree_sensitive(desc);

	return 0;

fail:
	/* State of the engine unknown: reset, as for a failed flow */
	fnp4l_sse_error(np);
	NL_SET_ERR_MSG_MOD(extack, "IPsec engine command failed");
	ret = -EIO;
idle:
	fnp4l_sse_idle(np);
	fnp4l_sse_unlock(np);
out:
	kfree_sensitive(desc);
	kfree(sa);
	return ret;
}

/*
 * xfrm deletes the SA, under x->lock: the RX path and the messages of the
 * engine no longer find it. The engine keeps it until it is freed.
 */
static void fnp4l_xdo_state_delete(struct net_device *ndev,
				   struct xfrm_state *x)
{
	struct fnp4l_sa *sa = (struct fnp4l_sa *)x->xso.offload_handle;

	if (!sa)
		return;

	WRITE_ONCE(sa->deleted, true);
	RCU_INIT_POINTER(sa->ips->sa_by_idx[sa->idx], NULL);
	fnp4l_sa_tx_unlink(sa);
	/*
	 * Its chained flows now, rather than when the SA is freed, which
	 * waits for the last reference: the flow table keeps its route
	 * until it tears the flow down.
	 */
	if (!sa->in)
		fnp4l_ipsec_purge(sa->ips, sa->idx, 0, false);
}

/* For fnp4l_ft_purge_chained(): the flows chained to the SA of index *@data */
static bool fnp4l_sa_idx_match(void *data, u16 sa, unsigned int out)
{
	return sa == *(u16 *)data;
}

/*
 * Take the SA out of the engine: inbound, its SPI entry first, once no frame to
 * send carries its index any more. A failed command resets the flow engine.
 * Should the slot not be seen clear, its index stays taken until the engine is
 * reset.
 */
static void fnp4l_xdo_state_free(struct net_device *ndev,
				 struct xfrm_state *x)
{
	struct fnp4l_sa *sa = (struct fnp4l_sa *)x->xso.offload_handle;
	struct fnp4l_ipsec *ips;
	unsigned int n = 0;
	bool keep = false;
	struct fnp4l *np;
	int ret = 0;

	if (!sa)
		return;
	WRITE_ONCE(x->xso.offload_handle, 0);
	ips = sa->ips;
	np = ips->np;
	RCU_INIT_POINTER(ips->sa_by_idx[sa->idx], NULL);
	fnp4l_sa_tx_unlink(sa);
	/* No ndo_start_xmit() still on its way with the index */
	synchronize_net();

	fnp4l_sse_lock(np);
	/*
	 * No flow chained to the SA may outlive its slot or index: delete
	 * them first. offload_handle was cleared before the lock was taken,
	 * so that no flow is chained to it any more
	 * (fnp4l_ipsec_ft_chain()).
	 */
	if (IS_ENABLED(CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS) && !sa->in)
		n = fnp4l_ft_purge_chained(np, fnp4l_sa_idx_match,
					   &sa->idx);
	if (sa->hw) {
		/* Nor a descriptor the NP has yet to read */
		if (fnp4l_tx_drain(np))
			keep = true;
		if (sa->in) {
			ret = fnp4l_sse_spi(np, sa->port, sa->saddr,
					    sa->daddr, sa->spi, sa->idx,
					    false);
			if (ret == -ENOENT)
				ret = 0;
		}
		if (!ret)
			ret = fnp4l_sa_post(ips, sa, NULL);
		if (ret)
			fnp4l_sse_error(np);
		else if (fnp4l_sa_verify(ips, sa, false))
			keep = true;
	}
	/* Unless the engine was reset in the meantime */
	if (sa->hw && sa->in) {
		ips->nr_in[sa->port]--;
		fnp4l_sse_port_sync(np, sa->port);
	}
	sa->hw = false;
	list_del(&sa->node);
	if (keep && !ret)
		dev_warn(ips->dev, "IPsec SA %u: index kept until the engine resets\n",
			 sa->idx);
	else
		__clear_bit(sa->idx, ips->sa_used);
	WRITE_ONCE(ips->nr_sa, ips->nr_sa - 1);
	fnp4l_sse_idle(np);
	fnp4l_sse_unlock(np);
	if (n)
		atomic_long_add(n, &ips->sse_purged_sa);

	kfree_rcu(sa, rcu);
}

/*
 * Whether the frame of host tag @htag and RX completion @wb0/@ctrl comes from
 * the IPsec engine: -ENOENT if not, another error to drop it, or the
 * port of its SA, @x set to the SA with a reference. RX path.
 *
 * FIXME: which of the two encodings the engine uses, and
 * where the LIF of the second one sits, is not known. The second one is
 * only taken for a frame whose source LIF (bytes 4 and 5) is not a port,
 * which would be dropped otherwise, and whose index is that of an inbound
 * SA.
 * FIXME: the anti-replay verdicts are dropped (no SA has
 * anti-replay).
 */
int fnp4l_ipsec_rx(struct fnp4l_ipsec *ips, const u8 *htag, u32 wb0,
		   u32 ctrl, struct xfrm_state **x)
{
	unsigned int lif01 = ((htag[0] & 3) << 8) | htag[1];
	unsigned int lif45 = ((htag[4] & 3) << 8) | htag[5];
	bool second = false;
	struct fnp4l_sa *sa;
	unsigned int idx;
	int ret;

	if (!ips)
		return -ENOENT;

	switch (FIELD_GET(NP4L_RX_IPSEC, ctrl)) {
	case NP4L_RX_IPSEC_DEC:
		idx = FIELD_GET(NP4L_RX_IPSEC_IDX, wb0);
		break;
	case NP4L_RX_IPSEC_REPLAY_F:
	case NP4L_RX_IPSEC_REPLAY_P:
		atomic_long_inc(&ips->rx_replay);
		return -EINVAL;
	default:
		if ((lif01 & NP4L_HTAG_LIF_MARK) != NP4L_HTAG_LIF_MARK ||
		    lif45 < NP4L_NR_PORTS)
			return -ENOENT;
		idx = (lif01 & 0xf) << 12 | (htag[2] & 0xf) << 8 | htag[3];
		second = true;
		break;
	}

	rcu_read_lock();
	sa = idx < NP4L_SA_NR ? rcu_dereference(ips->sa_by_idx[idx]) : NULL;
	if (sa && (!sa->in || !READ_ONCE(sa->hw) || READ_ONCE(sa->deleted) ||
		   READ_ONCE(ips->stalled)))
		sa = NULL;
	if (sa && !refcount_inc_not_zero(&sa->x->refcnt))
		sa = NULL;
	if (sa) {
		*x = sa->x;
		ret = sa->port;
	} else {
		ret = second ? -ENOENT : -EINVAL;
	}
	rcu_read_unlock();

	if (second && sa)
		atomic_long_inc(&ips->rx_lif_f);
	if (!second) {
		atomic_long_inc(&ips->rx_dec);
		if (!sa) {
			atomic_long_inc(&ips->rx_nosa);
			dev_dbg_ratelimited(ips->dev, "IPsec frame for SA %u, not in service\n",
					    idx);
		}
	}

	return ret;
}

static bool fnp4l_sel_match(const struct xfrm_selector *sel,
			    const struct fnp4l_ft_tuple *t);

/*
 * Whether the selector of SA @x covers the frame @skb, network header in
 * front, as xfrm checks it for an SA it decrypts itself: in packet offload
 * the policy check of xfrm takes the frame on the word of the driver, and
 * the engine only checks the ICV. The ports are those xfrm takes; those
 * of a fragment are not known here and are not checked. A frame that is
 * not IPv4 is not covered by an IPv4 selector.
 */
static bool fnp4l_ipsec_rx_sel(struct sk_buff *skb,
			       const struct xfrm_state *x)
{
	const struct xfrm_selector *sel = &x->sel;
	struct fnp4l_ft_tuple t = {};
	const struct iphdr *iph;
	__be16 *pp, buf[2];

	if (sel->family != AF_INET)
		return true;
	if (skb->protocol != htons(ETH_P_IP) ||
	    !pskb_may_pull(skb, sizeof(*iph)))
		return false;

	iph = (const struct iphdr *)skb->data;
	if (iph->version != 4 || iph->ihl < 5)
		return false;
	t.saddr = iph->saddr;
	t.daddr = iph->daddr;
	t.proto = iph->protocol;
	if (ip_is_fragment(iph)) {
		t.sport = sel->sport;
		t.dport = sel->dport;
		return fnp4l_sel_match(sel, &t);
	}

	switch (t.proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
		pp = skb_header_pointer(skb, iph->ihl * 4, sizeof(buf), buf);
		if (pp) {
			t.sport = pp[0];
			t.dport = pp[1];
		}
		break;
	case IPPROTO_ICMP:
		pp = skb_header_pointer(skb, iph->ihl * 4, sizeof(buf), buf);
		if (pp) {
			t.sport = htons(((u8 *)pp)[0]);
			t.dport = htons(((u8 *)pp)[1]);
		}
		break;
	}

	return fnp4l_sel_match(sel, &t);
}

/*
 * Attach the SA @x to the frame, which the engine has decrypted and
 * checked: the policy check of xfrm then takes it as is. The reference
 * goes with it. False if the frame must be dropped (not covered by the
 * selector of the SA, no sec_path, or a full one, counted as xfrm does):
 * the reference is then dropped too.
 */
bool fnp4l_ipsec_rx_skb(struct fnp4l_ipsec *ips, struct sk_buff *skb,
			struct xfrm_state *x)
{
	struct xfrm_offload *xo;
	struct sec_path *sp;

	if (unlikely(!fnp4l_ipsec_rx_sel(skb, x))) {
		atomic_long_inc(&ips->rx_sel);
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINSTATEMISMATCH);
		xfrm_state_put(x);
		return false;
	}

	sp = secpath_set(skb);
	if (unlikely(!sp)) {
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINERROR);
		xfrm_state_put(x);
		return false;
	}
	if (unlikely(sp->len == XFRM_MAX_DEPTH)) {
		secpath_reset(skb);
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINBUFFERERROR);
		xfrm_state_put(x);
		return false;
	}
	sp->xvec[sp->len++] = x;
	sp->olen++;
	xo = xfrm_offload(skb);
	xo->flags = CRYPTO_DONE;
	xo->status = CRYPTO_SUCCESS;

	/*
	 * FIXME: what the engine puts in the MAC header of a
	 * decapsulated frame is not known. The frame was addressed to the
	 * port, in its ESP.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		skb->pkt_type = PACKET_HOST;

	return true;
}

/* Drop the reference of fnp4l_ipsec_rx(), if any. */
void fnp4l_ipsec_rx_put(struct xfrm_state *x)
{
	if (x)
		xfrm_state_put(x);
}

/* ethtool statistics, global, after those of the Ethernet driver */
static const char fnp4l_ipsec_stats[][ETH_GSTRING_LEN] = {
	"ipsec_sa",		/* SAs, in service or not */
	"rx_ipsec_dec",		/* decrypted frames to the host */
	"rx_ipsec_nosa",	/* of them, dropped: no SA in service */
	"rx_ipsec_replay",	/* anti-replay verdicts, dropped */
	"rx_ipsec_htag_mark",	/* decrypted frames, second encoding */
	"tx_ipsec_enc",		/* frames sent to be encrypted */
	"tx_ipsec_nosa",	/* dropped: no SA in service */
	"tx_ipsec_nomac",	/* dropped: next hop not resolved */
	"tx_ipsec_block",	/* dropped: "block" policy */
	"ipsec_msg_lifetime",	/* messages of the engine: byte lifetime */
	"ipsec_msg_seq_exhausted",	/* sequence number exhausted */
	"ipsec_msg_seq",	/* sequence number */
	"ipsec_msg_replay_win",	/* anti-replay window */
	"ipsec_msg_nosa",	/* of them, for no SA */
	"ipsec_status",		/* status register (0x3cc), as read */
	"ipsec_ctrl0",		/* first control word, as read */
	"ipsec_stalled",	/* status not normal: SAs out of service */
	"ipsec_msg_bad",	/* byte lifetime messages not taken */
	"ft_refused_ipsec",	/* flow directions refused: policy, SA */
	"flow_purged_ipsec",	/* flow directions deleted: policy, SA added */
	"rx_ipsec_sel",		/* decrypted, dropped: not covered by the selector */
#ifdef CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS
	"flow_chained_ipsec",	/* flow directions chained to an SA */
	"flow_purged_sa",	/* of them, deleted for their SA */
#endif
};

unsigned int fnp4l_ipsec_nr_stats(const struct fnp4l_ipsec *ips)
{
	return ips ? ARRAY_SIZE(fnp4l_ipsec_stats) : 0;
}

void fnp4l_ipsec_get_strings(const struct fnp4l_ipsec *ips, u8 **data)
{
	unsigned int i;

	for (i = 0; i < fnp4l_ipsec_nr_stats(ips); i++)
		ethtool_puts(data, fnp4l_ipsec_stats[i]);
}

/* Returns the number of values written to @data. */
unsigned int fnp4l_ipsec_get_stats(const struct fnp4l_ipsec *ips,
				   u64 *data)
{
	if (!ips)
		return 0;

	data[0] = READ_ONCE(ips->nr_sa);
	data[1] = atomic_long_read(&ips->rx_dec);
	data[2] = atomic_long_read(&ips->rx_nosa);
	data[3] = atomic_long_read(&ips->rx_replay);
	data[4] = atomic_long_read(&ips->rx_lif_f);
	data[5] = atomic_long_read(&ips->tx_enc);
	data[6] = atomic_long_read(&ips->tx_nosa);
	data[7] = atomic_long_read(&ips->tx_nomac);
	data[8] = atomic_long_read(&ips->tx_block);
	data[9] = atomic_long_read(&ips->msg[0]);
	data[10] = atomic_long_read(&ips->msg[1]);
	data[11] = atomic_long_read(&ips->msg[2]);
	data[12] = atomic_long_read(&ips->msg[3]);
	data[13] = atomic_long_read(&ips->msg_nosa);
	/* Read only: the driver never writes the status */
	data[14] = readl(ips->base + NP4L_IPSEC_STATUS);
	data[15] = readl(ips->base + NP4L_IPSEC_CTRL0);
	data[16] = READ_ONCE(ips->stalled);
	data[17] = atomic_long_read(&ips->msg_bad);
	data[18] = atomic_long_read(&ips->ft_refused);
	data[19] = atomic_long_read(&ips->sse_purged);
	data[20] = atomic_long_read(&ips->rx_sel);
#ifdef CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS
	data[21] = atomic_long_read(&ips->sse_chained);
	data[22] = atomic_long_read(&ips->sse_purged_sa);
#endif

	return ARRAY_SIZE(fnp4l_ipsec_stats);
}

/*
 * Outbound policies, the only ones the driver needs, as xfrm has them:
 * IPv4 selector, without interface, mark nor security context, and one
 * ESP tunnel template (or none, a bypass), with the addresses of the
 * tunnel; "block" policies too.
 */
static int fnp4l_xdo_policy_add(struct xfrm_policy *xp,
				struct netlink_ext_ack *extack)
{
	struct net_device *ndev = xp->xdo.dev;
	const struct xfrm_tmpl *t = &xp->xfrm_vec[0];
	struct fnp4l_ipsec *ips;
	struct fnp4l_pol *pol, *pos;
	unsigned int id, n;

	xp->xdo.offload_handle = 0;
	if (xp->xdo.dir != XFRM_DEV_OFFLOAD_OUT)
		return 0;

	ips = fnp4l_port_info(ndev, &id);
	if (xp->selector.family != AF_INET || xp->selector.ifindex ||
	    xp->mark.m || xp->if_id || xp->security) {
		NL_SET_ERR_MSG_MOD(extack, "unsupported policy selector, mark or context");
		return -EINVAL;
	}
	if (xp->action == XFRM_POLICY_ALLOW && xp->xfrm_nr &&
	    (xp->xfrm_nr > 1 || t->mode != XFRM_MODE_TUNNEL ||
	     t->id.proto != IPPROTO_ESP || t->encap_family != AF_INET ||
	     t->optional || !t->id.daddr.a4)) {
		NL_SET_ERR_MSG_MOD(extack, "only one IPv4 ESP tunnel template");
		return -EINVAL;
	}

	pol = kzalloc_obj(*pol);
	if (!pol)
		return -ENOMEM;
	pol->ips = ips;
	pol->xp = xp;
	pol->port = id;

	/* By priority, after those of the same priority, as xfrm does */
	spin_lock_bh(&ips->tx_lock);
	list_for_each_entry(pos, &ips->tx_pols[id], node)
		if (pos->xp->priority > xp->priority)
			break;
	list_add_tail_rcu(&pol->node, &pos->node);
	pol->linked = true;
	WRITE_ONCE(ips->nr_pols[id], ips->nr_pols[id] + 1);
	spin_unlock_bh(&ips->tx_lock);

	xp->xdo.offload_handle = (unsigned long)pol;

	/*
	 * The flow engine would forward the flows of the port past the
	 * policy, in the clear: delete them. The policy and the count of
	 * policies are written under tx_lock, before the lock of the flow
	 * engine is taken here: fnp4l_ft_replace(), which reads them
	 * under that lock, either ran before the purge, which deletes what
	 * it offloaded, or sees the policy. Called from the netlink handler
	 * of xfrm, which may sleep.
	 */
	fnp4l_sse_lock(ips->np);
	n = fnp4l_ft_purge(ips->np, id);
	fnp4l_sse_unlock(ips->np);
	if (n) {
		atomic_long_add(n, &ips->sse_purged);
		netdev_dbg(ndev, "%u flow directions no longer offloaded: IPsec policy\n",
			   n);
	}

	return 0;
}

/*
 * Whether a flow through @ports must stay off the flow engine, which
 * would forward it past the offloaded policies, in the clear or around a
 * "block" policy: any outbound policy on one of the ports refuses it,
 * whether it covers the flow or not. Under the lock of the flow engine,
 * like the purge of fnp4l_xdo_policy_add().
 */
bool fnp4l_ipsec_ft_refuse(struct fnp4l_ipsec *ips, unsigned long ports)
{
	unsigned int id;

	if (!ips)
		return false;

	for_each_set_bit(id, &ports, NP4L_NR_PORTS) {
		if (READ_ONCE(ips->nr_pols[id])) {
			atomic_long_inc(&ips->ft_refused);
			return true;
		}
	}

	return false;
}

static void fnp4l_pol_unlink(struct fnp4l_pol *pol)
{
	struct fnp4l_ipsec *ips = pol->ips;

	spin_lock_bh(&ips->tx_lock);
	if (pol->linked) {
		list_del_rcu(&pol->node);
		WRITE_ONCE(ips->nr_pols[pol->port],
			   ips->nr_pols[pol->port] - 1);
	}
	pol->linked = false;
	spin_unlock_bh(&ips->tx_lock);
}

static void fnp4l_xdo_policy_delete(struct xfrm_policy *xp)
{
	struct fnp4l_pol *pol = (struct fnp4l_pol *)xp->xdo.offload_handle;

	if (!pol)
		return;

	fnp4l_pol_unlink(pol);
	/* Flows the policy sent to the IPsec engine, among others */
	fnp4l_ipsec_purge(pol->ips, 0, BIT(pol->port), false);
}

static void fnp4l_xdo_policy_free(struct xfrm_policy *xp)
{
	struct fnp4l_pol *pol = (struct fnp4l_pol *)xp->xdo.offload_handle;

	if (!pol)
		return;

	fnp4l_pol_unlink(pol);
	xp->xdo.offload_handle = 0;
	kfree_rcu(pol, rcu);
}

/* The IPv4 part of xfrm_selector_match() */
static bool fnp4l_sel_match(const struct xfrm_selector *sel,
			    const struct fnp4l_ft_tuple *t)
{
	return addr4_match(t->daddr, sel->daddr.a4, sel->prefixlen_d) &&
	       addr4_match(t->saddr, sel->saddr.a4, sel->prefixlen_s) &&
	       !((t->dport ^ sel->dport) & sel->dport_mask) &&
	       !((t->sport ^ sel->sport) & sel->sport_mask) &&
	       (!sel->proto || t->proto == sel->proto);
}

/* What the offloaded outbound policies of a port make of a tuple */
enum fnp4l_pol_verdict {
	NP4L_POL_NONE,		/* none covers it */
	NP4L_POL_BYPASS,	/* "allow" without template: as it is */
	NP4L_POL_ESP,		/* "allow" with the ESP tunnel template */
	NP4L_POL_BLOCK,		/* "block" */
};

/*
 * The first outbound policy of port @id, by priority, whose selector
 * covers @t, as xfrm picks it among the offloaded ones, in @pol, and what
 * it makes of @t. RCU.
 */
static enum fnp4l_pol_verdict
fnp4l_pol_lookup(struct fnp4l_ipsec *ips, unsigned int id,
		 const struct fnp4l_ft_tuple *t, struct fnp4l_pol **pol)
{
	struct fnp4l_pol *pos;

	list_for_each_entry_rcu(pos, &ips->tx_pols[id], node) {
		if (!fnp4l_sel_match(&pos->xp->selector, t))
			continue;
		*pol = pos;
		if (pos->xp->action != XFRM_POLICY_ALLOW)
			return NP4L_POL_BLOCK;
		return pos->xp->xfrm_nr ? NP4L_POL_ESP : NP4L_POL_BYPASS;
	}

	return NP4L_POL_NONE;
}

/*
 * Whether the direction of a flow that enters through port @id with the
 * tuple @t may be traffic of a tunnel, once decapsulated: the flow engine
 * must not forward it as a plain flow, which would also forward frames in
 * the clear of the same tuple that enter through the port, outside the
 * tunnel. It may be when
 *  - an inbound SA of the port has a selector that covers @t, or none;
 *  - or the outbound policy of the port for the reverse tuple sends it to
 *    a tunnel or blocks it: the tunnel stays declared once its last
 *    inbound SA is gone.
 * Every inbound SA of the port counts, in service or not. A forward or
 * inbound policy is not seen, xfrm keeping them for itself. Under the lock
 * of the flow engine, which the list of SAs is written under.
 */
bool fnp4l_ipsec_in_protected(struct fnp4l_ipsec *ips, unsigned int id,
			      const struct fnp4l_ft_tuple *t)
{
	const struct fnp4l_ft_tuple rev = {
		.saddr = t->daddr,
		.daddr = t->saddr,
		.sport = t->dport,
		.dport = t->sport,
		.proto = t->proto,
	};
	enum fnp4l_pol_verdict verdict;
	struct fnp4l_pol *pol;
	struct fnp4l_sa *sa;

	if (!ips)
		return false;

	list_for_each_entry(sa, &ips->sas, node) {
		const struct xfrm_selector *sel = &sa->x->sel;

		if (!sa->in || sa->port != id)
			continue;
		/* IPv6 selectors are refused: any other covers every tuple. */
		if (sel->family != AF_INET || fnp4l_sel_match(sel, t))
			return true;
	}

	rcu_read_lock();
	verdict = fnp4l_pol_lookup(ips, id, &rev, &pol);
	rcu_read_unlock();

	return verdict == NP4L_POL_ESP || verdict == NP4L_POL_BLOCK;
}

#ifdef CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS
static struct fnp4l_sa *fnp4l_tx_sa(struct fnp4l_ipsec *ips,
				    unsigned int id,
				    const struct xfrm_tmpl *t,
				    const struct fnp4l_ft_tuple *tuple);

/*
 * What the flow engine may do with the direction of a flow that enters
 * through port @in with the tuple @key and leaves through port @out with
 * the tuple @xlat, NAT (@nat) or VLAN (@vlan) aside; @xfrm tells that the
 * flow table sends it through an SA, which it does only when an xfrm
 * policy covers it. Judged on its own, since the flow table offloads a
 * flow as soon as one direction is taken:
 *  - a direction that may be the traffic of a tunnel, once decapsulated,
 *    stays with the host, where xfrm checks it
 *    (fnp4l_ipsec_in_protected());
 *  - one that no offloaded outbound policy of @out sends to a tunnel or
 *    blocks is forwarded, as any other, unless the flow table sends it
 *    through an SA;
 *  - one that such a policy sends to a tunnel may be sent to the IPsec
 *    engine, when the flow table does so too, without NAT nor VLAN, and
 *    TCP only unless ipsec_chain_udp is set;
 *  - everything else stays with the host.
 * Refusals are counted, with the reason in @why. Under the lock of the
 * flow engine, like the purges on a policy or an inbound SA added.
 */
enum fnp4l_admit
fnp4l_ipsec_ft_admit(struct fnp4l_ipsec *ips, unsigned int in,
		     unsigned int out, const struct fnp4l_ft_tuple *key,
		     const struct fnp4l_ft_tuple *xlat, bool xfrm, bool nat,
		     bool vlan, const char **why)
{
	enum fnp4l_pol_verdict verdict;
	struct fnp4l_pol *pol;

	if (!ips) {
		*why = "xfrm route without IPsec offload";
		return xfrm ? NP4L_ADMIT_REFUSE : NP4L_ADMIT_PLAIN;
	}

	if (fnp4l_ipsec_in_protected(ips, in, key)) {
		*why = "flow of an IPsec tunnel, decapsulated";
		goto refuse;
	}

	rcu_read_lock();
	verdict = fnp4l_pol_lookup(ips, out, xlat, &pol);
	rcu_read_unlock();

	switch (verdict) {
	case NP4L_POL_NONE:
	case NP4L_POL_BYPASS:
		if (!xfrm)
			return NP4L_ADMIT_PLAIN;
		*why = "xfrm route without offloaded IPsec policy";
		break;
	case NP4L_POL_ESP:
		if (!xfrm)
			*why = "IPsec policy, flow without xfrm route";
		else if (nat || vlan)
			*why = "IPsec flow with NAT or VLAN";
		else if (key->proto != IPPROTO_TCP && !READ_ONCE(ipsec_chain_udp))
			*why = "IPsec flow not TCP";
		else
			return NP4L_ADMIT_CHAIN;
		break;
	case NP4L_POL_BLOCK:
		*why = "flow blocked by an IPsec policy";
		break;
	}

refuse:
	atomic_long_inc(&ips->ft_refused);
	return NP4L_ADMIT_REFUSE;
}

/*
 * The SA of a direction the flow table sends through the outbound SA @x,
 * to port @out with the tuple @xlat, for the flow engine to chain it to
 * the IPsec engine: its index, the MTU of the tunnel and the MAC address
 * of the next hop. Only an SA in service on @out, the one the outbound
 * policy of @out picks for @xlat, as the TX path does.
 *
 * Under the lock of the flow engine. @x lives as long as the call, its
 * offloaded state may not: fnp4l_xdo_state_free() clears
 * offload_handle before it takes the lock, deletes the flows chained to
 * the SA under it, before the slot and the index go, and frees the SA
 * after it. A handle read here is thus that of an SA still in the engine,
 * whose flows the lock holder of fnp4l_xdo_state_free() will delete.
 */
int fnp4l_ipsec_ft_chain(struct fnp4l_ipsec *ips, unsigned int out,
			 const struct xfrm_state *x,
			 const struct fnp4l_ft_tuple *xlat, u16 *idx,
			 u16 *mtu, u8 *h_dest)
{
	struct fnp4l_sa *sa, *best = NULL;
	struct fnp4l_pol *pol;
	unsigned int seq;
	u32 m;

	if (!ips || !x)
		return -EOPNOTSUPP;
	fnp4l_sse_assert_held(ips->np);

	sa = (struct fnp4l_sa *)READ_ONCE(x->xso.offload_handle);
	if (!sa || sa->ips != ips || sa->x != x || sa->in ||
	    sa->port != out || !sa->hw || READ_ONCE(sa->deleted) ||
	    READ_ONCE(ips->stalled))
		return -EOPNOTSUPP;

	rcu_read_lock();
	if (fnp4l_pol_lookup(ips, out, xlat, &pol) == NP4L_POL_ESP)
		best = fnp4l_tx_sa(ips, out, &pol->xp->xfrm_vec[0], xlat);
	rcu_read_unlock();
	if (best != sa)
		return -EOPNOTSUPP;

	do {
		seq = read_seqbegin(&sa->mac_lock);
		ether_addr_copy(h_dest, sa->h_dest);
	} while (read_seqretry(&sa->mac_lock, seq));
	if (is_zero_ether_addr(h_dest))
		return -ENOENT;

	/* As xfrm checks the packets it sends through the SA */
	m = xfrm_state_mtu((struct xfrm_state *)x, READ_ONCE(sa->ndev->mtu));
	if (m < IPV4_MIN_MTU || m > ETH_DATA_LEN)
		return -EOPNOTSUPP;

	*mtu = m;
	*idx = sa->idx;

	return 0;
}

/* A direction chained after fnp4l_ipsec_ft_chain(). Under its lock. */
void fnp4l_ipsec_ft_chained(struct fnp4l_ipsec *ips)
{
	atomic_long_inc(&ips->sse_chained);
}
#endif /* CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS */

static bool fnp4l_sa_better(const struct fnp4l_sa *sa,
			    const struct fnp4l_sa *than)
{
	u8 dying = READ_ONCE(sa->x->km.dying);
	u8 than_dying = READ_ONCE(than->x->km.dying);

	if (dying != than_dying)
		return !dying;

	return sa->seq > than->seq;
}

/*
 * The SA of template @t for the frame, among the outbound SAs of the port
 * in service, as xfrm_state_find() picks it: not dying before dying, the
 * newest first. RCU.
 */
static struct fnp4l_sa *fnp4l_tx_sa(struct fnp4l_ipsec *ips,
				    unsigned int id,
				    const struct xfrm_tmpl *t,
				    const struct fnp4l_ft_tuple *tuple)
{
	struct fnp4l_sa *sa, *best = NULL;

	if (READ_ONCE(ips->stalled))
		return NULL;

	list_for_each_entry_rcu(sa, &ips->tx_sas[id], tx_node) {
		const struct xfrm_state *x = sa->x;

		if (!READ_ONCE(sa->hw) || READ_ONCE(sa->deleted) ||
		    READ_ONCE(x->km.state) != XFRM_STATE_VALID ||
		    (t->reqid && x->props.reqid != t->reqid) ||
		    (t->id.spi && sa->spi != t->id.spi) ||
		    sa->daddr != t->id.daddr.a4 ||
		    (t->saddr.a4 && sa->saddr != t->saddr.a4) ||
		    (x->sel.family == AF_INET &&
		     !fnp4l_sel_match(&x->sel, tuple)))
			continue;
		if (!best || fnp4l_sa_better(sa, best))
			best = sa;
	}

	return best;
}

/*
 * Frame through port @id, MAC header in front: whether an outbound
 * policy of the port takes it, and with which SA. Returns 0 to send it as
 * it is, the SA index with its MAC header rewritten, or an error to drop
 * it. The packet must be IPv4 without options, as xfrm checks it.
 *
 * xfrm sends no SA with an offloaded frame (no sec_path): the frame is
 * looked up in the offloaded policies, as the hardware of other devices
 * does. Frames of a socket with a policy of its own (the bypass of an IKE
 * daemon) go as they are. FIXME: policies of higher priority
 * that are not offloaded are not seen.
 */
int fnp4l_ipsec_xmit(struct fnp4l_ipsec *ips, unsigned int id,
		     struct sk_buff *skb)
{
	struct fnp4l_ft_tuple tuple = {};
	const struct iphdr *iph;
	struct fnp4l_pol *pol;
	struct fnp4l_sa *sa;
	unsigned int seq, thoff;
	__be16 *pp, buf[2];
	struct neighbour *n;
	struct ethhdr *eth;
	int ret = 0;

	if (!ips || !READ_ONCE(ips->nr_pols[id]))
		return 0;
	if (skb->protocol != htons(ETH_P_IP) || skb_vlan_tag_present(skb) ||
	    skb_network_offset(skb) != ETH_HLEN ||
	    !pskb_may_pull(skb, ETH_HLEN + sizeof(*iph)))
		return 0;
	if (skb->sk && sk_fullsock(skb->sk) &&
	    rcu_access_pointer(skb->sk->sk_policy[XFRM_POLICY_OUT]))
		return 0;

	iph = ip_hdr(skb);
	if (iph->version != 4 || iph->ihl != 5)
		return 0;
	tuple.saddr = iph->saddr;
	tuple.daddr = iph->daddr;
	tuple.proto = iph->protocol;
	/* Where the stack left the transport header is not relied upon. */
	thoff = ETH_HLEN + sizeof(*iph);
	if (!ip_is_fragment(iph)) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_UDPLITE:
		case IPPROTO_SCTP:
		case IPPROTO_DCCP:
			pp = skb_header_pointer(skb, thoff, sizeof(buf), buf);
			if (pp) {
				tuple.sport = pp[0];
				tuple.dport = pp[1];
			}
			break;
		case IPPROTO_ICMP:
			pp = skb_header_pointer(skb, thoff, sizeof(buf), buf);
			if (pp) {
				tuple.sport = htons(((u8 *)pp)[0]);
				tuple.dport = htons(((u8 *)pp)[1]);
			}
			break;
		}
	}

	rcu_read_lock();
	switch (fnp4l_pol_lookup(ips, id, &tuple, &pol)) {
	case NP4L_POL_NONE:
	case NP4L_POL_BYPASS:
		goto out;
	case NP4L_POL_BLOCK:
		atomic_long_inc(&ips->tx_block);
		ret = -EPERM;
		goto out;
	case NP4L_POL_ESP:
		break;
	}
	sa = fnp4l_tx_sa(ips, id, &pol->xp->xfrm_vec[0], &tuple);
	if (!sa) {
		atomic_long_inc(&ips->tx_nosa);
		ret = -ENOENT;
		goto out;
	}

	if (skb_cow_head(skb, 0)) {
		ret = -ENOMEM;
		goto out;
	}
	eth = (struct ethhdr *)skb->data;
	do {
		seq = read_seqbegin(&sa->mac_lock);
		ether_addr_copy(eth->h_dest, sa->h_dest);
	} while (read_seqretry(&sa->mac_lock, seq));
	if (is_zero_ether_addr(eth->h_dest)) {
		/*
		 * Resolved without an update the notifier saw (a neighbour
		 * already valid sends none), under way, or to start again
		 */
		n = ip_neigh_gw4(sa->ndev, sa->nh);
		if (!IS_ERR(n) && (READ_ONCE(n->nud_state) & NUD_VALID)) {
			fnp4l_sa_mac_set(sa, n);
			neigh_ha_snapshot(eth->h_dest, n, sa->ndev);
		} else if (!IS_ERR(n)) {
			neigh_event_send(n, NULL);
		}
	}
	if (is_zero_ether_addr(eth->h_dest)) {
		atomic_long_inc(&ips->tx_nomac);
		ret = -EHOSTUNREACH;
		goto out;
	}
	ether_addr_copy(eth->h_source, sa->ndev->dev_addr);
	eth->h_proto = htons(ETH_P_IP);
	atomic_long_inc(&ips->tx_enc);
	ret = sa->idx;
out:
	rcu_read_unlock();

	return ret;
}

/* Follow the neighbours of the next hops of the outbound SAs. */
static int fnp4l_ipsec_netevent(struct notifier_block *nb,
				unsigned long event, void *ptr)
{
	struct fnp4l_ipsec *ips = container_of(nb, struct fnp4l_ipsec,
					       netevent_nb);
	struct neighbour *n = ptr;
	struct fnp4l_sa *sa;
	unsigned int id;

	if (event != NETEVENT_NEIGH_UPDATE || n->tbl != &arp_tbl)
		return NOTIFY_DONE;

	rcu_read_lock();
	for (id = 0; id < NP4L_NR_PORTS; id++)
		list_for_each_entry_rcu(sa, &ips->tx_sas[id], tx_node)
			if (sa->ndev == n->dev &&
			    !memcmp(n->primary_key, &sa->nh, sizeof(sa->nh)))
				fnp4l_sa_mac_set(sa, n);
	rcu_read_unlock();

	return NOTIFY_DONE;
}

static void fnp4l_ipsec_netevent_stop(void *data)
{
	struct fnp4l_ipsec *ips = data;

	unregister_netevent_notifier(&ips->netevent_nb);
}

/*
 * A message of the IPsec engine, of @len bytes: the counts of its SA,
 * and the expiry xfrm would do. False if it is none. RX path.
 */
bool fnp4l_ipsec_msg(struct fnp4l_ipsec *ips, const void *buf,
		     unsigned int len)
{
	const struct fnp4l_ipsec_msg *msg = buf;
	struct fnp4l_sa *sa;
	struct xfrm_state *x;
	bool check = false;
	unsigned int idx;
	u64 bytes, old;
	u32 sn;

	if (!ips || len < sizeof(*msg) || msg->type < NP4L_MSG_SA_LIFETIME ||
	    msg->type > NP4L_MSG_SA_REPLAY_WIN)
		return false;

	atomic_long_inc(&ips->msg[msg->type - NP4L_MSG_SA_LIFETIME]);
	idx = le16_to_cpu(msg->idx);

	rcu_read_lock();
	sa = idx < NP4L_SA_NR ? rcu_dereference(ips->sa_by_idx[idx]) : NULL;
	if (!sa || READ_ONCE(sa->deleted)) {
		atomic_long_inc(&ips->msg_nosa);
		goto out;
	}

	x = sa->x;
	spin_lock(&x->lock);
	if (x->km.state != XFRM_STATE_VALID)
		goto unlock;
	if (!x->curlft.use_time)
		x->curlft.use_time = ktime_get_real_seconds();

	switch (msg->type) {
	case NP4L_MSG_SA_LIFETIME:
		bytes = NP4L_SA_VOL_MAX -
			((u64)FIELD_GET(NP4L_MSG_VOL_HI, le32_to_cpu(msg->hi)) << 16 |
			 le16_to_cpu(msg->lo));
		old = u64_stats_read(&sa->bytes);
		if (bytes < old || bytes - old > NP4L_SA_BYTES_JUMP) {
			/*
			 * About one a second per busy SA: counted, the raw
			 * message logged once only. One line each time, on a
			 * serial console at 9600 bauds, holds the CPU long
			 * enough to cost a third of the IPsec throughput.
			 */
			atomic_long_inc(&ips->msg_bad);
			dev_warn_once(ips->dev,
				      "IPsec SA %u: byte lifetime message %*ph not taken, count %llu; the next ones are counted (ipsec_msg_bad)\n",
				      idx, min_t(int, len, 32), buf, old);
			dev_dbg_ratelimited(ips->dev,
					    "IPsec SA %u: byte lifetime message %*ph not taken, count %llu\n",
					    idx, min_t(int, len, 32), buf, old);
			break;
		}
		u64_stats_update_begin(&sa->syncp);
		u64_stats_set(&sa->bytes, bytes);
		u64_stats_update_end(&sa->syncp);
		check = true;
		break;
	case NP4L_MSG_SA_SEQ:
		sn = le32_to_cpu(msg->hi);
		u64_stats_update_begin(&sa->syncp);
		u64_stats_add(&sa->packets, sn - sa->sn);
		u64_stats_update_end(&sa->syncp);
		sa->sn = sn;
		check = true;
		if (sa->in)
			break;
		x->replay.oseq = sn;
		if (sn >= NP4L_SA_SN_SOFT && !x->km.dying) {
			x->km.dying = 1;
			km_state_expired(x, 0, 0);
		}
		break;
	case NP4L_MSG_SA_REPLAY_WIN:
		if (sa->in)
			x->replay.seq = le32_to_cpu(msg->hi);
		break;
	case NP4L_MSG_SA_SEQ_EXHAUSTED:
		/* What the timer of xfrm does with a hard expiry */
		x->km.state = XFRM_STATE_EXPIRED;
		hrtimer_start(&x->mtimer, 0, HRTIMER_MODE_REL_SOFT);
		break;
	}

	/* Lifetimes: see xfrm_state_check_expire(), which reads the counts */
	if (check && (u64_stats_read(&sa->bytes) >= x->lft.soft_byte_limit ||
		      u64_stats_read(&sa->packets) >= x->lft.soft_packet_limit))
		xfrm_state_check_expire(x);
unlock:
	spin_unlock(&x->lock);
out:
	rcu_read_unlock();

	return true;
}

/*
 * Follow the status of the engine, read only, by the counter work alone,
 * every second or so. The first time a bit other than the busy ones is
 * set, report it with the counts of the moment, @hrx_pdq_full being the drops of the host queue
 * of the flow engine (DCE 0x12), and take the SAs out of service, in the
 * driver alone: no frame goes to the engine any more, no frame of it is
 * taken for decrypted, no SA is added, and xfrm drops the frames of the
 * SAs (packet offload has no software fallback) until they are deleted.
 * The engine, its SAs and the SPI entries of the flow engine are left as
 * they are: nothing is written to the NP. The status stays as it is until
 * a reboot, and so does the driver. Only an engine set up is followed,
 * and only two odd reads in a row count: one read may catch the engine
 * being set up.
 */
void fnp4l_ipsec_watch(struct fnp4l_ipsec *ips, u64 hrx_pdq_full)
{
	u32 status, ctrl0, ms, ok_ms;
	char ok[24] = "never";
	u64 s, ok_s;
	ktime_t now;

	if (!ips || ips->stalled)
		return;

	now = ktime_get_boottime();
	status = readl(ips->base + NP4L_IPSEC_STATUS);
	if (!(status & ~NP4L_IPSEC_STATUS_BUSY) || !READ_ONCE(ips->hw_ok)) {
		ips->bad = 0;
		if (!(status & ~NP4L_IPSEC_STATUS_BUSY))
			ips->status_ok_time = now;
		return;
	}
	if (ips->bad < 2)
		ips->bad++;
	if (ips->bad < 2)
		return;

	ctrl0 = readl(ips->base + NP4L_IPSEC_CTRL0);
	WRITE_ONCE(ips->stalled, true);
	/*
	 * Where the engine sends what the flow engine chains to it is not
	 * known: have the flows handed to the host, where xfrm drops them.
	 */
	fnp4l_ipsec_purge(ips, 0, 0, true);

	s = div_u64_rem(ktime_to_ms(now), MSEC_PER_SEC, &ms);
	if (ips->status_ok_time) {
		ok_s = div_u64_rem(ktime_to_ms(ips->status_ok_time),
				   MSEC_PER_SEC, &ok_ms);
		snprintf(ok, sizeof(ok), "%llu.%03u s", ok_s, ok_ms);
	}
	dev_err(ips->dev,
		"IPsec engine status %#010x ctrl0 %#010x at %llu.%03u s (last normal at %s): rx_ipsec_dec %lu tx_ipsec_enc %lu msg lifetime %lu seq_exhausted %lu seq %lu replay_win %lu nosa %lu rx_host_queue_full %llu, SAs out of service\n",
		status, ctrl0, s, ms, ok,
		atomic_long_read(&ips->rx_dec),
		atomic_long_read(&ips->tx_enc),
		atomic_long_read(&ips->msg[0]),
		atomic_long_read(&ips->msg[1]),
		atomic_long_read(&ips->msg[2]),
		atomic_long_read(&ips->msg[3]),
		atomic_long_read(&ips->msg_nosa), hrx_pdq_full);
}

/*
 * The counts of the messages, for xfrm: under x->lock, or under the state
 * lock of xfrm (dumps), while the SA may be freed.
 */
static void fnp4l_xdo_state_update_stats(struct xfrm_state *x)
{
	struct fnp4l_sa *sa;
	u64 bytes, packets;
	unsigned int start;

	rcu_read_lock();
	sa = (struct fnp4l_sa *)READ_ONCE(x->xso.offload_handle);
	if (!sa) {
		rcu_read_unlock();
		return;
	}
	do {
		start = u64_stats_fetch_begin(&sa->syncp);
		bytes = u64_stats_read(&sa->bytes);
		packets = u64_stats_read(&sa->packets);
	} while (u64_stats_fetch_retry(&sa->syncp, start));
	rcu_read_unlock();

	x->curlft.bytes = bytes;
	x->curlft.packets = packets;
}

/*
 * Inner IPv4 only: the engine has no IPv6 encoding of its own. Nothing
 * once the engine stalled: xfrm drops the frame.
 */
static bool fnp4l_xdo_offload_ok(struct sk_buff *skb,
				 struct xfrm_state *x)
{
	struct fnp4l_sa *sa;
	bool stalled = false;

	rcu_read_lock();
	sa = (struct fnp4l_sa *)READ_ONCE(x->xso.offload_handle);
	if (sa)
		stalled = READ_ONCE(sa->ips->stalled);
	rcu_read_unlock();

	return !stalled && ip_hdr(skb)->version == 4;
}

static const struct xfrmdev_ops fnp4l_xfrmdev_ops = {
	.xdo_dev_state_add	= fnp4l_xdo_state_add,
	.xdo_dev_state_delete	= fnp4l_xdo_state_delete,
	.xdo_dev_state_free	= fnp4l_xdo_state_free,
	.xdo_dev_offload_ok	= fnp4l_xdo_offload_ok,
	.xdo_dev_state_update_stats = fnp4l_xdo_state_update_stats,
	.xdo_dev_policy_add	= fnp4l_xdo_policy_add,
	.xdo_dev_policy_delete	= fnp4l_xdo_policy_delete,
	.xdo_dev_policy_free	= fnp4l_xdo_policy_free,
};

/*
 * The flows of the flow table set up before an outbound policy stay
 * forwarded in software, the directions sent directly, without the xfrm
 * route: checked against the MTU of the port, not the one of the SA, the
 * frames too long for the SA are lost. Tear the flows through the port
 * down, as the flow table does on NETDEV_DOWN, for the next packet to set
 * them up again with the route of the policy.
 *
 * Once the policy is in the policy database, not in
 * fnp4l_xdo_policy_add(): xfrm adds the policy to the device first,
 * and a packet between the cleanup and the insertion would set the flow
 * up again without the policy. xfrm tells key managers about the
 * policies it inserted, under the RCU read lock: the notification only
 * queues this work, which calls the cleanup outside any lock of xfrm or
 * of the flow engine (the cleanup waits for the work of the flow table,
 * whose callbacks take the lock of the flow engine).
 */
static void fnp4l_ipsec_ft_work(struct work_struct *work)
{
	struct fnp4l_ipsec *ips = container_of(work, struct fnp4l_ipsec,
					       ft_work);
	struct net_device *ndev;
	unsigned int id;

	for (id = 0; id < NP4L_NR_PORTS; id++) {
		spin_lock_bh(&ips->ft_lock);
		if (!__test_and_clear_bit(id, &ips->ft_pending)) {
			spin_unlock_bh(&ips->ft_lock);
			continue;
		}
		ndev = ips->ft_dev[id];
		spin_unlock_bh(&ips->ft_lock);

		if (IS_ENABLED(CONFIG_NF_FLOW_TABLE))
			nf_flow_table_cleanup(ndev);

		/* Held until no policy is pending on the port */
		spin_lock_bh(&ips->ft_lock);
		if (!test_bit(id, &ips->ft_pending)) {
			ips->ft_dev[id] = NULL;
			netdev_put(ndev, &ips->ft_tracker[id]);
		}
		spin_unlock_bh(&ips->ft_lock);
	}
}

/* Outbound policies offloaded to a port, once inserted or updated */
static int fnp4l_km_notify_policy(struct xfrm_policy *xp, int dir,
				  const struct km_event *c)
{
	struct fnp4l_ipsec *ips;
	struct net_device *ndev;
	unsigned int id;

	if (c->event != XFRM_MSG_NEWPOLICY && c->event != XFRM_MSG_UPDPOLICY)
		return 0;

	ndev = xp->xdo.dev;
	if (!ndev || xp->xdo.type != XFRM_DEV_OFFLOAD_PACKET ||
	    xp->xdo.dir != XFRM_DEV_OFFLOAD_OUT || !xp->xdo.offload_handle ||
	    ndev->xfrmdev_ops != &fnp4l_xfrmdev_ops)
		return 0;

	ips = fnp4l_port_info(ndev, &id);
	fnp4l_ipsec_ft_teardown(ips, ndev, id);

	return 0;
}

/* Called for every key manager: none of these are the driver's */
static int fnp4l_km_acquire(struct xfrm_state *x, struct xfrm_tmpl *t,
			    struct xfrm_policy *xp)
{
	return -EOPNOTSUPP;
}

/* The error of the previous managers left as it is */
static struct xfrm_policy *fnp4l_km_compile_policy(struct sock *sk,
						   int opt, u8 *data,
						   int len, int *dir)
{
	return NULL;
}

/* Out of the lock of xfrm: waits for the work, which puts the ports */
static void fnp4l_ipsec_km_stop(void *data)
{
	struct fnp4l_ipsec *ips = data;

	xfrm_unregister_km(&ips->km);
	flush_work(&ips->ft_work);
}

/* Before the port is registered */
void fnp4l_ipsec_port_init(struct fnp4l_ipsec *ips,
			   struct net_device *ndev)
{
	if (!ips)
		return;

	ndev->xfrmdev_ops = &fnp4l_xfrmdev_ops;
	ndev->hw_features |= NETIF_F_HW_ESP;
	ndev->features |= NETIF_F_HW_ESP;
}

/*
 * The SA region must lie below 1 GiB, 4 MiB aligned, as the table
 * registers of the flow engine need.
 * FIXME: constraints of the SA base registers not known.
 */
int fnp4l_ipsec_probe(struct fnp4l *np, struct device *dev,
		      void __iomem *base, const struct resource *sa,
		      struct fnp4l_ipsec **ipsec)
{
	struct fnp4l_ipsec *ips;
	unsigned int id;
	int ret;

	if (resource_size(sa) < NP4L_SA_AREA_SIZE ||
	    !IS_ALIGNED(sa->start, SZ_4M) ||
	    sa->start + NP4L_SA_AREA_SIZE > SZ_1G) {
		dev_warn(dev, "IPsec SA region %pR unusable, no IPsec offload\n",
			 sa);
		return 0;
	}

	ips = devm_kzalloc(dev, sizeof(*ips), GFP_KERNEL);
	if (!ips)
		return -ENOMEM;
	ips->np = np;
	ips->dev = dev;
	ips->base = base;
	ips->sa_phys = sa->start;

	INIT_LIST_HEAD(&ips->sas);
	spin_lock_init(&ips->tx_lock);
	for (id = 0; id < NP4L_NR_PORTS; id++) {
		INIT_LIST_HEAD(&ips->tx_pols[id]);
		INIT_LIST_HEAD(&ips->tx_sas[id]);
	}

	ips->sa_used = devm_bitmap_zalloc(dev, NP4L_SA_NR, GFP_KERNEL);
	if (!ips->sa_used)
		return -ENOMEM;
	__set_bit(0, ips->sa_used);
	ips->next_idx = 1;

	ips->sa_by_idx = devm_kcalloc(dev, NP4L_SA_NR, sizeof(*ips->sa_by_idx),
				      GFP_KERNEL);
	if (!ips->sa_by_idx)
		return -ENOMEM;

	ips->sa_mem = devm_ioremap(dev, sa->start, NP4L_SA_AREA_SIZE);
	if (!ips->sa_mem) {
		dev_warn(dev, "cannot map %pR, no IPsec offload\n", sa);
		return 0;
	}
	fnp4l_ipsec_clear(ips);

	if (IS_ENABLED(CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS)) {
		ips->purge_sas = devm_bitmap_zalloc(dev, NP4L_SA_NR, GFP_KERNEL);
		ips->purge_run_sas = devm_bitmap_zalloc(dev, NP4L_SA_NR,
							GFP_KERNEL);
		if (!ips->purge_sas || !ips->purge_run_sas)
			return -ENOMEM;
		spin_lock_init(&ips->purge_lock);
		INIT_WORK(&ips->purge_work, fnp4l_ipsec_purge_work);
		/* After the notifier and xfrm stop scheduling it */
		ret = devm_add_action_or_reset(dev, fnp4l_ipsec_purge_stop,
					       ips);
		if (ret)
			return ret;
	}

	ips->netevent_nb.notifier_call = fnp4l_ipsec_netevent;
	ret = register_netevent_notifier(&ips->netevent_nb);
	if (ret)
		return ret;
	ret = devm_add_action_or_reset(dev, fnp4l_ipsec_netevent_stop, ips);
	if (ret)
		return ret;

	if (IS_ENABLED(CONFIG_NF_FLOW_TABLE)) {
		spin_lock_init(&ips->ft_lock);
		INIT_WORK(&ips->ft_work, fnp4l_ipsec_ft_work);
		ips->km.notify_policy = fnp4l_km_notify_policy;
		ips->km.acquire = fnp4l_km_acquire;
		ips->km.compile_policy = fnp4l_km_compile_policy;
		xfrm_register_km(&ips->km);
		ret = devm_add_action_or_reset(dev, fnp4l_ipsec_km_stop, ips);
		if (ret)
			return ret;
	}

	*ipsec = ips;
	dev_info(dev, "IPsec offload, SA region %pR\n", sa);

	return 0;
}
