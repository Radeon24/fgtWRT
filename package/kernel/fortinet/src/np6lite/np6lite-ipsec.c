// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet NP6Lite network processor (FortiSOC3): IPsec ESP offload (v1)
 *
 * The NP6Lite has an in-line IPsec engine behind its flow engine. It keeps
 * its security associations (SA) in two tables of the dedicated DDR of the
 * network processor, one index per direction (outbound at 0x76300000, 128
 * bytes an entry; inbound at 0x76500000, 192 bytes an entry), behind two
 * tunnel managers in the register window. The host writes an entry by
 * locking its cache line (command register, tunnel operation "lock"),
 * writing the entry word by word through an indirect window, then writing
 * it to the entry and unlocking the line. Received ESP whose SPI has a
 * session entry in the flow engine comes to the host decrypted and without
 * its outer header, the completion word marking it (word 0 bit 30) and
 * carrying the SA index (word 1 bits 15:0); a frame the host sends with its
 * descriptor marked (word 2 bits 31:28 = 2, word 3 bits 15:0 = index) goes
 * out encrypted and encapsulated. The engine keeps the sequence numbers and
 * the byte lifetime, and reports them in messages on the host queue. This
 * matches the "packet" offload of xfrm, as the NP4Lite of the FortiGate 60D
 * does (np4lite-ipsec.c, in production): this file transposes that driver,
 * the "Linux" logic kept, the backend (tables in DDR, register transport,
 * completion decode) replaced.
 *
 * v1 is outbound first (ipsec_outbound_only, default on): an outbound SA is
 * offloaded (the engine encrypts); an inbound SA is left to software until
 * the inbound session entry and the completion decode are confirmed on
 * hardware. Fields of the entry or of the completion word that are not yet
 * confirmed are left inactive by default and named below, with the reading
 * on hardware that lifts each one.
 *
 * Register layout and values established by observation, for
 * interoperability; what is still to confirm on hardware is marked FIXME
 * and gated by a
 * module parameter.
 */

#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/bits.h>
#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/list.h>
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
#include <net/arp.h>
#include <net/ip.h>
#include <net/neighbour.h>
#include <net/netevent.h>
#include <net/route.h>
#include <net/xfrm.h>

#include "np6lite.h"

/*
 * v1 is outbound first: an inbound SA is left to software (the engine is
 * not told about it, no completion is decoded), until the inbound session
 * entry and the completion decode are confirmed on hardware. Clearing this
 * exercises the inbound path.
 */
static bool ipsec_outbound_only = true;
module_param(ipsec_outbound_only, bool, 0644);
MODULE_PARM_DESC(ipsec_outbound_only,
		 "offload outbound SAs only, leave inbound to software (default on until the inbound path is confirmed on hardware)");

/*
 * FIXME: the anomaly (anti-replay, integrity) of a received frame is
 * not read from a bit of the completion word (word 0 bit 31 is the L4
 * checksum result, not an anomaly bit). Off by default: no verdict is read
 * from a word bit until the exception path is established on hardware.
 */
static bool ipsec_rx_anomaly_bit;
module_param(ipsec_rx_anomaly_bit, bool, 0644);
MODULE_PARM_DESC(ipsec_rx_anomaly_bit,
		 "read an IPsec anomaly from a bit of the RX completion word (default off: unconfirmed)");

/*
 * Diagnostic of the SA table write: for each write
 * or clear of an entry, log its header (bytes 0..7: algorithms, flags, low
 * half of the byte lifetime, SPI) as read in the DDR table and as read back
 * through the tunnel manager (tunnel operation 1, word 0 of the indirect
 * window). Never a byte from 8 on: the key starts at byte 16. Off by
 * default: a refused write or clear is still reported (dev_err of
 * fnp6l_sa_verify); set at run time to read the headers back.
 */
static bool ipsec_sa_diag;
module_param(ipsec_sa_diag, bool, 0644);
MODULE_PARM_DESC(ipsec_sa_diag,
		 "log the header (bytes 0..7, never the key) of each SA entry written, from the DDR table and from the tunnel manager (default off)");

/* ---------------------------------------------------- tunnel-table tables */

/*
 * SA tables in the dedicated DDR of the network processor, told to the
 * tunnel managers by their table-information register. The whole DDR region
 * (0x76000000, 160 MiB) is already owned by the core (fnp6l_sse_init); the
 * SA tables lie within it and are only mapped here, not requested again.
 * Index 0 means "no SA" (SA pointer 0 in the host descriptor is "no IPsec");
 * 0x4000..0xffff are out of the count the engine is given (0x4000).
 */
#define NP6L_SA_IB_BASE		0x76500000U
#define NP6L_SA_IB_SIZE		SZ_4M
#define NP6L_SA_IB_STRIDE	192
#define NP6L_SA_OB_BASE		0x76300000U
#define NP6L_SA_OB_SIZE		SZ_2M
#define NP6L_SA_OB_STRIDE	128
#define NP6L_SA_NR		0x4000		/* indices, 0 reserved (engine count) */

/*
 * SA descriptor: the first 128 bytes, the same layout as the NP4Lite
 * (identical for the first 128 bytes), the only ones an
 * outbound entry needs; an inbound entry is 192 bytes, the last 64 the
 * anti-replay window (left zero in v1, ipsec_replay off). Multi-byte fields
 * as the engine reads them. The key bytes are never logged.
 */
struct fnp6l_sa_desc {
	u8 algs;		/* NP6L_SA_ENC_* | NP6L_SA_AUTH_* (byte 0) */
	u8 flags;		/* NP6L_SA_F_* (byte 1) */
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
	u8 action;		/* byte 100: 2 outbound */
	u8 ttl;			/* byte 101 */
	__le16 esn47_32;	/* bytes 102-103: ESN high half (0, ESN not offloaded) */
	u8 hmac2[24];		/* SHA-256: end of the outer state */
} __packed;

static_assert(sizeof(struct fnp6l_sa_desc) == NP6L_SA_OB_STRIDE);
static_assert(offsetof(struct fnp6l_sa_desc, hmac) == 48);
static_assert(offsetof(struct fnp6l_sa_desc, saddr) == 88);
static_assert(offsetof(struct fnp6l_sa_desc, action) == 100);
static_assert(offsetof(struct fnp6l_sa_desc, hmac2) == 104);

/* Byte 0: cipher in bits 2..0, authentication in bits 7..3 (as the NP4Lite) */
#define NP6L_SA_ENC_3DES	3
#define NP6L_SA_ENC_AES128	5
#define NP6L_SA_ENC_AES192	6
#define NP6L_SA_ENC_AES256	7
#define NP6L_SA_AUTH_MD5	0x10
#define NP6L_SA_AUTH_SHA1	0x18
#define NP6L_SA_AUTH_SHA256	0xd0
#define NP6L_SA_AUTH		GENMASK(7, 3)
/*
 * Byte 1: valid (bit 7); the reports of the byte lifetime and of the
 * sequence numbers (bits 5..3), bit 1 set. Anti-replay (bit 6) and ESN
 * (bit 2) stay clear. FIXME (ipsec_cmd_probe): the exact meaning of bits
 * 5..3/1 is to be confirmed on hardware, one parameter at a time.
 */
#define NP6L_SA_F_VALID		BIT(7)
#define NP6L_SA_F_DEFAULT	(BIT(5) | BIT(4) | BIT(3) | BIT(1))
#define NP6L_SA_VOL_MAX		GENMASK_ULL(46, 0)
#define NP6L_SA_TTL		64
#define NP6L_SA_ACTION_OUT	2	/* byte 100 outbound */

/* -------------------------------------------------- tunnel-manager registers */

/*
 * Each tunnel manager has a register block in the NP window: inbound at
 * 0x6800, outbound at 0x6880. The host locks a cache line (command
 * register, tunnel operation 2), writes the entry word by word through the
 * indirect table access window (low/high data words, then the control word
 * with the word index and the write bit), writes the line to the entry
 * (tunnel operation 0) and unlocks it (tunnel operation 3). The engine
 * keeps the line in its cache (16 lines); when it writes it back to the
 * DDR table is not established, so an entry is read back through the
 * manager (tunnel operation 1), never from the DDR table.
 */
#define NP6L_TUN_IB_BASE	0x6800
#define NP6L_TUN_OB_BASE	0x6880
#define NP6L_TUN_QWA_CTRL	0x00	/* idx[29:0], write bit 30, busy bit 31 */
#define NP6L_TUN_DATAL		0x08
#define NP6L_TUN_DATAH		0x10
#define NP6L_TUN_DATAX		0x18
#define NP6L_TUN_TUNINFO	0x30	/* table size[4:0] (/8 words), table base[31:8] */
#define NP6L_TUN_CMD		0x38	/* entry index[15:0], operation[30:28], busy bit 31 */
#define NP6L_TUN_QWA_WRITE	BIT(30)
#define NP6L_TUN_QWA_BUSY	BIT(31)
#define NP6L_TUN_CMD_BUSY	BIT(31)
#define NP6L_TUN_OP		GENMASK(30, 28)
#define NP6L_TUN_OP_READ	1
#define NP6L_TUN_OP_LOCK	2
#define NP6L_TUN_OP_WRITE	0
#define NP6L_TUN_OP_UNLOCK	3
/* control word 1 of the IPsec block: engine enables, set once at init (0x102) */
#define NP6L_IPSEC_CTRL1	0x6A40
#define NP6L_IPSEC_CTRL1_INIT	0x00000102
#define NP6L_TUN_CMD_US		2000	/* a command clears in a few us */
#define NP6L_TUN_QWA_US		2000

/*
 * RX completion of a decrypted frame (retained reading): word 0 bit 30 =
 * processed bit, set by the IPsec engine; the SA index is word 1 bits 15:0
 * (SA pointer). Word 0 bit 31 is
 * the L4 checksum result (NP6L_RXW0_L4_CSUM_OK in the core), never an
 * anomaly bit. The anomaly (anti-replay, integrity) is not read from a word
 * bit in v1 (ipsec_rx_anomaly_bit).
 */
#define NP6L_RXW0_IPSEC_DONE	BIT(30)
#define NP6L_RXW1_SA_IDX	GENMASK(15, 0)

/*
 * Host transmit marking: word 2 bits 31:28 = 2 and word 3 bits 15:0 =
 * SA index make the engine encrypt and encapsulate a frame the host sends
 * (the core applies it to the descriptor). Here only the engine needs the
 * MAC header of the next hop in front.
 */

/*
 * Messages of the IPsec engine, among those of the flow engine on the host
 * queue: header (type in byte 1, length in 64-bit words in byte 2), SA
 * index at bytes 8-9, then a 16-bit and a 32-bit value at bytes 12-15.
 * Types 4/8 byte lifetime, 5/6/7 sequence. FIXME: the length of each type
 * and what the byte lifetime counts are to be confirmed on hardware.
 */
#define NP6L_MSG_SA_LIFETIME	4
#define NP6L_MSG_SA_SEQ_EXHAUSTED	5
#define NP6L_MSG_SA_SEQ		6
#define NP6L_MSG_SA_REPLAY_WIN	7
#define NP6L_MSG_SA_LIFETIME2	8
#define NP6L_MSG_VOL_HI		GENMASK(30, 0)
#define NP6L_SA_BYTES_JUMP	SZ_256M
#define NP6L_SA_SN_SOFT		0xfffe0000

struct fnp6l_ipsec_msg {
	u8 src;
	u8 type;
	u8 len;
	u8 rsvd[5];
	__le16 idx;
	__le16 lo;
	__le32 hi;
} __packed;

/* An offloaded SA, x->xso.offload_handle */
struct fnp6l_sa {
	struct fnp6l_ipsec *ips;
	struct xfrm_state *x;
	struct net_device *ndev;	/* its port */
	struct list_head node;		/* ips->sas, under the flow-engine lock */
	struct rcu_head rcu;
	unsigned int lif;		/* port LIF */
	u16 idx;
	bool in;
	bool hw;			/* in the engine */
	bool deleted;			/* by xfrm, no longer used */
	__be32 saddr, daddr, spi;
	struct u64_stats_sync syncp;
	u64_stats_t bytes, packets;
	u32 sn;				/* last sequence number reported */
	/* Outbound */
	u32 seq;			/* order of creation */
	struct list_head tx_node;	/* ips->tx_sas[lif], RCU, tx_lock */
	bool tx_linked;			/* tx_lock */
	__be32 nh;			/* next hop of the outer header */
	seqlock_t mac_lock;
	u8 h_dest[ETH_ALEN];
};

struct fnp6l_pol {
	struct fnp6l_ipsec *ips;
	struct xfrm_policy *xp;
	struct list_head node;		/* ips->tx_pols[lif], RCU, tx_lock */
	struct rcu_head rcu;
	unsigned int lif;
	bool linked;			/* tx_lock */
};

struct fnp6l_ipsec {
	struct fnp6l *np;
	struct device *dev;
	void __iomem *base;		/* registers of the NP */
	void *ib_mem;			/* inbound SA table (DDR), write-combining */
	void *ob_mem;			/* outbound SA table (DDR) */
	struct fnp6l_sa __rcu **sa_by_idx;
	/* The rest under the flow-engine lock */
	bool hw_ok;			/* engine set up since the last reset */
	bool ctrl_done;			/* ctrl1 set up (once) */
	unsigned int nr_sa;
	unsigned long *sa_used;		/* indexes, 0 reserved */
	unsigned int next_idx;
	struct list_head sas;
	unsigned int nr_in[NP6L_MAX_LIF];
	u32 seq;
	/* RX path */
	atomic_long_t rx_dec, rx_nosa, rx_anomaly;
	/* TX path: outbound policies and SAs per LIF */
	spinlock_t tx_lock;
	struct list_head tx_pols[NP6L_MAX_LIF];
	struct list_head tx_sas[NP6L_MAX_LIF];
	unsigned int nr_pols[NP6L_MAX_LIF];
	atomic_long_t tx_enc, tx_nosa, tx_nomac, tx_block, tx_opts;
	/* Flows kept off the engine by the policies */
	atomic_long_t ft_refused, ft_purged;
	/* Messages, by type, then for no SA */
	atomic_long_t msg[5];
	atomic_long_t msg_nosa, msg_bad;
	struct xfrm_mgr km;
	struct notifier_block netevent_nb;
	bool stalled;
};

/* --------------------------------------------------------- table transport */

static void __iomem *fnp6l_tun_reg(struct fnp6l_ipsec *ips, bool in,
				   unsigned int off)
{
	return ips->base + (in ? NP6L_TUN_IB_BASE : NP6L_TUN_OB_BASE) + off;
}

static int fnp6l_tun_wait(void __iomem *reg, u32 busy)
{
	u32 v;

	return readl_poll_timeout_atomic(reg, v, !(v & busy), 1, NP6L_TUN_CMD_US);
}

static int fnp6l_tun_cmd(struct fnp6l_ipsec *ips, bool in, u16 tunid, u32 op)
{
	void __iomem *cmd = fnp6l_tun_reg(ips, in, NP6L_TUN_CMD);
	int ret = fnp6l_tun_wait(cmd, NP6L_TUN_CMD_BUSY);

	if (ret)
		return ret;
	writel(tunid | FIELD_PREP(NP6L_TUN_OP, op), cmd);
	return fnp6l_tun_wait(cmd, NP6L_TUN_CMD_BUSY);
}

/*
 * Write the descriptor @buf of @len bytes (a multiple of 8) at index
 * @tunid: lock the line, write every 64-bit word through the indirect
 * window, write the line to the entry, unlock it. Under the flow-engine
 * lock. The key bytes are never logged. @buf NULL clears the entry.
 */
static int fnp6l_tun_write(struct fnp6l_ipsec *ips, bool in, u16 tunid,
			   const void *buf, unsigned int len)
{
	void __iomem *ctrl = fnp6l_tun_reg(ips, in, NP6L_TUN_QWA_CTRL);
	void __iomem *datal = fnp6l_tun_reg(ips, in, NP6L_TUN_DATAL);
	void __iomem *datah = fnp6l_tun_reg(ips, in, NP6L_TUN_DATAH);
	void __iomem *datax = fnp6l_tun_reg(ips, in, NP6L_TUN_DATAX);
	const u8 *p = buf;
	unsigned int i;
	int ret;

	ret = fnp6l_tun_cmd(ips, in, tunid, NP6L_TUN_OP_LOCK);
	if (ret)
		return ret;
	for (i = 0; i < len / 8; i++) {
		writel(p ? get_unaligned_le32(p + 8 * i) : 0, datal);
		writel(p ? get_unaligned_le32(p + 8 * i + 4) : 0, datah);
		writel(0, datax);
		writel(i | NP6L_TUN_QWA_WRITE, ctrl);
		ret = fnp6l_tun_wait(ctrl, NP6L_TUN_QWA_BUSY);
		if (ret)
			goto unlock;
	}
	ret = fnp6l_tun_cmd(ips, in, tunid, NP6L_TUN_OP_WRITE);
unlock:
	/* unlock whatever happened: a locked line never freed stalls the cache */
	if (fnp6l_tun_cmd(ips, in, tunid, NP6L_TUN_OP_UNLOCK) && !ret)
		ret = -ETIMEDOUT;
	if (ret)
		dev_err(ips->dev, "IPsec %s SA %u: table write failed: %d\n",
			in ? "in" : "out", tunid, ret);
	return ret;
}

static void __iomem *fnp6l_sa_slot(struct fnp6l_ipsec *ips, bool in, u16 idx)
{
	return in ? ips->ib_mem + (size_t)idx * NP6L_SA_IB_STRIDE :
		    ips->ob_mem + (size_t)idx * NP6L_SA_OB_STRIDE;
}

/* Bytes of the entry header: no key byte (the key starts at byte 16) */
#define NP6L_SA_HDR_LEN		8
static_assert(offsetof(struct fnp6l_sa_desc, spi) + 4 == NP6L_SA_HDR_LEN);
static_assert(offsetof(struct fnp6l_sa_desc, key) >= NP6L_SA_HDR_LEN);

/*
 * Read word 0 of entry @tunid (the header, bytes 0..7) back through the
 * tunnel manager, as __np6lite_tunmgr_read does: tunnel operation 1 loads
 * the entry into the indirect window, then the window word 0 is read
 * (control word = index 0, write bit clear, as the core reads its indirect
 * tables). Only word 0 is ever read. Under the flow-engine lock.
 */
static int fnp6l_tun_read_hdr(struct fnp6l_ipsec *ips, bool in, u16 tunid,
			      u8 *hdr)
{
	void __iomem *ctrl = fnp6l_tun_reg(ips, in, NP6L_TUN_QWA_CTRL);
	int ret;

	ret = fnp6l_tun_cmd(ips, in, tunid, NP6L_TUN_OP_READ);
	if (ret)
		return ret;
	writel(0, ctrl);
	ret = fnp6l_tun_wait(ctrl, NP6L_TUN_QWA_BUSY);
	if (ret)
		return ret;
	put_unaligned_le32(readl(fnp6l_tun_reg(ips, in, NP6L_TUN_DATAL)), hdr);
	put_unaligned_le32(readl(fnp6l_tun_reg(ips, in, NP6L_TUN_DATAH)), hdr + 4);
	return 0;
}

/* The header of entry @idx as the DDR table holds it (never the key) */
static void fnp6l_sa_ddr_hdr(struct fnp6l_ipsec *ips, bool in, u16 idx,
			     u8 *hdr)
{
	void __iomem *slot = fnp6l_sa_slot(ips, in, idx);
	unsigned int i;

	for (i = 0; i < NP6L_SA_HDR_LEN; i++)
		hdr[i] = readb(slot + i);
}

/*
 * Test image (ipsec_sa_diag): log the header of entry @idx from the DDR
 * table and from the tunnel manager, with the command word, @what saying
 * when. Under the flow-engine lock.
 */
static void fnp6l_sa_diag(struct fnp6l_ipsec *ips, bool in, u16 idx,
			  const char *what)
{
	u8 ddr[NP6L_SA_HDR_LEN], reg[NP6L_SA_HDR_LEN];
	int ret;

	if (!READ_ONCE(ipsec_sa_diag))
		return;
	fnp6l_sa_ddr_hdr(ips, in, idx, ddr);
	ret = fnp6l_tun_read_hdr(ips, in, idx, reg);
	if (ret)
		dev_info(ips->dev,
			 "IPsec %s SA %u diag %s: ddr %*phN, tunop 1 failed %d, cmd %08x\n",
			 in ? "in" : "out", idx, what, NP6L_SA_HDR_LEN, ddr, ret,
			 readl(fnp6l_tun_reg(ips, in, NP6L_TUN_CMD)));
	else
		dev_info(ips->dev,
			 "IPsec %s SA %u diag %s: ddr %*phN, tunop 1 %*phN, cmd %08x\n",
			 in ? "in" : "out", idx, what, NP6L_SA_HDR_LEN, ddr,
			 NP6L_SA_HDR_LEN, reg,
			 readl(fnp6l_tun_reg(ips, in, NP6L_TUN_CMD)));
}

/*
 * Whether the entry holds what was written: the valid flag and the SPI
 * (never the key). The tunnel manager is a cache of 16 lines in front of
 * the DDR table; nothing shows that it writes a line back to the DDR on
 * unlock (eviction may be the only write-back), so the DDR table can be
 * stale: this driver reads an entry back through the manager (tunnel
 * operation 1) by default; ipsec_verify_reg off reads the DDR table instead
 * (the v1 behaviour, refused on hardware).
 */
static bool ipsec_verify_reg = true;
module_param(ipsec_verify_reg, bool, 0644);
MODULE_PARM_DESC(ipsec_verify_reg,
		 "check an SA entry written through the tunnel manager (tunnel operation 1, header only); off: from the DDR table (v1)");

static bool fnp6l_sa_in_slot(struct fnp6l_ipsec *ips, bool in, u16 idx,
			     __be32 spi, bool valid)
{
	u8 hdr[NP6L_SA_HDR_LEN];
	u8 flags;

	if (READ_ONCE(ipsec_verify_reg)) {
		/* a manager that does not answer: not taken, logged by the caller */
		if (fnp6l_tun_read_hdr(ips, in, idx, hdr))
			return false;
	} else {
		fnp6l_sa_ddr_hdr(ips, in, idx, hdr);
	}
	flags = hdr[offsetof(struct fnp6l_sa_desc, flags)];
	if (!valid)
		return !(flags & NP6L_SA_F_VALID);
	return (flags & NP6L_SA_F_VALID) &&
	       !memcmp(hdr + offsetof(struct fnp6l_sa_desc, spi), &spi,
		       sizeof(spi));
}

static int fnp6l_sa_verify(struct fnp6l_ipsec *ips, bool in, u16 idx,
			   __be32 spi, bool valid)
{
	bool ok;
	int ret;

	ret = read_poll_timeout(fnp6l_sa_in_slot, ok, ok, 100, 10000, false,
				ips, in, idx, spi, valid);
	/* before the caller clears a refused entry: a reading after it is void */
	fnp6l_sa_diag(ips, in, idx, valid ? (ret ? "write refused" : "write")
					  : (ret ? "clear refused" : "clear"));
	if (ret)
		dev_err(ips->dev, "IPsec %s SA %u: entry not %s by the engine (%s)\n",
			in ? "in" : "out", idx, valid ? "written" : "cleared",
			READ_ONCE(ipsec_verify_reg) ? "tunop 1" : "DDR table");
	return ret;
}

/* Clear both tables whole (keys left by a previous system): under the lock */
static void fnp6l_ipsec_clear(struct fnp6l_ipsec *ips)
{
	memset(ips->ib_mem, 0, NP6L_SA_IB_SIZE);
	memset(ips->ob_mem, 0, NP6L_SA_OB_SIZE);
	wmb();
}

/* --------------------------------------------------- engine init and reset */

/*
 * Set the IPsec block up: the tunnel info of both managers (base and size
 * of each table) and the control word, once per boot. The tables are
 * cleared (keys left by a previous system). Under the flow-engine lock.
 */
void fnp6l_ipsec_start(struct fnp6l_ipsec *ips)
{
	u32 ib, ob;

	if (!ips)
		return;
	WRITE_ONCE(ips->hw_ok, false);
	fnp6l_ipsec_clear(ips);

	ib = NP6L_SA_IB_BASE | (NP6L_SA_IB_STRIDE >> 3);
	ob = NP6L_SA_OB_BASE | (NP6L_SA_OB_STRIDE >> 3);
	writel(ib, fnp6l_tun_reg(ips, true, NP6L_TUN_TUNINFO));
	writel(ob, fnp6l_tun_reg(ips, false, NP6L_TUN_TUNINFO));
	if (readl(fnp6l_tun_reg(ips, true, NP6L_TUN_TUNINFO)) != ib ||
	    readl(fnp6l_tun_reg(ips, false, NP6L_TUN_TUNINFO)) != ob) {
		dev_err(ips->dev, "IPsec tuninfo not set, no IPsec offload\n");
		return;
	}
	if (!ips->ctrl_done) {
		ips->ctrl_done = true;
		writel(NP6L_IPSEC_CTRL1_INIT, ips->base + NP6L_IPSEC_CTRL1);
	}
	if (readl(ips->base + NP6L_IPSEC_CTRL1) != NP6L_IPSEC_CTRL1_INIT) {
		dev_err(ips->dev, "IPsec ctrl1 %#x, expected %#x\n",
			readl(ips->base + NP6L_IPSEC_CTRL1), NP6L_IPSEC_CTRL1_INIT);
		return;
	}
	WRITE_ONCE(ips->hw_ok, true);
	dev_dbg(ips->dev, "IPsec engine set up (IB %#x OB %#x)\n", ib, ob);
}

/* The flow engine was reset: SPI entries gone, SAs out of service */
void fnp6l_ipsec_reset(struct fnp6l_ipsec *ips)
{
	struct fnp6l_sa *sa;
	bool hw = false;

	if (!ips)
		return;
	list_for_each_entry(sa, &ips->sas, node) {
		hw |= sa->hw;
		WRITE_ONCE(sa->hw, false);
	}
	memset(ips->nr_in, 0, sizeof(ips->nr_in));
	if (hw) {
		dev_warn(ips->dev, "IPsec SAs out of service until deleted\n");
		synchronize_net();
		fnp6l_tx_drain(ips->np);
	}
	WRITE_ONCE(ips->hw_ok, false);
	fnp6l_ipsec_clear(ips);
	bitmap_zero(ips->sa_used, NP6L_SA_NR);
	__set_bit(0, ips->sa_used);
	list_for_each_entry(sa, &ips->sas, node)
		__set_bit(sa->idx, ips->sa_used);
}

/* -------------------------------------------------------- SA descriptor */

/*
 * HMAC states, as the engine takes them (as the NP4Lite and the CP7): inner
 * at 48, outer at 68 (MD5, SHA-1), SHA-256 inner at 48, outer at 80..87
 * then 104..127.
 */
static void fnp6l_sa_hmac(struct fnp6l_sa_desc *desc, u8 auth, const u8 *key,
			  unsigned int keylen)
{
	u8 kb[FCP_HMAC_KB_SIZE] = {};

	switch (auth) {
	case NP6L_SA_AUTH_MD5:
		fcp_hmac_md5_states(kb, key, keylen);
		break;
	case NP6L_SA_AUTH_SHA1:
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

static void fnp6l_sa_desc_fill(struct fnp6l_sa_desc *desc,
			       const struct xfrm_state *x, u8 algs, bool in)
{
	unsigned int klen = x->ealg->alg_key_len / 8;
	unsigned int alen = x->aalg->alg_key_len / 8;

	desc->algs = algs;
	desc->flags = NP6L_SA_F_VALID | NP6L_SA_F_DEFAULT;
	desc->vol_lo = cpu_to_le16(lower_16_bits(NP6L_SA_VOL_MAX));
	desc->vol_hi = cpu_to_le32(NP6L_SA_VOL_MAX >> 16);
	desc->spi = x->id.spi;
	memcpy(desc->key, x->ealg->alg_key, klen);
	memcpy(desc->key + klen, x->aalg->alg_key,
	       min(alen, (unsigned int)sizeof(desc->key) - klen));
	fnp6l_sa_hmac(desc, algs & NP6L_SA_AUTH, x->aalg->alg_key, alen);
	desc->saddr = x->props.saddr.a4;
	desc->daddr = x->id.daddr.a4;
	/* byte 100: 2 outbound, 0 inbound */
	desc->action = in ? 0 : NP6L_SA_ACTION_OUT;
	desc->ttl = NP6L_SA_TTL;
}

/*
 * What the engine offloads, as the NP4Lite: IPv4 ESP tunnels, without ESN,
 * NAT-T nor anti-replay, AES-CBC or 3DES-CBC with HMAC-MD5-96, HMAC-SHA1-96
 * or HMAC-SHA256-128 (GCM and SHA-384/512 only on the lookaside engine, not
 * here). The local end of the tunnel must be an address of the port.
 */
static int fnp6l_sa_check(struct net_device *ndev, struct xfrm_state *x,
			  struct netlink_ext_ack *extack, u8 *algs)
{
	bool in = x->xso.dir == XFRM_DEV_OFFLOAD_IN;
	unsigned int klen, trunc;
	struct net_device *ldev;
	u8 enc, auth;
	__be32 local;

	if (x->xso.type != XFRM_DEV_OFFLOAD_PACKET) {
		NL_SET_ERR_MSG_MOD(extack, "only packet offload is supported");
		return -EOPNOTSUPP;
	}
	if (in && READ_ONCE(ipsec_outbound_only)) {
		NL_SET_ERR_MSG_MOD(extack, "inbound offload off (ipsec_outbound_only), left to software");
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
		enc = NP6L_SA_ENC_AES128;
	else if (!strcmp(x->ealg->alg_name, "cbc(aes)") && klen == 192)
		enc = NP6L_SA_ENC_AES192;
	else if (!strcmp(x->ealg->alg_name, "cbc(aes)") && klen == 256)
		enc = NP6L_SA_ENC_AES256;
	else if (!strcmp(x->ealg->alg_name, "cbc(des3_ede)") && klen == 192)
		enc = NP6L_SA_ENC_3DES;
	else
		enc = 0;

	trunc = x->aalg->alg_trunc_len;
	if (!strcmp(x->aalg->alg_name, "hmac(md5)") && trunc == 96)
		auth = NP6L_SA_AUTH_MD5;
	else if (!strcmp(x->aalg->alg_name, "hmac(sha1)") && trunc == 96)
		auth = NP6L_SA_AUTH_SHA1;
	else if (!strcmp(x->aalg->alg_name, "hmac(sha256)") && trunc == 128)
		auth = NP6L_SA_AUTH_SHA256;
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

/* ---------------------------------------------------------- next hop MAC */

static void fnp6l_sa_mac_set(struct fnp6l_sa *sa, struct neighbour *n)
{
	u8 ha[ETH_ALEN] = {};

	if (READ_ONCE(n->nud_state) & NUD_VALID)
		neigh_ha_snapshot(ha, n, sa->ndev);
	write_seqlock_bh(&sa->mac_lock);
	ether_addr_copy(sa->h_dest, ha);
	write_sequnlock_bh(&sa->mac_lock);
}

static int fnp6l_sa_route(struct fnp6l_sa *sa, struct netlink_ext_ack *extack)
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

static void fnp6l_sa_neigh(struct fnp6l_sa *sa)
{
	struct neighbour *n;

	n = neigh_lookup(&arp_tbl, &sa->nh, sa->ndev);
	if (!n) {
		n = neigh_create(&arp_tbl, &sa->nh, sa->ndev);
		if (IS_ERR(n))
			return;
	}
	fnp6l_sa_mac_set(sa, n);
	if (!(READ_ONCE(n->nud_state) & NUD_VALID))
		neigh_event_send(n, NULL);
	neigh_release(n);
}

static void fnp6l_sa_tx_unlink(struct fnp6l_sa *sa)
{
	struct fnp6l_ipsec *ips = sa->ips;

	spin_lock_bh(&ips->tx_lock);
	if (sa->tx_linked)
		list_del_rcu(&sa->tx_node);
	sa->tx_linked = false;
	spin_unlock_bh(&ips->tx_lock);
}

/* -------------------------------------------------------- xfrm state ops */

static int fnp6l_xdo_state_add(struct net_device *ndev, struct xfrm_state *x,
			       struct netlink_ext_ack *extack)
{
	struct fnp6l_sa_desc *desc;
	struct fnp6l_ipsec *ips;
	unsigned int lif, idx;
	struct fnp6l_sa *sa;
	struct fnp6l *np;
	u8 algs;
	int ret;

	x->xso.offload_handle = 0;
	if (x->xso.flags & XFRM_DEV_OFFLOAD_FLAG_ACQ)
		return 0;

	ips = fnp6l_port_info(ndev, &lif);
	if (!ips) {
		NL_SET_ERR_MSG_MOD(extack, "no IPsec offload on this port");
		return -EOPNOTSUPP;
	}
	np = ips->np;
	ret = fnp6l_sa_check(ndev, x, extack, &algs);
	if (ret)
		return ret;

	sa = kzalloc(sizeof(*sa), GFP_KERNEL);
	desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!sa || !desc) {
		ret = -ENOMEM;
		goto out;
	}
	sa->ips = ips;
	sa->x = x;
	sa->ndev = ndev;
	sa->lif = lif;
	sa->in = x->xso.dir == XFRM_DEV_OFFLOAD_IN;
	sa->saddr = x->props.saddr.a4;
	sa->daddr = x->id.daddr.a4;
	sa->spi = x->id.spi;
	seqlock_init(&sa->mac_lock);
	u64_stats_init(&sa->syncp);
	if (!sa->in) {
		ret = fnp6l_sa_route(sa, extack);
		if (ret)
			goto out;
	}
	fnp6l_sa_desc_fill(desc, x, algs, sa->in);

	fnp6l_fe_lock(np);
	/* Inbound needs the flow engine (SPI session entry); outbound does not. */
	if ((sa->in && !fnp6l_fe_ready(np)) || !READ_ONCE(ips->hw_ok) ||
	    READ_ONCE(ips->stalled)) {
		NL_SET_ERR_MSG_MOD(extack, "IPsec engine not available");
		ret = -EIO;
		goto unlock;
	}
	/* next fit: an index freed is taken again as late as possible */
	idx = find_next_zero_bit(ips->sa_used, NP6L_SA_NR, ips->next_idx);
	if (idx >= NP6L_SA_NR)
		idx = find_next_zero_bit(ips->sa_used, NP6L_SA_NR, 1);
	if (idx >= NP6L_SA_NR) {
		NL_SET_ERR_MSG_MOD(extack, "no free SA index");
		ret = -ENOSPC;
		goto unlock;
	}
	sa->idx = idx;

	ret = fnp6l_tun_write(ips, sa->in, idx, desc,
			      sa->in ? NP6L_SA_IB_STRIDE : NP6L_SA_OB_STRIDE);
	if (ret)
		goto fail;
	if (fnp6l_sa_verify(ips, sa->in, idx, sa->spi, true)) {
		fnp6l_tun_write(ips, sa->in, idx, NULL,
				sa->in ? NP6L_SA_IB_STRIDE : NP6L_SA_OB_STRIDE);
		NL_SET_ERR_MSG_MOD(extack, "IPsec engine did not take the SA");
		ret = -EIO;
		goto unlock;
	}

	if (sa->in) {
		ret = fnp6l_ipsec_spi(np, sa->saddr, sa->daddr, sa->spi, lif,
				      idx, true);
		if (ret) {
			fnp6l_tun_write(ips, true, idx, NULL, NP6L_SA_IB_STRIDE);
			NL_SET_ERR_MSG_MOD(extack, "flow engine refused the SPI entry");
			goto unlock;
		}
	}

	__set_bit(idx, ips->sa_used);
	ips->next_idx = idx + 1;
	WRITE_ONCE(ips->nr_sa, ips->nr_sa + 1);
	sa->hw = true;
	list_add(&sa->node, &ips->sas);
	if (sa->in) {
		ips->nr_in[lif]++;
		/* tear down flows through the port: tunnel traffic in the clear */
		atomic_long_add(fnp6l_ft_flush_lif(np, lif), &ips->ft_purged);
	} else {
		sa->seq = ++ips->seq;
		spin_lock_bh(&ips->tx_lock);
		list_add_tail_rcu(&sa->tx_node, &ips->tx_sas[lif]);
		sa->tx_linked = true;
		spin_unlock_bh(&ips->tx_lock);
	}
	rcu_assign_pointer(ips->sa_by_idx[idx], sa);
	fnp6l_fe_unlock(np);
	if (!sa->in)
		fnp6l_sa_neigh(sa);

	x->xso.offload_handle = (unsigned long)sa;
	netdev_dbg(ndev, "IPsec SA %u %s, SPI %#x, %pI4 > %pI4, algorithms %#x\n",
		   idx, sa->in ? "in" : "out", be32_to_cpu(sa->spi), &sa->saddr,
		   &sa->daddr, algs);
	kfree_sensitive(desc);
	return 0;

fail:
	NL_SET_ERR_MSG_MOD(extack, "IPsec engine command failed");
	ret = -EIO;
unlock:
	fnp6l_fe_unlock(np);
out:
	kfree_sensitive(desc);
	kfree(sa);
	return ret;
}

static void fnp6l_xdo_state_delete(struct net_device *ndev,
				   struct xfrm_state *x)
{
	struct fnp6l_sa *sa = (struct fnp6l_sa *)x->xso.offload_handle;

	if (!sa)
		return;
	WRITE_ONCE(sa->deleted, true);
	RCU_INIT_POINTER(sa->ips->sa_by_idx[sa->idx], NULL);
	fnp6l_sa_tx_unlink(sa);
}

static void fnp6l_xdo_state_free(struct net_device *ndev, struct xfrm_state *x)
{
	struct fnp6l_sa *sa = (struct fnp6l_sa *)x->xso.offload_handle;
	struct fnp6l_ipsec *ips;
	bool keep = false;
	struct fnp6l *np;
	int ret = 0;

	if (!sa)
		return;
	WRITE_ONCE(x->xso.offload_handle, 0);
	ips = sa->ips;
	np = ips->np;
	RCU_INIT_POINTER(ips->sa_by_idx[sa->idx], NULL);
	fnp6l_sa_tx_unlink(sa);
	synchronize_net();

	fnp6l_fe_lock(np);
	if (sa->hw) {
		if (fnp6l_tx_drain(np))
			keep = true;
		if (sa->in)
			fnp6l_ipsec_spi(np, sa->saddr, sa->daddr, sa->spi,
					sa->lif, sa->idx, false);
		/* whether the engine wrote the entry back to the DDR meanwhile */
		fnp6l_sa_diag(ips, sa->in, sa->idx, "before clear");
		ret = fnp6l_tun_write(ips, sa->in, sa->idx, NULL,
				      sa->in ? NP6L_SA_IB_STRIDE :
					       NP6L_SA_OB_STRIDE);
		if (!ret && fnp6l_sa_verify(ips, sa->in, sa->idx, 0, false))
			keep = true;
		if (sa->in && ips->nr_in[sa->lif])
			ips->nr_in[sa->lif]--;
	}
	sa->hw = false;
	list_del(&sa->node);
	if (keep && !ret)
		dev_warn(ips->dev, "IPsec SA %u: index kept until the engine resets\n",
			 sa->idx);
	else
		__clear_bit(sa->idx, ips->sa_used);
	WRITE_ONCE(ips->nr_sa, ips->nr_sa - 1);
	fnp6l_fe_unlock(np);

	kfree_rcu(sa, rcu);
}

/* -------------------------------------------------------------- RX path */

/*
 * Whether the completion words of a frame mark it from the IPsec engine
 * (word 0 bit 30), and with which SA (word 1 bits 15:0): the LIF of its
 * port, @x set with a reference, or -ENOENT. RX path (NAPI). Inert while
 * ipsec_outbound_only (no inbound SA is in the engine).
 */
int fnp6l_ipsec_rx(struct fnp6l_ipsec *ips, u32 w0, u32 w1,
		   struct xfrm_state **x)
{
	struct fnp6l_sa *sa;
	unsigned int idx;
	int ret;

	if (!ips || !(w0 & NP6L_RXW0_IPSEC_DONE))
		return -ENOENT;

	idx = FIELD_GET(NP6L_RXW1_SA_IDX, w1);
	rcu_read_lock();
	sa = idx && idx < NP6L_SA_NR ? rcu_dereference(ips->sa_by_idx[idx]) : NULL;
	if (sa && (!sa->in || !READ_ONCE(sa->hw) || READ_ONCE(sa->deleted) ||
		   READ_ONCE(ips->stalled)))
		sa = NULL;
	if (sa && !refcount_inc_not_zero(&sa->x->refcnt))
		sa = NULL;
	if (sa) {
		*x = sa->x;
		ret = sa->lif;
	} else {
		/*
		 * No SA at that index: leave the frame to the host (software
		 * xfrm), never drop it. A frame with the "processed" bit set and
		 * no SA is either an SA just gone or, until the completion word
		 * is confirmed on hardware, a bit read where none was meant.
		 */
		ret = -ENOENT;
	}
	rcu_read_unlock();

	atomic_long_inc(&ips->rx_dec);
	if (!sa) {
		atomic_long_inc(&ips->rx_nosa);
		dev_dbg_ratelimited(ips->dev, "IPsec frame for SA %u, not in service\n",
				    idx);
	}
	return ret;
}

bool fnp6l_ipsec_rx_skb(struct fnp6l_ipsec *ips, struct sk_buff *skb,
			struct xfrm_state *x)
{
	struct xfrm_offload *xo;
	struct sec_path *sp;

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
	if (skb->pkt_type == PACKET_OTHERHOST)
		skb->pkt_type = PACKET_HOST;
	return true;
}

void fnp6l_ipsec_rx_put(struct xfrm_state *x)
{
	if (x)
		xfrm_state_put(x);
}

/* ---------------------------------------------------------- ethtool */

static const char fnp6l_ipsec_stats[][ETH_GSTRING_LEN] = {
	"ipsec_sa",
	"rx_ipsec_dec",
	"rx_ipsec_nosa",
	"rx_ipsec_anomaly",
	"tx_ipsec_enc",
	"tx_ipsec_nosa",
	"tx_ipsec_nomac",
	"tx_ipsec_block",
	"tx_ipsec_opts",
	"ipsec_msg_lifetime",
	"ipsec_msg_seq_exhausted",
	"ipsec_msg_seq",
	"ipsec_msg_replay_win",
	"ipsec_msg_lifetime2",
	"ipsec_msg_nosa",
	"ipsec_msg_bad",
	"ft_refused_ipsec",
	"flow_purged_ipsec",
	"ipsec_stalled",
};

unsigned int fnp6l_ipsec_nr_stats(const struct fnp6l_ipsec *ips)
{
	return ips ? ARRAY_SIZE(fnp6l_ipsec_stats) : 0;
}

void fnp6l_ipsec_get_strings(const struct fnp6l_ipsec *ips, u8 **data)
{
	unsigned int i;

	for (i = 0; i < fnp6l_ipsec_nr_stats(ips); i++)
		ethtool_puts(data, fnp6l_ipsec_stats[i]);
}

unsigned int fnp6l_ipsec_get_stats(const struct fnp6l_ipsec *ips, u64 *data)
{
	if (!ips)
		return 0;
	data[0] = READ_ONCE(ips->nr_sa);
	data[1] = atomic_long_read(&ips->rx_dec);
	data[2] = atomic_long_read(&ips->rx_nosa);
	data[3] = atomic_long_read(&ips->rx_anomaly);
	data[4] = atomic_long_read(&ips->tx_enc);
	data[5] = atomic_long_read(&ips->tx_nosa);
	data[6] = atomic_long_read(&ips->tx_nomac);
	data[7] = atomic_long_read(&ips->tx_block);
	data[8] = atomic_long_read(&ips->tx_opts);
	data[9] = atomic_long_read(&ips->msg[0]);
	data[10] = atomic_long_read(&ips->msg[1]);
	data[11] = atomic_long_read(&ips->msg[2]);
	data[12] = atomic_long_read(&ips->msg[3]);
	data[13] = atomic_long_read(&ips->msg[4]);
	data[14] = atomic_long_read(&ips->msg_nosa);
	data[15] = atomic_long_read(&ips->msg_bad);
	data[16] = atomic_long_read(&ips->ft_refused);
	data[17] = atomic_long_read(&ips->ft_purged);
	data[18] = READ_ONCE(ips->stalled);
	return ARRAY_SIZE(fnp6l_ipsec_stats);
}

/* ---------------------------------------------------------- policies */

static int fnp6l_xdo_policy_add(struct xfrm_policy *xp,
				struct netlink_ext_ack *extack)
{
	struct net_device *ndev = xp->xdo.dev;
	const struct xfrm_tmpl *t = &xp->xfrm_vec[0];
	struct fnp6l_ipsec *ips;
	struct fnp6l_pol *pol, *pos;
	unsigned int lif, n;

	xp->xdo.offload_handle = 0;
	if (xp->xdo.dir != XFRM_DEV_OFFLOAD_OUT)
		return 0;

	ips = fnp6l_port_info(ndev, &lif);
	if (!ips) {
		NL_SET_ERR_MSG_MOD(extack, "no IPsec offload on this port");
		return -EOPNOTSUPP;
	}
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

	pol = kzalloc(sizeof(*pol), GFP_KERNEL);
	if (!pol)
		return -ENOMEM;
	pol->ips = ips;
	pol->xp = xp;
	pol->lif = lif;

	spin_lock_bh(&ips->tx_lock);
	list_for_each_entry(pos, &ips->tx_pols[lif], node)
		if (pos->xp->priority > xp->priority)
			break;
	list_add_tail_rcu(&pol->node, &pos->node);
	pol->linked = true;
	WRITE_ONCE(ips->nr_pols[lif], ips->nr_pols[lif] + 1);
	spin_unlock_bh(&ips->tx_lock);

	xp->xdo.offload_handle = (unsigned long)pol;

	/* tear down flows through the port: they would go past the policy */
	fnp6l_fe_lock(ips->np);
	n = fnp6l_ft_flush_lif(ips->np, lif);
	fnp6l_fe_unlock(ips->np);
	if (n) {
		atomic_long_add(n, &ips->ft_purged);
		netdev_dbg(ndev, "%u flows no longer offloaded: IPsec policy\n", n);
	}
	return 0;
}

/*
 * Whether a flow direction (in @in_lif, out @out_lif) must stay off the
 * flow engine, which would forward it past an offloaded policy in the
 * clear, or forward in the clear the traffic of a tunnel once decapsulated:
 * any outbound policy on the egress LIF refuses it, and an inbound SA on the
 * ingress LIF whose selector covers it (or any, an SA with no IPv4
 * selector). Under the flow-engine lock.
 */
bool fnp6l_ipsec_ft_refuse(struct fnp6l_ipsec *ips, unsigned int in_lif,
			   unsigned int out_lif,
			   const struct fnp6l_ipsec_tuple *key)
{
	struct fnp6l_sa *sa;

	if (!ips)
		return false;
	if (out_lif < NP6L_MAX_LIF && READ_ONCE(ips->nr_pols[out_lif])) {
		atomic_long_inc(&ips->ft_refused);
		return true;
	}
	if (in_lif < NP6L_MAX_LIF && ips->nr_in[in_lif]) {
		list_for_each_entry(sa, &ips->sas, node) {
			const struct xfrm_selector *sel = &sa->x->sel;

			if (!sa->in || sa->lif != in_lif)
				continue;
			if (sel->family != AF_INET ||
			    (addr4_match(key->daddr, sel->daddr.a4, sel->prefixlen_d) &&
			     addr4_match(key->saddr, sel->saddr.a4, sel->prefixlen_s))) {
				atomic_long_inc(&ips->ft_refused);
				return true;
			}
		}
	}
	return false;
}

static void fnp6l_pol_unlink(struct fnp6l_pol *pol)
{
	struct fnp6l_ipsec *ips = pol->ips;

	spin_lock_bh(&ips->tx_lock);
	if (pol->linked) {
		list_del_rcu(&pol->node);
		WRITE_ONCE(ips->nr_pols[pol->lif], ips->nr_pols[pol->lif] - 1);
	}
	pol->linked = false;
	spin_unlock_bh(&ips->tx_lock);
}

static void fnp6l_xdo_policy_delete(struct xfrm_policy *xp)
{
	struct fnp6l_pol *pol = (struct fnp6l_pol *)xp->xdo.offload_handle;

	if (pol)
		fnp6l_pol_unlink(pol);
}

static void fnp6l_xdo_policy_free(struct xfrm_policy *xp)
{
	struct fnp6l_pol *pol = (struct fnp6l_pol *)xp->xdo.offload_handle;

	if (!pol)
		return;
	fnp6l_pol_unlink(pol);
	xp->xdo.offload_handle = 0;
	kfree_rcu(pol, rcu);
}

/* ------------------------------------------------------------- TX path */

static bool fnp6l_sel_match(const struct xfrm_selector *sel,
			    const struct fnp6l_ipsec_tuple *t)
{
	return addr4_match(t->daddr, sel->daddr.a4, sel->prefixlen_d) &&
	       addr4_match(t->saddr, sel->saddr.a4, sel->prefixlen_s) &&
	       !((t->dport ^ sel->dport) & sel->dport_mask) &&
	       !((t->sport ^ sel->sport) & sel->sport_mask) &&
	       (!sel->proto || t->proto == sel->proto);
}

enum fnp6l_pol_verdict {
	NP6L_POL_NONE,
	NP6L_POL_BYPASS,
	NP6L_POL_ESP,
	NP6L_POL_BLOCK,
};

static enum fnp6l_pol_verdict
fnp6l_pol_lookup(struct fnp6l_ipsec *ips, unsigned int lif,
		 const struct fnp6l_ipsec_tuple *t, struct fnp6l_pol **pol)
{
	struct fnp6l_pol *pos;

	list_for_each_entry_rcu(pos, &ips->tx_pols[lif], node) {
		if (!fnp6l_sel_match(&pos->xp->selector, t))
			continue;
		*pol = pos;
		if (pos->xp->action != XFRM_POLICY_ALLOW)
			return NP6L_POL_BLOCK;
		return pos->xp->xfrm_nr ? NP6L_POL_ESP : NP6L_POL_BYPASS;
	}
	return NP6L_POL_NONE;
}

static bool fnp6l_sa_better(const struct fnp6l_sa *sa,
			    const struct fnp6l_sa *than)
{
	u8 dying = READ_ONCE(sa->x->km.dying);
	u8 than_dying = READ_ONCE(than->x->km.dying);

	if (dying != than_dying)
		return !dying;
	return sa->seq > than->seq;
}

static struct fnp6l_sa *fnp6l_tx_sa(struct fnp6l_ipsec *ips, unsigned int lif,
				    const struct xfrm_tmpl *t,
				    const struct fnp6l_ipsec_tuple *tuple)
{
	struct fnp6l_sa *sa, *best = NULL;

	if (READ_ONCE(ips->stalled))
		return NULL;
	list_for_each_entry_rcu(sa, &ips->tx_sas[lif], tx_node) {
		const struct xfrm_state *x = sa->x;

		if (!READ_ONCE(sa->hw) || READ_ONCE(sa->deleted) ||
		    READ_ONCE(x->km.state) != XFRM_STATE_VALID ||
		    (t->reqid && x->props.reqid != t->reqid) ||
		    (t->id.spi && sa->spi != t->id.spi) ||
		    sa->daddr != t->id.daddr.a4 ||
		    (t->saddr.a4 && sa->saddr != t->saddr.a4) ||
		    (x->sel.family == AF_INET && !fnp6l_sel_match(&x->sel, tuple)))
			continue;
		if (!best || fnp6l_sa_better(sa, best))
			best = sa;
	}
	return best;
}

/*
 * Frame through LIF @lif, MAC header in front: 0 to send it as it is, the
 * SA index with the MAC header rewritten to the next hop, or an error to
 * drop it (a "block" policy, or an IPsec policy without an SA or a resolved
 * next hop, or IP options). RCU, no sleeping (called from ndo_start_xmit).
 */
int fnp6l_ipsec_xmit(struct fnp6l_ipsec *ips, unsigned int lif,
		     struct sk_buff *skb)
{
	struct fnp6l_ipsec_tuple tuple = {};
	const struct iphdr *iph;
	struct fnp6l_pol *pol;
	struct fnp6l_sa *sa;
	unsigned int thoff;
	__be16 *pp, buf[2];
	struct neighbour *n;
	struct ethhdr *eth;
	int ret = 0;

	if (!ips || lif >= NP6L_MAX_LIF || !READ_ONCE(ips->nr_pols[lif]))
		return 0;
	if (skb->protocol != htons(ETH_P_IP) || skb_vlan_tag_present(skb) ||
	    skb_network_offset(skb) != ETH_HLEN ||
	    !pskb_may_pull(skb, ETH_HLEN + sizeof(*iph)))
		return 0;
	if (skb->sk && sk_fullsock(skb->sk) &&
	    rcu_access_pointer(skb->sk->sk_policy[XFRM_POLICY_OUT]))
		return 0;

	iph = ip_hdr(skb);
	if (iph->version != 4)
		return 0;
	tuple.saddr = iph->saddr;
	tuple.daddr = iph->daddr;
	tuple.proto = iph->protocol;
	thoff = ETH_HLEN + max_t(unsigned int, iph->ihl, 5) * 4;
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
	switch (fnp6l_pol_lookup(ips, lif, &tuple, &pol)) {
	case NP6L_POL_NONE:
	case NP6L_POL_BYPASS:
		goto out;
	case NP6L_POL_BLOCK:
		atomic_long_inc(&ips->tx_block);
		ret = -EPERM;
		goto out;
	case NP6L_POL_ESP:
		break;
	}
	if (iph->ihl != 5) {
		atomic_long_inc(&ips->tx_opts);
		ret = -EPERM;
		goto out;
	}
	sa = fnp6l_tx_sa(ips, lif, &pol->xp->xfrm_vec[0], &tuple);
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
	for (;;) {
		unsigned int seq = read_seqbegin(&sa->mac_lock);

		ether_addr_copy(eth->h_dest, sa->h_dest);
		if (!read_seqretry(&sa->mac_lock, seq))
			break;
	}
	if (is_zero_ether_addr(eth->h_dest)) {
		n = ip_neigh_gw4(sa->ndev, sa->nh);
		if (!IS_ERR(n) && (READ_ONCE(n->nud_state) & NUD_VALID)) {
			fnp6l_sa_mac_set(sa, n);
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

/* --------------------------------------------------------- neigh follow */

static int fnp6l_ipsec_netevent(struct notifier_block *nb, unsigned long event,
				void *ptr)
{
	struct fnp6l_ipsec *ips = container_of(nb, struct fnp6l_ipsec,
					       netevent_nb);
	struct neighbour *n = ptr;
	struct fnp6l_sa *sa;
	unsigned int lif;

	if (event != NETEVENT_NEIGH_UPDATE || n->tbl != &arp_tbl)
		return NOTIFY_DONE;

	rcu_read_lock();
	for (lif = 0; lif < NP6L_MAX_LIF; lif++)
		list_for_each_entry_rcu(sa, &ips->tx_sas[lif], tx_node)
			if (sa->ndev == n->dev &&
			    !memcmp(n->primary_key, &sa->nh, sizeof(sa->nh)))
				fnp6l_sa_mac_set(sa, n);
	rcu_read_unlock();
	return NOTIFY_DONE;
}

static void fnp6l_ipsec_netevent_stop(void *data)
{
	struct fnp6l_ipsec *ips = data;

	unregister_netevent_notifier(&ips->netevent_nb);
}

/* --------------------------------------------------------- messages */

bool fnp6l_ipsec_msg(struct fnp6l_ipsec *ips, const void *buf, unsigned int len)
{
	const struct fnp6l_ipsec_msg *msg = buf;
	struct fnp6l_sa *sa;
	struct xfrm_state *x;
	bool check = false;
	unsigned int idx;
	u64 bytes, old;
	u32 sn;

	if (!ips || len < sizeof(*msg) || msg->type < NP6L_MSG_SA_LIFETIME ||
	    msg->type > NP6L_MSG_SA_LIFETIME2)
		return false;

	atomic_long_inc(&ips->msg[msg->type - NP6L_MSG_SA_LIFETIME]);
	idx = le16_to_cpu(msg->idx);

	rcu_read_lock();
	sa = idx && idx < NP6L_SA_NR ? rcu_dereference(ips->sa_by_idx[idx]) : NULL;
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
	case NP6L_MSG_SA_LIFETIME:
	case NP6L_MSG_SA_LIFETIME2:
		bytes = NP6L_SA_VOL_MAX -
			((u64)FIELD_GET(NP6L_MSG_VOL_HI, le32_to_cpu(msg->hi)) << 16 |
			 le16_to_cpu(msg->lo));
		old = u64_stats_read(&sa->bytes);
		if (bytes < old || bytes - old > NP6L_SA_BYTES_JUMP) {
			atomic_long_inc(&ips->msg_bad);
			dev_warn_once(ips->dev,
				      "IPsec SA %u: byte lifetime message not taken, count %llu; the next ones are counted (ipsec_msg_bad)\n",
				      idx, old);
			break;
		}
		u64_stats_update_begin(&sa->syncp);
		u64_stats_set(&sa->bytes, bytes);
		u64_stats_update_end(&sa->syncp);
		check = true;
		break;
	case NP6L_MSG_SA_SEQ:
		sn = le32_to_cpu(msg->hi);
		u64_stats_update_begin(&sa->syncp);
		u64_stats_add(&sa->packets, sn - sa->sn);
		u64_stats_update_end(&sa->syncp);
		sa->sn = sn;
		check = true;
		if (sa->in)
			break;
		x->replay.oseq = sn;
		if (sn >= NP6L_SA_SN_SOFT && !x->km.dying) {
			x->km.dying = 1;
			km_state_expired(x, 0, 0);
		}
		break;
	case NP6L_MSG_SA_REPLAY_WIN:
		if (sa->in)
			x->replay.seq = le32_to_cpu(msg->hi);
		break;
	case NP6L_MSG_SA_SEQ_EXHAUSTED:
		x->km.state = XFRM_STATE_EXPIRED;
		hrtimer_start(&x->mtimer, 0, HRTIMER_MODE_REL_SOFT);
		break;
	}

	if (check && (u64_stats_read(&sa->bytes) >= x->lft.soft_byte_limit ||
		      u64_stats_read(&sa->packets) >= x->lft.soft_packet_limit))
		xfrm_state_check_expire(x);
unlock:
	spin_unlock(&x->lock);
out:
	rcu_read_unlock();
	return true;
}

static void fnp6l_xdo_state_update_stats(struct xfrm_state *x)
{
	struct fnp6l_sa *sa;
	u64 bytes, packets;
	unsigned int start;

	rcu_read_lock();
	sa = (struct fnp6l_sa *)READ_ONCE(x->xso.offload_handle);
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

static bool fnp6l_xdo_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	struct fnp6l_sa *sa;
	bool stalled = false;

	rcu_read_lock();
	sa = (struct fnp6l_sa *)READ_ONCE(x->xso.offload_handle);
	if (sa)
		stalled = READ_ONCE(sa->ips->stalled);
	rcu_read_unlock();

	return !stalled && ip_hdr(skb)->version == 4 && ip_hdr(skb)->ihl == 5;
}

static const struct xfrmdev_ops fnp6l_xfrmdev_ops = {
	.xdo_dev_state_add	= fnp6l_xdo_state_add,
	.xdo_dev_state_delete	= fnp6l_xdo_state_delete,
	.xdo_dev_state_free	= fnp6l_xdo_state_free,
	.xdo_dev_offload_ok	= fnp6l_xdo_offload_ok,
	.xdo_dev_state_update_stats = fnp6l_xdo_state_update_stats,
	.xdo_dev_policy_add	= fnp6l_xdo_policy_add,
	.xdo_dev_policy_delete	= fnp6l_xdo_policy_delete,
	.xdo_dev_policy_free	= fnp6l_xdo_policy_free,
};

static int fnp6l_km_acquire(struct xfrm_state *x, struct xfrm_tmpl *t,
			    struct xfrm_policy *xp)
{
	return -EOPNOTSUPP;
}

static struct xfrm_policy *fnp6l_km_compile_policy(struct sock *sk, int opt,
						   u8 *data, int len, int *dir)
{
	return NULL;
}

static void fnp6l_ipsec_km_stop(void *data)
{
	struct fnp6l_ipsec *ips = data;

	xfrm_unregister_km(&ips->km);
}

/* ------------------------------------------------------------- probe */

void fnp6l_ipsec_port_init(struct fnp6l_ipsec *ips, struct net_device *ndev)
{
	if (!ips)
		return;
	ndev->xfrmdev_ops = &fnp6l_xfrmdev_ops;
	ndev->hw_features |= NETIF_F_HW_ESP;
	ndev->features |= NETIF_F_HW_ESP;
}

int fnp6l_ipsec_probe(struct fnp6l *np, struct device *dev, void __iomem *base,
		      struct fnp6l_ipsec **ipsec)
{
	struct fnp6l_ipsec *ips;
	unsigned int lif;
	int ret;

	ips = devm_kzalloc(dev, sizeof(*ips), GFP_KERNEL);
	if (!ips)
		return -ENOMEM;
	ips->np = np;
	ips->dev = dev;
	ips->base = base;

	INIT_LIST_HEAD(&ips->sas);
	spin_lock_init(&ips->tx_lock);
	for (lif = 0; lif < NP6L_MAX_LIF; lif++) {
		INIT_LIST_HEAD(&ips->tx_pols[lif]);
		INIT_LIST_HEAD(&ips->tx_sas[lif]);
	}

	ips->sa_used = devm_bitmap_zalloc(dev, NP6L_SA_NR, GFP_KERNEL);
	ips->sa_by_idx = devm_kcalloc(dev, NP6L_SA_NR, sizeof(*ips->sa_by_idx),
				      GFP_KERNEL);
	if (!ips->sa_used || !ips->sa_by_idx)
		return -ENOMEM;
	__set_bit(0, ips->sa_used);
	ips->next_idx = 1;

	/*
	 * The SA tables lie in the DDR region the core already owns: map them
	 * write-combining, not requested again.
	 */
	ips->ib_mem = devm_memremap(dev, NP6L_SA_IB_BASE, NP6L_SA_IB_SIZE,
				    MEMREMAP_WC);
	ips->ob_mem = devm_memremap(dev, NP6L_SA_OB_BASE, NP6L_SA_OB_SIZE,
				    MEMREMAP_WC);
	if (IS_ERR_OR_NULL(ips->ib_mem) || IS_ERR_OR_NULL(ips->ob_mem)) {
		dev_warn(dev, "cannot map the SA tables, no IPsec offload\n");
		return 0;
	}

	ips->netevent_nb.notifier_call = fnp6l_ipsec_netevent;
	ret = register_netevent_notifier(&ips->netevent_nb);
	if (ret)
		return ret;
	ret = devm_add_action_or_reset(dev, fnp6l_ipsec_netevent_stop, ips);
	if (ret)
		return ret;

	ips->km.acquire = fnp6l_km_acquire;
	ips->km.compile_policy = fnp6l_km_compile_policy;
	xfrm_register_km(&ips->km);
	ret = devm_add_action_or_reset(dev, fnp6l_ipsec_km_stop, ips);
	if (ret)
		return ret;

	*ipsec = ips;
	dev_info(dev, "IPsec offload (outbound%s)\n",
		 READ_ONCE(ipsec_outbound_only) ? " only" : " and inbound");
	return 0;
}
