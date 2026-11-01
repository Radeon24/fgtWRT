// SPDX-License-Identifier: GPL-2.0-only
/*
 * Packet DMA of the CMIC of the BCM53314: first steps.
 * Included by bcm5331x-dsa.c, after the base module and the DSA driver
 * state it reads (hwbridge, link_mode, front_ports, sw->lock).
 *
 * cmic=0 (default): nothing here runs, no access at all. cmic=2: one of
 * the test steps below, chosen by
 * cmic_stage, after the switch is registered:
 *   1  sequence only: reads D0-D3, coherent memory allocated, channel
 *      directions set (D5-D6), then undone at once (A6) and the memory
 *      given back; no channel is ever enabled;
 *   2  1 + one transmit (channel 0, memory to switch): cmic_tx_count test
 *      frames (broadcast, EtherType 0x88b5, locally administered source
 *      02:00:00:c3:14:01) with a stream-of-bytes header to switch port
 *      cmic_tx_port, one descriptor each, one in flight; the switch only
 *      reads host memory;
 *   3  1 + one receive descriptor (channel 1, switch to memory, no chain):
 *      EPC_LINK_BMAP bit 0 and EGR_ENABLE[0] set after the channel is
 *      enabled, L2_USER_ENTRY[39] = {DA ff:ff:ff:ff:ff:ff, VID of port1,
 *      CPU, DST_DISCARD}; the DONE word of the descriptor in memory is
 *      polled (never CMIC_DMA_STAT) until one accepted frame or cmic_rx_ms,
 *      then everything is undone;
 *   4  3 with a chain of CM_RX_N descriptors re-armed at its end, a second
 *      entry L2_USER_ENTRY[38] = {DA 01:00:5e:01:01:26 (group 239.1.1.38),
 *      VID of port2, CPU, DST_DISCARD}, running until the module is removed. Frames are counted by source port and reason and
 *      the last one is kept for the debugfs file "cmic"; nothing reaches
 *      the network stack yet: the frame format is unmeasured (Hx-C14).
 * Stages 3 and 4, the test entry of L2_USER_ENTRY[39] and how a frame of a
 * front port reaches the CMIC (all defaults: as written above):
 *   cmic_rx_da    its destination address;
 *   cmic_rx_vid   its VID: -1 VID of port1, 0 VID left out of the mask;
 *   cmic_rx_act   1 CPU, 2 DST_DISCARD, 4 BPDU; 0 no entry at all;
 *   cmic_cpu_vlan 1: the CMIC port added (tagged) to the VLAN of port1 in
 *                 EGR_VLAN then VLAN_TAB, taken back in reverse order: the
 *                 frames flooded in it reach the channel with no entry.
 * The file "cmic" prints the two test entries, the VLAN of port1 and
 * PORT_TAB of port1 as read now ("now", while the memory is held) and as read
 * just before they were given back ("stop").
 * A frame from the host links (SRC_PORT 3 and 4) is the host's own traffic
 * flooded in VLAN 1, the CPU port being a member: not what the stages
 * look for. It is counted in rx_skip_cpu and nothing else; the descriptors are
 * re-armed as at the end of a chain, cmic_stage 3 included.
 * Stage 1 and 2 are over when the module load returns. A frame that does
 * not fit one descriptor (END clear, jumbo, review m8) is dropped and
 * counted.
 *
 * A guard that finds something unexpected logs "cmic: guard: ..." and leaves
 * everything untouched; "refused" is kept for a write outside the lists.
 *
 * Safety rules (design note §3.2, §4.2; review M5):
 *  - the PCI configuration space is read only (PCI_COMMAND left by the boot
 *    firmware with MEMORY and MASTER set: never written); the
 *    upstream bridge 00:1e.0 is read only and must have MASTER set;
 *  - every DMA register write goes through cm_wr(): offset AND value from
 *    a fixed list, descriptor addresses only inside the coherent block;
 *    the starting writes (directions, descriptor, enable) are refused once
 *    the switch is halted, the stopping writes never are;
 *  - stop order: S-channel restores (A2, A3) then channels (A4-A6) on a
 *    normal stop; on a fault (switch halted), channels FIRST (MMIO only),
 *    the S-channel restores are then left (switch halted: logged, reboot);
 *  - the memory is freed only when both channels read back disabled and
 *    idle and both descriptor registers read back 0; otherwise it is
 *    deliberately leaked;
 *  - a reboot notifier stops everything before a warm reboot;
 *  - a fault seen while a receive is armed is handled by the poll work
 *    item, never under sw->lock in the path that raised it;
 *  - CMIC_SOFT_RESET must read 0x0001e3c1, the value the boot firmware
 *    leaves and step init checks at its end (line RFb): the same guard
 *    holds after a start from the disk.
 * The registers stay outside the CMIC lists of the base module, on purpose:
 * this file is the only code that reaches them. Stage 3 and 4 need
 * link=0 (EPC_LINK_BMAP has a single owner) and hwbridge=0.
 */

#include <linux/dma-mapping.h>
#include <linux/reboot.h>

#define CM_DMA_CTRL		0x100
#define CM_DMA_STAT		0x104
#define CM_CONFIG		0x10c
#define CM_DMA_DESC(c)		(0x110 + 4 * (c))
#define CM_ENDIAN		0x174
#define CM_PKT_FROMCPU_MH	0x1c8
#define CM_PKT_FROMCPU		0x1cc

#define CM_ST_EN(c)		BIT(c)
#define CM_ST_CHAIN(c)		BIT(4 + (c))
#define CM_ST_DESC(c)		BIT(8 + (c))
#define CM_ST_CLEANUP		BIT(15)
#define CM_ST_ACTIVE(c)		BIT(18 + (c))
#define CM_ST_ERR		GENMASK(31, 22)
#define CM_ST_CH01		(CM_ST_EN(0) | CM_ST_EN(1) | CM_ST_CHAIN(0) | CM_ST_CHAIN(1) | \
				 CM_ST_DESC(0) | CM_ST_DESC(1) | CM_ST_ACTIVE(0) | CM_ST_ACTIVE(1))
#define CM_CTRL_RUN		0x00008001	/* CH0 TX, CH1 RX + DROP_RX_PKT_ON_CHAIN_END */
#define CM_CTRL_ABORT(c)	(CM_CTRL_RUN | BIT(2 + 8 * (c)))

/* coherent block: offsets; buffers on a 64-byte boundary */
#define CM_RX_N			16
#define CM_DCB_WORDS		11
#define CM_DCB_BYTES		(4 * CM_DCB_WORDS)
#define CM_RXDCB		0x000
#define CM_TXDCB		0x300
#define CM_RXBUF		0x400
#define CM_BUF			2048
#define CM_TXBUF		(CM_RXBUF + CM_RX_N * CM_BUF)
#define CM_MEM			(CM_TXBUF + CM_BUF)
#define CM_W1_CHAIN		BIT(16)
#define CM_W1_HG		BIT(19)
#define CM_W6_BPDU		BIT(29)
#define CM_W9_SRC_PORT(w)	((w) >> 27)
#define CM_W9_VID(w)		(((w) >> 11) & 0xfff)
#define CM_W10_DONE		BIT(31)
#define CM_W10_ERROR		BIT(18)
#define CM_W10_END		BIT(16)
#define CM_W10_BYTES		GENMASK(15, 0)
#define CM_W7_REASON		GENMASK(27, 0)	/* above: priority fields */

#define CM_EGR_ENABLE0		0x0a900100	/* EPIPE EGR_ENABLE, port 0 */
#define CM_L2U_IDX(i)		(39 - (i))	/* test entries: below the bridge entries 40-63 */
#define CM_RX_PORT0		10		/* port1 */
#define CM_RX_PORT1		9		/* port2 */
#define CM_RX_SKIP_PORTS	(PBM_TRUNK | PBM_TRUNK2)	/* frames of the host */
#define CM_RX_MAC0		0xffffffffffffULL	/* broadcast */
#define CM_RX_MAC1		0x01005e010126ULL	/* group 239.1.1.38 */
#define CM_TX_LEN		64		/* room for the FCS included */
#define CM_TX_ETHERTYPE		0x88b5		/* IEEE local experimental */
#define CM_ACT_CPU		BIT(0)		/* cmic_rx_act */
#define CM_ACT_DISCARD		BIT(1)
#define CM_ACT_BPDU		BIT(2)
#define CM_VT_CMIC		BIT(0)		/* VLAN_TAB word 0, PORT_BITMAP 24:0 */
#define CM_EV_CMIC		BIT(25)		/* EGR_VLAN word 0, PORT_BITMAP 49:25; UT_BITMAP 24:0 stays clear */
#define CM_DEV_REV		0x0011c314
#define CM_CONFIG_BIOS		0x08000043
#define CM_STOP_US		500000
#define CM_TX_US		10000
#define CM_WLOG			96

static int cmic;
module_param(cmic, int, 0444);
MODULE_PARM_DESC(cmic, "Packet DMA of the CMIC: 0 = off (default, no access); 2 = test step cmic_stage");
static int cmic_stage = 1;
module_param(cmic_stage, int, 0444);
MODULE_PARM_DESC(cmic_stage, "cmic=2: 1 = sequence only, no channel enabled (default); 2 = + transmit test frames; 3 = + one receive descriptor; 4 = + chain of receive descriptors (3 and 4 need hwbridge=0 and link=0)");
static int cmic_tx_port = 10;
module_param(cmic_tx_port, int, 0444);
MODULE_PARM_DESC(cmic_tx_port, "cmic_stage=2: switch port of the test frames, a front port (default 10 = port1)");
static int cmic_tx_count = 1;
module_param(cmic_tx_count, int, 0444);
MODULE_PARM_DESC(cmic_tx_count, "cmic_stage=2: test frames sent, 1-8 (default 1)");
static int cmic_rx_ms = 30000;
module_param(cmic_rx_ms, int, 0444);
MODULE_PARM_DESC(cmic_rx_ms, "cmic_stage=3: longest wait for the frame, 1000-120000 ms (default 30000)");

static unsigned long long cmic_rx_da = CM_RX_MAC0;
module_param(cmic_rx_da, ullong, 0444);
MODULE_PARM_DESC(cmic_rx_da, "cmic_stage=3-4: DA of test entry L2_USER_ENTRY[39] (default broadcast)");
static int cmic_rx_vid = -1;
module_param(cmic_rx_vid, int, 0444);
MODULE_PARM_DESC(cmic_rx_vid, "cmic_stage=3-4: VID of that entry: -1 = VID of port1 (default), 0 = VID out of the mask, else 1-4094");
static int cmic_rx_act = CM_ACT_CPU | CM_ACT_DISCARD;
module_param(cmic_rx_act, int, 0444);
MODULE_PARM_DESC(cmic_rx_act, "cmic_stage=3-4: actions of that entry: 1 CPU, 2 DST_DISCARD, 4 BPDU (default 3), 0 = no entry");
static int cmic_cpu_vlan;
module_param(cmic_cpu_vlan, int, 0444);
MODULE_PARM_DESC(cmic_cpu_vlan, "cmic_stage=3-4: 1 = CMIC port added to the VLAN of port1 while the channel runs (default 0)");

/* what the file "cmic" prints of the tables of the test */
struct cm_tabs {
	bool ok;
	u32 l2u[2][HW_L2U_WORDS];
	u32 vt[HW_L2U_WORDS], ev[HW_L2U_WORDS], pt[3];
};

static struct {
	struct mutex mtx;		/* the state below */
	struct bcm53314 *sw;
	struct delayed_work poll;
	int stage;
	void *mem;
	dma_addr_t bus;
	bool notifier;
	bool ch1_on;			/* channel 1 enabled since the last stop */
	bool ch0_stuck;			/* a transmit did not complete: channel 0 to abort */
	bool stopping;			/* in cm_stop: the abort sequence restores DMA_CTRL */
	bool running;			/* receive armed, poll work active */
	bool egr_set, epc_set;
	u32 l2u_set;			/* bit i: test entry i written */
	u32 vlan_set;			/* bit 0 VLAN_TAB, bit 1 EGR_VLAN: CMIC port added */
	u32 vt_orig[2], ev_orig[2];	/* VLAN of port1, read by the guards */
	struct cm_tabs tabs_stop;
	u32 epc_orig;
	ktime_t rx_end;
	int rx_idx;
	unsigned long tx_ok, tx_fail, tx_nodone, rx_frames, rx_err, rx_split, rx_rearm;
	unsigned long rx_wait;		/* passes with the chain done, its end not flagged */
	unsigned long rx_skip_cpu;	/* frames of CM_RX_SKIP_PORTS: only counted here */
	unsigned long rx_port[32], rx_reason[32];
	unsigned long refused, leaked, pci_err;
	u32 last_dcb[CM_DCB_WORDS];
	u8 last_head[64];
	u32 last_len;
	struct { u32 off, val; } wl[CM_WLOG];
	unsigned long nw;
} cm;

/* what the stage may start */
static bool cm_is_tx(void)
{
	return cm.stage == 2;
}

static bool cm_is_rx(void)
{
	return cm.stage >= 3;
}

static int cm_rx_n(void)
{
	return cm.stage > 3 ? CM_RX_N : 1;
}

static u32 cm_rd(struct bcm53314 *sw, u32 off)
{
	return ioread32(sw->bar + off);
}

/*
 * Fixed list, offset and value. true: allowed once the switch is halted too
 * (a write that stops or clears); *start: a write that starts something,
 * refused once halted and outside its stage.
 */
static bool cm_wr_ok(u32 off, u32 val, bool *start)
{
	*start = false;
	switch (off) {
	case CM_DMA_STAT:
		if (val == 0x00 || val == 0x01 || val == 0x04 || val == 0x05 ||
		    val == 0x08 || val == 0x09)
			return true;
		*start = true;
		return (val == 0x80 && cm_is_tx()) || (val == 0x81 && cm_is_rx());
	case CM_DMA_CTRL:
		if (!val || val == CM_CTRL_ABORT(0) || val == CM_CTRL_ABORT(1))
			return true;
		*start = !cm.stopping;
		return val == CM_CTRL_RUN;
	case CM_DMA_DESC(0):
		if (!val)
			return true;
		*start = true;
		return cm_is_tx() && val == (u32)cm.bus + CM_TXDCB;
	case CM_DMA_DESC(1):
		if (!val)
			return true;
		*start = true;
		return cm_is_rx() && val == (u32)cm.bus + CM_RXDCB;
	}
	return false;
}

static int cm_wr(struct bcm53314 *sw, u32 off, u32 val)
{
	bool start;

	if (!cm_wr_ok(off, val, &start) || (start && READ_ONCE(sw->halted))) {
		cm.refused++;
		sw_fault(sw, "cmic: write 0x%03x <- 0x%08x refused", off, val);
		return -EPERM;
	}
	iowrite32(val, sw->bar + off);
	if (cm.nw < CM_WLOG) {
		cm.wl[cm.nw].off = off;
		cm.wl[cm.nw].val = val;
	}
	cm.nw++;
	return 0;
}

/* a register that keeps its value: written, read back */
static int cm_wr_chk(struct bcm53314 *sw, u32 off, u32 val)
{
	int err = cm_wr(sw, off, val);
	u32 rb;

	if (err)
		return err;
	rb = cm_rd(sw, off);
	if (rb != val) {
		sw_fault(sw, "cmic: 0x%03x read back 0x%08x, wrote 0x%08x", off, rb, val);
		return -EIO;
	}
	return 0;
}

static int cm_clear_chan(struct bcm53314 *sw, int c)
{
	return cm_wr(sw, CM_DMA_STAT, c) ? : cm_wr(sw, CM_DMA_STAT, 4 + c) ? :
	       cm_wr(sw, CM_DMA_STAT, 8 + c);
}

/* A4/A5: true when the channel is idle; on a timeout DMA_CTRL stays as it is */
static bool cm_abort(struct bcm53314 *sw, int c)
{
	ktime_t end = ktime_add_us(ktime_get(), CM_STOP_US);
	u32 st;

	if (cm_wr(sw, CM_DMA_STAT, c) || cm_wr(sw, CM_DMA_CTRL, CM_CTRL_ABORT(c)))
		return false;
	for (;;) {
		st = cm_rd(sw, CM_DMA_STAT);
		if (!(st & CM_ST_ACTIVE(c)))
			break;
		if (ktime_after(ktime_get(), end)) {
			dev_err(&sw->pdev->dev, "cmic: channel %d still active, DMA_STAT 0x%08x\n", c, st);
			return false;
		}
		usleep_range(100, 200);
	}
	if (st & CM_ST_CLEANUP)
		dev_warn(&sw->pdev->dev, "cmic: DMA_STAT 0x%08x: abort cleanup flagged, no purge frame sent\n", st);
	return !cm_wr(sw, CM_DMA_CTRL, CM_CTRL_RUN) && !cm_clear_chan(sw, c);
}

/* ---- S-channel writes: fixed list, re-read before, read back after ------ */

static void cm_l2u_build(u32 *w, u64 mac, u16 vid, int act)
{
	u64 key_mask = 0xffffffffffffULL | (u64)(vid ? 0xfff : 0) << 48;

	memset(w, 0, 4 * HW_L2U_WORDS);
	ent_set(w, 0, 1, 1);				/* VALID */
	ent_set(w, 1, 32, (u32)mac);			/* MAC_ADDR 48:1 */
	ent_set(w, 33, 16, (u32)(mac >> 32));
	ent_set(w, 49, 12, vid);			/* VLAN_ID 60:49 */
	ent_set(w, 68, 32, (u32)key_mask);		/* MASK 127:68 */
	ent_set(w, 100, 28, (u32)(key_mask >> 32));
	w[4] = (act & CM_ACT_CPU ? HW_L2U_W4_CPU : 0) |
	       (act & CM_ACT_DISCARD ? HW_L2U_W4_DISCARD : 0) |
	       (act & CM_ACT_BPDU ? HW_L2U_W4_BPDU : 0);
}

static int cm_rx_port(int i)
{
	return i ? CM_RX_PORT1 : CM_RX_PORT0;
}

static u64 cm_rx_mac(int i)
{
	return i ? CM_RX_MAC1 : cmic_rx_da;
}

static u16 cm_rx_vid(int i)
{
	return i || cmic_rx_vid < 0 ? bcm5331x_port_vid(cm_rx_port(i)) : cmic_rx_vid;
}

static int cm_rx_act(int i)
{
	return i ? CM_ACT_CPU | CM_ACT_DISCARD : cmic_rx_act;
}

/* under sw->lock */
static bool cm_same(const u32 *a, const u32 *b, int words, u32 parity1)
{
	int i;

	for (i = 0; i < words; i++)
		if ((a[i] ^ b[i]) & ~(i == 1 ? parity1 : 0))
			return false;
	return true;
}

/* parity1: the bit of word 1 the hardware keeps, not compared */
static int cm_sw_set(struct bcm53314 *sw, const char *name, u32 addr, bool mem, int words,
		     int idx, u32 parity1, const u32 *old, const u32 *val)
{
	u32 cur[HW_L2U_WORDS], rb[HW_L2U_WORDS];
	int err;

	if (!cm_is_rx()) {
		cm.refused++;
		sw_fault(sw, "cmic: %s refused at this stage", name);
		return -EPERM;
	}
	err = hw_read(sw, name, addr, mem, words, idx, cur);
	if (err)
		return err;
	if (!cm_same(cur, old, words, parity1)) {
		sw_fault(sw, "cmic: %s[%d] is 0x%08x, expected 0x%08x", name, idx, cur[0], old[0]);
		return -ESTALE;
	}
	memcpy(rb, val, 4 * words);
	err = schan_xfer(sw, true, mem, addr, words, rb, name, idx);
	if (err)
		return err;
	udelay(10);
	err = hw_read(sw, name, addr, mem, words, idx, rb);
	if (err)
		return err;
	if (!cm_same(rb, val, words, parity1)) {
		sw_fault(sw, "cmic: %s[%d] read back 0x%08x, wrote 0x%08x", name, idx, rb[0], val[0]);
		return -EIO;
	}
	return 0;
}

static int cm_egr_set(struct bcm53314 *sw, bool on)
{
	u32 o = !on, n = on;
	int err = cm_sw_set(sw, "EGR_ENABLE", CM_EGR_ENABLE0, false, 1, 0, 0, &o, &n);

	if (!err)
		cm.egr_set = on;
	return err;
}

static int cm_epc_set(struct bcm53314 *sw, bool on)
{
	u32 o = on ? cm.epc_orig : cm.epc_orig | BIT(0), n = on ? cm.epc_orig | BIT(0) : cm.epc_orig;
	int err = cm_sw_set(sw, "EPC_LINK_BMAP", obj_addr(&objs[O_EPC_LINK_BMAP], 0), false, 1, 0, 0, &o, &n);

	if (!err)
		cm.epc_set = on;
	return err;
}

static int cm_l2u_set(struct bcm53314 *sw, int i, bool on)
{
	u32 e[HW_L2U_WORDS], z[HW_L2U_WORDS] = { 0 };
	int idx = CM_L2U_IDX(i), err;

	cm_l2u_build(e, cm_rx_mac(i), cm_rx_vid(i), cm_rx_act(i));
	err = cm_sw_set(sw, "L2_USER_ENTRY", HW_L2U_ADDR + idx, true, HW_L2U_WORDS, idx, 0,
			on ? z : e, on ? e : z);
	if (!err)
		cm.l2u_set = on ? cm.l2u_set | BIT(i) : cm.l2u_set & ~BIT(i);
	return err;
}

/* the CMIC port in VLAN_TAB (obj O_VLAN_TAB) or EGR_VLAN of the VLAN of port1 */
static int cm_vlan_set(struct bcm53314 *sw, int obj, bool on)
{
	const struct sw_obj *o = &objs[obj];
	bool egr = obj == O_EGR_VLAN;
	int vid = bcm5331x_port_vid(CM_RX_PORT0), err;
	u32 clr[2], set[2], flag = egr ? BIT(1) : BIT(0);

	memcpy(clr, egr ? cm.ev_orig : cm.vt_orig, sizeof(clr));
	memcpy(set, clr, sizeof(set));
	set[0] |= egr ? CM_EV_CMIC : CM_VT_CMIC;
	err = cm_sw_set(sw, o->name, obj_addr(o, vid), true, 2, vid, o->parity,
			on ? clr : set, on ? set : clr);
	if (!err)
		cm.vlan_set = on ? cm.vlan_set | flag : cm.vlan_set & ~flag;
	return err;
}

/* under sw->lock: reads only; t->ok stays false at the first failure */
static void cm_tabs_read(struct bcm53314 *sw, struct cm_tabs *t)
{
	int vid = bcm5331x_port_vid(CM_RX_PORT0), i, err = 0;

	memset(t, 0, sizeof(*t));
	if (READ_ONCE(sw->halted))
		return;
	for (i = 0; i < 2 && !err; i++)
		err = hw_read(sw, "L2_USER_ENTRY", HW_L2U_ADDR + CM_L2U_IDX(i), true, HW_L2U_WORDS,
			      CM_L2U_IDX(i), t->l2u[i]);
	err = err ? : sw_read(sw, O_VLAN_TAB, vid, t->vt);
	err = err ? : sw_read(sw, O_EGR_VLAN, vid, t->ev);
	err = err ? : sw_read(sw, O_PORT_TAB, CM_RX_PORT0, t->pt);
	t->ok = !err;
}

/* A2, A3 under sw->lock: stops at the first failure, what is left stays flagged */
static void cm_sw_restore(struct bcm53314 *sw)
{
	int i, err = 0;

	mutex_lock(&sw->lock);
	if (cm_is_rx())
		cm_tabs_read(sw, &cm.tabs_stop);
	for (i = 1; i >= 0 && !err; i--)
		if (cm.l2u_set & BIT(i))
			err = cm_l2u_set(sw, i, false);
	if (!err && (cm.vlan_set & BIT(0)))
		err = cm_vlan_set(sw, O_VLAN_TAB, false);
	if (!err && (cm.vlan_set & BIT(1)))
		err = cm_vlan_set(sw, O_EGR_VLAN, false);
	if (!err && cm.egr_set)
		err = cm_egr_set(sw, false);
	if (!err && cm.epc_set)
		cm_epc_set(sw, false);
	mutex_unlock(&sw->lock);
}

/* ---- stop ---------------------------------------------------------------- */

/*
 * Under cm.mtx, poll work not running or being this one. Normal stop: the
 * port towards the CMIC is closed first (A2, A3), then the channels (A4-A6).
 * Fault: the channels first, MMIO only; the S-channel is out of reach.
 * The memory goes back only with both channels read back idle and both
 * descriptor registers at 0.
 */
static void cm_stop(struct bcm53314 *sw)
{
	bool fault = READ_ONCE(sw->halted), ok = true;
	u32 st = 0, d0 = 0, d1 = 0;

	cm.running = false;
	cm.stopping = true;
	if (!fault)
		cm_sw_restore(sw);
	if (cm.ch1_on)
		ok = cm_abort(sw, 1);
	if (cm.ch0_stuck)
		ok = cm_abort(sw, 0) && ok;
	if (ok)
		ok = !cm_wr_chk(sw, CM_DMA_CTRL, 0) && !cm_wr_chk(sw, CM_DMA_DESC(0), 0) &&
		     !cm_wr_chk(sw, CM_DMA_DESC(1), 0);
	cm.stopping = false;
	if (cm.l2u_set || cm.vlan_set || cm.egr_set || cm.epc_set)
		dev_err(&sw->pdev->dev, "cmic: not restored: L2_USER_ENTRY mask 0x%x, VLAN mask 0x%x, EGR_ENABLE[0] %d, EPC_LINK_BMAP bit 0 %d: reboot\n",
			cm.l2u_set, cm.vlan_set, cm.egr_set, cm.epc_set);
	if (ok) {
		st = cm_rd(sw, CM_DMA_STAT);
		d0 = cm_rd(sw, CM_DMA_DESC(0));
		d1 = cm_rd(sw, CM_DMA_DESC(1));
		ok = !(st & CM_ST_CH01) && !d0 && !d1;
		if (st & CM_ST_ERR) {
			cm.pci_err++;
			dev_err(&sw->pdev->dev, "cmic: PCI error at stop, DMA_STAT 0x%08x\n", st);
		}
	}
	if (ok) {
		dma_free_coherent(&sw->pdev->dev, CM_MEM, cm.mem, cm.bus);
		dev_info(&sw->pdev->dev, "cmic: stopped, memory given back; %lu write(s), tx %lu/%lu, rx %lu\n",
			 cm.nw, cm.tx_ok, cm.tx_fail, cm.rx_frames);
	} else {
		cm.leaked++;
		sw_fault(sw, "cmic: channels not stopped (DMA_STAT 0x%08x, DESC 0x%08x 0x%08x): memory left allocated",
			 st, d0, d1);
	}
	cm.mem = NULL;
	cm.ch1_on = cm.ch0_stuck = false;
}

/* ---- transmit ------------------------------------------------------------ */

static int cm_tx_one(struct bcm53314 *sw, int n)
{
	static const u8 src[ETH_ALEN] = { 0x02, 0x00, 0x00, 0xc3, 0x14, 0x01 };
	ktime_t end = ktime_add_us(ktime_get(), CM_TX_US);
	u8 *f = (u8 *)cm.mem + CM_TXBUF;
	u32 *d = (u32 *)((u8 *)cm.mem + CM_TXDCB);
	u32 st;
	int err;

	memset(f, 0, CM_TX_LEN);
	memset(f, 0xff, ETH_ALEN);
	memcpy(f + ETH_ALEN, src, ETH_ALEN);
	f[12] = CM_TX_ETHERTYPE >> 8;
	f[13] = CM_TX_ETHERTYPE & 0xff;
	f[14] = n;
	memset(d, 0, CM_DCB_BYTES);
	d[0] = (u32)cm.bus + CM_TXBUF;
	d[1] = CM_TX_LEN | CM_W1_HG;
	d[2] = 0xff000000;		/* stream-of-bytes module header, OpenMDK bmd_tx */
	d[4] = cmic_tx_port;
	dma_wmb();
	err = cm_wr_chk(sw, CM_DMA_DESC(0), (u32)cm.bus + CM_TXDCB) ? :
	      cm_wr(sw, CM_DMA_STAT, 0x80);
	if (err)
		return err;
	for (;;) {
		st = cm_rd(sw, CM_DMA_STAT);
		if (st & CM_ST_ERR) {
			cm.ch0_stuck = true;
			cm.tx_fail++;
			sw_fault(sw, "cmic: transmit, DMA_STAT 0x%08x", st);
			return -EIO;
		}
		if (st & CM_ST_DESC(0))
			break;
		if (ktime_after(ktime_get(), end)) {
			cm.ch0_stuck = true;
			cm.tx_fail++;
			dev_err(&sw->pdev->dev, "cmic: transmit %d not done, DMA_STAT 0x%08x\n", n, st);
			return -ETIMEDOUT;
		}
		udelay(10);
	}
	err = cm_clear_chan(sw, 0);
	if (err)
		return err;
	dma_rmb();
	/* DESC_DONE ends a transmit; the word in memory is only reported */
	cm.tx_ok++;
	if (!(READ_ONCE(d[10]) & CM_W10_DONE)) {
		cm.tx_nodone++;
		dev_info(&sw->pdev->dev, "cmic: transmit %d: descriptor word 10 0x%08x\n", n, READ_ONCE(d[10]));
	}
	return 0;
}

static int cm_tx_run(struct bcm53314 *sw)
{
	u32 mh = cm_rd(sw, CM_PKT_FROMCPU_MH), plain = cm_rd(sw, CM_PKT_FROMCPU);
	int i, err = 0;

	for (i = 0; i < cmic_tx_count && !err; i++)
		err = cm_tx_one(sw, i);
	dev_info(&sw->pdev->dev, "cmic: tx %lu to port %d: FROMCPU_MH 0x%08x -> 0x%08x, FROMCPU 0x%08x -> 0x%08x\n",
		 cm.tx_ok, cmic_tx_port, mh, cm_rd(sw, CM_PKT_FROMCPU_MH), plain, cm_rd(sw, CM_PKT_FROMCPU));
	return err;
}

/* ---- receive ------------------------------------------------------------- */

static u32 *cm_rxd(int n)
{
	return (u32 *)((u8 *)cm.mem + CM_RXDCB + n * CM_DCB_BYTES);
}

/* every descriptor of the stage, DONE clear; the last one ends the chain */
static void cm_rx_fill(void)
{
	int n = cm_rx_n(), i;

	for (i = 0; i < n; i++) {
		u32 *d = cm_rxd(i);

		memset(d, 0, CM_DCB_BYTES);
		d[0] = (u32)cm.bus + CM_RXBUF + i * CM_BUF;
		d[1] = CM_BUF | (i < n - 1 ? CM_W1_CHAIN : 0);
	}
	cm.rx_idx = 0;
	dma_wmb();
}

static void cm_rx_take(struct bcm53314 *sw, const u32 *d, const u8 *buf)
{
	u32 w10 = READ_ONCE(d[10]), len = min_t(u32, w10 & CM_W10_BYTES, CM_BUF);
	u32 w7 = READ_ONCE(d[7]), w9 = READ_ONCE(d[9]);
	int i;

	if (BIT(CM_W9_SRC_PORT(w9)) & CM_RX_SKIP_PORTS) {
		cm.rx_skip_cpu++;
		return;
	}
	cm.rx_frames++;
	if (w10 & CM_W10_ERROR)
		cm.rx_err++;
	if (!(w10 & CM_W10_END))
		cm.rx_split++;		/* does not fit one descriptor: dropped, counted (m8) */
	cm.rx_port[CM_W9_SRC_PORT(w9)]++;
	for (i = 0; i < 32; i++)
		if (w7 & CM_W7_REASON & BIT(i))
			cm.rx_reason[i]++;
	for (i = 0; i < CM_DCB_WORDS; i++)
		cm.last_dcb[i] = READ_ONCE(d[i]);
	cm.last_len = len;
	memcpy(cm.last_head, buf, min_t(u32, len, sizeof(cm.last_head)));
	if (cm.rx_frames <= 4)
		dev_info(&sw->pdev->dev, "cmic: rx %lu: %u bytes, port %lu, reason 0x%08x, VID %lu, untagged %d, BPDU %d, word 10 0x%08x\n",
			 cm.rx_frames, len, (unsigned long)CM_W9_SRC_PORT(w9), w7,
			 (unsigned long)CM_W9_VID(w9), !!(w9 & BIT(10)),
			 !!(READ_ONCE(d[6]) & CM_W6_BPDU), w10);
}

/* end of the chain, seen in memory: only here CMIC_DMA_STAT is read */
static void cm_rx_rearm(struct bcm53314 *sw)
{
	u32 st = cm_rd(sw, CM_DMA_STAT);

	if (st & CM_ST_ERR) {
		sw_fault(sw, "cmic: receive, DMA_STAT 0x%08x", st);
		return;
	}
	if (!(st & CM_ST_CHAIN(1))) {
		cm.rx_wait++;
		return;			/* not flagged yet: next pass */
	}
	if (cm_clear_chan(sw, 1))
		return;
	cm_rx_fill();
	if (cm_wr_chk(sw, CM_DMA_DESC(1), (u32)cm.bus + CM_RXDCB) ||
	    cm_wr(sw, CM_DMA_STAT, 0x81))
		return;
	cm.rx_rearm++;
}

static void cm_rx_drain(struct bcm53314 *sw)
{
	int n = cm_rx_n();

	while (cm.rx_idx < n) {
		const u32 *d = cm_rxd(cm.rx_idx);

		if (!(READ_ONCE(d[10]) & CM_W10_DONE))
			return;
		dma_rmb();
		cm_rx_take(sw, d, (const u8 *)cm.mem + CM_RXBUF + cm.rx_idx * CM_BUF);
		cm.rx_idx++;
	}
	if (cm.stage > 3 || !cm.rx_frames)
		cm_rx_rearm(sw);
}

static void cm_poll_fn(struct work_struct *work)
{
	struct bcm53314 *sw = cm.sw;

	mutex_lock(&cm.mtx);
	if (!cm.running)
		goto out;
	if (!READ_ONCE(sw->halted))
		cm_rx_drain(sw);
	if (READ_ONCE(sw->halted) ||
	    (cm.stage == 3 && (cm.rx_frames || ktime_after(ktime_get(), cm.rx_end)))) {
		if (cm.stage == 3 && !cm.rx_frames)
			dev_info(&sw->pdev->dev, "cmic: no frame in %d ms\n", cmic_rx_ms);
		cm_stop(sw);
		goto out;
	}
	schedule_delayed_work(&cm.poll, msecs_to_jiffies(1));
out:
	mutex_unlock(&cm.mtx);
}

/* D8-D11: channel first, then the port towards it, then what sends to it */
static int cm_rx_start(struct bcm53314 *sw)
{
	int i, n = cm.stage > 3 ? 2 : 1, err;
	u32 st;

	cm_rx_fill();
	err = cm_wr_chk(sw, CM_DMA_DESC(1), (u32)cm.bus + CM_RXDCB) ? :
	      cm_wr(sw, CM_DMA_STAT, 0x81);
	if (err)
		return err;
	cm.ch1_on = true;
	st = cm_rd(sw, CM_DMA_STAT);
	if (!(st & CM_ST_EN(1)) || (st & CM_ST_ERR)) {
		sw_fault(sw, "cmic: channel 1 not enabled, DMA_STAT 0x%08x", st);
		return -EIO;
	}
	mutex_lock(&sw->lock);
	err = cm_epc_set(sw, true) ? : cm_egr_set(sw, true);
	if (!err && cmic_cpu_vlan)
		err = cm_vlan_set(sw, O_EGR_VLAN, true) ? : cm_vlan_set(sw, O_VLAN_TAB, true);
	for (i = 0; i < n && !err; i++)
		if (i || cmic_rx_act)
			err = cm_l2u_set(sw, i, true);
	mutex_unlock(&sw->lock);
	return err;
}

/* ---- start --------------------------------------------------------------- */

/* D0-D3: reads only. Anything unexpected: nothing is written */
static int cm_guards(struct bcm53314 *sw)
{
	struct device *dev = &sw->pdev->dev;
	struct pci_dev *br = sw->pdev->bus->self;
	u16 cmd, status, brcmd;
	u32 rev, rst, ctrl, st, d0, d1, cfg, irq, endian, w[HW_L2U_WORDS];
	int i, err;

	if (access != 2) {
		dev_err(dev, "cmic: guard: access=%d\n", access);
		return -EPERM;
	}
	rev = cm_rd(sw, CMIC_DEV_REV_ID);
	rst = cm_rd(sw, CMIC_SOFT_RESET);
	if (rev != CM_DEV_REV || rst != SOFT_RESET_SET_UP) {
		dev_err(dev, "cmic: guard: revision 0x%08x, block reset 0x%08x\n", rev, rst);
		return -ENODEV;
	}
	if (!br) {
		dev_err(dev, "cmic: guard: no upstream bridge\n");
		return -ENODEV;
	}
	pci_read_config_word(sw->pdev, PCI_COMMAND, &cmd);
	pci_read_config_word(sw->pdev, PCI_STATUS, &status);
	pci_read_config_word(br, PCI_COMMAND, &brcmd);
	if (!(cmd & PCI_COMMAND_MEMORY) || !(cmd & PCI_COMMAND_MASTER) ||
	    !(brcmd & PCI_COMMAND_MASTER) ||
	    (status & (PCI_STATUS_REC_MASTER_ABORT | PCI_STATUS_SIG_SYSTEM_ERROR))) {
		dev_err(dev, "cmic: guard: PCI_COMMAND 0x%04x, PCI_STATUS 0x%04x, bridge PCI_COMMAND 0x%04x\n",
			cmd, status, brcmd);
		return -EPERM;
	}
	ctrl = cm_rd(sw, CM_DMA_CTRL);
	st = cm_rd(sw, CM_DMA_STAT);
	d0 = cm_rd(sw, CM_DMA_DESC(0));
	d1 = cm_rd(sw, CM_DMA_DESC(1));
	cfg = cm_rd(sw, CM_CONFIG);
	irq = cm_rd(sw, CMIC_IRQ_MASK);
	endian = cm_rd(sw, CM_ENDIAN);
	if (ctrl || (st & (CM_ST_CH01 | CM_ST_ERR)) || d0 || d1 || irq || endian ||
	    cfg != CM_CONFIG_BIOS) {
		dev_err(dev, "cmic: guard: DMA_CTRL 0x%08x, DMA_STAT 0x%08x, DESC 0x%08x 0x%08x, CONFIG 0x%08x, IRQ_MASK 0x%08x, ENDIANESS 0x%08x\n",
			ctrl, st, d0, d1, cfg, irq, endian);
		return -EBUSY;
	}
	mutex_lock(&sw->lock);
	err = READ_ONCE(sw->halted) ? -EIO : hw_read(sw, "EGR_ENABLE", CM_EGR_ENABLE0, false, 1, 0, w);
	if (!err && w[0]) {
		dev_err(dev, "cmic: guard: EGR_ENABLE[0] 0x%08x\n", w[0]);
		err = -EBUSY;
	}
	if (!err)
		err = sw_read(sw, O_EPC_LINK_BMAP, 0, w);
	if (!err) {
		cm.epc_orig = w[0];
		if (w[0] & BIT(0)) {
			dev_err(dev, "cmic: guard: EPC_LINK_BMAP 0x%08x\n", w[0]);
			err = -EBUSY;
		}
	}
	for (i = 0; i < 2 && !err && cm_is_rx(); i++) {
		err = hw_read(sw, "L2_USER_ENTRY", HW_L2U_ADDR + CM_L2U_IDX(i), true, HW_L2U_WORDS,
			      CM_L2U_IDX(i), w);
		if (!err && !hw_zero(w, HW_L2U_WORDS, 0)) {
			dev_err(dev, "cmic: guard: L2_USER_ENTRY[%d] in use\n", CM_L2U_IDX(i));
			err = -EBUSY;
		}
	}
	if (!err && cmic_cpu_vlan && cm_is_rx()) {
		int vid = bcm5331x_port_vid(CM_RX_PORT0);

		err = sw_read(sw, O_VLAN_TAB, vid, w);
		if (!err) {
			memcpy(cm.vt_orig, w, sizeof(cm.vt_orig));
			err = sw_read(sw, O_EGR_VLAN, vid, w);
		}
		if (!err) {
			memcpy(cm.ev_orig, w, sizeof(cm.ev_orig));
			if (!(VT_PBM(cm.vt_orig) & BIT(CM_RX_PORT0)) || (cm.vt_orig[0] & CM_VT_CMIC) ||
			    (cm.ev_orig[0] & CM_EV_CMIC)) {
				dev_err(dev, "cmic: guard: VLAN %d: VLAN_TAB 0x%08x, EGR_VLAN 0x%08x\n",
					vid, cm.vt_orig[0], cm.ev_orig[0]);
				err = -EBUSY;
			}
		}
	}
	mutex_unlock(&sw->lock);
	if (!err)
		dev_info(dev, "cmic: stage %d, PCI_COMMAND 0x%04x, bridge 0x%04x, EPC_LINK_BMAP 0x%08x\n",
			 cm.stage, cmd, brcmd, cm.epc_orig);
	return err;
}

/* under cm.mtx */
static void cm_bringup(struct bcm53314 *sw)
{
	int err;

	if (cm_guards(sw))
		return;
	cm.mem = dma_alloc_coherent(&sw->pdev->dev, CM_MEM, &cm.bus, GFP_KERNEL);
	if (!cm.mem) {
		dev_err(&sw->pdev->dev, "cmic: no coherent memory: nothing written\n");
		return;
	}
	if (upper_32_bits(cm.bus + CM_MEM - 1)) {
		dev_err(&sw->pdev->dev, "cmic: coherent memory above 4 GiB: nothing written\n");
		dma_free_coherent(&sw->pdev->dev, CM_MEM, cm.mem, cm.bus);
		cm.mem = NULL;
		return;
	}
	memset(cm.mem, 0, CM_MEM);
	dma_wmb();
	dev_info(&sw->pdev->dev, "cmic: block at bus address 0x%08x, %u bytes\n", (u32)cm.bus, (u32)CM_MEM);
	err = cm_clear_chan(sw, 0) ? : cm_clear_chan(sw, 1);
	if (!err && (cm_rd(sw, CM_DMA_STAT) & (CM_ST_CH01 | CM_ST_ERR))) {
		sw_fault(sw, "cmic: DMA_STAT not clear");
		err = -EIO;
	}
	err = err ? : cm_wr_chk(sw, CM_DMA_CTRL, CM_CTRL_RUN);
	if (!err && cm_is_tx())
		cm_tx_run(sw);
	if (!err && cm_is_rx())
		err = cm_rx_start(sw);
	if (err || !cm_is_rx()) {
		cm_stop(sw);
		return;
	}
	cm.rx_end = ktime_add_us(ktime_get(), 1000ULL * cmic_rx_ms);
	cm.running = true;
	schedule_delayed_work(&cm.poll, msecs_to_jiffies(1));
}

static void cm_shutdown(void)
{
	cancel_delayed_work_sync(&cm.poll);
	mutex_lock(&cm.mtx);
	if (cm.mem)
		cm_stop(cm.sw);
	mutex_unlock(&cm.mtx);
}

static int cm_reboot(struct notifier_block *nb, unsigned long action, void *data)
{
	cm_shutdown();
	return NOTIFY_DONE;
}

static struct notifier_block cm_nb = {
	.notifier_call = cm_reboot,
};

static void cm_show_tabs(struct seq_file *m, const char *when, const struct cm_tabs *t)
{
	int i, j;

	if (!t->ok)
		return;
	for (i = 0; i < 2; i++) {
		seq_printf(m, "l2u %s %d:", when, CM_L2U_IDX(i));
		for (j = 0; j < HW_L2U_WORDS; j++)
			seq_printf(m, " %08x", t->l2u[i][j]);
		seq_putc(m, '\n');
	}
	seq_printf(m, "vlan %s %d: VLAN_TAB %08x %08x EGR_VLAN %08x %08x PORT_TAB %08x %08x %08x\n",
		   when, bcm5331x_port_vid(CM_RX_PORT0), t->vt[0], t->vt[1], t->ev[0], t->ev[1],
		   t->pt[0], t->pt[1], t->pt[2]);
}

static int cm_show(struct seq_file *m, void *v)
{
	struct cm_tabs now = {};
	unsigned long i, n;

	mutex_lock(&cm.mtx);
	if (cm.mem && cm_is_rx()) {
		mutex_lock(&cm.sw->lock);
		cm_tabs_read(cm.sw, &now);
		mutex_unlock(&cm.sw->lock);
	}
	seq_printf(m, "stage %d running %d memory %d leaked %lu refused %lu writes %lu pci_err %lu\n",
		   cm.stage, cm.running, !!cm.mem, cm.leaked, cm.refused, cm.nw, cm.pci_err);
	seq_printf(m, "tx ok %lu fail %lu nodone %lu\nrx frames %lu err %lu split %lu rearm %lu wait %lu\n",
		   cm.tx_ok, cm.tx_fail, cm.tx_nodone, cm.rx_frames, cm.rx_err, cm.rx_split,
		   cm.rx_rearm, cm.rx_wait);
	seq_printf(m, "rx_skip_cpu %lu\n", cm.rx_skip_cpu);
	cm_show_tabs(m, "now", &now);
	cm_show_tabs(m, "stop", &cm.tabs_stop);
	for (i = 0; i < 32; i++)
		if (cm.rx_port[i])
			seq_printf(m, "port %lu: %lu\n", i, cm.rx_port[i]);
	for (i = 0; i < 32; i++)
		if (cm.rx_reason[i])
			seq_printf(m, "reason %lu: %lu\n", i, cm.rx_reason[i]);
	if (cm.rx_frames) {
		seq_printf(m, "last %u:", cm.last_len);
		for (i = 0; i < CM_DCB_WORDS; i++)
			seq_printf(m, " %08x", cm.last_dcb[i]);
		seq_puts(m, "\nhead:");
		for (i = 0; i < min_t(u32, cm.last_len, sizeof(cm.last_head)); i++)
			seq_printf(m, " %02x", cm.last_head[i]);
		seq_putc(m, '\n');
	}
	n = min_t(unsigned long, cm.nw, CM_WLOG);
	for (i = 0; i < n; i++)
		seq_printf(m, "w %03x %08x\n", cm.wl[i].off, cm.wl[i].val);
	mutex_unlock(&cm.mtx);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cm);

/* before anything is loaded: a refused combination writes nothing */
static int bcm5331x_cmic_param_check(void)
{
	if (cmic != 0 && cmic != 2) {
		pr_err("bcm5331x-dsa: cmic=%d: 0 or 2\n", cmic);
		return -EINVAL;
	}
	if (!cmic)
		return 0;
	if (cmic_stage < 1 || cmic_stage > 4 || !bcm5331x_is_front(cmic_tx_port) ||
	    cmic_tx_count < 1 || cmic_tx_count > 8 ||
	    cmic_rx_ms < 1000 || cmic_rx_ms > 120000) {
		pr_err("bcm5331x-dsa: cmic_stage, cmic_tx_port, cmic_tx_count or cmic_rx_ms out of range\n");
		return -EINVAL;
	}
	if (!cmic_rx_da || cmic_rx_da >> 48 || cmic_rx_vid < -1 || cmic_rx_vid > 4094 ||
	    cmic_rx_act < 0 || cmic_rx_act > 7 || cmic_cpu_vlan < 0 || cmic_cpu_vlan > 1) {
		pr_err("bcm5331x-dsa: cmic_rx_da, cmic_rx_vid, cmic_rx_act or cmic_cpu_vlan out of range\n");
		return -EINVAL;
	}
	if (cmic_stage >= 3 && (hwbridge || link_mode)) {
		pr_err("bcm5331x-dsa: cmic_stage=%d needs hwbridge=0 and link=0\n", cmic_stage);
		return -EINVAL;
	}
	return 0;
}

/* last step of the module load: a failure here leaves the DSA switch running */
static void bcm5331x_cmic_start(struct bcm53314 *sw)
{
	if (!cmic)
		return;
	mutex_init(&cm.mtx);
	INIT_DELAYED_WORK(&cm.poll, cm_poll_fn);
	cm.sw = sw;
	cm.stage = cmic_stage;
	debugfs_create_file("cmic", 0400, sw->dbg, NULL, &cm_fops);
	if (register_reboot_notifier(&cm_nb)) {
		dev_err(&sw->pdev->dev, "cmic: no reboot notifier: nothing written\n");
		return;
	}
	cm.notifier = true;
	mutex_lock(&cm.mtx);
	cm_bringup(sw);
	mutex_unlock(&cm.mtx);
}

/* first step of the module removal: everything stopped before the switch goes */
static void bcm5331x_cmic_exit(void)
{
	if (!cmic)
		return;
	if (cm.notifier)
		unregister_reboot_notifier(&cm_nb);
	cm.notifier = false;
	cm_shutdown();
}
