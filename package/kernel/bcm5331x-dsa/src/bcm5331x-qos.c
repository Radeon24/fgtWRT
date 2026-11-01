// SPDX-License-Identifier: GPL-2.0-only
/*
 * QoS of the BCM53314 DSA driver (module parameter qos),
 * #included by bcm5331x-dsa.c just before its operation table (same
 * translation unit: the CMIC/S-channel path, sw_fault and the front-port
 * helpers of the driver and of the base module are used as they are).
 *
 * Sources (no claim beyond them): OpenMDK
 * cdk/PKG/chip/bcm53314/bcm53314_a0_defs.h (addresses and fields of every
 * register and table below); OpenBCM sdk-6.5.16 src/bcm/esw/firebolt/cosq.c
 * (scheduler: COSARB 0 strict, 1 RR, 2 WRR, 3 DRR; DRR weights in quanta of
 * MTU_Quanta[MTU_QUANTA_SELECT] = 2048 << sel bytes, WEIGHT 0 = strict,
 * MTU_QUANTA_SELECT not written on this chip), firebolt/port.c
 * (bcm_fb_port_rate_egress_set: THD_SEL 0, REFRESH 0, bucket 0, then REFRESH
 * and THD_SEL; ING_PRI_CNG_MAP index port << 4 | pcp << 1 | cfi),
 * firebolt/meter.c (granularity 3 of this chip: REFRESH unit 64 kbit/s,
 * THD_SEL unit 4096 bytes), rate.c (meters of the storm control and of the
 * FP: REFRESHCOUNT x 64 kbit/s, BUCKETSIZE code 0-12 = 4 KiB << code).
 * Design notes below.
 *
 * Common engine (also used by the Field Processor, bcm5331x-fp.c): a
 * gesture computes the registers it changes as a list of operations (old
 * value, new value, bits the hardware keeps), the file's own check accepts
 * or refuses the whole list (only its own fields, only admitted ports,
 * bounded values) before any write, then each register is re-read (must
 * equal the last value known, else the module halts as the other
 * writers), written, read back (must equal the value written). Nothing is
 * written at load; the origin of each class of registers is read at its
 * first use, every removal and the teardown put the origin back.
 *
 * Never written by this file: the MMU thresholds (HOLCOS*, LWMCOS*, IBP*,
 * CNG*, DYNCELL*) and MISCCONFIG ("modify during traffic is an illegal
 * operation, will cause unrecoverable damage on MMU"), the number of
 * queues, WRRWEIGHT_COS.ENABLE (a queue disabled would mute the port), any
 * COS_SEL field outside 0-3 (queues 4-7 do not exist on this chip:
 * num_cos = 4).
 */

#define QF_WORDS		14	/* FP_TCAM: 422 bits */

struct qf_op {
	u8 cls;			/* class of the register, per file */
	u8 sub;			/* queue (COS) of a per-queue register */
	u8 words;
	bool mem;
	int idx;		/* port, entry...: label and check */
	u32 addr;
	const char *name;
	u32 *shadow;		/* last value known (updated after the write) */
	u32 old[QF_WORDS], val[QF_WORDS];
	u32 ign[QF_WORDS];	/* bits kept by the hardware: not compared */
};

typedef bool (*qf_check_t)(const struct bcm53314 *sw, const struct qf_op *op);

static int qf_rd(struct bcm53314 *sw, u32 addr, bool mem, int words, u32 *w,
		 const char *name, int idx)
{
	memset(w, 0, QF_WORDS * sizeof(*w));
	return schan_xfer(sw, false, mem, addr, words, w, name, idx);
}

static bool qf_same(const u32 *a, const u32 *b, const u32 *ign, int words)
{
	int j;

	for (j = 0; j < words; j++)
		if ((a[j] ^ b[j]) & ~ign[j])
			return false;
	return true;
}

/*
 * The plan is checked as a whole first (one refusal: nothing written),
 * then each register is re-read, written, read back (under sw->lock).
 */
static int qf_execute(struct bcm53314 *sw, struct device *dev, const char *what,
		      struct qf_op *ops, int n, qf_check_t check,
		      unsigned long *writes, unsigned long *refusals)
{
	int i, j, err;

	for (i = 0; i < n; i++)
		if (!check(sw, &ops[i])) {
			dev_err(dev, "%s: write %d/%d (%s[%d] class %d) refused: nothing written\n",
				what, i + 1, n, ops[i].name, ops[i].idx, ops[i].cls);
			(*refusals)++;
			return -EPERM;
		}
	for (i = 0; i < n; i++) {
		struct qf_op *op = &ops[i];
		u32 cur[QF_WORDS], rb[QF_WORDS];

		err = qf_rd(sw, op->addr, op->mem, op->words, cur, op->name, op->idx);
		if (err)
			return err;
		if (!qf_same(cur, op->old, op->ign, op->words)) {
			for (j = 0; j < op->words && !((cur[j] ^ op->old[j]) & ~op->ign[j]); j++)
				;
			sw_fault(sw, "dsa: %s %s[%d] word %d is %08x, expected %08x", what, op->name,
				 op->idx, j, cur[j], op->old[j]);
			return -ESTALE;
		}
		memcpy(rb, op->val, sizeof(rb));
		err = schan_xfer(sw, true, op->mem, op->addr, op->words, rb, op->name, op->idx);
		if (err)
			return err;
		udelay(10);
		err = qf_rd(sw, op->addr, op->mem, op->words, rb, op->name, op->idx);
		if (err)
			return err;
		(*writes)++;
		if (!qf_same(rb, op->val, op->ign, op->words)) {
			for (j = 0; j < op->words && !((rb[j] ^ op->val[j]) & ~op->ign[j]); j++)
				;
			sw_fault(sw, "dsa: %s %s[%d] word %d read back %08x, wrote %08x", what,
				 op->name, op->idx, j, rb[j], op->val[j]);
			return -EIO;
		}
		if (op->shadow)
			memcpy(op->shadow, op->val, op->words * sizeof(u32));
		dev_dbg(dev, "%s %s[%d] 0x%08x: %08x -> %08x\n", what, op->name, op->idx,
			op->addr, op->old[0], op->val[0]);
	}
	return 0;
}

/* even parity over bits 0..nbits-1 of w, written at bit nbits (kept on read-back) */
static __maybe_unused void qf_parity(u32 *w, int nbits)
{
	int b, ones = 0;

	for (b = 0; b < nbits; b++)
		ones += (w[b / 32] >> (b % 32)) & 1;
	w[nbits / 32] &= ~BIT(nbits % 32);
	if (ones & 1)
		w[nbits / 32] |= BIT(nbits % 32);
}

/* a field of up to 32 bits at bit lo of a multi-word entry */
static __maybe_unused void qf_put(u32 *w, int lo, int width, u32 v)
{
	int b;

	for (b = 0; b < width; b++) {
		u32 m = BIT((lo + b) % 32);

		if ((v >> b) & 1)
			w[(lo + b) / 32] |= m;
		else
			w[(lo + b) / 32] &= ~m;
	}
}

static __maybe_unused u32 qf_get(const u32 *w, int lo, int width)
{
	u32 v = 0;
	int b;

	for (b = 0; b < width; b++)
		v |= ((w[(lo + b) / 32] >> ((lo + b) % 32)) & 1) << b;
	return v;
}

/*
 * Rate conversions shared with the FP (granularity 3, firebolt/meter.c;
 * rate.c): a rate in bytes/s to a refresh count in units of 64 kbit/s
 * (rounded up), 0 if out of [1, max]; a burst in bytes to a bucket of
 * units of 4096 bytes (THD_SEL, at least 1) or to the code 0-12 of the
 * 4 KiB << code buckets; -1 when out of range.
 */
static __maybe_unused u32 qf_refresh(u64 rate_bytes_ps, u32 max)
{
	u64 kbps = div_u64(rate_bytes_ps * 8 + 999, 1000);
	u64 r = div_u64(kbps + 63, 64);

	return r >= 1 && r <= max ? (u32)r : 0;
}

static __maybe_unused int qf_thd(u32 burst_bytes, u32 max)
{
	u32 t = DIV_ROUND_UP(burst_bytes, 4096);

	if (!t)
		t = 1;
	return t <= max ? (int)t : -1;
}

static __maybe_unused int qf_bucket_code(u32 burst_bytes)
{
	int c;

	for (c = 0; c <= 12; c++)
		if (burst_bytes <= (4096u << c))
			return c;
	return -1;
}

/* ---------------------------------------------------------------------- */
/* Lot 9: registers                                                        */

/* OpenMDK bcm53314_a0_defs.h: per-port registers at port << 12, tables + index */
#define QS_A_DSCP(p, d)		(0x0c710000 + ((p) << 6) + (d))	/* DSCP_TABLE, 1600 x 12 bits */
#define QS_A_IPCM(p, i)		(0x04790000 + ((p) << 4) + (i))	/* ING_PRI_CNG_MAP, i = pcp << 1 | cfi */
#define QS_A_EPCM(i)		(0x05990000 + (i))		/* EGR_PRI_CNG_MAP, 800 (read only here) */
#define QS_A_COS_SEL(p)		(0x0f70010f | (p) << 12)
#define QS_A_XQCOSARB(p)	(0x00600061 | (p) << 12)
#define QS_A_WRR(p, c)		((0x00600062 + (c)) | (p) << 12)	/* c 0-7 */
#define QS_A_EGRMETER(p)	(0x0060006d | (p) << 12)
#define QS_A_EGRBUCKET(p)	(0x0060006e | (p) << 12)
#define QS_A_MINCFG(p, c)	((0x00600073 + (c)) | (p) << 12)	/* MINBUCKETCOS0..3CONFIG */
#define QS_A_MAXCFG(p, c)	((0x00600083 + (c)) | (p) << 12)	/* MAXBUCKETCONFIG, c 0-7 */
#define QS_A_MAXBUCKET(p, c)	((0x0060008b + (c)) | (p) << 12)
#define QS_A_BKPCFG(p)		(0x00600005 | (p) << 12)
#define QS_A_BKPEXT(p)		(0x006000a4 | (p) << 12)
#define QS_A_XQEMPTY(p)		(0x0060005e | (p) << 12)
#define QS_A_MISCCONFIG		0x00680012
#define QS_A_DSCP_PARCTL	0x0c780013			/* DSCP_TABLE_PARITY_CONTROL */
#define QS_A_STORM(k, p)	((0x0c700001 + (k)) | (p) << 12)	/* k 0 BCAST, 1 MCAST, 2 DLFBC */
#define QS_A_SCBYTE(p)		(0x0c70000b | (p) << 12)	/* SC_BYTE_METER_CONFIG */
#define QS_A_FPSC(k, p)		(0x0d780000 + 25 * (k) + (p))	/* FP_SC_{BCAST,MCAST,DLF}_METER_TABLE, 2 words */
#define QS_A_FP_SLICE_ENABLE	0x0d780007

/* PORT_TAB (3 words) */
#define QS_PT0_TRUST_V4		BIT(1)
#define QS_PT0_TRUST_V6		BIT(2)
#define QS_PT0_PORT_PRI		GENMASK(10, 8)
#define QS_PT1_MAP_TAG_PRI	BIT(1)		/* MAP_TAG_PKT_PRIORITY, bit 33 */
#define QS_PT1_USE_INNER_PRI	BIT(17)		/* bit 49 */
#define QS_PT1_USE_DOT1P	BIT(23)		/* USE_INCOMING_DOT1P, bit 55 */
/* DSCP_TABLE */
#define QS_DT_DSCP		GENMASK(5, 0)
#define QS_DT_PRI		GENMASK(8, 6)
#define QS_DT_CNG		GENMASK(10, 9)
#define QS_DT_PARITY		BIT(11)
/* ING_PRI_CNG_MAP */
#define QS_IM_CNG		GENMASK(1, 0)
#define QS_IM_PRI		GENMASK(4, 2)
/* XQCOSARBSEL, WRRWEIGHT_COS */
#define QS_ARB_COSARB		GENMASK(1, 0)
#define QS_ARB_QUANTA		GENMASK(3, 2)
#define QS_COSARB_STRICT	0
#define QS_COSARB_DRR		3
#define QS_WRR_WEIGHT		GENMASK(6, 0)
#define QS_WRR_ENABLE		BIT(7)
/* EGRMETERINGCONFIG, MAXBUCKETCONFIG: THD_SEL 11:0, REFRESH 29:12 */
#define QS_MT_THD		GENMASK(11, 0)
#define QS_MT_REFRESH		GENMASK(29, 12)
#define QS_MT_REFRESH_MAX	0x3ffff
#define QS_MT_THD_MAX		0xfff
#define QS_MISC_METERING_CLK	BIT(9)
#define QS_NUM_COS		4

/* classes of writes of this file */
enum { QS_PT, QS_DSCP, QS_IPCM, QS_COS_SEL, QS_ARB, QS_WRR, QS_EGRM, QS_EGRB,
       QS_MAXC, QS_MAXB, QS_STORM, QS_SCB, QS_FPSC };

#define QS_NOPS			160

static bool qos_on;
module_param_named(qos, qos_on, bool, 0644);
MODULE_PARM_DESC(qos, "Offload QoS to the switch: DCB default priority, DSCP priority and trust, tc ets, tbf (written at run time only, read back, origin restored at removal and at unload; may be set at run time; default N = no write; removals always run)");

static struct qf_op qs_ops[QS_NOPS];
static int qs_nops;
/* QoS writes done and read back, refusals: visible to debugfs */
static unsigned long bcm5331x_qos_writes, bcm5331x_qos_refusals;

/* the 19 front ports (MGMT and the CPU side never: no QoS write on them) */
static __maybe_unused bool qs_front(int port)
{
	return port > 0 && port < NUM_PORTS && port != PORT_MGMT && bcm5331x_is_front(port);
}

static struct qf_op *qs_new_op(int cls, int idx, u32 addr, bool mem, int words,
			       const char *name, u32 *shadow, const u32 *old)
{
	struct qf_op *op;

	if (qs_nops >= QS_NOPS)
		return NULL;
	op = &qs_ops[qs_nops++];
	memset(op, 0, sizeof(*op));
	op->cls = cls;
	op->idx = idx;
	op->addr = addr;
	op->mem = mem;
	op->words = words;
	op->name = name;
	op->shadow = shadow;
	memcpy(op->old, old, words * sizeof(u32));
	memcpy(op->val, old, words * sizeof(u32));
	return op;
}

/* one-word register or table entry: an op only if the value changes */
static __maybe_unused int qs_op1(int cls, int idx, u32 addr, bool mem, const char *name, u32 *shadow,
		  u32 val, u32 ign)
{
	struct qf_op *op;

	if (*shadow == val)
		return 0;
	op = qs_new_op(cls, idx, addr, mem, 1, name, shadow, shadow);
	if (!op)
		return -ENOSPC;
	op->val[0] = val;
	op->ign[0] = ign;
	return 0;
}

static int qs_rd1(struct bcm53314 *sw, u32 addr, bool mem, const char *name, int idx, u32 *v)
{
	u32 w[QF_WORDS];
	int err = qf_rd(sw, addr, mem, 1, w, name, idx);

	*v = w[0];
	return err;
}

static int qs_rd_pt(struct bcm53314 *sw, int port, u32 *w)
{
	return qf_rd(sw, obj_addr(&objs[O_PORT_TAB], port), true, 3, w, "PORT_TAB", port);
}

/* MISCCONFIG.METERING_CLK_EN: read once, never written; meters refused without it */
static int qs_misc_read;
static u32 qs_misc;

static __maybe_unused int qs_metering_ok(struct bcm53314 *sw)
{
	int err;

	if (!qs_misc_read) {
		err = qs_rd1(sw, QS_A_MISCCONFIG, false, "MISCCONFIG", 0, &qs_misc);
		if (err)
			return err;
		qs_misc_read = 1;
	}
	return qs_misc & QS_MISC_METERING_CLK ? 0 : -EOPNOTSUPP;
}

/* check of the writes: one case per class */
static bool qs_op_ok(const struct bcm53314 *sw, const struct qf_op *op);

static __maybe_unused int qs_run(struct bcm53314 *sw, struct device *dev)
{
	return qf_execute(sw, dev, "qos", qs_ops, qs_nops, qs_op_ok,
			  &bcm5331x_qos_writes, &bcm5331x_qos_refusals);
}

/* ---------------------------------------------------------------------- */
/* debugfs "qos": reads only                                               */

static void qs_show_port(struct seq_file *m, struct bcm53314 *sw, int p, int *err)
{
	u32 pt[QF_WORDS], v, w[QF_WORDS];
	int c;

	if (*err)
		return;
	*err = qs_rd_pt(sw, p, pt);
	if (*err)
		return;
	seq_printf(m, "p%-2d PORT_TAB %08x %08x %08x PRI %u TRUST v4 %u v6 %u MAPTAG %u INNER %u DOT1P %u",
		   p, pt[0], pt[1], pt[2], (u32)QQ_GET(QS_PT0_PORT_PRI, pt[0]),
		   !!(pt[0] & QS_PT0_TRUST_V4), !!(pt[0] & QS_PT0_TRUST_V6),
		   !!(pt[1] & QS_PT1_MAP_TAG_PRI), !!(pt[1] & QS_PT1_USE_INNER_PRI),
		   !!(pt[1] & QS_PT1_USE_DOT1P));
	*err = qs_rd1(sw, QS_A_COS_SEL(p), false, "COS_SEL", p, &v);
	if (!*err)
		seq_printf(m, " COS_SEL %08x", v);
	if (!*err)
		*err = qs_rd1(sw, QS_A_XQCOSARB(p), false, "XQCOSARBSEL", p, &v);
	if (!*err)
		seq_printf(m, " ARB %x", v);
	seq_puts(m, "\n    WRR");
	for (c = 0; c < 8 && !*err; c++) {
		*err = qs_rd1(sw, QS_A_WRR(p, c), false, "WRRWEIGHT_COS", p, &v);
		seq_printf(m, " %02x", v);
	}
	if (!*err)
		*err = qs_rd1(sw, QS_A_EGRMETER(p), false, "EGRMETERINGCONFIG", p, &v);
	if (!*err)
		seq_printf(m, " EGRM %08x", v);
	seq_puts(m, " MAX");
	for (c = 0; c < 8 && !*err; c++) {
		*err = qs_rd1(sw, QS_A_MAXCFG(p, c), false, "MAXBUCKETCONFIG", p, &v);
		seq_printf(m, " %08x", v);
	}
	seq_puts(m, "\n    MIN");
	for (c = 0; c < QS_NUM_COS && !*err; c++) {
		*err = qs_rd1(sw, QS_A_MINCFG(p, c), false, "MINBUCKETCOSCONFIG", p, &v);
		seq_printf(m, " %08x", v);
	}
	if (!*err)
		*err = qs_rd1(sw, QS_A_BKPCFG(p), false, "BKPMETERINGCONFIG", p, &v);
	if (!*err)
		seq_printf(m, " BKP %08x", v);
	if (!*err)
		*err = qs_rd1(sw, QS_A_BKPEXT(p), false, "BKPMETERINGCONFIG_EXT", p, &v);
	if (!*err)
		seq_printf(m, " BKPX %08x", v);
	if (!*err)
		*err = qs_rd1(sw, QS_A_XQEMPTY(p), false, "XQEMPTY", p, &v);
	if (!*err)
		seq_printf(m, " XQEMPTY %08x", v);
	seq_puts(m, " STORM");
	for (c = 0; c < 3 && !*err; c++) {
		*err = qs_rd1(sw, QS_A_STORM(c, p), false, "STORM_CONTROL", p, &v);
		seq_printf(m, " %08x", v);
	}
	if (!*err)
		*err = qs_rd1(sw, QS_A_SCBYTE(p), false, "SC_BYTE_METER_CONFIG", p, &v);
	if (!*err)
		seq_printf(m, " SCB %x FPSC", v);
	for (c = 0; c < 3 && !*err; c++) {
		*err = qf_rd(sw, QS_A_FPSC(c, p), true, 2, w, "FP_SC_METER_TABLE", p);
		seq_printf(m, " %08x:%08x", w[1], w[0]);
	}
	seq_puts(m, "\n    DSCP");
	for (c = 0; c < 64 && !*err; c++) {
		*err = qs_rd1(sw, QS_A_DSCP(p, c), true, "DSCP_TABLE", p, &v);
		seq_printf(m, " %03x", v);
	}
	seq_puts(m, "\n    IPCM");
	for (c = 0; c < 16 && !*err; c++) {
		*err = qs_rd1(sw, QS_A_IPCM(p, c), true, "ING_PRI_CNG_MAP", p, &v);
		seq_printf(m, " %02x", v);
	}
	seq_puts(m, "\n    EPCM");
	for (c = 0; c < 32 && !*err; c++) {
		*err = qs_rd1(sw, QS_A_EPCM((p << 5) + c), true, "EGR_PRI_CNG_MAP", p, &v);
		seq_printf(m, " %02x", v);
	}
	seq_putc(m, '\n');
}

static void qs_show_state(struct seq_file *m);

static int qs_show(struct seq_file *m, void *v)
{
	struct bcm53314 *sw = m->private;
	u32 misc = 0, par = 0, fpse = 0;
	int p, err;

	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : 0;
	if (!err)
		err = qs_rd1(sw, QS_A_MISCCONFIG, false, "MISCCONFIG", 0, &misc);
	if (!err)
		err = qs_rd1(sw, QS_A_DSCP_PARCTL, false, "DSCP_TABLE_PARITY_CONTROL", 0, &par);
	if (!err)
		err = qs_rd1(sw, QS_A_FP_SLICE_ENABLE, false, "FP_SLICE_ENABLE", 0, &fpse);
	if (!err) {
		seq_printf(m, "qos=%c writes=%lu refusals=%lu MISCCONFIG %08x (METERING_CLK_EN %u) DSCP_TABLE_PARITY_CONTROL %08x FP_SLICE_ENABLE %08x\n",
			   READ_ONCE(qos_on) ? 'Y' : 'N', bcm5331x_qos_writes, bcm5331x_qos_refusals,
			   misc, !!(misc & QS_MISC_METERING_CLK), par, fpse);
		qs_show_state(m);
	}
	for (p = 0; p < NUM_PORTS; p++)
		qs_show_port(m, sw, p, &err);
	mutex_unlock(&sw->lock);
	return err;
}
DEFINE_SHOW_ATTRIBUTE(qs);

/* ---------------------------------------------------------------------- */
/* Logical state and plan                                                  */

/*
 * What the gestures asked, per front port (-1 = origin): the plan of a
 * gesture is the difference between the registers this state calls for
 * and the values last known, in a fixed order: table values first, then
 * the triggers (PORT_TAB, scheduler) when a feature is turned on; the
 * reverse when it is turned off.
 */
static u32 qs_port_read;			/* front ports whose origin was read */
static u32 qs_pt0[NUM_PORTS][3];		/* PORT_TAB at origin */
static u32 qs_ptq[NUM_PORTS][3];		/* PORT_TAB as last read/written */
static s8 qs_prio[NUM_PORTS];			/* PORT_PRI asked, -1 = origin */
/* EGRMETERINGCONFIG (port shaper) at origin, as last known, asked (0 = origin) */
static u32 qs_egr0[NUM_PORTS], qs_egr[NUM_PORTS], qs_egr_want[NUM_PORTS];
static u32 qs_bucket_dummy;			/* buckets: written 0, value not kept */
/* DSCP_TABLE and ING_PRI_CNG_MAP of the port (origin, last known), DSCP priorities and trust asked */
static u32 qs_dscp0[NUM_PORTS][64], qs_dscp[NUM_PORTS][64];
static s8 qs_dscp_pri[NUM_PORTS][64];		/* -1 = origin */
static u32 qs_ipcm0[NUM_PORTS][16], qs_ipcm[NUM_PORTS][16];
#define QS_TR_DSCP		BIT(0)
#define QS_TR_PCP		BIT(1)
static s8 qs_trust[NUM_PORTS];			/* QS_TR_*, -1 = origin */
/*
 * 9d: scheduler of the port (XQCOSARBSEL, WRRWEIGHT_COS 0-3), per-queue
 * maximum shaper (MAXBUCKETCONFIG 0-3), priority -> queue map (COS_SEL of
 * the 25 ports, one map for all: set by the first ets, given back by the
 * last one).
 */
static u32 qs_arb0[NUM_PORTS], qs_arb[NUM_PORTS];
static u32 qs_wrr0[NUM_PORTS][QS_NUM_COS], qs_wrr[NUM_PORTS][QS_NUM_COS];
static u32 qs_maxc0[NUM_PORTS][QS_NUM_COS], qs_maxc[NUM_PORTS][QS_NUM_COS];
static u32 qs_maxc_want[NUM_PORTS][QS_NUM_COS];	/* 0 = origin */
static u32 qs_ets_on;				/* front ports with an offloaded ets */
static u32 qs_ets_handle[NUM_PORTS];
static u8 qs_ets_bands[NUM_PORTS];
static u8 qs_ets_cosarb[NUM_PORTS];		/* QS_COSARB_STRICT or _DRR */
static u8 qs_ets_w[NUM_PORTS][QS_NUM_COS];	/* DRR weight per queue, 0 = strict */
static bool qs_cos_read;
static u32 qs_cos0[NUM_PORTS], qs_cos[NUM_PORTS];
static u32 qs_cosmap;				/* COS0..7 fields (3 bits each, 0-3) */
#define QS_COS_FIELDS		GENMASK(23, 0)

/*
 * MAP_TAG_PKT_PRIORITY (PORT_TAB bit 33): accorded only if the trust of
 * the PCP needs it (assumed: ING_PRI_CNG_MAP may be
 * applied only with this bit set). Default N: never written; Y: set on a
 * port whose ING_PRI_CNG_MAP the driver changed, origin back with the map.
 */
static bool qos_maptag;
module_param(qos_maptag, bool, 0644);
MODULE_PARM_DESC(qos_maptag, "With qos=Y: also set PORT_TAB.MAP_TAG_PKT_PRIORITY on a port whose ING_PRI_CNG_MAP is changed (PCP untrusted); default N = never written");

static u32 qs_want_egr(int p)
{
	return qs_egr_want[p] ? qs_egr_want[p] : qs_egr0[p];
}

static u32 qs_want_maxc(int p, int c)
{
	return qs_maxc_want[p][c] ? qs_maxc_want[p][c] : qs_maxc0[p][c];
}

/* COS_SEL of any port: the map of the ets while one is offloaded, else origin */
static u32 qs_want_cos(int q)
{
	return qs_ets_on ? (qs_cos0[q] & ~QS_COS_FIELDS) | qs_cosmap : qs_cos0[q];
}

static u32 qs_want_arb(int p)
{
	if (!(qs_ets_on & BIT(p)))
		return qs_arb0[p];
	return (qs_arb0[p] & ~QS_ARB_COSARB) | QQ_PUT(QS_ARB_COSARB, qs_ets_cosarb[p]);
}

/* weights only in DRR, on the queues of the bands; ENABLE never changed */
static u32 qs_want_wrr(int p, int c)
{
	if (!(qs_ets_on & BIT(p)) || qs_ets_cosarb[p] != QS_COSARB_DRR || c < QS_NUM_COS - qs_ets_bands[p])
		return qs_wrr0[p][c];
	return (qs_wrr0[p][c] & ~QS_WRR_WEIGHT) | QQ_PUT(QS_WRR_WEIGHT, qs_ets_w[p][c]);
}

static bool qs_cosmap_ok(u32 v)
{
	int i;

	for (i = 0; i < 8; i++)
		if (((v >> (3 * i)) & 7) > QS_NUM_COS - 1)
			return false;
	return !(v & ~QS_COS_FIELDS);
}

static void qs_show_state(struct seq_file *m)
{
	int p;

	seq_printf(m, "origin read 0x%08x ets ports 0x%08x map %06x\n", qs_port_read, qs_ets_on, qs_cosmap);
	for (p = 0; p < NUM_PORTS; p++)
		if (qs_port_read & BIT(p))
			seq_printf(m, "p%-2d prio %d trust %d egr %08x (origin %08x)\n", p, qs_prio[p], qs_trust[p],
				   qs_want_egr(p), qs_egr0[p]);
}

/* the QoS bits of PORT_TAB (words 0 and 1) */
static u32 qs_pt_mask(int w)
{
	return w == 0 ? QS_PT0_PORT_PRI | QS_PT0_TRUST_V4 | QS_PT0_TRUST_V6 : w == 1 ? QS_PT1_MAP_TAG_PRI : 0;
}

static int qs_effective_prio(int p)
{
	return qs_prio[p] >= 0 ? qs_prio[p] : (int)QQ_GET(QS_PT0_PORT_PRI, qs_pt0[p][0]);
}

/* trust at origin: DSCP if TRUST_DSCP_V4 or _V6, the PCP always */
static int qs_trust0(int p)
{
	return QS_TR_PCP | (qs_pt0[p][0] & (QS_PT0_TRUST_V4 | QS_PT0_TRUST_V6) ? QS_TR_DSCP : 0);
}

static int qs_effective_trust(int p)
{
	return qs_trust[p] >= 0 ? qs_trust[p] : qs_trust0(p);
}

/*
 * DSCP_TABLE of a port: "New Diff Serv Code Point", PRI, CNG (OpenMDK);
 * the SDK (bcm_port_dscp_map_set, firebolt/port.c: TRUST_DSCP_V4 =
 * pc_dse_mode, the DSCP map mode) writes DSCP = the new code point of
 * the packet. The BIOS leaves every entry at 0: with
 * the DSCP trusted as found, every packet of the port would leave with
 * DSCP 0. So the table is driven as a whole as soon as a DSCP priority is
 * asked or the DSCP trust is turned on: the 64 entries of the port get
 * DSCP = index (no rewrite), PRI = the DSCP priority asked or else the
 * port priority, CNG of origin, even parity; back to origin as a whole
 * when neither remains.
 */
static bool qs_dscp_driven(int p)
{
	int d;

	if (qs_trust[p] >= 0 && (qs_trust[p] & QS_TR_DSCP))
		return true;
	for (d = 0; d < 64; d++)
		if (qs_dscp_pri[p][d] >= 0)
			return true;
	return false;
}

static u32 qs_want_dscp(int p, int d)
{
	int pri = qs_dscp_pri[p][d] >= 0 ? qs_dscp_pri[p][d] : qs_effective_prio(p);
	u32 v;

	if (!qs_dscp_driven(p))
		return qs_dscp0[p][d];
	v = (qs_dscp0[p][d] & QS_DT_CNG) | QQ_PUT(QS_DT_DSCP, d) | QQ_PUT(QS_DT_PRI, pri);
	qf_parity(&v, 11);
	return v;
}

/* ING_PRI_CNG_MAP entry: origin while the PCP is trusted, else PRI = the port priority (CNG of origin) */
static u32 qs_want_ipcm(int p, int i)
{
	if (qs_effective_trust(p) & QS_TR_PCP)
		return qs_ipcm0[p][i];
	return (qs_ipcm0[p][i] & ~QS_IM_PRI) | QQ_PUT(QS_IM_PRI, qs_effective_prio(p));
}

static bool qs_ipcm_changed(int p)
{
	int i;

	for (i = 0; i < 16; i++)
		if (qs_want_ipcm(p, i) != qs_ipcm0[p][i])
			return true;
	return false;
}

/* PORT_TAB as the state calls for, from the value read now (other writers' bits kept) */
static void qs_want_pt(int p, const u32 *cur, u32 *want)
{
	u32 tr = qs_pt0[p][0] & (QS_PT0_TRUST_V4 | QS_PT0_TRUST_V6);
	u32 maptag = qs_pt0[p][1] & QS_PT1_MAP_TAG_PRI;

	if (qs_trust[p] >= 0)
		tr = qs_trust[p] & QS_TR_DSCP ? QS_PT0_TRUST_V4 | QS_PT0_TRUST_V6 : 0;
	if (READ_ONCE(qos_maptag) && qs_ipcm_changed(p))
		maptag = QS_PT1_MAP_TAG_PRI;
	memcpy(want, cur, 3 * sizeof(u32));
	want[0] = (want[0] & ~(QS_PT0_PORT_PRI | QS_PT0_TRUST_V4 | QS_PT0_TRUST_V6)) |
		  QQ_PUT(QS_PT0_PORT_PRI, qs_effective_prio(p)) | tr;
	want[1] = (want[1] & ~QS_PT1_MAP_TAG_PRI) | maptag;
}

/* origin of a front port (first gesture on it) */
static int qs_origin_port(struct bcm53314 *sw, int p)
{
	u32 w[QF_WORDS];
	int err, i;

	if (qs_port_read & BIT(p))
		return 0;
	err = qs_rd_pt(sw, p, w);
	if (err)
		return err;
	memcpy(qs_pt0[p], w, sizeof(qs_pt0[p]));
	memcpy(qs_ptq[p], w, sizeof(qs_ptq[p]));
	err = qs_rd1(sw, QS_A_EGRMETER(p), false, "EGRMETERINGCONFIG", p, &qs_egr0[p]);
	if (err)
		return err;
	for (i = 0; i < 64 && !err; i++)
		err = qs_rd1(sw, QS_A_DSCP(p, i), true, "DSCP_TABLE", p, &qs_dscp0[p][i]);
	for (i = 0; i < 16 && !err; i++)
		err = qs_rd1(sw, QS_A_IPCM(p, i), true, "ING_PRI_CNG_MAP", p, &qs_ipcm0[p][i]);
	if (err)
		return err;
	err = qs_rd1(sw, QS_A_XQCOSARB(p), false, "XQCOSARBSEL", p, &qs_arb0[p]);
	for (i = 0; i < QS_NUM_COS && !err; i++)
		err = qs_rd1(sw, QS_A_WRR(p, i), false, "WRRWEIGHT_COS", p, &qs_wrr0[p][i]);
	for (i = 0; i < QS_NUM_COS && !err; i++)
		err = qs_rd1(sw, QS_A_MAXCFG(p, i), false, "MAXBUCKETCONFIG", p, &qs_maxc0[p][i]);
	if (err)
		return err;
	qs_arb[p] = qs_arb0[p];
	memcpy(qs_wrr[p], qs_wrr0[p], sizeof(qs_wrr[p]));
	memcpy(qs_maxc[p], qs_maxc0[p], sizeof(qs_maxc[p]));
	memset(qs_maxc_want[p], 0, sizeof(qs_maxc_want[p]));
	memcpy(qs_dscp[p], qs_dscp0[p], sizeof(qs_dscp[p]));
	memcpy(qs_ipcm[p], qs_ipcm0[p], sizeof(qs_ipcm[p]));
	memset(qs_dscp_pri[p], -1, sizeof(qs_dscp_pri[p]));
	qs_trust[p] = -1;
	qs_egr[p] = qs_egr0[p];
	qs_egr_want[p] = 0;
	qs_prio[p] = -1;
	qs_port_read |= BIT(p);
	return 0;
}

/*
 * PORT_TAB is shared with the other writers (hwbridge, vlanbr, qinq, fdb,
 * mirror): read at the plan, only the QoS bits change; the QoS bits
 * found different from the last ones known = another writer touched them:
 * fault, module halted, nothing written.
 */
static int qs_plan_pt(struct bcm53314 *sw, int p)
{
	u32 cur[QF_WORDS], want[3];
	struct qf_op *op;
	int err, j;

	err = qs_rd_pt(sw, p, cur);
	if (err)
		return err;
	for (j = 0; j < 2; j++)
		if ((cur[j] ^ qs_ptq[p][j]) & qs_pt_mask(j)) {
			sw_fault(sw, "dsa: qos PORT_TAB[%d] word %d is %08x, QoS bits expected as %08x", p, j,
				 cur[j], qs_ptq[p][j]);
			return -ESTALE;
		}
	memcpy(qs_ptq[p], cur, sizeof(qs_ptq[p]));
	qs_want_pt(p, cur, want);
	if (!memcmp(cur, want, sizeof(want)))
		return 0;
	op = qs_new_op(QS_PT, p, obj_addr(&objs[O_PORT_TAB], p), true, 3, "PORT_TAB", qs_ptq[p], cur);
	if (!op)
		return -ENOSPC;
	memcpy(op->val, want, sizeof(want));
	return 0;
}

/*
 * A meter (EGRMETERINGCONFIG of a port, MAXBUCKETCONFIG of a queue) from
 * its last value to the one asked, in the order of the SDK
 * (bcm_fb_port_rate_egress_set): THD_SEL to 0 (metering off), bucket to 0,
 * REFRESH with THD_SEL 0, then THD_SEL. Every step but the bucket is an
 * exact value of the register (bits outside THD_SEL and REFRESH kept);
 * the bucket counts traffic, it is re-read and read back, not compared.
 */
static int qs_plan_meter(int cls, int bcls, int p, int c, u32 addr, u32 baddr, const char *name,
			 const char *bname, u32 *shadow, u32 want)
{
	u32 v = *shadow, step;
	struct qf_op *op;

	if (v == want)
		return 0;
	if (v & QS_MT_THD) {
		step = v & ~QS_MT_THD;
		op = qs_new_op(cls, p, addr, false, 1, name, shadow, &v);
		if (!op)
			return -ENOSPC;
		op->sub = c;
		op->val[0] = step;
		v = step;
	}
	op = qs_new_op(bcls, p, baddr, false, 1, bname, NULL, &qs_bucket_dummy);
	if (!op)
		return -ENOSPC;
	op->sub = c;
	op->val[0] = 0;
	op->ign[0] = ~0u;
	step = (v & ~QS_MT_REFRESH) | (want & QS_MT_REFRESH);
	if (step != v) {
		op = qs_new_op(cls, p, addr, false, 1, name, shadow, &v);
		if (!op)
			return -ENOSPC;
		op->sub = c;
		op->val[0] = step;
		v = step;
	}
	if (want & QS_MT_THD) {
		op = qs_new_op(cls, p, addr, false, 1, name, shadow, &v);
		if (!op)
			return -ENOSPC;
		op->sub = c;
		op->val[0] = want;
	}
	return 0;
}

/* the writes of port p (and the shared registers) from the values known to the state */
static int qs_plan_port(struct bcm53314 *sw, int p, bool on)
{
	static const u8 up[] = { QS_DSCP, QS_IPCM, QS_COS_SEL, QS_WRR, QS_PT, QS_ARB, QS_MAXC, QS_EGRM };
	int i, j, err = 0;

	for (i = 0; i < (int)ARRAY_SIZE(up) && !err; i++) {
		switch (up[on ? i : ARRAY_SIZE(up) - 1 - i]) {
		case QS_DSCP:
			for (j = 0; j < 64 && !err; j++) {
				err = qs_op1(QS_DSCP, p, QS_A_DSCP(p, j), true, "DSCP_TABLE", &qs_dscp[p][j],
					     qs_want_dscp(p, j), QS_DT_PARITY);
				if (!err && qs_nops && qs_ops[qs_nops - 1].shadow == &qs_dscp[p][j])
					qs_ops[qs_nops - 1].sub = j;
			}
			break;
		case QS_IPCM:
			for (j = 0; j < 16 && !err; j++) {
				err = qs_op1(QS_IPCM, p, QS_A_IPCM(p, j), true, "ING_PRI_CNG_MAP", &qs_ipcm[p][j],
					     qs_want_ipcm(p, j), 0);
				if (!err && qs_nops && qs_ops[qs_nops - 1].shadow == &qs_ipcm[p][j])
					qs_ops[qs_nops - 1].sub = j;
			}
			break;
		case QS_COS_SEL:
			for (j = 0; j < NUM_PORTS && !err && qs_cos_read; j++)
				err = qs_op1(QS_COS_SEL, j, QS_A_COS_SEL(j), false, "COS_SEL", &qs_cos[j],
					     qs_want_cos(j), 0);
			break;
		case QS_WRR:
			for (j = 0; j < QS_NUM_COS && !err; j++) {
				err = qs_op1(QS_WRR, p, QS_A_WRR(p, j), false, "WRRWEIGHT_COS", &qs_wrr[p][j],
					     qs_want_wrr(p, j), 0);
				if (!err && qs_nops && qs_ops[qs_nops - 1].shadow == &qs_wrr[p][j])
					qs_ops[qs_nops - 1].sub = j;
			}
			break;
		case QS_ARB:
			err = qs_op1(QS_ARB, p, QS_A_XQCOSARB(p), false, "XQCOSARBSEL", &qs_arb[p],
				     qs_want_arb(p), 0);
			break;
		case QS_MAXC:
			for (j = 0; j < QS_NUM_COS && !err; j++)
				err = qs_plan_meter(QS_MAXC, QS_MAXB, p, j, QS_A_MAXCFG(p, j), QS_A_MAXBUCKET(p, j),
						    "MAXBUCKETCONFIG", "MAXBUCKET", &qs_maxc[p][j], qs_want_maxc(p, j));
			break;
		case QS_PT:
			err = qs_plan_pt(sw, p);
			break;
		case QS_EGRM:
			err = qs_plan_meter(QS_EGRM, QS_EGRB, p, 0, QS_A_EGRMETER(p), QS_A_EGRBUCKET(p),
					    "EGRMETERINGCONFIG", "EGRMETERINGBUCKET", &qs_egr[p], qs_want_egr(p));
			break;
		}
	}
	return err;
}

/*
 * A meter write: only THD_SEL and REFRESH change; THD_SEL 0 (metering
 * off, any REFRESH within bounds) or the value asked or the origin; a
 * value with THD_SEL set comes after the bucket zeroed in the same plan,
 * with only THD_SEL-0 writes of the same meter in between.
 */
static bool qs_meter_ok(const struct qf_op *op, int bcls, u32 want, u32 origin)
{
	const struct qf_op *q;
	u32 v = op->val[0];

	if (op->words != 1 || op->mem || ((op->old[0] ^ v) & ~(QS_MT_THD | QS_MT_REFRESH)))
		return false;
	if (!(v & QS_MT_THD))
		return (v & QS_MT_REFRESH) == (op->old[0] & QS_MT_REFRESH) ||
		       (v & QS_MT_REFRESH) == (want & QS_MT_REFRESH) ||
		       (v & QS_MT_REFRESH) == (origin & QS_MT_REFRESH);
	if (v != want && v != origin)
		return false;
	for (q = op - 1; q >= qs_ops; q--) {
		if (q->idx != op->idx || q->sub != op->sub)
			continue;
		if (q->cls == bcls)
			return q->val[0] == 0;
		if (q->cls != op->cls || (q->val[0] & QS_MT_THD))
			return false;
	}
	return false;
}

static bool qs_storm_op_ok(const struct qf_op *op);

/* The one change each QoS write may make, from the state alone (whole plan checked first) */
static bool qs_op_ok(const struct bcm53314 *sw, const struct qf_op *op)
{
	int p = op->idx, j;
	u32 want[3];

	switch (op->cls) {
	case QS_PT:
		if (!qs_front(p) || !(qs_port_read & BIT(p)) || op->words != 3 || !op->mem ||
		    op->addr != obj_addr(&objs[O_PORT_TAB], p))
			return false;
		for (j = 0; j < 3; j++)
			if ((op->old[j] ^ op->val[j]) & ~qs_pt_mask(j))
				return false;	/* only the QoS bits */
		qs_want_pt(p, op->old, want);
		return !memcmp(want, op->val, sizeof(want));
	case QS_DSCP:
		/* DSCP (= the index: no rewrite) and PRI only, CNG kept, parity recomputed (not compared) */
		if (!qs_front(p) || !(qs_port_read & BIT(p)) || op->sub > 63 || !op->mem || op->words != 1 ||
		    op->addr != QS_A_DSCP(p, op->sub) || op->ign[0] != QS_DT_PARITY ||
		    ((op->old[0] ^ op->val[0]) & ~(QS_DT_DSCP | QS_DT_PRI | QS_DT_PARITY)))
			return false;
		if (op->val[0] != qs_dscp0[p][op->sub] && QQ_GET(QS_DT_DSCP, op->val[0]) != op->sub)
			return false;
		return !((op->val[0] ^ qs_want_dscp(p, op->sub)) & ~QS_DT_PARITY);
	case QS_IPCM:
		return qs_front(p) && (qs_port_read & BIT(p)) && op->sub < 16 && op->mem && op->words == 1 &&
		       op->addr == QS_A_IPCM(p, op->sub) && !((op->old[0] ^ op->val[0]) & ~QS_IM_PRI) &&
		       op->val[0] == qs_want_ipcm(p, op->sub);
	case QS_COS_SEL:
		/* the 25 ports (the queue is chosen at ingress), fields 0-3 only (no queue 4-7) */
		if (p < 0 || p >= NUM_PORTS || !qs_cos_read || op->mem || op->words != 1 ||
		    op->addr != QS_A_COS_SEL(p) || ((op->old[0] ^ op->val[0]) & ~QS_COS_FIELDS))
			return false;
		if (op->val[0] != qs_cos0[p] && !qs_cosmap_ok(op->val[0] & QS_COS_FIELDS))
			return false;
		return op->val[0] == qs_want_cos(p);
	case QS_ARB:
		if (!qs_front(p) || !(qs_port_read & BIT(p)) || op->mem || op->words != 1 ||
		    op->addr != QS_A_XQCOSARB(p) || ((op->old[0] ^ op->val[0]) & ~QS_ARB_COSARB))
			return false;
		if (op->val[0] != qs_arb0[p] && QQ_GET(QS_ARB_COSARB, op->val[0]) != QS_COSARB_STRICT &&
		    QQ_GET(QS_ARB_COSARB, op->val[0]) != QS_COSARB_DRR)
			return false;
		return op->val[0] == qs_want_arb(p);
	case QS_WRR:
		/* WEIGHT only: ENABLE is never written (a queue disabled mutes the port) */
		return qs_front(p) && (qs_port_read & BIT(p)) && op->sub < QS_NUM_COS && !op->mem &&
		       op->words == 1 && op->addr == QS_A_WRR(p, op->sub) &&
		       !((op->old[0] ^ op->val[0]) & ~QS_WRR_WEIGHT) && op->val[0] == qs_want_wrr(p, op->sub);
	case QS_MAXC:
		return qs_front(p) && (qs_port_read & BIT(p)) && op->sub < QS_NUM_COS &&
		       op->addr == QS_A_MAXCFG(p, op->sub) &&
		       qs_meter_ok(op, QS_MAXB, qs_want_maxc(p, op->sub), qs_maxc0[p][op->sub]);
	case QS_MAXB:
		return qs_front(p) && (qs_port_read & BIT(p)) && op->sub < QS_NUM_COS &&
		       op->addr == QS_A_MAXBUCKET(p, op->sub) && op->words == 1 && !op->mem && op->val[0] == 0;
	case QS_EGRM:
		return qs_front(p) && (qs_port_read & BIT(p)) && op->sub == 0 &&
		       op->addr == QS_A_EGRMETER(p) && qs_meter_ok(op, QS_EGRB, qs_want_egr(p), qs_egr0[p]);
	case QS_EGRB:
		return qs_front(p) && (qs_port_read & BIT(p)) && op->sub == 0 &&
		       op->addr == QS_A_EGRBUCKET(p) && op->words == 1 && !op->mem && op->val[0] == 0;
	case QS_STORM:
	case QS_SCB:
	case QS_FPSC:
		return qs_storm_op_ok(op);
	}
	return false;
}

/*
 * Common prologue of a gesture on port p. Returns 1 for a removal with
 * nothing to undo (origin never read), 0 with sw->lock held and the
 * origin of the port read, < 0 on a refusal (no access made, lock free).
 */
static int qs_begin(struct bcm53314 *sw, int p, bool add, struct netlink_ext_ack *extack)
{
	int err;

	if (!qs_front(p)) {
		NL_SET_ERR_MSG_MOD(extack, "QoS offload on the front ports only");
		return -EOPNOTSUPP;
	}
	if (!add && !(READ_ONCE(qs_port_read) & BIT(p)))
		return 1;
	if (add && !READ_ONCE(qos_on)) {
		NL_SET_ERR_MSG_MOD(extack, "QoS offload off (module parameter qos=0)");
		return -EOPNOTSUPP;
	}
	if (access != 2 || dry_run)
		return -EPERM;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : qs_origin_port(sw, p);
	if (err)
		mutex_unlock(&sw->lock);
	return err;
}

/* plan of port p, then the writes; the state is put back by the caller on an error */
static int qs_apply(struct bcm53314 *sw, struct device *dev, int p, bool on)
{
	int err;

	qs_nops = 0;
	err = qs_plan_port(sw, p, on);
	if (!err)
		err = qs_run(sw, dev);
	return err;
}

/* ---------------------------------------------------------------------- */
/* default priority of a port (DCB app default-prio)                       */

/*
 * dcb app add dev portN default-prio P -> PORT_TAB[p].PORT_PRI = P. DSA
 * reads it at the creation of the user port (dsa_user_dcbnl_init: a
 * negative value fails the port): with qos=N and the port untouched the
 * answer is 0 with no access (nothing at load); else the priority in
 * force. A removal is a set to 0 by DSA: 0 gives the origin back.
 */
static int bcm5331x_dsa_port_get_default_prio(struct dsa_switch *ds, int port)
{
	struct bcm53314 *sw = ds->priv;
	int prio = 0;

	if (!qs_front(port) || access < 1)
		return 0;
	if (!(READ_ONCE(qs_port_read) & BIT(port)) && !READ_ONCE(qos_on))
		return 0;
	mutex_lock(&sw->lock);
	if (!sw->halted && !qs_origin_port(sw, port))
		prio = qs_effective_prio(port);
	mutex_unlock(&sw->lock);
	return prio;
}

static int bcm5331x_dsa_port_set_default_prio(struct dsa_switch *ds, int port, u8 prio)
{
	struct bcm53314 *sw = ds->priv;
	s8 was;
	int err;

	if (prio > 7)
		return -EINVAL;
	err = qs_begin(sw, port, prio != 0, NULL);
	if (err)
		return err > 0 ? 0 : err;
	was = qs_prio[port];
	qs_prio[port] = prio ? (s8)prio : -1;
	err = qs_apply(sw, ds->dev, port, prio != 0);
	if (err)
		qs_prio[port] = was;
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "qos: port %d default priority %u failed (%d)\n", port, prio, err);
	return err;
}

/* ---------------------------------------------------------------------- */
/* DSCP priority and trust (DCB app dscp-prio, apptrust)                   */

/*
 * dcb app add dev portN dscp-prio D:P -> DSCP_TABLE[p << 6 | D].PRI = P
 * (the table is per ingress port: dscp_prio_mapping_is_global stays
 * false); the 64 entries of the port are driven together, DSCP = index
 * (see qs_dscp_driven). dcb apptrust set dev portN order ...: {}, {pcp},
 * {dscp}, {dscp pcp} (the hardware takes the DSCP before the PCP; {pcp
 * dscp} is refused): DSCP trusted = TRUST_DSCP_V4 and _V6 of PORT_TAB;
 * PCP not trusted = the 16 entries of ING_PRI_CNG_MAP of the port give
 * the port priority (PCP trusted = the map of origin).
 */
static int bcm5331x_dsa_port_get_dscp_prio(struct dsa_switch *ds, int port, u8 dscp)
{
	struct bcm53314 *sw = ds->priv;
	int err;

	if (!qs_front(port) || dscp > 63 || access < 1)
		return -EOPNOTSUPP;
	if (!(READ_ONCE(qs_port_read) & BIT(port)) && !READ_ONCE(qos_on))
		return -EOPNOTSUPP;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : qs_origin_port(sw, port);
	/* the priority of the entry in force: asked, else the port's while the table is driven, else origin */
	if (!err)
		err = qs_dscp_pri[port][dscp] >= 0 ? qs_dscp_pri[port][dscp] :
		      qs_dscp_driven(port) ? qs_effective_prio(port) :
		      (int)QQ_GET(QS_DT_PRI, qs_dscp0[port][dscp]);
	mutex_unlock(&sw->lock);
	return err;
}

static int qs_dscp_set(struct dsa_switch *ds, int port, u8 dscp, int prio)
{
	struct bcm53314 *sw = ds->priv;
	bool add = prio >= 0;
	s8 was;
	int err;

	if (dscp > 63 || prio > 7)
		return -EINVAL;
	err = qs_begin(sw, port, add, NULL);
	if (err)
		return err > 0 ? 0 : err;
	was = qs_dscp_pri[port][dscp];
	qs_dscp_pri[port][dscp] = add ? (s8)prio : -1;
	err = qs_apply(sw, ds->dev, port, add);
	if (err)
		qs_dscp_pri[port][dscp] = was;
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "qos: port %d DSCP %u priority %d failed (%d)\n", port, dscp, prio, err);
	return err;
}

static int bcm5331x_dsa_port_add_dscp_prio(struct dsa_switch *ds, int port, u8 dscp, u8 prio)
{
	return qs_dscp_set(ds, port, dscp, prio);
}

static int bcm5331x_dsa_port_del_dscp_prio(struct dsa_switch *ds, int port, u8 dscp, u8 prio)
{
	return qs_dscp_set(ds, port, dscp, -1);
}

static int bcm5331x_dsa_port_set_apptrust(struct dsa_switch *ds, int port, const u8 *sel, int nsel)
{
	struct bcm53314 *sw = ds->priv;
	int trust = 0, i, err;
	bool add;
	s8 was;

	for (i = 0; i < nsel; i++) {
		if (sel[i] == IEEE_8021QAZ_APP_SEL_DSCP && !(trust & QS_TR_DSCP) && !(trust & QS_TR_PCP))
			trust |= QS_TR_DSCP;
		else if (sel[i] == DCB_APP_SEL_PCP && !(trust & QS_TR_PCP))
			trust |= QS_TR_PCP;
		else
			return -EOPNOTSUPP;	/* other selector, repeat, or PCP before DSCP */
	}
	if (!qs_front(port))
		return -EOPNOTSUPP;
	/* back to the trust of origin = a removal (also with qos=N) */
	add = !(READ_ONCE(qs_port_read) & BIT(port)) || trust != qs_trust0(port);
	if (!(READ_ONCE(qs_port_read) & BIT(port)) && !READ_ONCE(qos_on))
		return -EOPNOTSUPP;
	err = qs_begin(sw, port, add, NULL);
	if (err)
		return err > 0 ? 0 : err;
	was = qs_trust[port];
	qs_trust[port] = trust == qs_trust0(port) ? -1 : (s8)trust;
	err = qs_apply(sw, ds->dev, port, qs_trust[port] >= 0);
	if (err)
		qs_trust[port] = was;
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "qos: port %d trust 0x%x failed (%d)\n", port, trust, err);
	return err;
}

static int bcm5331x_dsa_port_get_apptrust(struct dsa_switch *ds, int port, u8 *sel, int *nsel)
{
	struct bcm53314 *sw = ds->priv;
	int err, trust = 0;

	if (!qs_front(port) || access < 1)
		return -EOPNOTSUPP;
	if (!(READ_ONCE(qs_port_read) & BIT(port)) && !READ_ONCE(qos_on))
		return -EOPNOTSUPP;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : qs_origin_port(sw, port);
	if (!err)
		trust = qs_effective_trust(port);
	mutex_unlock(&sw->lock);
	if (err)
		return err;
	*nsel = 0;
	if (trust & QS_TR_DSCP)
		sel[(*nsel)++] = IEEE_8021QAZ_APP_SEL_DSCP;
	if (trust & QS_TR_PCP)
		sel[(*nsel)++] = DCB_APP_SEL_PCP;
	return 0;
}

/* ---------------------------------------------------------------------- */
/* tbf as root qdisc of a port -> egress shaper (EGRMETERINGCONFIG)        */

/*
 * tc qdisc add dev portN root tbf rate R burst B ... : REFRESH = R in
 * units of 64 kbit/s (rounded up, 1..0x3ffff), THD_SEL = B in units of
 * 4096 bytes (at least 1, at most 0xfff); refused when MISCCONFIG has the
 * metering clock off (read once, never written). Removal (or replace by
 * another root qdisc) gives the origin back.
 */
static int qs_tbf(struct dsa_switch *ds, int port, struct tc_tbf_qopt_offload *qopt)
{
	struct bcm53314 *sw = ds->priv;
	bool add = qopt->command == TC_TBF_REPLACE;
	u32 refresh = 0, want, was, *slot;
	int thd = 0, cos = -1, err;

	switch (qopt->command) {
	case TC_TBF_REPLACE:
	case TC_TBF_DESTROY:
		break;
	case TC_TBF_STATS:
		return 0;	/* no counter of the shaper: nothing to add */
	default:
		return -EOPNOTSUPP;
	}
	if (add) {
		refresh = qf_refresh(qopt->replace_params.rate.rate_bytes_ps, QS_MT_REFRESH_MAX);
		thd = qf_thd(qopt->replace_params.max_size, QS_MT_THD_MAX);
		if (!refresh || thd < 0)
			return -ERANGE;
	}
	err = qs_begin(sw, port, add, NULL);
	if (err)
		return err > 0 ? 0 : err;
	/* under a band b of the ets of the port (parent = ets handle : b + 1): maximum shaper of queue 3 - b */
	if (qopt->parent != TC_H_ROOT) {
		cos = -1;
		if ((qs_ets_on & BIT(port)) && TC_H_MAJ(qopt->parent) == TC_H_MAJ(qs_ets_handle[port]) &&
		    TC_H_MIN(qopt->parent) >= 1 && TC_H_MIN(qopt->parent) <= qs_ets_bands[port])
			cos = QS_NUM_COS - TC_H_MIN(qopt->parent);
		if (cos < 0) {
			mutex_unlock(&sw->lock);
			return -EOPNOTSUPP;
		}
	}
	if (add) {
		err = qs_metering_ok(sw);
		if (err) {
			mutex_unlock(&sw->lock);
			if (err == -EOPNOTSUPP)
				dev_err(ds->dev, "qos: MISCCONFIG metering clock off: shaper refused, nothing written\n");
			return err;
		}
	}
	slot = cos < 0 ? &qs_egr_want[port] : &qs_maxc_want[port][cos];
	was = *slot;
	want = add ? ((cos < 0 ? qs_egr0[port] : qs_maxc0[port][cos]) & ~(QS_MT_THD | QS_MT_REFRESH)) |
		     QQ_PUT(QS_MT_REFRESH, refresh) | QQ_PUT(QS_MT_THD, thd) : 0;
	*slot = want;
	err = qs_apply(sw, ds->dev, port, add);
	if (err)
		*slot = was;
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "qos: port %d shaper %s failed (%d)\n", port, add ? "set" : "removal", err);
	else
		dev_info(ds->dev, "qos: port %d queue %d shaper %s (REFRESH %u, THD_SEL %d, %d writes)\n", port,
			 cos, add ? "set" : "removed", refresh, thd, qs_nops);
	return err;
}

/* ---------------------------------------------------------------------- */
/* ets as root qdisc of a port -> scheduler of the port, COS_SEL           */

/*
 * tc qdisc add dev portN root handle H: ets bands B [strict S] quanta ...
 * priomap ...: at most 4 bands (4 queues); band b -> queue 3 - b (band 0
 * = highest queue). All bands strict: XQCOSARBSEL.COSARB = 0 (strict),
 * weights untouched; else COSARB = 3 (DRR): strict bands weight 0, DRR
 * bands WEIGHT = quantum in units of 2048 << MTU_QUANTA_SELECT bytes
 * (MTU_QUANTA_SELECT of origin, not written on this chip by the SDK;
 * 1..127, rounded up), queues without a band untouched. Priorities 0-7 ->
 * COS_SEL (queue = 3 - band of the priority) on the 25 ports: the queue
 * is chosen at ingress, so one map for all ports: the first ets
 * sets it, an ets with another map is refused, the last one gives the
 * origin back. Children: a tbf under band b (parent H:b+1) shapes queue
 * 3 - b (MAXBUCKETCONFIG).
 */
static int qs_ets(struct dsa_switch *ds, int port, struct tc_ets_qopt_offload *qopt)
{
	struct tc_ets_qopt_offload_replace_params *rp = &qopt->replace_params;
	struct bcm53314 *sw = ds->priv;
	u8 w[QS_NUM_COS] = { 0 }, bands = 0, cosarb = QS_COSARB_STRICT, was_bands, was_arb;
	u8 was_w[QS_NUM_COS];
	u32 map = 0, was_on, was_handle, was_map, unit;
	bool add = qopt->command == TC_ETS_REPLACE;
	int b, i, err;

	switch (qopt->command) {
	case TC_ETS_REPLACE:
	case TC_ETS_DESTROY:
		break;
	case TC_ETS_STATS:
		return 0;	/* no queue counter added */
	case TC_ETS_GRAFT:
		return 0;	/* a child (tbf) is offloaded by its own call */
	default:
		return -EOPNOTSUPP;
	}
	if (qopt->parent != TC_H_ROOT)
		return -EOPNOTSUPP;
	if (add) {
		bands = rp->bands;
		if (bands < 1 || bands > QS_NUM_COS)
			return -EOPNOTSUPP;
		for (i = 0; i < 8; i++) {
			if (rp->priomap[i] >= bands)
				return -EINVAL;
			map |= (u32)(QS_NUM_COS - 1 - rp->priomap[i]) << (3 * i);
		}
		for (b = 0; b < bands; b++)
			if (rp->quanta[b])
				cosarb = QS_COSARB_DRR;
		for (b = 1; b < bands; b++)
			if (!rp->quanta[b] && rp->quanta[b - 1])
				return -EINVAL;	/* strict bands first (enforced by sch_ets) */
	}
	err = qs_begin(sw, port, add, NULL);
	if (err)
		return err > 0 ? 0 : err;
	if (add && !(qs_ets_on & BIT(port)) && !(qs_ets_on & ~BIT(port)) && !qs_cos_read) {
		for (i = 0; i < NUM_PORTS && !err; i++)
			err = qs_rd1(sw, QS_A_COS_SEL(i), false, "COS_SEL", i, &qs_cos0[i]);
		if (err)
			goto out;
		memcpy(qs_cos, qs_cos0, sizeof(qs_cos));
		qs_cos_read = true;
	}
	if (add) {
		if ((qs_ets_on & ~BIT(port)) && map != qs_cosmap) {
			dev_err(ds->dev, "qos: port %d ets: priority map %06x differs from the one in force %06x (one map for all ports): refused\n",
				port, map, qs_cosmap);
			err = -EBUSY;
			goto out;
		}
		unit = 2048u << QQ_GET(QS_ARB_QUANTA, qs_arb0[port]);
		for (b = 0; b < bands && cosarb == QS_COSARB_DRR; b++) {
			u32 q = DIV_ROUND_UP(rp->quanta[b], unit);

			if (rp->quanta[b] && (q < 1 || q > 127)) {
				err = -ERANGE;
				goto out;
			}
			w[QS_NUM_COS - 1 - b] = rp->quanta[b] ? q : 0;
		}
	}
	was_on = qs_ets_on;
	was_handle = qs_ets_handle[port];
	was_bands = qs_ets_bands[port];
	was_arb = qs_ets_cosarb[port];
	was_map = qs_cosmap;
	memcpy(was_w, qs_ets_w[port], sizeof(was_w));
	if (add) {
		qs_ets_on |= BIT(port);
		qs_ets_handle[port] = qopt->handle;
		qs_ets_bands[port] = bands;
		qs_ets_cosarb[port] = cosarb;
		memcpy(qs_ets_w[port], w, sizeof(w));
		qs_cosmap = map;
	} else {
		qs_ets_on &= ~BIT(port);
		memset(qs_maxc_want[port], 0, sizeof(qs_maxc_want[port]));
	}
	err = qs_apply(sw, ds->dev, port, add);
	if (err) {
		qs_ets_on = was_on;
		qs_ets_handle[port] = was_handle;
		qs_ets_bands[port] = was_bands;
		qs_ets_cosarb[port] = was_arb;
		memcpy(qs_ets_w[port], was_w, sizeof(was_w));
		qs_cosmap = was_map;
	}
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "qos: port %d ets %s failed (%d)\n", port, add ? "set" : "removal", err);
	else
		dev_info(ds->dev, "qos: port %d ets %s (%u bands, COSARB %u, map %06x, %d writes)\n", port,
			 add ? "set" : "removed", bands, cosarb, map, qs_nops);
	return err;
}

static int bcm5331x_dsa_port_setup_tc(struct dsa_switch *ds, int port, enum tc_setup_type type,
				      void *type_data)
{
	switch (type) {
	case TC_SETUP_QDISC_ETS:
		return qs_ets(ds, port, type_data);
	case TC_SETUP_QDISC_TBF:
		return qs_tbf(ds, port, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

/* ---------------------------------------------------------------------- */
/* storm control (flower dst_mac broadcast / multicast + police)           */

/*
 * tc filter add dev portN ingress flower skip_sw dst_mac
 * ff:ff:ff:ff:ff:ff (broadcast) or 01:00:00:00:00:00/01:00:00:00:00:00
 * (multicast), one key, one police action (exceed drop):
 *  - police pkts_rate N: {BCAST,MCAST}_STORM_CONTROL[p] THRESHOLD = N
 *    packets/s (OpenBCM rate.c: "pps"), ENABLE - one register;
 *  - police rate R burst B: FP_SC_{BCAST,MCAST}_METER_TABLE[p]
 *    (REFRESHCOUNT = R in units of 64 kbit/s, BUCKETSIZE code 0-12,
 *    BUCKETCOUNT 0) then SC_BYTE_METER_CONFIG[p].{BCAST,MCAST}_ENABLE.
 * One rule per port and kind; the DLF storm control (unknown unicast)
 * is not expressible as a flower key: never written. Removal: trigger
 * first, then the values of origin. Every other flower rule goes to the
 * Field Processor. A multicast limit applies to the link-local
 * control frames too (they are multicast): it is the user's explicit rule.
 */
#define QS_ST_THRESHOLD		GENMASK(24, 0)
#define QS_ST_ENABLE		BIT(25)
#define QS_SCB_ENABLE(k)	BIT(2 - (k))	/* SC_BYTE_METER_CONFIG: BCAST 2, MCAST 1, DLFBC 0 */
#define QS_SC_BUCKETCOUNT	GENMASK(29, 0)
#define QS_SC_REFRESH_MAX	0x7ffff

static bool fp_mac_zero_q(const u8 *m)
{
	return !(m[0] | m[1] | m[2] | m[3] | m[4] | m[5]);
}

static u32 qs_storm_read;			/* front ports whose storm origin was read */
static u32 qs_st0[NUM_PORTS][2], qs_st[NUM_PORTS][2], qs_st_want[NUM_PORTS][2];	/* 0 = origin */
static u32 qs_scb0[NUM_PORTS], qs_scb[NUM_PORTS];
static u32 qs_fpsc0[NUM_PORTS][2][2], qs_fpsc[NUM_PORTS][2][2], qs_fpsc_want[NUM_PORTS][2][2];
static bool qs_fpsc_on[NUM_PORTS][2];		/* byte mode asked */
static unsigned long qs_storm_cookie[NUM_PORTS][2];
static bool qs_storm_used[NUM_PORTS][2];

static u32 qs_want_st(int p, int k)
{
	return qs_st_want[p][k] ? qs_st_want[p][k] : qs_st0[p][k];
}

static u32 qs_want_scb(int p)
{
	u32 v = qs_scb0[p];
	int k;

	for (k = 0; k < 2; k++)
		if (qs_fpsc_on[p][k])
			v |= QS_SCB_ENABLE(k);
		else
			v = (v & ~QS_SCB_ENABLE(k)) | (qs_scb0[p] & QS_SCB_ENABLE(k));
	return v;
}

static const u32 *qs_want_fpsc(int p, int k)
{
	return qs_fpsc_on[p][k] ? qs_fpsc_want[p][k] : qs_fpsc0[p][k];
}

static int qs_storm_origin(struct bcm53314 *sw, int p)
{
	u32 w[QF_WORDS];
	int k, err = 0;

	if (qs_storm_read & BIT(p))
		return 0;
	for (k = 0; k < 2 && !err; k++)
		err = qs_rd1(sw, QS_A_STORM(k, p), false, "STORM_CONTROL", p, &qs_st0[p][k]);
	if (!err)
		err = qs_rd1(sw, QS_A_SCBYTE(p), false, "SC_BYTE_METER_CONFIG", p, &qs_scb0[p]);
	for (k = 0; k < 2 && !err; k++) {
		err = qf_rd(sw, QS_A_FPSC(k, p), true, 2, w, "FP_SC_METER_TABLE", p);
		memcpy(qs_fpsc0[p][k], w, sizeof(qs_fpsc0[p][k]));
	}
	if (err)
		return err;
	memcpy(qs_st[p], qs_st0[p], sizeof(qs_st[p]));
	memset(qs_st_want[p], 0, sizeof(qs_st_want[p]));
	qs_scb[p] = qs_scb0[p];
	memcpy(qs_fpsc[p], qs_fpsc0[p], sizeof(qs_fpsc[p]));
	memset(qs_fpsc_on[p], 0, sizeof(qs_fpsc_on[p]));
	qs_storm_read |= BIT(p);
	return 0;
}

/* values (meter entries) before the trigger (enable bits) when turned on, the reverse when off */
static int qs_plan_storm(int p, bool on)
{
	struct qf_op *op;
	int i, k, err = 0;

	for (i = 0; i < 2 && !err; i++) {
		if ((i == 0) == on) {
			for (k = 0; k < 2 && !err; k++) {
				const u32 *want = qs_want_fpsc(p, k);

				if (!memcmp(qs_fpsc[p][k], want, sizeof(qs_fpsc[p][k])))
					continue;
				op = qs_new_op(QS_FPSC, p, QS_A_FPSC(k, p), true, 2, "FP_SC_METER_TABLE",
					       qs_fpsc[p][k], qs_fpsc[p][k]);
				if (!op)
					return -ENOSPC;
				op->sub = k;
				memcpy(op->val, want, 2 * sizeof(u32));
				op->ign[0] = QS_SC_BUCKETCOUNT;	/* moves with the traffic */
			}
		} else {
			err = qs_op1(QS_SCB, p, QS_A_SCBYTE(p), false, "SC_BYTE_METER_CONFIG", &qs_scb[p],
				     qs_want_scb(p), 0);
			for (k = 0; k < 2 && !err; k++) {
				err = qs_op1(QS_STORM, p, QS_A_STORM(k, p), false, "STORM_CONTROL", &qs_st[p][k],
					     qs_want_st(p, k), 0);
				if (!err && qs_nops && qs_ops[qs_nops - 1].shadow == &qs_st[p][k])
					qs_ops[qs_nops - 1].sub = k;
			}
		}
	}
	return err;
}

/* SC_BYTE_METER_CONFIG enable bit of kind k when op runs (last earlier write of the plan, else known) */
static bool qs_scb_on_at(const struct qf_op *op, int p, int k)
{
	const struct qf_op *q;
	u32 v = qs_scb[p];

	for (q = qs_ops; q < op; q++)
		if (q->cls == QS_SCB && q->idx == p)
			v = q->val[0];
	return v & QS_SCB_ENABLE(k);
}

static bool qs_storm_op_ok(const struct qf_op *op)
{
	int p = op->idx, k = op->sub;
	const u32 *v = op->val;

	if (!qs_front(p) || !(qs_storm_read & BIT(p)))
		return false;
	switch (op->cls) {
	case QS_STORM:
		/* broadcast / multicast only (DLF never), THRESHOLD and ENABLE only */
		return k < 2 && !op->mem && op->words == 1 && op->addr == QS_A_STORM(k, p) && !op->ign[0] &&
		       !((op->old[0] ^ v[0]) & ~(QS_ST_THRESHOLD | QS_ST_ENABLE)) && v[0] == qs_want_st(p, k);
	case QS_SCB:
		/* the broadcast and multicast enable bits only (DLFBC never) */
		return !op->mem && op->words == 1 && op->addr == QS_A_SCBYTE(p) && !op->ign[0] &&
		       !((op->old[0] ^ v[0]) & ~(QS_SCB_ENABLE(0) | QS_SCB_ENABLE(1))) && v[0] == qs_want_scb(p);
	case QS_FPSC:
		/* meter of the kind, written while its enable bit is off at that point; bucket count 0 */
		if (k >= 2 || !op->mem || op->words != 2 || op->addr != QS_A_FPSC(k, p) ||
		    op->ign[0] != QS_SC_BUCKETCOUNT || op->ign[1] || qs_scb_on_at(op, p, k))
			return false;
		if (!memcmp(v, qs_fpsc0[p][k], 2 * sizeof(u32)))
			return !qs_fpsc_on[p][k];
		return qs_fpsc_on[p][k] && !memcmp(v, qs_want_fpsc(p, k), 2 * sizeof(u32)) &&
		       !(v[0] & QS_SC_BUCKETCOUNT) && qf_get(v, 30, 4) <= 12 && qf_get(v, 34, 19) >= 1 &&
		       !qf_get(v, 53, 11);
	}
	return false;
}

/*
 * A storm rule? -ENOENT if the flower rule is not one (the FP then takes
 * it); else 0 (done) or the error of the storm gesture.
 */
static int qs_storm_flower(struct dsa_switch *ds, int port, struct flow_cls_offload *cls)
{
	static const u8 bc[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	static const u8 mc[ETH_ALEN] = { 0x01, 0, 0, 0, 0, 0 };
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct netlink_ext_ack *extack = cls->common.extack;
	const struct flow_action_police *pl;
	struct bcm53314 *sw = ds->priv;
	struct flow_match_eth_addrs eth;
	u32 st = 0, met[2] = { 0, 0 }, wst[2], wfp[2][2];
	bool fpo[2];
	int k, err, code;

	if (rule->match.dissector->used_keys & ~(BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
						 BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
						 BIT_ULL(FLOW_DISSECTOR_KEY_ETH_ADDRS)) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS) || rule->action.num_entries != 1 ||
	    rule->action.entries[0].id != FLOW_ACTION_POLICE)
		return -ENOENT;
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic m;

		flow_rule_match_basic(rule, &m);
		if (m.mask->n_proto || m.mask->ip_proto)
			return -ENOENT;
	}
	flow_rule_match_eth_addrs(rule, &eth);
	if (!fp_mac_zero_q(eth.mask->src))
		return -ENOENT;
	if (!memcmp(eth.key->dst, bc, ETH_ALEN) && !memcmp(eth.mask->dst, bc, ETH_ALEN))
		k = 0;
	else if (!memcmp(eth.key->dst, mc, ETH_ALEN) && !memcmp(eth.mask->dst, mc, ETH_ALEN))
		k = 1;
	else
		return -ENOENT;
	/* a storm rule from here on */
	if (!qs_front(port) || cls->common.chain_index) {
		NL_SET_ERR_MSG_MOD(extack, "storm control of chain 0 on the front ports only");
		return -EOPNOTSUPP;
	}
	if (!READ_ONCE(qos_on)) {
		NL_SET_ERR_MSG_MOD(extack, "QoS offload off (module parameter qos=0)");
		return -EOPNOTSUPP;
	}
	pl = &rule->action.entries[0].police;
	if (pl->peakrate_bytes_ps || pl->avrate || pl->overhead || pl->exceed.act_id != FLOW_ACTION_DROP ||
	    (pl->notexceed.act_id != FLOW_ACTION_PIPE && pl->notexceed.act_id != FLOW_ACTION_ACCEPT) ||
	    (pl->rate_pkt_ps && pl->rate_bytes_ps)) {
		NL_SET_ERR_MSG_MOD(extack, "storm control: one packet or byte rate, exceed drop");
		return -EOPNOTSUPP;
	}
	if (pl->rate_pkt_ps) {
		if (pl->rate_pkt_ps > QS_ST_THRESHOLD)
			return -ERANGE;
		st = QQ_PUT(QS_ST_THRESHOLD, (u32)pl->rate_pkt_ps) | QS_ST_ENABLE;
	} else {
		u32 refresh = qf_refresh(pl->rate_bytes_ps, QS_SC_REFRESH_MAX);

		code = qf_bucket_code(pl->burst);
		if (!refresh || code < 0)
			return -ERANGE;
		qf_put(met, 30, 4, code);
		qf_put(met, 34, 19, refresh);
	}
	if (access != 2 || dry_run)
		return -EPERM;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : qs_storm_origin(sw, port);
	if (!err && qs_storm_used[port][k])
		err = -EBUSY;
	if (!err && !pl->rate_pkt_ps)
		err = qs_metering_ok(sw);
	if (err)
		goto out;
	memcpy(wst, qs_st_want[port], sizeof(wst));
	memcpy(wfp, qs_fpsc_want[port], sizeof(wfp));
	memcpy(fpo, qs_fpsc_on[port], sizeof(fpo));
	if (st)
		qs_st_want[port][k] = (qs_st0[port][k] & ~(QS_ST_THRESHOLD | QS_ST_ENABLE)) | st;
	else {
		qs_fpsc_on[port][k] = true;
		memcpy(qs_fpsc_want[port][k], met, sizeof(met));
	}
	qs_nops = 0;
	err = qs_plan_storm(port, true);
	if (!err)
		err = qs_run(sw, ds->dev);
	if (err) {
		memcpy(qs_st_want[port], wst, sizeof(wst));
		memcpy(qs_fpsc_want[port], wfp, sizeof(wfp));
		memcpy(qs_fpsc_on[port], fpo, sizeof(fpo));
	} else {
		qs_storm_used[port][k] = true;
		qs_storm_cookie[port][k] = cls->cookie;
	}
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "qos: port %d storm control %s failed (%d)\n", port, k ? "multicast" : "broadcast", err);
	return err;
}

/* removal of a storm rule (always permitted): -ENOENT if the cookie is not one */
static int qs_storm_del(struct dsa_switch *ds, int port, unsigned long cookie)
{
	struct bcm53314 *sw = ds->priv;
	int k, err = -ENOENT;

	if (port <= 0 || port >= NUM_PORTS)
		return -ENOENT;
	mutex_lock(&sw->lock);
	for (k = 0; k < 2; k++) {
		if (!qs_storm_used[port][k] || qs_storm_cookie[port][k] != cookie)
			continue;
		qs_storm_used[port][k] = false;
		qs_st_want[port][k] = 0;
		qs_fpsc_on[port][k] = false;
		qs_nops = 0;
		err = sw->halted ? -EIO : qs_plan_storm(port, false);
		if (!err)
			err = qs_run(sw, ds->dev);
		break;
	}
	mutex_unlock(&sw->lock);
	return err;
}

/* teardown: every register back to its origin (DSA removed the rules first) */
static void qs_teardown(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;
	int p, err = 0;

	mutex_lock(&sw->lock);
	qs_ets_on = 0;
	for (p = 0; p < NUM_PORTS; p++) {
		if (!(qs_port_read & BIT(p)))
			continue;
		qs_prio[p] = -1;
		qs_egr_want[p] = 0;
		qs_trust[p] = -1;
		memset(qs_dscp_pri[p], -1, sizeof(qs_dscp_pri[p]));
		memset(qs_maxc_want[p], 0, sizeof(qs_maxc_want[p]));
		if (!err)
			err = sw->halted ? -EIO : qs_apply(sw, ds->dev, p, false);
	}
	if (err)
		dev_err(ds->dev, "qos: origin not restored at teardown (%d)\n", err);
	for (p = 0; p < NUM_PORTS; p++) {
		if (!(qs_storm_read & BIT(p)))
			continue;
		memset(qs_st_want[p], 0, sizeof(qs_st_want[p]));
		memset(qs_fpsc_on[p], 0, sizeof(qs_fpsc_on[p]));
		memset(qs_storm_used[p], 0, sizeof(qs_storm_used[p]));
		qs_nops = 0;
		if (!err)
			err = sw->halted ? -EIO : qs_plan_storm(p, false);
		if (!err)
			err = qs_run(sw, ds->dev);
	}
	if (err)
		dev_err(ds->dev, "qos: storm control not restored at teardown (%d)\n", err);
	qs_storm_read = 0;
	qs_port_read = 0;
	qs_misc_read = 0;
	qs_cos_read = false;
	mutex_unlock(&sw->lock);
}
