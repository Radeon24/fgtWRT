// SPDX-License-Identifier: GPL-2.0-only
/*
 * Field Processor (ACL) of the BCM53314 DSA driver
 * (module parameter fp), #included by bcm5331x-dsa.c after bcm5331x-qos.c
 * (same translation unit: the write engine qf_* of the QoS file is used as
 * it is).
 *
 * Sources: OpenMDK cdk/PKG/chip/bcm53314/bcm53314_a0_defs.h (addresses,
 * sizes and fields of FP_SLICE_ENABLE, FP_PORT_FIELD_SEL, FP_TCAM,
 * FP_SLICE_ENTRY_PORT_SEL, FP_POLICY_TABLE, FP_METER_TABLE,
 * FP_COUNTER_TABLE); OpenBCM sdk-6.5.16 src/bcm/esw/raptor/field.c
 * (qualifier selectors of Raven/Hawkeye, entry/port bitmap index
 * port << 2 | slice on Hawkeye, a port bit 0 = the entry does not hit
 * that port, TCAM VALID = 3, meter pair index in both METER_INDEX fields,
 * FLOW mode = committed meter on the odd test/update bits), firebolt/field.c
 * (action encodings), include/bcm/field.h (METER_PAIR_MODE 1 = FLOW,
 * COUNTER_MODE 1 = NO_YES = the lower, even counter of the pair: seen
 * counting on slices 0 and 1, the odd one stays at 0), feature.c
 * (field_slices4: 4 slices of 128 entries on this chip).
 * Design notes below.
 *
 * Layout (fixed, set at the first rule): slice 0 "L2" (F2 = 6: outer VLAN,
 * EtherType, source and destination MAC), slice 1 "IPv4" (F1 = 5:
 * protocol, EtherType; F2 = 0xc: TTL, TCP flags, DSCP, L4 ports, protocol,
 * addresses), slice 2 "IPv6 source" (F2 = 3), slice 3 "IPv6 destination"
 * (F2 = 4); F3 = 6 (DSCP, protocol) everywhere, F4 = 0. Slices 1-3 match
 * the EtherType of IPv4 or IPv6: no rule there can hit a link-local
 * control frame (BPDU, LACP, LLDP, EAPOL carry no IP EtherType). In slice
 * 0, entry 0 of every port with a rule there is a "pass" entry (empty
 * policy) for 01:80:c2:00:00:0x: in a slice the entry of lowest index
 * wins, so no rule of the driver ever drops, polices, redirects or
 * remarks a link-local control frame.
 *
 * Writes: nothing at load. The first rule reads the origin (FP_SLICE_ENABLE
 * must be 0 and FP_SLICE_CONFIG 0: the FP unused), powers the slices
 * (FP_SLICE_ENABLE 0x0f, lookups off), sets the five slice memories to 0
 * (they hold random data once powered: no state of the BIOS, nothing to
 * give back) and turns the FP on: the field selectors of the 19 front
 * ports, then FP_SLICE_ENABLE 0xff (lookups), which is accepted only once
 * every port bitmap is 0. The last rule removed (and the teardown) gives
 * the selectors back, the port bitmaps back to 0, then the slices off; a
 * rule refused with the slices powered and the FP not on, and fp set to
 * N, turn the slices off again (only fp_power_hold keeps them on).
 * AUX_ARB_CONTROL is read with the origin; FP_REFRESH_ENABLE alone is set
 * in the plan that turns the FP on (the meter buckets are never refilled
 * without it) and the value of origin given back in the plan that turns
 * it off; a bit already set at origin is left alone, nothing written.
 * Never written: FP_SLICE_CONFIG, FP_SLICE_MAP, FP_METER_CONTROL,
 * FP_RANGE_CHECK, FP_UDF_OFFSET, ING_MISC_CONFIG2; never any copy to the
 * CPU (the CMIC has no DMA here), mirror, L3, ECMP or chain action.
 */

#define FP_SLICES		4
#define FP_ENTRIES		128		/* per slice */
#define FP_SLOTS		64		/* meter and counter pairs per slice (6-bit index) */
#define FP_RULES		128

/* OpenMDK bcm53314_a0_defs.h */
#define FP_A_SLICE_ENABLE	0x0d780007	/* register */
#define FP_A_AUX_ARB		0x00780000	/* AUX_ARB_CONTROL, register, block IPIPE */
#define FP_ARB_REFRESH		BIT(2)		/* FP_REFRESH_ENABLE: refreshes sent down the pipeline */
#define FP_A_METER_CONTROL	0x0d780008	/* register, read only here */
#define FP_A_SLICE_CONFIG	0x0d78000b	/* register, read only here */
#define FP_A_POLICY_PARCTL	0x0d78000d	/* FP_POLICY_PARITY_CONTROL, read only */
#define FP_A_MISC_CONFIG2	0x0c78000c	/* ING_MISC_CONFIG2, read only */
#define FP_A_SLICE_MAP		0x0d730000	/* table of 1 entry, read only */
#define FP_A_FSEL(p)		(0x0c700000 + (p))	/* FP_PORT_FIELD_SEL, 2 words */
#define FP_A_EPS(r)		(0x0d710000 + (r))	/* FP_SLICE_ENTRY_PORT_SEL, 4 words, r = port << 2 | slice */
#define FP_A_TCAM(i)		(0x0d720000 + (i))	/* FP_TCAM, 14 words, i = slice * 128 + entry */
#define FP_A_POLICY(i)		(0x0d750000 + (i))	/* FP_POLICY_TABLE, 5 words */
#define FP_A_METER(i)		(0x0d760000 + (i))	/* FP_METER_TABLE, 2 words */
#define FP_A_COUNTER(i)		(0x0d770000 + (i))	/* FP_COUNTER_TABLE, 1 word */
#define FP_W_FSEL		2
#define FP_W_EPS		4
#define FP_W_TCAM		14
#define FP_W_POLICY		5
#define FP_W_METER		2
#define FP_SE_ALL		0xff		/* FP_SLICE_ENABLE: slices 0-3 and lookups 0-3 */
/*
 * FP_SLICE_ENABLE_SLICE_0..3 (bits 3:0) alone: the slices are powered
 * (their memories FP_SLICE_ENTRY_PORT_SEL, FP_TCAM, FP_POLICY_TABLE...
 * take writes), lookups 0-3 (bits 7:4) stay off: no packet sees the FP.
 * Reset value 0 on the BCM53314 (OpenBCM allregs_f.i, FP_SLICE_ENABLE_
 * BCM5331X_A0r) and the SDK sets the slices on in soc_firebolt_misc_init
 * (Hawkeye only) before any FP memory is cleared; the BIOS never does:
 * reads of the per-slice memories give a constant, writes are lost
 *.
 */
#define FP_SE_SLICES		0x0f
#define FP_FSEL_BITS		52		/* field selectors of the 4 slices: bits 51:0 */

/* classes of writes of this file */
enum { FP_C_SE, FP_C_FSEL, FP_C_EPS, FP_C_TCAM, FP_C_POL, FP_C_MET, FP_C_CNT, FP_C_ARB };

#define FP_NOPS			(3 + NUM_PORTS + NUM_PORTS * FP_SLICES + 16)

static bool fp_on;
static void fp_param_off(void);
/* fp set to N: slices powered by a refused first rule are turned off again */
static int fp_on_set(const char *val, const struct kernel_param *kp)
{
	int err = param_set_bool(val, kp);

	if (!err && !READ_ONCE(fp_on))
		fp_param_off();
	return err;
}

static const struct kernel_param_ops fp_on_ops = {
	.set = fp_on_set,
	.get = param_get_bool,
};
module_param_cb(fp, &fp_on_ops, &fp_on, 0644);
MODULE_PARM_DESC(fp, "Offload tc flower rules (and ethtool ntuple drop rules, matchall police) of the front ports to the Field Processor (written at run time only, read back, origin restored at the last removal and at unload; may be set at run time, N turns slices left powered off; default N = no write; removals always run)");

static struct qf_op fp_ops[FP_NOPS];
static int fp_nops;
static unsigned long bcm5331x_fp_writes, bcm5331x_fp_refusals;

/* origin (first rule) and last values known */
static bool fp_read;			/* origin read */
static bool fp_active;			/* FP turned on by the driver */
static bool fp_busy;			/* FP found in use at origin: every rule refused until the teardown */
static u32 fp_se0, fp_se;
static u32 fp_arb0, fp_arb;		/* AUX_ARB_CONTROL: origin, last value known */
static u32 fp_fsel0[NUM_PORTS][FP_W_FSEL], fp_fsel[NUM_PORTS][FP_W_FSEL];
static u32 fp_eps0[NUM_PORTS * FP_SLICES][FP_W_EPS], fp_eps[NUM_PORTS * FP_SLICES][FP_W_EPS];

/* field selectors of the layout, bits 51:0 of FP_PORT_FIELD_SEL (other bits of origin kept) */
static void fp_fsel_layout(const u32 *origin, u32 *w)
{
	static const u8 sel[FP_SLICES][4] = {	/* F1, F2, F3, F4 */
		{ 4, 6, 6, 0 }, { 5, 0xc, 6, 0 }, { 5, 3, 6, 0 }, { 5, 4, 6, 0 },
	};
	int s;

	w[0] = origin[0];
	w[1] = origin[1];
	for (s = 0; s < FP_SLICES; s++) {
		qf_put(w, 13 * s, 4, sel[s][0]);
		qf_put(w, 13 * s + 4, 4, sel[s][1]);
		qf_put(w, 13 * s + 8, 3, sel[s][2]);
		qf_put(w, 13 * s + 11, 2, sel[s][3]);
	}
}

static struct qf_op *fp_new_op(int cls, int idx, u32 addr, bool mem, int words, const char *name,
			       u32 *shadow, const u32 *old, const u32 *val)
{
	struct qf_op *op;

	if (fp_nops >= FP_NOPS)
		return NULL;
	op = &fp_ops[fp_nops++];
	memset(op, 0, sizeof(*op));
	op->cls = cls;
	op->idx = idx;
	op->addr = addr;
	op->mem = mem;
	op->words = words;
	op->name = name;
	op->shadow = shadow;
	memcpy(op->old, old, words * sizeof(u32));
	memcpy(op->val, val, words * sizeof(u32));
	/* counters and meter buckets move with the traffic: re-read and read back, not compared */
	if (cls == FP_C_CNT)
		op->ign[0] = ~0u;
	if (cls == FP_C_MET)
		op->ign[0] = GENMASK(29, 0);
	return op;
}

/* an op only if the value changes from the one the register holds at that point of the plan */
static int fp_op_if(int cls, int idx, u32 addr, bool mem, int words, const char *name, u32 *shadow,
		    const u32 *val)
{
	const u32 *cur = shadow;
	int i;

	/* FP_SLICE_ENABLE: one register, whatever the step (idx) of the plan */
	for (i = 0; i < fp_nops; i++)
		if (fp_ops[i].cls == cls && (fp_ops[i].idx == idx || cls == FP_C_SE))
			cur = fp_ops[i].val;
	if (!memcmp(cur, val, words * sizeof(u32)))
		return 0;
	return fp_new_op(cls, idx, addr, mem, words, name, shadow, cur, val) ? 0 : -ENOSPC;
}

static bool fp_op_ok(const struct bcm53314 *sw, const struct qf_op *op);

static int fp_run(struct bcm53314 *sw, struct device *dev)
{
	return qf_execute(sw, dev, "fp", fp_ops, fp_nops, fp_op_ok, &bcm5331x_fp_writes,
			  &bcm5331x_fp_refusals);
}

/* the 19 front ports (never MGMT, the CPU side nor the CMIC) */
static bool fp_front(int port)
{
	return port > 0 && port < NUM_PORTS && port != PORT_MGMT && bcm5331x_is_front(port);
}

static bool fp_eps_zero(int r)
{
	return !(fp_eps[r][0] | fp_eps[r][1] | fp_eps[r][2] | fp_eps[r][3]);
}

/*
 * Module parameter fp_eps_probe (default N): one probe at the first rule,
 * after the clear, on the row of the rule itself (its port and slice): bit
 * 0 written and read back, then 0 written back and read back (lookups
 * off). Bit 0 read back: the table takes writes, the rule goes on; 0 read
 * back: writes ignored, FP refused (no fault, slices off again); anything
 * else: 0 written back, then a fault. The probe writes (2) are not in the
 * writes counter: debugfs fp counts the probes. (Once
 * the probe was the only test of a non-zero row at origin; now the clear and
 * its read back now test every row.)
 */
static bool fp_eps_probe;
module_param(fp_eps_probe, bool, 0644);
MODULE_PARM_DESC(fp_eps_probe, "With fp=Y: probe the port bitmap row of the first rule after the clear of the slice memories (bit 0, read back, 0 written back); default N");
static unsigned long bcm5331x_fp_eps_probes;

/* one write of row r, read back into rb */
static int fp_eps_put(struct bcm53314 *sw, int r, const u32 *val, u32 *rb)
{
	u32 w[QF_WORDS];
	int err;

	memset(w, 0, sizeof(w));
	memcpy(w, val, FP_W_EPS * sizeof(u32));
	err = schan_xfer(sw, true, true, FP_A_EPS(r), FP_W_EPS, w, "FP_SLICE_ENTRY_PORT_SEL", r);
	return err ?: qf_rd(sw, FP_A_EPS(r), true, FP_W_EPS, rb, "FP_SLICE_ENTRY_PORT_SEL", r);
}

static int fp_eps_try(struct bcm53314 *sw, struct device *dev, int r)
{
	u32 t[FP_W_EPS] = { 0 }, rb[QF_WORDS], tmp[QF_WORDS];
	int err;

	if (fp_eps_zero(r))
		t[0] = 1;		/* row already 0: bit 0 as test value (lookups off: no effect) */
	bcm5331x_fp_eps_probes++;
	err = fp_eps_put(sw, r, t, rb);
	if (err)
		return err;
	if (!memcmp(rb, t, sizeof(t))) {
		/* the table takes writes: value of origin back, then the plan zeroes it under its checks */
		err = fp_eps_put(sw, r, fp_eps0[r], rb);
		if (!err && memcmp(rb, fp_eps0[r], FP_W_EPS * sizeof(u32))) {
			sw_fault(sw, "dsa: fp probe: FP_SLICE_ENTRY_PORT_SEL[%d] not given back (%08x)", r, rb[0]);
			return -EIO;
		}
		if (!err)
			dev_info(dev, "fp: probe: FP_SLICE_ENTRY_PORT_SEL[%d] takes writes\n", r);
		return err;
	}
	if (!memcmp(rb, fp_eps0[r], FP_W_EPS * sizeof(u32))) {
		dev_err(dev, "fp: probe: FP_SLICE_ENTRY_PORT_SEL[%d] ignores writes (read back %08x): Field Processor refused\n",
			r, rb[0]);
		return -EBUSY;
	}
	if (!fp_eps_put(sw, r, fp_eps0[r], tmp))
		dev_err(dev, "fp: probe: FP_SLICE_ENTRY_PORT_SEL[%d] read back %08x after %08x, origin %08x written back\n",
			r, rb[0], t[0], fp_eps0[r][0]);
	sw_fault(sw, "dsa: fp probe: FP_SLICE_ENTRY_PORT_SEL[%d] read back %08x, wrote test value", r, rb[0]);
	return -EIO;
}

/* FP_SLICE_ENABLE written alone (outside any plan), read back */
static int fp_power(struct bcm53314 *sw, struct device *dev, u32 v)
{
	u32 rb;
	int err;

	if (access != 2 || dry_run)
		return -EPERM;
	if (v != FP_SE_SLICES && v != fp_se0)
		return -EINVAL;
	err = schan_xfer(sw, true, false, FP_A_SLICE_ENABLE, 1, (u32[QF_WORDS]){ v }, "FP_SLICE_ENABLE", 0);
	if (!err)
		err = qs_rd1(sw, FP_A_SLICE_ENABLE, false, "FP_SLICE_ENABLE", 0, &rb);
	if (err)
		return err;
	bcm5331x_fp_writes++;
	if (rb != v) {
		sw_fault(sw, "dsa: fp FP_SLICE_ENABLE read back %08x, wrote %08x", rb, v);
		return -EIO;
	}
	dev_info(dev, "fp: FP_SLICE_ENABLE %08x (slices %s, lookups off)\n", v, v ? "powered" : "off");
	return 0;
}

/* slices powered by fp_origin, FP not turned on: back to the value of origin (0) */
static void fp_unpower(struct bcm53314 *sw, struct device *dev)
{
	if (fp_se == FP_SE_SLICES && !fp_active && !sw->halted && !fp_power(sw, dev, fp_se0))
		fp_se = fp_se0;
}

/*
 * fp_power_hold (default N, 0644): the first rule stops once the slices
 * are powered and the origin read (and the probe made, if asked): rule
 * refused (-EBUSY), FP_SLICE_ENABLE left at 0x0f (lookups off), debugfs
 * fp readable in that state; set back to N, the next rule turns the FP on.
 * The slices go back to their origin at teardown.
 */
static bool fp_power_hold;
module_param(fp_power_hold, bool, 0644);
MODULE_PARM_DESC(fp_power_hold, "With fp=Y: stop the first rule once the Field Processor slices are powered (FP_SLICE_ENABLE 0x0f, lookups off) and the origin read: rule refused, state left for debugfs fp; default N");

/*
 * The five slice memories: once powered they hold random data
 * (the BIOS never initialises them: seen once, valid entries 261
 * of 512, port bitmaps and policies at random), so the first rule sets
 * every entry to 0 right after FP_SLICE_ENABLE 0x0f is read back (lookups
 * off), before any allocation: the soc_mem_clear of OpenBCM raptor/field.c
 * (_field_raptor_hw_clear), on these five memories only (FP_PORT_FIELD_SEL
 * read and given back as before; FP_SLICE_MAP, FP_RANGE_CHECK and
 * FP_UDF_OFFSET never written). Port bitmaps first: no entry can hit a
 * port. Every entry read back: a value other than 0 refuses the FP (no
 * fault: lookups off, slices turned off again). Volatile memories with no
 * state of the BIOS: the origin is 0 (port bitmaps and entries given back
 * to 0, then the slices off). The clear writes are counted apart (debugfs
 * fp "cleared"), not in the other writes.
 */
static const struct fp_mem {
	u32 base;
	int n, words;
	const char *name;
} fp_mems[] = {
	{ 0x0d710000, NUM_PORTS * FP_SLICES, FP_W_EPS, "FP_SLICE_ENTRY_PORT_SEL" },
	{ 0x0d720000, FP_SLICES * FP_ENTRIES, FP_W_TCAM, "FP_TCAM" },
	{ 0x0d750000, FP_SLICES * FP_ENTRIES, FP_W_POLICY, "FP_POLICY_TABLE" },
	{ 0x0d760000, FP_SLICES * FP_ENTRIES, FP_W_METER, "FP_METER_TABLE" },
	{ 0x0d770000, FP_SLICES * FP_ENTRIES, 1, "FP_COUNTER_TABLE" },
};
#define FP_NMEMS		ARRAY_SIZE(fp_mems)
static bool fp_clearing;		/* clear in progress (these writes are counted apart) */
static unsigned long bcm5331x_fp_cleared;	/* entries set to 0 and read back at the last origin */

static int fp_clear(struct bcm53314 *sw, struct device *dev)
{
	u32 z[QF_WORDS] = { 0 }, rb[QF_WORDS];
	unsigned int t;
	int i, err = 0;

	bcm5331x_fp_cleared = 0;
	if (access != 2 || dry_run)
		return -EPERM;
	fp_clearing = true;
	for (t = 0; t < FP_NMEMS && !err; t++) {
		const struct fp_mem *m = &fp_mems[t];

		for (i = 0; i < m->n && !err; i++) {
			err = schan_xfer(sw, true, true, m->base + i, m->words, z, m->name, i);
			if (!err)
				err = qf_rd(sw, m->base + i, true, m->words, rb, m->name, i);
			if (err)
				break;
			if (memcmp(rb, z, m->words * sizeof(u32))) {
				dev_err(dev, "fp: %s[%d] read back %08x after the clear: Field Processor refused\n",
					m->name, i, rb[0]);
				err = -EIO;
				break;
			}
			bcm5331x_fp_cleared++;
		}
	}
	fp_clearing = false;
	if (!err)
		dev_info(dev, "fp: slice memories cleared (%lu entries read back 0)\n", bcm5331x_fp_cleared);
	return err;
}

/* the switch of the slices powered (fp set to N at run time) */
static DEFINE_MUTEX(fp_sw_lock);
static struct bcm53314 *fp_sw;
static struct device *fp_dev;

static int fp_held(struct device *dev)
{
	if (!READ_ONCE(fp_power_hold) || fp_active)
		return 0;
	dev_info(dev, "fp: slices powered, lookups off, held (fp_power_hold=Y): rule refused\n");
	return -EBUSY;	/* never -EAGAIN: tc_new_tfilter replays the request on it */
}

/*
 * First rule (row: its port bitmap row, probed if asked): the origin; the
 * FP must be unused. Every refusal here leaves the slices off (fp_unpower),
 * except fp_power_hold.
 */
static int fp_origin(struct bcm53314 *sw, struct device *dev, int row)
{
	u32 w[QF_WORDS], cfg;
	int p, err;

	if (fp_read)
		return fp_busy ? -EBUSY : fp_held(dev);
	err = qs_rd1(sw, FP_A_SLICE_ENABLE, false, "FP_SLICE_ENABLE", 0, &fp_se0);
	if (!err)
		err = qs_rd1(sw, FP_A_SLICE_CONFIG, false, "FP_SLICE_CONFIG", 0, &cfg);
	if (!err && (fp_se0 || cfg)) {
		dev_err(dev, "fp: Field Processor in use at origin (FP_SLICE_ENABLE 0x%08x, FP_SLICE_CONFIG 0x%08x): rules refused, nothing written\n",
			fp_se0, cfg);
		bcm5331x_fp_refusals++;
		fp_read = fp_busy = true;
		return -EBUSY;
	}
	if (!err)
		err = qs_rd1(sw, FP_A_AUX_ARB, false, "AUX_ARB_CONTROL", 0, &fp_arb0);
	if (!err) {
		fp_arb = fp_arb0;
		dev_info(dev, "fp: AUX_ARB_CONTROL at origin %08x (FP_REFRESH_ENABLE %s)\n", fp_arb0,
			 fp_arb0 & FP_ARB_REFRESH ? "already set: nothing to write" : "off");
	}
	/* slices powered, lookups off: the first write */
	if (!err)
		err = fp_power(sw, dev, FP_SE_SLICES);
	if (err)
		return err;
	fp_se = FP_SE_SLICES;
	WRITE_ONCE(fp_dev, dev);
	WRITE_ONCE(fp_sw, sw);
	for (p = 0; p < NUM_PORTS && !err; p++) {
		if (!fp_front(p))
			continue;
		err = qf_rd(sw, FP_A_FSEL(p), true, FP_W_FSEL, w, "FP_PORT_FIELD_SEL", p);
		memcpy(fp_fsel0[p], w, sizeof(fp_fsel0[p]));
	}
	/* the five slice memories to 0, read back: the port bitmaps of origin are 0 */
	if (!err)
		err = fp_clear(sw, dev);
	memcpy(fp_fsel, fp_fsel0, sizeof(fp_fsel));
	memset(fp_eps0, 0, sizeof(fp_eps0));
	memset(fp_eps, 0, sizeof(fp_eps));
	fp_read = true;
	if (err) {
		bcm5331x_fp_refusals++;
		fp_unpower(sw, dev);	/* slices off again (no-op once halted) */
		fp_busy = true;
		return err;
	}
	/* fp_eps_probe: one probe of the row of the rule (now 0: bit 0 as test value) */
	if (!READ_ONCE(fp_eps_probe) || row < 0)
		return fp_held(dev);
	err = fp_eps_try(sw, dev, row);
	if (err) {
		bcm5331x_fp_refusals++;
		fp_unpower(sw, dev);
		fp_busy = true;
		return err;
	}
	return fp_held(dev);
}

/*
 * A rule refused once the origin is read, slices powered and the FP not
 * on (-ENOSPC, FILTER_ENABLE off, a plan refused...), and fp
 * set to N: slices back to 0, the origin read (and the memories cleared)
 * anew at the next first rule. fp_power_hold keeps them on (debugfs).
 */
static void fp_giveback(struct bcm53314 *sw, struct device *dev)
{
	if (!fp_read || fp_active || fp_busy || fp_se != FP_SE_SLICES)
		return;
	fp_unpower(sw, dev);
	if (fp_se == fp_se0)
		fp_read = false;
}

static void fp_param_off(void)
{
	struct bcm53314 *sw;

	mutex_lock(&fp_sw_lock);
	sw = READ_ONCE(fp_sw);
	if (sw) {
		mutex_lock(&sw->lock);
		if (!READ_ONCE(fp_on))
			fp_giveback(sw, READ_ONCE(fp_dev));
		mutex_unlock(&sw->lock);
	}
	mutex_unlock(&fp_sw_lock);
}

static const struct qf_op *fp_earlier(const struct qf_op *op, int cls, int idx);

/* the last earlier op of the plan on register (cls, idx), NULL if none */
static const struct qf_op *fp_earlier(const struct qf_op *op, int cls, int idx)
{
	const struct qf_op *q, *last = NULL;

	for (q = fp_ops; q < op; q++)
		if (q->cls == cls && q->idx == idx)
			last = q;
	return last;
}

static void fp_want_eps(int r, u32 *w);
static bool fp_eps_bits_ok(const struct qf_op *op);
static const u32 *fp_at(const struct qf_op *op, int cls, int idx, const u32 *shadow);

/* FP_SLICE_ENABLE when op runs: the last earlier write of the plan, else the value known */
static u32 fp_se_at(const struct qf_op *op)
{
	const struct qf_op *q, *last = NULL;

	for (q = fp_ops; q < op; q++)
		if (q->cls == FP_C_SE)
			last = q;
	return last ? last->val[0] : fp_se;
}

/* turning on (first rule, slices already powered by fp_origin): port bitmaps to 0, field selectors, then the lookups */
static int fp_plan_on(void)
{
	u32 w[QF_WORDS] = { 0 };
	int p, r, err = 0;

	for (r = 0; r < NUM_PORTS * FP_SLICES && !err; r++)
		err = fp_op_if(FP_C_EPS, r, FP_A_EPS(r), true, FP_W_EPS, "FP_SLICE_ENTRY_PORT_SEL", fp_eps[r], w);
	for (p = 0; p < NUM_PORTS && !err; p++) {
		if (!fp_front(p))
			continue;
		fp_fsel_layout(fp_fsel0[p], w);
		err = fp_op_if(FP_C_FSEL, p, FP_A_FSEL(p), true, FP_W_FSEL, "FP_PORT_FIELD_SEL", fp_fsel[p], w);
	}
	/* meter refresh on before the lookups (no write if set at origin) */
	w[0] = fp_arb0 | FP_ARB_REFRESH;
	if (!err)
		err = fp_op_if(FP_C_ARB, 0, FP_A_AUX_ARB, false, 1, "AUX_ARB_CONTROL", &fp_arb, w);
	w[0] = FP_SE_ALL;
	if (!err)
		err = fp_op_if(FP_C_SE, 0, FP_A_SLICE_ENABLE, false, 1, "FP_SLICE_ENABLE", &fp_se, w);
	return err;
}

/* turning off (last rule removed): FP_SLICE_ENABLE, field selectors, port bitmaps of origin */
static int fp_plan_off(void)
{
	int p, r, err;

	static const u32 se_slices[1] = { FP_SE_SLICES };

	/* lookups off, slices still powered: the rows and selectors written are kept */
	err = fp_op_if(FP_C_SE, 0, FP_A_SLICE_ENABLE, false, 1, "FP_SLICE_ENABLE", &fp_se, se_slices);
	for (p = 0; p < NUM_PORTS && !err; p++)
		if (fp_front(p))
			err = fp_op_if(FP_C_FSEL, p, FP_A_FSEL(p), true, FP_W_FSEL, "FP_PORT_FIELD_SEL",
				       fp_fsel[p], fp_fsel0[p]);
	for (r = 0; r < NUM_PORTS * FP_SLICES && !err; r++)
		err = fp_op_if(FP_C_EPS, r, FP_A_EPS(r), true, FP_W_EPS, "FP_SLICE_ENTRY_PORT_SEL",
			       fp_eps[r], fp_eps0[r]);
	/* meter refresh back to its origin, lookups off, slices still powered */
	if (!err)
		err = fp_op_if(FP_C_ARB, 0, FP_A_AUX_ARB, false, 1, "AUX_ARB_CONTROL", &fp_arb, &fp_arb0);
	/* slices off last (origin 0): the module may power them again at the next first rule */
	if (!err)
		err = fp_op_if(FP_C_SE, 1, FP_A_SLICE_ENABLE, false, 1, "FP_SLICE_ENABLE", &fp_se, &fp_se0);
	return err;
}

/* the FP-wide registers (rule entries: see the rules below) */
static bool fp_op_ok_base(const struct qf_op *op)
{
	const struct qf_op *q;
	u32 w[QF_WORDS];
	int r;

	switch (op->cls) {
	case FP_C_SE:
		if (op->idx > 1 || op->mem || op->words != 1 || op->addr != FP_A_SLICE_ENABLE || op->old[0] != fp_se_at(op))
			return false;
		/* off: lookups off first (idx 0), slices off last (idx 1), FP no longer active */
		if (op->val[0] == FP_SE_SLICES)
			return !fp_active && op->idx == 0 && op->old[0] == FP_SE_ALL;
		if (op->val[0] == fp_se0)
			return !fp_active && op->idx == 1 && op->old[0] == FP_SE_SLICES;
		if (op->idx || op->val[0] != FP_SE_ALL || op->old[0] != FP_SE_SLICES || !fp_active || fp_se0 || fp_busy)
			return false;
		/* slices on only once every port bitmap is 0 (now, or written to 0 earlier in the plan) */
		for (r = 0; r < NUM_PORTS * FP_SLICES; r++) {
			q = fp_earlier(op, FP_C_EPS, r);
			if (q ? (q->val[0] | q->val[1] | q->val[2] | q->val[3]) != 0 : !fp_eps_zero(r))
				return false;
		}
		return true;
	case FP_C_ARB:
		/* FP_REFRESH_ENABLE alone, set from an origin without it, lookups off at both ends */
		if (op->idx || op->mem || op->words != 1 || op->addr != FP_A_AUX_ARB || fp_arb0 & FP_ARB_REFRESH ||
		    fp_se_at(op) != FP_SE_SLICES)
			return false;
		if (fp_active)
			return op->old[0] == fp_arb0 && op->val[0] == (fp_arb0 | FP_ARB_REFRESH);
		return op->old[0] == (fp_arb0 | FP_ARB_REFRESH) && op->val[0] == fp_arb0 &&
		       fp_earlier(op, FP_C_SE, 0);
	case FP_C_FSEL:
		if (!fp_front(op->idx) || !op->mem || op->words != FP_W_FSEL || op->addr != FP_A_FSEL(op->idx) ||
		    memcmp(op->old, fp_at(op, FP_C_FSEL, op->idx, fp_fsel[op->idx]), sizeof(fp_fsel[op->idx])))
			return false;
		if (!memcmp(op->val, fp_fsel0[op->idx], sizeof(fp_fsel0[op->idx])))
			return !fp_active;
		fp_fsel_layout(fp_fsel0[op->idx], w);
		return fp_active && !memcmp(op->val, w, FP_W_FSEL * sizeof(u32));
	case FP_C_EPS:
		r = op->idx;
		if (r < 0 || r >= NUM_PORTS * FP_SLICES || !op->mem || op->words != FP_W_EPS ||
		    op->addr != FP_A_EPS(r) || memcmp(op->old, fp_at(op, FP_C_EPS, r, fp_eps[r]), sizeof(fp_eps[r])))
			return false;
		if (fp_se_at(op) != FP_SE_ALL) {
			/* rows of unpowered slices drop the writes */
			if (fp_se_at(op) != FP_SE_SLICES)
				return false;
			/* lookups off at that point: origin after turning off, 0 before turning on */
			if (!fp_active)
				return fp_earlier(op, FP_C_SE, 0) && !memcmp(op->val, fp_eps0[r], sizeof(fp_eps0[r]));
			return !(op->val[0] | op->val[1] | op->val[2] | op->val[3]);
		}
		fp_want_eps(r, w);
		return !memcmp(op->val, w, FP_W_EPS * sizeof(u32)) && fp_eps_bits_ok(op);
	}
	return false;
}

/* debugfs "fp": reads only (state, FP-wide registers, port bitmaps, valid entries) */
static int fp_show(struct seq_file *m, void *v)
{
	struct bcm53314 *sw = m->private;
	u32 w[QF_WORDS], x;
	int p, i, err, nvalid = 0;

	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : 0;
	seq_printf(m, "fp=%c origin=%s active=%u writes=%lu refusals=%lu eps_probe=%c probes=%lu hold=%c cleared=%lu\n",
		   READ_ONCE(fp_on) ? 'Y' : 'N', !fp_read ? "unread" : fp_busy ? "busy" : "free", fp_active,
		   bcm5331x_fp_writes, bcm5331x_fp_refusals, READ_ONCE(fp_eps_probe) ? 'Y' : 'N',
		   bcm5331x_fp_eps_probes, READ_ONCE(fp_power_hold) ? 'Y' : 'N', bcm5331x_fp_cleared);
	if (!err)
		err = qs_rd1(sw, FP_A_SLICE_ENABLE, false, "FP_SLICE_ENABLE", 0, &x);
	if (!err)
		seq_printf(m, "FP_SLICE_ENABLE %08x", x);
	if (!err)
		err = qs_rd1(sw, FP_A_SLICE_CONFIG, false, "FP_SLICE_CONFIG", 0, &x);
	if (!err)
		seq_printf(m, " FP_SLICE_CONFIG %08x", x);
	if (!err)
		err = qs_rd1(sw, FP_A_METER_CONTROL, false, "FP_METER_CONTROL", 0, &x);
	if (!err)
		seq_printf(m, " FP_METER_CONTROL %08x", x);
	if (!err)
		err = qs_rd1(sw, FP_A_POLICY_PARCTL, false, "FP_POLICY_PARITY_CONTROL", 0, &x);
	if (!err)
		seq_printf(m, " FP_POLICY_PARITY_CONTROL %08x", x);
	if (!err)
		err = qs_rd1(sw, FP_A_MISC_CONFIG2, false, "ING_MISC_CONFIG2", 0, &x);
	if (!err)
		seq_printf(m, " ING_MISC_CONFIG2 %08x", x);
	if (!err)
		err = qs_rd1(sw, FP_A_SLICE_MAP, true, "FP_SLICE_MAP", 0, &x);
	if (!err)
		seq_printf(m, " FP_SLICE_MAP %08x", x);
	if (!err)
		err = sw_read(sw, O_ING_CONFIG, 0, w);
	if (!err)
		seq_printf(m, " ING_CONFIG %08x", w[0]);
	if (!err)
		err = qs_rd1(sw, FP_A_AUX_ARB, false, "AUX_ARB_CONTROL", 0, &x);
	if (!err)
		seq_printf(m, " AUX_ARB_CONTROL %08x\n", x);
	for (p = 0; p < NUM_PORTS && !err; p++) {
		err = qs_rd_pt(sw, p, w);
		if (err)
			break;
		seq_printf(m, "p%-2d FILTER_ENABLE %u FP_PORT_SELECT_TYPE %u", p, w[0] & 1, (w[1] >> 28) & 1);
		err = qf_rd(sw, FP_A_FSEL(p), true, FP_W_FSEL, w, "FP_PORT_FIELD_SEL", p);
		if (!err)
			seq_printf(m, " FSEL %08x:%08x EPS", w[1], w[0]);
		for (i = 0; i < FP_SLICES && !err; i++) {
			err = qf_rd(sw, FP_A_EPS(p << 2 | i), true, FP_W_EPS, w, "FP_SLICE_ENTRY_PORT_SEL", p << 2 | i);
			seq_printf(m, " %08x%08x%08x%08x", w[3], w[2], w[1], w[0]);
		}
		seq_putc(m, '\n');
	}
	/* the 512 entries: valid TCAM entries in full, non-zero policy/meter/counter */
	for (i = 0; i < FP_SLICES * FP_ENTRIES && !err; i++) {
		u32 t[QF_WORDS], po[QF_WORDS], me[QF_WORDS], c;
		int j;

		err = qf_rd(sw, FP_A_TCAM(i), true, FP_W_TCAM, t, "FP_TCAM", i);
		if (!err)
			err = qf_rd(sw, FP_A_POLICY(i), true, FP_W_POLICY, po, "FP_POLICY_TABLE", i);
		if (!err)
			err = qf_rd(sw, FP_A_METER(i), true, FP_W_METER, me, "FP_METER_TABLE", i);
		if (!err)
			err = qs_rd1(sw, FP_A_COUNTER(i), true, "FP_COUNTER_TABLE", i, &c);
		if (err)
			break;
		if (t[0] & 3) {
			nvalid++;
			seq_printf(m, "TCAM %3d", i);
			for (j = FP_W_TCAM - 1; j >= 0; j--)
				seq_printf(m, " %08x", t[j]);
			seq_putc(m, '\n');
		}
		if (po[0] | po[1] | po[2] | po[3] | po[4])
			seq_printf(m, "POLICY %3d %08x %08x %08x %08x %08x\n", i, po[4], po[3], po[2], po[1], po[0]);
		if (me[0] | me[1])
			seq_printf(m, "METER %3d %08x:%08x\n", i, me[1], me[0]);
		if (c)
			seq_printf(m, "COUNTER %3d %u\n", i, c);
	}
	if (!err)
		seq_printf(m, "valid entries %d\n", nvalid);
	mutex_unlock(&sw->lock);
	return err;
}
DEFINE_SHOW_ATTRIBUTE(fp);

/* ---------------------------------------------------------------------- */
/* Rules and their entries                                                 */

enum { FP_K_FLOWER, FP_K_NTUPLE, FP_K_POLICER, FP_K_GUARD };

struct fp_rule {
	bool used;
	bool installed;		/* part of the state in force (its entries written or being written) */
	u8 kind;
	u8 port, slice, entry, slot;
	bool counted, metered;
	bool ip4;		/* the rule matches IPv4 only (EtherType 0x0800, full mask) */
	unsigned long cookie;	/* tc cookie, ntuple location */
	u32 prio;		/* tc priority (lower = first), ntuple location */
	u32 tcam[FP_W_TCAM], pol[FP_W_POLICY], met[FP_W_METER];		/* values asked */
	u32 tcam0[FP_W_TCAM], pol0[FP_W_POLICY], met0[FP_W_METER], cnt0;	/* origin of the entries */
	u32 tcam_c[FP_W_TCAM], pol_c[FP_W_POLICY], met_c[FP_W_METER], cnt_c;	/* last known */
	u32 last_cnt;
	u64 pkts;
};

static struct fp_rule fp_rules[FP_RULES];
static struct fp_rule fp_guard;		/* slice 0 entry 0: pass for 01:80:c2:00:00:0x */
static u32 fp_entry_used[FP_SLICES][FP_ENTRIES / 32];
static u64 __maybe_unused fp_slot_used[FP_SLICES];

static int fp_abs(const struct fp_rule *r)
{
	return r->slice * FP_ENTRIES + r->entry;
}

/*
 * Entries of a rule, in its slice (the policy indexes are relative to the
 * slice): the committed meter of FLOW mode is the odd meter of the pair,
 * COUNTER_MODE NO_YES counts on the even counter of the pair.
 */
static int fp_met_abs(const struct fp_rule *r)
{
	return r->slice * FP_ENTRIES + 2 * r->slot + 1;
}

static int fp_cnt_abs(const struct fp_rule *r)
{
	return r->slice * FP_ENTRIES + 2 * r->slot;
}

static int fp_nrules(int port, int slice)
{
	int i, n = 0;

	for (i = 0; i < FP_RULES; i++)
		if (fp_rules[i].used && fp_rules[i].installed && (port < 0 || fp_rules[i].port == port) &&
		    (slice < 0 || fp_rules[i].slice == slice))
			n++;
	return n;
}

/* port bitmap row r while the FP is on: the entries of the rules in force of that port and slice */
static void fp_want_eps(int r, u32 *w)
{
	int i, p = r >> 2, s = r & 3;

	memset(w, 0, FP_W_EPS * sizeof(u32));
	for (i = 0; i < FP_RULES; i++)
		if (fp_rules[i].used && fp_rules[i].installed && fp_rules[i].port == p && fp_rules[i].slice == s)
			w[fp_rules[i].entry / 32] |= BIT(fp_rules[i].entry % 32);
	if (s == 0 && (w[0] | w[1] | w[2] | w[3]))
		w[0] |= BIT(0);		/* the link-local guard of the port */
}

/* the rule that owns entry i of the meters (FP_C_MET) or of the counters, NULL if none */
static struct fp_rule *fp_pair_owner(int cls, int i)
{
	int k;

	for (k = 0; k < FP_RULES; k++)
		if (fp_rules[k].used && fp_rules[k].counted &&
		    (cls == FP_C_MET ? fp_met_abs(&fp_rules[k]) : fp_cnt_abs(&fp_rules[k])) == i)
			return &fp_rules[k];
	return NULL;
}

/* the rule (or the guard) that owns absolute entry i, NULL if none */
static struct fp_rule *fp_owner(int i)
{
	int k;

	if (fp_guard.used && i == fp_abs(&fp_guard))
		return &fp_guard;
	for (k = 0; k < FP_RULES; k++)
		if (fp_rules[k].used && fp_abs(&fp_rules[k]) == i)
			return &fp_rules[k];
	return NULL;
}

/* ---------------------------------------------------------------------- */
/* tc flower rules: keys, drop and pass                                    */

#define FP_F1			154	/* key fields in FP_TCAM (masks at + FP_MOFF) */
#define FP_F2			26
#define FP_F3			10
#define FP_MOFF			210
#define FP_TCAM_VALID		3
#define FP_ETH_P_IP		0x0800
#define FP_ETH_P_IPV6		0x86dd

/* FP_POLICY_TABLE fields: absolute bit numbers (OpenMDK FP_POLICY_TABLEm) */
#define FPP_REDIRECTION		5	/* 30 bits: modid << 6 | port */
#define FPP_YP_DSCP		54
#define FPP_RP_DSCP		60
#define FPP_NEWDSCP		66
#define FPP_NEWPRI		72
#define FPP_METER_PAIR_MODE	75
#define FPP_METER_TEST_EVEN	78
#define FPP_METER_TEST_ODD	79
#define FPP_METER_UPDATE_EVEN	80
#define FPP_METER_UPDATE_ODD	81
#define FPP_METER_INDEX_EVEN	82
#define FPP_METER_INDEX_ODD	88
#define FPP_COUNTER_MODE	94
#define FPP_COUNTER_INDEX	98
#define FPP_YP_CHANGE_DSCP	104
#define FPP_YP_DROP		109
#define FPP_RP_CHANGE_DSCP	111
#define FPP_RP_DROP		116
#define FPP_DROP		126
#define FPP_PACKET_REDIRECTION	129
#define FPP_CHANGE_DSCP_TOS	134
#define FPP_CHANGE_PRIORITY	137
#define FPP_PARITY		158
/*
 * FP_METER_TABLE (2 words): BUCKETCOUNT 29:0 (half bits, two's complement:
 * the frame passes while it is not negative, then it goes down by its
 * length), BUCKETSIZE 33:30 (code 0-12), REFRESHCOUNT 52:34, REFRESH_MODE 53
 */
#define FPM_BUCKETSIZE		30
#define FPM_BUCKET_FULL(code)	(0x10000u << (code))	/* (4 KiB << code) in half bits, 29 bits at most */
#define FPM_REFRESHCOUNT	34
#define FPM_REFRESH_MAX		0x7ffff
#define FP_PAIR_FLOW		1	/* METER_PAIR_MODE: committed meter alone (include/bcm/field.h) */
#define FP_COUNTER_NO_YES	1	/* COUNTER_MODE: the odd counter of the pair counts every hit */

static void fp_key(u32 *t, int lo, int width, u32 key, u32 mask)
{
	qf_put(t, lo, width, key & mask);
	qf_put(t, lo + FP_MOFF, width, mask);
}

static void fp_key_mac(u32 *t, int lo, const u8 *k, const u8 *m)
{
	fp_key(t, lo, 32, (u32)k[2] << 24 | (u32)k[3] << 16 | (u32)k[4] << 8 | k[5],
	       (u32)m[2] << 24 | (u32)m[3] << 16 | (u32)m[4] << 8 | m[5]);
	fp_key(t, lo + 32, 16, (u32)k[0] << 8 | k[1], (u32)m[0] << 8 | m[1]);
}

static bool fp_mac_zero(const u8 *m)
{
	return !(m[0] | m[1] | m[2] | m[3] | m[4] | m[5]);
}

/* a destination MAC key that can only match a link-local control address 01:80:c2:00:00:0x */
static bool fp_mac_linklocal(const u8 *k, const u8 *m)
{
	static const u8 ll[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };
	static const u8 llm[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0 };
	int i;

	for (i = 0; i < 6; i++)
		if ((m[i] & llm[i]) != llm[i] || (k[i] & llm[i]) != ll[i])
			return false;
	return true;
}

/* the guard entry: pass for 01:80:c2:00:00:0x (slice 0, entry 0) */
static void fp_guard_tcam(u32 *t)
{
	static const u8 ll[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };
	static const u8 llm[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0 };

	memset(t, 0, FP_W_TCAM * sizeof(u32));
	fp_key_mac(t, FP_F2 + 80, ll, llm);
	t[0] |= FP_TCAM_VALID;
}

/* keys of a rule, from tc flower or ethtool ntuple (masks: 0 = not matched) */
struct fp_keys {
	u16 proto, proto_m;
	u8 ipp, ipp_m, tos, tos_m;
	u8 dmac[ETH_ALEN], dmac_m[ETH_ALEN], smac[ETH_ALEN], smac_m[ETH_ALEN];
	u32 v4s, v4s_m, v4d, v4d_m;		/* host order */
	struct in6_addr v6s, v6s_m, v6d, v6d_m;
	u16 l4s, l4s_m, l4d, l4d_m;		/* host order */
};

/*
 * keys -> slice and TCAM key/mask (VALID left 0). Slice 0: MAC addresses
 * and EtherType; slice 1: EtherType 0x0800 (full mask), IPv4 addresses,
 * protocol, L4 ports, TOS; slices 2/3: EtherType 0x86dd, IPv6 source /
 * destination, protocol, traffic class. A rule needing two slices is
 * refused, as a link-local destination and the slow protocols, EAPOL and
 * LLDP EtherTypes (never filtered: the guard passes them).
 */
static int fp_encode(const struct fp_keys *k, struct fp_rule *r, struct netlink_ext_ack *extack)
{
	bool mac = !fp_mac_zero(k->dmac_m) || !fp_mac_zero(k->smac_m);
	bool ip4 = k->v4s_m || k->v4d_m, l4 = k->l4s_m || k->l4d_m, v6s = false, v6d = false;
	u32 *t = r->tcam;
	int i;

	for (i = 0; i < 4; i++) {
		v6s = v6s || k->v6s_m.s6_addr32[i];
		v6d = v6d || k->v6d_m.s6_addr32[i];
	}
	memset(t, 0, FP_W_TCAM * sizeof(u32));
	r->ip4 = k->proto_m == 0xffff && k->proto == FP_ETH_P_IP;
	if (r->ip4 && !mac && !v6s && !v6d) {
		r->slice = 1;
		fp_key(t, FP_F1 + 8, 16, FP_ETH_P_IP, 0xffff);
		if (k->ipp_m)
			fp_key(t, FP_F2 + 56, 8, k->ipp, k->ipp_m);
		if (k->tos_m)
			fp_key(t, FP_F2 + 16, 8, k->tos, k->tos_m);
		if (ip4) {
			fp_key(t, FP_F2 + 96, 32, k->v4s, k->v4s_m);
			fp_key(t, FP_F2 + 64, 32, k->v4d, k->v4d_m);
		}
		if (l4) {
			fp_key(t, FP_F2 + 40, 16, k->l4s, k->l4s_m);
			fp_key(t, FP_F2 + 24, 16, k->l4d, k->l4d_m);
		}
		return 0;
	}
	if (k->proto_m == 0xffff && k->proto == FP_ETH_P_IPV6 && !mac && !ip4 && !l4 && !(v6s && v6d)) {
		const struct in6_addr *a = v6d ? &k->v6d : &k->v6s;
		const struct in6_addr *am = v6d ? &k->v6d_m : &k->v6s_m;

		r->slice = v6d ? 3 : 2;
		fp_key(t, FP_F1 + 8, 16, FP_ETH_P_IPV6, 0xffff);
		if (k->ipp_m)
			fp_key(t, FP_F1, 8, k->ipp, k->ipp_m);
		if (k->tos_m)
			fp_key(t, FP_F3, 8, k->tos, k->tos_m);
		for (i = 0; i < 4 && (v6s || v6d); i++)	/* bit 127 of the field = first bit of the address */
			fp_key(t, FP_F2 + 32 * i, 32, be32_to_cpu(a->s6_addr32[3 - i]),
			       be32_to_cpu(am->s6_addr32[3 - i]));
		return 0;
	}
	if (ip4 || v6s || v6d || l4 || k->tos_m || k->ipp_m) {
		NL_SET_ERR_MSG_MOD(extack, "IP keys need the IPv4 or IPv6 EtherType, no MAC key, one IPv6 address side, no IPv6 port");
		return -EOPNOTSUPP;
	}
	r->slice = 0;
	if (k->proto_m) {
		if (k->proto_m == 0xffff && (k->proto == 0x8809 || k->proto == 0x888e || k->proto == 0x88cc)) {
			NL_SET_ERR_MSG_MOD(extack, "slow protocols, EAPOL and LLDP (link-local) are not filtered");
			return -EOPNOTSUPP;
		}
		fp_key(t, FP_F2 + 16, 16, k->proto, k->proto_m);
	}
	if (mac) {
		if (fp_mac_linklocal(k->dmac, k->dmac_m)) {
			NL_SET_ERR_MSG_MOD(extack, "link-local control frames (01:80:c2:00:00:0x) are not filtered");
			return -EOPNOTSUPP;
		}
		fp_key_mac(t, FP_F2 + 80, k->dmac, k->dmac_m);
		fp_key_mac(t, FP_F2 + 32, k->smac, k->smac_m);
	}
	return 0;
}

/* flower keys; VLAN keys refused (under double tagging the user tag is the inner one), as TTL, fragments */
static int fp_parse_keys(struct flow_rule *rule, struct fp_rule *r, struct netlink_ext_ack *extack)
{
	struct flow_dissector *d = rule->match.dissector;
	u16 addr_type = 0;
	struct fp_keys k;

	memset(&k, 0, sizeof(k));
	if (d->used_keys & ~(BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) | BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
			     BIT_ULL(FLOW_DISSECTOR_KEY_ETH_ADDRS) | BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
			     BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) | BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |
			     BIT_ULL(FLOW_DISSECTOR_KEY_IP))) {
		NL_SET_ERR_MSG_MOD(extack, "key not offloaded (VLAN keys: inner tag under double tagging)");
		return -EOPNOTSUPP;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control m;

		flow_rule_match_control(rule, &m);
		if (m.mask->flags) {
			NL_SET_ERR_MSG_MOD(extack, "fragment flags not offloaded");
			return -EOPNOTSUPP;
		}
		addr_type = m.key->addr_type;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic m;

		flow_rule_match_basic(rule, &m);
		k.proto = be16_to_cpu(m.key->n_proto);
		k.proto_m = be16_to_cpu(m.mask->n_proto);
		k.ipp = m.key->ip_proto;
		k.ipp_m = m.mask->ip_proto;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs m;

		flow_rule_match_eth_addrs(rule, &m);
		memcpy(k.dmac, m.key->dst, ETH_ALEN);
		memcpy(k.dmac_m, m.mask->dst, ETH_ALEN);
		memcpy(k.smac, m.key->src, ETH_ALEN);
		memcpy(k.smac_m, m.mask->src, ETH_ALEN);
	}
	/*
	 * The IPv4 and IPv6 addresses share one union in the keys of
	 * cls_flower (struct fl_flow_key): with IPv4 addresses both keys are
	 * marked used; the control key's addr_type tells which one is meant
	 * (seen with "protocol ip ... dst_ip" taken for IPv6).
	 */
	if ((flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) ||
	     flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) &&
	    addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS && addr_type != FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		NL_SET_ERR_MSG_MOD(extack, "address key without an IPv4 or IPv6 address type");
		return -EOPNOTSUPP;
	}
	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs m;

		flow_rule_match_ipv4_addrs(rule, &m);
		k.v4s = be32_to_cpu(m.key->src);
		k.v4s_m = be32_to_cpu(m.mask->src);
		k.v4d = be32_to_cpu(m.key->dst);
		k.v4d_m = be32_to_cpu(m.mask->dst);
	}
	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		struct flow_match_ipv6_addrs m;

		flow_rule_match_ipv6_addrs(rule, &m);
		k.v6s = m.key->src;
		k.v6s_m = m.mask->src;
		k.v6d = m.key->dst;
		k.v6d_m = m.mask->dst;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports m;

		flow_rule_match_ports(rule, &m);
		k.l4s = be16_to_cpu(m.key->src);
		k.l4s_m = be16_to_cpu(m.mask->src);
		k.l4d = be16_to_cpu(m.key->dst);
		k.l4d_m = be16_to_cpu(m.mask->dst);
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip m;

		flow_rule_match_ip(rule, &m);
		if (m.mask->ttl) {
			NL_SET_ERR_MSG_MOD(extack, "TTL key not offloaded");
			return -EOPNOTSUPP;
		}
		k.tos = m.key->tos;
		k.tos_m = m.mask->tos;
	}
	return fp_encode(&k, r, extack);
}

/*
 * police (tc police rate R burst B conform-exceed drop[/pipe|ok]): FLOW
 * meter, REFRESHCOUNT = R in units of 64 kbit/s (1..0x7ffff), BUCKETSIZE =
 * code of the smallest 4 KiB << code bucket holding B (0-12), BUCKETCOUNT
 * = a full bucket (the head of the traffic is not cut); packet rates, peak
 * rates and any exceed action but drop are refused.
 */
static int fp_police(const struct flow_action_police *pl, u32 *met, struct netlink_ext_ack *extack)
{
	u32 refresh;
	int code;

	if (pl->rate_pkt_ps || pl->burst_pkt || pl->peakrate_bytes_ps || pl->avrate || pl->overhead) {
		NL_SET_ERR_MSG_MOD(extack, "police: byte rate and burst only");
		return -EOPNOTSUPP;
	}
	if (pl->exceed.act_id != FLOW_ACTION_DROP ||
	    (pl->notexceed.act_id != FLOW_ACTION_PIPE && pl->notexceed.act_id != FLOW_ACTION_ACCEPT)) {
		NL_SET_ERR_MSG_MOD(extack, "police: conform-exceed drop/pipe or drop/ok only");
		return -EOPNOTSUPP;
	}
	refresh = qf_refresh(pl->rate_bytes_ps, FPM_REFRESH_MAX);
	code = qf_bucket_code(pl->burst);
	if (!refresh || code < 0) {
		NL_SET_ERR_MSG_MOD(extack, "police: rate or burst out of range");
		return -ERANGE;
	}
	memset(met, 0, FP_W_METER * sizeof(u32));
	qf_put(met, 0, 30, FPM_BUCKET_FULL(code));
	qf_put(met, FPM_BUCKETSIZE, 4, code);
	qf_put(met, FPM_REFRESHCOUNT, 19, refresh);
	return 0;
}

/* switch port of a net device of this switch (a user port), -1 if foreign */
static int fp_dev_port(const struct net_device *dev, struct dsa_switch *ds)
{
	struct dsa_port *dp;

	if (!dev || !dsa_user_dev_check(dev))
		return -1;
	dp = dsa_port_from_netdev((struct net_device *)dev);
	if (IS_ERR_OR_NULL(dp) || dp->ds != ds)
		return -1;
	return dp->index;
}

/*
 * pedit ex munge ip dsfield set (D << 2) retain 0xfc: one mangle of the
 * first word of the IPv4 header (offset 0), DSCP bits only (keys and masks
 * of pedit are in network order); -1 if anything else.
 */
static int fp_mangle_dscp(const struct flow_action_entry *act)
{
	if (act->mangle.htype != FLOW_ACT_MANGLE_HDR_TYPE_IP4 || act->mangle.offset ||
	    ~act->mangle.mask != (__force u32)cpu_to_be32(0x00fc0000))
		return -1;
	return (be32_to_cpu((__force __be32)act->mangle.val) >> 18) & 0x3f;
}

/* actions: one of drop / pass / skbedit priority / pedit DSCP (IPv4) / redirect to a front port, and/or police */
static int fp_parse_actions(struct dsa_switch *ds, struct flow_rule *rule, struct fp_rule *r,
			    struct netlink_ext_ack *extack)
{
	const struct flow_action_entry *act;
	u32 *po = r->pol;
	int i, err, q, main = 0;

	if (!flow_action_basic_hw_stats_check(&rule->action, extack))
		return -EOPNOTSUPP;
	memset(po, 0, FP_W_POLICY * sizeof(u32));
	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_DROP:
			qf_put(po, FPP_DROP, 2, 1);
			qf_put(po, FPP_RP_DROP, 2, 1);
			qf_put(po, FPP_YP_DROP, 2, 1);
			main++;
			break;
		case FLOW_ACTION_ACCEPT:
			main++;
			break;
		case FLOW_ACTION_PRIORITY:	/* skbedit priority P: internal priority of the switch */
			if (act->priority > 7) {
				NL_SET_ERR_MSG_MOD(extack, "skbedit priority 0-7 only");
				return -EOPNOTSUPP;
			}
			qf_put(po, FPP_CHANGE_PRIORITY, 4, 13);	/* PrioIntNew */
			qf_put(po, FPP_NEWPRI, 3, act->priority);
			main++;
			break;
		case FLOW_ACTION_MANGLE:
			q = fp_mangle_dscp(act);
			if (q < 0 || !r->ip4) {
				NL_SET_ERR_MSG_MOD(extack, "pedit: IPv4 DSCP (ip dsfield, retain 0xfc) of an IPv4 rule only");
				return -EOPNOTSUPP;
			}
			qf_put(po, FPP_CHANGE_DSCP_TOS, 3, 3);	/* DscpNew, all colours */
			qf_put(po, FPP_NEWDSCP, 6, q);
			qf_put(po, FPP_RP_CHANGE_DSCP, 1, 1);
			qf_put(po, FPP_RP_DSCP, 6, q);
			qf_put(po, FPP_YP_CHANGE_DSCP, 1, 1);
			qf_put(po, FPP_YP_DSCP, 6, q);
			main++;
			break;
		case FLOW_ACTION_REDIRECT:	/* mirred egress redirect dev portM */
			q = fp_dev_port(act->dev, ds);
			if (!fp_front(q) || q == r->port) {
				NL_SET_ERR_MSG_MOD(extack, "redirect to another front port of the switch only");
				return -EOPNOTSUPP;
			}
			qf_put(po, FPP_PACKET_REDIRECTION, 3, 1);
			qf_put(po, FPP_REDIRECTION, 30, q);	/* module 0 << 6 | port */
			main++;
			break;
		case FLOW_ACTION_POLICE:
			if (r->metered) {
				NL_SET_ERR_MSG_MOD(extack, "one police per rule");
				return -EOPNOTSUPP;
			}
			err = fp_police(&act->police, r->met, extack);
			if (err)
				return err;
			r->metered = true;
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack, "action not offloaded (trap, copy to the CPU, mirror, goto refused)");
			return -EOPNOTSUPP;
		}
	}
	if (main > 1 || (!main && !r->metered)) {
		NL_SET_ERR_MSG_MOD(extack, "one action per rule (and a police)");
		return -EOPNOTSUPP;
	}
	return 0;
}

/* a policy as written: parity bit 158 even, only the fields of the driver, values within their sets */
static bool fp_pol_ok(const u32 *v, const struct fp_rule *r)
{
	u32 x[QF_WORDS] = { 0 };
	u32 drop, rp, yp;

	memcpy(x, v, FP_W_POLICY * sizeof(u32));
	qf_parity(x, FPP_PARITY);
	if (qf_get(x, FPP_PARITY, 1) != qf_get(v, FPP_PARITY, 1))
		return false;
	drop = qf_get(v, FPP_DROP, 2);
	rp = qf_get(v, FPP_RP_DROP, 2);
	yp = qf_get(v, FPP_YP_DROP, 2);
	if (drop > 1 || rp > 1 || yp > 1 || (drop && (!rp || !yp)))
		return false;
	/* counter: none or the odd counter of the rule's own pair */
	if (qf_get(v, FPP_COUNTER_MODE, 4) > FP_COUNTER_NO_YES ||
	    (qf_get(v, FPP_COUNTER_MODE, 4) && (!r->counted || qf_get(v, FPP_COUNTER_INDEX, 6) != r->slot)) ||
	    (!qf_get(v, FPP_COUNTER_MODE, 4) && qf_get(v, FPP_COUNTER_INDEX, 6)))
		return false;
	/* meter: none, or FLOW mode on the committed (odd) meter of the rule's own pair, red dropped */
	if (qf_get(v, FPP_METER_PAIR_MODE, 3)) {
		if (qf_get(v, FPP_METER_PAIR_MODE, 3) != FP_PAIR_FLOW || !r->metered ||
		    qf_get(v, FPP_METER_TEST_EVEN, 1) || qf_get(v, FPP_METER_UPDATE_EVEN, 1) ||
		    !qf_get(v, FPP_METER_TEST_ODD, 1) || !qf_get(v, FPP_METER_UPDATE_ODD, 1) ||
		    qf_get(v, FPP_METER_INDEX_EVEN, 6) != r->slot || qf_get(v, FPP_METER_INDEX_ODD, 6) != r->slot ||
		    !rp)
			return false;
	} else if (qf_get(v, FPP_METER_TEST_EVEN, 4) || qf_get(v, FPP_METER_INDEX_EVEN, 12) || (rp && !drop)) {
		return false;	/* meter fields without a meter; red dropped without a meter */
	}
	/* internal priority: none or PrioIntNew (13) */
	if ((qf_get(v, FPP_CHANGE_PRIORITY, 4) != 0 && qf_get(v, FPP_CHANGE_PRIORITY, 4) != 13) ||
	    (!qf_get(v, FPP_CHANGE_PRIORITY, 4) && qf_get(v, FPP_NEWPRI, 3)))
		return false;
	/* DSCP: none, or DscpNew (3) of every colour with one value */
	if (qf_get(v, FPP_CHANGE_DSCP_TOS, 3) == 3) {
		if (!qf_get(v, FPP_RP_CHANGE_DSCP, 1) || !qf_get(v, FPP_YP_CHANGE_DSCP, 1) ||
		    qf_get(v, FPP_RP_DSCP, 6) != qf_get(v, FPP_NEWDSCP, 6) ||
		    qf_get(v, FPP_YP_DSCP, 6) != qf_get(v, FPP_NEWDSCP, 6) || !r->ip4)
			return false;
	} else if (qf_get(v, FPP_CHANGE_DSCP_TOS, 3) || qf_get(v, FPP_RP_CHANGE_DSCP, 1) ||
		   qf_get(v, FPP_YP_CHANGE_DSCP, 1) || qf_get(v, FPP_NEWDSCP, 6) || qf_get(v, FPP_RP_DSCP, 6) ||
		   qf_get(v, FPP_YP_DSCP, 6)) {
		return false;
	}
	/* redirection: none, or to another front port (module 0) */
	if (qf_get(v, FPP_PACKET_REDIRECTION, 3) == 1) {
		u32 q = qf_get(v, FPP_REDIRECTION, 30);

		if (q >= NUM_PORTS || !fp_front(q) || q == r->port)
			return false;
	} else if (qf_get(v, FPP_PACKET_REDIRECTION, 3) || qf_get(v, FPP_REDIRECTION, 30)) {
		return false;
	}
	memcpy(x, v, FP_W_POLICY * sizeof(u32));
	qf_put(x, FPP_DROP, 2, 0);
	qf_put(x, FPP_RP_DROP, 2, 0);
	qf_put(x, FPP_YP_DROP, 2, 0);
	qf_put(x, FPP_COUNTER_MODE, 4, 0);
	qf_put(x, FPP_COUNTER_INDEX, 6, 0);
	qf_put(x, FPP_METER_PAIR_MODE, 3, 0);
	qf_put(x, FPP_METER_TEST_EVEN, 4, 0);
	qf_put(x, FPP_METER_INDEX_EVEN, 12, 0);
	qf_put(x, FPP_CHANGE_PRIORITY, 4, 0);
	qf_put(x, FPP_NEWPRI, 3, 0);
	qf_put(x, FPP_CHANGE_DSCP_TOS, 3, 0);
	qf_put(x, FPP_NEWDSCP, 6, 0);
	qf_put(x, FPP_RP_CHANGE_DSCP, 1, 0);
	qf_put(x, FPP_RP_DSCP, 6, 0);
	qf_put(x, FPP_YP_CHANGE_DSCP, 1, 0);
	qf_put(x, FPP_YP_DSCP, 6, 0);
	qf_put(x, FPP_PACKET_REDIRECTION, 3, 0);
	qf_put(x, FPP_REDIRECTION, 30, 0);
	qf_put(x, FPP_PARITY, 1, 0);
	return !(x[0] | x[1] | x[2] | x[3] | x[4]);	/* no other field: no copy to the CPU, mirror, L3, chain */
}

/* a TCAM entry as written for a rule in force */
static bool fp_tcam_ok(const u32 *v, const struct fp_rule *r)
{
	u32 x[QF_WORDS];
	int b;

	if ((v[0] & 3) != FP_TCAM_VALID)
		return false;
	/* HIGIG_PKT, IP_TYPE, F4 and the reserved fields: key and mask 0 */
	if (qf_get(v, 2, 8) || qf_get(v, 186, 26) || qf_get(v, 212, 8) || qf_get(v, 396, 26))
		return false;
	/* no key bit outside its mask */
	memcpy(x, v, sizeof(x));
	for (b = 10; b < 186; b++)
		if (qf_get(x, b, 1) && !qf_get(x, b + FP_MOFF, 1))
			return false;
	if (r == &fp_guard)
		return true;
	/* slices 1-3: the IPv4 / IPv6 EtherType, full mask (no link-local control frame can match) */
	if (r->slice == 1)
		return qf_get(v, FP_F1 + 8, 16) == FP_ETH_P_IP && qf_get(v, FP_F1 + 8 + FP_MOFF, 16) == 0xffff;
	if (r->slice >= 2)
		return qf_get(v, FP_F1 + 8, 16) == FP_ETH_P_IPV6 && qf_get(v, FP_F1 + 8 + FP_MOFF, 16) == 0xffff;
	return true;
}

static const u32 *fp_at(const struct qf_op *op, int cls, int idx, const u32 *shadow)
{
	const struct qf_op *q = fp_earlier(op, cls, idx);

	return q ? q->val : shadow;
}

static bool fp_eps_bit_at(const struct qf_op *op, int row, int entry)
{
	const u32 *w = fp_at(op, FP_C_EPS, row, fp_eps[row]);

	return w[entry / 32] & BIT(entry % 32);
}

/* port bitmap: a bit newly set = an entry of a rule of that port, valid at that point; slice 0 with its guard */
static bool fp_eps_bits_ok(const struct qf_op *op)
{
	int row = op->idx, p = row >> 2, s = row & 3, b;
	const struct fp_rule *o;

	for (b = 0; b < FP_ENTRIES; b++) {
		if (!(op->val[b / 32] & BIT(b % 32)) || (op->old[b / 32] & BIT(b % 32)))
			continue;
		o = fp_owner(s * FP_ENTRIES + b);
		if (!o || !o->installed || (o != &fp_guard && o->port != p) || (o == &fp_guard && s))
			return false;
		if ((fp_at(op, FP_C_TCAM, s * FP_ENTRIES + b, o->tcam_c)[0] & 3) != FP_TCAM_VALID)
			return false;
	}
	if (s == 0 && (op->val[0] & ~1u || op->val[1] | op->val[2] | op->val[3]))
		return (op->val[0] & 1) && fp_guard.installed &&
		       (fp_at(op, FP_C_TCAM, 0, fp_guard.tcam_c)[0] & 3) == FP_TCAM_VALID;
	return true;
}

/* an entry of a rule: TCAM (VALID last), policy before it; given back after the bitmap bit is cleared */
static bool fp_op_ok_entry(const struct qf_op *op)
{
	const struct fp_rule *o = fp_owner(op->idx);
	int p;

	if (!o || op->idx < 0 || op->idx >= FP_SLICES * FP_ENTRIES || !op->mem)
		return false;
	switch (op->cls) {
	case FP_C_TCAM:
		if (op->words != FP_W_TCAM || op->addr != FP_A_TCAM(op->idx) ||
		    memcmp(op->old, fp_at(op, FP_C_TCAM, op->idx, o->tcam_c), sizeof(o->tcam_c)))
			return false;
		if (o->installed)
			return !memcmp(op->val, o->tcam, sizeof(o->tcam)) && fp_tcam_ok(op->val, o) &&
			       !memcmp(fp_at(op, FP_C_POL, op->idx, o->pol_c), o->pol, sizeof(o->pol)) &&
			       (o == &fp_guard || !fp_eps_bit_at(op, o->port << 2 | o->slice, o->entry));
		if (memcmp(op->val, o->tcam0, sizeof(o->tcam0)) || (op->val[0] & 3))
			return false;
		if (o != &fp_guard)
			return !fp_eps_bit_at(op, o->port << 2 | o->slice, o->entry);
		for (p = 0; p < NUM_PORTS; p++)
			if (fp_eps_bit_at(op, p << 2, 0))
				return false;
		return true;
	case FP_C_POL:
		if (op->words != FP_W_POLICY || op->addr != FP_A_POLICY(op->idx) ||
		    memcmp(op->old, fp_at(op, FP_C_POL, op->idx, o->pol_c), sizeof(o->pol_c)))
			return false;
		if (fp_at(op, FP_C_TCAM, op->idx, o->tcam_c)[0] & 3)
			return false;	/* never under a valid entry */
		if (o->installed)
			return !memcmp(op->val, o->pol, sizeof(o->pol)) && fp_pol_ok(op->val, o);
		return !memcmp(op->val, o->pol0, sizeof(o->pol0));
	}
	return false;
}

/*
 * Meter and counter of a rule: values of the rule (counter 0, meter of its
 * police: bucket full, REFRESH_MODE 0, bucket code 0-12) before its
 * policy and TCAM entry, origin back after its TCAM entry is invalid.
 */
static bool fp_op_ok_pair(const struct qf_op *op)
{
	const struct fp_rule *o = fp_pair_owner(op->cls, op->idx);
	const u32 *v = op->val;

	if (!o || !op->mem || fp_at(op, FP_C_TCAM, fp_abs(o), o->tcam_c)[0] & 3)
		return false;
	if (op->cls == FP_C_CNT) {
		if (op->words != 1 || op->addr != FP_A_COUNTER(op->idx) ||
		    op->old[0] != fp_at(op, FP_C_CNT, op->idx, &o->cnt_c)[0])
			return false;
		return o->installed ? v[0] == 0 : v[0] == o->cnt0;
	}
	if (op->words != FP_W_METER || op->addr != FP_A_METER(op->idx) ||
	    memcmp(op->old, fp_at(op, FP_C_MET, op->idx, o->met_c), sizeof(o->met_c)))
		return false;
	if (!o->installed || !o->metered)
		return !memcmp(v, o->met0, sizeof(o->met0));
	return !memcmp(v, o->met, sizeof(o->met)) && qf_get(v, FPM_BUCKETSIZE, 4) <= 12 &&
	       qf_get(v, 0, 30) == FPM_BUCKET_FULL(qf_get(v, FPM_BUCKETSIZE, 4)) &&
	       qf_get(v, FPM_REFRESHCOUNT, 19) >= 1 && !qf_get(v, 53, 11);
}

static bool fp_op_ok(const struct bcm53314 *sw, const struct qf_op *op)
{
	u32 ign = 0;
	int j;

	(void)sw;
	/* bits not compared: the counter, the bucket count of a meter, nothing else */
	if (op->cls == FP_C_CNT)
		ign = ~0u;
	if (op->cls == FP_C_MET)
		ign = GENMASK(29, 0);
	if (op->ign[0] != ign)
		return false;
	for (j = 1; j < QF_WORDS; j++)
		if (op->ign[j])
			return false;
	switch (op->cls) {
	case FP_C_MET:
	case FP_C_CNT:
		return fp_op_ok_pair(op);
	case FP_C_TCAM:
	case FP_C_POL:
		return fp_op_ok_entry(op);
	default:
		return fp_op_ok_base(op);
	}
}

static int fp_op_entry(struct fp_rule *r, int cls, const u32 *val)
{
	int i = fp_abs(r);

	switch (cls) {
	case FP_C_TCAM:
		return fp_op_if(FP_C_TCAM, i, FP_A_TCAM(i), true, FP_W_TCAM, "FP_TCAM", r->tcam_c, val);
	case FP_C_POL:
		return fp_op_if(FP_C_POL, i, FP_A_POLICY(i), true, FP_W_POLICY, "FP_POLICY_TABLE", r->pol_c, val);
	case FP_C_MET:
		i = fp_met_abs(r);
		return fp_op_if(FP_C_MET, i, FP_A_METER(i), true, FP_W_METER, "FP_METER_TABLE", r->met_c, val);
	case FP_C_CNT:
		i = fp_cnt_abs(r);
		return fp_op_if(FP_C_CNT, i, FP_A_COUNTER(i), true, 1, "FP_COUNTER_TABLE", &r->cnt_c, val);
	}
	return -EINVAL;
}

static int fp_plan_row(int row)
{
	u32 w[QF_WORDS] = { 0 };

	fp_want_eps(row, w);
	return fp_op_if(FP_C_EPS, row, FP_A_EPS(row), true, FP_W_EPS, "FP_SLICE_ENTRY_PORT_SEL", fp_eps[row], w);
}

/* origin of an entry before its first use: an entry valid at origin is never taken */
static int fp_read_entry(struct bcm53314 *sw, struct fp_rule *r)
{
	u32 w[QF_WORDS];
	int i = fp_abs(r), err;

	err = qf_rd(sw, FP_A_TCAM(i), true, FP_W_TCAM, w, "FP_TCAM", i);
	if (err)
		return err;
	memcpy(r->tcam0, w, sizeof(r->tcam0));
	if (w[0] & 3)
		return -EBUSY;
	err = qf_rd(sw, FP_A_POLICY(i), true, FP_W_POLICY, w, "FP_POLICY_TABLE", i);
	if (err)
		return err;
	memcpy(r->pol0, w, sizeof(r->pol0));
	memcpy(r->tcam_c, r->tcam0, sizeof(r->tcam_c));
	memcpy(r->pol_c, r->pol0, sizeof(r->pol_c));
	return 0;
}

/*
 * Entry of a rule in its slice: after every rule of the same port and
 * slice of lower or equal priority value (tc prio: lower first), before
 * those of higher value (an entry of lower index wins); no move of an
 * entry: no room in between = refused. Slice 0: entry 0 is the guard,
 * entry 127 the matchall policer.
 */
static int fp_alloc_entry(struct bcm53314 *sw, struct fp_rule *r)
{
	int lo = r->slice ? 0 : 1, hi = FP_ENTRIES - 1;
	int k, d, e, err;

	for (k = 0; k < FP_RULES; k++) {
		const struct fp_rule *q = &fp_rules[k];

		if (!q->used || !q->installed || q->port != r->port || q->slice != r->slice || q == r)
			continue;
		/* the matchall policer of a port comes after every other rule of that port */
		if (q->kind == FP_K_POLICER || (r->kind != FP_K_POLICER && q->prio > r->prio))
			hi = min_t(int, hi, q->entry - 1);
		else
			lo = max_t(int, lo, q->entry + 1);
	}
	for (d = 0; d <= hi - lo; d++) {
		/* a policer from the top, a rule from the middle of its room */
		e = r->kind == FP_K_POLICER ? hi - d : lo + (hi - lo) / 2 + (d & 1 ? -(d + 1) / 2 : d / 2);
		if (e < lo || e > hi || (fp_entry_used[r->slice][e / 32] & BIT(e % 32)))
			continue;
		r->entry = e;
		err = fp_read_entry(sw, r);
		if (err == -EBUSY)
			continue;	/* valid at origin: left alone */
		if (err)
			return err;
		fp_entry_used[r->slice][e / 32] |= BIT(e % 32);
		return 0;
	}
	return -ENOSPC;
}

static void fp_free_entry(struct fp_rule *r)
{
	fp_entry_used[r->slice][r->entry / 32] &= ~BIT(r->entry % 32);
	if (r->counted)
		fp_slot_used[r->slice] &= ~BIT_ULL(r->slot);
}

/* the meter/counter pair of a rule (64 per slice): its origin read */
static int fp_alloc_slot(struct bcm53314 *sw, struct fp_rule *r)
{
	u32 w[QF_WORDS];
	int k, i, err;

	for (k = 0; k < FP_SLOTS; k++)
		if (!(fp_slot_used[r->slice] & BIT_ULL(k)))
			break;
	if (k == FP_SLOTS)
		return -ENOSPC;
	r->slot = k;
	i = fp_met_abs(r);
	err = qf_rd(sw, FP_A_METER(i), true, FP_W_METER, w, "FP_METER_TABLE", i);
	if (err)
		return err;
	memcpy(r->met0, w, sizeof(r->met0));
	memcpy(r->met_c, w, sizeof(r->met_c));
	i = fp_cnt_abs(r);
	err = qs_rd1(sw, FP_A_COUNTER(i), true, "FP_COUNTER_TABLE", i, &r->cnt0);
	if (err)
		return err;
	r->cnt_c = r->cnt0;
	r->counted = true;
	fp_slot_used[r->slice] |= BIT_ULL(k);
	return 0;
}

/* the guard of slice 0: installed with the first rule of slice 0, removed with the last one */
static int fp_guard_prepare(struct bcm53314 *sw)
{
	int err;

	if (fp_guard.used)
		return 0;
	memset(&fp_guard, 0, sizeof(fp_guard));
	fp_guard.kind = FP_K_GUARD;
	fp_guard.slice = 0;
	fp_guard.entry = 0;
	err = fp_read_entry(sw, &fp_guard);
	if (err)
		return err;
	fp_guard_tcam(fp_guard.tcam);
	memset(fp_guard.pol, 0, sizeof(fp_guard.pol));	/* pass: no action */
	fp_guard.used = true;
	fp_entry_used[0][0] |= BIT(0);
	return 0;
}

/* plan of an added rule (state already updated): FP on, guard, entries, then the port bitmap bit */
static int fp_plan_add(struct fp_rule *r, bool was_active, bool guard_new)
{
	int err = 0;

	if (!was_active)
		err = fp_plan_on();
	if (!err && guard_new)
		err = fp_op_entry(&fp_guard, FP_C_POL, fp_guard.pol);
	if (!err && guard_new)
		err = fp_op_entry(&fp_guard, FP_C_TCAM, fp_guard.tcam);
	if (!err && r->counted)
		err = fp_op_entry(r, FP_C_CNT, (const u32[1]){ 0 });
	if (!err && r->metered)
		err = fp_op_entry(r, FP_C_MET, r->met);
	if (!err)
		err = fp_op_entry(r, FP_C_POL, r->pol);
	if (!err)
		err = fp_op_entry(r, FP_C_TCAM, r->tcam);
	if (!err)
		err = fp_plan_row(r->port << 2 | r->slice);
	return err;
}

/*
 * Plan of a removed rule (state already updated): the bitmap bit while
 * the FP is still on, the entries back to origin, the guard, then the FP
 * off at the end of the same plan with the last rule.
 */
static int fp_plan_del(struct fp_rule *r, bool guard_gone, bool off)
{
	int err;

	err = fp_plan_row(r->port << 2 | r->slice);
	if (!err)
		err = fp_op_entry(r, FP_C_TCAM, r->tcam0);
	if (!err)
		err = fp_op_entry(r, FP_C_POL, r->pol0);
	if (!err && r->metered)
		err = fp_op_entry(r, FP_C_MET, r->met0);
	/* the counter moved with the traffic since: always written back to its origin */
	if (!err && r->counted)
		err = fp_new_op(FP_C_CNT, fp_cnt_abs(r), FP_A_COUNTER(fp_cnt_abs(r)), true, 1, "FP_COUNTER_TABLE",
				&r->cnt_c, &r->cnt_c, &r->cnt0) ? 0 : -ENOSPC;
	if (!err && guard_gone)
		err = fp_op_entry(&fp_guard, FP_C_TCAM, fp_guard.tcam0);
	if (!err && guard_gone)
		err = fp_op_entry(&fp_guard, FP_C_POL, fp_guard.pol0);
	if (!err && off) {
		fp_active = false;
		err = fp_plan_off();
	}
	return err;
}

static struct fp_rule *fp_find(int port, int kind, unsigned long cookie)
{
	int k;

	for (k = 0; k < FP_RULES; k++)
		if (fp_rules[k].used && fp_rules[k].port == port && fp_rules[k].kind == kind &&
		    fp_rules[k].cookie == cookie)
			return &fp_rules[k];
	return NULL;
}

/* a rule built by its parser (port, kind, cookie, prio, slice, tcam without VALID, pol): allocated, written */
static int fp_add(struct dsa_switch *ds, const struct fp_rule *t, struct netlink_ext_ack *extack)
{
	struct bcm53314 *sw = ds->priv;
	bool was_active, guard_new = false;
	unsigned long w0;	/* writes of this rule, the slice power write (first rule) too */
	struct fp_rule *r = NULL;
	u32 pt[QF_WORDS];
	int k, err;

	mutex_lock(&sw->lock);
	w0 = bcm5331x_fp_writes;
	err = sw->halted ? -EIO : fp_origin(sw, ds->dev, t->port << 2 | t->slice);
	if (err)
		goto out_origin;	/* the slices left as fp_origin left them (fp_power_hold) */
	if (fp_find(t->port, t->kind, t->cookie)) {
		err = -EEXIST;
		goto out;
	}
	/* FILTER_ENABLE of the port (= 1 everywhere at origin, re-100D-G): the FP is not looked up without it */
	err = qs_rd_pt(sw, t->port, pt);
	if (err)
		goto out;
	if (!(pt[0] & BIT(0))) {
		NL_SET_ERR_MSG_MOD(extack, "PORT_TAB.FILTER_ENABLE off on this port");
		err = -EOPNOTSUPP;
		goto out;
	}
	for (k = 0; k < FP_RULES && !r; k++)
		if (!fp_rules[k].used)
			r = &fp_rules[k];
	if (!r) {
		err = -ENOSPC;
		goto out;
	}
	*r = *t;
	r->used = true;
	r->installed = false;
	err = fp_alloc_entry(sw, r);
	if (err) {
		r->used = false;
		if (err == -ENOSPC)
			NL_SET_ERR_MSG_MOD(extack, "no free entry at this priority in the slice");
		goto out;
	}
	err = fp_alloc_slot(sw, r);
	if (err) {
		fp_free_entry(r);
		r->used = false;
		if (err == -ENOSPC)
			NL_SET_ERR_MSG_MOD(extack, "no free meter/counter pair in the slice");
		goto out;
	}
	if (r->slice == 0 && !fp_guard.used) {
		err = fp_guard_prepare(sw);
		if (err) {
			fp_free_entry(r);
			r->used = false;
			if (err == -EBUSY)
				NL_SET_ERR_MSG_MOD(extack, "entry 0 of slice 0 valid at origin: no link-local guard");
			goto out;
		}
		guard_new = true;
	}
	r->tcam[0] = (r->tcam[0] & ~3u) | FP_TCAM_VALID;
	qf_put(r->pol, FPP_COUNTER_MODE, 4, FP_COUNTER_NO_YES);
	qf_put(r->pol, FPP_COUNTER_INDEX, 6, r->slot);
	if (r->metered) {
		qf_put(r->pol, FPP_METER_PAIR_MODE, 3, FP_PAIR_FLOW);
		qf_put(r->pol, FPP_METER_TEST_ODD, 1, 1);
		qf_put(r->pol, FPP_METER_UPDATE_ODD, 1, 1);
		qf_put(r->pol, FPP_METER_INDEX_EVEN, 6, r->slot);
		qf_put(r->pol, FPP_METER_INDEX_ODD, 6, r->slot);
		qf_put(r->pol, FPP_RP_DROP, 2, 1);
	}
	r->last_cnt = 0;
	r->pkts = 0;
	qf_parity(r->pol, FPP_PARITY);
	was_active = fp_active;
	fp_active = true;
	r->installed = true;
	if (guard_new)
		fp_guard.installed = true;
	fp_nops = 0;
	err = fp_plan_add(r, was_active, guard_new);
	if (!err)
		err = fp_run(sw, ds->dev);
	if (err) {
		/* refused before any write (a write fault halts the module) */
		fp_active = was_active;
		r->installed = false;
		fp_free_entry(r);
		r->used = false;
		if (guard_new) {
			fp_guard.installed = false;
			fp_guard.used = false;
			fp_entry_used[0][0] &= ~BIT(0);
		}
	}
out:
	if (err)
		fp_giveback(sw, ds->dev);	/* FP not on, slices off again */
out_origin:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "fp: port %d rule add failed (%d)\n", t->port, err);
	else
		dev_info(ds->dev, "fp: port %d rule in slice %u entry %u (%lu writes)\n", r->port, r->slice,
			 r->entry, bcm5331x_fp_writes - w0);
	return err;
}

/* removal (always permitted, also with fp=N): bit, entries, guard, FP off with the last rule */
static int fp_del_locked(struct dsa_switch *ds, struct fp_rule *r)
{
	struct bcm53314 *sw = ds->priv;
	bool guard_gone, off;
	int err;

	r->installed = false;
	guard_gone = r->slice == 0 && fp_guard.installed && !fp_nrules(-1, 0);
	off = !fp_nrules(-1, -1);
	if (guard_gone)
		fp_guard.installed = false;
	fp_nops = 0;
	err = sw->halted ? -EIO : fp_plan_del(r, guard_gone, off);
	if (!err)
		err = fp_run(sw, ds->dev);
	fp_free_entry(r);
	r->used = false;
	if (guard_gone) {
		fp_guard.used = false;
		fp_entry_used[0][0] &= ~BIT(0);
	}
	if (off)
		fp_active = false;
	/*
	 * FP given back (slices off again): the next first rule reads the origin
	 * anew, slices powered and cleared again
	 */
	if (off && !err)
		fp_read = false;
	if (err)
		dev_err(ds->dev, "fp: port %d rule removal failed (%d)\n", r->port, err);
	return err;
}

static int bcm5331x_dsa_cls_flower_add(struct dsa_switch *ds, int port, struct flow_cls_offload *cls,
				       bool ingress)
{
	struct netlink_ext_ack *extack = cls->common.extack;
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct fp_rule t;
	int err;

	if (!ingress || cls->common.chain_index || !fp_front(port)) {
		NL_SET_ERR_MSG_MOD(extack, "ingress rules of chain 0 on the front ports only");
		return -EOPNOTSUPP;
	}
	/* broadcast / multicast storm control (qos=Y), else the FP */
	err = qs_storm_flower(ds, port, cls);
	if (err != -ENOENT)
		return err;
	if (!READ_ONCE(fp_on)) {
		NL_SET_ERR_MSG_MOD(extack, "Field Processor offload off (module parameter fp=0)");
		return -EOPNOTSUPP;
	}
	memset(&t, 0, sizeof(t));
	t.kind = FP_K_FLOWER;
	t.port = port;
	t.cookie = cls->cookie;
	t.prio = cls->common.prio;
	err = fp_parse_keys(rule, &t, extack);
	if (!err)
		err = fp_parse_actions(ds, rule, &t, extack);
	if (err)
		return err;
	if (access != 2 || dry_run)
		return -EPERM;
	return fp_add(ds, &t, extack);
}

static int bcm5331x_dsa_cls_flower_del(struct dsa_switch *ds, int port, struct flow_cls_offload *cls,
				       bool ingress)
{
	struct bcm53314 *sw = ds->priv;
	struct fp_rule *r;
	int err = 0;

	if (port <= 0 || port >= NUM_PORTS)
		return 0;
	err = qs_storm_del(ds, port, cls->cookie);
	if (err != -ENOENT)
		return err;
	err = 0;
	mutex_lock(&sw->lock);
	r = fp_find(port, FP_K_FLOWER, cls->cookie);
	if (r)
		err = fp_del_locked(ds, r);
	mutex_unlock(&sw->lock);
	return err;
}

/* the counter of a rule (reads only): packets since the last call, on 32 bits read, kept on 64 */
static int bcm5331x_dsa_cls_flower_stats(struct dsa_switch *ds, int port, struct flow_cls_offload *cls,
					 bool ingress)
{
	struct bcm53314 *sw = ds->priv;
	struct fp_rule *r;
	u32 c = 0, d = 0;
	int err = 0;

	if (port <= 0 || port >= NUM_PORTS)
		return -EOPNOTSUPP;
	mutex_lock(&sw->lock);
	r = fp_find(port, FP_K_FLOWER, cls->cookie);
	if (!r || !r->installed || !r->counted) {
		err = -EOPNOTSUPP;
	} else {
		err = sw->halted ? -EIO : qs_rd1(sw, FP_A_COUNTER(fp_cnt_abs(r)), true, "FP_COUNTER_TABLE",
						  fp_cnt_abs(r), &c);
		if (!err) {
			d = c - r->last_cnt;
			r->last_cnt = c;
			r->pkts += d;
		}
	}
	mutex_unlock(&sw->lock);
	if (!err)
		flow_stats_update(&cls->stats, 0, d, 0, jiffies, FLOW_ACTION_HW_STATS_IMMEDIATE);
	return err;
}

/*
 * tc filter add dev portN ingress matchall skip_sw action police ... (the
 * port policer, served by the FP): a slice-0 entry with no key
 * (every frame of the port but the link-local control frames, passed by
 * the guard of entry 0), after every other rule of the port, metered,
 * red dropped, counted.
 */
static int bcm5331x_dsa_port_policer_add(struct dsa_switch *ds, int port,
					 const struct flow_action_police *policer,
					 struct netlink_ext_ack *extack)
{
	struct fp_rule t;
	int err;

	if (!fp_front(port)) {
		NL_SET_ERR_MSG_MOD(extack, "policer on the front ports only");
		return -EOPNOTSUPP;
	}
	if (!READ_ONCE(fp_on)) {
		NL_SET_ERR_MSG_MOD(extack, "Field Processor offload off (module parameter fp=0)");
		return -EOPNOTSUPP;
	}
	memset(&t, 0, sizeof(t));
	t.kind = FP_K_POLICER;
	t.port = port;
	t.slice = 0;
	t.prio = ~0u;
	err = fp_police(policer, t.met, extack);
	if (err)
		return err;
	t.metered = true;
	if (access != 2 || dry_run)
		return -EPERM;
	return fp_add(ds, &t, extack);
}

static void bcm5331x_dsa_port_policer_del(struct dsa_switch *ds, int port)
{
	struct bcm53314 *sw = ds->priv;
	struct fp_rule *r;

	if (port <= 0 || port >= NUM_PORTS)
		return;
	mutex_lock(&sw->lock);
	r = fp_find(port, FP_K_POLICER, 0);
	if (r)
		fp_del_locked(ds, r);
	mutex_unlock(&sw->lock);
}

/* ---------------------------------------------------------------------- */
/* ethtool ntuple drop rules on the same engine                            */

/*
 * ethtool -N portN flow-type ether|tcp4|udp4|ip4 ... action -1 loc L: a
 * drop rule at location L (0-127, explicit; the rules of a port are
 * ordered by location among themselves), keys as flower (slice 0 for
 * ether, slice 1 for IPv4); FLOW_EXT, FLOW_MAC_EXT, RSS, IPv6, the L4
 * bytes of ip4 and any action but drop (RX_CLS_FLOW_DISC) refused.
 */
static struct ethtool_rx_flow_spec fp_nt_fs[FP_RULES];	/* the rule as given, by rule slot */

static int fp_nt_keys(const struct ethtool_rx_flow_spec *fs, struct fp_keys *k, struct netlink_ext_ack *extack)
{
	const struct ethtool_tcpip4_spec *h4 = &fs->h_u.tcp_ip4_spec, *m4 = &fs->m_u.tcp_ip4_spec;
	const struct ethtool_usrip4_spec *hu = &fs->h_u.usr_ip4_spec, *mu = &fs->m_u.usr_ip4_spec;

	memset(k, 0, sizeof(*k));
	switch (fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS)) {	/* the flags: refused by the caller */
	case ETHER_FLOW:
		memcpy(k->dmac, fs->h_u.ether_spec.h_dest, ETH_ALEN);
		memcpy(k->dmac_m, fs->m_u.ether_spec.h_dest, ETH_ALEN);
		memcpy(k->smac, fs->h_u.ether_spec.h_source, ETH_ALEN);
		memcpy(k->smac_m, fs->m_u.ether_spec.h_source, ETH_ALEN);
		k->proto = be16_to_cpu(fs->h_u.ether_spec.h_proto);
		k->proto_m = be16_to_cpu(fs->m_u.ether_spec.h_proto);
		return 0;
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
		k->proto = FP_ETH_P_IP;
		k->proto_m = 0xffff;
		k->ipp = (fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS)) == TCP_V4_FLOW ? 6 : 17;
		k->ipp_m = 0xff;
		k->v4s = be32_to_cpu(h4->ip4src);
		k->v4s_m = be32_to_cpu(m4->ip4src);
		k->v4d = be32_to_cpu(h4->ip4dst);
		k->v4d_m = be32_to_cpu(m4->ip4dst);
		k->l4s = be16_to_cpu(h4->psrc);
		k->l4s_m = be16_to_cpu(m4->psrc);
		k->l4d = be16_to_cpu(h4->pdst);
		k->l4d_m = be16_to_cpu(m4->pdst);
		k->tos = h4->tos;
		k->tos_m = m4->tos;
		return 0;
	case IP_USER_FLOW:
		if (hu->ip_ver != ETH_RX_NFC_IP4 || mu->l4_4_bytes) {
			NL_SET_ERR_MSG_MOD(extack, "ip4 rules without L4 bytes only");
			return -EOPNOTSUPP;
		}
		k->proto = FP_ETH_P_IP;
		k->proto_m = 0xffff;
		k->ipp = hu->proto;
		k->ipp_m = mu->proto;
		k->v4s = be32_to_cpu(hu->ip4src);
		k->v4s_m = be32_to_cpu(mu->ip4src);
		k->v4d = be32_to_cpu(hu->ip4dst);
		k->v4d_m = be32_to_cpu(mu->ip4dst);
		k->tos = hu->tos;
		k->tos_m = mu->tos;
		return 0;
	}
	return -EOPNOTSUPP;
}

static int bcm5331x_dsa_set_rxnfc(struct dsa_switch *ds, int port, struct ethtool_rxnfc *nfc)
{
	struct ethtool_rx_flow_spec *fs = &nfc->fs;
	struct bcm53314 *sw = ds->priv;
	struct fp_rule t, *r;
	struct fp_keys k;
	int err;

	if (!fp_front(port))
		return -EOPNOTSUPP;
	if (nfc->cmd == ETHTOOL_SRXCLSRLDEL) {
		mutex_lock(&sw->lock);
		r = fs->location < FP_ENTRIES ? fp_find(port, FP_K_NTUPLE, fs->location) : NULL;
		err = r ? fp_del_locked(ds, r) : -ENOENT;
		mutex_unlock(&sw->lock);
		return err;
	}
	if (nfc->cmd != ETHTOOL_SRXCLSRLINS)
		return -EOPNOTSUPP;
	if (!READ_ONCE(fp_on))
		return -EOPNOTSUPP;
	if ((fs->flow_type & (FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS)) || fs->ring_cookie != RX_CLS_FLOW_DISC ||
	    fs->location >= FP_ENTRIES)
		return -EOPNOTSUPP;
	memset(&t, 0, sizeof(t));
	t.kind = FP_K_NTUPLE;
	t.port = port;
	t.cookie = fs->location;
	t.prio = fs->location;
	err = fp_nt_keys(fs, &k, NULL);
	if (!err)
		err = fp_encode(&k, &t, NULL);
	if (err)
		return err;
	qf_put(t.pol, FPP_DROP, 2, 1);
	qf_put(t.pol, FPP_RP_DROP, 2, 1);
	qf_put(t.pol, FPP_YP_DROP, 2, 1);
	if (access != 2 || dry_run)
		return -EPERM;
	err = fp_add(ds, &t, NULL);
	if (err == -EEXIST)
		return -EBUSY;	/* location taken: delete it first */
	if (!err) {
		mutex_lock(&sw->lock);
		r = fp_find(port, FP_K_NTUPLE, fs->location);
		if (r)
			fp_nt_fs[r - fp_rules] = *fs;
		mutex_unlock(&sw->lock);
	}
	return err;
}

static int bcm5331x_dsa_get_rxnfc(struct dsa_switch *ds, int port, struct ethtool_rxnfc *nfc, u32 *rule_locs)
{
	struct bcm53314 *sw = ds->priv;
	int k, n = 0, err = 0;
	struct fp_rule *r;

	if (!fp_front(port))
		return -EOPNOTSUPP;
	mutex_lock(&sw->lock);
	switch (nfc->cmd) {
	case ETHTOOL_GRXCLSRLCNT:
		nfc->rule_cnt = 0;
		for (k = 0; k < FP_RULES; k++)
			if (fp_rules[k].used && fp_rules[k].kind == FP_K_NTUPLE && fp_rules[k].port == port)
				nfc->rule_cnt++;
		nfc->data = FP_ENTRIES;
		break;
	case ETHTOOL_GRXCLSRULE:
		r = nfc->fs.location < FP_ENTRIES ? fp_find(port, FP_K_NTUPLE, nfc->fs.location) : NULL;
		if (r)
			nfc->fs = fp_nt_fs[r - fp_rules];
		else
			err = -ENOENT;
		break;
	case ETHTOOL_GRXCLSRLALL:
		for (k = 0; k < FP_RULES && !err; k++) {
			if (!fp_rules[k].used || fp_rules[k].kind != FP_K_NTUPLE || fp_rules[k].port != port)
				continue;
			if (n >= (int)nfc->rule_cnt)
				err = -EMSGSIZE;
			else
				rule_locs[n++] = fp_rules[k].cookie;
		}
		nfc->rule_cnt = n;
		nfc->data = FP_ENTRIES;
		break;
	default:
		err = -EOPNOTSUPP;
	}
	mutex_unlock(&sw->lock);
	return err;
}

/* teardown: rules left are removed (DSA removes them first), the FP given back */
static void fp_teardown(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;
	int k, err = 0;

	mutex_lock(&fp_sw_lock);
	WRITE_ONCE(fp_sw, NULL);
	mutex_unlock(&fp_sw_lock);
	mutex_lock(&sw->lock);
	for (k = 0; k < FP_RULES; k++)
		if (fp_rules[k].used) {
			dev_warn(ds->dev, "fp: rule left at teardown, removed\n");
			err = fp_del_locked(ds, &fp_rules[k]) ?: err;
		}
	if (fp_read && fp_active) {
		fp_active = false;
		fp_nops = 0;
		err = sw->halted ? -EIO : fp_plan_off();
		if (!err)
			err = fp_run(sw, ds->dev);
	} else if (fp_read && !fp_busy && fp_se == FP_SE_SLICES) {
		/* slices powered, FP never turned on (rule refused, fp_power_hold): origin */
		fp_unpower(sw, ds->dev);
		if (fp_se != fp_se0)
			err = -EIO;
	}
	if (err)
		dev_err(ds->dev, "fp: origin not restored at teardown (%d)\n", err);
	fp_read = false;
	fp_active = false;
	fp_busy = false;
	memset(fp_rules, 0, sizeof(fp_rules));
	memset(&fp_guard, 0, sizeof(fp_guard));
	memset(fp_entry_used, 0, sizeof(fp_entry_used));
	memset(fp_slot_used, 0, sizeof(fp_slot_used));
	mutex_unlock(&sw->lock);
}
