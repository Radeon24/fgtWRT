/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Data shared by the BCM53344 switch driver, its tag driver
 * (bcm53344-8021q) and the NP6Lite flow offload.
 *
 * An 802.1Q device on a standalone user port (port1.10) is translated by
 * the switch: a frame tagged 10 entering port1 is put on an internal VLAN
 * of its own, and leaves the switch towards the CPU port with that one tag;
 * a frame the CPU port receives with the internal VID leaves port1 tagged
 * 10. xlt[] maps each internal VID in use to its user port and its VID.
 *
 * The VLANs of the one VLAN-aware bridge reach the CPU port with their own
 * VID. aw_* holds them as the switch applies them (switch driver, under
 * aw_seq): which user ports (bit = DSA port index) are in a VLAN, which of
 * them leave it untagged, the PVID of each and how many VLANs it leaves
 * untagged. bcm53344_aware_gen counts the changes (any instance).
 */
#ifndef _LINUX_DSA_BCM53344_H
#define _LINUX_DSA_BCM53344_H

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/if_vlan.h>
#include <net/dsa.h>

#define BCM53344_XLT_VALID	BIT(31)
#define BCM53344_XLT_PORT	GENMASK(23, 16)	/* DSA port index */
#define BCM53344_XLT_VID	GENMASK(11, 0)	/* VID on the wire */

#define BCM53344_AW_PORTS	16	/* user ports of an instance */

struct bcm53344_tagger_data {
	u32 xlt[VLAN_N_VID];	/* by internal VID, written with WRITE_ONCE */
	/* VLAN-aware bridge: odd aw_seq while the switch driver writes */
	u32 aw_seq;
	u16 aw_ports;			/* user ports in the VLAN-aware bridge */
	u16 aw_mem[VLAN_N_VID];		/* members of a VLAN */
	u16 aw_ut[VLAN_N_VID];		/* members leaving it untagged */
	u16 aw_pvid[BCM53344_AW_PORTS];	/* 0: none */
	u16 aw_nut[BCM53344_AW_PORTS];	/* VLANs left untagged by a port */
};

extern atomic_t bcm53344_aware_gen;

static inline struct bcm53344_tagger_data *
bcm53344_tagger_data(const struct dsa_switch *ds)
{
	return ds->tagger_data;
}

/*
 * Internal VID of 802.1Q VID @vid on user port @port of @ds, 0 if the
 * switch does not translate it (now). Any context.
 */
static inline u16 bcm53344_xlt_ivid(const struct dsa_switch *ds, int port,
				    u16 vid)
{
	const struct bcm53344_tagger_data *td = bcm53344_tagger_data(ds);
	u32 want = BCM53344_XLT_VALID |
		   FIELD_PREP(BCM53344_XLT_PORT, port) |
		   FIELD_PREP(BCM53344_XLT_VID, vid);
	u16 i;

	if (!td || !vid)
		return 0;
	for (i = 1; i < VLAN_N_VID - 1; i++)
		if (READ_ONCE(td->xlt[i]) == want)
			return i;
	return 0;
}

/*
 * The VLAN of the VLAN-aware bridge a flow end on user port @port of @ds is
 * in, that is the VID its frames carry to and from the CPU port: @vid for
 * a tagged end (the port a member that keeps the tag), or for an untagged
 * end (@vid 0) the PVID, only when it is the one VLAN the port leaves
 * untagged (else the VLAN of the end is not known). 0 when there is none.
 * Any context.
 */
static inline u16 bcm53344_aware_vid(const struct dsa_switch *ds, int port,
				     u16 vid)
{
	const struct bcm53344_tagger_data *td = bcm53344_tagger_data(ds);
	u16 r, pvid, bit;
	u32 seq;

	if (!td || port < 0 || port >= BCM53344_AW_PORTS || vid >= VLAN_N_VID - 1)
		return 0;
	bit = BIT(port);
	do {
		seq = READ_ONCE(td->aw_seq);
		smp_rmb();
		r = 0;
		pvid = READ_ONCE(td->aw_pvid[port]);
		if (!(READ_ONCE(td->aw_ports) & bit))
			;
		else if (vid)
			r = (READ_ONCE(td->aw_mem[vid]) & bit) &&
			    !(READ_ONCE(td->aw_ut[vid]) & bit) ? vid : 0;
		else if (pvid && pvid < VLAN_N_VID - 1 &&
			 READ_ONCE(td->aw_nut[port]) == 1 &&
			 (READ_ONCE(td->aw_mem[pvid]) & bit) &&
			 (READ_ONCE(td->aw_ut[pvid]) & bit))
			r = pvid;
		smp_rmb();
	} while ((seq & 1) || READ_ONCE(td->aw_seq) != seq);
	return r;
}

#endif /* _LINUX_DSA_BCM53344_H */
