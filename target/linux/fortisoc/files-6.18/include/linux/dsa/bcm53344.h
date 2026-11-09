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

struct bcm53344_tagger_data {
	u32 xlt[VLAN_N_VID];	/* by internal VID, written with WRITE_ONCE */
};

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

#endif /* _LINUX_DSA_BCM53344_H */
