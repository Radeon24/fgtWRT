/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared between the DSA driver of the BCM53314 switch of the FortiGate
 * 100D and its VLAN-based tagger.
 *
 * The switch has no CPU header on its Ethernet ports: each front port
 * gets a VLAN of its own, shared with the CPU link only (untagged on the
 * front port, tagged on the CPU link). The tagger turns the VID of a
 * frame from the CPU link into the source port, and the destination port
 * of a frame from the host into its VID. The tagger allocates the two
 * tables in its .connect; the switch driver fills them once, from its
 * .connect_tag_protocol (called by DSA right after .connect, after .setup,
 * before any user port exists); they never change afterwards.
 *
 * Outer tag protocol (double tagging): by default the port VID rides
 * in an 802.1Q tag (TPID 0x8100). When the driver has put the switch in
 * double-tagging mode (module parameter qinq), the CPU link is a provider
 * port whose outer tag has TPID 0x88a8 and the frame keeps, as inner tag,
 * whatever 802.1Q tag it had on the front port: the driver then sets tpid
 * to 0x88a8 together with the tables.
 *
 * Hardware bridging (module parameter hwbridge of the driver):
 * the front ports of a VLAN-unaware bridge that forward in hardware share
 * a bridge VID (BCM5331X_BR_VID_FIRST + bridge number - 1) as their port
 * VID; a frame they send to the host arrives with that VID and no longer
 * tells its port. The driver then keeps, for each bridge VID, a member
 * port (the "designated" one: the frame is delivered to it, marked as
 * already forwarded by the switch), and for each such port its bridge VID
 * (a frame the bridge hands over for forwarding offload, skb->
 * offload_fwd_mark, is sent with it, and the switch forwards it by its own
 * address table). These two tables change at run time (bridge join/leave,
 * STP state), one entry at a time, read without lock by the tagger.
 *
 * VLAN-aware bridging (module parameter vlanbr of the driver, with hwbridge
 * and qinq): the front ports of one VLAN-aware bridge that
 * forward in hardware classify on their own 802.1Q tag; each user VLAN of
 * that bridge is a VLAN of the switch (hardware VID = user VID, or a VID of
 * the pool BCM5331X_VL_POOL_FIRST.. for a user VID the switch reserves).
 * A frame of such a VLAN reaches the host with the hardware VID: the driver
 * keeps, for each hardware VID in use, its user VID (vid_uvid, the tagger
 * gives the frame back its 802.1Q tag) and a designated member port
 * (vid_port, as for a bridge VID: "imprecise" receive, as the tag_8021q
 * taggers do for VLAN-aware bridges), and, for each user VID in use, its
 * hardware VID (uvid_hw: a frame the bridge hands over for forwarding
 * offload from a port of that bridge, port_vaware, is sent with it, its
 * 802.1Q tag removed: the switch adds it back on the tagged member ports).
 */
#ifndef BCM5331X_DSA_H
#define BCM5331X_DSA_H

#include <linux/if_vlan.h>
#include <linux/types.h>

#define BCM5331X_TAG_NAME	"bcm5331x-8021q"
#define BCM5331X_TAG_PORTS	32	/* DSA port index = switch port, 0-24 */
/* bridge VIDs of hardware bridging: bridge number 1-8 -> VID 141-148 */
#define BCM5331X_BR_MAX		8
#define BCM5331X_BR_VID_FIRST_DEF	141
#define BCM5331X_BR_VID_OFF	41	/* bridge VIDs at vid_base + 41..48 (141-148 at vid_base 100) */
#ifndef BCM5331X_BR_VID_FIRST
#define BCM5331X_BR_VID_FIRST	BCM5331X_BR_VID_FIRST_DEF
#endif
#define BCM5331X_BR_VID(num)	(BCM5331X_BR_VID_FIRST + (num) - 1)
/* VLAN-aware bridging: hardware VIDs 4079-4094 for user VIDs the switch reserves */
#define BCM5331X_VL_POOL_FIRST	4079

struct bcm5331x_tagger_data {
	u16 port_vid[BCM5331X_TAG_PORTS];	/* VID of each user port, 0 = none */
	u8 vid_port[VLAN_N_VID];		/* user port of each VID, 0 = none (port 0 is never a user port) */
	u16 port_bvid[BCM5331X_TAG_PORTS];	/* bridge VID of a port forwarding in hardware, 0 = none */
	u16 br_vid_first;			/* first bridge VID (vid_base + 41), set before ready */
	u16 vid_uvid[VLAN_N_VID];		/* user VID of a hardware VID of the VLAN-aware bridge, 0 = none */
	u16 uvid_hw[VLAN_N_VID];		/* hardware VID of a user VID of that bridge, 0 = none */
	u8 port_vaware[BCM5331X_TAG_PORTS];	/* port of the VLAN-aware bridge forwarding in hardware */
	u16 tpid;				/* outer TPID: 0 or 0x8100 = 802.1Q, 0x88a8 = Q-in-Q */
	u8 vaware_ad;				/* the VLAN-aware bridge is 802.1ad (vlanbr_ad): user tags 0x88a8 */
	bool ready;				/* tables complete */
};

/* TPID of the outer (port) tag, host order */
static inline u16 bcm5331x_tag_tpid(const struct bcm5331x_tagger_data *td)
{
	return td && td->tpid == ETH_P_8021AD ? ETH_P_8021AD : ETH_P_8021Q;
}

/* VID to send a frame of user port @port with, 0 = none */
static inline u16 bcm5331x_tag_vid(const struct bcm5331x_tagger_data *td, int port)
{
	if (!td || !READ_ONCE(td->ready) || port <= 0 || port >= BCM5331X_TAG_PORTS)
		return 0;
	return td->port_vid[port];
}

/* User port a frame received with @tci comes from, 0 = none */
static inline int bcm5331x_tag_port(const struct bcm5331x_tagger_data *td, u16 tci)
{
	if (!td || !READ_ONCE(td->ready))
		return 0;
	return READ_ONCE(td->vid_port[tci & VLAN_VID_MASK]);
}

/* VID is a bridge VID (hardware bridging) */
static inline bool bcm5331x_tag_is_bridge_vid(const struct bcm5331x_tagger_data *td, u16 tci)
{
	u16 vid = tci & VLAN_VID_MASK;
	u16 first = td ? READ_ONCE(td->br_vid_first) : 0;

	/* tables not filled yet: the default block (vid_base 100) */
	if (!first)
		first = BCM5331X_BR_VID_FIRST_DEF;
	return vid >= first && vid < first + BCM5331X_BR_MAX;
}

/* bridge VID to send a frame offloaded by the bridge to user port @port with, 0 = none */
static inline u16 bcm5331x_tag_bvid(const struct bcm5331x_tagger_data *td, int port)
{
	if (!td || !READ_ONCE(td->ready) || port <= 0 || port >= BCM5331X_TAG_PORTS)
		return 0;
	return READ_ONCE(td->port_bvid[port]);
}

/* user VID of a frame received with @tci (VLAN-aware bridging), 0 = none */
static inline u16 bcm5331x_tag_uvid(const struct bcm5331x_tagger_data *td, u16 tci)
{
	if (!td || !READ_ONCE(td->ready))
		return 0;
	return READ_ONCE(td->vid_uvid[tci & VLAN_VID_MASK]);
}

/* TPID of the user VLAN tags of the VLAN-aware bridge, host order */
static inline u16 bcm5331x_tag_uproto(const struct bcm5331x_tagger_data *td)
{
	return td && READ_ONCE(td->vaware_ad) ? ETH_P_8021AD : ETH_P_8021Q;
}

/* hardware VID to send a frame of user VID @uvid offloaded from port @port with, 0 = none */
static inline u16 bcm5331x_tag_hwvid(const struct bcm5331x_tagger_data *td, int port, u16 uvid)
{
	if (!td || !READ_ONCE(td->ready) || port <= 0 || port >= BCM5331X_TAG_PORTS ||
	    !READ_ONCE(td->port_vaware[port]))
		return 0;
	return READ_ONCE(td->uvid_hw[uvid & VLAN_VID_MASK]);
}

#endif
