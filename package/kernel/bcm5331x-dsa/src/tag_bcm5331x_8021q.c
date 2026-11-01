// SPDX-License-Identifier: GPL-2.0-only
/*
 * DSA tagger of the BCM53314 switch of the Fortinet FortiGate 100D
 *
 * The BCM53314 (StrataXGS) has no CPU header on its Ethernet ports: the
 * port of a frame exchanged with the host is told by an 802.1Q tag (TPID
 * 0x8100), one VID per front port, set up by the switch driver. On
 * receive the tag is taken from the frame or from the VLAN offload of the
 * conduit, looked up and removed; on transmit the VID of the destination
 * port is pushed in front of the frame, any VLAN tag the stack already
 * attached to it being written into the frame first, so that the port VID
 * stays the outer one. A short frame is padded to 64 bytes with its tag, so
 * that it still has the Ethernet minimum once the switch has removed the tag
 * on its way out of the front port (the switch MACs do not pad). The VID to
 * port table belongs to the switch driver
 * (struct bcm5331x_tagger_data); this file only allocates it.
 *
 * In double-tagging mode (the switch driver sets the outer TPID
 * to 0x88a8 in the shared data) the port VID rides in an 802.1ad outer tag
 * the 82574L conduit does not strip: it is found in the frame and removed
 * there, any 802.1Q tag behind it (a user VLAN of the front port) staying in
 * the frame for the stack. A hardware-accelerated 0x8100 tag is then never a
 * port tag and the frame is dropped.
 *
 * Hardware bridging (switch driver parameter hwbridge): a frame received
 * with a bridge VID is delivered to the member port the driver designates
 * for it and marked as already forwarded by the switch (offload_fwd_mark),
 * so the software bridge does not forward it again to the other members;
 * a frame the bridge hands over with offload_fwd_mark (tx_fwd_offload) is
 * sent with the bridge VID of its port, if the port forwards in hardware,
 * and the switch forwards it by its own address table. Without a bridge
 * VID for the port the port VID is used, as before.
 *
 * VLAN-aware bridging (switch driver parameter vlanbr): a frame received
 * with a hardware VID of the VLAN-aware bridge was classified by the switch
 * on its user VLAN (the 802.1Q tag on the front port, or the PVID): it gets
 * that user VLAN back as an accelerated 802.1Q tag and is delivered to the
 * designated member port, marked as already forwarded; a frame the bridge
 * hands over with offload_fwd_mark from a port of that bridge, carrying a
 * user VLAN in use, loses that 802.1Q tag and is sent with the hardware
 * VID: the switch forwards it in that VLAN and tags it again on the tagged
 * member ports. Any other frame keeps the port VID (exact port). An 802.1ad
 * VLAN-aware bridge (switch driver parameter vlanbr_ad) works the same with
 * 0x88a8 user tags: given back as accelerated 0x88a8 tags, taken off the
 * frames that bridge offloads.
 *
 * The tag_8021q helpers of DSA are not used: their encoding gives the
 * port 4 bits, too few for the 19 front ports of this switch.
 */
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <net/dsa.h>

#include "tag.h"
#include "bcm5331x-dsa.h"

#ifndef DSA_TAG_PROTO_BCM5331X_8021Q_VALUE
#error "the tag protocol number of the BCM53314 is missing from include/net/dsa.h"
#endif

/*
 * Write a VLAN header in front of the payload; the skb is never freed
 * here (the caller does it on error, once).
 */
static int bcm5331x_push_tag(struct sk_buff *skb, __be16 proto, u16 tci)
{
	return __vlan_insert_inner_tag(skb, proto, tci, ETH_HLEN);
}

/*
 * Tag of protocol @proto (0x8100, or 0x88a8 for an 802.1ad bridge) the
 * bridge left on a frame it offloads (accelerated, or in the frame when the
 * stack did not accelerate it): its TCI, false if none.
 */
static bool bcm5331x_user_tag(struct sk_buff *skb, u16 proto, u16 *tci)
{
	if (skb_vlan_tag_present(skb)) {
		if (skb->vlan_proto != htons(proto))
			return false;
		*tci = skb_vlan_tag_get(skb);
		return true;
	}
	if (skb->len < VLAN_ETH_HLEN || vlan_eth_hdr(skb)->h_vlan_proto != htons(proto))
		return false;
	*tci = ntohs(vlan_eth_hdr(skb)->h_vlan_TCI);
	return true;
}

/* remove that tag (skb->data is at the MAC header on transmit) */
static int bcm5331x_drop_user_tag(struct sk_buff *skb)
{
	u16 tci;

	if (skb_vlan_tag_present(skb)) {
		__vlan_hwaccel_clear_tag(skb);
		return 0;
	}
	return __skb_vlan_pop(skb, &tci);
}

static struct sk_buff *bcm5331x_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct dsa_port *dp = dsa_user_to_port(dev);
	u16 vid = bcm5331x_tag_vid(dp->ds->tagger_data, dp->index);
	u8 pcp = netdev_txq_to_tc(dev, skb_get_queue_mapping(skb));
	u16 tpid = bcm5331x_tag_tpid(dp->ds->tagger_data);

	if (!vid)
		return NULL;
	/* forwarding offloaded by the bridge: the switch forwards in the bridge VLAN */
	if (skb->offload_fwd_mark) {
		u16 bvid = bcm5331x_tag_bvid(dp->ds->tagger_data, dp->index);
		u16 utci, hw;

		if (bvid) {
			vid = bvid;
		} else if (bcm5331x_user_tag(skb, bcm5331x_tag_uproto(dp->ds->tagger_data), &utci) &&
			   (hw = bcm5331x_tag_hwvid(dp->ds->tagger_data, dp->index, utci))) {
			/* VLAN-aware bridge: the user VLAN is the switch VLAN */
			if (bcm5331x_drop_user_tag(skb))
				return NULL;
			vid = hw;
		}
	}
	/* a tag from the stack (VLAN upper, bridge) becomes the inner one */
	if (skb_vlan_tag_present(skb)) {
		if (bcm5331x_push_tag(skb, skb->vlan_proto, skb_vlan_tag_get(skb)))
			return NULL;
		__vlan_hwaccel_clear_tag(skb);
	}
	if (bcm5331x_push_tag(skb, htons(tpid), (pcp << VLAN_PRIO_SHIFT) | vid))
		return NULL;
	/*
	 * The switch removes the port tag on the way out of the front port and
	 * its port MACs do not pad (UniMAC COMMAND_CONFIG.PAD_EN = 0, found on
	 * every port): a frame shorter than 64 bytes with the tag would leave
	 * the front port shorter than the 64-byte minimum (FCS included) and be
	 * dropped by the link partner as a runt. The conduit pads only what it
	 * is given (60 bytes, tag included), so pad here, after the tag, to
	 * ETH_ZLEN + VLAN_HLEN, as tag_brcm does for its own tag. The skb is
	 * not freed here on error: the caller frees it once.
	 */
	if (__skb_put_padto(skb, ETH_ZLEN + VLAN_HLEN, false))
		return NULL;
	return skb;
}

static struct sk_buff *bcm5331x_rcv(struct sk_buff *skb, struct net_device *conduit)
{
	struct dsa_port *cpu_dp = conduit->dsa_ptr;
	u16 tpid = bcm5331x_tag_tpid(cpu_dp->ds->tagger_data);
	__be16 proto;
	u16 tci, uvid;
	int port;

	if (skb_vlan_tag_present(skb)) {
		proto = skb->vlan_proto;
		tci = skb_vlan_tag_get(skb);
		/* an 0x8100 tag stripped by the conduit is a port tag in 802.1Q mode only */
		if (proto != htons(tpid))
			return NULL;
		port = bcm5331x_tag_port(cpu_dp->ds->tagger_data, tci);
		if (!port)
			return NULL;
		__vlan_hwaccel_clear_tag(skb);
	} else {
		/* skb->data is at the TCI: the 802.1Q header is in the frame */
		if (unlikely(!pskb_may_pull(skb, VLAN_HLEN)))
			return NULL;
		proto = vlan_eth_hdr(skb)->h_vlan_proto;
		tci = ntohs(vlan_eth_hdr(skb)->h_vlan_TCI);
		if (proto != htons(tpid))
			return NULL;
		port = bcm5331x_tag_port(cpu_dp->ds->tagger_data, tci);
		if (!port)
			return NULL;
		skb_push_rcsum(skb, ETH_HLEN);
		__skb_vlan_pop(skb, &tci);
		skb_pull_rcsum(skb, ETH_HLEN);
	}

	skb->dev = dsa_conduit_find_user(conduit, 0, port);
	if (!skb->dev)
		return NULL;
	skb->priority = (tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	/*
	 * A hardware VID of the VLAN-aware bridge: the switch classified the
	 * frame on its user VLAN (802.1Q tag or PVID of the front port) and
	 * forwarded it to the other members; the bridge gets the user VLAN
	 * back as an accelerated tag (any inner tag stays in the frame).
	 */
	uvid = bcm5331x_tag_uvid(cpu_dp->ds->tagger_data, tci);
	if (uvid) {
		__vlan_hwaccel_put_tag(skb, htons(bcm5331x_tag_uproto(cpu_dp->ds->tagger_data)),
				       (tci & VLAN_PRIO_MASK) | uvid);
		dsa_default_offload_fwd_mark(skb);
		return skb;
	}
	/*
	 * A port VID: the switch only joined the front port to the host, the
	 * software bridge forwards. A bridge VID: the switch already forwarded
	 * the frame to the other members of the bridge.
	 */
	if (bcm5331x_tag_is_bridge_vid(cpu_dp->ds->tagger_data, tci))
		dsa_default_offload_fwd_mark(skb);
	return skb;
}

static int bcm5331x_connect(struct dsa_switch *ds)
{
	struct bcm5331x_tagger_data *td;

	/* about 21 KiB with the VLAN-aware tables: no need for contiguous pages */
	td = kvzalloc(sizeof(*td), GFP_KERNEL);
	if (!td)
		return -ENOMEM;
	ds->tagger_data = td;
	return 0;
}

static void bcm5331x_disconnect(struct dsa_switch *ds)
{
	kvfree(ds->tagger_data);
	ds->tagger_data = NULL;
}

static const struct dsa_device_ops bcm5331x_netdev_ops = {
	.name			= BCM5331X_TAG_NAME,
	.proto			= DSA_TAG_PROTO_BCM5331X_8021Q,
	.xmit			= bcm5331x_xmit,
	.rcv			= bcm5331x_rcv,
	.connect		= bcm5331x_connect,
	.disconnect		= bcm5331x_disconnect,
	.needed_headroom	= VLAN_HLEN,
	/* the conduit filters neither VIDs nor MAC addresses of the user ports */
	.promisc_on_conduit	= true,
};

MODULE_DESCRIPTION("DSA tagger of the BCM53314 switch of the FortiGate 100D (one VLAN per port, bridge VLANs, VLAN-aware bridge)");
MODULE_LICENSE("GPL");
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_BCM5331X_8021Q, BCM5331X_TAG_NAME);

module_dsa_tag_driver(bcm5331x_netdev_ops);
