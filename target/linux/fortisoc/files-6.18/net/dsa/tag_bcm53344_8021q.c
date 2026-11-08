// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DSA 802.1Q-based tag driver for the Broadcom BCM53344 of the Fortinet
 * FortiGate 100E. Its CPU ports are front-end ports of the switch towards
 * an NP6Lite MAC, not a CMIC packet DMA, so the frames carry no Broadcom
 * header: the source and destination port travel in a tag_8021q VLAN.
 */

#include <linux/dsa/8021q.h>
#include <linux/etherdevice.h>
#include <linux/if_bridge.h>

#include "tag.h"
#include "tag_8021q.h"

#define BCM53344_8021Q_NAME "bcm53344-8021q"

static bool bcm53344_8021q_aware(struct dsa_port *dp)
{
	struct net_device *br = dsa_port_bridge_dev_get(dp);

	return br && br_vlan_enabled(br);
}

static struct sk_buff *bcm53344_8021q_xmit(struct sk_buff *skb,
					   struct net_device *netdev)
{
	struct dsa_port *dp = dsa_user_to_port(netdev);
	u16 queue_mapping = skb_get_queue_mapping(skb);
	u8 pcp = netdev_txq_to_tc(netdev, queue_mapping);
	u16 tx_vid = dsa_tag_8021q_standalone_vid(dp);

	/*
	 * Forwarded by the bridge with offload: the bridge VLAN of a
	 * VLAN-unaware bridge, i.e. its whole broadcast domain (the switch
	 * looks the destination up). Otherwise the standalone VLAN reaches
	 * this one port, in a bridge too (see the driver).
	 */
	if (skb->offload_fwd_mark) {
		/* VLAN-aware bridge: the frame keeps its tag, the real VLAN */
		if (bcm53344_8021q_aware(dp))
			return skb;
		tx_vid = dsa_tag_8021q_bridge_vid(dsa_port_bridge_num_get(dp));
	}

	return dsa_8021q_xmit(skb, netdev, ETH_P_8021Q,
			      (pcp << VLAN_PRIO_SHIFT) | tx_vid);
}

static struct sk_buff *bcm53344_8021q_rcv(struct sk_buff *skb,
					  struct net_device *netdev)
{
	int src_port = -1, switch_id = -1, vbid = -1, vid = -1;

	/*
	 * The switch tags every frame towards its CPU port. Without a tag
	 * (dsa_8021q_rcv would take bytes of the frame for one) the frame is
	 * dropped.
	 */
	if (!skb_vlan_tag_present(skb) &&
	    (eth_hdr(skb)->h_proto != htons(ETH_P_8021Q) ||
	     !pskb_may_pull(skb, VLAN_HLEN)))
		return NULL;

	dsa_8021q_rcv(skb, &src_port, &switch_id, &vbid, &vid);
	/*
	 * Any other VID is a VLAN of the VLAN-aware bridge: the source port is
	 * unknown, a member of the VLAN stands in for it (hardware learns).
	 */
	if (src_port < 0 && vbid < 1 && vid <= 0)
		return NULL;

	skb->dev = dsa_tag_8021q_find_user(netdev, src_port, switch_id,
					    vid, vbid);
	if (!skb->dev)
		return NULL;

	/*
	 * A bridged port stays in its standalone VLAN for the frames the host
	 * sends, but receives in the bridge VLAN: never trust that VID then.
	 */
	if (src_port >= 0 && dsa_port_bridge_dev_get(dsa_user_to_port(skb->dev)))
		return NULL;

	/* such a VID only exists on the ports of a VLAN-aware bridge */
	if (src_port < 0 && vbid < 1 &&
	    !bcm53344_8021q_aware(dsa_user_to_port(skb->dev)))
		return NULL;

	if (likely(!is_link_local_ether_addr(eth_hdr(skb)->h_dest)))
		dsa_default_offload_fwd_mark(skb);

	return skb;
}

static const struct dsa_device_ops bcm53344_8021q_netdev_ops = {
	.name			= BCM53344_8021Q_NAME,
	.proto			= DSA_TAG_PROTO_BCM53344_8021Q,
	.xmit			= bcm53344_8021q_xmit,
	.rcv			= bcm53344_8021q_rcv,
	.needed_headroom	= VLAN_HLEN,
	.promisc_on_conduit	= true,
};

MODULE_DESCRIPTION("DSA tag driver for the Broadcom BCM53344, using VLAN");
MODULE_LICENSE("GPL");
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_BCM53344_8021Q, BCM53344_8021Q_NAME);

module_dsa_tag_driver(bcm53344_8021q_netdev_ops);
