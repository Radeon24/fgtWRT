/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Fortinet NP6Lite network processor (FortiSOC3): what the Ethernet driver
 * (np6lite-core.c) and its IPsec offload (np6lite-ipsec.c) share. Neither
 * sees the structures of the other. Mirror of np4lite.h, with the backend
 * of the NP6Lite: the security associations live in two tables of the DDR
 * of the network processor, one index per direction, written through the
 * tunnel-table command register, not on the session command ring; the
 * inbound SPI entry is an ordinary session entry of the flow engine.
 */
#ifndef __FORTINET_NP6LITE_H
#define __FORTINET_NP6LITE_H

#include <linux/errno.h>
#include <linux/types.h>

struct device;
struct net_device;
struct sk_buff;
struct xfrm_state;
struct fnp6l;
struct fnp6l_ipsec;

/* LIFs of the network processor (the core uses the same value) */
#ifndef NP6L_MAX_LIF
#define NP6L_MAX_LIF		16
#endif

/* A flow direction, as the IPsec offload looks it up: network order */
struct fnp6l_ipsec_tuple {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	u8 proto;
};

#ifdef CONFIG_FORTINET_NP6LITE_IPSEC
/*
 * Provided by np6lite-core.c. The flow-engine lock is the global mutex the
 * session commands and the flow table take (fnp6l_sse_lock): the IPsec
 * code takes it through fnp6l_fe_lock()/fnp6l_fe_unlock() for the inbound
 * SPI entries and the flow purges.
 */
struct fnp6l_ipsec *fnp6l_port_info(const struct net_device *ndev,
				    unsigned int *lif);
void fnp6l_fe_lock(struct fnp6l *np);
void fnp6l_fe_unlock(struct fnp6l *np);
void fnp6l_fe_assert_held(struct fnp6l *np);
int fnp6l_fe_ready(struct fnp6l *np);
int fnp6l_ipsec_spi(struct fnp6l *np, __be32 saddr, __be32 daddr, __be32 spi,
		    u32 in_lif, u16 sa, bool add);
int fnp6l_tx_drain(struct fnp6l *np);
unsigned int fnp6l_ft_flush_lif(struct fnp6l *np, unsigned int lif);

/* Provided by np6lite-ipsec.c */
int fnp6l_ipsec_probe(struct fnp6l *np, struct device *dev, void __iomem *base,
		      struct fnp6l_ipsec **ipsec);
void fnp6l_ipsec_start(struct fnp6l_ipsec *ips);
void fnp6l_ipsec_reset(struct fnp6l_ipsec *ips);
void fnp6l_ipsec_port_init(struct fnp6l_ipsec *ips, struct net_device *ndev);
/*
 * RX: whether the completion words of a decrypted frame carry an SA
 * (word 0 bit 30 "processed", SA index in word 1 bits 15:0). -ENOENT if
 * the frame is not from the IPsec engine, another error to drop it, or the
 * LIF of the port of its SA with @x set (a reference held).
 */
int fnp6l_ipsec_rx(struct fnp6l_ipsec *ips, u32 w0, u32 w1,
		   struct xfrm_state **x);
bool fnp6l_ipsec_rx_skb(struct fnp6l_ipsec *ips, struct sk_buff *skb,
			struct xfrm_state *x);
void fnp6l_ipsec_rx_put(struct xfrm_state *x);
unsigned int fnp6l_ipsec_nr_stats(const struct fnp6l_ipsec *ips);
void fnp6l_ipsec_get_strings(const struct fnp6l_ipsec *ips, u8 **data);
unsigned int fnp6l_ipsec_get_stats(const struct fnp6l_ipsec *ips, u64 *data);
/*
 * TX: 0 to send the frame as it is, or an SA index (> 0) for the network
 * processor to encrypt and encapsulate it (the host descriptor is then
 * marked, see fnp6l_ipsec_tx_mark()), or an error to drop it.
 */
int fnp6l_ipsec_xmit(struct fnp6l_ipsec *ips, unsigned int lif,
		     struct sk_buff *skb);
bool fnp6l_ipsec_msg(struct fnp6l_ipsec *ips, const void *buf,
		     unsigned int len);
bool fnp6l_ipsec_ft_refuse(struct fnp6l_ipsec *ips, unsigned int in_lif,
			   unsigned int out_lif,
			   const struct fnp6l_ipsec_tuple *key);
#else
static inline struct fnp6l_ipsec *
fnp6l_port_info(const struct net_device *ndev, unsigned int *lif)
{
	return NULL;
}

static inline int fnp6l_ipsec_probe(struct fnp6l *np, struct device *dev,
				    void __iomem *base,
				    struct fnp6l_ipsec **ipsec)
{
	return 0;
}

static inline void fnp6l_ipsec_start(struct fnp6l_ipsec *ips)
{
}

static inline void fnp6l_ipsec_reset(struct fnp6l_ipsec *ips)
{
}

static inline void fnp6l_ipsec_port_init(struct fnp6l_ipsec *ips,
					 struct net_device *ndev)
{
}

static inline int fnp6l_ipsec_rx(struct fnp6l_ipsec *ips, u32 w0, u32 w1,
				 struct xfrm_state **x)
{
	return -ENOENT;
}

static inline bool fnp6l_ipsec_rx_skb(struct fnp6l_ipsec *ips,
				      struct sk_buff *skb, struct xfrm_state *x)
{
	return true;
}

static inline void fnp6l_ipsec_rx_put(struct xfrm_state *x)
{
}

static inline unsigned int fnp6l_ipsec_nr_stats(const struct fnp6l_ipsec *ips)
{
	return 0;
}

static inline void fnp6l_ipsec_get_strings(const struct fnp6l_ipsec *ips,
					   u8 **data)
{
}

static inline unsigned int fnp6l_ipsec_get_stats(const struct fnp6l_ipsec *ips,
						 u64 *data)
{
	return 0;
}

static inline int fnp6l_ipsec_xmit(struct fnp6l_ipsec *ips, unsigned int lif,
				   struct sk_buff *skb)
{
	return 0;
}

static inline bool fnp6l_ipsec_msg(struct fnp6l_ipsec *ips, const void *buf,
				   unsigned int len)
{
	return false;
}

static inline bool fnp6l_ipsec_ft_refuse(struct fnp6l_ipsec *ips,
					 unsigned int in_lif,
					 unsigned int out_lif,
					 const struct fnp6l_ipsec_tuple *key)
{
	return false;
}
#endif /* CONFIG_FORTINET_NP6LITE_IPSEC */

#endif /* __FORTINET_NP6LITE_H */
