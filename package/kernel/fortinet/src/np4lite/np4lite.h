/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Fortinet NP4Lite network processor (FortiSOC1, FortiSOC2): what the
 * Ethernet driver (np4lite-core.c) and its IPsec offload (np4lite-ipsec.c)
 * share. Neither sees the structures of the other.
 */
#ifndef __FORTINET_NP4LITE_H
#define __FORTINET_NP4LITE_H

#include <linux/errno.h>
#include <linux/types.h>

struct device;
struct net_device;
struct resource;
struct sk_buff;
struct xfrm_state;
struct fnp4l;
struct fnp4l_ipsec;

#define NP4L_NR_PORTS		4

/* A flow direction, as the IPsec offload looks it up: network order */
struct fnp4l_ft_tuple {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	u8 proto;
};

/* What the flow engine may do with a flow direction, given IPsec */
enum fnp4l_admit {
	NP4L_ADMIT_PLAIN,	/* forward it, as any other */
	NP4L_ADMIT_CHAIN,	/* send it to the IPsec engine */
	NP4L_ADMIT_REFUSE,	/* leave it to the host */
};

#ifdef CONFIG_FORTINET_NP4LITE_IPSEC
/*
 * Provided by np4lite-core.c. The fnp4l_sse_*() functions, but for the
 * lock itself, are called under the lock of the flow engine.
 */
struct fnp4l_ipsec *fnp4l_port_info(const struct net_device *ndev,
				    unsigned int *id);
void fnp4l_sse_lock(struct fnp4l *np);
void fnp4l_sse_unlock(struct fnp4l *np);
int fnp4l_sse_ready(struct fnp4l *np);
void fnp4l_sse_idle(struct fnp4l *np);
void fnp4l_sse_error(struct fnp4l *np);
int fnp4l_sse_cmd(struct fnp4l *np, const void *cmd, unsigned int words);
int fnp4l_sse_spi(struct fnp4l *np, unsigned int id, __be32 saddr,
		  __be32 daddr, __be32 spi, u16 sa, bool add);
void fnp4l_sse_port_sync(struct fnp4l *np, unsigned int id);
void fnp4l_sse_assert_held(struct fnp4l *np);
unsigned int fnp4l_ft_purge(struct fnp4l *np, unsigned int id);
unsigned int fnp4l_ft_purge_chained(struct fnp4l *np,
				    bool (*match)(void *data, u16 sa,
						     unsigned int out),
				    void *data);
int fnp4l_tx_drain(struct fnp4l *np);

/* Provided by np4lite-ipsec.c */
int fnp4l_ipsec_probe(struct fnp4l *np, struct device *dev,
		      void __iomem *base, const struct resource *sa,
		      struct fnp4l_ipsec **ipsec);
void fnp4l_ipsec_start(struct fnp4l_ipsec *ips);
void fnp4l_ipsec_reset(struct fnp4l_ipsec *ips);
bool fnp4l_ipsec_busy(const struct fnp4l_ipsec *ips);
unsigned long fnp4l_ipsec_ports(const struct fnp4l_ipsec *ips);
void fnp4l_ipsec_port_init(struct fnp4l_ipsec *ips,
			   struct net_device *ndev);
int fnp4l_ipsec_rx(struct fnp4l_ipsec *ips, const u8 *htag, u32 wb0,
		   u32 ctrl, struct xfrm_state **x);
bool fnp4l_ipsec_rx_skb(struct fnp4l_ipsec *ips, struct sk_buff *skb,
			struct xfrm_state *x);
void fnp4l_ipsec_rx_put(struct xfrm_state *x);
unsigned int fnp4l_ipsec_nr_stats(const struct fnp4l_ipsec *ips);
void fnp4l_ipsec_get_strings(const struct fnp4l_ipsec *ips, u8 **data);
unsigned int fnp4l_ipsec_get_stats(const struct fnp4l_ipsec *ips,
				   u64 *data);
int fnp4l_ipsec_xmit(struct fnp4l_ipsec *ips, unsigned int id,
		     struct sk_buff *skb);
bool fnp4l_ipsec_msg(struct fnp4l_ipsec *ips, const void *buf,
		     unsigned int len);
void fnp4l_ipsec_watch(struct fnp4l_ipsec *ips, u64 hrx_pdq_full);
bool fnp4l_ipsec_ft_refuse(struct fnp4l_ipsec *ips, unsigned long ports);
bool fnp4l_ipsec_in_protected(struct fnp4l_ipsec *ips, unsigned int id,
			      const struct fnp4l_ft_tuple *t);
#else
static inline int fnp4l_ipsec_probe(struct fnp4l *np,
				    struct device *dev, void __iomem *base,
				    const struct resource *sa,
				    struct fnp4l_ipsec **ipsec)
{
	return 0;
}

static inline void fnp4l_ipsec_start(struct fnp4l_ipsec *ips)
{
}

static inline void fnp4l_ipsec_reset(struct fnp4l_ipsec *ips)
{
}

static inline bool fnp4l_ipsec_busy(const struct fnp4l_ipsec *ips)
{
	return false;
}

static inline unsigned long
fnp4l_ipsec_ports(const struct fnp4l_ipsec *ips)
{
	return 0;
}

static inline void fnp4l_ipsec_port_init(struct fnp4l_ipsec *ips,
					 struct net_device *ndev)
{
}

static inline int fnp4l_ipsec_rx(struct fnp4l_ipsec *ips,
				 const u8 *htag, u32 wb0, u32 ctrl,
				 struct xfrm_state **x)
{
	return -ENOENT;
}

static inline bool fnp4l_ipsec_rx_skb(struct fnp4l_ipsec *ips,
				      struct sk_buff *skb,
				      struct xfrm_state *x)
{
	return true;
}

static inline void fnp4l_ipsec_rx_put(struct xfrm_state *x)
{
}

static inline unsigned int
fnp4l_ipsec_nr_stats(const struct fnp4l_ipsec *ips)
{
	return 0;
}

static inline void fnp4l_ipsec_get_strings(const struct fnp4l_ipsec *ips,
					   u8 **data)
{
}

static inline unsigned int
fnp4l_ipsec_get_stats(const struct fnp4l_ipsec *ips, u64 *data)
{
	return 0;
}

static inline int fnp4l_ipsec_xmit(struct fnp4l_ipsec *ips,
				   unsigned int id, struct sk_buff *skb)
{
	return 0;
}

static inline bool fnp4l_ipsec_msg(struct fnp4l_ipsec *ips,
				   const void *buf, unsigned int len)
{
	return false;
}

static inline void fnp4l_ipsec_watch(struct fnp4l_ipsec *ips,
				     u64 hrx_pdq_full)
{
}

static inline bool fnp4l_ipsec_ft_refuse(struct fnp4l_ipsec *ips,
					 unsigned long ports)
{
	return false;
}

static inline bool
fnp4l_ipsec_in_protected(struct fnp4l_ipsec *ips, unsigned int id,
			 const struct fnp4l_ft_tuple *t)
{
	return false;
}
#endif /* CONFIG_FORTINET_NP4LITE_IPSEC */

#ifdef CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS
enum fnp4l_admit
fnp4l_ipsec_ft_admit(struct fnp4l_ipsec *ips, unsigned int in,
		     unsigned int out, const struct fnp4l_ft_tuple *key,
		     const struct fnp4l_ft_tuple *xlat, bool xfrm, bool nat,
		     bool vlan, const char **why);
int fnp4l_ipsec_ft_chain(struct fnp4l_ipsec *ips, unsigned int out,
			 const struct xfrm_state *x,
			 const struct fnp4l_ft_tuple *xlat, u16 *idx,
			 u16 *mtu, u8 *h_dest);
void fnp4l_ipsec_ft_chained(struct fnp4l_ipsec *ips);
#else
static inline enum fnp4l_admit
fnp4l_ipsec_ft_admit(struct fnp4l_ipsec *ips, unsigned int in,
		     unsigned int out, const struct fnp4l_ft_tuple *key,
		     const struct fnp4l_ft_tuple *xlat, bool xfrm, bool nat,
		     bool vlan, const char **why)
{
	*why = "no IPsec admission";
	return NP4L_ADMIT_REFUSE;
}

static inline int
fnp4l_ipsec_ft_chain(struct fnp4l_ipsec *ips, unsigned int out,
		     const struct xfrm_state *x,
		     const struct fnp4l_ft_tuple *xlat, u16 *idx,
		     u16 *mtu, u8 *h_dest)
{
	return -EOPNOTSUPP;
}

static inline void fnp4l_ipsec_ft_chained(struct fnp4l_ipsec *ips)
{
}
#endif /* CONFIG_FORTINET_NP4LITE_IPSEC_FLOWS */

#endif /* __FORTINET_NP4LITE_H */
