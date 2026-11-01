// SPDX-License-Identifier: GPL-2.0-only
/*
 * DSA driver of the BCM53314 switch of the Fortinet FortiGate 100D
 * (base mode: autonomous DSA over one 802.1Q VLAN per front
 * port; no hardware forwarding between front ports. Double tagging, module
 * parameter qinq: user VLANs, carried as inner tags under a provider outer
 * tag on the CPU link, VLAN-aware software bridge; see "Double tagging".
 * Module parameter hwbridge: VLAN-unaware bridges offloaded to the switch,
 * see "Hardware bridging"; module parameter lag: second CPU port on ge3
 * and conduit LAG over the trunk group of step trunk2, see "Conduit LAG";
 * module parameter fdb (with hwbridge): address table of the offloaded
 * bridges, see "Address table of offloaded bridges"; module parameter
 * vlanbr (with hwbridge and qinq): one VLAN-aware bridge offloaded to the
 * switch, see "VLAN-aware bridging"; module parameter link (1|2): link of
 * the front ports in EPC_LINK_BMAP, real port PHYs for ethtool -s and the
 * MAC speed, duplex and pause, see "Link of the front ports"; module
 * parameter lagf: hardware LAG of front ports in an offloaded bridge, see
 * "Hardware LAG of front ports"; module parameter mgmt: MGMT as a user
 * port; module parameter mirror: port mirroring; all default off, with no
 * switch write).
 * Lot 0 (reads only, no switch write): hardware statistics from the MIB
 * (parameter stats_ms, default on), bridge port flags on software bridges,
 * refusal of 802.1ad VLAN-aware bridges and of forced link settings (link=0|1;
 * link=2 judges them, see "Link of the front ports"); see
 * "Hardware statistics", "802.1ad bridges", "Bridge port flags".
 *
 * This driver *includes the current switch module unchanged*
 * (bcm53314-fg100d.c) and reuses its whole CMIC/S-channel/MIIM path, its
 * deny/allow list and its configuration steps. The base module brings the
 * switch to the same state it reaches on its own: step "init" sets the
 * switch up (run on its own, from a separate load), then the steps
 * "counters,learning,trunk,ports,ifilter" give each of the 19 front ports
 * a VLAN of its own (VID 100+N), shared with the CPU link (ge2, switch
 * port 3) only. Once that state is reached the switch needs no further
 * write for this base mode: the driver registers only if the plan the
 * base module built was fully applied (no remaining plan), and every DSA
 * operation below either reuses that state or is refused, so nothing is
 * ever written to the switch outside that plan.
 *
 * The port of a frame exchanged with the host is told by the port VID
 * (tagger tag_bcm5331x_8021q). The 82574L conduit (eth0) carries all front
 * ports; MGMT (switch port 6) is excluded by default, a user port with
 * module parameter mgmt (see "MGMT user port"). The emulated PHYs are driven,
 * read only: link from the MII status (BMSR) of the real port PHY by one
 * MIIM read (linksrc=bmsr, default), speed and duplex from MAC_MODE
 * (S-channel read); linksrc=mac keeps MAC_MODE alone. No PHY register of a
 * front port is written, no new switch write (link=0, default; link=2
 * passes the real PHY registers through, see "Link of the front ports").
 *
 * CPU link (ge2): the boot firmware leaves the internal PHY of ge2 at
 * 1000 Mb/s forced, auto-negotiation off (MII control 0x0140), and the
 * 82574L conduit then sees no carrier. At the set-up of the CPU port the
 * driver makes one MII control write to that PHY only (0x0140 -> 0x1340:
 * auto-negotiation enabled and restarted, the transition the base module
 * already makes for the trunk PHY), read back; none if auto-negotiation is
 * already on or if the register holds any other value; cpu_an=0 drops it.
 *
 * Link path (x86, no device tree): a user port has no OF node, so phylink
 * stays in PHY mode and phylink_of_phy_connect(NULL) gives -ENODEV. DSA then
 * falls back to its own user MII bus, which it allocates only when the
 * driver has phy_read (net/dsa/dsa.c dsa_switch_setup, net/dsa/user.c
 * dsa_user_phy_setup -> dsa_user_phy_connect(dp->index)). This driver
 * provides phy_read/phy_write that *emulate* a clause-22 PHY per front port
 * (address = switch port): registers built by libphy's swphy_read_reg()
 * from the sampled link state, a fixed ability set, phy ID 0 (the swphy
 * convention, bound to the generic PHY driver). phy_write is inert: no MIIM
 * transaction, nothing is sent to the switch.
 *
 * Device model: the PCI function of the switch stays unbound (as the base
 * module requires); the DSA switch is a platform device, child of it,
 * bound to this module's platform driver, so that the user net devices
 * have a parent with a driver (phylib needs its owner, see Registration).
 */

#include <linux/kernel.h>
#include <linux/ethtool.h>
#include <linux/if_bridge.h>
#include <linux/linkmode.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/phy_fixed.h>
#include <linux/phylink.h>
#include <linux/platform_device.h>
#include <linux/rtnetlink.h>
#include <linux/spinlock.h>
#include <net/dsa.h>
#include <net/switchdev.h>
#include <linux/math64.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/dcbnl.h>
#include <net/flow_offload.h>

/*
 * Software PHY register emulation of libphy (drivers/net/phy/swphy.c,
 * EXPORT_SYMBOL_GPL, built into libphy.ko when CONFIG_SWPHY=y). Its header
 * drivers/net/phy/swphy.h is private to the tree: same prototype here.
 */
int swphy_read_reg(int reg, const struct fixed_phy_status *state);

/* bridge VIDs follow vid_base of the base module */
#define BCM5331X_BR_VID_FIRST	(vid_base + BCM5331X_BR_VID_OFF)
#include "bcm5331x-dsa.h"

/*
 * Neutralise the module plumbing of the included base module: its init and
 * exit become plain function pointers this driver calls, its module
 * parameters stay as ordinary globals this driver sets, and its MODULE_*
 * macros are dropped (this module provides its own). The real macros are
 * saved with push_macro and restored with pop_macro right after the
 * include, so this driver's own plumbing below is unaffected. The base .c
 * itself is not touched.
 */
#pragma push_macro("module_init")
#pragma push_macro("module_exit")
#pragma push_macro("module_param")
#pragma push_macro("MODULE_PARM_DESC")
#pragma push_macro("MODULE_DESCRIPTION")
#pragma push_macro("MODULE_LICENSE")
#pragma push_macro("MODULE_ALIAS")
#pragma push_macro("__init")
#pragma push_macro("__exit")
/* drop the init/exit section markers of the base: its init and exit run as
 * plain text functions called from this driver (no .init/.exit sections) */
#undef __init
#undef __exit
#define __init
#define __exit
#undef module_init
#undef module_exit
#undef module_param
#undef MODULE_PARM_DESC
#undef MODULE_DESCRIPTION
#undef MODULE_LICENSE
#undef MODULE_ALIAS
#define module_init(fn)		static int (*bcm5331x_base_probe)(void) = (fn)
#define module_exit(fn)		static void (*bcm5331x_base_remove)(void) = (fn)
#define module_param(a, b, c)
#define MODULE_PARM_DESC(a, b)
#define MODULE_DESCRIPTION(a)
#define MODULE_LICENSE(a)
#define MODULE_ALIAS(a)
/* the base module sets its own pr_fmt; our kernel includes already set one */
#undef pr_fmt

/* BCM_BASE lets the off-line build point at the base module elsewhere */
#ifdef BCM_BASE
#include BCM_BASE
#else
#include "bcm53314-fg100d.c"
#endif

#pragma pop_macro("module_init")
#pragma pop_macro("module_exit")
#pragma pop_macro("module_param")
#pragma pop_macro("MODULE_PARM_DESC")
#pragma pop_macro("MODULE_DESCRIPTION")
#pragma pop_macro("MODULE_LICENSE")
#pragma pop_macro("MODULE_ALIAS")
#pragma pop_macro("__init")
#pragma pop_macro("__exit")

/* ---------------------------------------------------------------------- */
/* Parameters                                                              */

/*
 * Steps the base module runs before DSA registers. The default is the full
 * set a DSA layout needs: counters, shared-VLAN learning, trunk (ge2) and
 * one VLAN per front port with the ingress filter. "init" is not here: it
 * runs on its own, from an earlier load (step init runs alone).
 */
static char *dsa_steps = "counters,learning,trunk,ports,ifilter";
static char dsa_steps_mgmt[128];	/* dsa_steps + ",mgmt" (mgmt=Y) */
static char *conduit_name = "eth0";

/*
 * Auto-negotiation of the CPU link PHY (internal PHY of ge2, MIIM 0x83) at
 * the set-up of the CPU port: Y (default) = one MII control write
 * 0x0140 -> 0x1340 when found forced; N = the PHY is left as found.
 */
static bool cpu_an = true;

/*
 * Double tagging: N (default) = base mode
 * unchanged, no further write; Y = before DSA registers, the switch is put
 * in double-tagging mode with an 802.1ad outer tag on the CPU link (eight
 * register writes, twelve with steps ge3,trunk2 (ge3 too), each read back,
 * see bcm5331x_dsa_qinq), and VLAN-aware
 * bridges are accepted (software bridge, user VLANs as inner tags).
 */
static bool qinq;

/*
 * MGMT user port: N (default) = MGMT excluded,
 * no write of its own, the switch state of the other modes unchanged;
 * Y = the base module also runs its step "mgmt" (MGMT in VID 20, untagged,
 * shared with the CPU link only; tagged frames dropped on ingress, ingress
 * VLAN filter; MAC enabled last: twelve writes), planned
 * even without link on MGMT, and MGMT becomes the user port "mgmt" (DSA
 * index 6, port VID 20). See "MGMT user port".
 */
static bool dsa_mgmt;

/*
 * Auto-negotiation of the MGMT PHY (internal PHY of port 6, MIIM 0x86) at
 * the set-up of the MGMT user port (mgmt=Y only): Y (default) = one MII
 * control write 0x0140 -> 0x1340 when found forced
 * (left so by step "init"); N = the PHY is left as found.
 */
static bool mgmt_an = true;

/*
 * Link source of the emulated PHYs: the base module's own "linksrc"
 * parameter (default "bmsr"; "mac" = MAC_MODE alone). Read once
 * at load into dsa_link_bmsr; the base module checks the value.
 */
static bool dsa_link_bmsr;

module_param_named(linksrc, linksrc, charp, 0444);
MODULE_PARM_DESC(linksrc, "Link source of the emulated PHYs: bmsr (default, MIIM read of the port PHY status, read only) or mac (MAC_MODE link bit, does not fall on a link loss)");
module_param_named(steps, dsa_steps, charp, 0444);
MODULE_PARM_DESC(steps, "Base-module steps run before DSA registers (default counters,learning,trunk,ports,ifilter)");
module_param_named(conduit, conduit_name, charp, 0444);
MODULE_PARM_DESC(conduit, "Name of the CPU-side net device, the 82574L carrying ge2 (default eth0)");
module_param(vid_base, int, 0444);
MODULE_PARM_DESC(vid_base, "First VID of the front-port VLAN block, the base module's own parameter (21-3976, checked at load; default 100: port VIDs 101-122, bridge VIDs 141-148; else vid_base+1..+22 and vid_base+41..+48)");
module_param(cpu_an, bool, 0444);
MODULE_PARM_DESC(cpu_an, "At CPU port set-up, switch the ge2 PHY from forced 1000 Mb/s to auto-negotiation (MII control 0x0140 -> 0x1340, read back; default Y; N = PHY left as found)");
module_param(qinq, bool, 0444);
MODULE_PARM_DESC(qinq, "Double tagging before registration: 802.1ad outer tag (TPID 0x88a8) on the CPU link, user VLANs kept as inner tags, VLAN-aware bridges accepted (eight switch register writes, twelve with steps ge3,trunk2, read back; default N)");
module_param_named(mgmt, dsa_mgmt, bool, 0444);
MODULE_PARM_DESC(mgmt, "MGMT as user port \"mgmt\" (port VID 20): base-module step mgmt added to the steps (twelve switch writes, read back), planned without link too; not with lag (default N = MGMT excluded, no write)");
module_param(mgmt_an, bool, 0444);
MODULE_PARM_DESC(mgmt_an, "With mgmt=Y, at MGMT port set-up, switch the MGMT PHY (MIIM 0x86) from forced 1000 Mb/s to auto-negotiation (MII control 0x0140 -> 0x1340, read back; default Y; N = PHY left as found)");

/* ---------------------------------------------------------------------- */
/* Shared with the base module: port layout                                */

/* CPU link: ge2 = switch port 3 (PORT_TRUNK of the base module) */
#define BCM5331X_CPU_PORT	PORT_TRUNK

/* VID of a front port, 0 if @port is not a user port of this layout */
static u16 bcm5331x_port_vid(int port)
{
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++)
		if (front_ports[i].port == port)
			return fp_vid(i);
	return 0;
}

static bool bcm5331x_is_front(int port)
{
	return bcm5331x_port_vid(port) != 0;
}

/*
 * MGMT is a user port: step "mgmt" ran (the init refuses it without
 * mgmt=Y, and mgmt=Y adds it), so MGMT is in VID 20 with the CPU link.
 */
static bool bcm5331x_has_mgmt(const struct bcm53314 *sw)
{
	return sw && sw->mgmt;
}

/* VID of a user port (front port, or MGMT when it is one), 0 otherwise */
static u16 bcm5331x_user_vid(const struct bcm53314 *sw, int port)
{
	if (port == PORT_MGMT)
		return bcm5331x_has_mgmt(sw) ? MGMT_VID : 0;
	return bcm5331x_port_vid(port);
}

/* ---------------------------------------------------------------------- */
/* MGMT user port (mgmt=Y)                                                 */

/*
 * MGMT (switch port 6, internal PHY at MIIM 0x86) was left out of DSA: the
 * base module served it on its own, as VLAN 20 of the trunk (step "mgmt",
 * see below). With mgmt=Y the DSA driver adds that step to its own and
 * MGMT becomes the user port "mgmt" with port VID 20, in the same way as a
 * front port (VID 100+N):
 *  - switch: exactly the twelve writes of step "mgmt" (VID 20 = {MGMT
 *    untagged, CPU link tagged}, PORT_TAB[6] = VID 20 + PORT_DIS_TAG +
 *    EN_IFILTER, MGMT out of VID 1, MAC enabled last), after "ifilter" in
 *    the same plan ; the plan is built even without link on MGMT
 *    (mgmt_link_optional of the base module: a user port without cable is
 *    normal, and after step "init" the PHY is at forced 1000 Mb/s with no
 *    link to an auto-negotiating partner);
 *  - PHY: at the set-up of the MGMT user port, one MII control write
 *    0x0140 -> 0x1340 (auto-negotiation enabled and restarted, the value of
 *    the step "mgmt" and of step "ports" for 0x85/0x87/0x88), read back; none if
 *    auto-negotiation is already on (start from the network: the boot
 *    firmware served TFTP through MGMT) or for any other value (left as
 *    found, warned); mgmt_an=0 drops it;
 *  - link (linksrc=bmsr): the MII status of 0x86, as for a front port;
 *    the MAC of MGMT being fixed at 1000 Mb/s full duplex, a link counts
 *    only if it is resolved so: MII control and, under auto-negotiation,
 *    the link partner's 1000BASE-T full-duplex ability (MII register 10)
 *    are read (two more MIIM reads, link up only); any other speed is
 *    reported down and counted;
 *  - double tagging (qinq=Y): MGMT stays a customer (UNI) port, its frames
 *    get outer VLAN 20 and reach the host under 0x88a8/20; its tagged frames
 *    are dropped on ingress (PORT_DIS_TAG), so a tagged VLAN (8021q upper,
 *    tagged bridge VLAN) is refused on "mgmt" (port_vlan_add), untagged ones
 *    accepted;
 *  - hardware bridging (hwbridge=Y): MGMT is never in a bridge VLAN; it
 *    joins a bridge as a software port of its own (-EOPNOTSUPP to DSA, so
 *    not in the switch's forwarding domain);
 *  - not with lag=Y (the base module refuses steps ge3/trunk2 with mgmt:
 *    VID 20 holds ge2 only).
 * Nothing else is written; with mgmt=N nothing of this runs.
 */
#define BCM5331X_MGMT_PHY	(0x80 | PORT_MGMT)	/* internal bus, address 6 */

/* MGMT PHY writes, links at another speed than 1000 FD: visible to debugfs */
static unsigned long bcm5331x_mgmt_an_writes, bcm5331x_mgmt_slow;
static bool bcm5331x_mgmt_slow_seen;	/* warned once per slow link */

/*
 * MGMT link up in MII status: keep it only at 1000 Mb/s full duplex.
 * Called with the lock held; reads only (MII control, then MII register 10
 * under auto-negotiation).
 */
static int bcm5331x_dsa_mgmt_gig(struct bcm53314 *sw, u32 *mm)
{
	u16 bmcr, s1000 = 0;
	bool gig;
	int err;

	err = miim_op(sw, false, BCM5331X_MGMT_PHY, MII_BMCR, &bmcr);
	if (err)
		return err;
	if (bmcr & BMCR_ANENABLE) {
		err = miim_op(sw, false, BCM5331X_MGMT_PHY, MII_STAT1000, &s1000);
		if (err)
			return err;
		gig = s1000 != 0xffff && (s1000 & LPA_1000FULL);
	} else {
		gig = (bmcr & (BMCR_SPEED1000 | BMCR_SPEED100)) == BMCR_SPEED1000 &&
		      (bmcr & BMCR_FULLDPLX);
	}
	if (!gig) {
		if (!bcm5331x_mgmt_slow_seen)
			dev_warn(&sw->pdev->dev,
				 "mgmt: link not at 1000 Mb/s full duplex (MII control 0x%04x, 1000BASE-T status 0x%04x): reported down, the MGMT MAC is fixed at gigabit\n",
				 bmcr, s1000);
		bcm5331x_mgmt_slow_seen = true;
		bcm5331x_mgmt_slow++;
		mm[0] &= ~MAC_MODE_LINK;
	} else {
		bcm5331x_mgmt_slow_seen = false;
	}
	return 0;
}

/*
 * Remaining plan of the base module: operations it planned but did not
 * write. Zero means the switch is fully in the state the steps describe.
 */
static int bcm5331x_plan_remaining(const struct bcm53314 *sw)
{
	return sw->nops - sw->nwritten;
}

/* ---------------------------------------------------------------------- */
/* phylink: emulated PHYs, link state read from MAC_MODE (read only)       */

static void bcm5331x_dsa_phylink_get_caps(struct dsa_switch *ds, int port,
					  struct phylink_config *config)
{
	__set_bit(PHY_INTERFACE_MODE_INTERNAL, config->supported_interfaces);
	__set_bit(PHY_INTERFACE_MODE_GMII, config->supported_interfaces);

	/*
	 * MGMT: 1000 Mb/s full duplex only, its MAC being left at forced
	 * gigabit by step "init" (Q5/Q6 of init_port_mode) and enabled so by
	 * step "mgmt": a link at 10 or 100 Mb/s would carry nothing.
	 */
	config->mac_capabilities = MAC_SYM_PAUSE | MAC_ASYM_PAUSE | MAC_1000FD;
	if (bcm5331x_is_front(port))
		config->mac_capabilities |= MAC_10 | MAC_100 | MAC_10FD |
					    MAC_100FD;
}

/*
 * Link sample of a front port: the one place the link source is read.
 * MAC_MODE of the GPORT is always read (S-channel read): it gives speed and
 * duplex. Its LINK_STATUS bit rises with the link but does not fall when the
 * cable is pulled, so with linksrc=bmsr (default,
 * with the same work in the base module) the link bit is replaced by
 * bit 2 of the MII status register of the port PHY: one MIIM read of
 * register 1 at the address of the SDK's phy_addr table (link_phy() of the
 * base module: 0x85/0x87/0x88 internal, 0x09-0x10 and 0x12-0x19 external;
 * 0x11, the trunk, ge3 and MGMT never). The bit latches low and is passed
 * through as a real PHY's would be: phylib in polling mode reads BMSR once
 * a second and reports even a short loss (genphy_update_link). No PHY
 * register is written: the MIIM transaction only writes the CMIC service
 * registers of a read (0x4a0, 0x158, 0x050), as the base module does. A
 * busy MIIM (link scan on), no answer or a BMSR of 0xffff is a fault of the
 * base module (halted: every later read fails, all links read down).
 * mm[0] holds MAC_MODE with its link bit set from the source in use.
 */
static int bcm5331x_dsa_link_sample(struct bcm53314 *sw, int port, u32 *mm)
{
	u8 a = dsa_link_bmsr ? link_phy(port) : 0;
	u16 bmsr = 0;
	int err;

	/* MGMT (user port with mgmt=Y): its own internal PHY, MIIM 0x86 */
	if (dsa_link_bmsr && port == PORT_MGMT)
		a = BCM5331X_MGMT_PHY;
	mutex_lock(&sw->lock);
	err = sw_read(sw, O_MAC_MODE, port, mm);
	if (!err && a && a != BMSR_GAP_ADDR) {
		err = miim_op(sw, false, a, MII_BMSR, &bmsr);
		if (!err) {
			sw->bmsr_reads++;
			if (bmsr == 0xffff) {
				sw_fault(sw, "dsa: BMSR of PHY 0x%02x reads 0xffff", a);
				err = -EIO;
			} else if (bmsr & BMSR_LSTATUS) {
				mm[0] |= MAC_MODE_LINK;
			} else {
				mm[0] &= ~MAC_MODE_LINK;
			}
		}
	}
	/* MGMT: a link counts only at 1000 Mb/s full duplex (MAC fixed at gigabit) */
	if (!err && dsa_link_bmsr && port == PORT_MGMT && (mm[0] & MAC_MODE_LINK))
		err = bcm5331x_dsa_mgmt_gig(sw, mm);
	mutex_unlock(&sw->lock);
	return err;
}

/* MAC_MODE word 0 -> link, speed, duplex (base module field notes) */
static void bcm5331x_dsa_mac_mode_decode(u32 mm, int *link, int *speed,
					 int *duplex)
{
	*link = !!(mm & MAC_MODE_LINK);
	switch (mm & 3) {
	case 0:	*speed = SPEED_10;   break;
	case 1:	*speed = SPEED_100;  break;
	default: *speed = SPEED_1000; break;
	}
	/* MAC_DUPLEX reads 0 on a full-duplex gigabit link (base module note) */
	*duplex = (mm & BIT(2)) ? DUPLEX_HALF : DUPLEX_FULL;
}

/*
 * Fixed link state of a port: read MAC_MODE (GPORT, read only). The switch
 * MAC was already configured by the base module's "ports" step, so nothing
 * is written here. phylink calls it only for a port in fixed-link mode
 * (MLO_AN_FIXED), which a port without OF node never is: the user ports go
 * through the emulated PHY below. Kept for a fixed-link description.
 */
static void bcm5331x_dsa_phylink_fixed_state(struct dsa_switch *ds, int port,
					     struct phylink_link_state *state)
{
	struct bcm53314 *sw = ds->priv;
	u32 mm[3] = { 0 };
	int link, speed, duplex;

	state->link = 0;
	if (dsa_is_cpu_port(ds, port)) {
		/* ge2: the host-facing link is fixed gigabit full duplex */
		state->link = 1;
		state->speed = SPEED_1000;
		state->duplex = DUPLEX_FULL;
		state->pause = MLO_PAUSE_RX | MLO_PAUSE_TX;
		return;
	}

	if (bcm5331x_dsa_link_sample(sw, port, mm))
		return;

	bcm5331x_dsa_mac_mode_decode(mm[0], &link, &speed, &duplex);
	state->link = link;
	if (!state->link)
		return;
	state->speed = speed;
	state->duplex = duplex;
	if (mm[0] & BIT(3))
		state->pause |= MLO_PAUSE_RX;
	if (mm[0] & BIT(4))
		state->pause |= MLO_PAUSE_TX;
}

/* ---------------------------------------------------------------------- */
/* Emulated clause-22 PHY of each front port (DSA user MII bus)            */

/*
 * Abilities the emulated PHY reports whatever the link: the MAC
 * capabilities of a front port (10/100 half and full, 1000 full, see
 * phylink_get_caps). swphy_read_reg() alone reports only the abilities of
 * the current speed, which would freeze the PHY's "supported" set to the
 * link state seen when genphy reads it once at attach.
 */
#define BCM5331X_PHY_BMSR_ABILITY	(BMSR_ANEGCAPABLE | BMSR_ESTATEN | \
					 BMSR_10HALF | BMSR_10FULL | \
					 BMSR_100HALF | BMSR_100FULL)
#define BCM5331X_PHY_ESTATUS		ESTATUS_1000_TFULL
/*
 * Advertisement registers read back exactly what genphy_config_advert
 * computes from those abilities (phylink filters nothing out), so
 * genphy_config_aneg finds them unchanged and issues no write at all.
 */
#define BCM5331X_PHY_ADVERTISE		(ADVERTISE_CSMA | ADVERTISE_ALL | \
					 ADVERTISE_PAUSE_CAP | \
					 ADVERTISE_PAUSE_ASYM)
#define BCM5331X_PHY_CTRL1000		ADVERTISE_1000FULL
/*
 * MGMT user port: 1000 Mb/s full duplex only (see phylink_get_caps), so
 * its emulated PHY reports that ability alone and advertises no 10/100
 * mode: genphy_config_aneg finds the registers as it would set them.
 */
#define BCM5331X_MGMT_BMSR_ABILITY	(BMSR_ANEGCAPABLE | BMSR_ESTATEN)
#define BCM5331X_MGMT_ADVERTISE		(ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP | \
					 ADVERTISE_PAUSE_ASYM)

/* link=2 (see "Link of the front ports"): the real PHY behind the emulation */
static int lk_phy_read(struct dsa_switch *ds, int port, int reg);
static int lk_phy_write(struct dsa_switch *ds, int port, int reg, u16 val);
static int link_mode;
/* see "Own PHY driver of the BCM54684": ephy=Y, phyexp=Y, cable_test=Y */
static bool ephy, phyexp, cable_test;
#define BCM5331X_EPHY_ID	0xf0e54684	/* private: no OUI of a PHY maker, no upstream driver binds */
#define BCM5331X_EPHY_REAL_ID	0x0143bef3	/* BCM54684 of port1-16 */
#define BCM5331X_EPHY_ESR	0x11		/* extended status: bit 13 = MDI crossover (phy54684.c) */
#define BCM5331X_EPHY_ESR_XOVER	BIT(13)
enum { EP_ID_UNREAD, EP_ID_OK, EP_ID_OTHER };
static u8 ep_id[NUM_PORTS];			/* real ID of the PHY of a front port, checked once */
static unsigned long ep_sel_writes, ep_data_writes, ep_skipped, ep_id_other;
static int ep_id_read(struct bcm53314 *sw, int port);
static bool ep_port(int port);

/* phy_write calls received (and dropped): visible to debugfs */
static unsigned long bcm5331x_phy_writes;

/*
 * MII register @reg of the emulated PHY of front port @port. Only BMSR,
 * LPA and STAT1000 depend on the link. BMSR takes a link sample (MAC_MODE,
 * plus one MIIM read of the real BMSR with linksrc=bmsr). LPA and STAT1000
 * report the link up, with speed and duplex from MAC_MODE alone (S-channel
 * read, no MIIM): genphy_read_status reads them only after a BMSR with a
 * link change (LPA only once autonegotiation is complete; STAT1000 of a
 * port without link only feeds a master/slave state genphy discards). Cost
 * per open port: one MIIM read a second with the link up (genphy reads BMSR
 * once, then returns), two with the link down (genphy double read);
 * the ID registers, BMCR and the advertisement registers are constants, so
 * the bus scan (PHY ID probe) does not touch the switch. A failed read of
 * the link source is reported as link down, not as a bus error: a bus
 * error would stop the phylib state machine (PHY_ERROR) for good.
 * Clause-45-over-22 (MMD) access reads 0: no EEE.
 */
static int bcm5331x_dsa_phy_read(struct dsa_switch *ds, int port, int reg)
{
	struct bcm53314 *sw = ds->priv;
	struct fixed_phy_status st = {
		.link = 0, .speed = SPEED_1000, .duplex = DUPLEX_FULL,
	};
	u32 mm[3] = { 0 };
	bool mg = port == PORT_MGMT && bcm5331x_has_mgmt(sw);
	int val;

	if (!bcm5331x_user_vid(sw, port))
		return 0xffff;		/* no PHY at this address (not a user port) */
	/* link=2: real PHYs of the front ports only; MGMT keeps the emulated PHY */
	if (link_mode == 2 && bcm5331x_is_front(port))
		return lk_phy_read(ds, port, reg);

	switch (reg) {
	case MII_PHYSID1:
	case MII_PHYSID2:
		return 0;		/* phy ID 0 (swphy): generic PHY driver */
	case MII_BMCR:
		return BMCR_ANENABLE;	/* autoneg on, never restarting, never reset */
	case MII_ADVERTISE:
		return mg ? BCM5331X_MGMT_ADVERTISE : BCM5331X_PHY_ADVERTISE;
	case MII_CTRL1000:
		return BCM5331X_PHY_CTRL1000;
	case MII_ESTATUS:
		return BCM5331X_PHY_ESTATUS;
	case MII_MMD_CTRL:
	case MII_MMD_DATA:
		return 0;
	case MII_BMSR:
	case MII_LPA:
	case MII_STAT1000:
		break;
	default:
		return 0xffff;
	}

	if (reg == MII_BMSR) {
		if (!bcm5331x_dsa_link_sample(sw, port, mm))
			bcm5331x_dsa_mac_mode_decode(mm[0], &st.link, &st.speed,
						     &st.duplex);
	} else {
		/* LPA, STAT1000: the link genphy just read up in BMSR */
		int err;

		mutex_lock(&sw->lock);
		err = sw_read(sw, O_MAC_MODE, port, mm);
		mutex_unlock(&sw->lock);
		if (!err) {
			bcm5331x_dsa_mac_mode_decode(mm[0], &st.link, &st.speed,
						     &st.duplex);
			if (dsa_link_bmsr)
				st.link = 1;
		}
	}
	if (!st.link || mg) {
		/* any valid speed: swphy WARNs otherwise; MGMT links at 1000 FD only */
		st.speed = SPEED_1000;
		st.duplex = DUPLEX_FULL;
	}

	val = swphy_read_reg(reg, &st);
	if (val < 0)
		return 0xffff;
	if (reg == MII_BMSR)
		val |= mg ? BCM5331X_MGMT_BMSR_ABILITY : BCM5331X_PHY_BMSR_ABILITY;
	return val;
}

/*
 * A write to the emulated PHY (BMCR, advertisement, MMD, ethtool) is
 * dropped: no MIIM transaction, nothing reaches the switch or its PHYs.
 * With link=2 the real PHY takes BMCR, ADVERTISE and CTRL1000 (see "Link
 * of the front ports").
 */
static int bcm5331x_dsa_phy_write(struct dsa_switch *ds, int port, int reg,
				  u16 val)
{
	if (link_mode == 2 && bcm5331x_is_front(port))
		return lk_phy_write(ds, port, reg, val);
	WRITE_ONCE(bcm5331x_phy_writes, READ_ONCE(bcm5331x_phy_writes) + 1);
	return 0;
}

/* ---------------------------------------------------------------------- */
/* Link of the front ports (link=1|2)                                      */

/*
 * Module parameter link (default 0: nothing below runs, no switch write,
 * the MAC ops are empty and the emulated PHYs inert, as before):
 *
 * link=1: EPC_LINK_BMAP follows the link. The ingress pipeline forwards to
 *   a port only if its bit is set in EPC_LINK_BMAP (ING_MISC_CONFIG.
 *   USE_EPC_LINK_BMP, set by the boot firmware); step "ports"
 *   adds every front port to it once, whatever its link, and nothing
 *   removes it under DSA (the work item of the base module, which held it
 *   with monitor=2, is off). mac_link_down clears the bit of the
 *   port, mac_link_up sets it again: one write each, re-read before (it
 *   must hold the value this driver last wrote, else link writes stop),
 *   checked (one front port bit changes, the trunk stays in, no bit that
 *   was not set at load is ever added), read back (a mismatch halts the
 *   base module). At each link up the PHY registers BMCR, LPA and STAT1000
 *   (MIIM reads), MAC_MODE and COMMAND_CONFIG of the port (S-channel reads)
 *   are logged with the speed, duplex and pause phylink resolved: reads
 *   only, they tell whether the MAC follows the PHY by itself
 *   (COMMAND_CONFIG.ENA_EXT_CONFIG, bit 22, is 1 on every port as the boot
 *   firmware leaves it; OpenBCM keeps it so on Hawkeye, unimac.c
 *   mac_uni_init) or stays at the 1000 Mb/s full duplex of ETH_SPEED/HD_ENA.
 *
 * link=2: link=1, plus the real PHY of each front port and the MAC speed:
 *  - the emulated PHY passes the clause-22 registers BMCR, BMSR, ADVERTISE,
 *    LPA, CTRL1000, STAT1000 and ESTATUS of the real port PHY through (MIIM
 *    reads at the address of link_phy(); ID registers still 0, so the
 *    generic PHY driver stays bound and no vendor driver writes anything),
 *    so that phylib sees the real auto-negotiation result (speed, duplex,
 *    pause of the link partner) and the real forced mode;
 *  - writes of genphy (ethtool -s, config_aneg) reach the PHY for three
 *    registers only, each under a fixed rule, re-read before, read back
 *    (a mismatch halts the base module): ADVERTISE (10/100 half/full and
 *    the two pause bits may change, 100BASE-T4 may only be cleared,
 *    selector and the other bits unchanged), CTRL1000 (1000 half/full
 *    only), BMCR (auto-negotiation on, with or without restart; or forced
 *    10/100 half/full; never reset, loopback, power-down, isolate, forced
 *    1000 Mb/s or the reserved speed; power-down alone may be set
 *    or cleared, every other bit as read, which is what phylib does when the
 *    port is closed and opened again). Any other write is refused
 *    (-EINVAL, ethtool sees the error); writes of other registers (MMD
 *    for EEE) are dropped as before. The first write to a port saves its
 *    BMCR, ADVERTISE and CTRL1000;
 *  - at link up COMMAND_CONFIG of the port takes the speed (ETH_SPEED),
 *    duplex (HD_ENA, full at 1000 Mb/s as in OpenBCM mac_uni_duplex_set)
 *    and pause (PAUSE_IGNORE = !rx_pause, IGNORE_TX_PAUSE = !tx_pause,
 *    mac_uni_pause_set) phylink resolved: nothing if the four fields
 *    already hold them; else two writes, the new fields with SW_RESET set
 *    then the same with SW_RESET clear (mac_uni_speed_set), each read
 *    back; the register must hold the value this driver last saw (else
 *    link writes stop) and only these fields and SW_RESET may change.
 *    ENA_EXT_CONFIG, TX_ENA, RX_ENA are never written;
 *  - after an accepted ethtool -s, COMMAND_CONFIG follows the PHY even when
 *    the link did not change (lk_resync).
 *
 * At unload (teardown, after the user ports are closed) every value the
 * driver changed is written back as it was at load (EPC_LINK_BMAP; the
 * COMMAND_CONFIG of each port, through SW_RESET; ADVERTISE, CTRL1000, then
 * BMCR of each PHY written to, with a restart of auto-negotiation if it
 * was on), each read back. All of it is volatile: the switch and its PHYs
 * are reset by the boot firmware at the next boot. Not covered:
 * IPG_HD_BKP_CNTL (OpenBCM _hawkeye_new_link_check, 10/100 and half
 * duplex back-off), CMIC_TX/RX_PAUSE_CAPABILITY (Hawkeye A0 QSGMII pause
 * work-around), the SerDes of the QSGMII ports.
 * debugfs "link" (read only) shows the state, the saved values and the
 * write counters.
 */
module_param_named(link, link_mode, int, 0444);
MODULE_PARM_DESC(link, "Link of the front ports: 0 = nothing written (default); 1 = EPC_LINK_BMAP follows the link (one write per link change, read back), PHY/MAC state logged at link up; 2 = 1 + real port PHY (registers passed through, ethtool -s writes ADVERTISE/CTRL1000/BMCR under fixed rules) and MAC speed/duplex/pause in COMMAND_CONFIG; all restored at unload");

#define LK_CC_ETH_SPEED		GENMASK(3, 2)
#define LK_CC_PAUSE_IGNORE	BIT(8)
#define LK_CC_HD_ENA		BIT(10)
#define LK_CC_ENA_EXT_CONFIG	BIT(22)
#define LK_CC_IGNORE_TX_PAUSE	BIT(28)
#define LK_CC_FIELDS		(LK_CC_ETH_SPEED | LK_CC_PAUSE_IGNORE | LK_CC_HD_ENA | \
				 LK_CC_IGNORE_TX_PAUSE)
#define LK_CC_CMP		(~(u32)CC_LATE_COL_FIX)	/* bit 31 read only, self-clearing */
#define LK_EPC_FRONT		(GENMASK(24, 5) & ~BIT(PORT_MGMT))	/* front ports 5, 7-24 */
#define LK_BMCR_OK		(BMCR_ANENABLE | BMCR_ANRESTART | BMCR_SPEED100 | \
				 BMCR_SPEED1000 | BMCR_FULLDPLX)
#define LK_ADV_CHG		(ADVERTISE_10HALF | ADVERTISE_10FULL | ADVERTISE_100HALF | \
				 ADVERTISE_100FULL | ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM)
#define LK_C1000_CHG		(ADVERTISE_1000FULL | ADVERTISE_1000HALF)

static struct lk_port {
	bool cc_saved;
	u32 cc_orig, cc_cur;		/* COMMAND_CONFIG at load, as last read or written */
	bool phy_saved;
	u16 bmcr_orig, adv_orig, c1000_orig;
	bool up, txp, rxp;
	int speed, duplex;
	unsigned int ups, downs;
} lk[NUM_PORTS];
static bool lk_epc_saved, lk_stopped;
static u32 lk_epc_orig, lk_epc_cur;
static char lk_stop_why[96];
static unsigned long lk_epc_writes, lk_cc_writes, lk_phy_writes, lk_refusals, lk_restores;
static unsigned long lk_resyncs;	/* lk_resync: MAC set again with no link change */
static unsigned long lk_pdowns;		/* BMCR_PDOWN set or cleared alone (phylib suspend/resume) */
/*
 * While the switch is being removed, phylib detaches every
 * attached PHY and suspends it (phy_detach -> phy_suspend -> genphy_suspend):
 * those power-downs are left out (no MIIM write, counted), the PHYs stay as
 * they are; a PHY already powered down (port closed before the removal) is
 * powered up again by lk_restore.
 */
static bool lk_removing;
static unsigned long lk_pdown_left;
#define LK_WAKE_TRIES		20	/* reads of BMCR after power-up, 1-2 ms apart */

/* Parameter check, before anything is probed (called by the init) */
static int bcm5331x_link_param_check(void)
{
	if (link_mode < 0 || link_mode > 2) {
		pr_err("bcm5331x-dsa: link: 0, 1 or 2\n");
		return -EINVAL;
	}
	if (link_mode && !dsa_link_bmsr) {
		pr_err("bcm5331x-dsa: link=%d needs linksrc=bmsr\n", link_mode);
		return -EINVAL;
	}
	return 0;
}

static __printf(2, 3) void lk_stop(struct bcm53314 *sw, const char *fmt, ...)
{
	va_list ap;

	if (lk_stopped)
		return;
	va_start(ap, fmt);
	vscnprintf(lk_stop_why, sizeof(lk_stop_why), fmt, ap);
	va_end(ap);
	lk_stopped = true;
	dev_warn(&sw->pdev->dev, "link: writes stopped (%s), reads go on\n", lk_stop_why);
}

/*
 * At set-up (link >= 1): save EPC_LINK_BMAP and the COMMAND_CONFIG of each
 * front port, as step "ports" left them: every front port and the trunk in
 * EPC_LINK_BMAP, each MAC out of reset with TX and RX enabled. Anything else
 * refuses the registration (reads only).
 */
static int lk_setup(struct bcm53314 *sw, struct device *dev)
{
	u32 w[3], need = BIT(PORT_TRUNK);
	int i, err = 0;

	memset(lk, 0, sizeof(lk));
	lk_epc_saved = lk_stopped = false;
	lk_stop_why[0] = 0;
	lk_epc_writes = lk_cc_writes = lk_phy_writes = lk_refusals = lk_restores = 0;
	lk_resyncs = lk_pdowns = lk_pdown_left = 0;
	lk_removing = false;
	memset(ep_id, 0, sizeof(ep_id));
	ep_sel_writes = ep_data_writes = ep_skipped = ep_id_other = 0;
	if (!link_mode)
		return 0;
	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++)
		need |= BIT(front_ports[i].port);
	mutex_lock(&sw->lock);
	if (sw->halted) {
		err = -EIO;
		goto out;
	}
	err = sw_read(sw, O_EPC_LINK_BMAP, 0, w);
	if (err)
		goto out;
	if ((w[0] & need) != need) {
		dev_err(dev, "link: EPC_LINK_BMAP 0x%08x lacks ports 0x%08x: refusing to register\n",
			w[0], need & ~w[0]);
		err = -EINVAL;
		goto out;
	}
	lk_epc_orig = lk_epc_cur = w[0];
	lk_epc_saved = true;
	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++) {
		int p = front_ports[i].port;

		err = sw_read(sw, O_COMMAND_CONFIG, p, w);
		if (err)
			goto out;
		if ((w[0] & CC_SW_RESET) || (w[0] & (CC_TX_ENA | CC_RX_ENA)) != (CC_TX_ENA | CC_RX_ENA)) {
			dev_err(dev, "link: COMMAND_CONFIG[%d] 0x%08x: MAC not enabled out of reset, refusing to register\n",
				p, w[0]);
			err = -EINVAL;
			goto out;
		}
		lk[p].cc_orig = lk[p].cc_cur = w[0];
		lk[p].cc_saved = true;
	}
	dev_info(dev, "link=%d: EPC_LINK_BMAP 0x%08x, COMMAND_CONFIG of port1 0x%08x saved\n",
		 link_mode, lk_epc_orig, lk[front_ports[0].port].cc_orig);
out:
	mutex_unlock(&sw->lock);
	return err;
}

/* the one change of EPC_LINK_BMAP allowed: the bit of one front port, trunk kept, nothing new */
static bool lk_epc_ok(u32 old, u32 val, int port)
{
	return bcm5331x_is_front(port) && (old ^ val) == BIT(port) &&
	       (old & BIT(PORT_TRUNK)) && (val & BIT(PORT_TRUNK)) && !(val & ~lk_epc_orig);
}

/* under sw->lock */
static void lk_epc_apply(struct bcm53314 *sw, int port, bool on)
{
	u32 w[3], want;

	if (lk_stopped || sw->halted || !lk_epc_saved)
		return;
	if (sw_read(sw, O_EPC_LINK_BMAP, 0, w))
		return;
	if (w[0] != lk_epc_cur) {
		lk_stop(sw, "EPC_LINK_BMAP 0x%08x, last written 0x%08x", w[0], lk_epc_cur);
		return;
	}
	want = on ? w[0] | BIT(port) : w[0] & ~BIT(port);
	if (want == w[0])
		return;
	if (!lk_epc_ok(w[0], want, port)) {
		lk_refusals++;
		lk_stop(sw, "EPC_LINK_BMAP 0x%08x -> 0x%08x refused", w[0], want);
		return;
	}
	w[0] = want;
	if (schan_op(sw, true, O_EPC_LINK_BMAP, 0, w))
		return;
	lk_epc_writes++;
	udelay(10);
	if (sw_read(sw, O_EPC_LINK_BMAP, 0, w))
		return;
	if (w[0] != want) {
		sw_fault(sw, "dsa: EPC_LINK_BMAP read back 0x%08x, wrote 0x%08x", w[0], want);
		return;
	}
	lk_epc_cur = want;
	dev_info(&sw->pdev->dev, "link: port %d %s, EPC_LINK_BMAP -> 0x%08x\n",
		 port, on ? "up" : "down", want);
}

/* COMMAND_CONFIG wanted for a resolved link, from its current value */
static u32 lk_cc_want(u32 cc, int speed, int duplex, bool txp, bool rxp)
{
	u32 sp = speed == SPEED_10 ? 0 : speed == SPEED_100 ? 1 : 2;

	cc &= ~LK_CC_FIELDS;
	cc |= sp << 2;	/* ETH_SPEED */
	if (duplex == DUPLEX_HALF && sp != 2)
		cc |= LK_CC_HD_ENA;
	if (!rxp)
		cc |= LK_CC_PAUSE_IGNORE;
	if (!txp)
		cc |= LK_CC_IGNORE_TX_PAUSE;
	return cc;
}

/*
 * Bits of COMMAND_CONFIG not compared: LATE_COL_FIX always, TX_ENA and RX_ENA
 * while in reset ("not reliable while in reset", plan_port_on of the base).
 */
static u32 lk_cc_ignore(u32 v)
{
	return CC_LATE_COL_FIX | (v & CC_SW_RESET ? CC_TX_ENA | CC_RX_ENA : 0);
}

/* the changes of COMMAND_CONFIG allowed: the four fields and SW_RESET of a front port */
static bool lk_cc_ok(u32 old, u32 val, int port)
{
	u32 sp = (val & LK_CC_ETH_SPEED) >> 2;

	return bcm5331x_is_front(port) &&
	       !((old ^ val) & ~(LK_CC_FIELDS | CC_SW_RESET | lk_cc_ignore(old))) &&
	       sp <= 2 && !(sp == 2 && (val & LK_CC_HD_ENA)) &&
	       (val & (CC_TX_ENA | CC_RX_ENA)) == (CC_TX_ENA | CC_RX_ENA);
}

/* one COMMAND_CONFIG write, read back; under sw->lock */
static int lk_cc_write(struct bcm53314 *sw, int port, u32 val)
{
	u32 w[3] = { val };
	int err;

	if (!lk_cc_ok(lk[port].cc_cur, val, port)) {
		lk_refusals++;
		lk_stop(sw, "COMMAND_CONFIG[%d] 0x%08x -> 0x%08x refused", port, lk[port].cc_cur, val);
		return -EINVAL;
	}
	err = schan_op(sw, true, O_COMMAND_CONFIG, port, w);
	if (err)
		return err;
	lk_cc_writes++;
	udelay(2);	/* OpenBCM mac_uni_pause_set: 2 us before SW_RESET is released */
	err = sw_read(sw, O_COMMAND_CONFIG, port, w);
	if (err)
		return err;
	if ((w[0] ^ val) & ~lk_cc_ignore(val)) {
		sw_fault(sw, "dsa: COMMAND_CONFIG[%d] read back 0x%08x, wrote 0x%08x", port, w[0], val);
		return -EIO;
	}
	lk[port].cc_cur = val;
	return 0;
}

/* COMMAND_CONFIG of @port to @want through SW_RESET; under sw->lock */
static int lk_cc_set(struct bcm53314 *sw, int port, u32 want)
{
	u32 w[3];
	int err;

	if (lk_stopped || sw->halted || !lk[port].cc_saved)
		return -EPERM;
	err = sw_read(sw, O_COMMAND_CONFIG, port, w);
	if (err)
		return err;
	if ((w[0] ^ lk[port].cc_cur) & LK_CC_CMP) {
		lk_stop(sw, "COMMAND_CONFIG[%d] 0x%08x, last seen 0x%08x", port, w[0], lk[port].cc_cur);
		return -ESTALE;
	}
	lk[port].cc_cur = w[0];
	if (!((w[0] ^ want) & LK_CC_CMP))
		return 0;
	err = lk_cc_write(sw, port, want | CC_SW_RESET);
	if (!err)
		err = lk_cc_write(sw, port, want & ~CC_SW_RESET);
	if (!err)
		dev_info(&sw->pdev->dev, "link: COMMAND_CONFIG[%d] 0x%08x -> 0x%08x\n",
			 port, w[0], lk[port].cc_cur);
	return err;
}

/* reads only: what the PHY and the MAC hold at link up (link >= 1); under sw->lock */
static void lk_observe(struct bcm53314 *sw, int port, int speed, int duplex, bool txp, bool rxp)
{
	u16 bmcr = 0, lpa = 0, stat1000 = 0;
	u32 mm[3] = { 0 }, cc[3] = { 0 };
	u8 a = link_phy(port);

	if (sw->halted || !a)
		return;
	if (miim_op(sw, false, a, MII_BMCR, &bmcr) || miim_op(sw, false, a, MII_LPA, &lpa) ||
	    miim_op(sw, false, a, MII_STAT1000, &stat1000) ||
	    sw_read(sw, O_MAC_MODE, port, mm) || sw_read(sw, O_COMMAND_CONFIG, port, cc))
		return;
	dev_info(&sw->pdev->dev,
		 "link: port %d up %d/%s pause rx%d tx%d; PHY 0x%02x BMCR 0x%04x LPA 0x%04x STAT1000 0x%04x; MAC_MODE 0x%02x (speed %u, %s); COMMAND_CONFIG 0x%08x (ETH_SPEED %u, HD_ENA %d, ENA_EXT_CONFIG %d)\n",
		 port, speed, duplex == DUPLEX_HALF ? "half" : "full", rxp, txp, a, bmcr, lpa,
		 stat1000, mm[0] & 0x3f, mm[0] & 3, (mm[0] & BIT(2)) ? "half" : "full", cc[0],
		 (u32)((cc[0] & LK_CC_ETH_SPEED) >> 2), !!(cc[0] & LK_CC_HD_ENA),
		 !!(cc[0] & LK_CC_ENA_EXT_CONFIG));
}

/* ---- real PHY of a front port (link=2) ---- */

/* MIIM read of @reg of the PHY of @port; under sw->lock */
static int lk_phy_rd(struct bcm53314 *sw, int port, int reg, u16 *v)
{
	u8 a = link_phy(port);

	if (sw->halted)
		return -EIO;
	if (!a || a == BMSR_GAP_ADDR)
		return -ENODEV;
	return miim_op(sw, false, a, reg, v);
}

/* MIIM write of @reg (0, 4 or 9) of the PHY of @port, read back; under sw->lock */
static int lk_phy_wr(struct bcm53314 *sw, int port, int reg, u16 val)
{
	u8 a = link_phy(port);
	u16 v = val, rb;
	int err, tries;

	if (sw->halted)
		return -EIO;
	if (!a || a == BMSR_GAP_ADDR)
		return -ENODEV;
	sw->miim_adv_armed = reg == MII_ADVERTISE || reg == MII_CTRL1000;
	err = miim_op(sw, true, a, reg, &v);
	sw->miim_adv_armed = false;
	if (err)
		return err;
	lk_phy_writes++;
	err = miim_op(sw, false, a, reg, &rb);
	/*
	 * Out of power-down the PHY may still report
	 * BMCR_PDOWN for a while; read again (bounded) before judging.
	 */
	for (tries = 1; !err && reg == MII_BMCR && !(val & BMCR_PDOWN) && (rb & BMCR_PDOWN) &&
	     tries < LK_WAKE_TRIES; tries++) {
		usleep_range(1000, 2000);
		err = miim_op(sw, false, a, reg, &rb);
	}
	if (err)
		return err;
	/* restart and reset clear themselves */
	if (reg == MII_BMCR ? (rb ^ val) & ~(BMCR_ANRESTART | BMCR_RESET) : rb != val) {
		sw_fault(sw, "dsa: PHY 0x%02x register %d read back 0x%04x, wrote 0x%04x", a, reg, rb, val);
		return -EIO;
	}
	return 0;
}

/*
 * The PHY writes allowed (genphy config_aneg / setup_forced of ethtool -s;
 * genphy_suspend / genphy_resume). BMCR_PDOWN alone may be set or
 * cleared, every other bit as read (lk_phy_pdown): phylib powers the PHY
 * down when the port is closed (ip link set down, removal: phy_stop, then
 * PHY_HALTED -> phy_suspend -> genphy_suspend, phy_set_bits(BMCR, PDOWN))
 * and up again when it is opened (genphy_resume clears the bit).
 */
static bool lk_phy_pdown(int reg, u16 old, u16 val)
{
	return reg == MII_BMCR && (old ^ val) == BMCR_PDOWN;
}

/*
 * Power-down never on the PHY of MGMT (internal 0x86, the TFTP port of the boot loader grants
 * its auto-negotiation only): MGMT keeps its emulated PHY under link=2 today, this holds if that
 * ever changes (integration of mgmt=1 with link=2).
 */
static bool lk_pdown_port_ok(int port)
{
	return port != PORT_MGMT && link_phy(port) != BCM5331X_MGMT_PHY;
}

static bool lk_phy_ok(int reg, u16 old, u16 val)
{
	if (lk_phy_pdown(reg, old, val))
		return true;
	switch (reg) {
	case MII_BMCR:
		if (val & ~LK_BMCR_OK)
			return false;	/* reset, loopback, power-down, isolate, collision test */
		if (val & BMCR_ANENABLE)
			return true;
		/* forced: 10 or 100 Mb/s only (1000BASE-T needs auto-negotiation), no restart */
		return !(val & (BMCR_SPEED1000 | BMCR_ANRESTART));
	case MII_ADVERTISE:
		return !((old ^ val) & ~(LK_ADV_CHG | ADVERTISE_100BASE4)) &&
		       !(val & ADVERTISE_100BASE4) && (val & ADVERTISE_SLCT) == ADVERTISE_CSMA;
	case MII_CTRL1000:
		return !((old ^ val) & ~LK_C1000_CHG);
	}
	return false;
}

/*
 * ethtool -s on a front port, judged before phylink and phylib (glue:
 * bcm5331x_user_set_link_ksettings). A refusal must come here:
 * phy_ethtool_ksettings_set accepts a request, starts the PHY state
 * machine and returns 0; the state machine then writes the PHY
 * (genphy_setup_forced / genphy_config_aneg) and a refused write there
 * (lk_phy_ok above, the second barrier) is phy_error(): WARN, PHY_ERROR,
 * link down until the port is removed (drivers/net/phy/phy.c).
 *
 * link=0|1 (PHY emulated, its writes dropped): a forced speed or duplex,
 * or a changed advertisement, would change nothing on the link and leave
 * a wrong state on display; refused (-EOPNOTSUPP), only auto-negotiation
 * with the advertisement unchanged passes (as for the statistics).
 * link=2 (real PHY): only what lk_phy_ok would refuse is refused
 * (-EINVAL): forced 1000 Mb/s (1000BASE-T needs auto-negotiation), a
 * forced speed other than 10/100 or a duplex other than half/full, and an
 * advertisement with no speed or with a mode outside 10/100/1000 BASE-T
 * half/full, pause, asymmetric pause (adv_ok/adv_speed: computed by the
 * glue). Decisions kept apart from the glue, for testing.
 */
static unsigned long bcm5331x_ksettings_refusals;

static int bcm5331x_ksettings_check(bool autoneg, bool adv_same)
{
	if (autoneg && adv_same)
		return 0;
	bcm5331x_ksettings_refusals++;
	return -EOPNOTSUPP;
}

static int bcm5331x_ksettings_check_link2(bool autoneg, u32 speed, u8 duplex,
					  bool adv_ok, bool adv_speed)
{
	if (autoneg ? adv_ok && adv_speed :
	    (speed == SPEED_10 || speed == SPEED_100) &&
	    (duplex == DUPLEX_HALF || duplex == DUPLEX_FULL))
		return 0;
	bcm5331x_ksettings_refusals++;
	return -EINVAL;
}

/* first write to the PHY of @port: save the three registers it may change */
static int lk_phy_save(struct bcm53314 *sw, int port)
{
	struct lk_port *l = &lk[port];
	int err;

	if (l->phy_saved)
		return 0;
	err = lk_phy_rd(sw, port, MII_BMCR, &l->bmcr_orig);
	if (!err)
		err = lk_phy_rd(sw, port, MII_ADVERTISE, &l->adv_orig);
	if (!err)
		err = lk_phy_rd(sw, port, MII_CTRL1000, &l->c1000_orig);
	if (!err) {
		l->phy_saved = true;
		dev_info(&sw->pdev->dev, "link: PHY 0x%02x of port %d: BMCR 0x%04x ADVERTISE 0x%04x CTRL1000 0x%04x saved\n",
			 link_phy(port), port, l->bmcr_orig, l->adv_orig, l->c1000_orig);
	}
	return err;
}

static int lk_phy_read(struct dsa_switch *ds, int port, int reg)
{
	struct bcm53314 *sw = ds->priv;
	u16 v = 0;
	int err;

	switch (reg) {
	case MII_PHYSID1:
	case MII_PHYSID2:
		/* ephy=Y: private ID of the driver's own PHY driver (BCM54684 checked once) */
		if (ephy && ep_port(port)) {
			int ok;

			mutex_lock(&sw->lock);
			ok = ep_id_read(sw, port);
			mutex_unlock(&sw->lock);
			if (ok > 0)
				return reg == MII_PHYSID1 ? BCM5331X_EPHY_ID >> 16 : BCM5331X_EPHY_ID & 0xffff;
		}
		return 0;		/* generic PHY driver, as with the emulation */
	case MII_MMD_CTRL:
	case MII_MMD_DATA:
		return 0;		/* no EEE */
	case BCM5331X_EPHY_ESR:
		/* extended status (MDI-X): PHYs bound to the driver's own PHY driver only */
		if (!ephy || !ep_port(port) || ep_id[port] != EP_ID_OK)
			return 0xffff;
		break;
	case MII_BMCR:
	case MII_BMSR:
	case MII_ADVERTISE:
	case MII_LPA:
	case MII_CTRL1000:
	case MII_STAT1000:
	case MII_ESTATUS:
		break;
	default:
		return 0xffff;
	}
	mutex_lock(&sw->lock);
	err = lk_phy_rd(sw, port, reg, &v);
	if (!err && reg == MII_BMSR) {
		sw->bmsr_reads++;
		if (v == 0xffff) {
			sw_fault(sw, "dsa: BMSR of PHY 0x%02x reads 0xffff", link_phy(port));
			err = -EIO;
		}
	}
	mutex_unlock(&sw->lock);
	if (!err)
		return reg == MII_BMCR ? v & ~BMCR_RESET : v;
	/* a bus error would stop phylib for good: link down, emulated constants */
	switch (reg) {
	case BCM5331X_EPHY_ESR:	return 0;
	case MII_BMCR:		return BMCR_ANENABLE;
	case MII_BMSR:		return BCM5331X_PHY_BMSR_ABILITY;
	case MII_ADVERTISE:	return BCM5331X_PHY_ADVERTISE;
	case MII_CTRL1000:	return BCM5331X_PHY_CTRL1000;
	case MII_ESTATUS:	return BCM5331X_PHY_ESTATUS;
	default:		return 0;
	}
}

static int lk_phy_write(struct dsa_switch *ds, int port, int reg, u16 val)
{
	struct bcm53314 *sw = ds->priv;
	u16 old;
	int err;

	if (reg != MII_BMCR && reg != MII_ADVERTISE && reg != MII_CTRL1000) {
		WRITE_ONCE(bcm5331x_phy_writes, READ_ONCE(bcm5331x_phy_writes) + 1);
		return 0;	/* MMD and the rest: dropped, as with the emulation */
	}
	mutex_lock(&sw->lock);
	/* no power-down while the switch is removed (phylib detach), the PHY stays as it is */
	if (lk_removing && reg == MII_BMCR && (val & BMCR_PDOWN)) {
		err = lk_phy_rd(sw, port, reg, &old);
		if (!err && lk_phy_pdown(reg, old, val)) {
			lk_pdown_left++;
			mutex_unlock(&sw->lock);
			return 0;
		}
	}
	err = lk_stopped ? -EPERM : lk_phy_save(sw, port);
	if (!err)
		err = lk_phy_rd(sw, port, reg, &old);
	if (!err && (!lk_phy_ok(reg, old, val) || (lk_phy_pdown(reg, old, val) && !lk_pdown_port_ok(port)))) {
		lk_refusals++;
		dev_warn(&sw->pdev->dev, "link: PHY 0x%02x register %d 0x%04x -> 0x%04x refused\n",
			 link_phy(port), reg, old, val);
		err = -EINVAL;
	}
	if (!err && old != val) {
		err = lk_phy_wr(sw, port, reg, val);
		if (!err && lk_phy_pdown(reg, old, val)) {
			lk_pdowns++;
			dev_info(&sw->pdev->dev, "link: PHY 0x%02x of port %d powered %s (BMCR 0x%04x -> 0x%04x)\n",
				 link_phy(port), port, val & BMCR_PDOWN ? "down" : "up", old, val);
		}
	}
	mutex_unlock(&sw->lock);
	return err;
}

/* ---------------------------------------------------------------------- */
/* Own PHY driver of the BCM54684, expansion registers                     */

/*
 * Module parameter ephy (default N, needs link=2): the external PHYs of
 * port1-16 (BCM54684, MIIM 0x09-0x10 and 0x12-0x19) leave the generic PHY
 * driver for a PHY driver of this module, "bcm5331x-ephy". It binds by a
 * private ID (BCM5331X_EPHY_ID) that the emulated ID registers return for
 * such a PHY once its real ID (registers 2 and 3, MIIM reads) has been
 * found to be 0x0143bef3, the BCM54684: no other driver, from upstream or
 * not, can match it, and a PHY with any other ID keeps ID 0 and the
 * generic driver (logged once). The internal PHYs of wan2, ha1, ha2 and
 * MGMT keep ID 0. The PHY driver is the generic one plus the MDI/MDI-X
 * state read from the extended status register 0x11 (bit 13, crossover,
 * as phy_54684_mdix_status_get of OpenBCM): ethtool shows "MDI-X: on/off
 * (auto)". It has no soft_reset and no config_init: nothing is written at
 * attach; its writes are genphy's (auto-negotiation, power-down when
 * suspended), under the rules of link=2. Registered (owner NULL, see below)
 * before the switch, removed after it.
 *
 * Owner NULL: phylib takes a reference on the module of the PHY driver for
 * each attached PHY (phy_attach_direct, try_module_get(d->driver->owner)).
 * The PHYs are attached as long as the switch is registered, and the switch
 * is unregistered by this module's exit only: with THIS_MODULE the module
 * could never be removed (rmmod: in use). The PHY driver is unregistered
 * by the exit after the switch, so no PHY is bound to it when its code
 * goes away.
 *
 * Module parameter phyexp (default N, needs link=2): debugfs "phyexp"
 * (0400); each read reads the expansion registers 0x10-0x13 (cable
 * diagnostics results, OpenMDK bcm54684_defs.h) and 0xC0-0xC1 (ECD control
 * and fault type of the Linux Broadcom PHY library) of the 16 external
 * PHYs: register 0x17 read, then for each register 0x17 <- 0x0F00 | e
 * (read back) and 0x15 read, then 0x17 given back its value (read back),
 * under sw->lock for the whole PHY. The only writes are those of the
 * select register 0x17, each armed for its exact
 * value (miim_exp_armed of the base module); a PHY whose select register
 * does not read 0 or an allowed select is skipped untouched.
 *
 * Module parameter cable_test (default N, needs ephy=Y; to be turned on
 * only once the dump above has shown a hardware ECD):
 * ethtool --cable-test on a port without link: ECD control (expansion
 * 0xC0) <- 0x8000 (run, centimetres, inter-pair shorts checked, link not
 * broken: a port with link is refused, -EBUSY), then the status polled
 * by phylib: fault type of each pair (0xC1) and, for an open or a short,
 * its distance (0xC2 + pair), as bcm_phy_cable_test_get_status of Linux.
 * One data write per test (0x8000, armed, only behind select 0x0FC0).
 */
module_param(ephy, bool, 0444);
MODULE_PARM_DESC(ephy, "With link=2, the BCM54684 PHYs of port1-16 bound to the driver's own PHY driver bcm5331x-ephy (private PHY ID after the real one is checked; MDI-X state read; no write at attach) instead of the generic PHY driver (default N)");
module_param(phyexp, bool, 0444);
MODULE_PARM_DESC(phyexp, "With link=2, debugfs phyexp: read of the expansion registers 0x10-0x13 and 0xC0-0xC1 of the 16 BCM54684 PHYs through the select register 0x17 (written, read back, given back) (default N)");
module_param(cable_test, bool, 0444);
MODULE_PARM_DESC(cable_test, "With ephy=1, ethtool --cable-test through the ECD of the BCM54684 (expansion 0xC0 <- run, ports without link only); off until the ECD is confirmed (default N)");

static const u8 ep_exp_regs[] = { 0x10, 0x11, 0x12, 0x13, 0xc0, 0xc1 };
#define EP_ECD_CTRL		0xc0
#define EP_ECD_FAULT		0xc1
#define EP_ECD_LEN(pair)	(0xc2 + (pair))
#define EP_ECD_IN_PROGRESS	BIT(11)
#define EP_ECD_LEN_INVALID	0xffff

/* Parameter check, before anything is probed (called by the init) */
static int bcm5331x_ephy_param_check(void)
{
	if ((ephy || phyexp) && link_mode != 2) {
		pr_err("bcm5331x-dsa: ephy=1 and phyexp=1 need link=2\n");
		return -EINVAL;
	}
	if (cable_test && !ephy) {
		pr_err("bcm5331x-dsa: cable_test=1 needs ephy=1\n");
		return -EINVAL;
	}
	return 0;
}

/* a front port with an external BCM54684 (port1-16) */
static bool ep_port(int port)
{
	u8 a = link_phy(port);

	return bcm5331x_is_front(port) && miim_exp_phy_ok(a);
}

/*
 * Real ID of the PHY of @port, read once (ephy=Y): 1 = BCM54684, 0 = other
 * (generic driver), < 0 = read error (generic driver, read again next
 * time). Under sw->lock.
 */
static int ep_id_read(struct bcm53314 *sw, int port)
{
	u16 id1, id2;
	int err;

	if (ep_id[port] != EP_ID_UNREAD)
		return ep_id[port] == EP_ID_OK;
	err = lk_phy_rd(sw, port, MII_PHYSID1, &id1);
	if (!err)
		err = lk_phy_rd(sw, port, MII_PHYSID2, &id2);
	if (err)
		return err;
	if (((u32)id1 << 16 | id2) == BCM5331X_EPHY_REAL_ID) {
		ep_id[port] = EP_ID_OK;
		return 1;
	}
	ep_id[port] = EP_ID_OTHER;
	ep_id_other++;
	dev_warn(&sw->pdev->dev, "ephy: PHY 0x%02x of port %d has ID 0x%08x, not the BCM54684: generic PHY driver\n",
		 link_phy(port), port, (u32)id1 << 16 | id2);
	return 0;
}

/* MDI state of a PHY from its extended status (genphy has read the link) */
static int ep_mdix_of(int esr, bool link)
{
	if (!link || esr < 0)
		return ETH_TP_MDI_INVALID;
	return esr & BCM5331X_EPHY_ESR_XOVER ? ETH_TP_MDI_X : ETH_TP_MDI;
}

/* ethtool -s with ephy=Y: MDI-X control stays automatic (nothing written for it) */
static bool ep_mdix_ctrl_ok(u8 ctrl)
{
	return ctrl == ETH_TP_MDI_INVALID || ctrl == ETH_TP_MDI_AUTO;
}

/* one armed write of the select (0x17) or data (0x15) register of PHY @a, read back for 0x17; under sw->lock */
static int ep_exp_wr(struct bcm53314 *sw, u8 a, u8 reg, u16 val)
{
	u16 v = val, rb;
	int err;

	if (sw->halted)
		return -EIO;
	sw->miim_exp_armed = true;
	sw->miim_exp_val = val;
	err = miim_op(sw, true, a, reg, &v);
	sw->miim_exp_armed = false;
	sw->miim_exp_val = 0;
	if (err)
		return err;
	if (reg == MIIM_EXP_DATA) {
		ep_data_writes++;
		return 0;	/* run: self-clearing, the status is read by the caller */
	}
	ep_sel_writes++;
	err = miim_op(sw, false, a, MIIM_EXP_SEL, &rb);
	if (err)
		return err;
	if (rb != val) {
		sw_fault(sw, "dsa: PHY 0x%02x expansion select read back 0x%04x, wrote 0x%04x", a, rb, val);
		return -EIO;
	}
	return 0;
}

/* expansion register @e of PHY @a: select, data read; the caller gives the select back; under sw->lock */
static int ep_exp_rd(struct bcm53314 *sw, u8 a, u8 e, u16 *v)
{
	int err = ep_exp_wr(sw, a, MIIM_EXP_SEL, MIIM_EXP_ER | e);

	if (!err)
		err = miim_op(sw, false, a, MIIM_EXP_DATA, v);
	return err;
}

/* select of PHY @a as found; refused (-EBUSY, nothing written) if not a value the rules allow; under sw->lock */
static int ep_sel_save(struct bcm53314 *sw, u8 a, u16 *sel)
{
	int err = miim_op(sw, false, a, MIIM_EXP_SEL, sel);

	if (!err && !miim_exp_sel_ok(*sel)) {
		ep_skipped++;
		dev_warn(&sw->pdev->dev, "phyexp: PHY 0x%02x select register 0x%04x: left untouched\n", a, *sel);
		return -EBUSY;
	}
	return err;
}

/*
 * Dump of port @port (phyexp=Y): @out[i] = expansion ep_exp_regs[i],
 * @sel = select register as found (and given back). Under sw->lock.
 */
static int ep_exp_survey(struct bcm53314 *sw, int port, u16 *out, u16 *sel)
{
	u8 a = link_phy(port);
	unsigned int i;
	int err, err2;

	if (!ep_port(port))
		return -ENODEV;
	if (sw->halted)
		return -EIO;
	err = ep_sel_save(sw, a, sel);
	if (err)
		return err;
	for (i = 0; !err && i < ARRAY_SIZE(ep_exp_regs); i++)
		err = ep_exp_rd(sw, a, ep_exp_regs[i], &out[i]);
	/* the select back as found, also after a failed read (unless halted) */
	err2 = sw->halted ? -EIO : ep_exp_wr(sw, a, MIIM_EXP_SEL, *sel);
	return err ? err : err2;
}

static int ep_show(struct seq_file *m, void *v)
{
	struct bcm53314 *sw = m->private;
	int i, err = 0;

	seq_puts(m, "port   phy  sel   exp10 exp11 exp12 exp13 expc0 expc1\n");
	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++) {
		int p = front_ports[i].port;
		u16 out[ARRAY_SIZE(ep_exp_regs)] = { 0 }, sel = 0;
		unsigned int k;

		if (!ep_port(p))
			continue;
		mutex_lock(&sw->lock);
		err = ep_exp_survey(sw, p, out, &sel);
		mutex_unlock(&sw->lock);
		if (err == -EBUSY) {
			seq_printf(m, "%-6s 0x%02x %04x  skipped\n", front_ports[i].label, link_phy(p), sel);
			err = 0;
			continue;
		}
		if (err)
			break;
		seq_printf(m, "%-6s 0x%02x %04x ", front_ports[i].label, link_phy(p), sel);
		for (k = 0; k < ARRAY_SIZE(ep_exp_regs); k++)
			seq_printf(m, " %04x ", out[k]);
		seq_putc(m, '\n');
	}
	seq_printf(m, "writes: select %lu data %lu; skipped %lu\n", ep_sel_writes, ep_data_writes, ep_skipped);
	return err;
}
DEFINE_SHOW_ATTRIBUTE(ep);

/*
 * cable_test=Y: start the ECD of the PHY of @port. The port must have no
 * link (BMSR read twice, latched-low bit): the run bit alone, without
 * BREAK_LINK. Under sw->lock.
 */
static int ep_cable_start(struct bcm53314 *sw, int port)
{
	u8 a = link_phy(port);
	u16 bmsr, sel, ctrl;
	int err, err2;

	if (!cable_test || !ep_port(port) || ep_id[port] != EP_ID_OK)
		return -EOPNOTSUPP;
	err = lk_phy_rd(sw, port, MII_BMSR, &bmsr);
	if (!err)
		err = lk_phy_rd(sw, port, MII_BMSR, &bmsr);
	if (err)
		return err;
	if (bmsr & BMSR_LSTATUS)
		return -EBUSY;		/* link up: the test would break it */
	err = ep_sel_save(sw, a, &sel);
	if (err)
		return err;
	err = ep_exp_rd(sw, a, EP_ECD_CTRL, &ctrl);
	if (!err && (ctrl & EP_ECD_IN_PROGRESS))
		err = -EBUSY;
	if (!err)
		err = ep_exp_wr(sw, a, MIIM_EXP_DATA, MIIM_EXP_ECD_RUN);
	err2 = sw->halted ? -EIO : ep_exp_wr(sw, a, MIIM_EXP_SEL, sel);
	if (!err)
		dev_info(&sw->pdev->dev, "cable test: PHY 0x%02x of port %d: ECD control 0x%04x, run\n",
			 a, port, ctrl);
	return err ? err : err2;
}

/*
 * cable_test=Y: status of the ECD of @port: *@finished false while in
 * progress; else @fault[pair] (fault type nibble, pair A = bits 15:12) and
 * @len[pair] (centimetres, -1 if none). Reads and select writes only.
 * Under sw->lock.
 */
static int ep_cable_status(struct bcm53314 *sw, int port, bool *finished, u8 *fault, int *len)
{
	u8 a = link_phy(port);
	u16 sel, ctrl, ft, l;
	int pair, err, err2;

	*finished = false;
	if (!cable_test || !ep_port(port) || ep_id[port] != EP_ID_OK)
		return -EOPNOTSUPP;
	err = ep_sel_save(sw, a, &sel);
	if (err)
		return err;
	err = ep_exp_rd(sw, a, EP_ECD_CTRL, &ctrl);
	if (!err && !(ctrl & EP_ECD_IN_PROGRESS)) {
		err = ep_exp_rd(sw, a, EP_ECD_FAULT, &ft);
		for (pair = 0; !err && pair < 4; pair++) {
			fault[pair] = (ft >> (12 - 4 * pair)) & 0xf;
			len[pair] = -1;
			/* open (2), short on the pair (3), short between pairs (4): a distance */
			if (fault[pair] >= 2 && fault[pair] <= 4) {
				err = ep_exp_rd(sw, a, EP_ECD_LEN(pair), &l);
				if (!err && l != EP_ECD_LEN_INVALID)
					len[pair] = l;
			}
		}
		if (!err)
			*finished = true;
	}
	err2 = sw->halted ? -EIO : ep_exp_wr(sw, a, MIIM_EXP_SEL, sel);
	return err ? err : err2;
}

#include <linux/ethtool_netlink.h>

static int bcm5331x_ephy_probe(struct phy_device *phydev)
{
	phydev->mdix_ctrl = ETH_TP_MDI_AUTO;	/* automatic crossover, as the PHY does; nothing written */
	return 0;
}

static int bcm5331x_ephy_read_status(struct phy_device *phydev)
{
	int err = genphy_read_status(phydev), esr = 0;

	if (err)
		return err;
	if (phydev->link)
		esr = phy_read(phydev, BCM5331X_EPHY_ESR);
	phydev->mdix = ep_mdix_of(esr, phydev->link);
	return 0;
}

static struct bcm53314 *bcm5331x_ephy_sw(struct phy_device *phydev)
{
	struct dsa_switch *ds = phydev->mdio.bus->priv;

	return ds->priv;
}

static int bcm5331x_ephy_cable_test_start(struct phy_device *phydev)
{
	struct bcm53314 *sw = bcm5331x_ephy_sw(phydev);
	int err;

	mutex_lock(&sw->lock);
	err = ep_cable_start(sw, phydev->mdio.addr);
	mutex_unlock(&sw->lock);
	if (err == -EBUSY)
		phydev_info(phydev, "cable test refused: link up or test running (the link is never broken)\n");
	return err;
}

static int bcm5331x_ephy_code(u8 fault)
{
	switch (fault) {
	case 1:		return ETHTOOL_A_CABLE_RESULT_CODE_OK;
	case 2:		return ETHTOOL_A_CABLE_RESULT_CODE_OPEN;
	case 3:		return ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT;
	case 4:		return ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT;
	default:	return ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC;
	}
}

static int bcm5331x_ephy_cable_test_get_status(struct phy_device *phydev, bool *finished)
{
	struct bcm53314 *sw = bcm5331x_ephy_sw(phydev);
	u8 fault[4] = { 0 };
	int len[4], pair, err;

	mutex_lock(&sw->lock);
	err = ep_cable_status(sw, phydev->mdio.addr, finished, fault, len);
	mutex_unlock(&sw->lock);
	if (err || !*finished)
		return err;
	for (pair = 0; pair < 4; pair++) {
		ethnl_cable_test_result(phydev, ETHTOOL_A_CABLE_PAIR_A + pair, bcm5331x_ephy_code(fault[pair]));
		if (len[pair] >= 0)
			ethnl_cable_test_fault_length(phydev, ETHTOOL_A_CABLE_PAIR_A + pair, len[pair]);
	}
	return 0;
}

static struct phy_driver bcm5331x_ephy_driver = {
	.phy_id		= BCM5331X_EPHY_ID,
	.phy_id_mask	= 0xffffffff,
	.name		= "bcm5331x-ephy",
	.probe		= bcm5331x_ephy_probe,
	.get_features	= genphy_read_abilities,
	.config_aneg	= genphy_config_aneg,
	.read_status	= bcm5331x_ephy_read_status,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
};
static bool bcm5331x_ephy_registered;

/* ---- MAC ops ---- */

static void bcm5331x_mac_link_up(struct phylink_config *config,
				 struct phy_device *phy, unsigned int mode,
				 phy_interface_t interface, int speed,
				 int duplex, bool tx_pause, bool rx_pause)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct bcm53314 *sw = dp->ds->priv;
	int port = dp->index;

	if (!link_mode || !bcm5331x_is_front(port))
		return;
	mutex_lock(&sw->lock);
	lk[port].up = true;
	lk[port].ups++;
	lk[port].speed = speed;
	lk[port].duplex = duplex;
	lk[port].txp = tx_pause;
	lk[port].rxp = rx_pause;
	lk_observe(sw, port, speed, duplex, tx_pause, rx_pause);
	if (link_mode == 2 && !lk_stopped && !sw->halted)
		lk_cc_set(sw, port, lk_cc_want(lk[port].cc_cur, speed, duplex, tx_pause, rx_pause));
	lk_epc_apply(sw, port, true);
	mutex_unlock(&sw->lock);
}

static void bcm5331x_mac_link_down(struct phylink_config *config,
				   unsigned int mode, phy_interface_t interface)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct bcm53314 *sw = dp->ds->priv;
	int port = dp->index;

	if (!link_mode || !bcm5331x_is_front(port))
		return;
	mutex_lock(&sw->lock);
	lk[port].up = false;
	lk[port].downs++;
	lk_epc_apply(sw, port, false);
	mutex_unlock(&sw->lock);
}

/*
 * link=2, after an accepted ethtool -s (glue: bcm5331x_user_resync). A new
 * duplex or pause at the same speed may leave the link up: phylib then
 * reports the link up once more (phy_check_link_status from PHY_UP calls
 * phy_link_up), but phylink_resolve calls mac_link_up only when the link
 * state changes, so COMMAND_CONFIG would keep what the last link up set
 * (link partner forced to 100 full, PHY in auto-negotiation at 100 half by
 * parallel detection, then ethtool -s 100 full: MAC at half duplex on a full
 * duplex link). @link, @speed, @duplex: what phylib holds once its state
 * machine has run; pause as phylink resolves it (phylink_apply_manual_flow):
 * the PHY result (@phy_tx, @phy_rx) if pause autoneg is on, else the manual
 * setting. Nothing unless the port is up for this driver (else mac_link_up
 * is still to come) and the PHY link is up (else mac_link_down is); then the
 * state is updated and COMMAND_CONFIG set through lk_cc_set (nothing written
 * if the four fields already hold it), with no link change and no
 * EPC_LINK_BMAP write. Returns 1 when the state was resynchronised.
 */
static int lk_resync(struct bcm53314 *sw, int port, bool link, int speed, int duplex,
		     bool phy_tx, bool phy_rx, bool pause_an, bool man_tx, bool man_rx)
{
	bool txp = pause_an ? phy_tx : man_tx;
	bool rxp = pause_an ? phy_rx : man_rx;
	struct lk_port *l;
	int ret = 0;

	if (link_mode != 2 || !bcm5331x_is_front(port) || !link ||
	    (speed != SPEED_10 && speed != SPEED_100 && speed != SPEED_1000) ||
	    (duplex != DUPLEX_HALF && duplex != DUPLEX_FULL))
		return 0;
	mutex_lock(&sw->lock);
	l = &lk[port];
	if (l->up && (l->speed != speed || l->duplex != duplex ||
		      l->txp != txp || l->rxp != rxp)) {
		l->speed = speed;
		l->duplex = duplex;
		l->txp = txp;
		l->rxp = rxp;
		lk_resyncs++;
		dev_info(&sw->pdev->dev, "link: port %d %d/%s pause rx%d tx%d without a link change: COMMAND_CONFIG follows the PHY\n",
			 port, speed, duplex == DUPLEX_HALF ? "half" : "full", rxp, txp);
		if (!lk_stopped && !sw->halted)
			lk_cc_set(sw, port, lk_cc_want(l->cc_cur, speed, duplex, txp, rxp));
		ret = 1;
	}
	mutex_unlock(&sw->lock);
	return ret;
}

/*
 * At teardown: every value changed back to the one saved at load, each read
 * back, whatever lk_stopped says (the rules of the restore: saved values
 * only). Nothing if the base module halted.
 */
static void lk_restore(struct bcm53314 *sw)
{
	u32 w[3];
	int p, err = 0;

	if (!link_mode)
		return;
	mutex_lock(&sw->lock);
	for (p = 0; p < NUM_PORTS && !err && !sw->halted; p++) {
		struct lk_port *l = &lk[p];

		if (l->phy_saved) {
			u16 cur, orig = l->bmcr_orig & ~BMCR_PDOWN;

			/* a PHY left powered down is powered up first (PDOWN alone cleared, read back) */
			err = lk_phy_rd(sw, p, MII_BMCR, &cur);
			if (!err && (cur & BMCR_PDOWN)) {
				err = lk_phy_wr(sw, p, MII_BMCR, cur & ~BMCR_PDOWN);
				lk_restores++;
			}
			if (!err)
				err = lk_phy_rd(sw, p, MII_ADVERTISE, &cur);
			if (!err && cur != l->adv_orig) {
				err = lk_phy_wr(sw, p, MII_ADVERTISE, l->adv_orig);
				lk_restores++;
			}
			if (!err)
				err = lk_phy_rd(sw, p, MII_CTRL1000, &cur);
			if (!err && cur != l->c1000_orig) {
				err = lk_phy_wr(sw, p, MII_CTRL1000, l->c1000_orig);
				lk_restores++;
			}
			if (!err)
				err = lk_phy_rd(sw, p, MII_BMCR, &cur);
			/* every restore clears BMCR_PDOWN */
			if (!err && (cur & ~BMCR_ANRESTART) != (orig & ~BMCR_ANRESTART)) {
				err = lk_phy_wr(sw, p, MII_BMCR, orig | (orig & BMCR_ANENABLE ? BMCR_ANRESTART : 0));
				lk_restores++;
			}
		}
		if (!err && l->cc_saved) {
			err = sw_read(sw, O_COMMAND_CONFIG, p, w);
			if (!err && ((w[0] ^ l->cc_orig) & LK_CC_CMP)) {
				l->cc_cur = w[0];
				err = lk_cc_write(sw, p, l->cc_orig | CC_SW_RESET);
				if (!err)
					err = lk_cc_write(sw, p, l->cc_orig & ~CC_SW_RESET);
				lk_restores++;
			}
		}
	}
	if (!err && !sw->halted && lk_epc_saved) {
		err = sw_read(sw, O_EPC_LINK_BMAP, 0, w);
		if (!err && w[0] != lk_epc_orig) {
			u32 want = lk_epc_orig;

			/* only front port bits may differ from the value at load */
			if ((w[0] ^ want) & ~LK_EPC_FRONT) {
				sw_fault(sw, "dsa: EPC_LINK_BMAP 0x%08x at unload, saved 0x%08x", w[0], want);
				err = -EIO;
			} else {
				w[0] = want;
				err = schan_op(sw, true, O_EPC_LINK_BMAP, 0, w);
				if (!err) {
					lk_epc_writes++;
					lk_restores++;
					udelay(10);
					err = sw_read(sw, O_EPC_LINK_BMAP, 0, w);
				}
				if (!err && w[0] != want) {
					sw_fault(sw, "dsa: EPC_LINK_BMAP read back 0x%08x, wrote 0x%08x", w[0], want);
					err = -EIO;
				}
				if (!err)
					lk_epc_cur = want;
			}
		}
	}
	mutex_unlock(&sw->lock);
	if (lk_pdown_left)
		dev_info(&sw->pdev->dev, "link: %lu power-down(s) of the removal left out\n", lk_pdown_left);
	dev_info(&sw->pdev->dev, "link: unload, %lu value(s) restored%s (EPC %lu, COMMAND_CONFIG %lu, PHY %lu writes, %lu refused, %lu power-down)\n",
		 lk_restores, err || sw->halted ? ", RESTORE FAILED" : "", lk_epc_writes, lk_cc_writes,
		 lk_phy_writes, lk_refusals, lk_pdowns);
}

static int lk_show(struct seq_file *m, void *v)
{
	struct bcm53314 *sw = m->private;
	u32 epc[3] = { 0 };
	int i, err;

	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : sw_read(sw, O_EPC_LINK_BMAP, 0, epc);
	mutex_unlock(&sw->lock);
	if (err)
		return err;
	seq_printf(m, "link %d stopped %d%s%s\nEPC_LINK_BMAP %08x saved %08x last %08x\n",
		   link_mode, lk_stopped, lk_stopped ? " " : "", lk_stop_why, epc[0], lk_epc_orig,
		   lk_epc_cur);
	seq_printf(m, "writes: EPC %lu COMMAND_CONFIG %lu PHY %lu; refused %lu; restored %lu\n",
		   lk_epc_writes, lk_cc_writes, lk_phy_writes, lk_refusals, lk_restores);
	seq_printf(m, "resync %lu pdown %lu\n", lk_resyncs, lk_pdowns);
	seq_printf(m, "pdown left at removal %lu\n", lk_pdown_left);
	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++) {
		int p = front_ports[i].port;
		const struct lk_port *l = &lk[p];
		u32 cc[3] = { 0 };

		mutex_lock(&sw->lock);
		err = sw->halted ? -EIO : sw_read(sw, O_COMMAND_CONFIG, p, cc);
		mutex_unlock(&sw->lock);
		if (err)
			return err;
		seq_printf(m, "%-6s p%-2d %s %4d/%s rx%d tx%d up %u down %u cc %08x saved %08x",
			   front_ports[i].label, p, l->up ? "up  " : "down", l->up ? l->speed : 0,
			   l->duplex == DUPLEX_HALF ? "half" : "full", l->rxp, l->txp, l->ups, l->downs,
			   cc[0], l->cc_orig);
		if (l->phy_saved)
			seq_printf(m, " phy saved %04x %04x %04x", l->bmcr_orig, l->adv_orig, l->c1000_orig);
		seq_putc(m, '\n');
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(lk);

/*
 * MAC ops: the front-port MACs are already configured and enabled by the
 * base module's "ports" step; mac_config writes nothing. mac_link_up and
 * mac_link_down write nothing with link=0 (default); see above for link=1|2.
 */
static void bcm5331x_mac_config(struct phylink_config *config,
				unsigned int mode,
				const struct phylink_link_state *state)
{
}

static const struct phylink_mac_ops bcm5331x_dsa_phylink_mac_ops = {
	.mac_config	= bcm5331x_mac_config,
	.mac_link_up	= bcm5331x_mac_link_up,
	.mac_link_down	= bcm5331x_mac_link_down,
};

/* ---------------------------------------------------------------------- */
/* DSA switch ops                                                          */

static enum dsa_tag_protocol
bcm5331x_dsa_get_tag_protocol(struct dsa_switch *ds, int port,
			      enum dsa_tag_protocol mprot)
{
	return DSA_TAG_PROTO_BCM5331X_8021Q;
}

/* set once the double-tagging writes are done and read back (qinq=Y) */
static bool qinq_on;

/*
 * Fill the VID<->port tables the tagger owns, from the layout the base
 * module already wrote. The tagger allocates them in its .connect, which
 * the DSA core calls *after* .setup (net/dsa/dsa.c dsa_switch_setup: ops->
 * setup, then dsa_switch_setup_tag_protocol: tag_ops->connect, then
 * ops->connect_tag_protocol): they are filled from connect_tag_protocol,
 * before any user port exists. During .setup ds->tagger_data is still NULL.
 */
static int bcm5331x_fill_tagger(struct dsa_switch *ds)
{
	struct bcm5331x_tagger_data *td = ds->tagger_data;
	int i;

	if (!td)
		return -EINVAL;
	td->tpid = qinq_on ? ETH_P_8021AD : ETH_P_8021Q;
	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++) {
		td->port_vid[front_ports[i].port] = fp_vid(i);
		td->vid_port[fp_vid(i)] = front_ports[i].port;
	}
	if (bcm5331x_has_mgmt(ds->priv)) {
		td->port_vid[PORT_MGMT] = MGMT_VID;
		td->vid_port[MGMT_VID] = PORT_MGMT;
	}
	td->br_vid_first = BCM5331X_BR_VID_FIRST;
	smp_wmb();
	WRITE_ONCE(td->ready, true);
	return 0;
}

/*
 * The tagger is connected (its tables allocated): fill them. Any other
 * protocol, or no table, refuses the connection, and DSA then tears the
 * switch down (no user port is created). Nothing is sent to the switch.
 */
static int bcm5331x_dsa_connect_tag_protocol(struct dsa_switch *ds,
					     enum dsa_tag_protocol proto)
{
	int err;

	if (proto != DSA_TAG_PROTO_BCM5331X_8021Q)
		return -EPROTONOSUPPORT;
	err = bcm5331x_fill_tagger(ds);
	if (err)
		return err;
	dev_info(ds->dev, "tagger tables filled: %zu port VIDs\n",
		 ARRAY_SIZE(front_ports) + bcm5331x_has_mgmt(ds->priv));
	if (qinq_on)
		dev_info(ds->dev, "tagger outer TPID 0x%04x (double tagging)\n",
			 ETH_P_8021AD);
	return 0;
}

/* hardware statistics, see "Hardware statistics" */
static void st_start(struct bcm53314 *sw);
static void st_stop(void);
/* PTP, see "Time stamping" */
static void ts_setup(struct dsa_switch *ds);
static void ts_teardown(struct dsa_switch *ds);

static int bcm5331x_dsa_setup(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;
	int rem;

	/*
	 * The base module must have run the "ports" step and written its whole
	 * plan: this base mode adds no switch write, so a non-empty remaining
	 * plan means the switch is not in the state DSA relies on.
	 */
	if (!sw->ports) {
		dev_err(ds->dev, "step \"ports\" not run: no DSA layout, refusing to register\n");
		return -EINVAL;
	}
	rem = bcm5331x_plan_remaining(sw);
	if (rem != 0) {
		dev_err(ds->dev, "remaining plan not empty (%d of %d operations not written): refusing to register\n",
			rem, sw->nops);
		return -EINVAL;
	}

	rem = lk_setup(sw, ds->dev);
	if (rem)
		return rem;
	ts_setup(ds);

	if (bcm5331x_has_mgmt(sw))
		dev_info(ds->dev, "DSA registered: %zu front ports, CPU port %d, MGMT user port %d (VID %d)\n",
			 ARRAY_SIZE(front_ports), BCM5331X_CPU_PORT, PORT_MGMT, MGMT_VID);
	else
		dev_info(ds->dev, "DSA registered: %zu front ports, CPU port %d, MGMT excluded\n",
			 ARRAY_SIZE(front_ports), BCM5331X_CPU_PORT);
	st_start(sw);
	return 0;
}

/*
 * CPU link PHY: internal PHY of ge2 (TRUNK_PHY of the base module, MIIM 0x83,
 * internal bus), the only PHY this driver ever writes. The boot firmware
 * leaves it at 1000 Mb/s forced without auto-negotiation (MII control 0x0140)
 * and the 82574L at the other end of the link then has no carrier. One write
 * of 0x1340 (auto-negotiation enabled and restarted, 1000 Mb/s full duplex
 * kept) is made, through the base module's MIIM path and checks, and read
 * back (the restart bit clears itself: 0x1140 expected); nothing is written
 * if auto-negotiation is already on (idempotent: a second load writes
 * nothing) or if the register holds any other value (left as found, warned).
 * No write with cpu_an=0, below access=2, with dry_run, or once the base
 * module has halted. A failed MIIM transaction or read-back halts the base
 * module and refuses the registration. Not undone at unload: the PHY keeps
 * auto-negotiating until its next reset (volatile state).
 */
#define BCM5331X_CPU_PHY	TRUNK_PHY

/* MII control writes made to the CPU link PHY: visible to debugfs */
static unsigned long bcm5331x_cpu_an_writes;

static int bcm5331x_dsa_cpu_an(struct bcm53314 *sw, struct device *dev)
{
	u16 bmcr, val = BMCR_AUTONEG_RESTART, rb;
	int err;

	if (!cpu_an) {
		dev_info(dev, "cpu_an=0: ge2 PHY left as found\n");
		return 0;
	}
	if (access != 2 || dry_run) {
		dev_info(dev, "ge2 PHY left as found (access %d, dry_run %d)\n",
			 access, dry_run);
		return 0;
	}
	mutex_lock(&sw->lock);
	if (sw->halted) {
		err = -EIO;
		goto out;
	}
	err = miim_op(sw, false, BCM5331X_CPU_PHY, MII_BMCR, &bmcr);
	if (err)
		goto out;
	if (bmcr & BMCR_ANENABLE) {
		dev_info(dev, "ge2 PHY: MII control 0x%04x, auto-negotiation already on, nothing written\n",
			 bmcr);
		goto out;
	}
	if (bmcr != BMCR_FORCED_1000) {
		dev_warn(dev, "ge2 PHY: MII control 0x%04x, not 0x%04x: left as found\n",
			 bmcr, BMCR_FORCED_1000);
		goto out;
	}
	err = miim_op(sw, true, BCM5331X_CPU_PHY, MII_BMCR, &val);
	if (err)
		goto out;
	bcm5331x_cpu_an_writes++;
	err = miim_op(sw, false, BCM5331X_CPU_PHY, MII_BMCR, &rb);
	if (err)
		goto out;
	if ((rb & ~BMCR_ANRESTART) != (BMCR_AUTONEG_RESTART & ~BMCR_ANRESTART)) {
		sw_fault(sw, "dsa: ge2 PHY MII control reads 0x%04x after 0x%04x",
			 rb, BMCR_AUTONEG_RESTART);
		err = -EIO;
		goto out;
	}
	dev_info(dev, "ge2 PHY: MII control 0x%04x -> 0x%04x, read back 0x%04x (auto-negotiation)\n",
		 bmcr, BMCR_AUTONEG_RESTART, rb);
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(dev, "ge2 PHY auto-negotiation failed (%d): refusing to register\n",
			err);
	return err;
}

/* ---------------------------------------------------------------------- */
/* Double tagging (qinq=Y)                                                 */

/*
 * The switch has no CPU header: the port of a frame on the CPU link is its
 * port VID. A front port that should carry user VLANs must not let their
 * 802.1Q tag stand for the frame's VLAN in the switch. Double-tagging mode
 * (OpenBCM _bcm_fb_port_dtag_mode_set, src/bcm/esw/firebolt/port.c; field
 * layout of OpenMDK bcm53314_a0_defs.h) does exactly that:
 *  - ING_CONFIG.DT_MODE and EGR_CONFIG.DT_MODE (bit 0 of each) turn the
 *    chip to double tagging; every port is then a customer (UNI) port by
 *    default: a frame entering a front port always gets the outer VLAN of
 *    the port (PORT_VID, here 100+N), its own 802.1Q tag, if any, staying
 *    behind as the inner tag; the outer tag is removed at a front port
 *    (untagged member of the port VLAN), the inner tag kept;
 *  - the CPU link (ge2, port 3) becomes a provider (NNI) port, as the SDK's
 *    BCM_PORT_DTAG_MODE_INTERNAL: PORT_TAB.NNI_PORT (bit 32) and
 *    EGR_PORT.NNI_PORT (bit 1): its outer tag is parsed on ingress and added
 *    on egress (tagged member of every port VLAN);
 *  - the outer TPID of the CPU link is 0x88a8 (802.1ad), so that a user tag
 *    0x8100 is never taken for a port tag, by the switch or by the 82574L
 *    (which strips 0x8100 only). It uses the second TPID slot, unused here,
 *    as bcm_port_tpid_set does (_bcm_fb2_outer_tpid_entry_add,
 *    src/bcm/esw/firebolt/vlan.c; _bcm_fb2_port_tpid_set, port.c):
 *    ING_OUTER_TPID_1 and EGR_OUTER_TPID_1 = 0x88a8, then, for port 3 only,
 *    EGR_VLAN_CONTROL_1.OUTER_TPID_INDEX (bits 6:5) = 1, PORT_TAB.
 *    OUTER_TPID_ENABLE (bits 53:50) = 0b0010 and EGR_SRC_PORT.
 *    OUTER_TPID_ENABLE (bits 20:17) = 0b0010. Slot 0 keeps 0x8100 for every
 *    other port. The inner TPID (VLAN_CTRL / EGR_CONFIG INNER_TPID) is the
 *    reset 0x8100, checked, not written.
 * Eight writes in all, planned on what is read, checked against fixed rules
 * before the first one, each re-read before, written and read back; a
 * mismatch halts the base module (no further access, registration refused).
 * With steps ge3 and trunk2 (conduit LAG) ge3, the second member
 * of the trunk group, is set up exactly as ge2 (provider port, slot 1):
 * four writes more, twelve in all, the rules being those of ge2.
 * Refused before any write if the state is not the one the base mode leaves:
 * ports step done and fully written, no MGMT step, step ge3 only with step
 * trunk2, double tagging
 * off, slot 1 referenced by no port, no inner-tag add/remove, no VLAN
 * translation, every port UNI and not HiGig. Not undone at unload (volatile
 * until the next reset of the switch, like the steps): a reload needs a
 * reboot, the base module refusing a switch in double-tagging mode.
 */
#define QQ_TPID			ETH_P_8021AD
#define QQ_A_ING_OUTER_TPID_1	0x0278000d	/* IPIPE */
#define QQ_A_EGR_OUTER_TPID_1	0x04980001	/* EPIPE */
#define QQ_A_EGR_SRC_PORT	0x06900002	/* EPIPE, | port << 12 */
#define QQ_DT_MODE		BIT(0)		/* ING_CONFIG, EGR_CONFIG */
#define QQ_EP_HIGIG		BIT(0)		/* EGR_PORT */
#define QQ_EP_NNI		BIT(1)
#define QQ_EVC_VT_ENABLE	BIT(0)		/* EGR_VLAN_CONTROL_1 */
#define QQ_EVC_TPID_SEL		BIT(4)
#define QQ_EVC_TPID_INDEX	GENMASK(6, 5)
#define QQ_EVC_REMOVE_INNER	BIT(11)
#define QQ_ESP_ADD_INNER	BIT(0)		/* EGR_SRC_PORT */
#define QQ_ESP_TPID_EN		GENMASK(20, 17)
#define QQ_PT1_NNI		BIT(0)		/* PORT_TAB word 1: bit 32 */
#define QQ_PT1_TPID_EN		GENMASK(21, 18)	/* bits 53:50 */
#define QQ_PT1_VT_ENABLE	BIT(26)		/* bit 58 */
#define QQ_SLOT0		BIT(0)		/* OUTER_TPID_ENABLE: slot 0 (0x8100) */
#define QQ_SLOT1		BIT(1)		/* slot 1 (0x88a8) */
#define QQ_NOPS			8	/* CPU link ge2 only */
#define QQ_NOPS_TRUNK2		12	/* + ge3, second member of the trunk group of step trunk2 */
/* value of a field of contiguous mask m in a word, and the reverse */
#define QQ_GET(m, x)		(((x) & (m)) >> __builtin_ctz(m))
#define QQ_PUT(m, x)		(((u32)(x) << __builtin_ctz(m)) & (m))

enum qq_kind { QQ_ING_TPID1, QQ_EGR_TPID1, QQ_EVC1, QQ_ESP, QQ_EP, QQ_PT, QQ_ING_CFG, QQ_EGR_CFG };

struct qq_op {
	enum qq_kind kind;
	const char *name;
	u32 addr;
	bool mem;
	int words;
	int idx;
	u32 old[3];
	u32 val[3];
};

static struct qq_op qq_ops[QQ_NOPS_TRUNK2];
/* step trunk2 written: ge3 is a provider port too, as ge2 */
static bool qq_trunk2;
static int qq_nops;
/* double-tagging writes done and read back: visible to debugfs */
static unsigned long bcm5331x_qinq_writes;

static int qq_read(struct bcm53314 *sw, const char *name, u32 addr, bool mem, int words,
		   int idx, u32 *w)
{
	memset(w, 0, 3 * sizeof(*w));
	return schan_xfer(sw, false, mem, addr, words, w, name, idx);
}

static int qq_read_obj(struct bcm53314 *sw, int obj, int idx, u32 *w)
{
	return sw_read(sw, obj, idx, w);
}

static int qq_add(enum qq_kind kind, const char *name, u32 addr, bool mem, int words,
		  int idx, const u32 *old, const u32 *val)
{
	struct qq_op *op;

	if (qq_nops >= (qq_trunk2 ? QQ_NOPS_TRUNK2 : QQ_NOPS))
		return -ENOSPC;
	op = &qq_ops[qq_nops++];
	memset(op, 0, sizeof(*op));
	op->kind = kind;
	op->name = name;
	op->addr = addr;
	op->mem = mem;
	op->words = words;
	op->idx = idx;
	memcpy(op->old, old, 4 * words);
	memcpy(op->val, val, 4 * words);
	return 0;
}

/* a port whose CPU-link settings double tagging changes: ge2, and ge3 under step trunk2 */
static bool qq_cpu_idx(int idx)
{
	return idx == BCM5331X_CPU_PORT || (qq_trunk2 && idx == PORT_TRUNK2);
}

/* The one change each write may make (checked on the whole plan first) */
static bool qq_op_ok(const struct qq_op *op)
{
	const u32 *a = op->old, *n = op->val;

	switch (op->kind) {
	case QQ_ING_TPID1:
		return op->addr == QQ_A_ING_OUTER_TPID_1 && !(a[0] >> 16) && n[0] == QQ_TPID;
	case QQ_EGR_TPID1:
		return op->addr == QQ_A_EGR_OUTER_TPID_1 && !(a[0] >> 16) && n[0] == QQ_TPID;
	case QQ_EVC1:
		return qq_cpu_idx(op->idx) &&
		       op->addr == obj_addr(&objs[O_EGR_VLAN_CONTROL_1], op->idx) &&
		       !(a[0] & (QQ_EVC_TPID_SEL | QQ_EVC_TPID_INDEX)) &&
		       n[0] == (a[0] | QQ_PUT(QQ_EVC_TPID_INDEX, 1));
	case QQ_ESP:
		return qq_cpu_idx(op->idx) &&
		       op->addr == (QQ_A_EGR_SRC_PORT | op->idx << 12) &&
		       !(a[0] & QQ_ESP_ADD_INNER) && !(a[0] & QQ_PUT(QQ_ESP_TPID_EN, QQ_SLOT1)) &&
		       n[0] == ((a[0] & ~QQ_ESP_TPID_EN) | QQ_PUT(QQ_ESP_TPID_EN, QQ_SLOT1));
	case QQ_EP:
		return qq_cpu_idx(op->idx) &&
		       op->addr == obj_addr(&objs[O_EGR_PORT], op->idx) &&
		       !(a[0] & (QQ_EP_HIGIG | QQ_EP_NNI)) && n[0] == (a[0] | QQ_EP_NNI);
	case QQ_PT:
		return qq_cpu_idx(op->idx) &&
		       op->addr == obj_addr(&objs[O_PORT_TAB], op->idx) &&
		       a[0] == n[0] && a[2] == n[2] &&
		       !(a[1] & QQ_PT1_NNI) && QQ_GET(QQ_PT1_TPID_EN, a[1]) == QQ_SLOT0 &&
		       n[1] == ((a[1] & ~QQ_PT1_TPID_EN) | QQ_PT1_NNI |
				QQ_PUT(QQ_PT1_TPID_EN, QQ_SLOT1));
	case QQ_ING_CFG:
		return op->addr == obj_addr(&objs[O_ING_CONFIG], 0) &&
		       !(a[0] & QQ_DT_MODE) && n[0] == (a[0] | QQ_DT_MODE);
	case QQ_EGR_CFG:
		return op->addr == obj_addr(&objs[O_EGR_CONFIG], 0) &&
		       !(a[0] & QQ_DT_MODE) && n[0] == (a[0] | QQ_DT_MODE);
	}
	return false;
}

/*
 * Build the plan from what is read now (slot 1 entries, then the CPU link:
 * selection, source enable, egress NNI, ingress NNI and slot; double
 * tagging last); any unexpected state refuses it, nothing written.
 */
static int bcm5331x_qinq_plan(struct bcm53314 *sw, struct device *dev)
{
	static const u32 tpid[3] = { QQ_TPID };
	u32 w[3], v[3], ing[3], egr[3];
	const char *why = NULL;
	int p, bad = -1, err;

	qq_nops = 0;
	err = qq_read_obj(sw, O_ING_CONFIG, 0, ing);
	if (!err)
		err = qq_read_obj(sw, O_EGR_CONFIG, 0, egr);
	if (!err)
		err = qq_read_obj(sw, O_VLAN_CTRL, 0, w);
	if (err)
		return err;
	if ((ing[0] & QQ_DT_MODE) || (egr[0] & QQ_DT_MODE))
		why = "double tagging already on";
	else if (((egr[0] >> 14) & 0xffff) != ETH_P_8021Q || ((w[0] >> 13) & 0xffff) != ETH_P_8021Q)
		why = "inner TPID not 0x8100";
	err = qq_read_obj(sw, O_ING_OUTER_TPID_0, 0, w);
	if (!err)
		err = qq_read_obj(sw, O_EGR_OUTER_TPID_0, 0, v);
	if (err)
		return err;
	if (!why && (w[0] != ETH_P_8021Q || v[0] != ETH_P_8021Q))
		why = "outer TPID slot 0 not 0x8100";

	/* slot 1 (0x88a8): referenced by no port, checked below */
	err = qq_read(sw, "ING_OUTER_TPID_1", QQ_A_ING_OUTER_TPID_1, false, 1, 0, w);
	if (!err)
		err = qq_add(QQ_ING_TPID1, "ING_OUTER_TPID_1", QQ_A_ING_OUTER_TPID_1, false, 1, 0, w, tpid);
	if (!err)
		err = qq_read(sw, "EGR_OUTER_TPID_1", QQ_A_EGR_OUTER_TPID_1, false, 1, 0, w);
	if (!err)
		err = qq_add(QQ_EGR_TPID1, "EGR_OUTER_TPID_1", QQ_A_EGR_OUTER_TPID_1, false, 1, 0, w, tpid);
	if (err)
		return err;

	/* every GE port: UNI, not HiGig, no translation, no inner tag add/remove, slot 1 unused */
	for (p = 1; !why && p < NUM_PORTS; p++) {
		u32 pt[3], ev[3], es[3], ep[3];

		err = qq_read_obj(sw, O_PORT_TAB, p, pt);
		if (!err)
			err = qq_read_obj(sw, O_EGR_VLAN_CONTROL_1, p, ev);
		if (!err)
			err = qq_read(sw, "EGR_SRC_PORT", QQ_A_EGR_SRC_PORT | p << 12, false, 1, p, es);
		if (!err)
			err = qq_read_obj(sw, O_EGR_PORT, p, ep);
		if (err)
			return err;
		if ((pt[1] & (QQ_PT1_NNI | QQ_PT1_VT_ENABLE)) ||
		    (QQ_GET(QQ_PT1_TPID_EN, pt[1]) & QQ_SLOT1))
			why = "PORT_TAB: NNI, translation or outer TPID slot 1";
		else if (ev[0] & (QQ_EVC_VT_ENABLE | QQ_EVC_TPID_SEL | QQ_EVC_TPID_INDEX | QQ_EVC_REMOVE_INNER))
			why = "EGR_VLAN_CONTROL_1: translation, TPID selection or inner tag removal";
		else if ((es[0] & QQ_ESP_ADD_INNER) || (QQ_GET(QQ_ESP_TPID_EN, es[0]) & QQ_SLOT1))
			why = "EGR_SRC_PORT: inner tag added or outer TPID slot 1";
		else if (ep[0] & (QQ_EP_HIGIG | QQ_EP_NNI))
			why = "EGR_PORT: HiGig or NNI";
		else if (qq_cpu_idx(p) && QQ_GET(QQ_PT1_TPID_EN, pt[1]) != QQ_SLOT0)
			why = "PORT_TAB of the CPU link: outer TPID slots not {0}";
		if (why) {
			bad = p;
			break;
		}
		if (!qq_cpu_idx(p))
			continue;
		memcpy(v, ev, sizeof(v));
		v[0] |= QQ_PUT(QQ_EVC_TPID_INDEX, 1);
		err = qq_add(QQ_EVC1, objs[O_EGR_VLAN_CONTROL_1].name,
			     obj_addr(&objs[O_EGR_VLAN_CONTROL_1], p), false, 1, p, ev, v);
		memcpy(v, es, sizeof(v));
		v[0] = (v[0] & ~QQ_ESP_TPID_EN) | QQ_PUT(QQ_ESP_TPID_EN, QQ_SLOT1);
		if (!err)
			err = qq_add(QQ_ESP, "EGR_SRC_PORT", QQ_A_EGR_SRC_PORT | p << 12, false, 1, p, es, v);
		memcpy(v, ep, sizeof(v));
		v[0] |= QQ_EP_NNI;
		if (!err)
			err = qq_add(QQ_EP, objs[O_EGR_PORT].name, obj_addr(&objs[O_EGR_PORT], p),
				     false, 1, p, ep, v);
		memcpy(v, pt, sizeof(v));
		v[1] = (v[1] & ~QQ_PT1_TPID_EN) | QQ_PT1_NNI | QQ_PUT(QQ_PT1_TPID_EN, QQ_SLOT1);
		if (!err)
			err = qq_add(QQ_PT, objs[O_PORT_TAB].name, obj_addr(&objs[O_PORT_TAB], p),
				     true, objs[O_PORT_TAB].words, p, pt, v);
		if (err)
			return err;
	}
	if (why) {
		if (bad >= 0)
			dev_err(dev, "Q-in-Q: port %d: %s\n", bad, why);
		else
			dev_err(dev, "Q-in-Q: %s\n", why);
		dev_err(dev, "Q-in-Q: state not as the base mode leaves it: nothing written\n");
		return -EINVAL;
	}

	memcpy(v, ing, sizeof(v));
	v[0] |= QQ_DT_MODE;
	err = qq_add(QQ_ING_CFG, objs[O_ING_CONFIG].name, obj_addr(&objs[O_ING_CONFIG], 0),
		     false, 1, 0, ing, v);
	memcpy(v, egr, sizeof(v));
	v[0] |= QQ_DT_MODE;
	if (!err)
		err = qq_add(QQ_EGR_CFG, objs[O_EGR_CONFIG].name, obj_addr(&objs[O_EGR_CONFIG], 0),
			     false, 1, 0, egr, v);
	return err;
}

/*
 * qinq=Y: put the switch in double-tagging mode before DSA registers. Run
 * after the base module's steps (plan fully written), under its lock and
 * its write rules (access=2, no dry run, not halted). Returns 0 with
 * qinq_on set, or an error with nothing written (refusal) or with the
 * base module halted (a write that did not read back).
 */
static int bcm5331x_dsa_qinq(struct bcm53314 *sw, struct device *dev)
{
	int i, err;

	qq_trunk2 = false;
	qinq_on = false;
	if (!qinq)
		return 0;
	if (dry_run || access != 2) {
		dev_err(dev, "Q-in-Q: needs access=2 without dry run (access %d, dry_run %d): refusing\n",
			access, dry_run);
		return -EPERM;
	}
	/*
	 * ge3 alone (no trunk group): refused; ge3 with trunk2: both CPU links.
	 * MGMT (step mgmt, mgmt=Y) stays a customer port like a front port, in
	 * VID 20: no write of its own here (PORT_TAB/EGR_PORT of MGMT are read
	 * and checked as every port's below). MGMT without mgmt=Y is refused.
	 */
	if (!sw->ports || sw->ge3 != sw->trunk2 || (sw->mgmt && !dsa_mgmt) ||
	    bcm5331x_plan_remaining(sw) != 0) {
		dev_err(dev, "Q-in-Q: needs step ports fully written, mgmt only with mgmt=1, ge3 only with trunk2: refusing\n");
		return -EINVAL;
	}
	qq_trunk2 = sw->trunk2;
	mutex_lock(&sw->lock);
	if (sw->halted) {
		err = -EIO;
		goto out;
	}
	err = bcm5331x_qinq_plan(sw, dev);
	if (err)
		goto out;
	for (i = 0; i < qq_nops; i++)
		if (!qq_op_ok(&qq_ops[i])) {
			dev_err(dev, "Q-in-Q: write %d/%d %s[%d] refused: nothing written\n",
				i + 1, qq_nops, qq_ops[i].name, qq_ops[i].idx);
			err = -EPERM;
			goto out;
		}
	if (qq_nops != (qq_trunk2 ? QQ_NOPS_TRUNK2 : QQ_NOPS)) {
		err = -EINVAL;
		goto out;
	}
	for (i = 0; i < qq_nops; i++) {
		struct qq_op *op = &qq_ops[i];

		dev_info(dev, "Q-in-Q %d/%d %s[%d] addr 0x%08x: %08x %08x %08x -> %08x %08x %08x\n",
			 i + 1, qq_nops, op->name, op->idx, op->addr, op->old[0], op->old[1],
			 op->old[2], op->val[0], op->val[1], op->val[2]);
	}
	for (i = 0; i < qq_nops; i++) {
		struct qq_op *op = &qq_ops[i];
		u32 cur[3], rb[3];

		err = qq_read(sw, op->name, op->addr, op->mem, op->words, op->idx, cur);
		if (err)
			goto out;
		if (memcmp(cur, op->old, 4 * op->words)) {
			sw_fault(sw, "dsa: Q-in-Q %s[%d] is %08x, expected %08x", op->name, op->idx,
				 cur[0], op->old[0]);
			err = -ESTALE;
			goto out;
		}
		memcpy(rb, op->val, sizeof(rb));
		err = schan_xfer(sw, true, op->mem, op->addr, op->words, rb, op->name, op->idx);
		if (err)
			goto out;
		udelay(10);
		err = qq_read(sw, op->name, op->addr, op->mem, op->words, op->idx, rb);
		if (err)
			goto out;
		bcm5331x_qinq_writes++;
		if (memcmp(rb, op->val, 4 * op->words)) {
			sw_fault(sw, "dsa: Q-in-Q %s[%d] read back %08x %08x, wrote %08x %08x",
				 op->name, op->idx, rb[0], rb[1], op->val[0], op->val[1]);
			err = -EIO;
			goto out;
		}
	}
	qinq_on = true;
	dev_info(dev, "Q-in-Q: double tagging on, outer TPID 0x%04x on the CPU link (%d writes, read back)\n",
		 QQ_TPID, qq_nops);
out:
	mutex_unlock(&sw->lock);
	return err;
}

/*
 * MGMT PHY (MIIM 0x86) at the set-up of the MGMT user port: one MII control
 * write 0x0140 -> 0x1340, read back (0x1140 expected, the restart bit
 * clearing itself), the same transition as the step "mgmt";
 * nothing written if auto-negotiation is already on or if the register
 * holds any other value (power-down, isolate, loopback, other speed: left
 * as found, warned, the port registers without link); none with
 * mgmt_an=0, below access=2, with dry_run or once halted. A failed MIIM
 * transaction or read-back halts the base module and refuses the
 * registration, as for the CPU link PHY. Not undone at unload.
 */
static int bcm5331x_dsa_mgmt_an(struct bcm53314 *sw, struct device *dev)
{
	u16 val = BMCR_AUTONEG_RESTART, bmcr, rb;
	int err;

	if (!mgmt_an) {
		dev_info(dev, "mgmt_an=0: MGMT PHY left as found\n");
		return 0;
	}
	if (access != 2 || dry_run) {
		dev_info(dev, "MGMT PHY left as found (access %d, dry_run %d)\n",
			 access, dry_run);
		return 0;
	}
	mutex_lock(&sw->lock);
	if (sw->halted) {
		err = -EIO;
		goto out;
	}
	err = miim_op(sw, false, BCM5331X_MGMT_PHY, MII_BMCR, &bmcr);
	if (err)
		goto out;
	if (bmcr & BMCR_ANENABLE) {
		dev_info(dev, "MGMT PHY: MII control 0x%04x, auto-negotiation already on, nothing written\n",
			 bmcr);
		goto out;
	}
	if (bmcr != BMCR_FORCED_1000) {
		dev_warn(dev, "MGMT PHY: MII control 0x%04x, not 0x%04x: left as found\n",
			 bmcr, BMCR_FORCED_1000);
		goto out;
	}
	err = miim_op(sw, true, BCM5331X_MGMT_PHY, MII_BMCR, &val);
	if (err)
		goto out;
	bcm5331x_mgmt_an_writes++;
	err = miim_op(sw, false, BCM5331X_MGMT_PHY, MII_BMCR, &rb);
	if (err)
		goto out;
	if ((rb & ~BMCR_ANRESTART) != (BMCR_AUTONEG_RESTART & ~BMCR_ANRESTART)) {
		sw_fault(sw, "dsa: MGMT PHY MII control reads 0x%04x after 0x%04x",
			 rb, BMCR_AUTONEG_RESTART);
		err = -EIO;
		goto out;
	}
	dev_info(dev, "MGMT PHY: MII control 0x%04x -> 0x%04x, read back 0x%04x (auto-negotiation)\n",
		 bmcr, BMCR_AUTONEG_RESTART, rb);
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(dev, "MGMT PHY auto-negotiation failed (%d): refusing to register\n",
			err);
	return err;
}

/* set-up of a port (dsa_port_devlink_setup): the CPU port and the MGMT user port only */
static int bcm5331x_dsa_port_setup(struct dsa_switch *ds, int port)
{
	if (port == PORT_MGMT && bcm5331x_has_mgmt(ds->priv) && dsa_is_user_port(ds, port))
		return bcm5331x_dsa_mgmt_an(ds->priv, ds->dev);
	if (port != BCM5331X_CPU_PORT || !dsa_is_cpu_port(ds, port))
		return 0;
	return bcm5331x_dsa_cpu_an(ds->priv, ds->dev);
}

/* ---------------------------------------------------------------------- */
/* Hardware bridging (hwbridge=Y)                                          */

/*
 * A Linux bridge over front ports is, by default, a software bridge: each
 * port keeps its own VLAN {port, ge2}, every frame goes through the host.
 * With hwbridge=Y a VLAN-unaware bridge (the mode is fixed when its first
 * port joins, see port_bridge_join) is offloaded: its ports share one
 * bridge VLAN (VID 141-148, one per DSA bridge number, BCM5331X_BR_VID),
 * in which the switch learns and forwards between them on its own; ge2
 * (and ge3 under trunk2) is a tagged member, as in the port VLANs.
 *
 * A port is a member of the bridge VLAN exactly while its STP state is
 * forwarding; in any other state it is back in its own VLAN, as a
 * standalone port. There is therefore no per-port spanning-tree state in
 * the switch (STG_TAB/EGR_VLAN_STG keep group 1 forwarding everywhere): a
 * port blocked in STG_TAB would also drop the BPDUs it receives and the
 * frames the host sends through it, since the host reaches the switch by
 * an Ethernet port (ge2), not by the CMIC. A blocked port is isolated
 * instead: its frames reach the host with the port VID (exact source port,
 * BPDUs included) and the switch forwards nothing between it and the
 * others.
 *
 * Writes of one membership change, planned on what is read, checked
 * against fixed rules (hw_op_ok) before the first one, each re-read before,
 * written and read back (a mismatch halts the base module):
 *  - joining (state -> forwarding): L2_USER_ENTRY of the bridge, first
 *    member only; EGR_VLAN[bridge VID] then VLAN_TAB[bridge VID] with the
 *    port added (untagged); PORT_TAB[port].PORT_VID = bridge VID;
 *  - leaving: the same in reverse order (PORT_VID back to the port VID,
 *    port removed from VLAN_TAB then EGR_VLAN, entries cleared to zero
 *    with the last member, L2_USER_ENTRY cleared last).
 * L2_USER_ENTRY (IPIPE 0x06740000 + index, 64 x 156 bits; OpenMDK
 * bcm53314_a0_defs.h, layout of OpenBCM l2cache.c _bcm_l2_cache_to_l2u):
 * entry 55 + bridge number holds key {VID = bridge VID, DA = 01:80:c2:00:
 * 00:00}, mask {VID, DA/44}, BPDU and DST_DISCARD set, CPU, MIRROR,
 * PORT_TGID and MODULE_ID zero (word 4 = 0x04004000, the form of the boot
 * firmware entries below): the link-local frames (STP, LACP, 802.1X, LLDP:
 * 01:80:c2:00:00:0x) of the bridge VLAN are dropped, so never forwarded
 * to the other members, as the Linux bridge does not forward them (it
 * forwards STP only with STP off and no bpdu_filter).
 * The entry cannot send them to ge2 only: for a multicast DA the hardware
 * reads MODULE_ID:PORT_TGID as an L2MC index, not as a port (OpenBCM
 * l2cache.c _bcm_l2_cache_to_l2u and _bcm_l2u_to_l2_cache: "If MACDA is
 * MC, HW interprets value encoded in MODULE_IDf and PORT_FIELD as
 * L2MC_INDEX"). PORT_TGID 3 (ge2), as first written, pointed to L2MC[3],
 * not written by this driver: in practice the BPDUs of
 * port1 still left by port2. L2MC is outside the written tables, CPU
 * targets the CMIC (not the host, reached through ge2), hence the drop.
 * Consequences: the host does not receive the link-local frames of a
 * member while it forwards in hardware (STP over an offloaded bridge is
 * not supported: to be run with STP off or bpdu_filter;
 * LACP/LLDP on a member are lost, :01, :02 and :0e being dropped anyway
 * by the boot firmware entries), unless they are classified on the port
 * VID by protocol: lagf=2 for LACP, llproto for STP, LLDP and EAPOL (see
 * "Link-local protocols at the exact port"). Only frames classified in a bridge VLAN
 * are matched (VID compared): a member (PORT_VID = bridge VID) or a frame
 * of the host tagged with the bridge VID (tx_fwd_offload; the bridge
 * sends its own link-local frames on the port VID). Standalone ports and
 * software bridges (port VID 100+N) keep their link-local frames to the
 * host. A mask without the VID would drop those too (the host's STP on a
 * software bridge, LLDP of standalone ports), hence one entry per bridge.
 * Before the first entry is written the whole table is read once
 * (and, at load, logged: every non-zero entry, 5 words; reads only).
 * Entries 56-63 must be zero. The table is matched from its lowest index
 * (OpenBCM l2cache.c bcm_esw_l2_cache_set: "matched from lowest entry to
 * highest entry"; l2u.c: index 0 = high priority end), so an entry below
 * 56 is matched before ours. Such entries belong to the boot firmware: a
 * network load leaves 0-2 valid, keys 01:80:c2:00:00:01, :02 and :0e
 * (full MAC mask), VLAN_ID 1, BPDU and DST_DISCARD set, CPU clear
 * (read back on the board), VLAN_ID out of the mask, i.e. every
 * VLAN (word 4 0x04004000, as ours). They are never
 * written by the bridge offload (entry 1 alone may be cleared by
 * lagf=2, see "Hardware LAG of front ports"). One is accepted when it
 * only drops what it matches (DST_DISCARD set, CPU and MIRROR clear) or
 * when its key cannot match a frame of a bridge VLAN (keys differ on a
 * bit both masks compare): a link-local frame of a member is then
 * dropped, by our entry or by that one, never sent to another port. Any
 * other valid entry, or a non-zero entry at 56-63, refuses hardware
 * bridging.
 *
 * Without fdb=Y neither the address table (L2X) nor the ageing is written:
 * the switch learns by itself in the bridge VLAN (independent VLAN
 * learning, step "learning"); an address learnt on a port that left the
 * bridge VLAN is dropped by the egress VLAN check until it is learnt again
 * or ages out (port_fast_age empty, port_fdb_* absent). With fdb=Y: see
 * "Address table of offloaded bridges".
 */
#define HW_BR_FIRST_VID		BCM5331X_BR_VID_FIRST
#define HW_L2U_ADDR		0x06740000	/* IPIPE L2_USER_ENTRY, + index */
#define HW_L2U_NUM		64
#define HW_L2U_WORDS		5
#define HW_L2U_IDX(num)		(HW_L2U_NUM - BCM5331X_BR_MAX + (num) - 1)	/* 56-63 */
#define HW_L2U_W4_CPU		BIT(138 - 128)	/* L2_USER_ENTRY word 4: CPU */
#define HW_L2U_W4_MIRROR	BIT(141 - 128)	/* MIRROR */
#define HW_L2U_W4_DISCARD	BIT(142 - 128)	/* DST_DISCARD */
#define HW_L2U_W4_BPDU		BIT(154 - 128)	/* BPDU */
#define HW_PT_VID		GENMASK(30, 19)	/* PORT_TAB word 0 */
#define HW_PT_CMLF		GENMASK(7, 5)	/* PORT_TAB word 0: CML (fdb=Y, port learning) */
#define HW_NOPS			32	/* bridge: 7 at most, + learning (fdb); slow-protocol VLAN (lagf=2): 25 */

enum hw_kind { HW_L2U, HW_EGR_VLAN, HW_VLAN_TAB, HW_PORT_TAB,
	       /* VLAN-aware bridging (vlanbr=Y) */
	       HW_VL_L2U, HW_VL_EGR_VLAN, HW_VL_VLAN_TAB, HW_VL_PORT_TAB, HW_VL_EGR_PORT,
	       /* 802.1ad VLAN-aware bridging (vlanbr_ad=Y) */
	       HW_VL_ESP, HW_VL_EVC1,
	       /* ingress time stamping through ge2 (ptp=3) */
	       HW_TS_EP, HW_TS_DA,
	       /* learning of the ports of offloaded bridges (fdb=Y) */
	       HW_PT_CML,
	       /* hardware LAG of front ports (lagf=1|2) */
	       HW_TRUNK_GROUP, HW_TRUNK_BITMAP, HW_STM, HW_VPROT, HW_VPROT_DATA, HW_L2U_BIOS,
	       /* multicast groups of offloaded bridges (mdb=Y) */
	       HW_L2MC, HW_IGMP, HW_VPROF };

struct hw_op {
	enum hw_kind kind;
	const char *name;
	u32 addr;
	bool mem;
	int words;
	int idx;
	u32 parity0;		/* bit of word 0 kept by the hardware (L2MC, mdb) */
	u32 parity1;		/* bit of word 1 kept by the hardware */
	u32 old[HW_L2U_WORDS];
	u32 val[HW_L2U_WORDS];
};

/* bridge modes */
enum { HW_BR_NONE, HW_BR_HW, HW_BR_SOFT, HW_BR_VLAN };

static bool hwbridge;
static u8 hw_br_mode[BCM5331X_BR_MAX + 1];	/* per bridge number */
static int hw_br_users[BCM5331X_BR_MAX + 1];	/* ports joined (any mode) */
static u32 hw_br_fwd[BCM5331X_BR_MAX + 1];	/* members forwarding in hardware */
static u8 hw_port_br[NUM_PORTS];		/* bridge number of a port in hardware mode */
static bool hw_l2u_checked;			/* whole L2_USER_ENTRY read, found usable */
/* VLAN-aware bridging: L2_USER_ENTRY 40-55, one per user VLAN slot; entries 0-39 as read */
#define VL_L2U_FIRST		40
static u32 hw_l2u_low[VL_L2U_FIRST][HW_L2U_WORDS];
static bool vlanbr;
/* fdb=Y extensions: address table and learning of the VLAN-aware bridge, ageing time */
static bool fdbvlan, ageing;
static void fdb_vl_purge(struct dsa_switch *ds, int i);
static struct hw_op hw_ops[HW_NOPS];
static int hw_nops;
/* bridge writes done and read back, refusals: visible to debugfs */
static unsigned long bcm5331x_hw_writes, bcm5331x_hw_refusals;

module_param(hwbridge, bool, 0444);
MODULE_PARM_DESC(hwbridge, "Offload VLAN-unaware bridges of front ports to the switch: shared bridge VLAN (VID 141-148), membership by STP state, link-local frames of the bridge VLAN dropped (switch writes at run time, read back; default N = software bridge, no write)");

/*
 * Hardware LAG of front ports (module parameter lagf; needs
 * hwbridge). Default 0: a bond of front ports stays a software LAG
 * (-EOPNOTSUPP, DSA falls back), nothing is written.
 *
 * lagf=1: port_lag_join of a front port is accepted for a hash LAG
 * (balance-xor, 802.3ad), without any write: while the LAG is not in an
 * offloaded bridge its ports keep their own VLAN, the host bonds them as
 * it would bond a software LAG (exact port of every frame both ways). The
 * switch only needs a trunk group once the LAG forwards in a bridge VLAN:
 * the members then share the bridge VID, the switch must learn the far end
 * on the group (not on one member), must not send a frame of a member back
 * to another member, and must send a flooded frame to the LAG only once.
 * Trunk group t = DSA LAG id - 1 (0-6; 7 is the CPU group of step trunk2)
 * holds the members forwarding in the bridge VLAN, written with them (the
 * bridge writes, port_stp_state_set):
 *   SOURCE_TRUNK_MAP_TABLE[p] = trunk member of group t (learning on the
 *     group), TRUNK_BITMAP[t] = members (the source group is never a
 *     destination of its own frames),
 *   TRUNK_GROUP[t] = one member, the "egress member", in all eight slots,
 *   EGR_VLAN of the bridge VID: of the LAG, the egress member only.
 * Only one member leaves the switch towards the far end: a unicast frame
 * learnt on the group goes to the egress member (TRUNK_GROUP), a flooded
 * one reaches the other members in the ingress membership (VLAN_TAB) but
 * they are out of the egress membership (EGR_VLAN). The flood block masks
 * (NONUCAST_TRUNK_BLOCK_MASK, indexed by a hash of addresses and source
 * port: OpenBCM firebolt/trunk.c _bcm_xgs3_trunk_block_mask, switch.c
 * BCM_HASH_CONTROL_TRUNK_NUC_*) are not written: they would apply as well
 * to the frames the host sends to one member on its own VLAN (LACPDUs: the
 * same addresses for every member, one fixed hash), which must leave by
 * that member; spreading over the members would need them. The egress
 * member is the first member whose DSA lag_tx_enabled is set (link up and,
 * under 802.3ad, distributing), else the first member; port_lag_change
 * moves it (EGR_VLAN swap, then TRUNK_GROUP). Frames from the far end may
 * arrive on any member (they go to the host by the bridge VID, delivered to
 * a designated port that is not a LAG member, or a LAG member allowed to
 * transmit: see hw_tagger_update).
 *
 * lagf=2: as 1, plus the slow protocols (ethertype 0x8809: LACP, marker)
 * of every port classified on the port's own VID, whatever its PORT_VID:
 * a LACPDU of a member forwarding in a bridge VLAN would otherwise be
 * dropped by the bridge's L2_USER_ENTRY (link-local frames of the bridge
 * VLAN) or reach the host on the designated port. VLAN_PROTOCOL[15] =
 * {ETHERTYPE 0x8809, ETHERII, MATCHUPPER, MATCHLOWER} and, for each port p
 * 1-24, VLAN_PROTOCOL_DATA[16 p + 15].VLAN_ID = port VID (100+N of a front
 * port, PORT_VID read for the others; none if 0): OpenBCM firebolt/port.c
 * _bcm_fb_port_protocol_vlan_add (every port uses its data entry once the
 * protocol entry is valid). Written at the first front-port LAG join (data
 * first, protocol entry last), undone at the last leave (protocol entry
 * first). The LACPDU then floods in the port VLAN {port, ge2[, ge3]} to the
 * host, which needs no L2_USER_ENTRY of its own.
 *
 * The boot firmware leaves L2_USER_ENTRY[1] for 01:80:c2:00:00:02 (full
 * MAC mask, VLAN_ID 1 out of the mask: every VLAN; BPDU and DST_DISCARD,
 * word 4 0x04004000), after a network load and, step "init" not clearing
 * it, after a start from the disk as well: matched
 * before any other lookup, it drops every LACPDU. With lagf=2
 * that one entry, if it holds exactly this form, is cleared to zero (the
 * deletion of OpenBCM soc_l2u_delete) right after the slow-protocol VLAN
 * is written, its five words read before, logged and kept; it is written
 * back first when the slow-protocol VLAN is undone (last front-port LAG
 * leave, whatever the result of the rest of the removal) and at the
 * removal of the driver if still cleared, then read back. Entries 0 and 2
 * (:01, :0e) and any other entry are never written; an entry 1 of another
 * form is left as found. Re-aiming the entry instead was not kept: its
 * CPU bit targets the CMIC, not the host (reached through ge2), and for a
 * multicast DA PORT_TGID is an L2MC index (see the bridge offload above),
 * so it can only drop or let the frame through. A valid entry that still
 * catches the LACPDUs of a port VLAN is reported at the join (LACP then
 * cannot work, a static LAG can). A halted switch accepts no further
 * access: a cleared entry is then given back by the next reset of the
 * switch by the boot firmware (every write here is volatile).
 *
 * Every write is checked against the state the driver left, against the
 * rules (hw_op_ok) and read back, as the bridge writes.
 */
static int lagf;
#define LAGF_TGIDS		7	/* trunk groups 0-6 (7: CPU group of step trunk2) */
#define LAGF_MAX_PORTS		8
#define LAGF_RTAG		3	/* source and destination MAC (one port in the group: no choice) */
#define LAGF_STM(t)		(1 | (t) << 2)	/* PORT_TYPE 1 (trunk member), TGID */
#define LAGF_SLOW_ETYPE		0x8809
#define LAGF_VP_IDX		15	/* VLAN_PROTOCOL entry of the slow protocols */
#define LAGF_VP_VAL		(LAGF_SLOW_ETYPE | BIT(18) | BIT(19) | BIT(20))	/* ETHERII, MATCHLOWER, MATCHUPPER */

static u32 lg_ports[LAGF_TGIDS];	/* front ports of the LAG of group t (join accepted) */
static u32 lg_trunk[LAGF_TGIDS];	/* members in hardware group t (forwarding in a bridge VLAN) */
static u8 lg_des[LAGF_TGIDS];		/* egress member of group t in hardware, 0 = group empty */
#define LAGF_L2U_BIOS		1	/* L2_USER_ENTRY of the boot firmware for the LACPDUs */
static unsigned long bcm5331x_lagf_joins;
static unsigned long bcm5331x_lagf_vlanbr_refusals;	/* lagf LAG member refused in a VLAN-aware bridge (vlanbr) */

module_param(lagf, int, 0444);
MODULE_PARM_DESC(lagf, "Hardware LAG of front ports in an offloaded bridge (needs hwbridge): 1 = trunk group, one egress member; 2 = 1 + slow protocols (LACP) on the port VID, boot firmware L2_USER_ENTRY[1] for the LACPDUs cleared while in use (switch writes at run time, read back; default 0 = software LAG, no write)");

/*
 * Link-local protocols at the exact port (module parameter llproto;
 * needs hwbridge). Default 0: nothing read or written, a
 * link-local frame of a member forwarding in a bridge VLAN is dropped by
 * the bridge's L2_USER_ENTRY (see "Hardware bridging"), so STP of an
 * offloaded bridge needs bpdu_filter or STP off.
 *
 * llproto is a mask: bit 0 STP (BPDUs, LLC 0x42/0x42), bit 1 LLDP
 * (ethertype 0x88cc), bit 2 EAPOL (0x888e). Each protocol asked is
 * classified on the port's own VID, whatever its PORT_VID, exactly as the
 * slow protocols under lagf=2: one VLAN_PROTOCOL entry and, for each port
 * p 1-24, VLAN_PROTOCOL_DATA[16 p + entry].VLAN_ID = port VID (100+N of a
 * front port, PORT_VID read for the others, MGMT 20 under mgmt=1; none if
 * 0). The frame then floods in the port VLAN {port, ge2[, ge3]} to the
 * host, out of the key of the bridge entries: the bridge sees the BPDU of
 * each member on that member (STP computes roles and blocks ports), lldpd
 * and hostapd see their frames on the exact port. Written at the first
 * join of a front port to an offloaded bridge (VLAN-unaware, or the
 * VLAN-aware bridge of vlanbr), undone at the last leave; a refusal
 * leaves that bridge to software bridging (each port in its own VLAN,
 * nothing lost). Sending is unchanged (the host sends on the port VID).
 *
 * VLAN_PROTOCOL entries of this driver, one table for every feature
 * (vp_defs): 15 slow protocols (lagf=2), 14 STP, 13 LLDP, 12 EAPOL.
 * Entries 0-11 must be empty, entries 12-15 empty or as the driver left
 * them (a feature turned off leaves its entry empty), checked before
 * every change; data first, entry last, removed in the reverse order.
 * STP entry {ETHERTYPE 0x4242, LLC, MATCHLOWER, MATCHUPPER}: the value of
 * ETHERTYPE for an LLC entry (DSAP/SSAP) is not documented (OpenBCM
 * firebolt/port.c _bcm_fb_port_protocol_vlan_add only sets the LLC bit):
 * an assumption, to be judged on the board.
 *
 * LLDP: the boot firmware entry L2_USER_ENTRY[2] (01:80:c2:00:00:0e, every
 * VLAN, dropped; after a network load and after step "init" as well)
 * matches first and drops every LLDPDU: with llproto bit 1, that entry is
 * cleared and given back as entry 1 is under lagf=2 (see
 * hw_bios_l2u). Every other L2_USER_ENTRY that still catches the
 * protocol's address in a port VLAN is reported ("cannot work").
 * 802.1X: EAPOL reaches hostapd on the exact port, but the port cannot be
 * authorized by the switch (BR_PORT_LOCKED not supported): observation.
 */
#define LL_STP			BIT(0)
#define LL_LLDP			BIT(1)
#define LL_EAPOL		BIT(2)
#define LL_ALL			(LL_STP | LL_LLDP | LL_EAPOL)
#define LL_L2U_BIOS		2	/* L2_USER_ENTRY of the boot firmware for the LLDPDUs */
static int llproto;
static int ll_users;			/* front ports joined to an offloaded bridge */

module_param(llproto, int, 0444);
MODULE_PARM_DESC(llproto, "Link-local protocols of the front ports of offloaded bridges on the port VID (needs hwbridge), mask: 1 = STP, 2 = LLDP (boot firmware L2_USER_ENTRY[2] cleared while in use), 4 = EAPOL (switch writes at run time, read back; default 0 = dropped in the bridge VLAN, no write)");

#define VP_FIRST		12	/* entries 12-15 attributed, 0-11 always empty */
#define VP_NUM			4
#define VP_BIT(e)		BIT((e) - VP_FIRST)
#define VP_STP_IDX		14
#define VP_LLDP_IDX		13
#define VP_EAPOL_IDX		12
#define VP_ETHERII		BIT(18)
#define VP_LLC			BIT(16)
#define VP_MATCH		(BIT(19) | BIT(20))	/* MATCHLOWER, MATCHUPPER */
#define VP_VPD_ADDR		0x04710000	/* IPIPE VLAN_PROTOCOL_DATA, + 16 port + entry */
#define VP_VPD_IDX(p, e)	(16 * (p) + (e))
#define VP_VPD_VID		GENMASK(14, 3)	/* VLAN_ID 14:3, PRI 2:0 = 0 */
#define VP_VPD_FIRST		1	/* ports 1-24 */

static const struct vp_def {
	u32 val;		/* VLAN_PROTOCOL entry */
	u8 da;			/* last byte of the usual DA 01:80:c2:00:00:xx */
	int bios;		/* boot firmware L2_USER_ENTRY dropping it, -1 none */
	const char *who;	/* log prefix */
	const char *vname;	/* "<vname> VLAN" */
	const char *name;	/* "<name> on the port VIDs" */
	const char *what;	/* frames */
	const char *fail;	/* when still caught */
} vp_defs[VP_NUM] = {
	[VP_EAPOL_IDX - VP_FIRST] = { 0x888e | VP_ETHERII | VP_MATCH, 0x03, -1, "llproto", "EAPOL",
				      "EAPOL (0x888e)", "EAPOL frames", "802.1X cannot work" },
	[VP_LLDP_IDX - VP_FIRST] = { 0x88cc | VP_ETHERII | VP_MATCH, 0x0e, LL_L2U_BIOS, "llproto", "LLDP",
				     "LLDP (0x88cc)", "LLDPDUs", "LLDP cannot work" },
	[VP_STP_IDX - VP_FIRST] = { 0x4242 | VP_LLC | VP_MATCH, 0x00, -1, "llproto", "STP",
				    "STP (LLC 0x4242)", "BPDUs", "STP cannot work" },
	[LAGF_VP_IDX - VP_FIRST] = { LAGF_VP_VAL, 0x02, LAGF_L2U_BIOS, "LAG", "slow-protocol",
				     "slow protocols (0x8809)", "LACPDUs", "LACP cannot work, static LAGs only" },
};
static u8 vp_on;			/* VP_BIT(e): entry e and its data written by the driver */
static u8 vp_bios_back;			/* VP_BIT(e): entry e still on, its boot firmware entry given back (removal refused) */
static u16 vp_vid[VP_NUM][NUM_PORTS];	/* VLAN_PROTOCOL_DATA VID written per entry and port */

static bool vp_is_on(int e)
{
	return e >= VP_FIRST && e < VP_FIRST + VP_NUM && (vp_on & VP_BIT(e));
}

/* entries a feature in use may write: 15 under lagf=2, 12-14 by llproto */
static bool vp_allowed(int e)
{
	switch (e) {
	case LAGF_VP_IDX:
		return lagf == 2;
	case VP_STP_IDX:
		return llproto & LL_STP;
	case VP_LLDP_IDX:
		return llproto & LL_LLDP;
	case VP_EAPOL_IDX:
		return llproto & LL_EAPOL;
	}
	return false;
}

static int ll_set(struct dsa_switch *ds, bool on);
static void ll_leave(struct dsa_switch *ds);

/* group of a front port, -1 if none */
static int lg_of(int port)
{
	int t;

	if (port < 0 || port >= NUM_PORTS)
		return -1;
	for (t = 0; t < LAGF_TGIDS; t++)
		if (lg_ports[t] & BIT(port))
			return t;
	return -1;
}

static bool lg_tx(struct dsa_switch *ds, int port)
{
	return dsa_to_port(ds, port)->lag_tx_enabled;
}

/*
 * Egress member of a set: the current one @cur while it is in the set and
 * allowed to transmit (or no member is), else the first member allowed to
 * transmit, else the first member; 0 if the set is empty. Sticky: a member
 * joining or leaving does not move it without need.
 */
static int lg_pick(struct dsa_switch *ds, u32 set, int cur)
{
	int p, tx = 0;

	for (p = NUM_PORTS - 1; p >= 0; p--)
		if ((set & BIT(p)) && lg_tx(ds, p))
			tx = p;
	if (cur && (set & BIT(cur)) && (lg_tx(ds, cur) || !tx))
		return cur;
	if (tx)
		return tx;
	return set ? __builtin_ctz(set) : 0;
}

/* members out of the egress membership of the bridge VLANs: all but the egress member */
static u32 lg_hidden(void)
{
	u32 h = 0;
	int t;

	for (t = 0; t < LAGF_TGIDS; t++)
		if (lg_trunk[t])
			h |= lg_trunk[t] & ~BIT(lg_des[t]);
	return h;
}

/* TRUNK_GROUP: PORTi 10i+5:10i, MODULEi 10i+9:10i+6 (0), RTAG 82:80; @des in all slots, 0 = empty */
static void lg_group_build(u32 *w, int des)
{
	int i;

	w[0] = w[1] = w[2] = 0;
	if (!des)
		return;
	for (i = 0; i < 8; i++)
		ent_set(w, 10 * i, 6, des);
	ent_set(w, 80, 3, LAGF_RTAG);
}

/* egress member of a TRUNK_GROUP entry this driver writes: port, 0 = empty, -1 = other content */
static int lg_group_of(const u32 *w)
{
	u32 e[3];
	int p = ent_get(w, 0, 6);

	if (!w[0] && !w[1] && !w[2])
		return 0;
	if (!bcm5331x_is_front(p))
		return -1;
	lg_group_build(e, p);
	return memcmp(e, w, sizeof(e)) ? -1 : p;
}

/* CPU-side ports of every VLAN: ge2, and ge3 under step trunk2 */
static u32 hw_cpu_pbm(const struct bcm53314 *sw)
{
	return PBM_TRUNK | (sw->trunk2 ? PBM_TRUNK2 : 0);
}

/* front ports of DSA (MGMT excluded) */
static u32 hw_front_pbm(void)
{
	u32 m = 0;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++)
		m |= BIT(front_ports[i].port);
	return m;
}

/* the exact L2_USER_ENTRY of switch VLAN @vid (bit layout: see above) */
static void hw_l2u_build_vid(u32 *w, u16 vid)
{
	u64 mac = 0x0180c2000000ULL, mmask = 0xfffffffffff0ULL;
	u64 key_mask = mmask | (u64)0xfff << 48;	/* mask bits 0-59 = key bits 1-60 */

	memset(w, 0, 4 * HW_L2U_WORDS);
	ent_set(w, 0, 1, 1);				/* VALID */
	ent_set(w, 1, 32, (u32)mac);			/* MAC_ADDR 48:1 */
	ent_set(w, 33, 16, (u32)(mac >> 32));
	ent_set(w, 49, 12, vid);			/* VLAN_ID 60:49 */
	ent_set(w, 68, 32, (u32)key_mask);		/* MASK 127:68 */
	ent_set(w, 100, 28, (u32)(key_mask >> 32));
	w[4] = HW_L2U_W4_DISCARD | HW_L2U_W4_BPDU;	/* DST_DISCARD 142, BPDU 154; PORT_TGID,
							 * MODULE_ID 0 (an L2MC index for a multicast DA) */
}

/* the exact L2_USER_ENTRY of bridge @num */
static void hw_l2u_build(u32 *w, int num)
{
	hw_l2u_build_vid(w, BCM5331X_BR_VID(num));
}

/*
 * Boot firmware entries of L2_USER_ENTRY that a feature may clear while it
 * needs the frames they drop, then give back (see "Hardware LAG of
 * front ports"): index i of 0-2 holds, exactly, VALID, key {MAC
 * 01:80:c2:00:00:01, :02 or :0e, VLAN_ID 1}, mask of the MAC only (every
 * VLAN), BPDU and DST_DISCARD (word 4 0x04004000); entry 1 read on the
 * board: 84000005 00020301 fffffff0 000fffff 04004000. Which feature may
 * clear which entry: hw_bios_l2u_allowed (entry 1 under lagf=2).
 * Each entry cleared is kept (bit i of hw_bios_l2u_off, its words read
 * before clearing) until given back.
 */
#define HW_BIOS_L2U_NUM		3
static const u8 hw_bios_l2u_da[HW_BIOS_L2U_NUM] = { 0x01, 0x02, 0x0e };
static const char *const hw_bios_l2u_what[HW_BIOS_L2U_NUM] = {
	"01:80:c2:00:00:01 frames", "LACPDUs", "LLDPDUs" };
static u32 hw_bios_l2u_off;			/* bit i: entry i cleared, to be given back */
static u32 hw_bios_l2u_saved[HW_BIOS_L2U_NUM][HW_L2U_WORDS];	/* words read before clearing */

/* the exact boot firmware entry @i (0-2) */
static void hw_bios_l2u_build(u32 *w, int i)
{
	u64 mac = 0x0180c2000000ULL | hw_bios_l2u_da[i], key_mask = 0xffffffffffffULL;

	memset(w, 0, 4 * HW_L2U_WORDS);
	ent_set(w, 0, 1, 1);				/* VALID */
	ent_set(w, 1, 32, (u32)mac);			/* MAC_ADDR 48:1 */
	ent_set(w, 33, 16, (u32)(mac >> 32));
	ent_set(w, 49, 12, 1);				/* VLAN_ID 60:49 (out of the mask) */
	ent_set(w, 68, 32, (u32)key_mask);		/* MASK 127:68: MAC_ADDR only */
	ent_set(w, 100, 28, (u32)(key_mask >> 32));
	w[4] = HW_L2U_W4_BPDU | HW_L2U_W4_DISCARD;	/* 0x04004000 */
}

/*
 * entries a feature in use may clear: entry 1 (LACPDUs) under
 * lagf=2; entry 2 (LLDPDUs) under llproto bit 1
 */
static bool hw_bios_l2u_allowed(int i)
{
	return (i == LAGF_L2U_BIOS && lagf == 2) ||
	       (i == LL_L2U_BIOS && (llproto & LL_LLDP));
}

static bool hw_vlan_ok(const struct bcm53314 *sw, const u32 *w, bool egr)
{
	u32 pbm = egr ? EV_PBM(w) : VT_PBM(w), cpu = hw_cpu_pbm(sw);

	/* no bit beyond the fields: VLAN_TAB 42:0 (+ parity 43), EGR_VLAN 58:0 (+ parity 59) */
	if (w[1] & ~(egr ? GENMASK(26, 0) | objs[O_EGR_VLAN].parity :
			   GENMASK(10, 0) | objs[O_VLAN_TAB].parity))
		return false;
	if (egr)
		return EV_VALID(w) && EV_STG(w) == STG_DEFAULT && !ent_get(w, 57, 2) &&
		       (pbm & cpu) == cpu && !(pbm & ~(cpu | hw_front_pbm())) &&
		       EV_UT(w) == (pbm & hw_front_pbm()) && (pbm & hw_front_pbm());
	return VT_VALID(w) && VT_STG(w) == STG_DEFAULT && !ent_get(w, 32, 11) &&
	       (pbm & cpu) == cpu && !(pbm & ~(cpu | hw_front_pbm())) &&
	       (pbm & hw_front_pbm());
}

static bool hw_zero(const u32 *w, int words, u32 parity1)
{
	int i;

	for (i = 0; i < words; i++)
		if (w[i] & ~(i == 1 ? parity1 : 0))
			return false;
	return true;
}

/* front-port membership of a VLAN_TAB/EGR_VLAN entry (0 if empty) */
static u32 hw_members(const u32 *w, bool egr)
{
	if (hw_zero(w, 2, egr ? objs[O_EGR_VLAN].parity : objs[O_VLAN_TAB].parity))
		return 0;
	return (egr ? EV_PBM(w) : VT_PBM(w)) & hw_front_pbm();
}

static bool vl_op_ok(const struct bcm53314 *sw, const struct hw_op *op);
static bool fdb_cml_op_ok(const struct hw_op *op);
static bool mdb_op_ok(const struct bcm53314 *sw, const struct hw_op *op);
static bool ts_op_ok(const struct hw_op *op);

/* The one change each write may make (checked on the whole plan first) */
static bool hw_op_ok(const struct bcm53314 *sw, const struct hw_op *op)
{
	const u32 *a = op->old, *n = op->val;
	bool egr = op->kind == HW_EGR_VLAN;
	u32 d;

	switch (op->kind) {
	case HW_L2U: {
		u32 e[HW_L2U_WORDS];
		int num = op->idx - HW_L2U_IDX(1) + 1;

		if (num < 1 || num > BCM5331X_BR_MAX || op->addr != HW_L2U_ADDR + op->idx ||
		    op->words != HW_L2U_WORDS)
			return false;
		hw_l2u_build(e, num);
		return (hw_zero(a, HW_L2U_WORDS, 0) && !memcmp(n, e, sizeof(e))) ||
		       (!memcmp(a, e, sizeof(e)) && hw_zero(n, HW_L2U_WORDS, 0));
	}
	case HW_EGR_VLAN:
	case HW_VLAN_TAB: {
		const struct sw_obj *o = &objs[egr ? O_EGR_VLAN : O_VLAN_TAB];

		if (op->idx < HW_BR_FIRST_VID || op->idx >= HW_BR_FIRST_VID + BCM5331X_BR_MAX ||
		    op->addr != obj_addr(o, op->idx) || op->words != o->words)
			return false;
		if (!hw_zero(a, 2, o->parity) && !hw_vlan_ok(sw, a, egr))
			return false;
		if (!hw_zero(n, 2, o->parity) && !hw_vlan_ok(sw, n, egr))
			return false;
		/* exactly one front port added or removed */
		d = hw_members(a, egr) ^ hw_members(n, egr);
		if (d && !(d & (d - 1)))
			return true;
		/* lagf: or, in EGR_VLAN, the egress member of one LAG swapped for another member */
		if (egr && lagf && d && hw_zero(a, 2, o->parity) == hw_zero(n, 2, o->parity)) {
			int t = lg_of(__builtin_ctz(d));

			return t >= 0 && !(d & ~lg_ports[t]) && hweight32(d) == 2 &&
			       hweight32(hw_members(a, egr)) == hweight32(hw_members(n, egr));
		}
		return false;
	}
	case HW_PORT_TAB: {
		u16 pv = bcm5331x_port_vid(op->idx), ov = PT_VID(a), nv = PT_VID(n);
		bool ob = ov >= HW_BR_FIRST_VID && ov < HW_BR_FIRST_VID + BCM5331X_BR_MAX;
		bool nb = nv >= HW_BR_FIRST_VID && nv < HW_BR_FIRST_VID + BCM5331X_BR_MAX;

		return pv && op->addr == obj_addr(&objs[O_PORT_TAB], op->idx) &&
		       op->words == objs[O_PORT_TAB].words &&
		       !((a[0] ^ n[0]) & ~HW_PT_VID) && a[1] == n[1] && a[2] == n[2] &&
		       ((ov == pv && nb) || (ob && nv == pv));
	}
	case HW_VL_L2U:
	case HW_VL_EGR_VLAN:
	case HW_VL_VLAN_TAB:
	case HW_VL_PORT_TAB:
	case HW_VL_EGR_PORT:
	case HW_VL_ESP:
	case HW_VL_EVC1:
		return vl_op_ok(sw, op);
	case HW_TS_EP:
	case HW_TS_DA:
		return ts_op_ok(op);
	case HW_PT_CML:
		return fdb_cml_op_ok(op);
	case HW_L2MC:
	case HW_IGMP:
	case HW_VPROF:
		return mdb_op_ok(sw, op);
	case HW_TRUNK_GROUP: {
		/* group 0-6 only, between empty and one front port in all slots (RTAG 3, module 0) */
		int ga = lg_group_of(a), gn = lg_group_of(n);

		return lagf && op->idx >= 0 && op->idx < LAGF_TGIDS &&
		       op->addr == obj_addr(&objs[O_TRUNK_GROUP], op->idx) &&
		       op->words == objs[O_TRUNK_GROUP].words && ga >= 0 && gn >= 0 && ga != gn;
	}
	case HW_TRUNK_BITMAP:
		/* group 0-6 only, front ports only, one port added or removed */
		d = a[0] ^ n[0];
		return lagf && op->idx >= 0 && op->idx < LAGF_TGIDS &&
		       op->addr == obj_addr(&objs[O_TRUNK_BITMAP], op->idx) &&
		       op->words == objs[O_TRUNK_BITMAP].words &&
		       !((a[0] | n[0]) & ~hw_front_pbm()) && d && !(d & (d - 1));
	case HW_STM:
		/* a front port, between "not a trunk member" and member of group 0-6 */
		return lagf && bcm5331x_is_front(op->idx) &&
		       op->addr == obj_addr(&objs[O_SOURCE_TRUNK_MAP], op->idx) &&
		       op->words == objs[O_SOURCE_TRUNK_MAP].words &&
		       ((!a[0] && (n[0] & 3) == 1 && !(n[0] & ~GENMASK(6, 0)) && (n[0] >> 2) < LAGF_TGIDS) ||
			(!n[0] && (a[0] & 3) == 1 && !(a[0] & ~GENMASK(6, 0)) && (a[0] >> 2) < LAGF_TGIDS));
	case HW_VPROT: {
		/* an entry 12-15 of a feature in use, between empty and the entry of vp_defs */
		u32 e;

		if (op->idx < VP_FIRST || op->idx >= VP_FIRST + VP_NUM || !vp_allowed(op->idx))
			return false;
		e = vp_defs[op->idx - VP_FIRST].val;
		return op->addr == obj_addr(&objs[O_VLAN_PROTOCOL], op->idx) && op->words == 1 &&
		       ((!a[0] && n[0] == e) || (a[0] == e && !n[0]));
	}
	case HW_L2U_BIOS: {
		/* an allowed boot firmware entry, between its exact form and zero */
		u32 e[HW_L2U_WORDS];

		if (op->idx < 0 || op->idx >= HW_BIOS_L2U_NUM || !hw_bios_l2u_allowed(op->idx) ||
		    op->addr != HW_L2U_ADDR + op->idx || !op->mem || op->words != HW_L2U_WORDS)
			return false;
		hw_bios_l2u_build(e, op->idx);
		return (!memcmp(a, e, sizeof(e)) && hw_zero(n, HW_L2U_WORDS, 0)) ||
		       (hw_zero(a, HW_L2U_WORDS, 0) && !memcmp(n, e, sizeof(e)));
	}
	case HW_VPROT_DATA: {
		/* data of an entry 12-15 in use, port 1-24: between 0 and a VID (the port VID for a front port) */
		int p = op->idx >= 0 ? op->idx / 16 : -1, e = op->idx >= 0 ? op->idx % 16 : -1;
		u32 v = a[0] | n[0];
		u16 vid = (v & VP_VPD_VID) >> 3;

		return e >= VP_FIRST && vp_allowed(e) && p >= VP_VPD_FIRST && p < NUM_PORTS &&
		       op->addr == VP_VPD_ADDR + op->idx && op->words == 1 &&
		       (!a[0] != !n[0]) && !(v & ~VP_VPD_VID) && vid &&
		       (!bcm5331x_is_front(p) || vid == bcm5331x_port_vid(p));
	}
	}
	return false;
}

static int hw_read(struct bcm53314 *sw, const char *name, u32 addr, bool mem, int words,
		   int idx, u32 *w)
{
	memset(w, 0, 4 * HW_L2U_WORDS);
	return schan_xfer(sw, false, mem, addr, words, w, name, idx);
}

static int hw_add(enum hw_kind kind, const char *name, u32 addr, bool mem, int words,
		  int idx, u32 parity1, const u32 *old, const u32 *val)
{
	struct hw_op *op;

	if (hw_nops >= HW_NOPS)
		return -ENOSPC;
	op = &hw_ops[hw_nops++];
	memset(op, 0, sizeof(*op));
	op->kind = kind;
	op->name = name;
	op->addr = addr;
	op->mem = mem;
	op->words = words;
	op->idx = idx;
	op->parity1 = parity1;
	memcpy(op->old, old, 4 * words);
	memcpy(op->val, val, 4 * words);
	return 0;
}

static bool hw_same(const struct hw_op *op, const u32 *x, const u32 *y)
{
	int i;

	for (i = 0; i < op->words; i++)
		if ((x[i] ^ y[i]) & ~(i == 0 ? op->parity0 : i == 1 ? op->parity1 : 0))
			return false;
	return true;
}

/* plan checked, then each write re-read before, written, read back (under sw->lock) */
static int hw_execute(struct bcm53314 *sw, struct device *dev)
{
	int i, err;

	for (i = 0; i < hw_nops; i++)
		if (!hw_op_ok(sw, &hw_ops[i])) {
			dev_err(dev, "bridge: write %d/%d %s[%d] refused: nothing written\n",
				i + 1, hw_nops, hw_ops[i].name, hw_ops[i].idx);
			bcm5331x_hw_refusals++;
			return -EPERM;
		}
	for (i = 0; i < hw_nops; i++) {
		struct hw_op *op = &hw_ops[i];
		u32 cur[HW_L2U_WORDS], rb[HW_L2U_WORDS];

		err = hw_read(sw, op->name, op->addr, op->mem, op->words, op->idx, cur);
		if (err)
			return err;
		if (!hw_same(op, cur, op->old)) {
			sw_fault(sw, "dsa: bridge %s[%d] is %08x %08x, expected %08x %08x", op->name,
				 op->idx, cur[0], cur[1], op->old[0], op->old[1]);
			return -ESTALE;
		}
		memcpy(rb, op->val, sizeof(rb));
		err = schan_xfer(sw, true, op->mem, op->addr, op->words, rb, op->name, op->idx);
		if (err)
			return err;
		udelay(10);
		err = hw_read(sw, op->name, op->addr, op->mem, op->words, op->idx, rb);
		if (err)
			return err;
		bcm5331x_hw_writes++;
		if (!hw_same(op, rb, op->val)) {
			sw_fault(sw, "dsa: bridge %s[%d] read back %08x %08x, wrote %08x %08x",
				 op->name, op->idx, rb[0], rb[1], op->val[0], op->val[1]);
			return -EIO;
		}
		dev_dbg(dev, "bridge %s[%d] addr 0x%08x: %08x %08x %08x -> %08x %08x %08x\n",
			op->name, op->idx, op->addr, op->old[0], op->old[1], op->old[2],
			op->val[0], op->val[1], op->val[2]);
	}
	return 0;
}

/*
 * Boot firmware entry @i of L2_USER_ENTRY (see hw_bios_l2u_build), for
 * feature @who (log prefix): @clear = cleared to zero if it holds exactly
 * the boot firmware form (its five words read before, logged and kept),
 * else given back as kept. One write, planned on what is read, checked by
 * hw_op_ok (hw_bios_l2u_allowed), re-read before, written and read back.
 * 0 done or nothing to do (an entry of another form is left as found),
 * < 0 error. Under sw->lock.
 */
static int hw_bios_l2u(struct bcm53314 *sw, struct device *dev, const char *who, int i, bool clear)
{
	u32 cur[HW_L2U_WORDS], e[HW_L2U_WORDS], z[HW_L2U_WORDS] = { 0 }, *sv;
	int err;

	if (i < 0 || i >= HW_BIOS_L2U_NUM)
		return -EINVAL;
	sv = hw_bios_l2u_saved[i];
	if (clear == !!(hw_bios_l2u_off & BIT(i)))
		return 0;
	if (sw->halted) {
		if (!clear)
			dev_err(dev, "%s: switch halted, L2_USER_ENTRY[%d] of the boot firmware not given back (%08x %08x %08x %08x %08x): back at the next reset of the switch by the boot firmware\n",
				who, i, sv[0], sv[1], sv[2], sv[3], sv[4]);
		return -EIO;
	}
	if (dry_run || access != 2)
		return -EPERM;
	err = hw_read(sw, "L2_USER_ENTRY", HW_L2U_ADDR + i, true, HW_L2U_WORDS, i, cur);
	if (err)
		goto out;
	hw_bios_l2u_build(e, i);
	if (clear && memcmp(cur, e, sizeof(e))) {
		if (!hw_zero(cur, HW_L2U_WORDS, 0))
			dev_info(dev, "%s: L2_USER_ENTRY[%d] = %08x %08x %08x %08x %08x, not the boot firmware entry for the %s: left as found\n",
				 who, i, cur[0], cur[1], cur[2], cur[3], cur[4], hw_bios_l2u_what[i]);
		else
			dev_info(dev, "%s: L2_USER_ENTRY[%d] already clear (no boot firmware entry for the %s): nothing written\n",
				 who, i, hw_bios_l2u_what[i]);
		return 0;
	}
	if (!clear && !hw_zero(cur, HW_L2U_WORDS, 0)) {
		dev_err(dev, "%s: L2_USER_ENTRY[%d] = %08x %08x %08x %08x %08x, not the state left by the driver: boot firmware entry not given back\n",
			who, i, cur[0], cur[1], cur[2], cur[3], cur[4]);
		bcm5331x_hw_refusals++;
		hw_bios_l2u_off &= ~BIT(i);
		return -EBUSY;
	}
	hw_nops = 0;
	err = hw_add(HW_L2U_BIOS, "L2_USER_ENTRY", HW_L2U_ADDR + i, true, HW_L2U_WORDS, i, 0,
		     clear ? cur : z, clear ? z : sv);
	if (!err)
		err = hw_execute(sw, dev);
	if (!err) {
		if (clear) {
			memcpy(sv, cur, sizeof(cur));
			hw_bios_l2u_off |= BIT(i);
		} else {
			hw_bios_l2u_off &= ~BIT(i);
		}
		dev_info(dev, "%s: L2_USER_ENTRY[%d] of the boot firmware (%s, every VLAN, dropped: %08x %08x %08x %08x %08x) %s (1 write, read back)\n",
			 who, i, hw_bios_l2u_what[i], sv[0], sv[1], sv[2], sv[3], sv[4],
			 clear ? "cleared" : "given back");
		return 0;
	}
out:
	dev_err(dev, "%s: L2_USER_ENTRY[%d] of the boot firmware %s failed (%d)\n", who, i,
		clear ? "clearing" : "give-back", err);
	return err;
}

/* key bits 1-60 (MAC_ADDR 48:1, VLAN_ID 60:49) and its mask (MASK 127:68: key bit n at 67 + n) */
static u64 hw_l2u_key(const u32 *w)
{
	return ent_get(w, 1, 32) | (u64)ent_get(w, 33, 28) << 32;
}

static u64 hw_l2u_mask(const u32 *w)
{
	return ent_get(w, 68, 32) | (u64)ent_get(w, 100, 28) << 32;
}

/*
 * A valid entry below 56: 0 if it is compatible with hardware bridging
 * (drops what it matches, or matches no frame of a bridge VLAN), otherwise
 * the number of the first bridge whose key it overlaps.
 */
/* the entry only drops what it matches */
static bool hw_l2u_drop_only(const u32 *w)
{
	return (w[4] & (HW_L2U_W4_DISCARD | HW_L2U_W4_MIRROR | HW_L2U_W4_CPU)) == HW_L2U_W4_DISCARD;
}

/* the keys of @w and @e are equal on every bit both masks compare */
static bool hw_l2u_overlap(const u32 *w, const u32 *e)
{
	return !((hw_l2u_key(w) ^ hw_l2u_key(e)) & hw_l2u_mask(w) & hw_l2u_mask(e));
}

static int hw_l2u_foreign(const u32 *w)
{
	u32 e[HW_L2U_WORDS];
	int num;

	if (hw_l2u_drop_only(w))
		return 0;
	for (num = 1; num <= BCM5331X_BR_MAX; num++) {
		hw_l2u_build(e, num);
		if (hw_l2u_overlap(w, e))
			return num;
	}
	return 0;
}

/*
 * Whole L2_USER_ENTRY (reads only): entries 56-63 zero, every valid entry
 * below compatible (see above). @log (at load): every non-zero entry is
 * logged in full. Called under sw->lock.
 */
static int hw_l2u_scan(struct bcm53314 *sw, struct device *dev, bool log)
{
	u32 w[HW_L2U_WORDS];
	int i, num, err, ret = 0, nz = 0;
	bool vl;

	for (i = 0; i < HW_L2U_NUM; i++) {
		err = hw_read(sw, "L2_USER_ENTRY", HW_L2U_ADDR + i, true, HW_L2U_WORDS, i, w);
		if (err)
			return err;
		if (i < VL_L2U_FIRST)
			memcpy(hw_l2u_low[i], w, sizeof(w));
		if (hw_zero(w, HW_L2U_WORDS, 0))
			continue;
		nz++;
		num = i < HW_L2U_IDX(1) && (w[0] & 1) ? hw_l2u_foreign(w) : 0;
		/* vlanbr=Y: 40-55 are the entries of the user VLANs */
		vl = vlanbr && i >= VL_L2U_FIRST && i < HW_L2U_IDX(1);
		if (log)
			dev_info(dev, "bridge: L2_USER_ENTRY[%d] at load: %08x %08x %08x %08x %08x (%s)\n",
				 i, w[0], w[1], w[2], w[3], w[4],
				 i >= HW_L2U_IDX(1) ? "index of a bridge: in use" :
				 vl ? "index of a VLAN-aware entry: in use" :
				 !(w[0] & 1) ? "not valid: ignored" :
				 num ? "overlaps a bridge VLAN" : "kept, compatible");
		if (ret)
			continue;
		if (i >= HW_L2U_IDX(1)) {
			dev_err(dev, "bridge: L2_USER_ENTRY[%d] not empty (%08x ...): hardware bridging refused\n",
				i, w[0]);
			ret = -EBUSY;
		} else if (vl) {
			dev_err(dev, "bridge: L2_USER_ENTRY[%d] not empty (%08x ...): VLAN-aware bridging refused\n",
				i, w[0]);
			ret = -EBUSY;
		} else if (num) {
			dev_err(dev, "bridge: L2_USER_ENTRY[%d] (%08x %08x %08x %08x %08x) matches frames of bridge VLAN %u before entry %d: hardware bridging refused\n",
				i, w[0], w[1], w[2], w[3], w[4], BCM5331X_BR_VID(num), HW_L2U_IDX(num));
			ret = -EBUSY;
		}
		if (ret && !log)
			return ret;
	}
	if (log)
		dev_info(dev, "bridge: L2_USER_ENTRY at load: %d non-zero entr%s, hardware bridging %s\n",
			 nz, nz == 1 ? "y" : "ies", ret ? "refused" : "possible");
	return ret;
}

/*
 * At load, hwbridge=Y only: what the boot firmware left in L2_USER_ENTRY,
 * logged (reads only; a refusal here is repeated at the first join).
 */
static void bcm5331x_dsa_l2u_report(struct bcm53314 *sw, struct device *dev)
{
	int err;

	if (!hwbridge)
		return;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : hw_l2u_scan(sw, dev, true);
	mutex_unlock(&sw->lock);
	if (err && err != -EBUSY)
		dev_err(dev, "bridge: L2_USER_ENTRY not read at load (%d)\n", err);
}

/* Whole L2_USER_ENTRY, once, before the first entry is written. Called under sw->lock. */
static int hw_l2u_check(struct bcm53314 *sw, struct device *dev)
{
	int err;

	if (hw_l2u_checked)
		return 0;
	err = hw_l2u_scan(sw, dev, false);
	if (!err)
		hw_l2u_checked = true;
	return err;
}

/* a port a frame of the bridge VID may be delivered to: not a LAG member, or one allowed to transmit */
static bool hw_rx_port_ok(struct dsa_switch *ds, int p)
{
	return !lagf || lg_of(p) < 0 || lg_tx(ds, p);
}

/* tagger: bridge VID of @port, designated port of the bridge VID */
static void hw_tagger_update(struct dsa_switch *ds, int num)
{
	struct bcm5331x_tagger_data *td = ds->tagger_data;
	u16 vid = BCM5331X_BR_VID(num);
	int p, des = 0, first = 0;

	if (!td)
		return;
	for (p = 0; p < NUM_PORTS; p++) {
		bool fwd = hw_port_br[p] == num && (hw_br_fwd[num] & BIT(p));

		/*
		 * Designated port: the first member, skipping a LAG member
		 * whose bond would not take the frame (lagf: a member not
		 * allowed to transmit is inactive in its bond).
		 */
		if (fwd && !first)
			first = p;
		if (fwd && !des && hw_rx_port_ok(ds, p))
			des = p;
		/*
		 * Every port of the bridge sends offloaded frames in the bridge
		 * VLAN while it has a member: the bridge offloads to the first
		 * port of the switch it forwards to, the switch floods to the
		 * members only (a blocked port is not one).
		 */
		if (hw_port_br[p] == num || READ_ONCE(td->port_bvid[p]) == vid)
			WRITE_ONCE(td->port_bvid[p],
				   hw_port_br[p] == num && hw_br_fwd[num] ? vid : 0);
	}
	WRITE_ONCE(td->vid_port[vid], des ? des : first);
}

/*
 * Port @port of bridge @num enters (@on) or leaves the bridge VLAN. Plan
 * from what is read now, each entry checked against the state the driver
 * left (refused, nothing written, otherwise), then executed. A member of a
 * front-port LAG (lagf) enters or leaves its trunk group with it, and the
 * egress member of the group may move (see "Hardware LAG of front ports").
 */
static int hw_member(struct dsa_switch *ds, int port, int num, bool on)
{
	struct bcm53314 *sw = ds->priv;
	u16 vid = BCM5331X_BR_VID(num), pvid = bcm5331x_port_vid(port);
	u32 cur = hw_br_fwd[num], nxt = on ? cur | BIT(port) : cur & ~BIT(port);
	u32 cpu = hw_cpu_pbm(sw), l2u[HW_L2U_WORDS], e[HW_L2U_WORDS], w[HW_L2U_WORDS];
	u32 vt[3], ev[3], pt[3], tg[3], tb[3], stm[3];
	const struct sw_obj *ovt = &objs[O_VLAN_TAB], *oev = &objs[O_EGR_VLAN];
	const struct sw_obj *otg = &objs[O_TRUNK_GROUP], *otb = &objs[O_TRUNK_BITMAP];
	const struct sw_obj *ostm = &objs[O_SOURCE_TRUNK_MAP];
	int t = lagf ? lg_of(port) : -1, ndes = 0, err;
	u32 ntrunk = 0, hid = lg_hidden(), nhid = hid, egr, negr;

	if (!pvid || num < 1 || num > BCM5331X_BR_MAX || cur == nxt)
		return 0;
	if (t >= 0) {
		ntrunk = on ? lg_trunk[t] | BIT(port) : lg_trunk[t] & ~BIT(port);
		ndes = lg_pick(ds, ntrunk, lg_des[t]);
		nhid = (hid & ~lg_trunk[t]) | (ntrunk & ~BIT(ndes));
	}
	/* egress membership: the forwarding members but the LAG members other than the egress one */
	egr = cur & ~hid;
	negr = nxt & ~nhid;
	if (access != 2 || dry_run)
		return -EPERM;
	mutex_lock(&sw->lock);
	hw_nops = 0;
	if (sw->halted) {
		err = -EIO;
		goto out;
	}
	if (on && !cur) {
		err = hw_l2u_check(sw, ds->dev);
		if (err)
			goto out;
	}
	err = hw_read(sw, "L2_USER_ENTRY", HW_L2U_ADDR + HW_L2U_IDX(num), true, HW_L2U_WORDS,
		      HW_L2U_IDX(num), l2u);
	if (!err)
		err = sw_read(sw, O_VLAN_TAB, vid, vt);
	if (!err)
		err = sw_read(sw, O_EGR_VLAN, vid, ev);
	if (!err)
		err = sw_read(sw, O_PORT_TAB, port, pt);
	if (!err && t >= 0)
		err = sw_read(sw, O_TRUNK_GROUP, t, tg);
	if (!err && t >= 0)
		err = sw_read(sw, O_TRUNK_BITMAP, t, tb);
	if (!err && t >= 0)
		err = sw_read(sw, O_SOURCE_TRUNK_MAP, port, stm);
	if (err)
		goto out;
	/* the state the driver left: entries of the current members, port VID, trunk group */
	hw_l2u_build(e, num);
	if ((cur ? memcmp(l2u, e, sizeof(e)) : !hw_zero(l2u, HW_L2U_WORDS, 0)) ||
	    (!cur && (!hw_zero(vt, 2, ovt->parity) || !hw_zero(ev, 2, oev->parity))) ||
	    hw_members(vt, false) != cur || hw_members(ev, true) != egr ||
	    (cur && (!hw_vlan_ok(sw, vt, false) || !hw_vlan_ok(sw, ev, true) ||
		     VT_PBM(vt) != (cur | cpu) || EV_PBM(ev) != (egr | cpu))) ||
	    PT_VID(pt) != (on ? pvid : vid) ||
	    (t >= 0 && (lg_group_of(tg) != lg_des[t] || tb[0] != lg_trunk[t] ||
			stm[0] != (on ? 0 : LAGF_STM(t))))) {
		dev_err(ds->dev, "bridge %d, port %d: switch not in the state left by the driver: nothing written\n",
			num, port);
		bcm5331x_hw_refusals++;
		err = -EBUSY;
		goto out;
	}
	if (on) {
		/* trunk group first: the port is learnt on the group from its first frame in the bridge VLAN */
		if (t >= 0) {
			lg_group_build(w, ndes);
			if (memcmp(w, tg, sizeof(tg)))
				err = hw_add(HW_TRUNK_GROUP, otg->name, obj_addr(otg, t), true, otg->words, t,
					     0, tg, w);
			w[0] = ntrunk;
			if (!err)
				err = hw_add(HW_TRUNK_BITMAP, otb->name, obj_addr(otb, t), true, otb->words, t,
					     0, tb, w);
			w[0] = LAGF_STM(t);
			if (!err)
				err = hw_add(HW_STM, ostm->name, obj_addr(ostm, port), true, ostm->words, port,
					     0, stm, w);
		}
		if (!err && !cur)
			err = hw_add(HW_L2U, "L2_USER_ENTRY", HW_L2U_ADDR + HW_L2U_IDX(num), true,
				     HW_L2U_WORDS, HW_L2U_IDX(num), 0, l2u, e);
		egr_vlan_build(w, negr | cpu, negr);
		if (!err && negr != egr)
			err = hw_add(HW_EGR_VLAN, oev->name, obj_addr(oev, vid), true, oev->words, vid,
				     oev->parity, ev, w);
		vlan_tab_build(w, nxt | cpu);
		if (!err)
			err = hw_add(HW_VLAN_TAB, ovt->name, obj_addr(ovt, vid), true, ovt->words, vid,
				     ovt->parity, vt, w);
		memcpy(w, pt, sizeof(pt));
		ent_set(w, 19, 12, vid);
		if (!err)
			err = hw_add(HW_PORT_TAB, objs[O_PORT_TAB].name, obj_addr(&objs[O_PORT_TAB], port),
				     true, objs[O_PORT_TAB].words, port, 0, pt, w);
	} else {
		memcpy(w, pt, sizeof(pt));
		ent_set(w, 19, 12, pvid);
		err = hw_add(HW_PORT_TAB, objs[O_PORT_TAB].name, obj_addr(&objs[O_PORT_TAB], port),
			     true, objs[O_PORT_TAB].words, port, 0, pt, w);
		if (nxt)
			vlan_tab_build(w, nxt | cpu);
		else
			memset(w, 0, sizeof(w));
		if (!err)
			err = hw_add(HW_VLAN_TAB, ovt->name, obj_addr(ovt, vid), true, ovt->words, vid,
				     ovt->parity, vt, w);
		if (nxt)
			egr_vlan_build(w, negr | cpu, negr);
		else
			memset(w, 0, sizeof(w));
		if (!err && (negr != egr || !nxt))
			err = hw_add(HW_EGR_VLAN, oev->name, obj_addr(oev, vid), true, oev->words, vid,
				     oev->parity, ev, w);
		memset(w, 0, sizeof(w));
		if (!err && !nxt)
			err = hw_add(HW_L2U, "L2_USER_ENTRY", HW_L2U_ADDR + HW_L2U_IDX(num), true,
				     HW_L2U_WORDS, HW_L2U_IDX(num), 0, l2u, w);
		/* trunk group last: the port no longer receives in the bridge VLAN */
		if (t >= 0) {
			w[0] = 0;
			if (!err)
				err = hw_add(HW_STM, ostm->name, obj_addr(ostm, port), true, ostm->words, port,
					     0, stm, w);
			w[0] = ntrunk;
			if (!err)
				err = hw_add(HW_TRUNK_BITMAP, otb->name, obj_addr(otb, t), true, otb->words, t,
					     0, tb, w);
			lg_group_build(w, ndes);
			if (!err && memcmp(w, tg, sizeof(tg)))
				err = hw_add(HW_TRUNK_GROUP, otg->name, obj_addr(otg, t), true, otg->words, t,
					     0, tg, w);
		}
	}
	if (err)
		goto out;
	/* leaving: the tagger stops using the bridge VID before the switch does */
	if (!on) {
		hw_br_fwd[num] = nxt;
		hw_tagger_update(ds, num);
	}
	err = hw_execute(sw, ds->dev);
	if (!err && t >= 0) {
		lg_trunk[t] = ntrunk;
		lg_des[t] = ndes;
	}
	if (!err && on) {
		hw_br_fwd[num] = nxt;
		hw_tagger_update(ds, num);
	}
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "bridge %d, port %d: %s the bridge VLAN %u failed (%d)\n",
			num, port, on ? "entering" : "leaving", vid, err);
	else
		dev_info(ds->dev, "bridge %d, port %d: %s the bridge VLAN %u (%d writes, read back)%s\n",
			 num, port, on ? "in" : "out of", vid, hw_nops,
			 t >= 0 ? ", LAG member" : "");
	return err;
}

/* ---------------------------------------------------------------------- */
/* VLAN-aware bridging (vlanbr=Y, with hwbridge and qinq)                  */

/*
 * A VLAN-aware bridge (vlan_filtering 1: the br-lan of OpenWrt with
 * bridge-vlan sections) is a software bridge unless vlanbr=Y. With
 * vlanbr=Y (which needs hwbridge=Y and qinq=Y: the switch in double-tagging
 * mode, the CPU link a provider port with outer TPID 0x88a8), the first
 * VLAN-aware bridge of front ports is offloaded (later ones stay software:
 * the VLANs of the switch are global, two bridges would share them).
 *
 * Classification: a front port of that bridge that forwards in hardware is
 * turned from a customer (UNI) port into a provider (NNI) port whose outer
 * TPID is that of slot 0, 0x8100 (PORT_TAB.NNI_PORT, bit 32, and EGR_PORT.
 * NNI_PORT, bit 1; OUTER_TPID_ENABLE, EGR_SRC_PORT and EGR_VLAN_CONTROL_1
 * of the front ports already select slot 0 and are not written): the
 * switch then reads its 802.1Q tag as the VLAN of the frame (an inner tag
 * behind it stays inner), an untagged frame takes PORT_VID, and on the way
 * out the tag is removed on the untagged members (EGR_VLAN.UT_BITMAP) and
 * written, TPID 0x8100, on the others: an IEEE 802.1Q bridge port. The CPU
 * link keeps its outer TPID 0x88a8: a frame of such a VLAN reaches the host
 * as 88a8/VID, whatever the front port.
 *
 * Switch VLAN of a user VID ("hardware VID"): the user VID itself, unless
 * the switch reserves it (VID 1 of the boot firmware and MGMT, 20 of the
 * MGMT network, 100-199 of the port and bridge VLANs, 4079-4095); a
 * reserved user VID uses a VID of the pool 4079-4094 instead, and is then
 * accepted untagged only on the front ports (its tag would be written with
 * the pool VID): the PVID 1 untagged of OpenWrt and of the Linux bridge
 * fits. No VLAN translation table is used (VLAN_XLATE: 16 entries, its
 * double-tagging semantics not read). Each user VID in use takes one of 16
 * slots: slot i holds its user VID, its pool VID 4079 + i if needed, and its
 * L2_USER_ENTRY 40 + i, the form of the bridge VLANs (key switch VLAN +
 * 01:80:c2:00:00:0x, BPDU and DST_DISCARD, no PORT_TGID: for a multicast
 * DA it would be an L2MC index): the link-local frames classified in that
 * VLAN are dropped, never flooded to the other members; at most 16 user
 * VIDs per bridge (-ENOSPC beyond). The host does not receive them either
 * (STP, LLDP, LACP over the offloaded bridge are not supported); an
 * untagged one of a port without PVID still reaches it on the port VID.
 *
 * Membership by STP state, as for hwbridge: a port that forwards is NNI,
 * member of the switch VLAN of each of its user VIDs (untagged where the
 * bridge says so) and PORT_VID = switch VLAN of its PVID, or its own port
 * VID 100+N without PVID (an untagged frame then reaches the host from the
 * exact port and the bridge drops it, as without hardware); in any other
 * state it is back to UNI in its own VLAN only (exact port, BPDUs
 * included). The host is a tagged member (ge2, and ge3 under trunk2) of
 * every switch VLAN in use.
 *
 * Receive: a frame of a switch VLAN in use is given back its user VID as
 * an accelerated 802.1Q tag and delivered to the designated member (lowest
 * forwarding member port of that VLAN), marked as forwarded by the switch
 * ("imprecise" receive, as tag_8021q taggers for VLAN-aware bridges).
 * Transmit: a frame offloaded by the bridge (tx_fwd_offload) loses its
 * 802.1Q tag and is sent with the switch VLAN; any other frame keeps the
 * exact port VID (its user tag inner), as standalone.
 *
 * Writes: the classes of hwbridge (L2_USER_ENTRY, EGR_VLAN, VLAN_TAB,
 * PORT_TAB.PORT_VID) at new indices, plus the NNI bits of the front ports
 * (PORT_TAB word 1 bit 0, EGR_PORT bit 1). One change at a time, planned on
 * what is read, the state checked against what the driver left (-EBUSY,
 * nothing written, otherwise), the rules (vl_op_ok) checked on the whole
 * plan, each write re-read before, written, read back (hw_execute):
 *  - a port enters a switch VLAN: L2_USER_ENTRY (first member), EGR_VLAN,
 *    VLAN_TAB; leaves it: VLAN_TAB, EGR_VLAN, L2_USER_ENTRY (last member);
 *    untagged flag only: EGR_VLAN;
 *  - a port turns NNI: its VLANs first, then EGR_PORT, PORT_TAB (NNI and
 *    PORT_VID in one write); back to UNI: PORT_TAB, EGR_PORT, then its
 *    VLANs; PVID change: PORT_TAB.
 */
#define VL_SLOTS		16
#define VL_POOL_FIRST		BCM5331X_VL_POOL_FIRST	/* 4079-4094 */
#define VL_PT1_NNI		BIT(0)		/* PORT_TAB word 1: NNI_PORT (bit 32) */
#define VL_PT1_TPID_EN		GENMASK(21, 18)	/* OUTER_TPID_ENABLE 53:50 */
#define VL_PT1_VT_ENABLE	BIT(26)		/* VT_ENABLE 58 */
#define VL_EP_HIGIG		BIT(0)		/* EGR_PORT: HIGIG_PACKET */
#define VL_EP_NNI		BIT(1)		/* EGR_PORT: NNI_PORT */
#define VL_WORDS		(VLAN_N_VID / 32)

static int vl_br;				/* bridge number of the offloaded VLAN-aware bridge */
static bool vl_ad;				/* ... with the 802.1ad protocol (vlanbr_ad=Y) */
static bool vlanbr_ad;
static struct {
	u16 uvid;				/* user VID, 0 = free slot */
	int users;				/* ports of the bridge with that VID */
	u32 mem, ut;				/* front members / untagged written in the switch */
} vl_slot[VL_SLOTS];
static u32 vl_vids[NUM_PORTS][VL_WORDS];	/* user VIDs of each port (bridge) */
static u32 vl_untag[NUM_PORTS][VL_WORDS];	/* ... egressing untagged */
static u16 vl_pvid[NUM_PORTS];			/* PVID of each port, 0 = none */
static u32 vl_fwd;				/* ports forwarding (wanted in hardware) */
static u32 vl_nni;				/* ports written NNI */
static u16 vl_ptvid[NUM_PORTS];			/* PORT_VID written while NNI */

/*
 * Module parameter vlanbr_ad (default N, needs vlanbr=Y): the
 * offloaded VLAN-aware bridge may have the 802.1ad protocol (S-VLANs of a
 * provider bridge), else refused as before. Its forwarding ports
 * are NNI with the outer TPID slot 1 (0x88a8, written by qinq on ING/
 * EGR_OUTER_TPID_1 and used by ge2): PORT_TAB.OUTER_TPID_ENABLE 0b0001 ->
 * 0b0010 (with NNI_PORT), EGR_SRC_PORT.OUTER_TPID_ENABLE 0b0001 -> 0b0010,
 * EGR_VLAN_CONTROL_1.OUTER_TPID_INDEX 0 -> 1, the values ge2 already holds
 * ("TPID 0x88a8 on a front port"); given back to slot 0 /
 * index 0 when the port stops forwarding or leaves. On such a port an
 * 0x88a8 tag is the S-VLAN, an 0x8100 tag alone is not an outer tag (the
 * frame takes the PVID, the C-tag kept inside), as in the 802.1ad Linux
 * bridge. The tagger gives the user VLAN back as an accelerated 0x88a8
 * tag and takes 0x88a8 tags from that bridge on transmit. The protocol of
 * the bridge is read at the first join (one offloaded VLAN-aware bridge,
 * 802.1Q or 802.1ad); a later change of the protocol is not passed on to
 * DSA (net/dsa/user.c dsa_user_port_attr_set): each VLAN added afterwards
 * checks it again and is refused (-EBUSY) if it changed.
 */
module_param(vlanbr_ad, bool, 0444);
MODULE_PARM_DESC(vlanbr_ad, "With vlanbr=1, the offloaded VLAN-aware bridge may be 802.1ad (front ports NNI with outer TPID 0x88a8 while forwarding: three fields per port, the values of ge2, given back when it leaves); default N = 802.1ad bridges refused");
module_param(vlanbr, bool, 0444);
MODULE_PARM_DESC(vlanbr, "Offload one VLAN-aware bridge of front ports to the switch: front ports 802.1Q (NNI, TPID 0x8100) while forwarding, one switch VLAN per user VID (at most 16; reserved VIDs untagged only), link-local frames of the user VLANs dropped (needs hwbridge=1 and qinq=1; switch writes at run time, read back; default N = software bridge, no write)");

static bool vl_test(const u32 *b, u16 v)
{
	return b[v / 32] & BIT(v % 32);
}

static void vl_put(u32 *b, u16 v, bool on)
{
	if (on)
		b[v / 32] |= BIT(v % 32);
	else
		b[v / 32] &= ~BIT(v % 32);
}

/* user VIDs the switch keeps for itself: accepted untagged only, through the pool */
static bool vl_reserved(u16 v)
{
	return v <= VID_DEFAULT || v == MGMT_VID || (v >= VID_MIN && v <= VID_MAX) ||
	       v >= VL_POOL_FIRST;
}

static int vl_slot_of(u16 uvid)
{
	int i;

	for (i = 0; uvid && i < VL_SLOTS; i++)
		if (vl_slot[i].uvid == uvid)
			return i;
	return -1;
}

/* switch VLAN of slot @i */
static u16 vl_hwvid(int i)
{
	return vl_reserved(vl_slot[i].uvid) ? VL_POOL_FIRST + i : vl_slot[i].uvid;
}

/* slot whose switch VLAN is @hw, -1 if none */
static int vl_slot_of_hw(u16 hw)
{
	int i;

	for (i = 0; i < VL_SLOTS; i++)
		if (vl_slot[i].uvid && vl_hwvid(i) == hw)
			return i;
	return -1;
}

/* a port of the offloaded VLAN-aware bridge */
static bool vl_port(int port)
{
	return port > 0 && port < NUM_PORTS && vl_br && hw_port_br[port] == vl_br &&
	       hw_br_mode[vl_br] == HW_BR_VLAN;
}

/* PORT_VID a forwarding port of the bridge should have */
static u16 vl_want_ptvid(int port)
{
	int i = vl_slot_of(vl_pvid[port]);

	return i >= 0 ? vl_hwvid(i) : bcm5331x_port_vid(port);
}

/* user VLAN entry: valid, STG 1, the host tagged, front members only, untagged among them */
static bool vl_vlan_ok(const struct bcm53314 *sw, const u32 *w, bool egr)
{
	u32 pbm = egr ? EV_PBM(w) : VT_PBM(w), cpu = hw_cpu_pbm(sw), fr = hw_front_pbm();
	/* no bit beyond the fields (parity aside) */
	u32 hi = egr ? GENMASK(26, 0) | objs[O_EGR_VLAN].parity : GENMASK(10, 0) | objs[O_VLAN_TAB].parity;

	if (w[1] & ~hi)
		return false;
	if ((pbm & cpu) != cpu || (pbm & ~(cpu | fr)) || !(pbm & fr))
		return false;
	if (egr)
		return EV_VALID(w) && EV_STG(w) == STG_DEFAULT && !ent_get(w, 57, 2) &&
		       !(EV_UT(w) & ~(pbm & fr));
	return VT_VALID(w) && VT_STG(w) == STG_DEFAULT && !ent_get(w, 32, 11);
}

/*
 * PORT_TAB of a front port: UNI in its own VLAN (outer TPID slot 0), or NNI
 * in its own VLAN or a user VLAN, slot 0 (802.1Q bridge) or slot 1 only
 * (802.1ad bridge, vlanbr_ad=Y)
 */
static bool vl_pt_state_ok(int port, const u32 *w)
{
	u16 vid = PT_VID(w), pv = bcm5331x_port_vid(port);
	u32 slot = QQ_GET(VL_PT1_TPID_EN, w[1]);

	if (w[1] & VL_PT1_VT_ENABLE)
		return false;
	if (!(w[1] & VL_PT1_NNI))
		return slot == QQ_SLOT0 && vid == pv;
	if (slot != (vl_ad ? QQ_SLOT1 : QQ_SLOT0))
		return false;
	return vid == pv || vl_slot_of_hw(vid) >= 0;
}

/* EGR_SRC_PORT of a front port in a VLAN-aware bridge: no inner tag added, outer TPID slot 0 or 1 */
static bool vl_esp_ok(const u32 *w, u32 slot)
{
	return !(w[0] & QQ_ESP_ADD_INNER) && QQ_GET(QQ_ESP_TPID_EN, w[0]) == slot;
}

/* EGR_VLAN_CONTROL_1 of a front port: no translation, no TPID selection, no inner removal; index 0 or 1 */
static bool vl_evc1_ok(const u32 *w, u32 idx)
{
	return !(w[0] & (QQ_EVC_VT_ENABLE | QQ_EVC_TPID_SEL | QQ_EVC_REMOVE_INNER)) &&
	       QQ_GET(QQ_EVC_TPID_INDEX, w[0]) == idx;
}

/* The one change each write of VLAN-aware bridging may make (whole plan checked first) */
static bool vl_op_ok(const struct bcm53314 *sw, const struct hw_op *op)
{
	const u32 *a = op->old, *n = op->val;
	bool egr = op->kind == HW_VL_EGR_VLAN;
	int i;

	if (!vlanbr || !qinq_on)
		return false;
	switch (op->kind) {
	case HW_VL_L2U: {
		u32 e[HW_L2U_WORDS];

		i = op->idx - VL_L2U_FIRST;
		if (i < 0 || i >= VL_SLOTS || !vl_slot[i].uvid || op->addr != HW_L2U_ADDR + op->idx ||
		    op->words != HW_L2U_WORDS)
			return false;
		hw_l2u_build_vid(e, vl_hwvid(i));
		return (hw_zero(a, HW_L2U_WORDS, 0) && !memcmp(n, e, sizeof(e))) ||
		       (!memcmp(a, e, sizeof(e)) && hw_zero(n, HW_L2U_WORDS, 0));
	}
	case HW_VL_EGR_VLAN:
	case HW_VL_VLAN_TAB: {
		const struct sw_obj *o = &objs[egr ? O_EGR_VLAN : O_VLAN_TAB];
		bool az = hw_zero(a, 2, o->parity), nz = hw_zero(n, 2, o->parity);
		u32 d, du;

		if (vl_slot_of_hw(op->idx) < 0 || op->addr != obj_addr(o, op->idx) ||
		    op->words != o->words || (az && nz))
			return false;
		if ((!az && !vl_vlan_ok(sw, a, egr)) || (!nz && !vl_vlan_ok(sw, n, egr)))
			return false;
		d = hw_members(a, egr) ^ hw_members(n, egr);
		du = egr ? (az ? 0 : EV_UT(a)) ^ (nz ? 0 : EV_UT(n)) : 0;
		/* one front port in or out (its untagged bit with it), or one untagged bit flipped */
		if (d)
			return (d & (d - 1)) == 0 && !(du & ~d);
		return egr && du && (du & (du - 1)) == 0;
	}
	case HW_VL_PORT_TAB:
		/* 802.1ad: the outer TPID slots change with NNI_PORT (vl_pt_state_ok: UNI slot 0, NNI slot 1) */
		return bcm5331x_is_front(op->idx) &&
		       op->addr == obj_addr(&objs[O_PORT_TAB], op->idx) &&
		       op->words == objs[O_PORT_TAB].words &&
		       !((a[0] ^ n[0]) & ~HW_PT_VID) &&
		       !((a[1] ^ n[1]) & ~(VL_PT1_NNI | (vl_ad ? VL_PT1_TPID_EN : 0))) && a[2] == n[2] &&
		       vl_pt_state_ok(op->idx, a) && vl_pt_state_ok(op->idx, n) &&
		       memcmp(a, n, 4 * op->words);
	case HW_VL_ESP:
		/* 802.1ad only: OUTER_TPID_ENABLE between slot 0 and slot 1, nothing else */
		return vl_ad && bcm5331x_is_front(op->idx) &&
		       op->addr == (QQ_A_EGR_SRC_PORT | op->idx << 12) && op->words == 1 &&
		       !((a[0] ^ n[0]) & ~QQ_ESP_TPID_EN) &&
		       ((vl_esp_ok(a, QQ_SLOT0) && vl_esp_ok(n, QQ_SLOT1)) ||
			(vl_esp_ok(a, QQ_SLOT1) && vl_esp_ok(n, QQ_SLOT0)));
	case HW_VL_EVC1:
		/* 802.1ad only: OUTER_TPID_INDEX between 0 and 1, nothing else */
		return vl_ad && bcm5331x_is_front(op->idx) &&
		       op->addr == obj_addr(&objs[O_EGR_VLAN_CONTROL_1], op->idx) && op->words == 1 &&
		       !((a[0] ^ n[0]) & ~QQ_EVC_TPID_INDEX) &&
		       ((vl_evc1_ok(a, 0) && vl_evc1_ok(n, 1)) || (vl_evc1_ok(a, 1) && vl_evc1_ok(n, 0)));
	case HW_VL_EGR_PORT:
		return bcm5331x_is_front(op->idx) &&
		       op->addr == obj_addr(&objs[O_EGR_PORT], op->idx) && op->words == 1 &&
		       !(a[0] & VL_EP_HIGIG) && n[0] == (a[0] ^ VL_EP_NNI);
	default:
		return false;
	}
}

/* a valid L2_USER_ENTRY below 40 that would take the link-local frames of switch VLAN @hw */
static bool vl_l2u_foreign(u16 hw)
{
	u32 e[HW_L2U_WORDS];
	int i;

	hw_l2u_build_vid(e, hw);
	for (i = 0; i < VL_L2U_FIRST; i++) {
		const u32 *w = hw_l2u_low[i];

		if ((w[0] & 1) && !hw_l2u_drop_only(w) && hw_l2u_overlap(w, e))
			return true;
	}
	return false;
}

/*
 * Before the first member of switch VLAN @hw: the whole L2_USER_ENTRY once
 * (as for hwbridge: 40-63 empty), then no entry below 40 that would take
 * its link-local frames. Called under sw->lock.
 */
static int vl_l2u_ready(struct bcm53314 *sw, struct device *dev, u16 hw)
{
	int err = hw_l2u_check(sw, dev);

	if (err)
		return err;
	if (vl_l2u_foreign(hw)) {
		dev_err(dev, "VLAN-aware bridge: an L2_USER_ENTRY of the boot firmware takes the link-local frames of VLAN %u: refused\n",
			hw);
		bcm5331x_hw_refusals++;
		return -EBUSY;
	}
	return 0;
}

/* tagger: switch VLAN of slot @i with front members @mem */
static void vl_tagger_update(struct dsa_switch *ds, int i, u32 mem)
{
	struct bcm5331x_tagger_data *td = ds->tagger_data;
	u16 hw = vl_hwvid(i), uvid = vl_slot[i].uvid;

	if (!td)
		return;
	if (!mem) {
		WRITE_ONCE(td->vid_uvid[hw], 0);
		WRITE_ONCE(td->uvid_hw[uvid], 0);
		WRITE_ONCE(td->vid_port[hw], 0);
		return;
	}
	WRITE_ONCE(td->vid_port[hw], __builtin_ctz(mem));
	WRITE_ONCE(td->uvid_hw[uvid], hw);
	WRITE_ONCE(td->vid_uvid[hw], uvid);
}

/*
 * Port @port in (@in, untagged @ut) or out of the switch VLAN of slot @i.
 * Called under sw->lock.
 */
static int vl_vlan_apply(struct dsa_switch *ds, int i, int port, bool in, bool ut)
{
	struct bcm53314 *sw = ds->priv;
	const struct sw_obj *ovt = &objs[O_VLAN_TAB], *oev = &objs[O_EGR_VLAN];
	u32 cur = vl_slot[i].mem, cut = vl_slot[i].ut, cpu = hw_cpu_pbm(sw);
	u32 nxt = in ? cur | BIT(port) : cur & ~BIT(port);
	u32 nut = in && ut ? cut | BIT(port) : cut & ~BIT(port);
	u32 l2u[HW_L2U_WORDS], e[HW_L2U_WORDS], w[HW_L2U_WORDS], vt[3], ev[3], x[3];
	u16 hw = vl_hwvid(i);
	int err;

	if (nxt == cur && nut == cut)
		return 0;
	hw_nops = 0;
	if (sw->halted)
		return -EIO;
	if (!cur) {
		err = vl_l2u_ready(sw, ds->dev, hw);
		if (err)
			return err;
	}
	err = hw_read(sw, "L2_USER_ENTRY", HW_L2U_ADDR + VL_L2U_FIRST + i, true, HW_L2U_WORDS,
		      VL_L2U_FIRST + i, l2u);
	if (!err)
		err = sw_read(sw, O_VLAN_TAB, hw, vt);
	if (!err)
		err = sw_read(sw, O_EGR_VLAN, hw, ev);
	if (err)
		return err;
	/* the state the driver left: exactly its entries, or zero */
	hw_l2u_build_vid(e, hw);
	if (cur) {
		vlan_tab_build(x, cur | cpu);
		err = memcmp(l2u, e, sizeof(e)) || ((vt[0] ^ x[0]) | ((vt[1] ^ x[1]) & ~ovt->parity));
		egr_vlan_build(x, cur | cpu, cut);
		err = err || ((ev[0] ^ x[0]) | ((ev[1] ^ x[1]) & ~oev->parity));
	} else {
		err = !hw_zero(l2u, HW_L2U_WORDS, 0) || !hw_zero(vt, 2, ovt->parity) ||
		      !hw_zero(ev, 2, oev->parity);
	}
	if (err) {
		dev_err(ds->dev, "VLAN-aware bridge: VLAN %u (user VID %u), port %d: switch not in the state left by the driver: nothing written\n",
			hw, vl_slot[i].uvid, port);
		bcm5331x_hw_refusals++;
		return -EBUSY;
	}
	memset(w, 0, sizeof(w));
	if (!cur)
		err = hw_add(HW_VL_L2U, "L2_USER_ENTRY", HW_L2U_ADDR + VL_L2U_FIRST + i, true,
			     HW_L2U_WORDS, VL_L2U_FIRST + i, 0, l2u, e);
	if (nxt && (nxt != cur ? in : true)) {
		/* entering (or untagged flag only): egress first, then ingress */
		egr_vlan_build(w, nxt | cpu, nut);
		if (!err)
			err = hw_add(HW_VL_EGR_VLAN, oev->name, obj_addr(oev, hw), true, oev->words, hw,
				     oev->parity, ev, w);
		vlan_tab_build(w, nxt | cpu);
		if (!err && nxt != cur)
			err = hw_add(HW_VL_VLAN_TAB, ovt->name, obj_addr(ovt, hw), true, ovt->words, hw,
				     ovt->parity, vt, w);
	} else {
		/* leaving: ingress first, then egress, entry cleared with the last member */
		if (nxt)
			vlan_tab_build(w, nxt | cpu);
		else
			memset(w, 0, sizeof(w));
		err = hw_add(HW_VL_VLAN_TAB, ovt->name, obj_addr(ovt, hw), true, ovt->words, hw,
			     ovt->parity, vt, w);
		if (nxt)
			egr_vlan_build(w, nxt | cpu, nut);
		else
			memset(w, 0, sizeof(w));
		if (!err)
			err = hw_add(HW_VL_EGR_VLAN, oev->name, obj_addr(oev, hw), true, oev->words, hw,
				     oev->parity, ev, w);
		memset(w, 0, sizeof(w));
		if (!err && !nxt)
			err = hw_add(HW_VL_L2U, "L2_USER_ENTRY", HW_L2U_ADDR + VL_L2U_FIRST + i, true,
				     HW_L2U_WORDS, VL_L2U_FIRST + i, 0, l2u, w);
	}
	if (err)
		return err;
	/* leaving: the tagger stops using the VLAN for this port before the switch does */
	if (nxt != cur && !in)
		vl_tagger_update(ds, i, nxt);
	err = hw_execute(sw, ds->dev);
	if (err)
		return err;
	vl_slot[i].mem = nxt;
	vl_slot[i].ut = nut;
	if (in)
		vl_tagger_update(ds, i, nxt);
	dev_dbg(ds->dev, "VLAN-aware bridge: port %d %s VLAN %u (user VID %u, %d writes)\n",
		port, in ? "in" : "out of", hw, vl_slot[i].uvid, hw_nops);
	return 0;
}

/* Port @port to NNI with PORT_VID @ptvid (@nni) or back to UNI in its own VLAN. Under sw->lock. */
static int vl_port_apply(struct dsa_switch *ds, int port, bool nni, u16 ptvid)
{
	struct bcm53314 *sw = ds->priv;
	const struct sw_obj *opt = &objs[O_PORT_TAB], *oep = &objs[O_EGR_PORT];
	const struct sw_obj *oev = &objs[O_EGR_VLAN_CONTROL_1];
	bool was = vl_nni & BIT(port);
	u16 pv = bcm5331x_port_vid(port), cv = was ? vl_ptvid[port] : pv;
	u32 pt[3], ep[3], w[3], es[HW_L2U_WORDS] = { 0 }, ev[3] = { 0 }, nes, nev;
	u32 a_esp = QQ_A_EGR_SRC_PORT | port << 12;
	int err;

	if (!nni)
		ptvid = pv;
	if (was == nni && cv == ptvid)
		return 0;
	hw_nops = 0;
	if (sw->halted)
		return -EIO;
	err = sw_read(sw, O_PORT_TAB, port, pt);
	if (!err)
		err = sw_read(sw, O_EGR_PORT, port, ep);
	/* 802.1ad: EGR_SRC_PORT and EGR_VLAN_CONTROL_1 of the port as the driver left them too */
	if (!err && vl_ad)
		err = hw_read(sw, "EGR_SRC_PORT", a_esp, false, 1, port, es);
	if (!err && vl_ad)
		err = sw_read(sw, O_EGR_VLAN_CONTROL_1, port, ev);
	if (err)
		return err;
	if (PT_VID(pt) != cv || !!(pt[1] & VL_PT1_NNI) != was || !!(ep[0] & VL_EP_NNI) != was ||
	    !vl_pt_state_ok(port, pt) ||
	    (vl_ad && (!vl_esp_ok(es, was ? QQ_SLOT1 : QQ_SLOT0) || !vl_evc1_ok(ev, was)))) {
		dev_err(ds->dev, "VLAN-aware bridge: port %d: switch not in the state left by the driver: nothing written\n",
			port);
		bcm5331x_hw_refusals++;
		return -EBUSY;
	}
	memcpy(w, pt, sizeof(w));
	ent_set(w, 19, 12, ptvid);
	w[1] = nni ? w[1] | VL_PT1_NNI : w[1] & ~VL_PT1_NNI;
	if (vl_ad)
		w[1] = (w[1] & ~VL_PT1_TPID_EN) | QQ_PUT(VL_PT1_TPID_EN, nni ? QQ_SLOT1 : QQ_SLOT0);
	nes = (es[0] & ~QQ_ESP_TPID_EN) | QQ_PUT(QQ_ESP_TPID_EN, nni ? QQ_SLOT1 : QQ_SLOT0);
	nev = (ev[0] & ~QQ_EVC_TPID_INDEX) | QQ_PUT(QQ_EVC_TPID_INDEX, nni ? 1 : 0);
	if (nni && !was) {
		u32 n = ep[0] | VL_EP_NNI;

		/* egress first (802.1ad: TPID index, source TPID, then NNI), ingress last */
		if (vl_ad)
			err = hw_add(HW_VL_EVC1, oev->name, obj_addr(oev, port), false, 1, port, 0, ev, &nev);
		if (!err && vl_ad)
			err = hw_add(HW_VL_ESP, "EGR_SRC_PORT", a_esp, false, 1, port, 0, es, &nes);
		if (!err)
			err = hw_add(HW_VL_EGR_PORT, oep->name, obj_addr(oep, port), false, 1, port, 0, ep, &n);
		if (!err)
			err = hw_add(HW_VL_PORT_TAB, opt->name, obj_addr(opt, port), true, opt->words,
				     port, 0, pt, w);
	} else {
		err = hw_add(HW_VL_PORT_TAB, opt->name, obj_addr(opt, port), true, opt->words, port,
			     0, pt, w);
		if (!err && !nni) {
			u32 n = ep[0] & ~VL_EP_NNI;

			err = hw_add(HW_VL_EGR_PORT, oep->name, obj_addr(oep, port), false, 1, port, 0,
				     ep, &n);
			if (!err && vl_ad)
				err = hw_add(HW_VL_ESP, "EGR_SRC_PORT", a_esp, false, 1, port, 0, es, &nes);
			if (!err && vl_ad)
				err = hw_add(HW_VL_EVC1, oev->name, obj_addr(oev, port), false, 1, port, 0,
					     ev, &nev);
		}
	}
	if (!err)
		err = hw_execute(sw, ds->dev);
	if (err)
		return err;
	if (nni)
		vl_nni |= BIT(port);
	else
		vl_nni &= ~BIT(port);
	vl_ptvid[port] = nni ? ptvid : 0;
	return 0;
}

/* A port of the bridge starts (@on) or stops forwarding in hardware */
static int vl_member(struct dsa_switch *ds, int port, bool on)
{
	struct bcm53314 *sw = ds->priv;
	int i, err = 0;

	if (!!(vl_fwd & BIT(port)) == on)
		return 0;
	if (access != 2 || dry_run)
		return -EPERM;
	mutex_lock(&sw->lock);
	if (on) {
		vl_fwd |= BIT(port);
		for (i = 0; !err && i < VL_SLOTS; i++)
			if (vl_slot[i].uvid && vl_test(vl_vids[port], vl_slot[i].uvid))
				err = vl_vlan_apply(ds, i, port, true,
						    vl_test(vl_untag[port], vl_slot[i].uvid));
		if (!err)
			err = vl_port_apply(ds, port, true, vl_want_ptvid(port));
	} else {
		vl_fwd &= ~BIT(port);
		err = vl_port_apply(ds, port, false, 0);
		for (i = 0; !err && i < VL_SLOTS; i++)
			if (vl_slot[i].mem & BIT(port))
				err = vl_vlan_apply(ds, i, port, false, false);
	}
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "VLAN-aware bridge: port %d: %s hardware forwarding failed (%d)\n",
			port, on ? "entering" : "leaving", err);
	else
		dev_info(ds->dev, "VLAN-aware bridge: port %d %s hardware forwarding\n", port,
			 on ? "in" : "out of");
	return err;
}

/* number of user VIDs in use by the bridge, plus @uvid if new */
static int vl_slots_needed(u16 uvid)
{
	int i, n = 0;

	for (i = 0; i < VL_SLOTS; i++)
		if (vl_slot[i].uvid)
			n++;
	return n + (vl_slot_of(uvid) < 0);
}

/* Bridge VLAN @vlan added to (or changed on) port @port of the offloaded VLAN-aware bridge */
static int vl_vlan_add(struct dsa_switch *ds, int port, const struct switchdev_obj_port_vlan *vlan,
		       struct netlink_ext_ack *extack)
{
	struct bcm53314 *sw = ds->priv;
	u16 v = vlan->vid, opvid = vl_pvid[port];
	bool ut = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED, was = vl_test(vl_vids[port], v);
	bool out = vl_test(vl_untag[port], v);
	int i, err = 0;

	if (!v || v >= VLAN_N_VID)
		return 0;		/* priority tags: PORT_VID */
	if (vl_reserved(v) && !ut) {
		NL_SET_ERR_MSG_MOD(extack, "VID reserved by the BCM53314 (1, 20, the vid_base block, 4079-4095): untagged only on its ports with vlanbr=1");
		return -EBUSY;
	}
	i = vl_slot_of(v);
	if (i < 0) {
		if (vl_slots_needed(v) > VL_SLOTS) {
			NL_SET_ERR_MSG_MOD(extack, "BCM53314: at most 16 VLANs on the offloaded VLAN-aware bridge");
			return -ENOSPC;
		}
		for (i = 0; vl_slot[i].uvid; i++)
			;
		vl_slot[i].uvid = v;
		vl_slot[i].users = 0;
		vl_slot[i].mem = vl_slot[i].ut = 0;
	}
	if (!was)
		vl_slot[i].users++;
	vl_put(vl_vids[port], v, true);
	vl_put(vl_untag[port], v, ut);
	if (vlan->flags & BRIDGE_VLAN_INFO_PVID)
		vl_pvid[port] = v;
	else if (vl_pvid[port] == v)
		vl_pvid[port] = 0;
	if (!(vl_fwd & BIT(port)))
		return 0;
	if (access != 2 || dry_run)
		err = -EPERM;
	if (!err) {
		mutex_lock(&sw->lock);
		/* the VLAN first, then the PVID (which may point at it) */
		err = vl_vlan_apply(ds, i, port, true, ut);
		if (!err)
			err = vl_port_apply(ds, port, true, vl_want_ptvid(port));
		mutex_unlock(&sw->lock);
	}
	if (err) {
		/* the bridge keeps its old state: so does the driver (what was written stays, read back) */
		vl_put(vl_vids[port], v, was);
		vl_put(vl_untag[port], v, out);
		vl_pvid[port] = opvid;
		if (!was && !--vl_slot[i].users && !vl_slot[i].mem)
			vl_slot[i].uvid = 0;
		NL_SET_ERR_MSG_MOD(extack, "BCM53314: switch write of the VLAN failed");
	}
	return err;
}

static int vl_vlan_del(struct dsa_switch *ds, int port, const struct switchdev_obj_port_vlan *vlan)
{
	struct bcm53314 *sw = ds->priv;
	u16 v = vlan->vid;
	int i = vl_slot_of(v), err = 0;

	if (!v || v >= VLAN_N_VID || i < 0 || !vl_test(vl_vids[port], v))
		return 0;
	if ((vl_slot[i].mem & BIT(port)) && (access != 2 || dry_run))
		return -EPERM;
	/* fdbvlan=Y: the static entries of a slot about to be freed go first */
	if (vl_slot[i].users == 1 && !(vl_slot[i].mem & ~BIT(port)))
		fdb_vl_purge(ds, i);
	vl_put(vl_vids[port], v, false);
	vl_put(vl_untag[port], v, false);
	if (vl_pvid[port] == v)
		vl_pvid[port] = 0;
	if (vl_slot[i].mem & BIT(port)) {
		mutex_lock(&sw->lock);
		/* the PVID first (back to the port VID if it was this VLAN), then the VLAN */
		err = vl_port_apply(ds, port, true, vl_want_ptvid(port));
		if (!err)
			err = vl_vlan_apply(ds, i, port, false, false);
		mutex_unlock(&sw->lock);
	}
	if (!--vl_slot[i].users && !vl_slot[i].mem)
		vl_slot[i].uvid = 0;
	return err;
}

/* the port leaves the bridge: out of the switch VLANs, its user VIDs forgotten */
static void vl_leave(struct dsa_switch *ds, int port)
{
	struct bcm5331x_tagger_data *td = ds->tagger_data;
	int i;

	/* fdbvlan=Y: the static entries of the slots this port is the last user of go first */
	for (i = 0; i < VL_SLOTS; i++)
		if (vl_slot[i].uvid && vl_test(vl_vids[port], vl_slot[i].uvid) &&
		    vl_slot[i].users == 1 && !(vl_slot[i].mem & ~BIT(port)))
			fdb_vl_purge(ds, i);
	if (vl_fwd & BIT(port))
		vl_member(ds, port, false);
	for (i = 0; i < VL_SLOTS; i++)
		if (vl_slot[i].uvid && vl_test(vl_vids[port], vl_slot[i].uvid) &&
		    !--vl_slot[i].users && !vl_slot[i].mem)
			vl_slot[i].uvid = 0;
	memset(vl_vids[port], 0, sizeof(vl_vids[port]));
	memset(vl_untag[port], 0, sizeof(vl_untag[port]));
	vl_pvid[port] = 0;
	if (td)
		WRITE_ONCE(td->port_vaware[port], 0);
}

static void fdb_learn_set(struct dsa_switch *ds, int port, bool learn);
static void mdb_reeval(struct dsa_switch *ds, int num);
static void mdb_port_gone(struct dsa_switch *ds, int port, int num);
static void mdb_bridge_gone(struct dsa_switch *ds, int num);
/* brflags=Y: flags of the ports of offloaded bridges, see "Bridge port flags" */
static bool brflags;
static u32 fl_nolearn;			/* front ports with BR_LEARNING off */
static u8 fl_stp[NUM_PORTS];		/* last STP state of each port of an offloaded bridge */
static void fl_leave(struct dsa_switch *ds, int port);
static void fl_teardown(struct dsa_switch *ds);
static void fl_fwd_set(struct dsa_switch *ds, int port, bool on);

/* ---------------------------------------------------------------------- */
/* 802.1ad bridges (refused, no switch write)                              */

/*
 * Bridge of each front port (any mode), from port_bridge_join to
 * port_bridge_leave: the 802.1ad checks below need it.
 */
static const struct net_device *port_br_dev[NUM_PORTS];

/*
 * VLAN-aware bridges with the 802.1ad protocol: refused. The switch, the
 * tagger and vlanbr know only 802.1Q tags on the front ports (0x88a8 is
 * the outer tag of the CPU link with qinq), and the bridge's protocol
 * change reaches no DSA driver (SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL is
 * not passed on, net/dsa/user.c dsa_user_port_attr_set). Checked when a
 * port joins a VLAN-aware bridge, when VLAN filtering is turned on and
 * when a VLAN is added to a port of a VLAN-aware bridge. Known limit: a
 * VLAN-aware bridge whose protocol is changed to 802.1ad once its ports
 * have joined keeps the VLANs it had (the change is not seen here); only
 * later VLANs are refused. A front port that becomes a user port later
 * (MGMT, mgmt=1) has no hardware statistics until st_idx() lists it: its
 * net device counters stay those of the DSA core (get_stats64).
 */
static unsigned long bcm5331x_ad_refusals;

static bool bcm5331x_br_ad(const struct net_device *br)
{
	u16 proto;

	return br && !br_vlan_get_proto(br, &proto) && proto == ETH_P_8021AD;
}

/*
 * vlanbr_ad=Y: a front port may join an 802.1ad VLAN-aware bridge @num if
 * that bridge is (or becomes, as the first VLAN-aware bridge offloaded)
 * the offloaded one in 802.1ad mode; any other 802.1ad bridge is refused
 * as before (no software 802.1ad over these ports).
 */
static bool vl_ad_join_ok(int num)
{
	if (!vlanbr_ad || !vlanbr || !hwbridge || !qinq_on || num < 1 || num > BCM5331X_BR_MAX)
		return false;
	if (!hw_br_users[num])
		return !vl_br;
	return vl_br == num && vl_ad && hw_br_mode[num] == HW_BR_VLAN;
}

static int bcm5331x_ad_refuse(struct netlink_ext_ack *extack)
{
	bcm5331x_ad_refusals++;
	NL_SET_ERR_MSG_MOD(extack,
			   "802.1ad VLAN-aware bridges are not supported on the BCM53314 ports (802.1Q only)");
	return -EINVAL;
}

/*
 * Mode of bridge @num at the join of a front port: its own once it has
 * ports, else the one its first port fixes (no side effect).
 */
static int hw_br_join_mode(struct dsa_bridge bridge, int num)
{
	int mode;

	if (hw_br_users[num])
		return hw_br_mode[num];
	mode = br_vlan_enabled(bridge.dev) ? HW_BR_SOFT : HW_BR_HW;
	/* vlanbr=Y: the first VLAN-aware bridge is offloaded too (one only) */
	if (mode == HW_BR_SOFT && vlanbr && qinq_on && !vl_br)
		mode = HW_BR_VLAN;
	return mode;
}

/*
 * A front port joins a bridge. Software bridge (as without hwbridge, no
 * write, tx_fwd_offload false) unless hwbridge=Y, a bridge number 1-8 and
 * a VLAN-unaware bridge; the mode is the bridge's, fixed by its first port
 * (a later change of vlan_filtering does not move it: see
 * port_vlan_filtering). Hardware mode writes nothing here: the port enters
 * the bridge VLAN when DSA sets its STP state to forwarding, right after.
 */
static int bcm5331x_dsa_port_bridge_join(struct dsa_switch *ds, int port,
					 struct dsa_bridge bridge,
					 bool *tx_fwd_offload,
					 struct netlink_ext_ack *extack)
{
	int num = bridge.num, mode;

	*tx_fwd_offload = false;
	/*
	 * MGMT under hwbridge: never in a bridge VLAN. -EOPNOTSUPP makes DSA
	 * leave it out of the switch's forwarding domain (net/dsa/user.c
	 * dsa_user_changeupper: software bridging), so the bridge forwards to
	 * it the frames the switch already forwarded among the other members.
	 */
	if (hwbridge && port == PORT_MGMT) {
		NL_SET_ERR_MSG_MOD(extack, "mgmt: software bridging only");
		return -EOPNOTSUPP;
	}
	if (bcm5331x_is_front(port) && br_vlan_enabled(bridge.dev) && bcm5331x_br_ad(bridge.dev) &&
	    !vl_ad_join_ok(num))
		return bcm5331x_ad_refuse(extack);
	/*
	 * lagf with vlanbr: the trunk group is written by
	 * the bridge VLAN path (hw_member) only, not by the VLAN-aware one
	 * (vl_member). A hardware LAG of front ports in a VLAN-aware bridge
	 * that vlanbr could offload is left to software bridging (DSA falls
	 * back on -EOPNOTSUPP); a VLAN-unaware bridge is offloaded as before.
	 */
	if (lagf && vlanbr && lg_of(port) >= 0 && br_vlan_enabled(bridge.dev)) {
		bcm5331x_lagf_vlanbr_refusals++;
		NL_SET_ERR_MSG_MOD(extack, "lagf: hardware LAG in a VLAN-aware bridge: software bridging");
		return -EOPNOTSUPP;
	}
	if (port >= 0 && port < NUM_PORTS)
		port_br_dev[port] = bridge.dev;
	if (!hwbridge || !bcm5331x_is_front(port) || num < 1 || num > BCM5331X_BR_MAX)
		return 0;
	mode = hw_br_join_mode(bridge, num);
	/*
	 * llproto: the VLANs by protocol before the first port forwards in
	 * hardware; refused, the bridge is left to software bridging (DSA
	 * falls back on -EOPNOTSUPP, no leave follows: nothing kept here).
	 */
	if (llproto && !ll_users && (mode == HW_BR_HW || mode == HW_BR_VLAN) && ll_set(ds, true)) {
		port_br_dev[port] = NULL;
		NL_SET_ERR_MSG_MOD(extack, "llproto: link-local protocol VLANs not written, software bridging");
		return -EOPNOTSUPP;
	}
	if (!hw_br_users[num]) {
		hw_br_mode[num] = mode;
		if (mode == HW_BR_VLAN) {
			struct bcm5331x_tagger_data *td = ds->tagger_data;

			vl_br = num;
			/* the protocol of the bridge, read once (vlanbr_ad=Y; else refused above) */
			vl_ad = bcm5331x_br_ad(bridge.dev);
			if (td)
				WRITE_ONCE(td->vaware_ad, vl_ad);
		}
	}
	hw_br_users[num]++;
	if (hw_br_mode[num] == HW_BR_VLAN) {
		struct bcm5331x_tagger_data *td = ds->tagger_data;

		hw_port_br[port] = num;
		ll_users++;
		if (td)
			WRITE_ONCE(td->port_vaware[port], 1);
		*tx_fwd_offload = true;
		return 0;
	}
	if (hw_br_mode[num] != HW_BR_HW)
		return 0;
	hw_port_br[port] = num;
	ll_users++;
	*tx_fwd_offload = true;
	return 0;
}

static void bcm5331x_dsa_port_bridge_leave(struct dsa_switch *ds, int port,
					   struct dsa_bridge bridge)
{
	int num = bridge.num;

	if (port >= 0 && port < NUM_PORTS && port_br_dev[port] == bridge.dev)
		port_br_dev[port] = NULL;
	if (!hwbridge || !bcm5331x_is_front(port) || num < 1 || num > BCM5331X_BR_MAX ||
	    !hw_br_users[num])
		return;
	/* brflags=Y: the port's flood and isolation bits go first, while it is still a member */
	if (hw_port_br[port] == num)
		fl_leave(ds, port);
	if (hw_port_br[port] == num && hw_br_mode[num] == HW_BR_VLAN) {
		vl_leave(ds, port);
		hw_port_br[port] = 0;
		/* fdbvlan=Y: learning as found, the port standalone again */
		fdb_learn_set(ds, port, true);
		ll_leave(ds);
	} else if (hw_port_br[port] == num) {
		if (hw_br_fwd[num] & BIT(port))
			hw_member(ds, port, num, false);
		hw_port_br[port] = 0;
		hw_tagger_update(ds, num);
		/* fdb=Y: learning as found, the port standalone again */
		fdb_learn_set(ds, port, true);
		/* mdb=Y: its groups lose it, the others follow the designated port */
		mdb_port_gone(ds, port, num);
		mdb_reeval(ds, num);
		ll_leave(ds);
	}
	if (!--hw_br_users[num]) {
		mdb_bridge_gone(ds, num);
		if (num == vl_br) {
			struct bcm5331x_tagger_data *td = ds->tagger_data;

			vl_br = 0;
			vl_ad = false;
			if (td)
				WRITE_ONCE(td->vaware_ad, 0);
		}
		hw_br_mode[num] = HW_BR_NONE;
	}
}

/*
 * STP state of a port in hardware mode: member of the bridge VLAN when
 * forwarding, standalone otherwise (see above). A port of a software bridge
 * or without bridge: nothing (the software bridge applies the state).
 * fdb=Y: no hardware learning in the disabled, blocking and listening
 * states (see "Learning of the ports of offloaded bridges"), turned off
 * before the port leaves the bridge VLAN, back on after it entered it or
 * at the learning state; the same for the VLAN-aware bridge with
 * fdbvlan=Y, around its switch VLANs. DSA ages the port's addresses (port_fast_age)
 * right after this call.
 */
static void bcm5331x_dsa_port_stp_state_set(struct dsa_switch *ds, int port,
					    u8 state)
{
	int num = hw_port_br[port < NUM_PORTS && port >= 0 ? port : 0];
	bool fwd = state == BR_STATE_FORWARDING, learn = fwd || state == BR_STATE_LEARNING;

	if (!hwbridge || port < 0 || port >= NUM_PORTS || !num)
		return;
	/* brflags=Y: BR_LEARNING off keeps the port from learning in any state */
	fl_stp[port] = state;
	if (fl_nolearn & BIT(port))
		learn = false;
	if (hw_br_mode[num] == HW_BR_VLAN) {
		/* fdbvlan=Y: learning as for hwbridge (nothing with fdbvlan=N) */
		if (!learn)
			fdb_learn_set(ds, port, false);
		/* brflags=Y: flag bits out before the port leaves the switch VLANs, back after */
		if (!fwd)
			fl_fwd_set(ds, port, false);
		vl_member(ds, port, fwd);
		if (fwd)
			fl_fwd_set(ds, port, true);
		if (learn)
			fdb_learn_set(ds, port, true);
		return;
	}
	if (!learn)
		fdb_learn_set(ds, port, false);
	if (!fwd)
		fl_fwd_set(ds, port, false);
	hw_member(ds, port, num, fwd);
	if (fwd)
		fl_fwd_set(ds, port, true);
	if (learn)
		fdb_learn_set(ds, port, true);
	/* mdb=Y: the designated port may have moved */
	mdb_reeval(ds, num);
}

/* fdb=N: nothing to age (the switch ages its own entries, L2_AGE_TIMER) */
static void bcm5331x_dsa_port_fast_age(struct dsa_switch *ds, int port)
{
}

/* ---------------------------------------------------------------------- */
/* Address table of offloaded bridges (fdb=Y)                              */

/*
 * With hwbridge=Y the switch learns by itself in each bridge VLAN (VID
 * 141-148, independent VLAN learning of step "learning"). fdb=Y adds the
 * address-table operations of DSA on those bridges, all on the L2 table
 * L2X (IPIPE 0x06700000 + index, 8192 entries of 3 words, OpenMDK
 * bcm53314_a0_defs.h L2Xm: MAC_ADDR 47:0, VLAN_ID 59:48, PORT_TGID 73:67
 * (T 73, TGID 72:67), MODULE_ID 77:74, STATIC_BIT 85, VALID 88, EVEN_PARITY
 * 90, HITDA 91, HITSA 92):
 *  - port_fdb_add/del: a static entry {MAC, bridge VID} -> front port of
 *    the bridge (bridge fdb ... master static), or -> the host, ge2 (the
 *    trunk group 7 {ge2, ge3} under step trunk2), for the host addresses
 *    of the bridge (bridge and port MAC addresses, ds->fdb_isolation: one
 *    database per bridge). Written by the switch's own hash insert and
 *    delete (S-channel ARL_INSERT 0x0f / ARL_DELETE 0x11 with the entry, no
 *    address: OpenMDK bcm53314_a0_bmd_port_mac_addr_add.c l. 26-54,
 *    _remove.c l. 26-53; reply as OpenBCM src/soc/esw/l2x.c
 *    soc_fb_l2x_bank_insert/_delete l. 2661-2866: index of the entry at bits
 *    105:93 of the reply, OP_FAIL 106 = bucket full / not found, MODFIFO
 *    full 107, parity bitmap 115:108), never by an indexed write: the
 *    Hawkeye hashes L2X twice (soc_feature_dual_hash, OpenBCM
 *    src/soc/common/feature.c l. 1715; banks of 4 entries of a bucket of 8,
 *    HASH_CONTROL / L2_AUX_HASH_CONTROL), so the switch picks the slot, the
 *    driver never computes the hash, and an indexed write could not avoid
 *    racing the hardware learning of the same bucket. Each insert is read
 *    back at the index of the reply (hardware bits 92:90 ignored); each
 *    delete checks that the entry at the reply's index no longer holds the
 *    key. Bucket full: -ENOSPC, nothing written (refusal, not a fault).
 *    Host addresses of a software bridge, or of a standalone port (port
 *    VLAN {port, ge2}: every frame already goes to the host), are accepted
 *    without any write; a static entry on a port of a software bridge is
 *    refused (-EOPNOTSUPP: the software bridge forwards).
 *  - port_fast_age of a port of an offloaded bridge (DSA calls it when the
 *    port leaves the learning/forwarding states, hence also when it leaves
 *    the bridge): the switch's per-port ageing (PER_PORT_AGE_CONTROL IPIPE
 *    0x00780004: TGID_PORT 6:0, MODULE_ID 10:7, VLAN_ID 22:11, PPA_MODE
 *    25:23 = 0 delete by port, EXCL_STATIC 26, START 27, COMPLETE 28) as
 *    OpenBCM src/bcm/esw/firebolt/l2.c _bcm_fb_age_reg_config l. 977-994
 *    and src/soc/esw/l2x.c soc_l2x_port_age l. 1389-1530: the fields are
 *    written with START clear, then START set, COMPLETE polled; ageing
 *    (L2_AGE_TIMER IPIPE 0x00780003, AGE_ENA 20, AGE_VAL 19:0) is turned off
 *    around it, as "the chip requires" (l2x.c l. 1384) and restored. Static
 *    entries are kept. Learning is not frozen (the SDK also freezes the
 *    learning of every port, for its software shadow table, which this
 *    driver does not keep: an address learnt during the operation is
 *    either deleted or kept, both harmless).
 *  - port_fdb_dump: L2X read entry by entry (8192 S-channel reads, about
 *    0.1 s, in chunks with the lock released in between), kept one second
 *    for the dumps of the other ports (bridge fdb show), reported with VID
 *    0 (VLAN-unaware bridges), for the entries of the port in its own VLAN
 *    or its bridge VLAN.
 * Every write is planned on what is read, checked against fixed rules
 * (fdb_entry_ok, fdb_reg_ok), the registers re-read before, written and
 * read back; a mismatch halts the base module. The driver keeps the static
 * entries it wrote (with a reference count per key, two CPU ports may add
 * the same host address) and deletes those left at teardown. fdb=N: none
 * of these operations exists (DSA as before), nothing new is read or
 * written. With fdb=Y, fdbvlan=Y (and vlanbr=Y) extends the entries and
 * the learning rule to the VLAN-aware bridge (fdb_vl_key, fdb_vl_purge),
 * ageing=Y adds the ageing time (L2_AGE_TIMER.AGE_VAL); both default N.
 */
#define FDB_L2X_ADDR		0x06700000	/* IPIPE L2X, + index */
#define FDB_L2X_NUM		8192
#define FDB_L2X_WORDS		3
#define FDB_A_AGE_TIMER		0x00780003	/* IPIPE L2_AGE_TIMER */
#define FDB_A_PPA		0x00780004	/* IPIPE PER_PORT_AGE_CONTROL */
#define FDB_A_AUX_HASH		0x0678000c	/* IPIPE L2_AUX_HASH_CONTROL (read, debugfs) */
#define FDB_AGE_VAL		GENMASK(19, 0)
#define FDB_AGE_ENA		BIT(20)
#define FDB_PPA_TGID_PORT	GENMASK(6, 0)
#define FDB_PPA_EXCL_STATIC	BIT(26)
#define FDB_PPA_START		BIT(27)
#define FDB_PPA_COMPLETE	BIT(28)
#define FDB_PPA_FIELDS		GENMASK(26, 0)
#define FDB_PPA_POLL_US		1000000		/* port ageing scans 8192 entries */
/* L2X word 2 (bits 95:64) */
#define L2X_W2_PORT_TGID	GENMASK(9, 3)	/* 73:67 */
#define L2X_W2_STATIC		BIT(21)		/* 85 */
#define L2X_W2_VALID		BIT(24)		/* 88 */
#define L2X_W2_HW		GENMASK(28, 26)	/* 92:90 EVEN_PARITY, HITDA, HITSA: hardware */
#define L2X_W2_MODULE		GENMASK(13, 10)	/* 77:74 */
#define L2X_TGID_T		BIT(6)		/* PORT_TGID: T, trunk group */
#define L2X_DEST_TRUNK2		(L2X_TGID_T | TRUNK2_TGID)
/* reply of an insert/delete: data word 3 (bits 127:96) */
#define ARL_R_OP_FAIL		BIT(10)		/* 106 */
#define ARL_R_MFIFO_FULL	BIT(11)		/* 107 */
#define ARL_R_PERR		GENMASK(19, 12)	/* 115:108 */
#define FDB_MAX			256		/* static entries kept by the driver */
#define FDB_DUMP_CHUNK		256		/* L2X reads per hold of the lock */
#define FDB_DUMP_KEEP_US	1000000

static bool fdb;
/* static entries written by the driver */
static struct fdb_ent {
	u8 mac[ETH_ALEN];
	u16 vid;
	u8 dest;		/* PORT_TGID */
	int refs;		/* 0 = free slot */
	int index;		/* L2X index of the reply */
} fdb_tab[FDB_MAX];
/* driver-visible counters (debugfs) */
static unsigned long bcm5331x_fdb_inserts, bcm5331x_fdb_deletes, bcm5331x_fdb_age_writes,
		     bcm5331x_fdb_refusals, bcm5331x_fdb_l2x_reads;
/* L2X scan kept for the dumps of the other ports */
struct fdb_scan_ent {
	u8 mac[ETH_ALEN];
	u16 vid;
	u8 dest;
	u8 is_static;
};
static struct fdb_scan_ent *fdb_scan;
static int fdb_scan_n;
static bool fdb_scan_valid;
static ktime_t fdb_scan_end;

/*
 * Learning of the ports of offloaded bridges (fdb=Y). The switch learns on
 * every front port (PORT_TAB.CML 0 after the set-up) and this driver writes
 * no STP state (no STG): a port of an offloaded bridge that is disabled,
 * blocking or listening is only out of the bridge VLAN, and it still learnt
 * the source of every frame it received. After the per-port ageing that
 * DSA asks for at the change of state (port_fast_age), the address of the
 * far end came back on the blocked port within two seconds (the BPDU
 * of the link partner, every 2 s). IEEE
 * 802.1D learns in the learning and forwarding states only.
 *
 * Such a port gets CML 2 ("!learn ARL, !CPU, forward" on a source lookup
 * failure: PVP_CML_FORWARD, OpenBCM include/soc/ptable.h; values of the
 * Firebolt class this chip belongs to, bcm_esw_port_learn_set,
 * src/bcm/esw/port.c, not the TRX encoding; CML = PORT_TAB bits 7:5,
 * OpenMDK bcm53314_a0_defs.h PORT_TABm_CMLf). Its frames still go to the
 * host in its own port VLAN {port, ge2}, where the software bridge drops
 * what a blocked port must drop and keeps the BPDU it needs; CML 3 (drop)
 * would lose the BPDU too, CML 1 (to the CPU) sends them to the CMIC, not
 * to the host. The value found is restored in the learning and forwarding
 * states and when the port leaves the bridge; a port found not learning
 * (CML other than 0 or 4) is left alone. One PORT_TAB write, CML only,
 * re-read before (CML 2 expected when turning learning back on: otherwise
 * refused, nothing written) and read back. Ports of the VLAN-aware bridge
 * (vlanbr=Y) are concerned with fdbvlan=Y only (the same rule, around the
 * switch VLANs of the port).
 */
#define FDB_CML_NOLEARN		2	/* PVP_CML_FORWARD */
static u32 fdb_nolearn;			/* front ports whose learning the driver turned off */
static u8 fdb_cml_found[NUM_PORTS];	/* their CML as found */

/* bridges whose ports learn by STP state: offloaded VLAN-unaware ones, the VLAN-aware one with fdbvlan=Y */
static bool fdb_learn_br(int num)
{
	return num > 0 && num <= BCM5331X_BR_MAX &&
	       (hw_br_mode[num] == HW_BR_HW || (fdbvlan && hw_br_mode[num] == HW_BR_VLAN));
}

/* CML values that learn: PVP_CML_SWITCH 0, PVP_CML_CPU_SWITCH 4 */
static bool fdb_cml_learns(u32 cml)
{
	return cml == 0 || cml == 4;
}

/* The one change of a learning write: CML only, off from a learning value, back to the value found */
static bool fdb_cml_op_ok(const struct hw_op *op)
{
	const u32 *a = op->old, *n = op->val;
	u32 ca = QQ_GET(HW_PT_CMLF, a[0]), cn = QQ_GET(HW_PT_CMLF, n[0]);
	int p = op->idx;

	if (!fdb || p < 0 || p >= NUM_PORTS || !bcm5331x_is_front(p) ||
	    op->addr != obj_addr(&objs[O_PORT_TAB], p) || op->words != objs[O_PORT_TAB].words ||
	    ((a[0] ^ n[0]) & ~HW_PT_CMLF) || a[1] != n[1] || a[2] != n[2])
		return false;
	if (!(fdb_nolearn & BIT(p)))
		return fdb_cml_learns(ca) && cn == FDB_CML_NOLEARN && ca == fdb_cml_found[p] &&
		       fdb_learn_br(hw_port_br[p]);
	return ca == FDB_CML_NOLEARN && cn == fdb_cml_found[p] && fdb_cml_learns(cn);
}

/* learning of front port @port off (@learn false) or back as found; no lock held */
static void fdb_learn_set(struct dsa_switch *ds, int port, bool learn)
{
	struct bcm53314 *sw = ds->priv;
	const struct sw_obj *opt = &objs[O_PORT_TAB];
	bool off, wrote = false;
	u32 pt[3], w[3], cml = 0, to = 0;
	int err;

	if (!fdb || port < 0 || port >= NUM_PORTS || !bcm5331x_is_front(port))
		return;
	off = fdb_nolearn & BIT(port);
	if (off == !learn)
		return;		/* already so */
	if (!learn && !fdb_learn_br(hw_port_br[port]))
		return;		/* software bridge, or VLAN-aware without fdbvlan: not ours */
	if (access != 2 || dry_run)
		return;
	mutex_lock(&sw->lock);
	hw_nops = 0;
	err = sw->halted ? -EIO : sw_read(sw, O_PORT_TAB, port, pt);
	if (err)
		goto out;
	cml = QQ_GET(HW_PT_CMLF, pt[0]);
	if (!off && !fdb_cml_learns(cml))
		goto out;	/* found not learning: left alone */
	if (off && cml != FDB_CML_NOLEARN) {
		dev_err(ds->dev, "fdb: port %d: PORT_TAB CML %u, not the %u the driver left: nothing written\n",
			port, cml, FDB_CML_NOLEARN);
		bcm5331x_fdb_refusals++;
		err = -EBUSY;
		goto out;
	}
	to = off ? fdb_cml_found[port] : FDB_CML_NOLEARN;
	if (!off)
		fdb_cml_found[port] = cml;
	memcpy(w, pt, sizeof(w));
	w[0] = (w[0] & ~HW_PT_CMLF) | QQ_PUT(HW_PT_CMLF, to);
	err = hw_add(HW_PT_CML, opt->name, obj_addr(opt, port), true, opt->words, port, 0, pt, w);
	if (!err)
		err = hw_execute(sw, ds->dev);
	if (!err) {
		fdb_nolearn ^= BIT(port);
		wrote = true;
	}
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "fdb: port %d: learning %s failed (%d)\n", port, learn ? "on" : "off", err);
	else if (wrote)
		dev_info(ds->dev, "fdb: port %d: learning %s (PORT_TAB CML %u -> %u, 1 write, read back)\n",
			 port, learn ? "on" : "off", cml, to);
}

module_param(fdb, bool, 0444);
MODULE_PARM_DESC(fdb, "Address table of offloaded bridges (needs hwbridge=1): static entries by the switch's L2 insert/delete, per-port ageing on STP changes, dump of the L2 table (switch writes at run time, read back; default N = no address-table operation, no write)");
module_param(fdbvlan, bool, 0444);
MODULE_PARM_DESC(fdbvlan, "With fdb=1 and vlanbr=1: static and host entries of the offloaded VLAN-aware bridge keyed by the switch VLAN of their VID, its ports' learning by STP state, dump with the user VID (switch writes at run time, read back; default N = its entries refused as before)");
module_param(ageing, bool, 0444);
MODULE_PARM_DESC(ageing, "With fdb=1: the bridge ageing time (1-1048575 s, the shortest of the bridges, as DSA programs it) written to L2_AGE_TIMER.AGE_VAL, read back, the value found restored at teardown (default N = left as found, 300 s after the boot firmware)");

static void l2x_build(u32 *w, const unsigned char *mac, u16 vid, u8 dest)
{
	w[0] = (u32)mac[2] << 24 | (u32)mac[3] << 16 | (u32)mac[4] << 8 | mac[5];
	w[1] = (u32)mac[0] << 8 | mac[1] | (u32)vid << 16;
	w[2] = (u32)dest << 3 | L2X_W2_STATIC | L2X_W2_VALID;
}

static void l2x_mac(const u32 *w, u8 *mac)
{
	mac[0] = w[1] >> 8; mac[1] = w[1]; mac[2] = w[0] >> 24;
	mac[3] = w[0] >> 16; mac[4] = w[0] >> 8; mac[5] = w[0];
}

/* key {MAC, VLAN_ID} of two entries (bits 59:0) */
static bool l2x_same_key(const u32 *a, const u32 *b)
{
	return a[0] == b[0] && !((a[1] ^ b[1]) & GENMASK(27, 0));
}

/* host destination: ge2, or trunk group 7 {ge2, ge3} under step trunk2 */
static u8 fdb_host_dest(const struct bcm53314 *sw)
{
	return sw->trunk2 ? L2X_DEST_TRUNK2 : PORT_TRUNK;
}

static bool mdb_entry_ok(const struct bcm53314 *sw, const u32 *w);
/* the form of every entry the driver writes: valid, static, unicast MAC, module 0, no other bit */
static bool fdb_entry_form(const u32 *w)
{
	return !(w[1] & GENMASK(31, 28)) &&
	       !(w[2] & ~(L2X_W2_PORT_TGID | L2X_W2_STATIC | L2X_W2_VALID)) &&
	       (w[2] & L2X_W2_STATIC) && (w[2] & L2X_W2_VALID) && !(w[1] & BIT(8));
}

/*
 * fdbvlan=Y: an entry of the offloaded VLAN-aware bridge: switch VLAN of a
 * slot in use, destination the host or a front port (@insert: a port of the
 * bridge with that user VID; a delete also takes the entry of a port that
 * dropped the VID or left, which the driver wrote and still keeps).
 */
static bool fdb_vl_entry_ok(const struct bcm53314 *sw, const u32 *w, bool insert)
{
	u16 vid = (w[1] >> 16) & 0xfff;
	u8 dest = (w[2] & L2X_W2_PORT_TGID) >> 3;
	int i = vl_slot_of_hw(vid);

	if (!fdbvlan || !fdb_entry_form(w) || !vl_br || hw_br_mode[vl_br] != HW_BR_VLAN || i < 0)
		return false;
	if (dest == fdb_host_dest(sw))
		return true;
	if (dest >= NUM_PORTS || !bcm5331x_is_front(dest))
		return false;
	return !insert || (vl_port(dest) && vl_test(vl_vids[dest], vl_slot[i].uvid));
}

/*
 * The one kind of entry the driver writes: valid, static, unicast MAC,
 * bridge VID of an offloaded bridge, destination a forwarding-capable
 * member of that bridge or the host; every other bit zero. fdbvlan=Y: or
 * an entry of the VLAN-aware bridge (fdb_vl_entry_ok).
 */
static bool fdb_entry_ok(const struct bcm53314 *sw, const u32 *w)
{
	u16 vid = (w[1] >> 16) & 0xfff;
	u8 dest = (w[2] & L2X_W2_PORT_TGID) >> 3;
	int num = vid - BCM5331X_BR_VID_FIRST + 1;

	if (!fdb_entry_form(w))
		return false;
	if (num < 1 || num > BCM5331X_BR_MAX || hw_br_mode[num] != HW_BR_HW)
		return fdb_vl_entry_ok(sw, w, true);
	if (dest == fdb_host_dest(sw))
		return true;
	return dest < NUM_PORTS && bcm5331x_is_front(dest) && hw_port_br[dest] == num;
}

/*
 * One L2X insert or delete by the switch (under sw->lock): the message is
 * armed word for word (base module, cmic_write_allowed), sent, and the reply
 * read: header (DONE opcode of the command, no error bit) and four data
 * words. *nack: the switch did not do it (OP_FAIL & co. in rep[3]).
 */
static int fdb_arl(struct bcm53314 *sw, bool insert, const u32 *e, u32 *rep, bool *nack)
{
	u32 ctrl, hdr;
	int err, werr, i;

	*nack = false;
	if (access != 2 || dry_run)
		return -EPERM;
	err = cmic_rd(sw, CMIC_SCHAN_CTRL, &ctrl);
	if (err)
		return err;
	if (ctrl & SC_MSG_BUSY) {
		sw_fault(sw, "S-channel busy (0x%08x)", ctrl);
		return -EBUSY;
	}
	sw->arl_msg[0] = schan_header(insert ? OP_ARL_INSERT : OP_ARL_DELETE, FDB_L2X_ADDR,
				      4 * FDB_L2X_WORDS);
	memcpy(&sw->arl_msg[1], e, 4 * FDB_L2X_WORDS);
	sw->arl_armed = true;
	for (i = 0; !err && i < ARL_MSG_WORDS; i++)
		err = cmic_wr(sw, CMIC_SCHAN_MSG + 4 * i, sw->arl_msg[i]);
	sw->arl_armed = false;
	if (!err)
		err = cmic_wr(sw, CMIC_SCHAN_CTRL, SC_MSG_START_SET);
	if (err)
		return err;
	werr = cmic_wait(sw, SC_MSG_DONE, SCHAN_TIMEOUT_US, &ctrl);
	err = cmic_wr(sw, CMIC_SCHAN_CTRL, SC_MSG_DONE_CLR);
	if (werr || err || (ctrl & SC_MSG_TIMEOUT)) {
		sw_fault(sw, "L2X %s: %s (0x%08x)", insert ? "insert" : "delete",
			 werr ? "no answer" : "timeout", ctrl);
		return -EIO;
	}
	err = cmic_rd(sw, CMIC_SCHAN_MSG, &hdr);
	for (i = 0; !err && i < 4; i++)
		err = cmic_rd(sw, CMIC_SCHAN_MSG + 4 + 4 * i, &rep[i]);
	if (err)
		return err;
	if (hdr >> 26 != (insert ? OP_ARL_INSERT_DONE : OP_ARL_DELETE_DONE) || (hdr & BIT(6))) {
		sw_fault(sw, "L2X %s: bad reply 0x%08x", insert ? "insert" : "delete", hdr);
		return -EIO;
	}
	*nack = (ctrl & SC_MSG_NAK) || (hdr & BIT(0));
	err = cmic_rd(sw, CMIC_SCHAN_CTRL, &ctrl);
	if (err)
		return err;
	if (ctrl & SC_MSG_BUSY) {
		sw_fault(sw, "S-channel status 0x%08x after completion", ctrl);
		return -EIO;
	}
	return 0;
}

static int fdb_l2x_read(struct bcm53314 *sw, int idx, u32 *w)
{
	memset(w, 0, 4 * FDB_L2X_WORDS);
	bcm5331x_fdb_l2x_reads++;
	return schan_xfer(sw, false, true, FDB_L2X_ADDR + idx, FDB_L2X_WORDS, w, "L2X", idx);
}

/* index of the entry in a reply (bits 105:93), 0-8191 */
static int arl_rep_index(const u32 *rep)
{
	return ((rep[2] >> 29) | rep[3] << 3) & (FDB_L2X_NUM - 1);
}

/* refused or failed reply: -ENOSPC/-ENOENT (OP_FAIL), -EBUSY (MODFIFO), else a fault */
static int arl_rep_fail(struct bcm53314 *sw, bool insert, const u32 *rep)
{
	if (rep[3] & ARL_R_PERR) {
		sw_fault(sw, "L2X %s: parity error, bucket bitmap 0x%02lx", insert ? "insert" : "delete",
			 (unsigned long)((rep[3] & ARL_R_PERR) >> 12));
		return -EIO;
	}
	if (rep[3] & ARL_R_OP_FAIL)
		return insert ? -ENOSPC : -ENOENT;
	if (rep[3] & ARL_R_MFIFO_FULL)
		return -EBUSY;
	sw_fault(sw, "L2X %s: refused without a cause (0x%08x)", insert ? "insert" : "delete", rep[3]);
	return -EIO;
}

/* insert @e, read back at the index of the reply (under sw->lock) */
static int fdb_insert(struct bcm53314 *sw, const u32 *e, int *index)
{
	u32 rep[4] = { 0 }, rb[FDB_L2X_WORDS];
	bool nack;
	int err, idx;

	if (!fdb_entry_ok(sw, e) && !mdb_entry_ok(sw, e)) {
		bcm5331x_fdb_refusals++;
		return -EPERM;
	}
	err = fdb_arl(sw, true, e, rep, &nack);
	if (err)
		return err;
	bcm5331x_fdb_inserts++;
	if (nack)
		return arl_rep_fail(sw, true, rep);
	idx = arl_rep_index(rep);
	err = fdb_l2x_read(sw, idx, rb);
	if (err)
		return err;
	if (rb[0] != e[0] || rb[1] != e[1] || (rb[2] & ~L2X_W2_HW) != e[2]) {
		sw_fault(sw, "L2X[%d] reads %08x %08x %08x after insert of %08x %08x %08x", idx,
			 rb[0], rb[1], rb[2], e[0], e[1], e[2]);
		return -EIO;
	}
	*index = idx;
	return 0;
}

/* delete the key of @e, then the entry at the reply's index must not hold it */
static int fdb_delete(struct bcm53314 *sw, const u32 *e)
{
	u32 rep[4] = { 0 }, rb[FDB_L2X_WORDS];
	bool nack;
	int err, idx;

	if (!fdb_entry_ok(sw, e) && !mdb_entry_ok(sw, e) && !fdb_vl_entry_ok(sw, e, false)) {
		bcm5331x_fdb_refusals++;
		return -EPERM;
	}
	err = fdb_arl(sw, false, e, rep, &nack);
	if (err)
		return err;
	bcm5331x_fdb_deletes++;
	if (nack)
		return arl_rep_fail(sw, false, rep);
	idx = arl_rep_index(rep);
	err = fdb_l2x_read(sw, idx, rb);
	if (err)
		return err;
	if ((rb[2] & L2X_W2_VALID) && l2x_same_key(rb, e)) {
		sw_fault(sw, "L2X[%d] still holds %08x %08x after delete", idx, e[0], e[1]);
		return -EIO;
	}
	return 0;
}

static struct fdb_ent *fdb_find(const unsigned char *mac, u16 vid)
{
	int i;

	for (i = 0; i < FDB_MAX; i++)
		if (fdb_tab[i].refs && fdb_tab[i].vid == vid && !memcmp(fdb_tab[i].mac, mac, ETH_ALEN))
			return &fdb_tab[i];
	return NULL;
}

/*
 * Bridge VID of an FDB operation, 0 if it has no hardware meaning: a
 * database other than an offloaded bridge, or a VLAN other than 0 (the
 * offloaded bridges are VLAN-unaware).
 */
static u16 fdb_vid(struct dsa_db db, u16 vid)
{
	int num;

	if (db.type != DSA_DB_BRIDGE || vid)
		return 0;
	num = db.bridge.num;
	if (num < 1 || num > BCM5331X_BR_MAX || hw_br_mode[num] != HW_BR_HW)
		return 0;
	return BCM5331X_BR_VID(num);
}

/*
 * An entry of a VLAN-unaware offloaded bridge with a VLAN: "bridge fdb add
 * ... master static" without "vlan" adds the entry for VID 0 and again for
 * every VLAN of the port (br_fdb_add, net/bridge/br_fdb.c of 6.18.55
 * l. 1393: "To be nice, add/update entry for every vlan on this port"),
 * VLAN 1 of the default PVID even with vlan_filtering 0. The bridge does
 * not forward by VLAN: the VID-0 entry is the one the switch holds; the
 * others have no hardware meaning, accepted without any write instead of
 * -EOPNOTSUPP (a "failed to add/delete ... vid 1" error line of DSA per
 * entry). Add: front port member of that bridge;
 * delete: also once the port or the bridge is gone (nothing was written).
 */
static bool fdb_vid_alias(int port, u16 vid, struct dsa_db db, bool add)
{
	int num = db.bridge.num;

	if (db.type != DSA_DB_BRIDGE || !vid || num < 1 || num > BCM5331X_BR_MAX ||
	    !bcm5331x_is_front(port))
		return false;
	if (add)
		return hw_br_mode[num] == HW_BR_HW && hw_port_br[port] == num;
	return hw_br_mode[num] == HW_BR_HW || hw_br_mode[num] == HW_BR_NONE;
}

/*
 * fdbvlan=Y: key of an operation on the offloaded VLAN-aware bridge. The
 * switch learns there by switch VLAN ({MAC, VLAN_ID}, independent VLAN
 * learning): a user VID is keyed by the switch VLAN of its slot (the VID
 * itself, or 4079 + slot for a VID the switch reserves). 1: *bvid set,
 * written; 0: accepted without any write (VID 0, which the bridge adds
 * besides each VLAN as for a VLAN-unaware bridge; a VLAN of the host
 * only, which no front port carries; a delete with no slot left, the
 * entry gone with its slot); -EOPNOTSUPP: a front port that is not a
 * member with that VID; 2: not the VLAN-aware bridge (as before).
 */
static int fdb_vl_key(int port, u16 vid, struct dsa_db db, bool host, bool add, u16 *bvid)
{
	int num = db.bridge.num, i;

	*bvid = 0;
	if (!fdbvlan || db.type != DSA_DB_BRIDGE || num < 1 || num > BCM5331X_BR_MAX ||
	    hw_br_mode[num] != HW_BR_VLAN || vid >= VLAN_N_VID)
		return 2;
	if (!vid)
		return host || !add || hw_port_br[port] == num ? 0 : -EOPNOTSUPP;
	i = vl_slot_of(vid);
	if (i < 0)
		return host || !add ? 0 : -EOPNOTSUPP;
	if (add && !host && !(vl_port(port) && vl_test(vl_vids[port], vid)))
		return -EOPNOTSUPP;
	*bvid = vl_hwvid(i);
	return 1;
}

static int bcm5331x_dsa_port_fdb_add(struct dsa_switch *ds, int port, const unsigned char *addr,
				     u16 vid, struct dsa_db db)
{
	struct bcm53314 *sw = ds->priv;
	bool host = dsa_is_cpu_port(ds, port);
	u16 bvid = fdb_vid(db, vid);
	struct fdb_ent *f, *slot = NULL;
	u32 e[FDB_L2X_WORDS];
	u8 dest;
	int i, err, idx = -1;

	if (!bvid) {
		err = fdb_vl_key(port, vid, db, host, true, &bvid);
		if (err <= 0)
			return err;
	}
	if (!bvid)	/* host address of a software bridge or standalone port: already to the host */
		return host || fdb_vid_alias(port, vid, db, true) ? 0 : -EOPNOTSUPP;
	if (addr[0] & 1)
		return -EOPNOTSUPP;	/* multicast: port_mdb_* (not offloaded) */
	if (!host && (!bcm5331x_is_front(port) || hw_port_br[port] != db.bridge.num))
		return -EOPNOTSUPP;
	if (access != 2 || dry_run)
		return -EPERM;
	mutex_lock(&sw->lock);
	dest = host ? fdb_host_dest(sw) : port;
	err = sw->halted ? -EIO : 0;
	if (err)
		goto out;
	f = fdb_find(addr, bvid);
	if (f && f->dest == dest) {
		f->refs++;	/* same key, same destination: already written */
		goto out;
	}
	for (i = 0; !f && !slot && i < FDB_MAX; i++)
		if (!fdb_tab[i].refs)
			slot = &fdb_tab[i];
	if (!f && !slot) {
		err = -ENOSPC;
		goto out;
	}
	l2x_build(e, addr, bvid, dest);
	err = fdb_insert(sw, e, &idx);	/* same key, other destination: replaced by the switch */
	if (err)
		goto out;
	if (!f) {
		f = slot;
		memcpy(f->mac, addr, ETH_ALEN);
		f->vid = bvid;
		f->refs = 0;
	}
	f->dest = dest;
	f->refs++;
	f->index = idx;
	fdb_scan_valid = false;
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "fdb: port %d, %pM VID %u: add failed (%d)\n", port, addr, bvid, err);
	else
		dev_dbg(ds->dev, "fdb: port %d, %pM VID %u -> %u, L2X[%d]\n", port, addr, bvid, dest, idx);
	return err;
}

static int bcm5331x_dsa_port_fdb_del(struct dsa_switch *ds, int port, const unsigned char *addr,
				     u16 vid, struct dsa_db db)
{
	struct bcm53314 *sw = ds->priv;
	bool host = dsa_is_cpu_port(ds, port);
	u16 bvid = fdb_vid(db, vid);
	struct fdb_ent *f;
	u32 e[FDB_L2X_WORDS];
	u8 dest;
	int err = 0, vk = 2;

	if (!bvid) {
		vk = fdb_vl_key(port, vid, db, host, false, &bvid);
		if (vk <= 0)
			return vk;
	}
	if (!bvid)
		return host || fdb_vid_alias(port, vid, db, false) ? 0 : -EOPNOTSUPP;
	if (access != 2 || dry_run)
		return -EPERM;
	mutex_lock(&sw->lock);
	dest = host ? fdb_host_dest(sw) : port;
	f = fdb_find(addr, bvid);
	if (sw->halted) {
		err = -EIO;
	} else if (!f && vk == 1) {
		err = 0;	/* VLAN-aware bridge: gone with the slot of its VID (fdb_vl_purge) */
	} else if (!f || f->dest != dest) {
		err = -ENOENT;	/* not written by this driver: nothing to delete */
	} else if (--f->refs == 0) {
		l2x_build(e, addr, bvid, dest);
		err = fdb_delete(sw, e);
		if (err == -ENOENT) {	/* a static entry is never aged: gone by other means */
			dev_warn(ds->dev, "fdb: %pM VID %u was no longer in L2X\n", addr, bvid);
			err = 0;
		}
		if (err)
			f->refs = 1;	/* still there (or module halted): kept for teardown */
		fdb_scan_valid = false;
	}
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "fdb: port %d, %pM VID %u: delete failed (%d)\n", port, addr, bvid, err);
	return err;
}

/* static entries left at teardown (normally none: DSA deletes them first) */
static void fdb_flush_all(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;
	u32 e[FDB_L2X_WORDS];
	int i, err;

	mutex_lock(&sw->lock);
	for (i = 0; i < FDB_MAX; i++) {
		struct fdb_ent *f = &fdb_tab[i];
		u16 vid = f->vid;
		int num = vid - BCM5331X_BR_VID_FIRST + 1;

		if (!f->refs)
			continue;
		err = sw->halted ? -EIO : 0;
		if (!err) {
			/* the rule needs the bridge offloaded: it is, while an entry of it is kept */
			l2x_build(e, f->mac, vid, f->dest);
			if ((num >= 1 && num <= BCM5331X_BR_MAX && hw_br_mode[num] == HW_BR_HW) ||
			    fdb_vl_entry_ok(sw, e, false))
				err = fdb_delete(sw, e);
			else
				err = -EPERM;
		}
		dev_warn(ds->dev, "fdb: %pM VID %u left at teardown, deleted (%d)\n", f->mac, vid, err);
		f->refs = 0;
	}
	fdb_scan_valid = false;
	mutex_unlock(&sw->lock);
}

/* ---------------------------------------------------------------------- */
/* Multicast groups of offloaded bridges (mdb=Y)                           */

/*
 * With mdb=Y (default N, needs fdb=Y) the multicast
 * database of a VLAN-unaware offloaded bridge (port_mdb_add/del, DSA's
 * static and learnt groups of its ports and the host groups of the
 * bridge) is offloaded where it is safe to:
 *  - group G = {MAC, bridge VID}; S(G) = front ports holding an entry,
 *    plus the host (ge2 only: one copy also under trunk2/lag);
 *  - a hardware entry exists only when S(G) is not empty, holds no member
 *    of a front-port LAG and does NOT hold the designated port of the
 *    bridge (the port the tagger delivers the frames of the bridge VID
 *    to, see hw_tagger_update): an IGMP/MLD report of a member reaches
 *    the host with the bridge VID, so every group learnt by snooping sits
 *    on the designated port whatever the listener; such a group, or a
 *    static one on the designated port, has no entry and is flooded in
 *    the bridge VLAN as before (a superset: no multicast ever lost). So,
 *    in effect, the static groups of non-designated ports and the host
 *    groups are offloaded; a change of designated port re-evaluates the
 *    groups of the bridge (mdb_reeval);
 *  - an entry is L2MC[k] (IPIPE 0x07700000 + k, PORT_BITMAP 24:0, VALID 25,
 *    EVEN_PARITY 28 kept by the hardware), k 1-255 (0 avoided),
 *    then an L2X entry {MAC, VID, L2MC_PTR 74:67 = k, STATIC, VALID}
 *    written by the switch's own insert (ARL_INSERT, as fdb=Y does; OpenBCM
 *    firebolt/l2.c writes L2MC_PTR for a multicast DA); a change of S(G)
 *    rewrites L2MC[k] only; removal: ARL_DELETE, then L2MC[k] to zero.
 *    L2MC is read whole at the first group: an index found not empty is
 *    never used;
 *  - the first hardware group also sets, and the last one gives back:
 *    IGMP_MLD_PKT_CONTROL (IPIPE 0x0c700009, per port, | port << 12) of
 *    the 19 front ports to 0x04924924 (every one of the nine actions =
 *    flood in the VLAN, nothing to the CMIC, PFM_RULE_APPLY 0), so that
 *    reports and queries keep reaching the host (the bridge's snooping)
 *    and the other members even for a group known in L2X (origin read,
 *    written back); and, VLAN_PROFILE_TAB[0].L2_PFM (IPIPE
 *    0x05720000, bits 1:0; profile of every VLAN of this driver): 1 =
 *    known groups by L2MC, unknown flooded is needed (0 = every multicast
 *    flooded, entries ignored): if it reads 1 nothing is written; if it
 *    reads 0, this one field is written 0 -> 1 and given back; any other
 *    value refuses (no entry, flooding as before). IP multicast lookups
 *    (L3 IPMC, and the L2 IPMC lookup on (S,G)/(*,G) instead of {MAC,
 *    VLAN}) need the enable of the ingress port in PORT_TAB as well as
 *    the one of the VLAN profile: OpenBCM firebolt/ipmc.c _xgs3_ipmc_enable
 *    turns IPMC on and off by the port bits alone (V4IPMC_ENABLE,
 *    V6IPMC_ENABLE, IPMC_DO_VLAN), the VLAN profile keeping its IPMC bits
 *    set by default (firebolt/vlan.c _vlan_profile_default_add: flags 0 ->
 *    IPMCV4/V6_ENABLE and _L2_ENABLE 1); bcm_port_control
 *    bcmPortControlIP4McastL2 = PORT_TAB.V4IPMC_L2_ENABLE ("L2 switching
 *    on IPv4 IPMC packets based on (SG,*G) instead of (DMAC,VLAN)").
 *    The boot firmware leaves exactly that default profile (0x00002fe1:
 *    L2_PFM 1, the four IPMC bits, IPV4L3/IPV6L3, L3_IPV4/IPV6_PFM 1;
 *    seen on the board). The bits of the profile are therefore only
 *    logged; the guard is on the ports: V4IPMC_ENABLE, V6IPMC_ENABLE,
 *    V4IPMC_L2_ENABLE or V6IPMC_L2_ENABLE of a front port, ge2 (or ge3
 *    under trunk2) not zero refuses (with them all zero, IP
 *    multicast is switched by {MAC, VLAN}, L2X and L2MC).
 * The host groups of a standalone port or of a software bridge need
 * nothing (port VLAN, every frame reaches the host): 0, no write; a group
 * on a port of a software bridge, of the VLAN-aware bridge of vlanbr (its
 * groups stay flooded) or of a LAG: -EOPNOTSUPP; a VID on a VLAN-unaware
 * bridge: no hardware meaning, 0. Every write is planned on what is read,
 * checked against fixed rules (mdb_op_ok, mdb_entry_ok), re-read before,
 * written and read back (a mismatch halts the base module); an insert
 * refused by the switch (bucket full) gives L2MC[k] back. Known limits:
 * mcast_snooping turned off after static groups is not passed on by the
 * bridge (entries kept until removed or teardown); learnt groups are
 * never offloaded (exact source port unknown).
 */
static bool mdb;
#define MDB_L2MC_ADDR		0x07700000	/* IPIPE L2MC, + index */
#define MDB_L2MC_NUM		256
#define MDB_L2MC_PBM		((u32)GENMASK(24, 0))
#define MDB_L2MC_VALID		((u32)BIT(25))
#define MDB_L2MC_PARITY		((u32)BIT(28))
#define MDB_IGMP_ADDR		0x0c700009	/* IPIPE IGMP_MLD_PKT_CONTROL, | port << 12 */
#define MDB_IGMP_FLOOD		0x04924924	/* nine FWD_ACTION = 2 (flood in the VLAN) */
#define MDB_VPROF_ADDR		0x05720000	/* IPIPE VLAN_PROFILE_TAB[0] */
#define MDB_VPROF_PFM		((u32)GENMASK(1, 0))	/* L2_PFM */
#define MDB_VPROF_IPMC		((u32)(BIT(5) | BIT(6) | BIT(7) | BIT(8)))	/* IPMCV6/V4_ENABLE, _L2_ENABLE */
#define MDB_PT1_IPMC		((u32)(BIT(30) | BIT(31)))	/* PORT_TAB word 1: V6IPMC_ENABLE, V4IPMC_ENABLE */
#define MDB_PT2_IPMC_L2		((u32)(BIT(0) | BIT(1)))	/* PORT_TAB word 2: V6IPMC_L2_ENABLE, V4IPMC_L2_ENABLE */
#define L2X_W2_L2MC_PTR		GENMASK(10, 3)	/* 74:67 for a multicast DA */
#define MDB_MAX			255

static struct mdb_grp {
	u8 mac[ETH_ALEN];
	u8 num;			/* bridge number, 0 = free slot */
	u32 ports;		/* front ports holding an entry */
	int host;		/* host entries (two CPU ports may add the same) */
	u8 k;			/* L2MC index in hardware, 0 = flooded */
	u32 pbm;		/* L2MC bitmap written */
} mdb_tab[MDB_MAX];
static u32 mdb_l2mc_busy[MDB_L2MC_NUM / 32];	/* indices found not empty: never used */
static u32 mdb_l2mc_mine[MDB_L2MC_NUM / 32];	/* indices held by the driver */
static bool mdb_l2mc_read;		/* L2MC read whole */
static int mdb_hw;			/* groups with a hardware entry */
static bool mdb_ctl;			/* IGMP_MLD_PKT_CONTROL (and L2_PFM) set */
static u32 mdb_igmp0[NUM_PORTS];	/* IGMP_MLD_PKT_CONTROL as found */
static u32 mdb_vprof0;			/* VLAN_PROFILE_TAB[0] as found */
static bool mdb_pfm_set;		/* L2_PFM written 0 -> 1 by the driver */
static unsigned long bcm5331x_mdb_hw_adds, bcm5331x_mdb_refusals;

module_param(mdb, bool, 0444);
MODULE_PARM_DESC(mdb, "Multicast groups of offloaded bridges (needs fdb): static groups of non-designated ports and host groups in L2MC/L2X, IGMP/MLD flooded to the host, VLAN_PROFILE_TAB[0].L2_PFM 0 -> 1 if found 0 (switch writes at run time, read back; default N = flooded, no write)");

static bool mdb_bit(const u32 *map, int k)
{
	return k >= 0 && k < MDB_L2MC_NUM && (map[k / 32] & BIT(k % 32));
}

/* the one kind of L2X entry mdb writes: multicast MAC, VID of an offloaded bridge, L2MC_PTR held */
static bool mdb_entry_ok(const struct bcm53314 *sw, const u32 *w)
{
	u16 vid = (w[1] >> 16) & 0xfff;
	int num = vid - BCM5331X_BR_VID_FIRST + 1, k = (w[2] & L2X_W2_L2MC_PTR) >> 3;

	return mdb && !(w[1] & GENMASK(31, 28)) && (w[1] & BIT(8)) &&
	       !(w[2] & ~(L2X_W2_L2MC_PTR | L2X_W2_STATIC | L2X_W2_VALID)) &&
	       (w[2] & L2X_W2_STATIC) && (w[2] & L2X_W2_VALID) && k >= 1 && mdb_bit(mdb_l2mc_mine, k) &&
	       num >= 1 && num <= BCM5331X_BR_MAX && hw_br_mode[num] == HW_BR_HW;
}

/* an L2MC word mdb writes: 0, or VALID with a bitmap of front ports and ge2 */
static bool mdb_l2mc_val_ok(u32 v)
{
	return !v || ((v & MDB_L2MC_VALID) && (v & MDB_L2MC_PBM) && !(v & ~(MDB_L2MC_VALID | MDB_L2MC_PBM)) &&
		      !(v & MDB_L2MC_PBM & ~(hw_front_pbm() | BIT(PORT_TRUNK))));
}

/* the one change each mdb register or table write may make */
static bool mdb_op_ok(const struct bcm53314 *sw, const struct hw_op *op)
{
	const u32 *a = op->old, *n = op->val;
	int p = op->idx;

	if (!mdb || op->words != 1 || a[0] == n[0])
		return false;
	switch (op->kind) {
	case HW_L2MC:
		return p >= 1 && p < MDB_L2MC_NUM && op->mem && op->addr == MDB_L2MC_ADDR + p &&
		       mdb_bit(mdb_l2mc_mine, p) && !mdb_bit(mdb_l2mc_busy, p) &&
		       mdb_l2mc_val_ok(a[0]) && mdb_l2mc_val_ok(n[0]);
	case HW_IGMP:
		return bcm5331x_is_front(p) && !op->mem && op->addr == (MDB_IGMP_ADDR | p << 12) &&
		       ((a[0] == mdb_igmp0[p] && n[0] == MDB_IGMP_FLOOD) ||
			(a[0] == MDB_IGMP_FLOOD && n[0] == mdb_igmp0[p]));
	case HW_VPROF:
		/* L2_PFM alone, 0 -> 1 if found 0, and back */
		return !p && op->mem && op->addr == MDB_VPROF_ADDR &&
		       (((a[0] & MDB_VPROF_PFM) == 0 && n[0] == (a[0] | 1) && a[0] == mdb_vprof0) ||
			(mdb_pfm_set && a[0] == (mdb_vprof0 | 1) && n[0] == mdb_vprof0));
	default:
		break;
	}
	return false;
}

/* designated port of bridge @num (the tagger's), 0 if none or unknown */
static int mdb_des(struct dsa_switch *ds, int num)
{
	struct bcm5331x_tagger_data *td = ds->tagger_data;

	return td ? READ_ONCE(td->vid_port[BCM5331X_BR_VID(num)]) : 0;
}

/* L2MC bitmap group @g should have in hardware, 0 = flooded (see above) */
static u32 mdb_want(struct dsa_switch *ds, const struct mdb_grp *g)
{
	int des = mdb_des(ds, g->num), p;

	if ((!g->ports && !g->host) || !des || (g->ports & BIT(des)))
		return 0;
	for (p = 0; p < NUM_PORTS; p++)
		if ((g->ports & BIT(p)) && (lg_of(p) >= 0 || hw_port_br[p] != g->num))
			return 0;
	return g->ports | (g->host ? BIT(PORT_TRUNK) : 0);
}

/* plan + execute one write of an mdb kind (under sw->lock) */
static int mdb_write(struct bcm53314 *sw, struct device *dev, enum hw_kind kind, const char *name,
		     u32 addr, bool mem, int idx, u32 old, u32 val)
{
	int err;

	hw_nops = 0;
	err = hw_add(kind, name, addr, mem, 1, idx, 0, &old, &val);
	if (!err && kind == HW_L2MC)
		hw_ops[0].parity0 = MDB_L2MC_PARITY;
	if (!err)
		err = hw_execute(sw, dev);
	return err;
}

/*
 * First hardware group: L2MC read whole (once), the guards above,
 * IGMP_MLD_PKT_CONTROL of the front ports to flood, then L2_PFM 0 -> 1 if
 * found 0 (refused for any other value). @on false: back as found, L2_PFM
 * first. Under sw->lock.
 */
static int mdb_ctl_set(struct bcm53314 *sw, struct device *dev, bool on)
{
	u32 w[HW_L2U_WORDS], pt[3];
	int i, p, err = 0;

	if (on && !mdb_l2mc_read) {
		memset(mdb_l2mc_busy, 0, sizeof(mdb_l2mc_busy));
		for (i = 0; i < MDB_L2MC_NUM; i++) {
			err = hw_read(sw, "L2MC", MDB_L2MC_ADDR + i, true, 1, i, w);
			if (err)
				return err;
			if (w[0] & ~MDB_L2MC_PARITY) {
				mdb_l2mc_busy[i / 32] |= BIT(i % 32);
				dev_info(dev, "mdb: L2MC[%d] = %08x found, never used\n", i, w[0]);
			}
		}
		mdb_l2mc_read = true;
	}
	if (on) {
		err = hw_read(sw, "VLAN_PROFILE_TAB", MDB_VPROF_ADDR, true, 1, 0, w);
		if (err)
			return err;
		mdb_vprof0 = w[0];
		if ((w[0] & MDB_VPROF_PFM) > 1) {
			dev_err(dev, "mdb: VLAN_PROFILE_TAB[0] = %08x (L2_PFM %u): groups not offloaded\n",
				w[0], w[0] & MDB_VPROF_PFM);
			bcm5331x_mdb_refusals++;
			return -EOPNOTSUPP;
		}
		for (p = 0; p < NUM_PORTS; p++) {
			if (!bcm5331x_is_front(p) && p != PORT_TRUNK && !(p == PORT_TRUNK2 && sw->trunk2))
				continue;
			err = sw_read(sw, O_PORT_TAB, p, pt);
			if (err)
				return err;
			if ((pt[1] & MDB_PT1_IPMC) || (pt[2] & MDB_PT2_IPMC_L2)) {
				dev_err(dev, "mdb: PORT_TAB[%d] IPMC enabled (word 1 %08x, word 2 %08x): groups not offloaded\n",
					p, pt[1], pt[2]);
				bcm5331x_mdb_refusals++;
				return -EOPNOTSUPP;
			}
		}
		dev_info(dev, "mdb: VLAN_PROFILE_TAB[0] = %08x (L2_PFM %u, IPMC bits %s), IPMC off on every port: IP multicast switched by MAC\n",
			 w[0], w[0] & MDB_VPROF_PFM, (w[0] & MDB_VPROF_IPMC) ? "set" : "clear");
		for (p = 0; p < NUM_PORTS; p++) {
			if (!bcm5331x_is_front(p))
				continue;
			err = hw_read(sw, "IGMP_MLD_PKT_CONTROL", MDB_IGMP_ADDR | p << 12, false, 1, p, w);
			if (err)
				return err;
			mdb_igmp0[p] = w[0];
		}
		for (p = 0; p < NUM_PORTS && !err; p++)
			if (bcm5331x_is_front(p) && mdb_igmp0[p] != MDB_IGMP_FLOOD)
				err = mdb_write(sw, dev, HW_IGMP, "IGMP_MLD_PKT_CONTROL", MDB_IGMP_ADDR | p << 12,
						false, p, mdb_igmp0[p], MDB_IGMP_FLOOD);
		mdb_ctl = true;		/* given back by the off path, even partly written */
		if (!err && !(mdb_vprof0 & MDB_VPROF_PFM)) {
			err = mdb_write(sw, dev, HW_VPROF, "VLAN_PROFILE_TAB", MDB_VPROF_ADDR, true, 0,
					mdb_vprof0, mdb_vprof0 | 1);
			if (!err) {
				mdb_pfm_set = true;
				dev_info(dev, "mdb: VLAN_PROFILE_TAB[0].L2_PFM 0 -> 1 (%08x -> %08x, read back)\n",
					 mdb_vprof0, mdb_vprof0 | 1);
			}
		}
		if (err)
			goto undo;
		dev_info(dev, "mdb: IGMP/MLD flooded to the host on the front ports, L2_PFM %u\n",
			 (mdb_vprof0 & MDB_VPROF_PFM) | 1);
		return 0;
	}
undo:
	if (!mdb_ctl)
		return err;
	if (mdb_pfm_set && !sw->halted) {
		int e2 = mdb_write(sw, dev, HW_VPROF, "VLAN_PROFILE_TAB", MDB_VPROF_ADDR, true, 0,
				   mdb_vprof0 | 1, mdb_vprof0);

		if (!e2)
			mdb_pfm_set = false;
		err = err ? err : e2;
	}
	for (p = 0; p < NUM_PORTS && !sw->halted; p++) {
		if (!bcm5331x_is_front(p) || mdb_igmp0[p] == MDB_IGMP_FLOOD)
			continue;
		err = hw_read(sw, "IGMP_MLD_PKT_CONTROL", MDB_IGMP_ADDR | p << 12, false, 1, p, w) ? : err;
		if (w[0] == MDB_IGMP_FLOOD)
			err = mdb_write(sw, dev, HW_IGMP, "IGMP_MLD_PKT_CONTROL", MDB_IGMP_ADDR | p << 12,
					false, p, MDB_IGMP_FLOOD, mdb_igmp0[p]) ? : err;
	}
	if (!sw->halted && !mdb_pfm_set)
		mdb_ctl = false;
	if (!on && !err)
		dev_info(dev, "mdb: IGMP_MLD_PKT_CONTROL and L2_PFM as found\n");
	return err;
}

/* the L2X entry of group @g at L2MC index @k */
static void mdb_l2x_build(u32 *e, const struct mdb_grp *g, int k)
{
	l2x_build(e, g->mac, BCM5331X_BR_VID(g->num), 0);
	e[2] = (e[2] & ~L2X_W2_L2MC_PTR) | (u32)k << 3;
}

/* hardware state of group @g to mdb_want (under sw->lock): 0, or an error with the hardware left consistent */
static int mdb_apply(struct dsa_switch *ds, struct mdb_grp *g)
{
	struct bcm53314 *sw = ds->priv;
	u32 want = mdb_want(ds, g), e[FDB_L2X_WORDS];
	int k = g->k, err = 0, idx;

	if (sw->halted)
		return -EIO;
	if (access != 2 || dry_run)
		return -EPERM;
	if (!want && !k)
		return 0;
	if (want && k) {
		if (want == g->pbm)
			return 0;
		err = mdb_write(sw, ds->dev, HW_L2MC, "L2MC", MDB_L2MC_ADDR + k, true, k,
				MDB_L2MC_VALID | g->pbm, MDB_L2MC_VALID | want);
		if (!err)
			g->pbm = want;
		return err;
	}
	if (!want) {
		/* L2X entry first (no lookup reaches L2MC[k] any more), then L2MC[k] */
		mdb_l2x_build(e, g, k);
		err = fdb_delete(sw, e);
		if (err == -ENOENT) {
			dev_warn(ds->dev, "mdb: %pM VID %u was no longer in L2X\n", g->mac, BCM5331X_BR_VID(g->num));
			err = 0;
		}
		if (!err)
			err = mdb_write(sw, ds->dev, HW_L2MC, "L2MC", MDB_L2MC_ADDR + k, true, k,
					MDB_L2MC_VALID | g->pbm, 0);
		if (err)
			return err;
		mdb_l2mc_mine[k / 32] &= ~BIT(k % 32);
		g->k = 0;
		g->pbm = 0;
		if (!--mdb_hw)
			err = mdb_ctl_set(sw, ds->dev, false);
		fdb_scan_valid = false;
		return err;
	}
	/* new hardware group: the controls with the first one, an index, L2MC[k], then the L2X entry */
	if (!mdb_hw) {
		err = mdb_ctl_set(sw, ds->dev, true);
		if (err)
			return err;
	}
	for (k = 1; k < MDB_L2MC_NUM; k++)
		if (!mdb_bit(mdb_l2mc_busy, k) && !mdb_bit(mdb_l2mc_mine, k))
			break;
	if (k == MDB_L2MC_NUM) {
		err = -ENOSPC;
		goto first;
	}
	mdb_l2mc_mine[k / 32] |= BIT(k % 32);
	err = mdb_write(sw, ds->dev, HW_L2MC, "L2MC", MDB_L2MC_ADDR + k, true, k, 0, MDB_L2MC_VALID | want);
	if (err) {
		mdb_l2mc_mine[k / 32] &= ~BIT(k % 32);
		goto first;
	}
	mdb_l2x_build(e, g, k);
	err = fdb_insert(sw, e, &idx);
	if (err) {
		/* refused (bucket full) or failed: L2MC[k] back to zero */
		if (!sw->halted && !mdb_write(sw, ds->dev, HW_L2MC, "L2MC", MDB_L2MC_ADDR + k, true, k,
					      MDB_L2MC_VALID | want, 0))
			mdb_l2mc_mine[k / 32] &= ~BIT(k % 32);
		goto first;
	}
	g->k = k;
	g->pbm = want;
	mdb_hw++;
	bcm5331x_mdb_hw_adds++;
	fdb_scan_valid = false;
	dev_dbg(ds->dev, "mdb: %pM VID %u -> L2MC[%d] = %08x, L2X[%d]\n", g->mac,
		BCM5331X_BR_VID(g->num), k, MDB_L2MC_VALID | want, idx);
	return 0;
first:
	if (!mdb_hw && !sw->halted)
		mdb_ctl_set(sw, ds->dev, false);
	return err;
}

/* the designated port of bridge @num may have changed: its groups re-evaluated */
static void mdb_reeval(struct dsa_switch *ds, int num)
{
	struct bcm53314 *sw = ds->priv;
	int i, err;

	if (!mdb || num < 1 || num > BCM5331X_BR_MAX)
		return;
	mutex_lock(&sw->lock);
	for (i = 0; i < MDB_MAX; i++) {
		if (mdb_tab[i].num != num)
			continue;
		err = mdb_apply(ds, &mdb_tab[i]);
		if (err && err != -EOPNOTSUPP && err != -ENOSPC)
			dev_err(ds->dev, "mdb: %pM VID %u: re-evaluation failed (%d)\n", mdb_tab[i].mac,
				BCM5331X_BR_VID(num), err);
	}
	mutex_unlock(&sw->lock);
}

/*
 * Bridge number of an mdb operation that may need hardware, 0 if none
 * (host group of a standalone port or software bridge, VID alias: nothing
 * to write), -1 if refused (-EOPNOTSUPP).
 */
static int mdb_num(struct dsa_switch *ds, int port, const struct switchdev_obj_port_mdb *m,
		   struct dsa_db db, bool add)
{
	bool host = dsa_is_cpu_port(ds, port);
	int num = db.bridge.num;

	if (db.type != DSA_DB_BRIDGE)
		return host ? 0 : -1;
	if (num < 1 || num > BCM5331X_BR_MAX || hw_br_mode[num] != HW_BR_HW) {
		if (host || (!add && hw_br_mode[num] == HW_BR_NONE))
			return 0;
		return -1;
	}
	if (!host && (!bcm5331x_is_front(port) || hw_port_br[port] != num)) {
		if (!add && bcm5331x_is_front(port))
			return 0;	/* left the bridge: its entry was dropped with it */
		return -1;
	}
	if (m->vid)
		return 0;	/* VLAN-unaware bridge: the VID-0 group is the one the switch holds */
	if (!host && lg_of(port) >= 0)
		return -1;	/* member of a front-port LAG: flooded (software) */
	return num;
}

static int bcm5331x_dsa_port_mdb_add(struct dsa_switch *ds, int port,
				     const struct switchdev_obj_port_mdb *m, struct dsa_db db)
{
	struct bcm53314 *sw = ds->priv;
	bool host = dsa_is_cpu_port(ds, port);
	int num = mdb_num(ds, port, m, db, true), i, err;
	struct mdb_grp *g = NULL, *slot = NULL;

	if (num <= 0)
		return num ? -EOPNOTSUPP : 0;
	mutex_lock(&sw->lock);
	for (i = 0; i < MDB_MAX; i++) {
		if (mdb_tab[i].num == num && ether_addr_equal(mdb_tab[i].mac, m->addr))
			g = &mdb_tab[i];
		else if (!mdb_tab[i].num && !slot)
			slot = &mdb_tab[i];
	}
	if (!g && !slot) {
		err = -ENOSPC;
		goto out;
	}
	if (!g) {
		g = slot;
		memset(g, 0, sizeof(*g));
		ether_addr_copy(g->mac, m->addr);
		g->num = num;
	}
	if (host)
		g->host++;
	else
		g->ports |= BIT(port);
	err = mdb_apply(ds, g);
	if (err == -EOPNOTSUPP || err == -ENOSPC)
		err = 0;	/* flooded: the group stays known, in software */
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "mdb: port %d, %pM VID %u: add failed (%d)\n", port, m->addr,
			BCM5331X_BR_VID(num), err);
	return err;
}

static int bcm5331x_dsa_port_mdb_del(struct dsa_switch *ds, int port,
				     const struct switchdev_obj_port_mdb *m, struct dsa_db db)
{
	struct bcm53314 *sw = ds->priv;
	bool host = dsa_is_cpu_port(ds, port);
	int num = mdb_num(ds, port, m, db, false), i, err = 0;
	struct mdb_grp *g = NULL;

	if (num <= 0)
		return num ? -EOPNOTSUPP : 0;
	mutex_lock(&sw->lock);
	for (i = 0; i < MDB_MAX && !g; i++)
		if (mdb_tab[i].num == num && ether_addr_equal(mdb_tab[i].mac, m->addr))
			g = &mdb_tab[i];
	if (!g || (host ? !g->host : !(g->ports & BIT(port)))) {
		err = -ENOENT;
		goto out;
	}
	if (host)
		g->host--;
	else
		g->ports &= ~BIT(port);
	err = mdb_apply(ds, g);
	if (err == -EOPNOTSUPP || err == -ENOSPC)
		err = 0;
	if (!g->host && !g->ports && !g->k)
		g->num = 0;
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "mdb: port %d, %pM VID %u: delete failed (%d)\n", port, m->addr,
			BCM5331X_BR_VID(num), err);
	return err;
}

/* a port leaves the bridge: its groups (if any) lose it */
static void mdb_port_gone(struct dsa_switch *ds, int port, int num)
{
	struct bcm53314 *sw = ds->priv;
	int i;

	if (!mdb || num < 1 || num > BCM5331X_BR_MAX)
		return;
	mutex_lock(&sw->lock);
	for (i = 0; i < MDB_MAX; i++) {
		struct mdb_grp *g = &mdb_tab[i];

		if (g->num != num || !(g->ports & BIT(port)))
			continue;
		g->ports &= ~BIT(port);
		mdb_apply(ds, g);
		if (!g->host && !g->ports && !g->k)
			g->num = 0;
	}
	mutex_unlock(&sw->lock);
}

/*
 * The last port left bridge @num (still offloaded here): its groups are
 * forgotten, a hardware entry left (normally none: no designated port any
 * more) deleted first; the host groups the bridge deletes later find no
 * offloaded bridge and need nothing.
 */
static void mdb_bridge_gone(struct dsa_switch *ds, int num)
{
	struct bcm53314 *sw = ds->priv;
	int i;

	if (!mdb || num < 1 || num > BCM5331X_BR_MAX || hw_br_mode[num] != HW_BR_HW)
		return;
	mutex_lock(&sw->lock);
	for (i = 0; i < MDB_MAX; i++) {
		struct mdb_grp *g = &mdb_tab[i];

		if (g->num != num)
			continue;
		if (g->k) {
			g->ports = 0;
			g->host = 0;
			mdb_apply(ds, g);
		}
		g->num = 0;
	}
	mutex_unlock(&sw->lock);
}

/* groups left at teardown (normally none): entries deleted, controls back */
static void mdb_flush_all(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;
	int i;

	mutex_lock(&sw->lock);
	for (i = 0; i < MDB_MAX; i++) {
		struct mdb_grp *g = &mdb_tab[i];

		if (!g->num)
			continue;
		if (g->k) {
			g->ports = 0;
			g->host = 0;
			dev_warn(ds->dev, "mdb: %pM VID %u left at teardown, deleted (%d)\n", g->mac,
				 BCM5331X_BR_VID(g->num), mdb_apply(ds, g));
		}
		g->num = 0;
	}
	if (mdb_ctl && !sw->halted)
		mdb_ctl_set(sw, ds->dev, false);
	mutex_unlock(&sw->lock);
}

/*
 * fdbvlan=Y: slot @i of the VLAN-aware bridge is about to be freed (its last
 * user drops the VID or leaves): the static entries keyed by its switch
 * VLAN are deleted first, so that a later user VID given the same slot (the
 * pool VID 4079 + i of a reserved VID, or the same VID) never inherits
 * them. The bridge may still list them (it keeps a static entry of a VLAN
 * a port no longer has): their later delete is accepted without any write.
 * Called without sw->lock.
 */
static void fdb_vl_purge(struct dsa_switch *ds, int i)
{
	struct bcm53314 *sw = ds->priv;
	u16 hw = vl_hwvid(i);
	u32 e[FDB_L2X_WORDS];
	int k, err;

	if (!fdb || !fdbvlan || !vl_slot[i].uvid)
		return;
	mutex_lock(&sw->lock);
	for (k = 0; k < FDB_MAX; k++) {
		struct fdb_ent *f = &fdb_tab[k];

		if (!f->refs || f->vid != hw)
			continue;
		l2x_build(e, f->mac, hw, f->dest);
		err = sw->halted ? -EIO : fdb_delete(sw, e);
		if (err == -ENOENT)
			err = 0;
		dev_warn(ds->dev, "fdb: %pM VID %u (user VID %u) left at slot free, deleted (%d)\n",
			 f->mac, hw, vl_slot[i].uvid, err);
		f->refs = 0;
		fdb_scan_valid = false;
	}
	mutex_unlock(&sw->lock);
}

/* one register write of the port ageing: re-read before, written, read back (under sw->lock) */
static int fdb_reg_write(struct bcm53314 *sw, const char *name, u32 addr, u32 old, u32 val)
{
	u32 w[3];
	int err;

	memset(w, 0, sizeof(w));
	err = schan_xfer(sw, false, false, addr, 1, w, name, 0);
	if (err)
		return err;
	if (w[0] != old) {
		sw_fault(sw, "dsa: fdb %s is %08x, expected %08x", name, w[0], old);
		return -ESTALE;
	}
	w[0] = val;
	err = schan_xfer(sw, true, false, addr, 1, w, name, 0);
	if (err)
		return err;
	bcm5331x_fdb_age_writes++;
	if (val & FDB_PPA_START)
		return 0;	/* read back by the poll of COMPLETE */
	udelay(10);
	w[0] = 0;
	err = schan_xfer(sw, false, false, addr, 1, w, name, 0);
	if (err)
		return err;
	if (w[0] != val) {
		sw_fault(sw, "dsa: fdb %s read back %08x, wrote %08x", name, w[0], val);
		return -EIO;
	}
	return 0;
}

/*
 * The changes the port ageing may make: AGE_ENA alone, or the per-port
 * ageing of one front port of an offloaded bridge by port number, static
 * entries excluded, all VLANs, delete mode.
 */
static bool fdb_reg_ok(u32 addr, u32 old, u32 val, int port)
{
	u32 fields = FDB_PPA_EXCL_STATIC | port;

	if (addr == FDB_A_AGE_TIMER)
		return !((old ^ val) & ~FDB_AGE_ENA) && !(old & ~(FDB_AGE_VAL | FDB_AGE_ENA)) &&
		       (old ^ val) == FDB_AGE_ENA;
	if (addr != FDB_A_PPA || !bcm5331x_is_front(port) || !hw_port_br[port])
		return false;
	return val == fields || (val == (fields | FDB_PPA_START) && old == fields);
}

static void bcm5331x_dsa_fdb_fast_age(struct dsa_switch *ds, int port)
{
	struct bcm53314 *sw = ds->priv;
	u32 t[3], a[3], fields = FDB_PPA_EXCL_STATIC | port, off;
	ktime_t end;
	int err;

	if (port < 0 || port >= NUM_PORTS || !bcm5331x_is_front(port) || !hw_port_br[port])
		return;		/* software bridge or standalone: its port VLAN has no forwarding to age */
	if (access != 2 || dry_run)
		return;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : 0;
	memset(t, 0, sizeof(t));
	memset(a, 0, sizeof(a));
	if (!err)
		err = schan_xfer(sw, false, false, FDB_A_AGE_TIMER, 1, t, "L2_AGE_TIMER", 0);
	if (!err)
		err = schan_xfer(sw, false, false, FDB_A_PPA, 1, a, "PER_PORT_AGE_CONTROL", 0);
	if (err)
		goto out;
	off = t[0] & ~FDB_AGE_ENA;
	/* a run in progress, or bits outside the fields: not the state the driver leaves */
	if (((a[0] & FDB_PPA_START) && !(a[0] & FDB_PPA_COMPLETE)) || (a[0] & ~GENMASK(28, 0)) ||
	    (t[0] & ~(FDB_AGE_VAL | FDB_AGE_ENA)) ||
	    ((t[0] & FDB_AGE_ENA) && !fdb_reg_ok(FDB_A_AGE_TIMER, t[0], off, port)) ||
	    !fdb_reg_ok(FDB_A_PPA, a[0], fields, port) ||
	    !fdb_reg_ok(FDB_A_PPA, fields, fields | FDB_PPA_START, port)) {
		dev_err(ds->dev, "fdb: port %d: ageing registers %08x %08x not as expected: nothing written\n",
			port, t[0], a[0]);
		bcm5331x_fdb_refusals++;
		err = -EBUSY;
		goto out;
	}
	if (t[0] & FDB_AGE_ENA) {
		err = fdb_reg_write(sw, "L2_AGE_TIMER", FDB_A_AGE_TIMER, t[0], off);
		if (err)
			goto out;
	}
	err = fdb_reg_write(sw, "PER_PORT_AGE_CONTROL", FDB_A_PPA, a[0], fields);
	if (!err)
		err = fdb_reg_write(sw, "PER_PORT_AGE_CONTROL", FDB_A_PPA, fields, fields | FDB_PPA_START);
	if (err)
		goto out;
	end = ktime_add_us(ktime_get(), FDB_PPA_POLL_US);
	for (;;) {
		a[0] = 0;
		err = schan_xfer(sw, false, false, FDB_A_PPA, 1, a, "PER_PORT_AGE_CONTROL", 0);
		if (err)
			goto out;
		if (a[0] & FDB_PPA_COMPLETE)
			break;
		if (ktime_after(ktime_get(), end)) {
			sw_fault(sw, "dsa: fdb: port %d ageing not complete (%08x)", port, a[0]);
			err = -ETIMEDOUT;
			goto out;
		}
		usleep_range(50, 100);
	}
	if ((a[0] & FDB_PPA_FIELDS) != fields) {
		sw_fault(sw, "dsa: fdb: PER_PORT_AGE_CONTROL read back %08x, wrote %08x", a[0],
			 (u32)(fields | FDB_PPA_START));
		err = -EIO;
		goto out;
	}
	if (t[0] & FDB_AGE_ENA)
		err = fdb_reg_write(sw, "L2_AGE_TIMER", FDB_A_AGE_TIMER, off, t[0]);
	fdb_scan_valid = false;
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "fdb: port %d: fast ageing failed (%d)\n", port, err);
}

/*
 * Ageing time (ageing=Y, with fdb=Y). L2_AGE_TIMER (IPIPE 0x00780003,
 * AGE_VAL 19:0 in seconds, AGE_ENA 20; OpenMDK bcm53314_a0_defs.h; written
 * whole, AGE_ENA | AGE_VAL, by OpenBCM src/soc/esw/firebolt.c, at most
 * 0xfffff s) holds 0x0010012c after the boot firmware (300 s, on).
 * The register is global: DSA checks the range (ds->ageing_time_min/max,
 * -ERANGE otherwise, "ageing_time 0" included: AGE_ENA stays the business
 * of the port ageing above) and programs the shortest ageing time of the
 * bridges of the switch, software ones included (net/dsa/switch.c), at
 * each join and change, also the 2 x forward_delay of an STP topology
 * change. AGE_VAL = the time rounded up to the second; the register is
 * re-read (bits outside the fields: refused, nothing written), written
 * only if AGE_VAL changes, AGE_ENA kept as read, and read back. The value
 * found at the first write is restored at teardown (not when a bridge
 * goes: DSA keeps the last value, "ageing time may be global"). An entry
 * learnt and then silent goes between AGE_VAL and 2 x AGE_VAL (one sweep
 * per period, hit bit).
 */
#define AGE_MIN_MS		1000
#define AGE_MAX_MS		(FDB_AGE_VAL * 1000U)	/* 0xfffff s */
static bool age_saved;
static u32 age_found;		/* AGE_VAL found at the first write */
/* ageing time writes done and read back, refusals: visible to debugfs */
static unsigned long bcm5331x_age_writes, bcm5331x_age_refusals;

/* the one change of an ageing time write: AGE_VAL alone, 1-0xfffff, nothing else set */
static bool age_op_ok(u32 old, u32 val)
{
	u32 v = val & FDB_AGE_VAL;

	return !(old & ~(FDB_AGE_VAL | FDB_AGE_ENA)) && !((old ^ val) & ~FDB_AGE_VAL) &&
	       old != val && v >= 1 && v <= FDB_AGE_VAL;
}

/* AGE_VAL @secs (or the value found, @restore), under sw->lock */
static int age_write(struct bcm53314 *sw, struct device *dev, u32 secs, bool restore)
{
	u32 t[3] = { 0 }, n;
	int err;

	err = sw->halted ? -EIO : schan_xfer(sw, false, false, FDB_A_AGE_TIMER, 1, t, "L2_AGE_TIMER", 0);
	if (err)
		return err;
	if (t[0] & ~(FDB_AGE_VAL | FDB_AGE_ENA)) {
		dev_err(dev, "ageing: L2_AGE_TIMER %08x not as expected: nothing written\n", t[0]);
		bcm5331x_age_refusals++;
		return -EBUSY;
	}
	if (restore)
		secs = age_found;
	n = (t[0] & ~FDB_AGE_VAL) | secs;
	if (n == t[0])
		return 0;
	if (!age_op_ok(t[0], n)) {
		dev_err(dev, "ageing: L2_AGE_TIMER %08x -> %08x refused: nothing written\n", t[0], n);
		bcm5331x_age_refusals++;
		return -EPERM;
	}
	if (!age_saved) {
		age_found = t[0] & FDB_AGE_VAL;
		age_saved = true;
	}
	err = fdb_reg_write(sw, "L2_AGE_TIMER", FDB_A_AGE_TIMER, t[0], n);
	if (err)
		return err;
	bcm5331x_age_writes++;
	dev_info(dev, "ageing: L2_AGE_TIMER %08x -> %08x (%u s%s, read back)\n", t[0], n, secs,
		 restore ? ", value found" : "");
	return 0;
}

static int bcm5331x_dsa_set_ageing_time(struct dsa_switch *ds, unsigned int msecs)
{
	struct bcm53314 *sw = ds->priv;
	u32 secs = DIV_ROUND_UP(msecs, 1000);
	int err;

	if (!secs || secs > FDB_AGE_VAL)
		return -ERANGE;		/* DSA checks first (ds->ageing_time_min/max) */
	/* no write allowed: the bridge keeps its own ageing (a join must not fail on it) */
	if (access != 2 || dry_run)
		return -EOPNOTSUPP;
	mutex_lock(&sw->lock);
	/* module halted: no access any more, the joins of software bridges must still pass */
	err = sw->halted ? -EOPNOTSUPP : age_write(sw, ds->dev, secs, false);
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "ageing: %u ms failed (%d)\n", msecs, err);
	return err;
}

/* ageing=Y, at teardown: the ageing time found */
static void age_restore(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;

	if (!ageing || !age_saved || access != 2 || dry_run)
		return;
	mutex_lock(&sw->lock);
	if (age_write(sw, ds->dev, 0, true))
		dev_err(ds->dev, "ageing: L2_AGE_TIMER not restored\n");
	else
		age_saved = false;
	mutex_unlock(&sw->lock);
}

/* read the whole L2X into fdb_scan, a chunk per hold of the lock */
static int fdb_scan_l2x(struct bcm53314 *sw)
{
	u32 w[FDB_L2X_WORDS];
	int i, n = 0, err = 0;

	for (i = 0; !err && i < FDB_L2X_NUM; i++) {
		if (i % FDB_DUMP_CHUNK == 0) {
			if (i)
				mutex_unlock(&sw->lock);
			mutex_lock(&sw->lock);
			if (sw->halted)
				err = -EIO;
		}
		if (!err)
			err = fdb_l2x_read(sw, i, w);
		/* multicast address: PORT_TGID is an L2MC index, not a port (not ours to report) */
		if (err || !(w[2] & L2X_W2_VALID) || (w[2] & L2X_W2_MODULE) || (w[1] & BIT(8)))
			continue;
		l2x_mac(w, fdb_scan[n].mac);
		fdb_scan[n].vid = (w[1] >> 16) & 0xfff;
		fdb_scan[n].dest = (w[2] & L2X_W2_PORT_TGID) >> 3;
		fdb_scan[n].is_static = !!(w[2] & L2X_W2_STATIC);
		n++;
	}
	fdb_scan_n = err ? 0 : n;
	fdb_scan_valid = !err;
	fdb_scan_end = ktime_add_us(ktime_get(), FDB_DUMP_KEEP_US);
	mutex_unlock(&sw->lock);
	return err;
}

static DEFINE_MUTEX(fdb_dump_lock);

static int bcm5331x_dsa_port_fdb_dump(struct dsa_switch *ds, int port, dsa_fdb_dump_cb_t *cb,
				      void *data)
{
	struct bcm53314 *sw = ds->priv;
	u16 pvid = bcm5331x_port_vid(port), bvid;
	int i, err = 0;

	if (!pvid)
		return 0;
	bvid = hw_port_br[port] ? BCM5331X_BR_VID(hw_port_br[port]) : 0;
	mutex_lock(&fdb_dump_lock);
	if (!fdb_scan_valid || ktime_after(ktime_get(), fdb_scan_end))
		err = fdb_scan_l2x(sw);
	for (i = 0; !err && i < fdb_scan_n; i++) {
		struct fdb_scan_ent *s = &fdb_scan[i];

		int sl;

		if (s->dest != port)
			continue;
		if (s->vid == pvid || (bvid && s->vid == bvid)) {
			err = cb(s->mac, 0, s->is_static, data);
			continue;
		}
		/* fdbvlan=Y: a switch VLAN of the VLAN-aware bridge, reported with its user VID */
		sl = fdbvlan && vl_port(port) ? vl_slot_of_hw(s->vid) : -1;
		if (sl >= 0)
			err = cb(s->mac, vl_slot[sl].uvid, s->is_static, data);
	}
	mutex_unlock(&fdb_dump_lock);
	return err;
}

/* debugfs "l2x": hash selections, ageing, every valid entry with its index (reads only) */
static int fdb_l2x_show(struct seq_file *m, void *v)
{
	struct bcm53314 *sw = m->private;
	u32 hc[3] = { 0 }, aux[3] = { 0 }, age[3] = { 0 }, w[FDB_L2X_WORDS];
	u8 mac[ETH_ALEN];
	int i, err;

	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : sw_read(sw, O_HASH_CONTROL, 0, hc);
	if (!err)
		err = schan_xfer(sw, false, false, FDB_A_AUX_HASH, 1, aux, "L2_AUX_HASH_CONTROL", 0);
	if (!err)
		err = schan_xfer(sw, false, false, FDB_A_AGE_TIMER, 1, age, "L2_AGE_TIMER", 0);
	mutex_unlock(&sw->lock);
	if (err)
		return err;
	seq_printf(m, "HASH_CONTROL %08x L2_AUX_HASH_CONTROL %08x L2_AGE_TIMER %08x\n", hc[0], aux[0], age[0]);
	for (i = 0; i < FDB_L2X_NUM; i++) {
		if (i % FDB_DUMP_CHUNK == 0)
			mutex_lock(&sw->lock);
		err = sw->halted ? -EIO : fdb_l2x_read(sw, i, w);
		if (i % FDB_DUMP_CHUNK == FDB_DUMP_CHUNK - 1 || err)
			mutex_unlock(&sw->lock);
		if (err)
			return err;
		if (!(w[2] & L2X_W2_VALID))
			continue;
		l2x_mac(w, mac);
		seq_printf(m, "%4d %02x:%02x:%02x:%02x:%02x:%02x vid %4u dest %c%u%s hit %u%u %08x %08x %08x\n",
			   i, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (w[1] >> 16) & 0xfff,
			   /* m: multicast address, PORT_TGID = L2MC index; t: trunk group; p: port */
			   (w[1] & BIT(8)) ? 'm' : (w[2] & BIT(9)) ? 't' : 'p',
			   (w[1] & BIT(8)) ? (u32)((w[2] & L2X_W2_PORT_TGID) >> 3) : (w[2] >> 3) & 0x3f,
			   (w[2] & L2X_W2_STATIC) ? " static" : "", (w[2] >> 27) & 1, (w[2] >> 28) & 1,
			   w[0], w[1], w[2]);
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(fdb_l2x);

/* ---------------------------------------------------------------------- */
/* Conduit LAG ge2 + ge3 (lag=Y)                                           */

/*
 * The 82574L of ge3 (eth1) becomes a second CPU port (switch port 4) and
 * the two links can be bonded on the host (balance-xor, layer3+4: the DSA
 * conduit LAG of net/dsa/conduit.c). On the switch side the two links must
 * then be one trunk group: that is the base module's step trunk2 (group 7
 * {ge2, ge3}, RTAG 6, source trunk map, alternate flood block masks, flood
 * hash, ge3 tagged in every port VLAN), played at load as the other steps
 * (steps=...,ge3,trunk2), after step ge3 alone in an earlier load and with
 * eth1 up (trunk2 needs the ge3 link). The driver refuses lag=Y without
 * steps ge3 and trunk2 written.
 *
 * Nothing is written by the LAG operations: port_lag_join of a CPU port
 * checks, by reads, that group 7 is the trunk2 group and accepts a hash
 * LAG only; port_lag_leave keeps the group (the switch still spreads its
 * frames to the host over both links, both conduits receive them);
 * port_change_conduit accepts eth0, eth1 or their LAG (each port VLAN and
 * bridge VLAN holds ge2 and ge3). A LAG of front ports stays a software
 * bond (-EOPNOTSUPP: DSA falls back). No failover in the switch (the
 * Hawkeye has none, H-2L-g): port_lag_change is absent, a member that
 * loses its link keeps its share of the frames to the host.
 *
 * Towards the host, the switch picks the member of a known unicast by the
 * hash of RTAG 6 (IP source and destination) over the eight slots of group
 * 7, ge2 and ge3 alternately as _bcm_xgs3_trunk_set lays two members out
 * (OpenBCM src/bcm/esw/firebolt/trunk.c): only the lowest bit of the hash
 * index chooses the link. The hash function itself is not in the SDK (no
 * software model of RTAG 1-6). The host addresses are learnt on the group
 * (source trunk map of ge2 and ge3, written by trunk2 and read back at
 * port_lag_join), which the read-only debugfs l2x, created with lag=Y too,
 * shows as "dest t7" (a port number would be "dest p3"/"p4").
 */
static bool lag;
static char *conduit2_name = "eth1";
#define LAG_NUM_IDS		8	/* trunk groups of the Hawkeye */
/* LAG checks that passed: visible to debugfs */
static unsigned long bcm5331x_lag_joins;

module_param(lag, bool, 0444);
MODULE_PARM_DESC(lag, "Second CPU port on ge3 (conduit2) and conduit LAG of both links over the trunk group of step trunk2 (needs steps ge3,trunk2; no write of its own; default N)");
module_param_named(conduit2, conduit2_name, charp, 0444);
MODULE_PARM_DESC(conduit2, "Name of the second CPU-side net device, the 82574L carrying ge3, with lag=Y (default eth1)");

/* group 7 as step trunk2 leaves it (reads only, under sw->lock) */
static int lag_check_group(struct bcm53314 *sw)
{
	u32 g[3], w[3];
	int err;

	if (!sw->ge3 || !sw->trunk2)
		return -EINVAL;
	err = sw_read(sw, O_TRUNK_GROUP, TRUNK2_TGID, w);
	if (err)
		return err;
	trunk2_group(g);
	if (memcmp(w, g, sizeof(g)))
		return -EINVAL;
	err = sw_read(sw, O_TRUNK_BITMAP, TRUNK2_TGID, w);
	if (!err && w[0] != (PBM_TRUNK | PBM_TRUNK2))
		err = -EINVAL;
	if (!err)
		err = sw_read(sw, O_SOURCE_TRUNK_MAP, PORT_TRUNK, w);
	if (!err && w[0] != STM_TRUNK2)
		err = -EINVAL;
	if (!err)
		err = sw_read(sw, O_SOURCE_TRUNK_MAP, PORT_TRUNK2, w);
	if (!err && w[0] != STM_TRUNK2)
		err = -EINVAL;
	return err;
}

static bool lag_cpu_port(struct dsa_switch *ds, int port)
{
	return (port == PORT_TRUNK || port == PORT_TRUNK2) && dsa_is_cpu_port(ds, port);
}

/* ---- Hardware LAG of front ports (lagf): slow protocols, join, leave, change ---- */

static bool lg_any(void)
{
	int t;

	for (t = 0; t < LAGF_TGIDS; t++)
		if (lg_ports[t])
			return true;
	return false;
}

/*
 * A valid L2_USER_ENTRY below the bridge entries that catches the address
 * 01:80:c2:00:00:@da of a port VLAN (LACPDUs :02, LLDPDUs :0e, ...):
 * matched first, so the protocol cannot work (the boot firmware leaves
 * :01, :02 and :0e, dropping, after a network load). Reads only, under
 * sw->lock. Index, or -1.
 */
static int vp_l2u_catch(struct bcm53314 *sw, u8 da, u32 *w4, int *err)
{
	u32 w[HW_L2U_WORDS];
	int i, k;

	for (i = 0; i < HW_L2U_IDX(1); i++) {
		*err = hw_read(sw, "L2_USER_ENTRY", HW_L2U_ADDR + i, true, HW_L2U_WORDS, i, w);
		if (*err)
			return -1;
		if (!(w[0] & 1))
			continue;
		for (k = 0; k < (int)ARRAY_SIZE(front_ports); k++) {
			u64 fk = 0x0180c2000000ULL | da | (u64)fp_vid(k) << 48;

			if (!((hw_l2u_key(w) ^ fk) & hw_l2u_mask(w))) {
				*w4 = w[4];
				return i;
			}
		}
	}
	return -1;
}

/*
 * VLAN by protocol of entry @e (12-15, vp_defs) on or off: VLAN_PROTOCOL[e]
 * and the data of entry e of ports 1-24 (see "Hardware LAG of front ports"
 * and "Link-local protocols at the exact port"). State checked first
 * (every entry 0-15 as the driver left it: 0-11 empty, 12-15 empty or
 * written by their feature, so @e empty to set it up and exactly written
 * to remove it; the data of @e empty, or exactly written), then the plan,
 * then each write read back. On: then the boot firmware L2_USER_ENTRY of
 * the protocol cleared, if any (its own plan); off: that
 * entry given back first, whatever follows.
 */
static int vp_set(struct dsa_switch *ds, int e, bool on)
{
	struct bcm53314 *sw = ds->priv;
	const struct sw_obj *ovp = &objs[O_VLAN_PROTOCOL];
	const struct vp_def *d;
	u32 w[HW_L2U_WORDS], old[HW_L2U_WORDS], pt[3], w4 = 0;
	u16 vids[NUM_PORTS] = { 0 };
	int i, p, err, drop = -1, nw = 0;

	if (e < VP_FIRST || e >= VP_FIRST + VP_NUM || on == vp_is_on(e))
		return -EINVAL;
	d = &vp_defs[e - VP_FIRST];
	if (dry_run || access != 2)
		return -EPERM;
	mutex_lock(&sw->lock);
	/* off: the boot firmware entry back first, even if the rest is refused */
	if (!on && d->bios >= 0)
		hw_bios_l2u(sw, ds->dev, d->who, d->bios, false);
	hw_nops = 0;
	if (sw->halted) {
		err = -EIO;
		goto out;
	}
	for (i = 0; i <= ovp->max; i++) {
		err = sw_read(sw, O_VLAN_PROTOCOL, i, w);
		if (err)
			goto out;
		if (w[0] != (vp_is_on(i) ? vp_defs[i - VP_FIRST].val : 0)) {
			dev_err(ds->dev, "%s: VLAN_PROTOCOL[%d] = %08x, not the state left by the driver: nothing written\n",
				d->who, i, w[0]);
			goto busy;
		}
	}
	for (p = VP_VPD_FIRST; p < NUM_PORTS; p++) {
		u16 v = on ? bcm5331x_port_vid(p) : vp_vid[e - VP_FIRST][p];

		if (on && !v) {
			err = sw_read(sw, O_PORT_TAB, p, pt);
			if (err)
				goto out;
			v = PT_VID(pt);
		}
		vids[p] = v;
		err = hw_read(sw, "VLAN_PROTOCOL_DATA", VP_VPD_ADDR + VP_VPD_IDX(p, e), true, 1,
			      VP_VPD_IDX(p, e), w);
		if (err)
			goto out;
		if (w[0] != (on ? 0 : (u32)v << 3)) {
			dev_err(ds->dev, "%s: VLAN_PROTOCOL_DATA[%d] = %08x, not the state left by the driver: nothing written\n",
				d->who, VP_VPD_IDX(p, e), w[0]);
			goto busy;
		}
	}
	/* off: the protocol entry first (no port uses its data any more) */
	old[0] = on ? 0 : d->val;
	w[0] = on ? d->val : 0;
	if (!on)
		err = hw_add(HW_VPROT, ovp->name, obj_addr(ovp, e), true, 1, e, 0, old, w);
	for (p = VP_VPD_FIRST; !err && p < NUM_PORTS; p++) {
		u32 o = 0, n = (u32)vids[p] << 3;

		if (!vids[p])
			continue;
		if (!on) {
			o = n;
			n = 0;
		}
		err = hw_add(HW_VPROT_DATA, "VLAN_PROTOCOL_DATA", VP_VPD_ADDR + VP_VPD_IDX(p, e), true,
			     1, VP_VPD_IDX(p, e), 0, &o, &n);
	}
	/* on: the protocol entry last (every port has its data) */
	if (!err && on)
		err = hw_add(HW_VPROT, ovp->name, obj_addr(ovp, e), true, 1, e, 0, old, w);
	if (!err)
		err = hw_execute(sw, ds->dev);
	nw = hw_nops;
	if (!err) {
		vp_bios_back &= ~VP_BIT(e);
		if (on)
			vp_on |= VP_BIT(e);
		else
			vp_on &= ~VP_BIT(e);
		for (p = 0; p < NUM_PORTS; p++)
			vp_vid[e - VP_FIRST][p] = on ? vids[p] : 0;
	}
	goto out;
busy:
	bcm5331x_hw_refusals++;
	err = -EBUSY;
out:
	/* removal refused: the entry stays on, its boot firmware entry was given back first (vp_bios_reclaim) */
	if (err && !on && d->bios >= 0)
		vp_bios_back |= VP_BIT(e);
	if (err)
		dev_err(ds->dev, "%s: %s VLAN %s failed (%d)\n", d->who, d->vname, on ? "set-up" : "removal", err);
	else
		dev_info(ds->dev, "%s: %s on the port VIDs %s (%d writes, read back)\n",
			 d->who, d->name, on ? "on" : "off", nw);
	/* on: the boot firmware entry cleared once the VLAN by protocol is in place */
	if (!err && on) {
		int rerr = 0;

		if (d->bios >= 0)
			hw_bios_l2u(sw, ds->dev, d->who, d->bios, true);
		drop = vp_l2u_catch(sw, d->da, &w4, &rerr);
	}
	mutex_unlock(&sw->lock);
	if (drop >= 0)
		dev_warn(ds->dev, "%s: L2_USER_ENTRY[%d] (word 4 %08x) catches the %s of the port VLANs before any lookup: %s\n",
			 d->who, drop, w4, d->what, d->fail);
	return err;
}

/*
 * Entry @e still on after a refused removal, its boot firmware entry
 * given back: a new user (LAG join, first bridge
 * join) clears it again and checks for a catching entry, as the set-up
 * does. Nothing otherwise (no access).
 */
static void vp_bios_reclaim(struct dsa_switch *ds, int e)
{
	struct bcm53314 *sw = ds->priv;
	const struct vp_def *d;
	u32 w4 = 0;
	int drop = -1, rerr = 0;

	if (!vp_is_on(e) || !(vp_bios_back & VP_BIT(e)))
		return;
	d = &vp_defs[e - VP_FIRST];
	mutex_lock(&sw->lock);
	if (!hw_bios_l2u(sw, ds->dev, d->who, d->bios, true))
		vp_bios_back &= ~VP_BIT(e);
	drop = vp_l2u_catch(sw, d->da, &w4, &rerr);
	mutex_unlock(&sw->lock);
	if (drop < 0)
		return;
	dev_warn(ds->dev, "%s: L2_USER_ENTRY[%d] (word 4 %08x) catches the %s of the port VLANs before any lookup: %s\n",
		 d->who, drop, w4, d->what, d->fail);
}

/*
 * llproto (see "Link-local protocols at the exact port"): the VLANs by
 * protocol asked and not yet written (on), in the order STP, LLDP, EAPOL;
 * on a failure those written are undone; or every one written (off), in
 * the reverse order. 0, or the first error of the set-up.
 */
static const u8 ll_order[] = { VP_STP_IDX, VP_LLDP_IDX, VP_EAPOL_IDX };

static int ll_set(struct dsa_switch *ds, bool on)
{
	int k, err = 0;

	if (on) {
		for (k = 0; k < (int)ARRAY_SIZE(ll_order) && !err; k++)
			if (vp_allowed(ll_order[k]) && !vp_is_on(ll_order[k]))
				err = vp_set(ds, ll_order[k], true);
			else
				vp_bios_reclaim(ds, ll_order[k]);
		if (!err)
			return 0;
	}
	for (k = (int)ARRAY_SIZE(ll_order) - 1; k >= 0; k--)
		if (vp_is_on(ll_order[k]))
			vp_set(ds, ll_order[k], false);
	return err;
}

/* a front port left hardware bridging: llproto undone after the last one */
static void ll_leave(struct dsa_switch *ds)
{
	if (ll_users && !--ll_users)
		ll_set(ds, false);
}

/*
 * A front port joins a LAG (lagf). Nothing written but the slow-protocol
 * VLAN at the first front-port LAG (lagf=2); the trunk group follows the
 * members forwarding in a bridge VLAN (hw_member).
 */
static int lagf_join(struct dsa_switch *ds, int port, struct dsa_lag dlag,
		     struct netdev_lag_upper_info *info, struct netlink_ext_ack *extack)
{
	int t = (int)dlag.id - 1;

	if (!hwbridge)
		return -EOPNOTSUPP;
	if (!info || info->tx_type != NETDEV_LAG_TX_TYPE_HASH) {
		NL_SET_ERR_MSG_MOD(extack, "Front-port LAG: hash transmit policy only (balance-xor, 802.3ad)");
		return -EOPNOTSUPP;
	}
	if (t < 0 || t >= LAGF_TGIDS) {
		NL_SET_ERR_MSG_MOD(extack, "Front-port LAG: no trunk group for this LAG id (0-6, 7 is the CPU group)");
		return -EOPNOTSUPP;
	}
	if (lg_of(port) >= 0 || hw_port_br[port])
		return -EBUSY;
	if (hweight32(lg_ports[t]) >= LAGF_MAX_PORTS) {
		NL_SET_ERR_MSG_MOD(extack, "Front-port LAG: eight members at most");
		return -EOPNOTSUPP;
	}
	if (lagf == 2 && !vp_is_on(LAGF_VP_IDX) && vp_set(ds, LAGF_VP_IDX, true)) {
		NL_SET_ERR_MSG_MOD(extack, "Front-port LAG: slow-protocol VLAN not written, software LAG");
		return -EOPNOTSUPP;
	}
	/* after a refused removal: the boot firmware entry cleared again */
	if (lagf == 2)
		vp_bios_reclaim(ds, LAGF_VP_IDX);
	lg_ports[t] |= BIT(port);
	bcm5331x_lagf_joins++;
	dev_info(ds->dev, "LAG %u, port %d: trunk group %d (written while in an offloaded bridge VLAN)\n",
		 dlag.id, port, t);
	return 0;
}

static int lagf_leave(struct dsa_switch *ds, int port)
{
	int t = lg_of(port), num = port >= 0 && port < NUM_PORTS ? hw_port_br[port] : 0;

	if (t < 0)
		return 0;
	/* DSA leaves the bridge first (dsa_port_lag_leave): never in the group here */
	if ((lg_trunk[t] & BIT(port)) && num) {
		dev_warn(ds->dev, "LAG, port %d: leaving while in the trunk group, taken out of the bridge VLAN\n",
			 port);
		hw_member(ds, port, num, false);
	}
	lg_ports[t] &= ~BIT(port);
	if (lagf == 2 && vp_is_on(LAGF_VP_IDX) && !lg_any())
		vp_set(ds, LAGF_VP_IDX, false);
	if (num) {
		hw_tagger_update(ds, num);
		mdb_reeval(ds, num);
	}
	return 0;
}

/*
 * DSA lag_tx_enabled of a member changed (link, 802.3ad distributing): the
 * egress member of its group may move. EGR_VLAN of the bridge VID swaps the
 * old egress member for the new one, then TRUNK_GROUP follows; the
 * designated port of the tagger is updated in any case.
 */
static int bcm5331x_dsa_port_lag_change(struct dsa_switch *ds, int port)
{
	struct bcm53314 *sw = ds->priv;
	const struct sw_obj *oev = &objs[O_EGR_VLAN], *otg = &objs[O_TRUNK_GROUP];
	int t = lagf ? lg_of(port) : -1, num, ndes, err = 0;
	u32 ev[3], tg[3], w[3], hid, nhid, egr, negr, cpu;
	u16 vid;

	if (t < 0)
		return 0;
	num = hw_port_br[port];
	if (!lg_trunk[t])
		goto tagger;
	ndes = lg_pick(ds, lg_trunk[t], lg_des[t]);
	if (ndes == lg_des[t])
		goto tagger;
	num = hw_port_br[lg_des[t]];
	if (num < 1 || num > BCM5331X_BR_MAX)
		return -EINVAL;
	if (dry_run || access != 2)
		return -EPERM;
	vid = BCM5331X_BR_VID(num);
	hid = lg_hidden();
	nhid = (hid & ~lg_trunk[t]) | (lg_trunk[t] & ~BIT(ndes));
	egr = hw_br_fwd[num] & ~hid;
	negr = hw_br_fwd[num] & ~nhid;
	mutex_lock(&sw->lock);
	hw_nops = 0;
	cpu = hw_cpu_pbm(sw);
	err = sw->halted ? -EIO : sw_read(sw, O_EGR_VLAN, vid, ev);
	if (!err)
		err = sw_read(sw, O_TRUNK_GROUP, t, tg);
	if (err)
		goto out;
	if (!hw_vlan_ok(sw, ev, true) || hw_members(ev, true) != egr || EV_PBM(ev) != (egr | cpu) ||
	    lg_group_of(tg) != lg_des[t]) {
		dev_err(ds->dev, "LAG, port %d: switch not in the state left by the driver: nothing written\n",
			port);
		bcm5331x_hw_refusals++;
		err = -EBUSY;
		goto out;
	}
	egr_vlan_build(w, negr | cpu, negr);
	err = hw_add(HW_EGR_VLAN, oev->name, obj_addr(oev, vid), true, oev->words, vid, oev->parity,
		     ev, w);
	lg_group_build(w, ndes);
	if (!err)
		err = hw_add(HW_TRUNK_GROUP, otg->name, obj_addr(otg, t), true, otg->words, t, 0, tg, w);
	if (!err)
		err = hw_execute(sw, ds->dev);
	if (!err)
		lg_des[t] = ndes;
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "LAG, port %d: egress member of trunk group %d not moved (%d)\n",
			port, t, err);
	else
		dev_info(ds->dev, "LAG, port %d: egress member of trunk group %d = port %d (%d writes, read back)\n",
			 port, t, ndes, hw_nops);
tagger:
	if (num >= 1 && num <= BCM5331X_BR_MAX) {
		hw_tagger_update(ds, num);
		mdb_reeval(ds, num);
	}
	return err;
}

static int bcm5331x_dsa_port_lag_join(struct dsa_switch *ds, int port,
				      struct dsa_lag dlag,
				      struct netdev_lag_upper_info *info,
				      struct netlink_ext_ack *extack)
{
	struct bcm53314 *sw = ds->priv;
	int err;

	if (lagf && bcm5331x_is_front(port))
		return lagf_join(ds, port, dlag, info, extack);
	if (!lag || !lag_cpu_port(ds, port))
		return -EOPNOTSUPP;	/* front ports: software bond */
	if (!info || info->tx_type != NETDEV_LAG_TX_TYPE_HASH) {
		NL_SET_ERR_MSG_MOD(extack, "Conduit LAG: hash transmit policy only (balance-xor)");
		return -EOPNOTSUPP;
	}
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : lag_check_group(sw);
	mutex_unlock(&sw->lock);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Conduit LAG: trunk group 7 {ge2, ge3} not in place");
		return err;
	}
	bcm5331x_lag_joins++;
	return 0;
}

static int bcm5331x_dsa_port_lag_leave(struct dsa_switch *ds, int port,
				       struct dsa_lag dlag)
{
	if (lagf && bcm5331x_is_front(port))
		return lagf_leave(ds, port);
	return lag && lag_cpu_port(ds, port) ? 0 : -EOPNOTSUPP;
}

static int bcm5331x_dsa_port_change_conduit(struct dsa_switch *ds, int port,
					    struct net_device *conduit,
					    struct netlink_ext_ack *extack)
{
	if (!lag || !bcm5331x_is_front(port)) {
		NL_SET_ERR_MSG_MOD(extack, "Changing the conduit needs lag=1");
		return -EOPNOTSUPP;
	}
	return 0;
}

/*
 * Removal of the driver, after the switch left DSA: every boot firmware
 * entry of L2_USER_ENTRY still cleared is given back (normally
 * done by the feature itself, e.g. at the last front-port LAG leave). The
 * rest of what the features wrote stays, as the other steps do (volatile).
 */
static void bcm5331x_bios_l2u_release(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;
	int i;

	if (!hw_bios_l2u_off)
		return;
	mutex_lock(&sw->lock);
	for (i = 0; i < HW_BIOS_L2U_NUM; i++)
		if (hw_bios_l2u_off & BIT(i))
			hw_bios_l2u(sw, ds->dev, "removal", i, false);
	mutex_unlock(&sw->lock);
}

/*
 * The DSA core disconnects the tagger (tables freed, ds->tagger_data NULL)
 * before calling .teardown; the tables are only marked not ready if they
 * are still there (error path of the tag protocol set-up).
 */
static void mr_teardown(struct dsa_switch *ds);
static void qs_teardown(struct dsa_switch *ds);
static void fp_teardown(struct dsa_switch *ds);

static void bcm5331x_dsa_teardown(struct dsa_switch *ds)
{
	struct bcm5331x_tagger_data *td = ds->tagger_data;

	if (td)
		WRITE_ONCE(td->ready, false);
	st_stop();
	fl_teardown(ds);
	if (fdb) {
		int p;

		/* normally none: every port left its bridge first */
		for (p = 0; p < NUM_PORTS; p++)
			if (fdb_nolearn & BIT(p)) {
				dev_warn(ds->dev, "fdb: port %d: learning off left at teardown, restored\n", p);
				fdb_learn_set(ds, p, true);
			}
		if (mdb)
			mdb_flush_all(ds);
		fdb_flush_all(ds);
		age_restore(ds);
	}
	lk_restore(ds->priv);
	ts_teardown(ds);
	mr_teardown(ds);
	fp_teardown(ds);
	qs_teardown(ds);
}

/*
 * A front port is brought up/down by the stack opening the user netdev.
 * The switch MAC stays enabled (set by the "ports" step); the link is a
 * matter of the far end only. Nothing is written to the switch.
 */
static int bcm5331x_dsa_port_enable(struct dsa_switch *ds, int port,
				    struct phy_device *phy)
{
	return 0;
}

static void bcm5331x_dsa_port_disable(struct dsa_switch *ds, int port)
{
}

/*
 * Without double tagging, user VLANs are refused: turning VLAN
 * filtering on fails. The switch already uses the port VIDs internally;
 * letting the stack push 0x8100 VLANs would collide with them. The refusal
 * is -EINVAL, as the DSA core gives when VLAN filtering cannot be applied:
 * the bridge skips -EOPNOTSUPP (SWITCHDEV_F_SKIP_EOPNOTSUPP, filtering then
 * done in software over ports whose tagged frames the switch drops), so
 * -EOPNOTSUPP would not refuse anything. With -EINVAL, turning filtering on
 * over these ports fails and a port cannot join a VLAN-filtering bridge.
 *
 * With double tagging (qinq=Y) the switch carries any 802.1Q tag
 * of a front port as the inner tag and never looks at it: VLAN filtering is
 * the software bridge's, accepted with no switch write.
 *
 * A port of a bridge offloaded to the switch (hwbridge=Y) refuses VLAN
 * filtering in either mode: the bridge VLAN forwards every inner tag
 * between its members, the switch would not filter them. A port of the
 * VLAN-aware bridge offloaded with vlanbr=Y refuses the reverse (its user
 * VLANs are switch VLANs).
 */
static int bcm5331x_dsa_port_vlan_filtering(struct dsa_switch *ds, int port,
					    bool vlan_filtering,
					    struct netlink_ext_ack *extack)
{
	/* 802.1ad: refused before anything else (the protocol is already the bridge's), unless offloaded (vlanbr_ad) */
	if (vlan_filtering && port >= 0 && port < NUM_PORTS && bcm5331x_br_ad(port_br_dev[port]) &&
	    !(vl_port(port) && vl_ad))
		return bcm5331x_ad_refuse(extack);
	/* the offloaded VLAN-aware bridge (vlanbr=Y) keeps VLAN filtering on */
	if (vl_port(port)) {
		if (vlan_filtering)
			return 0;
		NL_SET_ERR_MSG_MOD(extack,
				   "VLAN filtering cannot be turned off on a VLAN-aware bridge offloaded to the BCM53314 (vlanbr=1): recreate the bridge");
		return -EINVAL;
	}
	if (vlan_filtering && port >= 0 && port < NUM_PORTS && hw_port_br[port]) {
		NL_SET_ERR_MSG_MOD(extack,
				   "VLAN filtering is not supported on a bridge offloaded to the BCM53314 (hwbridge=1): create the bridge VLAN-aware");
		return -EINVAL;
	}
	if (qinq_on)
		return 0;
	if (vlan_filtering) {
		NL_SET_ERR_MSG_MOD(extack,
				   "VLAN filtering is not supported on the BCM53314 ports");
		return -EINVAL;
	}
	return 0;
}

/*
 * Bridge and 8021q-upper VLANs of a port. With double tagging they live in
 * the software bridge only (the switch forwards every inner tag of a front
 * port to the CPU link and back): accepted, nothing written; on a port of
 * the VLAN-aware bridge offloaded with vlanbr=Y they are switch VLANs (see
 * "VLAN-aware bridging"; an 8021q upper there is a tagged member too). Without it,
 * -EOPNOTSUPP, the answer of the DSA core when the operation is absent
 * (net/dsa/switch.c dsa_switch_vlan_add/dsa_switch_host_vlan_add), which
 * the bridge skips: base mode behaviour unchanged.
 */
static int bcm5331x_dsa_port_vlan_add(struct dsa_switch *ds, int port,
				      const struct switchdev_obj_port_vlan *vlan,
				      struct netlink_ext_ack *extack)
{
	/* vlanbr_ad: the protocol of the offloaded bridge must still be the one read at its first join */
	if (qinq_on && vl_port(port) && bcm5331x_br_ad(port_br_dev[port]) != vl_ad) {
		bcm5331x_ad_refusals++;
		NL_SET_ERR_MSG_MOD(extack, "BCM53314: VLAN protocol of the offloaded bridge changed after its ports joined: recreate the bridge");
		return -EBUSY;
	}
	if (qinq_on && port >= 0 && port < NUM_PORTS && port_br_dev[port] &&
	    br_vlan_enabled(port_br_dev[port]) && bcm5331x_br_ad(port_br_dev[port]) &&
	    !(vl_port(port) && vl_ad))
		return bcm5331x_ad_refuse(extack);
	/*
	 * MGMT drops every tagged frame on ingress (PORT_DIS_TAG of step
	 * mgmt): a tagged VLAN would send but never receive. Untagged bridge
	 * VLANs and VID 0 (added by 8021q to every device) are accepted.
	 */
	if (qinq_on && port == PORT_MGMT && vlan->vid &&
	    !(vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED)) {
		NL_SET_ERR_MSG_MOD(extack, "mgmt: untagged VLANs only (tagged frames are dropped on ingress)");
		return -EINVAL;
	}
	if (qinq_on && vl_port(port))
		return vl_vlan_add(ds, port, vlan, extack);
	return qinq_on ? 0 : -EOPNOTSUPP;
}

static int bcm5331x_dsa_port_vlan_del(struct dsa_switch *ds, int port,
				      const struct switchdev_obj_port_vlan *vlan)
{
	if (qinq_on && vl_port(port))
		return vl_vlan_del(ds, port, vlan);
	return qinq_on ? 0 : -EOPNOTSUPP;
}

/*
 * Jumbo frames are already allowed by the switch (FRM_LENGTH reset 10240
 * >= 9216, measured): changing the MTU of a port needs no switch write.
 */
static int bcm5331x_dsa_port_change_mtu(struct dsa_switch *ds, int port,
					int new_mtu)
{
	return 0;
}

/*
 * 82574L conduit: frame max 9234, so its MTU max is 9212 (e1000e counts one
 * VLAN tag in the frame). DSA sets the conduit MTU to the user MTU plus the
 * tagger overhead (one 802.1Q tag, 4 bytes) and refuses anything above the
 * conduit's maximum (net/dsa/user.c dsa_user_change_mtu: -ERANGE): the
 * largest user MTU it can apply is 9212 - 4 = 9208. The switch takes the
 * resulting frames (FRM_LENGTH reset 10240). With double tagging, a user
 * VLAN adds its inner tag outside the MTU: 9208 + 14 + 4 + 4 + FCS 4 = 9234,
 * the largest frame of the 82574L, so 9208 holds in both modes.
 */
#define BCM5331X_CONDUIT_MAX_MTU	9212
#define BCM5331X_TAG_OVERHEAD		VLAN_HLEN

static int bcm5331x_dsa_port_max_mtu(struct dsa_switch *ds, int port)
{
	/* MGMT: FRM_LENGTH of port 6 never read (front ports only) */
	if (port == PORT_MGMT)
		return ETH_DATA_LEN;
	return BCM5331X_CONDUIT_MAX_MTU - BCM5331X_TAG_OVERHEAD;
}

/* ---------------------------------------------------------------------- */
/* Hardware statistics (reads only)                                        */

/*
 * The MIB of each port is read from the same 25 counters as the base
 * module's debugfs "mib" (mib_objs[]: 32-bit GPORT counters, never cleared
 * on read, plus the drop counters RDISC, RDBGC0, HOLD, TDBGC2 and
 * EGRDROPPKTCOUNT, whose selections step "counters" sets), with the same
 * S-channel read (sw_read). Under DSA the base module's work item is off
 * (monitor=0), so this driver keeps its own 64-bit sums: a delayed work
 * reads every front port and the CPU link (ge2) every stats_ms (default
 * 10 s: a byte counter wraps in 34 s at 1 Gb/s), one port per hold of
 * sw->lock, and adds the 32-bit difference since the previous read. The
 * sums start at the first read after registration (counts since then, as
 * debugfs "mib" counts since its first read). ethtool -S reads the port
 * once more before answering; ndo_get_stats64 (any context) answers from
 * the copy the last read left, under a spinlock. MGMT and ge3 are not
 * user ports here: not read. Nothing is ever written to the switch; a
 * fault of the base module (halted) stops the reads, the last sums stay.
 * stats_ms=0 = no read at all, no hardware statistics: ndo_get_stats64
 * then gives the DSA core's software counters, as before (and so does a
 * user port that st_idx() does not list).
 */
static unsigned int stats_ms = 10000;
#define ST_MS_MIN		1000
#define ST_MS_MAX		30000	/* below the 34 s wrap of a byte counter at 1 Gb/s */
#define ST_TRUNK		(NUM_SHOWN - 1)	/* shown_port(): trunk = ge2, last line */

module_param(stats_ms, uint, 0444);
MODULE_PARM_DESC(stats_ms, "Period of the MIB reads of the front ports and of ge2, in ms (1000-30000, default 10000; 0 = no hardware statistics, no read)");

/* indexes of mib_objs[] (order of the base module's table: count checked at build, order by a test) */
enum { ST_GRPKT, ST_GRBYT, ST_GRUC, ST_GRMCA, ST_GRBCA, ST_GRFCS, ST_GROVR, ST_GRJBR,
       ST_GRMTUE, ST_GRUND, ST_GRFRG, ST_GR9216, ST_GTPKT, ST_GTBYT, ST_GTUC, ST_GTMCA,
       ST_GTBCA, ST_GTFCS, ST_GTOVR, ST_GT9216, ST_RDISC, ST_RDBGC0, ST_HOLD, ST_TDBGC2,
       ST_EGRDROP, ST_NUM };
static_assert(ST_NUM == NUM_MIB);

struct st_port {
	u32 last[NUM_MIB];
	u64 sum[NUM_MIB];
	bool valid;
};
static struct st_port st_hw[NUM_SHOWN];		/* under sw->lock */
static u64 st_snap[NUM_SHOWN][NUM_MIB];		/* under st_lock */
static DEFINE_SPINLOCK(st_lock);
static struct delayed_work st_work;
static struct bcm53314 *st_sw;
static bool st_inited, st_on;
/* MIB reads made and failed passes: visible to debugfs */
static unsigned long bcm5331x_stats_reads, bcm5331x_stats_faults;

/* line of shown_port() for a DSA port: front ports and ge2 only, else -1 */
static int st_idx(int port)
{
	int i;

	if (port == PORT_TRUNK)
		return ST_TRUNK;
	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++)
		if (front_ports[i].port == port)
			return i;
	return -1;
}

static bool st_enabled(void)
{
	return stats_ms != 0;
}

/* one port: 25 reads, sums on 64 bits; caller holds sw->lock */
static int st_read_port(struct bcm53314 *sw, int i)
{
	struct st_port *s = &st_hw[i];
	const char *label;
	unsigned long flags;
	int p = shown_port(i, &label), j, err;
	u32 w[3];

	if (sw->halted)
		return -EIO;
	for (j = 0; j < NUM_MIB; j++) {
		err = sw_read(sw, mib_objs[j], p, w);
		if (err)
			return err;
		bcm5331x_stats_reads++;
		if (s->valid)
			s->sum[j] += (u32)(w[0] - s->last[j]);
		s->last[j] = w[0];
	}
	s->valid = true;
	spin_lock_irqsave(&st_lock, flags);
	memcpy(st_snap[i], s->sum, sizeof(st_snap[i]));
	spin_unlock_irqrestore(&st_lock, flags);
	return 0;
}

static int st_refresh(struct bcm53314 *sw, int i)
{
	int err;

	mutex_lock(&sw->lock);
	err = st_read_port(sw, i);
	mutex_unlock(&sw->lock);
	return err;
}

/* one pass over the front ports and ge2 (MGMT, line NUM_SHOWN - 2, is not a user port) */
static void st_pass(struct bcm53314 *sw)
{
	int i;

	for (i = 0; i < NUM_SHOWN; i++) {
		if (i == ST_TRUNK - 1)
			continue;	/* MGMT */
		if (st_refresh(sw, i)) {
			bcm5331x_stats_faults++;
			return;
		}
	}
}

static void st_work_fn(struct work_struct *work)
{
	if (!READ_ONCE(st_on) || !st_sw)
		return;
	st_pass(st_sw);
	if (READ_ONCE(st_on) && !st_sw->halted)
		schedule_delayed_work(&st_work, msecs_to_jiffies(stats_ms));
}

/* .setup: first pass (baseline) as soon as the work runs; no read here */
static void st_start(struct bcm53314 *sw)
{
	if (!st_enabled())
		return;
	memset(st_hw, 0, sizeof(st_hw));
	memset(st_snap, 0, sizeof(st_snap));
	st_sw = sw;
	if (!st_inited) {
		INIT_DELAYED_WORK(&st_work, st_work_fn);
		st_inited = true;
	}
	WRITE_ONCE(st_on, true);
	schedule_delayed_work(&st_work, 0);
}

static void st_stop(void)
{
	WRITE_ONCE(st_on, false);
	if (st_inited)
		cancel_delayed_work_sync(&st_work);
}

static u64 st_get(const u64 *v, int k)
{
	return v[k];
}

static void st_copy(int i, u64 *v)
{
	unsigned long flags;

	spin_lock_irqsave(&st_lock, flags);
	memcpy(v, st_snap[i], sizeof(st_snap[i]));
	spin_unlock_irqrestore(&st_lock, flags);
}

static void bcm5331x_dsa_get_strings(struct dsa_switch *ds, int port, u32 stringset,
				     uint8_t *data)
{
	int j;

	if (stringset != ETH_SS_STATS || !st_enabled() || st_idx(port) < 0)
		return;
	for (j = 0; j < NUM_MIB; j++)
		ethtool_puts(&data, objs[mib_objs[j]].name);
}

static int bcm5331x_dsa_get_sset_count(struct dsa_switch *ds, int port, int sset)
{
	if (sset != ETH_SS_STATS || !st_enabled() || st_idx(port) < 0)
		return 0;
	return NUM_MIB;
}

/* ethtool -S: the port is read again first (process context), then the sums */
static void bcm5331x_dsa_get_ethtool_stats(struct dsa_switch *ds, int port, uint64_t *data)
{
	struct bcm53314 *sw = ds->priv;
	int i = st_idx(port);

	if (!st_enabled() || i < 0)
		return;
	if (READ_ONCE(st_on) && st_refresh(sw, i))
		bcm5331x_stats_faults++;
	st_copy(i, data);
}

/*
 * Net device counters of a front port, from the wire side of the switch
 * port (as other DSA drivers report them): good frames, all bytes, error
 * and drop counters; from the copy of the last read (no switch access
 * here, any context). Before the first read: zeros. With stats_ms=0, and
 * for a user port with no line in st_idx() (MGMT under mgmt=1), the DSA
 * core's software counters, as when the operation is absent
 * (net/dsa/user.c dsa_user_get_stats64 uses them only then).
 */
static void bcm5331x_dsa_get_stats64(struct dsa_switch *ds, int port,
				     struct rtnl_link_stats64 *s)
{
	u64 v[NUM_MIB];
	int i = st_idx(port);

	if (!st_enabled() || i < 0 || i == ST_TRUNK) {
		struct net_device *user = dsa_to_port(ds, port)->user;

		if (user)
			dev_get_tstats64(user, s);
		return;
	}
	st_copy(i, v);
	s->rx_packets = st_get(v, ST_GRUC) + st_get(v, ST_GRMCA) + st_get(v, ST_GRBCA);
	s->tx_packets = st_get(v, ST_GTUC) + st_get(v, ST_GTMCA) + st_get(v, ST_GTBCA);
	s->rx_bytes = st_get(v, ST_GRBYT);
	s->tx_bytes = st_get(v, ST_GTBYT);
	s->multicast = st_get(v, ST_GRMCA);
	s->rx_crc_errors = st_get(v, ST_GRFCS);
	s->rx_length_errors = st_get(v, ST_GRUND) + st_get(v, ST_GROVR) + st_get(v, ST_GRMTUE);
	s->rx_errors = st_get(v, ST_GRFCS) + st_get(v, ST_GROVR) + st_get(v, ST_GRJBR) +
		       st_get(v, ST_GRMTUE) + st_get(v, ST_GRUND) + st_get(v, ST_GRFRG);
	s->rx_dropped = st_get(v, ST_RDISC);
	s->tx_errors = st_get(v, ST_GTFCS) + st_get(v, ST_GTOVR);
	s->tx_dropped = st_get(v, ST_TDBGC2) + st_get(v, ST_EGRDROP);
}

/*
 * Standard groups, only the fields the 25 counters give exactly: MAC
 * (IEEE 802.3 30.3.1.1) without octets (GRBYT/GTBYT count bad frames too)
 * and RMON without histograms (only the 4096-9216 bucket is read here).
 * Pause and control frames: not read (GRXPF/GTXPF/GRXCF never read in
 * testing), so no get_pause_stats/get_eth_ctrl_stats.
 */
static void bcm5331x_dsa_get_eth_mac_stats(struct dsa_switch *ds, int port,
					   struct ethtool_eth_mac_stats *m)
{
	u64 v[NUM_MIB];
	int i = st_idx(port);

	if (!st_enabled() || i < 0)
		return;
	st_copy(i, v);
	m->FramesTransmittedOK = v[ST_GTUC] + v[ST_GTMCA] + v[ST_GTBCA];
	m->FramesReceivedOK = v[ST_GRUC] + v[ST_GRMCA] + v[ST_GRBCA];
	m->FrameCheckSequenceErrors = v[ST_GRFCS];
	m->MulticastFramesXmittedOK = v[ST_GTMCA];
	m->BroadcastFramesXmittedOK = v[ST_GTBCA];
	m->MulticastFramesReceivedOK = v[ST_GRMCA];
	m->BroadcastFramesReceivedOK = v[ST_GRBCA];
	m->FrameTooLongErrors = v[ST_GROVR] + v[ST_GRJBR];
}

static void bcm5331x_dsa_get_rmon_stats(struct dsa_switch *ds, int port,
					struct ethtool_rmon_stats *r,
					const struct ethtool_rmon_hist_range **ranges)
{
	u64 v[NUM_MIB];
	int i = st_idx(port);

	if (!st_enabled() || i < 0)
		return;
	st_copy(i, v);
	r->undersize_pkts = v[ST_GRUND];
	r->oversize_pkts = v[ST_GROVR];
	r->fragments = v[ST_GRFRG];
	r->jabbers = v[ST_GRJBR];
	*ranges = NULL;
}

/* ---------------------------------------------------------------------- */
/* Bridge port flags (no switch write); ethtool -s                         */

/*
 * Flags of a bridge port (learning, flooding, isolation, locked port,
 * hairpin, multicast to unicast). On a software bridge (every bridge
 * without hwbridge, and the bridges hwbridge leaves in software) the
 * bridge itself forwards every frame, the switch forwards none between
 * front ports: the bridge applies any flag in software, accepted with no
 * switch write. Without these operations DSA refused every flag with
 * -EINVAL (net/dsa/port.c dsa_port_pre_bridge_flags), so that, e.g.,
 * "bridge link set dev port1 isolated on" or netifd's "option isolate"
 * failed on br-lan. On a bridge offloaded to the switch (hwbridge=1,
 * vlanbr=1) the switch forwards between members and none of these flags
 * is applied in hardware: refused with -EINVAL and a message (the bridge
 * then answers "Operation not supported"; -EOPNOTSUPP here would be taken
 * as "applied in software", net/bridge/br_switchdev.c
 * br_switchdev_set_port_flag). port_bridge_flags itself is reached for an
 * offloaded port only through the DSA core's inherit/clear at join and
 * leave (no pre_ call): -EOPNOTSUPP, which the core skips there.
 */
#define BCM5331X_BRPORT_FLAGS	(BR_LEARNING | BR_FLOOD | BR_MCAST_FLOOD | BR_BCAST_FLOOD | \
				 BR_PORT_LOCKED | BR_PORT_MAB | BR_HAIRPIN_MODE | \
				 BR_ISOLATED | BR_MULTICAST_TO_UNICAST)
/* flags accepted (software bridge) and refused (offloaded bridge): visible to debugfs */
static unsigned long bcm5331x_brflags_soft, bcm5331x_brflags_refused;

static bool bcm5331x_port_offloaded(int port)
{
	return port >= 0 && port < NUM_PORTS && hw_port_br[port];
}

/*
 * Flags of the ports of offloaded bridges (brflags=Y, needs hwbridge=1).
 * With brflags=Y a port of a bridge offloaded to the switch
 * (hwbridge, vlanbr) accepts unicast_flood, multicast_flood,
 * broadcast_flood and isolated, and learning with fdb=1 (on the VLAN-aware
 * bridge with fdbvlan=1 too); locked, MAB, hairpin and multicast to
 * unicast stay refused (-EINVAL: the switch has no such function here, it
 * never sends a frame back to its ingress port). brflags=N: as above.
 *
 * Flooding: three registers per ingress port q, UNKNOWN_UCAST_BLOCK_MASK
 * (IPIPE 0x0f700100 | q << 12), UNKNOWN_MCAST_BLOCK_MASK (0x0f700102) and
 * BCAST_BLOCK_MASK (0x0f700104), BLK_BITMAP 24:0 = egress ports that do
 * not get this kind of flooded frame from q (OpenMDK bcm53314_a0_defs.h,
 * FLAG_PORT; OpenBCM src/bcm/esw/port.c _bcm_port_flood_block_op: register
 * of the ingress port, bit of the egress port). Flag X off on port x: bit
 * x set in the X register of every other front port, never in those of
 * ge2/ge3 (the host must still reach x on the VID of its port: BPDU,
 * frames to an address not yet learnt) nor MGMT. A standalone front port
 * or one of a software bridge has {port, ge2} only in its VLAN: the bit is
 * harmless there, nothing is recomputed at each join. The frames the
 * bridge floods itself through tx_fwd_offload (from ge2) still reach x.
 *
 * Isolation: ING_EGRMSKBMAP (IPIPE 0x0f700135 | q << 12, "Ingress Block
 * Mask", BLK_BITMAP 24:0 = egress ports that get no frame of ingress port
 * q; OpenBCM port.c _bcm_port_flood_block_op, BCM_PORT_FLOOD_BLOCK_ALL,
 * next to the three flood masks; OpenMDK bcm53314_a0_defs.h). Two isolated
 * ports x, y of the same bridge: bit y in the register of x, bit x in that
 * of y; ge2/ge3 never blocked. EGR_MASK (IPIPE memory 0x0f700000), which
 * bcm_esw_port_egress_set indexes by the source module and port "in HiGig
 * mod header", was written and read back but left known unicast between
 * two front ports untouched : not used.
 * The base module only reads this register (no ge2/ge3 bit, steps ports,
 * trunk2, mgmt): bits other than those of the front ports are kept as
 * found.
 *
 * Forwarding state: the bits of a port are in the switch only while it
 * forwards in hardware: taken out before it leaves the bridge VLAN (STP
 * state, and the bridge disables the port before it leaves:
 * net/bridge/br_if.c del_nbp, br_stp_disable_port before
 * netdev_upper_dev_unlink), put back after it entered it; the flags
 * themselves are kept.
 *
 * Learning: BR_LEARNING off = CML 2 in every STP state (fdb_learn_set),
 * on = the rule of the STP state.
 *
 * At the first write the three flood masks of the 25 ports and their
 * ING_EGRMSKBMAP are read: any bit set in a flood mask, or any front-port
 * bit in ING_EGRMSKBMAP, refuses (nothing written, the driver does not
 * know who set it). The driver then keeps a shadow of the
 * bits it wrote; each write re-reads the register (it must hold the
 * shadow), is checked by fl_op_ok (front-port bits only, never the
 * ingress port's own, a set bit is a port of an offloaded bridge, of the
 * same bridge for ING_EGRMSKBMAP, other bits unchanged), written and read back (a mismatch halts the
 * base module). A port leaving its bridge has its bits cleared first, as
 * the DSA core does not clear BR_ISOLATED and restores flooding only after
 * the port is standalone; teardown clears whatever is left. Volatile, as
 * every write of this driver.
 */
#define FL_A_ISO		0x0f700135	/* IPIPE ING_EGRMSKBMAP, | ingress port << 12 */
#define FL_NTYPES		3
#define FL_HW_FLAGS		(BR_FLOOD | BR_MCAST_FLOOD | BR_BCAST_FLOOD | BR_ISOLATED)
/* the value of a flag the switch cannot apply that is still accepted (DSA inherit/clear) */
#define FL_DEFAULTS		(BR_LEARNING | BR_FLOOD | BR_MCAST_FLOOD | BR_BCAST_FLOOD)
static const u32 fl_addr[FL_NTYPES] = {
	0x0f700100,	/* UNKNOWN_UCAST_BLOCK_MASK */
	0x0f700102,	/* UNKNOWN_MCAST_BLOCK_MASK */
	0x0f700104,	/* BCAST_BLOCK_MASK */
};
static const char *const fl_name[FL_NTYPES] = {
	"UNKNOWN_UCAST_BLOCK_MASK", "UNKNOWN_MCAST_BLOCK_MASK", "BCAST_BLOCK_MASK",
};
static const unsigned long fl_flag[FL_NTYPES] = { BR_FLOOD, BR_MCAST_FLOOD, BR_BCAST_FLOOD };
static bool fl_checked;				/* registers read once, found clear */
static u32 fl_noflood[FL_NTYPES];		/* front ports with flag X off */
static u32 fl_isolated;				/* front ports isolated */
static u32 fl_shadow[FL_NTYPES][NUM_PORTS];	/* bits written in each block mask */
static u32 fl_egr_shadow[NUM_PORTS];		/* front-port bits written in ING_EGRMSKBMAP[port] */
static u32 fl_iso_base[NUM_PORTS];		/* its other bits as found */
static u32 fl_fwd;				/* ports of offloaded bridges forwarding in hardware */
/* writes done and read back, refusals: visible to debugfs */
static unsigned long bcm5331x_fl_writes, bcm5331x_fl_refusals;

module_param(brflags, bool, 0444);
MODULE_PARM_DESC(brflags, "Flags of the ports of offloaded bridges (needs hwbridge=1): unicast/multicast/broadcast flooding by the switch's flood block masks, isolation by ING_EGRMSKBMAP, learning with fdb=1 (switch writes at run time, read back; default N = refused as before)");

/* flags a port of an offloaded bridge applies in the switch */
static unsigned long fl_hw_flags(int port)
{
	return FL_HW_FLAGS | (fdb && fdb_learn_br(hw_port_br[port]) ? BR_LEARNING : 0);
}

/* bits of block mask @t of ingress port @q for the flood state @nf */
static u32 fl_want(const u32 *nf, int t, int q)
{
	return bcm5331x_is_front(q) ? nf[t] & fl_fwd & hw_front_pbm() & ~BIT(q) : 0;
}

/* front-port bits of ING_EGRMSKBMAP[@x] for the isolated ports @ni: the other forwarding isolated ports of its bridge */
static u32 fl_egr_want(u32 ni, int x)
{
	u32 m = 0;
	int y;

	ni &= fl_fwd;
	if (!bcm5331x_is_front(x) || !(ni & BIT(x)) || !hw_port_br[x])
		return 0;
	for (y = 0; y < NUM_PORTS; y++)
		if (y != x && (ni & BIT(y)) && bcm5331x_is_front(y) && hw_port_br[y] == hw_port_br[x])
			m |= BIT(y);
	return m;
}

/* The one change of a flag write: front-port bits only, own bit never, set bits = offloaded ports */
static bool fl_op_ok(u32 addr, bool mem, int q, u32 old, u32 val)
{
	u32 fr = hw_front_pbm(), set = val & ~old;
	int t, y, ok = 0;

	bool iso = addr == (FL_A_ISO | (u32)q << 12);

	if (!brflags || mem || q < 0 || q >= NUM_PORTS || !bcm5331x_is_front(q) || old == val ||
	    (val & BIT(q)) || ((old ^ val) & ~fr) || (!iso && ((old | val) & ~fr)))
		return false;
	if (!iso) {
		for (t = 0; t < FL_NTYPES; t++)
			ok |= addr == (fl_addr[t] | (u32)q << 12);
		if (!ok)
			return false;
	}
	for (y = 0; y < NUM_PORTS; y++)
		if ((set & BIT(y)) && (!hw_port_br[y] || (iso && hw_port_br[y] != hw_port_br[q])))
			return false;
	return true;
}

/* one flag write: re-read (must hold @old), rule, written, read back; under sw->lock */
static int fl_write(struct bcm53314 *sw, struct device *dev, const char *name, u32 addr, bool mem,
		    int q, u32 old, u32 val)
{
	u32 w[3] = { 0 };
	int err;

	if (!fl_op_ok(addr, mem, q, old, val)) {
		dev_err(dev, "flags: %s[%d] %08x -> %08x refused: nothing written\n", name, q, old, val);
		bcm5331x_fl_refusals++;
		return -EPERM;
	}
	err = schan_xfer(sw, false, mem, addr, 1, w, name, q);
	if (err)
		return err;
	if (w[0] != old) {
		sw_fault(sw, "dsa: flags %s[%d] is %08x, expected %08x", name, q, w[0], old);
		return -ESTALE;
	}
	w[0] = val;
	err = schan_xfer(sw, true, mem, addr, 1, w, name, q);
	if (err)
		return err;
	udelay(10);
	w[0] = 0;
	err = schan_xfer(sw, false, mem, addr, 1, w, name, q);
	if (err)
		return err;
	bcm5331x_fl_writes++;
	if (w[0] != val) {
		sw_fault(sw, "dsa: flags %s[%d] read back %08x, wrote %08x", name, q, w[0], val);
		return -EIO;
	}
	return 0;
}

/* first write: the flood masks of the 25 ports clear, no front-port bit in their ING_EGRMSKBMAP (reads only); under sw->lock */
static int fl_check(struct bcm53314 *sw, struct device *dev)
{
	u32 w[3];
	int t, q, err;

	for (t = 0; t < FL_NTYPES; t++)
		for (q = 0; q < NUM_PORTS; q++) {
			memset(w, 0, sizeof(w));
			err = schan_xfer(sw, false, false, fl_addr[t] | (u32)q << 12, 1, w, fl_name[t], q);
			if (err)
				return err;
			if (w[0]) {
				dev_err(dev, "flags: %s[%d] = %08x as found: refused, nothing written\n",
					fl_name[t], q, w[0]);
				bcm5331x_fl_refusals++;
				return -EBUSY;
			}
		}
	for (q = 0; q < NUM_PORTS; q++) {
		memset(w, 0, sizeof(w));
		err = schan_xfer(sw, false, false, FL_A_ISO | (u32)q << 12, 1, w, "ING_EGRMSKBMAP", q);
		if (err)
			return err;
		if (w[0] & hw_front_pbm()) {
			dev_err(dev, "flags: ING_EGRMSKBMAP[%d] = %08x as found: refused, nothing written\n", q, w[0]);
			bcm5331x_fl_refusals++;
			return -EBUSY;
		}
		fl_iso_base[q] = w[0];
	}
	fl_checked = true;
	return 0;
}

/* the switch to the flood state @nf and isolated ports @ni (only what differs from the shadow) */
static int fl_sync(struct dsa_switch *ds, const u32 *nf, u32 ni)
{
	struct bcm53314 *sw = ds->priv;
	int t, q, n = 0, err = 0;
	bool need = false;

	for (q = 0; q < NUM_PORTS; q++) {
		for (t = 0; t < FL_NTYPES; t++)
			need |= fl_want(nf, t, q) != fl_shadow[t][q];
		need |= fl_egr_want(ni, q) != fl_egr_shadow[q];
	}
	if (!need)
		return 0;
	if (access != 2 || dry_run)
		return -EPERM;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : 0;
	if (!err && !fl_checked)
		err = fl_check(sw, ds->dev);
	/* ING_EGRMSKBMAP first, then the flood block masks */
	for (q = 0; !err && q < NUM_PORTS; q++) {
		u32 v = fl_egr_want(ni, q);

		if (v == fl_egr_shadow[q])
			continue;
		err = fl_write(sw, ds->dev, "ING_EGRMSKBMAP", FL_A_ISO | (u32)q << 12, false, q,
			       fl_iso_base[q] | fl_egr_shadow[q], fl_iso_base[q] | v);
		if (!err) {
			fl_egr_shadow[q] = v;
			n++;
		}
	}
	for (t = 0; !err && t < FL_NTYPES; t++)
		for (q = 0; !err && q < NUM_PORTS; q++) {
			u32 v = fl_want(nf, t, q);

			if (v == fl_shadow[t][q])
				continue;
			err = fl_write(sw, ds->dev, fl_name[t], fl_addr[t] | (u32)q << 12, false, q,
				       fl_shadow[t][q], v);
			if (!err) {
				fl_shadow[t][q] = v;
				n++;
			}
		}
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "flags: switch update failed after %d writes (%d)\n", n, err);
	else
		dev_info(ds->dev, "flags: %d writes, read back\n", n);
	return err;
}

/* apply @flags to port @port of an offloaded bridge (brflags=Y) */
static int fl_set(struct dsa_switch *ds, int port, struct switchdev_brport_flags flags)
{
	unsigned long hw = fl_hw_flags(port), other = flags.mask & ~hw;
	u32 nf[FL_NTYPES], ni = fl_isolated, bit = BIT(port);
	bool lchg = false, lon = true;
	int t, err;

	/* a flag the switch does not apply: only its default value (DSA inherit/clear) */
	if ((flags.val ^ FL_DEFAULTS) & other)
		return -EINVAL;
	for (t = 0; t < FL_NTYPES; t++) {
		nf[t] = fl_noflood[t];
		if (flags.mask & fl_flag[t])
			nf[t] = flags.val & fl_flag[t] ? nf[t] & ~bit : nf[t] | bit;
	}
	if (flags.mask & BR_ISOLATED)
		ni = flags.val & BR_ISOLATED ? ni | bit : ni & ~bit;
	if (flags.mask & hw & BR_LEARNING) {
		lon = flags.val & BR_LEARNING;
		lchg = lon != !(fl_nolearn & bit);
	}
	err = fl_sync(ds, nf, ni);
	if (err)
		return err;
	memcpy(fl_noflood, nf, sizeof(fl_noflood));
	fl_isolated = ni;
	if (lchg) {
		u8 st = fl_stp[port];

		fl_nolearn ^= bit;
		fdb_learn_set(ds, port, lon && (st == BR_STATE_LEARNING || st == BR_STATE_FORWARDING));
	}
	return 0;
}

/* port @port starts (@on) or stops forwarding in hardware: its flag bits follow */
static void fl_fwd_set(struct dsa_switch *ds, int port, bool on)
{
	u32 bit = BIT(port);

	if (!brflags || port < 0 || port >= NUM_PORTS || !!(fl_fwd & bit) == on)
		return;
	fl_fwd = on ? fl_fwd | bit : fl_fwd & ~bit;
	fl_sync(ds, fl_noflood, fl_isolated);	/* a failure is logged; retried at the next change */
}

/* port @port leaves its offloaded bridge: its bits cleared (still a member) */
static void fl_leave(struct dsa_switch *ds, int port)
{
	u32 nf[FL_NTYPES], bit = BIT(port);
	int t;

	if (!brflags)
		return;
	for (t = 0; t < FL_NTYPES; t++)
		nf[t] = fl_noflood[t] & ~bit;
	fl_nolearn &= ~bit;	/* the CML itself comes back with fdb_learn_set at the leave */
	fl_fwd &= ~bit;
	if (!fl_sync(ds, nf, fl_isolated & ~bit)) {
		memcpy(fl_noflood, nf, sizeof(fl_noflood));
		fl_isolated &= ~bit;
	}
}

/* teardown: nothing left in the switch (normally already so) */
static void fl_teardown(struct dsa_switch *ds)
{
	static const u32 none[FL_NTYPES];

	if (!brflags)
		return;
	fl_fwd = 0;
	if (!fl_sync(ds, none, 0)) {
		memset(fl_noflood, 0, sizeof(fl_noflood));
		fl_isolated = 0;
	}
	fl_nolearn = 0;
}

static int bcm5331x_dsa_port_pre_bridge_flags(struct dsa_switch *ds, int port,
					      struct switchdev_brport_flags flags,
					      struct netlink_ext_ack *extack)
{
	if (flags.mask & ~BCM5331X_BRPORT_FLAGS)
		return -EINVAL;
	if (bcm5331x_port_offloaded(port)) {
		if (brflags && !(flags.mask & ~fl_hw_flags(port)))
			return 0;
		bcm5331x_brflags_refused++;
		if (brflags)
			NL_SET_ERR_MSG_MOD(extack,
					   "BCM53314 offloaded bridge: only flooding, isolation and (with fdb=1) learning are applied in the switch");
		else
			NL_SET_ERR_MSG_MOD(extack,
					   "Bridge port flags are not offloaded to the BCM53314 (bridge offloaded with hwbridge=1): use a software bridge");
		return -EINVAL;
	}
	return 0;
}

static int bcm5331x_dsa_port_bridge_flags(struct dsa_switch *ds, int port,
					  struct switchdev_brport_flags flags,
					  struct netlink_ext_ack *extack)
{
	if (bcm5331x_port_offloaded(port))
		return brflags ? fl_set(ds, port, flags) : -EOPNOTSUPP;
	bcm5331x_brflags_soft++;
	return 0;
}

/* ---------------------------------------------------------------------- */
/* Port mirroring (mirror=Y)                                               */

/*
 * tc matchall + mirred on a front port (ingress or egress) is offloaded to
 * the mirroring of the switch. Registers and their meaning:
 *  - OpenMDK cdk/PKG/chip/bcm53314/bcm53314_a0_defs.h: MIRROR_CONTROL
 *    (IPIPE 0x0f700108, per port: M_ENABLE 0, IM_MTP_INDEX 2:1,
 *    EM_MTP_INDEX 4:3, NON_UC_EM_MTP_INDEX 6:5, SRC_MODID_BLOCK_* 7-8),
 *    EMIRROR_CONTROL (IPIPE 0x0f700109, per port: BITMAP 24:0),
 *    IM_MTP_INDEX / EM_MTP_INDEX (IPIPE tables 0x0f7a0000 / 0x0f7b0000,
 *    4 entries: PORT_TGID 6:0, MODULE_ID 10:7 "needs to be zeros"),
 *    PORT_TAB.MIRROR (bit 4, "mirror enable", per ingress port);
 *  - OpenBCM sdk-6.5.16 src/bcm/esw/mirror.c (non-flexible XGS3 path of
 *    the Raptor family the Hawkeye belongs to): ingress mirroring of port p
 *    = MIRROR_CONTROL[p].IM_MTP_INDEX set to the MTP (destination) index
 *    (_bcm_xgs3_mirror_ingress_mtp_install) and PORT_TAB[p].MIRROR set
 *    (_bcm_port_mirror_enable_set, firebolt/port.c pc_mirror_ing ->
 *    MIRRORf); egress mirroring of port x = bit x in EMIRROR_CONTROL[q].
 *    BITMAP of every ingress port q (EMIRROR_CONTROL is indexed by the
 *    INGRESS port: _bcm_esw_mirror_egress_set over PBMP_ALL,
 *    _bcm_raptor_mirror_egr_dest_set), destination from
 *    MIRROR_CONTROL[q].EM_MTP_INDEX and NON_UC_EM_MTP_INDEX, set on every
 *    port (_bcm_xgs3_mirror_egress_mtp_install); M_ENABLE "must also be
 *    globally enabled" (_bcm_xgs3_mirror_enable_set). MTP entries:
 *    PORT_TGID = destination port, MODULE_ID 0.
 *
 * Layout kept by this driver (one MIRROR_CONTROL per ingress port, a
 * single EM_MTP_INDEX field per port):
 *  - ingress: one destination per source port, IM_MTP_INDEX[0-3] shared by
 *    the sources of the same destination (at most 4 destinations);
 *  - egress: one destination for all egress-mirrored ports, in
 *    EM_MTP_INDEX[0]; the ingress ports that may send to a front port (ge2,
 *    ge3 under trunk2, the 19 front ports; never MGMT nor the CMIC) get the
 *    bitmap of the mirrored ports, EM and NON_UC_EM index 0 and M_ENABLE;
 *  - M_ENABLE set only on a port with a role (ingress source, or ingress
 *    port of egress mirroring), the rest of MIRROR_CONTROL kept;
 *  - sources and destinations are front ports (MGMT excluded), a
 *    destination is never a source (no chain), never the port itself; a
 *    destination on the CPU (mirred to a foreign device, or to the ingress
 *    of a user port) is refused: DSA then keeps the software rule, which
 *    does that copy already (and the switch's copy to ge2 would carry no
 *    usable port: the tagger takes the port from the VID).
 *
 * Writes: nothing at load. The first add reads the whole origin (25
 * MIRROR_CONTROL, 25 EMIRROR_CONTROL, 4 + 4 MTP entries, PORT_TAB of the 19
 * front ports) and requires mirroring off everywhere (M_ENABLE clear,
 * empty bitmaps, PORT_TAB.MIRROR clear) - else every mirror is refused,
 * nothing written. Each add/del computes the registers it changes, checks
 * the whole plan (only the mirroring fields, only these ports), then
 * re-reads each register before its write and reads it back after (fault
 * = module halted, as the other writers). Enabling writes the MTP entries
 * first, then MIRROR_CONTROL, then the triggers (EMIRROR_CONTROL,
 * PORT_TAB.MIRROR); disabling goes the other way. The last del, and the
 * teardown, put every register back to its origin value.
 *
 * Step mgmt of the base module (plan_mgmt) refuses to run while any
 * MIRROR_CONTROL.M_ENABLE or EMIRROR_CONTROL bitmap is set: it runs at
 * load, before any DSA operation, and the teardown here restores the
 * origin, so a later load with steps=...,mgmt finds mirroring off. MGMT is
 * never a source, a destination, nor an ingress port of egress mirroring.
 *
 * The flag (module parameter mirror, default N) may be set at run time
 * (/sys/module/bcm5331x_dsa/parameters/mirror): it only gates new adds;
 * a del always runs. debugfs "mirror" shows the state, the registers and
 * the receive/transmit packet counters of the front ports (reads only).
 */
#define MR_A_IM_MTP		0x0f7a0000	/* IPIPE IM_MTP_INDEX, + index */
#define MR_A_EM_MTP		0x0f7b0000	/* IPIPE EM_MTP_INDEX, + index */
#define MR_MTP_NUM		4
#define MR_MTP_PORT		GENMASK(6, 0)	/* PORT_TGID */
#define MR_MTP_FIELDS		GENMASK(10, 0)	/* PORT_TGID, MODULE_ID */
#define MR_MC_ENABLE		BIT(0)		/* MIRROR_CONTROL */
#define MR_MC_IM		GENMASK(2, 1)
#define MR_MC_EM		GENMASK(4, 3)
#define MR_MC_NUC_EM		GENMASK(6, 5)
#define MR_MC_ROLE		(MR_MC_ENABLE | MR_MC_IM | MR_MC_EM | MR_MC_NUC_EM)
#define MR_EMC_BITMAP		GENMASK(24, 0)	/* EMIRROR_CONTROL */
#define MR_PT0_MIRROR		BIT(4)		/* PORT_TAB word 0 */
#define MR_EM_SLOT		0
#define MR_NOPS			(2 * MR_MTP_NUM + 2 * NUM_PORTS + NUM_PORTS)

enum mr_kind { MR_IM, MR_EM, MR_MC, MR_EMC, MR_PT };

struct mr_op {
	enum mr_kind kind;
	int idx;
	u32 old[3];
	u32 val[3];
};

static bool mirror_on;
static bool mr_read;			/* origin read */
static bool mr_ok;			/* origin read and mirroring off: mirrors possible */
static u32 mr_mc0[NUM_PORTS], mr_emc0[NUM_PORTS], mr_im0[MR_MTP_NUM], mr_em0[MR_MTP_NUM];	/* origin */
static u32 mr_mc[NUM_PORTS], mr_emc[NUM_PORTS], mr_im[MR_MTP_NUM], mr_em[MR_MTP_NUM];	/* last read or written */
static u32 mr_pt;			/* front ports whose PORT_TAB.MIRROR is set (by the driver) */
static u8 mr_ing_dest[NUM_PORTS];	/* ingress destination of a source port, 0 = none */
static u8 mr_ing_slot[NUM_PORTS];
static u8 mr_slot_dest[MR_MTP_NUM];
static int mr_slot_refs[MR_MTP_NUM];
static u32 mr_egr_src;			/* front ports mirrored at egress */
static u8 mr_egr_dest;
static struct mr_op mr_ops[MR_NOPS];
static int mr_nops;
/* mirroring writes done and read back, refusals: visible to debugfs */
static unsigned long bcm5331x_mirror_writes, bcm5331x_mirror_refusals;

module_param_named(mirror, mirror_on, bool, 0644);
MODULE_PARM_DESC(mirror, "Offload tc matchall mirred (ingress and egress mirroring) between front ports to the switch (MIRROR_CONTROL, EMIRROR_CONTROL, IM/EM_MTP_INDEX, PORT_TAB.MIRROR; written at run time only, read back, origin restored at the last del and at unload; may be set at run time; default N = software mirroring only, no write)");

/* a front port of DSA, never MGMT */
static bool mr_front(int port)
{
	return port > 0 && port < NUM_PORTS && port != PORT_MGMT && bcm5331x_is_front(port);
}

/* ingress ports of egress mirroring: CPU side and front ports, never MGMT nor the CMIC */
static u32 mr_e_pbm(const struct bcm53314 *sw)
{
	return (hw_cpu_pbm(sw) | hw_front_pbm()) & ~BIT(PORT_MGMT) & ~BIT(0);
}

static bool mr_is_dest(int port)
{
	int i;

	for (i = 0; i < MR_MTP_NUM; i++)
		if (mr_slot_refs[i] && mr_slot_dest[i] == port)
			return true;
	return mr_egr_src && mr_egr_dest == port;
}

static bool mr_is_src(int port)
{
	return mr_ing_dest[port] || (mr_egr_src & BIT(port));
}

static bool mr_active(void)
{
	int i;

	for (i = 0; i < MR_MTP_NUM; i++)
		if (mr_slot_refs[i])
			return true;
	return mr_egr_src != 0;
}

/* the value each register must hold for the current state */
static u32 mr_want_mc(const struct bcm53314 *sw, int p)
{
	bool ing = mr_ing_dest[p], egr = mr_egr_src && (mr_e_pbm(sw) & BIT(p));
	u32 v = mr_mc0[p];

	if (!ing && !egr)
		return v;
	v |= MR_MC_ENABLE;
	if (ing)
		v = (v & ~MR_MC_IM) | QQ_PUT(MR_MC_IM, mr_ing_slot[p]);
	if (egr)
		v = (v & ~(MR_MC_EM | MR_MC_NUC_EM)) | QQ_PUT(MR_MC_EM, MR_EM_SLOT) |
		    QQ_PUT(MR_MC_NUC_EM, MR_EM_SLOT);
	return v;
}

static u32 mr_want_emc(const struct bcm53314 *sw, int p)
{
	if (!mr_egr_src || !(mr_e_pbm(sw) & BIT(p)))
		return mr_emc0[p];
	return (mr_emc0[p] & ~MR_EMC_BITMAP) | mr_egr_src;
}

static u32 mr_want_im(int i)
{
	return mr_slot_refs[i] ? (mr_im0[i] & ~MR_MTP_FIELDS) | mr_slot_dest[i] : mr_im0[i];
}

static u32 mr_want_em(int i)
{
	return i == MR_EM_SLOT && mr_egr_src ? (mr_em0[i] & ~MR_MTP_FIELDS) | mr_egr_dest : mr_em0[i];
}

static void mr_reg(enum mr_kind k, int idx, u32 *addr, bool *mem, int *words, const char **name)
{
	*mem = true;
	*words = 1;
	switch (k) {
	case MR_IM:
		*addr = MR_A_IM_MTP + idx;
		*name = "IM_MTP_INDEX";
		break;
	case MR_EM:
		*addr = MR_A_EM_MTP + idx;
		*name = "EM_MTP_INDEX";
		break;
	case MR_MC:
	case MR_EMC: {
		const struct sw_obj *o = &objs[k == MR_MC ? O_MIRROR_CONTROL : O_EMIRROR_CONTROL];

		*addr = obj_addr(o, idx);
		*mem = false;
		*name = o->name;
		break;
	}
	case MR_PT:
		*addr = obj_addr(&objs[O_PORT_TAB], idx);
		*words = objs[O_PORT_TAB].words;
		*name = objs[O_PORT_TAB].name;
		break;
	}
}

static int mr_rd(struct bcm53314 *sw, enum mr_kind k, int idx, u32 *w)
{
	const char *name;
	u32 addr;
	bool mem;
	int words;

	mr_reg(k, idx, &addr, &mem, &words, &name);
	memset(w, 0, 3 * sizeof(*w));
	return schan_xfer(sw, false, mem, addr, words, w, name, idx);
}

/* a destination as an MTP entry holds it: PORT_TGID = a front port, MODULE_ID 0 */
static bool mr_mtp_ok(u32 v, u32 v0)
{
	return v == v0 || (!((v ^ v0) & ~MR_MTP_FIELDS) && !(v & MR_MTP_FIELDS & ~MR_MTP_PORT) &&
			   mr_front(v & MR_MTP_PORT));
}

/* The one change each mirroring write may make (whole plan checked first) */
static bool mr_op_ok(const struct bcm53314 *sw, const struct mr_op *op)
{
	const u32 *a = op->old, *n = op->val;
	int p = op->idx;
	u32 b;

	switch (op->kind) {
	case MR_IM:
		return p >= 0 && p < MR_MTP_NUM && a[0] == mr_im[p] && mr_mtp_ok(n[0], mr_im0[p]);
	case MR_EM:
		return p >= 0 && p < MR_MTP_NUM && a[0] == mr_em[p] &&
		       (n[0] == mr_em0[p] || (p == MR_EM_SLOT && mr_mtp_ok(n[0], mr_em0[p])));
	case MR_MC:
		if (p < 0 || p >= NUM_PORTS || a[0] != mr_mc[p] || ((a[0] ^ n[0]) & ~MR_MC_ROLE))
			return false;
		if (n[0] == mr_mc0[p])
			return true;
		/* enabled on a port with a role only; the ingress index of a source = the MTP of its destination */
		if (!(n[0] & MR_MC_ENABLE) || (!mr_ing_dest[p] && !(mr_egr_src && (mr_e_pbm(sw) & BIT(p)))))
			return false;
		if (mr_ing_dest[p] &&
		    (mr_want_im(QQ_GET(MR_MC_IM, n[0])) & MR_MTP_PORT) != mr_ing_dest[p])
			return false;
		return !mr_egr_src || !(mr_e_pbm(sw) & BIT(p)) ||
		       (QQ_GET(MR_MC_EM, n[0]) == MR_EM_SLOT && QQ_GET(MR_MC_NUC_EM, n[0]) == MR_EM_SLOT);
	case MR_EMC:
		if (p < 0 || p >= NUM_PORTS || a[0] != mr_emc[p] || ((a[0] ^ n[0]) & ~MR_EMC_BITMAP))
			return false;
		if (n[0] == mr_emc0[p])
			return true;
		b = n[0] & MR_EMC_BITMAP;
		/* bitmap = the egress-mirrored front ports, on an ingress port of egress mirroring */
		return (mr_e_pbm(sw) & BIT(p)) && b == mr_egr_src && !(b & ~hw_front_pbm()) &&
		       !(b & BIT(PORT_MGMT)) && mr_front(mr_egr_dest) && !(b & BIT(mr_egr_dest));
	case MR_PT:
		return mr_front(p) && !((a[0] ^ n[0]) & ~MR_PT0_MIRROR) && a[1] == n[1] && a[2] == n[2] &&
		       !!(n[0] & MR_PT0_MIRROR) == !!mr_ing_dest[p] && !!(a[0] & MR_PT0_MIRROR) == !!(mr_pt & BIT(p));
	}
	return false;
}

static int mr_add_op(enum mr_kind k, int idx, const u32 *old, const u32 *val)
{
	struct mr_op *op;

	if (mr_nops >= MR_NOPS)
		return -ENOSPC;
	op = &mr_ops[mr_nops++];
	memset(op, 0, sizeof(*op));
	op->kind = k;
	op->idx = idx;
	memcpy(op->old, old, sizeof(op->old));
	memcpy(op->val, val, sizeof(op->val));
	return 0;
}

static int mr_plan_one(struct bcm53314 *sw, enum mr_kind k, int n)
{
	u32 o[3] = { 0 }, v[3] = { 0 };
	int i, err = 0;

	for (i = 0; i < n && !err; i++) {
		switch (k) {
		case MR_IM:
			o[0] = mr_im[i];
			v[0] = mr_want_im(i);
			break;
		case MR_EM:
			o[0] = mr_em[i];
			v[0] = mr_want_em(i);
			break;
		case MR_MC:
			o[0] = mr_mc[i];
			v[0] = mr_want_mc(sw, i);
			break;
		case MR_EMC:
			o[0] = mr_emc[i];
			v[0] = mr_want_emc(sw, i);
			break;
		case MR_PT:
			if (!mr_front(i) || !!(mr_pt & BIT(i)) == !!mr_ing_dest[i])
				continue;
			/* PORT_TAB is shared with the other writers: read now, only bit 4 changes */
			err = mr_rd(sw, MR_PT, i, o);
			if (err)
				return err;
			memcpy(v, o, sizeof(v));
			v[0] = mr_ing_dest[i] ? o[0] | MR_PT0_MIRROR : o[0] & ~MR_PT0_MIRROR;
			break;
		}
		if (memcmp(o, v, sizeof(o)))
			err = mr_add_op(k, i, o, v);
	}
	return err;
}

/* the writes from the registers as left to the current state: triggers last on, first off */
static int mr_plan(struct bcm53314 *sw, bool on)
{
	static const enum mr_kind up[] = { MR_IM, MR_EM, MR_MC, MR_EMC, MR_PT };
	int i, err = 0;

	mr_nops = 0;
	for (i = 0; i < (int)ARRAY_SIZE(up) && !err; i++) {
		enum mr_kind k = up[on ? i : ARRAY_SIZE(up) - 1 - i];

		err = mr_plan_one(sw, k, k == MR_IM || k == MR_EM ? MR_MTP_NUM : NUM_PORTS);
	}
	return err;
}

static void mr_note(const struct mr_op *op)
{
	switch (op->kind) {
	case MR_IM:
		mr_im[op->idx] = op->val[0];
		break;
	case MR_EM:
		mr_em[op->idx] = op->val[0];
		break;
	case MR_MC:
		mr_mc[op->idx] = op->val[0];
		break;
	case MR_EMC:
		mr_emc[op->idx] = op->val[0];
		break;
	case MR_PT:
		if (op->val[0] & MR_PT0_MIRROR)
			mr_pt |= BIT(op->idx);
		else
			mr_pt &= ~BIT(op->idx);
		break;
	}
}

/* plan checked, then each write re-read before, written, read back (under sw->lock) */
static int mr_execute(struct bcm53314 *sw, struct device *dev)
{
	int i, j, err;

	for (i = 0; i < mr_nops; i++)
		if (!mr_op_ok(sw, &mr_ops[i])) {
			dev_err(dev, "mirror: write %d/%d (kind %d, index %d) refused: nothing written\n",
				i + 1, mr_nops, mr_ops[i].kind, mr_ops[i].idx);
			bcm5331x_mirror_refusals++;
			return -EPERM;
		}
	for (i = 0; i < mr_nops; i++) {
		struct mr_op *op = &mr_ops[i];
		u32 cur[3], rb[3], addr;
		const char *name;
		bool mem;
		int words;

		mr_reg(op->kind, op->idx, &addr, &mem, &words, &name);
		err = mr_rd(sw, op->kind, op->idx, cur);
		if (err)
			return err;
		for (j = 0; j < words; j++)
			if (cur[j] != op->old[j]) {
				sw_fault(sw, "dsa: mirror %s[%d] is %08x, expected %08x", name, op->idx,
					 cur[j], op->old[j]);
				return -ESTALE;
			}
		memcpy(rb, op->val, sizeof(rb));
		err = schan_xfer(sw, true, mem, addr, words, rb, name, op->idx);
		if (err)
			return err;
		udelay(10);
		err = mr_rd(sw, op->kind, op->idx, rb);
		if (err)
			return err;
		bcm5331x_mirror_writes++;
		for (j = 0; j < words; j++)
			if (rb[j] != op->val[j]) {
				sw_fault(sw, "dsa: mirror %s[%d] read back %08x, wrote %08x", name, op->idx,
					 rb[j], op->val[j]);
				return -EIO;
			}
		mr_note(op);
		dev_dbg(dev, "mirror %s[%d] addr 0x%08x: %08x -> %08x\n", name, op->idx, addr,
			op->old[0], op->val[0]);
	}
	return 0;
}

/* first use: the whole origin, mirroring required off everywhere */
static int mr_origin(struct bcm53314 *sw, struct device *dev)
{
	u32 w[3];
	int p, i, err = 0;

	if (mr_read)
		return mr_ok ? 0 : -EBUSY;
	for (p = 0; p < NUM_PORTS && !err; p++) {
		err = mr_rd(sw, MR_MC, p, w);
		mr_mc0[p] = w[0];
		if (!err)
			err = mr_rd(sw, MR_EMC, p, w);
		mr_emc0[p] = w[0];
	}
	for (i = 0; i < MR_MTP_NUM && !err; i++) {
		err = mr_rd(sw, MR_IM, i, w);
		mr_im0[i] = w[0];
		if (!err)
			err = mr_rd(sw, MR_EM, i, w);
		mr_em0[i] = w[0];
	}
	mr_pt = 0;
	for (p = 0; p < NUM_PORTS && !err; p++) {
		if (!mr_front(p))
			continue;
		err = mr_rd(sw, MR_PT, p, w);
		if (!err && (w[0] & MR_PT0_MIRROR))
			mr_pt |= BIT(p);
	}
	if (err)
		return err;
	memcpy(mr_mc, mr_mc0, sizeof(mr_mc));
	memcpy(mr_emc, mr_emc0, sizeof(mr_emc));
	memcpy(mr_im, mr_im0, sizeof(mr_im));
	memcpy(mr_em, mr_em0, sizeof(mr_em));
	mr_read = true;
	mr_ok = !mr_pt;
	for (p = 0; p < NUM_PORTS; p++)
		if ((mr_mc0[p] & MR_MC_ENABLE) || (mr_emc0[p] & MR_EMC_BITMAP))
			mr_ok = false;
	if (!mr_ok) {
		dev_err(dev, "mirror: switch already mirroring (PORT_TAB.MIRROR 0x%08x, M_ENABLE or EMIRROR_CONTROL set): mirroring refused, nothing written\n",
			mr_pt);
		bcm5331x_mirror_refusals++;
		return -EBUSY;
	}
	return 0;
}

static int bcm5331x_dsa_port_mirror_add(struct dsa_switch *ds, int port,
					struct dsa_mall_mirror_tc_entry *mirror,
					bool ingress, struct netlink_ext_ack *extack)
{
	struct bcm53314 *sw = ds->priv;
	int to = mirror->to_local_port, slot = -1, i, err;

	if (!READ_ONCE(mirror_on)) {
		NL_SET_ERR_MSG_MOD(extack, "mirroring offload off (module parameter mirror=0)");
		return -EOPNOTSUPP;
	}
	if (!mr_front(port) || !mr_front(to) || to == port) {
		NL_SET_ERR_MSG_MOD(extack, "only a front port mirrored to another front port is offloaded");
		return -EOPNOTSUPP;
	}
	if (access != 2 || dry_run)
		return -EPERM;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : 0;
	if (!err)
		err = mr_origin(sw, ds->dev);
	if (err)
		goto out;
	if (mr_is_dest(port) || mr_is_src(to)) {
		NL_SET_ERR_MSG_MOD(extack, "a mirror destination cannot be mirrored, nor a mirrored port be a destination");
		err = -EBUSY;
		goto out;
	}
	if (ingress) {
		if (mr_ing_dest[port]) {
			NL_SET_ERR_MSG_MOD(extack, "one ingress mirror per port");
			err = -EBUSY;
			goto out;
		}
		for (i = 0; i < MR_MTP_NUM && slot < 0; i++)
			if (mr_slot_refs[i] && mr_slot_dest[i] == to)
				slot = i;
		for (i = 0; i < MR_MTP_NUM && slot < 0; i++)
			if (!mr_slot_refs[i])
				slot = i;
		if (slot < 0) {
			NL_SET_ERR_MSG_MOD(extack, "four ingress mirror destinations at most");
			err = -ENOSPC;
			goto out;
		}
		mr_ing_dest[port] = to;
		mr_ing_slot[port] = slot;
		mr_slot_dest[slot] = to;
		mr_slot_refs[slot]++;
	} else {
		if ((mr_egr_src & BIT(port)) || (mr_egr_src && mr_egr_dest != to)) {
			NL_SET_ERR_MSG_MOD(extack, "one egress mirror destination for all ports");
			err = -EBUSY;
			goto out;
		}
		mr_egr_src |= BIT(port);
		mr_egr_dest = to;
	}
	err = mr_plan(sw, true);
	if (!err)
		err = mr_execute(sw, ds->dev);
	if (err) {
		/* refused before any write (plan): the state goes back; a write fault halts the module */
		if (ingress) {
			mr_ing_dest[port] = 0;
			mr_slot_refs[slot]--;
		} else {
			mr_egr_src &= ~BIT(port);
		}
	}
out:
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "mirror: port %d -> %d %s: add failed (%d)\n", port, to,
			ingress ? "ingress" : "egress", err);
	else
		dev_info(ds->dev, "mirror: port %d -> %d %s (%d writes)\n", port, to,
			 ingress ? "ingress" : "egress", mr_nops);
	return err;
}

static void bcm5331x_dsa_port_mirror_del(struct dsa_switch *ds, int port,
					 struct dsa_mall_mirror_tc_entry *mirror)
{
	struct bcm53314 *sw = ds->priv;
	int err;

	if (port <= 0 || port >= NUM_PORTS)
		return;
	mutex_lock(&sw->lock);
	if (mirror->ingress) {
		if (!mr_ing_dest[port])
			goto out_unlock;
		mr_slot_refs[mr_ing_slot[port]]--;
		mr_ing_dest[port] = 0;
	} else {
		if (!(mr_egr_src & BIT(port)))
			goto out_unlock;
		mr_egr_src &= ~BIT(port);
	}
	err = sw->halted ? -EIO : mr_plan(sw, false);
	if (!err)
		err = mr_execute(sw, ds->dev);
	mutex_unlock(&sw->lock);
	if (err)
		dev_err(ds->dev, "mirror: port %d %s: del failed (%d)\n", port,
			mirror->ingress ? "ingress" : "egress", err);
	else
		dev_info(ds->dev, "mirror: port %d %s removed (%d writes)%s\n", port,
			 mirror->ingress ? "ingress" : "egress", mr_nops,
			 mr_active() ? "" : ", origin restored");
	return;
out_unlock:
	mutex_unlock(&sw->lock);
}

/* teardown: a mirror left (DSA removes the tc rules first) is removed, origin restored */
static void mr_teardown(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;
	int err;

	if (!mr_read)
		return;
	mutex_lock(&sw->lock);
	if (mr_active())
		dev_warn(ds->dev, "mirror: mirrors left at teardown, removed\n");
	memset(mr_ing_dest, 0, sizeof(mr_ing_dest));
	memset(mr_slot_refs, 0, sizeof(mr_slot_refs));
	mr_egr_src = 0;
	err = sw->halted ? -EIO : mr_plan(sw, false);
	if (!err)
		err = mr_execute(sw, ds->dev);
	if (err)
		dev_err(ds->dev, "mirror: origin not restored at teardown (%d)\n", err);
	mr_read = mr_ok = false;
	mutex_unlock(&sw->lock);
}

static int mr_show(struct seq_file *m, void *v)
{
	struct bcm53314 *sw = m->private;
	u32 mc[NUM_PORTS], emc[NUM_PORTS], im[MR_MTP_NUM], em[MR_MTP_NUM], pt = 0, w[3];
	u32 rx[ARRAY_SIZE(front_ports)], tx[ARRAY_SIZE(front_ports)];
	int p, i, err = 0;

	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : 0;
	for (p = 0; p < NUM_PORTS && !err; p++) {
		err = mr_rd(sw, MR_MC, p, w);
		mc[p] = w[0];
		if (!err)
			err = mr_rd(sw, MR_EMC, p, w);
		emc[p] = w[0];
	}
	for (i = 0; i < MR_MTP_NUM && !err; i++) {
		err = mr_rd(sw, MR_IM, i, w);
		im[i] = w[0];
		if (!err)
			err = mr_rd(sw, MR_EM, i, w);
		em[i] = w[0];
	}
	for (i = 0; i < (int)ARRAY_SIZE(front_ports) && !err; i++) {
		p = front_ports[i].port;
		err = mr_rd(sw, MR_PT, p, w);
		if (!err && (w[0] & MR_PT0_MIRROR))
			pt |= BIT(p);
		if (!err)
			err = sw_read(sw, O_GRPKT, p, w);
		rx[i] = w[0];
		if (!err)
			err = sw_read(sw, O_GTPKT, p, w);
		tx[i] = w[0];
	}
	mutex_unlock(&sw->lock);
	if (err)
		return err;
	seq_printf(m, "mirror=%c origin=%s writes=%lu refusals=%lu egress_src=0x%08x egress_dest=%u\n",
		   READ_ONCE(mirror_on) ? 'Y' : 'N', !mr_read ? "unread" : mr_ok ? "off" : "busy",
		   bcm5331x_mirror_writes, bcm5331x_mirror_refusals, mr_egr_src, mr_egr_src ? mr_egr_dest : 0);
	for (p = 0; p < NUM_PORTS; p++)
		if (mr_ing_dest[p])
			seq_printf(m, "ING p%d -> p%u slot %u\n", p, mr_ing_dest[p], mr_ing_slot[p]);
	for (p = 0; p < NUM_PORTS; p++)
		seq_printf(m, "MC %2d %08x EMC %08x%s\n", p, mc[p], emc[p],
			   mr_read && (mc[p] != mr_mc0[p] || emc[p] != mr_emc0[p]) ? " (origin changed)" : "");
	for (i = 0; i < MR_MTP_NUM; i++)
		seq_printf(m, "MTP %d IM %08x EM %08x\n", i, im[i], em[i]);
	seq_printf(m, "PTM %08x\n", pt);
	for (i = 0; i < (int)ARRAY_SIZE(front_ports); i++)
		seq_printf(m, "MIB %-6s p%-2d rx %10u tx %10u\n", front_ports[i].label,
			   front_ports[i].port, rx[i], tx[i]);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(mr);

/* ---------------------------------------------------------------------- */
/* Time stamping (module parameter ptp)                                    */

/*
 * Module parameter ptp (default 0: nothing below runs, no read, no write):
 *
 * ptp=1 (reads only): debugfs "ptp" (0400); each read reads
 *   CMIC_TIMESYNC_CONTROL once and CMIC_TIMESYNC_TIMER ten times 100 ms
 *   apart (step and wrap of the counter), TS_CONTROL,
 *   TS_CONTROL_1/_2 (ethertype, message bitmap and DA of the frames the
 *   switch stamps), and for ge2 and the front ports PROTOCOL_PKT_CONTROL
 *   (TS_PKT_TO_CPU, TS_FWD_ACTION), PORT_TAB.IEEE_802_1AS_ENABLE (word 2
 *   bit 9) and EGR_PORT.IEEE_802_1AS_ENABLE (bit 13). The two CMIC
 *   registers are outside the reads of the base module: each read is armed
 *   (timesync_rd_armed). TX_TS_DATA (a FIFO: each read pops an entry) is
 *   never read.
 * ptp=2: 1, plus a PTP hardware clock over CMIC_TIMESYNC_TIMER
 *   read as a nanoseconds field: it counts 0..999999999 and wraps to 0
 *   every second (seen on the board: values below
 *   0x3b9aca00 only, steps of 8, one step of 2^32 - 10^9 + 110 ms a
 *   second when taken modulo 2^32), ptp_tick_ps picoseconds a count
 *   (default 1000; another value only corrects the rate); folded into
 *   64-bit nanoseconds by a work item every quarter of the wrap and at
 *   each read; frequency (adjfine) and phase
 *   (adjtime, settime) adjusted in software only: CMIC_TIMESYNC_CONTROL
 *   is never written. ethtool -T of a front port names the clock, with
 *   software time stamps only (no hardware stamping).
 * ptp=3: 2, plus EGR_PORT[3].IEEE_802_1AS_ENABLE = 1 (ge2:
 *   the SDK sets it on the CMIC port "to get the ingress time stamp",
 *   eav.c) and TS_CONTROL_1/_2 = 01:1b:19:00:00:00 (PTP over Ethernet,
 *   end-to-end: the default 01:80:c2:00:00:0e of the boot firmware is
 *   dropped by its L2_USER_ENTRY[2] after a network load); written at set-up only if
 *   TS_CONTROL already holds ethertype 0x88f7, each re-read before and
 *   read back, given back at unload. Where the stamp lands in a frame sent
 *   to ge2 is to be found (capture on the conduit):
 *   no extraction yet.
 */
static int ptp_mode;
static unsigned int ptp_tick_ps = 1000;
module_param_named(ptp, ptp_mode, int, 0444);
MODULE_PARM_DESC(ptp, "Time stamping: 0 = nothing (default); 1 = debugfs ptp, dump of the time stamping registers (reads only); 2 = 1 + PTP clock on the CMIC timer, adjusted in software; 3 = 2 + ge2 ingress stamping armed (EGR_PORT[3] bit 13, TS_CONTROL_1/_2 PTP DA; read back, given back at unload)");
module_param(ptp_tick_ps, uint, 0444);
MODULE_PARM_DESC(ptp_tick_ps, "With ptp>=2, length of a tick of CMIC_TIMESYNC_TIMER in picoseconds (500-100000, default 1000)");

#define TS_A_CONTROL		0x02780017	/* IPIPE TS_CONTROL: ETHERTYPE 31:16, TS_MSG_BITMAP 15:0 */
#define TS_A_CONTROL_1		0x0278001d	/* MAC_DA_LOWER */
#define TS_A_CONTROL_2		0x0278001c	/* MAC_DA_UPPER 15:0 */
#define TS_A_PPC		0x0c700006	/* PROTOCOL_PKT_CONTROL, | port << 12 */
#define TS_PPC_FIELDS		GENMASK(10, 8)	/* TS_PKT_TO_CPU 8, TS_FWD_ACTION 10:9 */
#define TS_PT2_1AS		BIT(9)		/* PORT_TAB word 2: IEEE_802_1AS_ENABLE */
#define TS_EP_1AS		BIT(13)		/* EGR_PORT: IEEE_802_1AS_ENABLE */
#define TS_ETHERTYPE		0x88f7
#define TS_DA_LOWER		0x19000000	/* 01:1b:19:00:00:00 */
#define TS_DA_UPPER		0x011b
#define TS_SAMPLES		10
#define TS_TICK_MIN		500	/* wrap >= 0.5 s: folded four times per wrap by the work (125 ms) */
#define TS_TICK_MAX		100000
#define TS_WRAP			1000000000U	/* the counter is a nanoseconds field: 0..TS_WRAP - 1 */
#define TS_SHIFT		24	/* mult = ns << 24 per tick: 1 ppm = 16.8 units; delta (< 2^30) * mult (< 2^31) fits 64 bits */

/* dump (ptp>=1) */
struct ts_survey {
	u32 control, timer[TS_SAMPLES];
	s64 ns[TS_SAMPLES];		/* monotonic time of each timer sample (ktime) */
	u32 tsc, tsc1, tsc2;
	u32 ppc[NUM_PORTS], pt2[NUM_PORTS], ep[NUM_PORTS];
	u32 shown;			/* ports read (ge2 and front ports) */
};
static unsigned long ts_cmic_reads;
static unsigned long ts_wild;		/* counter values >= TS_WRAP met (not a nanoseconds field), never folded */

/* counts from @a to @b of the counter, which wraps at TS_WRAP (one wrap at most in between) */
static u32 ts_delta(u32 a, u32 b)
{
	return b >= a ? b - a : b + (TS_WRAP - a);
}

/* PTP clock (ptp>=2): 64-bit nanoseconds over the 32-bit counter */
struct ts_clk {
	u32 last;			/* counter at the last fold */
	u64 ns;				/* nanoseconds at the last fold */
	u32 frac;			/* remainder below 1 ns, in 1/2^TS_SHIFT */
	u32 mult, base_mult;		/* ns << TS_SHIFT per tick (adjusted, nominal) */
};
static struct ts_clk ts_clk;

/* ptp=3: values found, given back at unload */
static bool ts_armed;
static u32 ts_ep3_orig, ts_tsc1_orig, ts_tsc2_orig;
static unsigned long ts_writes, ts_refusals;

/* Parameter check, before anything is probed (called by the init) */
static int bcm5331x_ptp_param_check(void)
{
	if (ptp_mode < 0 || ptp_mode > 3) {
		pr_err("bcm5331x-dsa: ptp: 0, 1, 2 or 3\n");
		return -EINVAL;
	}
	if (ptp_tick_ps < TS_TICK_MIN || ptp_tick_ps > TS_TICK_MAX) {
		pr_err("bcm5331x-dsa: ptp_tick_ps: %d-%d\n", TS_TICK_MIN, TS_TICK_MAX);
		return -EINVAL;
	}
	return 0;
}

/* one armed read of CMIC_TIMESYNC_CONTROL or _TIMER; under sw->lock */
static int ts_cmic_rd(struct bcm53314 *sw, u32 off, u32 *v)
{
	int err;

	if (ptp_mode < 1 || (off != CMIC_TIMESYNC_CONTROL && off != CMIC_TIMESYNC_TIMER))
		return -EPERM;
	sw->timesync_rd_armed = true;
	err = cmic_rd(sw, off, v);
	sw->timesync_rd_armed = false;
	if (!err)
		ts_cmic_reads++;
	return err;
}

static int ts_reg_rd(struct bcm53314 *sw, const char *name, u32 addr, int idx, u32 *v)
{
	u32 w[HW_L2U_WORDS];
	int err = hw_read(sw, name, addr, false, 1, idx, w);

	*v = w[0];
	return err;
}

/* ge2 and the front ports */
static bool ts_port(int p)
{
	return p == BCM5331X_CPU_PORT || bcm5331x_is_front(p);
}

/* dump: reads only (the timer samples apart, the lock dropped in between) */
static int ts_survey_run(struct bcm53314 *sw, struct ts_survey *t)
{
	int i, p, err = 0;

	memset(t, 0, sizeof(*t));
	if (ptp_mode < 1)
		return -EPERM;
	for (i = 0; !err && i < TS_SAMPLES; i++) {
		if (i)
			msleep(100);
		mutex_lock(&sw->lock);
		err = sw->halted ? -EIO : ts_cmic_rd(sw, CMIC_TIMESYNC_TIMER, &t->timer[i]);
		t->ns[i] = (s64)ktime_get();
		mutex_unlock(&sw->lock);
	}
	if (err)
		return err;
	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : ts_cmic_rd(sw, CMIC_TIMESYNC_CONTROL, &t->control);
	if (!err)
		err = ts_reg_rd(sw, "TS_CONTROL", TS_A_CONTROL, 0, &t->tsc);
	if (!err)
		err = ts_reg_rd(sw, "TS_CONTROL_1", TS_A_CONTROL_1, 0, &t->tsc1);
	if (!err)
		err = ts_reg_rd(sw, "TS_CONTROL_2", TS_A_CONTROL_2, 0, &t->tsc2);
	for (p = 0; !err && p < NUM_PORTS; p++) {
		u32 w[3];

		if (!ts_port(p))
			continue;
		err = ts_reg_rd(sw, "PROTOCOL_PKT_CONTROL", TS_A_PPC | p << 12, p, &t->ppc[p]);
		if (!err)
			err = sw_read(sw, O_PORT_TAB, p, w);
		if (!err)
			t->pt2[p] = w[2];
		if (!err)
			err = sw_read(sw, O_EGR_PORT, p, w);
		if (!err)
			t->ep[p] = w[0];
		if (!err)
			t->shown |= BIT(p);
	}
	mutex_unlock(&sw->lock);
	return err;
}

/*
 * Tick of the counter in picoseconds from @dns nanoseconds of monotonic time over @dcnt counts
 * (M13-3: the samples are taken with their own time, msleep() sleeps longer than asked); 0 if none.
 */
static u64 ts_tick_of(s64 dns, u64 dcnt)
{
	return dns > 0 && dcnt ? (u64)dns * 1000 / dcnt : 0;
}

static int ts_show(struct seq_file *m, void *v)
{
	struct bcm53314 *sw = m->private;
	struct ts_survey *t = kzalloc(sizeof(*t), GFP_KERNEL);
	int i, p, err;

	if (!t)
		return -ENOMEM;
	err = ts_survey_run(sw, t);
	if (err)
		goto out;
	seq_printf(m, "CMIC_TIMESYNC_CONTROL %08x (mode %u)\nCMIC_TIMESYNC_TIMER (100 ms apart)", t->control,
		   (t->control >> 20) & 3);
	for (i = 0; i < TS_SAMPLES; i++)
		seq_printf(m, " %08x", t->timer[i]);
	{
		u64 dcnt = 0;
		unsigned int over = 0;

		for (i = 0; i < TS_SAMPLES; i++)
			over += t->timer[i] >= TS_WRAP;
		seq_puts(m, "\nsteps");
		for (i = 1; i < TS_SAMPLES; i++)
			seq_printf(m, " %u", ts_delta(t->timer[i - 1], t->timer[i]));
		for (i = 1; i < TS_SAMPLES; i++)
			dcnt += ts_delta(t->timer[i - 1], t->timer[i]);
		seq_printf(m, "\nwrap %u (nanoseconds field), values at or above it %u%s", TS_WRAP, over,
			   over ? " (not a nanoseconds field: steps and tick_ps wrong)" : "");
		seq_printf(m, "\ntick_ps %llu (%lld ns over %llu counts)",
			   (unsigned long long)ts_tick_of(t->ns[TS_SAMPLES - 1] - t->ns[0], dcnt),
			   (long long)(t->ns[TS_SAMPLES - 1] - t->ns[0]), (unsigned long long)dcnt);
	}
	seq_printf(m, "\nTS_CONTROL %08x (ethertype %04x, messages %04x) TS_CONTROL_1 %08x TS_CONTROL_2 %08x\n",
		   t->tsc, t->tsc >> 16, t->tsc & 0xffff, t->tsc1, t->tsc2);
	for (p = 0; p < NUM_PORTS; p++)
		if (t->shown & BIT(p))
			seq_printf(m, "p%-2d PROTOCOL_PKT_CONTROL %08x (TS %u) PORT_TAB.1AS %u EGR_PORT %08x (1AS %u)\n",
				   p, t->ppc[p], (u32)((t->ppc[p] & TS_PPC_FIELDS) >> 8), !!(t->pt2[p] & TS_PT2_1AS),
				   t->ep[p], !!(t->ep[p] & TS_EP_1AS));
	seq_printf(m, "PTP clock values outside the field %lu\n", ts_wild);
	seq_printf(m, "ptp %d tick %u ps; CMIC reads %lu; armed %d writes %lu refusals %lu\n", ptp_mode, ptp_tick_ps,
		   ts_cmic_reads, ts_armed, ts_writes, ts_refusals);
out:
	kfree(t);
	return err;
}
DEFINE_SHOW_ATTRIBUTE(ts);

/* ---- PTP clock (ptp>=2) ---- */

/* nominal multiplier: ns << TS_SHIFT per tick */
static u32 ts_mult_of(unsigned int tick_ps)
{
	return (u32)(((u64)tick_ps << TS_SHIFT) / 1000);
}

/* multiplier for a frequency offset of @scaled_ppm (ppm << 16, as adjfine gives it) */
static u32 ts_mult_adj(u32 base, long scaled_ppm)
{
	s64 d = (s64)base * scaled_ppm / (1000000LL << 16);

	return (u32)((s64)base + d);
}

/* fold counter value @now into the clock (one wrap at TS_WRAP at most since the last fold) */
static void ts_fold(struct ts_clk *c, u32 now)
{
	u64 acc;

	if (now >= TS_WRAP) {		/* outside the field: not folded, counted */
		ts_wild++;
		return;
	}
	acc = (u64)ts_delta(c->last, now) * c->mult + c->frac;

	c->ns += acc >> TS_SHIFT;
	c->frac = acc & (BIT(TS_SHIFT) - 1);
	c->last = now;
}

static void ts_clk_init(struct ts_clk *c, u32 now, u64 ns)
{
	c->base_mult = ts_mult_of(ptp_tick_ps);
	c->mult = c->base_mult;
	c->last = now;
	c->ns = ns;
	c->frac = 0;
}

/* ptp=3: the one change each write may make (whole plan checked first) */
static bool ts_op_ok(const struct hw_op *op)
{
	const u32 *a = op->old, *n = op->val;

	if (ptp_mode != 3 || op->words != 1)
		return false;
	switch (op->kind) {
	case HW_TS_EP:
		/* EGR_PORT of ge2: IEEE_802_1AS_ENABLE alone */
		return op->idx == BCM5331X_CPU_PORT &&
		       op->addr == obj_addr(&objs[O_EGR_PORT], BCM5331X_CPU_PORT) && (a[0] ^ n[0]) == TS_EP_1AS;
	case HW_TS_DA:
		/* DA of the stamped frames: to the PTP end-to-end DA, or back to the value found */
		if (op->addr == TS_A_CONTROL_1)
			return (n[0] == TS_DA_LOWER && a[0] == ts_tsc1_orig) || (a[0] == TS_DA_LOWER && n[0] == ts_tsc1_orig);
		if (op->addr == TS_A_CONTROL_2)
			return !(n[0] >> 16) && !(a[0] >> 16) &&
			       ((n[0] == TS_DA_UPPER && a[0] == ts_tsc2_orig) || (a[0] == TS_DA_UPPER && n[0] == ts_tsc2_orig));
		return false;
	default:
		return false;
	}
}

/* ptp=3 at set-up: arm the ge2 ingress stamping (DA first, EGR_PORT[3] last); under sw->lock */
static int ts_arm(struct bcm53314 *sw, struct device *dev)
{
	const struct sw_obj *oep = &objs[O_EGR_PORT];
	u32 tsc, c1, c2, ep[3], n;
	int err;

	hw_nops = 0;
	err = ts_reg_rd(sw, "TS_CONTROL", TS_A_CONTROL, 0, &tsc);
	if (!err)
		err = ts_reg_rd(sw, "TS_CONTROL_1", TS_A_CONTROL_1, 0, &c1);
	if (!err)
		err = ts_reg_rd(sw, "TS_CONTROL_2", TS_A_CONTROL_2, 0, &c2);
	if (!err)
		err = sw_read(sw, O_EGR_PORT, BCM5331X_CPU_PORT, ep);
	if (err)
		return err;
	if ((tsc >> 16) != TS_ETHERTYPE || (c2 >> 16) || (ep[0] & TS_EP_1AS)) {
		ts_refusals++;
		dev_err(dev, "ptp=3: TS_CONTROL %08x, TS_CONTROL_2 %08x, EGR_PORT[3] %08x: not as expected (ethertype 0x88f7, 1AS off): nothing written\n",
			tsc, c2, ep[0]);
		return -EBUSY;
	}
	ts_tsc1_orig = c1;
	ts_tsc2_orig = c2;
	ts_ep3_orig = ep[0];
	n = TS_DA_LOWER;
	if (c1 != n)
		err = hw_add(HW_TS_DA, "TS_CONTROL_1", TS_A_CONTROL_1, false, 1, 0, 0, &c1, &n);
	n = TS_DA_UPPER;
	if (!err && c2 != n)
		err = hw_add(HW_TS_DA, "TS_CONTROL_2", TS_A_CONTROL_2, false, 1, 0, 0, &c2, &n);
	n = ep[0] | TS_EP_1AS;
	if (!err)
		err = hw_add(HW_TS_EP, oep->name, obj_addr(oep, BCM5331X_CPU_PORT), false, 1, BCM5331X_CPU_PORT, 0,
			     ep, &n);
	if (!err)
		err = hw_execute(sw, dev);
	if (err)
		return err;
	ts_writes += hw_nops;
	ts_armed = true;
	dev_info(dev, "ptp=3: ge2 ingress stamping armed (EGR_PORT[3] %08x -> %08x, DA 01:1b:19:00:00:00; %d writes, read back)\n",
		 ep[0], n, hw_nops);
	return 0;
}

/* at teardown: EGR_PORT[3] first, then the DA, as found; under sw->lock */
static int ts_disarm(struct bcm53314 *sw, struct device *dev)
{
	const struct sw_obj *oep = &objs[O_EGR_PORT];
	u32 c1, c2, ep[3], n;
	int err;

	if (!ts_armed || sw->halted)
		return 0;
	hw_nops = 0;
	err = sw_read(sw, O_EGR_PORT, BCM5331X_CPU_PORT, ep);
	if (!err)
		err = ts_reg_rd(sw, "TS_CONTROL_1", TS_A_CONTROL_1, 0, &c1);
	if (!err)
		err = ts_reg_rd(sw, "TS_CONTROL_2", TS_A_CONTROL_2, 0, &c2);
	if (err)
		return err;
	n = ts_ep3_orig;
	if (ep[0] != n)
		err = hw_add(HW_TS_EP, oep->name, obj_addr(oep, BCM5331X_CPU_PORT), false, 1, BCM5331X_CPU_PORT, 0,
			     ep, &n);
	n = ts_tsc1_orig;
	if (!err && c1 != n)
		err = hw_add(HW_TS_DA, "TS_CONTROL_1", TS_A_CONTROL_1, false, 1, 0, 0, &c1, &n);
	n = ts_tsc2_orig;
	if (!err && c2 != n)
		err = hw_add(HW_TS_DA, "TS_CONTROL_2", TS_A_CONTROL_2, false, 1, 0, 0, &c2, &n);
	if (!err)
		err = hw_execute(sw, dev);
	if (!err) {
		ts_writes += hw_nops;
		ts_armed = false;
	}
	dev_info(dev, "ptp=3: ge2 ingress stamping given back (%d writes)%s\n", hw_nops, err ? ", RESTORE FAILED" : "");
	return err;
}

#ifdef CONFIG_PTP_1588_CLOCK
#include <linux/ptp_clock_kernel.h>

static struct ptp_clock_info ts_info;
static struct ptp_clock *ts_ptp;
static struct bcm53314 *ts_sw;
static struct delayed_work ts_work;

/* read and fold the counter; under sw->lock */
static int ts_now(struct bcm53314 *sw, u64 *ns)
{
	u32 v;
	int err = sw->halted ? -EIO : ts_cmic_rd(sw, CMIC_TIMESYNC_TIMER, &v);

	if (err)
		return err;
	ts_fold(&ts_clk, v);
	*ns = ts_clk.ns;
	return 0;
}

static int ts_gettimex64(struct ptp_clock_info *info, struct timespec64 *ts, struct ptp_system_timestamp *sts)
{
	u64 ns;
	int err;

	mutex_lock(&ts_sw->lock);
	ptp_read_system_prets(sts);
	err = ts_now(ts_sw, &ns);
	ptp_read_system_postts(sts);
	mutex_unlock(&ts_sw->lock);
	if (!err)
		*ts = ns_to_timespec64(ns);
	return err;
}

static int ts_settime64(struct ptp_clock_info *info, const struct timespec64 *ts)
{
	u64 ns;
	int err;

	mutex_lock(&ts_sw->lock);
	err = ts_now(ts_sw, &ns);
	if (!err)
		ts_clk.ns = timespec64_to_ns(ts);
	mutex_unlock(&ts_sw->lock);
	return err;
}

static int ts_adjtime(struct ptp_clock_info *info, s64 delta)
{
	u64 ns;
	int err;

	mutex_lock(&ts_sw->lock);
	err = ts_now(ts_sw, &ns);
	if (!err)
		ts_clk.ns += delta;
	mutex_unlock(&ts_sw->lock);
	return err;
}

static int ts_adjfine(struct ptp_clock_info *info, long scaled_ppm)
{
	u64 ns;
	int err;

	mutex_lock(&ts_sw->lock);
	err = ts_now(ts_sw, &ns);
	if (!err)
		ts_clk.mult = ts_mult_adj(ts_clk.base_mult, scaled_ppm);
	mutex_unlock(&ts_sw->lock);
	return err;
}

/* fold four times per wrap: TS_WRAP counts = ptp_tick_ps ms (1 s at 1 ns a count) */
static unsigned long ts_work_delay(void)
{
	return msecs_to_jiffies(ptp_tick_ps / 4);
}

static void ts_work_fn(struct work_struct *work)
{
	u64 ns;

	mutex_lock(&ts_sw->lock);
	ts_now(ts_sw, &ns);
	mutex_unlock(&ts_sw->lock);
	schedule_delayed_work(&ts_work, ts_work_delay());
}

static int bcm5331x_dsa_get_ts_info(struct dsa_switch *ds, int port, struct kernel_ethtool_ts_info *info)
{
	if (!ts_ptp || !bcm5331x_is_front(port))
		return -EOPNOTSUPP;
	info->phc_index = ptp_clock_index(ts_ptp);
	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE;	/* the core adds the receive software ones */
	return 0;
}

static void ts_phc_start(struct bcm53314 *sw, struct device *dev)
{
	u32 v;
	int err;

	mutex_lock(&sw->lock);
	err = sw->halted ? -EIO : ts_cmic_rd(sw, CMIC_TIMESYNC_TIMER, &v);
	if (!err && v >= TS_WRAP) {
		dev_err(dev, "ptp: CMIC_TIMESYNC_TIMER %08x is not a nanoseconds field: no PTP clock\n", v);
		err = -ERANGE;
	}
	if (!err)
		ts_clk_init(&ts_clk, v, ktime_get_real_ns());
	mutex_unlock(&sw->lock);
	if (err)
		return;
	ts_sw = sw;
	ts_info = (struct ptp_clock_info) {
		.owner		= THIS_MODULE,
		.name		= "bcm53314 timesync",
		.max_adj	= 100000,	/* ppb, software multiplier */
		.gettimex64	= ts_gettimex64,
		.settime64	= ts_settime64,
		.adjtime	= ts_adjtime,
		.adjfine	= ts_adjfine,
	};
	INIT_DELAYED_WORK(&ts_work, ts_work_fn);
	ts_ptp = ptp_clock_register(&ts_info, dev);
	if (IS_ERR(ts_ptp)) {
		dev_err(dev, "ptp: clock not registered (%ld)\n", PTR_ERR(ts_ptp));
		ts_ptp = NULL;
		return;
	}
	schedule_delayed_work(&ts_work, ts_work_delay());
	dev_info(dev, "ptp: PTP clock %d on CMIC_TIMESYNC_TIMER (%u ps a tick, wrap at 10^9, software adjustments)\n",
		 ptp_clock_index(ts_ptp), ptp_tick_ps);
}

static void ts_phc_stop(void)
{
	if (!ts_ptp)
		return;
	ptp_clock_unregister(ts_ptp);
	cancel_delayed_work_sync(&ts_work);
	ts_ptp = NULL;
}
#else
static void ts_phc_start(struct bcm53314 *sw, struct device *dev) { }
static void ts_phc_stop(void) { }
#endif

static void ts_setup(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;

	ts_armed = false;
	ts_writes = ts_refusals = ts_cmic_reads = 0;
	if (ptp_mode >= 2)
		ts_phc_start(sw, ds->dev);
	if (ptp_mode == 3) {
		mutex_lock(&sw->lock);
		if (!sw->halted && access == 2 && !dry_run)
			ts_arm(sw, ds->dev);
		mutex_unlock(&sw->lock);
	}
}

static void ts_teardown(struct dsa_switch *ds)
{
	struct bcm53314 *sw = ds->priv;

	ts_phc_stop();
	mutex_lock(&sw->lock);
	ts_disarm(sw, ds->dev);
	mutex_unlock(&sw->lock);
}
/* QoS (qos=Y): bcm5331x-qos.c */
#include "bcm5331x-qos.c"
/* Field Processor (fp=Y): bcm5331x-fp.c */
#include "bcm5331x-fp.c"

static const struct dsa_switch_ops bcm5331x_dsa_ops = {
	.get_tag_protocol	= bcm5331x_dsa_get_tag_protocol,
	.setup			= bcm5331x_dsa_setup,
	.teardown		= bcm5331x_dsa_teardown,
	.connect_tag_protocol	= bcm5331x_dsa_connect_tag_protocol,
	.port_setup		= bcm5331x_dsa_port_setup,
	.phylink_get_caps	= bcm5331x_dsa_phylink_get_caps,
	.phylink_fixed_state	= bcm5331x_dsa_phylink_fixed_state,
	.phy_read		= bcm5331x_dsa_phy_read,
	.phy_write		= bcm5331x_dsa_phy_write,
	.port_enable		= bcm5331x_dsa_port_enable,
	.port_disable		= bcm5331x_dsa_port_disable,
	.port_bridge_join	= bcm5331x_dsa_port_bridge_join,
	.port_bridge_leave	= bcm5331x_dsa_port_bridge_leave,
	.port_stp_state_set	= bcm5331x_dsa_port_stp_state_set,
	.port_fast_age		= bcm5331x_dsa_port_fast_age,
	.port_vlan_filtering	= bcm5331x_dsa_port_vlan_filtering,
	.port_vlan_add		= bcm5331x_dsa_port_vlan_add,
	.port_vlan_del		= bcm5331x_dsa_port_vlan_del,
	.port_lag_join		= bcm5331x_dsa_port_lag_join,
	.port_lag_leave		= bcm5331x_dsa_port_lag_leave,
	.port_lag_change	= bcm5331x_dsa_port_lag_change,
	.port_change_conduit	= bcm5331x_dsa_port_change_conduit,
	.port_change_mtu	= bcm5331x_dsa_port_change_mtu,
	.port_max_mtu		= bcm5331x_dsa_port_max_mtu,
	.get_strings		= bcm5331x_dsa_get_strings,
	.get_sset_count		= bcm5331x_dsa_get_sset_count,
	.get_ethtool_stats	= bcm5331x_dsa_get_ethtool_stats,
	.get_stats64		= bcm5331x_dsa_get_stats64,
	.get_eth_mac_stats	= bcm5331x_dsa_get_eth_mac_stats,
	.get_rmon_stats		= bcm5331x_dsa_get_rmon_stats,
	.port_pre_bridge_flags	= bcm5331x_dsa_port_pre_bridge_flags,
	.port_bridge_flags	= bcm5331x_dsa_port_bridge_flags,
	.port_mirror_add	= bcm5331x_dsa_port_mirror_add,
	.port_mirror_del	= bcm5331x_dsa_port_mirror_del,
#ifdef CONFIG_PTP_1588_CLOCK
	.get_ts_info		= bcm5331x_dsa_get_ts_info,
#endif
	.port_get_default_prio	= bcm5331x_dsa_port_get_default_prio,
	.port_set_default_prio	= bcm5331x_dsa_port_set_default_prio,
	.port_get_dscp_prio	= bcm5331x_dsa_port_get_dscp_prio,
	.port_add_dscp_prio	= bcm5331x_dsa_port_add_dscp_prio,
	.port_del_dscp_prio	= bcm5331x_dsa_port_del_dscp_prio,
	.port_set_apptrust	= bcm5331x_dsa_port_set_apptrust,
	.port_get_apptrust	= bcm5331x_dsa_port_get_apptrust,
	.port_setup_tc		= bcm5331x_dsa_port_setup_tc,
	.cls_flower_add		= bcm5331x_dsa_cls_flower_add,
	.cls_flower_del		= bcm5331x_dsa_cls_flower_del,
	.cls_flower_stats	= bcm5331x_dsa_cls_flower_stats,
	.port_policer_add	= bcm5331x_dsa_port_policer_add,
	.port_policer_del	= bcm5331x_dsa_port_policer_del,
	.get_rxnfc		= bcm5331x_dsa_get_rxnfc,
	.set_rxnfc		= bcm5331x_dsa_set_rxnfc,
};

/*
 * fdb=Y: the table above plus the address-table operations and the real
 * fast ageing, filled at load (fdb=N keeps the table above: DSA then
 * installs no FDB entry and asks for no dump, as before).
 */
static struct dsa_switch_ops bcm5331x_dsa_fdb_ops;

static void bcm5331x_fdb_ops_init(void)
{
	bcm5331x_dsa_fdb_ops = bcm5331x_dsa_ops;
	bcm5331x_dsa_fdb_ops.port_fast_age = bcm5331x_dsa_fdb_fast_age;
	bcm5331x_dsa_fdb_ops.port_fdb_add = bcm5331x_dsa_port_fdb_add;
	bcm5331x_dsa_fdb_ops.port_fdb_del = bcm5331x_dsa_port_fdb_del;
	bcm5331x_dsa_fdb_ops.port_fdb_dump = bcm5331x_dsa_port_fdb_dump;
	if (mdb) {
		bcm5331x_dsa_fdb_ops.port_mdb_add = bcm5331x_dsa_port_mdb_add;
		bcm5331x_dsa_fdb_ops.port_mdb_del = bcm5331x_dsa_port_mdb_del;
	}
	if (ageing)
		bcm5331x_dsa_fdb_ops.set_ageing_time = bcm5331x_dsa_set_ageing_time;
}

/* ---------------------------------------------------------------------- */
/* Registration (real build)                                               */

/*
 * The switch is a PCI function (14e4:c314) that the base module drives
 * without binding a PCI driver to it: it looks the function up, requires
 * that no driver is bound and that memory decoding is already enabled, and
 * never writes its configuration space. DSA however needs ds->dev to be a
 * device with a bound driver: the user net devices take ds->dev as their
 * parent (net/dsa/user.c dsa_user_create, SET_NETDEV_DEV) and phylib reads
 * the owner of the parent's driver when it attaches their PHY
 * (drivers/net/phy/phy_device.c phy_attach_direct,
 * dev->dev.parent->driver->owner). With ds->dev pointing at the unbound
 * PCI function that driver is NULL and the first user port oopses.
 *
 * The switch is therefore described as a platform device, child of the
 * PCI function, that carries the DSA platform data (struct dsa_chip_data),
 * and this module binds its own platform driver to it: the form of the DSA
 * drivers instantiated by a parent driver or by board code (ocelot_ext,
 * b53_mmap). The PCI function itself stays unbound, so the checks of the
 * base module hold unchanged, and the standalone base module and this one
 * still exclude each other through the BAR (request_mem_region). Nothing
 * is written to the PCI configuration space; the probe of the child takes
 * a runtime PM reference on the parent, which PCI keeps active (runtime PM
 * forbidden by default), so no PCI access results. No modalias: the
 * platform device exists only while this module is loaded.
 */
#define BCM5331X_DSA_PDEV	"bcm5331x-dsa"

static struct platform_device *bcm5331x_plat;
static struct dsa_chip_data *bcm5331x_cd;	/* owns the port names */
static struct net_device *bcm5331x_conduit;
static struct net_device *bcm5331x_conduit2;	/* ge3, lag=Y only */
static struct dsa_switch *bcm5331x_ds;		/* set by a successful probe */
static int bcm5331x_probe_err;			/* result of the last probe */

/*
 * ethtool -s glue (see bcm5331x_ksettings_check): once the switch is
 * registered, the user ports take a copy of the DSA core's ethtool
 * operations whose set_link_ksettings checks the request first, then
 * hands it to the DSA core unchanged. Swapped under RTNL (ethtool runs
 * under it); both tables stay valid while the module is loaded and the
 * user net devices are gone before it is unloaded.
 */
static const struct ethtool_ops *bcm5331x_user_eth_orig;
static struct ethtool_ops bcm5331x_user_eth_ops;

/* link=2: the link modes the real port PHY can advertise (lk_phy_ok) */
static const int bcm5331x_adv_modes[] = {
	ETHTOOL_LINK_MODE_10baseT_Half_BIT, ETHTOOL_LINK_MODE_10baseT_Full_BIT,
	ETHTOOL_LINK_MODE_100baseT_Half_BIT, ETHTOOL_LINK_MODE_100baseT_Full_BIT,
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT, ETHTOOL_LINK_MODE_1000baseT_Full_BIT,
};
static const int bcm5331x_adv_other[] = {	/* allowed, no speed */
	ETHTOOL_LINK_MODE_Autoneg_BIT, ETHTOOL_LINK_MODE_TP_BIT, ETHTOOL_LINK_MODE_MII_BIT,
	ETHTOOL_LINK_MODE_Pause_BIT, ETHTOOL_LINK_MODE_Asym_Pause_BIT,
};

/*
 * link=2, after an accepted ethtool -s on @dev: COMMAND_CONFIG follows the
 * PHY even with no link change (lk_resync). phy_ethtool_ksettings_set put a
 * started PHY back to PHY_UP and queued its state machine (config_aneg, the
 * status read, then the link callbacks to phylink); it is run to its end
 * here (it takes no RTNL), then phylib's view is read. A link that drops
 * goes through mac_link_down/mac_link_up as before.
 */
static void bcm5331x_user_resync(struct net_device *dev)
{
	struct ethtool_pauseparam pp = { .autoneg = 1 };
	struct phy_device *phy = dev->phydev;
	bool link, tx = false, rx = false;
	struct dsa_port *dp, *u = NULL;
	int speed, duplex;

	if (!bcm5331x_ds || !phy)
		return;
	dsa_switch_for_each_user_port(dp, bcm5331x_ds)
		if (dp->user == dev)
			u = dp;
	if (!u)
		return;
	flush_delayed_work(&phy->state_queue);
	mutex_lock(&phy->lock);
	link = phy->link;
	speed = phy->speed;
	duplex = phy->duplex;
	phy_get_pause(phy, &tx, &rx);
	mutex_unlock(&phy->lock);
	if (bcm5331x_user_eth_orig->get_pauseparam)
		bcm5331x_user_eth_orig->get_pauseparam(dev, &pp);
	lk_resync(bcm5331x_ds->priv, u->index, link, speed, duplex, tx, rx,
		  pp.autoneg, pp.tx_pause, pp.rx_pause);
}

/*
 * link=2 judges ethtool -s against the real PHY of a front port only; the
 * MGMT user port (mgmt=1) keeps its emulated 1000/full PHY, as with link=0|1.
 */
static bool bcm5331x_user_is_front(struct net_device *dev)
{
	struct dsa_port *dp;

	if (!bcm5331x_ds)
		return false;
	dsa_switch_for_each_user_port(dp, bcm5331x_ds)
		if (dp->user == dev)
			return bcm5331x_is_front(dp->index);
	return false;
}

static int bcm5331x_user_set_link_ksettings(struct net_device *dev,
					     const struct ethtool_link_ksettings *cmd)
{
	struct ethtool_link_ksettings cur;
	bool autoneg = cmd->base.autoneg == AUTONEG_ENABLE;
	int err;

	if (link_mode == 2 && bcm5331x_user_is_front(dev)) {
		__ETHTOOL_DECLARE_LINK_MODE_MASK(rest);
		bool speed = false;
		unsigned int i;

		linkmode_copy(rest, cmd->link_modes.advertising);
		for (i = 0; i < ARRAY_SIZE(bcm5331x_adv_modes); i++) {
			speed |= linkmode_test_bit(bcm5331x_adv_modes[i], rest);
			linkmode_clear_bit(bcm5331x_adv_modes[i], rest);
		}
		for (i = 0; i < ARRAY_SIZE(bcm5331x_adv_other); i++)
			linkmode_clear_bit(bcm5331x_adv_other[i], rest);
		err = bcm5331x_ksettings_check_link2(autoneg, cmd->base.speed, cmd->base.duplex,
						     linkmode_empty(rest), speed);
		if (!err && ephy && !ep_mdix_ctrl_ok(cmd->base.eth_tp_mdix_ctrl)) {
			bcm5331x_ksettings_refusals++;
			netdev_info(dev, "ethtool -s refused (ephy=1): MDI-X control stays automatic\n");
			return -EINVAL;
		}
		if (err) {
			netdev_info(dev, "ethtool -s refused (link=2): forced 1000 Mb/s, a forced speed other than 10/100 or half/full duplex, or an advertisement outside 10/100/1000 BASE-T and pause\n");
			return err;
		}
		err = bcm5331x_user_eth_orig->set_link_ksettings(dev, cmd);
		if (!err)
			bcm5331x_user_resync(dev);
		return err;
	}
	memset(&cur, 0, sizeof(cur));
	err = bcm5331x_user_eth_orig->get_link_ksettings(dev, &cur);
	if (err)
		return err;
	err = bcm5331x_ksettings_check(autoneg,
				       linkmode_equal(cmd->link_modes.advertising,
						      cur.link_modes.advertising));
	if (err) {
		netdev_info(dev, "ethtool -s refused: forced speed/duplex or a changed advertisement does not reach the BCM53314 port PHY (emulated PHY); auto-negotiation only\n");
		return err;
	}
	return bcm5331x_user_eth_orig->set_link_ksettings(dev, cmd);
}

static void bcm5331x_hook_users(struct dsa_switch *ds)
{
	struct dsa_port *dp;
	int n = 0;

	rtnl_lock();
	dsa_switch_for_each_user_port(dp, ds) {
		struct net_device *u = dp->user;

		if (!u || !u->ethtool_ops || !u->ethtool_ops->get_link_ksettings ||
		    !u->ethtool_ops->set_link_ksettings)
			continue;
		if (!bcm5331x_user_eth_orig) {
			bcm5331x_user_eth_orig = u->ethtool_ops;
			bcm5331x_user_eth_ops = *u->ethtool_ops;
			bcm5331x_user_eth_ops.set_link_ksettings = bcm5331x_user_set_link_ksettings;
		}
		if (u->ethtool_ops == bcm5331x_user_eth_orig) {
			WRITE_ONCE(u->ethtool_ops, &bcm5331x_user_eth_ops);
			n++;
		}
	}
	rtnl_unlock();
	if (link_mode == 2)
		dev_info(ds->dev, "ethtool -s: invalid link settings refused on %d user port(s) (link=2)\n", n);
	else
		dev_info(ds->dev, "ethtool -s: forced link settings refused on %d user port(s)\n", n);
}

#ifndef BCM_NO_CMIC
/* packet DMA of the CMIC, off by default */
#include "bcm5331x-cmic.c"
#else
static int bcm5331x_cmic_param_check(void) { return 0; }
static void bcm5331x_cmic_start(struct bcm53314 *sw) { }
static void bcm5331x_cmic_exit(void) { }
#endif

static int bcm5331x_dsa_probe(struct platform_device *pdev)
{
	struct bcm53314 *sw = sw_dev;
	struct dsa_switch *ds;
	int err;

	/* only the device this module created, under the switch it set up */
	if (!sw || !dev_get_platdata(&pdev->dev) ||
	    pdev->dev.parent != &sw->pdev->dev) {
		bcm5331x_probe_err = -ENODEV;
		return -ENODEV;
	}

	ds = devm_kzalloc(&pdev->dev, sizeof(*ds), GFP_KERNEL);
	if (!ds) {
		bcm5331x_probe_err = -ENOMEM;
		return -ENOMEM;
	}
	ds->dev = &pdev->dev;
	ds->num_ports = NUM_PORTS;
	ds->ops = fdb ? &bcm5331x_dsa_fdb_ops : &bcm5331x_dsa_ops;
	/* fdb=Y: one address database per bridge (bridge number -> bridge VID) */
	ds->fdb_isolation = fdb;
	/* ageing=Y: the range of AGE_VAL; DSA refuses any other ageing time (-ERANGE) */
	if (fdb && ageing) {
		ds->ageing_time_min = AGE_MIN_MS;
		ds->ageing_time_max = AGE_MAX_MS;
	}
	ds->phylink_mac_ops = &bcm5331x_dsa_phylink_mac_ops;
	ds->priv = sw;
	/* bridge numbers 1-8 -> bridge VIDs 141-148 (hardware bridging) */
	ds->max_num_bridges = hwbridge ? BCM5331X_BR_MAX : 0;
	/* conduit LAG of ge2 + ge3 (lag=Y), LAGs of front ports (lagf): the trunk groups of the Hawkeye */
	ds->num_lag_ids = lag || lagf ? LAG_NUM_IDS : 0;

	err = dsa_register_switch(ds);
	bcm5331x_probe_err = err;
	if (err)
		return err;
	platform_set_drvdata(pdev, ds);
	bcm5331x_ds = ds;
	bcm5331x_hook_users(ds);
	return 0;
}

static void bcm5331x_dsa_remove(struct platform_device *pdev)
{
	struct dsa_switch *ds = platform_get_drvdata(pdev);

	if (!ds)
		return;
	lk_removing = true;	/* the detach power-downs of phylib are left out */
	dsa_unregister_switch(ds);
	bcm5331x_bios_l2u_release(ds);
	bcm5331x_ds = NULL;
	bcm5331x_user_eth_orig = NULL;	/* the user net devices are gone */
}

/* at reboot: unlink the user ports from the conduit (no switch access) */
static void bcm5331x_dsa_shutdown(struct platform_device *pdev)
{
	struct dsa_switch *ds = platform_get_drvdata(pdev);

	if (!ds)
		return;
	dsa_switch_shutdown(ds);
	platform_set_drvdata(pdev, NULL);
}

static struct platform_driver bcm5331x_dsa_driver = {
	.probe		= bcm5331x_dsa_probe,
	.remove		= bcm5331x_dsa_remove,
	.shutdown	= bcm5331x_dsa_shutdown,
	.driver = {
		.name			= BCM5331X_DSA_PDEV,
		/* bound for the life of the module only: no unbind/bind from sysfs */
		.suppress_bind_attrs	= true,
		/* probed within platform_device_add(): its result is known here */
		.probe_type		= PROBE_FORCE_SYNCHRONOUS,
	},
};

static void bcm5331x_free_cd(struct dsa_chip_data *cd)
{
	int i;

	if (!cd)
		return;
	for (i = 0; i < DSA_MAX_PORTS; i++)
		kfree(cd->port_names[i]);
	kfree(cd);
}

static int bcm5331x_dsa_init(void)
{
	struct platform_device *plat;
	struct dsa_chip_data *cd;
	struct bcm53314 *sw;
	int i, err;

	/* Run the base module's steps and grab the switch it set up. */
	access = 2;
	dry_run = false;
	steps = dsa_steps;
	monitor = 0;	/* no work item of the base: the emulated PHYs sample */
	/*
	 * MGMT user port: step mgmt after the others (it needs ports and
	 * ifilter in the same load), planned without link; refused with lag
	 * and when the steps already name it (mgmt=Y is the only way in).
	 */
	mgmt_link_optional = false;
	if (step_wanted("mgmt")) {
		pr_err("bcm5331x-dsa: step mgmt: use mgmt=1\n");
		return -EINVAL;
	}
	if (dsa_mgmt) {
		if (lag) {
			pr_err("bcm5331x-dsa: mgmt=1 not with lag=1 (VID 20 holds ge2 only)\n");
			return -EINVAL;
		}
		if (snprintf(dsa_steps_mgmt, sizeof(dsa_steps_mgmt), "%s,mgmt", dsa_steps) >=
		    (int)sizeof(dsa_steps_mgmt))
			return -EINVAL;
		steps = dsa_steps_mgmt;
		mgmt_link_optional = true;
	}
	if (!linksrc || (strcmp(linksrc, "bmsr") && strcmp(linksrc, "mac"))) {
		pr_err("bcm5331x-dsa: linksrc: bmsr or mac\n");
		return -EINVAL;
	}
	dsa_link_bmsr = !strcmp(linksrc, "bmsr");
	if (vlanbr_ad && !vlanbr) {
		pr_err("bcm5331x-dsa: vlanbr_ad=1 needs vlanbr=1\n");
		return -EINVAL;
	}
	if ((fdbvlan && (!fdb || !vlanbr)) || (ageing && !fdb)) {
		pr_err("bcm5331x-dsa: fdbvlan=1 needs fdb=1 and vlanbr=1, ageing=1 needs fdb=1\n");
		return -EINVAL;
	}
	if (brflags && !hwbridge) {
		pr_err("bcm5331x-dsa: brflags=1 needs hwbridge=1\n");
		return -EINVAL;
	}
	if (vlanbr && (!hwbridge || !qinq)) {
		pr_err("bcm5331x-dsa: vlanbr=1 needs hwbridge=1 and qinq=1\n");
		return -EINVAL;
	}
	if (fdb && !hwbridge) {
		pr_err("bcm5331x-dsa: fdb=1 needs hwbridge=1\n");
		return -EINVAL;
	}
	if (stats_ms && (stats_ms < ST_MS_MIN || stats_ms > ST_MS_MAX)) {
		pr_err("bcm5331x-dsa: stats_ms: 0 or %d-%d\n", ST_MS_MIN, ST_MS_MAX);
		return -EINVAL;
	}
	/* hardware LAG of front ports: within offloaded bridges only */
	if (lagf < 0 || lagf > 2 || (lagf && !hwbridge)) {
		pr_err("bcm5331x-dsa: lagf: 0, 1 or 2; 1 and 2 need hwbridge=1\n");
		return -EINVAL;
	}
	if (mdb && !fdb) {
		pr_err("bcm5331x-dsa: mdb needs fdb=1\n");
		return -EINVAL;
	}
	if (llproto < 0 || llproto > LL_ALL || (llproto && !hwbridge)) {
		pr_err("bcm5331x-dsa: llproto: mask 0-7 (1 STP, 2 LLDP, 4 EAPOL), needs hwbridge=1\n");
		return -EINVAL;
	}
	err = bcm5331x_link_param_check();
	if (!err)
		err = bcm5331x_ephy_param_check();
	if (!err)
		err = bcm5331x_ptp_param_check();
	if (!err)
		err = bcm5331x_cmic_param_check();
	if (err)
		return err;
	if (fdb) {
		fdb_scan = kvzalloc(FDB_L2X_NUM * sizeof(*fdb_scan), GFP_KERNEL);
		if (!fdb_scan)
			return -ENOMEM;
		bcm5331x_fdb_ops_init();
	}
	err = bcm5331x_base_probe();
	if (err)
		return err;
	sw = sw_dev;
	if (!sw)
		return -ENODEV;

	bcm5331x_conduit = dev_get_by_name(&init_net, conduit_name);
	if (!bcm5331x_conduit) {
		pr_err("bcm5331x-dsa: conduit %s not found\n", conduit_name);
		err = -ENODEV;
		goto base_out;
	}

	/* conduit LAG: second CPU port on ge3, trunk group of step trunk2 written */
	if (lag) {
		if (!sw->ge3 || !sw->trunk2 || bcm5331x_plan_remaining(sw)) {
			pr_err("bcm5331x-dsa: lag=1 needs steps ge3,trunk2 fully written\n");
			err = -EINVAL;
			goto conduit_out;
		}
		bcm5331x_conduit2 = dev_get_by_name(&init_net, conduit2_name);
		if (!bcm5331x_conduit2 || bcm5331x_conduit2 == bcm5331x_conduit) {
			pr_err("bcm5331x-dsa: conduit2 %s not found\n", conduit2_name);
			err = -ENODEV;
			goto conduit_out;
		}
	}

	/* double tagging, before anything is registered */
	err = bcm5331x_dsa_qinq(sw, &sw->pdev->dev);
	if (err)
		goto conduit_out;

	bcm5331x_dsa_l2u_report(sw, &sw->pdev->dev);

	if (dsa_mgmt && !sw->mgmt) {
		err = -EINVAL;
		goto conduit_out;
	}

	/* platform data: CPU port on ge2, one user port per front label (and MGMT) */
	cd = kzalloc(sizeof(*cd), GFP_KERNEL);
	if (!cd) {
		err = -ENOMEM;
		goto conduit_out;
	}
	cd->netdev[BCM5331X_CPU_PORT] = &bcm5331x_conduit->dev;
	cd->port_names[BCM5331X_CPU_PORT] = kstrdup("cpu", GFP_KERNEL);
	err = cd->port_names[BCM5331X_CPU_PORT] ? 0 : -ENOMEM;
	if (!err && bcm5331x_conduit2) {
		cd->netdev[PORT_TRUNK2] = &bcm5331x_conduit2->dev;
		cd->port_names[PORT_TRUNK2] = kstrdup("cpu", GFP_KERNEL);
		if (!cd->port_names[PORT_TRUNK2])
			err = -ENOMEM;
	}
	for (i = 0; !err && i < (int)ARRAY_SIZE(front_ports); i++) {
		cd->port_names[front_ports[i].port] =
			kstrdup(front_ports[i].label, GFP_KERNEL);
		if (!cd->port_names[front_ports[i].port])
			err = -ENOMEM;
	}
	if (!err && bcm5331x_has_mgmt(sw)) {
		cd->port_names[PORT_MGMT] = kstrdup("mgmt", GFP_KERNEL);
		if (!cd->port_names[PORT_MGMT])
			err = -ENOMEM;
	}
	if (err)
		goto cd_out;

	/* ephy=Y: the PHY driver first, so that the PHYs of the switch bind to it when DSA scans its bus */
	if (ephy) {
		if (cable_test) {
			bcm5331x_ephy_driver.cable_test_start = bcm5331x_ephy_cable_test_start;
			bcm5331x_ephy_driver.cable_test_get_status = bcm5331x_ephy_cable_test_get_status;
		}
		err = phy_drivers_register(&bcm5331x_ephy_driver, 1, NULL);
		if (err)
			goto cd_out;
		bcm5331x_ephy_registered = true;
	}

	err = platform_driver_register(&bcm5331x_dsa_driver);
	if (err)
		goto ephy_out;

	plat = platform_device_alloc(BCM5331X_DSA_PDEV, PLATFORM_DEVID_NONE);
	if (!plat) {
		err = -ENOMEM;
		goto drv_out;
	}
	plat->dev.parent = &sw->pdev->dev;
	/* copied into the device; the port names stay owned by cd */
	err = platform_device_add_data(plat, cd, sizeof(*cd));
	if (err)
		goto put_out;

	bcm5331x_ds = NULL;
	bcm5331x_probe_err = -ENODEV;	/* not probed */
	err = platform_device_add(plat);
	if (err)
		goto put_out;
	if (!bcm5331x_ds) {
		/* added but not bound: DSA refused the switch, nothing registered */
		err = bcm5331x_probe_err ? bcm5331x_probe_err : -ENODEV;
		if (err == -EPROBE_DEFER)
			err = -ENODEV;
		pr_err("bcm5331x-dsa: switch not registered (%d)\n", err);
		platform_device_unregister(plat);
		goto drv_out;
	}

	bcm5331x_plat = plat;
	bcm5331x_cd = cd;
	/* reads only: also with lag=Y, to see where the host addresses are learnt (port or group 7) */
	if (fdb || lag)
		debugfs_create_file("l2x", 0400, sw->dbg, sw, &fdb_l2x_fops);
	if (link_mode)
		debugfs_create_file("dsalink", 0400, sw->dbg, sw, &lk_fops);
	if (phyexp)
		debugfs_create_file("phyexp", 0400, sw->dbg, sw, &ep_fops);
	if (ptp_mode)
		debugfs_create_file("ptp", 0400, sw->dbg, sw, &ts_fops);
	debugfs_create_file("mirror", 0400, sw->dbg, sw, &mr_fops);
	debugfs_create_file("qos", 0400, sw->dbg, sw, &qs_fops);
	debugfs_create_file("fp", 0400, sw->dbg, sw, &fp_fops);
	bcm5331x_cmic_start(sw);
	return 0;

put_out:
	platform_device_put(plat);
drv_out:
	platform_driver_unregister(&bcm5331x_dsa_driver);
ephy_out:
	if (bcm5331x_ephy_registered)
		phy_drivers_unregister(&bcm5331x_ephy_driver, 1);
	bcm5331x_ephy_registered = false;
cd_out:
	bcm5331x_free_cd(cd);
conduit_out:
	dev_put(bcm5331x_conduit2);
	bcm5331x_conduit2 = NULL;
	dev_put(bcm5331x_conduit);
	bcm5331x_conduit = NULL;
base_out:
	bcm5331x_base_remove();
	kvfree(fdb_scan);
	fdb_scan = NULL;
	return err;
}

static void bcm5331x_dsa_exit(void)
{
	bcm5331x_cmic_exit();
	/* remove() unregisters the switch while its driver is still bound */
	platform_device_unregister(bcm5331x_plat);
	platform_driver_unregister(&bcm5331x_dsa_driver);
	/* after the switch: no PHY is attached any more */
	if (bcm5331x_ephy_registered)
		phy_drivers_unregister(&bcm5331x_ephy_driver, 1);
	bcm5331x_ephy_registered = false;
	bcm5331x_free_cd(bcm5331x_cd);
	dev_put(bcm5331x_conduit2);
	dev_put(bcm5331x_conduit);
	bcm5331x_base_remove();
	kvfree(fdb_scan);
	fdb_scan = NULL;
}

module_init(bcm5331x_dsa_init);
module_exit(bcm5331x_dsa_exit);

MODULE_DESCRIPTION("DSA driver of the BCM53314 switch of the FortiGate 100D (one VLAN per port, optional double tagging, optional bridge offload, VLAN-aware included)");
MODULE_LICENSE("GPL");
/*
 * No alias: the tagger module carries its own ("dsa_tag:" name and id) and
 * DSA loads it by id; an alias here would let a request for the tagger
 * load this driver, which writes to the switch.
 */
MODULE_SOFTDEP("pre: tag_bcm5331x_8021q");
