# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=bcm5331x-dsa
PKG_RELEASE:=16
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define KernelPackage/bcm5331x-dsa
  SUBMENU:=Network Devices
  TITLE:=BCM5331x (Hawkeye) DSA driver (BCM53314 of the FortiGate 100D)
  FILES:=$(PKG_BUILD_DIR)/bcm5331x-dsa.ko $(PKG_BUILD_DIR)/tag_bcm5331x_8021q.ko \
	$(PKG_BUILD_DIR)/bcm53314-fg100d.ko
  DEPENDS:=@TARGET_x86_fortigate +kmod-dsa +kmod-libphy
endef

define KernelPackage/bcm5331x-dsa/description
  DSA driver of the BCM53314 switch of the FortiGate 100D (autonomous
  DSA, one 802.1Q VLAN per front port, software bridge only). The
  driver includes the unchanged base switch module and refuses to register if
  the base module's plan was not fully applied. A VLAN-based tagger carries the
  port in the VID. It needs step "init" to have set the switch up first.
  The emulated PHY of each front port takes its link from the MII status
  of the real port PHY (linksrc=bmsr, default; MIIM reads only).
  At the set-up of the CPU port, the internal PHY of ge2, left at 1000 Mb/s
  forced by the boot firmware, is switched to auto-negotiation (one MII
  control write 0x0140 -> 0x1340, read back; none if already on;
  cpu_an=0 leaves it as found).
  The switch registers with DSA as a platform device, child of its PCI
  function (which stays unbound), bound to the driver's own platform driver.
  The base switch module is shipped too, on its own, for its step "init"
  and the LED set-up of the PHYs of port1-16 (phyled).
  Step iii (module parameter qinq, default off): before registration the
  switch is put in double-tagging mode with an 802.1ad outer tag (TPID
  0x88a8) on the CPU link (eight register writes, each read back); user
  VLANs of the front ports then ride as inner tags and VLAN-aware bridges
  are accepted (software bridge).
  Module parameter hwbridge (default off): VLAN-unaware bridges of front
  ports are offloaded to the switch (shared bridge VLAN 141-148, membership
  by STP state, link-local frames of the bridge VLAN dropped; switch writes at run
  time, each read back). Module parameter lag (default off): ge3 (conduit2,
  eth1) as a second CPU port and DSA conduit LAG over the trunk group of the
  base module's step trunk2 (no write of its own). Module parameter fdb
  (default off, needs hwbridge): address table of the offloaded bridges
  (static and host entries by the switch's own L2 insert/delete, per-port
  ageing on STP changes, no hardware learning on a disabled, blocking or
  listening port (CML of the port, restored at forwarding and when it
  leaves), dump of the L2 table; switch writes at run time, each read
  back; debugfs l2x lists the table, read only, also with lag).
  Module parameter vlanbr (default off; needs hwbridge and qinq): the first
  VLAN-aware bridge of front ports is offloaded too: its forwarding ports
  read their 802.1Q tag (provider port, TPID 0x8100), one switch VLAN per
  user VID (at most 16; VIDs the switch reserves, 1 included, untagged only,
  through VIDs 4079-4094), PVID as port VID, link-local frames of the user
  VLANs dropped; frames to the host are delivered to a designated member port (switch
  writes at run time, each read back). Module parameter vlanbr_ad
  (default off, needs vlanbr): that bridge may be 802.1ad, its forwarding
  ports reading the 0x88a8 tag (outer TPID slot 1, as on ge2: three fields
  per port, given back when it leaves); otherwise 802.1ad bridges are
  refused.
  Hardware statistics (module parameter stats_ms, default 10000 ms; 0 =
  off): the 25 MIB and drop counters of each front port and of ge2 are
  read (reads only, as debugfs mib) and summed on 64 bits by a work item;
  ethtool -S, the net device counters and the eth-mac/rmon groups are
  served from them. Bridge port flags are accepted with no switch write on
  a software bridge and refused on a bridge offloaded to the switch;
  802.1ad VLAN-aware bridges and forced link settings (ethtool -s speed,
  duplex, advertisement) are refused with link=0|1 (emulated PHYs).
  Module parameter link (default 0, nothing written): 1 = EPC_LINK_BMAP
  follows the link of each front port (one write per link change, read
  back) and the PHY and MAC state is logged at each link up (reads); 2 =
  1 plus the real port PHY behind the emulated one (registers passed
  through, ethtool -s writes ADVERTISE, CTRL1000 and BMCR under fixed
  rules, each read back) and COMMAND_CONFIG speed, duplex and pause set
  from the resolved link (through SW_RESET, read back); everything
  restored at unload; debugfs dsalink, read only. ethtool -s is judged
  before phylib: with link=0|1 forced settings and a changed advertisement
  are refused (emulated PHY); with link=2 only forced 1000 Mb/s, other
  invalid forced settings and advertisements outside 10/100/1000 BASE-T
  and pause are refused (a refusal from the PHY state machine would put
  the PHY in error). With link=2 phylib may also power a port PHY down
  and up (BMCR power-down alone) when the port is closed and opened.
  Module parameter ephy (default off, needs link=2): the BCM54684 PHYs of
  port1-16 are bound to the driver's own PHY driver bcm5331x-ephy (private
  PHY ID once the real one is checked, MDI-X state read, nothing written at
  attach). Module parameter phyexp (default off, needs link=2): debugfs
  phyexp reads the expansion registers 0x10-0x13 and 0xC0-0xC1 of those
  PHYs through their select register (written, read back, given back).
  Module parameter cable_test (default off, needs ephy): ethtool
  --cable-test through the ECD of the BCM54684 on a port without link.
  Module parameter ptp (default 0, nothing read or written): 1 = debugfs
  ptp, dump of the time stamping registers (CMIC timesync timer and
  control, TS_CONTROL, per-port 802.1AS and protocol-packet bits; reads
  only); 2 = 1 plus a PTP hardware clock over the CMIC timer (ptp_tick_ps
  picoseconds a tick, default 1000), adjusted in software; 3 = 2 plus the
  ge2 ingress stamping armed for a capture (EGR_PORT[3] IEEE_802_1AS_ENABLE,
  TS_CONTROL_1/_2 = PTP end-to-end DA; read back, given back at unload).
  Module parameter mirror (default off; may be set at run time): tc
  matchall mirred between front ports (ingress: one destination per
  port, four at most; egress: one destination for all ports) is
  offloaded to the mirroring of the switch (MIRROR_CONTROL,
  EMIRROR_CONTROL, IM/EM_MTP_INDEX, PORT_TAB.MIRROR; written at run time
  only, each read back, origin restored by the last removal and at
  unload); a mirror to the CPU stays in software. debugfs mirror shows
  the registers and the packet counters of the front ports (reads only).
  Module parameter qos (default off; may be set at run time): DCB default
  priority (PORT_PRI), DSCP priority (DSCP_TABLE) and trust (TRUST_DSCP,
  ING_PRI_CNG_MAP; qos_maptag=1 also sets MAP_TAG_PKT_PRIORITY), tc ets
  (XQCOSARBSEL, WRRWEIGHT_COS weights, COS_SEL of all ports), tc tbf
  (EGRMETERINGCONFIG, MAXBUCKETCONFIG under an ets band) and flower storm
  control (broadcast / multicast, packets or bytes) of the front ports;
  MMU thresholds, MISCCONFIG and WRRWEIGHT_COS.ENABLE are never written;
  debugfs qos (reads only). Module parameter fp (default off; may be set
  at run time): tc flower (drop, pass, police, skbedit priority, pedit
  DSCP, redirect to a front port), matchall police and ethtool ntuple drop
  rules of the front ports on the Field Processor (4 slices: L2, IPv4,
  IPv6 source, IPv6 destination; a pass entry keeps the link-local control
  frames out of every rule); debugfs fp (reads only). Both: written at run
  time only, each write read back, origin restored at the last removal and
  at unload, removals always permitted.
  Module parameter mgmt (default off): MGMT becomes the user port "mgmt"
  (port VID 20): the base module's step mgmt joins the steps (twelve
  switch writes, read back, planned without link too) and, at its set-up,
  the internal PHY of MGMT, left at 1000 Mb/s forced by step init, is
  switched to auto-negotiation (one MII control write 0x0140 -> 0x1340,
  read back; mgmt_an=0 leaves it). 1000 Mb/s full duplex only, untagged
  VLANs only, software bridging only, not with lag.
  Module parameter lagf
  (default 0, needs hwbridge): a hash LAG of front ports (balance-xor,
  802.3ad) forwarding in an offloaded bridge becomes a trunk group of the
  switch (groups 0-6, one egress member moved by the LAG state); lagf=2
  also classifies the slow protocols (LACP) on the port VID of every port,
  so that the LACPDUs of a member reach the host on that member, and
  clears while in use the entry of the boot firmware that drops the
  LACPDUs (L2_USER_ENTRY[1], given back at the last LAG leave and at
  removal; switch writes at run time, each read back).
  Module parameter llproto (mask, default 0, needs hwbridge): link-local
  protocols of the front ports of an offloaded bridge classified on the
  port VID (1 = STP, LLC 0x4242; 2 = LLDP, 0x88cc, with the boot firmware
  entry that drops the LLDPDUs, L2_USER_ENTRY[2], cleared while in use;
  4 = EAPOL, 0x888e): VLAN_PROTOCOL entries 14, 13, 12 and their data
  written at the first join of a front port to an offloaded bridge and
  undone at the last leave (each write read back), so that the bridge's
  STP, lldpd and hostapd see their frames on the exact port.
  Module parameter mdb (default off, needs fdb): multicast groups of the
  VLAN-unaware offloaded bridges (port_mdb_add/del): a group whose ports
  do not include the designated port of the bridge (static groups of the
  other ports, host groups) gets an L2MC entry and a static L2X entry
  pointing to it (the switch's own insert); groups learnt by snooping
  stay flooded. With the first such group, IGMP_MLD_PKT_CONTROL of the
  front ports floods IGMP/MLD (reports keep reaching the host) and
  VLAN_PROFILE_TAB[0].L2_PFM is set to 1 if found 0; both given back with
  the last group (switch writes at run time, each read back).
  At boot, /etc/init.d/fg100d-switch (before the network) loads the base
  module alone for each of: a read of the block reset register; step
  "init" when the boot firmware did not set the switch up (start from
  the disk); phyled; with option lag, steps up to ge3. Then it loads the
  DSA driver, with qinq by default (/etc/config/fg100d-switch: enabled,
  phyled, qinq, ledram; driver options hwbridge, fdb, vlanbr, mgmt (1)
  and lagf (2) on when absent as far as their needs allow,
  lag, llproto, mdb, mirror, link, stats, stats_ms, qos, fp, ptp and cmic
  off when absent: not passed, stats_ms=0 unless option stats is 1;
  vid_base; ptp_tick_ps with ptp 2-3; cmic_stage, cmic_tx_port,
  cmic_tx_count, cmic_rx_ms, cmic_rx_da, cmic_rx_vid, cmic_rx_act and
  cmic_cpu_vlan with cmic 2).
  Module parameter vid_base of the base module (default 100):
  first VID of the front-port VLAN block (21-3976): port VIDs vid_base+1
  to +22 (101-122 at 100), bridge VIDs vid_base+41 to +48 (141-148 at
  100); the block stays clear of VID 1, 20 and 4076-4095; the user VIDs
  of that block are untagged only under vlanbr.
  Module parameter fdbvlan (default off; needs fdb and vlanbr): static and
  host entries of the offloaded VLAN-aware bridge, keyed by the switch
  VLAN of their VID (deleted when the VID's slot is freed), no hardware
  learning on its disabled, blocking or listening ports, dump with the
  user VID. Module parameter ageing (default off; needs fdb): the bridge
  ageing time (1-1048575 s, the shortest of the bridges) written to the
  switch's ageing timer, read back, the value found restored at removal.
  Module parameter brflags (default off; needs hwbridge): flooding
  (unknown unicast, unknown multicast, broadcast), isolation and, with
  fdb, learning of the ports of offloaded bridges applied in the switch
  (flood block masks, EGR_MASK, CML; found clear at first use, each write
  read back, cleared when the port leaves).
  Module parameter cmic (default 0, no access): 2 = test stages of the
  packet DMA of the CMIC (cmic_stage: sequence, test frames sent, one
  receive descriptor, chain of them), through coherent host memory, guards
  read first, stopped at unload and at reboot; test tables written read
  back and given back. Nothing it receives reaches the network stack.
endef

define KernelPackage/bcm5331x-dsa/conffiles
/etc/config/fg100d-switch
endef

define KernelPackage/bcm5331x-dsa/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) ./files/fg100d-switch.init $(1)/etc/init.d/fg100d-switch
	$(INSTALL_CONF) ./files/fg100d-switch.config $(1)/etc/config/fg100d-switch
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef

$(eval $(call KernelPackage,bcm5331x-dsa))
