<!-- SPDX-License-Identifier: GPL-2.0-only -->
# fgtwrt packages

`fgtwrt-base` finds the FortiGate model, describes what it can do
(`/usr/share/fgtwrt/models/<model>.json`) and applies `/etc/config/fgtwrt`
through the `fgtwrt` service. `luci-app-fgtwrt` adds System → fgtWRT to
LuCI: an overview, and the fan and USB management port pages on the
models that have them. Both are in the image of every published FortiGate
profile (60D, 90D, 60E; the 100D profile when its subtarget is merged)
and of the 100E profile (no fan entry: its fans follow the curve set by
`fan-profile`).

## Fan (FortiGate 100D)

The boot firmware of the 100D drives the CPU fan by a three-point table
of its W83627DHG-P (SmartFan III+, board sensor SYSTIN): 45/50/60 C to
PWM 63/102/255. Manual and cruise settings have no effect while the fan
is routed to that table, so the 100D uses the `smartfan` strategy: a
profile rewrites the table once (`pwm2_auto_point[1-3]_temp/_pwm`), and
the chip keeps regulating by itself, even if the service stops.

Profiles: `default` (firmware table, nothing is written), `quiet`
(45:16 50:102 60:255), `medium` (45:128 50:128 60:255) and `full`
(255 everywhere). Above the last point the fan runs at full speed. The
firmware table is put back on stop, on reload and on error; a reboot
also restores it. Writing the table needs the `w83627ehf` driver with
SmartFan III+ support and its `sf3p_write` parameter; without it the
table is only shown and the profiles fail, the firmware table staying.
The chip computes its output again when its input temperature changes,
not when the table is written: after a write, below T1, `fgtwrt-fan`
switches the source of the table to the other sensor and back (10 s at
most) so that a profile applies at once; at or above T1, or when the
output does not follow, it logs that the table applies at the next
temperature change. On the `x86/fortigate` subtarget, the package
`kmod-hwmon-w83627ehf` sets the parameter
(`/etc/modules.d/hwmon-w83627ehf`: `w83627ehf sf3p_write=1`); loading the
driver writes nothing, and the `default` profile still leaves the firmware
table untouched.

There is no critical temperature guard on the 100D (no `critical` in its
capabilities): its temperature sensors read too low until they are
calibrated, and a guard on such readings would only look safe. Once the
CPU sensor is calibrated, the threshold goes into `fan.critical` of
`fg100d.json`.

### User defined table (`custom` profile)

`fgtwrt.fan.profile=custom` writes three points of the user (`list point
'T:P'`, true degrees C) to the table: on the board sensor (`source
systin`, last point at most 60 C) or on the CPU sensor (`source cputin`,
last point at most 80 C true). On both, the first duty cycle is at least
16 (lowest duty cycle measured to keep the fan turning; below, it may
stall) and the last one is 255 (`fgtwrt-fan -B` refuses a bound below
16); the service checks these bounds and keeps the firmware table on any
refusal. Without points,
the defaults of the capabilities apply.

The CPU sensor CPUTIN reads too low. It is used through a software
calibration, per board, in the section `fgtwrt.cputin` (`gain`,
`offset`, `calibrated`): true = gain x read + offset. The points are
converted to read degrees, rounded down, before they are written to the
chip; the chip itself compares read values. The calibration is set from
the command line only (LuCI shows it): the first boot adds the
provisional values of the capabilities (gain 1, offset 22.5 C,
`calibrated 0`), chosen so that the fan speeds up earlier rather than
later. `fgtwrt-fan -K "GAIN OFFSET" -Q DEGREES` prints the read value of
a point, `-q MILLIDEGREES` the true value of a reading. The table is
refused when `temp2_offset` of the driver is not 0 (no double
correction).

With the CPU sensor, the chip no longer watches the board sensor: the
service then runs a guard (procd instance `guard`, every 10 s, nothing
written while all is well) that sets the duty cycles to 255 when SYSTIN
reaches `guard_systin` (55 C by default, 20-60, never `off` with this
source), when the fan runs below 1000 RPM on two readings in a row or
when a reading fails, and puts the user duty cycles back below the
threshold minus 5 C. Its state is in `/var/run/fgtwrt/guard-pwm2`.
At low duty cycles the fan count of the chip saturates: the driver then
reads 0 (as for a stopped fan) and doubles `fan2_div` (never lowered
afterwards). A 0 read with `fan2_div` at 8 or less is read again 2 s
later (at most 3 times) before it counts as a low reading.

### CPUTIN sensing mode (diagnostics)

The driver shows `temp2_current_mode` (bank 0 register 0x5e bit 2: 1
current mode, 0 as set by 0x5d), read only. Loaded with
`cputin_mode_write=1`, it can be written, for a diagnostic comparison of
both modes only: never in the configuration of a board. The boot firmware
sets it again at the next reset.

## USB management port (60D, 90D, 100D)

`fgtwrt.usb.mode`:

- `off` (default): no gadget;
- `console`: serial gadget (`usbgadget-acm`), login on `/dev/ttyGS0`;
- `network`: network gadget (`usbgadget-ncm`), device `usb0` in the
  static interface `usb` (192.168.2.1/24 by default), apart from `lan`,
  with its own firewall zone `usb` (input accepted, no forwarding) and a
  DHCP server. The interface is named `usb`, not `mgmt`, because some
  models already have an Ethernet port named mgmt.

The service writes the section `fgtwrt` of `/etc/config/usbgadget` when
the mode changes. The modes need the preset package of the mode and a
kernel with the gadget support of the board (FOTG210 device side on the
60D and 90D, NET2282 on the 100D); without them the page says what is
missing and the service logs it. The 60E has no device controller: no
USB management setting.

## LEDs

The HA LED of the 60D and 60E (green and orange halves), the second
bicolour LED of the 60C (ALARM or HA, not established) and the STATUS,
HA and ALARM LEDs of the 100D are listed in System → LED Configuration,
without a trigger, off but for STATUS green on the 100D (on once the
system is up). On the 100D they need kmod-leds-fg100d, loaded at boot. No
GPIO line is known for: ALARM on the 60D, HA and ALARM on the 90D
(`leds_missing` in the capabilities). The 60E has no ALARM LED.

## Network processor offload

The overview shows the offload parameters of the network processor
driver (`/sys/module/<driver>/parameters/`), read only. LuCI never sets
them.
