# SPDX-License-Identifier: GPL-2.0-only
#
# Board detection and capability lookup shared by the fgtwrt service and
# the LuCI application.
#
# The model is found from the OpenWrt board name (/tmp/sysinfo/board_name:
# the first device tree "compatible" string on the fortisoc target, the
# sanitised DMI vendor and product on x86), through the table
# /usr/share/fgtwrt/boards ("<board_name> <model id>" per line). A board
# without DMI tables (the FortiGate 100D) is "generic" for OpenWrt: lines
# "@pci <vendor:device>[,<vendor:device>...] <model id>" then match when
# every listed PCI device is present. The capabilities of a model are in
# /usr/share/fgtwrt/models/<model id>.json.
#
# FGTWRT_SYSROOT prefixes every /sys and /tmp path (offline tests).

FGTWRT_SHARE="${FGTWRT_SHARE:-/usr/share/fgtwrt}"

fgtwrt_board_name() {
	local b
	b="$(cat "${FGTWRT_SYSROOT}/tmp/sysinfo/board_name" 2>/dev/null)"
	[ -n "$b" ] || return 1
	echo "$b"
}

# fgtwrt_pci_present <vendor:device>: a PCI function with these ids.
fgtwrt_pci_present() {
	local d v p
	for d in "${FGTWRT_SYSROOT}"/sys/bus/pci/devices/*; do
		[ -r "$d/vendor" ] || continue
		read -r v < "$d/vendor"
		read -r p < "$d/device"
		[ "${v#0x}:${p#0x}" = "$1" ] && return 0
	done
	return 1
}

# Model id of this board, or nothing (return 1) on an unknown board.
fgtwrt_model() {
	local board name id ids ok
	board="$(fgtwrt_board_name)" || board=generic
	while read -r name id; do
		case "$name" in
		''|'#'*|@*) continue ;;
		esac
		[ "$name" = "$board" ] && { echo "$id"; return 0; }
	done < "$FGTWRT_SHARE/boards"
	[ "$board" = generic ] || return 1
	while read -r name ids id; do
		[ "$name" = "@pci" ] || continue
		ok=1
		for name in $(echo "$ids" | tr ',' ' '); do
			fgtwrt_pci_present "$name" || { ok=0; break; }
		done
		[ "$ok" = 1 ] && { echo "$id"; return 0; }
	done < "$FGTWRT_SHARE/boards"
	return 1
}

fgtwrt_caps_file() {
	local id
	id="$(fgtwrt_model)" || return 1
	[ -r "$FGTWRT_SHARE/models/$id.json" ] || return 1
	echo "$FGTWRT_SHARE/models/$id.json"
}

# fgtwrt_cap <jsonfilter expression>: one value from the capability file.
fgtwrt_cap() {
	local f
	f="$(fgtwrt_caps_file)" || return 1
	jsonfilter -i "$f" -e "$1" 2>/dev/null
}

# hwmon directory whose "name" attribute is $1; with $2, the directory
# whose device link resolves to a path containing $2 (two chips with the
# same driver name).
fgtwrt_hwmon_dir() {
	local d n
	for d in "${FGTWRT_SYSROOT}"/sys/class/hwmon/hwmon*; do
		[ -r "$d/name" ] || continue
		read -r n < "$d/name"
		[ "$n" = "$1" ] || continue
		if [ -n "$2" ]; then
			case "$(readlink -f "$d/device" 2>/dev/null)" in
			*"$2"*) ;;
			*) continue ;;
			esac
		fi
		echo "$d"
		return 0
	done
	return 1
}

# USB management port (device side): gadget preset of a mode of the fgtwrt
# "usb" section, from the usbgadget package: "off" has none.
fgtwrt_usb_preset() {
	case "$1" in
	off) echo "" ;;
	console) echo acm ;;
	network) echo ncm ;;
	*) return 1 ;;
	esac
}

# fgtwrt_udc [name]: USB device controller to bind the gadget to. With a
# name (from the capabilities), that controller if the kernel has it;
# without, the only controller of the board (a PCI one has no fixed name).
fgtwrt_udc() {
	local d n=0 found=
	for d in "${FGTWRT_SYSROOT}"/sys/class/udc/*; do
		[ -e "$d" ] || continue
		if [ -n "$1" ]; then
			[ "${d##*/}" = "$1" ] && { echo "$1"; return 0; }
		else
			n=$((n + 1))
			found="${d##*/}"
		fi
	done
	[ -z "$1" ] && [ "$n" = 1 ] && { echo "$found"; return 0; }
	return 1
}
