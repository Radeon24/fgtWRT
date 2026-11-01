// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require view';
'require form';
'require poll';
'require rpc';
'require dom';

const callStatus = rpc.declare({
	object: 'luci.fgtwrt',
	method: 'status'
});

const MODES = {
	off: _('off'),
	console: _('serial console'),
	network: _('network interface "usb"')
};

const PRESETS = {
	console: 'acm',
	network: 'ncm'
};

function renderLive(st) {
	const u = st.usb;

	if (!u)
		return E('em', _('This model has no USB management port.'));

	const rows = [
		[ _('Device controller'), u.udc ?? _('not available (kernel without gadget support?)') ],
		[ _('Serial console (ttyGS0)'), u.console ? _('present') : _('absent') ],
		[ _('Network device (usb0)'), u.network ? _('present') : _('absent') ]
	];

	for (const m in PRESETS)
		if (!u.presets?.[PRESETS[m]])
			rows.push([ MODES[m], _('needs the package usbgadget-%s').format(PRESETS[m]) ]);

	return E('table', { 'class': 'table' }, rows.map((r) =>
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'width': '33%' }, r[0]),
			E('td', { 'class': 'td left' }, r[1])
		])));
}

return view.extend({
	load: function() {
		return callStatus();
	},

	render: function(st) {
		const gadget = st.caps?.usb?.gadget;
		let m, s, o;

		m = new form.Map('fgtwrt', _('USB management port'),
			_('Use of the %s port when it is connected to a computer. <em>serial console</em>: a login console, as on the console port. <em>network interface "usb"</em>: a static interface, apart from the LAN, with its own firewall zone and DHCP server (Network → Interfaces, 192.168.2.1/24 by default).').format(gadget?.port ?? 'USB'));

		s = m.section(form.NamedSection, 'usb', 'usb');

		o = s.option(form.ListValue, 'mode', _('Mode'));
		for (const v of gadget?.modes ?? [ 'off' ])
			o.value(v, MODES[v] ?? v);
		o.default = 'off';

		s = m.section(form.NamedSection, 'usb', 'usb', _('Current state'));
		o = s.option(form.DummyValue, '_live');
		o.rawhtml = true;
		o.cfgvalue = () => E('div', { 'id': 'fgtwrt-usb-live' }, renderLive(st));

		poll.add(() => callStatus().then((ns) => {
			const node = document.getElementById('fgtwrt-usb-live');
			if (node)
				dom.content(node, renderLive(ns));
		}), 5);

		return m.render();
	}
});
