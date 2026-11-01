// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require view';
'require rpc';

const callStatus = rpc.declare({
	object: 'luci.fgtwrt',
	method: 'status'
});

const LED_ROLES = {
	ha: _('HA'),
	alarm: _('ALARM')
};

function yesno(v) {
	return v ? _('yes') : _('no');
}

function table(rows) {
	return E('table', { 'class': 'table' }, rows.map((r) =>
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'width': '33%' }, r[0]),
			E('td', { 'class': 'td left' }, String(r[1]))
		])));
}

/* Offload parameters of the network processor driver: shown only, they
 * are module parameters set at load time or by hand, never from here. */
function npSection(caps, np) {
	if (!caps?.np)
		return '';

	const rows = [ [ _('Driver'), caps.np.module + ' (' + (np?.loaded ? _('loaded') : _('not loaded')) + ')' ] ];
	for (const p of caps.np.params ?? [])
		rows.push([ p, np?.params?.[p] ?? '-' ]);

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', _('Network processor offload')),
		E('div', { 'class': 'cbi-section-descr' },
			_('Current values of the offload parameters of the driver, read only.')),
		table(rows)
	]);
}

return view.extend({
	load: function() {
		return callStatus();
	},

	render: function(st) {
		const caps = st.caps;
		const rows = [
			[ _('Board name'), st.board_name ],
			[ _('Model'), st.name ?? _('unknown board') ]
		];

		if (caps) {
			const usb = caps.usb ?? {};
			rows.push(
				[ _('Fan control'), caps.fan ? (caps.fan.experimental ? _('yes (experimental)') : _('yes')) : _('no fan') ],
				[ _('USB host port'), yesno(usb.host) ],
				[ _('USB management port'), usb.gadget ? usb.gadget.port : _('none') ],
				[ _('Network processor'), caps.np ? caps.np.module : _('none') ],
				[ _('LEDs'), (caps.leds ?? []).length ? caps.leds.join(', ') : _('none described') ],
				[ _('LEDs without a known control line'), (caps.leds_missing ?? []).length ? caps.leds_missing.map((l) => LED_ROLES[l] ?? l).join(', ') : _('none') ],
				[ _('Reset button'), yesno(caps.button) ],
				[ _('Watchdog'), caps.watchdog ?? _('none') ]
			);
		}

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', _('fgtWRT')),
			E('div', { 'class': 'cbi-map-descr' },
				_('FortiGate specific features of this board. Only the settings this model supports are shown.')),
			st.error ? E('div', { 'class': 'alert-message warning' }, st.error) : '',
			table(rows),
			(caps?.leds ?? []).length ? E('p', {},
				_('The HA and ALARM LEDs, where the board has them, are set up under System → LED Configuration (no trigger by default).')) : '',
			npSection(caps, st.np)
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
