// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require view';
'require form';
'require poll';
'require rpc';
'require dom';
'require uci';

const callStatus = rpc.declare({
	object: 'luci.fgtwrt',
	method: 'status'
});

const MODES = {
	1: _('manual'),
	2: _('automatic (thermal cruise)'),
	3: _('automatic (fan speed cruise)'),
	4: _('automatic (smart fan)'),
	5: _('automatic (hardware table)')
};

const SOURCES = { 1: 'SYSTIN', 2: 'CPUTIN', 4: 'AUXTIN' };

function degrees(mdeg) {
	return (mdeg == null) ? '-' : '%.1f °C'.format(mdeg / 1000);
}

// Points of the "custom" profile: UCI list "T:P", else the defaults of the
// capabilities for the source.
function customPoints(fan, sid, source) {
	let l = uci.get('fgtwrt', sid, 'point');
	l = Array.isArray(l) ? l : (l ? [ l ] : []);
	if (l.length != 3)
		l = (fan?.custom?.default_points?.[source] ?? '').split(' ');
	return l.map((pt) => (pt ?? '').split(':'));
}

function renderLive(st) {
	const f = st.fan;

	if (!f || !f.present)
		return E('em', _('The fan controller is not available (driver not loaded?).'));

	const rows = [
		[ _('Mode'), MODES[f.enable] ?? String(f.enable) ],
		[ _('Set by'), f.overridden ? _('this service') : _('firmware (BIOS)') ],
		[ _('Duty cycle'), (f.pwm == null) ? '-' : '%d / 255 (%d %%)'.format(f.pwm, Math.round(f.pwm * 100 / 255)) ],
		[ _('Fan speed'), (f.rpm == null) ? '-' : '%d RPM'.format(f.rpm) ]
	];

	if (f.target != null && f.enable != 5)
		rows.push([ _('Target temperature'), degrees(f.target) ]);

	if (f.enable == 5 && (f.points ?? []).every((pt) => pt.mdeg != null && pt.pwm != null))
		rows.push([ _('Hardware table'), f.points.map((pt) =>
			'%s → %d'.format(degrees(pt.mdeg), pt.pwm)).join(', ') +
			(f.source != null ? ' (%s)'.format(SOURCES[f.source] ?? f.source) : '') ]);

	for (const t of f.temps ?? [])
		rows.push([ t.label, (t.true_mdeg != null)
			? _('%s read, %s calibrated').format(degrees(t.mdeg), degrees(t.true_mdeg))
			: degrees(t.mdeg) ]);

	if (f.guard != null)
		rows.push([ _('Board temperature guard'), f.guard ]);

	if (f.cputin_current_mode != null)
		rows.push([ _('CPUTIN sensing'), f.cputin_current_mode ? _('current mode') : _('voltage mode') ]);

	return E('table', { 'class': 'table' }, rows.map((r) =>
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'width': '33%' }, r[0]),
			E('td', { 'class': 'td left' }, r[1])
		])));
}

return view.extend({
	load: function() {
		return Promise.all([ callStatus(), uci.load('fgtwrt') ]);
	},

	// Profile "custom": source, three points (true degrees on the calibrated
	// CPU sensor), last duty cycle fixed at 255; the service checks the
	// same bounds again and keeps the firmware table on any refusal.
	renderCustom: function(s, fan, st) {
		const c = fan.custom;
		// lowest first duty cycle: the capabilities, never below 16 (fgtwrt-fan -B)
		const pwmMin = Math.max(+(c?.pwm_min ?? 16) || 16, 16);
		let o;

		o = s.option(form.ListValue, 'source', _('Temperature source'),
			_('SYSTIN follows the board and the room, not the CPU load; CPUTIN follows the CPU load and is used through its calibration, with a board temperature guard.'));
		for (const src of c.sources ?? [])
			o.value(src, { systin: _('board sensor (SYSTIN)'), cputin: _('CPU sensor, calibrated (CPUTIN)') }[src] ?? src);
		o.default = 'systin';
		o.depends('profile', 'custom');

		for (let i = 0; i < 3; i++) {
			for (const k of [ 't', 'p' ]) {
				if (k == 'p' && i == 2) {
					o = s.option(form.DummyValue, '_p3', _('Point 3 duty cycle'));
					o.cfgvalue = () => '255';
					o.depends('profile', 'custom');
					continue;
				}
				o = s.option(form.Value, '_%s%d'.format(k, i + 1),
					k == 't' ? _('Point %d temperature (°C)').format(i + 1)
						: _('Point %d duty cycle (%d-255)').format(i + 1, pwmMin));
				o.datatype = k == 't' ? 'range(0,100)' : 'range(%d,255)'.format(pwmMin);
				o.depends('profile', 'custom');
				o.cfgvalue = function(sid) {
					const sv = this.section.formvalue(sid, 'source') ?? uci.get('fgtwrt', sid, 'source') ?? 'systin';
					return customPoints(fan, sid, sv)[i]?.[k == 't' ? 0 : 1];
				};
				o.validate = function(sid, value) {
					const v = +value;
					const fv = (n) => +this.section.formvalue(sid, n);
					const sv = this.section.formvalue(sid, 'source') ?? 'systin';
					if (k == 't' && i > 0 && v <= fv('_t%d'.format(i)))
						return _('Temperatures must be strictly ascending.');
					if (k == 't' && i == 2 && v > (c.t3_max?.[sv] ?? 0))
						return _('Point 3 at most %d °C on this source.').format(c.t3_max?.[sv]);
					if (k == 'p' && i == 0 && v < pwmMin)
						return _('Point 1 duty cycle at least %d (below, the fan may stall).').format(pwmMin);
					if (k == 'p' && i == 1 && v < fv('_p1'))
						return _('Duty cycles must be ascending.');
					return true;
				};
				// Each field writes the whole list "T:P" x 3 from the form.
				o.write = function(sid) {
					const fv = (n) => this.section.formvalue(sid, n);
					uci.set('fgtwrt', sid, 'point', [
						'%s:%s'.format(fv('_t1'), fv('_p1')),
						'%s:%s'.format(fv('_t2'), fv('_p2')),
						'%s:255'.format(fv('_t3'))
					]);
				};
				o.remove = function() {};
			}
		}

		o = s.option(form.Value, 'guard_systin', _('Board temperature guard (°C)'),
			_('With the CPU sensor, the fan goes to full speed when the board sensor reaches this temperature or the fan stalls.'));
		o.datatype = 'range(20,60)';
		o.placeholder = String(c.guard_systin ?? 55);
		o.depends({ profile: 'custom', source: 'cputin' });
	},

	// Calibration of the CPU sensor: shown only, set from the command line.
	renderCalibration: function(m, fan) {
		const cal = fan.calibration;
		const s = m.section(form.NamedSection, cal.sensor, 'sensor', _('CPU sensor calibration'),
			_('True temperature = gain × read temperature + offset. Set from the command line only, for example: <code>uci set fgtwrt.cputin.offset=15; uci set fgtwrt.cputin.calibrated=1; uci commit fgtwrt</code>.'));
		let o;

		if (uci.get('fgtwrt', cal.sensor, 'calibrated') != '1')
			s.description += ' <strong>' + _('Provisional calibration (not measured yet): the fan speeds up earlier than needed.') + '</strong>';

		for (const k of [ 'gain', 'offset' ]) {
			o = s.option(form.DummyValue, k, k == 'gain' ? _('Gain') : _('Offset (°C)'));
			o.default = cal[k];
		}
		o = s.option(form.DummyValue, 'calibrated', _('Measured'));
		o.cfgvalue = (sid) => uci.get('fgtwrt', sid, 'calibrated') == '1' ? _('yes') : _('no (provisional)');
	},

	render: function(data) {
		const st = data[0];
		const fan = st.caps?.fan;
		let m, s, o;

		m = new form.Map('fgtwrt', _('Fan'),
			_('The <em>default</em> profile leaves the fan to the firmware, as on the original system. The other profiles change the fan controller settings until the next reboot or until the profile is set back to <em>default</em>; nothing is stored in the controller.'));

		s = m.section(form.NamedSection, 'fan', 'fan');

		if (fan?.experimental)
			s.description = _('Fan control on this model is experimental: watch the temperatures after changing the profile.');

		if (fan?.strategy == 'smartfan')
			s.description = (s.description ? s.description + ' ' : '') +
				_('The profiles program the temperature table of the fan controller, which then regulates the fan by itself from the board sensor, at full speed above the last point of the table.');
		else if (fan && fan.critical == null)
			s.description = (s.description ? s.description + ' ' : '') +
				_('There is no critical temperature guard on this model until its temperature sensors are calibrated; a stalled fan still restores the firmware settings.');

		o = s.option(form.ListValue, 'profile', _('Profile'));
		o.value('default', _('default (firmware)'));
		for (const p of [ 'quiet', 'medium', 'full' ])
			if (fan?.profiles?.[p])
				o.value(p, {
					quiet: _('quiet'),
					medium: _('medium'),
					full: _('full speed')
				}[p]);
		if (fan?.custom)
			o.value('custom', _('custom (three points)'));
		o.default = 'default';

		if (fan?.custom)
			this.renderCustom(s, fan, st);

		if (fan?.calibration)
			this.renderCalibration(m, fan);

		s = m.section(form.NamedSection, 'fan', 'fan', _('Current state'));
		o = s.option(form.DummyValue, '_live');
		o.rawhtml = true;
		o.cfgvalue = () => E('div', { 'id': 'fgtwrt-fan-live' }, renderLive(st));

		poll.add(() => callStatus().then((ns) => {
			const node = document.getElementById('fgtwrt-fan-live');
			if (node)
				dom.content(node, renderLive(ns));
		}), 5);

		return m.render();
	}
});
