let latestSnap = null;
let currentView = 'home';
let scanPage = 0;
const SCAN_PAGE_SIZE = 6;
let ws = null;

// Milestone 1 + Milestone 2 + Milestone 3 UI state
let diagTab = 'ping';
let selectedPingTarget = 'gw';
let customPingTarget = '';
let selectedTraceTarget = '1.1.1.1';
let customTraceTarget = '';
let selectedIperfTarget = '';
let speedIfaceMode = 'auto';
let staticIpDraft = { ip_cidr: '192.168.0.50/24', gateway: '', dns: '' };
let dot1xDraft = { identity: '', password: '' };
let wifiTab = 'list';
let wifiBandFilter = 'ALL';
let wifiGraphBand = '2.4 GHz';
let selectedWalkBssid = '';
let wifiAutoScannedOnce = false;
let swTab = 'panel';
let customSnmpTarget = '';
let linkActiveTab = 'tdr';
let secTab = 'grade';
let auditTab = 'log';
let sysTab = 'general';
let ptSniffTab = 'exp';
let ptReconTab = 'findings';
let ptReconProfile = 'quick_banners';
let ptReconTarget = '';
let activeHostInspect = null;
let pentestUiActive = false;

// On-screen keyboard state
let kbValue = '';
let kbMode = 'text'; // 'text' | 'ip'
let kbShift = false;
let kbSymbols = false;
let kbSecret = false;
let kbReveal = false;
let kbKeyChars = [];
let kbCallback = null;
let wifiSurveyRows = [];
let wifiClientSavedRows = [];
let wifiClientAvailRows = [];

const params = new URLSearchParams(window.location.search);
if (params.get('kiosk') === '1') {
  document.body.classList.add('kiosk-mode');
} else if (params.get('mode') === 'app' || params.get('mode') === 'fluid') {
  document.body.classList.add('app-mode');
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function nav(viewId) {
  currentView = viewId;
  const allViews = [
    'home', 'autotest', 'sw', 'link', 'diag', 'scan', 'wifi', 'sec', 'audit',
    'pt-hub', 'pt-recon', 'pt-sniff', 'pt-nac', 'pt-wifi'
  ];
  allViews.forEach(v => {
    const el = document.getElementById('view-' + v);
    if (el) el.classList.toggle('active', v === viewId);
  });
  const railMap = {
    home: 'rail-home',
    autotest: 'rail-home',
    sw: 'rail-sw',
    link: 'rail-link',
    diag: 'rail-diag',
    scan: 'rail-scan',
    wifi: 'rail-wifi',
    sec: 'rail-sec',
    audit: pentestUiActive ? 'rail-pt-log' : 'rail-audit',
    'pt-hub': 'rail-pt-hub',
    'pt-recon': 'rail-pt-recon',
    'pt-sniff': 'rail-pt-sniff',
    'pt-nac': 'rail-pt-nac',
    'pt-wifi': 'rail-pt-wifi'
  };
  [
    'rail-home', 'rail-sw', 'rail-link', 'rail-diag', 'rail-scan', 'rail-wifi', 'rail-sec', 'rail-audit',
    'rail-pt-hub', 'rail-pt-recon', 'rail-pt-sniff', 'rail-pt-nac', 'rail-pt-wifi', 'rail-pt-log'
  ].forEach(id => {
    const r = document.getElementById(id);
    if (r) r.classList.toggle('active', id === railMap[viewId]);
  });
  const titles = {
    home: 'LIVE WORKBENCH',
    autotest: 'AUTOTEST CHECKLIST',
    sw: 'SWITCH & PORT ANALYZER',
    link: 'CABLE TDR & PHY',
    diag: 'SPEED & PATH DIAGNOSTICS',
    scan: 'SUBNET HOST DISCOVERY',
    wifi: 'WI-FI SITE SURVEY',
    sec: 'SECURITY, L2 & CAPTURE',
    audit: 'AUDIT LOG & REPORTS',
    'pt-hub': 'PENTEST COMMAND HUB',
    'pt-recon': 'ACTIVE RECON & PROFILES',
    'pt-sniff': 'PASSIVE SNIFF & STREAM',
    'pt-nac': 'NAC, TAP & MAC IDENTITY',
    'pt-wifi': 'EXTERNAL WI-FI & ROGUE AP'
  };
  document.getElementById('top-title').textContent = titles[viewId] || 'JACKTRACE';
  if (viewId === 'diag' && latestSnap && latestSnap.diagnostics) {
    requestAnimationFrame(() => renderPingCanvas(latestSnap.diagnostics.ping));
  }
  if (viewId === 'wifi' && latestSnap && latestSnap.wifi) {
    renderWifiView(latestSnap.wifi);
    if (!wifiAutoScannedOnce && (!latestSnap.wifi.networks || !latestSnap.wifi.networks.length) && !latestSnap.wifi.scanning && !latestSnap.wifi.ap_mode_blocked) {
      wifiAutoScannedOnce = true;
      scanWifiNow();
    }
    requestAnimationFrame(() => {
      if (wifiTab === 'graph') renderWifiChanCanvas(latestSnap.wifi);
      else if (wifiTab === 'walk') renderWifiWalkCanvas(latestSnap.wifi.walk);
    });
  }
}

function setVerdictClass(el, verdict) {
  if (!el) return;
  el.classList.remove('verdict-pass', 'verdict-warn', 'verdict-fail');
  if (verdict === 'PASS') el.classList.add('verdict-pass');
  else if (verdict === 'WARN' || verdict === 'UNPATCHED' || verdict === 'TESTING' || verdict === 'NOT_RUN' || verdict === 'WAIT' || verdict === 'WAITING') el.classList.add('verdict-warn');
  else el.classList.add('verdict-fail');
}

function drillAutoTestStep(key) {
  if (key === 'link') { nav('link'); return; }
  if (key === 'switch') { nav('sw'); setSwTab('panel'); return; }
  if (key === 'dhcp') { nav('sec'); setSecTab('forensics'); return; }
  if (key === 'gateway') { nav('diag'); setDiagTab('ping'); return; }
  if (key === 'dns') { nav('diag'); setDiagTab('trace'); return; }
  if (key === 'wan') { nav('diag'); setDiagTab('speed'); return; }
  if (key === 'security') { nav('sec'); setSecTab('grade'); return; }
  if (key === 'poe_vlan') { nav('sw'); setSwTab('vlan'); }
}

function renderAutoTestView(s) {
  const at = s.autotest || {};
  const banner = document.getElementById('at-banner');
  const chip = document.getElementById('at-verdict-chip');
  const verdict = at.verdict || s.autotest_verdict || 'WAITING';

  document.getElementById('at-banner-title').textContent = `AUTOTEST • ${verdict} (${at.passed_count || 0}/${at.total_count || 7})`;
  document.getElementById('at-banner-sub').textContent = `${at.summary || 'Waiting for link...'} • Time: ${at.duration_s || 0}s`;
  banner.classList.toggle('warn', verdict === 'FAIL');

  chip.textContent = verdict;
  setVerdictClass(chip, verdict);

  const btnProf = document.getElementById('btn-at-profile');
  const isLan = at.profile === 'lan_only';
  btnProf.textContent = isLan ? 'Profile: LAN-Only' : 'Profile: WAN';
  btnProf.classList.toggle('active', isLan);

  const btnAutoLog = document.getElementById('btn-at-autolog');
  btnAutoLog.textContent = at.auto_log ? 'Auto-Log: ON' : 'Auto-Log: OFF';
  btnAutoLog.classList.toggle('active', Boolean(at.auto_log));

  const steps = at.steps || [];
  const cardsHtml = steps.map(st => `
    <div class="at-step clickable st-${esc(st.status)}" onclick="drillAutoTestStep('${esc(st.key)}')" title="Tap to open diagnostic view">
      <div class="at-step-top">
        <span class="at-step-lbl">${esc(st.label)}<span class="at-step-arr">▸</span></span>
        <span class="st-badge ${esc(st.status)}">${esc(st.status)}</span>
      </div>
      <div class="at-step-val">${esc(st.value)}</div>
      <div class="at-step-det">${esc(st.detail)}</div>
    </div>
  `).join('');

  // 8th summary tile for symmetrical 2x4 grid
  const poeStr = (s.poe && s.poe.supported)
    ? `${s.poe.standard}${s.poe.allocated_watts ? ' (' + s.poe.allocated_watts + 'W)' : ''}`
    : 'No PoE TLV';
  const taggedList = (s.vlan && s.vlan.tagged_vlans) ? s.vlan.tagged_vlans : [];
  const baseVlan = s.vlan && s.vlan.native_vlan ? `VLAN ${s.vlan.native_vlan}` : 'Untagged';
  const extraTags = taggedList.filter(v => v !== (s.vlan && s.vlan.native_vlan));
  const vlanStr = extraTags.length
    ? (s.vlan && s.vlan.native_vlan ? `${baseVlan} • Tag: ${extraTags.join(',')}` : `Tag: ${extraTags.join(',')}`)
    : baseVlan;
  const nextDrop = s.audit && s.audit.next_drop_label ? s.audit.next_drop_label : 'W-01';
  const eighthCard = `
    <div class="at-step clickable st-WAIT" onclick="drillAutoTestStep('poe_vlan')" title="Tap to open VLAN Trunk Probe">
      <div class="at-step-top">
        <span class="at-step-lbl">PoE / VLAN / Audit Drop<span class="at-step-arr">▸</span></span>
        <span class="st-badge WAIT">${esc(nextDrop)}</span>
      </div>
      <div class="at-step-val">${esc(vlanStr)} • ${esc(poeStr)}</div>
      <div class="at-step-det">Session #${s.port_session_id || 1} • Logged Drops: ${s.audit ? s.audit.total_saved : 0}</div>
    </div>
  `;

  document.getElementById('at-grid').innerHTML = cardsHtml + eighthCard;
}

function renderFaceplate(sw, blink) {
  const grid = document.getElementById('fp-grid');
  const card = grid.closest('.faceplate-card');
  const total = (sw.panel && sw.panel.total_ports) ? sw.panel.total_ports : 24;
  const target = sw.detected && sw.panel ? sw.panel.port_number : null;
  const peers = new Set((sw.panel && sw.panel.active_peer_ports) || []);

  document.getElementById('fp-title').textContent = `${total}-PORT PANEL MAP`;
  grid.classList.remove('cols-8', 'cols-12', 'cols-24');
  if (card) card.classList.toggle('wide-48', total > 24);

  const blinkTag = document.getElementById('fp-blink-tag');
  if (blink.active) {
    blinkTag.textContent = `● ${blink.phase} (${blink.remaining_seconds}s)`;
    blinkTag.classList.add('active');
  } else {
    blinkTag.textContent = 'LED: NORMAL';
    blinkTag.classList.remove('active');
  }

  let targetCls = 'target';
  if (blink.active) {
    if (blink.phase.includes('GREEN') || blink.phase.includes('ON')) targetCls = 'target-green';
    else if (blink.phase.includes('AMBER')) targetCls = 'target-amber';
    else if (blink.phase.includes('OFF')) targetCls = 'target-off';
  }

  let cells = [];
  if (total === 8) {
    grid.classList.add('cols-8');
    document.getElementById('fp-footer').innerHTML = '<span>Single Row (Ports 1–8)</span><span></span>';
    for (let p = 1; p <= 8; p++) {
      const cls = (p === target) ? targetCls : (peers.has(p) ? 'peer' : '');
      cells.push(`<div class="rj-cell ${cls}">${p}</div>`);
    }
  } else {
    const cols = Math.min(24, Math.max(8, Math.floor(total / 2)));
    grid.classList.add(cols === 8 ? 'cols-8' : (cols > 12 ? 'cols-24' : 'cols-12'));
    document.getElementById('fp-footer').innerHTML = `<span>Top: Odd (01–${String(total - 1).padStart(2, '0')})</span><span>Bot: Even (02–${String(total).padStart(2, '0')})</span>`;
    for (const start of [1, 2]) {
      for (let c = 0; c < cols; c++) {
        const p = start + c * 2;
        const cls = (p === target) ? targetCls : (peers.has(p) ? 'peer' : '');
        const lbl = String(p).padStart(2, '0');
        cells.push(`<div class="rj-cell ${cls}">${lbl}</div>`);
      }
    }
  }
  grid.innerHTML = cells.join('');
}

function renderTdrSection(s) {
  const tdr = s.tdr || {};
  const link = s.link;
  const pBanner = document.getElementById('pair-banner');
  const pChip = document.getElementById('pair-chip');

  const hasTdr = tdr.pairs && tdr.pairs.length === 4;
  if (hasTdr) {
    document.getElementById('pair-banner-title').textContent = tdr.summary;
    const dbg = (tdr.raw_debug && tdr.overall_verdict === 'WARN') ? ` • ${tdr.raw_debug}` : '';
    document.getElementById('pair-banner-sub').textContent =
      `PHY: ${tdr.phy_id} • Tested: ${tdr.tested_at || 'Live'} • Mode: ${tdr.method}${dbg}`;
    pBanner.classList.toggle('warn', tdr.overall_verdict === 'FAIL');
    pChip.textContent = tdr.overall_verdict;
    setVerdictClass(pChip, tdr.overall_verdict);
  } else {
    document.getElementById('pair-banner-title').textContent = link.pair_diagnostic_note;
    document.getElementById('pair-banner-sub').textContent =
      `Tap PULSE HARDWARE TDR below to measure all 4 pairs (works on dead or live sockets)`;
    pBanner.classList.toggle('warn', link.pair_downshift_suspected);
    const lv = !link.carrier_up ? 'UNPROBED' : (link.pair_downshift_suspected ? 'WARN' : 'PASS');
    pChip.textContent = lv;
    setVerdictClass(pChip, lv === 'UNPROBED' ? 'WARN' : lv);
  }

  document.getElementById('btn-tdr-title').textContent = tdr.running
    ? 'PULSING...'
    : 'PULSE TDR';

  const swatches = ['sw-ora', 'sw-grn', 'sw-blu', 'sw-brn'];
  const defaultSpecs = [
    { pair_name: 'Pair A', pins: 'Pins 1–2', wire_colors: 'White/Orange • Orange' },
    { pair_name: 'Pair B', pins: 'Pins 3–6', wire_colors: 'White/Green • Green' },
    { pair_name: 'Pair C', pins: 'Pins 4–5', wire_colors: 'Blue • White/Blue' },
    { pair_name: 'Pair D', pins: 'Pins 7–8', wire_colors: 'White/Brown • Brown' }
  ];

  let maxScaleM = 40.0;
  if (hasTdr) {
    const dists = tdr.pairs.map(p => p.distance_m || 0);
    maxScaleM = Math.max(20.0, ...dists) * 1.25;
  }
  const scaleEl = document.getElementById('tdr-scale-labels');
  if (scaleEl) {
    const mMax = Math.ceil(maxScaleM / 4) * 4;
    maxScaleM = mMax;
    scaleEl.innerHTML = `<span>0m</span><span>${mMax * 0.25}m</span><span>${mMax * 0.5}m</span><span>${mMax * 0.75}m</span><span>${mMax}m SCALE</span>`;
  }

  const rowsHtml = (hasTdr ? tdr.pairs : defaultSpecs).map((p, idx) => {
    let fillCls = 'tdr-fill-ok';
    let pct = 0;
    let barTxt = '';
    let statTxt = '';
    let statCol = 'v-good';
    let trackFault = false;

    if (hasTdr) {
      if (p.status === 'OK') {
        fillCls = 'tdr-fill-ok';
        pct = p.distance_m ? Math.min(92, Math.max(20, Math.round((p.distance_m / maxScaleM) * 100))) : 88;
        barTxt = p.detail;
        statTxt = 'PASS • 100Ω';
        statCol = 'v-good';
      } else if (p.status === 'OPEN') {
        const isFault = tdr.overall_verdict === 'FAIL';
        fillCls = isFault ? 'tdr-fill-bad' : 'tdr-fill-open';
        trackFault = isFault;
        pct = p.distance_m !== null ? Math.min(90, Math.max(8, Math.round((p.distance_m / maxScaleM) * 100))) : 45;
        barTxt = p.detail;
        statTxt = p.distance_m !== null ? `OPEN @ ${p.distance_m}m` : 'OPEN';
        statCol = isFault ? 'v-bad' : 'v-warn';
      } else {
        fillCls = 'tdr-fill-bad';
        trackFault = true;
        pct = p.distance_m !== null ? Math.min(90, Math.max(12, Math.round((p.distance_m / maxScaleM) * 100))) : 40;
        barTxt = p.detail;
        statTxt = p.status;
        statCol = 'v-bad';
      }
    } else {
      if (!link.carrier_up) {
        pct = 0;
        barTxt = 'Tap PULSE HARDWARE TDR to measure dead cable';
        statTxt = 'NO CARRIER';
        statCol = '';
      } else if (link.speed_mbps >= 1000) {
        pct = 100;
        barTxt = link.speed_mbps >= 2500
          ? `Active ${(link.speed_mbps / 1000).toFixed(1)}GBASE-T (Pulse TDR for length)`
          : 'Active 1000BASE-T (Pulse TDR for length)';
        statTxt = link.speed_mbps >= 2500 ? `${(link.speed_mbps / 1000).toFixed(1)}G ACTIVE` : '1G ACTIVE';
        statCol = 'v-good';
      } else if (link.speed_mbps === 100 && idx < 2) {
        pct = 85;
        barTxt = 'Active 100BASE-TX Pair';
        statTxt = '100M OK';
        statCol = 'v-good';
      } else if (link.pair_downshift_suspected) {
        fillCls = 'tdr-fill-bad';
        trackFault = true;
        pct = 45;
        barTxt = 'Suspected Open — Pulse TDR for meter distance!';
        statTxt = 'FAULT?';
        statCol = 'v-bad';
      } else {
        pct = 0;
        barTxt = 'Idle on 100BASE-TX';
        statTxt = 'UNUSED';
        statCol = '';
      }
    }

    return `<div class="tdr-row">
      <div class="tdr-label">
        <span class="pair-swatch ${swatches[idx]}"></span>
        <div>
          <div class="tdr-pname">${esc(p.pair_name)} (${esc(p.pins)})</div>
          <div class="tdr-pcol">${esc(p.wire_colors)}</div>
        </div>
      </div>
      <div class="tdr-track ${trackFault ? 'fault' : ''}">
        <div class="${fillCls}" style="width:${pct}%"></div>
        <span class="tdr-bar-txt">${esc(barTxt)}</span>
      </div>
      <div class="tdr-stat ${statCol}">${esc(statTxt)}</div>
    </div>`;
  }).join('');

  document.getElementById('tdr-rows').innerHTML = rowsHtml;
}

function setLinkTab(tab) {
  linkActiveTab = ['tdr', 'wiremap'].includes(tab) ? tab : 'tdr';
  ['tdr', 'wiremap'].forEach(t => {
    const btn = document.getElementById('ltab-' + t);
    const pane = document.getElementById('link-pane-' + t);
    if (btn) btn.classList.toggle('active', t === linkActiveTab);
    if (pane) pane.classList.toggle('hidden', t !== linkActiveTab);
  });
}

function resetPhyErrors() {
  apiPost('/api/phy/reset-counters', {});
}

function renderWiremapSection(s) {
  const link = s.link || {};
  const tdr = s.tdr || {};
  const pw = link.phy_wiring || {};
  const carrier = Boolean(link.carrier_up);
  const verdict = pw.verdict || 'IDLE';

  const banner = document.getElementById('wm-banner');
  const chip = document.getElementById('wm-chip');
  const titleEl = document.getElementById('wm-title');
  const subEl = document.getElementById('wm-sub');
  if (!banner || !chip || !titleEl || !subEl) return;

  banner.classList.toggle('warn', verdict === 'FAIL' || verdict === 'WARN');
  chip.textContent = verdict;
  setVerdictClass(chip, verdict);
  titleEl.textContent = pw.summary || 'Waiting for link or TDR pulse';
  const phySub = pw.phy_name && pw.phy_name !== '—' ? pw.phy_name : 'IEEE / ethtool PHY';
  subEl.textContent = `${link.iface || 'eth0'} · ${phySub}${tdr.tested_at ? ` · TDR: ${tdr.tested_at}` : ''}`;

  const mdixEl = document.getElementById('wm-mdix');
  const mdixTxt = (pw.mdix_state === 'MDI' || pw.mdix_state === 'MDI-X')
    ? `${pw.mdix_state} (Auto)`
    : (pw.mdix_state || 'Unknown');
  mdixEl.textContent = mdixTxt;
  mdixEl.className = 'v ' + (pw.mdix_state === 'MDI-X' ? 'v-cyan' : (pw.mdix_state === 'MDI' ? 'v-good' : ''));

  const hdrRoleEl = document.getElementById('wm-hdr-role');
  if (hdrRoleEl) {
    hdrRoleEl.textContent = (carrier && (pw.mdix_state === 'MDI' || pw.mdix_state === 'MDI-X'))
      ? `4-PAIR SOFTWARE WIREMAP · PHY: ${pw.mdix_state} (Auto)`
      : '4-PAIR SOFTWARE WIREMAP';
  }

  const roleEl = document.getElementById('wm-role');
  roleEl.textContent = pw.master_slave || 'Unknown';
  roleEl.className = 'v ' + (pw.master_slave && pw.master_slave !== 'Unknown' ? 'v-cyan' : '');

  const rxEl = document.getElementById('wm-rxlock');
  if (!carrier) {
    rxEl.textContent = 'No Carrier';
    rxEl.className = 'v';
  } else if (pw.local_rx_ok !== null && pw.local_rx_ok !== undefined) {
    const locTxt = pw.local_rx_ok ? 'OK' : 'FAIL';
    const remTxt = pw.remote_rx_ok ? 'OK' : 'FAIL';
    const scrTxt = pw.descrambler_locked === false ? ' (UNLK)' : '';
    rxEl.textContent = `${locTxt} / ${remTxt}${scrTxt}`;
    rxEl.className = 'v ' + (pw.local_rx_ok && pw.remote_rx_ok && pw.descrambler_locked !== false ? 'v-good' : 'v-bad');
  } else if (pw.descrambler_locked !== null && pw.descrambler_locked !== undefined) {
    rxEl.textContent = pw.descrambler_locked ? 'Descrambler Locked' : 'Unlocked';
    rxEl.className = 'v ' + (pw.descrambler_locked ? 'v-good' : 'v-bad');
  } else {
    rxEl.textContent = 'Link Active';
    rxEl.className = 'v v-good';
  }

  document.getElementById('wm-phy').textContent = phySub;

  const setErrEl = (id, val, txt) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = txt !== undefined ? txt : String(val);
    el.className = 'v ' + (val > 0 ? 'v-warn' : 'v-good');
  };
  setErrEl('wm-idle', pw.idle_errors || 0);
  setErrEl('wm-sym', pw.rx_symbol_errors || 0);
  setErrEl('wm-fcs', pw.false_carrier_errors || 0);
  const nokSum = (pw.local_rx_not_ok_count || 0) + (pw.remote_rx_not_ok_count || 0);
  setErrEl('wm-nok', nokSum, `${pw.local_rx_not_ok_count || 0} / ${pw.remote_rx_not_ok_count || 0}`);

  const svg = document.getElementById('wm-svg');
  if (!svg) return;
  const hasTdr = tdr.pairs && tdr.pairs.length === 4;
  const ys = [20, 49, 78, 107];
  const pairMeta = [
    { name: 'Pair A', pins: '1–2', col: '#fb923c' },
    { name: 'Pair B', pins: '3–6', col: '#4ade80' },
    { name: 'Pair C', pins: '4–5', col: '#60a5fa' },
    { name: 'Pair D', pins: '7–8', col: '#b45309' },
  ];

  const statuses = pairMeta.map((m, idx) => {
    const tp = hasTdr ? tdr.pairs[idx] : null;
    let st = 'IDLE';
    let lbl = 'UNPROBED';
    if (tp && tp.status && tp.status !== 'UNKNOWN') {
      st = tp.status;
      lbl = tp.distance_m !== null && tp.distance_m !== undefined ? `${st} ${tp.distance_m}m` : st;
    } else if (carrier) {
      if (link.speed_mbps >= 1000) {
        st = 'OK';
        lbl = link.speed_mbps >= 2500 ? '2.5G OK' : '1G OK';
      } else if (link.speed_mbps === 100 && idx < 2) {
        st = 'OK';
        lbl = '100M OK';
      } else if (link.pair_downshift_suspected && idx >= 2) {
        st = 'OPEN';
        lbl = 'OPEN?';
      } else {
        st = 'UNUSED';
        lbl = 'UNUSED';
      }
    }
    return { st, lbl };
  });

  const hasNoise = verdict === 'WARN';
  let parts = [];

  for (let i = 0; i < 4; i++) {
    const y = ys[i];
    const m = pairMeta[i];
    const { st, lbl } = statuses[i];

    // Left pin terminal box
    parts.push(`<rect x="8" y="${y - 10}" width="106" height="20" rx="3" fill="#111214" stroke="${m.col}" stroke-width="1.5"/>`);
    parts.push(`<rect x="12" y="${y - 6}" width="6" height="12" rx="1" fill="${m.col}"/>`);
    parts.push(`<text x="24" y="${y + 4}" fill="#f4f4f5" font-size="10.5" font-family="Consolas, monospace" font-weight="700">${m.name} (${m.pins})</text>`);

    // Far-end status box
    let rStroke = '#353944';
    let rFill = '#111214';
    let rTxtCol = '#8b909a';
    if (st === 'OK') {
      rStroke = hasNoise ? '#f59e0b' : '#22c55e';
      rTxtCol = hasNoise ? '#fbbf24' : '#4ade80';
    } else if (st === 'OPEN') {
      rStroke = tdr.overall_verdict === 'UNPATCHED' ? '#f59e0b' : '#e11d48';
      rTxtCol = tdr.overall_verdict === 'UNPATCHED' ? '#fbbf24' : '#fda4af';
    } else if (st === 'SHORT' || st === 'CROSS_SHORT') {
      rStroke = '#e11d48';
      rFill = '#2a1215';
      rTxtCol = '#fda4af';
    }
    parts.push(`<rect x="556" y="${y - 10}" width="116" height="20" rx="3" fill="${rFill}" stroke="${rStroke}" stroke-width="1.4"/>`);
    parts.push(`<text x="614" y="${y + 4}" text-anchor="middle" fill="${rTxtCol}" font-size="10" font-family="Consolas, monospace" font-weight="700">${esc(lbl)}</text>`);

    // Center trace (keep healthy Auto-MDIX traces straight; physical pin role shown in header & KV)
    const x0 = 114;
    const x1 = 556;
    if (st === 'OK') {
      parts.push(`<line x1="${x0}" y1="${y}" x2="${x1}" y2="${y}" stroke="${hasNoise ? '#f59e0b' : '#22c55e'}" stroke-width="2.4" ${hasNoise ? 'stroke-dasharray="7 4"' : ''}/>`);
      if (hasNoise) {
        parts.push(`<rect x="305" y="${y - 8}" width="60" height="16" rx="3" fill="#2a1f0a" stroke="#f59e0b" stroke-width="1"/>`);
        parts.push(`<text x="335" y="${y + 3}" text-anchor="middle" fill="#fbbf24" font-size="9" font-family="Consolas, monospace" font-weight="700">NOISE</text>`);
      }
    } else if (st === 'OPEN') {
      const col = tdr.overall_verdict === 'UNPATCHED' ? '#f59e0b' : '#e11d48';
      parts.push(`<line x1="${x0}" y1="${y}" x2="310" y2="${y}" stroke="${col}" stroke-width="2.2" stroke-dasharray="5 4"/>`);
      parts.push(`<line x1="360" y1="${y}" x2="${x1}" y2="${y}" stroke="#2b2e36" stroke-width="1.5" stroke-dasharray="3 4"/>`);
      parts.push(`<rect x="310" y="${y - 8}" width="50" height="16" rx="3" fill="#251318" stroke="${col}" stroke-width="1"/>`);
      parts.push(`<text x="335" y="${y + 3}" text-anchor="middle" fill="${col}" font-size="9" font-family="Consolas, monospace" font-weight="700">OPEN</text>`);
    } else if (st === 'SHORT') {
      parts.push(`<line x1="${x0}" y1="${y}" x2="310" y2="${y}" stroke="#e11d48" stroke-width="2.4"/>`);
      parts.push(`<rect x="310" y="${y - 8}" width="52" height="16" rx="3" fill="#3b131a" stroke="#e11d48" stroke-width="1.2"/>`);
      parts.push(`<text x="336" y="${y + 3}" text-anchor="middle" fill="#fda4af" font-size="9" font-family="Consolas, monospace" font-weight="700">SHORT</text>`);
    } else if (st === 'CROSS_SHORT') {
      const yNext = ys[Math.min(3, i + 1)];
      parts.push(`<line x1="${x0}" y1="${y}" x2="305" y2="${y}" stroke="#e11d48" stroke-width="2.4"/>`);
      parts.push(`<line x1="305" y1="${y}" x2="365" y2="${yNext}" stroke="#fb7185" stroke-width="2.2" stroke-dasharray="3 2"/>`);
      parts.push(`<rect x="303" y="${y - 8}" width="64" height="16" rx="3" fill="#3b131a" stroke="#e11d48" stroke-width="1.2"/>`);
      parts.push(`<text x="335" y="${y + 3}" text-anchor="middle" fill="#fda4af" font-size="9" font-family="Consolas, monospace" font-weight="700">X-SHORT</text>`);
    } else {
      parts.push(`<line x1="${x0}" y1="${y}" x2="${x1}" y2="${y}" stroke="#2b2e36" stroke-width="1.5" stroke-dasharray="3 4"/>`);
    }
  }

  svg.innerHTML = parts.join('');
}

function resolvedGateway(s) {
  if (s && s.l3 && s.l3.gateway_ip && s.l3.gateway_ip !== '—') return s.l3.gateway_ip;
  if (s && s.switch && s.switch.mgmt_ip && s.switch.mgmt_ip !== '—') return s.switch.mgmt_ip;
  return '1.1.1.1';
}

function getEffectivePingTarget() {
  if (selectedPingTarget === 'gw') return resolvedGateway(latestSnap);
  if (selectedPingTarget === 'custom' && customPingTarget) return customPingTarget;
  return selectedPingTarget || '1.1.1.1';
}

function getEffectiveTraceTarget() {
  if (selectedTraceTarget === 'gw') return resolvedGateway(latestSnap);
  if (selectedTraceTarget === 'custom' && customTraceTarget) return customTraceTarget;
  return selectedTraceTarget || '1.1.1.1';
}

function updateTargetChipUI(containerId, selectedKey, customVal) {
  const row = document.getElementById(containerId);
  if (!row) return;
  row.querySelectorAll('.target-chip').forEach(btn => {
    const key = btn.getAttribute('data-t');
    btn.classList.toggle('active', key === selectedKey);
    if (key === 'custom') {
      btn.textContent = customVal ? `⌨ ${customVal}` : '⌨ Custom';
    }
  });
}

function renderPingCanvas(ping) {
  const canvas = document.getElementById('ping-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const samples = (ping && ping.samples) || [];
  const padL = 42, padR = 14, padT = 14, padB = 22;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  const rtts = samples.filter(p => p.ok && p.rtt_ms !== null).map(p => p.rtt_ms);
  const maxRtt = rtts.length ? Math.max(5, Math.ceil(Math.max(...rtts) * 1.25)) : 20;

  // Gridlines
  ctx.strokeStyle = '#252830';
  ctx.lineWidth = 1;
  ctx.font = '10px Consolas, monospace';
  ctx.fillStyle = '#71717a';
  [0, 0.5, 1].forEach(frac => {
    const y = padT + plotH * (1 - frac);
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    const labelVal = (maxRtt * frac).toFixed(maxRtt >= 10 ? 0 : 1);
    ctx.fillText(`${labelVal}ms`, 4, y + 3);
  });

  if (!samples.length) {
    ctx.fillStyle = '#71717a';
    ctx.font = '12px Segoe UI, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Select a target above and tap ▶ START PING for 1 Hz rolling sparkline', w / 2, h / 2);
    ctx.textAlign = 'left';
    return;
  }

  const maxSlots = Math.max(samples.length, 40);
  const stepX = plotW / Math.max(1, maxSlots - 1);
  const offsetSlots = maxSlots - samples.length;

  // Line path
  ctx.strokeStyle = '#f59e0b';
  ctx.lineWidth = 2;
  ctx.beginPath();
  let drawing = false;
  samples.forEach((pt, i) => {
    const x = padL + (offsetSlots + i) * stepX;
    if (!pt.ok || pt.rtt_ms === null) {
      drawing = false;
      return;
    }
    const y = padT + plotH - (Math.min(pt.rtt_ms, maxRtt) / maxRtt) * plotH;
    if (!drawing) {
      ctx.moveTo(x, y);
      drawing = true;
    } else {
      ctx.lineTo(x, y);
    }
  });
  ctx.stroke();

  // Points & loss markers
  samples.forEach((pt, i) => {
    const x = padL + (offsetSlots + i) * stepX;
    if (!pt.ok || pt.rtt_ms === null) {
      ctx.strokeStyle = '#ef4444';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(x, padT);
      ctx.lineTo(x, padT + plotH);
      ctx.stroke();
    } else {
      const y = padT + plotH - (Math.min(pt.rtt_ms, maxRtt) / maxRtt) * plotH;
      ctx.fillStyle = pt.rtt_ms > 50 ? '#facc15' : '#4ade80';
      ctx.beginPath();
      ctx.arc(x, y, 2.7, 0, Math.PI * 2);
      ctx.fill();
    }
  });
}

function renderDiagnosticsView(s) {
  const diag = s.diagnostics || {};
  const ping = diag.ping || {};
  const trace = diag.traceroute || {};
  const spd = diag.speedtest || {};
  const ipf = diag.iperf || {};
  const mtu = diag.mtu || {};

  // Update Ping pane
  updateTargetChipUI('ping-target-chips', selectedPingTarget, customPingTarget);
  const effPingTarget = ping.running ? ping.target : getEffectivePingTarget();
  document.getElementById('ping-hdr-left').textContent = `PING SPARKLINE • TARGET: ${effPingTarget}`;
  document.getElementById('ping-hdr-right').textContent = ping.running
    ? `● LIVE (${ping.sent || 0} sent / ${ping.received || 0} recv)`
    : (ping.sent > 0 ? `Stopped (${ping.sent} sent)` : 'Idle');
  const btnPing = document.getElementById('btn-ping-toggle');
  btnPing.textContent = ping.running ? '⏹ STOP PING' : '▶ START PING';
  btnPing.classList.toggle('running', Boolean(ping.running));

  document.getElementById('ping-stat-avg').textContent = ping.avg_ms !== null && ping.avg_ms !== undefined ? `${ping.avg_ms} ms` : '—';
  document.getElementById('ping-stat-minmax').textContent = (ping.min_ms !== null && ping.min_ms !== undefined)
    ? `${ping.min_ms} / ${ping.max_ms} ms`
    : '—';
  document.getElementById('ping-stat-jitter').textContent = ping.jitter_ms !== null && ping.jitter_ms !== undefined ? `${ping.jitter_ms} ms` : '—';
  const elLoss = document.getElementById('ping-stat-loss');
  const lossPct = ping.loss_percent ?? 0;
  elLoss.textContent = `${lossPct}%`;
  elLoss.className = 'pdf-stat-val ' + (lossPct > 5 ? 'v-bad' : (lossPct > 0 ? 'v-warn' : 'v-good'));
  if (currentView === 'diag' && diagTab === 'ping') {
    renderPingCanvas(ping);
  }

  // Update Trace & MTU pane
  updateTargetChipUI('trace-target-chips', selectedTraceTarget, customTraceTarget);
  const effTraceTarget = getEffectiveTraceTarget();
  document.getElementById('mtu-target-lbl').textContent = mtu.target && mtu.target !== '—' ? mtu.target : effTraceTarget;
  document.getElementById('mtu-status-txt').textContent = mtu.running ? `Probing PMTU to ${mtu.target}...` : (mtu.status || 'Ready');

  const btnTrace = document.getElementById('btn-trace-run');
  btnTrace.textContent = trace.running ? 'TRACING...' : 'TRACEROUTE';
  btnTrace.classList.toggle('running', Boolean(trace.running));
  const btnMtu = document.getElementById('btn-mtu-run');
  btnMtu.textContent = mtu.running ? 'PROBING...' : 'CHECK MTU';

  const hops = trace.hops || [];
  const tBody = document.getElementById('trace-tbody');
  if (!hops.length) {
    const emptyMsg = trace.running
      ? `Running traceroute to ${effTraceTarget}...`
      : (trace.error ? `Error: ${trace.error}` : `Select target and tap TRACEROUTE or CHECK MTU above.`);
    tBody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#71717a;padding:24px;">${esc(emptyMsg)}</td></tr>`;
  } else {
    tBody.innerHTML = hops.map(h => `<tr>
      <td style="font-weight:800;color:#a1a1aa">${h.hop}</td>
      <td style="font-weight:700;color:${h.loss ? '#71717a' : '#fbbf24'}">${esc(h.ip)}</td>
      <td>${esc(h.host)}</td>
      <td style="color:${h.loss ? '#fbbf24' : '#4ade80'}">${h.rtt_ms !== null && h.rtt_ms !== undefined ? h.rtt_ms + ' ms' : '*'}</td>
      <td>${h.loss ? '<span class="v-warn">Timeout *</span>' : '<span class="v-good">OK</span>'}</td>
    </tr>`).join('');
  }

  // Update WAN Speed pane
  const activeNic = (s.link && s.link.iface) || 'eth0';
  const btnEthSpd = document.getElementById('btn-spd-eth');
  if (btnEthSpd) btnEthSpd.textContent = `ETH (${activeNic})`;
  document.querySelectorAll('#speed-iface-chips .target-chip').forEach(ch => {
    ch.classList.toggle('active', ch.dataset.s === speedIfaceMode);
  });

  const egPill = document.getElementById('speed-egress-pill');
  if (egPill) {
    if (spd.egress_iface && spd.egress_iface !== '—') {
      const ipPart = spd.egress_ip && spd.egress_ip !== '—' ? ` (${spd.egress_ip})` : '';
      egPill.textContent = `VIA ${spd.egress_iface}${ipPart}`;
    } else if (speedIfaceMode === 'eth') {
      const ethIp = s.l3 && s.l3.ipv4_address !== '—' ? ` (${s.l3.ipv4_address})` : '';
      egPill.textContent = `TARGET: ${activeNic}${ethIp}`;
    } else if (speedIfaceMode === 'wifi') {
      const wIp = s.wifi_client && s.wifi_client.ipv4 && s.wifi_client.ipv4 !== '—' ? ` (${s.wifi_client.ipv4})` : '';
      egPill.textContent = `TARGET: wlan0${wIp}`;
    } else {
      egPill.textContent = 'EGRESS: AUTO ROUTE';
    }
  }

  document.getElementById('speed-status-title').textContent = spd.running
    ? `Testing via ${spd.egress_iface || 'WAN'} (${spd.egress_ip || '—'})...`
    : `Cloudflare Edge • ${spd.status || 'Ready'}`;
  const viaTxt = (spd.egress_iface && spd.egress_iface !== '—') ? ` • Via ${spd.egress_iface} (${spd.egress_ip || '—'})` : '';
  document.getElementById('speed-status-sub').textContent = spd.completed_at
    ? `Last Run: ${spd.completed_at}${viaTxt}`
    : `Measures HTTP DL/UL throughput plus loaded latency spike${viaTxt}`;
  const btnSpd = document.getElementById('btn-speed-run');
  btnSpd.textContent = spd.running ? 'TESTING WAN...' : 'RUN SPEED TEST';
  btnSpd.classList.toggle('running', Boolean(spd.running));

  document.getElementById('spd-dl').textContent = spd.download_mbps !== null && spd.download_mbps !== undefined ? `${spd.download_mbps} Mbps` : '—';
  document.getElementById('spd-ul').textContent = spd.upload_mbps !== null && spd.upload_mbps !== undefined ? `${spd.upload_mbps} Mbps` : '—';
  document.getElementById('spd-lat').textContent = (spd.unloaded_ms !== null && spd.unloaded_ms !== undefined)
    ? `${spd.unloaded_ms} → ${spd.loaded_ms ?? spd.unloaded_ms} ms`
    : '—';
  const bloatEl = document.getElementById('spd-bloat');
  bloatEl.textContent = spd.bufferbloat_grade || '—';
  bloatEl.className = 'speed-val ' + (['A+', 'A'].includes(spd.bufferbloat_grade) ? 'v-good' : (spd.bufferbloat_grade === 'B' ? 'v-cyan' : 'v-warn'));

  // Update iperf3 pane
  const savedTargets = ipf.saved_targets || ['192.168.0.1'];
  if (!selectedIperfTarget || !savedTargets.includes(selectedIperfTarget)) {
    selectedIperfTarget = (ipf.target && ipf.target !== '—' && savedTargets.includes(ipf.target))
      ? ipf.target
      : (savedTargets[0] || '192.168.0.1');
  }
  const chipsHtml = savedTargets.map(t => {
    const active = t === selectedIperfTarget ? 'active' : '';
    const delBtn = savedTargets.length > 1
      ? `<span class="target-del" onclick="event.stopPropagation(); removeIperfTarget('${esc(t)}')" title="Remove">×</span>`
      : '';
    return `<button class="target-chip ${active}" onclick="selectIperfTarget('${esc(t)}')">${esc(t)}${delBtn}</button>`;
  }).join('');
  document.getElementById('iperf-target-chips').innerHTML = chipsHtml;

  document.getElementById('ipf-target').textContent = selectedIperfTarget;
  document.getElementById('ipf-tx').textContent = ipf.tx_mbps !== null && ipf.tx_mbps !== undefined ? `${ipf.tx_mbps} Mbps` : '—';
  document.getElementById('ipf-rx').textContent = ipf.rx_mbps !== null && ipf.rx_mbps !== undefined ? `${ipf.rx_mbps} Mbps` : '—';
  const retTxt = ipf.retransmits !== null && ipf.retransmits !== undefined ? `${ipf.retransmits} retr • ` : '';
  document.getElementById('ipf-status').textContent = ipf.error ? ipf.error : `${retTxt}${ipf.status || 'Ready'}`;
  const btnIpfCli = document.getElementById('btn-ipf-client');
  btnIpfCli.textContent = ipf.client_running ? '⏳ RUNNING iPERF3...' : '⚡ RUN 5s iPERF3 CLIENT';
  btnIpfCli.classList.toggle('running', Boolean(ipf.client_running));

  const bindIp = ipf.server_bind_ip && ipf.server_bind_ip !== '—' ? ipf.server_bind_ip : (s.l3 ? s.l3.ipv4_address : '—');
  const srvEl = document.getElementById('ipf-srv-status');
  srvEl.textContent = ipf.server_running ? 'LISTENING (:5201)' : 'Stopped';
  srvEl.className = 'v ' + (ipf.server_running ? 'v-good' : '');
  document.getElementById('ipf-srv-ip').textContent = bindIp || '—';
  document.getElementById('ipf-srv-cli').textContent = `iperf3 -c ${bindIp && bindIp !== '—' ? bindIp : '<pi-ip>'}`;
  const btnIpfSrv = document.getElementById('btn-ipf-srv');
  btnIpfSrv.textContent = ipf.server_running ? '⏹ STOP LOCAL SERVER' : '🖥 START LOCAL SERVER';
  btnIpfSrv.classList.toggle('running', Boolean(ipf.server_running));
}

function renderScanView(scan) {
  const hosts = scan.hosts || [];
  const total = hosts.length;
  const maxPage = Math.max(0, Math.ceil(total / SCAN_PAGE_SIZE) - 1);
  if (scanPage > maxPage) scanPage = 0;

  const startIdx = scanPage * SCAN_PAGE_SIZE;
  const slice = hosts.slice(startIdx, startIdx + SCAN_PAGE_SIZE);

  document.getElementById('scan-hdr-left').textContent = total > 0
    ? `SHOWING ${startIdx + 1}–${startIdx + slice.length} OF ${total} DEVICES • SUBNET: ${scan.subnet}`
    : `0 DEVICES • SUBNET: ${scan.subnet}`;
  document.getElementById('scan-hdr-right').textContent = scan.scanning
    ? '⏳ Scanning...'
    : (scan.last_scan_at ? `Tap host: Ports & WoL • ${scan.duration_s}s` : 'Tap any host for Ports & WoL');

  document.getElementById('btn-scan-title').textContent = scan.scanning ? 'SWEEPING...' : 'SWEEP /24';
  document.getElementById('btn-scan-page-sub').textContent = total > 0
    ? `PG ${scanPage + 1}/${maxPage + 1}`
    : 'PG 1/1';

  const tbody = document.getElementById('scan-tbody');
  if (!slice.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:#71717a;padding:26px;">${
      scan.scanning ? 'Sweeping local /24 subnet via ARP, rDNS, NetBIOS & TCP probes...' : 'Tap SWEEP /24 above to discover active hosts on this subnet.'
    }</td></tr>`;
    return;
  }

  tbody.innerHTML = slice.map(h => {
    const pStr = h.open_ports && h.open_ports.length ? h.open_ports.slice(0, 4).join(',') + ' • ' : '';
    const isRogue = h.role.toLowerCase().includes('rogue');
    return `<tr onclick="openHostModal('${esc(h.ip)}')" title="Tap for deep host inspection &amp; WoL">
      <td style="font-weight:700;color:${isRogue ? '#fda4af' : '#fbbf24'}">${esc(h.ip)}</td>
      <td>${esc(h.hostname)}</td>
      <td style="color:#a1a1aa">${esc(h.vendor)}</td>
      <td style="color:${isRogue ? '#fda4af' : '#4ade80'}">${esc(pStr + h.role)}</td>
    </tr>`;
  }).join('');
}

function renderSecurityView(sec, scanCount) {
  const gBox = document.getElementById('sec-grade-box');
  gBox.classList.remove('warn', 'crit');
  if (sec.rogue_dhcp_detected || (sec.arp_conflicts && sec.arp_conflicts.length) ||
      (sec.forensics && (sec.forensics.storm_detected || sec.forensics.rogue_ra_detected))) {
    gBox.classList.add('crit');
  } else if (sec.score < 85) {
    gBox.classList.add('warn');
  }

  document.getElementById('sec-grade').textContent = sec.grade;
  document.getElementById('sec-score').textContent = `${sec.score} / 100 PTS`;
  document.getElementById('sec-summary').textContent = sec.summary;
  document.getElementById('btn-sec-probe-title').textContent = sec.probing
    ? 'LISTENING...'
    : 'PROBE DHCP';
  const secHostsSub = document.getElementById('sec-hosts-sub');
  if (secHostsSub) secHostsSub.textContent = `Inspect ${scanCount} Discovered Hosts`;

  const mDiv = document.getElementById('sec-metrics');
  mDiv.innerHTML = (sec.metrics || []).map(m => {
    const pct = Math.round((m.score / Math.max(1, m.max_score)) * 100);
    const col = m.status === 'FAIL' ? '#ef4444' : (m.status === 'WARN' ? '#f59e0b' : '#22c55e');
    return `<div class="m-item">
      <div class="m-row"><span>${esc(m.name)}</span><span style="font-family:Consolas,monospace;font-weight:700;color:${col}">${m.score}/${m.max_score}</span></div>
      <div class="m-bar"><div class="m-fill" style="width:${pct}%;background:${col}"></div></div>
    </div>`;
  }).join('');

  const fDiv = document.getElementById('sec-findings');
  fDiv.innerHTML = (sec.findings || []).map(f => `
    <div class="find-card ${esc(f.severity)}">
      <div class="find-t">[${esc(f.severity)}] ${esc(f.title)}</div>
      <div class="find-d">${esc(f.detail)}</div>
    </div>
  `).join('');

  // L2 & DHCP Option Forensics Pane
  const f = sec.forensics || {};
  const stp = f.stp || {};
  document.getElementById('for-stp-proto').textContent = stp.detected
    ? `${stp.protocol} (${stp.bpdu_count || 0} BPDUs)`
    : 'No STP BPDU Heard';
  document.getElementById('for-stp-root').textContent = stp.detected
    ? `Pri ${stp.root_priority ?? '?'} • ${stp.root_mac}`
    : '—';
  document.getElementById('for-stp-cost').textContent = stp.detected
    ? `Cost ${stp.root_path_cost ?? 0} • Port ${stp.port_id}`
    : '—';

  document.getElementById('for-pps').textContent = `${f.bcast_pps ?? 0} bcast/s • ${f.mcast_pps ?? 0} mcast/s`;
  const strmEl = document.getElementById('for-storm');
  strmEl.textContent = f.storm_detected ? `ALERT: STORM (${f.bcast_pps} pps)` : 'Normal (<100 pps)';
  strmEl.className = 'v ' + (f.storm_detected ? 'v-bad' : 'v-good');

  const ras = f.ipv6_ra_senders || [];
  const raEl = document.getElementById('for-ra');
  if (f.rogue_ra_detected) {
    raEl.textContent = `🚨 ${ras.length} Senders (Rogue RA!)`;
    raEl.className = 'v v-bad';
  } else if (ras.length === 1) {
    raEl.textContent = `1 Router (${ras[0].src_mac})`;
    raEl.className = 'v v-good';
  } else {
    raEl.textContent = '0 RA Senders';
    raEl.className = 'v';
  }

  const exp = f.exposure || {};
  const expEl = document.getElementById('for-exposure');
  if (expEl) {
    const poisonCnt = (exp.llmnr_count || 0) + (exp.nbns_count || 0) + (exp.wpad_count || 0);
    const clrCnt = exp.cleartext_count || 0;
    if (clrCnt > 0) {
      expEl.textContent = `${clrCnt} Cleartext • ${poisonCnt} Poison`;
      expEl.className = 'v v-bad';
    } else if (poisonCnt > 0) {
      expEl.textContent = `${poisonCnt} Poison Talker(s)`;
      expEl.className = 'v v-warn';
    } else {
      expEl.textContent = 'Clean (0)';
      expEl.className = 'v v-good';
    }
  }

  const offers = sec.dhcp_offers || [];
  const dBody = document.getElementById('for-dhcp-tbody');
  if (!offers.length) {
    dBody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:18px;">Tap Refresh Probe to inspect DHCP Options (Subnet Mask, NTP, PXE/TFTP Opt 66/150, Boot 67, Opt 43, WPAD 252).</td></tr>';
  } else {
    dBody.innerHTML = offers.map(o => {
      const lease = o.lease_time_s ? `${Math.round(o.lease_time_s / 3600)}h` : '—';
      const wpadStyle = (o.wpad_url && o.wpad_url !== '—') ? 'color:#facc15;font-weight:700;' : 'color:#94a3b8;';
      return `<tr>
        <td style="font-weight:700;color:${o.authorized ? '#4ade80' : '#fda4af'}">${esc(o.server_ip)}</td>
        <td>${esc(o.subnet_mask || '—')} • ${esc(lease)}</td>
        <td>${esc(o.domain_name || '—')} • ${esc(o.ntp_server || '—')}</td>
        <td>${esc(o.tftp_server || '—')} / ${esc(o.boot_file || '—')}</td>
        <td style="${wpadStyle}">${esc(o.vendor_opt43 || '—')} • ${esc(o.wpad_url || '—')}</td>
      </tr>`;
    }).join('');
  }
}

function renderVlanProbePane(s) {
  const vp = s.vlan_probe || {};
  const presets = vp.preset_vlans || [10, 20, 30, 50, 99, 100, 200];
  document.getElementById('vlan-preset-chips').innerHTML = presets.map(v => {
    const del = presets.length > 1
      ? `<span class="target-del" onclick="event.stopPropagation(); removeVlanPreset(${v})" title="Remove">×</span>`
      : '';
    return `<span class="target-chip">${v}${del}</span>`;
  }).join('');

  const btn = document.getElementById('btn-vlan-probe');
  btn.textContent = vp.running ? 'PROBING...' : 'PROBE TRUNK';
  btn.classList.toggle('running', Boolean(vp.running));
  document.getElementById('vlan-probe-ts').textContent = vp.running
    ? 'Testing tagged DHCP...'
    : (vp.last_run_at ? `Last Probe: ${vp.last_run_at}` : (vp.error || 'Ready'));

  const res = vp.results || [];
  const tbody = document.getElementById('vlan-probe-tbody');
  if (!res.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#71717a;padding:24px;">${
      esc(vp.error || 'Tap PROBE TRUNK above to actively probe DHCP/connectivity across observed & preset VLAN IDs.')
    }</td></tr>`;
  } else {
    tbody.innerHTML = res.map(e => {
      const col = e.status === 'LIVE_DHCP' ? 'v-good' : (e.status === 'TRAFFIC_ONLY' ? 'v-warn' : '');
      const srv = e.offered_ip && e.offered_ip !== '—' ? `${e.dhcp_server_ip} → ${e.offered_ip}` : e.dhcp_server_ip;
      const gw = e.router_ip && e.router_ip !== '—' ? `${e.router_ip} (${e.subnet_mask})` : '—';
      return `<tr>
        <td style="font-weight:800;color:#fbbf24">VLAN ${e.vlan_id}</td>
        <td>${esc(e.source)}</td>
        <td class="${col}" style="font-weight:700">${esc(e.status)}</td>
        <td>${esc(srv)}</td>
        <td>${esc(gw)}</td>
      </tr>`;
    }).join('');
  }
}

function renderSnmpPane(s) {
  const sn = s.snmp || {};
  const autoIp = (s.switch && s.switch.mgmt_ip && s.switch.mgmt_ip !== '—') ? s.switch.mgmt_ip : '—';
  const tgtIp = customSnmpTarget || autoIp;
  document.getElementById('snmp-target-lbl').textContent = tgtIp;
  document.getElementById('btn-snmp-comm').textContent = `${sn.community || 'public'} ⌨`;

  const btn = document.getElementById('btn-snmp-query');
  btn.textContent = sn.running ? 'QUERYING...' : 'QUERY SNMP';
  btn.classList.toggle('running', Boolean(sn.running));

  document.getElementById('snmp-sysname').textContent = sn.sys_name || '—';
  document.getElementById('snmp-sysdescr').textContent = sn.sys_descr || '—';
  document.getElementById('snmp-uptime').textContent = sn.uptime_str || '—';
  const errEl = document.getElementById('snmp-err');
  errEl.textContent = sn.error ? sn.error : (sn.last_run_at ? `Queried ${sn.target_ip} at ${sn.last_run_at}` : 'Manual-tap only (never auto-polls)');
  errEl.className = 'v ' + (sn.error ? 'v-warn' : '');

  document.getElementById('snmp-port').textContent = sn.matched_port || '—';
  document.getElementById('snmp-in-err').textContent = sn.if_in_errors !== null && sn.if_in_errors !== undefined ? String(sn.if_in_errors) : '—';
  document.getElementById('snmp-out-err').textContent = sn.if_out_errors !== null && sn.if_out_errors !== undefined ? String(sn.if_out_errors) : '—';
  document.getElementById('snmp-poe').textContent = sn.poe_draw_w !== null && sn.poe_draw_w !== undefined
    ? `${sn.poe_draw_w}W / ${sn.poe_budget_w || '?'}W`
    : '—';
}

function renderAuditView(audit) {
  const jobs = audit.jobs || [];
  const sel = document.getElementById('sel-audit-job');
  if (sel && document.activeElement !== sel) {
    sel.innerHTML = jobs.length
      ? jobs.map(j => `<option value="${esc(j.name)}" ${j.name === audit.job_name ? 'selected' : ''}>${esc(j.name)} (${j.count})</option>`).join('')
      : `<option value="${esc(audit.job_name)}">${esc(audit.job_name)}</option>`;
  }

  const curPref = audit.drop_prefix || 'W';
  document.querySelectorAll('#audit-prefix-bar .target-chip').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-p') === curPref);
  });

  document.getElementById('audit-next-lbl').textContent = `NEXT: ${audit.next_drop_label}`;
  document.getElementById('at-save-title').textContent = `SAVE ${audit.next_drop_label}`;
  document.getElementById('sw-save-title').textContent = `SAVE ${audit.next_drop_label}`;
  document.getElementById('tdr-save-title').textContent = `SAVE ${audit.next_drop_label}`;
  document.getElementById('sec-save-title').textContent = `SAVE ${audit.next_drop_label}`;
  document.getElementById('audit-save-title').textContent = `SAVE ${audit.next_drop_label}`;
  const liveSave = document.getElementById('live-btn-save');
  if (liveSave && !liveSave.dataset.toast) liveSave.textContent = `💾 LOG ${audit.next_drop_label}`;

  const rows = (audit.recent_ports || []).slice(0, 6);
  const tbody = document.getElementById('audit-tbody');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#71717a;padding:22px;">No wall ports logged yet in "${esc(audit.job_name)}". Tap SAVE ${esc(audit.next_drop_label)} above to record.</td></tr>`;
  } else {
    tbody.innerHTML = rows.map(r => {
      const ok = r.verdict === 'PASS';
      const swPort = r.port_id !== '—' ? `${r.switch_name} • ${r.port_id}` : r.switch_name;
      const badgeCol = ok ? 'background:#132a1d;color:#4ade80' : 'background:#3b131a;color:#fda4af';
      const noteMark = r.notes ? ` <span style="color:#fbbf24;" title="${esc(r.notes)}">•</span>` : '';
      return `<tr>
        <td style="font-weight:800;color:#fff">${esc(r.drop_label)}${noteMark}</td>
        <td>${esc(swPort)}</td>
        <td style="color:#fbbf24">${esc(r.tdr_summary || r.vlan_summary)}</td>
        <td>${esc(r.speed_summary)}</td>
        <td><span style="padding:1px 5px;border-radius:3px;font-weight:700;font-size:9px;${badgeCol}">${esc(r.verdict)}</span></td>
        <td style="white-space:nowrap;">
          <button class="del-btn" style="color:#fbbf24;margin-right:2px;" onclick="printSavedPort(${r.id})" title="Print 58mm Label">🖨</button>
          <button class="del-btn" style="color:${r.notes ? '#fbbf24' : '#a1a1aa'};margin-right:2px;" onclick="editPortNotes(${r.id}, '${esc(r.drop_label)}', '${esc(r.notes || '')}')" title="Add/Edit Drop Notes">📝</button>
          <button class="del-btn" onclick="deleteSavedPort(${r.id})" title="Delete">×</button>
        </td>
      </tr>`;
    }).join('');
  }

  document.getElementById('audit-foot').textContent =
    `Total Logged: ${audit.total_saved} (${audit.pass_count} Pass • ${audit.warn_fail_count} Warn/Fail)`;

  if (audit.qr_svg_data_uri) document.getElementById('audit-qr').src = audit.qr_svg_data_uri;

  const pdfLink = document.getElementById('audit-pdf-link');
  pdfLink.href = '/api/audit/report.pdf';
  pdfLink.textContent = audit.pdf_url;

  const wifiMode = audit.wifi_ap_active ? `AP: ${audit.wifi_ssid}` : `${audit.wifi_ssid} (${audit.wifi_ip})`;
  document.getElementById('audit-wifi-lbl').textContent = wifiMode;
  document.getElementById('btn-hotspot').textContent = audit.wifi_ap_active ? 'Stop AP' : 'Field AP';

  const pc = audit.pcap || {};
  const dlPcap = document.getElementById('btn-dl-pcap');
  if (pc.capturing) {
    document.getElementById('audit-pcap-lbl').textContent = `Capturing (${pc.packets_captured} pkts)...`;
    dlPcap.classList.add('hidden');
  } else if (pc.filename && pc.filename !== '—') {
    const kb = Math.max(1, Math.round(pc.size_bytes / 1024));
    document.getElementById('audit-pcap-lbl').textContent = `${pc.filename} (${kb} KB)`;
    dlPcap.classList.remove('hidden');
  } else {
    document.getElementById('audit-pcap-lbl').textContent = 'None recorded';
    dlPcap.classList.add('hidden');
  }
}

function renderPcapPane(audit, hw, link) {
  const pc = (audit && audit.pcap) || {};
  const tapActive = Boolean(hw && hw.tap && hw.tap.active);
  const stEl = document.getElementById('pcap-pane-status');
  const ifEl = document.getElementById('pcap-pane-iface');
  const fileEl = document.getElementById('pcap-pane-file');
  const dlEl = document.getElementById('btn-pcap-pane-dl');
  const stopBtn = document.getElementById('btn-pcap-stop');
  const titleEl = document.getElementById('btn-pcap-title');
  const subEl = document.getElementById('btn-pcap-sub');
  if (!stEl) return;

  ifEl.textContent = tapActive ? 'br0 (Inline Tap Bridge)' : ((link && link.iface) || 'eth0');
  if (stopBtn) stopBtn.classList.toggle('hidden', !pc.capturing);

  if (pc.capturing) {
    const modeTag = pc.continuous ? 'CONTINUOUS' : 'CAPTURING';
    stEl.textContent = `${modeTag} (${pc.packets_captured || 0} pkts)`;
    stEl.className = 'v v-warn';
    fileEl.textContent = pc.filename || 'Recording...';
    dlEl.classList.add('hidden');
    if (titleEl) titleEl.textContent = '⏳ CAPTURING PCAP...';
    if (subEl) subEl.textContent = `${pc.packets_captured || 0} packets buffered`;
  } else if (pc.filename && pc.filename !== '—') {
    const kb = Math.max(1, Math.round((pc.size_bytes || 0) / 1024));
    stEl.textContent = `Complete (${pc.packets_captured || 0} pkts)`;
    stEl.className = 'v v-good';
    fileEl.textContent = `${pc.filename} (${kb} KB)`;
    dlEl.classList.remove('hidden');
    if (titleEl) titleEl.textContent = '📦 QUICK 15s PCAP';
    if (subEl) subEl.textContent = 'Capture Live L2/DHCP/VLAN Frames';
  } else {
    stEl.textContent = 'Idle';
    stEl.className = 'v v-cyan';
    fileEl.textContent = 'None recorded';
    dlEl.classList.add('hidden');
    if (titleEl) titleEl.textContent = '📦 QUICK 15s PCAP';
    if (subEl) subEl.textContent = 'Capture Live L2/DHCP/VLAN Frames';
  }

  ['btn-pcap-15', 'btn-pcap-30', 'btn-pcap-60'].forEach(id => {
    const b = document.getElementById(id);
    if (b) b.disabled = Boolean(pc.capturing);
  });
}

function renderSnapshot(s) {
  latestSnap = s;

  const selSource = document.getElementById('sel-source');
  const expectedVal = s.mode === 'demo' ? `demo:${s.demo_scenario}` : 'live';
  if (document.activeElement !== selSource) selSource.value = expectedVal;

  const inpIface = document.getElementById('inp-iface');
  if (document.activeElement !== inpIface && s.link && s.link.iface) inpIface.value = s.link.iface;

  const hw = s.hw_nics || {};
  const tapActive = Boolean(hw.tap && hw.tap.active);
  const ptEnabled = Boolean(s.pentest && s.pentest.enabled);
  applyPentestTheme(ptEnabled);
  const modeBase = ptEnabled ? 'PENTEST' : (s.mode === 'demo' ? 'DEMO' : 'LIVE');
  const pillMode = document.getElementById('pill-mode');
  pillMode.textContent = tapActive ? `${modeBase} • TAP` : modeBase;
  pillMode.classList.toggle('pentest-active', ptEnabled);
  if (s.system && s.system.cpu_temp_c !== null) {
    document.getElementById('pill-temp').textContent = `${Math.round(s.system.cpu_temp_c)}°C`;
  }

  const pillPoe = document.getElementById('pill-poe');
  if (s.poe && s.poe.supported) {
    pillPoe.classList.remove('hidden');
    const w = s.poe.allocated_watts ? ` ${s.poe.allocated_watts}W` : '';
    pillPoe.textContent = `⚡ ${s.poe.standard}${w}`;
  } else {
    pillPoe.classList.add('hidden');
  }

  const dot = document.getElementById('link-dot');
  dot.className = 'dot ' + (!s.link.carrier_up ? 'down' : (s.link.pair_downshift_suspected ? 'warn' : 'up'));
  const spdStr = !s.link.carrier_up
    ? 'NO LINK'
    : (s.link.speed_mbps >= 2500 ? `${(s.link.speed_mbps / 1000).toFixed(1)}GbE` : (s.link.speed_mbps >= 1000 ? '1GbE' : `${s.link.speed_mbps || '?'}M`));
  const ipShort = (s.l3.ipv4_address && s.l3.ipv4_address !== '—') ? s.l3.ipv4_address : 'No IP';
  const nicTag = (s.link.iface && s.link.iface !== 'eth0') ? `${s.link.iface} • ` : '';
  document.getElementById('pill-link-txt').textContent = `${nicTag}${spdStr} • ${ipShort}`;

  // Topbar Wi-Fi pill
  const wcTop = s.wifi_client || {};
  const wDot = document.getElementById('wifi-dot');
  const wTxt = document.getElementById('pill-wifi-txt');
  if (wDot && wTxt) {
    if (wcTop.ap_mode_active) {
      wDot.className = 'dot warn';
      wTxt.textContent = `AP • ${wcTop.ipv4 && wcTop.ipv4 !== '—' ? wcTop.ipv4 : '10.42.0.1'}`;
    } else if (wcTop.connected || (s.audit && s.audit.wifi_ip && s.audit.wifi_ip !== '—')) {
      wDot.className = 'dot up';
      const rawSsid = wcTop.active_ssid || (s.audit && s.audit.wifi_ssid) || 'Wi-Fi';
      const shortSsid = rawSsid.length > 10 ? rawSsid.slice(0, 9) + '…' : rawSsid;
      const wIp = (wcTop.ipv4 && wcTop.ipv4 !== '—') ? wcTop.ipv4 : ((s.audit && s.audit.wifi_ip) || '—');
      wTxt.textContent = `${shortSsid} • ${wIp}`;
    } else {
      wDot.className = 'dot down';
      wTxt.textContent = 'Wi-Fi Off';
    }
  }

  // Live Workbench Hero + 4x2 Instrument Grid
  const at = s.autotest || {};
  const atVerdict = at.verdict || s.autotest_verdict || 'WAITING';
  const pnum = s.switch.panel && s.switch.panel.port_number;

  document.getElementById('live-port-num').textContent = s.switch.detected
    ? (pnum ? String(pnum) : s.switch.port_id.slice(0, 4))
    : (s.link.carrier_up ? 'UP' : '—');

  const liveAtChip = document.getElementById('live-at-chip');
  liveAtChip.textContent = `AUTOTEST ${at.passed_count || 0}/${at.total_count || 7} ${atVerdict}`;
  setVerdictClass(liveAtChip, atVerdict);

  const poeBrief = (s.poe && s.poe.supported)
    ? `${s.poe.standard}${s.poe.allocated_watts ? ' ' + s.poe.allocated_watts + 'W' : ''}`
    : 'No PoE';
  const protoBrief = s.switch.protocols.length ? s.switch.protocols.join('+') : 'Passive';
  document.getElementById('live-proto-meta').textContent = `${protoBrief} · ${poeBrief} · ${spdStr}`;

  document.getElementById('live-sw-model').textContent = s.switch.detected
    ? `${s.switch.model} (${s.switch.switch_name})`
    : (s.link.carrier_up ? 'Link Active — Listening for LLDP / CDP' : 'No Carrier — Plug into Wall Port');

  const gwTxt = s.l3.gateway_ping_ms !== null ? `GW ${s.l3.gateway_ping_ms}ms` : 'GW —';
  const tdrNote = (s.tdr && s.tdr.overall_verdict !== 'NOT_RUN')
    ? `TDR ${s.tdr.overall_verdict}`
    : (s.link.pair_downshift_suspected ? 'PAIR FAULT' : '4 Pairs');
  document.getElementById('live-sw-sub').textContent = s.switch.detected
    ? `${s.switch.port_id} · ${s.vlan.native_vlan_name} · ${tdrNote} · ${gwTxt}`
    : (s.tdr && s.tdr.summary ? s.tdr.summary : s.link.pair_diagnostic_note);

  const liveBlink = document.getElementById('live-btn-blink');
  if (liveBlink) {
    liveBlink.classList.toggle('blinking', Boolean(s.blink.active));
    liveBlink.textContent = s.blink.active ? `⏹ STOP (${s.blink.remaining_seconds}s)` : '⚡ BLINK PORT';
  }
  document.getElementById('live-job-name').textContent = `${s.audit.job_name} (${s.audit.total_saved} logged)`;
  document.getElementById('live-next-drop').textContent = s.audit.next_drop_label;
  document.getElementById('live-portal-url').textContent = s.audit.portal_url;

  const setMetric = (id, text, cls) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = 'bench-tile-metric' + (cls ? ' ' + cls : '');
  };

  // Tile 01: AutoTest
  const homeBadge01 = document.getElementById('home-badge-01');
  homeBadge01.textContent = atVerdict;
  setVerdictClass(homeBadge01, atVerdict);
  setMetric('home-val-01', `${at.passed_count || 0}/${at.total_count || 7} ${atVerdict}`,
    atVerdict === 'PASS' ? 'v-good' : (atVerdict === 'FAIL' ? 'v-bad' : 'v-amber'));
  document.getElementById('home-sub-01').textContent = ipShort !== 'No IP' ? `${ipShort} · ${s.l3.dhcp_status || 'Bound'}` : (at.summary || 'Plug in to start');
  document.getElementById('home-meta-01').textContent = `${at.profile === 'lan_only' ? 'LAN-Only' : 'WAN'} · ${at.duration_s ? at.duration_s + 's' : 'Auto'}`;

  // Tile 02: Switch & Port
  document.getElementById('home-badge-02').textContent = s.switch.detected ? protoBrief : 'WAIT';
  setMetric('home-val-02', s.switch.detected ? (s.switch.port_id || `P${pnum}`) : (s.link.carrier_up ? 'LISTENING' : 'NO LINK'),
    s.switch.detected ? 'v-cyan' : (s.link.carrier_up ? 'v-amber' : 'v-bad'));
  document.getElementById('home-sub-02').textContent = s.switch.detected ? `${s.switch.switch_name}` : (s.link.carrier_up ? 'Waiting LLDP/CDP...' : 'Switch & faceplate');
  const vShort = s.vlan.native_vlan ? `VLAN ${s.vlan.native_vlan}` : 'Untagged';
  document.getElementById('home-meta-02').textContent = `${vShort} · ${poeBrief}`;

  // Tile 03: Cable & PHY
  const pwLive = s.link.phy_wiring || {};
  const tdrDists = (s.tdr && s.tdr.pairs) ? s.tdr.pairs.map(p => p.distance_m).filter(d => d !== null && d !== undefined) : [];
  const tdrAvgM = tdrDists.length ? `${(tdrDists.reduce((a, b) => a + b, 0) / tdrDists.length).toFixed(1)}m` : '';
  document.getElementById('home-badge-03').textContent = (s.tdr && s.tdr.overall_verdict !== 'NOT_RUN') ? s.tdr.overall_verdict : (pwLive.verdict || 'PHY');
  setMetric('home-val-03', `${spdStr}${tdrAvgM ? ' · ' + tdrAvgM : ''}`,
    !s.link.carrier_up ? (s.tdr && s.tdr.overall_verdict === 'UNPATCHED' ? 'v-amber' : '') : (s.link.pair_downshift_suspected ? 'v-bad' : 'v-good'));
  document.getElementById('home-sub-03').textContent = pwLive.mdix_state && pwLive.mdix_state !== 'Unknown'
    ? `PHY: ${pwLive.mdix_state} · ${pwLive.master_slave || 'Auto'}`
    : (s.link.pair_diagnostic_note || '4-pair TDR & wiremap');
  document.getElementById('home-meta-03').textContent = `${(s.tdr && s.tdr.cable_type) || 'Cat5e (69%)'} · ${s.link.rx_crc_errors || 0} CRC`;

  // Tile 04: Speed & Path
  const diag = s.diagnostics || {};
  const pingObj = diag.ping || {};
  const spdObj = diag.speedtest || {};
  let diagBadge = s.l3.internet_ok ? 'WAN OK' : (s.l3.gateway_ping_ms !== null ? 'GW OK' : 'IDLE');
  let diagVal = s.l3.gateway_ping_ms !== null ? `GW ${s.l3.gateway_ping_ms} ms` : 'READY';
  let diagCls = s.l3.internet_ok ? 'v-good' : '';
  let diagSub = s.l3.dns_resolve_ms !== null ? `DNS ${s.l3.dns_resolve_ms}ms · HTTP ${s.l3.http_probe_ms ?? '—'}ms` : 'Ping, Trace, WAN & iperf3';
  let diagMeta = s.l3.gateway_ip !== '—' ? `GW ${s.l3.gateway_ip}` : 'Tap for Speed/Ping';
  if (pingObj.running && pingObj.avg_ms !== null) {
    diagBadge = 'PINGING';
    diagVal = `${pingObj.avg_ms} ms`;
    diagCls = 'v-cyan';
    diagSub = `Ping ${pingObj.target}`;
    diagMeta = `Loss ${pingObj.loss_percent}% · Jit ${pingObj.jitter_ms ?? '—'}ms`;
  } else if (spdObj.download_mbps) {
    diagBadge = `BB ${spdObj.bufferbloat_grade || 'OK'}`;
    diagVal = `${spdObj.download_mbps}↓ ${spdObj.upload_mbps || '?'}↑`;
    diagCls = 'v-good';
    diagSub = `Via ${spdObj.egress_iface || 'WAN'} (${spdObj.egress_ip || '—'})`;
    diagMeta = `Latency ${spdObj.unloaded_ms ?? '?'}→${spdObj.loaded_ms ?? '?'}ms`;
  } else if (diag.iperf && diag.iperf.tx_mbps) {
    diagBadge = 'iPERF3';
    diagVal = `${diag.iperf.tx_mbps} Mbps`;
    diagCls = 'v-cyan';
    diagSub = `LAN → ${diag.iperf.target}`;
  }
  document.getElementById('home-badge-04').textContent = diagBadge;
  setMetric('home-val-04', diagVal, diagCls);
  document.getElementById('home-sub-04').textContent = diagSub;
  document.getElementById('home-meta-04').textContent = diagMeta;

  // Tile 05: Subnet Hosts
  document.getElementById('home-badge-05').textContent = s.scan.scanning ? 'SCAN...' : 'ARP /24';
  setMetric('home-val-05', s.scan.scanning ? 'SCANNING' : `${s.scan.active_count || 0} HOSTS`, s.scan.active_count > 0 ? 'v-cyan' : '');
  document.getElementById('home-sub-05').textContent = s.scan.subnet && s.scan.subnet !== '—' ? s.scan.subnet : 'No active subnet';
  document.getElementById('home-meta-05').textContent = s.scan.last_scan_at ? `Updated ${s.scan.last_scan_at}` : 'Tap to sweep & WoL';

  // Tile 06: Wi-Fi Link & Survey
  const wifiState = s.wifi || {};
  const sigTop = (wcTop.signal_pct !== null && wcTop.signal_pct !== undefined) ? `${wcTop.signal_pct}%` : '';
  document.getElementById('home-badge-06').textContent = wcTop.ap_mode_active
    ? 'AP ON'
    : (wifiState.total_count > 0 ? `CH ${wifiState.best_24g_channel || '?'}` : (wcTop.connected ? 'CLIENT' : 'OFF'));
  const wifiIf = (s.system && s.system.wifi_iface) || (s.wifi && s.wifi.iface) || 'wlan0';
  if (wcTop.ap_mode_active) {
    setMetric('home-val-06', 'Field AP', 'v-amber');
    document.getElementById('home-sub-06').textContent = 'JackTrace-AP (10.42.0.1)';
  } else if (wcTop.connected) {
    setMetric('home-val-06', `${wcTop.active_ssid || 'Wi-Fi'}${sigTop ? ' · ' + sigTop : ''}`, 'v-good');
    document.getElementById('home-sub-06').textContent = `IP ${wcTop.ipv4 || '—'} · ${wifiIf}`;
  } else {
    setMetric('home-val-06', 'Disconnected', '');
    document.getElementById('home-sub-06').textContent = 'Tap SYS → Wi-Fi to join';
  }
  const cnt6Home = wifiState.count_6g ? `/6G:${wifiState.count_6g}` : '';
  document.getElementById('home-meta-06').textContent = wifiState.total_count > 0
    ? `Survey: ${wifiState.total_count} APs (2.4G:${wifiState.count_24g}/5G:${wifiState.count_5g}${cnt6Home})`
    : (wifiState.count_6g ? '2.4 / 5 / 6 GHz Analyzer' : '2.4 / 5 GHz Analyzer');

  // Tile 07: Security & Tap
  const tapTxt = tapActive ? 'TAP ON' : (s.security.rogue_dhcp_detected ? 'ROGUE!' : 'GUARD');
  document.getElementById('home-badge-07').textContent = tapTxt;
  setMetric('home-val-07', tapActive
    ? 'br0 TAP'
    : (s.link.carrier_up ? `GRADE ${s.security.grade}` : 'L2 IDLE'),
    tapActive ? 'v-amber' : (s.security.grade === 'A' ? 'v-good' : (s.link.carrier_up ? 'v-warn' : '')));
  document.getElementById('home-sub-07').textContent = s.link.carrier_up
    ? `${s.security.score}/100 · ${s.security.rogue_dhcp_detected ? 'ROGUE DHCP!' : 'DHCP Clean'}`
    : 'Rogue DHCP, PCAP & br0';
  document.getElementById('home-meta-07').textContent = s.audit && s.audit.pcap && s.audit.pcap.capturing
    ? `Capturing (${s.audit.pcap.packets_captured} pkts)`
    : `${s.vlan.eapol_8021x_seen ? '802.1X Seen' : 'No 802.1X'} · L2 Forensics`;

  // Tile 08: Audit & Sync
  const syncPend = (s.sync && s.sync.pending_count) || 0;
  document.getElementById('home-badge-08').textContent = `${s.audit.total_saved} LOGS`;
  setMetric('home-val-08', `${s.audit.next_drop_label} NEXT`, 'v-amber');
  document.getElementById('home-sub-08').textContent = `${s.audit.job_name}`;
  document.getElementById('home-meta-08').textContent = `Queue: ${syncPend} · BT: ${(s.printer && s.printer.selected_mac) ? 'Paired' : 'None'}`;

  // View 01 AutoTest
  renderAutoTestView(s);

  // View 02 Switch & Port
  const protoStr = s.switch.protocols.length ? s.switch.protocols.join(' + ') : 'PASSIVE LISTEN';
  const durStr = s.autotest_duration_s > 0 ? ` • ${s.autotest_duration_s}s` : '';
  document.getElementById('sw-kicker').textContent = s.switch.detected
    ? `${protoStr} (${s.switch.confidence})${durStr}`
    : (s.link.carrier_up ? 'CARRIER UP • LISTENING...' : 'NO CARRIER');

  const vChip = document.getElementById('sw-verdict');
  vChip.textContent = s.autotest_verdict;
  setVerdictClass(vChip, s.autotest_verdict);

  document.getElementById('sw-model').textContent = s.switch.detected
    ? s.switch.model
    : (s.link.carrier_up ? 'Unmanaged Switch / Listening' : 'No Switch Detected');
  const swMetaEl = document.getElementById('sw-meta');
  if (s.switch.detected) {
    swMetaEl.innerHTML =
      `<span><b>${esc(s.switch.switch_name)}</b></span>` +
      `<span>·</span>` +
      `<span>${esc(s.switch.mgmt_ip)}</span>`;
  } else {
    swMetaEl.textContent = `NIC: ${s.link.iface} (${s.link.mac_address})`;
  }

  document.getElementById('sw-port').textContent = s.switch.detected
    ? (pnum ? `P${pnum} (${s.switch.port_id})` : s.switch.port_id)
    : (s.link.carrier_up ? 'LIVE LINK' : 'UNPLUGGED');

  const descSuffix = (s.switch.port_descr && s.switch.port_descr !== '—' && s.switch.port_descr !== s.switch.port_id)
    ? ` · "${s.switch.port_descr}"`
    : '';
  document.getElementById('sw-loc').textContent = s.switch.detected
    ? `${s.switch.panel.summary}${descSuffix}`
    : s.link.pair_diagnostic_note;

  renderFaceplate(s.switch, s.blink);

  const elMac = document.getElementById('sw-kv-mac');
  if (elMac) elMac.textContent = s.switch.detected ? s.switch.chassis_mac : s.link.mac_address;

  const elSpd = document.getElementById('sw-kv-speed');
  elSpd.textContent = s.link.carrier_up ? `${s.link.speed_mbps || '?'} Mbps ${s.link.duplex}` : 'Link Down';
  elSpd.className = 'v ' + (!s.link.carrier_up ? 'v-bad' : (s.link.pair_downshift_suspected ? 'v-warn' : 'v-good'));

  const elPoe = document.getElementById('sw-kv-poe');
  if (s.poe.supported) {
    const alloc = s.poe.allocated_watts ? ` (${s.poe.allocated_watts}W)` : '';
    elPoe.textContent = `${s.poe.standard}${alloc}`;
    elPoe.className = 'v v-warn';
  } else {
    elPoe.textContent = 'No PoE TLV';
    elPoe.className = 'v';
  }

  document.getElementById('sw-kv-proto').textContent = s.switch.detected
    ? `${s.switch.port_id} · ${s.switch.protocols.join('/')}`
    : '—';

  const elNac = document.getElementById('sw-kv-nac');
  elNac.textContent = s.vlan.nac_status;
  elNac.className = 'v ' + (s.vlan.eapol_8021x_seen ? 'v-warn' : '');

  document.getElementById('sw-kv-pvid').textContent = s.vlan.native_vlan_name;
  document.getElementById('sw-kv-voice').textContent = s.vlan.voice_vlan ? `VLAN ${s.vlan.voice_vlan} (VOIP)` : 'None';
  document.getElementById('sw-kv-tags').textContent = s.vlan.tagged_vlans.length ? s.vlan.tagged_vlans.join(', ') : 'Access Port';

  const elGw = document.getElementById('sw-kv-gw');
  if (s.l3.gateway_ip !== '—') {
    const rtt = s.l3.gateway_ping_ms !== null ? `${s.l3.gateway_ping_ms}ms` : 'timeout';
    elGw.textContent = `${s.l3.gateway_ip} (${rtt})`;
    elGw.className = 'v ' + (s.l3.gateway_ping_ms !== null ? 'v-good' : 'v-warn');
  } else {
    elGw.textContent = 'No Gateway';
    elGw.className = 'v';
  }

  const btnBlink = document.getElementById('btn-blink');
  const bTitle = document.getElementById('btn-blink-title');
  if (s.blink.active) {
    btnBlink.classList.add('blinking');
    bTitle.textContent = `⏹ BLINKING (${s.blink.remaining_seconds}s)`;
  } else {
    btnBlink.classList.remove('blinking');
    bTitle.textContent = '⚡ BLINK LED';
  }

  // View 03 Cable TDR + Wiremap + PHY Link + Stress
  renderTdrSection(s);
  renderWiremapSection(s);

  const phySpd = s.link.carrier_up
    ? (s.link.speed_mbps >= 2500 ? `${(s.link.speed_mbps / 1000).toFixed(1)}GbE` : `${s.link.speed_mbps || '?'} Mbps`)
    : 'Link Down';
  const phySpdEl = document.getElementById('phy-nic-speed');
  phySpdEl.textContent = s.link.carrier_up ? `${s.link.iface} · ${phySpd} ${s.link.duplex}` : `${s.link.iface} · Down`;
  phySpdEl.className = 'pdf-stat-val ' + (!s.link.carrier_up ? 'v-bad' : (s.link.pair_downshift_suspected ? 'v-warn' : 'v-good'));
  const pw = s.link.phy_wiring || {};
  const mdixBadge = (pw.mdix_state && pw.mdix_state !== 'Unknown') ? ` · ${pw.mdix_state}` : '';
  document.getElementById('phy-autoneg').textContent = s.link.carrier_up
    ? `${s.link.autoneg ? 'Auto-Neg' : 'Forced'} · ${s.link.partner_supports_1g ? '1G+ Partner' : '10/100'}${mdixBadge}`
    : 'No Carrier';
  document.getElementById('phy-frames').textContent =
    `${s.link.pair_downshift_suspected ? '2-Pair Downshift' : (s.link.carrier_up ? '4 Pairs Active' : 'Idle')} · ${s.link.rx_packets || 0} RX`;

  const stV = document.getElementById('st-verdict');
  stV.textContent = s.stress.verdict;
  stV.className = 'pdf-stat-val ' + (s.stress.verdict.startsWith('PASS') ? 'v-good' : (s.stress.verdict === 'Not Run' ? '' : 'v-warn'));
  document.getElementById('st-loss').textContent = s.stress.packets_sent > 0
    ? `${s.stress.loss_percent}% loss · avg ${s.stress.avg_ms || '—'} ms`
    : 'Tap 20-PKT STRESS above';
  const phyErrSum = (pw.idle_errors || 0) + (pw.rx_symbol_errors || 0) + (pw.false_carrier_errors || 0);
  document.getElementById('st-crc').textContent = phyErrSum > 0
    ? `${s.link.rx_crc_errors} CRC · ${phyErrSum} PHY`
    : `${s.link.rx_crc_errors} total (Δ ${s.stress.crc_delta})`;
  document.getElementById('btn-stress-title').textContent = s.stress.running ? 'TESTING...' : '20-PKT STRESS';

  // View 04 Speed & Path
  renderDiagnosticsView(s);

  // Views 02 VLAN/SNMP, 05, 06, 07, 08, M4 Sync/Printer/NICs
  renderVlanProbePane(s);
  renderSnmpPane(s);
  renderScanView(s.scan);
  renderWifiView(s.wifi || {});
  renderSecurityView(s.security, s.scan.active_count || 0);
  renderAuditView(s.audit);
  renderSyncPane(s.sync || {});
  renderPrinterPane(s.printer || {}, s.audit || {});
  renderNicsPane(s.hw_nics || {}, s.link || {});
  renderPcapPane(s.audit || {}, s.hw_nics || {}, s.link || {});
  renderWifiClientPane(s.wifi_client || {});
  renderSysNetCalPane(s);
  renderTailcatUI(s);
  renderPentestViews(s);
  const pdfModal = document.getElementById('pdf-modal');
  if (pdfModal && !pdfModal.classList.contains('hidden') && pdfActiveTab === 'sheet') {
    renderPdfTouchSheet();
  }

  // System Modal & Battery Pill values
  if (s.system) {
    const caps = s.system.capabilities || {};
    const sysWifiIf = s.system.wifi_iface || (s.wifi && s.wifi.iface) || 'wlan0';
    const batPill = document.getElementById('pill-bat');
    if (batPill) {
      const bp = s.system.battery_pct;
      if (bp !== null && bp !== undefined) {
        const bst = String(s.system.battery_status || '').toLowerCase();
        const isChg = bst.includes('charg') && !bst.includes('discharg');
        batPill.classList.remove('hidden', 'bat-low', 'bat-warn', 'bat-chg');
        if (isChg) batPill.classList.add('bat-chg');
        else if (bp <= 15) batPill.classList.add('bat-low');
        else if (bp <= 35) batPill.classList.add('bat-warn');
        batPill.textContent = `${isChg ? '⚡' : '🔋'} ${bp}%`;
        batPill.title = `Battery: ${bp}%${s.system.battery_status ? ' (' + s.system.battery_status + ')' : ''}`;
      } else {
        batPill.classList.add('hidden');
      }
    }

    document.getElementById('sys-host').textContent = `${s.system.hostname} • ${s.system.uptime_str}`;
    document.getElementById('sys-temp').textContent = s.system.cpu_temp_c !== null ? `${s.system.cpu_temp_c} °C` : '—';
    const sysWlanIfEl = document.getElementById('sys-wlan-iface');
    if (sysWlanIfEl) sysWlanIfEl.textContent = sysWifiIf;
    document.getElementById('sys-wlan').textContent = `${s.audit.wifi_ssid} (${s.audit.wifi_ip})`;
    document.getElementById('sys-eth').textContent = `${s.link.iface}: ${s.l3.ipv4_address}`;

    const blSec = document.getElementById('sys-sec-backlight');
    if (blSec) blSec.classList.toggle('hidden', caps.supports_backlight === false);

    const dsiFlipSupported = caps.supports_dsi_flip !== false;
    const overlaySupported = caps.supports_overlayfs !== false;
    document.getElementById('btn-ori-normal').classList.toggle('hidden', !dsiFlipSupported);
    document.getElementById('btn-ori-flipped').classList.toggle('hidden', !dsiFlipSupported);
    document.getElementById('btn-ori-normal').classList.toggle('active', !s.system.screen_flipped);
    document.getElementById('btn-ori-flipped').classList.toggle('active', Boolean(s.system.screen_flipped));
    document.getElementById('sys-reboot-note').classList.toggle('hidden', !s.system.reboot_required);

    const btnRo = document.getElementById('btn-sys-ro');
    if (btnRo) {
      btnRo.classList.toggle('hidden', !overlaySupported);
      const roActive = Boolean(s.system.overlayfs_active);
      const roPending = Boolean(s.system.overlayfs_pending_enable);
      btnRo.classList.toggle('active', roActive || roPending);
      btnRo.textContent = roActive
        ? '🛡 RO Root: ON'
        : (roPending ? '🛡 RO Root: REBOOT' : '🛡 RO Root: OFF');
    }
    const optsLbl = document.getElementById('sys-opts-label');
    if (optsLbl) {
      optsLbl.textContent = (dsiFlipSupported || overlaySupported)
        ? 'DSI Orientation & Read-Only Root (OverlayFS)'
        : 'Security & Testing Mode';
    }
  }

  const drawer = document.getElementById('json-drawer');
  if (!drawer.classList.contains('hidden')) {
    drawer.textContent = JSON.stringify(s, null, 2);
  }
}

async function apiPost(path, body = {}) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (res.ok) {
    const data = await res.json();
    if (data && data.link) renderSnapshot(data);
    return data;
  }
  return null;
}

// AutoTest Actions
function toggleAutotestProfile() {
  if (!latestSnap || !latestSnap.autotest) return;
  const nextProf = latestSnap.autotest.profile === 'lan_only' ? 'standard' : 'lan_only';
  apiPost('/api/autotest/config', { profile: nextProf, auto_log: Boolean(latestSnap.autotest.auto_log) });
}

function toggleAutotestAutoLog() {
  if (!latestSnap || !latestSnap.autotest) return;
  const nextAutoLog = !latestSnap.autotest.auto_log;
  apiPost('/api/autotest/config', { profile: latestSnap.autotest.profile || 'standard', auto_log: nextAutoLog });
}

async function runAutotestNow() {
  const btn = document.getElementById('btn-at-run-title');
  btn.textContent = 'RUNNING...';
  await apiPost('/api/autotest/run', {});
  setTimeout(() => { btn.textContent = 'RE-RUN'; }, 400);
}

// Diagnostics View Actions
function setDiagTab(tab) {
  diagTab = tab;
  ['ping', 'trace', 'speed', 'iperf'].forEach(t => {
    document.getElementById('dtab-' + t).classList.toggle('active', t === tab);
    document.getElementById('diag-pane-' + t).classList.toggle('hidden', t !== tab);
  });
  if (tab === 'ping' && latestSnap && latestSnap.diagnostics) {
    requestAnimationFrame(() => renderPingCanvas(latestSnap.diagnostics.ping));
  }
}

function selectPingTarget(key) {
  selectedPingTarget = key;
  updateTargetChipUI('ping-target-chips', selectedPingTarget, customPingTarget);
  if (latestSnap) renderDiagnosticsView(latestSnap);
}

function openCustomPingTarget() {
  openTouchKeyboard({
    title: 'Enter Ping Target IP / Hostname',
    initialValue: customPingTarget || '192.168.0.1',
    mode: 'ip',
    onDone: (val) => {
      const cleaned = val.trim();
      if (!cleaned) return;
      customPingTarget = cleaned;
      selectedPingTarget = 'custom';
      if (latestSnap) renderDiagnosticsView(latestSnap);
    }
  });
}

function togglePingMonitor() {
  const running = latestSnap && latestSnap.diagnostics && latestSnap.diagnostics.ping && latestSnap.diagnostics.ping.running;
  if (running) {
    apiPost('/api/diag/ping/stop', {});
  } else {
    apiPost('/api/diag/ping/start', { target: getEffectivePingTarget() });
  }
}

function selectTraceTarget(key) {
  selectedTraceTarget = key;
  updateTargetChipUI('trace-target-chips', selectedTraceTarget, customTraceTarget);
  if (latestSnap) renderDiagnosticsView(latestSnap);
}

function openCustomTraceTarget() {
  openTouchKeyboard({
    title: 'Enter Traceroute / MTU Target IP or Host',
    initialValue: customTraceTarget || '1.1.1.1',
    mode: 'ip',
    onDone: (val) => {
      const cleaned = val.trim();
      if (!cleaned) return;
      customTraceTarget = cleaned;
      selectedTraceTarget = 'custom';
      if (latestSnap) renderDiagnosticsView(latestSnap);
    }
  });
}

function runTracerouteNow() {
  apiPost('/api/diag/traceroute', { target: getEffectiveTraceTarget() });
}

function runMtuNow() {
  apiPost('/api/diag/mtu', { target: getEffectiveTraceTarget() });
}

function selectSpeedIface(mode) {
  speedIfaceMode = ['auto', 'eth', 'wifi'].includes(mode) ? mode : 'auto';
  if (latestSnap) renderDiagnosticsView(latestSnap);
}

function runSpeedTestNow() {
  apiPost('/api/diag/speedtest', { iface_mode: speedIfaceMode });
}

function selectIperfTarget(ip) {
  selectedIperfTarget = ip;
  if (latestSnap) renderDiagnosticsView(latestSnap);
}

function openAddIperfTarget() {
  openTouchKeyboard({
    title: 'Add LAN iperf3 Server IP / Host',
    initialValue: '192.168.0.',
    mode: 'ip',
    onDone: (val) => {
      const cleaned = val.trim();
      if (!cleaned || !latestSnap) return;
      const cur = (latestSnap.diagnostics && latestSnap.diagnostics.iperf && latestSnap.diagnostics.iperf.saved_targets) || [];
      const nextList = cur.includes(cleaned) ? cur : [...cur, cleaned];
      selectedIperfTarget = cleaned;
      apiPost('/api/diag/iperf/targets', { targets: nextList });
    }
  });
}

function removeIperfTarget(ip) {
  if (!latestSnap || !latestSnap.diagnostics || !latestSnap.diagnostics.iperf) return;
  const cur = latestSnap.diagnostics.iperf.saved_targets || [];
  const nextList = cur.filter(x => x !== ip);
  if (!nextList.length) return;
  if (selectedIperfTarget === ip) selectedIperfTarget = nextList[0];
  apiPost('/api/diag/iperf/targets', { targets: nextList });
}

function runIperfClientNow() {
  apiPost('/api/diag/iperf/client', { target: selectedIperfTarget || '192.168.0.1', duration_sec: 5 });
}

function toggleIperfServerNow() {
  const running = latestSnap && latestSnap.diagnostics && latestSnap.diagnostics.iperf && latestSnap.diagnostics.iperf.server_running;
  apiPost('/api/diag/iperf/server', { enable: !running });
}

// ==========================================
// VIEW 06: WI-FI SURVEY, CHANNEL GRAPH & WALK
// ==========================================

const WIFI_PALETTE = ['#f59e0b', '#4ade80', '#fb7185', '#a78bfa', '#38bdf8', '#fb923c', '#e879f9', '#2dd4bf'];

function signalColor(dbm) {
  if (dbm >= -60) return '#4ade80';
  if (dbm >= -72) return '#facc15';
  return '#f87171';
}

function signalQualityLabel(dbm) {
  if (dbm === null || dbm === undefined) return '—';
  if (dbm >= -55) return 'EXCELLENT';
  if (dbm >= -67) return 'GOOD';
  if (dbm >= -78) return 'FAIR';
  return 'WEAK';
}

function setWifiTab(tab) {
  wifiTab = tab;
  ['list', 'graph', 'walk'].forEach(t => {
    document.getElementById('wtab-' + t).classList.toggle('active', t === tab);
    document.getElementById('wifi-pane-' + t).classList.toggle('hidden', t !== tab);
  });
  if (latestSnap && latestSnap.wifi) {
    requestAnimationFrame(() => {
      if (tab === 'graph') renderWifiChanCanvas(latestSnap.wifi);
      else if (tab === 'walk') renderWifiWalkCanvas(latestSnap.wifi.walk);
    });
  }
}

function setWifiBandFilter(band) {
  wifiBandFilter = band;
  document.querySelectorAll('#wifi-band-chips .target-chip').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-b') === band);
  });
  if (latestSnap && latestSnap.wifi) renderWifiView(latestSnap.wifi);
}

function setWifiGraphBand(band) {
  wifiGraphBand = band;
  document.querySelectorAll('#wifi-graph-band-chips .target-chip').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-gb') === band);
  });
  if (latestSnap && latestSnap.wifi) renderWifiChanCanvas(latestSnap.wifi);
}

function scanWifiNow() {
  apiPost('/api/wifi/scan', {});
}

function walkWifiAp(bssid) {
  if (!bssid || bssid === '—') return;
  selectedWalkBssid = bssid;
  setWifiTab('walk');
  apiPost('/api/wifi/walk/start', { bssid });
}

function walkConnectedWifi() {
  if (!latestSnap || !latestSnap.wifi) return;
  const wf = latestSnap.wifi;
  const target = (wf.connected_bssid && wf.connected_bssid !== '—')
    ? wf.connected_bssid
    : (wf.networks && wf.networks.length ? wf.networks[0].bssid : '');
  if (target) walkWifiAp(target);
}

function toggleWifiWalk() {
  const wf = (latestSnap && latestSnap.wifi) || {};
  const walk = wf.walk || {};
  if (walk.running) {
    apiPost('/api/wifi/walk/stop', {});
    return;
  }
  const bssid = selectedWalkBssid || (walk.bssid && walk.bssid !== '—' ? walk.bssid : '') ||
    (wf.connected_bssid && wf.connected_bssid !== '—' ? wf.connected_bssid : '') ||
    (wf.networks && wf.networks.length ? wf.networks[0].bssid : '');
  if (bssid) apiPost('/api/wifi/walk/start', { bssid });
}

function renderWifiView(wf) {
  const nets = wf.networks || [];
  const apWarn = document.getElementById('wifi-ap-warn');
  apWarn.classList.toggle('hidden', !wf.ap_mode_blocked);
  if (wf.ap_mode_blocked && wf.error) {
    document.getElementById('wifi-ap-warn-sub').textContent = wf.error;
  }

  document.getElementById('wcnt-all').textContent = wf.total_count ?? nets.length;
  document.getElementById('wcnt-24').textContent = wf.count_24g ?? 0;
  document.getElementById('wcnt-5').textContent = wf.count_5g ?? 0;
  const cnt6 = wf.count_6g ?? nets.filter(n => n.band === '6 GHz').length;
  const wcnt6El = document.getElementById('wcnt-6');
  if (wcnt6El) wcnt6El.textContent = cnt6;
  const show6 = cnt6 > 0 || wifiBandFilter === '6 GHz' || wifiGraphBand === '6 GHz';
  const btnBand6 = document.getElementById('btn-wband-6g');
  if (btnBand6) btnBand6.classList.toggle('hidden', !show6);
  const btnGraph6 = document.getElementById('btn-wgraph-6g');
  if (btnGraph6) btnGraph6.classList.toggle('hidden', !show6);

  const bestChTxt = wf.best_24g_channel ? `Best 2.4G: Ch ${wf.best_24g_channel}` : 'Best 2.4G: Ch —';
  document.getElementById('wifi-best-ch').textContent = bestChTxt;
  document.getElementById('wifi-graph-best-ch').textContent = bestChTxt;

  const btnScan = document.getElementById('btn-wifi-scan');
  btnScan.textContent = wf.scanning ? 'SCANNING...' : 'SCAN WI-FI';
  btnScan.classList.toggle('running', Boolean(wf.scanning));
  const btnRescan = document.getElementById('btn-wifi-rescan');
  btnRescan.textContent = wf.scanning ? 'SCANNING...' : 'RE-SCAN';
  btnRescan.classList.toggle('running', Boolean(wf.scanning));

  const filtered = wifiBandFilter === 'ALL'
    ? nets
    : nets.filter(n => n.band === wifiBandFilter);
  wifiSurveyRows = filtered;

  const tbody = document.getElementById('wifi-tbody');
  if (!filtered.length) {
    const wifiIfLbl = wf.iface || 'wlan0';
    const msg = wf.scanning
      ? `Scanning RF channels via ${wifiIfLbl}...`
      : (wf.error || 'No networks in this filter. Tap SCAN WI-FI above.');
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#71717a;padding:24px;">${esc(msg)}</td></tr>`;
  } else {
    tbody.innerHTML = filtered.map((n, idx) => {
      const col = signalColor(n.signal_dbm);
      const assocDot = n.associated ? `<span style="color:#4ade80">● </span>` : '';
      const bndShort = n.band === '2.4 GHz' ? '2.4G' : (n.band === '5 GHz' ? '5G' : (n.band === '6 GHz' ? '6G' : n.band));
      const joinBtn = (!n.associated && n.ssid && n.ssid !== '<Hidden>')
        ? `<button class="mini-btn" style="padding:1px 5px;font-size:9px;margin-left:5px;" onclick="event.stopPropagation(); joinSurveyWifiIdx(${idx})">Join</button>`
        : '';
      return `<tr onclick="walkWifiAp('${esc(n.bssid)}')" title="Tap to track live dBm in Walk Meter">
        <td>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:4px;">
            <span style="font-weight:800;color:${n.associated ? '#4ade80' : '#f4f4f5'};min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${assocDot}${esc(n.ssid)}</span>${joinBtn}
          </div>
          <div style="font-size:9px;color:#71717a;">${esc(n.bssid)} • ${esc(bndShort)}</div>
        </td>
        <td style="color:#fbbf24;font-weight:700;">Ch ${n.channel} <span style="color:#71717a;font-weight:400;">(${n.width_mhz}MHz)</span></td>
        <td>
          <div style="font-weight:700;color:#e4e4e7;">${esc(n.security)}</div>
          <div style="font-size:9px;color:#8b909a;">${esc(n.wifi_gen)}</div>
        </td>
        <td style="color:#a1a1aa;">${esc(n.vendor)}</td>
        <td>
          <div class="sig-wrap">
            <span style="font-weight:800;color:${col};min-width:46px;">${n.signal_dbm} dBm</span>
            <div class="sig-bar-track"><div class="sig-bar-fill" style="width:${n.quality_pct}%;background:${col};"></div></div>
          </div>
        </td>
      </tr>`;
    }).join('');
  }

  // Walk Meter pane fields
  const walk = wf.walk || {};
  const walkBssid = walk.bssid && walk.bssid !== '—' ? walk.bssid : (wf.connected_bssid || '—');
  const walkSsid = walk.ssid && walk.ssid !== '—' ? walk.ssid : (wf.connected_ssid || 'No AP Selected');
  document.getElementById('walk-ap-title').textContent = `Tracking: ${walkSsid} (${walkBssid})`;
  document.getElementById('walk-ap-sub').textContent = walk.channel
    ? `${walk.band} • Channel ${walk.channel} (${walk.freq_mhz || '?'} MHz) • Tap STOP to freeze`
    : 'Tap any AP row in Networks or click Track Connected';

  const btnWalk = document.getElementById('btn-walk-toggle');
  btnWalk.textContent = walk.running ? '⏹ STOP WALK' : '▶ START WALK';
  btnWalk.classList.toggle('running', Boolean(walk.running));

  const curEl = document.getElementById('walk-stat-cur');
  if (walk.current_dbm !== null && walk.current_dbm !== undefined) {
    curEl.textContent = `${walk.current_dbm} dBm • ${signalQualityLabel(walk.current_dbm)}`;
    curEl.style.color = signalColor(walk.current_dbm);
  } else {
    curEl.textContent = '—';
    curEl.style.color = '#f8fafc';
  }
  document.getElementById('walk-stat-minmax').textContent = (walk.min_dbm !== null && walk.min_dbm !== undefined)
    ? `${walk.min_dbm} / ${walk.max_dbm} dBm`
    : '—';
  document.getElementById('walk-stat-avg').textContent = (walk.avg_dbm !== null && walk.avg_dbm !== undefined)
    ? `${walk.avg_dbm} dBm`
    : '—';
  document.getElementById('walk-stat-rate').textContent = (walk.rx_mbps || walk.tx_mbps)
    ? `${walk.rx_mbps || '?'} / ${walk.tx_mbps || '?'} M`
    : '—';

  document.getElementById('walk-hdr-right').textContent = walk.running
    ? `● TRACKING (${(walk.samples || []).length} pts)`
    : ((walk.samples || []).length ? `Paused (${walk.samples.length} pts)` : 'Idle');

  if (currentView === 'wifi') {
    if (wifiTab === 'graph') renderWifiChanCanvas(wf);
    else if (wifiTab === 'walk') renderWifiWalkCanvas(walk);
  }
}

function renderWifiChanCanvas(wf) {
  const canvas = document.getElementById('wifi-chan-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const is24 = wifiGraphBand === '2.4 GHz';
  const is6 = wifiGraphBand === '6 GHz';
  const aps = (wf.networks || []).filter(n => n.band === wifiGraphBand);
  document.getElementById('wifi-graph-hdr-left').textContent = `${wifiGraphBand} CHANNEL OVERLAP & DENSITY`;
  document.getElementById('wifi-graph-hdr-right').textContent = `${aps.length} APs Visible`;

  const padL = 46, padR = 16, padT = 18, padB = 26;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;
  const minDbm = -100, maxDbm = -30;

  const chMin = is24 ? -1 : (is6 ? -5 : 30);
  const chMax = is24 ? 15 : (is6 ? 240 : 171);
  const xForCh = (ch) => padL + ((ch - chMin) / (chMax - chMin)) * plotW;
  const yForDbm = (dbm) => padT + plotH - ((Math.max(minDbm, Math.min(maxDbm, dbm)) - minDbm) / (maxDbm - minDbm)) * plotH;

  // Highlight clean non-overlapping 2.4 GHz bands (1, 6, 11) subtly
  if (is24 && wf.best_24g_channel) {
    const bx = xForCh(wf.best_24g_channel);
    const bw = (xForCh(wf.best_24g_channel + 2) - xForCh(wf.best_24g_channel - 2));
    ctx.fillStyle = 'rgba(34, 197, 94, 0.08)';
    ctx.fillRect(bx - bw / 2, padT, bw, plotH);
  }

  // Horizontal dBm guide lines
  ctx.strokeStyle = '#252830';
  ctx.lineWidth = 1;
  ctx.font = '10px Consolas, monospace';
  ctx.fillStyle = '#71717a';
  [-40, -60, -80, -100].forEach(db => {
    const y = yForDbm(db);
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    ctx.fillText(`${db}dB`, 4, y + 3);
  });

  // Channel X-axis labels
  const ticks = is24
    ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    : (is6 ? [1, 33, 65, 97, 129, 161, 193, 229] : [36, 48, 52, 64, 100, 116, 132, 149, 165]);
  ctx.textAlign = 'center';
  ticks.forEach(ch => {
    const x = xForCh(ch);
    ctx.strokeStyle = '#1c1f26';
    ctx.beginPath();
    ctx.moveTo(x, padT);
    ctx.lineTo(x, padT + plotH);
    ctx.stroke();
    ctx.fillStyle = (is24 && ch === wf.best_24g_channel) ? '#4ade80' : '#8b909a';
    ctx.fillText(String(ch), x, h - 8);
  });
  ctx.textAlign = 'left';

  if (!aps.length) {
    ctx.fillStyle = '#71717a';
    ctx.font = '12px Segoe UI, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(`No ${wifiGraphBand} APs detected — tap RE-SCAN`, w / 2, h / 2);
    ctx.textAlign = 'left';
    return;
  }

  const baseY = yForDbm(minDbm);
  aps.forEach((ap, idx) => {
    const col = WIFI_PALETTE[idx % WIFI_PALETTE.length];
    const halfSpan = is24
      ? (ap.width_mhz >= 40 ? 4.0 : 2.0)
      : (ap.width_mhz >= 160 ? 15.0 : (ap.width_mhz >= 80 ? 7.5 : (ap.width_mhz >= 40 ? 3.8 : 2.0)));
    const cx = ap.center_channel || ap.channel;
    const xL = xForCh(cx - halfSpan);
    const xTL = xForCh(cx - halfSpan * 0.52);
    const xTR = xForCh(cx + halfSpan * 0.52);
    const xR = xForCh(cx + halfSpan);
    const yPeak = yForDbm(ap.signal_dbm);

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(xL, baseY);
    ctx.quadraticCurveTo(xL + (xTL - xL) * 0.25, yPeak, xTL, yPeak);
    ctx.lineTo(xTR, yPeak);
    ctx.quadraticCurveTo(xR - (xR - xTR) * 0.25, yPeak, xR, baseY);
    ctx.closePath();

    ctx.globalAlpha = ap.associated ? 0.28 : 0.14;
    ctx.fillStyle = col;
    ctx.fill();

    ctx.globalAlpha = ap.associated ? 1.0 : 0.85;
    ctx.strokeStyle = ap.associated ? '#ffffff' : col;
    ctx.lineWidth = ap.associated ? 2.4 : 1.7;
    ctx.stroke();

    // Label top APs cleanly without vertical crowding
    if (idx < 7) {
      ctx.globalAlpha = 1.0;
      ctx.fillStyle = ap.associated ? '#4ade80' : col;
      ctx.font = 'bold 10px Consolas, monospace';
      ctx.textAlign = 'center';
      const shortSsid = ap.ssid.length > 14 ? ap.ssid.slice(0, 13) + '…' : ap.ssid;
      ctx.fillText(`${shortSsid} (${ap.signal_dbm})`, xForCh(cx), Math.max(padT + 10, yPeak - 4));
    }
    ctx.restore();
  });
}

function renderWifiWalkCanvas(walk) {
  const canvas = document.getElementById('wifi-walk-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const samples = (walk && walk.samples) || [];
  const padL = 46, padR = 16, padT = 14, padB = 22;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;
  const minDbm = -95, maxDbm = -30;
  const yForDbm = (dbm) => padT + plotH - ((Math.max(minDbm, Math.min(maxDbm, dbm)) - minDbm) / (maxDbm - minDbm)) * plotH;

  const zones = [
    { db: -50, col: '#16a34a', lbl: '-50 EXCELLENT' },
    { db: -67, col: '#ca8a04', lbl: '-67 GOOD' },
    { db: -80, col: '#dc2626', lbl: '-80 WEAK' }
  ];
  ctx.font = '9.5px Consolas, monospace';
  zones.forEach(z => {
    const y = yForDbm(z.db);
    ctx.strokeStyle = z.col;
    ctx.globalAlpha = 0.45;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.globalAlpha = 0.85;
    ctx.fillStyle = '#94a3b8';
    ctx.fillText(`${z.db}dB`, 4, y + 3);
    ctx.fillText(z.lbl, w - padR - 86, y - 3);
  });
  ctx.globalAlpha = 1.0;

  if (!samples.length) {
    ctx.fillStyle = '#64748b';
    ctx.font = '12px Segoe UI, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Tap ▶ START WALK and walk the floor to map dBm signal strength', w / 2, h / 2);
    ctx.textAlign = 'left';
    return;
  }

  const maxSlots = Math.max(samples.length, 60);
  const stepX = plotW / Math.max(1, maxSlots - 1);
  const offset = maxSlots - samples.length;

  ctx.strokeStyle = '#f59e0b';
  ctx.lineWidth = 2.2;
  ctx.beginPath();
  let drawing = false;
  samples.forEach((pt, i) => {
    const x = padL + (offset + i) * stepX;
    if (pt.signal_dbm === null || pt.signal_dbm === undefined) {
      drawing = false;
      return;
    }
    const y = yForDbm(pt.signal_dbm);
    if (!drawing) {
      ctx.moveTo(x, y);
      drawing = true;
    } else {
      ctx.lineTo(x, y);
    }
  });
  ctx.stroke();

  samples.forEach((pt, i) => {
    const x = padL + (offset + i) * stepX;
    if (pt.signal_dbm === null || pt.signal_dbm === undefined) {
      ctx.strokeStyle = '#ef4444';
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.moveTo(x, padT);
      ctx.lineTo(x, padT + plotH);
      ctx.stroke();
    } else {
      const y = yForDbm(pt.signal_dbm);
      ctx.fillStyle = signalColor(pt.signal_dbm);
      ctx.beginPath();
      ctx.arc(x, y, 2.8, 0, Math.PI * 2);
      ctx.fill();
    }
  });
}

// On-Screen Touch Keyboard & Numpad Modal (+ Physical Keyboard Support)
let kbShowVirtualKeys = (() => {
  try {
    const stored = localStorage.getItem('jacktrace_kb_virtual');
    if (stored === '0' || stored === '1') return stored === '1';
  } catch (_) {}
  return !document.body.classList.contains('app-mode');
})();

function applyKbVirtualKeysState() {
  const modal = document.getElementById('kb-modal');
  const toggleBtn = document.getElementById('btn-kb-keys-toggle');
  const hint = document.getElementById('kb-hw-hint');
  if (modal) modal.classList.toggle('kb-compact', !kbShowVirtualKeys);
  if (toggleBtn) toggleBtn.textContent = kbShowVirtualKeys ? 'Hide Keys' : 'Show Keys';
  if (hint) hint.classList.toggle('hidden', kbShowVirtualKeys);
}

function toggleKbVirtualKeys() {
  kbShowVirtualKeys = !kbShowVirtualKeys;
  try {
    localStorage.setItem('jacktrace_kb_virtual', kbShowVirtualKeys ? '1' : '0');
  } catch (_) {}
  applyKbVirtualKeysState();
}

function openTouchKeyboard({ title, initialValue, mode, secret, onDone }) {
  kbValue = String(initialValue ?? '');
  kbMode = mode === 'ip' ? 'ip' : 'text';
  kbShift = false;
  kbSymbols = false;
  kbSecret = Boolean(secret);
  kbReveal = false;
  kbCallback = onDone;
  document.getElementById('kb-title').textContent = title || 'TOUCH INPUT';
  const eyeBtn = document.getElementById('btn-kb-eye');
  if (eyeBtn) {
    eyeBtn.classList.toggle('hidden', !kbSecret);
    eyeBtn.textContent = '👁 Show';
  }
  document.getElementById('kb-modal').classList.remove('hidden');
  applyKbVirtualKeysState();
  renderTouchKeyboard();
}

function isTouchKeyboardOpen() {
  const m = document.getElementById('kb-modal');
  return Boolean(m && !m.classList.contains('hidden'));
}

document.addEventListener('keydown', (ev) => {
  if (!isTouchKeyboardOpen()) return;
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
  if (ev.key === 'Enter') {
    ev.preventDefault();
    kbSubmit();
  } else if (ev.key === 'Escape') {
    ev.preventDefault();
    closeTouchKeyboard();
  } else if (ev.key === 'Backspace') {
    ev.preventDefault();
    kbBackspace();
  } else if (ev.key === 'Delete') {
    ev.preventDefault();
    kbClear();
  } else if (ev.key.length === 1) {
    ev.preventDefault();
    kbType(ev.key);
  }
});

document.addEventListener('paste', (ev) => {
  if (!isTouchKeyboardOpen()) return;
  const txt = ev.clipboardData ? ev.clipboardData.getData('text') : '';
  if (txt) {
    ev.preventDefault();
    kbValue += txt.replace(/[\r\n]+/g, '');
    renderKbDisplay();
  }
});

function closeTouchKeyboard() {
  document.getElementById('kb-modal').classList.add('hidden');
  kbSecret = false;
  kbReveal = false;
  kbCallback = null;
}

function toggleKbLayoutMode() {
  kbMode = kbMode === 'ip' ? 'text' : 'ip';
  kbSymbols = false;
  renderTouchKeyboard();
}

function kbToggleSymbols() {
  kbSymbols = !kbSymbols;
  kbShift = false;
  renderTouchKeyboard();
}

function kbToggleReveal() {
  kbReveal = !kbReveal;
  const eyeBtn = document.getElementById('btn-kb-eye');
  if (eyeBtn) eyeBtn.textContent = kbReveal ? '🙈 Hide' : '👁 Show';
  renderKbDisplay();
}

function kbType(ch) {
  kbValue += ch;
  renderKbDisplay();
}

function kbTypeIdx(idx) {
  if (idx >= 0 && idx < kbKeyChars.length) {
    kbValue += kbKeyChars[idx];
    renderKbDisplay();
  }
}

function kbBackspace() {
  kbValue = kbValue.slice(0, -1);
  renderKbDisplay();
}

function kbClear() {
  kbValue = '';
  renderKbDisplay();
}

function kbToggleShift() {
  kbShift = !kbShift;
  renderTouchKeyboard();
}

function kbSubmit() {
  const cb = kbCallback;
  const out = kbValue;
  closeTouchKeyboard();
  if (cb) cb(out);
}

function renderKbDisplay() {
  const shown = (kbSecret && !kbReveal) ? '•'.repeat(kbValue.length) : kbValue;
  document.getElementById('kb-display').innerHTML = `${esc(shown)}<span class="kb-cursor"></span>`;
}

function renderTouchKeyboard() {
  renderKbDisplay();
  document.getElementById('btn-kb-mode').textContent = kbMode === 'ip' ? 'Mode: 123 IP' : (kbSymbols ? 'Mode: !@# SYM' : 'Mode: QWERTY');
  const container = document.getElementById('kb-keys');

  if (kbMode === 'ip') {
    const keys = [
      { lbl: '1', fn: "kbType('1')" },
      { lbl: '2', fn: "kbType('2')" },
      { lbl: '3', fn: "kbType('3')" },
      { lbl: '-', fn: "kbType('-')" },
      { lbl: '4', fn: "kbType('4')" },
      { lbl: '5', fn: "kbType('5')" },
      { lbl: '6', fn: "kbType('6')" },
      { lbl: ':', fn: "kbType(':')" },
      { lbl: '7', fn: "kbType('7')" },
      { lbl: '8', fn: "kbType('8')" },
      { lbl: '9', fn: "kbType('9')" },
      { lbl: 'ABC', cls: 'kb-key-alt', fn: 'toggleKbLayoutMode()' },
      { lbl: '.', fn: "kbType('.')" },
      { lbl: '0', fn: "kbType('0')" },
      { lbl: '⌫', cls: 'kb-key-alt', fn: 'kbBackspace()' },
      { lbl: '✓ DONE', cls: 'kb-key-alt', fn: 'kbSubmit()' }
    ];
    container.innerHTML = `<div class="kb-numpad">${
      keys.map(k => `<button class="kb-key ${k.cls || ''}" onclick="${k.fn}">${k.lbl}</button>`).join('')
    }</div>`;
    return;
  }

  kbKeyChars = [];
  const renderRow = (arr) => arr.map(ch => {
    const idx = kbKeyChars.push(ch) - 1;
    return `<button class="kb-key" onclick="kbTypeIdx(${idx})">${esc(ch)}</button>`;
  }).join('');

  if (kbSymbols) {
    const s1 = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')'];
    const s2 = ['-', '_', '=', '+', '[', ']', '{', '}', ';', ':'];
    const s3 = ["'", '"', ',', '.', '/', '?', '\\', '|', '~', '`'];
    const s4 = ['<', '>', '1', '2', '3', '4', '5', '6', '7', '8'];
    container.innerHTML = `
      <div class="kb-row">${renderRow(s1)}</div>
      <div class="kb-row">${renderRow(s2)}</div>
      <div class="kb-row">${renderRow(s3)}</div>
      <div class="kb-row">${renderRow(s4)}</div>
      <div class="kb-row">
        <button class="kb-key kb-key-alt" onclick="kbToggleSymbols()">ABC</button>
        <button class="kb-key kb-key-alt" onclick="kbClear()">CLR</button>
        <button class="kb-key kb-key-space" onclick="kbType(' ')">SPACE</button>
        <button class="kb-key kb-key-alt" onclick="kbBackspace()">⌫</button>
        <button class="kb-key kb-key-alt" style="background:#16a34a;color:#fff;" onclick="kbSubmit()">✓ DONE</button>
      </div>
    `;
    return;
  }

  const row1 = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'];
  const row2 = 'qwertyuiop'.split('').map(c => kbShift ? c.toUpperCase() : c);
  const row3 = [...'asdfghjkl'.split('').map(c => kbShift ? c.toUpperCase() : c), '-'];
  const row4Chars = [...'zxcvbnm'.split('').map(c => kbShift ? c.toUpperCase() : c), '_', '.', '/', ':'];

  container.innerHTML = `
    <div class="kb-row">${renderRow(row1)}</div>
    <div class="kb-row">${renderRow(row2)}</div>
    <div class="kb-row">${renderRow(row3)}</div>
    <div class="kb-row">
      <button class="kb-key kb-key-alt" style="${kbShift ? 'background:#f59e0b;color:#111214;' : ''}" onclick="kbToggleShift()">⇧</button>
      ${renderRow(row4Chars)}
    </div>
    <div class="kb-row">
      <button class="kb-key kb-key-alt" onclick="kbToggleSymbols()">!@#</button>
      <button class="kb-key kb-key-alt" onclick="kbClear()">CLR</button>
      <button class="kb-key kb-key-space" onclick="kbType(' ')">SPACE</button>
      <button class="kb-key kb-key-alt" onclick="kbBackspace()">⌫</button>
      <button class="kb-key kb-key-alt" style="background:#16a34a;color:#fff;" onclick="kbSubmit()">✓ DONE</button>
    </div>
  `;
}

// Legacy / Phase 1-3 Actions
function toggleBlink() {
  const mode = document.getElementById('sel-blink-mode').value;
  apiPost('/api/blink/toggle', { mode });
}

async function rescanPort() {
  const t = document.getElementById('btn-rescan-title');
  t.textContent = 'PROBING...';
  await apiPost('/api/rescan', {});
  setTimeout(() => { t.textContent = 'RE-SCAN'; }, 400);
}

function runTdrPulse() {
  apiPost('/api/tdr/run', {});
}

function runStress() {
  apiPost('/api/stress', { count: 20 });
}

function startSubnetScan() {
  scanPage = 0;
  apiPost('/api/scan/start', {});
}

function nextScanPage() {
  if (!latestSnap || !latestSnap.scan.hosts.length) return;
  const maxPage = Math.max(0, Math.ceil(latestSnap.scan.hosts.length / SCAN_PAGE_SIZE) - 1);
  scanPage = (scanPage + 1) > maxPage ? 0 : (scanPage + 1);
  renderScanView(latestSnap.scan);
}

function probeSecurity() {
  apiPost('/api/security/probe', {});
}

async function quickSavePort() {
  const saved = await apiPost('/api/audit/save', {});
  if (saved && saved.drop_label) {
    const liveSave = document.getElementById('live-btn-save');
    if (liveSave) {
      liveSave.dataset.toast = '1';
      liveSave.textContent = `✓ SAVED ${saved.drop_label}`;
      setTimeout(() => {
        delete liveSave.dataset.toast;
        if (latestSnap && latestSnap.audit) liveSave.textContent = `💾 LOG ${latestSnap.audit.next_drop_label}`;
      }, 1800);
    }
    const swSave = document.getElementById('sw-save-title');
    if (swSave) {
      swSave.textContent = `✓ ${saved.drop_label}`;
      setTimeout(() => {
        if (latestSnap && latestSnap.audit) swSave.textContent = `SAVE ${latestSnap.audit.next_drop_label}`;
      }, 1800);
    }
  }
  const snapRes = await fetch('/api/snapshot');
  if (snapRes.ok) renderSnapshot(await snapRes.json());
}

async function deleteSavedPort(rowId) {
  const res = await fetch(`/api/audit/port/${rowId}`, { method: 'DELETE' });
  if (res.ok) renderSnapshot(await res.json());
}

// ==========================================
// MILESTONE 3 ACTIONS: VLAN, SNMP, HOST, MULTI-JOB
// ==========================================

function setSwTab(tab) {
  swTab = tab;
  ['panel', 'vlan', 'snmp'].forEach(t => {
    document.getElementById('swtab-' + t).classList.toggle('active', t === tab);
    document.getElementById('sw-pane-' + t).classList.toggle('hidden', t !== tab);
  });
  const panelCmds = document.getElementById('sw-panel-cmds');
  if (panelCmds) panelCmds.classList.toggle('hidden', tab !== 'panel');
}

function setSecTab(tab) {
  secTab = ['grade', 'forensics', 'pcap'].includes(tab) ? tab : 'grade';
  ['grade', 'forensics', 'pcap'].forEach(t => {
    document.getElementById('sectab-' + t).classList.toggle('active', t === secTab);
    document.getElementById('sec-pane-' + t).classList.toggle('hidden', t !== secTab);
  });
  if (secTab === 'pcap') refreshNicsNow();
}

function openAddVlanPreset() {
  openTouchKeyboard({
    title: 'Add 802.1Q VLAN ID (1–4094)',
    initialValue: '',
    mode: 'ip',
    onDone: (val) => {
      const vid = parseInt(val.trim(), 10);
      if (!vid || vid < 1 || vid > 4094 || !latestSnap) return;
      const cur = (latestSnap.vlan_probe && latestSnap.vlan_probe.preset_vlans) || [10, 20, 30, 50, 99, 100, 200];
      const next = cur.includes(vid) ? cur : [...cur, vid];
      apiPost('/api/vlan/presets', { vlans: next });
    }
  });
}

function removeVlanPreset(vid) {
  if (!latestSnap || !latestSnap.vlan_probe) return;
  const cur = latestSnap.vlan_probe.preset_vlans || [];
  const next = cur.filter(x => x !== vid);
  if (!next.length) return;
  apiPost('/api/vlan/presets', { vlans: next });
}

function runVlanProbeNow() {
  apiPost('/api/vlan/probe', {});
}

function editSnmpTarget() {
  const curIp = customSnmpTarget || (latestSnap && latestSnap.switch && latestSnap.switch.mgmt_ip !== '—' ? latestSnap.switch.mgmt_ip : '192.168.0.254');
  openTouchKeyboard({
    title: 'Switch SNMPv2c Target IP',
    initialValue: curIp,
    mode: 'ip',
    onDone: (val) => {
      customSnmpTarget = val.trim();
      if (latestSnap) renderSnmpPane(latestSnap);
    }
  });
}

function editSnmpCommunity() {
  const curComm = (latestSnap && latestSnap.snmp && latestSnap.snmp.community) || 'public';
  openTouchKeyboard({
    title: 'SNMPv2c Read Community String',
    initialValue: curComm,
    mode: 'text',
    onDone: (val) => {
      const cleaned = val.trim() || 'public';
      const tgt = customSnmpTarget || (latestSnap && latestSnap.switch && latestSnap.switch.mgmt_ip !== '—' ? latestSnap.switch.mgmt_ip : '');
      apiPost('/api/snmp/query', { target_ip: tgt || null, community: cleaned });
    }
  });
}

function querySnmpNow() {
  const comm = (latestSnap && latestSnap.snmp && latestSnap.snmp.community) || 'public';
  const tgt = customSnmpTarget || (latestSnap && latestSnap.switch && latestSnap.switch.mgmt_ip !== '—' ? latestSnap.switch.mgmt_ip : '');
  apiPost('/api/snmp/query', { target_ip: tgt || null, community: comm });
}

async function openHostModal(ip) {
  document.getElementById('host-modal').classList.remove('hidden');
  document.getElementById('hm-title').textContent = `🔍 HOST DEEP DIVE • ${ip}`;
  document.getElementById('hm-host').textContent = 'Scanning ports...';
  document.getElementById('hm-mac').textContent = '—';
  document.getElementById('hm-vendor').textContent = '—';
  document.getElementById('hm-role').textContent = 'Probing 17 TCP ports...';
  document.getElementById('hm-ports').innerHTML = '';
  document.getElementById('hm-http').textContent = '—';
  document.getElementById('hm-mdns').textContent = '—';

  const res = await apiPost('/api/host/inspect', { ip });
  if (!res) return;
  activeHostInspect = res;
  document.getElementById('hm-title').textContent = `🔍 HOST DEEP DIVE • ${res.ip}`;
  document.getElementById('hm-host').textContent = res.hostname || '—';
  document.getElementById('hm-mac').textContent = res.mac || '—';
  document.getElementById('hm-vendor').textContent = res.vendor || 'Unknown';
  const rttTxt = res.rtt_ms !== null && res.rtt_ms !== undefined ? ` (${res.rtt_ms}ms)` : '';
  document.getElementById('hm-role').textContent = `${res.role || 'Host'}${rttTxt}`;

  const svcs = res.port_services || [];
  document.getElementById('hm-ports').innerHTML = svcs.length
    ? svcs.map(p => `<span class="target-chip active">${esc(p)}</span>`).join('')
    : '<span class="k" style="font-size:11px;">No common TCP services open</span>';
  document.getElementById('hm-http').textContent = res.http_title || 'No HTTP title';
  document.getElementById('hm-mdns').textContent = (res.mdns_services && res.mdns_services.length)
    ? res.mdns_services.join(' • ')
    : 'None';

  const btnWol = document.getElementById('hm-btn-wol');
  const hasMac = Boolean(res.mac && res.mac !== '—');
  btnWol.disabled = !hasMac;
  btnWol.textContent = '⚡ Wake-on-LAN';
}

function closeHostModal() {
  document.getElementById('host-modal').classList.add('hidden');
}

function rescanHostModal() {
  if (activeHostInspect && activeHostInspect.ip) openHostModal(activeHostInspect.ip);
}

async function sendHostWol() {
  if (!activeHostInspect || !activeHostInspect.mac || activeHostInspect.mac === '—') return;
  const res = await apiPost('/api/host/wol', { ip: activeHostInspect.ip, mac: activeHostInspect.mac });
  const btn = document.getElementById('hm-btn-wol');
  btn.textContent = (res && res.ok) ? '✓ Magic Pkt Sent!' : 'WoL Failed';
}

function pingHostFromModal() {
  if (!activeHostInspect || !activeHostInspect.ip) return;
  const ip = activeHostInspect.ip;
  closeHostModal();
  customPingTarget = ip;
  selectedPingTarget = 'custom';
  nav('diag');
  setDiagTab('ping');
  apiPost('/api/diag/ping/start', { target: ip });
}

function traceHostFromModal() {
  if (!activeHostInspect || !activeHostInspect.ip) return;
  const ip = activeHostInspect.ip;
  closeHostModal();
  customTraceTarget = ip;
  selectedTraceTarget = 'custom';
  nav('diag');
  setDiagTab('trace');
  apiPost('/api/diag/traceroute', { target: ip });
}

function switchAuditJob() {
  const sel = document.getElementById('sel-audit-job');
  if (sel && sel.value) {
    apiPost('/api/audit/job/switch', { job_name: sel.value });
  }
}

function openRenameJobKeyboard() {
  const curName = (latestSnap && latestSnap.audit && latestSnap.audit.job_name) || 'West Wing Audit';
  openTouchKeyboard({
    title: 'Rename Active Audit Job',
    initialValue: curName,
    mode: 'text',
    onDone: (val) => {
      const cleaned = val.trim() || 'Site Audit';
      apiPost('/api/audit/job', { job_name: cleaned, clear_ports: false });
    }
  });
}

function openNewJobKeyboard() {
  openTouchKeyboard({
    title: 'Create New Audit Job Name',
    initialValue: 'Floor 2 Audit',
    mode: 'text',
    onDone: (val) => {
      const cleaned = val.trim();
      if (cleaned) apiPost('/api/audit/job/switch', { job_name: cleaned });
    }
  });
}

async function deleteActiveAuditJob() {
  if (!latestSnap || !latestSnap.audit) return;
  const cur = latestSnap.audit.job_name;
  if (!confirm(`Delete job "${cur}" and all its logged drops?`)) return;
  const res = await fetch(`/api/audit/job/${encodeURIComponent(cur)}`, { method: 'DELETE' });
  if (res.ok) renderSnapshot(await res.json());
}

function setDropPrefix(pref) {
  apiPost('/api/audit/prefix', { prefix: pref });
}

function editPortNotes(rowId, dropLbl, existingNotes) {
  openTouchKeyboard({
    title: `Notes for ${dropLbl}`,
    initialValue: existingNotes || '',
    mode: 'text',
    onDone: (val) => {
      apiPost(`/api/audit/port/${rowId}/notes`, { notes: val.trim() });
    }
  });
}

function setOrientation(flipped) {
  apiPost('/api/system/orientation', { flipped: Boolean(flipped) });
}

function clearAuditJob() {
  const name = (latestSnap && latestSnap.audit && latestSnap.audit.job_name) || 'Site Audit';
  if (!confirm(`Clear all saved drops in "${name}" and reset counter to -01?`)) return;
  apiPost('/api/audit/job', { job_name: name, next_drop: 1, clear_ports: true });
}

function startPcap(durationSec = 15.0) {
  apiPost('/api/audit/pcap/start', { duration_sec: Number(durationSec) || 15.0 });
}

let pdfActiveTab = 'sheet';

function renderPdfTouchSheet() {
  const box = document.getElementById('pdf-sheet-body');
  if (!box || !latestSnap) return;
  const audit = latestSnap.audit || {};
  const sec = latestSnap.security || {};
  const scan = latestSnap.scan || {};
  const ports = (audit.recent_ports || []).slice().reverse();

  document.getElementById('pdf-modal-title').textContent = `AUDIT REPORT • ${audit.job_name || 'Site Audit'}`;

  const rowsHtml = ports.length
    ? ports.map(r => {
        const ok = r.verdict === 'PASS';
        const badgeCol = ok ? 'background:#132a1d;color:#4ade80' : 'background:#3b131a;color:#fda4af';
        const swPort = r.port_id && r.port_id !== '—' ? `${r.switch_name} • ${r.port_id}` : r.switch_name;
        return `<tr>
          <td style="font-weight:800;color:#fff">${esc(r.drop_label)}</td>
          <td>${esc(swPort)}</td>
          <td style="color:#fbbf24">${esc(r.vlan_summary)} • ${esc(r.poe_summary)}</td>
          <td>${esc(r.tdr_summary || '—')}</td>
          <td>${esc(r.speed_summary)}</td>
          <td><span style="padding:1px 5px;border-radius:3px;font-weight:700;font-size:9.5px;${badgeCol}">${esc(r.verdict)}</span></td>
        </tr>`;
      }).join('')
    : `<tr><td colspan="6" style="text-align:center;color:#71717a;padding:24px;">No wall ports saved yet. Tap ◄ BACK and save a port (e.g. ${esc(audit.next_drop_label || 'W-01')}) to populate the report.</td></tr>`;

  box.innerHTML = `
    <div class="pdf-summary-strip">
      <div class="pdf-stat-box">
        <div class="pdf-stat-lbl">Logged Drops</div>
        <div class="pdf-stat-val">${audit.total_saved || 0} (${audit.pass_count || 0} Pass / ${audit.warn_fail_count || 0} Warn)</div>
      </div>
      <div class="pdf-stat-box">
        <div class="pdf-stat-lbl">Security Grade</div>
        <div class="pdf-stat-val">${esc(sec.grade || '—')} (${sec.score ?? 0}/100)</div>
      </div>
      <div class="pdf-stat-box">
        <div class="pdf-stat-lbl">Subnet Hosts</div>
        <div class="pdf-stat-val">${scan.active_count || 0} • ${esc(scan.subnet || '—')}</div>
      </div>
      <div class="pdf-stat-box">
        <div class="pdf-stat-lbl">Phone PDF URL</div>
        <div class="pdf-stat-val" style="color:#fbbf24">${esc(audit.portal_url || '—')}</div>
      </div>
    </div>
    <table class="data-table compact-table">
      <thead>
        <tr>
          <th>DROP</th>
          <th>SWITCH / PORT</th>
          <th>VLAN / PoE</th>
          <th>TDR / CABLE</th>
          <th>SPEED</th>
          <th>VERDICT</th>
        </tr>
      </thead>
      <tbody>${rowsHtml}</tbody>
    </table>
  `;
}

function setPdfTab(tab) {
  pdfActiveTab = tab;
  const isSheet = tab === 'sheet';
  document.getElementById('btn-pdf-tab-sheet').classList.toggle('active', isSheet);
  document.getElementById('btn-pdf-tab-raw').classList.toggle('active', !isSheet);
  document.getElementById('pdf-sheet-body').classList.toggle('hidden', !isSheet);
  const iframe = document.getElementById('pdf-iframe');
  iframe.classList.toggle('hidden', isSheet);
  if (isSheet) {
    iframe.src = 'about:blank';
    renderPdfTouchSheet();
  } else {
    iframe.src = `/api/audit/report.pdf?t=${Date.now()}#toolbar=0&navpanes=0&view=FitH`;
  }
}

function openPdfReport() {
  const modal = document.getElementById('pdf-modal');
  modal.classList.remove('hidden');
  const preferSheet = document.body.classList.contains('kiosk-mode') || window.innerWidth <= 820;
  setPdfTab(preferSheet ? 'sheet' : 'raw');
}

function closePdfReport() {
  document.getElementById('pdf-modal').classList.add('hidden');
  const iframe = document.getElementById('pdf-iframe');
  if (iframe) iframe.src = 'about:blank';
}

function toggleHotspot() {
  if (!latestSnap) return;
  const enable = !latestSnap.audit.wifi_ap_active;
  if (enable) {
    const ok = confirm(
      'Switch wlan0 from client Wi-Fi into standalone Field Hotspot (SSID: JackTrace-AP / Pass: jacktrace)?\n\nNote: If you are currently viewing this page over home/office Wi-Fi, your browser will disconnect until you join JackTrace-AP.'
    );
    if (!ok) return;
  }
  apiPost('/api/audit/hotspot', { enable });
}

function toggleSysModal() {
  const m = document.getElementById('sys-modal');
  m.classList.toggle('hidden');
  if (!m.classList.contains('hidden')) {
    if (sysTab === 'nics') refreshNicsNow();
    else if (sysTab === 'wifi') refreshWifiClientNow();
  }
}

function setSysTab(tab) {
  sysTab = ['general', 'wifi', 'netcal', 'nics', 'remote'].includes(tab) ? tab : 'general';
  ['general', 'wifi', 'netcal', 'nics', 'remote'].forEach(t => {
    const btn = document.getElementById('systab-' + t);
    const pane = document.getElementById('sys-pane-' + t);
    if (btn) btn.classList.toggle('active', t === sysTab);
    if (pane) pane.classList.toggle('hidden', t !== sysTab);
  });
  if (sysTab === 'nics') refreshNicsNow();
  else if (sysTab === 'wifi') refreshWifiClientNow();
}

function renderSysNetCalPane(s) {
  const sip = s.static_ip || {};
  const d1x = s.dot1x || {};
  const tdr = s.tdr || {};

  const sipIface = document.getElementById('sip-iface-lbl');
  if (!sipIface) return;
  sipIface.textContent = (s.link && s.link.iface) || sip.iface || 'eth0';

  const sipBadge = document.getElementById('sip-mode-badge');
  sipBadge.textContent = sip.error ? 'ERROR' : (sip.mode === 'static' ? 'STATIC' : 'DHCP (Auto)');
  sipBadge.style.color = sip.error ? '#fda4af' : (sip.mode === 'static' ? '#fbbf24' : '#4ade80');

  if (sip.ip_cidr && !staticIpDraft._edited) {
    staticIpDraft.ip_cidr = sip.ip_cidr;
    staticIpDraft.gateway = sip.gateway || '';
    staticIpDraft.dns = sip.dns || '';
  }
  document.getElementById('sip-cidr').textContent = staticIpDraft.ip_cidr || '192.168.0.50/24';
  document.getElementById('sip-gwdns').textContent = `${staticIpDraft.gateway || 'No GW'} · ${staticIpDraft.dns || 'No DNS'}`;

  const cType = tdr.cable_type || 'Cat5e (69%)';
  const nvp = tdr.nvp_pct || 69.0;
  document.getElementById('nvp-active-lbl').textContent = `${cType}`;
  document.getElementById('btn-nvp-cat5e').classList.toggle('active', Math.abs(nvp - 69.0) < 0.2);
  document.getElementById('btn-nvp-cat6').classList.toggle('active', Math.abs(nvp - 72.0) < 0.2);
  document.getElementById('btn-nvp-cat6a').classList.toggle('active', Math.abs(nvp - 76.0) < 0.2);

  const d1xBadge = document.getElementById('d1x-status-badge');
  d1xBadge.textContent = d1x.status || 'Idle';
  d1xBadge.style.color = d1x.status === 'Authenticated' ? '#4ade80' : (d1x.status === 'Failed' ? '#fda4af' : '#38bdf8');
  document.getElementById('d1x-id-lbl').textContent = dot1xDraft.identity || d1x.identity || 'Not set';
  document.getElementById('d1x-pw-lbl').textContent = dot1xDraft.password ? '••••••••' : (d1x.has_password ? 'Set' : 'Not set');
  document.getElementById('d1x-detail-lbl').textContent = d1x.detail || 'Ready';
}

function editStaticIpCidr() {
  openTouchKeyboard({
    title: 'Wired Static IPv4/CIDR (e.g. 192.168.0.50/24)',
    initialValue: staticIpDraft.ip_cidr || '192.168.0.50/24',
    mode: 'ip',
    onDone: (val) => {
      staticIpDraft.ip_cidr = val.trim();
      staticIpDraft._edited = true;
      if (latestSnap) renderSysNetCalPane(latestSnap);
    }
  });
}

function editStaticGw() {
  openTouchKeyboard({
    title: 'Optional Gateway IPv4',
    initialValue: staticIpDraft.gateway || '192.168.0.1',
    mode: 'ip',
    onDone: (val) => {
      staticIpDraft.gateway = val.trim();
      staticIpDraft._edited = true;
      if (latestSnap) renderSysNetCalPane(latestSnap);
    }
  });
}

function editStaticDns() {
  openTouchKeyboard({
    title: 'Optional DNS IPv4',
    initialValue: staticIpDraft.dns || '1.1.1.1',
    mode: 'ip',
    onDone: (val) => {
      staticIpDraft.dns = val.trim();
      staticIpDraft._edited = true;
      if (latestSnap) renderSysNetCalPane(latestSnap);
    }
  });
}

async function applyStaticIpNow() {
  const res = await fetch('/api/net/ipv4/static', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ip_cidr: staticIpDraft.ip_cidr,
      gateway: staticIpDraft.gateway,
      dns: staticIpDraft.dns
    })
  });
  if (res.ok) {
    staticIpDraft._edited = false;
    renderSnapshot(await res.json());
  } else {
    const err = await res.json().catch(() => ({}));
    document.getElementById('sip-mode-badge').textContent = err.detail || 'Invalid IP';
    document.getElementById('sip-mode-badge').style.color = '#fda4af';
  }
}

function revertDhcpNow() {
  staticIpDraft._edited = false;
  apiPost('/api/net/ipv4/dhcp', {});
}

function setTdrPreset(preset) {
  apiPost('/api/tdr/calibration', { preset });
}

function openCustomNvp() {
  const cur = (latestSnap && latestSnap.tdr && latestSnap.tdr.nvp_pct) || 69;
  openTouchKeyboard({
    title: 'Cable NVP Percentage (55–85%)',
    initialValue: String(cur),
    mode: 'ip',
    onDone: (val) => {
      const num = parseFloat(val.trim());
      if (num >= 55 && num <= 85) apiPost('/api/tdr/calibration', { nvp_pct: num });
    }
  });
}

function editDot1xIdentity() {
  openTouchKeyboard({
    title: '802.1X EAP-PEAP Username / Identity',
    initialValue: dot1xDraft.identity || '',
    mode: 'text',
    onDone: (val) => {
      dot1xDraft.identity = val.trim();
      if (latestSnap) renderSysNetCalPane(latestSnap);
    }
  });
}

function editDot1xPassword() {
  openTouchKeyboard({
    title: '802.1X EAP-PEAP Password',
    initialValue: '',
    mode: 'text',
    secret: true,
    onDone: (val) => {
      dot1xDraft.password = val;
      if (latestSnap) renderSysNetCalPane(latestSnap);
    }
  });
}

async function startDot1xNow() {
  if (!dot1xDraft.identity || !dot1xDraft.password) {
    document.getElementById('d1x-detail-lbl').textContent = 'Enter Identity & Password first';
    return;
  }
  const res = await fetch('/api/dot1x/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identity: dot1xDraft.identity, password: dot1xDraft.password, method: 'PEAP' })
  });
  if (res.ok) {
    renderSnapshot(await res.json());
  } else {
    const err = await res.json().catch(() => ({}));
    document.getElementById('d1x-detail-lbl').textContent = err.detail || '802.1X start failed';
  }
}

function stopDot1xNow() {
  apiPost('/api/dot1x/stop', {});
}

function toggleOverlayFs() {
  const sys = (latestSnap && latestSnap.system) || {};
  const nextEnable = !(sys.overlayfs_active || sys.overlayfs_pending_enable);
  const msg = nextEnable
    ? 'Enable Read-Only Root (OverlayFS) on next reboot? OS & system config become immutable against SD power loss (data/ stays writable if separate).'
    : 'Disable Read-Only Root (OverlayFS) on next reboot?';
  if (!confirm(msg)) return;
  apiPost('/api/system/overlayfs', { enable: nextEnable });
}

function openSysWifiTab() {
  document.getElementById('sys-modal').classList.remove('hidden');
  setSysTab('wifi');
}

function renderWifiClientPane(wc) {
  const activeLbl = document.getElementById('wcli-active-lbl');
  if (!activeLbl) return;

  const busy = Boolean(wc.busy);
  const apOn = Boolean(wc.ap_mode_active);
  const sigTxt = (wc.signal_pct !== null && wc.signal_pct !== undefined) ? `${wc.signal_pct}%` : '—';

  if (apOn) {
    activeLbl.textContent = 'wlan0: Field AP (JackTrace-AP)';
    activeLbl.style.color = '#fcd34d';
    document.getElementById('wcli-active-sub').textContent = 'Hotspot active — joining a Wi-Fi SSID stops Field AP';
  } else if (wc.connected) {
    activeLbl.textContent = `Connected: ${wc.active_ssid || '—'}`;
    activeLbl.style.color = '#4ade80';
    document.getElementById('wcli-active-sub').textContent = `IPv4: ${wc.ipv4 || '—'} • Signal: ${sigTxt} • Profile: ${wc.active_profile || '—'}`;
  } else {
    activeLbl.textContent = 'wlan0: Disconnected';
    activeLbl.style.color = '#94a3b8';
    document.getElementById('wcli-active-sub').textContent = wc.available === false
      ? 'NetworkManager (nmcli) unavailable'
      : 'Select a Saved or Nearby network below to connect';
  }

  document.getElementById('wcli-ap-banner').classList.toggle('hidden', !apOn);
  const btnScan = document.getElementById('btn-wcli-scan');
  btnScan.textContent = busy ? '⏳ Busy...' : '🔍 Scan';
  btnScan.disabled = busy || wc.available === false;
  const btnDisc = document.getElementById('btn-wcli-disc');
  btnDisc.disabled = busy || !wc.connected;
  const btnAp = document.getElementById('btn-wcli-ap');
  if (btnAp) {
    btnAp.textContent = apOn ? '⏹ Stop AP' : '📡 Field AP';
    btnAp.classList.toggle('active', apOn);
    btnAp.disabled = busy;
  }

  const saved = wc.saved_profiles || [];
  wifiClientSavedRows = saved;
  const savedEl = document.getElementById('wcli-saved-list');
  if (!saved.length) {
    savedEl.innerHTML = `<div style="font-size:10.5px;color:#64748b;padding:8px 4px;">No saved Wi-Fi profiles on ${esc(wc.iface || 'wlan0')}.</div>`;
  } else {
    savedEl.innerHTML = saved.map((p, idx) => `
      <div class="wcli-row ${p.active ? 'selected' : ''}">
        <div style="min-width:0;flex:1;">
          <div style="font-size:11px;font-weight:800;color:${p.active ? '#4ade80' : '#f8fafc'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${p.active ? '● ' : ''}${esc(p.ssid)}</div>
          <div style="font-size:9px;color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(p.name)}</div>
        </div>
        <div style="display:flex;gap:4px;flex-shrink:0;">
          <button class="mini-btn ${p.active ? 'active' : ''}" ${busy || p.active ? 'disabled' : ''} onclick="joinClientSavedIdx(${idx})">${p.active ? 'Active' : 'Use'}</button>
          <button class="del-btn" ${busy ? 'disabled' : ''} onclick="forgetClientIdx(${idx})" title="Forget network">×</button>
        </div>
      </div>
    `).join('');
  }

  const avail = wc.available_networks || [];
  wifiClientAvailRows = avail;
  const availEl = document.getElementById('wcli-avail-list');
  if (!avail.length) {
    availEl.innerHTML = `<div style="font-size:10.5px;color:#64748b;padding:8px 4px;">${busy ? 'Scanning nearby 2.4 / 5 GHz SSIDs...' : 'Tap 🔍 Scan to search nearby Wi-Fi networks.'}</div>`;
  } else {
    availEl.innerHTML = avail.map((n, idx) => {
      const tag = n.saved ? ' • Saved' : '';
      return `<div class="wcli-row ${n.in_use ? 'selected' : ''}">
        <div style="min-width:0;flex:1;">
          <div style="font-size:11px;font-weight:800;color:${n.in_use ? '#4ade80' : '#f8fafc'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${n.in_use ? '● ' : ''}${esc(n.ssid)}</div>
          <div style="font-size:9px;color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(n.signal_pct)}% • ${esc(n.band)} • ${esc(n.security)}${tag}</div>
        </div>
        <button class="mini-btn ${n.in_use ? 'active' : ''}" ${busy || n.in_use ? 'disabled' : ''} onclick="joinClientAvailIdx(${idx})">${n.in_use ? 'Connected' : 'Join'}</button>
      </div>`;
    }).join('');
  }

  const stEl = document.getElementById('wcli-status');
  if (wc.error) {
    stEl.textContent = wc.error;
    stEl.style.color = '#fda4af';
  } else {
    const tsPart = wc.last_scan_at ? ` • Scanned ${wc.last_scan_at}` : '';
    stEl.textContent = `${wc.status || 'Ready'}${tsPart}`;
    stEl.style.color = '#94a3b8';
  }
}

async function refreshWifiClientNow() {
  try {
    const res = await fetch('/api/wifi/client/status');
    if (res.ok) {
      const wc = await res.json();
      if (latestSnap) latestSnap.wifi_client = wc;
      renderWifiClientPane(wc);
    }
  } catch (_) {}
}

function scanWifiClientNow() {
  apiPost('/api/wifi/client/scan', {});
}

function _confirmWifiLeaveOrConnect(ssid, fn) {
  const wc = (latestSnap && latestSnap.wifi_client) || {};
  const isRemoteBrowser = window.location.hostname && !['localhost', '127.0.0.1'].includes(window.location.hostname);
  if (wc.ap_mode_active && isRemoteBrowser) {
    if (!confirm(`Joining "${ssid}" will disable Field AP (JackTrace-AP) and switch wlan0 to client Wi-Fi. Continue?`)) return;
  }
  fn();
}

function joinClientSavedIdx(idx) {
  const p = wifiClientSavedRows[idx];
  if (!p) return;
  _confirmWifiLeaveOrConnect(p.ssid || p.name, () => {
    apiPost('/api/wifi/client/connect', { ssid: p.ssid || '', profile_name: p.name });
  });
}

function _promptJoinSsid(ssid, security, saved, profileName) {
  if (saved && profileName) {
    _confirmWifiLeaveOrConnect(ssid, () => {
      apiPost('/api/wifi/client/connect', { ssid, profile_name: profileName });
    });
    return;
  }
  if ((security || '').toLowerCase() === 'open') {
    _confirmWifiLeaveOrConnect(ssid, () => {
      apiPost('/api/wifi/client/connect', { ssid });
    });
    return;
  }
  openTouchKeyboard({
    title: `Wi-Fi Password • ${ssid}`,
    initialValue: '',
    mode: 'text',
    secret: true,
    onDone: (pw) => {
      _confirmWifiLeaveOrConnect(ssid, () => {
        apiPost('/api/wifi/client/connect', { ssid, password: pw });
      });
    }
  });
}

function joinClientAvailIdx(idx) {
  const n = wifiClientAvailRows[idx];
  if (!n) return;
  _promptJoinSsid(n.ssid, n.security, Boolean(n.saved), n.profile_name || '');
}

function joinSurveyWifiIdx(idx) {
  const n = wifiSurveyRows[idx];
  if (!n || !n.ssid || n.ssid === '<Hidden>') return;
  const saved = ((latestSnap && latestSnap.wifi_client && latestSnap.wifi_client.saved_profiles) || [])
    .find(p => p.ssid === n.ssid);
  _promptJoinSsid(n.ssid, n.security, Boolean(saved), saved ? saved.name : '');
}

function openHiddenWifiJoin() {
  openTouchKeyboard({
    title: 'Hidden Wi-Fi Network SSID',
    initialValue: '',
    mode: 'text',
    onDone: (rawSsid) => {
      const ssid = (rawSsid || '').trim();
      if (!ssid) return;
      openTouchKeyboard({
        title: `Password for "${ssid}" (CLR if Open)`,
        initialValue: '',
        mode: 'text',
        secret: true,
        onDone: (pw) => {
          _confirmWifiLeaveOrConnect(ssid, () => {
            apiPost('/api/wifi/client/connect', { ssid, password: pw || null, hidden: true });
          });
        }
      });
    }
  });
}

function disconnectWifiNow() {
  const wc = (latestSnap && latestSnap.wifi_client) || {};
  if (!wc.connected) return;
  if (!confirm(`Disconnect wlan0 from "${wc.active_ssid}"? If managing remotely over Wi-Fi, you will lose connection until reconnected on touchscreen.`)) return;
  apiPost('/api/wifi/client/disconnect', {});
}

function forgetClientIdx(idx) {
  const p = wifiClientSavedRows[idx];
  if (!p) return;
  if (!confirm(`Forget saved Wi-Fi network "${p.ssid || p.name}"?`)) return;
  apiPost('/api/wifi/client/forget', { uuid: p.uuid, name: p.name });
}

function setAuditTab(tab) {
  auditTab = tab;
  ['log', 'sync', 'printer'].forEach(t => {
    document.getElementById('atab-' + t).classList.toggle('active', t === tab);
    document.getElementById('audit-pane-' + t).classList.toggle('hidden', t !== tab);
  });
}

function renderSyncPane(sy) {
  const whBtn = document.getElementById('btn-wh-toggle');
  whBtn.textContent = sy.webhook_enabled ? 'ON' : 'OFF';
  whBtn.classList.toggle('active', Boolean(sy.webhook_enabled));
  document.getElementById('sync-wh-url').textContent = sy.webhook_url || 'Not set';
  document.getElementById('sync-wh-tok').textContent = sy.webhook_has_token ? 'Configured (Masked)' : 'None';

  const nbBtn = document.getElementById('btn-nb-toggle');
  nbBtn.textContent = sy.netbox_enabled ? 'ON' : 'OFF';
  nbBtn.classList.toggle('active', Boolean(sy.netbox_enabled));
  document.getElementById('sync-nb-url').textContent = sy.netbox_url || 'Not set';
  document.getElementById('sync-nb-tok').textContent = sy.netbox_has_token ? 'Configured (Masked)' : 'None';

  document.getElementById('sync-queue-summary').textContent =
    `OFFLINE RETRY QUEUE • ${sy.pending_count || 0} Pending • ${sy.sent_count || 0} Sent • ${sy.failed_count || 0} Failed`;

  const autoBtn = document.getElementById('btn-sync-auto');
  autoBtn.textContent = sy.auto_sync_on_save ? 'Auto-Sync: ON' : 'Auto-Sync: OFF';
  autoBtn.classList.toggle('active', Boolean(sy.auto_sync_on_save));
  document.getElementById('btn-sync-flush').textContent = sy.syncing ? '⏳ Syncing...' : '🔄 Flush';

  const rows = (sy.recent_queue || []).slice(0, 4);
  const tbody = document.getElementById('sync-queue-tbody');
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#64748b;padding:16px;">Sync queue is empty. Tap ☁️ Push Job or enable Auto-Sync on Save.</td></tr>';
  } else {
    tbody.innerHTML = rows.map(q => {
      const col = q.status === 'SENT' ? '#4ade80' : (q.status === 'FAILED' ? '#fda4af' : '#fcd34d');
      const det = q.last_error ? q.last_error : (q.status === 'SENT' ? 'Delivered' : 'Waiting retry');
      return `<tr>
        <td style="text-transform:uppercase;font-weight:700;">${esc(q.target)}</td>
        <td>${esc(q.drop_label)}</td>
        <td style="font-weight:800;color:${col}">${esc(q.status)}</td>
        <td style="color:#94a3b8">#${q.attempts} • ${esc(det)}</td>
      </tr>`;
    }).join('');
  }
  const tsSuffix = sy.last_sync_at ? ` (${sy.last_sync_at})` : '';
  document.getElementById('sync-last-status').textContent = `${sy.last_status || 'Ready'}${tsSuffix}`;
}

function editWebhookUrl() {
  const cur = (latestSnap && latestSnap.sync && latestSnap.sync.webhook_url) || 'http://192.168.0.';
  openTouchKeyboard({
    title: 'Webhook (JSON) Endpoint URL',
    initialValue: cur,
    mode: 'text',
    onDone: (val) => apiPost('/api/sync/config', { webhook_url: val.trim(), webhook_enabled: Boolean(val.trim()) })
  });
}

function editWebhookToken() {
  openTouchKeyboard({
    title: 'Webhook Bearer Token (Stored Masked)',
    initialValue: '',
    mode: 'text',
    onDone: (val) => {
      if (val.trim()) apiPost('/api/sync/config', { webhook_token: val.trim() });
    }
  });
}

function clearWebhookToken() {
  apiPost('/api/sync/config', { webhook_token: '' });
}

function toggleWebhookEnabled() {
  const cur = Boolean(latestSnap && latestSnap.sync && latestSnap.sync.webhook_enabled);
  apiPost('/api/sync/config', { webhook_enabled: !cur });
}

function editNetboxUrl() {
  const cur = (latestSnap && latestSnap.sync && latestSnap.sync.netbox_url) || 'http://192.168.0.';
  openTouchKeyboard({
    title: 'NetBox DCIM Base URL',
    initialValue: cur,
    mode: 'text',
    onDone: (val) => apiPost('/api/sync/config', { netbox_url: val.trim(), netbox_enabled: Boolean(val.trim()) })
  });
}

function editNetboxToken() {
  openTouchKeyboard({
    title: 'NetBox API Token (Stored Masked)',
    initialValue: '',
    mode: 'text',
    onDone: (val) => {
      if (val.trim()) apiPost('/api/sync/config', { netbox_token: val.trim() });
    }
  });
}

function clearNetboxToken() {
  apiPost('/api/sync/config', { netbox_token: '' });
}

function toggleNetboxEnabled() {
  const cur = Boolean(latestSnap && latestSnap.sync && latestSnap.sync.netbox_enabled);
  apiPost('/api/sync/config', { netbox_enabled: !cur });
}

function testNetboxNow() {
  apiPost('/api/sync/test-netbox', {});
}

function toggleAutoSync() {
  const cur = Boolean(latestSnap && latestSnap.sync && latestSnap.sync.auto_sync_on_save);
  apiPost('/api/sync/config', { auto_sync_on_save: !cur });
}

function pushJobToSync() {
  apiPost('/api/sync/push-job', {});
}

function flushSyncNow() {
  apiPost('/api/sync/flush', {});
}

function clearSyncQueueNow() {
  apiPost('/api/sync/queue/clear', { only_sent: false });
}

function renderPrinterPane(prt, audit) {
  document.getElementById('btn-prt-scan').textContent = prt.scanning ? '⏳ Scanning...' : '🔍 Scan BT';
  document.getElementById('prt-selected-lbl').textContent = prt.selected_mac
    ? `${prt.selected_name} (${prt.selected_mac} ch${prt.rfcomm_channel || 1})`
    : 'Not Paired';

  const devs = prt.devices || [];
  const listEl = document.getElementById('prt-dev-list');
  if (!devs.length) {
    listEl.innerHTML = '<div style="font-size:10.5px;color:#64748b;padding:8px 4px;">No Bluetooth printers listed yet. Tap 🔍 Scan BT or ✎ MAC.</div>';
  } else {
    listEl.innerHTML = devs.map(d => {
      const sel = d.mac && d.mac === prt.selected_mac;
      const badge = d.paired ? 'Paired' : 'Discovered';
      return `<div class="prt-row ${sel ? 'selected' : ''}">
        <div style="min-width:0;">
          <div style="font-size:11px;font-weight:800;color:#f8fafc;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(d.name)}</div>
          <div style="font-size:9.5px;color:#94a3b8;font-family:Consolas,monospace;">${esc(d.mac)} • ${badge}</div>
        </div>
        <button class="mini-btn ${sel ? 'active' : ''}" onclick="selectPrinterDevice('${esc(d.mac)}', '${esc(d.name)}')">${sel ? '✓ Active' : 'Pair / Use'}</button>
      </div>`;
    }).join('');
  }

  const hasSaved = Boolean(audit && audit.recent_ports && audit.recent_ports.length);
  document.getElementById('btn-prt-last').disabled = !hasSaved;
  document.getElementById('btn-prt-live').textContent = prt.printing ? '⏳ Printing...' : '🧾 Print Live Port';

  if (prt.last_preview) {
    document.getElementById('prt-preview').textContent = prt.last_preview;
  }
  const printTs = prt.last_print_at ? ` • ${prt.last_print_at}` : '';
  document.getElementById('prt-status').textContent = `${prt.last_status || 'Ready'}${printTs}`;
}

function scanPrintersNow() {
  apiPost('/api/printer/scan', {});
}

function selectPrinterDevice(mac, name) {
  apiPost('/api/printer/select', { mac, name, channel: 1 });
}

function openManualPrinterMac() {
  const cur = (latestSnap && latestSnap.printer && latestSnap.printer.selected_mac) || '00:11:22:33:44:55';
  openTouchKeyboard({
    title: 'Bluetooth Thermal Printer MAC (AA:BB:CC:DD:EE:FF)',
    initialValue: cur,
    mode: 'text',
    onDone: (val) => {
      const cleaned = val.trim().toUpperCase();
      if (cleaned) apiPost('/api/printer/select', { mac: cleaned, name: 'BT 58mm Printer', channel: 1 });
    }
  });
}

function printLiveReceiptNow() {
  apiPost('/api/printer/print-live', {});
}

function printSavedPort(rowId) {
  nav('audit');
  setAuditTab('printer');
  apiPost(`/api/printer/print-port/${rowId}`, {});
}

function printLastSavedDrop() {
  const rows = (latestSnap && latestSnap.audit && latestSnap.audit.recent_ports) || [];
  if (!rows.length) return;
  apiPost(`/api/printer/print-port/${rows[0].id}`, {});
}

function renderNicsPane(hw, link) {
  const nics = hw.nics || [];
  const tap = hw.tap || {};
  const listEl = document.getElementById('sys-nic-list');

  if (!nics.length) {
    listEl.innerHTML = '<div style="font-size:11px;color:#64748b;">No wired Ethernet NICs detected</div>';
  } else {
    listEl.innerHTML = nics.map(n => {
      const spd = n.carrier_up
        ? (n.speed_mbps >= 2500 ? `${(n.speed_mbps / 1000).toFixed(1)}GbE` : `${n.speed_mbps || '?'}M`)
        : 'Down';
      const usbTag = n.is_usb ? 'USB' : 'Onboard';
      const capTag = n.supports_2500 ? '2.5G Capable' : '1G';
      return `<div class="nic-row ${n.active ? 'selected' : ''}">
        <div style="min-width:0;">
          <div style="font-size:11.5px;font-weight:800;color:#f4f4f5;">${esc(n.iface)} • <span style="color:#fbbf24;">${spd}</span> (${usbTag} / ${esc(n.driver)} / ${capTag})</div>
          <div style="font-size:9.5px;color:#8b909a;font-family:Consolas,monospace;">MAC: ${esc(n.mac)} • State: ${esc(n.operstate)}</div>
        </div>
        <button class="mini-btn ${n.active ? 'active' : ''}" ${tap.active ? 'disabled' : ''} onclick="selectTestNic('${esc(n.iface)}')">${n.active ? '✓ Active' : 'Use Port'}</button>
      </div>`;
    }).join('');
  }

  const selA = document.getElementById('sel-tap-nica');
  const selB = document.getElementById('sel-tap-nicb');
  const selSecA = document.getElementById('sel-sec-tap-nica');
  const selSecB = document.getElementById('sel-sec-tap-nicb');

  const optsB = nics.length > 1 ? nics : [...nics, { iface: 'eth1' }];
  [selA, selSecA].forEach(el => {
    if (el && document.activeElement !== el) {
      const cur = el.value || tap.nic_a || (nics[0] ? nics[0].iface : 'eth0');
      el.innerHTML = nics.map(n => `<option value="${esc(n.iface)}" ${n.iface === cur ? 'selected' : ''}>${esc(n.iface)}</option>`).join('');
    }
  });
  [selB, selSecB].forEach(el => {
    if (el && document.activeElement !== el) {
      const defB = nics.length > 1 ? nics[1].iface : 'eth1';
      const cur = el.value || tap.nic_b || defB;
      el.innerHTML = optsB.map(n => `<option value="${esc(n.iface)}" ${n.iface === cur ? 'selected' : ''}>${esc(n.iface)}</option>`).join('');
    }
  });

  const pktTxt = tap.active
    ? `ACTIVE br0 (${tap.rx_packets || 0} RX / ${tap.tx_packets || 0} TX)`
    : 'Inactive';
  document.getElementById('tap-pkt-lbl').textContent = pktTxt;
  const secPkt = document.getElementById('sec-tap-pkt');
  if (secPkt) secPkt.textContent = pktTxt;

  let noteTxt = '';
  let noteCol = '#94a3b8';
  if (tap.error) {
    noteTxt = tap.error;
    noteCol = '#fcd34d';
  } else if (tap.active) {
    noteTxt = tap.status || `Bridging ${tap.nic_a} ⇄ br0 ⇄ ${tap.nic_b} (LLDP/802.1X passthrough)`;
    noteCol = '#4ade80';
  } else {
    noteTxt = nics.length < 2
      ? 'Only 1 Ethernet NIC detected — plug a USB Ethernet adapter to enable Dual-NIC Inline Tap'
      : 'Ready: bridges Wall Jack ⇄ Client transparently with net.ipv4.ip_forward=0';
  }

  const noteEl = document.getElementById('tap-status-note');
  noteEl.textContent = noteTxt;
  noteEl.style.color = noteCol;
  const secNote = document.getElementById('sec-tap-note');
  if (secNote) {
    secNote.textContent = noteTxt;
    secNote.style.color = noteCol;
  }

  const btnTap = document.getElementById('btn-tap-toggle');
  btnTap.textContent = tap.active ? '⏹ STOP INLINE TAP' : '🔀 ENABLE INLINE TAP';
  btnTap.classList.toggle('active', Boolean(tap.active));
  const btnSecTap = document.getElementById('btn-sec-tap-toggle');
  if (btnSecTap) {
    btnSecTap.textContent = tap.active ? '⏹ STOP INLINE TAP' : '🔀 ENABLE TAP';
    btnSecTap.classList.toggle('active', Boolean(tap.active));
  }
}

async function refreshNicsNow() {
  try {
    const res = await fetch('/api/nics/list');
    if (res.ok) {
      const hw = await res.json();
      if (latestSnap) {
        latestSnap.hw_nics = hw;
        renderNicsPane(hw, latestSnap.link || {});
      }
    }
  } catch (_) {}
}

function selectTestNic(iface) {
  apiPost('/api/nics/select', { iface });
}

function toggleInlineTap(source = 'sys') {
  const tapActive = Boolean(latestSnap && latestSnap.hw_nics && latestSnap.hw_nics.tap && latestSnap.hw_nics.tap.active);
  const idA = source === 'sec' ? 'sel-sec-tap-nica' : 'sel-tap-nica';
  const idB = source === 'sec' ? 'sel-sec-tap-nicb' : 'sel-tap-nicb';
  const nicA = (document.getElementById(idA) && document.getElementById(idA).value) || 'eth0';
  const nicB = (document.getElementById(idB) && document.getElementById(idB).value) || 'eth1';
  apiPost('/api/tap/toggle', { enable: !tapActive, nic_a: nicA, nic_b: nicB });
}

function openSysNicsTab() {
  document.getElementById('sys-modal').classList.remove('hidden');
  setSysTab('nics');
}

function openSysNetCalTab() {
  document.getElementById('sys-modal').classList.remove('hidden');
  setSysTab('netcal');
}

function openSysRemoteTab() {
  document.getElementById('sys-modal').classList.remove('hidden');
  setSysTab('remote');
}

function applyPentestTheme(enabled) {
  const wasActive = pentestUiActive;
  pentestUiActive = Boolean(enabled);
  document.body.classList.toggle('pentest-mode', pentestUiActive);
  const stdGroup = document.getElementById('rail-group-std');
  const ptGroup = document.getElementById('rail-group-pt');
  if (stdGroup) stdGroup.classList.toggle('hidden', pentestUiActive);
  if (ptGroup) ptGroup.classList.toggle('hidden', !pentestUiActive);

  const btnSysPt = document.getElementById('btn-sys-pentest');
  if (btnSysPt) {
    btnSysPt.classList.toggle('active', pentestUiActive);
    btnSysPt.textContent = pentestUiActive ? '🔴 Pentest: ON' : '🔴 Pentest: OFF';
  }

  if (wasActive && !pentestUiActive && currentView.startsWith('pt-')) {
    nav('home');
  } else if (currentView === 'audit') {
    nav('audit');
  }
}

function onModePillClick() {
  if (pentestUiActive) {
    setPentestMode(false, false);
  } else {
    const gate = document.getElementById('pentest-gate-modal');
    if (gate) gate.classList.remove('hidden');
  }
}

function closePentestGate() {
  const gate = document.getElementById('pentest-gate-modal');
  if (gate) gate.classList.add('hidden');
}

async function confirmEnterPentestMode() {
  closePentestGate();
  await setPentestMode(true, true);
}

async function setPentestMode(enable, authorizedAck = false) {
  const snap = await apiPost('/api/pentest/mode', { enable, authorized_ack: authorizedAck });
  if (snap) {
    const sysModal = document.getElementById('sys-modal');
    if (sysModal && !sysModal.classList.contains('hidden')) {
      sysModal.classList.add('hidden');
    }
    nav(enable ? 'pt-hub' : 'home');
  }
}

async function _tailcatPost(path, body = {}) {
  const errEl = document.getElementById('tc-error-lbl');
  if (errEl) {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  let payload = null;
  try { payload = await res.json(); } catch (_) {}
  if (res.ok && payload && payload.link) {
    renderSnapshot(payload);
    return payload;
  }
  const msg = (payload && payload.detail) ? payload.detail : `Request failed (HTTP ${res.status})`;
  if (errEl) {
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
  }
  return null;
}

function startTailcat(mode) {
  return _tailcatPost('/api/tailcat/start', { mode });
}

function stopTailcat() {
  return _tailcatPost('/api/tailcat/stop', {});
}

function pushTailcatWebhook() {
  return _tailcatPost('/api/tailcat/webhook', {});
}

async function launchTailcatPcapStream() {
  await startTailcat('pcap_stream');
  if (currentView !== 'pt-sniff') openSysRemoteTab();
}

function setPtSniffTab(tab) {
  ptSniffTab = ['exp', 'clear', 'stream'].includes(tab) ? tab : 'exp';
  ['exp', 'clear', 'stream'].forEach(t => {
    const btn = document.getElementById('ptsnifftab-' + t);
    const pane = document.getElementById('pt-sniff-pane-' + t);
    if (btn) btn.classList.toggle('active', t === ptSniffTab);
    if (pane) pane.classList.toggle('hidden', t !== ptSniffTab);
  });
}

function stopPcap() {
  return apiPost('/api/audit/pcap/stop', {});
}

function clearSnifferExposure() {
  return apiPost('/api/sniffer/clear-exposure', {});
}

function setPtReconTab(tab) {
  ptReconTab = ['findings', 'targets'].includes(tab) ? tab : 'findings';
  ['findings', 'targets'].forEach(t => {
    const btn = document.getElementById('ptrecontab-' + t);
    const pane = document.getElementById('pt-recon-pane-' + t);
    if (btn) btn.classList.toggle('active', t === ptReconTab);
    if (pane) pane.classList.toggle('hidden', t !== ptReconTab);
  });
}

function setReconProfile(prof) {
  ptReconProfile = prof;
  ['quick_banners', 'smb_signing', 'tls_audit', 'snmp_defaults'].forEach(p => {
    const el = document.getElementById('pt-prof-' + p);
    if (el) el.classList.toggle('active', p === ptReconProfile);
  });
}

function editReconTarget() {
  const fallback = (latestSnap && ((latestSnap.scan && latestSnap.scan.subnet !== '—' && latestSnap.scan.subnet) || (latestSnap.l3 && latestSnap.l3.subnet_cidr !== '—' && latestSnap.l3.subnet_cidr))) || '192.168.0.0/24';
  openTouchKeyboard({
    title: 'Recon Target IPv4 or /24 CIDR',
    initialValue: ptReconTarget || fallback,
    mode: 'ip',
    onDone: (val) => {
      ptReconTarget = val.trim();
      const lbl = document.getElementById('pt-recon-target-lbl');
      if (lbl) lbl.textContent = ptReconTarget || 'Auto';
    }
  });
}

function selectReconTarget(ip) {
  ptReconTarget = ip;
  const lbl = document.getElementById('pt-recon-target-lbl');
  if (lbl) lbl.textContent = ip;
  setPtReconTab('findings');
}

async function runPtReconNow() {
  const errEl = document.getElementById('pt-recon-status');
  if (errEl) errEl.textContent = `Running ${ptReconProfile}...`;
  const res = await fetch('/api/pentest/recon/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile: ptReconProfile, target: ptReconTarget || null })
  });
  let payload = null;
  try { payload = await res.json(); } catch (_) {}
  if (res.ok && payload && payload.link) {
    renderSnapshot(payload);
    setPtReconTab('findings');
  } else if (errEl) {
    errEl.textContent = (payload && payload.detail) ? payload.detail : `Recon failed (${res.status})`;
  }
}

function stopPtReconNow() {
  return apiPost('/api/pentest/recon/stop', {});
}

function clearPtReconNow() {
  return apiPost('/api/pentest/recon/clear', {});
}

async function _macPost(path, body = {}) {
  const errEl = document.getElementById('pt-nac-mac-err');
  if (errEl) errEl.textContent = '';
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  let payload = null;
  try { payload = await res.json(); } catch (_) {}
  if (res.ok && payload && payload.link) {
    renderSnapshot(payload);
    return payload;
  }
  if (errEl) errEl.textContent = (payload && payload.detail) ? payload.detail : `MAC change failed (${res.status})`;
  return null;
}

function cloneSelectedHostMac() {
  const sel = document.getElementById('sel-pt-clone-host');
  if (!sel || !sel.value) return;
  const [mac, label] = sel.value.split('|');
  if (mac) _macPost('/api/pentest/mac/spoof', { mac, label: label || 'Cloned Host' });
}

function spoofRandomLocalMac() {
  return _macPost('/api/pentest/mac/spoof', { random_local: true, label: 'Random Local' });
}

function editCustomSpoofMac() {
  const cur = (latestSnap && latestSnap.pentest && latestSnap.pentest.active_mac) || '02:11:22:33:44:55';
  openTouchKeyboard({
    title: 'Spoof Unicast MAC (AA:BB:CC:DD:EE:FF)',
    initialValue: cur,
    mode: 'text',
    onDone: (val) => {
      const cleaned = val.trim().toUpperCase();
      if (cleaned) _macPost('/api/pentest/mac/spoof', { mac: cleaned, label: 'Custom MAC' });
    }
  });
}

function restoreOriginalMac() {
  return _macPost('/api/pentest/mac/restore', {});
}

function editWifiWatchSsid() {
  const cur = (latestSnap && latestSnap.pentest && latestSnap.pentest.wifi_audit && latestSnap.pentest.wifi_audit.watch_ssid) || '';
  openTouchKeyboard({
    title: 'Watch Corporate SSID for Evil Twins',
    initialValue: cur,
    mode: 'text',
    onDone: (val) => apiPost('/api/pentest/wifi/watch', { ssid: val.trim() })
  });
}

function clearWifiWatchSsid() {
  return apiPost('/api/pentest/wifi/watch', { ssid: '' });
}

function togglePtPcapStream() {
  const tc = (latestSnap && latestSnap.tailcat) || {};
  if (tc.running && tc.mode === 'pcap_stream') stopTailcat();
  else startTailcat('pcap_stream');
}

function togglePtInlineTap() {
  const tapActive = Boolean(latestSnap && latestSnap.hw_nics && latestSnap.hw_nics.tap && latestSnap.hw_nics.tap.active);
  const nics = (latestSnap && latestSnap.hw_nics && latestSnap.hw_nics.nics) || [];
  const nicA = (nics[0] && nics[0].iface) || 'eth0';
  const nicB = (nics[1] && nics[1].iface) || 'eth1';
  apiPost('/api/tap/toggle', { enable: !tapActive, nic_a: nicA, nic_b: nicB });
}

function copyTailcatCmd() {
  const cmd = (latestSnap && latestSnap.tailcat && latestSnap.tailcat.client_cmd) || '';
  if (!cmd || !navigator.clipboard) return;
  navigator.clipboard.writeText(cmd).then(() => {
    const btn = document.getElementById('btn-tc-copy');
    if (btn) {
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy Cmd'; }, 1400);
    }
  }).catch(() => {});
}

function renderTailcatUI(s) {
  const tc = s.tailcat || {};
  const pill = document.getElementById('pill-tailcat');
  if (pill) {
    pill.classList.toggle('hidden', !tc.running);
    if (tc.running) pill.textContent = `TC • ${String(tc.mode || '').toUpperCase()}`;
  }

  const badge = document.getElementById('tc-install-badge');
  if (badge) {
    badge.textContent = tc.running ? 'ACTIVE' : (tc.installed ? 'READY' : 'NOT INSTALLED');
    badge.style.color = tc.running ? '#4ade80' : (tc.installed ? '#38bdf8' : '#fda4af');
  }

  const statusEl = document.getElementById('tc-status');
  if (statusEl) {
    statusEl.textContent = tc.status || 'Idle';
    statusEl.className = 'v ' + (tc.running ? 'v-good' : (tc.error ? 'v-bad' : 'v-cyan'));
  }
  const modeIfEl = document.getElementById('tc-mode-iface');
  if (modeIfEl) modeIfEl.textContent = tc.running ? `${tc.mode} (${tc.iface})` : '—';
  const addrEl = document.getElementById('tc-addr');
  if (addrEl) addrEl.textContent = tc.address || '—';
  const cmdEl = document.getElementById('tc-cmd');
  if (cmdEl) cmdEl.textContent = tc.client_cmd || '—';

  const qrImg = document.getElementById('tc-qr-img');
  const qrEmpty = document.getElementById('tc-qr-empty');
  if (qrImg && qrEmpty) {
    if (tc.running && tc.qr_svg_data_uri) {
      qrImg.src = tc.qr_svg_data_uri;
      qrImg.classList.remove('hidden');
      qrEmpty.classList.add('hidden');
    } else {
      qrImg.classList.add('hidden');
      qrEmpty.classList.remove('hidden');
    }
  }

  const modeBtnMap = {
    web_ui: 'btn-tc-web',
    pcap_stream: 'btn-tc-pcap',
    iperf: 'btn-tc-iperf',
    ssh: 'btn-tc-ssh'
  };
  Object.entries(modeBtnMap).forEach(([m, id]) => {
    const b = document.getElementById(id);
    if (b) b.classList.toggle('active', Boolean(tc.running && tc.mode === m));
  });

  const whBtn = document.getElementById('btn-tc-webhook');
  if (whBtn) whBtn.disabled = !tc.running;
  const whSt = document.getElementById('tc-wh-status');
  if (whSt) whSt.textContent = tc.webhook_status ? `${tc.webhook_status}${tc.webhook_pushed_at ? ' (' + tc.webhook_pushed_at + ')' : ''}` : '';

  const errEl = document.getElementById('tc-error-lbl');
  if (errEl && tc.error) {
    errEl.textContent = tc.error;
    errEl.classList.remove('hidden');
  }
}

function renderPentestViews(s) {
  const pt = s.pentest || {};
  const tc = s.tailcat || {};
  const sec = s.security || {};
  const scan = s.scan || {};
  const hw = s.hw_nics || {};
  const tap = hw.tap || {};
  const d1x = s.dot1x || {};
  const pcap = (s.audit && s.audit.pcap) || {};

  // HUB
  const hubIface = document.getElementById('pt-hub-iface');
  if (hubIface) hubIface.textContent = pt.active_iface || (s.link && s.link.iface) || 'eth0';
  const hubMeta = document.getElementById('pt-hub-meta');
  if (hubMeta) hubMeta.textContent = pt.enabled_at ? `Enabled ${pt.enabled_at} • Resets on reboot` : 'Authorized mode • Resets on reboot';
  const hubMac = document.getElementById('pt-hub-mac');
  if (hubMac) hubMac.textContent = `MAC ${pt.active_mac || (s.link && s.link.mac_address) || '—'}${pt.mac_spoofed ? ' (SPOOFED)' : ''}`;
  const hubSub = document.getElementById('pt-hub-sub');
  if (hubSub) {
    const swTxt = (s.switch && s.switch.detected) ? `${s.switch.switch_name} ${s.switch.port_id}` : 'No LLDP/CDP';
    const gwTxt = (s.l3 && s.l3.gateway_ip && s.l3.gateway_ip !== '—') ? s.l3.gateway_ip : 'No GW';
    hubSub.textContent = `${swTxt} · GW ${gwTxt} · ${s.l3 && s.l3.ipv4_address ? s.l3.ipv4_address : '—'}`;
  }
  const footNic = document.getElementById('pt-foot-nic');
  if (footNic) footNic.textContent = pt.active_iface || 'eth0';

  const recBadge = document.getElementById('pt-tile-recon-badge');
  if (recBadge) recBadge.textContent = (pt.recon && pt.recon.running) ? 'RUNNING' : ((pt.recon_findings || 0) > 0 ? 'FINDINGS' : 'SCAN');
  const tRecVal = document.getElementById('pt-tile-recon-val');
  if (tRecVal) tRecVal.textContent = (pt.recon_findings || 0) > 0 ? `${pt.recon_findings} FINDINGS` : `${scan.active_count || 0} HOSTS`;
  const tRecSub = document.getElementById('pt-tile-recon-sub');
  if (tRecSub) tRecSub.textContent = (pt.recon && pt.recon.last_run_at) ? `${pt.recon.active_profile} @ ${pt.recon.last_run_at}` : (scan.subnet && scan.subnet !== '—' ? scan.subnet : 'Tap to sweep & audit');

  const alertsCount = (sec.arp_conflicts ? sec.arp_conflicts.length : 0) + (sec.rogue_dhcp_detected ? 1 : 0) + (pt.cleartext_alerts || 0);
  const pHits = pt.passive_hits || 0;
  const tSnfBadge = document.getElementById('pt-tile-sniff-badge');
  if (tSnfBadge) tSnfBadge.textContent = (tc.running && tc.mode === 'pcap_stream') ? 'STREAMING' : (alertsCount > 0 ? 'ALERT' : (pHits > 0 ? 'EXPOSED' : 'GUARD'));
  const tSnfVal = document.getElementById('pt-tile-sniff-val');
  if (tSnfVal) tSnfVal.textContent = `${pHits} HITS · ${alertsCount} ALERTS`;

  const tNacBadge = document.getElementById('pt-tile-nac-badge');
  if (tNacBadge) tNacBadge.textContent = pt.mac_spoofed ? 'SPOOFED' : (tap.active ? 'TAP' : 'L2');
  const tNacVal = document.getElementById('pt-tile-nac-val');
  if (tNacVal) tNacVal.textContent = pt.mac_spoofed ? 'MAC CLONED' : (tap.active ? 'br0 TAP' : ((s.vlan && s.vlan.eapol_8021x_seen) ? '802.1X' : 'OPEN'));
  const tNacSub = document.getElementById('pt-tile-nac-sub');
  if (tNacSub) tNacSub.textContent = pt.mac_spoofed ? `Active ${pt.active_mac}` : (tap.active ? `Bridging ${tap.nic_a} ⇄ ${tap.nic_b}` : ((s.vlan && s.vlan.nac_status) || '802.1X & br0 Tap'));

  const tTcBadge = document.getElementById('pt-tile-tc-badge');
  if (tTcBadge) tTcBadge.textContent = tc.running ? 'LIVE' : 'IDLE';
  const tTcVal = document.getElementById('pt-tile-tc-val');
  if (tTcVal) tTcVal.textContent = tc.running ? String(tc.mode || '').toUpperCase() : 'READY';
  const tTcSub = document.getElementById('pt-tile-tc-sub');
  if (tTcSub) tTcSub.textContent = tc.running ? (tc.address || tc.status) : 'No-account WireGuard/DERP';

  // RECON
  const recon = pt.recon || {};
  const recTgtLbl = document.getElementById('pt-recon-target-lbl');
  if (recTgtLbl) {
    const autoTgt = (scan.subnet && scan.subnet !== '—') ? scan.subnet : ((s.l3 && s.l3.subnet_cidr && s.l3.subnet_cidr !== '—') ? s.l3.subnet_cidr : 'Auto');
    recTgtLbl.textContent = ptReconTarget || autoTgt;
  }
  const recSt = document.getElementById('pt-recon-status');
  if (recSt) {
    recSt.textContent = recon.error || recon.status || 'Ready';
    recSt.style.color = recon.error ? '#fda4af' : (recon.running ? '#fbbf24' : '#94a3b8');
  }
  const recRunBtn = document.getElementById('btn-pt-recon-run');
  if (recRunBtn) recRunBtn.disabled = Boolean(recon.running);
  const recStopBtn = document.getElementById('btn-pt-recon-stop');
  if (recStopBtn) recStopBtn.classList.toggle('hidden', !recon.running);

  const rFindings = recon.findings || [];
  const recFindCnt = document.getElementById('pt-recon-find-count');
  if (recFindCnt) recFindCnt.textContent = `${rFindings.length} finding(s)${recon.duration_s ? ' · ' + recon.duration_s + 's' : ''}`;
  const recFindTbody = document.getElementById('pt-recon-find-tbody');
  if (recFindTbody) {
    if (!rFindings.length) {
      recFindTbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#71717a;">Select a profile above and tap ▶ RUN</td></tr>';
    } else {
      recFindTbody.innerHTML = rFindings.slice(0, 30).map(f => `
        <tr>
          <td><span class="sev-badge sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
          <td class="mono v-cyan">${esc(f.host_ip)}${f.port ? ':' + f.port : ''}</td>
          <td class="mono">${esc(f.service)}</td>
          <td><b>${esc(f.title)}</b> <span style="color:#a1a1aa;">— ${esc(f.detail)}</span></td>
        </tr>
      `).join('');
    }
  }

  const recCnt = document.getElementById('pt-recon-count');
  if (recCnt) recCnt.textContent = `${scan.active_count || 0} hosts`;
  const recTbody = document.getElementById('pt-recon-tbody');
  if (recTbody) {
    const hosts = scan.hosts || [];
    if (!hosts.length) {
      recTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#71717a;">No hosts scanned yet — tap ↻ Sweep</td></tr>';
    } else {
      recTbody.innerHTML = hosts.slice(0, 15).map(h => `
        <tr onclick="selectReconTarget('${esc(h.ip)}')" style="cursor:pointer;" title="Tap to set as Recon target">
          <td class="mono v-cyan">${esc(h.ip)}</td>
          <td>${esc(h.hostname)}</td>
          <td>${esc(h.vendor)}</td>
          <td>${esc(h.role)}</td>
          <td class="mono">${(h.open_ports && h.open_ports.length) ? esc(h.open_ports.join(', ')) : '—'}</td>
        </tr>
      `).join('');
    }
  }

  // SNIFF
  const exp = (sec.forensics && sec.forensics.exposure) || {};
  const setTxt = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setTxt('pt-exp-llmnr', String(exp.llmnr_count || 0));
  setTxt('pt-exp-nbns', String(exp.nbns_count || 0));
  setTxt('pt-exp-wpad', String(exp.wpad_count || 0));
  setTxt('pt-exp-mdns', String(exp.mdns_count || 0));

  const expTbody = document.getElementById('pt-exp-tbody');
  if (expTbody) {
    const talkers = exp.talkers || [];
    if (!talkers.length) {
      expTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#71717a;">Listening passively — 0 LLMNR / NBT-NS / WPAD / mDNS queries seen</td></tr>';
    } else {
      expTbody.innerHTML = talkers.slice(0, 20).map(t => `
        <tr>
          <td><span class="sev-badge ${t.risk === 'HIGH' ? 'sev-HIGH' : 'sev-INFO'}">${esc(t.protocol)}</span></td>
          <td><span class="mono">${esc(t.src_ip)}</span> <span style="color:#8b909a;font-size:9.5px;">${esc(t.vendor)}</span></td>
          <td class="mono">${esc(t.query)}</td>
          <td class="mono">${t.count || 1}</td>
          <td><span class="sev-badge ${t.risk === 'HIGH' ? 'sev-HIGH' : 'sev-INFO'}">${esc(t.risk)}</span></td>
        </tr>
      `).join('');
    }
  }

  const clrAlerts = exp.cleartext_alerts || [];
  setTxt('pt-clear-count', `${clrAlerts.length} alert(s)`);
  const clrTbody = document.getElementById('pt-clear-tbody');
  if (clrTbody) {
    if (!clrAlerts.length) {
      clrTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#71717a;">No cleartext credentials or legacy protocols observed</td></tr>';
    } else {
      clrTbody.innerHTML = clrAlerts.slice(0, 20).map(a => `
        <tr>
          <td><span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
          <td class="mono">${esc(a.protocol)}</td>
          <td class="mono">${esc(a.src_ip)} → ${esc(a.dst_ip)}${a.dst_port ? ':' + a.dst_port : ''}</td>
          <td>${esc(a.detail)}</td>
          <td class="mono">${a.count || 1}</td>
        </tr>
      `).join('');
    }
  }

  const snfNic = document.getElementById('pt-sniff-nic-lbl');
  if (snfNic) snfNic.textContent = `NIC: ${pt.active_iface || 'eth0'}`;
  const snfCapIf = document.getElementById('pt-sniff-cap-iface');
  if (snfCapIf) snfCapIf.textContent = tc.running ? tc.iface : (pt.active_iface || 'eth0');
  const snfLocPcap = document.getElementById('pt-sniff-local-pcap');
  if (snfLocPcap) snfLocPcap.textContent = pcap.capturing ? `${pcap.continuous ? 'CONT' : 'REC'} (${pcap.packets_captured} pkts)` : (pcap.filename && pcap.filename !== '—' ? 'Complete' : 'Idle');
  const snfPcapFile = document.getElementById('pt-sniff-pcap-file');
  if (snfPcapFile) {
    const kb = pcap.size_bytes ? Math.max(1, Math.round(pcap.size_bytes / 1024)) : 0;
    snfPcapFile.textContent = (pcap.filename && pcap.filename !== '—') ? `${pcap.filename} (${kb} KB)` : 'None recorded';
  }
  const ptStopPcap = document.getElementById('btn-pt-pcap-stop');
  if (ptStopPcap) ptStopPcap.classList.toggle('hidden', !pcap.capturing);
  const ptDlPcap = document.getElementById('btn-pt-pcap-dl');
  if (ptDlPcap) ptDlPcap.classList.toggle('hidden', pcap.capturing || !pcap.filename || pcap.filename === '—');
  const snfBtn = document.getElementById('btn-pt-stream-toggle');
  if (snfBtn) snfBtn.textContent = (tc.running && tc.mode === 'pcap_stream') ? '⏹ STOP' : '▶ STREAM';
  const snfTcSt = document.getElementById('pt-sniff-tc-status');
  if (snfTcSt) snfTcSt.textContent = (tc.running && tc.mode === 'pcap_stream') ? 'STREAMING' : 'Idle';
  const snfCmd = document.getElementById('pt-sniff-cmd');
  if (snfCmd) snfCmd.textContent = (tc.running && tc.mode === 'pcap_stream' && tc.client_cmd) ? tc.client_cmd : 'tailcat <addr> | wireshark -k -i -';
  const snfQr = document.getElementById('pt-sniff-qr');
  const snfQrEmpty = document.getElementById('pt-sniff-qr-empty');
  if (snfQr && snfQrEmpty) {
    if (tc.running && tc.mode === 'pcap_stream' && tc.qr_svg_data_uri) {
      snfQr.src = tc.qr_svg_data_uri;
      snfQr.classList.remove('hidden');
      snfQrEmpty.classList.add('hidden');
    } else {
      snfQr.classList.add('hidden');
      snfQrEmpty.classList.remove('hidden');
    }
  }
  const snfGrade = document.getElementById('pt-sniff-grade');
  if (snfGrade) snfGrade.textContent = `GRADE ${sec.grade || '—'} (${sec.score ?? 0})`;
  const snfArp = document.getElementById('pt-sniff-arp');
  if (snfArp) snfArp.textContent = (sec.arp_conflicts && sec.arp_conflicts.length) ? `${sec.arp_conflicts.length} CONFLICTS` : `Clean (${sec.arp_frames_checked || 0} frames)`;
  const snfDhcp = document.getElementById('pt-sniff-dhcp');
  if (snfDhcp) snfDhcp.textContent = sec.rogue_dhcp_detected ? 'ROGUE DHCP DETECTED' : `${(sec.dhcp_offers || []).length} authorized`;
  const snfRa = document.getElementById('pt-sniff-ra');
  if (snfRa) snfRa.textContent = `${(sec.forensics && sec.forensics.ipv6_ra_senders ? sec.forensics.ipv6_ra_senders.length : 0)} sender(s)`;

  // NAC
  const macSp = pt.mac_spoof || {};
  const nacTap = document.getElementById('pt-nac-tap');
  if (nacTap) nacTap.textContent = tap.active ? `ACTIVE (${tap.nic_a} ⇄ ${tap.nic_b})` : 'Inactive';
  const nacBtn = document.getElementById('btn-pt-tap-toggle');
  if (nacBtn) nacBtn.textContent = tap.active ? '⏹ STOP br0 TAP' : '🔀 ENABLE br0 TAP';
  const nacEapol = document.getElementById('pt-nac-eapol');
  if (nacEapol) nacEapol.textContent = (s.vlan && s.vlan.eapol_8021x_seen) ? 'EAPOL Challenge Seen' : 'None Seen';
  const nacD1x = document.getElementById('pt-nac-d1x');
  if (nacD1x) nacD1x.textContent = d1x.status || 'Idle';
  const nacVlan = document.getElementById('pt-nac-vlan');
  if (nacVlan) nacVlan.textContent = (s.vlan && s.vlan.native_vlan_name) || 'Untagged';
  const nacIf = document.getElementById('pt-nac-iface');
  if (nacIf) nacIf.textContent = pt.active_iface || 'eth0';
  const nacOrigMac = document.getElementById('pt-nac-orig-mac');
  if (nacOrigMac) nacOrigMac.textContent = macSp.original_mac || (s.link && s.link.mac_address) || '—';
  const nacMac = document.getElementById('pt-nac-mac');
  if (nacMac) {
    nacMac.textContent = pt.active_mac || '—';
    nacMac.className = 'v mono ' + (pt.mac_spoofed ? 'v-red' : '');
  }
  const nacSpoof = document.getElementById('pt-nac-spoofed');
  if (nacSpoof) {
    nacSpoof.textContent = macSp.status || (pt.mac_spoofed ? 'SPOOFED' : 'Original MAC');
    nacSpoof.style.color = pt.mac_spoofed ? '#f87171' : '#4ade80';
  }
  const btnRestoreMac = document.getElementById('btn-pt-mac-restore');
  if (btnRestoreMac) btnRestoreMac.disabled = !pt.mac_spoofed;

  const selClone = document.getElementById('sel-pt-clone-host');
  if (selClone && document.activeElement !== selClone) {
    const hosts = (scan.hosts || []).filter(h => h.mac && h.mac !== '—');
    if (!hosts.length) {
      selClone.innerHTML = '<option value="">Sweep subnet first...</option>';
    } else {
      const curVal = selClone.value;
      selClone.innerHTML = hosts.map(h => {
        const v = `${h.mac}|${h.role} (${h.ip})`;
        return `<option value="${esc(v)}" ${v === curVal ? 'selected' : ''}>${esc(h.ip)} • ${esc(h.role)} (${esc(h.mac)})</option>`;
      }).join('');
    }
  }

  // WIFI+
  const wAudit = pt.wifi_audit || {};
  const wWatchLbl = document.getElementById('pt-wifi-watch-lbl');
  if (wWatchLbl) wWatchLbl.textContent = wAudit.watch_ssid || 'Any SSID';
  const wUsb = document.getElementById('pt-wifi-usb');
  if (wUsb) wUsb.textContent = pt.usb_wifi_iface ? `${pt.usb_wifi_iface} (Ready)` : 'Not Detected';
  const wWlan0 = document.getElementById('pt-wifi-wlan0');
  if (wWlan0) wWlan0.textContent = (s.wifi_client && s.wifi_client.ap_mode_active) ? 'Field AP Active' : ((s.wifi_client && s.wifi_client.connected) ? `Connected (${s.wifi_client.active_ssid})` : 'Survey Ready');
  const wNote = document.getElementById('pt-wifi-usb-note');
  if (wNote) {
    wNote.textContent = pt.usb_wifi_iface
      ? `Secondary USB Wi-Fi radio (${pt.usb_wifi_iface}) detected — monitor capture ready.`
      : 'Plug monitor USB Wi-Fi for active capture; wlan0 passive watch active.';
  }
  const wAps = document.getElementById('pt-wifi-aps');
  if (wAps) wAps.textContent = `${(s.wifi && s.wifi.total_count) || 0} APs`;
  const wCh = document.getElementById('pt-wifi-ch');
  if (wCh) wCh.textContent = (s.wifi && s.wifi.best_24g_channel) ? `Ch ${s.wifi.best_24g_channel}` : '—';
  const wRogues = document.getElementById('pt-wifi-rogues');
  if (wRogues) {
    wRogues.textContent = `${wAudit.rogue_count || 0} rogue · ${wAudit.weak_sec_count || 0} weak`;
    wRogues.className = 'v ' + ((wAudit.rogue_count || 0) > 0 ? 'v-red' : ((wAudit.weak_sec_count || 0) > 0 ? 'v-warn' : 'v-good'));
  }

  const wFindings = wAudit.findings || [];
  const wCnt = document.getElementById('pt-wifi-alert-cnt');
  if (wCnt) wCnt.textContent = `${wFindings.length} alert(s)`;
  const wTbody = document.getElementById('pt-wifi-tbody');
  if (wTbody) {
    if (!wFindings.length) {
      wTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#71717a;">No Rogue AP / Evil Twin or weak-security anomalies detected</td></tr>';
    } else {
      wTbody.innerHTML = wFindings.slice(0, 20).map(f => `
        <tr>
          <td><span class="sev-badge sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
          <td class="mono v-cyan">${esc(f.ssid)}</td>
          <td><span class="mono">${esc(f.bssid)}</span> <span style="color:#8b909a;font-size:9.5px;">${esc(f.vendor)}</span></td>
          <td class="mono">Ch ${f.channel} · ${esc(f.security)}</td>
          <td>${esc(f.reason)}</td>
        </tr>
      `).join('');
    }
  }
}

function openAuditFromTap() {
  document.getElementById('sys-modal').classList.add('hidden');
  nav('sec');
  setSecTab('pcap');
}

function setBacklight(pct) {
  apiPost('/api/system/backlight', { pct });
}

async function powerAction(action) {
  const label = action === 'shutdown'
    ? 'Safely shut down the Raspberry Pi now? Wait 10 seconds for the green LED to stop flashing before unplugging USB-C power.'
    : 'Reboot JackTrace now?';
  if (!confirm(label)) return;
  await apiPost('/api/system/power', { action });
  toggleSysModal();
}

function changeMode() {
  const val = document.getElementById('sel-source').value;
  const iface = document.getElementById('inp-iface').value.trim() || 'eth0';
  if (val === 'live') {
    apiPost('/api/mode', { demo_mode: false, demo_scenario: 'healthy_1g', iface });
  } else {
    const scen = val.split(':')[1] || 'healthy_1g';
    apiPost('/api/mode', { demo_mode: true, demo_scenario: scen, iface });
  }
}

function toggleRawJson() {
  const d = document.getElementById('json-drawer');
  d.classList.toggle('hidden');
  if (!d.classList.contains('hidden') && latestSnap) {
    d.textContent = JSON.stringify(latestSnap, null, 2);
  }
}

function enterKiosk() {
  document.body.classList.remove('app-mode');
  document.body.classList.toggle('kiosk-mode');
}

function enterAppMode() {
  document.body.classList.remove('kiosk-mode');
  document.body.classList.toggle('app-mode');
}

function connectWs() {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${window.location.host}/ws`);
  ws.onmessage = (ev) => {
    try {
      renderSnapshot(JSON.parse(ev.data));
    } catch (_) {}
  };
  ws.onclose = () => {
    setTimeout(connectWs, 2000);
  };
}

fetch('/api/snapshot')
  .then(r => r.json())
  .then(renderSnapshot)
  .catch(() => {});

connectWs();
