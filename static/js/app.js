'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  packets: [],
  alerts: [],
  filteredPackets: [],
  selectedPacket: null,
  filter: '',
  autoScroll: true,
  sortCol: 'id',
  sortAsc: true,
  running: false,
  paused: false,
  protocolStats: {},
  trafficHistory: [],
  threatCounts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  charts: {},
};

// ─── Socket ───────────────────────────────────────────────────────────────────
const socket = io();

socket.on('connect', () => {
  console.log('[WS] Connected');
  toast('info', '🔌 Connected', 'Dashboard connected to IDS server');
});

socket.on('disconnect', () => {
  toast('high', '⚠ Disconnected', 'Lost connection to IDS server');
  setCaptureBtns(false, false);
});

socket.on('init', (data) => {
  state.protocolStats = data.protocol_stats || {};
  state.trafficHistory = data.traffic_history || [];
  updateStatus(data.status);
  renderSidebarRules(data.rules || []);
  if (data.recent_packets) {
    data.recent_packets.forEach(p => addPacket(p, false));
    renderPackets();
  }
  if (data.recent_alerts) {
    data.recent_alerts.forEach(a => addAlert(a));
    updateAlertCount();
  }
  initCharts();
  updateCharts();
});

socket.on('packet', (pkt) => {
  addPacket(pkt, true);
});

socket.on('alert', (alert) => {
  addAlert(alert);
  showAlertToast(alert);
  updateAlertCount();
  updateThreatLevel();
});

socket.on('traffic_update', (data) => {
  if (data.protocol_stats) state.protocolStats = data.protocol_stats;
  if (data.traffic) {
    state.trafficHistory.push(data.traffic);
    if (state.trafficHistory.length > 60) state.trafficHistory.shift();
  }
  if (data.status) updateStatus(data.status);
  updateCharts();
  updateCounters();
});

socket.on('status_update', (status) => {
  updateStatus(status);
});

socket.on('cleared', () => {
  state.packets = [];
  state.filteredPackets = [];
  state.alerts = [];
  state.threatCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  state.trafficHistory = [];
  renderPackets();
  el('alert-tbody').innerHTML = '';
  el('sb-alerts-list').innerHTML = '<div class="empty-state">No alerts detected</div>';
  updateAlertCount();
  updateThreatLevel();
  updateCharts();
});

socket.on('rules_loaded', (data) => {
  renderSidebarRules(data.rules || []);
  toast('info', '📜 Rules Loaded', `${data.count} rules loaded`);
});

socket.on('capture_error', (data) => {
  toast('high', '⚠ Capture Error', data.error || 'Failed to capture packets');
  setCaptureBtns(false, false);
});

// ─── Packet Management ────────────────────────────────────────────────────────
function addPacket(pkt, live) {
  state.packets.push(pkt);
  if (state.packets.length > 2000) state.packets.shift();

  if (pkt.threat) {
    state.threatCounts[pkt.threat] = (state.threatCounts[pkt.threat] || 0) + 1;
  }

  if (matchesFilter(pkt, state.filter)) {
    state.filteredPackets.push(pkt);
    if (live) {
      appendPacketRow(pkt);
      if (state.autoScroll) scrollBottom();
    }
  }
}

function matchesFilter(pkt, filter) {
  if (!filter) return true;
  const f = filter.toLowerCase();
  return (
    pkt.src_ip.includes(f) ||
    pkt.dst_ip.includes(f) ||
    pkt.proto.toLowerCase().includes(f) ||
    (pkt.info || '').toLowerCase().includes(f) ||
    String(pkt.id).includes(f) ||
    (pkt.threat || '').toLowerCase().includes(f) ||
    f.startsWith('port ') && (
      String(pkt.src_port || '').includes(f.slice(5)) ||
      String(pkt.dst_port || '').includes(f.slice(5))
    ) ||
    f === 'tcp' && pkt.proto === 'TCP' ||
    f === 'udp' && pkt.proto === 'UDP' ||
    f === 'icmp' && pkt.proto === 'ICMP' ||
    f === 'http' && pkt.proto === 'HTTP' ||
    f === 'dns' && pkt.proto === 'DNS' ||
    f === 'alert' && pkt.is_alert ||
    f === 'critical' && pkt.threat === 'CRITICAL'
  );
}

// ─── Rendering ────────────────────────────────────────────────────────────────
function renderPackets() {
  const tbody = el('packet-tbody');
  tbody.innerHTML = '';
  const sorted = getSortedPackets();
  sorted.forEach(p => appendPacketRow(p, false));
  if (state.autoScroll) scrollBottom();
}

function getSortedPackets() {
  const col = state.sortCol;
  const asc = state.sortAsc ? 1 : -1;
  return [...state.filteredPackets].sort((a, b) => {
    let va = a[col], vb = b[col];
    if (col === 'id' || col === 'length') { va = +va; vb = +vb; }
    return va < vb ? -asc : va > vb ? asc : 0;
  });
}

function appendPacketRow(pkt, scrollLast = true) {
  const tbody = el('packet-tbody');
  const tr = document.createElement('tr');

  const rowClass = pkt.threat === 'CRITICAL' ? 'row-critical' :
                   pkt.threat === 'HIGH'     ? 'row-high' :
                   pkt.threat === 'MEDIUM'   ? 'row-medium' : '';
  if (rowClass) tr.className = rowClass;
  tr.dataset.id = pkt.id;
  tr.onclick = () => selectPacket(pkt, tr);

  tr.innerHTML = `
    <td class="col-no">${pkt.id}</td>
    <td class="col-ts" style="font-family:monospace">${pkt.ts}</td>
    <td class="col-src">${pkt.src_ip}</td>
    <td class="col-dst">${pkt.dst_ip}</td>
    <td class="col-proto"><span class="proto-${pkt.proto}">${pkt.proto}</span></td>
    <td class="col-len" style="text-align:right">${pkt.length}</td>
    <td class="col-threat"><span class="threat-badge threat-${pkt.threat}">${pkt.threat}</span></td>
    <td class="col-info" title="${escHtml(pkt.info || '')}">${escHtml(pkt.info || '')}</td>
  `;
  tbody.appendChild(tr);
}

function selectPacket(pkt, tr) {
  document.querySelectorAll('#packet-tbody tr.selected').forEach(r => r.classList.remove('selected'));
  if (tr) tr.classList.add('selected');
  state.selectedPacket = pkt;
  renderDetailTree(pkt);
  renderHex(pkt);
  el('detail-hint').textContent = `Packet #${pkt.id} — ${pkt.proto} ${pkt.src_ip} → ${pkt.dst_ip}`;
}

function renderDetailTree(pkt) {
  const tree = el('detail-tree');
  if (!pkt.layers || pkt.layers.length === 0) {
    tree.innerHTML = '<div class="empty-state">No layer data</div>';
    return;
  }
  tree.innerHTML = pkt.layers.map((layer, i) => `
    <div class="tree-node">
      <div class="tree-header" onclick="toggleTree('tree-body-${pkt.id}-${i}')">
        <span class="tree-toggle" id="tree-arrow-${pkt.id}-${i}">▶</span>
        <span>${escHtml(layer.name)}</span>
      </div>
      <div class="tree-body" id="tree-body-${pkt.id}-${i}">
        ${(layer.fields || []).map(f => `
          <div class="tree-field">
            <span class="tree-field-key">${escHtml(f.key)}:</span>
            <span class="tree-field-val">${escHtml(f.value)}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
  // Open first layer by default
  const firstBody = el(`tree-body-${pkt.id}-0`);
  if (firstBody) { firstBody.classList.add('open'); }
  const firstArrow = el(`tree-arrow-${pkt.id}-0`);
  if (firstArrow) firstArrow.textContent = '▼';
}

function toggleTree(id) {
  const body = el(id);
  if (!body) return;
  const arrowId = id.replace('tree-body-', 'tree-arrow-');
  const arrow = el(arrowId);
  body.classList.toggle('open');
  if (arrow) arrow.textContent = body.classList.contains('open') ? '▼' : '▶';
}

function renderHex(pkt) {
  const hb = el('hex-body');
  if (!pkt.hex || pkt.hex.length === 0) {
    hb.innerHTML = '<div class="empty-state">No hex data</div>';
    return;
  }
  hb.innerHTML = pkt.hex.map(row => `
    <div class="hex-row">
      <span class="hex-offset">${row.offset}</span>
      <span class="hex-data">${escHtml(row.hex)}</span>
      <span class="hex-ascii">${escHtml(row.ascii)}</span>
    </div>
  `).join('');
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
function addAlert(alert) {
  state.alerts.push(alert);
  if (state.alerts.length > 500) state.alerts.shift();

  const tbody = el('alert-tbody');
  const tr = document.createElement('tr');
  const rowClass = alert.threat === 'CRITICAL' ? 'row-critical' :
                   alert.threat === 'HIGH' ? 'row-high' : 'row-medium';
  tr.className = rowClass;
  tr.innerHTML = `
    <td>${alert.id}</td>
    <td style="font-family:monospace">${alert.ts}</td>
    <td><strong>${escHtml(alert.type || '')}</strong></td>
    <td><span class="threat-badge threat-${alert.threat}">${alert.threat}</span></td>
    <td>${escHtml(alert.src || '')}</td>
    <td>${escHtml(alert.dst || '')}</td>
    <td><span class="proto-${alert.proto}">${alert.proto || ''}</span></td>
    <td style="font-size:11px;color:var(--text2)">${escHtml(alert.rule || alert.detail || alert.info || '')}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);

  // Sidebar alert item
  const list = el('sb-alerts-list');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  const item = document.createElement('div');
  item.className = `sb-alert-item ${alert.threat}`;
  item.innerHTML = `
    <div class="sb-alert-top">
      <span class="sai-type">${escHtml(alert.type || 'Intrusion')}</span>
      <span class="sai-time">${alert.ts}</span>
    </div>
    <div class="sai-detail">${escHtml(alert.src || '')} → ${escHtml(alert.dst || '')} | ${escHtml(alert.rule || alert.info || '')}</div>
  `;
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 15) list.removeChild(list.lastChild);
}

function showAlertToast(alert) {
  const level = (alert.threat || 'MEDIUM').toLowerCase();
  const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
  toast(level, `${icons[level] || '⚠'} ${alert.type || 'Alert'}`,
    `${alert.src} → ${alert.dst} | ${alert.rule || alert.info || ''}`);
}

function updateAlertCount() {
  const n = state.alerts.length;
  el('badge-alerts').textContent = n > 0 ? n : '';
  el('sb-alert-count').textContent = n;
  el('sb-alerts').textContent = n;
  el('alerts-count-label').textContent = `${n} alerts`;
}

function updateThreatLevel() {
  const d = el('threat-level-display');
  const recent = state.alerts.slice(-30);
  let level = 'LOW';
  if (recent.some(a => a.threat === 'CRITICAL')) level = 'CRITICAL';
  else if (recent.some(a => a.threat === 'HIGH')) level = 'HIGH';
  else if (recent.some(a => a.threat === 'MEDIUM')) level = 'MEDIUM';

  d.textContent = level;
  d.className = `threat-level ${level}`;
  document.body.dataset.threat = level.toLowerCase();

  document.querySelectorAll('.tm-seg').forEach(s => s.classList.remove('active'));
  const map = { LOW: 'tm-low', MEDIUM: 'tm-med', HIGH: 'tm-high', CRITICAL: 'tm-crit' };
  const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const idx = order.indexOf(level);
  order.slice(0, idx + 1).forEach(l => {
    const segs = document.querySelectorAll(`.${map[l]}`);
    segs.forEach(s => s.classList.add('active'));
  });
}

function clearAlerts() {
  state.alerts = [];
  el('alert-tbody').innerHTML = '';
  el('sb-alerts-list').innerHTML = '<div class="empty-state">No alerts detected</div>';
  updateAlertCount();
  updateThreatLevel();
}

// ─── Status & Controls ────────────────────────────────────────────────────────
function updateStatus(status) {
  if (!status) return;
  state.running = status.running;
  state.paused = status.paused;

  el('sb-packets').textContent = status.packet_count || 0;
  el('sb-filtered').textContent = status.filtered_count || 0;
  el('sb-alerts').textContent = status.alert_count || 0;
  el('sb-interface').textContent = status.interface || '';
  el('uptime-display').textContent = status.uptime || '00:00:00';

  const dot = el('ci-dot');
  const label = el('ci-label');
  if (status.running && !status.paused) {
    dot.className = 'ci-dot running';
    label.textContent = 'Capturing';
    el('sb-status').textContent = 'Live capture in progress…';
  } else if (status.paused) {
    dot.className = 'ci-dot paused';
    label.textContent = 'Paused';
    el('sb-status').textContent = 'Capture paused';
  } else {
    dot.className = 'ci-dot';
    label.textContent = 'Idle';
    el('sb-status').textContent = 'Idle — press Start to begin capture';
  }

  setCaptureBtns(status.running, status.paused);
  updateCounters();
}

function setCaptureBtns(running, paused) {
  el('btn-start').disabled  = running && !paused;
  el('btn-stop').disabled   = !running;
  el('btn-pause').disabled  = !running;
  el('btn-pause').textContent = paused ? 'Resume' : 'Pause';
  const pauseIcon = el('btn-pause').querySelector('svg');
  if (pauseIcon && paused) {
    pauseIcon.innerHTML = '<polygon points="5,3 19,12 5,21"/>';
  } else if (pauseIcon) {
    pauseIcon.innerHTML = '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
  }
}

function startCapture()   { socket.emit('start_capture'); }
function stopCapture()    { socket.emit('stop_capture'); }
function pauseCapture()   { socket.emit('pause_capture'); }
function restartCapture() { socket.emit('restart_capture'); }

// ─── Filter ───────────────────────────────────────────────────────────────────
function onFilterInput(val) {
  const wrap = el('filter-wrap');
  const hint = el('filter-hint');
  if (!val) {
    wrap.className = 'filter-input-wrap';
    hint.textContent = '';
    return;
  }
  // Simple validation
  const valid = /^[\w\s\.\*:!\[\]\-\>\<"'\/]+$/i.test(val);
  wrap.className = 'filter-input-wrap ' + (valid ? 'valid' : 'invalid');
  hint.textContent = valid ? '✓ Valid filter' : '✗ Invalid expression';
  hint.style.color = valid ? 'var(--green)' : 'var(--red)';
}

function applyFilter() {
  const val = el('filter-input').value.trim();
  state.filter = val.toLowerCase();
  state.filteredPackets = state.packets.filter(p => matchesFilter(p, state.filter));
  renderPackets();
  el('sb-filtered').textContent = state.filteredPackets.length;
  el('sb-filter-active').textContent = val ? `Filter: ${val}` : '';
  socket.emit('set_filter', { filter: val });
}

function clearFilter() {
  el('filter-input').value = '';
  state.filter = '';
  state.filteredPackets = [...state.packets];
  renderPackets();
  el('filter-wrap').className = 'filter-input-wrap';
  el('filter-hint').textContent = '';
  el('sb-filter-active').textContent = '';
  el('sb-filtered').textContent = state.filteredPackets.length;
}

// ─── Sorting ──────────────────────────────────────────────────────────────────
function sortTable(col) {
  if (state.sortCol === col) state.sortAsc = !state.sortAsc;
  else { state.sortCol = col; state.sortAsc = true; }

  document.querySelectorAll('.sort-arrow').forEach(s => s.textContent = '');
  const arrow = el(`sort-${col}`);
  if (arrow) arrow.textContent = state.sortAsc ? ' ▲' : ' ▼';

  renderPackets();
}

// ─── Tab Switching ────────────────────────────────────────────────────────────
function showTab(tab) {
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  const content = el(`tab-${tab}`);
  if (content) content.classList.add('active');

  if (tab === 'stats') updateCharts();
}

// ─── Charts ───────────────────────────────────────────────────────────────────
const PROTO_COLORS = {
  TCP: '#388bfd', UDP: '#3fb950', ICMP: '#f0883e',
  HTTP: '#a371f7', DNS: '#39d353', OTHER: '#6e7681',
};

function initCharts() {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = '#30363d';

  // Proto donut
  const cp = el('chart-proto');
  if (cp && !state.charts.proto) {
    state.charts.proto = new Chart(cp, {
      type: 'doughnut',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 1, borderColor: '#0d1117' }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { boxWidth: 12, font: { size: 11 } } } },
      },
    });
  }

  // Traffic line
  const ct = el('chart-traffic');
  if (ct && !state.charts.traffic) {
    state.charts.traffic = new Chart(ct, {
      type: 'line',
      data: { labels: [], datasets: [{
        label: 'pkt/s', data: [],
        borderColor: '#388bfd', backgroundColor: 'rgba(56,139,253,0.1)',
        borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { ticks: { maxTicksLimit: 6 } }, y: { min: 0 } },
      },
    });
  }

  // Threat bar
  const cth = el('chart-threat');
  if (cth && !state.charts.threat) {
    state.charts.threat = new Chart(cth, {
      type: 'bar',
      data: {
        labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        datasets: [{
          label: 'Packets',
          data: [0, 0, 0, 0],
          backgroundColor: ['rgba(63,185,80,0.7)', 'rgba(210,153,34,0.7)', 'rgba(219,109,40,0.7)', 'rgba(248,81,73,0.7)'],
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { }, y: { min: 0 } },
      },
    });
  }

  // Mini traffic
  const mt = el('mini-chart-traffic');
  if (mt && !state.charts.mini) {
    state.charts.mini = new Chart(mt, {
      type: 'line',
      data: { labels: [], datasets: [{
        data: [], borderColor: '#388bfd', backgroundColor: 'rgba(56,139,253,0.15)',
        borderWidth: 1.5, pointRadius: 0, fill: true, tension: 0.4,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: { display: false, min: 0 },
        },
      },
    });
  }
}

function updateCharts() {
  const ps = state.protocolStats || {};

  // Proto donut
  if (state.charts.proto) {
    const labels = Object.keys(ps);
    const data   = Object.values(ps);
    const colors = labels.map(l => PROTO_COLORS[l] || '#6e7681');
    state.charts.proto.data.labels = labels;
    state.charts.proto.data.datasets[0].data = data;
    state.charts.proto.data.datasets[0].backgroundColor = colors;
    state.charts.proto.update('none');
  }

  // Traffic line
  if (state.charts.traffic && state.trafficHistory.length) {
    const labels = state.trafficHistory.map(t => t.ts);
    const data   = state.trafficHistory.map(t => t.pps);
    state.charts.traffic.data.labels = labels;
    state.charts.traffic.data.datasets[0].data = data;
    state.charts.traffic.update('none');
  }

  // Threat bar
  if (state.charts.threat) {
    const tc = state.threatCounts;
    state.charts.threat.data.datasets[0].data = [tc.LOW||0, tc.MEDIUM||0, tc.HIGH||0, tc.CRITICAL||0];
    state.charts.threat.update('none');
  }

  // Mini traffic
  if (state.charts.mini && state.trafficHistory.length) {
    const data = state.trafficHistory.slice(-20).map(t => t.pps);
    state.charts.mini.data.labels = data.map((_, i) => i);
    state.charts.mini.data.datasets[0].data = data;
    state.charts.mini.update('none');
  }

  // Mini proto list
  const mpl = el('mini-proto-list');
  if (mpl) {
    mpl.innerHTML = Object.entries(ps).map(([proto, cnt]) => `
      <div class="mpl-item">
        <div class="mpl-dot" style="background:${PROTO_COLORS[proto]||'#6e7681'}"></div>
        <span class="mpl-label">${proto}</span>
        <span class="mpl-count">${cnt}</span>
      </div>
    `).join('');
  }
}

function updateCounters() {
  const ps = state.protocolStats || {};
  setEl('cnt-total', state.packets.length);
  setEl('cnt-alerts', state.alerts.length);
  setEl('cnt-tcp', ps.TCP || 0);
  setEl('cnt-udp', ps.UDP || 0);
  setEl('cnt-icmp', ps.ICMP || 0);
  setEl('cnt-http', ps.HTTP || 0);
  setEl('cnt-dns', ps.DNS || 0);
  setEl('cnt-other', ps.OTHER || 0);
}

// ─── Rules ────────────────────────────────────────────────────────────────────
function renderSidebarRules(rules) {
  const list = el('sb-rules-list');
  const count = el('sb-rules-count');
  if (!rules || rules.length === 0) {
    list.innerHTML = '<div class="empty-state">No rules loaded</div>';
    count.textContent = 0;
    return;
  }
  count.textContent = rules.length;
  list.innerHTML = rules.map(r => `<div class="sb-rule-item" title="${escHtml(r)}">${escHtml(r)}</div>`).join('');
}

async function loadRulesTab() {
  const resp = await fetch('/api/rules');
  const rules = await resp.json();
  const container = el('rules-list');
  if (!rules.length) { container.innerHTML = '<div class="empty-state">No rules found</div>'; return; }

  let html = '';
  let lastFile = null;
  rules.forEach(r => {
    if (r.file !== lastFile) {
      html += `<div class="rule-file-header">${escHtml(r.file)}</div>`;
      lastFile = r.file;
    }
    if (r.is_empty) return;
    const cls = r.is_comment ? 'rule-comment' : 'rule-text';
    html += `<div class="rule-row">
      <span class="rule-num">${r.line}</span>
      <span class="${cls}">${escHtml(r.text)}</span>
    </div>`;
  });
  container.innerHTML = html;
}

async function validateRuleInline() {
  const input = el('rule-validate-input');
  const result = el('rule-validate-result');
  const val = input.value.trim();
  if (!val) { result.textContent = 'Enter a rule'; result.className = 'err'; return; }
  const resp = await fetch('/api/rules/validate', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ rule: val }),
  });
  const data = await resp.json();
  if (data.valid) {
    result.textContent = `✓ Valid — ${data.parsed}`;
    result.className = 'ok';
  } else {
    result.textContent = `✗ ${data.error}`;
    result.className = 'err';
  }
}

// ─── Modal ────────────────────────────────────────────────────────────────────
function showModal(id) { el(id).classList.add('open'); }
function closeModal(id) { el(id).classList.remove('open'); }

async function validateRule() {
  const input = el('modal-rule-input');
  const result = el('modal-rule-result');
  const val = input.value.trim();
  if (!val) { result.textContent = 'Please enter a rule.'; result.className = 'modal-result err'; return; }
  const resp = await fetch('/api/rules/validate', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ rule: val }),
  });
  const data = await resp.json();
  result.className = 'modal-result ' + (data.valid ? 'ok' : 'err');
  result.textContent = data.valid ? `✓ Valid  — Parsed: ${data.parsed}` : `✗ Invalid: ${data.error}`;
}

function useExample(el_) {
  el('modal-rule-input').value = el_.textContent.replace(/→/g, '->').replace(/&gt;/g, '>').replace(/&lt;/g, '<');
  el('modal-rule-result').textContent = '';
  el('modal-rule-result').className = 'modal-result';
}

// ─── Panel toggles ────────────────────────────────────────────────────────────
function togglePanel(id) {
  const panel = el(id);
  if (panel) panel.style.display = panel.style.display === 'none' ? '' : 'none';
}

function toggleTheme() {
  document.documentElement.classList.toggle('light');
}

// ─── File ops (mock) ──────────────────────────────────────────────────────────
async function loadInterfaces() {
  try {
    const resp = await fetch('/api/interfaces');
    const ifaces = await resp.json();
    const sel = el('iface-select');
    sel.innerHTML = ifaces.map(i => `
      <option value="${escHtml(i.name)}" ${i.active ? 'selected' : ''}>
        ${escHtml(i.name)}${i.ip ? ' (' + escHtml(i.ip) + ')' : ''}
      </option>
    `).join('');
  } catch (e) {
    console.warn('Could not load interfaces:', e);
  }
}

function setInterface(name) {
  if (!name) return;
  socket.emit('set_interface', { interface: name });
  toast('info', '📡 Interface Changed', `Now monitoring: ${name}`);
}

function openFile()  { toast('info', '📂 Open File', 'File dialog not available in web mode'); }

let classifierFeatures = null;
let classifierLoaded = false;

function loadClassifierTab() {
  if (classifierLoaded) return;
  fetch('/api/classifier/features')
    .then(r => r.json())
    .then(data => {
      if (!data.success) { toast('error', 'Classifier', data.error); return; }
      classifierFeatures = data.features;
      classifierLoaded = true;
      renderClassifierForm(data.features);
    })
    .catch(e => toast('error', 'Classifier', 'Failed to load features'));
}

function renderClassifierForm(features) {
  const wrap = document.getElementById('classifier-form-wrap');
  wrap.innerHTML = '';
  const grid = document.createElement('div');
  grid.className = 'classifier-grid';
  const keys = Object.keys(features);
  keys.forEach(name => {
    const meta = features[name];
    const cell = document.createElement('div');
    const inModel = meta.in_model !== false;
    cell.className = 'clf-cell' + (inModel ? '' : ' not-in-model');
    const label = document.createElement('label');
    label.className = 'clf-label';
    label.textContent = name.trim();
    label.title = inModel ? 'Used by model' : 'Not a model feature';
    cell.appendChild(label);
    if (meta.type === 'numeric') {
      const inp = document.createElement('input');
      inp.type = 'text';
      inp.className = 'clf-input';
      inp.dataset.field = name;
      inp.dataset.type = 'numeric';
      inp.placeholder = `median: ${meta.median}`;
      cell.appendChild(inp);
    } else {
      const sel = document.createElement('select');
      sel.className = 'clf-input';
      sel.dataset.field = name;
      sel.dataset.type = 'categorical';
      const opt0 = document.createElement('option');
      opt0.value = '';
      opt0.textContent = '-- select --';
      sel.appendChild(opt0);
      (meta.values || []).forEach(v => {
        const opt = document.createElement('option');
        opt.value = v;
        opt.textContent = v;
        if (v === meta.mode) opt.selected = true;
        sel.appendChild(opt);
      });
      cell.appendChild(sel);
    }
    grid.appendChild(cell);
  });
  wrap.appendChild(grid);
}

function classifierPredict() {
  if (!classifierFeatures) { toast('error', 'Classifier', 'Features not loaded yet'); return; }
  const inputs = document.querySelectorAll('#classifier-form-wrap .clf-input');
  const row = {};
  inputs.forEach(inp => {
    const field = inp.dataset.field;
    const val = inp.value.trim();
    if (val !== '') row[field] = val;
  });
  document.getElementById('classifier-result').textContent = 'Predicting...';
  fetch('/api/classifier/predict', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(row)
  })
    .then(r => r.json())
    .then(data => {
      if (!data.success) {
        document.getElementById('classifier-result').textContent = 'Error: ' + data.error;
        toast('error', 'Prediction Failed', data.error);
        return;
      }
      const resultEl = document.getElementById('classifier-result');
      resultEl.textContent = 'Predicted: ' + data.prediction;
      const isBenign = String(data.prediction).toLowerCase() === 'benign';
      resultEl.className = 'classifier-result pred-' + (isBenign ? 'benign' : 'threat');
      if (data.probabilities) {
        const probDiv = document.getElementById('classifier-probs');
        const barsDiv = document.getElementById('prob-bars');
        probDiv.style.display = 'block';
        barsDiv.innerHTML = '';
        data.probabilities.forEach(p => {
          const bar = document.createElement('div');
          bar.className = 'prob-row';
          const pBenign = String(p.class).toLowerCase() === 'benign';
          bar.innerHTML = `<span class="prob-label">${p.class}</span>
            <div class="prob-track"><div class="prob-fill ${pBenign ? 'fill-benign' : 'fill-threat'}" style="width:${Math.max(p.prob, 0.5)}%"></div></div>
            <span class="prob-val">${p.prob}%</span>`;
          barsDiv.appendChild(bar);
        });
      }
      toast('success', 'Classification', 'Predicted: ' + data.prediction);
    })
    .catch(e => {
      document.getElementById('classifier-result').textContent = 'Error';
      toast('error', 'Prediction', 'Request failed');
    });
}

function classifierClear() {
  const inputs = document.querySelectorAll('#classifier-form-wrap .clf-input');
  inputs.forEach(inp => {
    if (inp.tagName === 'SELECT') inp.selectedIndex = 0;
    else inp.value = '';
  });
  document.getElementById('classifier-result').textContent = '';
  document.getElementById('classifier-probs').style.display = 'none';
}

function classifierFillDefaults() {
  if (!classifierFeatures) return;
  const inputs = document.querySelectorAll('#classifier-form-wrap .clf-input');
  inputs.forEach(inp => {
    const field = inp.dataset.field;
    const meta = classifierFeatures[field];
    if (!meta) return;
    if (meta.type === 'numeric') inp.value = meta.median;
    else if (meta.type === 'categorical' && meta.mode) {
      for (let i = 0; i < inp.options.length; i++) {
        if (inp.options[i].value === meta.mode) { inp.selectedIndex = i; break; }
      }
    }
  });
}

function classifierLoadCSV(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';

  const totalBytes = file.size;
  const totalGB = totalBytes / (1024 ** 3);
  const AVG_BYTES_PER_ROW = 220;

  const nameEl    = document.getElementById('clf-csv-name');
  const progWrap  = document.getElementById('clf-upload-progress');
  const progBar   = document.getElementById('clf-prog-bar');
  const progFile  = document.getElementById('clf-prog-filename');
  const progStat  = document.getElementById('clf-prog-status');
  const progXfer  = document.getElementById('clf-prog-transferred');
  const progRows  = document.getElementById('clf-prog-rows');
  const progLeft  = document.getElementById('clf-prog-remaining');

  function fmtBytes(b) {
    if (b >= 1024 ** 3) return (b / 1024 ** 3).toFixed(2) + ' GB';
    if (b >= 1024 ** 2) return (b / 1024 ** 2).toFixed(1) + ' MB';
    return (b / 1024).toFixed(0) + ' KB';
  }
  function fmtRows(b) {
    const r = Math.floor(b / AVG_BYTES_PER_ROW);
    return r >= 1000 ? (r / 1000).toFixed(1) + 'k' : r;
  }

  nameEl.textContent = 'Uploading…';
  progFile.textContent = file.name;
  progStat.textContent = 'Uploading…';
  progBar.style.width = '0%';
  progBar.classList.remove('prog-done', 'prog-analyzing');
  progWrap.style.display = 'block';

  const xhr = new XMLHttpRequest();

  xhr.upload.addEventListener('progress', e => {
    if (!e.lengthComputable) return;
    const pct = (e.loaded / e.total) * 100;
    const remaining = e.total - e.loaded;
    progBar.style.width = pct.toFixed(1) + '%';
    progStat.textContent = pct.toFixed(1) + '%';
    progXfer.textContent = fmtBytes(e.loaded) + ' / ' + fmtBytes(e.total);
    progRows.textContent = '~' + fmtRows(e.loaded) + ' rows sent';
    progLeft.textContent = fmtBytes(remaining) + ' remaining';
  });

  xhr.upload.addEventListener('load', () => {
    progBar.style.width = '100%';
    progBar.classList.add('prog-analyzing');
    progStat.textContent = 'Analyzing…';
    progXfer.textContent = fmtBytes(totalBytes) + ' uploaded';
    progRows.textContent = 'Reading rows…';
    progLeft.textContent = '';
  });

  xhr.addEventListener('load', () => {
    let data;
    try { data = JSON.parse(xhr.responseText); } catch { data = { success: false, error: 'Invalid response' }; }
    if (!data.success) {
      progStat.textContent = 'Error';
      progBar.classList.remove('prog-analyzing');
      progBar.classList.add('prog-error');
      nameEl.textContent = 'Load failed';
      toast('error', 'Load CSV', data.error);
      return;
    }
    progBar.style.width = '100%';
    progBar.classList.remove('prog-analyzing');
    progBar.classList.add('prog-done');
    progStat.textContent = 'Done';
    progXfer.textContent = fmtBytes(totalBytes);
    progRows.textContent = data.count + ' features loaded';
    progLeft.textContent = '';
    nameEl.textContent = file.name + ' (' + data.count + ' features)';
    classifierFeatures = data.features;
    classifierLoaded = true;
    renderClassifierForm(data.features);
    toast('success', 'CSV Loaded', file.name + ' — ' + data.count + ' features');
    setTimeout(() => { progWrap.style.display = 'none'; }, 4000);
  });

  xhr.addEventListener('error', () => {
    progStat.textContent = 'Upload failed';
    progBar.classList.add('prog-error');
    nameEl.textContent = 'Upload failed';
    toast('error', 'Load CSV', 'Network error during upload');
  });

  const formData = new FormData();
  formData.append('file', file);
  xhr.open('POST', '/api/classifier/upload-csv');
  xhr.send(formData);
}
function saveCapture() {
  const data = JSON.stringify(state.packets.slice(-500), null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `capture_${Date.now()}.json`;
  a.click(); URL.revokeObjectURL(url);
  toast('info', '💾 Saved', 'Packets exported as JSON');
}

// ─── Toast ────────────────────────────────────────────────────────────────────
let toastQueue = 0;
function toast(level, title, msg) {
  if (toastQueue > 4) return;
  toastQueue++;
  const c = el('toast-container');
  const t = document.createElement('div');
  t.className = `toast ${level}`;
  t.innerHTML = `<div class="toast-body"><div class="toast-title">${escHtml(title)}</div><div class="toast-msg">${escHtml(msg)}</div></div>`;
  c.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0'; t.style.transform = 'translateX(40px)';
    t.style.transition = 'all 0.3s';
    setTimeout(() => { t.remove(); toastQueue--; }, 300);
  }, 3500);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function el(id)         { return document.getElementById(id); }
function setEl(id, val) { const e = el(id); if (e) e.textContent = val; }
function escHtml(str)   { return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function scrollBottom() {
  const wrap = el('packet-table-wrap');
  if (wrap) wrap.scrollTop = wrap.scrollHeight;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  loadInterfaces();

  // Close dropdowns on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.menu-item')) {
      document.querySelectorAll('.dropdown').forEach(d => d.style.display = '');
    }
  });

  // Uptime ticker
  setInterval(() => {
    if (state.running && !state.paused) {
      updateThreatLevel();
    }
  }, 5000);

  // Auto-scroll toggle on manual scroll
  const wrap = el('packet-table-wrap');
  if (wrap) {
    wrap.addEventListener('scroll', () => {
      const atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 40;
      state.autoScroll = atBottom;
    });
  }

  // Enter key in modal input
  const mi = el('modal-rule-input');
  if (mi) mi.addEventListener('keydown', e => { if (e.key === 'Enter') validateRule(); });

  // Enter key in rule validate inline
  const ri = el('rule-validate-input');
  if (ri) ri.addEventListener('keydown', e => { if (e.key === 'Enter') validateRuleInline(); });
});
