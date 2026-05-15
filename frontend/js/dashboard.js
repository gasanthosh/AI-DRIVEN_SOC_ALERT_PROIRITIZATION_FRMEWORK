/**
 * dashboard.js — SOC·AI Dashboard v2
 * Features: SSE real-time streaming, Sniffer Start/Stop, Toast notifications,
 *           Alert detail modal, Source filter pills, Chart.js charts,
 *           Export CSV, Auto-simulate
 */

'use strict';

const API = '';   // same-origin — FastAPI serves this file

// ── State ─────────────────────────────────────────────────────────────────────
const state = {
  alerts:        [],
  metrics:       null,
  fprHistory:    [],
  autoTimer:     null,
  currentPage:   1,
  pageSize:      25,
  searchQuery:   '',
  priorityFilter:'',
  sourceFilter:  '',          // '' | 'SNIFFER' | 'UPLOAD' | 'SIM'
  filters:       { HIGH: true, MEDIUM: true, LOW: true },
  soundEnabled:  false,
  snifferRunning:false,
  sseConnected:  false,
};

// ── Charts ────────────────────────────────────────────────────────────────────
let donutChart = null, lineChart = null, fprChart = null, labelChart = null;

// ── Web Audio context for beep ────────────────────────────────────────────────
let audioCtx = null;

// ══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ══════════════════════════════════════════════════════════════════════════════
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function formatTime(iso) {
  try { return new Date(iso).toLocaleTimeString('en-IN', { hour12: false }); }
  catch { return iso; }
}

function srcClass(src) {
  const m = { SNIFFER:'sniffer', UPLOAD:'upload', SIM:'sim', PREDICT:'predict' };
  return 'src-badge src-' + (m[(src||'').toUpperCase()] || 'unknown');
}

async function fetchJSON(url, opts = {}) {
  const res = await fetch(API + url, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ══════════════════════════════════════════════════════════════════════════════
// CLOCK
// ══════════════════════════════════════════════════════════════════════════════
function updateClock() {
  setText('clock', new Date().toLocaleTimeString('en-IN', { hour12: false }));
}
setInterval(updateClock, 1000);
updateClock();

// ══════════════════════════════════════════════════════════════════════════════
// TOAST SYSTEM
// ══════════════════════════════════════════════════════════════════════════════
function showToast(title, msg, type = 'info', duration = 4000) {
  const icons = { high: '🔴', medium: '🟠', low: '🟢', info: 'ℹ️' };
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
    <div class="toast-content">
      <div class="toast-title">${escHtml(title)}</div>
      <div class="toast-msg">${escHtml(msg)}</div>
    </div>
    <button class="toast-close">✕</button>`;
  toast.querySelector('.toast-close').addEventListener('click', () => removeToast(toast));
  container.appendChild(toast);
  setTimeout(() => removeToast(toast), duration);
}

function removeToast(el) {
  el.classList.add('removing');
  setTimeout(() => el.remove(), 320);
}

// ══════════════════════════════════════════════════════════════════════════════
// SOUND ALERT
// ══════════════════════════════════════════════════════════════════════════════
function beep(freq = 880, duration = 200) {
  if (!state.soundEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc  = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.frequency.value = freq;
    osc.type = 'square';
    gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration / 1000);
    osc.start();
    osc.stop(audioCtx.currentTime + duration / 1000);
  } catch {}
}

document.getElementById('sound-btn').addEventListener('click', () => {
  state.soundEnabled = !state.soundEnabled;
  const btn = document.getElementById('sound-btn');
  btn.textContent = state.soundEnabled ? '🔔' : '🔕';
  btn.classList.toggle('active', state.soundEnabled);
  showToast('Sound Alerts', state.soundEnabled ? 'Enabled' : 'Disabled', 'info', 2000);
});

// ══════════════════════════════════════════════════════════════════════════════
// ALERT DETAIL MODAL
// ══════════════════════════════════════════════════════════════════════════════
function openModal(alert) {
  const modal = document.getElementById('alert-modal');
  document.getElementById('modal-title').textContent = `🔍 ${alert.attack_type}`;
  const rows = [
    ['Timestamp',   new Date(alert.timestamp).toLocaleString()],
    ['Attack Type', alert.attack_type],
    ['Priority',    alert.priority],
    ['Source',      alert.source || 'UNKNOWN'],
    ['Src IP',      alert.src_ip || '—'],
    ['Dst IP',      alert.dst_ip || '—'],
    ['Confidence',  (alert.confidence * 100).toFixed(2) + '%'],
    ['Risk Score',  alert.risk_score.toFixed(4)],
    ['Is Benign',   alert.is_benign ? '✔ Yes' : '✘ No'],
    ['Action',      alert.action],
    ['Ground Truth',alert.ground_truth || '—'],
    ['Alert ID',    alert.id],
  ];
  document.getElementById('modal-body').innerHTML = rows.map(([k, v]) =>
    `<div class="modal-row">
       <span class="modal-key">${escHtml(k)}</span>
       <span class="modal-val">${escHtml(String(v))}</span>
     </div>`
  ).join('');
  modal.classList.remove('hidden');
}

document.getElementById('modal-close').addEventListener('click', () => {
  document.getElementById('alert-modal').classList.add('hidden');
});
document.getElementById('alert-modal').addEventListener('click', e => {
  if (e.target === document.getElementById('alert-modal'))
    document.getElementById('alert-modal').classList.add('hidden');
});

// ══════════════════════════════════════════════════════════════════════════════
// BUILD TABLE ROW
// ══════════════════════════════════════════════════════════════════════════════
/**
 * @param {object}  a            - alert object
 * @param {boolean} compact      - omit the Action column (used in full Alerts tab)
 * @param {boolean} monitorMode  - add Src IP / Dst IP columns (used in Live Monitor)
 */
function buildRow(a, compact = false, monitorMode = false) {
  const tr   = document.createElement('tr');
  tr.className = `priority-${a.priority.toLowerCase()}`;
  const conf  = (a.confidence * 100).toFixed(1);
  const barColor = a.priority === 'HIGH' ? '#ff3860' : a.priority === 'MEDIUM' ? '#ff7043' : '#00e676';

  const ipCells = monitorMode ? `
    <td><span class="ip-cell">${escHtml(a.src_ip || '—')}</span></td>
    <td><span class="ip-cell">${escHtml(a.dst_ip || '—')}</span></td>` : '';

  tr.innerHTML = `
    <td>${formatTime(a.timestamp)}</td>
    <td>${escHtml(a.attack_type)}</td>
    <td><span class="badge ${a.priority.toLowerCase()}">${a.priority}</span></td>
    <td><span class="${srcClass(a.source)}">${escHtml(a.source || 'SIM')}</span></td>
    ${ipCells}
    <td>
      <div class="conf-bar-wrap">
        <div class="conf-bar-bg"><div class="conf-bar-fill" style="width:${conf}%;background:${barColor}"></div></div>
        ${conf}%
      </div>
    </td>
    <td>${a.risk_score.toFixed(3)}</td>
    ${compact ? '' : `<td>${escHtml(a.action)}</td>`}`;
  tr.addEventListener('click', () => openModal(a));
  return tr;
}

// ══════════════════════════════════════════════════════════════════════════════
// NAV / TAB
// ══════════════════════════════════════════════════════════════════════════════
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    const tab = item.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById(`tab-${tab}`).classList.add('active');
    document.getElementById('page-title').textContent = {
      dashboard: 'Dashboard Overview',
      alerts:    'Alert History',
      metrics:   'SOC Metrics',
      monitor:   'Live Traffic Monitor',
      simulate:  'Traffic Simulator',
      analytics: 'Model Analytics',
    }[tab] || '';
    if (tab === 'alerts')   renderAlertsTab();
    if (tab === 'metrics')  refreshMetrics();
    if (tab === 'monitor')  renderMonitorTab();
    if (tab === 'analytics') {
      import('/static/js/analytics.js').then(m => m.initAnalytics()).catch(() => {});
    }
  });
});

document.getElementById('hamburger').addEventListener('click', () =>
  document.getElementById('sidebar').classList.toggle('open')
);

// ══════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK
// ══════════════════════════════════════════════════════════════════════════════
async function checkHealth() {
  const dot = document.getElementById('api-status-dot');
  const txt = document.getElementById('api-status-text');
  try {
    const h = await fetchJSON('/health');
    dot.className = 'status-dot online';
    txt.textContent = h.model_loaded ? 'API online · Model loaded' : 'API online · Demo mode';
    // Sync sniffer running state
    state.snifferRunning = h.sniffer_running;
    updateSnifferUI();
  } catch {
    dot.className = 'status-dot offline';
    txt.textContent = 'API offline';
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SSE — REAL-TIME ALERT STREAMING
// ══════════════════════════════════════════════════════════════════════════════
let sseSource = null;
const MAX_LIVE_ROWS = 100;

function connectSSE() {
  if (sseSource) return;
  try {
    sseSource = new EventSource(API + '/stream');
    sseSource.addEventListener('alert', e => {
      try {
        const alert = JSON.parse(e.data);
        onNewSSEAlert(alert);
      } catch {}
    });
    sseSource.addEventListener('open', () => { state.sseConnected = true; });
    sseSource.addEventListener('error', () => {
      state.sseConnected = false;
      sseSource.close();
      sseSource = null;
      // Reconnect after 3s
      setTimeout(connectSSE, 3000);
    });
  } catch {}
}

function onNewSSEAlert(alert) {
  // De-duplicate
  if (state.alerts.some(a => a.id === alert.id)) return;
  state.alerts.unshift(alert);
  if (state.alerts.length > 2000) state.alerts.pop();

  // Update badge
  setText('alert-badge', state.alerts.length);

  // Flash row in Live Monitor if tab is active
  const monitorTab = document.getElementById('tab-monitor');
  if (monitorTab && monitorTab.classList.contains('active')) {
    prependMonitorRow(alert);
  }

  // HIGH alert → toast + beep
  if (alert.priority === 'HIGH') {
    showToast(`HIGH ALERT — ${alert.attack_type}`,
      `Risk: ${alert.risk_score.toFixed(3)} · Source: ${alert.source || 'UNKNOWN'}`,
      'high', 6000);
    beep(660, 300);
  }

  // If dashboard tab is active, re-render
  const dashTab = document.getElementById('tab-dashboard');
  if (dashTab && dashTab.classList.contains('active')) {
    renderDashboard();
  }
}

function prependMonitorRow(alert) {
  const tbody = document.getElementById('monitor-tbody');
  if (!tbody) return;
  const tr = buildRow(alert, true, true);   // compact=true, monitorMode=true (show IPs)
  tr.classList.add('new-alert');
  tbody.insertBefore(tr, tbody.firstChild);
  // Trim to max rows
  while (tbody.rows.length > MAX_LIVE_ROWS) tbody.deleteRow(tbody.rows.length - 1);
  // Update live badge
  document.getElementById('live-badge').textContent = '● LIVE';
}

// ══════════════════════════════════════════════════════════════════════════════
// FETCH ALERTS / METRICS (polling fallback)
// ══════════════════════════════════════════════════════════════════════════════
async function refreshAlerts() {
  try {
    const data = await fetchJSON('/alerts?limit=500');
    state.alerts = data;
    setText('alert-badge', data.length);
    renderDashboard();
    if (document.getElementById('tab-alerts').classList.contains('active'))  renderAlertsTab();
    if (document.getElementById('tab-monitor').classList.contains('active')) renderMonitorTab();
  } catch (e) { console.error('Alert fetch failed:', e); }
}

async function refreshMetrics() {
  try {
    const m = await fetchJSON('/metrics');
    state.metrics = m;
    renderMetricsTab(m);
    setText('monitor-sniffer-count', m.source_counts?.SNIFFER  || 0);
    setText('monitor-upload-count',  m.source_counts?.UPLOAD   || 0);
    setText('monitor-sim-count',     m.source_counts?.SIM      || 0);
    setText('monitor-predict-count', m.source_counts?.PREDICT  || 0);
    state.fprHistory.push(m.fpr_estimate);
    if (state.fprHistory.length > 20) state.fprHistory.shift();
    updateFprChart();
    updateKPIs(m);

    // Sniffer real-time stats
    const sn = m.sniffer;
    if (sn) {
      setText('pkt-rate',    sn.pkt_rate   || 0);
      setText('pkt-total',   sn.packets_captured || 0);
      setText('flows-total', sn.flows_processed  || 0);
      if (state.snifferRunning !== sn.running) {
        state.snifferRunning = sn.running;
        updateSnifferUI();
      }
    }
  } catch (e) { console.error('Metrics fetch failed:', e); }
}

async function poll() {
  await Promise.all([refreshAlerts(), refreshMetrics()]);
}

// ══════════════════════════════════════════════════════════════════════════════
// KPIs
// ══════════════════════════════════════════════════════════════════════════════
const _kpiPrev = {};
function updateKPIs(m) {
  const vals = {
    'kpi-high':   m.high,
    'kpi-medium': m.medium,
    'kpi-low':    m.low,
    'kpi-total':  m.total_alerts,
    'kpi-fpr':    (m.fpr_estimate * 100).toFixed(1) + '%',
    'kpi-prec':   (m.precision_estimate * 100).toFixed(1) + '%',
  };
  for (const [id, val] of Object.entries(vals)) {
    const el = document.getElementById(id);
    if (!el) continue;
    if (_kpiPrev[id] !== val) {
      el.textContent = val;
      const card = el.closest('.kpi-card');
      if (card) { card.classList.remove('kpi-flash'); void card.offsetWidth; card.classList.add('kpi-flash'); }
      _kpiPrev[id] = val;
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// DASHBOARD RENDER
// ══════════════════════════════════════════════════════════════════════════════
function applyFilters(alerts) {
  return alerts.filter(a => {
    const pOk = state.filters[a.priority] !== false;
    const sOk = !state.searchQuery || a.attack_type.toLowerCase().includes(state.searchQuery);
    return pOk && sOk;
  });
}

function renderDashboard() {
  const alerts = applyFilters(state.alerts);
  const tbody  = document.getElementById('recent-tbody');
  tbody.innerHTML = '';
  alerts.slice(0, 50).forEach(a => tbody.appendChild(buildRow(a)));
  updateDonutChart(alerts);
  updateLineChart(alerts.slice(0, 60));
}

// ══════════════════════════════════════════════════════════════════════════════
// MONITOR TAB
// ══════════════════════════════════════════════════════════════════════════════
function renderMonitorTab() {
  const tbody = document.getElementById('monitor-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  const real = state.alerts.filter(a => a.source === 'SNIFFER' || a.source === 'UPLOAD');
  real.slice(0, MAX_LIVE_ROWS).forEach(a => tbody.appendChild(buildRow(a, true, true)));
  if (real.length > 0)
    document.getElementById('live-badge').textContent = '● LIVE';
}

// ══════════════════════════════════════════════════════════════════════════════
// ALERTS TAB
// ══════════════════════════════════════════════════════════════════════════════
function renderAlertsTab() {
  const priority = document.getElementById('filter-priority-select').value;
  const search   = document.getElementById('search-input').value.toLowerCase();
  const source   = state.sourceFilter;
  const filtered = state.alerts.filter(a => {
    const pOk = !priority || a.priority === priority;
    const sOk = !search   || a.attack_type.toLowerCase().includes(search);
    const srcOk = !source || (a.source || '').toUpperCase() === source;
    return pOk && sOk && srcOk;
  });
  const pages = Math.max(1, Math.ceil(filtered.length / state.pageSize));
  state.currentPage = Math.min(state.currentPage, pages);
  const slice = filtered.slice(
    (state.currentPage - 1) * state.pageSize,
    state.currentPage * state.pageSize,
  );
  const tbody = document.getElementById('alerts-tbody');
  tbody.innerHTML = '';
  slice.forEach(a => tbody.appendChild(buildRow(a)));
  renderPagination(pages);
}

function renderPagination(pages) {
  const wrap = document.getElementById('pagination');
  wrap.innerHTML = '';
  for (let i = 1; i <= Math.min(pages, 10); i++) {
    const btn = document.createElement('button');
    btn.className = `page-btn${i === state.currentPage ? ' active' : ''}`;
    btn.textContent = i;
    btn.addEventListener('click', () => { state.currentPage = i; renderAlertsTab(); });
    wrap.appendChild(btn);
  }
}

// Source filter pills
document.querySelectorAll('.pill').forEach(pill => {
  pill.addEventListener('click', () => {
    document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    state.sourceFilter = pill.dataset.source;
    state.currentPage  = 1;
    renderAlertsTab();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// METRICS TAB
// ══════════════════════════════════════════════════════════════════════════════
function renderMetricsTab(m) {
  const sn = m.sniffer || {};
  const rows = [
    ['Total Alerts',       m.total_alerts],
    ['🔴 HIGH',            m.high],
    ['🟠 MEDIUM',          m.medium],
    ['🟢 LOW',             m.low],
    ['Benign Flows',       m.benign_count],
    ['Attack Flows',       m.attack_count],
    ['FPR Estimate',       (m.fpr_estimate * 100).toFixed(2) + '%'],
    ['Precision Estimate', (m.precision_estimate * 100).toFixed(2) + '%'],
    ['━━━ Sniffer ━━━',   ''],
    ['Sniffer Status',     sn.running ? '🟢 RUNNING' : '⚫ OFFLINE'],
    ['Packets Captured',   sn.packets_captured ?? '—'],
    ['Flows Processed',    sn.flows_processed  ?? '—'],
    ['Packet Rate',        sn.pkt_rate != null ? sn.pkt_rate + ' pkt/s' : '—'],
  ];
  const list = document.getElementById('metrics-list');
  list.innerHTML = rows.map(([k, v]) =>
    v === '' ? `<div class="metric-row" style="border-bottom:1px solid rgba(255,255,255,.08);margin:4px 0"><span style="font-size:.65rem;color:var(--text-dim);letter-spacing:1px">${k}</span></div>`
             : `<div class="metric-row"><span class="metric-key">${k}</span><span class="metric-val">${v}</span></div>`
  ).join('');
  updateLabelChart(m.label_distribution || {});
}

// ══════════════════════════════════════════════════════════════════════════════
// CHARTS
// ══════════════════════════════════════════════════════════════════════════════
const PALETTE = [
  '#ff3860','#ff7043','#00e676','#3d9cf5','#a29bfe',
  '#00d4ff','#fd79a8','#fab1a0','#55efc4','#ffc107',
  '#ffeaa7','#74b9ff','#e17055','#b2bec3',
];

const CHART_OPTS = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#7f9ab5', font: { size: 11 }, boxWidth: 12 } } },
};

function updateDonutChart(alerts) {
  const counts = {};
  alerts.forEach(a => { counts[a.attack_type] = (counts[a.attack_type] || 0) + 1; });
  const labels = Object.keys(counts); const data = Object.values(counts);
  if (donutChart) {
    donutChart.data.labels = labels;
    donutChart.data.datasets[0].data = data;
    donutChart.update('none'); return;
  }
  donutChart = new Chart(document.getElementById('chart-donut'), {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: PALETTE, borderWidth: 2, borderColor: '#05080f' }] },
    options: { ...CHART_OPTS, cutout: '65%' },
  });
}

function updateLineChart(alerts) {
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  const tLabels = [], hD = [], mD = [], lD = [];
  [...alerts].reverse().forEach((a, i) => {
    tLabels.push(i + 1); counts[a.priority]++;
    hD.push(counts.HIGH); mD.push(counts.MEDIUM); lD.push(counts.LOW);
  });
  const ds = (color, label, data) => ({
    label, data, borderColor: color, backgroundColor: color + '22',
    fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2,
  });
  if (lineChart) {
    lineChart.data.labels = tLabels;
    lineChart.data.datasets[0].data = hD;
    lineChart.data.datasets[1].data = mD;
    lineChart.data.datasets[2].data = lD;
    lineChart.update('none'); return;
  }
  lineChart = new Chart(document.getElementById('chart-line'), {
    type: 'line',
    data: { labels: tLabels, datasets: [ds('#ff3860','HIGH',hD), ds('#ff7043','MEDIUM',mD), ds('#00e676','LOW',lD)] },
    options: {
      ...CHART_OPTS,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: { ticks: { color: '#4a6380', maxTicksLimit: 10 }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
      },
    },
  });
}

function updateFprChart() {
  const labels = state.fprHistory.map((_, i) => i + 1);
  const data   = state.fprHistory.map(v => +(v * 100).toFixed(2));
  if (fprChart) { fprChart.data.labels = labels; fprChart.data.datasets[0].data = data; fprChart.update('none'); return; }
  const ctx = document.getElementById('chart-fpr'); if (!ctx) return;
  fprChart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [{ label: 'FPR %', data, borderColor: '#a29bfe', backgroundColor: 'rgba(162,155,254,.15)', fill: true, tension: 0.4, pointRadius: 4, pointBackgroundColor: '#a29bfe' }] },
    options: { ...CHART_OPTS, scales: {
      x: { ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
      y: { min: 0, max: 100, ticks: { color: '#4a6380', callback: v => v + '%' }, grid: { color: 'rgba(255,255,255,0.04)' } },
    }},
  });
}

function updateLabelChart(dist) {
  const labels = Object.keys(dist); const data = Object.values(dist);
  const ctx = document.getElementById('chart-labels'); if (!ctx) return;
  if (labelChart) { labelChart.data.labels = labels; labelChart.data.datasets[0].data = data; labelChart.update('none'); return; }
  labelChart = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Count', data, backgroundColor: PALETTE, borderRadius: 4 }] },
    options: { ...CHART_OPTS, indexAxis: 'y', plugins: { legend: { display: false } }, scales: {
      x: { ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
      y: { ticks: { color: '#7f9ab5', font: { size: 10 } }, grid: { display: false } },
    }},
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// SNIFFER CONTROL
// ══════════════════════════════════════════════════════════════════════════════
async function loadInterfaces() {
  const sel = document.getElementById('iface-select');
  try {
    const data = await fetchJSON('/network/interfaces');
    sel.innerHTML = '<option value="">— Default Interface —</option>';
    (data.interfaces || []).forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface.name;
      opt.textContent = `${iface.name}  [${iface.mac}]`;
      sel.appendChild(opt);
    });
    if (data.error) sel.innerHTML += `<option disabled>${data.error}</option>`;
  } catch {
    sel.innerHTML = '<option value="">Could not load interfaces</option>';
  }
}

function updateSnifferUI() {
  const dot   = document.getElementById('sniffer-dot');
  const label = document.getElementById('sniffer-label');
  const startBtn = document.getElementById('sniffer-start-btn');
  const stopBtn  = document.getElementById('sniffer-stop-btn');
  const navPulse = document.getElementById('nav-pulse');

  if (state.snifferRunning) {
    dot.className   = 'sniffer-dot running';
    label.className = 'sniffer-label running';
    label.textContent = 'SNIFFER LIVE';
    startBtn.disabled = true;
    stopBtn.disabled  = false;
    if (navPulse) navPulse.style.display = 'inline-block';
    document.getElementById('live-badge').textContent = '● LIVE';
  } else {
    dot.className   = 'sniffer-dot';
    label.className = 'sniffer-label';
    label.textContent = 'SNIFFER OFFLINE';
    startBtn.disabled = false;
    stopBtn.disabled  = true;
    if (navPulse) navPulse.style.display = 'none';
    document.getElementById('live-badge').textContent = '● WAITING';
  }
}

document.getElementById('sniffer-start-btn').addEventListener('click', async () => {
  const iface    = document.getElementById('iface-select').value;
  const interval = document.getElementById('interval-select').value;
  try {
    const data = await fetchJSON(`/sniffer/start?interface=${encodeURIComponent(iface)}&interval=${interval}`, { method: 'POST' });
    state.snifferRunning = data.running || data.status === 'started';
    updateSnifferUI();
    showToast('Network Scan', `Started on ${iface || 'Default'} · Interval ${interval}s`, 'low', 4000);
  } catch (e) {
    showToast('Sniffer Error', e.message, 'high', 5000);
  }
});

document.getElementById('sniffer-stop-btn').addEventListener('click', async () => {
  try {
    await fetchJSON('/sniffer/stop', { method: 'POST' });
    state.snifferRunning = false;
    updateSnifferUI();
    setText('pkt-rate', '0');
    showToast('Network Scan', 'Stopped.', 'info', 3000);
  } catch (e) {
    showToast('Sniffer Error', e.message, 'high', 5000);
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// FILTERS
// ══════════════════════════════════════════════════════════════════════════════
['high','medium','low'].forEach(p => {
  document.getElementById(`filter-${p}`).addEventListener('change', e => {
    state.filters[p.toUpperCase()] = e.target.checked;
    renderDashboard();
  });
});

document.getElementById('search-input').addEventListener('input', e => {
  state.searchQuery = e.target.value.toLowerCase();
  renderDashboard();
  if (document.getElementById('tab-alerts').classList.contains('active')) {
    state.currentPage = 1; renderAlertsTab();
  }
});

document.getElementById('filter-priority-select').addEventListener('change', () => {
  state.currentPage = 1; renderAlertsTab();
});

// ══════════════════════════════════════════════════════════════════════════════
// CLEAR ALERTS
// ══════════════════════════════════════════════════════════════════════════════
document.getElementById('clear-btn').addEventListener('click', async () => {
  if (!confirm('Clear all alerts and reset counters?')) return;
  try {
    await fetchJSON('/alerts', { method: 'DELETE' });
    state.alerts = [];
    state.fprHistory = [];
    setText('alert-badge', '0');
    renderDashboard();
    showToast('Alerts Cleared', 'Alert store has been reset.', 'info', 3000);
    await poll();
  } catch (e) {
    showToast('Error', e.message, 'high');
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// REFRESH
// ══════════════════════════════════════════════════════════════════════════════
document.getElementById('refresh-btn').addEventListener('click', poll);

// ══════════════════════════════════════════════════════════════════════════════
// EXPORT CSV
// ══════════════════════════════════════════════════════════════════════════════
function exportCSV(data) {
  const header = 'timestamp,attack_type,priority,source,confidence,risk_score,action\n';
  const rows   = data.map(a =>
    `${a.timestamp},${a.attack_type},${a.priority},${a.source},${a.confidence},${a.risk_score},"${a.action}"`
  ).join('\n');
  const blob = new Blob([header + rows], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url; link.download = `soc_alerts_${Date.now()}.csv`; link.click();
  URL.revokeObjectURL(url);
}

document.getElementById('export-btn').addEventListener('click', () => exportCSV(state.alerts.slice(0, 50)));
document.getElementById('alerts-export-btn').addEventListener('click', () => exportCSV(state.alerts));

// ══════════════════════════════════════════════════════════════════════════════
// SIMULATE
// ══════════════════════════════════════════════════════════════════════════════
document.getElementById('sim-inject-btn').addEventListener('click', async () => {
  const attackType = document.getElementById('sim-attack-type').value;
  const count      = +document.getElementById('sim-count').value;
  const res        = document.getElementById('sim-result');
  try {
    const data = await fetchJSON('/simulate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: attackType, count }),
    });
    res.className   = 'sim-result';
    res.textContent = `✅ Injected ${data.generated} alert(s) of type "${attackType}"`;
    res.classList.remove('hidden');
    await poll();
  } catch (e) {
    res.className   = 'sim-result error';
    res.textContent = '❌ Error: ' + e.message;
    res.classList.remove('hidden');
  }
});

document.getElementById('flood-btn').addEventListener('click', async () => {
  const count = +document.getElementById('flood-count').value;
  const res   = document.getElementById('flood-result');
  try {
    const data = await fetchJSON(`/simulate/random?count=${count}`, { method: 'POST' });
    res.className   = 'sim-result';
    res.textContent = `✅ Injected ${data.generated} random alerts`;
    res.classList.remove('hidden');
    await poll();
  } catch (e) {
    res.className   = 'sim-result error';
    res.textContent = '❌ Error: ' + e.message;
    res.classList.remove('hidden');
  }
});

// Auto-simulate
document.getElementById('auto-start-btn').addEventListener('click', () => {
  const interval = +document.getElementById('auto-interval').value * 1000;
  const status   = document.getElementById('auto-status');
  document.getElementById('auto-start-btn').disabled = true;
  document.getElementById('auto-stop-btn').disabled  = false;
  status.className   = 'sim-result';
  status.textContent = '▶️ Auto-simulate running…';
  status.classList.remove('hidden');
  state.autoTimer = setInterval(async () => {
    try { await fetchJSON('/simulate/random?count=5', { method: 'POST' }); await poll(); } catch {}
  }, interval);
});

document.getElementById('auto-stop-btn').addEventListener('click', () => {
  clearInterval(state.autoTimer); state.autoTimer = null;
  document.getElementById('auto-start-btn').disabled = false;
  document.getElementById('auto-stop-btn').disabled  = true;
  document.getElementById('auto-status').textContent = '⏹ Stopped.';
});

// ══════════════════════════════════════════════════════════════════════════════
// FILE UPLOAD
// ══════════════════════════════════════════════════════════════════════════════
(function initUpload() {
  const dropzone  = document.getElementById('upload-dropzone');
  const fileInput = document.getElementById('upload-file-input');
  const fileInfo  = document.getElementById('upload-file-info');
  const clearBtn  = document.getElementById('upload-clear-btn');
  const uploadBtn = document.getElementById('upload-btn');
  const statusEl  = document.getElementById('upload-status');
  const statusTxt = document.getElementById('upload-status-text');
  const progBar   = document.getElementById('upload-progress-bar');
  const summary   = document.getElementById('upload-summary');
  let selectedFile = null;

  ['dragenter','dragover'].forEach(evt => dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.add('drag-over'); }));
  ['dragleave','drop'].forEach(evt => dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.remove('drag-over'); }));
  dropzone.addEventListener('drop', e => { if (e.dataTransfer.files.length) selectFile(e.dataTransfer.files[0]); });
  fileInput.addEventListener('change', () => { if (fileInput.files.length) selectFile(fileInput.files[0]); });

  function selectFile(file) {
    if (!file.name.toLowerCase().endsWith('.csv')) {
      showToast('File Error', 'Only .csv files are accepted.', 'high'); return;
    }
    selectedFile = file;
    document.getElementById('upload-filename').textContent = `${file.name}  (${(file.size/1024).toFixed(1)} KB)`;
    dropzone.classList.add('hidden');
    fileInfo.classList.remove('hidden');
    uploadBtn.disabled = false;
    statusEl.classList.add('hidden');
    summary.classList.add('hidden');
  }

  clearBtn.addEventListener('click', () => {
    selectedFile   = null; fileInput.value = '';
    dropzone.classList.remove('hidden'); fileInfo.classList.add('hidden');
    uploadBtn.disabled = true;
    statusEl.classList.add('hidden'); summary.classList.add('hidden');
    progBar.style.width = '0%';
  });

  uploadBtn.addEventListener('click', async () => {
    if (!selectedFile) return;
    uploadBtn.disabled   = true;
    uploadBtn.textContent = '⏳ Processing…';
    statusEl.classList.remove('hidden');
    statusTxt.textContent = 'Uploading…';
    progBar.style.width  = '20%';
    summary.classList.add('hidden');

    try {
      const formData = new FormData();
      formData.append('file', selectedFile, selectedFile.name);
      progBar.style.width = '50%';
      const res  = await fetch('/upload', { method: 'POST', body: formData });
      progBar.style.width = '80%';
      if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || `HTTP ${res.status}`); }
      const data = await res.json();
      progBar.style.width = '100%';
      statusTxt.textContent = `✅ ${data.rows_processed} rows classified from "${data.filename}"`;
      const pb = data.priority_breakdown || {};
      document.getElementById('upload-total').textContent  = data.rows_processed;
      document.getElementById('upload-high').textContent   = pb.HIGH || 0;
      document.getElementById('upload-medlow').textContent = (pb.MEDIUM||0) + (pb.LOW||0);
      summary.classList.remove('hidden');
      showToast('Upload Complete', `${data.rows_processed} flows classified | HIGH: ${pb.HIGH||0}`, 'low', 5000);
      await poll();
    } catch (e) {
      progBar.style.width = '100%';
      statusTxt.textContent = '❌ ' + e.message;
      showToast('Upload Failed', e.message, 'high');
    } finally {
      uploadBtn.disabled    = false;
      uploadBtn.textContent = '🚀 Start Batch Processing';
      setTimeout(() => { progBar.style.width = '0%'; }, 1500);
    }
  });
})();

// ══════════════════════════════════════════════════════════════════════════════
// BOOT
// ══════════════════════════════════════════════════════════════════════════════
async function boot() {
  await checkHealth();
  await loadInterfaces();
  updateSnifferUI();

  // Bootstrap demo if empty
  try {
    const h = await fetchJSON('/health');
    if (h.alert_count === 0) {
      await fetchJSON('/simulate/random?count=30', { method: 'POST' });
    }
  } catch {}

  await poll();

  // Start SSE for real-time streaming
  connectSSE();

  // Polling fallback (less frequent since SSE handles live updates)
  setInterval(poll, 8000);
  setInterval(checkHealth, 30000);
}

boot();
