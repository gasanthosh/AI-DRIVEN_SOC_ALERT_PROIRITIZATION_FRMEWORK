/**
 * analytics.js — SOC·AI Model Comparison Analytics
 * Charts: Confusion Matrix (CSS grid heatmap), ROC Curve, Precision/Recall/F1,
 *         FP Rate Comparison, Business Impact grid, Per-class table.
 */

'use strict';

// ── State ────────────────────────────────────────────────────────────────────
const an = {
  data:         null,
  selectedModel:'XGBoost',
  rocChart:     null,
  prfChart:     null,
  fprChart:     null,
  pollTimer:    null,
};

// ── Chart palette matches main dashboard ─────────────────────────────────────
const MODEL_COLORS = {
  'Rule-Based (Baseline)': '#b2bec3',
  'Logistic Regression':   '#3d9cf5',
  'Random Forest':         '#00e676',
  'XGBoost':               '#a29bfe',
};
const CHART_DEFAULTS = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#7f9ab5', font: { size: 11 }, boxWidth: 12 } } },
  scales: {
    x: { ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
    y: { ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function pct(v) { return (v * 100).toFixed(1) + '%'; }
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function destroyChart(ref) { if (ref) { try { ref.destroy(); } catch{} } }

// ── Boot ─────────────────────────────────────────────────────────────────────
export function initAnalytics() {
  document.getElementById('run-comparison-btn').addEventListener('click', startComparison);
  tryLoadAnalytics();
}

async function tryLoadAnalytics() {
  try {
    const data = await fetch('/analytics').then(r => {
      if (!r.ok) throw new Error(r.status);
      return r.json();
    });
    an.data = data;
    // Default to first AI model (skip baseline)
    const names = Object.keys(data.models);
    an.selectedModel = names.find(n => n !== 'Rule-Based (Baseline)') || names[0];
    renderAll();
  } catch {
    setStatus('⚙️ No comparison data yet — click "Run Comparison" to generate.', 'muted');
  }
}

// ── Poll for completion ───────────────────────────────────────────────────────
async function startComparison() {
  setStatus('⏳ Starting comparison…', 'muted');
  document.getElementById('run-comparison-btn').disabled = true;

  try {
    await fetch('/analytics/run', { method: 'POST' });
    setStatus('🔄 Comparison running (training LR, evaluating all models)…', 'muted');
    an.pollTimer = setInterval(pollStatus, 3000);
  } catch (e) {
    setStatus('❌ Failed to start: ' + e.message, 'error');
    document.getElementById('run-comparison-btn').disabled = false;
  }
}

async function pollStatus() {
  try {
    const s = await fetch('/analytics/status').then(r => r.json());
    if (!s.running && s.ready) {
      clearInterval(an.pollTimer);
      setStatus('✅ Done!', 'ok');
      document.getElementById('run-comparison-btn').disabled = false;
      await tryLoadAnalytics();
    }
  } catch {}
}

function setStatus(msg, type = 'muted') {
  const el = document.getElementById('analytics-status-txt');
  if (!el) return;
  el.textContent = msg;
  el.className   = `analytics-status-txt ${type}`;
}

// ── Render All ────────────────────────────────────────────────────────────────
function renderAll() {
  if (!an.data) return;
  renderModelTabs();
  renderKPIs();
  renderConfusionMatrix();
  renderROC();
  renderPRF();
  renderFPRComparison();
  renderBusinessImpact();
  renderPerClassTable();
}

// ── Model Selector Tabs ───────────────────────────────────────────────────────
function renderModelTabs() {
  const wrap = document.getElementById('model-tabs');
  wrap.innerHTML = '';
  Object.entries(an.data.models).forEach(([name, info]) => {
    const pill = document.createElement('button');
    pill.className  = `model-pill${name === an.selectedModel ? ' active' : ''}`;
    pill.style.setProperty('--mpcolor', info.color || '#00d4ff');
    pill.textContent = name;
    pill.addEventListener('click', () => {
      an.selectedModel = name;
      renderAll();
    });
    wrap.appendChild(pill);
  });
}

// ── KPI Cards ─────────────────────────────────────────────────────────────────
function renderKPIs() {
  const grid = document.getElementById('analytics-kpi-grid');
  grid.innerHTML = '';
  const m   = an.data.models[an.selectedModel];
  const met = m.metrics;
  const fp  = m.fp_stats;
  const col = m.color || '#00d4ff';
  const cards = [
    { icon: '🎯', label: 'Macro Precision', val: pct(met.macro_precision),   glow: 'glow-blue' },
    { icon: '📡', label: 'Macro Recall',    val: pct(met.macro_recall),       glow: 'glow-green' },
    { icon: '⚡', label: 'Macro F1',        val: pct(met.macro_f1),           glow: 'glow-purple' },
    { icon: '🔴', label: 'False Positive Rate', val: pct(fp.fpr),             glow: 'glow-red' },
    { icon: '✅', label: 'True Positives',  val: fp.total_benign - fp.false_positives, glow: 'glow-cyan' },
    { icon: '🛡️', label: 'ROC AUC',        val: m.roc ? m.roc.auc.toFixed(3) : '—', glow: 'glow-orange' },
  ];
  cards.forEach(c => {
    grid.insertAdjacentHTML('beforeend', `
      <div class="kpi-card ${c.glow}">
        <div class="kpi-icon">${c.icon}</div>
        <div class="kpi-label">${c.label}</div>
        <div class="kpi-value">${c.val}</div>
      </div>`);
  });
}

// ── Confusion Matrix (CSS grid heatmap) ──────────────────────────────────────
function renderConfusionMatrix() {
  const container = document.getElementById('cm-container');
  container.innerHTML = '';
  const m       = an.data.models[an.selectedModel];
  const cm      = m.metrics.confusion_matrix;
  const classes = an.data.classes;
  const maxVal  = Math.max(...cm.flat());

  // Build grid CSS
  const n   = classes.length;
  const dim  = Math.max(28, Math.min(52, Math.floor(400 / n)));

  container.style.gridTemplateColumns = `max-content repeat(${n}, ${dim}px)`;
  container.style.gridTemplateRows    = `max-content repeat(${n}, ${dim}px)`;

  // Top-left corner cell (empty)
  container.insertAdjacentHTML('beforeend', '<div class="cm-corner">Actual \\ Predicted</div>');
  // Column headers
  classes.forEach(c => {
    container.insertAdjacentHTML('beforeend',
      `<div class="cm-col-header" title="${esc(c)}">${esc(c.length > 10 ? c.slice(0,9)+'…' : c)}</div>`);
  });
  // Rows
  cm.forEach((row, ri) => {
    container.insertAdjacentHTML('beforeend',
      `<div class="cm-row-header" title="${esc(classes[ri])}">${esc(classes[ri].length > 10 ? classes[ri].slice(0,9)+'…' : classes[ri])}</div>`);
    row.forEach((val, ci) => {
      const intensity = maxVal > 0 ? val / maxVal : 0;
      const isDiag    = ri === ci;
      const bg        = isDiag
        ? `rgba(0,212,255,${0.1 + intensity * 0.7})`
        : `rgba(255,56,96,${intensity * 0.6})`;
      const textColor = intensity > 0.55 ? '#fff' : (isDiag ? '#00d4ff' : '#ff3860');
      container.insertAdjacentHTML('beforeend', `
        <div class="cm-cell" style="background:${bg};color:${textColor}" title="${classes[ri]} → ${classes[ci]}: ${val}">
          ${val > 999 ? (val/1000).toFixed(1)+'k' : val}
        </div>`);
    });
  });
}

// ── ROC Curve ────────────────────────────────────────────────────────────────
function renderROC() {
  const ctx = document.getElementById('chart-roc');
  destroyChart(an.rocChart);

  const datasets = [];
  // Diagonal baseline
  datasets.push({
    label: 'Random (AUC=0.5)', data: [{x:0,y:0},{x:1,y:1}],
    borderColor: '#3a5060', borderDash: [4,4], borderWidth: 1.5,
    pointRadius: 0, fill: false,
  });

  Object.entries(an.data.models).forEach(([name, model]) => {
    if (!model.roc) return;
    const pts = model.roc.fpr.map((f, i) => ({ x: f, y: model.roc.tpr[i] }));
    datasets.push({
      label: `${name} (AUC ${model.roc.auc.toFixed(3)})`,
      data: pts, borderColor: model.color, backgroundColor: model.color + '18',
      fill: name === an.selectedModel,
      tension: 0.3, pointRadius: 0, borderWidth: name === an.selectedModel ? 2.5 : 1.5,
    });
  });

  an.rocChart = new Chart(ctx, {
    type: 'scatter',
    data: { datasets },
    options: {
      ...CHART_DEFAULTS,
      showLine: true,
      plugins: { legend: { labels: { color: '#7f9ab5', font: { size: 11 }, boxWidth: 12 } } },
      scales: {
        x: { type: 'linear', min: 0, max: 1, title: { display: true, text: 'False Positive Rate', color: '#5a7a9a' }, ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { min: 0, max: 1, title: { display: true, text: 'True Positive Rate', color: '#5a7a9a' }, ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
      },
    },
  });
}

// ── Precision / Recall / F1 Bar Chart ────────────────────────────────────────
function renderPRF() {
  const ctx = document.getElementById('chart-prf');
  destroyChart(an.prfChart);

  const labels  = Object.keys(an.data.models);
  const mkDS = (label, key, color) => ({
    label, borderRadius: 5, borderWidth: 0, backgroundColor: color + 'cc',
    data: labels.map(n => +(an.data.models[n].metrics[key] * 100).toFixed(1)),
  });

  an.prfChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        mkDS('Precision', 'macro_precision', '#3d9cf5'),
        mkDS('Recall',    'macro_recall',    '#00e676'),
        mkDS('F1-Score',  'macro_f1',        '#a29bfe'),
      ],
    },
    options: {
      ...CHART_DEFAULTS,
      plugins: { legend: { labels: { color: '#7f9ab5', font: { size: 11 }, boxWidth: 12 } } },
      scales: {
        x: { ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { min: 0, max: 100, ticks: { color: '#4a6380', callback: v => v + '%' }, grid: { color: 'rgba(255,255,255,0.04)' } },
      },
    },
  });
}

// ── False Positive Rate comparison ───────────────────────────────────────────
function renderFPRComparison() {
  const ctx = document.getElementById('chart-fpr-compare');
  destroyChart(an.fprChart);

  const labels = Object.keys(an.data.models);
  const fprs   = labels.map(n => +(an.data.models[n].fp_stats.fpr * 100).toFixed(2));
  const colors = labels.map(n => (an.data.models[n].color || '#00d4ff') + 'cc');

  an.fprChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'False Positive Rate (%)',
        data: fprs, backgroundColor: colors, borderRadius: 5, borderWidth: 0,
      }],
    },
    options: {
      ...CHART_DEFAULTS,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#4a6380' }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { min: 0, ticks: { color: '#4a6380', callback: v => v + '%' }, grid: { color: 'rgba(255,255,255,0.04)' } },
      },
    },
  });
}

// ── Business Impact Grid ──────────────────────────────────────────────────────
function renderBusinessImpact() {
  const grid = document.getElementById('business-impact-grid');
  grid.innerHTML = '';

  const baseline = an.data.models['Rule-Based (Baseline)'];
  Object.entries(an.data.models).forEach(([name, model]) => {
    if (name === 'Rule-Based (Baseline)') return;
    const b     = model.business;
    const color = model.color || '#00d4ff';
    grid.insertAdjacentHTML('beforeend', `
      <div class="biz-card" style="--biz-color:${color}">
        <div class="biz-model-name">${esc(name)}</div>
        <div class="biz-metrics">
          <div class="biz-row">
            <span class="biz-key">FP Reduced</span>
            <span class="biz-val" style="color:${color}">${b.fp_reduced.toLocaleString()}</span>
          </div>
          <div class="biz-row">
            <span class="biz-key">Alert Load ↓</span>
            <span class="biz-val" style="color:${color}">${b.alert_load_reduction_pct}%</span>
          </div>
          <div class="biz-row">
            <span class="biz-key">Analyst Hours Saved</span>
            <span class="biz-val" style="color:${color}">${b.analyst_hours_saved}h</span>
          </div>
          <div class="biz-row">
            <span class="biz-key">Efficiency Gain</span>
            <span class="biz-val" style="color:${color}">${b.operational_efficiency_gain_pct}%</span>
          </div>
        </div>
      </div>`);
  });
}

// ── Per-class Table ───────────────────────────────────────────────────────────
function renderPerClassTable() {
  const tbody   = document.getElementById('per-class-tbody');
  tbody.innerHTML = '';
  const perClass = an.data.models[an.selectedModel].metrics.per_class;
  const classes  = an.data.classes;

  classes.forEach(cls => {
    const row = perClass[cls];
    if (!row) return;
    const f1val = +row['f1-score'];
    const barColor = f1val >= 0.8 ? '#00e676' : f1val >= 0.5 ? '#ff7043' : '#ff3860';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="ip-cell" style="color:#e8f0fe;background:rgba(255,255,255,.06);border-color:rgba(255,255,255,.1)">${esc(cls)}</span></td>
      <td>${pct(row.precision)}</td>
      <td>${pct(row.recall)}</td>
      <td>
        <div class="conf-bar-wrap">
          <div class="conf-bar-bg"><div class="conf-bar-fill" style="width:${(f1val*100).toFixed(0)}%;background:${barColor}"></div></div>
          ${pct(f1val)}
        </div>
      </td>
      <td>${row.support}</td>`;
    tbody.appendChild(tr);
  });
}
