const riskColors = {
  Critical: '#fb4f5b',
  High: '#ef4444',
  Medium: '#f59e0b',
  Low: '#eab308',
  Info: '#3b82f6'
};

let currentAlerts = [];

async function loadStatus() {
  try {
    const response = await fetch('/api/status');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    document.getElementById('monitoring-status').textContent = data.monitoring ? 'Active' : 'Inactive';
    document.getElementById('monitoring-status').className = `status-indicator ${data.monitoring ? 'is-active' : 'is-inactive'}`;
    document.getElementById('watch-paths').textContent = data.paths || 'Not configured';

    const componentList = document.getElementById('component-list');
    const components = data.components || {};
    const componentNames = {
      filesystem: 'File monitoring',
      processes: 'Process monitoring',
      periodic_scans: 'Periodic scans',
      registry: 'Registry monitoring',
      anomaly_detection: 'Anomaly detection'
    };
    componentList.replaceChildren();
    Object.entries(componentNames).forEach(([key, label]) => {
      const item = document.createElement('li');
      const dot = document.createElement('span');
      dot.className = `component-dot ${components[key] ? 'online' : ''}`;
      item.append(dot, document.createTextNode(`${label}: ${components[key] ? 'Running' : 'Stopped'}`));
      componentList.appendChild(item);
    });
    const scanInfo = document.createElement('li');
    scanInfo.textContent = `Scans: ${components.scan_count || 0}; last scan: ${components.last_scan || 'not yet run'}; files inspected: ${components.last_scan_files || 0}`;
    componentList.appendChild(scanInfo);
    const baselineInfo = document.createElement('li');
    baselineInfo.textContent = `Baseline relationships: ${components.baseline_relationships || 0}`;
    componentList.appendChild(baselineInfo);

    currentAlerts = data.activities || [];
    renderAlerts(currentAlerts);
    renderRiskChart(currentAlerts);
    renderTimeline(currentAlerts);
  } catch (error) {
    console.error('Failed to load status', error);
    document.getElementById('activity-table-body').innerHTML = '<tr><td colspan="7" class="empty-state">Unable to load status.</td></tr>';
  }
}

function getRisk(alert) {
  const score = Number(alert.risk_score) || 0;
  const severity = alert.severity || (score >= 80 ? 'Critical' : score >= 60 ? 'High' : score >= 30 ? 'Medium' : 'Low');
  return { score, severity, color: score === 0 && alert.alert_type === 'Info' ? riskColors.Info : riskColors[severity] || riskColors.Info };
}

function renderAlerts(alerts) {
  const tableBody = document.getElementById('activity-table-body');
  const newestFirst = alerts.slice().reverse();
  document.getElementById('alert-count').textContent = `${alerts.length} ${alerts.length === 1 ? 'alert' : 'alerts'}`;
  tableBody.replaceChildren();

  if (!newestFirst.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 7;
    cell.className = 'empty-state';
    cell.textContent = 'No security alerts recorded.';
    row.appendChild(cell);
    tableBody.appendChild(row);
    return;
  }

  newestFirst.forEach(alert => {
    const row = document.createElement('tr');
    row.className = 'alert-row';
    row.tabIndex = 0;
    const risk = getRisk(alert);
    const values = [
      alert.timestamp || '—',
      alert.process_name || extractProcessName(alert.message) || 'System',
      alert.pid ?? '—',
      alert.parent_pid ?? '—',
      null,
      (alert.yara_rules || []).join(', ') || '—',
      alert.action_taken || 'Detected'
    ];
    values.forEach((value, index) => {
      const cell = document.createElement('td');
      if (index === 4) {
        const badge = document.createElement('span');
        badge.className = `risk-badge risk-${risk.severity.toLowerCase()}`;
        badge.style.setProperty('--risk-color', risk.color);
        badge.textContent = `${risk.score} · ${risk.severity}`;
        cell.appendChild(badge);
      } else {
        cell.textContent = value;
        if (index === 5) cell.className = 'yara-cell';
      }
      row.appendChild(cell);
    });
    row.addEventListener('click', () => showDetails(alert));
    row.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        showDetails(alert);
      }
    });
    tableBody.appendChild(row);
  });
}

function extractProcessName(message = '') {
  const match = message.match(/SUSPICIOUS PROCESS:\s*([^\s(]+)/i) || message.match(/SUSPICIOUS FILE [^:]+:\s*([^ ]+)/i);
  return match ? match[1].split(/[\\/]/).pop() : '';
}

function showDetails(alert) {
  const sidebar = document.getElementById('details-sidebar');
  const backdrop = document.getElementById('details-backdrop');
  const content = document.getElementById('detail-content');
  const risk = getRisk(alert);
  document.getElementById('detail-title').textContent = alert.process_name || extractProcessName(alert.message) || 'Security alert';
  content.replaceChildren();

  const riskPanel = document.createElement('div');
  riskPanel.className = 'detail-risk';
  riskPanel.style.setProperty('--risk-color', risk.color);
  riskPanel.textContent = `${risk.score}/100 · ${risk.severity} severity`;
  content.appendChild(riskPanel);

  const fields = [
    ['Timestamp', alert.timestamp],
    ['Process name', alert.process_name || extractProcessName(alert.message)],
    ['PID', alert.pid],
    ['Parent PID', alert.parent_pid],
    ['Process path', alert.process_path],
    ['Command line', alert.command_line],
    ['YARA rule(s)', (alert.yara_rules || []).join(', ')],
    ['Action taken', alert.action_taken],
    ['Alert message', alert.message]
  ];
  fields.forEach(([label, value]) => {
    const section = document.createElement('section');
    section.className = 'detail-field';
    const heading = document.createElement('h3');
    heading.textContent = label;
    const text = document.createElement('p');
    text.textContent = value === null || value === undefined || value === '' ? 'Not available' : String(value);
    section.append(heading, text);
    content.appendChild(section);
  });

  const details = alert.details || {};
  if (details.risk_factors?.length) addDetailField(content, 'Risk factors', details.risk_factors.join(', '));
  if (details.indicators?.length) addDetailField(content, 'Indicators', details.indicators.join('; '));
  if (details.apk) addDetailField(content, 'APK metadata', JSON.stringify(details.apk, null, 2));

  sidebar.classList.add('open');
  sidebar.setAttribute('aria-hidden', 'false');
  backdrop.hidden = false;
}

function addDetailField(parent, label, value) {
  const section = document.createElement('section');
  section.className = 'detail-field';
  const heading = document.createElement('h3');
  heading.textContent = label;
  const text = document.createElement('pre');
  text.textContent = value;
  section.append(heading, text);
  parent.appendChild(section);
}

function closeDetails() {
  document.getElementById('details-sidebar').classList.remove('open');
  document.getElementById('details-sidebar').setAttribute('aria-hidden', 'true');
  document.getElementById('details-backdrop').hidden = true;
}

function renderRiskChart(alerts) {
  const canvas = document.getElementById('risk-chart');
  const ctx = prepareCanvas(canvas);
  const categories = [
    { label: 'Critical', color: riskColors.Critical, count: 0 },
    { label: 'High', color: riskColors.High, count: 0 },
    { label: 'Medium', color: riskColors.Medium, count: 0 },
    { label: 'Low', color: riskColors.Low, count: 0 },
    { label: 'Info', color: riskColors.Info, count: 0 }
  ];
  alerts.forEach(alert => {
    const { score } = getRisk(alert);
    const category = score === 0 && alert.alert_type === 'Info'
      ? 'Info'
      : score >= 80 ? 'Critical' : score >= 60 ? 'High' : score >= 30 ? 'Medium' : 'Low';
    categories.find(item => item.label === category).count += 1;
  });

  const total = alerts.length;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) * 0.38;
  let angle = -Math.PI / 2;
  if (total) {
    categories.forEach(item => {
      if (!item.count) return;
      const nextAngle = angle + (item.count / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, angle, nextAngle);
      ctx.arc(centerX, centerY, radius * 0.62, nextAngle, angle, true);
      ctx.closePath();
      ctx.fillStyle = item.color;
      ctx.fill();
      angle = nextAngle;
    });
  } else {
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.arc(centerX, centerY, radius * 0.62, Math.PI * 2, 0, true);
    ctx.closePath();
    ctx.fillStyle = '#253149';
    ctx.fill();
  }
  ctx.fillStyle = '#e2e8f0';
  ctx.font = '600 22px Arial';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(String(total), centerX, centerY - 7);
  ctx.fillStyle = '#94a3b8';
  ctx.font = '12px Arial';
  ctx.fillText('alerts', centerX, centerY + 13);

  const legend = document.getElementById('risk-legend');
  legend.replaceChildren();
  categories.forEach(item => {
    const entry = document.createElement('span');
    entry.className = 'legend-item';
    const dot = document.createElement('i');
    dot.style.backgroundColor = item.color;
    entry.append(dot, document.createTextNode(`${item.label} ${total ? Math.round(item.count * 100 / total) : 0}%`));
    legend.appendChild(entry);
  });
}

function renderTimeline(alerts) {
  const canvas = document.getElementById('timeline-chart');
  const ctx = prepareCanvas(canvas);
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  const now = new Date();
  const start = new Date(now);
  start.setMinutes(0, 0, 0);
  start.setHours(start.getHours() - 23);
  const buckets = Array(24).fill(0);
  alerts.forEach(alert => {
    const timestamp = new Date((alert.timestamp || '').replace(' ', 'T'));
    const index = Math.floor((timestamp - start) / 3600000);
    if (!Number.isNaN(timestamp.getTime()) && index >= 0 && index < 24) buckets[index] += 1;
  });

  const pad = { top: 18, right: 12, bottom: 30, left: 30 };
  const chartWidth = width - pad.left - pad.right;
  const chartHeight = height - pad.top - pad.bottom;
  const maxValue = Math.max(4, Math.ceil(Math.max(...buckets) / 4) * 4);
  ctx.font = '10px Arial';
  ctx.textAlign = 'right';
  for (let line = 0; line <= 4; line += 1) {
    const y = pad.top + chartHeight * line / 4;
    ctx.strokeStyle = '#263247';
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    ctx.fillStyle = '#94a3b8';
    ctx.fillText(String(Math.round(maxValue * (4 - line) / 4)), pad.left - 7, y + 3);
  }

  const points = buckets.map((value, index) => ({
    x: pad.left + chartWidth * index / (buckets.length - 1),
    y: pad.top + chartHeight - value / maxValue * chartHeight
  }));
  const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartHeight);
  gradient.addColorStop(0, 'rgba(59,130,246,0.3)');
  gradient.addColorStop(1, 'rgba(59,130,246,0)');
  ctx.beginPath();
  ctx.moveTo(points[0].x, pad.top + chartHeight);
  points.forEach(point => ctx.lineTo(point.x, point.y));
  ctx.lineTo(points[points.length - 1].x, pad.top + chartHeight);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();
  ctx.beginPath();
  points.forEach((point, index) => index ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y));
  ctx.strokeStyle = '#60a5fa';
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.fillStyle = '#94a3b8';
  ctx.textAlign = 'center';
  [0, 6, 12, 18, 23].forEach(index => {
    ctx.fillText(`${String((start.getHours() + index) % 24).padStart(2, '0')}:00`, points[index].x, height - 8);
  });
}

function prepareCanvas(canvas) {
  const ctx = canvas.getContext('2d');
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  ctx.scale(ratio, ratio);
  return ctx;
}

function downloadExport(format) {
  const records = currentAlerts.map(alert => ({
    timestamp: alert.timestamp || '',
    process_name: alert.process_name || extractProcessName(alert.message),
    pid: alert.pid ?? '',
    parent_pid: alert.parent_pid ?? '',
    risk_score: Number(alert.risk_score) || 0,
    severity: getRisk(alert).severity,
    yara_rules: alert.yara_rules || [],
    action_taken: alert.action_taken || 'Detected',
    process_path: alert.process_path || '',
    command_line: alert.command_line || '',
    message: alert.message || '',
    details: alert.details || {}
  }));
  let content;
  let mimeType;
  let extension;
  if (format === 'csv') {
    const columns = ['timestamp', 'process_name', 'pid', 'parent_pid', 'risk_score', 'severity', 'yara_rules', 'action_taken', 'process_path', 'command_line', 'message'];
    const escapeCsv = value => `"${String(value ?? '').replace(/"/g, '""')}"`;
    content = [columns.join(','), ...records.map(record => columns.map(column =>
      escapeCsv(Array.isArray(record[column]) ? record[column].join('; ') : record[column])
    ).join(','))].join('\r\n');
    mimeType = 'text/csv;charset=utf-8';
    extension = 'csv';
  } else {
    content = JSON.stringify(records, null, 2);
    mimeType = 'application/json';
    extension = 'json';
  }
  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `hids-alerts-${new Date().toISOString().replace(/[:.]/g, '-')}.${extension}`;
  link.click();
  URL.revokeObjectURL(url);
}

async function postAction(endpoint) {
  try {
    const response = await fetch(endpoint, { method: 'POST' });
    const result = await response.json();
    if (!response.ok || !result.success) throw new Error(result.message || 'Request failed');
    await loadStatus();
  } catch (error) {
    window.alert(error.message || 'Request failed');
  }
}

document.getElementById('start-btn').addEventListener('click', () => postAction('/api/start'));
document.getElementById('stop-btn').addEventListener('click', () => postAction('/api/stop'));
document.getElementById('clear-btn').addEventListener('click', () => postAction('/api/clear'));
document.getElementById('export-json-btn').addEventListener('click', () => downloadExport('json'));
document.getElementById('export-csv-btn').addEventListener('click', () => downloadExport('csv'));
document.getElementById('close-details-btn').addEventListener('click', closeDetails);
document.getElementById('details-backdrop').addEventListener('click', closeDetails);
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') closeDetails();
});
window.addEventListener('resize', () => {
  renderRiskChart(currentAlerts);
  renderTimeline(currentAlerts);
});

loadStatus();
setInterval(loadStatus, 2000);
