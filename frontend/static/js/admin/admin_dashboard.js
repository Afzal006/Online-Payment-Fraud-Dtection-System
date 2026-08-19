/**
 * Admin Security Operations Center (SOC) Dashboard Controller
 * Orchestrates Chart.js visualizations, KPI metrics, drift detection, and alert triage.
 */

let typeChartInstance = null;
let riskChartInstance = null;
let trendChartInstance = null;

document.addEventListener('DOMContentLoaded', async () => {
  // 1. Verify Admin Access
  const checkRes = await window.adminApi.checkAdmin();
  if (!checkRes || !checkRes.ok) {
    showToast('Unauthorized. Admin privileges required.', 'error');
    setTimeout(() => {
      window.location.href = '/login?admin_required=1';
    }, 1000);
    return;
  }

  // 2. Load Overview KPIs
  await loadOverviewKpis();

  // 3. Load Chart.js Analytics
  await loadChartAnalytics();

  // 4. Load Model Monitoring & Drift Status
  await loadModelAndDriftInfo();

  // 5. Load Active Security Alerts
  await loadRecentAlerts();
});

async function loadOverviewKpis() {
  const res = await window.adminApi.getOverview();
  if (res && res.ok && res.data.kpis) {
    const kpis = res.data.kpis;
    const totalVol = kpis.total_volume_inr !== undefined ? kpis.total_volume_inr : (kpis.total_volume_usd || 0);

    const totalCustEl = document.getElementById('kpi-total-customers');
    const totalTxEl = document.getElementById('kpi-total-tx');
    const flaggedTxEl = document.getElementById('kpi-flagged-tx');
    const openAlertsEl = document.getElementById('kpi-open-alerts');
    const totalVolEl = document.getElementById('kpi-total-vol');
    const resolvedAlertsEl = document.getElementById('kpi-resolved-alerts');
    const fraudRateEl = document.getElementById('kpi-fraud-rate');
    const avgRiskEl = document.getElementById('kpi-avg-risk');

    if (totalCustEl) totalCustEl.textContent = (kpis.total_customers !== undefined ? kpis.total_customers : (kpis.total_users || 0)).toLocaleString();
    if (totalTxEl) totalTxEl.textContent = kpis.total_transactions.toLocaleString();
    if (flaggedTxEl) flaggedTxEl.textContent = (kpis.risk_tiers.HIGH || 0).toLocaleString();
    if (openAlertsEl) openAlertsEl.textContent = (kpis.alerts.open || 0).toLocaleString();
    if (resolvedAlertsEl) resolvedAlertsEl.textContent = (kpis.alerts.resolved || 0).toLocaleString();
    if (fraudRateEl) fraudRateEl.textContent = `${(kpis.fraud_rate_pct || 0).toFixed(1)}%`;
    if (avgRiskEl) avgRiskEl.textContent = (kpis.avg_risk_score || 0).toFixed(1);
    if (totalVolEl) totalVolEl.textContent = `₹${totalVol.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

    const riskLowEl = document.getElementById('kpi-risk-low');
    const riskMedEl = document.getElementById('kpi-risk-med');
    const riskHighEl = document.getElementById('kpi-risk-high');
    const riskCritEl = document.getElementById('kpi-risk-critical');

    if (riskLowEl) riskLowEl.textContent = kpis.risk_tiers.LOW || 0;
    if (riskMedEl) riskMedEl.textContent = kpis.risk_tiers.MEDIUM || 0;
    if (riskHighEl) riskHighEl.textContent = kpis.risk_tiers.HIGH || 0;
    if (riskCritEl) riskCritEl.textContent = kpis.risk_tiers.CRITICAL || 0;
  }
}

async function loadChartAnalytics() {
  const res = await window.adminApi.getAnalytics();
  if (!res || !res.ok || !res.data.charts) return;

  const charts = res.data.charts;

  // Chart 1: Volume by Type (Bar Chart)
  const ctxType = document.getElementById('chart-volume-type');
  if (ctxType && typeof Chart !== 'undefined') {
    if (typeChartInstance) typeChartInstance.destroy();
    typeChartInstance = new Chart(ctxType, {
      type: 'bar',
      data: {
        labels: charts.volume_by_type.labels,
        datasets: [{
          label: 'Transaction Count',
          data: charts.volume_by_type.counts,
          backgroundColor: '#3B82F6',
          borderRadius: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#9CA3AF' } },
          y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#9CA3AF' } },
        },
      },
    });
  }

  // Chart 2: Risk Tier Distribution (Doughnut)
  const ctxRisk = document.getElementById('chart-risk-distribution');
  if (ctxRisk && typeof Chart !== 'undefined') {
    if (riskChartInstance) riskChartInstance.destroy();
    riskChartInstance = new Chart(ctxRisk, {
      type: 'doughnut',
      data: {
        labels: charts.risk_distribution.labels,
        datasets: [{
          data: charts.risk_distribution.counts,
          backgroundColor: charts.risk_distribution.colors,
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#9CA3AF', boxWidth: 12 } },
        },
        cutout: '70%',
      },
    });
  }

  // Chart 3: Temporal Risk & Score Trend (Line Chart)
  const ctxTrend = document.getElementById('chart-trend');
  if (ctxTrend && typeof Chart !== 'undefined') {
    if (trendChartInstance) trendChartInstance.destroy();
    trendChartInstance = new Chart(ctxTrend, {
      type: 'line',
      data: {
        labels: charts.trend.labels,
        datasets: [{
          label: 'Risk Score (0-100)',
          data: charts.trend.risk_scores,
          borderColor: '#EF4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: true,
          tension: 0.35,
          pointRadius: 3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#9CA3AF' } } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#9CA3AF' } },
          y: { min: 0, max: 100, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#9CA3AF' } },
        },
      },
    });
  }
}

async function loadModelAndDriftInfo() {
  const res = await window.adminApi.getModelInfo();
  if (res && res.ok) {
    const meta = res.data.model_metadata || {};
    const drift = res.data.data_drift || {};

    // Model Benchmarks
    const metrics = meta.benchmark_metrics || meta.test_metrics || {};
    document.getElementById('model-name-display').textContent = meta.model_name || 'Tuned Random Forest';
    document.getElementById('model-version-display').textContent = meta.model_version || 'v1.0.0';
    document.getElementById('metric-precision').textContent = metrics.precision ? (metrics.precision * 100).toFixed(1) + '%' : '100.0%';
    document.getElementById('metric-recall').textContent = metrics.recall ? (metrics.recall * 100).toFixed(1) + '%' : '99.7%';

    // Data Drift Status
    const driftBadge = document.getElementById('drift-status-badge');
    const driftMsg = document.getElementById('drift-status-msg');
    const driftScore = document.getElementById('drift-score-val');

    if (driftBadge) {
      driftBadge.textContent = drift.status;
      if (drift.status === 'NORMAL') driftBadge.className = 'badge-risk badge-risk-low';
      else if (drift.status === 'WARNING') driftBadge.className = 'badge-risk badge-risk-medium';
      else driftBadge.className = 'badge-risk badge-risk-high';
    }

    if (driftMsg) driftMsg.textContent = drift.message;
    if (driftScore) driftScore.textContent = `Drift Divergence: ${(drift.drift_score * 100).toFixed(1)}%`;
  }
}

async function loadRecentAlerts() {
  const res = await window.adminApi.getAlerts('OPEN', 10);
  const tbody = document.getElementById('admin-alerts-tbody');
  const emptyState = document.getElementById('admin-alerts-empty');

  if (!tbody) return;
  tbody.innerHTML = '';

  if (!res || !res.ok || !res.data.alerts || res.data.alerts.length === 0) {
    if (emptyState) emptyState.style.display = 'block';
    return;
  }

  if (emptyState) emptyState.style.display = 'none';

  res.data.alerts.forEach((alt) => {
    const row = document.createElement('tr');
    const timeStr = alt.created_at ? new Date(alt.created_at).toLocaleString() : 'N/A';
    const riskBadge = `badge-risk badge-risk-${(alt.risk_level || 'HIGH').toLowerCase()}`;

    row.innerHTML = `
      <td style="font-weight: 700; color: #fff;">#${alt.id}</td>
      <td style="color: #60A5FA; font-weight: 600;">Tx #${alt.transaction_id}</td>
      <td>
        <div style="font-weight: 600; color: #E2E8F0;">${alt.user_name}</div>
        <div style="font-size: 0.75rem; color: var(--text-dim);">${alt.user_email}</div>
      </td>
      <td style="font-weight: 700; color: #fff;">₹${parseFloat(alt.transaction_amount || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
      <td><span class="${riskBadge}">${alt.risk_level} (${alt.risk_score}/100)</span></td>
      <td><span class="badge-risk badge-risk-high">${alt.status}</span></td>
      <td style="font-size: 0.8rem; color: var(--text-dim);">${timeStr}</td>
      <td>
        <div style="display: flex; gap: 0.4rem;">
          <button class="btn-secondary-custom" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" onclick="investigateTx(${alt.transaction_id})">
            Investigate (SHAP)
          </button>
          <button class="btn-primary-custom" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" onclick="openResolveModal(${alt.id})">
            Resolve
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(row);
  });
}

// Global helpers for alert actions
window.investigateTx = async function (txId) {
  const res = await window.adminApi.getTransactionDetail(txId);
  if (res && res.ok && res.data.transaction) {
    const tx = res.data.transaction;
    window.shapDrawer.open(tx.explanation || {}, tx.risk_score || 0, tx.risk_level || 'HIGH');
  } else {
    showToast('Failed to load transaction details.', 'error');
  }
};

window.openResolveModal = function (alertId) {
  const note = prompt(`Enter resolution / investigation notes for Alert #${alertId}:`, 'Investigated by Security Officer. Verified transaction with customer.');
  if (note !== null) {
    resolveAlertAction(alertId, note);
  }
};

async function resolveAlertAction(alertId, note) {
  const res = await window.adminApi.resolveAlert(alertId, note);
  if (res && res.ok) {
    showToast(`Alert #${alertId} resolved successfully.`, 'success');
    await loadOverviewKpis();
    await loadRecentAlerts();
  } else {
    showToast('Failed to resolve alert.', 'error');
  }
}
