/**
 * Admin Customer Deep-Dive Controller
 * Renders individual customer profile, payment identity, saved beneficiaries, and transaction history ledger.
 */

let currentTxDetailData = null;

document.addEventListener('DOMContentLoaded', async () => {
  // 1. Verify Admin Permissions
  const checkRes = await window.adminApi.checkAdmin();
  if (!checkRes || !checkRes.ok) {
    showToast('Unauthorized. Administrator privileges required.', 'error');
    setTimeout(() => {
      window.location.href = '/login?admin_required=1';
    }, 800);
    return;
  }

  // 2. Load Customer Data
  const customerId = window.CURRENT_CUSTOMER_ID;
  if (!customerId) {
    showToast('Invalid customer identifier.', 'error');
    return;
  }

  await loadCustomerProfileAndHistory(customerId);
});

async function loadCustomerProfileAndHistory(customerId) {
  const res = await window.adminApi.getCustomerDetail(customerId);
  if (!res || !res.ok || !res.data.customer) {
    showToast('Failed to load customer profile details.', 'error');
    return;
  }

  const cust = res.data.customer;
  const summary = res.data.summary || {};
  const txs = res.data.transactions || [];
  const beneficiaries = res.data.beneficiaries || [];

  // 1. Fill Profile Headers & Payment Identity
  const headerName = document.getElementById('cust-header-name');
  const accountIdEl = document.getElementById('cust-account-id-display');
  const nameEl = document.getElementById('cust-name-display');
  const upiEl = document.getElementById('cust-upi-display');
  const phoneEl = document.getElementById('cust-phone-display');
  const balanceEl = document.getElementById('cust-balance-display');
  const emailEl = document.getElementById('cust-email-display');
  const statusBadge = document.getElementById('cust-status-badge');

  const accId = cust.customer_account_id || `FS-${100000 + cust.id}`;
  const upiId = cust.primary_upi_id || `${cust.email.split('@')[0]}@fraudshield`;
  const phone = cust.phone_number || 'N/A';
  const balance = cust.account_balance !== undefined ? parseFloat(cust.account_balance) : 0;

  if (headerName) headerName.textContent = cust.name || `User #${cust.id}`;
  if (accountIdEl) accountIdEl.textContent = accId;
  if (nameEl) nameEl.textContent = cust.name;
  if (upiEl) upiEl.textContent = upiId;
  if (phoneEl) {
    phoneEl.innerHTML = `${phone}${cust.is_phone_verified ? ' <span style="color: #34D399; font-size: 0.75rem;">✓ Verified</span>' : ''}`;
  }
  if (balanceEl) {
    balanceEl.textContent = `₹${balance.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
  if (emailEl) emailEl.textContent = cust.email;

  if (statusBadge) {
    statusBadge.textContent = cust.is_active ? 'ACTIVE' : 'SUSPENDED';
    statusBadge.className = cust.is_active ? 'badge-risk badge-risk-low' : 'badge-risk badge-risk-high';
  }

  // 2. Fill Beneficiaries
  const bCountEl = document.getElementById('cust-b-count');
  const bListEl = document.getElementById('cust-beneficiaries-list');
  const bEmptyEl = document.getElementById('cust-beneficiaries-empty');

  if (bCountEl) bCountEl.textContent = beneficiaries.length;
  if (bListEl) {
    bListEl.innerHTML = '';
    if (beneficiaries.length === 0) {
      if (bEmptyEl) bEmptyEl.style.display = 'block';
    } else {
      if (bEmptyEl) bEmptyEl.style.display = 'none';
      beneficiaries.forEach((b) => {
        const item = document.createElement('div');
        item.className = 'glass-card';
        item.style.padding = '0.75rem 1rem';
        item.style.background = 'rgba(15, 23, 42, 0.5)';
        const nickStr = b.nickname ? ` <span style="color: var(--primary); font-size: 0.75rem;">(${b.nickname})</span>` : '';
        const phoneStr = b.beneficiary_phone ? `<div style="font-size: 0.75rem; color: var(--text-dim);">📞 ${b.beneficiary_phone}</div>` : '';

        item.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.25rem;">
            <div style="font-weight: 700; color: #fff; font-size: 0.9rem;">${b.beneficiary_name}${nickStr}</div>
            <span class="badge-risk badge-risk-low" style="font-size: 0.65rem; padding: 0.1rem 0.35rem;">Verified</span>
          </div>
          <div style="font-family: monospace; font-size: 0.8rem; color: var(--primary);">${b.beneficiary_upi_id}</div>
          ${phoneStr}
        `;
        bListEl.appendChild(item);
      });
    }
  }

  // 3. Fill KPI Summary Cards
  const totalTxEl = document.getElementById('summary-total-tx');
  const totalVolEl = document.getElementById('summary-total-vol');
  const approvedEl = document.getElementById('summary-approved-tx');
  const otpEl = document.getElementById('summary-otp-tx');
  const highRiskEl = document.getElementById('summary-highrisk-tx');
  const alertsEl = document.getElementById('summary-alerts-count');

  if (totalTxEl) totalTxEl.textContent = (summary.total_transactions || 0).toLocaleString();
  if (totalVolEl) totalVolEl.textContent = `₹${(summary.total_amount || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  if (approvedEl) approvedEl.textContent = (summary.approved_transactions || 0).toLocaleString();
  if (otpEl) otpEl.textContent = (summary.otp_transactions || 0).toLocaleString();
  if (highRiskEl) highRiskEl.textContent = (summary.high_risk_transactions || 0).toLocaleString();
  if (alertsEl) alertsEl.textContent = (summary.open_alerts_count || 0).toLocaleString();

  // 4. Fill Transactions Table
  const tbody = document.getElementById('customer-tx-tbody');
  const emptyState = document.getElementById('customer-tx-empty');

  if (!tbody) return;
  tbody.innerHTML = '';

  if (txs.length === 0) {
    if (emptyState) emptyState.style.display = 'block';
    return;
  }

  if (emptyState) emptyState.style.display = 'none';

  txs.forEach((t) => {
    const row = document.createElement('tr');
    const timeStr = t.created_at ? new Date(t.created_at).toLocaleString() : 'N/A';
    const riskBadge = `badge-risk badge-risk-${(t.risk_level || 'LOW').toLowerCase()}`;
    const statusBadge = `badge-risk badge-risk-${t.status === 'APPROVED' ? 'low' : (t.status === 'REJECTED' ? 'high' : 'medium')}`;

    const fraudProbPct = t.fraud_probability !== undefined && t.fraud_probability !== null 
      ? `${(t.fraud_probability * 100).toFixed(1)}%`
      : '0.0%';

    const destDisplay = t.destination_name ? `${t.destination_name} (${t.destination_upi_id || t.name_dest})` : (t.destination_upi_id || t.name_dest);
    const balanceAfterStr = t.balance_after !== null && t.balance_after !== undefined ? `₹${parseFloat(t.balance_after).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}` : '—';

    row.innerHTML = `
      <td style="font-weight: 700; color: #60A5FA;">#${t.id}</td>
      <td style="font-weight: 600; color: #fff;">${t.type}</td>
      <td style="font-weight: 700; color: #34D399;">₹${parseFloat(t.amount || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
      <td style="font-size: 0.85rem; color: #94A3B8;">${destDisplay}</td>
      <td style="font-family: monospace; font-size: 0.85rem; color: #34D399;">${balanceAfterStr}</td>
      <td style="color: #60A5FA; font-weight: 600;">${fraudProbPct}</td>
      <td style="color: #FBBF24; font-weight: 600;">${t.rule_score || 0}/100</td>
      <td style="font-weight: 700; color: #fff;">${t.risk_score || 0}/100</td>
      <td><span class="${riskBadge}">${t.risk_level}</span></td>
      <td><span class="${statusBadge}">${t.status}</span></td>
      <td style="font-size: 0.8rem; color: var(--text-dim);">${timeStr}</td>
      <td>
        <div style="display: flex; gap: 0.35rem;">
          <button class="btn-primary-custom" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" onclick="viewTxModal(${t.id})">
            Audit
          </button>
          <button class="btn-secondary-custom" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" onclick="openShapDirect(${t.id})">
            SHAP
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(row);
  });
}

// Modal Controllers
window.viewTxModal = async function(txId) {
  const res = await window.adminApi.getTransactionDetail(txId);
  if (!res || !res.ok || !res.data.transaction) {
    showToast('Failed to load transaction audit data.', 'error');
    return;
  }

  currentTxDetailData = res.data;
  const tx = res.data.transaction;
  const user = res.data.user || {};
  const alert = res.data.alert;

  document.getElementById('modal-tx-id').textContent = tx.id;
  document.getElementById('modal-user-name').textContent = user.name || 'Unknown';
  document.getElementById('modal-user-email').textContent = user.email || 'Unknown';
  document.getElementById('modal-user-id').textContent = user.customer_account_id || user.id || '--';

  document.getElementById('modal-tx-amount').textContent = `₹${parseFloat(tx.amount || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  document.getElementById('modal-tx-type').textContent = tx.type;
  document.getElementById('modal-tx-dest').textContent = tx.destination_upi_id || tx.name_dest;
  document.getElementById('modal-tx-time').textContent = tx.created_at ? new Date(tx.created_at).toLocaleString() : 'N/A';

  const probPct = tx.fraud_probability !== undefined && tx.fraud_probability !== null ? `${(tx.fraud_probability * 100).toFixed(1)}%` : '0.0%';
  document.getElementById('modal-ml-prob').textContent = probPct;
  document.getElementById('modal-rule-score').textContent = `${tx.rule_score || 0}/100`;
  document.getElementById('modal-final-score').textContent = `${tx.risk_score || 0}/100`;
  document.getElementById('modal-risk-tier-status').textContent = `${tx.risk_level} (${tx.status})`;
  document.getElementById('modal-tx-decision').textContent = tx.decision || '--';

  const narrativeText = (tx.explanation && tx.explanation.human_readable_summary) ? tx.explanation.human_readable_summary : 'Evaluation logged in security ledger.';
  document.getElementById('modal-narrative').textContent = narrativeText;

  const alertBox = document.getElementById('modal-alert-box');
  if (alert) {
    alertBox.style.display = 'block';
    document.getElementById('modal-alert-status').textContent = alert.status;
    document.getElementById('modal-alert-severity').textContent = alert.severity;
    document.getElementById('modal-alert-resolver').textContent = alert.resolved_by || 'Unresolved';
    document.getElementById('modal-alert-notes').textContent = alert.notes || 'No notes added.';
  } else {
    alertBox.style.display = 'none';
  }

  document.getElementById('tx-modal-overlay').classList.add('active');
};

window.closeTxModal = function() {
  document.getElementById('tx-modal-overlay').classList.remove('active');
};

window.openShapFromModal = function() {
  if (currentTxDetailData && currentTxDetailData.transaction) {
    const tx = currentTxDetailData.transaction;
    window.shapDrawer.open(tx.explanation || {}, tx.risk_score || 0, tx.risk_level || 'HIGH');
  }
};

window.openShapDirect = async function(txId) {
  const res = await window.adminApi.getTransactionDetail(txId);
  if (res && res.ok && res.data.transaction) {
    const tx = res.data.transaction;
    window.shapDrawer.open(tx.explanation || {}, tx.risk_score || 0, tx.risk_level || 'HIGH');
  } else {
    showToast('Failed to load transaction explanation.', 'error');
  }
};
