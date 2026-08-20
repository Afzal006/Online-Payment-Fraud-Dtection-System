/**
 * Customer Dashboard Controller: Payment Identity, Beneficiaries, & Live Ledger
 */

document.addEventListener('DOMContentLoaded', async () => {
  if (!window.api.isAuthenticated()) {
    window.location.href = '/login';
    return;
  }

  // Role guard: redirect admin to SOC dashboard
  const user = window.api.getUser();
  if (user && user.role === 'ADMIN') {
    window.location.href = '/admin/dashboard';
    return;
  }

  await loadCustomerProfile();
  await loadBeneficiaries();
  await loadRecentTransactions();
  setupBeneficiaryForm();
});

let currentBeneficiaries = [];

async function loadCustomerProfile() {
  const res = await window.api.getProfile();
  if (res && res.ok && res.data && res.data.profile) {
    const p = res.data.profile;
    document.getElementById('user-display-name').textContent = p.name || 'Account Holder';
    document.getElementById('prof-name').textContent = p.name || 'Customer';
    document.getElementById('prof-account-id').textContent = p.customer_account_id || `FS-${100000 + p.id}`;
    document.getElementById('prof-upi-id').textContent = p.primary_upi_id || `${p.email.split('@')[0]}@fraudshield`;
    document.getElementById('prof-phone').textContent = p.phone_number || '+91 98765 00000';
    
    const balance = parseFloat(p.account_balance || 0);
    document.getElementById('prof-balance').textContent = `₹${balance.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

    const pinStatusEl = document.getElementById('prof-pin-status');
    const pinBadgeEl = document.getElementById('prof-pin-badge');
    const pinBtnEl = document.getElementById('btn-manage-pin');

    if (pinStatusEl && pinBadgeEl) {
      if (p.is_pin_set) {
        pinStatusEl.textContent = 'Configured (••••)';
        pinBadgeEl.className = 'badge-risk badge-risk-low';
        pinBadgeEl.textContent = '✓ Active';
        if (pinBtnEl) pinBtnEl.textContent = 'Change';
      } else {
        pinStatusEl.textContent = 'Not Set';
        pinBadgeEl.className = 'badge-risk badge-risk-high';
        pinBadgeEl.textContent = '⚠️ Required';
        if (pinBtnEl) pinBtnEl.textContent = 'Set PIN';
      }
    }
  }
}

async function loadBeneficiaries() {
  const res = await window.api.getBeneficiaries();
  const grid = document.getElementById('beneficiaries-grid');
  const empty = document.getElementById('beneficiaries-empty');
  if (!grid) return;

  grid.innerHTML = '';
  if (res && res.ok && res.data && Array.isArray(res.data.beneficiaries)) {
    currentBeneficiaries = res.data.beneficiaries;
    if (currentBeneficiaries.length === 0) {
      if (empty) empty.style.display = 'block';
      return;
    }
    if (empty) empty.style.display = 'none';

    currentBeneficiaries.forEach((b) => {
      const card = document.createElement('div');
      card.className = 'glass-card';
      card.style.padding = '1rem';
      card.style.background = 'rgba(30, 41, 59, 0.45)';
      card.style.display = 'flex';
      card.style.flexDirection = 'column';
      card.style.justifyContent = 'space-between';

      const nickTag = b.nickname ? `<span style="font-size: 0.7rem; color: var(--primary); background: rgba(59, 130, 246, 0.15); padding: 0.15rem 0.4rem; border-radius: 4px; margin-left: 0.35rem;">${b.nickname}</span>` : '';

      card.innerHTML = `
        <div>
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
            <div style="font-weight: 700; color: #fff; font-size: 1rem;">
              ${b.beneficiary_name} ${nickTag}
            </div>
            <span class="badge-risk badge-risk-low" style="font-size: 0.65rem; padding: 0.15rem 0.4rem;">✓ Verified</span>
          </div>
          <div style="font-size: 0.8rem; color: var(--primary); font-family: monospace; margin-bottom: 0.25rem;">
            ${b.beneficiary_upi_id}
          </div>
          <div style="font-size: 0.75rem; color: var(--text-dim); margin-bottom: 0.75rem;">
            ${b.beneficiary_phone ? `📞 ${b.beneficiary_phone}` : ''}
          </div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 0.75rem; margin-top: 0.5rem;">
          <a href="/payment?b=${b.id}" class="btn-primary-custom" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;">
            ⚡ Pay Now
          </a>
          <div style="display: flex; gap: 0.4rem;">
            <button type="button" class="btn-secondary-custom" style="padding: 0.35rem 0.6rem; font-size: 0.75rem;" onclick="openEditBeneficiaryModal(${b.id})">
              ✏️
            </button>
            <button type="button" class="btn-secondary-custom" style="padding: 0.35rem 0.6rem; font-size: 0.75rem; color: #F87171;" onclick="deleteBeneficiaryRecord(${b.id})">
              🗑️
            </button>
          </div>
        </div>
      `;
      grid.appendChild(card);
    });
  }
}

async function loadRecentTransactions() {
  const res = await window.api.getMyTransactions(10);
  if (res && res.ok && res.data.transactions) {
    const txs = res.data.transactions;
    document.getElementById('dash-total-tx').textContent = txs.length;

    const approved = txs.filter(t => t.status === 'APPROVED' || t.status === 'VERIFIED').length;
    const review = txs.filter(t => t.status === 'UNDER_REVIEW' || t.status === 'OTP_REQUIRED' || t.status === 'VERIFIED_PENDING_REVIEW').length;

    document.getElementById('dash-approved-tx').textContent = approved;
    document.getElementById('dash-review-tx').textContent = review;

    const tbody = document.getElementById('dash-recent-tx-tbody');
    const emptyState = document.getElementById('dash-tx-empty');

    if (txs.length === 0) {
      if (emptyState) emptyState.style.display = 'block';
      return;
    }

    if (emptyState) emptyState.style.display = 'none';

    tbody.innerHTML = '';
    txs.slice(0, 8).forEach((tx) => {
      const row = document.createElement('tr');
      const timeStr = tx.created_at ? new Date(tx.created_at).toLocaleString() : 'N/A';
      const riskBadge = `badge-risk badge-risk-${(tx.risk_level || 'LOW').toLowerCase()}`;
      const recipientName = tx.destination_name ? `${tx.destination_name} (${tx.destination_upi_id || tx.name_dest})` : (tx.destination_upi_id || tx.name_dest || 'N/A');
      const balanceAfterStr = tx.balance_after !== null && tx.balance_after !== undefined ? `₹${parseFloat(tx.balance_after).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}` : '—';

      row.innerHTML = `
        <td style="font-weight: 700; color: #fff;">#${tx.id}</td>
        <td><span style="font-weight: 600;">${tx.type}</span></td>
        <td style="font-weight: 700; color: #fff;">₹${parseFloat(tx.amount).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
        <td style="color: var(--text-muted); font-size: 0.85rem;">${recipientName}</td>
        <td style="font-family: monospace; font-size: 0.85rem; color: #34D399;">${balanceAfterStr}</td>
        <td><span class="${riskBadge}">${tx.risk_level} (${tx.risk_score}/100)</span></td>
        <td>
          <span style="font-weight: 600; color: ${tx.status === 'APPROVED' ? '#34D399' : (tx.status === 'REJECTED' ? '#F87171' : '#FBBF24')};">
            ${tx.status.replace(/_/g, ' ')}
          </span>
        </td>
        <td style="font-size: 0.8rem; color: var(--text-dim);">${timeStr}</td>
        <td>
          <button class="btn-secondary-custom" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" onclick="viewShapForTx(${tx.id})">
            Explain AI
          </button>
        </td>
      `;
      tbody.appendChild(row);
    });
  }
}

function openAddBeneficiaryModal() {
  const modal = document.getElementById('beneficiary-modal-overlay');
  document.getElementById('beneficiary-modal-title').textContent = 'Add New Beneficiary';
  document.getElementById('modal-b-id').value = '';
  document.getElementById('modal-b-name').value = '';
  document.getElementById('modal-b-upi').value = '';
  document.getElementById('modal-b-phone').value = '';
  document.getElementById('modal-b-nick').value = '';
  document.getElementById('beneficiary-modal-error').style.display = 'none';
  if (modal) modal.style.display = 'flex';
}

function openEditBeneficiaryModal(id) {
  const b = currentBeneficiaries.find(item => item.id === id);
  if (!b) return;

  const modal = document.getElementById('beneficiary-modal-overlay');
  document.getElementById('beneficiary-modal-title').textContent = 'Edit Beneficiary';
  document.getElementById('modal-b-id').value = b.id;
  document.getElementById('modal-b-name').value = b.beneficiary_name || '';
  document.getElementById('modal-b-upi').value = b.beneficiary_upi_id || '';
  document.getElementById('modal-b-phone').value = b.beneficiary_phone || '';
  document.getElementById('modal-b-nick').value = b.nickname || '';
  document.getElementById('beneficiary-modal-error').style.display = 'none';
  if (modal) modal.style.display = 'flex';
}

function closeBeneficiaryModal() {
  const modal = document.getElementById('beneficiary-modal-overlay');
  if (modal) modal.style.display = 'none';
}

function setupBeneficiaryForm() {
  const form = document.getElementById('beneficiary-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('modal-b-id').value;
    const name = document.getElementById('modal-b-name').value.trim();
    const upi = document.getElementById('modal-b-upi').value.trim();
    const phone = document.getElementById('modal-b-phone').value.trim();
    const nick = document.getElementById('modal-b-nick').value.trim();
    const errBox = document.getElementById('beneficiary-modal-error');
    const saveBtn = document.getElementById('btn-save-beneficiary');

    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';
    errBox.style.display = 'none';

    const payload = {
      beneficiary_name: name,
      beneficiary_upi_id: upi,
      beneficiary_phone: phone || null,
      nickname: nick || null,
    };

    let res;
    if (id) {
      res = await window.api.updateBeneficiary(id, payload);
    } else {
      res = await window.api.addBeneficiary(payload);
    }

    saveBtn.disabled = false;
    saveBtn.textContent = 'Save Beneficiary';

    if (res && res.ok && res.data.success) {
      showToast(id ? 'Beneficiary updated successfully!' : 'Beneficiary added successfully!', 'success');
      closeBeneficiaryModal();
      await loadBeneficiaries();
    } else {
      const msg = (res && res.data && res.data.error) || 'Failed to save beneficiary.';
      errBox.textContent = msg;
      errBox.style.display = 'block';
    }
  });
}

async function deleteBeneficiaryRecord(id) {
  if (!confirm('Are you sure you want to remove this saved beneficiary?')) return;

  const res = await window.api.deleteBeneficiary(id);
  if (res && res.ok && res.data.success) {
    showToast('Beneficiary removed.', 'success');
    await loadBeneficiaries();
  } else {
    showToast((res && res.data && res.data.error) || 'Failed to delete beneficiary.', 'error');
  }
}

async function viewShapForTx(txId) {
  const res = await window.api.getTransactionDetail(txId);
  if (res && res.ok && res.data) {
    window.shapDrawer.open(
      res.data.explanation || {},
      res.data.risk_score || 0,
      res.data.risk_level || 'LOW'
    );
  } else {
    showToast('Failed to load transaction details.', 'error');
  }
}

// ==========================================
// Payment PIN Setup Modal Handlers
// ==========================================

function openPinSetupModal() {
  const modal = document.getElementById('pin-setup-modal-overlay');
  const errBanner = document.getElementById('pin-setup-error-banner');
  const form = document.getElementById('pin-setup-form');
  if (errBanner) errBanner.style.display = 'none';
  if (form) form.reset();
  if (modal) modal.style.display = 'flex';
}

function closePinSetupModal() {
  const modal = document.getElementById('pin-setup-modal-overlay');
  if (modal) modal.style.display = 'none';
}

async function handlePinSetupSubmit(e) {
  e.preventDefault();
  const password = document.getElementById('pin-account-password').value;
  const pin = document.getElementById('new-pin-input').value.trim();
  const confirmPin = document.getElementById('confirm-pin-input').value.trim();
  const errBanner = document.getElementById('pin-setup-error-banner');
  const submitBtn = document.getElementById('btn-save-pin');

  if (!/^\d{4,6}$/.test(pin)) {
    if (errBanner) {
      errBanner.textContent = 'Payment PIN must be exactly 4 to 6 numeric digits (0-9).';
      errBanner.style.display = 'block';
    }
    return;
  }

  if (pin !== confirmPin) {
    if (errBanner) {
      errBanner.textContent = 'Payment PIN and Confirm PIN do not match.';
      errBanner.style.display = 'block';
    }
    return;
  }

  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span>Securing Payment PIN...</span>';

  const res = await window.api.setPaymentPin(password, pin, confirmPin);
  submitBtn.disabled = false;
  submitBtn.innerHTML = '<span>Save Payment PIN</span>';

  if (res && res.ok) {
    showToast('Payment PIN configured successfully! You can now authorize UPI payments.', 'success');
    closePinSetupModal();
    await loadCustomerProfile();
  } else {
    const errMsg = (res && res.data && res.data.error) || 'Failed to save Payment PIN.';
    if (errBanner) {
      errBanner.textContent = errMsg;
      errBanner.style.display = 'block';
    }
    showToast(errMsg, 'error');
  }
}

window.openAddBeneficiaryModal = openAddBeneficiaryModal;
window.openEditBeneficiaryModal = openEditBeneficiaryModal;
window.closeBeneficiaryModal = closeBeneficiaryModal;
window.deleteBeneficiaryRecord = deleteBeneficiaryRecord;
window.viewShapForTx = viewShapForTx;
window.openPinSetupModal = openPinSetupModal;
window.closePinSetupModal = closePinSetupModal;
window.handlePinSetupSubmit = handlePinSetupSubmit;
