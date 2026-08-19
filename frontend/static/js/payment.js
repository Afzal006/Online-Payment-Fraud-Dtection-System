/**
 * Payment Simulator & Real-Time Decision Modal Controller
 */

let userAvailableBalance = 0;
let userBeneficiaries = [];
let lastPredictionData = null;

document.addEventListener('DOMContentLoaded', async () => {
  if (!window.api.isAuthenticated()) {
    window.location.href = '/login';
    return;
  }

  await loadSenderProfile();
  await loadBeneficiariesDropdown();

  const paymentForm = document.getElementById('payment-form');
  const resultModal = document.getElementById('result-modal-overlay');
  const btnCloseResult = document.getElementById('btn-close-result-modal');
  const btnWhyFlagged = document.getElementById('btn-why-flagged');
  const btnProceedOtp = document.getElementById('btn-proceed-otp');

  // Check URL query parameters for pre-selected beneficiary
  const urlParams = new URLSearchParams(window.location.search);
  const preSelectedBId = urlParams.get('b');
  if (preSelectedBId) {
    const select = document.getElementById('tx-beneficiary-select');
    if (select) {
      select.value = preSelectedBId;
      handleBeneficiarySelectChange();
    }
  }

  if (paymentForm) {
    paymentForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const type = document.getElementById('tx-type').value;
      const amount = parseFloat(document.getElementById('tx-amount').value);
      const bSelect = document.getElementById('tx-beneficiary-select');
      const bVal = bSelect ? bSelect.value : '';
      const destInput = document.getElementById('tx-destination');
      const noteInput = document.getElementById('tx-note');
      const submitBtn = document.getElementById('btn-submit-payment');
      const formError = document.getElementById('payment-form-error');

      // Balance validation
      if (isNaN(amount) || amount <= 0) {
        if (formError) {
          formError.textContent = 'Please enter a valid transfer amount greater than zero.';
          formError.style.display = 'block';
        }
        return;
      }

      if (type !== 'CASH_IN' && userAvailableBalance > 0 && amount > userAvailableBalance) {
        if (formError) {
          formError.textContent = `Insufficient funds: Transfer amount (₹${amount.toLocaleString('en-IN')}) exceeds available balance (₹${userAvailableBalance.toLocaleString('en-IN')}).`;
          formError.style.display = 'block';
        }
        return;
      }

      let beneficiaryId = null;
      let destinationUpi = null;
      let destinationName = null;
      let destination = '';

      if (bVal && bVal !== 'custom') {
        const selectedB = userBeneficiaries.find(b => b.id === parseInt(bVal));
        if (selectedB) {
          beneficiaryId = selectedB.id;
          destinationUpi = selectedB.beneficiary_upi_id;
          destinationName = selectedB.beneficiary_name;
          destination = selectedB.beneficiary_upi_id;
        }
      } else {
        destination = destInput ? destInput.value.trim() : '';
        if (!destination) {
          if (formError) {
            formError.textContent = 'Please enter a recipient UPI ID or account identifier.';
            formError.style.display = 'block';
          }
          return;
        }
        if (destination.includes('@')) {
          destinationUpi = destination;
        }
      }

      // Optional balance simulation fields
      const oldOrigInput = document.getElementById('tx-oldbalance-org');
      const newOrigInput = document.getElementById('tx-newbalance-orig');
      const oldOrig = oldOrigInput && oldOrigInput.value.trim() !== '' ? parseFloat(oldOrigInput.value) : null;
      const newOrig = newOrigInput && newOrigInput.value.trim() !== '' ? parseFloat(newOrigInput.value) : null;

      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>Evaluating Risk with Hybrid AI Engine...</span>';
      if (formError) formError.style.display = 'none';

      const payload = {
        type,
        amount,
        destination,
      };

      if (beneficiaryId) payload.beneficiary_id = beneficiaryId;
      if (destinationUpi) payload.destination_upi_id = destinationUpi;
      if (destinationName) payload.destination_name = destinationName;
      if (noteInput && noteInput.value.trim()) payload.payment_note = noteInput.value.trim();

      if (oldOrig !== null && !isNaN(oldOrig)) payload.oldbalance_org = oldOrig;
      if (newOrig !== null && !isNaN(newOrig)) payload.newbalance_orig = newOrig;

      const res = await window.api.submitTransaction(payload);
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Submit & Verify Payment</span>';

      if (res && res.ok && res.data.success) {
        lastPredictionData = res.data;
        if (res.data.account_balance !== undefined) {
          userAvailableBalance = res.data.account_balance;
          updateBalanceDisplay(userAvailableBalance);
        }
        showResultModal(res.data);
      } else {
        const errorMsg = (res && res.data && res.data.error) || 'Failed to process payment.';
        if (formError) {
          formError.textContent = errorMsg;
          formError.style.display = 'block';
        }
        showToast(errorMsg, 'error');
      }
    });
  }

  if (btnCloseResult && resultModal) {
    btnCloseResult.addEventListener('click', () => {
      resultModal.classList.remove('active');
    });
  }

  if (btnWhyFlagged) {
    btnWhyFlagged.addEventListener('click', () => {
      if (lastPredictionData && lastPredictionData.explanation) {
        window.shapDrawer.open(
          lastPredictionData.explanation,
          lastPredictionData.risk_score,
          lastPredictionData.risk_level
        );
      }
    });
  }
});

async function loadSenderProfile() {
  const res = await window.api.getProfile();
  if (res && res.ok && res.data && res.data.profile) {
    const p = res.data.profile;
    userAvailableBalance = parseFloat(p.account_balance || 0);
    const accountInfo = document.getElementById('sender-account-info');
    const upiInfo = document.getElementById('sender-upi-info');

    if (accountInfo) accountInfo.textContent = `${p.name} (${p.customer_account_id || `FS-${100000 + p.id}`})`;
    if (upiInfo) upiInfo.textContent = `UPI: ${p.primary_upi_id || `${p.email.split('@')[0]}@fraudshield`}`;
    updateBalanceDisplay(userAvailableBalance);
  }
}

function updateBalanceDisplay(bal) {
  const balEl = document.getElementById('sender-balance-display');
  if (balEl) {
    balEl.textContent = `₹${parseFloat(bal).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
}

async function loadBeneficiariesDropdown() {
  const res = await window.api.getBeneficiaries();
  const select = document.getElementById('tx-beneficiary-select');
  if (!select) return;

  if (res && res.ok && res.data && Array.isArray(res.data.beneficiaries)) {
    userBeneficiaries = res.data.beneficiaries;

    // Reset options
    select.innerHTML = '<option value="">-- Choose from Saved Beneficiaries --</option>';
    userBeneficiaries.forEach((b) => {
      const opt = document.createElement('option');
      opt.value = b.id;
      const nick = b.nickname ? ` (${b.nickname})` : '';
      opt.textContent = `👤 ${b.beneficiary_name}${nick} — ${b.beneficiary_upi_id}`;
      select.appendChild(opt);
    });

    const customOpt = document.createElement('option');
    customOpt.value = 'custom';
    customOpt.textContent = '✏️ Enter Custom UPI ID or Account Identifier';
    select.appendChild(customOpt);
  }
}

function handleBeneficiarySelectChange() {
  const select = document.getElementById('tx-beneficiary-select');
  const customGroup = document.getElementById('custom-destination-group');
  const preview = document.getElementById('beneficiary-preview-card');
  const prevName = document.getElementById('preview-b-name');
  const prevUpi = document.getElementById('preview-b-upi');

  if (!select) return;

  const val = select.value;
  if (val === 'custom') {
    if (customGroup) customGroup.style.display = 'block';
    if (preview) preview.style.display = 'none';
  } else if (val) {
    const selectedB = userBeneficiaries.find(b => b.id === parseInt(val));
    if (selectedB) {
      if (customGroup) customGroup.style.display = 'none';
      if (preview) {
        if (prevName) prevName.textContent = selectedB.beneficiary_name + (selectedB.nickname ? ` (${selectedB.nickname})` : '');
        if (prevUpi) prevUpi.textContent = selectedB.beneficiary_upi_id;
        preview.style.display = 'block';
      }
    }
  } else {
    if (customGroup) customGroup.style.display = 'none';
    if (preview) preview.style.display = 'none';
  }
}

function showResultModal(data) {
  const resultModal = document.getElementById('result-modal-overlay');
  const btnProceedOtp = document.getElementById('btn-proceed-otp');
  if (!resultModal) return;

  // Fill Modal Data
  const statusBadge = document.getElementById('res-status-badge');
  const riskScoreVal = document.getElementById('res-risk-score');
  const fraudProbVal = document.getElementById('res-fraud-prob');
  const decisionText = document.getElementById('res-decision-text');
  const narrativeText = document.getElementById('res-narrative-text');
  const factorsContainer = document.getElementById('res-risk-factors-container');
  const factorsList = document.getElementById('res-risk-factors-list');

  if (riskScoreVal) riskScoreVal.textContent = `${data.risk_score}/100`;
  if (fraudProbVal) fraudProbVal.textContent = `${(data.fraud_probability * 100).toFixed(1)}%`;
  if (decisionText) decisionText.textContent = data.decision.replace(/_/g, ' ');

  if (statusBadge) {
    statusBadge.textContent = `${data.risk_level} RISK - ${data.status.replace(/_/g, ' ')}`;
    statusBadge.className = `badge-risk badge-risk-${data.risk_level.toLowerCase()}`;
  }

  // Populate Risk Factors
  if (factorsContainer && factorsList) {
    factorsList.innerHTML = '';
    const factors = data.risk_factors || (data.explanation && data.explanation.rule_risk_factors) || [];
    if (factors.length > 0) {
      factors.forEach((f) => {
        const li = document.createElement('li');
        li.textContent = f;
        factorsList.appendChild(li);
      });
      factorsContainer.style.display = 'block';
    } else {
      factorsContainer.style.display = 'none';
    }
  }

  if (narrativeText && data.explanation) {
    narrativeText.textContent = data.explanation.human_readable_summary || 'Evaluated against security baseline.';
  }

  // Configure OTP button visibility
  if (btnProceedOtp) {
    if (data.requires_otp) {
      btnProceedOtp.style.display = 'inline-flex';
      btnProceedOtp.onclick = () => {
        resultModal.classList.remove('active');
        triggerOtpChallenge(data.transaction_id);
      };
    } else {
      btnProceedOtp.style.display = 'none';
    }
  }

  resultModal.classList.add('active');
}

async function triggerOtpChallenge(txId) {
  const res = await window.api.generateOtp(txId);
  if (res && res.ok) {
    const devOtp = res.data._dev_simulated_otp || null;
    window.otpModal.open(txId, devOtp, async (updatedTx) => {
      showToast(`Transaction #${updatedTx.id} status updated to ${updatedTx.status}`, 'success');
      await loadSenderProfile();
      setTimeout(() => {
        window.location.href = '/history';
      }, 1500);
    });
  } else {
    showToast((res && res.data && res.data.error) || 'Failed to issue OTP challenge.', 'error');
  }
}

window.handleBeneficiarySelectChange = handleBeneficiarySelectChange;
