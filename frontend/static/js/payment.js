/**
 * FraudShield AI - UPI Payment Simulator & Real-Time Decision Controller
 *
 * Implements:
 * 1. Tabbed Payment Options: Scan QR, UPI ID / VPA, Mobile Number, Saved Beneficiaries
 * 2. Real-Time Dynamic Payee Resolution
 * 3. 6-Digit Payment PIN Authentication & Secure Lockout UX
 * 4. Idempotency Key Generation (Double-Debit Protection)
 * 5. Integrated Real-Time Hybrid AI Fraud Scoring & SHAP Explanations
 */

let userAvailableBalance = 0;
let userBeneficiaries = [];
let resolvedRecipient = null;
let currentPaymentMethod = 'QR_CODE';
let isUserPinConfigured = false;
let pendingPaymentPayload = null;
let lastPredictionData = null;

let html5QrScannerInstance = null;
let isCameraScanningActive = false;

document.addEventListener('DOMContentLoaded', async () => {
  if (!window.api.isAuthenticated()) {
    window.location.href = '/login';
    return;
  }

  await loadSenderProfile();
  await checkPinStatus();
  await loadBeneficiariesList();

  // Check URL query parameters for mode or pre-selected beneficiary
  const urlParams = new URLSearchParams(window.location.search);
  const modeParam = urlParams.get('mode');
  const preSelectedBId = urlParams.get('b');

  if (modeParam && ['qr', 'upi', 'mobile', 'saved'].includes(modeParam)) {
    switchPaymentTab(modeParam);
  }

  if (preSelectedBId) {
    switchPaymentTab('saved');
    const select = document.getElementById('select-saved-beneficiary');
    if (select) {
      select.value = preSelectedBId;
      handleSavedBeneficiaryChange();
    }
  }

  // Result modal close & SHAP drawer handlers
  const btnCloseResult = document.getElementById('btn-close-result-modal');
  const resultModal = document.getElementById('result-modal-overlay');
  const btnWhyFlagged = document.getElementById('btn-why-flagged');

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

// ==========================================
// 1. Sender Profile & PIN State Management
// ==========================================

async function loadSenderProfile() {
  const res = await window.api.getProfile();
  if (res && res.ok && res.data && res.data.profile) {
    const p = res.data.profile;
    userAvailableBalance = parseFloat(p.account_balance || 0);
    const accountInfo = document.getElementById('sender-account-info');
    const upiInfo = document.getElementById('sender-upi-info');

    if (accountInfo) accountInfo.textContent = `${p.name} (${p.customer_account_id || `FS-${100000 + p.id}`})`;
    if (upiInfo) upiInfo.textContent = `UPI VPA: ${p.primary_upi_id || `${p.email.split('@')[0]}@fraudshield`}`;
    updateBalanceDisplay(userAvailableBalance);
  }
}

function updateBalanceDisplay(bal) {
  const balEl = document.getElementById('sender-balance-display');
  if (balEl) {
    balEl.textContent = `₹${parseFloat(bal).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
}

async function checkPinStatus() {
  const res = await window.api.getPaymentPinStatus();
  const pinBtnText = document.getElementById('pin-status-btn-text');
  if (res && res.ok && res.data) {
    isUserPinConfigured = !!res.data.is_pin_set;
    if (pinBtnText) {
      pinBtnText.textContent = isUserPinConfigured ? 'Change Payment PIN' : 'Set Payment PIN';
    }
  }
}

// ==========================================
// 2. Tabbed Payment Navigation
// ==========================================

function switchPaymentTab(tabName) {
  if (tabName !== 'qr') {
    stopCameraScanner();
  }

  const tabs = ['qr', 'upi', 'mobile', 'saved'];
  tabs.forEach((t) => {
    const btn = document.getElementById(`tab-${t}`);
    const content = document.getElementById(`tab-content-${t}`);
    if (btn) {
      if (t === tabName) {
        btn.classList.add('active');
        btn.style.borderBottomColor = 'var(--primary)';
        btn.style.color = '#fff';
      } else {
        btn.classList.remove('active');
        btn.style.borderBottomColor = 'transparent';
        btn.style.color = 'var(--text-muted)';
      }
    }
    if (content) {
      content.style.display = t === tabName ? 'block' : 'none';
    }
  });

  if (tabName === 'qr') currentPaymentMethod = 'QR_CODE';
  else if (tabName === 'upi') currentPaymentMethod = 'UPI_ID';
  else if (tabName === 'mobile') currentPaymentMethod = 'MOBILE_NUMBER';
  else if (tabName === 'saved') currentPaymentMethod = 'SAVED_BENEFICIARY';
}

// ==========================================
// 3. Real Camera QR Scanner Handlers
// ==========================================

async function startCameraScanner() {
  const startBtn = document.getElementById('btn-start-camera');
  const stopBtn = document.getElementById('btn-stop-camera');
  const statusEl = document.getElementById('camera-scan-status');
  const errEl = document.getElementById('camera-error-banner');
  const placeholderEl = document.getElementById('qr-camera-placeholder');

  if (errEl) errEl.style.display = 'none';

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showCameraError('Camera access is not supported by your browser or environment. Please enter UPI ID manually or upload a QR image.');
    return;
  }

  if (typeof Html5Qrcode === 'undefined') {
    showCameraError('QR Scanner engine is initializing. Please try again in a moment or use manual UPI entry.');
    return;
  }

  try {
    if (statusEl) {
      statusEl.textContent = 'Requesting camera permissions...';
      statusEl.style.display = 'block';
    }

    if (!html5QrScannerInstance) {
      html5QrScannerInstance = new Html5Qrcode('qr-reader');
    }

    const config = {
      fps: 10,
      qrbox: { width: 250, height: 250 },
      aspectRatio: 1.0,
    };

    if (placeholderEl) placeholderEl.style.display = 'none';

    await html5QrScannerInstance.start(
      { facingMode: 'environment' },
      config,
      (decodedText) => {
        onQrCodeScanned(decodedText);
      },
      () => {
        // Continuous scan loop frame drop (expected while searching for QR)
      }
    );

    isCameraScanningActive = true;
    if (startBtn) startBtn.style.display = 'none';
    if (stopBtn) stopBtn.style.display = 'inline-flex';
    if (statusEl) statusEl.textContent = 'Camera active. Point at any standard UPI QR code...';
  } catch (err) {
    console.error('Camera startup error:', err);
    let userMsg = 'Unable to access camera. Please grant camera permission or use manual UPI entry.';
    if (err && (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError')) {
      userMsg = 'Camera permission was denied. Please allow camera access in browser permissions or use manual entry.';
    } else if (err && err.name === 'NotFoundError') {
      userMsg = 'No camera device found on this system. Please use manual UPI entry or upload a QR image.';
    }
    showCameraError(userMsg);
    if (placeholderEl) placeholderEl.style.display = 'block';
  }
}

async function stopCameraScanner() {
  const startBtn = document.getElementById('btn-start-camera');
  const stopBtn = document.getElementById('btn-stop-camera');
  const statusEl = document.getElementById('camera-scan-status');
  const placeholderEl = document.getElementById('qr-camera-placeholder');

  if (html5QrScannerInstance && isCameraScanningActive) {
    try {
      await html5QrScannerInstance.stop();
    } catch (e) {
      console.warn('Camera stop warning:', e);
    }
    isCameraScanningActive = false;
  }

  if (startBtn) startBtn.style.display = 'inline-flex';
  if (stopBtn) stopBtn.style.display = 'none';
  if (statusEl) statusEl.style.display = 'none';
  if (placeholderEl) placeholderEl.style.display = 'block';
}

function showCameraError(msg) {
  const errEl = document.getElementById('camera-error-banner');
  if (errEl) {
    errEl.textContent = msg;
    errEl.style.display = 'block';
  }
  showToast(msg, 'error');
}

function onQrCodeScanned(qrPayload) {
  stopCameraScanner();
  showToast('UPI QR code detected and decoded!', 'success');
  resolveAndDisplayRecipient(qrPayload, 'QR_CODE');
}

async function decodeQrFromFile(file) {
  const imgUrl = URL.createObjectURL(file);
  const img = new Image();
  await new Promise((resolve, reject) => {
    img.onload = () => resolve();
    img.onerror = () => reject(new Error('Failed to load image file.'));
    img.src = imgUrl;
  });

  const origW = img.naturalWidth || img.width;
  const origH = img.naturalHeight || img.height;
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  // Pass 1: jsQR at native resolution
  if (typeof jsQR !== 'undefined') {
    canvas.width = origW;
    canvas.height = origH;
    ctx.drawImage(img, 0, 0);
    try {
      const imgData = ctx.getImageData(0, 0, origW, origH);
      const code = jsQR(imgData.data, origW, origH, { inversionAttempts: 'attemptBoth' });
      if (code && code.data && code.data.trim()) {
        URL.revokeObjectURL(imgUrl);
        return code.data.trim();
      }
    } catch (e) {
      console.warn('jsQR native pass notice:', e);
    }
  }

  // Pass 2: jsQR with Multi-Scale Downsampling for High-Res Phone Screenshots (1400, 1000, 800, 600, 400)
  if (typeof jsQR !== 'undefined' && origW > 400) {
    const scales = [1400, 1000, 800, 600, 400];
    for (const tw of scales) {
      if (origW > tw) {
        const th = Math.round((origH / origW) * tw);
        canvas.width = tw;
        canvas.height = th;
        ctx.drawImage(img, 0, 0, tw, th);
        try {
          const scaledData = ctx.getImageData(0, 0, tw, th);
          const code = jsQR(scaledData.data, tw, th, { inversionAttempts: 'attemptBoth' });
          if (code && code.data && code.data.trim()) {
            URL.revokeObjectURL(imgUrl);
            return code.data.trim();
          }
        } catch (e) {}
      }
    }
  }

  // Pass 3: Grayscale & Contrast Binarization (Paytm / PhonePe Colored Soundbox & Dark QR Themes)
  if (typeof jsQR !== 'undefined') {
    const testSizes = [Math.min(900, origW), Math.min(600, origW), Math.min(400, origW)];
    for (const tw of testSizes) {
      const th = Math.round((origH / origW) * tw);
      canvas.width = tw;
      canvas.height = th;
      ctx.drawImage(img, 0, 0, tw, th);
      try {
        const rawData = ctx.getImageData(0, 0, tw, th);
        const d = rawData.data;
        for (let i = 0; i < d.length; i += 4) {
          const lum = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
          const v = lum < 128 ? 0 : 255;
          d[i] = v;
          d[i + 1] = v;
          d[i + 2] = v;
        }
        const code = jsQR(d, tw, th, { inversionAttempts: 'attemptBoth' });
        if (code && code.data && code.data.trim()) {
          URL.revokeObjectURL(imgUrl);
          return code.data.trim();
        }
      } catch (e) {}
    }
  }

  // Pass 4: ZXing BrowserQRCodeReader
  if (typeof ZXing !== 'undefined' && ZXing.BrowserQRCodeReader) {
    try {
      const codeReader = new ZXing.BrowserQRCodeReader();
      const zxRes = await codeReader.decodeFromImageElement(img);
      if (zxRes && zxRes.getText() && zxRes.getText().trim()) {
        URL.revokeObjectURL(imgUrl);
        return zxRes.getText().trim();
      }
    } catch (e) {}
  }

  // Pass 5: Html5Qrcode scanFile fallback
  if (typeof Html5Qrcode !== 'undefined') {
    try {
      if (!html5QrScannerInstance) {
        html5QrScannerInstance = new Html5Qrcode('qr-reader');
      }
      const html5Text = await html5QrScannerInstance.scanFile(file, true);
      if (html5Text && html5Text.trim()) {
        URL.revokeObjectURL(imgUrl);
        return html5Text.trim();
      }
    } catch (e) {}
  }

  URL.revokeObjectURL(imgUrl);
  throw new Error('Unable to detect a readable QR code. Please ensure the QR code image is clearly visible.');
}

async function handleQrFileUpload(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;

  const errEl = document.getElementById('camera-error-banner');
  if (errEl) errEl.style.display = 'none';

  try {
    showToast('Analyzing and decoding QR image...', 'info');
    const decodedText = await decodeQrFromFile(file);
    if (decodedText) {
      showToast('QR Image decoded successfully!', 'success');
      resolveAndDisplayRecipient(decodedText, 'QR_CODE');
    }
  } catch (err) {
    console.error('QR File decoding error:', err);
    showCameraError('Could not decode a valid UPI QR code from the uploaded image. Please ensure the QR is clear and well-lit.');
  } finally {
    e.target.value = '';
  }
}

async function handleScanQrSubmit() {
  const qrInput = document.getElementById('qr-input-text');
  const qrData = qrInput ? qrInput.value.trim() : '';
  if (!qrData) {
    showFormError('Please enter or paste a UPI QR URI string.');
    return;
  }
  await resolveAndDisplayRecipient(qrData, 'QR_CODE');
}

function loadQrPreset(qrUri) {
  const qrInput = document.getElementById('qr-input-text');
  if (qrInput) qrInput.value = qrUri;
  resolveAndDisplayRecipient(qrUri, 'QR_CODE');
}

async function handleResolveUpiSubmit() {
  const upiInput = document.getElementById('input-upi-id');
  const upiVal = upiInput ? upiInput.value.trim() : '';
  if (!upiVal) {
    showFormError('Please enter a payee UPI ID (e.g. name@fraudshield or merchant@upi).');
    return;
  }
  await resolveAndDisplayRecipient(upiVal, 'UPI_ID');
}

async function handleResolveMobileSubmit() {
  const mobileInput = document.getElementById('input-mobile-number');
  const mobileVal = mobileInput ? mobileInput.value.trim() : '';
  if (!mobileVal || mobileVal.length < 10) {
    showFormError('Please enter a valid 10-digit mobile number.');
    return;
  }
  await resolveAndDisplayRecipient(mobileVal, 'MOBILE_NUMBER');
}

async function loadBeneficiariesList() {
  const res = await window.api.getBeneficiaries();
  const select = document.getElementById('select-saved-beneficiary');
  if (!select) return;

  if (res && res.ok && res.data && Array.isArray(res.data.beneficiaries)) {
    userBeneficiaries = res.data.beneficiaries;
    select.innerHTML = '<option value="">-- Choose Beneficiary --</option>';
    userBeneficiaries.forEach((b) => {
      const opt = document.createElement('option');
      opt.value = b.id;
      const nick = b.nickname ? ` (${b.nickname})` : '';
      opt.textContent = `👤 ${b.beneficiary_name}${nick} — ${b.beneficiary_upi_id}`;
      select.appendChild(opt);
    });
  }
}

function handleSavedBeneficiaryChange() {
  const select = document.getElementById('select-saved-beneficiary');
  if (!select || !select.value) return;

  const selectedB = userBeneficiaries.find((b) => b.id === parseInt(select.value));
  if (selectedB) {
    resolvedRecipient = {
      resolved: true,
      recipient_id: null,
      recipient_name: selectedB.beneficiary_name,
      recipient_upi_id: selectedB.beneficiary_upi_id,
      recipient_phone: selectedB.beneficiary_phone,
      account_type: 'SAVED_BENEFICIARY',
      is_saved_beneficiary: true,
      beneficiary_id: selectedB.id,
      trust_status: selectedB.trust_status,
      is_cooling_active: selectedB.is_cooling_active,
    };
    displayRecipientCard(resolvedRecipient);
  }
}

async function resolveAndDisplayRecipient(query, method) {
  hideFormError();
  const res = await window.api.resolveRecipient(query);
  if (res && res.ok && res.data && res.data.recipient) {
    resolvedRecipient = res.data.recipient;
    currentPaymentMethod = method;
    displayRecipientCard(resolvedRecipient);

    // If QR payload specified amount, populate it
    if (resolvedRecipient.suggested_amount) {
      const amountInput = document.getElementById('tx-amount');
      if (amountInput) amountInput.value = resolvedRecipient.suggested_amount;
    }
    if (resolvedRecipient.suggested_note) {
      const noteInput = document.getElementById('tx-note');
      if (noteInput) noteInput.value = resolvedRecipient.suggested_note;
    }
    showToast(`Recipient verified: ${resolvedRecipient.recipient_name}`, 'success');
  } else {
    resolvedRecipient = null;
    const errMsg = (res && res.data && res.data.error) || `Could not resolve payee '${query}'.`;
    showFormError(errMsg);
    const card = document.getElementById('recipient-confirmed-card');
    if (card) card.style.display = 'none';
  }
}

function displayRecipientCard(rec) {
  const card = document.getElementById('recipient-confirmed-card');
  const nameEl = document.getElementById('rec-name');
  const upiEl = document.getElementById('rec-upi');
  const typeEl = document.getElementById('rec-type-badge');
  const avatarEl = document.getElementById('rec-avatar');
  const coolingBanner = document.getElementById('rec-cooling-banner');

  if (!card) return;

  if (nameEl) nameEl.textContent = rec.recipient_name;
  if (upiEl) upiEl.textContent = rec.recipient_upi_id;
  if (typeEl) {
    let typeLabel = 'Internal User';
    if (rec.account_type === 'MERCHANT') typeLabel = '🏪 Verified Merchant POS';
    else if (rec.account_type === 'SAVED_BENEFICIARY') typeLabel = '⭐ Saved Beneficiary';
    else if (rec.account_type === 'EXTERNAL_UPI') typeLabel = '🌐 External UPI Handle';
    typeEl.textContent = `${typeLabel} • Trust: ${rec.trust_status || 'NEW'}`;
  }

  if (avatarEl) {
    avatarEl.textContent = rec.account_type === 'MERCHANT' ? '🏪' : '👤';
  }

  if (coolingBanner) {
    coolingBanner.style.display = rec.is_cooling_active ? 'block' : 'none';
  }

  card.style.display = 'block';
}

function setAmountChip(val) {
  const amountInput = document.getElementById('tx-amount');
  if (amountInput) {
    amountInput.value = val.toFixed(2);
  }
}

function showFormError(msg) {
  const el = document.getElementById('payment-form-error');
  if (el) {
    el.textContent = msg;
    el.style.display = 'block';
  }
}

function hideFormError() {
  const el = document.getElementById('payment-form-error');
  if (el) el.style.display = 'none';
}

// ==========================================
// 4. Quick Test Scenarios
// ==========================================

function loadUpiScenario(scenario) {
  const amountInput = document.getElementById('tx-amount');
  const typeSelect = document.getElementById('tx-type');
  const oldOrig = document.getElementById('tx-oldbalance-org');
  const newOrig = document.getElementById('tx-newbalance-orig');

  if (oldOrig) oldOrig.value = '';
  if (newOrig) newOrig.value = '';

  if (scenario === 'low') {
    switchPaymentTab('qr');
    loadQrPreset('upi://pay?pa=coffee@fraudshield&pn=Artisan%20Coffee&am=150.00&cu=INR&tn=Cappuccino');
    if (typeSelect) typeSelect.value = 'PAYMENT';
    if (amountInput) amountInput.value = '150.00';
  } else if (scenario === 'merchant') {
    switchPaymentTab('qr');
    loadQrPreset('upi://pay?pa=merchant@fraudshield&pn=SuperMart%20POS&am=1250.00&cu=INR&tn=Groceries');
    if (typeSelect) typeSelect.value = 'PAYMENT';
    if (amountInput) amountInput.value = '1250.00';
  } else if (scenario === '92k') {
    switchPaymentTab('upi');
    const upiInput = document.getElementById('input-upi-id');
    if (upiInput) upiInput.value = 'priya@fraudshield';
    resolveAndDisplayRecipient('priya@fraudshield', 'UPI_ID');
    if (typeSelect) typeSelect.value = 'TRANSFER';
    if (amountInput) amountInput.value = '92000.00';
  } else if (scenario === '250k') {
    switchPaymentTab('upi');
    const upiInput = document.getElementById('input-upi-id');
    if (upiInput) upiInput.value = 'unknown@fraudshield';
    resolveAndDisplayRecipient('unknown@fraudshield', 'UPI_ID');
    if (typeSelect) typeSelect.value = 'TRANSFER';
    if (amountInput) amountInput.value = '250001.00';
  } else if (scenario === 'drain') {
    switchPaymentTab('qr');
    loadQrPreset('upi://pay?pa=atm.drain@upi&pn=FastCash%20ATM&am=750000.00&cu=INR&tn=CashOut');
    if (typeSelect) typeSelect.value = 'CASH_OUT';
    if (amountInput) amountInput.value = '750000.00';
    if (oldOrig) oldOrig.value = '750000.00';
    if (newOrig) newOrig.value = '0.00';
  }
}

// ==========================================
// 5. Payment Review & PIN Modal UX
// ==========================================

function openPaymentReviewModal() {
  hideFormError();

  if (!resolvedRecipient) {
    showFormError('Please resolve or select a verified recipient first.');
    return;
  }

  const type = document.getElementById('tx-type').value;
  const amount = parseFloat(document.getElementById('tx-amount').value);
  const note = document.getElementById('tx-note').value.trim();

  if (isNaN(amount) || amount <= 0) {
    showFormError('Please enter a valid transfer amount greater than ₹0.00.');
    return;
  }

  if (type !== 'CASH_IN' && userAvailableBalance > 0 && amount > userAvailableBalance) {
    showFormError(`Insufficient account balance: Transfer amount (₹${amount.toLocaleString('en-IN')}) exceeds available funds (₹${userAvailableBalance.toLocaleString('en-IN')}).`);
    return;
  }

  // Check optional simulation balances
  const oldOrigInput = document.getElementById('tx-oldbalance-org');
  const newOrigInput = document.getElementById('tx-newbalance-orig');
  const oldOrig = oldOrigInput && oldOrigInput.value.trim() !== '' ? parseFloat(oldOrigInput.value) : null;
  const newOrig = newOrigInput && newOrigInput.value.trim() !== '' ? parseFloat(newOrigInput.value) : null;

  // Generate unique client-side idempotency key
  const idempotencyKey = `UPI-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;

  pendingPaymentPayload = {
    type,
    amount,
    idempotency_key: idempotencyKey,
    payment_method: currentPaymentMethod,
    destination: resolvedRecipient.recipient_upi_id,
    destination_upi_id: resolvedRecipient.recipient_upi_id,
    destination_name: resolvedRecipient.recipient_name,
    beneficiary_id: resolvedRecipient.beneficiary_id || null,
    recipient_user_id: resolvedRecipient.recipient_id || null,
    payment_note: note || null,
  };

  if (oldOrig !== null && !isNaN(oldOrig)) pendingPaymentPayload.oldbalance_org = oldOrig;
  if (newOrig !== null && !isNaN(newOrig)) pendingPaymentPayload.newbalance_orig = newOrig;

  // Prompt for PIN or PIN Setup
  if (!isUserPinConfigured) {
    openPinSetupModal();
    showToast('Please set your 4-6 digit Payment PIN to authenticate UPI payments.', 'info');
    return;
  }

  // Open PIN Modal
  const modal = document.getElementById('pin-modal-overlay');
  const payAmtEl = document.getElementById('modal-pay-amount');
  const payRecEl = document.getElementById('modal-pay-recipient');
  const pinInput = document.getElementById('modal-pin-input');
  const pinErr = document.getElementById('pin-error-banner');

  if (payAmtEl) payAmtEl.textContent = `₹${amount.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
  if (payRecEl) payRecEl.textContent = resolvedRecipient.recipient_name;
  if (pinInput) {
    pinInput.value = '';
    setTimeout(() => pinInput.focus(), 150);
  }
  if (pinErr) pinErr.style.display = 'none';

  if (modal) {
    modal.classList.add('active');
  }
}

function closePinModal() {
  const modal = document.getElementById('pin-modal-overlay');
  if (modal) {
    modal.classList.remove('active');
  }
}

async function executeFinalPayment() {
  const pinInput = document.getElementById('modal-pin-input');
  const pinErr = document.getElementById('pin-error-banner');
  const submitBtn = document.getElementById('btn-submit-pin-payment');
  const pin = pinInput ? pinInput.value.trim() : '';

  if (!pin || pin.length < 4) {
    if (pinErr) {
      pinErr.textContent = 'Please enter your 4-6 digit payment PIN.';
      pinErr.style.display = 'block';
    }
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span>Evaluating AI Fraud Defense...</span>';
  }

  pendingPaymentPayload.payment_pin = pin;

  const res = await window.api.submitTransaction(pendingPaymentPayload);

  if (submitBtn) {
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span>Confirm & Submit Payment</span>';
  }

  if (res && res.ok && res.data.success) {
    closePinModal();
    lastPredictionData = res.data;
    if (res.data.account_balance !== undefined) {
      userAvailableBalance = res.data.account_balance;
      updateBalanceDisplay(userAvailableBalance);
    }
    showResultModal(res.data);
  } else {
    const errorMsg = (res && res.data && res.data.error) || 'Transaction failed.';
    if (pinErr) {
      pinErr.textContent = errorMsg;
      pinErr.style.display = 'block';
    }
    showToast(errorMsg, 'error');
  }
}

// ==========================================
// 6. PIN Setup Modal Handlers
// ==========================================

function openPinSetupModal() {
  const modal = document.getElementById('pin-setup-modal-overlay');
  const errBanner = document.getElementById('pin-setup-error-banner');
  const form = document.getElementById('pin-setup-form');
  if (errBanner) errBanner.style.display = 'none';
  if (form) form.reset();
  if (modal) {
    modal.classList.add('active');
  }
}

function closePinSetupModal() {
  const modal = document.getElementById('pin-setup-modal-overlay');
  if (modal) {
    modal.classList.remove('active');
  }
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
  submitBtn.innerHTML = '<span>Securing PIN...</span>';

  const res = await window.api.setPaymentPin(password, pin, confirmPin);
  submitBtn.disabled = false;
  submitBtn.innerHTML = '<span>Save Payment PIN</span>';

  if (res && res.ok) {
    showToast('Payment PIN configured successfully!', 'success');
    closePinSetupModal();
    await checkPinStatus();
    // If user had clicked to pay, resume flow
    if (pendingPaymentPayload) {
      openPaymentReviewModal();
    }
  } else {
    const errorMsg = (res && res.data && res.data.error) || 'Failed to set Payment PIN.';
    if (errBanner) {
      errBanner.textContent = errorMsg;
      errBanner.style.display = 'block';
    }
    showToast(errorMsg, 'error');
  }
}

// ==========================================
// 7. Decision Result Screen & Checklist
// ==========================================

function showResultModal(data) {
  const resultModal = document.getElementById('result-modal-overlay');
  const btnProceedOtp = document.getElementById('btn-proceed-otp');
  if (!resultModal) return;

  const receiptBanner = document.getElementById('res-receipt-banner');
  const receiptIcon = document.getElementById('res-receipt-icon');
  const receiptTitle = document.getElementById('res-receipt-title');
  const receiptAmount = document.getElementById('res-receipt-amount');
  const receiptRecipient = document.getElementById('res-receipt-recipient');
  const receiptRefId = document.getElementById('res-receipt-ref-id');
  const balanceBox = document.getElementById('res-balance-box');
  const prevBalEl = document.getElementById('res-prev-balance');
  const newBalEl = document.getElementById('res-new-balance');
  const securityDetails = document.getElementById('res-security-details');

  const statusBadge = document.getElementById('res-status-badge');
  const riskScoreVal = document.getElementById('res-risk-score');
  const fraudProbVal = document.getElementById('res-fraud-prob');
  const decisionText = document.getElementById('res-decision-text');
  const narrativeText = document.getElementById('res-narrative-text');
  const factorsContainer = document.getElementById('res-risk-factors-container');
  const factorsList = document.getElementById('res-risk-factors-list');

  const payAmt = pendingPaymentPayload ? pendingPaymentPayload.amount : (data.amount || 0);
  const payeeName = data.destination_name || (resolvedRecipient && resolvedRecipient.recipient_name) || 'Payee';
  const payeeUpi = data.destination_upi_id || (resolvedRecipient && resolvedRecipient.recipient_upi_id) || '';

  if (receiptAmount) {
    receiptAmount.textContent = `₹${parseFloat(payAmt).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
  if (receiptRecipient) {
    receiptRecipient.textContent = `Paid to ${payeeName} (${payeeUpi})`;
  }
  if (receiptRefId) {
    receiptRefId.textContent = `UPI Ref: ${data.reference_id || `UPI${Date.now()}`}`;
  }

  // Visual state configuration
  if (data.status === 'APPROVED') {
    if (receiptBanner) {
      receiptBanner.style.background = 'rgba(52, 211, 153, 0.12)';
      receiptBanner.style.borderColor = 'rgba(52, 211, 153, 0.3)';
    }
    if (receiptIcon) {
      receiptIcon.textContent = '✓';
      receiptIcon.style.color = '#34D399';
    }
    if (receiptTitle) {
      receiptTitle.textContent = 'Payment Successful';
      receiptTitle.style.color = '#fff';
    }
    if (receiptAmount) receiptAmount.style.color = '#34D399';

    if (balanceBox) {
      balanceBox.style.display = 'flex';
      if (prevBalEl) prevBalEl.textContent = `₹${parseFloat(data.balance_before !== undefined ? data.balance_before : userAvailableBalance + payAmt).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
      if (newBalEl) newBalEl.textContent = `₹${parseFloat(data.balance_after !== undefined ? data.balance_after : userAvailableBalance).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    }
    if (securityDetails) securityDetails.open = false;
  } else if (data.requires_otp || data.status === 'OTP_REQUIRED' || data.status === 'PENDING_OTP') {
    if (receiptBanner) {
      receiptBanner.style.background = 'rgba(251, 191, 36, 0.12)';
      receiptBanner.style.borderColor = 'rgba(251, 191, 36, 0.3)';
    }
    if (receiptIcon) {
      receiptIcon.textContent = '🔐';
      receiptIcon.style.color = '#FBBF24';
    }
    if (receiptTitle) {
      receiptTitle.textContent = 'Additional Verification Required';
      receiptTitle.style.color = '#FBBF24';
    }
    if (receiptAmount) receiptAmount.style.color = '#FBBF24';

    if (balanceBox) {
      balanceBox.style.display = 'block';
      balanceBox.innerHTML = '<div style="color: #FBBF24; text-align: center; font-size: 0.85rem;">🛡️ Funds remain protected in escrow until one-time code is verified. No amount debited yet.</div>';
    }
    if (securityDetails) securityDetails.open = true;
  } else {
    // REJECTED / UNDER_REVIEW / BLOCKED
    if (receiptBanner) {
      receiptBanner.style.background = 'rgba(239, 68, 68, 0.12)';
      receiptBanner.style.borderColor = 'rgba(239, 68, 68, 0.3)';
    }
    if (receiptIcon) {
      receiptIcon.textContent = '✕';
      receiptIcon.style.color = '#F87171';
    }
    if (receiptTitle) {
      receiptTitle.textContent = 'Payment Not Completed';
      receiptTitle.style.color = '#F87171';
    }
    if (receiptAmount) receiptAmount.style.color = '#F87171';

    if (balanceBox) {
      balanceBox.style.display = 'block';
      balanceBox.innerHTML = '<div style="color: #FCA5A5; text-align: center; font-size: 0.85rem;">🛡️ No amount was deducted from your balance.</div>';
    }
    if (securityDetails) securityDetails.open = true;
  }

  if (riskScoreVal) riskScoreVal.textContent = `${data.risk_score}/100`;
  if (fraudProbVal) fraudProbVal.textContent = `${(data.fraud_probability * 100).toFixed(1)}%`;
  if (decisionText) decisionText.textContent = data.decision.replace(/_/g, ' ');

  if (statusBadge) {
    statusBadge.textContent = `${data.risk_level} RISK — ${data.status.replace(/_/g, ' ')}`;
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
    narrativeText.textContent = data.customer_message || data.explanation.customer_explanation || 'Payment evaluated against real-time baseline.';
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
      showToast(`Transaction #${updatedTx.id} approved!`, 'success');
      await loadSenderProfile();
      setTimeout(() => {
        window.location.href = '/history';
      }, 1500);
    });
  } else {
    showToast((res && res.data && res.data.error) || 'Failed to issue OTP challenge.', 'error');
  }
}

// Global exposes
window.switchPaymentTab = switchPaymentTab;
window.startCameraScanner = startCameraScanner;
window.stopCameraScanner = stopCameraScanner;
window.handleQrFileUpload = handleQrFileUpload;
window.handleScanQrSubmit = handleScanQrSubmit;
window.loadQrPreset = loadQrPreset;
window.handleResolveUpiSubmit = handleResolveUpiSubmit;
window.handleResolveMobileSubmit = handleResolveMobileSubmit;
window.handleSavedBeneficiaryChange = handleSavedBeneficiaryChange;
window.setAmountChip = setAmountChip;
window.loadUpiScenario = loadUpiScenario;
window.openPaymentReviewModal = openPaymentReviewModal;
window.closePinModal = closePinModal;
window.executeFinalPayment = executeFinalPayment;
window.openPinSetupModal = openPinSetupModal;
window.closePinSetupModal = closePinSetupModal;
window.handlePinSetupSubmit = handlePinSetupSubmit;

