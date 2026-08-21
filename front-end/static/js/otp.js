/**
 * Adaptive OTP Modal & Verification Component
 */

class OtpModal {
  constructor() {
    this.overlay = document.getElementById('otp-modal-overlay');
    this.txIdEl = document.getElementById('otp-tx-id');
    this.inputEl = document.getElementById('otp-input-code');
    this.verifyBtn = document.getElementById('btn-verify-otp');
    this.resendBtn = document.getElementById('btn-resend-otp');
    this.timerEl = document.getElementById('otp-timer');
    this.errorBox = document.getElementById('otp-error-msg');
    this.devHelperBox = document.getElementById('otp-dev-helper');

    this.currentTxId = null;
    this.timerInterval = null;
    this.remainingSeconds = 180;
    this.onSuccessCallback = null;

    this.bindEvents();
  }

  bindEvents() {
    if (this.verifyBtn) {
      this.verifyBtn.addEventListener('click', () => this.handleVerify());
    }

    if (this.resendBtn) {
      this.resendBtn.addEventListener('click', () => this.handleResend());
    }

    if (this.inputEl) {
      this.inputEl.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') this.handleVerify();
      });
    }
  }

  open(transactionId, devOtp = null, onSuccess = null) {
    this.currentTxId = transactionId;
    this.onSuccessCallback = onSuccess;

    if (this.txIdEl) this.txIdEl.textContent = `#${transactionId}`;
    if (this.inputEl) {
      this.inputEl.value = '';
      this.inputEl.disabled = false;
    }
    if (this.errorBox) this.errorBox.style.display = 'none';

    // Show clean email notice only (NEVER render OTP code in the browser)
    if (this.devHelperBox) {
      this.devHelperBox.innerHTML = '📧 Verification code sent to your registered email.';
      this.devHelperBox.style.display = 'block';
    }

    this.startTimer(180);
    if (this.overlay) this.overlay.classList.add('active');
    if (this.inputEl) this.inputEl.focus();
  }

  close() {
    this.stopTimer();
    if (this.overlay) this.overlay.classList.remove('active');
    this.currentTxId = null;
  }

  startTimer(seconds) {
    this.stopTimer();
    this.remainingSeconds = seconds;
    this.updateTimerDisplay();

    this.timerInterval = setInterval(() => {
      this.remainingSeconds--;
      this.updateTimerDisplay();

      if (this.remainingSeconds <= 0) {
        this.stopTimer();
        if (this.errorBox) {
          this.errorBox.textContent = 'OTP code expired. Please click Resend Code.';
          this.errorBox.style.display = 'block';
        }
        if (this.inputEl) this.inputEl.disabled = true;
      }
    }, 1000);
  }

  stopTimer() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
      this.timerInterval = null;
    }
  }

  updateTimerDisplay() {
    if (!this.timerEl) return;
    const mins = Math.floor(this.remainingSeconds / 60);
    const secs = this.remainingSeconds % 60;
    this.timerEl.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  }

  async handleVerify() {
    const code = this.inputEl ? this.inputEl.value.trim() : '';
    if (!code || code.length < 6) {
      if (this.errorBox) {
        this.errorBox.textContent = 'Please enter the 6-digit OTP code.';
        this.errorBox.style.display = 'block';
      }
      return;
    }

    this.verifyBtn.disabled = true;
    this.verifyBtn.innerHTML = '<span>Verifying...</span>';
    if (this.errorBox) this.errorBox.style.display = 'none';

    const res = await window.api.verifyOtp(this.currentTxId, code);
    this.verifyBtn.disabled = false;
    this.verifyBtn.innerHTML = '<span>Verify Code</span>';

    if (res && res.ok) {
      showToast('OTP verified successfully!', 'success');
      this.close();
      if (this.onSuccessCallback) {
        this.onSuccessCallback(res.data.transaction);
      }
    } else {
      const errorMsg = (res && res.data && res.data.error) || 'Invalid or expired OTP code.';
      if (this.errorBox) {
        this.errorBox.textContent = errorMsg;
        this.errorBox.style.display = 'block';
      }
      showToast(errorMsg, 'error');
    }
  }

  async handleResend() {
    if (!this.currentTxId) return;

    this.resendBtn.disabled = true;
    this.resendBtn.textContent = 'Generating...';

    const res = await window.api.generateOtp(this.currentTxId);
    this.resendBtn.disabled = false;
    this.resendBtn.textContent = 'Resend Code';

    if (res && res.ok) {
      showToast('New verification code sent to your registered email.', 'success');
      this.open(this.currentTxId, null, this.onSuccessCallback);
    } else {
      showToast((res && res.data && res.data.error) || 'Failed to resend OTP.', 'error');
    }
  }
}

window.otpModal = new OtpModal();
