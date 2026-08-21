/**
 * FraudShield AI — User Profile Management Script
 */

document.addEventListener('DOMContentLoaded', async () => {
  if (!window.api || !window.api.isAuthenticated()) {
    window.location.href = '/login?expired=1';
    return;
  }

  let userProfile = null;

  const viewName = document.getElementById('view-name');
  const viewRoleBadge = document.getElementById('view-role-badge');
  const viewAccountId = document.getElementById('view-account-id');
  const viewUpiId = document.getElementById('view-upi-id');
  const viewEmail = document.getElementById('view-email');
  const viewEmailBadge = document.getElementById('view-email-badge');
  const viewPhone = document.getElementById('view-phone');
  const viewPhoneBadge = document.getElementById('view-phone-badge');
  const viewStatusBadge = document.getElementById('view-status-badge');
  const viewCreatedAt = document.getElementById('view-created-at');
  const btnTriggerPhoneVerify = document.getElementById('btn-trigger-phone-verify');

  const editName = document.getElementById('edit-name');
  const editEmail = document.getElementById('edit-email');
  const editPhone = document.getElementById('edit-phone');
  const editForm = document.getElementById('profile-edit-form');
  const btnResetForm = document.getElementById('btn-reset-form');
  const alertMsg = document.getElementById('profile-alert-msg');

  const modalPhoneOtp = document.getElementById('modal-phone-otp');
  const modalPhoneDisplay = document.getElementById('modal-phone-display');
  const modalPhoneAlert = document.getElementById('modal-phone-alert');
  const formVerifyPhoneOtp = document.getElementById('form-verify-phone-otp');
  const inputPhoneOtp = document.getElementById('modal-phone-otp-input');
  const btnCancelPhoneModal = document.getElementById('btn-cancel-phone-modal');
  const btnResendProfileOtp = document.getElementById('btn-resend-profile-otp');

  // Load and render user profile
  async function loadProfile() {
    const res = await window.api.getProfile();
    if (!res || !res.ok) {
      showToast('Failed to load profile details.', 'error');
      return;
    }

    userProfile = res.data.profile || {};
    renderProfile(userProfile);
  }

  function renderProfile(p) {
    if (viewName) viewName.textContent = p.name || 'FraudShield User';
    if (viewRoleBadge) viewRoleBadge.textContent = p.role || 'USER';
    if (viewAccountId) viewAccountId.textContent = p.customer_account_id || '--';
    if (viewUpiId) viewUpiId.textContent = p.primary_upi_id || '--';
    if (viewEmail) viewEmail.textContent = p.email || '--';

    if (viewEmailBadge) {
      if (p.is_email_verified) {
        viewEmailBadge.className = 'badge-risk badge-risk-low';
        viewEmailBadge.textContent = '✓ Verified';
      } else {
        viewEmailBadge.className = 'badge-risk badge-risk-medium';
        viewEmailBadge.textContent = '⚠️ Pending';
      }
    }

    if (viewPhone) {
      if (p.phone_number) {
        const rawDigits = String(p.phone_number).replace(/\D/g, '');
        const clean10 = rawDigits.length === 12 && rawDigits.startsWith('91')
          ? rawDigits.slice(2)
          : (rawDigits.length === 11 && rawDigits.startsWith('0') ? rawDigits.slice(1) : rawDigits);
        if (clean10.length === 10) {
          viewPhone.textContent = `+91 ${clean10.slice(0, 5)} ${clean10.slice(5)}`;
        } else {
          viewPhone.textContent = p.phone_number.startsWith('+91') ? p.phone_number : `+91 ${p.phone_number}`;
        }
      } else {
        viewPhone.textContent = 'Not Configured';
      }
    }

    if (viewPhoneBadge) {
      if (p.is_phone_verified) {
        viewPhoneBadge.className = 'badge-risk badge-risk-low';
        viewPhoneBadge.textContent = '✓ Verified';
        if (btnTriggerPhoneVerify) btnTriggerPhoneVerify.style.display = 'none';
      } else {
        viewPhoneBadge.className = 'badge-risk badge-risk-medium';
        viewPhoneBadge.textContent = p.phone_number ? '⚠️ Not Verified' : 'None';
        if (btnTriggerPhoneVerify) {
          btnTriggerPhoneVerify.style.display = p.phone_number ? 'inline-block' : 'none';
        }
      }
    }

    if (viewStatusBadge) {
      viewStatusBadge.textContent = p.account_status || (p.is_active ? 'ACTIVE' : 'PENDING');
      viewStatusBadge.style.color = p.account_status === 'ACTIVE' ? '#34d399' : '#fbbf24';
    }

    if (viewCreatedAt) {
      if (p.created_at) {
        try {
          const d = new Date(p.created_at);
          viewCreatedAt.textContent = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
        } catch {
          viewCreatedAt.textContent = p.created_at;
        }
      } else {
        viewCreatedAt.textContent = '--';
      }
    }

    // Pre-populate form
    if (editName) editName.value = p.name || '';
    if (editEmail) editEmail.value = p.email || '';
    if (editPhone) {
      if (p.phone_number) {
        const rawDigits = String(p.phone_number).replace(/\D/g, '');
        const clean10 = rawDigits.length === 12 && rawDigits.startsWith('91')
          ? rawDigits.slice(2)
          : (rawDigits.length === 11 && rawDigits.startsWith('0') ? rawDigits.slice(1) : rawDigits);
        editPhone.value = clean10;
      } else {
        editPhone.value = '';
      }
    }
  }

  // Reset form to active profile values
  if (btnResetForm) {
    btnResetForm.addEventListener('click', () => {
      if (userProfile) renderProfile(userProfile);
      if (alertMsg) alertMsg.style.display = 'none';
    });
  }

  // Form Submission
  if (editForm) {
    editForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (alertMsg) alertMsg.style.display = 'none';

      const name = editName ? editName.value.trim() : '';
      let rawPhone = editPhone ? editPhone.value.trim() : '';
      let phone = '';
      if (rawPhone) {
        const digits = rawPhone.replace(/\D/g, '');
        if (digits.length === 12 && digits.startsWith('91')) {
          phone = digits.slice(2);
        } else if (digits.length === 11 && digits.startsWith('0')) {
          phone = digits.slice(1);
        } else {
          phone = digits;
        }
      }

      const submitBtn = document.getElementById('btn-save-profile');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span>Saving...</span>';
      }

      const res = await window.api.updateProfile({
        name: name,
        phone_number: phone || null,
      });

      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span>Save Profile Changes</span>';
      }

      if (res && res.ok) {
        showToast(res.data.message || 'Profile updated successfully!', 'success');
        userProfile = res.data.profile;
        renderProfile(userProfile);

        if (res.data.phone_verification_required) {
          openPhoneVerificationModal(userProfile.phone_number);
        }
      } else {
        const err = (res && res.data && res.data.error) || 'Failed to update profile.';
        if (alertMsg) {
          alertMsg.textContent = err;
          alertMsg.style.display = 'block';
        }
        showToast(err, 'error');
      }
    });
  }

  // Trigger verify on existing unverified phone
  if (btnTriggerPhoneVerify) {
    btnTriggerPhoneVerify.addEventListener('click', async () => {
      if (!userProfile || !userProfile.phone_number) return;
      btnTriggerPhoneVerify.disabled = true;
      btnTriggerPhoneVerify.textContent = 'Sending...';

      const res = await window.api.resendProfilePhoneOtp();
      btnTriggerPhoneVerify.disabled = false;
      btnTriggerPhoneVerify.textContent = 'Verify Now →';

      if (res && res.ok) {
        showToast('Verification code dispatched via SMS.', 'info');
        openPhoneVerificationModal(userProfile.phone_number);
      } else {
        const err = (res && res.data && res.data.error) || 'Could not dispatch code.';
        showToast(err, 'error');
      }
    });
  }

  // Open Modal
  function openPhoneVerificationModal(phone) {
    if (!modalPhoneOtp) return;
    if (modalPhoneDisplay) {
      if (phone && phone.length >= 4) {
        modalPhoneDisplay.textContent = `+91 ${phone.slice(0, 2)}******${phone.slice(-2)}`;
      } else {
        modalPhoneDisplay.textContent = `+91 ${phone}`;
      }
    }
    if (modalPhoneAlert) modalPhoneAlert.style.display = 'none';
    if (inputPhoneOtp) {
      inputPhoneOtp.value = '';
      setTimeout(() => inputPhoneOtp.focus(), 100);
    }
    modalPhoneOtp.style.display = 'flex';
  }

  // Close Modal
  if (btnCancelPhoneModal) {
    btnCancelPhoneModal.addEventListener('click', () => {
      if (modalPhoneOtp) modalPhoneOtp.style.display = 'none';
    });
  }

  // Verify Phone OTP
  if (formVerifyPhoneOtp) {
    formVerifyPhoneOtp.addEventListener('submit', async (e) => {
      e.preventDefault();
      const otpCode = inputPhoneOtp ? inputPhoneOtp.value.trim() : '';
      if (!otpCode || otpCode.length !== 6) {
        if (modalPhoneAlert) {
          modalPhoneAlert.textContent = 'Please enter a valid 6-digit verification code.';
          modalPhoneAlert.style.display = 'block';
        }
        return;
      }

      const submitBtn = document.getElementById('btn-submit-phone-otp');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span>Verifying...</span>';
      }

      const res = await window.api.verifyProfilePhoneOtp(otpCode);

      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span>Verify Phone</span>';
      }

      if (res && res.ok) {
        showToast('Mobile number verified successfully!', 'success');
        if (modalPhoneOtp) modalPhoneOtp.style.display = 'none';
        userProfile = res.data.profile;
        renderProfile(userProfile);
      } else {
        const err = (res && res.data && res.data.error) || 'Invalid verification code.';
        if (modalPhoneAlert) {
          modalPhoneAlert.textContent = err;
          modalPhoneAlert.style.display = 'block';
        }
        showToast(err, 'error');
      }
    });
  }

  // Resend Phone OTP with timer
  if (btnResendProfileOtp) {
    btnResendProfileOtp.addEventListener('click', async () => {
      btnResendProfileOtp.disabled = true;
      const res = await window.api.resendProfilePhoneOtp();
      if (res && res.ok) {
        showToast('A new 6-digit code has been dispatched.', 'info');
        startResendCountdown();
      } else {
        const err = (res && res.data && res.data.error) || 'Could not resend code.';
        if (modalPhoneAlert) {
          modalPhoneAlert.textContent = err;
          modalPhoneAlert.style.display = 'block';
        }
        showToast(err, 'error');
        btnResendProfileOtp.disabled = false;
      }
    });
  }

  function startResendCountdown() {
    let seconds = 60;
    btnResendProfileOtp.disabled = true;
    btnResendProfileOtp.style.color = '#64748b';
    btnResendProfileOtp.style.cursor = 'not-allowed';
    btnResendProfileOtp.textContent = `Resend available in ${seconds}s`;

    const timer = setInterval(() => {
      seconds -= 1;
      if (seconds <= 0) {
        clearInterval(timer);
        btnResendProfileOtp.disabled = false;
        btnResendProfileOtp.style.color = '#38bdf8';
        btnResendProfileOtp.style.cursor = 'pointer';
        btnResendProfileOtp.textContent = 'Resend SMS Code';
      } else {
        btnResendProfileOtp.textContent = `Resend available in ${seconds}s`;
      }
    }, 1000);
  }

  // Toast Helper
  function showToast(message, type = 'info') {
    let toast = document.getElementById('global-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'global-toast';
      toast.style.position = 'fixed';
      toast.style.bottom = '24px';
      toast.style.right = '24px';
      toast.style.zIndex = '9999';
      toast.style.padding = '12px 20px';
      toast.style.borderRadius = '8px';
      toast.style.fontWeight = '600';
      toast.style.fontSize = '14px';
      toast.style.boxShadow = '0 10px 25px rgba(0,0,0,0.5)';
      toast.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
      document.body.appendChild(toast);
    }

    if (type === 'error') {
      toast.style.background = '#ef4444';
      toast.style.color = '#ffffff';
    } else if (type === 'success') {
      toast.style.background = '#10b981';
      toast.style.color = '#ffffff';
    } else {
      toast.style.background = '#0284c7';
      toast.style.color = '#ffffff';
    }

    toast.textContent = message;
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
    }, 3500);
  }

  // Initial load
  loadProfile();
});
