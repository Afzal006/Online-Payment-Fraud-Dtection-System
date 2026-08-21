/**
 * Authentication Form Handlers (Login & Register)
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Check if token expired parameter exists
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('expired') === '1') {
    showToast('Your session has expired. Please sign in again.', 'warning');
  }

  // 2. Login Form Handler
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    // Autofill email if passed via query parameter
    const loginEmailInput = document.getElementById('email');
    if (loginEmailInput && urlParams.get('email')) {
      loginEmailInput.value = urlParams.get('email').trim();
    }

    // Show banner if redirected with verified notice
    if (urlParams.get('verified') === '1' || urlParams.get('verified') === 'email') {
      showToast('Verification complete! Please sign in with your credentials.', 'success');
    }

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const submitBtn = document.getElementById('btn-login-submit');
      const errorBox = document.getElementById('auth-error-msg');

      if (!email || !password) {
        if (errorBox) {
          errorBox.textContent = 'Please enter both email and password.';
          errorBox.style.display = 'block';
        }
        return;
      }

      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>Verifying...</span>';
      if (errorBox) errorBox.style.display = 'none';

      const res = await window.api.login(email, password);
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Sign In</span>';

      if (res && res.ok && res.data.access_token) {
        window.api.setSession(res.data.access_token, res.data.user);
        showToast('Login successful! Redirecting...', 'success');
        const redirectTarget = res.data.redirect_url || (res.data.user && res.data.user.role === 'ADMIN' ? '/admin/dashboard' : '/dashboard');
        setTimeout(() => {
          window.location.href = redirectTarget;
        }, 500);
      } else {
        const errorText = (res && res.data && res.data.error) || 'Invalid email or password.';
        const errorCode = res && res.data && res.data.code;
        
        if (errorBox) {
          if (errorCode === 'EMAIL_NOT_VERIFIED' || errorCode === 'PHONE_NOT_VERIFIED' || errorText.toLowerCase().includes('verify')) {
            errorBox.innerHTML = `<div><strong>Account Verification Required:</strong> ${errorText}</div>
            <div style="margin-top: 8px;"><a href="/register?verify=1&email=${encodeURIComponent(email)}" style="color: #38bdf8; text-decoration: underline; font-weight: 600;">Complete Verification Now →</a></div>`;
          } else {
            errorBox.textContent = errorText;
          }
          errorBox.style.display = 'block';
        }
        showToast(errorText, 'error');
      }
    });
  }

  // 3. Register & Verification Hub Form Handler
  const registerForm = document.getElementById('register-form');
  const stepRegContainer = document.getElementById('step-registration-container');
  const stepVerifyContainer = document.getElementById('step-verification-container');

  let currentRegEmail = '';
  let currentRegPhone = '';
  let emailVerified = false;
  let phoneVerified = false;

  function updateActivationState() {
    if (emailVerified || phoneVerified) {
      const completeSection = document.getElementById('section-activation-complete');
      if (completeSection) completeSection.style.display = 'block';
      showToast('Account activated! You can now log in.', 'success');
    }
  }

  function startCountdown(buttonId, originalText, durationSec = 60) {
    const btn = document.getElementById(buttonId);
    if (!btn) return;
    btn.disabled = true;
    let remaining = durationSec;
    btn.textContent = `Resend in ${remaining}s`;
    const interval = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        clearInterval(interval);
        btn.disabled = false;
        btn.textContent = originalText;
      } else {
        btn.textContent = `Resend in ${remaining}s`;
      }
    }, 1000);
  }

  function showVerifyHubAlert(msg, type = 'error') {
    const alertBox = document.getElementById('verify-hub-alert');
    if (!alertBox) return;
    alertBox.textContent = msg;
    if (type === 'success') {
      alertBox.style.background = 'rgba(16, 185, 129, 0.15)';
      alertBox.style.border = '1px solid rgba(16, 185, 129, 0.4)';
      alertBox.style.color = '#34d399';
    } else {
      alertBox.style.background = 'rgba(239, 68, 68, 0.15)';
      alertBox.style.border = '1px solid rgba(239, 68, 68, 0.4)';
      alertBox.style.color = '#fca5a5';
    }
    alertBox.style.display = 'block';
  }

  if (registerForm) {
    // Check if user came from verification prompt with ?verify=1&email=...
    if (urlParams.get('verify') === '1' && urlParams.get('email')) {
      const targetEmail = urlParams.get('email').trim();
      currentRegEmail = targetEmail;
      if (stepRegContainer) stepRegContainer.style.display = 'none';
      if (stepVerifyContainer) stepVerifyContainer.style.display = 'block';
      const emailDisplay = document.getElementById('verify-email-display');
      if (emailDisplay) emailDisplay.textContent = targetEmail;
      window.api.resendEmailVerification(targetEmail);
      showToast('Loaded verification portal. Fresh verification code requested.', 'info');
    }

    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('reg-name').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const rawPhone = document.getElementById('reg-phone') ? document.getElementById('reg-phone').value.trim() : '';
      let phone = rawPhone.replace(/[^\d+]/g, '');
      if (phone.startsWith('+91')) {
        phone = phone.slice(3);
      } else if (phone.startsWith('91') && phone.length === 12) {
        phone = phone.slice(2);
      } else if (phone.startsWith('0') && phone.length === 11) {
        phone = phone.slice(1);
      }
      const password = document.getElementById('reg-password').value;
      const confirmPassword = document.getElementById('reg-confirm-password').value;
      const submitBtn = document.getElementById('btn-register-submit');
      const errorBox = document.getElementById('auth-error-msg');

      if (!name || !email || !password) {
        if (errorBox) {
          errorBox.textContent = 'Please fill out all required fields.';
          errorBox.style.display = 'block';
        }
        return;
      }

      if (password !== confirmPassword) {
        if (errorBox) {
          errorBox.textContent = 'Passwords do not match.';
          errorBox.style.display = 'block';
        }
        return;
      }

      if (password.length < 8) {
        if (errorBox) {
          errorBox.textContent = 'Password must be at least 8 characters long.';
          errorBox.style.display = 'block';
        }
        return;
      }

      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>Creating Account...</span>';
      if (errorBox) errorBox.style.display = 'none';

      const res = await window.api.register(name, email, password, phone);
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Create Account & Verify</span>';

      if (res && res.ok) {
        currentRegEmail = email;
        currentRegPhone = phone;
        emailVerified = false;
        phoneVerified = !phone; // If no phone, phone is automatically resolved

        // Transition to Step 2 Verification Hub
        if (stepRegContainer) stepRegContainer.style.display = 'none';
        if (stepVerifyContainer) stepVerifyContainer.style.display = 'block';

        const emailDisplay = document.getElementById('verify-email-display');
        if (emailDisplay) emailDisplay.textContent = email;

        const phoneDisplay = document.getElementById('verify-phone-display');
        const phoneCard = document.getElementById('card-phone-verification');
        if (phone) {
          if (phoneDisplay) phoneDisplay.textContent = `+91 ${phone.slice(0, 2)}******${phone.slice(-2)}`;
          if (phoneCard) phoneCard.style.display = 'block';
        } else {
          if (phoneCard) phoneCard.style.display = 'none';
        }

        showToast('Account created! Please enter verification code.', 'success');
      } else {
        const errorText = (res && res.data && res.data.error) || 'Registration failed.';
        const errorCode = res && res.data && res.data.code;
        if (errorBox) {
          if (errorCode === 'ACCOUNT_EXISTS_UNVERIFIED' || errorText.toLowerCase().includes('pending verification')) {
            errorBox.innerHTML = `
              <div style="margin-bottom: 8px;"><strong>Account Pending Verification:</strong> ${errorText}</div>
              <div style="margin-top: 10px;">
                <button type="button" id="btn-resume-verify" style="font-size: 13px; padding: 7px 14px; background: rgba(56, 189, 248, 0.15); border: 1px solid #38bdf8; color: #38bdf8; border-radius: 6px; cursor: pointer; font-weight: 600;">
                  Resume Verification →
                </button>
              </div>
            `;
            const resumeBtn = document.getElementById('btn-resume-verify');
            if (resumeBtn) {
              resumeBtn.addEventListener('click', () => {
                currentRegEmail = email;
                currentRegPhone = phone;
                emailVerified = false;
                phoneVerified = !phone;
                if (stepRegContainer) stepRegContainer.style.display = 'none';
                if (stepVerifyContainer) stepVerifyContainer.style.display = 'block';
                const emailDisplay = document.getElementById('verify-email-display');
                if (emailDisplay) emailDisplay.textContent = email;
                window.api.resendEmailVerification(email);
                showToast('Switched to verification portal. Verification code requested.', 'info');
              });
            }
          } else if (errorCode === 'ACCOUNT_ALREADY_EXISTS' || errorText.toLowerCase().includes('already')) {
            errorBox.innerHTML = `
              <div style="margin-bottom: 8px;"><strong>Account Already Exists:</strong> ${errorText}</div>
              <div style="display: flex; gap: 12px; margin-top: 10px; align-items: center;">
                <a href="/login?email=${encodeURIComponent(email)}" style="color: #38bdf8; text-decoration: underline; font-weight: 600; font-size: 13px;">Sign In →</a>
                <span style="color: #64748b;">|</span>
                <a href="/forgot-password?email=${encodeURIComponent(email)}" style="color: #38bdf8; text-decoration: underline; font-weight: 600; font-size: 13px;">Reset Forgotten Password →</a>
              </div>
            `;
          } else {
            errorBox.textContent = errorText;
          }
          errorBox.style.display = 'block';
        }
        showToast(errorText, 'error');
      }
    });

    // Verification Hub: Email OTP verification button
    const btnVerifyEmail = document.getElementById('btn-verify-email');
    if (btnVerifyEmail) {
      btnVerifyEmail.addEventListener('click', async () => {
        const inputOtp = document.getElementById('input-email-otp');
        const otpCode = inputOtp ? inputOtp.value.trim() : '';
        if (!otpCode || otpCode.length !== 6) {
          showVerifyHubAlert('Please enter the valid 6-digit email verification code.');
          return;
        }

        btnVerifyEmail.disabled = true;
        btnVerifyEmail.innerHTML = '<span>Checking...</span>';

        const res = await window.api.verifyEmailOtp(currentRegEmail, otpCode);
        btnVerifyEmail.disabled = false;
        btnVerifyEmail.innerHTML = '<span>Verify</span>';

        if (res && res.ok) {
          emailVerified = true;
          const badge = document.getElementById('badge-email-status');
          if (badge) {
            badge.textContent = 'Verified ✓';
            badge.style.background = 'rgba(16, 185, 129, 0.2)';
            badge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
            badge.style.color = '#34d399';
          }
          const sectionInput = document.getElementById('section-email-input');
          const sectionDone = document.getElementById('section-email-completed');
          if (sectionInput) sectionInput.style.display = 'none';
          if (sectionDone) sectionDone.style.display = 'flex';

          showVerifyHubAlert('Email ownership verified successfully!', 'success');
          updateActivationState();
        } else {
          const err = (res && res.data && res.data.error) || 'Verification code failed.';
          showVerifyHubAlert(err, 'error');
        }
      });
    }

    // Verification Hub: Email OTP resend button
    const btnResendEmail = document.getElementById('btn-resend-email-otp');
    if (btnResendEmail) {
      btnResendEmail.addEventListener('click', async () => {
        if (!currentRegEmail) return;
        const res = await window.api.resendEmailVerification(currentRegEmail);
        if (res && res.ok) {
          showToast('New verification code sent to your email.', 'success');
          startCountdown('btn-resend-email-otp', 'Resend Email Code', 60);
        } else {
          const err = (res && res.data && res.data.error) || 'Failed to resend code.';
          showVerifyHubAlert(err, 'error');
        }
      });
    }

    // Verification Hub: Phone OTP verification button
    const btnVerifyPhone = document.getElementById('btn-verify-phone');
    if (btnVerifyPhone) {
      btnVerifyPhone.addEventListener('click', async () => {
        const inputOtp = document.getElementById('input-phone-otp');
        const otpCode = inputOtp ? inputOtp.value.trim() : '';
        if (!otpCode || otpCode.length !== 6) {
          showVerifyHubAlert('Please enter the 6-digit SMS OTP.');
          return;
        }

        btnVerifyPhone.disabled = true;
        btnVerifyPhone.innerHTML = '<span>Checking...</span>';

        const res = await window.api.verifyPhoneOtp(currentRegPhone, otpCode, currentRegEmail);
        btnVerifyPhone.disabled = false;
        btnVerifyPhone.innerHTML = '<span>Verify</span>';

        if (res && res.ok) {
          phoneVerified = true;
          const badge = document.getElementById('badge-phone-status');
          if (badge) {
            badge.textContent = 'Verified ✓';
            badge.style.background = 'rgba(16, 185, 129, 0.2)';
            badge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
            badge.style.color = '#34d399';
          }
          const sectionInput = document.getElementById('section-phone-input');
          const sectionDone = document.getElementById('section-phone-completed');
          if (sectionInput) sectionInput.style.display = 'none';
          if (sectionDone) sectionDone.style.display = 'flex';

          showVerifyHubAlert('Mobile number verified successfully!', 'success');
          updateActivationState();
        } else {
          const err = (res && res.data && res.data.error) || 'SMS verification code failed.';
          showVerifyHubAlert(err, 'error');
        }
      });
    }

    // Verification Hub: Phone OTP resend button
    const btnResendPhone = document.getElementById('btn-resend-phone-otp');
    if (btnResendPhone) {
      btnResendPhone.addEventListener('click', async () => {
        const id = currentRegPhone || currentRegEmail;
        if (!id) return;
        const res = await window.api.resendPhoneOtp(id, currentRegEmail);
        if (res && res.ok) {
          showToast('New verification code sent via SMS.', 'success');
          startCountdown('btn-resend-phone-otp', 'Resend SMS Code', 60);
        } else {
          const err = (res && res.data && res.data.error) || 'Failed to resend SMS code.';
          showVerifyHubAlert(err, 'error');
        }
      });
    }
  }

  // 4. Forgot Password Form Handler
  const forgotForm = document.getElementById('forgot-password-form');
  if (forgotForm) {
    const forgotEmailInput = document.getElementById('forgot-email');
    if (forgotEmailInput && urlParams.get('email')) {
      forgotEmailInput.value = urlParams.get('email').trim();
    }

    forgotForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('forgot-email').value.trim();
      const submitBtn = document.getElementById('btn-forgot-submit');
      const errorBox = document.getElementById('forgot-error-msg');
      const successBox = document.getElementById('forgot-success-box');
      const successText = document.getElementById('forgot-success-text');

      if (!email) {
        if (errorBox) {
          errorBox.textContent = 'Please enter a valid email address.';
          errorBox.style.display = 'block';
        }
        return;
      }

      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>Sending Instructions...</span>';
      if (errorBox) errorBox.style.display = 'none';

      const res = await window.api.forgotPassword(email);
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Send Reset Instructions</span>';

      if (res && res.ok) {
        if (forgotForm) forgotForm.style.display = 'none';
        if (successBox) {
          successBox.style.display = 'block';
          if (res.data && res.data.message) {
            successText.textContent = res.data.message;
          }
        }
        showToast('Password reset instructions processed', 'success');
      } else {
        const errorText = (res && res.data && res.data.error) || 'Failed to process request.';
        if (errorBox) {
          errorBox.textContent = errorText;
          errorBox.style.display = 'block';
        }
        showToast(errorText, 'error');
      }
    });
  }

  // 5. Reset Password Form Handler
  const resetForm = document.getElementById('reset-password-form');
  if (resetForm) {
    // Autofill token from query parameter if present
    const resetTokenInput = document.getElementById('reset-token');
    if (resetTokenInput && urlParams.get('token')) {
      resetTokenInput.value = urlParams.get('token').trim();
    }

    resetForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = document.getElementById('reset-token').value.trim();
      const newPassword = document.getElementById('reset-new-password').value;
      const confirmPassword = document.getElementById('reset-confirm-password').value;
      const submitBtn = document.getElementById('btn-reset-submit');
      const errorBox = document.getElementById('reset-error-msg');
      const successBox = document.getElementById('reset-success-box');

      if (!token) {
        if (errorBox) {
          errorBox.textContent = 'Please provide the password reset token.';
          errorBox.style.display = 'block';
        }
        return;
      }

      if (!newPassword || newPassword.length < 8) {
        if (errorBox) {
          errorBox.textContent = 'New password must be at least 8 characters long.';
          errorBox.style.display = 'block';
        }
        return;
      }

      if (newPassword !== confirmPassword) {
        if (errorBox) {
          errorBox.textContent = 'Passwords do not match.';
          errorBox.style.display = 'block';
        }
        return;
      }

      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>Updating Password...</span>';
      if (errorBox) errorBox.style.display = 'none';

      const res = await window.api.resetPassword(token, newPassword, confirmPassword);
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Reset Password</span>';

      if (res && res.ok) {
        if (resetForm) resetForm.style.display = 'none';
        if (successBox) successBox.style.display = 'block';
        showToast('Password reset successful! Redirecting to sign in...', 'success');
        setTimeout(() => {
          window.location.href = '/login?reset=1';
        }, 1500);
      } else {
        const errorText = (res && res.data && res.data.error) || 'Failed to reset password.';
        if (errorBox) {
          errorBox.textContent = errorText;
          errorBox.style.display = 'block';
        }
        showToast(errorText, 'error');
      }
    });
  }
});
