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
        if (errorBox) {
          errorBox.textContent = errorText;
          errorBox.style.display = 'block';
        }
        showToast(errorText, 'error');
      }
    });
  }

  // 3. Register Form Handler
  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('reg-name').value.trim();
      const email = document.getElementById('reg-email').value.trim();
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

      const res = await window.api.register(name, email, password);
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Register Account</span>';

      if (res && res.ok) {
        showToast('Registration successful! Please sign in.', 'success');
        setTimeout(() => {
          window.location.href = '/login?registered=1';
        }, 800);
      } else {
        const errorText = (res && res.data && res.data.error) || 'Registration failed.';
        if (errorBox) {
          errorBox.textContent = errorText;
          errorBox.style.display = 'block';
        }
        showToast(errorText, 'error');
      }
    });
  }

  // 4. Forgot Password Form Handler
  const forgotForm = document.getElementById('forgot-password-form');
  if (forgotForm) {
    forgotForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('forgot-email').value.trim();
      const submitBtn = document.getElementById('btn-forgot-submit');
      const errorBox = document.getElementById('forgot-error-msg');
      const successBox = document.getElementById('forgot-success-box');
      const successText = document.getElementById('forgot-success-text');
      const devBanner = document.getElementById('dev-token-banner');
      const devTokenVal = document.getElementById('dev-token-value');
      const proceedBtn = document.getElementById('btn-proceed-reset');

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
          if (res.data && res.data.dev_reset_token) {
            if (devBanner && devTokenVal) {
              devBanner.style.display = 'block';
              devTokenVal.textContent = res.data.dev_reset_token;
            }
            if (proceedBtn) {
              proceedBtn.href = `/reset-password?token=${encodeURIComponent(res.data.dev_reset_token)}`;
            }
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

// Helpers for Demo Autofill
window.autofillDemoUser = function () {
  const emailField = document.getElementById('email');
  const passwordField = document.getElementById('password');
  if (emailField && passwordField) {
    emailField.value = 'user@example.com';
    passwordField.value = 'UserDemo2026!';
  }
};

window.autofillDemoAdmin = function () {
  const emailField = document.getElementById('email');
  const passwordField = document.getElementById('password');
  if (emailField && passwordField) {
    emailField.value = 'admin@example.com';
    passwordField.value = 'AdminDemo2026!';
  }
};

window.autofillDemoCustomer1 = function () {
  const emailField = document.getElementById('email');
  const passwordField = document.getElementById('password');
  if (emailField && passwordField) {
    emailField.value = 'customer1@example.com';
    passwordField.value = 'UserDemo2026!';
  }
};

window.autofillDemoCustomer2 = function () {
  const emailField = document.getElementById('email');
  const passwordField = document.getElementById('password');
  if (emailField && passwordField) {
    emailField.value = 'customer2@example.com';
    passwordField.value = 'UserDemo2026!';
  }
};
