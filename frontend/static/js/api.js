/**
 * AegisGuard AI - Centralized Frontend API Client & State Management
 */

const API_BASE_URL = window.location.origin;

class ApiClient {
  constructor() {
    this.tokenKey = 'aegis_access_token';
    this.userKey = 'aegis_user_profile';
  }

  getToken() {
    return localStorage.getItem(this.tokenKey);
  }

  setSession(token, user) {
    localStorage.setItem(this.tokenKey, token);
    if (user) {
      localStorage.setItem(this.userKey, JSON.stringify(user));
    }
  }

  getUser() {
    const raw = localStorage.getItem(this.userKey);
    try {
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  clearSession() {
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.userKey);
  }

  isAuthenticated() {
    return !!this.getToken();
  }

  async request(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      const data = await response.json().catch(() => ({}));

      // Handle 401 Unauthorized only for actual JWT token expiry / invalidation
      if (response.status === 401) {
        const isJwtFailure = !token || (data && (
          data.code === 'TOKEN_EXPIRED' ||
          (typeof data.msg === 'string' && (
            data.msg.toLowerCase().includes('token') ||
            data.msg.toLowerCase().includes('authorization header') ||
            data.msg.toLowerCase().includes('signature')
          ))
        ));

        if (isJwtFailure && !window.location.pathname.includes('/login') && !window.location.pathname.includes('/register') && !window.location.pathname.includes('/forgot-password') && !window.location.pathname.includes('/reset-password')) {
          this.clearSession();
          window.location.href = '/login?expired=1';
          return null;
        }
      }

      return {
        ok: response.ok,
        status: response.status,
        data,
      };
    } catch (err) {
      console.error('API Request Network Error:', err);
      return {
        ok: false,
        status: 0,
        data: { error: 'Network communication failure. Please check server connectivity.' },
      };
    }
  }

  // Common API Endpoints
  async login(email, password) {
    return this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async register(name, email, password) {
    return this.request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, role: 'USER' }),
    });
  }

  async forgotPassword(email) {
    return this.request('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async resetPassword(token, new_password, confirm_password) {
    return this.request('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, new_password, confirm_password }),
    });
  }

  async getProfile() {
    return this.request('/api/profile', { method: 'GET' });
  }

  async updateProfile(payload) {
    return this.request('/api/profile', {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  }

  async getBeneficiaries() {
    return this.request('/api/beneficiaries', { method: 'GET' });
  }

  async addBeneficiary(payload) {
    return this.request('/api/beneficiaries', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async updateBeneficiary(id, payload) {
    return this.request(`/api/beneficiaries/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  }

  async deleteBeneficiary(id) {
    return this.request(`/api/beneficiaries/${id}`, {
      method: 'DELETE',
    });
  }

  async submitTransaction(payload) {
    return this.request('/api/transactions/predict', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getMyTransactions(limit = 50) {
    return this.request(`/api/transactions/my-history?limit=${limit}`, { method: 'GET' });
  }

  async getTransactionDetail(id) {
    return this.request(`/api/transactions/${id}`, { method: 'GET' });
  }

  async generateOtp(transactionId) {
    return this.request('/api/otp/generate', {
      method: 'POST',
      body: JSON.stringify({ transaction_id: transactionId }),
    });
  }

  async verifyOtp(transactionId, otpCode) {
    return this.request('/api/otp/verify', {
      method: 'POST',
      body: JSON.stringify({ transaction_id: transactionId, otp_code: otpCode }),
    });
  }

  async resolveRecipient(query) {
    return this.request('/api/transactions/resolve-recipient', {
      method: 'POST',
      body: JSON.stringify({ query }),
    });
  }

  async parseQrCode(qrData) {
    return this.request('/api/transactions/parse-qr', {
      method: 'POST',
      body: JSON.stringify({ qr_data: qrData }),
    });
  }

  async setPaymentPin(password, pin, confirmPin) {
    return this.request('/api/auth/payment-pin/set', {
      method: 'POST',
      body: JSON.stringify({ password, pin, confirm_pin: confirmPin }),
    });
  }

  async getPaymentPinStatus() {
    return this.request('/api/auth/payment-pin/status', { method: 'GET' });
  }
}

// Global API instance
window.api = new ApiClient();

// Toast notification utility
window.showToast = function (message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast-item';

  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'error') icon = '❌';
  if (type === 'warning') icon = '⚠️';

  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
};
