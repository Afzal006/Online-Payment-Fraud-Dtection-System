/**
 * Admin Security Operations Center (SOC) API Client
 */

class AdminApiClient {
  constructor() {
    this.api = window.api;
  }

  async checkAdmin() {
    return this.api.request('/api/admin/check', { method: 'GET' });
  }

  async getOverview() {
    return this.api.request('/api/admin/overview', { method: 'GET' });
  }

  async getCustomers(search = '', sortBy = 'newest', limit = 100) {
    let url = `/api/admin/customers?limit=${limit}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (sortBy) url += `&sort_by=${encodeURIComponent(sortBy)}`;
    return this.api.request(url, { method: 'GET' });
  }

  async getCustomerDetail(customerId) {
    return this.api.request(`/api/admin/customers/${customerId}`, { method: 'GET' });
  }

  async getAnalytics() {
    return this.api.request('/api/admin/analytics', { method: 'GET' });
  }

  async getAlerts(status = '', limit = 50) {
    let url = `/api/admin/alerts?limit=${limit}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    return this.api.request(url, { method: 'GET' });
  }

  async getAlertDetail(alertId) {
    return this.api.request(`/api/admin/alerts/${alertId}`, { method: 'GET' });
  }

  async resolveAlert(alertId, note = '') {
    return this.api.request(`/api/admin/alerts/${alertId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ note }),
    });
  }

  async dismissAlert(alertId, note = '') {
    return this.api.request(`/api/admin/alerts/${alertId}/dismiss`, {
      method: 'POST',
      body: JSON.stringify({ note }),
    });
  }

  async getTransactions(limit = 100, riskLevel = '', type = '', status = '', search = '', sortBy = 'newest') {
    let url = `/api/admin/transactions?limit=${limit}`;
    if (riskLevel) url += `&risk_level=${encodeURIComponent(riskLevel)}`;
    if (type) url += `&type=${encodeURIComponent(type)}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (sortBy) url += `&sort_by=${encodeURIComponent(sortBy)}`;
    return this.api.request(url, { method: 'GET' });
  }

  async getTransactionDetail(txId) {
    return this.api.request(`/api/admin/transactions/${txId}`, { method: 'GET' });
  }

  async getModelInfo() {
    return this.api.request('/api/admin/model-info', { method: 'GET' });
  }
}

window.adminApi = new AdminApiClient();
