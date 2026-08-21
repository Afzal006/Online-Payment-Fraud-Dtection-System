/**
 * Admin Customer Accounts Directory Controller
 * Handles customer listing, search queries, sorting, and navigation to details.
 */

let searchDebounceTimer = null;

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

  // 2. Load Customers
  await loadCustomersTable();
});

function onCustomerSearch() {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => {
    loadCustomersTable();
  }, 300);
}

async function loadCustomersTable() {
  const searchInput = document.getElementById('customer-search-input');
  const sortSelect = document.getElementById('customer-sort-select');
  const tbody = document.getElementById('customers-page-tbody');
  const emptyState = document.getElementById('customers-page-empty');

  const search = searchInput ? searchInput.value.trim() : '';
  const sortBy = sortSelect ? sortSelect.value : 'newest';

  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="11" style="text-align: center; color: var(--text-muted); padding: 2rem;">Loading customer identities...</td></tr>';

  const res = await window.adminApi.getCustomers(search, sortBy, 100);

  tbody.innerHTML = '';

  if (!res || !res.ok || !res.data.customers || res.data.customers.length === 0) {
    if (emptyState) emptyState.style.display = 'block';
    return;
  }

  if (emptyState) emptyState.style.display = 'none';

  res.data.customers.forEach((cust) => {
    const row = document.createElement('tr');
    const accountId = cust.customer_account_id || `FS-${100000 + cust.id}`;
    const upiId = cust.primary_upi_id || `${cust.email.split('@')[0]}@fraudshield`;
    const phone = cust.phone_number || 'N/A';
    const balance = cust.account_balance !== undefined ? parseFloat(cust.account_balance) : 0;
    const bCount = cust.beneficiary_count || 0;

    const highRiskBadge = cust.high_risk_count > 0 
      ? `<span class="badge-risk badge-risk-high" style="font-size: 0.75rem;">${cust.high_risk_count} Flags</span>`
      : `<span style="color: var(--text-dim); font-size: 0.8rem;">0</span>`;

    const alertsBadge = cust.open_alert_count > 0
      ? `<span class="badge-risk badge-risk-high" style="font-size: 0.75rem;">${cust.open_alert_count} OPEN</span>`
      : `<span style="color: var(--text-dim); font-size: 0.8rem;">0</span>`;

    row.innerHTML = `
      <td style="font-weight: 700; color: #60A5FA; font-family: monospace;">${accountId}</td>
      <td style="font-weight: 600; color: #fff;">
        <div>${cust.name}</div>
        <div style="font-size: 0.75rem; color: var(--text-dim); font-weight: normal;">${cust.email}</div>
      </td>
      <td style="color: var(--primary); font-family: monospace; font-size: 0.85rem;">${upiId}</td>
      <td style="font-size: 0.85rem; color: #E2E8F0;">
        ${phone}
        ${cust.is_phone_verified ? '<span style="color: #34D399; font-size: 0.75rem;"> ✓</span>' : ''}
      </td>
      <td style="font-weight: 700; color: #34D399; font-family: monospace;">₹${balance.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
      <td style="font-weight: 600; color: #E2E8F0; text-align: center;">
        <span style="background: rgba(59, 130, 246, 0.15); color: #60A5FA; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">${bCount} saved</span>
      </td>
      <td style="font-weight: 600; color: #E2E8F0; text-align: center;">${cust.transaction_count}</td>
      <td style="font-weight: 700; color: #fff;">₹${cust.total_volume.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
      <td style="text-align: center;">${highRiskBadge}</td>
      <td style="text-align: center;">${alertsBadge}</td>
      <td>
        <a href="/admin/customers/${cust.id}" class="btn-primary-custom" style="padding: 0.35rem 0.75rem; font-size: 0.75rem; display: inline-flex; align-items: center; gap: 0.25rem;">
          <span>View Customer</span>
          <span>→</span>
        </a>
      </td>
    `;
    tbody.appendChild(row);
  });
}
