/**
 * User Transaction History Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  if (!window.api.isAuthenticated()) {
    window.location.href = '/login';
    return;
  }

  const profileRes = await window.api.getProfile();
  if (profileRes && profileRes.ok && profileRes.data.user && profileRes.data.user.role === 'ADMIN') {
    window.location.href = '/admin/transactions';
    return;
  }

  let allTransactions = [];

  const tbody = document.getElementById('history-tbody');
  const emptyState = document.getElementById('history-empty-state');
  const searchInput = document.getElementById('history-search');
  const filterType = document.getElementById('filter-type');
  const filterRisk = document.getElementById('filter-risk');

  // Fetch all user transactions
  const res = await window.api.getMyTransactions(100);
  if (res && res.ok) {
    allTransactions = res.data.transactions || [];
    renderHistoryTable(allTransactions);
  }

  function renderHistoryTable(txs) {
    if (!tbody) return;
    tbody.innerHTML = '';

    if (txs.length === 0) {
      if (emptyState) emptyState.style.display = 'block';
      return;
    }

    if (emptyState) emptyState.style.display = 'none';

    txs.forEach((tx) => {
      const row = document.createElement('tr');
      const dateStr = tx.created_at ? new Date(tx.created_at).toLocaleString() : 'N/A';
      const riskClass = `badge-risk badge-risk-${(tx.risk_level || 'LOW').toLowerCase()}`;

      row.innerHTML = `
        <td style="font-weight: 600; color: #E2E8F0;">#${tx.id}</td>
        <td><span style="font-weight: 600;">${tx.type}</span></td>
        <td style="font-weight: 700; color: #fff;">$${parseFloat(tx.amount).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
        <td style="color: var(--text-muted); font-size: 0.85rem;">${tx.name_dest || 'N/A'}</td>
        <td><span class="${riskClass}">${tx.risk_level} (${tx.risk_score})</span></td>
        <td>
          <span style="font-weight: 600; color: ${tx.status === 'APPROVED' ? '#34D399' : (tx.status === 'REJECTED' ? '#F87171' : '#FBBF24')};">
            ${tx.status}
          </span>
        </td>
        <td style="color: var(--text-dim); font-size: 0.8rem;">${dateStr}</td>
        <td>
          <button class="btn-secondary-custom" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;" onclick="viewShapForTx(${tx.id})">
            Explain AI
          </button>
        </td>
      `;
      tbody.appendChild(row);
    });
  }

  // Filter and Search
  function applyFilters() {
    const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
    const typeVal = filterType ? filterType.value : '';
    const riskVal = filterRisk ? filterRisk.value : '';

    const filtered = allTransactions.filter((tx) => {
      const matchesSearch =
        !q ||
        String(tx.id).includes(q) ||
        (tx.name_dest && tx.name_dest.toLowerCase().includes(q)) ||
        (tx.type && tx.type.toLowerCase().includes(q));

      const matchesType = !typeVal || tx.type === typeVal;
      const matchesRisk = !riskVal || tx.risk_level === riskVal;

      return matchesSearch && matchesType && matchesRisk;
    });

    renderHistoryTable(filtered);
  }

  if (searchInput) searchInput.addEventListener('input', applyFilters);
  if (filterType) filterType.addEventListener('change', applyFilters);
  if (filterRisk) filterRisk.addEventListener('change', applyFilters);
});
