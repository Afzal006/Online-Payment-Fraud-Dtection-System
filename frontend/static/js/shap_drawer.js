/**
 * SHAP Explainability Drawer Component
 * Renders dynamic feature contribution bars and natural language risk summary.
 */

class ShapDrawer {
  constructor() {
    this.overlay = document.getElementById('shap-drawer-overlay');
    this.panel = document.getElementById('shap-drawer-panel');
    this.closeBtn = document.getElementById('btn-close-shap-drawer');

    if (this.closeBtn) {
      this.closeBtn.addEventListener('click', () => this.close());
    }

    if (this.overlay) {
      this.overlay.addEventListener('click', (e) => {
        if (e.target === this.overlay) this.close();
      });
    }
  }

  open(explanationData, riskScore, riskLevel) {
    if (!this.overlay) return;

    // 1. Set Risk Score Badge
    const scoreVal = document.getElementById('shap-risk-score-val');
    const scoreBadge = document.getElementById('shap-risk-badge');
    if (scoreVal) scoreVal.textContent = `${riskScore}/100`;

    if (scoreBadge) {
      scoreBadge.className = `badge-risk badge-risk-${riskLevel.toLowerCase()}`;
      scoreBadge.textContent = riskLevel;
    }

    // 2. Set Natural Language Narrative
    const narrativeEl = document.getElementById('shap-narrative-text');
    if (narrativeEl) {
      narrativeEl.textContent =
        explanationData.explanation_text ||
        explanationData.human_readable_summary ||
        'Model assessment determined based on transaction baseline variance.';
    }

    // 3. Render Feature Bars
    const listEl = document.getElementById('shap-features-list');
    if (listEl) {
      listEl.innerHTML = '';
      const topFeatures = explanationData.top_features || [];

      if (topFeatures.length === 0) {
        listEl.innerHTML = '<p class="text-muted">No high-variance feature drivers detected.</p>';
      } else {
        // Calculate max absolute SHAP for relative bar scaling
        const maxAbs = Math.max(...topFeatures.map((f) => Math.abs(f.shap_value || f.impact || 0.001)), 0.01);

        topFeatures.forEach((feat) => {
          const name = feat.feature_name || feat.feature || 'Unknown Feature';
          const shapVal = feat.shap_value || feat.impact || 0;
          const isRiskIncreaser = feat.direction === 'INCREASES_FRAUD_RISK' || shapVal > 0;
          const fillWidth = Math.min(100, Math.max(8, (Math.abs(shapVal) / maxAbs) * 100));

          const item = document.createElement('div');
          item.className = 'shap-bar-item';
          item.innerHTML = `
            <div class="shap-bar-header">
              <span style="font-weight: 600; color: #E2E8F0;">${name}</span>
              <span style="font-weight: 700; color: ${isRiskIncreaser ? '#F87171' : '#34D399'};">
                ${isRiskIncreaser ? '+' : ''}${shapVal.toFixed(4)}
              </span>
            </div>
            <div class="shap-bar-track">
              <div class="${isRiskIncreaser ? 'shap-bar-fill-positive' : 'shap-bar-fill-negative'}" 
                   style="width: ${fillWidth}%;"></div>
            </div>
          `;
          listEl.appendChild(item);
        });
      }
    }

    this.overlay.classList.add('active');
  }

  close() {
    if (this.overlay) {
      this.overlay.classList.remove('active');
    }
  }
}

window.shapDrawer = new ShapDrawer();
