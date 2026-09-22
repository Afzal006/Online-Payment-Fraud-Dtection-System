"""
High-Resolution Academic Diagram Generator for FraudShield AI Project Report.
Generates publication-quality diagrams for Design Thinking, UML, Architecture, and XAI.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
from pathlib import Path

FIGURES_DIR = Path(__file__).resolve().parent.parent / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Helvetica", "DejaVu Sans", "Arial"]

# ----------------------------------------------------------------------
# 1. EMPATHY MAP (Design Thinking Phase)
# ----------------------------------------------------------------------
def generate_empathy_map():
    fig, ax = plt.subplots(figsize=(10, 7), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")

    # Title & Header
    ax.text(5, 6.6, "DESIGN THINKING EMPATHY MAP: RETAIL PAYMENT USERS & SOC ANALYSTS",
            ha="center", va="center", fontsize=12, fontweight="bold", color="#1e3a8a")

    # 4 Quadrants
    quadrants = [
        ("SAYS", ["\"I need my payments to clear instantly without friction.\"",
                  "\"Why was my payment blocked when I had sufficient funds?\"",
                  "\"I want clear notifications if something looks suspicious.\"",
                  "\"As a SOC analyst, I need exact feature explanations, not black-box scores.\""],
         0.4, 3.4, 4.4, 2.8, "#f0f9ff", "#0284c7"),
        ("THINKS", ["Will my account be drained if I click the wrong link?",
                   "Is this transaction blocked because of a real threat or a bug?",
                   "Legitimate users shouldn't have their funds deducted during review.",
                   "Can we trust this ML model on edge cases and high-value transfers?"],
         5.2, 3.4, 4.4, 2.8, "#f8fafc", "#475569"),
        ("DOES", ["Initiates P2P and merchant payments via UPI and web forms.",
                  "Enters OTP verification when prompted for high-value transfers.",
                  "SOC Analyst reviews alert queue and inspects SHAP waterfall graphs.",
                  "Manages trusted beneficiaries and verifies account balances."],
         0.4, 0.4, 4.4, 2.8, "#fefce8", "#ca8a04"),
        ("FEELS", ["Anxious about digital payment fraud and unauthorized account draining.",
                   "Frustrated when transactions are delayed without transparent explanation.",
                   "Confident when security holds balance and explains risk reasons.",
                   "Empowered when provided dual-perspective transparency (User + SOC)."],
         5.2, 0.4, 4.4, 2.8, "#fdf2f8", "#db2777")
    ]

    for title, items, x, y, w, h, bg, border in quadrants:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.15,rounding_size=0.2",
                                      facecolor=bg, edgecolor=border, linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x + 0.3, y + h - 0.4, title, fontsize=11, fontweight="bold", color=border)
        item_y = y + h - 0.8
        for it in items:
            ax.text(x + 0.3, item_y, f"• {it}", fontsize=7.5, color="#1e293b", wrap=True)
            item_y -= 0.48

    # Center Hub Icon/Text
    hub = patches.Circle((5.0, 3.5), 0.65, facecolor="#1e3a8a", edgecolor="#ffffff", linewidth=2, zorder=5)
    ax.add_patch(hub)
    ax.text(5.0, 3.55, "USER &\nANALYST", ha="center", va="center", fontsize=8, fontweight="bold", color="#ffffff", zorder=6)

    out_path = FIGURES_DIR / "empathy_map.png"
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated: {out_path}")


# ----------------------------------------------------------------------
# 2. PRE-SETTLEMENT SECURITY WORKFLOW (Crucial Invariant)
# ----------------------------------------------------------------------
def generate_presettlement_workflow():
    fig, ax = plt.subplots(figsize=(11, 6), dpi=300)
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 6)
    ax.axis("off")

    ax.text(5.5, 5.6, "PRE-SETTLEMENT RISK EVALUATION & ZERO-DEBIT INVARIANT",
            ha="center", va="center", fontsize=12, fontweight="bold", color="#1e3a8a")

    steps = [
        ("1. Transaction Request", "User submits transfer\n(Amount, Sender, Dest)", 0.5, 3.6, 2.0, 1.2, "#e0f2fe", "#0284c7"),
        ("2. Pre-Settlement Ingestion", "Session, Balance & PIN\nValidated (ZERO DEBIT)", 2.9, 3.6, 2.2, 1.2, "#e0e7ff", "#4338ca"),
        ("3. Hybrid Risk Engine", "ML Inference + Velocity +\nBehavioral Risk (0-100)", 5.5, 3.6, 2.3, 1.2, "#fae8ff", "#a21caf"),
        ("4. 4-Tier Policy Decision", "LOW (0-29) | MED (30-59)\nHIGH (60-79) | CRIT (80-100)", 8.2, 3.6, 2.3, 1.2, "#fef3c7", "#d97706")
    ]

    for title, desc, x, y, w, h, bg, border in steps:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1",
                                      facecolor=bg, edgecolor=border, linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h - 0.35, title, ha="center", va="center", fontsize=8.5, fontweight="bold", color=border)
        ax.text(x + w/2, y + 0.4, desc, ha="center", va="center", fontsize=7.5, color="#1e293b")

    # Arrows between top steps
    for ax_start, ax_end in [(2.5, 2.9), (5.1, 5.5), (7.8, 8.2)]:
        ax.annotate("", xy=(ax_end, 4.2), xytext=(ax_start, 4.2),
                    arrowprops=dict(arrowstyle="->", color="#475569", lw=1.5))

    # Decision Branches
    branches = [
        ("LOW RISK (0-29)", "APPROVE_IMMEDIATELY\n-> Atomic Balance Deduction\n-> Final Settlement Complete", 0.5, 0.8, 3.0, 1.6, "#dcfce7", "#15803d"),
        ("MEDIUM / HIGH (30-79)", "TRIGGER_OTP_VERIFICATION\n-> Account Balance PRESERVED\n-> Cryptographic Email OTP Step-up\n-> Settled ONLY on Valid OTP", 4.0, 0.8, 3.2, 1.6, "#ffedd5", "#c2410c"),
        ("CRITICAL (80-100)", "TRIGGER_SECURITY_REVIEW\n-> Account Balance LOCKED/PRESERVED\n-> SOC Incident Case Created\n-> Settled ONLY on Analyst Approval", 7.6, 0.8, 3.0, 1.6, "#fee2e2", "#b91c1c")
    ]

    for title, desc, x, y, w, h, bg, border in branches:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1",
                                      facecolor=bg, edgecolor=border, linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h - 0.35, title, ha="center", va="center", fontsize=8.5, fontweight="bold", color=border)
        ax.text(x + w/2, y + 0.55, desc, ha="center", va="center", fontsize=7.2, color="#1e293b")

    # Connector lines from Decision box down to branches
    ax.annotate("", xy=(2.0, 2.4), xytext=(9.35, 3.6),
                arrowprops=dict(arrowstyle="->", color="#15803d", lw=1.5, connectionstyle="angle,angleA=0,angleB=90,rad=10"))
    ax.annotate("", xy=(5.6, 2.4), xytext=(9.35, 3.6),
                arrowprops=dict(arrowstyle="->", color="#c2410c", lw=1.5, connectionstyle="angle,angleA=0,angleB=90,rad=10"))
    ax.annotate("", xy=(9.1, 2.4), xytext=(9.35, 3.6),
                arrowprops=dict(arrowstyle="->", color="#b91c1c", lw=1.5, connectionstyle="angle,angleA=0,angleB=90,rad=10"))

    out_path = FIGURES_DIR / "presettlement_security_flow.png"
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated: {out_path}")


# ----------------------------------------------------------------------
# 3. DFD LEVEL 2 (Subsystem Decomposition)
# ----------------------------------------------------------------------
def generate_dfd_level2():
    fig, ax = plt.subplots(figsize=(11, 7), dpi=300)
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 7)
    ax.axis("off")

    ax.text(5.5, 6.6, "DATA FLOW DIAGRAM (DFD) — LEVEL 2: TRANSACTION RISK & SETTLEMENT SUBSYSTEM",
            ha="center", va="center", fontsize=11, fontweight="bold", color="#1e3a8a")

    nodes = [
        ("Process 2.1\nInput Validation &\nSanitization", 1.0, 4.4, 2.0, 1.2, "#e0f2fe", "#0284c7"),
        ("Process 2.2\nFeature Engineering &\nHistorical Velocity", 4.5, 4.4, 2.2, 1.2, "#fae8ff", "#a21caf"),
        ("Process 2.3\nML Random Forest\nInference Pipeline", 8.0, 4.4, 2.2, 1.2, "#e0e7ff", "#4338ca"),
        ("Process 2.4\nHybrid Risk Aggregator\n& 4-Tier Policy", 8.0, 1.8, 2.2, 1.2, "#fef3c7", "#d97706"),
        ("Process 2.5\nStep-Up OTP Challenge\n& Email Dispatch", 4.5, 1.8, 2.2, 1.2, "#ffedd5", "#ea580c"),
        ("Process 2.6\nAtomic Settlement &\nLedger Persistence", 1.0, 1.8, 2.0, 1.2, "#dcfce7", "#16a34a"),
    ]

    for label, x, y, w, h, bg, border in nodes:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1",
                                      facecolor=bg, edgecolor=border, linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2, label, ha="center", va="center", fontsize=8, fontweight="bold", color="#0f172a")

    # Data Stores
    stores = [
        ("D1: Users & Balances", 1.0, 0.3, 2.0, 0.6),
        ("D2: Transactions & Ledger", 4.5, 0.3, 2.2, 0.6),
        ("D3: Risk Signals & Alerts", 8.0, 0.3, 2.2, 0.6)
    ]
    for sname, x, y, w, h in stores:
        rect = patches.Rectangle((x, y), w, h, facecolor="#f8fafc", edgecolor="#475569", linewidth=1.2)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2, sname, ha="center", va="center", fontsize=7.5, fontweight="bold", color="#334155")

    # Arrows between processes
    arrows = [
        ((3.0, 5.0), (4.5, 5.0), "Sanitized Payload"),
        ((6.7, 5.0), (8.0, 5.0), "Extracted Features (11)"),
        ((9.1, 4.4), (9.1, 3.0), "ML Probability"),
        ((8.0, 2.4), (6.7, 2.4), "MEDIUM / HIGH Tier"),
        ((4.5, 2.4), (3.0, 2.4), "Verified OTP Token"),
        ((2.0, 4.4), (2.0, 3.0), "LOW Risk Auto-Pass"),
    ]
    for p_start, p_end, txt in arrows:
        ax.annotate(txt, xy=p_end, xytext=p_start,
                    arrowprops=dict(arrowstyle="->", color="#475569", lw=1.2),
                    fontsize=6.5, color="#1e293b", ha="center", va="bottom")

    out_path = FIGURES_DIR / "dfd_level2.png"
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated: {out_path}")


# ----------------------------------------------------------------------
# 4. UML ACTIVITY DIAGRAM
# ----------------------------------------------------------------------
def generate_uml_activity():
    fig, ax = plt.subplots(figsize=(10, 8), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 8)
    ax.axis("off")

    ax.text(5.0, 7.6, "UML ACTIVITY DIAGRAM: PRE-SETTLEMENT TRANSACTION PROCESSING",
            ha="center", va="center", fontsize=11, fontweight="bold", color="#1e3a8a")

    # Start Node
    start = patches.Circle((5.0, 7.1), 0.18, facecolor="#0f172a", edgecolor="#0f172a")
    ax.add_patch(start)

    actions = [
        ("Initiate Payment & Enter PIN", 5.0, 6.3, 3.2, 0.6, "#e0f2fe", "#0284c7"),
        ("Validate Session, PIN & Balance\n(Zero Balance Deduction)", 5.0, 5.3, 3.4, 0.6, "#f1f5f9", "#475569"),
        ("Extract Features & Run ML Inference", 5.0, 4.3, 3.4, 0.6, "#fae8ff", "#a21caf"),
        ("Compute Hybrid Risk Score (0-100)", 5.0, 3.4, 3.4, 0.6, "#fef3c7", "#d97706"),
    ]

    for label, cx, cy, w, h, bg, border in actions:
        rect = patches.FancyBboxPatch((cx - w/2, cy - h/2), w, h, boxstyle="round,pad=0.1",
                                      facecolor=bg, edgecolor=border, linewidth=1.2)
        ax.add_patch(rect)
        ax.text(cx, cy, label, ha="center", va="center", fontsize=7.5, fontweight="bold", color="#0f172a")

    # Connect top nodes
    ax.annotate("", xy=(5.0, 6.6), xytext=(5.0, 6.9), arrowprops=dict(arrowstyle="->", color="#334155", lw=1.2))
    ax.annotate("", xy=(5.0, 5.6), xytext=(5.0, 6.0), arrowprops=dict(arrowstyle="->", color="#334155", lw=1.2))
    ax.annotate("", xy=(5.0, 4.6), xytext=(5.0, 5.0), arrowprops=dict(arrowstyle="->", color="#334155", lw=1.2))
    ax.annotate("", xy=(5.0, 3.7), xytext=(5.0, 4.0), arrowprops=dict(arrowstyle="->", color="#334155", lw=1.2))

    # Decision Diamond
    diamond = patches.RegularPolygon((5.0, 2.4), numVertices=4, radius=0.6, facecolor="#fef9c3", edgecolor="#ca8a04", linewidth=1.5)
    ax.add_patch(diamond)
    ax.text(5.0, 2.4, "Risk\nTier?", ha="center", va="center", fontsize=7.5, fontweight="bold", color="#854d0e")
    ax.annotate("", xy=(5.0, 2.9), xytext=(5.0, 3.1), arrowprops=dict(arrowstyle="->", color="#334155", lw=1.2))

    # 3 Branches
    # Left: LOW RISK
    rect_low = patches.FancyBboxPatch((0.5, 0.8), 2.5, 0.8, boxstyle="round,pad=0.1", facecolor="#dcfce7", edgecolor="#16a34a", linewidth=1.2)
    ax.add_patch(rect_low)
    ax.text(1.75, 1.2, "Atomic Balance Deduct &\nApprove Transaction", ha="center", va="center", fontsize=7, fontweight="bold", color="#15803d")
    ax.annotate("[LOW: 0-29]", xy=(1.75, 1.6), xytext=(4.5, 2.4),
                arrowprops=dict(arrowstyle="->", color="#16a34a", lw=1.2, connectionstyle="angle,angleA=0,angleB=90,rad=5"),
                fontsize=7, color="#15803d", ha="center")

    # Center: MEDIUM / HIGH RISK
    rect_med = patches.FancyBboxPatch((3.8, 0.8), 2.4, 0.8, boxstyle="round,pad=0.1", facecolor="#ffedd5", edgecolor="#ea580c", linewidth=1.2)
    ax.add_patch(rect_med)
    ax.text(5.0, 1.2, "Dispatch Email OTP;\nHold Balance Until Verified", ha="center", va="center", fontsize=7, fontweight="bold", color="#c2410c")
    ax.annotate("[MED/HIGH: 30-79]", xy=(5.0, 1.6), xytext=(5.0, 1.9),
                arrowprops=dict(arrowstyle="->", color="#ea580c", lw=1.2),
                fontsize=7, color="#c2410c", ha="center")

    # Right: CRITICAL
    rect_crit = patches.FancyBboxPatch((6.8, 0.8), 2.7, 0.8, boxstyle="round,pad=0.1", facecolor="#fee2e2", edgecolor="#dc2626", linewidth=1.2)
    ax.add_patch(rect_crit)
    ax.text(8.15, 1.2, "Create SOC Alert;\nLock Balance & Security Review", ha="center", va="center", fontsize=7, fontweight="bold", color="#b91c1c")
    ax.annotate("[CRITICAL: 80-100]", xy=(8.15, 1.6), xytext=(5.5, 2.4),
                arrowprops=dict(arrowstyle="->", color="#dc2626", lw=1.2, connectionstyle="angle,angleA=0,angleB=90,rad=5"),
                fontsize=7, color="#b91c1c", ha="center")

    out_path = FIGURES_DIR / "uml_activity.png"
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated: {out_path}")


# ----------------------------------------------------------------------
# 5. UML CLASS DIAGRAM
# ----------------------------------------------------------------------
def generate_uml_class():
    fig, ax = plt.subplots(figsize=(11, 7.5), dpi=300)
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 7.5)
    ax.axis("off")

    ax.text(5.5, 7.1, "UML CLASS DIAGRAM: DATA MODELS, ENGINES & SERVICE ARCHITECTURE",
            ha="center", va="center", fontsize=11, fontweight="bold", color="#1e3a8a")

    classes = [
        ("User", ["+ id: Integer [PK]", "+ email: String", "+ balance: Float", "+ payment_pin_hash: String", "+ is_admin: Boolean"],
         0.5, 4.2, 2.8, 2.3, "#f8fafc", "#0284c7"),
        ("Transaction", ["+ id: Integer [PK]", "+ user_id: Integer [FK]", "+ amount: Float", "+ risk_level: String", "+ status: String", "+ is_settled: Boolean"],
         3.8, 4.2, 3.2, 2.3, "#f8fafc", "#0284c7"),
        ("Alert & SOCCase", ["+ id: Integer [PK]", "+ transaction_id: Integer [FK]", "+ severity: String", "+ status: String", "+ assigned_analyst: Integer"],
         7.5, 4.2, 3.0, 2.3, "#f8fafc", "#0284c7"),
        ("InferenceService", ["- model: RandomForest", "- preprocessor: Pipeline", "+ predict_proba(X): Float", "+ get_decision(prob): String"],
         0.5, 1.0, 3.0, 2.3, "#f0fdf4", "#16a34a"),
        ("HybridRiskEngine", ["- policy: RiskPolicy", "+ calculate_risk(X, signals)", "+ enforce_presettlement(tx)"],
         4.0, 1.0, 3.0, 2.3, "#fefce8", "#ca8a04"),
        ("SHAPExplainerService", ["- explainer: TreeExplainer", "+ explain(features): Dict", "+ generate_waterfall(tx): Img"],
         7.5, 1.0, 3.0, 2.3, "#fdf4ff", "#a21caf"),
    ]

    for title, attrs, x, y, w, h, bg, border in classes:
        rect = patches.Rectangle((x, y), w, h, facecolor=bg, edgecolor=border, linewidth=1.5)
        ax.add_patch(rect)
        ax.plot([x, x + w], [y + h - 0.45, y + h - 0.45], color=border, lw=1.2)
        ax.text(x + w/2, y + h - 0.25, title, ha="center", va="center", fontsize=8.5, fontweight="bold", color=border)
        item_y = y + h - 0.75
        for at in attrs:
            ax.text(x + 0.15, item_y, at, fontsize=6.8, fontfamily="monospace", color="#0f172a")
            item_y -= 0.32

    # Associations
    ax.annotate("1..*  has", xy=(3.8, 5.35), xytext=(3.3, 5.35),
                arrowprops=dict(arrowstyle="->", color="#475569", lw=1.2), fontsize=7)
    ax.annotate("1..1 triggers", xy=(7.5, 5.35), xytext=(7.0, 5.35),
                arrowprops=dict(arrowstyle="->", color="#475569", lw=1.2), fontsize=7)
    ax.annotate("evaluates", xy=(4.0, 2.2), xytext=(2.0, 4.2),
                arrowprops=dict(arrowstyle="->", color="#475569", lw=1.2, connectionstyle="arc3,rad=-0.2"), fontsize=7)
    ax.annotate("interprets", xy=(7.5, 2.2), xytext=(5.4, 4.2),
                arrowprops=dict(arrowstyle="->", color="#475569", lw=1.2, connectionstyle="arc3,rad=-0.2"), fontsize=7)

    out_path = FIGURES_DIR / "uml_class.png"
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated: {out_path}")


# ----------------------------------------------------------------------
# 6. UML COMPONENT & DEPLOYMENT DIAGRAMS
# ----------------------------------------------------------------------
def generate_uml_component_and_deployment():
    # Component Diagram
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6)
    ax.axis("off")
    ax.text(5.0, 5.6, "UML COMPONENT DIAGRAM: FRAUDSHIELD AI ARCHITECTURE",
            ha="center", va="center", fontsize=11, fontweight="bold", color="#1e3a8a")

    components = [
        ("Client UI Component\n(HTML5/CSS3/Chart.js)", 0.5, 3.4, 2.6, 1.4, "#e0f2fe", "#0284c7"),
        ("Flask REST API Gateway\n(Blueprints & JWT Auth)", 3.7, 3.4, 2.6, 1.4, "#f1f5f9", "#475569"),
        ("ML & SHAP Engine\n(Random Forest + XAI)", 6.9, 3.4, 2.6, 1.4, "#fae8ff", "#a21caf"),
        ("Hybrid Risk Engine\n(Rule + Velocity Signals)", 3.7, 1.0, 2.6, 1.4, "#fef3c7", "#d97706"),
        ("Persistence & Email Service\n(SQLAlchemy + Brevo/SMTP)", 6.9, 1.0, 2.6, 1.4, "#dcfce7", "#16a34a"),
    ]

    for label, x, y, w, h, bg, border in components:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1",
                                      facecolor=bg, edgecolor=border, linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2, label, ha="center", va="center", fontsize=7.8, fontweight="bold", color="#0f172a")

    # Connectors
    ax.annotate("HTTP / JSON", xy=(3.7, 4.1), xytext=(3.1, 4.1), arrowprops=dict(arrowstyle="<->", color="#334155", lw=1.2), fontsize=6.8)
    ax.annotate("Features", xy=(6.9, 4.1), xytext=(6.3, 4.1), arrowprops=dict(arrowstyle="->", color="#334155", lw=1.2), fontsize=6.8)
    ax.annotate("Telemetry", xy=(5.0, 3.4), xytext=(5.0, 2.4), arrowprops=dict(arrowstyle="<->", color="#334155", lw=1.2), fontsize=6.8)
    ax.annotate("Persist / Alert", xy=(6.9, 1.7), xytext=(6.3, 1.7), arrowprops=dict(arrowstyle="->", color="#334155", lw=1.2), fontsize=6.8)

    out_comp = FIGURES_DIR / "uml_component.png"
    plt.tight_layout()
    plt.savefig(out_comp, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated: {out_comp}")

    # Deployment Diagram
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6)
    ax.axis("off")
    ax.text(5.0, 5.6, "UML DEPLOYMENT DIAGRAM: PRODUCTION HOSTING TOPOLOGY",
            ha="center", va="center", fontsize=11, fontweight="bold", color="#1e3a8a")

    nodes = [
        ("<<device>>\nClient Browser\n(Desktop / Mobile)", 0.6, 2.2, 2.4, 2.2, "#e0f2fe", "#0284c7"),
        ("<<server node>>\nReverse Proxy & Gateway\n(Nginx / HTTPS:443)", 3.8, 2.2, 2.4, 2.2, "#f8fafc", "#475569"),
        ("<<application container>>\nGunicorn WSGI + Flask 3.1\nPython 3.11 Runtime\n(ML Artifacts & SHAP)", 7.0, 2.2, 2.6, 2.2, "#fae8ff", "#a21caf"),
        ("<<database node>>\nSQLite / PostgreSQL\n(Encrypted Database)", 7.0, 0.3, 2.6, 1.4, "#dcfce7", "#16a34a"),
    ]

    for label, x, y, w, h, bg, border in nodes:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1",
                                      facecolor=bg, edgecolor=border, linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2, label, ha="center", va="center", fontsize=7.5, fontweight="bold", color="#0f172a")

    # Connectors
    ax.annotate("HTTPS / TLS 1.3", xy=(3.8, 3.3), xytext=(3.0, 3.3), arrowprops=dict(arrowstyle="<->", color="#334155", lw=1.2), fontsize=7)
    ax.annotate("Proxy Pass :5000", xy=(7.0, 3.3), xytext=(6.2, 3.3), arrowprops=dict(arrowstyle="<->", color="#334155", lw=1.2), fontsize=7)
    ax.annotate("SQLAlchemy ORM", xy=(8.3, 2.2), xytext=(8.3, 1.7), arrowprops=dict(arrowstyle="<->", color="#334155", lw=1.2), fontsize=7)

    out_dep = FIGURES_DIR / "uml_deployment.png"
    plt.tight_layout()
    plt.savefig(out_dep, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated: {out_dep}")


# ----------------------------------------------------------------------
# 7. SHAP WATERFALL CONCEPT DIAGRAM
# ----------------------------------------------------------------------
def generate_shap_waterfall():
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.5)
    ax.axis("off")

    ax.text(5.0, 5.1, "SHAP (SHapley Additive exPlanations) LOCAL FEATURE ATTRIBUTION WATERFALL",
            ha="center", va="center", fontsize=11, fontweight="bold", color="#1e3a8a")

    features = [
        ("Base Value (E[f(x)]): 0.0013", 0.0, "#94a3b8"),
        ("+ diffOrgBalance = $750,000 (Account Drained)", +0.48, "#dc2626"),
        ("+ amountToOldBalanceRatio = 1.0 (100% Exfiltration)", +0.28, "#ef4444"),
        ("+ type_TRANSFER = 1 (Irreversible Push Payment)", +0.16, "#f87171"),
        ("- velocity_1h = 1 (First Transaction in Window)", -0.04, "#16a34a"),
        ("Output Probability f(x) = 0.8813 (CRITICAL FRAUD)", 0.0, "#b91c1c")
    ]

    y = 4.2
    for name, delta, color in features:
        if delta == 0.0:
            ax.text(0.8, y, name, fontsize=8.5, fontweight="bold", color=color)
        else:
            bar_w = abs(delta) * 4.5
            bar_x = 5.2 if delta > 0 else 5.2 - bar_w
            rect = patches.FancyBboxPatch((bar_x, y - 0.15), bar_w, 0.35, boxstyle="round,pad=0.02", facecolor=color, edgecolor="none")
            ax.add_patch(rect)
            ax.text(0.8, y, name, fontsize=8, color="#0f172a")
            ax.text(bar_x + bar_w + 0.1 if delta > 0 else bar_x - 0.6, y, f"{delta:+.2f}", fontsize=8, fontweight="bold", color=color)
        y -= 0.65

    out_path = FIGURES_DIR / "shap_waterfall_concept.png"
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated: {out_path}")


if __name__ == "__main__":
    generate_empathy_map()
    generate_presettlement_workflow()
    generate_dfd_level2()
    generate_uml_activity()
    generate_uml_class()
    generate_uml_component_and_deployment()
    generate_shap_waterfall()
    print("All supplementary academic diagrams generated successfully.")
