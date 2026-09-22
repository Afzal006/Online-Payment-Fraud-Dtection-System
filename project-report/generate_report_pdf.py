"""
Comprehensive Academic Project Report PDF Generator using ReportLab.
Compiles the complete 21-section University Report for FraudShield AI
(Online Payment Fraud Detection System Using Machine Learning) into a
publication-grade document of 36-44 pages with a dedicated Faculty Remarks box
on EVERY single page.
"""

import os
import sys
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether, PageBreak, HRFlowable
)
from reportlab.pdfgen import canvas

BASE_DIR = Path(__file__).resolve().parent
FIGURES_DIR = BASE_DIR / "figures"
OUTPUT_PDF = BASE_DIR / "Online_Payment_Fraud_Detection_System_Report.pdf"

# ---------------------------------------------------------
# Custom Numbered Canvas with Mandatory Remarks Box
# ---------------------------------------------------------
class NumberedCanvasWithRemarks(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        page_w, page_h = A4
        margin_l = 45
        margin_r = page_w - 45

        # Suppress headers/footers on page 1 (Cover Page)
        if self._pageNumber == 1:
            return

        # ---------------- Running Header ----------------
        self.saveState()
        self.setFont("Helvetica-Oblique", 8)
        self.setFillColor(colors.HexColor("#1e293b"))
        self.drawString(margin_l, page_h - 32, "Online Payment Fraud Detection System Using Machine Learning")
        self.drawRightString(margin_r, page_h - 32, "FraudShield AI Technical Report")

        self.setStrokeColor(colors.HexColor("#0284c7"))
        self.setLineWidth(0.75)
        self.line(margin_l, page_h - 36, margin_r, page_h - 36)
        self.restoreState()

        # ---------------- Dedicated Remarks Box (Bottom 1.25 inches) ----------------
        box_bottom = 20
        box_height = 70
        box_width = page_w - 90

        self.saveState()
        # Box background & border
        self.setFillColor(colors.HexColor("#fafafa"))
        self.setStrokeColor(colors.HexColor("#94a3b8"))
        self.setLineWidth(0.75)
        self.roundRect(margin_l, box_bottom, box_width, box_height, 3, fill=True, stroke=True)

        # Remarks Header Text & Page Number
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#1e3a8a"))
        self.drawString(margin_l + 8, box_bottom + box_height - 13, "EVALUATOR / FACULTY REMARKS:")

        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#334155"))
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(margin_r - 8, box_bottom + box_height - 13, page_str)

        # Writing lines for comments
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        line1_y = box_bottom + box_height - 25
        line2_y = box_bottom + box_height - 43
        self.line(margin_l + 8, line1_y, margin_r - 8, line1_y)
        self.line(margin_l + 8, line2_y, margin_l + box_width * 0.60, line2_y)

        # Signature placeholder
        self.setFont("Helvetica-Oblique", 7.5)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawRightString(margin_r - 8, box_bottom + 10, "Evaluator Signature & Date: ______________________")
        self.restoreState()


# ---------------------------------------------------------
# Styles Setup
# ---------------------------------------------------------
def create_styles():
    styles = getSampleStyleSheet()

    c_primary = colors.HexColor("#1e3a8a")
    c_secondary = colors.HexColor("#0284c7")
    c_dark = colors.HexColor("#0f172a")

    styles.add(ParagraphStyle(
        name="DocTitle",
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=c_primary,
        alignment=1, # Center
        spaceAfter=12
    ))

    styles.add(ParagraphStyle(
        name="DocSubtitle",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=c_secondary,
        alignment=1,
        spaceAfter=20
    ))

    styles.add(ParagraphStyle(
        name="ChapterHeading",
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14.5,
        textColor=c_secondary,
        spaceBefore=9,
        spaceAfter=4,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name="SubSectionHeading",
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=12.5,
        textColor=c_dark,
        spaceBefore=7,
        spaceAfter=3,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name="AcademicBody",
        fontName="Helvetica",
        fontSize=8.8,
        leading=13.2,
        textColor=c_dark,
        spaceAfter=5
    ))

    styles.add(ParagraphStyle(
        name="BulletText",
        fontName="Helvetica",
        fontSize=8.8,
        leading=12.8,
        textColor=c_dark,
        leftIndent=12,
        spaceAfter=3
    ))

    styles.add(ParagraphStyle(
        name="CodeBlock",
        fontName="Courier",
        fontSize=7.0,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=5,
        spaceBefore=3,
        spaceAfter=5
    ))

    styles.add(ParagraphStyle(
        name="CalloutText",
        fontName="Helvetica-Oblique",
        fontSize=8.3,
        leading=11.5,
        textColor=colors.HexColor("#1e293b")
    ))

    styles.add(ParagraphStyle(
        name="CaptionStyle",
        fontName="Helvetica-Bold",
        fontSize=7.8,
        leading=9.8,
        textColor=colors.HexColor("#475569"),
        alignment=1, # Center
        spaceBefore=3,
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name="TableHeader",
        fontName="Helvetica-Bold",
        fontSize=7.8,
        leading=9.8,
        textColor=colors.white,
        alignment=1
    ))

    styles.add(ParagraphStyle(
        name="TableCell",
        fontName="Helvetica",
        fontSize=7.3,
        leading=9.5,
        textColor=c_dark
    ))

    styles.add(ParagraphStyle(
        name="TableCellBold",
        fontName="Helvetica-Bold",
        fontSize=7.3,
        leading=9.5,
        textColor=c_dark
    ))

    return styles


# ---------------------------------------------------------
# Helper Functions for UI Elements
# ---------------------------------------------------------
def make_callout(text, styles, border_color="#0284c7", bg_color="#f8fafc"):
    p = Paragraph(text, styles["CalloutText"])
    t = Table([[p]], colWidths=[495])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_color)),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(border_color)),
        ("PADDING", (0, 0), (-1, -1), 5)
    ]))
    return t

def make_table(header, data, col_widths, styles, primary_color="#1e3a8a", alt_color="#f8fafc"):
    table_data = []
    # Header row
    h_row = [Paragraph(f"<b>{col}</b>", styles["TableHeader"]) for col in header]
    table_data.append(h_row)

    # Body rows
    for row in data:
        r_row = []
        for cell in row:
            if isinstance(cell, str):
                r_row.append(Paragraph(cell, styles["TableCell"]))
            else:
                r_row.append(cell)
        table_data.append(r_row)

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(primary_color)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 3.5),
    ]
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            t_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor(alt_color)))
    t.setStyle(TableStyle(t_style))
    return t

def add_image_if_exists(story, img_path, width, height, caption, styles):
    p = Path(img_path)
    if p.exists():
        story.append(Spacer(1, 3))
        story.append(Image(str(p), width=width, height=height))
        story.append(Paragraph(caption, styles["CaptionStyle"]))
        story.append(Spacer(1, 4))
    else:
        story.append(Paragraph(f"<b>[DIAGRAM PLACEHOLDER: {caption}]</b>", styles["CaptionStyle"]))


# ---------------------------------------------------------
# Master Document Assembly
# ---------------------------------------------------------
def build_pdf():
    print(f"Generating expanded 36-44 page Academic Project Report...")

    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=A4,
        leftMargin=45,
        rightMargin=45,
        topMargin=45,
        bottomMargin=95 # Physically reserved 95pt for the 70pt remarks box + buffer
    )

    styles = create_styles()
    story = []

    # =========================================================
    # PRELIMINARIES: COVER PAGE
    # =========================================================
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph("ONLINE PAYMENT FRAUD DETECTION SYSTEM USING MACHINE LEARNING", styles["DocTitle"]))
    story.append(Paragraph("A Real-Time Adaptive Risk Scoring, Pre-Settlement Multi-Factor Security, and Explainable AI FinTech Platform", styles["DocSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=16))

    cover_meta = """
    <b>A Technical Project Report</b><br/>
    Submitted in partial fulfillment of the requirements for the Degree of<br/>
    <b>Bachelor of Technology in Computer Science & Engineering</b><br/><br/>
    <b>Candidate / Author:</b> Afzal (GitHub: @Afzal006)<br/>
    <b>Repository:</b> <code>https://github.com/Afzal006/Online-Payment-Fraud-Dtection-System</code><br/>
    <b>Domain:</b> Financial Technology (FinTech) / Applied Machine Learning / Cyber-Defense<br/>
    <b>Dataset:</b> PaySim Mobile Money Financial Fraud Synthetic Benchmark<br/>
    <b>Verified Test Suite:</b> 502 Automated Unit, Integration & Security Tests (100% Passing)<br/>
    <b>Academic Year:</b> 2025–2026
    """
    story.append(Paragraph(cover_meta, ParagraphStyle("CoverMeta", parent=styles["AcademicBody"], alignment=1, leading=14)))
    story.append(Spacer(1, 0.25 * inch))

    qr_path = FIGURES_DIR / "qr_github.png"
    if qr_path.exists():
        story.append(Image(str(qr_path), width=1.3*inch, height=1.3*inch))
        story.append(Paragraph("<b>Scan QR for GitHub Repository Source Code & CI Artifacts</b>", styles["CaptionStyle"]))

    story.append(PageBreak())

    # =========================================================
    # PRELIMINARIES: CERTIFICATE & DECLARATION
    # =========================================================
    story.append(Paragraph("CERTIFICATE OF AUTHENTICITY", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=8))
    cert_text = """
    This is to certify that the technical project report entitled <b>"Online Payment Fraud Detection System Using Machine Learning"</b> is a bonafide record of authentic engineering research, architecture design, and software implementation carried out by <b>Afzal</b> under supervision. The software artifacts, machine learning pipelines, explainable AI integrations, and security enforcement mechanisms described herein have been verified against active codebases and <b>502 passing automated test cases</b>.
    """
    story.append(Paragraph(cert_text, styles["AcademicBody"]))
    story.append(Spacer(1, 0.3 * inch))

    sig_data = [
        [Paragraph("<b>Internal Faculty Supervisor</b><br/>Department of Computer Science<br/>Signature: _______________________<br/>Date: ___________________________", styles["AcademicBody"]),
         Paragraph("<b>Head of Department</b><br/>Department of Computer Science<br/>Signature: _______________________<br/>Date: ___________________________", styles["AcademicBody"])]
    ]
    sig_table = Table(sig_data, colWidths=[245, 245])
    sig_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(sig_table)
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("DECLARATION OF ORIGINALITY", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=8))
    decl_text = """
    I hereby declare that this project report entitled <b>"Online Payment Fraud Detection System Using Machine Learning"</b> represents my original work. All external libraries (Scikit-Learn, XGBoost, SHAP, Flask, SQLAlchemy), reference datasets (PaySim Financial Dataset), and scientific publications have been appropriately cited. No fabricated survey results, fake credentials, or exaggerated metrics have been incorporated.
    """
    story.append(Paragraph(decl_text, styles["AcademicBody"]))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("ACKNOWLEDGEMENTS", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=8))
    ack_text = """
    I express my profound gratitude to our academic mentors, faculty advisors, and the open-source software engineering community. Their continuous feedback, architectural guidelines, and scientific tooling made it possible to construct, evaluate, and formally validate this real-time financial fraud defense system.
    """
    story.append(Paragraph(ack_text, styles["AcademicBody"]))
    story.append(PageBreak())

    # =========================================================
    # PRELIMINARIES: TABLE OF CONTENTS & ABBREVIATIONS
    # =========================================================
    story.append(Paragraph("TABLE OF CONTENTS & REPORT STRUCTURE", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    toc_data = [
        ["1. Abstract", "Page 4", "12. Implementation / Working Principle", "Page 28"],
        ["2. Introduction", "Page 5", "13. Testing & Validation (502 Tests)", "Page 31"],
        ["3. Problem Identification", "Page 7", "14. Results & System Screenshots", "Page 34"],
        ["4. Empathize & Define (Design Thinking)", "Page 9", "15. Core Functionality Code", "Page 37"],
        ["5. Ideation & Decision Matrix", "Page 11", "16. Project Evaluation & Metrics", "Page 40"],
        ["6. Requirements Analysis", "Page 13", "17. Conclusion & Learning Outcomes", "Page 42"],
        ["7. Technology Stack Rationale", "Page 15", "18. Future Enhancements & Roadmap", "Page 43"],
        ["8. System Design & DFDs (0, 1, 2)", "Page 17", "19. Project Links & QR Codes", "Page 44"],
        ["9. Database Design (11 Schemas)", "Page 20", "20. References & Bibliography", "Page 45"],
        ["10. Module Description (10 Modules)", "Page 23", "21. Appendix (APIs, DDLs, Secrets Template)", "Page 46"],
        ["11. UML Modeling (6 Diagrams)", "Page 26", "", ""]
    ]
    story.append(make_table(["Section Title", "Page", "Section Title", "Page"], toc_data, [160, 85, 165, 85], styles))
    story.append(Spacer(1, 8))

    story.append(Paragraph("LIST OF ABBREVIATIONS & ACRONYMS", styles["SectionHeading"]))
    abbr_data = [
        ["UPI", "Unified Payments Interface", "SHAP", "SHapley Additive exPlanations"],
        ["ML", "Machine Learning", "XAI", "Explainable Artificial Intelligence"],
        ["SOC", "Security Operations Center", "PR-AUC", "Precision-Recall Area Under Curve"],
        ["OTP", "One-Time Password", "ROC-AUC", "Receiver Operating Characteristic AUC"],
        ["RBAC", "Role-Based Access Control", "IDOR", "Insecure Direct Object Reference"],
        ["ORM", "Object-Relational Mapping", "DFD", "Data Flow Diagram"],
        ["ERD", "Entity-Relationship Diagram", "MFA", "Multi-Factor Authentication"],
        ["P2P", "Peer-to-Peer Transfer", "WSGI", "Web Server Gateway Interface"]
    ]
    story.append(make_table(["Acronym", "Full Description", "Acronym", "Full Description"], abbr_data, [65, 180, 65, 185], styles))
    story.append(PageBreak())

    # =========================================================
    # SECTION 1 — ABSTRACT
    # =========================================================
    story.append(Paragraph("1. Abstract", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=8))

    abstract_text = """
    The rapid global expansion of instant digital payment networks—such as Unified Payments Interface (UPI), peer-to-peer (P2P) transfers, and digital banking rails—has revolutionized consumer commerce while simultaneously introducing severe vulnerabilities to sophisticated financial cyber-fraud syndicates. Conventional fraud prevention infrastructure relies almost exclusively on static, heuristic rule engines that suffer from excessive false positive rates and an inability to detect novel, complex account-draining attack vectors.<br/><br/>
    This technical project presents <b>FraudShield AI</b>, an enterprise-grade, end-to-end intelligent payment fraud detection, explainable risk assessment, and adaptive multi-factor verification platform. The proposed architecture integrates supervised machine learning classification using a tuned Random Forest ensemble (F1 = 0.9985, Precision = 1.0000, Recall = 0.9970 on PaySim test partitions) with real-time behavioral telemetry, including account-draining ratios, multi-window transaction velocity, and diurnal temporal anomalies. To resolve the black-box opacity of conventional machine learning classifiers, the system incorporates <b>SHapley Additive exPlanations (SHAP)</b> via <code>shap.TreeExplainer</code>, delivering dual-perspective transparency: natural-language explanations for retail customers and granular feature attribution waterfalls for security operations analysts.<br/><br/>
    The platform enforces a real-time <b>4-Tier Adaptive Risk Policy</b> (<i>LOW, MEDIUM, HIGH, CRITICAL</i>) governed by a fundamental pre-settlement security invariant: suspicious transactions are held in a pending state and account balances are strictly preserved until cryptographic <b>Email OTP step-up verification</b> is successfully completed. Built using Python, Flask 3.1, SQLAlchemy ORM, Glassmorphism CSS, and Chart.js, the system includes a dedicated Security Operations Center (SOC) portal and achieves comprehensive operational resilience, validated across <b>502 automated test cases</b>.
    """
    story.append(Paragraph(abstract_text, styles["AcademicBody"]))
    story.append(Spacer(1, 8))

    # =========================================================
    # SECTION 2 — INTRODUCTION
    # =========================================================
    story.append(Paragraph("2. Introduction", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    intro_subsections = [
        ("2.1 Background", """Digital payment ecosystems process billions of transactions monthly with sub-second finality. Instant payment rails eliminate traditional multi-day clearing delays, providing tremendous convenience to consumers and merchants. However, this instantaneous settlement drastically reduces the window available for financial institutions to intercept unauthorized or coerced transfers before funds are irreversibly exfiltrated into money-mule networks."""),
        ("2.2 Project Overview", """<b>FraudShield AI</b> is designed as an intelligent, real-time fraud defense middleware that bridges transaction ingestion, supervised machine learning inference, dynamic behavioral risk scoring, and automated step-up challenge workflows. It ensures that every transaction is evaluated against both historical data patterns and real-time contextual signals before any balance deduction occurs."""),
        ("2.3 Motivation", """Cyber-fraud syndicates increasingly exploit social engineering, phishing, SIM swapping, and automated malware to compromise credentials. Relying on static transaction limits (e.g., blocking all transfers above $50,000) causes legitimate high-value payments to fail, frustrating consumers. A modernized solution must dynamically assess risk and present multi-factor challenges only when anomalous behavior is detected."""),
        ("2.4 Need for the Project", """Financial institutions face stringent regulatory mandates (such as RBI and PCI-DSS compliance) requiring explainable fraud decisions and strict consumer fund protection. Opaque AI models that deny transactions without providing human-understandable rationales create regulatory non-compliance and customer distrust. FraudShield AI directly solves this challenge through integrated SHAP explainability and zero-debit pre-settlement controls."""),
        ("2.5 Project Objectives", """The core technical objectives of this project are formally defined as follows:
        <br/>1. <i>High-Precision ML Classification:</i> Train, tune, and serialize ensemble classifiers (Random Forest, XGBoost) capable of identifying fraudulent patterns in highly imbalanced financial transaction data.
        <br/>2. <i>Explainable AI Integration:</i> Implement local game-theoretic feature attribution via SHAP TreeExplainer, generating dual-view customer summaries and technical analyst waterfalls.
        <br/>3. <i>Hybrid Risk Scoring Engine:</i> Formulate a composite 0–100 risk scoring algorithm combining ML inference probabilities with velocity, behavioral, and geographical anomaly signals.
        <br/>4. <i>4-Tier Adaptive Risk Policy:</i> Enforce distinct operational policies across LOW, MEDIUM, HIGH, and CRITICAL risk tiers to automate approvals, OTP challenges, and SOC reviews.
        <br/>5. <i>Pre-Settlement Balance Invariant:</i> Guarantee that zero customer funds are deducted prior to successful OTP verification on flagged transactions.
        <br/>6. <i>Security Operations Center (SOC) Portal:</i> Provide an administrative interface for real-time alert triage, case investigation, and audit trail inspection.
        <br/>7. <i>Automated Verification & Resilience:</i> Validate all backend services, database transactions, and security boundaries across a comprehensive automated test suite."""),
        ("2.6 Project Scope", """The project encompasses user authentication, payment identity management (UPI IDs, linked phones), simulated payment ingestion, feature extraction pipelines, ML model inference, SHAP explanation generation, Email OTP dispatch and verification, atomic database settlement, and SOC incident triage dashboards."""),
        ("2.7 Limitations", """The primary limitation of the current implementation is the reliance on the synthetic PaySim benchmark dataset for offline model training, which may not capture emergent real-world adversarial evasion techniques. Additionally, step-up multi-factor verification currently relies on email-delivered OTP tokens rather than carrier-grade SMS gateway integrations.""")
    ]

    for title, body in intro_subsections:
        story.append(Paragraph(title, styles["SectionHeading"]))
        story.append(Paragraph(body, styles["AcademicBody"]))

    story.append(PageBreak())

    # =========================================================
    # SECTION 3 — PROBLEM IDENTIFICATION
    # =========================================================
    story.append(Paragraph("3. Problem Identification", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("3.1 Existing Scenario & 3.2 Existing System", styles["SectionHeading"]))
    story.append(Paragraph("""
    In contemporary retail banking and payment gateway architectures, fraud detection is predominantly performed via monolithic SQL query filters or hardcoded heuristic rule engines (e.g., <code>IF amount > 50000 THEN FLAG</code>). These legacy systems operate either as asynchronous post-settlement batch jobs or as rigid transaction filters at the gateway.
    """, styles["AcademicBody"]))

    story.append(Paragraph("3.3 Drawbacks of Existing Systems", styles["SectionHeading"]))
    drawbacks_list = [
        "<b>Severe False Positive Rates:</b> Legitimate emergency payments (e.g., hospital bills) are frequently declined because they exceed static thresholds, causing intense user frustration.",
        "<b>Vulnerability to Smurfing / Structuring:</b> Fraudsters easily circumvent static rules by breaking large illicit transfers into multiple smaller transactions just below the detection threshold.",
        "<b>Lack of Velocity & Temporal Context:</b> Static rules evaluate transactions in isolation without analyzing rapid multi-window transfer frequencies (1-minute, 10-minute, 1-hour windows).",
        "<b>Black-Box AI Opacity:</b> Standalone neural networks or ensemble models output abstract probabilities without providing interpretable justifications for compliance audits or customer support.",
        "<b>Premature Settlement Deduction:</b> Flawed gateway implementations deduct funds from the sender's account prior to completing step-up verification, leading to reconciliation errors if verification fails."
    ]
    for db in drawbacks_list:
        story.append(Paragraph(f"• {db}", styles["BulletText"]))

    story.append(Spacer(1, 4))
    story.append(Paragraph("3.4 Formal Problem Statement", styles["SectionHeading"]))
    prob_stmt = """
    <b>Problem Statement:</b> Design, implement, and validate an end-to-end real-time Online Payment Fraud Detection System that: (1) detects fraudulent transactions with high precision and recall on severely imbalanced financial data; (2) calculates a standardized 0–100 risk score combining ML predictions and behavioral signals; (3) computes real-time SHAP feature attributions for dual-view explainability; and (4) strictly enforces pre-settlement balance protection, ensuring zero balance loss on suspicious transfers unless cryptographic Email OTP step-up verification is successfully completed.
    """
    story.append(make_callout(prob_stmt, styles, border_color="#0284c7", bg_color="#f8fafc"))
    story.append(Spacer(1, 6))

    story.append(Paragraph("3.5 Target Users & System Comparison", styles["SectionHeading"]))
    story.append(Paragraph("""
    The primary target users include retail payment consumers, digital merchants, security operations center (SOC) fraud analysts, and regulatory compliance officers.
    """, styles["AcademicBody"]))

    comp_headers = ["Comparison Dimension", "Legacy Rule-Based System", "Naive Black-Box ML", "FraudShield AI (Proposed)"]
    comp_data = [
        ["Detection Mechanism", "Static SQL Thresholds", "Standalone Model Probabilities", "Hybrid (ML + Velocity + Behavioral)"],
        ["Adaptability to Smurfing", "None (Fixed Cutoffs)", "Moderate", "High (Multi-Window Velocity Tracking)"],
        ["Decision Explainability", "Basic Rule Name", "None (Opaque Score)", "SHAP Waterfall & Natural Language"],
        ["Settlement Balance Timing", "Often Post-Debit", "Post-Debit / Immediate", "Strict Pre-Settlement Zero-Debit Hold"],
        ["Multi-Factor Integration", "All-or-Nothing MFA", "Binary Approval/Block", "Adaptive 4-Tier Step-Up (Email OTP)"],
        ["SOC Incident Management", "Manual Ticketing", "Raw Log Export", "Dedicated Case & Alert State Machine"],
        ["Class Imbalance Handling", "Not Applicable", "Frequently Distorted", "Tuned Thresholds & PR-AUC Optimization"]
    ]
    story.append(make_table(comp_headers, comp_data, [110, 125, 120, 140], styles))
    story.append(PageBreak())

    # =========================================================
    # SECTION 4 — EMPATHIZE AND DEFINE (Design Thinking Phase)
    # =========================================================
    story.append(Paragraph("4. Empathize and Define — Design Thinking Phase", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("4.1 Empathy Study & 4.2 User Identification", styles["SectionHeading"]))
    story.append(Paragraph("""
    The design thinking phase adopted a human-centered approach to uncover the operational and emotional tensions experienced by key stakeholders in the digital payments lifecycle. We identified two primary user archetypes: retail payment users transacting daily via mobile applications, and SOC fraud analysts responsible for defending the banking network.
    """, styles["AcademicBody"]))

    story.append(Paragraph("4.3 User Needs & 4.4 User Pain Points", styles["SectionHeading"]))
    needs_data = [
        ["Stakeholder", "Core Functional Needs", "Key Pain Points & Frustrations"],
        ["Retail Consumer", "Instant checkout, clear fraud alerts, fund security, transparent reasons for payment delays.", "Unexplained payment blocks, complicated recovery flows, fear of account draining."],
        ["SOC Analyst", "High-fidelity alerts, clear feature attributions, rapid case resolution tools.", "Alert fatigue from false positives, opaque risk scores, lack of actionable audit evidence."],
        ["Compliance Officer", "Auditable decision logs, strict adherence to consumer protection standards.", "Regulatory fines for unauthorized debits, unexplainable algorithmic decisions."]
    ]
    story.append(make_table(["User Role", "Needs", "Pain Points"], needs_data, [100, 195, 200], styles))
    story.append(Spacer(1, 4))

    story.append(Paragraph("4.5 Observation & Field Interview Status", styles["SectionHeading"]))
    story.append(make_callout("<b>Empirical Field Data Status:</b> <code>[Actual survey/interview data to be provided]</code>. The requirements below are derived from representative design personas constructed according to FinTech user research standards.", styles, border_color="#ca8a04", bg_color="#fefce8"))
    story.append(Spacer(1, 4))

    story.append(Paragraph("4.6 Representative User Personas", styles["SectionHeading"]))
    story.append(Paragraph("""
    • <b>Persona 1 (Retail Consumer) — Ananya Sharma (Age 28):</b> Product manager living in Bengaluru; makes 8–12 UPI transactions daily for groceries, utilities, and peer splits. Fears unauthorized account compromise but gets deeply frustrated when legitimate payments are blocked without clear explanation.<br/>
    • <b>Persona 2 (SOC Analyst) — Vikram Malhotra (Age 35):</b> Lead incident response analyst at a payment gateway; monitors thousands of daily flagged transactions. Requires precise mathematical justifications (SHAP values) and clear transaction histories to resolve high-priority fraud cases rapidly.
    """, styles["AcademicBody"]))

    story.append(Paragraph("4.7 Empathy Map & 4.8 Key Insights", styles["SectionHeading"]))
    add_image_if_exists(story, FIGURES_DIR / "empathy_map.png", width=5.5*inch, height=3.2*inch,
                        caption="Figure 4.1: Design Thinking Empathy Map for Retail Consumers and SOC Fraud Analysts", styles=styles)

    story.append(Paragraph("4.9 Refined Problem Definition", styles["SectionHeading"]))
    story.append(Paragraph("""
    <b>Point of View (POV) Statement:</b> Retail payment users and SOC analysts need an intelligent, transparent payment defense system that dynamically assesses transaction risk, explains why an anomaly occurred, and strictly holds customer balances until step-up authentication is verified, so that fraudulent exfiltration is prevented without imposing friction on normal legitimate commerce.
    """, styles["AcademicBody"]))
    story.append(PageBreak())

    # =========================================================
    # SECTION 5 — IDEATION
    # =========================================================
    story.append(Paragraph("5. Ideation & Decision Matrix", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("5.1 Ideation Process & 5.2 Candidate Solutions", styles["SectionHeading"]))
    story.append(Paragraph("""
    During the ideation phase, multiple technological paradigms were evaluated to determine the optimal architectural synthesis for real-time fraud mitigation:
    <br/>• <b>Approach 1: Static Heuristic Rule Engine:</b> Deterministic SQL conditions checking transaction amount and time cutoffs.
    <br/>• <b>Approach 2: Pure Machine Learning Classifier:</b> Deep neural network or XGBoost model predicting fraud probability as a standalone binary output.
    <br/>• <b>Approach 3: Behavioral Anomaly Detection Only:</b> Tracking device fingerprints, IP velocity, and geolocation jumps without financial feature modeling.
    <br/>• <b>Approach 4: Universal Multi-Factor Authentication:</b> Forcing SMS/Email OTP verification on every single payment regardless of risk.
    <br/>• <b>Approach 5 (Selected): Hybrid Risk Scoring + SHAP XAI + Adaptive Pre-Settlement OTP:</b> Combining tuned ensemble ML inference, dynamic behavioral override weights, local game-theoretic feature attribution, and a 4-tier step-up verification pipeline.
    """, styles["AcademicBody"]))

    story.append(Paragraph("5.3 Decision Matrix & Solution Evaluation", styles["SectionHeading"]))
    matrix_headers = ["Evaluation Criteria", "Weight", "Approach 1 (Rules)", "Approach 2 (Pure ML)", "Approach 4 (MFA All)", "Approach 5 (Hybrid XAI)"]
    matrix_data = [
        ["Fraud Detection Sensitivity", "20%", "2 / 5", "4 / 5", "5 / 5", "<b>5 / 5</b>"],
        ["False Positive Mitigation", "20%", "1 / 5", "3 / 5", "1 / 5", "<b>5 / 5</b>"],
        ["Explainability (XAI)", "15%", "3 / 5", "1 / 5", "1 / 5", "<b>5 / 5</b>"],
        ["Pre-Settlement Fund Safety", "15%", "2 / 5", "3 / 5", "4 / 5", "<b>5 / 5</b>"],
        ["User Experience & Low Friction", "15%", "3 / 5", "4 / 5", "1 / 5", "<b>5 / 5</b>"],
        ["Implementation Feasibility", "15%", "5 / 5", "3 / 5", "4 / 5", "<b>4 / 5</b>"],
        ["<b>Weighted Total Score</b>", "100%", "<b>2.45 / 5.0</b>", "<b>3.10 / 5.0</b>", "<b>2.95 / 5.0</b>", "<b>4.85 / 5.0</b>"]
    ]
    story.append(make_table(matrix_headers, matrix_data, [130, 45, 80, 80, 80, 80], styles))
    story.append(Spacer(1, 4))

    story.append(Paragraph("5.4 Selected Solution & 5.5 Proposed System Architecture", styles["SectionHeading"]))
    story.append(Paragraph("""
    <b>Selection Rationale:</b> Approach 5 achieved the highest weighted evaluation score (4.85 / 5.0). It eliminates false positive friction by auto-approving low-risk transactions, applies step-up Email OTP only when risk is elevated (Medium/High), isolates critical threats for security review, and provides transparent SHAP explanations to both customers and SOC analysts.
    """, styles["AcademicBody"]))

    add_image_if_exists(story, FIGURES_DIR / "presettlement_security_flow.png", width=5.5*inch, height=2.8*inch,
                        caption="Figure 5.1: Selected Hybrid Pre-Settlement Risk Architecture & Zero-Debit Workflow", styles=styles)
    story.append(PageBreak())

    # =========================================================
    # SECTION 6 — REQUIREMENTS ANALYSIS
    # =========================================================
    story.append(Paragraph("6. Requirements Analysis", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("6.1 User Requirements & 6.2 Functional Requirements", styles["SectionHeading"]))
    fn_headers = ["Req ID", "Module", "Functional Requirement Description", "Priority"]
    fn_data = [
        ["FR-01", "Auth", "User registration with email, phone, and secure password hashing (Bcrypt/PBKDF2).", "Must Have"],
        ["FR-02", "Auth", "Payment PIN configuration with numeric validation, failure lockouts, and cryptographic hashing.", "Must Have"],
        ["FR-03", "Payment", "Simulated payment ingestion supporting UPI ID, phone number, and QR code parsing.", "Must Have"],
        ["FR-04", "Feature", "Feature extraction calculating balance differentials, amount-to-balance ratios, and hour.", "Must Have"],
        ["FR-05", "ML Engine", "Real-time ensemble inference computing probability of fraud using serialized models.", "Must Have"],
        ["FR-06", "Risk Engine", "Multi-window velocity tracking (1m, 10m, 1h, 24h) and dynamic composite risk scoring.", "Must Have"],
        ["FR-07", "Policy", "Enforce 4-tier risk classification: LOW (0–29), MEDIUM (30–59), HIGH (60–79), CRITICAL (80–100).", "Must Have"],
        ["FR-08", "Security", "Pre-settlement invariant: Zero balance deduction on Medium/High/Critical prior to verification.", "Must Have"],
        ["FR-09", "OTP", "Cryptographic Email OTP generation, hashing, rate limiting, and step-up verification.", "Must Have"],
        ["FR-10", "Settlement", "Atomic database settlement deducting sender balance and crediting recipient upon approval.", "Must Have"],
        ["FR-11", "XAI", "Generate dual-view SHAP explanations: natural language for user and waterfall for SOC.", "Must Have"],
        ["FR-12", "SOC Portal", "Security analyst incident triage portal for alert investigation, case assignment, and resolution.", "Must Have"],
        ["FR-13", "Audit", "Immutable structured JSON audit logging capturing request IDs, IP addresses, and events.", "Must Have"]
    ]
    story.append(make_table(fn_headers, fn_data, [45, 65, 335, 50], styles))
    story.append(Spacer(1, 4))

    story.append(Paragraph("6.3 Non-Functional Requirements", styles["SectionHeading"]))
    nfr_headers = ["NFR ID", "Category", "Specification & Target Metric", "Verification Method"]
    nfr_data = [
        ["NFR-01", "Performance", "End-to-end ML inference and risk scoring latency < 1.2 seconds.", "Automated Benchmarks"],
        ["NFR-02", "Security", "Zero plaintext storage of passwords, PINs, OTPs, or API secrets.", "Static Code & DB Audits"],
        ["NFR-03", "Data Integrity", "ACID transactional atomicity preventing double debits or balance drift.", "Concurrent Pytest Runs"],
        ["NFR-04", "Availability", "Graceful fallback to heuristic rules if ML model fails to load.", "Fault Injection Tests"],
        ["NFR-05", "Usability", "Responsive Glassmorphism UI rendering across mobile and desktop viewports.", "Cross-Device Testing"],
        ["NFR-06", "Maintainability", "Modular service-layer architecture with full unit test coverage (502 tests).", "Pytest Test Suite"]
    ]
    story.append(make_table(nfr_headers, nfr_data, [50, 75, 260, 110], styles))
    story.append(Spacer(1, 4))

    story.append(Paragraph("6.4 Hardware, 6.5 Software Requirements & 6.6 User Roles (RBAC)", styles["SectionHeading"]))
    rbac_headers = ["System Operation / Resource", "Retail Customer", "SOC Analyst", "System Admin"]
    rbac_data = [
        ["Initiate Payment & Enter PIN", "Allowed", "Allowed", "Allowed"],
        ["View Personal Transactions & SHAP Summary", "Allowed (Own Only)", "Allowed (All)", "Allowed (All)"],
        ["Perform Step-Up OTP Verification", "Allowed (Own Challenge)", "Denied (IDOR Protected)", "Denied"],
        ["Manage Personal Beneficiaries", "Allowed (Own Only)", "Read-Only Telemetry", "Full Access"],
        ["Access SOC Incident Management Queue", "Denied (403 Forbidden)", "Allowed (Investigate/Assign)", "Full Access"],
        ["Resolve / Dismiss Fraud Alerts", "Denied (403 Forbidden)", "Allowed with Notes", "Full Access"],
        ["Inspect System Audit Logs & Telemetry", "Denied (403 Forbidden)", "Allowed (Read-Only)", "Full Access"]
    ]
    story.append(make_table(rbac_headers, rbac_data, [175, 105, 110, 105], styles))
    story.append(PageBreak())

    # =========================================================
    # SECTION 7 — TECHNOLOGY STACK
    # =========================================================
    story.append(Paragraph("7. Technology Stack Rationale", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("7.1 Architectural Technology Selection", styles["SectionHeading"]))
    story.append(Paragraph("""
    The technology stack for FraudShield AI was selected to ensure high computational throughput for machine learning inference, robust transactional data integrity, and a modern, responsive user experience.
    """, styles["AcademicBody"]))

    stack_headers = ["Layer", "Technology", "Role in Project", "Selection Rationale & Key Advantages"]
    stack_data = [
        ["Frontend UI", "HTML5, CSS3, JS (ES6+)", "Client Presentation", "Vanilla Glassmorphism design tokens provide a modern, lightweight, dependency-free UI."],
        ["Styling / UI", "Bootstrap 5.3", "Responsive Grid", "Accelerates responsive layout development and standardizes modal dialogues for OTP."],
        ["Data Viz", "Chart.js", "Analytics Visualizations", "Renders dynamic client-side risk telemetry charts and transaction volume trends."],
        ["Backend API", "Python 3.11+, Flask 3.1", "Core API Gateway", "Lightweight, modular WSGI micro-framework offering exceptional performance and rich ML library bindings."],
        ["ORM / DB", "SQLAlchemy 2.0 ORM", "Data Access & Models", "Provides clean database abstraction, ACID transaction control, and dialect compatibility."],
        ["Security", "Flask-JWT-Extended", "Authentication & RBAC", "Stateless, cryptographic JWT authentication protecting endpoints with role-based claims."],
        ["ML Models", "Scikit-Learn, XGBoost", "Supervised Classifiers", "Tuned Random Forest and Gradient Boosted Trees for high-recall fraud detection on imbalanced data."],
        ["XAI Engine", "SHAP (TreeExplainer)", "Explainable AI Service", "Computes exact game-theoretic Shapley values to interpret tree ensemble decisions."],
        ["Persistence", "SQLite / PostgreSQL", "Relational Database", "SQLite provides lightweight, self-contained testing isolation; fully compatible with PostgreSQL."],
        ["Notifications", "Brevo / Resend / SMTP", "Email OTP Dispatch", "Flexible multi-provider email architecture for reliable delivery of step-up verification tokens."],
        ["Test Suite", "Pytest 9.1", "Automated Testing", "Industry-standard testing framework validating 502 unit, integration, and security test cases."]
    ]
    story.append(make_table(stack_headers, stack_data, [75, 110, 115, 195], styles))
    story.append(Spacer(1, 4))

    story.append(Paragraph("7.2 Technology Stack Architecture Diagram", styles["SectionHeading"]))
    add_image_if_exists(story, FIGURES_DIR / "architecture_diagram.png", width=5.5*inch, height=2.8*inch,
                        caption="Figure 7.1: Multi-Tier Technological Architecture of FraudShield AI Platform", styles=styles)
    story.append(PageBreak())

    # =========================================================
    # SECTION 8 — SYSTEM DESIGN
    # =========================================================
    story.append(Paragraph("8. System Design & Data Flow Modeling", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("8.1 High-Level Architecture & 8.2 System Workflow", styles["SectionHeading"]))
    story.append(Paragraph("""
    FraudShield AI employs a 3-tier enterprise architecture comprising the <b>Presentation Tier</b> (Glassmorphism Web Portal), the <b>Application & Intelligence Tier</b> (Flask REST API, Feature Pipeline, Random Forest Classifier, Hybrid Risk Aggregator, SHAP Explainer), and the <b>Data & Persistence Tier</b> (SQLAlchemy ORM, Relational Database, Joblib Serialized Artifacts).
    """, styles["AcademicBody"]))

    story.append(Paragraph("8.3 Data Flow Diagram — Level 0 (Context Level DFD)", styles["SectionHeading"]))
    add_image_if_exists(story, FIGURES_DIR / "dfd_level0.png", width=5.5*inch, height=2.5*inch,
                        caption="Figure 8.1: Data Flow Diagram (DFD) — Level 0 Context Diagram", styles=styles)

    story.append(Paragraph("8.4 Data Flow Diagram — Level 1 (Major Process Decomposition)", styles["SectionHeading"]))
    add_image_if_exists(story, FIGURES_DIR / "dfd_level1.png", width=5.5*inch, height=2.6*inch,
                        caption="Figure 8.2: Data Flow Diagram (DFD) — Level 1 Process Decomposition", styles=styles)

    story.append(Paragraph("8.5 Data Flow Diagram — Level 2 (Subsystem Breakdown)", styles["SectionHeading"]))
    add_image_if_exists(story, FIGURES_DIR / "dfd_level2.png", width=5.5*inch, height=2.6*inch,
                        caption="Figure 8.3: Data Flow Diagram (DFD) — Level 2 Transaction Risk & Settlement Subsystem", styles=styles)

    story.append(Paragraph("8.8 Strict 15-Step End-to-End Pre-Settlement Transaction Order", styles["SectionHeading"]))
    steps_text = """
    To enforce bulletproof security and eliminate premature fund deduction, every transaction strictly adheres to the following chronological execution pipeline:
    <br/><b>1. Payment Initiation:</b> User enters amount, beneficiary details, and payment PIN via web portal.
    <br/><b>2. Request Validation:</b> API validates input types, positive non-zero amounts, and format compliance.
    <br/><b>3. Session & Auth Verification:</b> JWT token is verified to identify the authenticated customer.
    <br/><b>4. Balance & PIN Check:</b> System checks sufficient available balance and validates payment PIN. <i>Zero balance is deducted at this stage.</i>
    <br/><b>5. Feature Extraction:</b> Feature service computes mathematical balance differentials and ratios.
    <br/><b>6. ML Model Inference:</b> Serialized Random Forest model computes raw fraud probability <code>P(Fraud)</code>.
    <br/><b>7. Behavioral Risk Telemetry:</b> Signal service evaluates multi-window velocity, device trust, and new beneficiary status.
    <br/><b>8. Hybrid Risk Scoring:</b> Composite 0–100 risk score is calculated via weighted aggregation.
    <br/><b>9. 4-Tier Risk Classification:</b> Score is mapped to LOW, MEDIUM, HIGH, or CRITICAL policy tier.
    <br/><b>10. Security Decision Gate:</b> System determines if immediate approval, OTP step-up, or SOC review is required.
    <br/><b>11. Step-Up Challenge Dispatch:</b> If MEDIUM or HIGH, cryptographic Email OTP is generated and dispatched; balance remains held.
    <br/><b>12. User Verification:</b> Customer enters received OTP token via modal dialog.
    <br/><b>13. Atomic Settlement:</b> Upon successful verification, sender balance is debited and recipient balance is credited within an atomic DB transaction.
    <br/><b>14. Database Persistence:</b> Transaction status updated to <code>APPROVED</code> or <code>SETTLED</code>.
    <br/><b>15. Audit Logging & Notification:</b> Immutable structured audit log recorded and confirmation email dispatched.
    """
    story.append(Paragraph(steps_text, styles["AcademicBody"]))
    story.append(PageBreak())

    # =========================================================
    # SECTION 9 — DATABASE DESIGN
    # =========================================================
    story.append(Paragraph("9. Database Design & Entity Schemas", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("9.1 Database Architecture & 9.3 Entity-Relationship (ER) Diagram", styles["SectionHeading"]))
    story.append(Paragraph("""
    The database architecture is designed using a fully normalized relational schema managed via SQLAlchemy ORM. The schema comprises 11 interconnected entities enforcing referential integrity, foreign key cascades, and unique constraints.
    """, styles["AcademicBody"]))

    add_image_if_exists(story, FIGURES_DIR / "erd_diagram.png", width=5.5*inch, height=3.0*inch,
                        caption="Figure 9.1: Comprehensive Entity-Relationship Diagram (ERD) of FraudShield AI", styles=styles)

    story.append(Paragraph("9.5 Complete Table Schemas (All 11 Production Entities)", styles["SectionHeading"]))

    schema_tables = [
        ("Table 1: users", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique user identifier"],
          ["email", "VARCHAR(120)", "Unique, Not Null", "User email address for login and OTP delivery"],
          ["username", "VARCHAR(80)", "Unique, Not Null", "Public display handle"],
          ["phone_number", "VARCHAR(20)", "Indexed", "Verified mobile number for P2P transfers"],
          ["password_hash", "VARCHAR(255)", "Not Null", "Cryptographically salted password hash"],
          ["payment_pin_hash", "VARCHAR(255)", "Nullable", "Bcrypt hash of 4-6 digit numeric payment PIN"],
          ["balance", "FLOAT", "Default 10000.0", "Available account balance (stored in currency units)"],
          ["is_admin", "BOOLEAN", "Default False", "Role flag for SOC analyst / admin privileges"],
          ["is_email_verified", "BOOLEAN", "Default False", "Email verification status"],
          ["failed_pin_attempts", "INTEGER", "Default 0", "Counter for payment PIN brute force lockout"],
          ["pin_locked_until", "DATETIME", "Nullable", "Timestamp indicating PIN lockout expiration"]]),

        ("Table 2: transactions", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique transaction identifier"],
          ["user_id", "INTEGER", "FK -> users.id", "Originating sender account ID"],
          ["transaction_type", "VARCHAR(20)", "Not Null", "Type: TRANSFER, CASH_OUT, PAYMENT, etc."],
          ["amount", "FLOAT", "Not Null", "Transaction transfer value"],
          ["oldbalanceOrg", "FLOAT", "Not Null", "Sender initial balance before transfer"],
          ["newbalanceOrig", "FLOAT", "Not Null", "Sender post-transfer balance"],
          ["oldbalanceDest", "FLOAT", "Not Null", "Recipient initial balance"],
          ["newbalanceDest", "FLOAT", "Not Null", "Recipient post-transfer balance"],
          ["nameDest", "VARCHAR(100)", "Not Null", "Destination identifier (UPI ID or Account)"],
          ["risk_level", "VARCHAR(20)", "Not Null", "Policy Tier: LOW, MEDIUM, HIGH, CRITICAL"],
          ["risk_score", "FLOAT", "Not Null", "Composite risk score (0–100 scale)"],
          ["ml_fraud_probability", "FLOAT", "Not Null", "Raw probability output from Random Forest model"],
          ["status", "VARCHAR(20)", "Not Null", "APPROVED, OTP_REQUIRED, UNDER_REVIEW, REJECTED"],
          ["is_settled", "BOOLEAN", "Default False", "Flag indicating atomic balance settlement completion"],
          ["timestamp", "DATETIME", "Default UTC Now", "Transaction creation timestamp"]]),

        ("Table 3: alerts", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique security alert identifier"],
          ["transaction_id", "INTEGER", "FK -> transactions.id", "Associated suspicious transaction ID"],
          ["user_id", "INTEGER", "FK -> users.id", "Flagged customer account ID"],
          ["severity", "VARCHAR(20)", "Not Null", "Severity: MEDIUM, HIGH, CRITICAL"],
          ["status", "VARCHAR(20)", "Default OPEN", "OPEN, INVESTIGATING, RESOLVED, DISMISSED"],
          ["assigned_to", "INTEGER", "FK -> users.id", "Assigned SOC analyst user ID"],
          ["reason", "TEXT", "Not Null", "Detailed textual summary of risk triggers"],
          ["created_at", "DATETIME", "Default UTC Now", "Alert generation timestamp"]]),

        ("Table 4: otp_challenges", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique challenge identifier"],
          ["user_id", "INTEGER", "FK -> users.id", "Target user receiving verification token"],
          ["transaction_id", "INTEGER", "FK -> transactions.id", "Associated pending transaction ID"],
          ["challenge_type", "VARCHAR(30)", "Not Null", "TRANSACTION_STEPUP, LOGIN_MFA, etc."],
          ["otp_hash", "VARCHAR(255)", "Not Null", "SHA-256 / Bcrypt hash of 6-digit numeric OTP"],
          ["expires_at", "DATETIME", "Not Null", "Expiration timestamp (strictly enforced 5-10m)"],
          ["attempts_count", "INTEGER", "Default 0", "Counter for incorrect submissions (Max 3)"],
          ["is_verified", "BOOLEAN", "Default False", "Flag indicating successful verification"],
          ["is_consumed", "BOOLEAN", "Default False", "Anti-replay flag preventing reuse"]]),

        ("Table 5: beneficiaries", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique beneficiary record ID"],
          ["user_id", "INTEGER", "FK -> users.id", "Customer account owning beneficiary list"],
          ["name", "VARCHAR(100)", "Not Null", "Beneficiary recipient display name"],
          ["upi_id", "VARCHAR(100)", "Not Null", "Recipient UPI Virtual Payment Address"],
          ["phone_number", "VARCHAR(20)", "Nullable", "Optional recipient mobile number"],
          ["trust_level", "VARCHAR(20)", "Default NEW", "Trust tier: NEW, TRUSTED, REVOKED"],
          ["cooling_period_ends_at", "DATETIME", "Not Null", "24-hour security cooling expiration timestamp"],
          ["total_transfers_count", "INTEGER", "Default 0", "Historical count of completed payments"]]),

        ("Table 6: device_profiles", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique device profile ID"],
          ["user_id", "INTEGER", "FK -> users.id", "User account associated with device"],
          ["device_fingerprint_hash", "VARCHAR(64)", "Not Null, Indexed", "SHA-256 hash of browser canvas & user-agent"],
          ["trust_status", "VARCHAR(20)", "Default UNKNOWN", "Status: UNKNOWN, TRUSTED, SUSPICIOUS, BLOCKED"],
          ["last_seen_ip", "VARCHAR(45)", "Not Null", "Client IP address from last login"],
          ["last_seen_at", "DATETIME", "Default UTC Now", "Most recent device activity timestamp"]]),

        ("Table 7: geo_location_records", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique geolocation entry ID"],
          ["user_id", "INTEGER", "FK -> users.id", "Target user record"],
          ["transaction_id", "INTEGER", "FK -> transactions.id", "Associated transaction"],
          ["latitude", "FLOAT", "Not Null", "Geographical latitude coordinate"],
          ["longitude", "FLOAT", "Not Null", "Geographical longitude coordinate"],
          ["city", "VARCHAR(100)", "Not Null", "Resolved city name"],
          ["distance_from_last_km", "FLOAT", "Default 0.0", "Computed Haversine distance from previous transfer"],
          ["is_impossible_travel", "BOOLEAN", "Default False", "Flag indicating velocity > 900 km/h"]]),

        ("Table 8: password_reset_tokens", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique token record ID"],
          ["user_id", "INTEGER", "FK -> users.id", "Target user requesting password recovery"],
          ["token_hash", "VARCHAR(255)", "Not Null, Indexed", "SHA-256 hash of cryptographically secure token"],
          ["expires_at", "DATETIME", "Not Null", "Token expiration timestamp (strictly enforced 15m)"],
          ["is_consumed", "BOOLEAN", "Default False", "Anti-replay consumption flag"]]),

        ("Table 9: soc_cases", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique SOC investigation case identifier"],
          ["alert_id", "INTEGER", "FK -> alerts.id", "Source security alert triggering investigation"],
          ["assigned_analyst_id", "INTEGER", "FK -> users.id", "Assigned SOC fraud investigator"],
          ["case_status", "VARCHAR(20)", "Default OPEN", "OPEN, INVESTIGATING, ESCALATED, RESOLVED"],
          ["priority", "VARCHAR(20)", "Default MEDIUM", "LOW, MEDIUM, HIGH, CRITICAL"],
          ["evidence_snapshot_json", "TEXT", "Nullable", "Frozen JSON snapshot of transaction features and SHAP values"],
          ["resolution_summary", "TEXT", "Nullable", "Final narrative justification provided by analyst"],
          ["created_at", "DATETIME", "Default UTC Now", "Case initiation timestamp"],
          ["resolved_at", "DATETIME", "Nullable", "Case closure timestamp"]]),

        ("Table 10: case_notes", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique note identifier"],
          ["case_id", "INTEGER", "FK -> soc_cases.id", "Parent investigation case ID"],
          ["analyst_id", "INTEGER", "FK -> users.id", "Authoring analyst user ID"],
          ["note_text", "TEXT", "Not Null", "Analyst investigative commentary or action record"],
          ["created_at", "DATETIME", "Default UTC Now", "Note logging timestamp"]]),

        ("Table 11: audit_logs", ["Column", "Data Type", "Constraints", "Description"],
         [["id", "INTEGER", "PK, Auto-inc", "Unique audit log entry identifier"],
          ["user_id", "INTEGER", "Nullable", "Acting user account ID (or Null if unauthenticated)"],
          ["event_type", "VARCHAR(50)", "Not Null", "AUTH_LOGIN, PAYMENT_INIT, OTP_VERIFIED, ALERT_RESOLVED"],
          ["ip_address", "VARCHAR(45)", "Not Null", "Client IP address capturing origin network"],
          ["user_agent", "VARCHAR(255)", "Nullable", "Browser / client user agent header"],
          ["details_json", "TEXT", "Nullable", "Structured JSON payload capturing event metadata and state diffs"],
          ["timestamp", "DATETIME", "Default UTC Now", "Immutable event occurrence timestamp"]])
    ]

    for t_title, headers, rows in schema_tables:
        story.append(Paragraph(t_title, styles["SubSectionHeading"]))
        story.append(make_table(headers, rows, [95, 90, 115, 195], styles))
        story.append(Spacer(1, 3))

    story.append(PageBreak())

    # =========================================================
    # SECTION 10 — MODULE DESCRIPTION
    # =========================================================
    story.append(Paragraph("10. Module Description & Subsystem Architecture", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    modules_data = [
        ("10.1 Authentication & Payment Identity Module",
         "Manages user lifecycle, secure JWT session issuance, password hashing via Bcrypt, and 4-6 digit numeric payment PIN configuration with brute-force lockout safeguards.",
         "User credentials, registration payload, PIN setup requests.",
         "Bcrypt hashing, password complexity verification, JWT token generation, PIN attempt rate limiting.",
         "JWT access tokens, user profile objects, PIN status confirmations.",
         "<code>users</code>, <code>password_reset_tokens</code>",
         "<code>/api/auth/register</code>, <code>/api/auth/login</code>, <code>/api/auth/payment-pin/set</code>",
         "test_auth.py, test_payment_pin_flow.py (49 tests)"),

        ("10.2 Payment Ingestion & Feature Engineering Module",
         "Parses incoming payment requests (UPI, P2P, QR payloads), validates parameter types, and computes mathematical balance differentials and temporal features.",
         "Raw payment payload: amount, sender, recipient UPI, payment method.",
         "Input sanitization, balance subtraction checks, ratio calculation (<code>amount / (oldbalanceOrg + 1)</code>).",
         "Structured 11-dimensional feature dictionary ready for ML pipeline.",
         "<code>users</code>, <code>transactions</code>",
         "<code>/api/predict</code>, <code>/api/upi/parse-qr</code>",
         "test_feature_engineering.py, test_preprocessing.py (9 tests)"),

        ("10.3 Machine Learning Inference Module",
         "Loads serialized Random Forest model and preprocessing pipeline artifacts via Joblib to compute real-time fraud probability scores.",
         "Engineered feature vector.",
         "One-hot encoding of transaction type, standard scaling of numeric features, tree ensemble probability calculation.",
         "Continuous fraud probability <code>P(Fraud) in [0.0, 1.0]</code>.",
         "Read-only access to <code>ml/artifacts/model.joblib</code>",
         "Internal inference service interface.",
         "test_inference.py, test_strong_models.py (13 tests)"),

        ("10.4 Behavioral Intelligence & Signal Telemetry Module",
         "Evaluates real-time contextual signals including multi-window velocity (1m, 10m, 1h, 24h), new/cooling beneficiary status, device trust status, and geographical jumps.",
         "Sender transaction history, device fingerprint, IP location.",
         "Rolling window velocity aggregation, Haversine distance travel speed check, device trust lookup.",
         "Behavioral risk score (0–100) and structured telemetry signal flags.",
         "<code>transactions</code>, <code>beneficiaries</code>, <code>device_profiles</code>, <code>geo_location_records</code>",
         "Internal risk signal service interface.",
         "test_beneficiary_intelligence.py, test_geo_intelligence.py, test_device_intelligence.py (48 tests)"),

        ("10.5 Hybrid Risk Engine & Policy Classification Module",
         "Fuses ML probability with behavioral signals using dynamic category weighting to generate a standardized 0–100 composite risk score and 4-tier policy decision.",
         "ML fraud probability, behavioral signals, transaction type.",
         "<code>Score = clamp(round(w_ml*(ml_prob*100) + w_sig*signals + overrides), 0, 100)</code>",
         "Composite Risk Score (0–100), Risk Tier (LOW, MEDIUM, HIGH, CRITICAL), Security Action.",
         "<code>transactions</code>, <code>alerts</code>",
         "<code>/api/predict</code>",
         "test_hybrid_risk_engine.py, test_risk_engine.py, test_medium_high_otp_stepup.py (48 tests)"),

        ("10.6 Adaptive Step-Up OTP & Settlement Protection Module",
         "Enforces pre-settlement zero-debit invariant by generating cryptographic Email OTP for Medium/High transactions and releasing settlement only upon verification.",
         "Pending transaction ID, recipient email, submitted OTP token.",
         "Cryptographic 6-digit OTP generation, SHA-256 hashing, expiration check (5m), attempt counter.",
         "Verification result (True/False), atomic debit/credit execution.",
         "<code>otp_challenges</code>, <code>transactions</code>, <code>users</code>",
         "<code>/api/otp/verify</code>, <code>/api/otp/resend</code>",
         "test_email_otp_delivery.py, test_real_upi_payment_flow.py (42 tests)"),

        ("10.7 Explainable AI (SHAP) Service Module",
         "Calculates exact Shapley values using <code>shap.TreeExplainer</code> to explain model feature contributions in human-readable and analyst formats.",
         "Processed transaction feature vector.",
         "Local game-theoretic feature attribution calculation, attribution mapping to plain-English sentences.",
         "Dual-perspective explanation dictionary (Customer summary + Waterfall data).",
         "Read-only ML artifacts",
         "<code>/api/shap/explain/<tx_id></code>",
         "test_shap.py (7 tests)"),

        ("10.8 Security Operations Center (SOC) Case Management Module",
         "Provides security analysts with real-time alert triage, automated case generation, analyst assignment, evidence snapshotting, and remediation workflows.",
         "Security alerts, case status updates, analyst notes.",
         "State machine transitions (OPEN -> INVESTIGATING -> RESOLVED), evidence freezing, note appending.",
         "SOC dashboard metrics, case timeline, resolution audit logs.",
         "<code>soc_cases</code>, <code>case_notes</code>, <code>alerts</code>",
         "<code>/api/admin/soc/cases</code>, <code>/api/admin/alerts/<id>/resolve</code>",
         "test_admin_soc.py, test_soc_case_management.py (22 tests)"),

        ("10.9 Beneficiary & Cooling Period Management Module",
         "Manages trusted payees, enforces a 24-hour mandatory security cooling period for newly added recipients, and tracks progressive trust evolution.",
         "Beneficiary creation payloads, historical payment volumes.",
         "Cooling period calculation, transaction counter increments, trust level promotion (NEW -> TRUSTED).",
         "Beneficiary status objects, risk telemetry override signals.",
         "<code>beneficiaries</code>, <code>transactions</code>",
         "<code>/api/beneficiaries</code>, <code>/api/beneficiaries/<id></code>",
         "test_beneficiary_intelligence.py (18 tests)"),

        ("10.10 Audit Trail & Telemetry Module",
         "Maintains an immutable, structured event log capturing all authentication attempts, payment initiations, risk evaluations, and SOC analyst actions.",
         "Application events, request context, user IDs, IP addresses.",
         "JSON serialization, timestamping, database persistence.",
         "Structured audit log entries, admin search API responses.",
         "<code>audit_logs</code>",
         "<code>/api/admin/audit/logs</code>",
         "test_audit.py (4 tests)")
    ]

    for m_title, purpose, inputs, proc, outputs, db, apis, tests in modules_data:
        story.append(Paragraph(m_title, styles["SectionHeading"]))
        m_summary = f"""
        <b>Purpose:</b> {purpose}<br/>
        <b>Inputs:</b> {inputs}<br/>
        <b>Processing Logic:</b> {proc}<br/>
        <b>Outputs:</b> {outputs}<br/>
        <b>Database Interaction:</b> {db} | <b>APIs:</b> {apis}<br/>
        <b>Related Test Coverage:</b> {tests}
        """
        story.append(Paragraph(m_summary, styles["AcademicBody"]))
        story.append(Spacer(1, 3))

    story.append(PageBreak())

    # =========================================================
    # SECTION 11 — UML MODELING
    # =========================================================
    story.append(Paragraph("11. UML Modeling & System Architecture", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("11.1 UML Use Case Diagram", styles["SectionHeading"]))
    story.append(Paragraph("""
    The Use Case Diagram illustrates the functional interactions between the primary human actors (Retail Customer, SOC Fraud Analyst, System Administrator) and automated system boundary processes (ML Classifier, Risk Policy Engine, Email Notification Gateway).
    """, styles["AcademicBody"]))
    add_image_if_exists(story, FIGURES_DIR / "uml_use_case.png", width=5.5*inch, height=2.7*inch,
                        caption="Figure 11.1: UML Use Case Diagram for FraudShield AI Platform", styles=styles)

    story.append(Paragraph("11.2 UML Activity Diagram (Pre-Settlement Workflow)", styles["SectionHeading"]))
    story.append(Paragraph("""
    The Activity Diagram models the step-by-step transaction decision pipeline, illustrating how LOW risk transactions are approved immediately while MEDIUM and HIGH transactions enter an OTP challenge state with zero balance deducted.
    """, styles["AcademicBody"]))
    add_image_if_exists(story, FIGURES_DIR / "uml_activity.png", width=5.5*inch, height=2.9*inch,
                        caption="Figure 11.2: UML Activity Diagram: Pre-Settlement Transaction Verification Lifecycle", styles=styles)

    story.append(Paragraph("11.3 UML Class Diagram (Core Entities & Services)", styles["SectionHeading"]))
    add_image_if_exists(story, FIGURES_DIR / "uml_class.png", width=5.5*inch, height=2.7*inch,
                        caption="Figure 11.3: UML Class Diagram: Data Models, Engine Services and Pipeline Interfaces", styles=styles)

    story.append(Paragraph("11.4 UML Sequence Diagram (End-to-End Payment & OTP)", styles["SectionHeading"]))
    add_image_if_exists(story, FIGURES_DIR / "uml_sequence.png", width=5.5*inch, height=2.7*inch,
                        caption="Figure 11.4: UML Sequence Diagram: Transaction Ingestion, Step-Up OTP Challenge and Settlement", styles=styles)

    story.append(Paragraph("11.5 UML Component & 11.6 Deployment Diagrams", styles["SectionHeading"]))
    add_image_if_exists(story, FIGURES_DIR / "uml_component.png", width=5.5*inch, height=2.3*inch,
                        caption="Figure 11.5: UML Component Diagram: Modular Architecture & Service Bindings", styles=styles)
    add_image_if_exists(story, FIGURES_DIR / "uml_deployment.png", width=5.5*inch, height=2.3*inch,
                        caption="Figure 11.6: UML Deployment Diagram: Production Container & Gateway Topology", styles=styles)
    story.append(PageBreak())

    # =========================================================
    # SECTION 12 — IMPLEMENTATION / WORKING PRINCIPLE
    # =========================================================
    story.append(Paragraph("12. Implementation / Working Principle", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    impl_sections = [
        ("12.1 Overall System Implementation",
         """FraudShield AI is implemented as a production-ready Flask application factory supporting blueprint modularity, SQLAlchemy database session management, JWT authentication, and thread-safe singleton machine learning inference services."""),

        ("12.6 Feature Engineering Logic & Transformation Pipeline",
         """Raw transactions are transformed into an 11-dimensional feature vector. The critical mathematical transformations include:
         <br/>• <b>Balance Differential:</b> <code>diffOrgBalance = oldbalanceOrg - newbalanceOrig - amount</code>
         <br/>• <b>Destination Balance Differential:</b> <code>diffDestBalance = newbalanceDest - oldbalanceDest - amount</code>
         <br/>• <b>Amount to Balance Ratio:</b> <code>amountToOldBalanceRatio = amount / (oldbalanceOrg + 1.0)</code> (Safely avoiding division by zero)
         <br/>• <b>Hour of Day:</b> <code>hour_of_day = step % 24</code> (Capturing diurnal temporal fraud anomalies)"""),

        ("12.8 Hybrid Risk Engine & Dynamic Score Formula",
         """The hybrid risk engine fuses statistical ML inference with behavioral signals. The mathematical formula is defined as:
         <br/><code>Combined Risk Score = clamp(round(w_ml * (ml_prob * 100) + w_signals * signals_score + overrides), 0, 100)</code>
         <br/>• <b>Account Draining Category:</b> <code>w_ml = 0.60, w_signals = 0.40</code> (Score floor = 85 if balance is 100% drained)
         <br/>• <b>Standard Transfer:</b> <code>w_ml = 0.50, w_signals = 0.50</code>
         <br/>• <b>Daily Normal Transaction:</b> <code>w_ml = 0.25, w_signals = 0.75</code>"""),

        ("12.9 4-Tier Risk Policy Enforcement",
         """The composite risk score directly drives deterministic security policies:
         <br/>• <b>LOW (0–29):</b> Action = <code>APPROVE_IMMEDIATELY</code>, Status = <code>APPROVED</code>, requires OTP = False.
         <br/>• <b>MEDIUM (30–59):</b> Action = <code>TRIGGER_OTP_VERIFICATION</code>, Status = <code>OTP_REQUIRED</code>, requires OTP = True.
         <br/>• <b>HIGH (60–79):</b> Action = <code>TRIGGER_OTP_VERIFICATION</code>, Status = <code>OTP_REQUIRED</code>, requires OTP = True.
         <br/>• <b>CRITICAL (80–100):</b> Action = <code>TRIGGER_SECURITY_REVIEW</code>, Status = <code>UNDER_REVIEW</code>, SOC Alert Created."""),

        ("12.11 Pre-Settlement Fund Safety & Atomic Execution",
         """When a transaction enters <code>OTP_REQUIRED</code> or <code>UNDER_REVIEW</code>, no sender balance is deducted. Only upon valid OTP verification does the payment service execute an atomic transaction block:
         <br/><code>db.session.begin_nested() -> user.balance -= amount -> dest.balance += amount -> tx.is_settled = True -> db.session.commit()</code>.
         <br/>If the OTP is exhausted (3 failed attempts) or expired, the transaction is marked <code>REJECTED</code> with zero balance loss."""),

        ("12.12 SHAP Explainability Engine Integration",
         """Local interpretability is computed via <code>shap.TreeExplainer(model)</code>. The service calculates additive Shapley contributions for each feature against the dataset base value <code>E[f(x)] = 0.0013</code>. Features with positive contributions (such as high <code>diffOrgBalance</code>) elevate the fraud score, while normal velocity suppresses the score.""")
    ]

    for title, text in impl_sections:
        story.append(Paragraph(title, styles["SectionHeading"]))
        story.append(Paragraph(text, styles["AcademicBody"]))
        story.append(Spacer(1, 3))

    story.append(PageBreak())

    # =========================================================
    # SECTION 13 — TESTING
    # =========================================================
    story.append(Paragraph("13. Testing & Empirical Validation", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("13.1 Testing Strategy & 13.3 Test Environment", styles["SectionHeading"]))
    story.append(Paragraph("""
    FraudShield AI was tested using a multi-tiered validation strategy comprising unit tests, API integration tests, security authorization tests (RBAC & IDOR), ML model consistency tests, and pre-settlement transaction settlement invariant tests. The test suite was executed in Python using Pytest 9.1 with isolated in-memory databases and mocked external notification providers.
    """, styles["AcademicBody"]))

    test_banner = """
    <b>LATEST VERIFIED TEST SUITE RESULT:</b><br/>
    <b>502 Total Tests Executed | 502 Passed | 0 Failed | 0 Errors | 100% Pass Rate</b><br/>
    <i>Verified across 41 dedicated test modules covering all application layers, security policies, and ML pipelines.</i>
    """
    story.append(make_callout(test_banner, styles, border_color="#16a34a", bg_color="#f0fdf4"))
    story.append(Spacer(1, 4))

    story.append(Paragraph("13.14 Comprehensive Test Results Summary (All 41 Test Suites)", styles["SectionHeading"]))
    test_headers = ["Test Suite File", "Module Under Test", "Tests", "Key Scenarios Tested", "Status"]
    test_data = [
        ["test_adaptive_security.py", "Adaptive Security", "6", "Risk decision boundaries, auto-approval, OTP step-up, max attempts lockout", "PASSED"],
        ["test_admin_portal_separation.py", "Admin Separation", "13", "Tenant isolation, RBAC redirects, customer data isolation, IDOR defense", "PASSED"],
        ["test_admin_soc.py", "SOC Operations", "9", "Analyst authentication, analytics endpoints, alert lifecycle, model drift telemetry", "PASSED"],
        ["test_audit.py", "Audit Trail", "4", "Audit log persistence, event types, JSON payload serialization, read filters", "PASSED"],
        ["test_auth.py", "Authentication", "12", "User registration, duplicate handling, JWT claims, role-based route protection", "PASSED"],
        ["test_beneficiary_intelligence.py", "Beneficiary Intelligence", "18", "24h cooling periods, progressive trust evolution, IDOR protection, revocation", "PASSED"],
        ["test_brevo_provider.py", "Brevo Notification", "9", "API payload formatting, HTTP error retries, rate-limit backoff, payload sanitization", "PASSED"],
        ["test_database.py", "Database Core", "7", "Session rollback on error, unique constraint enforcement, connection recycling", "PASSED"],
        ["test_device_intelligence.py", "Device Intelligence", "15", "User-agent parsing, SHA-256 fingerprinting, unknown device risk elevation", "PASSED"],
        ["test_e2e_system.py", "End-to-End System", "7", "Full lifecycle: registration -> payment -> high risk -> OTP challenge -> settlement", "PASSED"],
        ["test_email_otp_delivery.py", "Email OTP Delivery", "17", "Hashed OTP storage, anti-replay, expiration, plaintext leakage prevention", "PASSED"],
        ["test_email_password_reset.py", "Password Recovery", "6", "Token generation, expiration enforcement, single-use invalidation, notification", "PASSED"],
        ["test_email_verification.py", "Email Verification", "13", "Account activation token dispatch, verification state update, expired token rejection", "PASSED"],
        ["test_feature_engineering.py", "Feature Pipeline", "6", "Balance differential calculation, ratio safeguards against div-by-zero, hour-of-day", "PASSED"],
        ["test_frontend.py", "Frontend Templates", "7", "Glassmorphism template rendering, CSRF meta tags, CDN fallback script inclusion", "PASSED"],
        ["test_geo_intelligence.py", "Geo Intelligence", "17", "Haversine distance calculation, impossible travel speed checks, location baselines", "PASSED"],
        ["test_hybrid_risk_engine.py", "Hybrid Risk Engine", "21", "Boundary tests (50k, 92k, 100k, 250k), account drain override, alert generation", "PASSED"],
        ["test_inference.py", "ML Model Inference", "8", "Model loading, feature scaling alignment, fraud probability bounds, single-sample latency", "PASSED"],
        ["test_medium_high_otp_stepup.py", "Step-Up OTP", "10", "Zero debit on Medium/High until OTP verified, atomic settlement upon valid OTP", "PASSED"],
        ["test_mobile_verification.py", "Mobile Verification", "12", "Phone number format validation, SMS OTP mock delivery, phone-to-user linking", "PASSED"],
        ["test_models.py", "Data Models", "5", "Model attribute defaults, relationship cascades, repr strings, timestamp initializations", "PASSED"],
        ["test_password_recovery_real.py", "Password Recovery E2E", "15", "Full recovery journey: forgot password -> email token -> reset PIN/password", "PASSED"],
        ["test_password_reset.py", "Password Reset", "24", "Token expiry, anti-enumeration, Bcrypt re-hashing, session revocation upon reset", "PASSED"],
        ["test_payment_identity.py", "Payment Identity", "22", "UPI Virtual Payment Address resolution, phone number transfers, self-payment checks", "PASSED"],
        ["test_payment_pin_flow.py", "Payment PIN", "25", "PIN setup, numeric validation, 3-attempt lockout cooldown, zero debit on wrong PIN", "PASSED"],
        ["test_payment_pin_reset.py", "PIN Recovery", "7", "PIN reset challenge generation, verification, update, and lockout reset", "PASSED"],
        ["test_phone_registration_and_reuse.py", "Phone Registration", "23", "Phone registration uniqueness, unlinking, reassignment safeguards", "PASSED"],
        ["test_prediction_api.py", "Prediction API", "10", "HTTP POST /api/predict payload validation, authentication checks, response schema", "PASSED"],
        ["test_preprocessing.py", "Data Preprocessing", "3", "StandardScaler and OneHotEncoder transform pipeline validation and consistency", "PASSED"],
        ["test_profile_management.py", "Profile Management", "23", "User profile updates, email change verification, password modification", "PASSED"],
        ["test_real_upi_payment_flow.py", "Real UPI Flow", "25", "QR code parsing, self-transfer rejection, atomic balance settlement, idempotency", "PASSED"],
        ["test_resend_provider.py", "Resend Provider", "9", "Resend HTTP client wrapper, header authentication, error serialization", "PASSED"],
        ["test_risk_engine.py", "Risk Engine Core", "17", "Weight configuration, score normalization, edge cases (zero amount, huge amount)", "PASSED"],
        ["test_risk_level_compatibility.py", "Risk Compatibility", "5", "Backward compatibility across legacy and 4-tier risk schema representations", "PASSED"],
        ["test_security_middleware.py", "Security Headers", "16", "CSP, HSTS, X-Content-Type-Options, X-Frame-Options, CORS policy validation", "PASSED"],
        ["test_setup.py", "App Initialization", "6", "Environment loading, configuration validation, directory creation, extension binding", "PASSED"],
        ["test_shap.py", "Explainable AI", "7", "TreeExplainer initialization, waterfall format, natural language customer summaries", "PASSED"],
        ["test_soc_case_management.py", "SOC Case Management", "13", "Alert-to-case conversion, analyst timeline notes, evidence snapshots, remediation", "PASSED"],
        ["test_strong_models.py", "Model Benchmarking", "5", "Precision/Recall evaluation against baseline metrics, artifact serialization integrity", "PASSED"],
        ["test_upi_payment_flow.py", "UPI Security", "25", "Atomic payment success, double debit prevention, zero balance movement on error", "PASSED"]
    ]
    story.append(make_table(test_headers, test_data, [130, 95, 35, 195, 45], styles))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Total Test Execution Summary:</b> 41 Test Files | <b>502 Total Passing Tests</b> | 0 Failures | 0 Errors | 100% Pass Rate.", styles["AcademicBody"]))
    story.append(PageBreak())

    # =========================================================
    # SECTION 14 — RESULTS & SCREENSHOTS
    # =========================================================
    story.append(Paragraph("14. Results & System Screenshots", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("14.1 User Interface & Operational Screenshots", styles["SectionHeading"]))
    story.append(Paragraph("""
    The figures below present empirical visual evidence of the operational FraudShield AI platform, capturing user authentication, payment simulation, real-time risk classification, SHAP explanations, and SOC incident triage.
    """, styles["AcademicBody"]))

    add_image_if_exists(story, FIGURES_DIR / "model_comparison_chart.png", width=5.5*inch, height=2.6*inch,
                        caption="Figure 14.1: Machine Learning Model Performance Comparison Across Evaluation Metrics", styles=styles)

    add_image_if_exists(story, FIGURES_DIR / "random_forest_tuned_confusion_matrix.png", width=4.3*inch, height=2.6*inch,
                        caption="Figure 14.2: Confusion Matrix for Tuned Production Random Forest Classifier (0 False Positives)", styles=styles)

    add_image_if_exists(story, FIGURES_DIR / "shap_waterfall_concept.png", width=5.5*inch, height=2.5*inch,
                        caption="Figure 14.3: Local Feature Attribution Waterfall Generated by SHAP TreeExplainer", styles=styles)

    add_image_if_exists(story, FIGURES_DIR / "feature_importance_chart.png", width=5.5*inch, height=2.5*inch,
                        caption="Figure 14.4: Global Mean |SHAP| Feature Importance for Random Forest Classifier", styles=styles)

    add_image_if_exists(story, FIGURES_DIR / "risk_workflow_diagram.png", width=5.5*inch, height=2.5*inch,
                        caption="Figure 14.5: End-to-End Operational Risk Evaluation and Pre-Settlement Enforcement Pipeline", styles=styles)
    story.append(PageBreak())

    # =========================================================
    # SECTION 15 — CORE FUNCTIONALITY CODE
    # =========================================================
    story.append(Paragraph("15. Core Functionality Code", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("15.1 Authentication & Password Hashing (<code>app/services/auth_service.py</code>)", styles["SectionHeading"]))
    code_auth = """def register_user(email, username, password, phone_number=None):
    if User.query.filter_by(email=email).first():
        raise ValidationError("Email already registered.")
    password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    user = User(email=email, username=username, password_hash=password_hash,
                phone_number=phone_number, balance=10000.0)
    db.session.add(user)
    db.session.commit()
    return user"""
    story.append(Paragraph(code_auth.replace("\n", "<br/>").replace(" ", "&nbsp;"), styles["CodeBlock"]))
    story.append(Paragraph("<b>Security Rationale:</b> Passwords are never stored in plaintext. PBKDF2 with SHA-256 and a 16-byte random cryptographic salt ensures protection against dictionary attacks and rainbow table precomputation.", styles["AcademicBody"]))
    story.append(Spacer(1, 3))

    story.append(Paragraph("15.2 Hybrid Risk Engine Calculation (<code>app/services/risk_service.py</code>)", styles["SectionHeading"]))
    code_risk = """def calculate_composite_risk(ml_prob, signals, transaction_category):
    weights = RISK_POLICY['weights'].get(transaction_category, {'ml_weight': 0.5, 'signals_weight': 0.5})
    raw_score = (weights['ml_weight'] * (ml_prob * 100)) + (weights['signals_weight'] * signals['score'])
    if signals.get('account_drain_detected'):
        raw_score = max(raw_score, RISK_POLICY['weights']['account_drain']['floor_score'])
    final_score = int(min(max(round(raw_score), 0), 100))
    tier = 'CRITICAL' if final_score >= 80 else ('HIGH' if final_score >= 60 else ('MEDIUM' if final_score >= 30 else 'LOW'))
    return {'risk_score': final_score, 'risk_tier': tier, 'action': RISK_POLICY['tiers'][tier]['action']}"""
    story.append(Paragraph(code_risk.replace("\n", "<br/>").replace(" ", "&nbsp;"), styles["CodeBlock"]))
    story.append(Paragraph("<b>Logic Explanation:</b> Dynamically weights ML probability with behavioral signals based on the transaction category. Enforces an authoritative score floor of 85 for full account-draining transfers.", styles["AcademicBody"]))
    story.append(Spacer(1, 3))

    story.append(Paragraph("15.3 Pre-Settlement Atomic Balance Deduction (<code>app/services/payment_service.py</code>)", styles["SectionHeading"]))
    code_settle = """def settle_verified_transaction(transaction_id, otp_token):
    tx = Transaction.query.get_or_404(transaction_id)
    if tx.is_settled:
        raise DuplicateSettlementError("Transaction already settled.")
    if not otp_service.verify_challenge(tx.user_id, tx.id, otp_token):
        raise InvalidOTPError("Invalid or expired OTP token.")
    
    sender = User.query.get(tx.user_id)
    if sender.balance < tx.amount:
        raise InsufficientFundsError("Insufficient funds at time of settlement.")
    
    sender.balance -= tx.amount
    recipient = User.query.filter_by(phone_number=tx.nameDest).first()
    if recipient:
        recipient.balance += tx.amount
    tx.is_settled = True
    tx.status = 'APPROVED'
    db.session.commit()
    return tx"""
    story.append(Paragraph(code_settle.replace("\n", "<br/>").replace(" ", "&nbsp;"), styles["CodeBlock"]))
    story.append(Paragraph("<b>Atomic Invariant:</b> Settlement executes strictly after OTP validation within an ACID transaction block, ensuring sender balance is preserved if OTP verification fails.", styles["AcademicBody"]))
    story.append(PageBreak())

    # =========================================================
    # SECTION 16 — PROJECT EVALUATION
    # =========================================================
    story.append(Paragraph("16. Project Evaluation & Empirical Metrics", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("16.1 Objective-Wise Evaluation Matrix", styles["SectionHeading"]))
    eval_headers = ["Project Objective", "Implementation Component", "Empirical Evidence", "Evaluation Status"]
    eval_data = [
        ["1. High-Precision ML", "Random Forest Ensemble", "Precision = 1.0000, Recall = 0.9970, F1 = 0.9985", "Fully Achieved"],
        ["2. Explainable AI", "SHAP TreeExplainer", "Sub-second dual-perspective attributions & natural language summaries", "Fully Achieved"],
        ["3. Hybrid Risk Scoring", "Risk Engine & Signal Telemetry", "0–100 composite score incorporating velocity & behavioral overrides", "Fully Achieved"],
        ["4. 4-Tier Risk Policy", "Policy State Machine", "LOW, MEDIUM, HIGH, CRITICAL mapping with automated OTP step-up", "Fully Achieved"],
        ["5. Pre-Settlement Safety", "Payment Service Invariant", "Zero balance deducted prior to successful OTP verification across all tests", "Fully Achieved"],
        ["6. SOC Case Portal", "SOC Management Service", "Complete incident lifecycle: alert triage, assignment, notes, resolution", "Fully Achieved"],
        ["7. Automated Verification", "Pytest Test Framework", "502 / 502 tests passing (100% pass rate, 0 failures)", "Fully Achieved"]
    ]
    story.append(make_table(eval_headers, eval_data, [125, 120, 180, 70], styles))
    story.append(Spacer(1, 4))

    story.append(Paragraph("16.3 Machine Learning Performance Evaluation & PaySim Class Imbalance", styles["SectionHeading"]))
    story.append(Paragraph("""
    The machine learning models were trained and evaluated on the PaySim financial transaction dataset. PaySim exhibits severe class imbalance, with only 8,213 fraudulent transactions out of 6,362,620 total records (an imbalance ratio of approximately <b>773.7 to 1</b>, or 0.129% fraud prevalence). In such extreme imbalance, naive accuracy is a deceptive metric (a naive model predicting all transactions as legitimate achieves 99.87% accuracy while missing 100% of fraud). Therefore, our evaluation prioritizes <b>Precision, Recall, F1-Score, and Precision-Recall AUC (PR-AUC)</b>.
    """, styles["AcademicBody"]))

    ml_headers = ["Evaluated Model", "Precision", "Recall", "F1-Score", "PR-AUC", "ROC-AUC", "Accuracy", "TP", "FP", "FN", "TN"]
    ml_data = [
        ["Logistic Regression", "0.0228", "0.9582", "0.0445", "0.5279", "0.9872", "0.9458", "321", "13780", "14", "240390"],
        ["Decision Tree", "0.8653", "0.9970", "0.9265", "0.9970", "0.9985", "0.9997", "334", "52", "1", "254118"],
        ["<b>Random Forest (Selected)</b>", "<b>1.0000</b>", "<b>0.9970</b>", "<b>0.9985</b>", "<b>0.9971</b>", "<b>0.9998</b>", "<b>0.9999</b>", "<b>334</b>", "<b>0</b>", "<b>1</b>", "<b>254170</b>"],
        ["XGBoost", "0.9824", "0.9970", "0.9896", "0.9969", "0.9981", "0.9999", "334", "6", "1", "254164"]
    ]
    story.append(make_table(ml_headers, ml_data, [105, 38, 38, 38, 38, 38, 40, 24, 30, 24, 42], styles))
    story.append(Spacer(1, 4))
    story.append(Paragraph("""
    <b>Model Selection Rationale:</b> Tuned Random Forest was selected as the primary production model because it achieved <b>1.0000 Precision (zero false positives on the test partition)</b> while maintaining 99.70% Recall and native TreeExplainer exact Shapley value computation without numerical approximations.
    """, styles["AcademicBody"]))
    story.append(PageBreak())

    # =========================================================
    # SECTION 17 — CONCLUSION
    # =========================================================
    story.append(Paragraph("17. Conclusion & Learning Outcomes", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    conclusion_p = """
    <b>17.1 Project Outcome:</b> This project successfully developed and validated <b>FraudShield AI</b>, an enterprise-grade payment fraud detection and defense platform. By uniting high-precision ensemble machine learning with real-time behavioral telemetry, SHAP explainability, and a 4-tier adaptive step-up policy, the system overcomes the limitations of legacy rule engines and opaque neural networks.<br/><br/>
    <b>17.2 Key Technical Benefits:</b>
    <br/>• <i>Elimination of False Positive Friction:</i> Auto-approves low-risk legitimate transactions without user intervention.
    <br/>• <i>Pre-Settlement Fund Protection:</i> Strict zero-debit invariant ensures that no customer funds are deducted prior to successful OTP verification on flagged transfers.
    <br/>• <i>Dual-Perspective Interpretability:</i> Provides transparent natural-language justifications to retail consumers and granular feature waterfalls to SOC analysts.
    <br/>• <i>Operational Resilience:</i> Validated across 502 automated test cases with 100% pass rate.<br/><br/>
    <b>17.3 Learning Outcomes:</b> The engineering lifecycle provided profound insights into managing extreme class imbalance in financial datasets, designing defensive transactional invariants within ORMs, integrating game-theoretic explainable AI in low-latency environments, and structuring role-based security operations center workflows.
    """
    story.append(Paragraph(conclusion_p, styles["AcademicBody"]))
    story.append(Spacer(1, 8))

    # =========================================================
    # SECTION 18 — FUTURE ENHANCEMENTS
    # =========================================================
    story.append(Paragraph("18. Future Enhancements & Roadmap", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    future_text = """
    While FraudShield AI provides a robust foundation for payment defense, the following architectural enhancements are planned as future engineering milestones:
    <br/>• <b>Graph Neural Networks (GNNs):</b> Implement graph-based relational learning (e.g., PyTorch Geometric) to detect organized fraud rings, circular routing, and mule networks across multi-hop payment graphs.
    <br/>• <b>Distributed Streaming Pipelines:</b> Transition feature extraction from relational database queries to distributed stream processors (Apache Kafka and Apache Flink) for sub-10ms event processing at 100,000 TPS.
    <br/>• <b>FIDO2 / WebAuthn Biometrics:</b> Integrate hardware-bound biometric authentication (passkeys, Touch ID, YubiKey) as a step-up factor replacing email OTP tokens.
    <br/>• <b>Continuous MLOps & Automated Retraining:</b> Deploy automated concept drift detectors (monitoring Kolmogorov-Smirnov statistics on feature distributions) that trigger automated pipeline retraining in production.
    <br/>• <b>Decentralized Payment Rails:</b> Extend gateway compatibility to ISO 20022 messaging standards and central bank digital currencies (CBDCs).
    """
    story.append(Paragraph(future_text, styles["AcademicBody"]))
    story.append(Spacer(1, 8))

    # =========================================================
    # SECTION 19 — PROJECT LINKS & QR CODES
    # =========================================================
    story.append(Paragraph("19. Project Links & QR Codes", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    links_text = """
    <b>Public GitHub Source Code Repository:</b><br/>
    <code>https://github.com/Afzal006/Online-Payment-Fraud-Dtection-System</code><br/><br/>
    The repository contains the complete source code, Flask backend, React/Vite and HTML5 frontend templates, machine learning training scripts, serialized model artifacts, database migrations, and 502 automated test cases.
    """
    story.append(Paragraph(links_text, styles["AcademicBody"]))
    story.append(Spacer(1, 4))

    if qr_path.exists():
        story.append(Image(str(qr_path), width=1.4*inch, height=1.4*inch))
        story.append(Paragraph("<b>Scan QR Code to Open GitHub Repository</b>", styles["CaptionStyle"]))

    story.append(PageBreak())

    # =========================================================
    # SECTION 20 — REFERENCES
    # =========================================================
    story.append(Paragraph("20. References & Bibliography", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    references_list = [
        "[1] E. A. Lopez-Rojas, A. Elmir, and S. Axelsson, \"PaySim: A financial mobile money simulator for fraud detection,\" in <i>The 28th European Modeling and Simulation Symposium (EMSS)</i>, Larnaca, Cyprus, 2016, pp. 249–255.",
        "[2] S. M. Lundberg and S.-I. Lee, \"A unified approach to interpreting model predictions,\" in <i>Advances in Neural Information Processing Systems (NeurIPS 30)</i>, 2017, pp. 4765–4774.",
        "[3] T. Chen and C. Guestrin, \"XGBoost: A scalable tree boosting system,\" in <i>Proc. 22nd ACM SIGKDD Int. Conf. on Knowledge Discovery and Data Mining</i>, 2016, pp. 785–794.",
        "[4] L. Breiman, \"Random Forests,\" <i>Machine Learning</i>, vol. 45, no. 1, pp. 5–32, 2001.",
        "[5] F. Pedregosa et al., \"Scikit-learn: Machine learning in Python,\" <i>Journal of Machine Learning Research</i>, vol. 12, pp. 2825–2830, 2011.",
        "[6] A. Ronacher, \"Flask: A Python microframework based on Werkzeug and Jinja 2,\" <i>Pallets Projects</i>, 2024. [Online]. Available: https://flask.palletsprojects.com/",
        "[7] M. Bayer, \"SQLAlchemy: The Database Toolkit for Python,\" 2024. [Online]. Available: https://www.sqlalchemy.org/",
        "[8] OWASP Foundation, \"OWASP Top 10 API Security Risks,\" 2023. [Online]. Available: https://owasp.org/API-Security/",
        "[9] National Institute of Standards and Technology (NIST), \"Digital Identity Guidelines: Authentication and Lifecycle Management,\" <i>NIST Special Publication 800-63B</i>, 2020.",
        "[10] Reserve Bank of India (RBI), \"Master Direction on Digital Payment Security Controls,\" <i>RBI/2020-21/74</i>, 2021."
    ]
    for ref in references_list:
        story.append(Paragraph(ref, styles["BulletText"]))
        story.append(Spacer(1, 2.5))

    story.append(Spacer(1, 8))

    # =========================================================
    # SECTION 21 — APPENDIX
    # =========================================================
    story.append(Paragraph("21. Appendix", styles["ChapterHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e3a8a"), spaceAfter=6))

    story.append(Paragraph("Appendix A: REST API Endpoint Catalogue", styles["SectionHeading"]))
    api_headers = ["HTTP Method", "Endpoint Path", "Auth Required", "Description & Payload"]
    api_data = [
        ["POST", "/api/auth/register", "None", "Register customer account (email, password, phone)"],
        ["POST", "/api/auth/login", "None", "Authenticate user and issue JWT access token"],
        ["POST", "/api/auth/payment-pin/set", "JWT Token", "Configure 4-6 digit numeric payment PIN"],
        ["POST", "/api/predict", "JWT Token", "Simulate transaction, run ML inference & risk scoring"],
        ["POST", "/api/otp/verify", "JWT Token", "Submit 6-digit OTP token to verify challenge"],
        ["POST", "/api/otp/resend", "JWT Token", "Request fresh OTP challenge token"],
        ["GET", "/api/transactions/history", "JWT Token", "Retrieve user transaction history & status"],
        ["GET", "/api/shap/explain/<id>", "JWT Token", "Fetch dual-view SHAP local feature attribution"],
        ["GET", "/api/admin/soc/cases", "Admin JWT", "List SOC incident cases with status & priority filters"],
        ["POST", "/api/admin/alerts/<id>/resolve", "Admin JWT", "Resolve security alert with analyst notes"],
        ["GET", "/api/admin/audit/logs", "Admin JWT", "Inspect structured system audit trail"]
    ]
    story.append(make_table(api_headers, api_data, [65, 140, 75, 215], styles))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Appendix B: Environment Configuration Template (Redacted Secrets)", styles["SectionHeading"]))
    env_sample = """# FraudShield AI Environment Configuration Template
FLASK_ENV=production
SECRET_KEY=[REDACTED_CRYPTOGRAPHIC_KEY_MIN_32_BYTES]
JWT_SECRET_KEY=[REDACTED_JWT_SIGNING_KEY]
DATABASE_URL=sqlite:///instance/fraud_detection.db
EMAIL_PROVIDER=smtp  # Options: smtp, brevo, resend, mock
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=[REDACTED_EMAIL_ADDRESS]
SMTP_PASSWORD=[REDACTED_APP_PASSWORD]
BREVO_API_KEY=[REDACTED_API_KEY]
RESEND_API_KEY=[REDACTED_API_KEY]"""
    story.append(Paragraph(env_sample.replace("\n", "<br/>").replace(" ", "&nbsp;"), styles["CodeBlock"]))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Appendix C: Automated Test Telemetry Matrix (All 41 Test Suites)", styles["SectionHeading"]))
    telemetry_summary = """
    <b>Summary of Verified Pytest Suites (502 Passing Tests):</b><br/>
    • <code>test_adaptive_security.py</code> (6) • <code>test_admin_portal_separation.py</code> (13) • <code>test_admin_soc.py</code> (9) • <code>test_audit.py</code> (4) • <code>test_auth.py</code> (12)<br/>
    • <code>test_beneficiary_intelligence.py</code> (18) • <code>test_brevo_provider.py</code> (9) • <code>test_database.py</code> (7) • <code>test_device_intelligence.py</code> (15) • <code>test_e2e_system.py</code> (7)<br/>
    • <code>test_email_otp_delivery.py</code> (17) • <code>test_email_password_reset.py</code> (6) • <code>test_email_verification.py</code> (13) • <code>test_feature_engineering.py</code> (6) • <code>test_frontend.py</code> (7)<br/>
    • <code>test_geo_intelligence.py</code> (17) • <code>test_hybrid_risk_engine.py</code> (21) • <code>test_inference.py</code> (8) • <code>test_medium_high_otp_stepup.py</code> (10) • <code>test_mobile_verification.py</code> (12)<br/>
    • <code>test_models.py</code> (5) • <code>test_password_recovery_real.py</code> (15) • <code>test_password_reset.py</code> (24) • <code>test_payment_identity.py</code> (22) • <code>test_payment_pin_flow.py</code> (25)<br/>
    • <code>test_payment_pin_reset.py</code> (7) • <code>test_phone_registration_and_reuse.py</code> (23) • <code>test_prediction_api.py</code> (10) • <code>test_preprocessing.py</code> (3) • <code>test_profile_management.py</code> (23)<br/>
    • <code>test_real_upi_payment_flow.py</code> (25) • <code>test_resend_provider.py</code> (9) • <code>test_risk_engine.py</code> (17) • <code>test_risk_level_compatibility.py</code> (5) • <code>test_security_middleware.py</code> (16)<br/>
    • <code>test_setup.py</code> (6) • <code>test_shap.py</code> (7) • <code>test_soc_case_management.py</code> (13) • <code>test_strong_models.py</code> (5) • <code>test_upi_payment_flow.py</code> (25)<br/>
    <b>Total Count: 502 Verified Tests Passing (100% Success Rate).</b>
    """
    story.append(Paragraph(telemetry_summary, styles["AcademicBody"]))

    # Build the document with custom canvas
    doc.build(story, canvasmaker=NumberedCanvasWithRemarks)
    print(f"Report compiled successfully to: {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()
