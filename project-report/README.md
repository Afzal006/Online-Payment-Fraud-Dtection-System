# Online Payment Fraud Detection System Using Machine Learning
## University Academic Project Report — LaTeX / Overleaf Project Package

This directory contains the complete, professional university project report for **FraudShield AI (Online Payment Fraud Detection System Using Machine Learning)**.

---

## 1. Directory Structure

```
project-report/
├── main.tex                         # Master LaTeX Root Document
├── references.bib                   # BibTeX Academic Citations File
├── generate_report_pdf.py           # Standalone Python ReportLab PDF Builder
├── Online_Payment_Fraud_Detection_System_Report.pdf  # Compiled Final PDF Report
├── README.md                        # Compilation & Usage Guide
│
├── chapters/                        # Modular Chapter LaTeX Documents
│   ├── 00_preliminaries.tex         # Cover, Certificate, Declaration, Acknowledgement, TOC, LOF, LOT, Abbreviations
│   ├── 01_abstract.tex              # Section 1: Abstract
│   ├── 02_introduction.tex          # Section 2: Introduction
│   ├── 03_problem_identification.tex# Section 3: Problem Identification
│   ├── 04_empathize_define.tex      # Section 4: Empathize and Define (Design Thinking)
│   ├── 05_ideation.tex              # Section 5: Ideation & Architectural Selection
│   ├── 06_requirements.tex          # Section 6: Requirements Analysis & Specification
│   ├── 07_technology_stack.tex      # Section 7: Technology Stack
│   ├── 08_system_design.tex         # Section 8: System Design & DFDs (0, 1, 2)
│   ├── 09_database_design.tex       # Section 9: Database Schema & Relational Design
│   ├── 10_modules.tex               # Section 10: Module Descriptions (All 9 Subsystems)
│   ├── 11_uml_modeling.tex          # Section 11: UML Modeling (Use Case, Sequence, Class, Activity)
│   ├── 12_implementation.tex        # Section 12: Implementation & Working Principle
│   ├── 13_testing.tex               # Section 13: Testing Strategy & 501 Verified Test Cases
│   ├── 14_results.tex               # Section 14: Results, Confusion Matrices & Visual Evidence
│   ├── 15_code.tex                  # Section 15: Core Functionality Code Snippets
│   ├── 16_evaluation.tex            # Section 16: Project Evaluation & Imbalance Metrics
│   ├── 17_conclusion.tex            # Section 17: Conclusion & Academic Outcomes
│   ├── 18_future_enhancements.tex   # Section 18: Future Enhancements (GNNs, Kafka, WebAuthn)
│   ├── 19_links.tex                 # Section 19: Project Links & QR Codes
│   ├── 20_references.tex            # Section 20: Academic References
│   └── 21_appendix.tex              # Section 21: Appendix (API Catalog & Sanitized Config)
│
└── figures/                         # High-Resolution Figures, Diagrams & Confusion Matrices
    ├── architecture_diagram.png     # 5-Tier System Architecture
    ├── risk_workflow_diagram.png    # 4-Tier Risk Engine & Settlement Protection Flow
    ├── dfd_level0.png               # DFD Level 0 Context Diagram
    ├── dfd_level1.png               # DFD Level 1 Subsystem Diagram
    ├── erd_diagram.png              # Entity Relationship Diagram
    ├── uml_use_case.png             # UML Use Case Diagram
    ├── uml_sequence.png             # UML Sequence Diagram
    ├── model_comparison_chart.png   # Performance Metrics Comparison Bar Chart
    ├── feature_importance_chart.png # Top 10 SHAP Feature Attributions
    ├── qr_github.png                # GitHub Repository QR Code
    ├── random_forest_tuned_confusion_matrix.png
    ├── xgboost_tuned_confusion_matrix.png
    ├── decision_tree_confusion_matrix.png
    └── logistic_regression_confusion_matrix.png
```

---

## 2. Compilation on Overleaf

1. Compress the `project-report/` directory into a `.zip` archive.
2. Log into [Overleaf](https://www.overleaf.com/) and click **New Project** $\to$ **Upload Project**.
3. Select `main.tex` as the root document.
4. Set compiler to **pdfLaTeX** (or **XeLaTeX**) and compile.

---

## 3. Local LaTeX Compilation (TeXLive / MikTeX / MacTeX)

From terminal/command prompt:

```bash
cd project-report
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

---

## 4. Standalone PDF Generation via Python ReportLab

If LaTeX is not installed locally, generate the complete PDF directly using Python:

```bash
py project-report/generate_report_pdf.py
```

This compiles `Online_Payment_Fraud_Detection_System_Report.pdf` with the mandatory dedicated faculty remarks box on every page.
