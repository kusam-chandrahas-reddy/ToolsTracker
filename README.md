# Veracode Sandbox Vulnerability & Metrics Tracker

An enterprise-grade, security-focused full-stack web application designed to integrate directly with the **Veracode Application Security Platform**. It inspects available applications and developer sandboxes, monitors the latest sandbox scan status, and provides rich tabular summaries and multidimensional metrics of reported **SAST (Static Analysis)** and **SCA (Software Composition Analysis)** vulnerabilities.

> **Key Architectural Guarantee:** This tool enforces **Sandbox Context Isolation** (`context={sandbox_guid}`). As specified, **policy scan details are strictly excluded**, keeping focus entirely on developer branch/feature sandboxes.

---

## What's New in This Release

1. **Multi-Sandbox Selection & Aggregation:**
   - Select one, multiple, or all development sandboxes simultaneously for an application.
   - Aggregate latest scan statuses, metrics, and vulnerabilities across all selected branch sandboxes.
   - Interactive checkbox dropdown with quick "Select All", "Clear", and removable tag chips.

2. **Metrics with Severity, Mitigation Status Data & Scan Type:**
   - **Primary Tabular Matrix:** Cross-tabulates **Scan Type** (`SAST`, `SCA`) $\times$ **Severity** (`Very High 5` to `Informational 0`) $\times$ **Mitigation Status** (`Unmitigated`, `Mitigation Proposed`, `Mitigation Approved`, `Mitigation Rejected`, `Fixed / Resolved`).
   - Includes subtotal rows for each scan type and a **Grand Total** row.
   - **Mitigation Status Overview Table:** Summarizes governance states across SAST and SCA engines with percentages.
   - **Per-Sandbox Comparison Table:** Compares flaw counts, scan statuses, and unmitigated findings across sandboxes.

3. **Multi-Format Report Downloads for All Selected Sandboxes:**
   - **Excel (.xlsx) Report:** Downloads all latest scans reported instances in a formatted multi-sheet workbook (`Executive Summary`, `Severity & Mitigation Matrix`, `All Reported Instances`, `SAST Flaws Only`, `SCA Vulnerabilities Only`).
   - **PDF Report:** High-resolution landscape PDF report featuring executive KPI cards, scan statuses, cross-tabulation matrix, and complete flaw tables with page numbering.
   - **XML Report:** Machine-readable XML report compliant with Veracode data structures.

4. **Expanded Vulnerabilities Register & Export Columns:**
   - Both the interactive web data table and all export files (Excel, PDF, XML, CSV) now explicitly include:
     - **`Description`** (full technical flaw narrative and attack vector)
     - **`Mitigation Status`** (`Unmitigated`, `Mitigation Proposed`, `Mitigation Approved`, `Mitigation Rejected`, `Fixed / Resolved`)
     - **`Vulnerability First Found Date`** (exact discovery timestamp)
     - Target location (file path and line number for SAST; component and version for SCA)
     - CWE ID, CWE Name, CVE ID, and CVSS score

---

## Directory Structure

```
ToolTracker/
├── backend/
│   ├── __init__.py
│   ├── config.py              # Credential resolution (.env, ~/.veracode, or in-memory)
│   ├── veracode_client.py     # HMAC-SHA256 client for Veracode REST & XML APIs
│   ├── veracode_mock.py       # Multi-sandbox mock data with mitigation states
│   ├── metrics_engine.py      # Severity, mitigation status & scan type metrics
│   ├── report_generator.py    # Excel (.xlsx), PDF, and XML report generators
│   ├── routes.py              # FastAPI REST & download endpoints
│   └── main.py                # FastAPI app initialization, middleware & static mount
├── static/
│   ├── index.html             # Multi-sandbox UI with metrics & download buttons
│   ├── css/style.css          # Styling, mitigation pills & responsive tables
│   └── js/app.js              # Multi-select state management & table renderers
├── tests/
│   └── test_tracker.py        # Automated test suite (HMAC, multi-sandbox, reports)
├── .env.example               # Environment variables template
├── requirements.txt           # Dependencies (fastapi, openpyxl, reportlab, pandas)
├── run.py                     # Primary application launcher
└── README.md                  # Documentation
```

---

## Quick Start Guide

### 1. Installation
Install the dependencies:
```bash
py -m pip install -r requirements.txt
```

### 2. Run Automated Tests
Verify HMAC signing, multi-sandbox aggregation, and Excel/PDF/XML report generation:
```bash
py tests/test_tracker.py
```

### 3. Launch the Application
Start the server using Python:
```bash
py run.py
```
Open your browser at: **`http://127.0.0.1:8000`**

---

## Report Download Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/applications/{app_guid}/reports/excel?sandbox_guids=sb1,sb2` | Multi-tab Excel workbook (`.xlsx`) of all reported instances |
| `GET` | `/api/applications/{app_guid}/reports/pdf?sandbox_guids=sb1,sb2` | Formatted landscape executive & technical PDF report |
| `GET` | `/api/applications/{app_guid}/reports/xml?sandbox_guids=sb1,sb2` | Structured XML document of all reported instances and metrics |
| `GET` | `/api/applications/{app_guid}/sandboxes/findings?sandbox_guids=sb1,sb2` | JSON list of all reported instances across selected sandboxes |
| `GET` | `/api/applications/{app_guid}/sandboxes/metrics?sandbox_guids=sb1,sb2` | Severity, mitigation status & scan type metrics |
