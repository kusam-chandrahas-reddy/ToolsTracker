"""
Comprehensive Automated Test Suite for Veracode Sandbox Vulnerability & Metrics Tracker.
Tests Multi-Sandbox Support, Severity & Mitigation Matrix, Excel/PDF/XML Reports, and Flaw Columns.
"""
import sys
import io
from pathlib import Path
import xml.etree.ElementTree as ET
import openpyxl

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from backend.main import app
from backend.veracode_client import VeracodeClient
from backend.metrics_engine import metrics_engine
from backend.veracode_mock import MOCK_FINDINGS, MOCK_APPLICATIONS

client = TestClient(app)

def test_serve_index():
    """Verify that root URL serves HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "Veracode Sandbox Tracker" in response.text

def test_hmac_signature_generation():
    """Verify Veracode HMAC-SHA256 signature format."""
    api_id = "test_api_id"
    api_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    host = "api.veracode.com"
    method = "GET"
    url_path = "/appsec/v1/applications?size=10"

    header = VeracodeClient.calculate_hmac_header(
        api_id=api_id,
        api_secret=api_secret,
        host=host,
        method=method,
        url_path=url_path
    )

    assert header.startswith("VERACODE-HMAC-SHA-256 ")
    assert f"id={api_id}" in header
    assert "ts=" in header
    assert "nonce=" in header
    assert "sig=" in header
    print("[OK] HMAC signature generation verified.")

def test_severity_mitigation_metrics_engine():
    """Verify metrics contain severity, mitigation status data, and scan type."""
    findings = MOCK_FINDINGS["sb000001-aaaa-bbbb-cccc-111111111111"]
    metrics = metrics_engine.calculate_metrics(findings)

    # 1. KPIs
    kpis = metrics["kpis"]
    assert kpis["total_flaws"] == len(findings)
    assert "unmitigated_count" in kpis
    assert "mit_proposed_count" in kpis
    assert "mit_approved_count" in kpis

    # 2. Severity & Mitigation Status by Scan Type Matrix Table
    matrix = metrics["severity_mitigation_matrix"]
    assert len(matrix) > 0
    first_row = matrix[0]
    assert "scan_type" in first_row
    assert "severity_label" in first_row
    assert "unmitigated" in first_row
    assert "mitigation_proposed" in first_row
    assert "mitigation_approved" in first_row
    assert "fixed_resolved" in first_row

    # Verify Grand Total row exists
    grand_total_row = next((r for r in matrix if r.get("is_grand_total")), None)
    assert grand_total_row is not None
    assert grand_total_row["total"] == len(findings)

    # 3. Mitigation Summary Table
    mit_table = metrics["mitigation_table"]
    assert len(mit_table) > 0
    assert any(m["mitigation_status"] == "Unmitigated" for m in mit_table)

    print("[OK] Severity & Mitigation metrics engine verified.")

def test_multi_sandbox_endpoints():
    """Test multi-sandbox selection API endpoints."""
    app_guid = MOCK_APPLICATIONS[0]["guid"]
    sb1 = "sb000001-aaaa-bbbb-cccc-111111111111"
    sb2 = "sb000001-aaaa-bbbb-cccc-222222222222"
    multi_param = f"{sb1},{sb2}"

    # 1. Multi-sandbox Status Endpoint
    resp_st = client.get(f"/api/applications/{app_guid}/sandboxes/status?sandbox_guids={multi_param}")
    assert resp_st.status_code == 200
    st_data = resp_st.json()
    assert st_data["count"] == 2
    assert len(st_data["statuses"]) == 2

    # 2. Multi-sandbox Findings Endpoint
    resp_f = client.get(f"/api/applications/{app_guid}/sandboxes/findings?sandbox_guids={multi_param}")
    assert resp_f.status_code == 200
    f_data = resp_f.json()
    assert f_data["sandboxes_count"] == 2
    assert len(f_data["findings"]) > 0

    # Verify every finding has description, mitigation_status, and first_found_date
    for f in f_data["findings"]:
        assert "description" in f and f["description"]
        assert "mitigation_status" in f and f["mitigation_status"]
        assert "first_found_date" in f and f["first_found_date"]
        assert "sandbox_name" in f and f["sandbox_name"]

    # 3. Multi-sandbox Metrics Endpoint
    resp_m = client.get(f"/api/applications/{app_guid}/sandboxes/metrics?sandbox_guids={multi_param}")
    assert resp_m.status_code == 200
    m_data = resp_m.json()
    assert m_data["sandboxes_count"] == 2
    assert "severity_mitigation_matrix" in m_data["metrics"]
    assert "sandboxes_table" in m_data["metrics"]
    assert len(m_data["metrics"]["sandboxes_table"]) == 2

    print("[OK] Multi-sandbox endpoints verified.")

def test_excel_report_download():
    """Test downloading all reported instances in Excel (.xlsx) format including Module."""
    app_guid = MOCK_APPLICATIONS[0]["guid"]
    sb1 = "sb000001-aaaa-bbbb-cccc-111111111111"
    sb2 = "sb000001-aaaa-bbbb-cccc-222222222222"

    resp = client.get(f"/api/applications/{app_guid}/reports/excel?sandbox_guids={sb1},{sb2}")
    assert resp.status_code == 200
    assert "spreadsheetml.sheet" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]

    # Verify with openpyxl that sheets and columns are correct
    wb = openpyxl.load_workbook(io.BytesIO(resp.content))
    sheet_names = wb.sheetnames
    assert "Executive Summary" in sheet_names
    assert "Severity & Mitigation Matrix" in sheet_names
    assert "All Reported Instances" in sheet_names
    assert "SAST Flaws Only" in sheet_names
    assert "SCA Vulnerabilities Only" in sheet_names

    ws_all = wb["All Reported Instances"]
    headers = [cell.value for cell in ws_all[1]]
    assert "Module" in headers
    assert "Description" in headers
    assert "Mitigation Status" in headers
    assert "First Found Date" in headers
    assert "Sandbox Name" in headers
    assert ws_all.max_row > 1  # Contains data rows

    # Verify Module is in SAST and SCA sub-sheets as well
    ws_sast = wb["SAST Flaws Only"]
    sast_headers = [cell.value for cell in ws_sast[1]]
    assert "Module" in sast_headers

    ws_sca = wb["SCA Vulnerabilities Only"]
    sca_headers = [cell.value for cell in ws_sca[1]]
    assert "Module" in sca_headers

    # Verify Module cell values in rows
    mod_col_idx = headers.index("Module") + 1
    row_module_vals = [ws_all.cell(row=r, column=mod_col_idx).value for r in range(2, ws_all.max_row + 1)]
    assert any("payment" in str(v).lower() for v in row_module_vals)

    print("[OK] Excel report (.xlsx) generation verified with Module column.")

def test_pdf_report_download():
    """Test downloading PDF report for selected sandboxes including Module."""
    app_guid = MOCK_APPLICATIONS[0]["guid"]
    sb1 = "sb000001-aaaa-bbbb-cccc-111111111111"
    sb2 = "sb000001-aaaa-bbbb-cccc-222222222222"

    resp = client.get(f"/api/applications/{app_guid}/reports/pdf?sandbox_guids={sb1},{sb2}")
    assert resp.status_code == 200
    assert "application/pdf" in resp.headers["content-type"]
    assert resp.content.startswith(b"%PDF")
    assert len(resp.content) > 1000

    print("[OK] PDF report (.pdf) generation verified.")

def test_xml_report_download():
    """Test downloading structured XML report for selected sandboxes including module."""
    app_guid = MOCK_APPLICATIONS[0]["guid"]
    sb1 = "sb000001-aaaa-bbbb-cccc-111111111111"
    sb2 = "sb000001-aaaa-bbbb-cccc-222222222222"

    resp = client.get(f"/api/applications/{app_guid}/reports/xml?sandbox_guids={sb1},{sb2}")
    assert resp.status_code == 200
    assert "xml" in resp.headers["content-type"]

    # Parse XML and verify structure
    root = ET.fromstring(resp.content)
    assert root.tag == "veracode_sandbox_report"
    assert root.find(".//application") is not None
    assert root.find(".//sandboxes") is not None
    assert root.find(".//metrics") is not None
    assert root.find(".//findings") is not None

    findings = root.findall(".//finding")
    assert len(findings) > 0
    first_f = findings[0]
    assert "module" in first_f.attrib and first_f.attrib["module"]
    assert "mitigation_status" in first_f.attrib
    assert "first_found_date" in first_f.attrib
    assert first_f.find("description") is not None
    assert first_f.find("module") is not None

    print("[OK] XML report (.xml) generation verified with module.")

def test_csv_export():
    """Test CSV export containing Module, Description, Mitigation Status, and First Found Date."""
    app_guid = MOCK_APPLICATIONS[0]["guid"]
    sb1 = "sb000001-aaaa-bbbb-cccc-111111111111"

    resp = client.get(f"/api/applications/{app_guid}/sandboxes/{sb1}/export?format=csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    text = resp.text
    assert "Module" in text
    assert "Description" in text
    assert "Mitigation Status" in text
    assert "First Found Date" in text
    assert "payment-core.jar" in text

    print("[OK] Single sandbox CSV export verified with Module.")

def test_multi_sandbox_csv_report_download():
    """Test multi-app/multi-sandbox CSV report download containing Module."""
    app_guid = MOCK_APPLICATIONS[0]["guid"]
    sb1 = "sb000001-aaaa-bbbb-cccc-111111111111"
    sb2 = "sb000001-aaaa-bbbb-cccc-222222222222"

    resp = client.get(f"/api/reports/csv?app_guids={app_guid}&sandbox_guids={sb1},{sb2}")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    text = resp.text
    assert "Module" in text
    assert "Description" in text
    assert "Mitigation Status" in text
    assert "First Found Date" in text
    assert "payment-core.jar" in text or "payment-api.war" in text

    print("[OK] Multi-sandbox CSV report download verified with Module.")

if __name__ == "__main__":
    test_serve_index()
    test_hmac_signature_generation()
    test_severity_mitigation_metrics_engine()
    test_multi_sandbox_endpoints()
    test_excel_report_download()
    test_pdf_report_download()
    test_xml_report_download()
    test_csv_export()
    test_multi_sandbox_csv_report_download()
    print("\n[SUCCESS] All multi-sandbox, metrics, report downloads, and column verification tests passed!")
