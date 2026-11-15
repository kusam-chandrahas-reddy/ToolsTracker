import re
import io
import csv
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field

from backend.config import settings, REGIONS
from backend.veracode_client import veracode_client
from backend.veracode_mock import (
    get_mock_applications,
    get_mock_sandboxes,
    get_mock_sandbox_status,
    get_mock_findings,
    get_multi_mock_findings
)
from backend.metrics_engine import metrics_engine
from backend.report_generator import report_generator

router = APIRouter(prefix="/api")

GUID_REGEX = re.compile(r"^[0-9a-zA-Z\-_]{4,64}$")

def validate_guid(guid: str, name: str = "GUID"):
    if not guid or not GUID_REGEX.match(guid):
        raise HTTPException(status_code=400, detail=f"Invalid {name} format.")

def parse_guids(guid_str: Optional[str], name: str = "GUID") -> List[str]:
    """Parses and validates comma-separated GUIDs."""
    if not guid_str:
        return []
    guids = [g.strip() for g in guid_str.split(",") if g.strip()]
    for g in guids:
        validate_guid(g, name)
    return guids

def get_apps_metadata(target_app_guids: List[str]) -> List[Dict[str, Any]]:
    """Helper to retrieve application profiles for specified application GUIDs."""
    api_id, _ = settings.get_credentials()
    if settings.mock_mode or not api_id:
        all_apps = get_mock_applications()
    else:
        try:
            all_apps = veracode_client.get_applications()
        except Exception:
            all_apps = get_mock_applications()

    if not target_app_guids:
        return all_apps

    matched = [a for a in all_apps if a.get("guid") in target_app_guids]
    return matched if matched else all_apps

def fetch_sandboxes_for_apps(app_guids: List[str], refresh: bool = False) -> List[Dict[str, Any]]:
    """Retrieves all sandboxes across multiple applications."""
    api_id, _ = settings.get_credentials()
    is_mock = settings.mock_mode or not api_id
    all_apps = get_apps_metadata(app_guids)
    app_map = {a.get("guid"): a.get("name") for a in all_apps}

    combined_sandboxes = []
    for a_guid in app_guids:
        app_name = app_map.get(a_guid, "Application")
        if is_mock:
            raw_sbs = get_mock_sandboxes(a_guid)
        else:
            try:
                raw_sbs = veracode_client.get_sandboxes(a_guid, force_refresh=refresh)
            except Exception:
                raw_sbs = get_mock_sandboxes(a_guid)

        for s in raw_sbs:
            s["application_name"] = app_name
            s["application_guid"] = a_guid
            combined_sandboxes.append(s)

    return combined_sandboxes

def get_multi_sandboxes_status_list(app_guids: List[str], target_sb_guids: List[str]) -> List[Dict[str, Any]]:
    """Helper to retrieve metadata and scan statuses for sandboxes across applications."""
    all_sbs = fetch_sandboxes_for_apps(app_guids)
    sb_lookup = {s.get("guid"): s for s in all_sbs}

    api_id, _ = settings.get_credentials()
    is_mock = settings.mock_mode or not api_id

    statuses = []
    for sb_guid in target_sb_guids:
        meta = sb_lookup.get(sb_guid, {})
        app_g = meta.get("application_guid") or (app_guids[0] if app_guids else "default")
        app_n = meta.get("application_name") or "Application"
        sb_n = meta.get("name") or "Sandbox"

        if is_mock:
            st = get_mock_sandbox_status(sb_guid, app_g)
        else:
            try:
                st = veracode_client.get_sandbox_status(
                    app_guid=app_g,
                    sandbox_guid=sb_guid,
                    app_id=meta.get("application_id"),
                    sandbox_id=meta.get("id")
                )
            except Exception:
                st = get_mock_sandbox_status(sb_guid, app_g)

        st["application_name"] = app_n
        st["application_guid"] = app_g
        st["sandbox_name"] = sb_n
        statuses.append(st)

    return statuses

def fetch_findings_for_multi_apps(app_guids: List[str], target_sb_guids: List[str], scan_type: str = "ALL") -> List[Dict[str, Any]]:
    """Fetches and aggregates findings for specified sandboxes across applications."""
    all_sbs = fetch_sandboxes_for_apps(app_guids)
    sb_lookup = {s.get("guid"): s for s in all_sbs}

    api_id, _ = settings.get_credentials()
    is_mock = settings.mock_mode or not api_id

    all_findings = []
    for sb_guid in target_sb_guids:
        meta = sb_lookup.get(sb_guid, {})
        app_g = meta.get("application_guid") or (app_guids[0] if app_guids else "")
        app_n = meta.get("application_name") or "Application"
        sb_n = meta.get("name") or "Sandbox"

        if is_mock:
            raw_flaws = get_mock_findings(sb_guid, scan_type=scan_type)
        else:
            try:
                raw_flaws = veracode_client.get_sandbox_findings(
                    app_guid=app_g,
                    sandbox_guid=sb_guid,
                    sandbox_name=sb_n,
                    scan_type=scan_type
                )
            except Exception:
                raw_flaws = get_mock_findings(sb_guid, scan_type=scan_type)

        for f in raw_flaws:
            f["application_name"] = app_n
            f["application_guid"] = app_g
            f["sandbox_name"] = sb_n
            f["sandbox_guid"] = sb_guid
            all_findings.append(f)

    return all_findings

# ----------------- CONFIG & STATUS -----------------

class CredentialsRequest(BaseModel):
    api_id: Optional[str] = Field(None, description="Veracode API ID")
    api_secret: Optional[str] = Field(None, description="Veracode API Secret Key")
    region: Optional[str] = Field("us", description="Veracode Region: us, eu, or us-gov")
    use_mock: Optional[bool] = Field(False, description="Explicitly use demo simulation mode")

@router.get("/status")
def get_system_status():
    return settings.get_status()

@router.post("/config")
def update_credentials(payload: CredentialsRequest):
    if payload.use_mock:
        settings.mock_mode = True
        veracode_client.clear_cache()
        return {"success": True, "message": "Demo / Simulation mode enabled.", "status": settings.get_status()}

    if payload.api_id and payload.api_secret:
        settings.mock_mode = False
        settings.set_session_credentials(payload.api_id, payload.api_secret, payload.region)
        veracode_client.clear_cache()
        test_res = veracode_client.test_connection()
        return {
            "success": test_res["success"],
            "message": test_res["message"],
            "status": settings.get_status()
        }
    else:
        settings.clear_session_credentials()
        settings.mock_mode = False
        veracode_client.clear_cache()
        return {"success": True, "message": "Reset to default credentials.", "status": settings.get_status()}

@router.post("/config/test")
def test_connection():
    if settings.mock_mode or not settings.get_credentials()[0]:
        return {
            "success": True,
            "message": "Demo mode active. Simulated connection verified successfully.",
            "is_mock": True
        }
    return veracode_client.test_connection()

# ----------------- APPLICATIONS -----------------

@router.get("/applications")
def list_applications(refresh: bool = Query(False)):
    """Lists available Veracode applications."""
    api_id, _ = settings.get_credentials()
    if settings.mock_mode or not api_id:
        return {"source": "simulation", "applications": get_mock_applications()}

    try:
        apps = veracode_client.get_applications(force_refresh=refresh)
        return {"source": "live", "applications": apps}
    except Exception as e:
        return {
            "source": "simulation",
            "warning": f"Veracode API call failed ({str(e)}). Displaying simulation data.",
            "applications": get_mock_applications()
        }

# ----------------- MULTI-APPLICATION SANDBOXES -----------------

@router.get("/sandboxes")
def list_sandboxes_multi_app(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    refresh: bool = Query(False)
):
    """Lists sandboxes across multiple selected applications."""
    target_app_guids = parse_guids(app_guids, "Application GUID")
    if not target_app_guids:
        raise HTTPException(status_code=400, detail="No application GUIDs provided.")

    sandboxes = fetch_sandboxes_for_apps(target_app_guids, refresh=refresh)
    return {
        "applications_count": len(target_app_guids),
        "sandboxes_count": len(sandboxes),
        "sandboxes": sandboxes
    }

@router.get("/applications/{app_guid}/sandboxes")
def list_sandboxes_single_app(app_guid: str, refresh: bool = Query(False)):
    """Backwards compatible endpoint for single application sandboxes."""
    validate_guid(app_guid, "Application GUID")
    sandboxes = fetch_sandboxes_for_apps([app_guid], refresh=refresh)
    return {"source": "live" if (settings.get_credentials()[0] and not settings.mock_mode) else "simulation", "sandboxes": sandboxes}

# ----------------- MULTI-APP & MULTI-SANDBOX TELEMETRY -----------------

@router.get("/sandboxes/status")
def get_sandboxes_status(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    sandbox_guids: str = Query(..., description="Comma-separated sandbox GUIDs")
):
    """Retrieves scan statuses for sandboxes across applications."""
    a_guids = parse_guids(app_guids, "Application GUID")
    sb_guids = parse_guids(sandbox_guids, "Sandbox GUID")
    if not sb_guids:
        raise HTTPException(status_code=400, detail="No sandbox GUIDs specified.")

    statuses = get_multi_sandboxes_status_list(a_guids, sb_guids)
    return {
        "count": len(statuses),
        "statuses": statuses
    }

@router.get("/sandboxes/findings")
def get_sandboxes_findings(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    sandbox_guids: str = Query(..., description="Comma-separated sandbox GUIDs"),
    scan_type: str = Query("ALL", description="Filter: ALL, SAST, SCA")
):
    """Retrieves reported SAST/SCA vulnerabilities across selected applications and sandboxes."""
    a_guids = parse_guids(app_guids, "Application GUID")
    sb_guids = parse_guids(sandbox_guids, "Sandbox GUID")
    if not sb_guids:
        raise HTTPException(status_code=400, detail="No sandbox GUIDs specified.")

    findings = fetch_findings_for_multi_apps(a_guids, sb_guids, scan_type=scan_type)
    return {
        "applications_count": len(a_guids),
        "sandboxes_count": len(sb_guids),
        "total_flaws": len(findings),
        "scan_type_requested": scan_type,
        "findings": findings
    }

@router.get("/sandboxes/metrics")
def get_sandboxes_metrics(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    sandbox_guids: str = Query(..., description="Comma-separated sandbox GUIDs")
):
    """Computes comprehensive tabular metrics across selected applications and sandboxes."""
    a_guids = parse_guids(app_guids, "Application GUID")
    sb_guids = parse_guids(sandbox_guids, "Sandbox GUID")
    if not sb_guids:
        raise HTTPException(status_code=400, detail="No sandbox GUIDs specified.")

    statuses = get_multi_sandboxes_status_list(a_guids, sb_guids)
    findings = fetch_findings_for_multi_apps(a_guids, sb_guids, scan_type="ALL")
    metrics = metrics_engine.calculate_metrics(findings, sandboxes_status=statuses)

    return {
        "applications_count": len(a_guids),
        "sandboxes_count": len(sb_guids),
        "metrics": metrics
    }

# ----------------- BACKWARDS-COMPATIBLE APP-SCOPED ROUTES -----------------

@router.get("/applications/{app_guid}/sandboxes/status")
def get_app_sandboxes_status(app_guid: str, sandbox_guids: str = Query(...)):
    return get_sandboxes_status(app_guids=app_guid, sandbox_guids=sandbox_guids)

@router.get("/applications/{app_guid}/sandboxes/findings")
def get_app_sandboxes_findings(app_guid: str, sandbox_guids: str = Query(...), scan_type: str = "ALL"):
    return get_sandboxes_findings(app_guids=app_guid, sandbox_guids=sandbox_guids, scan_type=scan_type)

@router.get("/applications/{app_guid}/sandboxes/metrics")
def get_app_sandboxes_metrics(app_guid: str, sandbox_guids: str = Query(...)):
    return get_sandboxes_metrics(app_guids=app_guid, sandbox_guids=sandbox_guids)

@router.get("/applications/{app_guid}/sandboxes/{sandbox_guid}/status")
def get_single_sandbox_status(app_guid: str, sandbox_guid: str):
    res = get_sandboxes_status(app_guids=app_guid, sandbox_guids=sandbox_guid)
    st = res.get("statuses", [])
    return {"status": st[0] if st else {"scan_status": "Results Ready"}}

@router.get("/applications/{app_guid}/sandboxes/{sandbox_guid}/findings")
def get_single_sandbox_findings(app_guid: str, sandbox_guid: str, scan_type: str = "ALL"):
    res = get_sandboxes_findings(app_guids=app_guid, sandbox_guids=sandbox_guid, scan_type=scan_type)
    return {
        "count": res.get("total_flaws", 0),
        "scan_type_requested": scan_type,
        "findings": res.get("findings", [])
    }

@router.get("/applications/{app_guid}/sandboxes/{sandbox_guid}/metrics")
def get_single_sandbox_metrics(app_guid: str, sandbox_guid: str):
    res = get_sandboxes_metrics(app_guids=app_guid, sandbox_guids=sandbox_guid)
    return {"metrics": res.get("metrics")}

# ----------------- MULTI-APP & MULTI-SANDBOX REPORT DOWNLOADS -----------------

@router.get("/reports/excel")
def download_excel_report(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    sandbox_guids: str = Query(..., description="Comma-separated sandbox GUIDs")
):
    """Downloads all latest scans reported instances across applications and sandboxes in Excel (.xlsx)."""
    a_guids = parse_guids(app_guids, "Application GUID")
    sb_guids = parse_guids(sandbox_guids, "Sandbox GUID")
    if not sb_guids:
        raise HTTPException(status_code=400, detail="No sandbox GUIDs specified.")

    apps_info = get_apps_metadata(a_guids)
    statuses = get_multi_sandboxes_status_list(a_guids, sb_guids)
    findings = fetch_findings_for_multi_apps(a_guids, sb_guids, scan_type="ALL")
    metrics = metrics_engine.calculate_metrics(findings, sandboxes_status=statuses)

    excel_io = report_generator.generate_excel(
        app_info=apps_info,
        sandboxes_info=statuses,
        findings=findings,
        metrics=metrics
    )

    filename = f"Veracode_Report_{len(a_guids)}apps_{len(sb_guids)}sbx.xlsx"
    return Response(
        content=excel_io.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/reports/pdf")
def download_pdf_report(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    sandbox_guids: str = Query(..., description="Comma-separated sandbox GUIDs")
):
    """
    Downloads official Veracode Detailed PDF Report(s) for the selected sandboxes.

    Strategy (per sandbox):
      1. Resolve the numeric sandbox build_id from getbuildlist.do
      2. Download the PDF via detailedreportpdf.do (Veracode XML API v4.0)
      3. If only one sandbox → return Veracode PDF directly
      4. If multiple sandboxes OR any download fails → fall back to locally-generated PDF
      (In mock mode always uses local generation)
    """
    a_guids = parse_guids(app_guids, "Application GUID")
    sb_guids = parse_guids(sandbox_guids, "Sandbox GUID")
    if not sb_guids:
        raise HTTPException(status_code=400, detail="No sandbox GUIDs specified.")

    api_id, _ = settings.get_credentials()
    is_live = api_id and not settings.mock_mode

    # ---- Live Veracode path ----
    if is_live:
        all_sbs = fetch_sandboxes_for_apps(a_guids)
        sb_lookup = {s.get("guid"): s for s in all_sbs}

        if len(sb_guids) == 1:
            # Single sandbox → try to stream Veracode's own PDF
            sb_guid = sb_guids[0]
            meta = sb_lookup.get(sb_guid, {})
            app_id_num = meta.get("application_id")
            sb_id_num  = meta.get("id")

            if app_id_num and sb_id_num:
                build_id = veracode_client.get_build_id_for_sandbox(
                    int(app_id_num), int(sb_id_num)
                )
                if build_id:
                    pdf_bytes = veracode_client.fetch_veracode_pdf_report(build_id)
                    if pdf_bytes:
                        sb_name = (meta.get("name") or sb_guid[:8]).replace("/", "-")
                        filename = f"Veracode_DetailedReport_{sb_name}_build{build_id}.pdf"
                        return Response(
                            content=pdf_bytes,
                            media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
                        )
        # Multi-sandbox or single-sandbox retrieval failed → fall through to local generation

    # ---- Local generation fallback ----
    apps_info = get_apps_metadata(a_guids)
    statuses  = get_multi_sandboxes_status_list(a_guids, sb_guids)
    findings  = fetch_findings_for_multi_apps(a_guids, sb_guids, scan_type="ALL")
    metrics   = metrics_engine.calculate_metrics(findings, sandboxes_status=statuses)

    pdf_io = report_generator.generate_pdf(
        app_info=apps_info,
        sandboxes_info=statuses,
        findings=findings,
        metrics=metrics
    )
    filename = f"Veracode_Report_{len(a_guids)}apps_{len(sb_guids)}sbx.pdf"
    return Response(
        content=pdf_io.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/reports/xml")
def download_xml_report(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    sandbox_guids: str = Query(..., description="Comma-separated sandbox GUIDs")
):
    """
    Downloads official Veracode Detailed XML Report(s) for the selected sandboxes.

    Strategy (per sandbox):
      1. Resolve the numeric sandbox build_id from getbuildlist.do
      2. Download the XML via detailedreport.do (Veracode XML API v5.0)
      3. Single sandbox → return Veracode XML directly (gzip if applicable)
      4. Multiple sandboxes → download all, wrap them in a <veracode_multi_report> envelope XML
      5. Any failure → fall back to locally-generated XML
      (In mock mode always uses local generation)
    """
    a_guids = parse_guids(app_guids, "Application GUID")
    sb_guids = parse_guids(sandbox_guids, "Sandbox GUID")
    if not sb_guids:
        raise HTTPException(status_code=400, detail="No sandbox GUIDs specified.")

    import gzip
    import xml.etree.ElementTree as ET

    api_id, _ = settings.get_credentials()
    is_live = api_id and not settings.mock_mode

    # ---- Live Veracode path ----
    if is_live:
        all_sbs    = fetch_sandboxes_for_apps(a_guids)
        sb_lookup  = {s.get("guid"): s for s in all_sbs}
        collected  = []  # list of (sandbox_meta, xml_bytes)

        for sb_guid in sb_guids:
            meta       = sb_lookup.get(sb_guid, {})
            app_id_num = meta.get("application_id")
            sb_id_num  = meta.get("id")
            if not (app_id_num and sb_id_num):
                continue
            build_id = veracode_client.get_build_id_for_sandbox(
                int(app_id_num), int(sb_id_num)
            )
            if not build_id:
                continue
            xml_bytes = veracode_client.fetch_veracode_xml_report(build_id)
            if xml_bytes:
                collected.append((meta, build_id, xml_bytes))

        if collected and len(collected) == len(sb_guids):
            # All sandboxes resolved from Veracode
            if len(collected) == 1:
                # Single sandbox: stream as-is (gzip or plain XML)
                meta, build_id, raw = collected[0]
                sb_name  = (meta.get("name") or sb_guids[0][:8]).replace("/", "-")
                filename = f"Veracode_DetailedReport_{sb_name}_build{build_id}.xml"
                # Decompress if gzipped
                if raw[:2] == b"\x1f\x8b":
                    raw = gzip.decompress(raw)
                return Response(
                    content=raw,
                    media_type="application/xml",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'}
                )
            else:
                # Multiple sandboxes: wrap in an envelope
                envelope = ET.Element("veracode_multi_report")
                envelope.set("sandbox_count", str(len(collected)))
                for meta, build_id, raw in collected:
                    sb_name = meta.get("name") or "sandbox"
                    # Decompress if gzipped
                    if raw[:2] == b"\x1f\x8b":
                        raw = gzip.decompress(raw)
                    try:
                        sb_root = ET.fromstring(raw)
                    except ET.ParseError:
                        # Keep raw text in a wrapper if parse fails
                        sb_root = ET.Element("sandbox_report")
                    sb_root.set("sandbox_name", sb_name)
                    sb_root.set("build_id", str(build_id))
                    envelope.append(sb_root)

                xml_out = ET.tostring(envelope, encoding="utf-8", xml_declaration=True)
                filename = f"Veracode_DetailedReport_{len(sb_guids)}sandboxes.xml"
                return Response(
                    content=xml_out,
                    media_type="application/xml",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'}
                )
        # Partial success or no live data → fall through

    # ---- Local generation fallback ----
    apps_info = get_apps_metadata(a_guids)
    statuses  = get_multi_sandboxes_status_list(a_guids, sb_guids)
    findings  = fetch_findings_for_multi_apps(a_guids, sb_guids, scan_type="ALL")
    metrics   = metrics_engine.calculate_metrics(findings, sandboxes_status=statuses)

    xml_io = report_generator.generate_xml(
        app_info=apps_info,
        sandboxes_info=statuses,
        findings=findings,
        metrics=metrics
    )
    filename = f"Veracode_Report_{len(a_guids)}apps_{len(sb_guids)}sbx.xml"
    return Response(
        content=xml_io.getvalue(),
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/reports/csv")
def download_csv_report(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    sandbox_guids: str = Query(..., description="Comma-separated sandbox GUIDs")
):
    """Downloads all latest scans reported instances across applications and sandboxes in CSV format with Module, Description, Mitigation Status, and First Found Date."""
    a_guids = parse_guids(app_guids, "Application GUID")
    sb_guids = parse_guids(sandbox_guids, "Sandbox GUID")
    if not sb_guids:
        raise HTTPException(status_code=400, detail="No sandbox GUIDs specified.")

    findings = fetch_findings_for_multi_apps(a_guids, sb_guids, scan_type="ALL")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Application Name", "Sandbox Name", "Sandbox GUID", "Module", "Issue ID", "Scan Type",
        "Severity", "Severity Label", "Category", "CWE ID", "CWE Name",
        "CVE ID", "CVSS", "Description", "Mitigation Status",
        "Resolution Status", "First Found Date", "Location", "Line Number",
        "Remediation Advice"
    ])

    for f in findings:
        target = f.get("file_path") or f.get("component_filename") or ""
        mod = f.get("module") or f.get("component_filename") or f.get("file_name") or "N/A"
        writer.writerow([
            f.get("application_name") or "Application",
            f.get("sandbox_name") or "Sandbox",
            f.get("sandbox_guid") or "",
            mod,
            f.get("issue_id"),
            f.get("scan_type"),
            f.get("severity"),
            f.get("severity_label"),
            f.get("category"),
            f.get("cwe_id"),
            f.get("cwe_name"),
            f.get("cve_id"),
            f.get("cvss"),
            f.get("description", ""),
            f.get("mitigation_status", "Unmitigated"),
            f.get("resolution_status", "UNRESOLVED"),
            f.get("first_found_date", ""),
            target,
            f.get("line_number"),
            f.get("remediation_advice")
        ])

    filename = f"Veracode_Report_{len(a_guids)}apps_{len(sb_guids)}sbx.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# Backwards compatible report endpoints
@router.get("/applications/{app_guid}/reports/excel")
def app_scoped_excel(app_guid: str, sandbox_guids: str = Query(...)):
    return download_excel_report(app_guids=app_guid, sandbox_guids=sandbox_guids)

@router.get("/applications/{app_guid}/reports/pdf")
def app_scoped_pdf(app_guid: str, sandbox_guids: str = Query(...)):
    return download_pdf_report(app_guids=app_guid, sandbox_guids=sandbox_guids)

@router.get("/applications/{app_guid}/reports/xml")
def app_scoped_xml(app_guid: str, sandbox_guids: str = Query(...)):
    return download_xml_report(app_guids=app_guid, sandbox_guids=sandbox_guids)

@router.get("/applications/{app_guid}/reports/csv")
def app_scoped_csv(app_guid: str, sandbox_guids: str = Query(...)):
    return download_csv_report(app_guids=app_guid, sandbox_guids=sandbox_guids)

@router.get("/applications/{app_guid}/sandboxes/{sandbox_guid}/export")
def export_single_sandbox(
    app_guid: str,
    sandbox_guid: str,
    format: str = Query("csv", description="Format: excel, pdf, xml, csv, json")
):
    fmt = format.lower()
    if fmt in ("excel", "xlsx"):
        return download_excel_report(app_guids=app_guid, sandbox_guids=sandbox_guid)
    elif fmt == "pdf":
        return download_pdf_report(app_guids=app_guid, sandbox_guids=sandbox_guid)
    elif fmt == "xml":
        return download_xml_report(app_guids=app_guid, sandbox_guids=sandbox_guid)
    elif fmt == "csv":
        return download_csv_report(app_guids=app_guid, sandbox_guids=sandbox_guid)

    findings = fetch_findings_for_multi_apps([app_guid], [sandbox_guid], scan_type="ALL")
    if fmt == "json":
        return findings

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Application Name", "Sandbox Name", "Sandbox GUID", "Module", "Issue ID", "Scan Type",
        "Severity", "Severity Label", "Category", "CWE ID", "CWE Name",
        "CVE ID", "CVSS", "Description", "Mitigation Status",
        "Resolution Status", "First Found Date", "Location", "Line Number",
        "Remediation Advice"
    ])

    for f in findings:
        target = f.get("file_path") or f.get("component_filename") or ""
        mod = f.get("module") or f.get("component_filename") or f.get("file_name") or "N/A"
        writer.writerow([
            f.get("application_name") or "Application",
            f.get("sandbox_name") or "Sandbox",
            f.get("sandbox_guid") or "",
            mod,
            f.get("issue_id"),
            f.get("scan_type"),
            f.get("severity"),
            f.get("severity_label"),
            f.get("category"),
            f.get("cwe_id"),
            f.get("cwe_name"),
            f.get("cve_id"),
            f.get("cvss"),
            f.get("description", ""),
            f.get("mitigation_status", "Unmitigated"),
            f.get("resolution_status", "UNRESOLVED"),
            f.get("first_found_date", ""),
            target,
            f.get("line_number"),
            f.get("remediation_advice")
        ])

    filename = f"veracode_findings_{sandbox_guid[:8]}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# ----------------- VERACODE NATIVE REPORT DIRECT DOWNLOAD -----------------
# These endpoints expose the official Veracode detailedreport.do / detailedreportpdf.do
# downloads keyed by build_id or by sandbox numeric identifiers.

@router.get("/veracode/report/pdf")
def download_veracode_native_pdf(
    app_id: int = Query(..., description="Numeric Veracode application ID"),
    sandbox_id: int = Query(..., description="Numeric Veracode sandbox ID"),
    build_id: Optional[str] = Query(None, description="Specific build ID (omit to use latest)")
):
    """
    Downloads the official Veracode Detailed PDF Report from detailedreportpdf.do.
    If build_id is not supplied, resolves the latest build from getbuildlist.do first.
    Returns 404 if credentials are not configured or the report is unavailable.
    """
    api_id, _ = settings.get_credentials()
    if not api_id or settings.mock_mode:
        raise HTTPException(
            status_code=404,
            detail="Veracode API credentials are required to fetch native reports. "
                   "Configure credentials and disable mock mode."
        )

    effective_build_id = build_id
    if not effective_build_id:
        effective_build_id = veracode_client.get_build_id_for_sandbox(app_id, sandbox_id)
    if not effective_build_id:
        raise HTTPException(
            status_code=404,
            detail=f"Could not resolve a build_id for app_id={app_id} sandbox_id={sandbox_id}. "
                   "Ensure a scan has completed for this sandbox."
        )

    pdf_bytes = veracode_client.fetch_veracode_pdf_report(effective_build_id)
    if not pdf_bytes:
        raise HTTPException(
            status_code=502,
            detail=f"Veracode did not return a valid PDF for build_id={effective_build_id}. "
                   "The scan may still be in progress or the build may have no flaw data."
        )

    filename = f"Veracode_DetailedReport_app{app_id}_sb{sandbox_id}_build{effective_build_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/veracode/report/xml")
def download_veracode_native_xml(
    app_id: int = Query(..., description="Numeric Veracode application ID"),
    sandbox_id: int = Query(..., description="Numeric Veracode sandbox ID"),
    build_id: Optional[str] = Query(None, description="Specific build ID (omit to use latest)")
):
    """
    Downloads the official Veracode Detailed XML Report from detailedreport.do.
    If build_id is not supplied, resolves the latest build from getbuildlist.do first.
    Decompresses gzip automatically before streaming.
    Returns 404 if credentials are not configured or the report is unavailable.
    """
    import gzip

    api_id, _ = settings.get_credentials()
    if not api_id or settings.mock_mode:
        raise HTTPException(
            status_code=404,
            detail="Veracode API credentials are required to fetch native reports. "
                   "Configure credentials and disable mock mode."
        )

    effective_build_id = build_id
    if not effective_build_id:
        effective_build_id = veracode_client.get_build_id_for_sandbox(app_id, sandbox_id)
    if not effective_build_id:
        raise HTTPException(
            status_code=404,
            detail=f"Could not resolve a build_id for app_id={app_id} sandbox_id={sandbox_id}. "
                   "Ensure a scan has completed for this sandbox."
        )

    xml_bytes = veracode_client.fetch_veracode_xml_report(effective_build_id)
    if not xml_bytes:
        raise HTTPException(
            status_code=502,
            detail=f"Veracode did not return valid XML for build_id={effective_build_id}. "
                   "The scan may still be in progress or the build may have no flaw data."
        )

    # Decompress gzip if needed
    if xml_bytes[:2] == b"\x1f\x8b":
        xml_bytes = gzip.decompress(xml_bytes)

    filename = f"Veracode_DetailedReport_app{app_id}_sb{sandbox_id}_build{effective_build_id}.xml"
    return Response(
        content=xml_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/veracode/report/info")
def get_veracode_report_info(
    app_guids: str = Query(..., description="Comma-separated application GUIDs"),
    sandbox_guids: str = Query(..., description="Comma-separated sandbox GUIDs")
):
    """
    Returns per-sandbox build_id availability so the UI can show whether
    native Veracode XML/PDF reports can be downloaded.
    Returns is_live=false in mock mode.
    """
    a_guids  = parse_guids(app_guids, "Application GUID")
    sb_guids = parse_guids(sandbox_guids, "Sandbox GUID")
    if not sb_guids:
        raise HTTPException(status_code=400, detail="No sandbox GUIDs specified.")

    api_id, _ = settings.get_credentials()
    is_live   = bool(api_id and not settings.mock_mode)

    info = {
        "is_live": is_live,
        "veracode_reports_available": False,
        "sandboxes": []
    }

    if not is_live:
        return info

    all_sbs   = fetch_sandboxes_for_apps(a_guids)
    sb_lookup = {s.get("guid"): s for s in all_sbs}
    any_avail = False

    for sb_guid in sb_guids:
        meta       = sb_lookup.get(sb_guid, {})
        app_id_num = meta.get("application_id")
        sb_id_num  = meta.get("id")
        build_id   = None
        available  = False

        if app_id_num and sb_id_num:
            build_id  = veracode_client.get_build_id_for_sandbox(int(app_id_num), int(sb_id_num))
            available = build_id is not None

        if available:
            any_avail = True

        info["sandboxes"].append({
            "sandbox_guid":  sb_guid,
            "sandbox_name":  meta.get("name", "Sandbox"),
            "application_id": app_id_num,
            "sandbox_id":    sb_id_num,
            "build_id":      build_id,
            "veracode_report_available": available,
            "pdf_url": (
                f"/api/veracode/report/pdf?app_id={app_id_num}&sandbox_id={sb_id_num}&build_id={build_id}"
                if available else None
            ),
            "xml_url": (
                f"/api/veracode/report/xml?app_id={app_id_num}&sandbox_id={sb_id_num}&build_id={build_id}"
                if available else None
            ),
        })

    info["veracode_reports_available"] = any_avail
    return info
