import os
import time
import hmac
import hashlib
import logging
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, quote
from typing import Dict, List, Optional, Any, Tuple
import requests

from backend.config import settings

logger = logging.getLogger("veracode_client")
logging.basicConfig(level=logging.INFO)

class VeracodeClient:
    """
    Robust client for Veracode REST and XML APIs with HMAC-SHA256 authentication,
    in-memory caching, and error resilience.
    """
    def __init__(self):
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self.default_cache_ttl = 120  # seconds

    def _get_cache(self, key: str) -> Optional[Any]:
        if key in self._cache:
            timestamp, data = self._cache[key]
            if time.time() - timestamp < self.default_cache_ttl:
                return data
            del self._cache[key]
        return None

    def _set_cache(self, key: str, data: Any):
        self._cache[key] = (time.time(), data)

    def clear_cache(self):
        self._cache.clear()

    @staticmethod
    def calculate_hmac_header(api_id: str, api_secret: str, host: str, method: str, url_path: str) -> str:
        """
        Calculates the Veracode HMAC-SHA256 authorization header according to Veracode specs:
        1. Nonce: 16 random bytes (hex)
        2. Timestamp: epoch milliseconds
        3. Secret & Nonce decoded from hex
        4. Key chaining: Nonce -> Timestamp -> 'vcode_request_version_1'
        5. Data string: id={api_id}&host={host}&url={url_path}&method={method}
        """
        timestamp = str(int(time.time() * 1000))
        nonce = os.urandom(16).hex()

        try:
            secret_bytes = bytes.fromhex(api_secret)
        except ValueError:
            secret_bytes = api_secret.encode('utf-8')

        nonce_bytes = bytes.fromhex(nonce)

        # Chained HMAC-SHA256 derivations
        key_nonce = hmac.new(secret_bytes, nonce_bytes, hashlib.sha256).digest()
        key_date = hmac.new(key_nonce, timestamp.encode('utf-8'), hashlib.sha256).digest()
        key_sig = hmac.new(key_date, b"vcode_request_version_1", hashlib.sha256).digest()

        # Strict data formatting
        data_string = f"id={api_id}&host={host}&url={url_path}&method={method.upper()}"
        signature = hmac.new(key_sig, data_string.encode('utf-8'), hashlib.sha256).hexdigest()

        return f"VERACODE-HMAC-SHA-256 id={api_id},ts={timestamp},nonce={nonce},sig={signature}"

    def request(
        self,
        endpoint_or_url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        timeout: int = 30
    ) -> requests.Response:
        """
        Executes an authenticated HTTP request to Veracode API.
        """
        api_id, api_secret = settings.get_credentials()
        if not api_id or not api_secret:
            raise ValueError("Veracode API ID and Secret are required.")

        # Determine full URL
        if endpoint_or_url.startswith("http://") or endpoint_or_url.startswith("https://"):
            full_url = endpoint_or_url
        else:
            if not endpoint_or_url.startswith("/"):
                endpoint_or_url = f"/{endpoint_or_url}"
            full_url = f"{settings.base_url}{endpoint_or_url}"

        # Prepare query parameters
        req_prep = requests.Request(method, full_url, params=params).prepare()
        parsed = urlparse(req_prep.url)
        host = parsed.hostname
        url_path = parsed.path
        if parsed.query:
            url_path += f"?{parsed.query}"

        # Calculate HMAC authorization header
        auth_header = self.calculate_hmac_header(
            api_id=api_id,
            api_secret=api_secret,
            host=host,
            method=method,
            url_path=url_path
        )

        headers = {
            "Authorization": auth_header,
            "User-Agent": "Veracode-Sandbox-Tracker/1.0",
            "Accept": "application/json, application/xml, text/xml"
        }

        response = requests.request(
            method=method,
            url=req_prep.url,
            headers=headers,
            json=json_data,
            timeout=timeout
        )

        return response

    def test_connection(self) -> Dict[str, Any]:
        """Validates credentials by attempting to reach the applications endpoint."""
        api_id, api_secret = settings.get_credentials()
        if not api_id or not api_secret:
            return {
                "success": False,
                "message": "No Veracode API credentials provided."
            }

        try:
            resp = self.request("/appsec/v1/applications", params={"size": 1})
            if resp.status_code == 200:
                return {
                    "success": True,
                    "message": "Successfully authenticated with Veracode platform.",
                    "status_code": resp.status_code
                }
            elif resp.status_code == 401:
                return {
                    "success": False,
                    "message": "Authentication failed (401 Unauthorized). Check API ID and Secret Key, and ensure system clock is synchronized.",
                    "status_code": resp.status_code
                }
            elif resp.status_code == 403:
                return {
                    "success": False,
                    "message": "Forbidden (403). API credentials lack necessary permissions (Results API or Reviewer role).",
                    "status_code": resp.status_code
                }
            else:
                return {
                    "success": False,
                    "message": f"Veracode API returned HTTP {resp.status_code}: {resp.text[:200]}",
                    "status_code": resp.status_code
                }
        except Exception as e:
            logger.error(f"Error testing connection: {str(e)}")
            return {
                "success": False,
                "message": f"Connection error: {str(e)}"
            }

    def get_applications(self, page: int = 0, size: int = 50, force_refresh: bool = False) -> List[Dict]:
        """Retrieves list of available applications."""
        cache_key = f"apps_{page}_{size}"
        if not force_refresh:
            cached = self._get_cache(cache_key)
            if cached is not None:
                return cached

        resp = self.request("/appsec/v1/applications", params={"page": page, "size": size})
        resp.raise_for_status()
        data = resp.json()

        applications = []
        embedded = data.get("_embedded", {})
        raw_apps = embedded.get("applications", [])

        for app in raw_apps:
            profile = app.get("profile", {})
            applications.append({
                "guid": app.get("guid"),
                "id": app.get("id"),
                "name": profile.get("name") or app.get("name", "Unnamed Application"),
                "business_criticality": profile.get("business_criticality", "Not Specified"),
                "teams": [t.get("team_name") for t in profile.get("teams", []) if t.get("team_name")],
                "policy_name": app.get("policy_name"),
                "last_completed_scan_date": app.get("last_completed_scan_date"),
                "modified": app.get("modified")
            })

        self._set_cache(cache_key, applications)
        return applications

    def get_sandboxes(self, app_guid: str, force_refresh: bool = False) -> List[Dict]:
        """Retrieves available sandboxes for an application."""
        cache_key = f"sandboxes_{app_guid}"
        if not force_refresh:
            cached = self._get_cache(cache_key)
            if cached is not None:
                return cached

        resp = self.request(f"/appsec/v1/applications/{app_guid}/sandboxes", params={"size": 100})
        resp.raise_for_status()
        data = resp.json()

        sandboxes = []
        embedded = data.get("_embedded", {})
        raw_sandboxes = embedded.get("sandboxes", [])

        for sb in raw_sandboxes:
            sandboxes.append({
                "guid": sb.get("guid"),
                "id": sb.get("id") or sb.get("sandbox_id"),
                "name": sb.get("name", "Unnamed Sandbox"),
                "owner": sb.get("owner", "N/A"),
                "created": sb.get("created_date") or sb.get("created"),
                "modified": sb.get("last_modified") or sb.get("modified"),
                "auto_recreate": sb.get("auto_recreate", False),
                "status": sb.get("status", "READY"),
                "application_id": sb.get("application_id"),
                "application_guid": app_guid
            })

        self._set_cache(cache_key, sandboxes)
        return sandboxes

    def get_sandbox_status(
        self,
        app_guid: str,
        sandbox_guid: str,
        app_id: Optional[int] = None,
        sandbox_id: Optional[int] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Retrieves the latest scan status for the specified sandbox.
        Combines REST sandbox data and XML getbuildinfo if available.
        """
        cache_key = f"status_{app_guid}_{sandbox_guid}"
        if not force_refresh:
            cached = self._get_cache(cache_key)
            if cached is not None:
                return cached

        status_info = {
            "sandbox_guid": sandbox_guid,
            "application_guid": app_guid,
            "scan_status": "Unknown",
            "lifecycle_stage": "Unknown",
            "last_scan_date": None,
            "build_id": None,
            "version": None,
            "is_scan_in_progress": False,
            "details": "Checking status..."
        }

        # 1. First check REST sandbox endpoint
        try:
            resp = self.request(f"/appsec/v1/applications/{app_guid}/sandboxes/{sandbox_guid}")
            if resp.status_code == 200:
                sb_data = resp.json()
                status_info["last_scan_date"] = sb_data.get("last_modified") or sb_data.get("modified")
                status_info["sandbox_status"] = sb_data.get("status", "READY")
                if not status_info["scan_status"] or status_info["scan_status"] == "Unknown":
                    status_info["scan_status"] = "Results Ready" if sb_data.get("last_modified") else "No Scans"
        except Exception as e:
            logger.warning(f"REST sandbox status check: {e}")

        # 2. Check XML getbuildinfo.do if numeric IDs are provided or discoverable
        if app_id and sandbox_id:
            try:
                xml_url = f"https://{settings.host}/api/5.0/getbuildinfo.do"
                resp = self.request(xml_url, params={"app_id": app_id, "sandbox_id": sandbox_id})
                if resp.status_code == 200 and "<buildinfo" in resp.text:
                    root = ET.fromstring(resp.content)
                    build = root.find(".//build")
                    if build is not None:
                        build_id = build.get("build_id")
                        version = build.get("version")
                        status_info["build_id"] = build_id
                        status_info["version"] = version

                        analysis_unit = build.find(".//analysis_unit")
                        if analysis_unit is not None:
                            stage = analysis_unit.get("status")
                            status_info["lifecycle_stage"] = stage
                            status_info["scan_status"] = stage
                            status_info["last_scan_date"] = analysis_unit.get("published_date") or status_info["last_scan_date"]

                            # Detect in-progress states
                            in_progress_keywords = ["scanning", "analysis in progress", "prescan", "submitted"]
                            if stage and any(k in stage.lower() for k in in_progress_keywords):
                                status_info["is_scan_in_progress"] = True
            except Exception as e:
                logger.warning(f"XML getbuildinfo check failed: {e}")

        # Fallback normalization
        if not status_info["scan_status"] or status_info["scan_status"] == "Unknown":
            status_info["scan_status"] = "Results Ready"

        self._set_cache(cache_key, status_info)
        return status_info

    def get_sandbox_findings(
        self,
        app_guid: str,
        sandbox_guid: str,
        sandbox_name: Optional[str] = None,
        scan_type: str = "ALL",
        force_refresh: bool = False
    ) -> List[Dict]:
        """
        Retrieves SAST and/or SCA findings specifically for the sandbox.
        Ensures policy scan details are excluded via context={sandbox_guid}.
        """
        cache_key = f"findings_{app_guid}_{sandbox_guid}_{scan_type}"
        if not force_refresh:
            cached = self._get_cache(cache_key)
            if cached is not None:
                return cached

        all_findings = []

        scan_types_to_fetch = []
        if scan_type.upper() in ("STATIC", "SAST"):
            scan_types_to_fetch = ["STATIC"]
        elif scan_type.upper() in ("SCA", "SOFTWARE_COMPOSITION_ANALYSIS"):
            scan_types_to_fetch = ["SCA"]
        else:
            # Per Veracode docs, SCA cannot be queried simultaneously with STATIC, so fetch both independently
            scan_types_to_fetch = ["STATIC", "SCA"]

        for st in scan_types_to_fetch:
            try:
                # Veracode REST Findings v2 API
                endpoint = f"/appsec/v2/applications/{app_guid}/findings"
                params = {
                    "context": sandbox_guid,
                    "scan_type": st,
                    "size": 500
                }
                resp = self.request(endpoint, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    raw_findings = data.get("_embedded", {}).get("findings", [])
                    for f in raw_findings:
                        normalized = self._normalize_finding(
                            f, 
                            default_scan_type=st, 
                            sandbox_guid=sandbox_guid,
                            sandbox_name=sandbox_name or "Sandbox"
                        )
                        all_findings.append(normalized)
                else:
                    logger.warning(f"Findings fetch returned {resp.status_code} for {st}")
            except Exception as e:
                logger.error(f"Error fetching {st} findings: {e}")

        self._set_cache(cache_key, all_findings)
        return all_findings

    @staticmethod
    def _normalize_finding(
        finding: Dict, 
        default_scan_type: str,
        sandbox_guid: Optional[str] = None,
        sandbox_name: Optional[str] = None
    ) -> Dict:
        """
        Normalizes finding structure across SAST and SCA formats.
        Extracts mitigation status, description, and first found date.
        """
        finding_details = finding.get("finding_details", {})
        finding_status = finding.get("finding_status", {})
        cwe = finding_details.get("cwe", {})
        cve = finding_details.get("cve", {}) or {}
        component = finding_details.get("component_filename") or finding_details.get("file_name")
        module = (
            finding_details.get("module_name") or 
            finding_details.get("module") or 
            finding.get("module") or 
            finding_details.get("component_filename") or 
            finding_details.get("file_name") or 
            "N/A"
        )

        raw_scan_type = finding.get("scan_type", default_scan_type).upper()
        # Canonicalize to SAST or SCA
        normalized_scan_type = "SAST" if "STATIC" in raw_scan_type else ("SCA" if "SCA" in raw_scan_type else raw_scan_type)

        severity_num = finding.get("severity", 0)
        severity_names = {
            5: "Very High",
            4: "High",
            3: "Medium",
            2: "Low",
            1: "Very Low",
            0: "Informational"
        }
        severity_label = severity_names.get(severity_num, "Unknown")

        # Normalize mitigation status
        raw_mitigation = finding_status.get("mitigation_status") or finding_status.get("mitigation_review_status") or ""
        resolution = str(finding_status.get("resolution_status", "")).upper()
        flaw_status = str(finding_status.get("status", "")).upper()

        if flaw_status == "CLOSED" or resolution == "RESOLVED":
            mitigation_status = "Fixed / Resolved"
        elif "APPROV" in str(raw_mitigation).upper() or resolution == "APPROVED":
            mitigation_status = "Mitigation Approved"
        elif "PROPOS" in str(raw_mitigation).upper() or resolution == "PROPOSED":
            mitigation_status = "Mitigation Proposed"
        elif "REJECT" in str(raw_mitigation).upper() or resolution == "REJECTED":
            mitigation_status = "Mitigation Rejected"
        else:
            mitigation_status = "Unmitigated"

        description = (
            finding.get("description") or 
            finding_details.get("description") or 
            finding_details.get("attack_vector") or 
            finding.get("summary") or
            f"Vulnerability identified in {component or finding_details.get('file_name', 'target')}."
        )

        first_found = (
            finding_status.get("first_found_date") or 
            finding.get("created") or 
            finding_status.get("found_date") or
            None
        )

        return {
            "issue_id": finding.get("issue_id"),
            "sandbox_guid": sandbox_guid or finding.get("sandbox_guid"),
            "sandbox_name": sandbox_name or finding.get("sandbox_name") or "Sandbox",
            "module": module,
            "scan_type": normalized_scan_type,
            "severity": severity_num,
            "severity_label": severity_label,
            "category": finding.get("finding_category", {}).get("name") or "General Flaw",
            "cwe_id": cwe.get("id"),
            "cwe_name": cwe.get("name"),
            "cve_id": cve.get("name") or finding_details.get("cve_id"),
            "cvss": cve.get("cvss") or finding_details.get("cvss"),
            "status": flaw_status or "OPEN",
            "mitigation_status": mitigation_status,
            "resolution_status": resolution or "UNRESOLVED",
            "is_new": finding_status.get("new", False),
            "file_path": finding_details.get("file_path"),
            "file_name": finding_details.get("file_name"),
            "line_number": finding_details.get("line_number"),
            "component_filename": component,
            "version": finding_details.get("version"),
            "description": description,
            "remediation_advice": finding_details.get("remediation_guidance") or finding.get("recommendation", "Review and apply secure coding practices / update dependency."),
            "first_found_date": first_found
        }

    # ------------------------------------------------------------------ #
    # Veracode XML Report APIs  (analysiscenter host, not api host)       #
    # detailedreport.do   → v5.0 → gzip XML                              #
    # detailedreportpdf.do→ v4.0 → PDF bytes                             #
    # Both require a numeric build_id obtained from getbuildlist.do       #
    # ------------------------------------------------------------------ #

    def _xml_api_host(self) -> str:
        """Return the analysiscenter host that serves the classic XML APIs."""
        region_map = {
            "us":     "analysiscenter.veracode.com",
            "eu":     "analysiscenter.veracode.eu",
            "us-gov": "analysiscenter.veracode.us",
        }
        return region_map.get(settings.region, "analysiscenter.veracode.com")

    def _xml_api_url(self, path: str) -> str:
        """Build a full URL for a classic XML API path."""
        return f"https://{self._xml_api_host()}{path}"

    def get_build_id_for_sandbox(
        self,
        app_id: int,
        sandbox_id: int,
        force_refresh: bool = False
    ) -> Optional[str]:
        """
        Fetches the most recent build_id for a sandbox via the classic
        XML API: GET /api/5.0/getbuildlist.do?app_id=X&sandbox_id=Y

        Returns the latest build_id string or None if unavailable.
        """
        cache_key = f"buildid_{app_id}_{sandbox_id}"
        if not force_refresh:
            cached = self._get_cache(cache_key)
            if cached is not None:
                return cached

        try:
            url = self._xml_api_url("/api/5.0/getbuildlist.do")
            resp = self.request(url, params={"app_id": app_id, "sandbox_id": sandbox_id}, timeout=20)
            if resp.status_code == 200 and resp.content:
                root = ET.fromstring(resp.content)
                # <buildlist> → one or more <build build_id="…"> newest is last
                builds = root.findall(".//build")
                if builds:
                    build_id = builds[-1].get("build_id")
                    self._set_cache(cache_key, build_id)
                    return build_id
        except Exception as e:
            logger.warning(f"getbuildlist.do failed for app_id={app_id} sandbox_id={sandbox_id}: {e}")
        return None

    def fetch_veracode_xml_report(self, build_id: str) -> Optional[bytes]:
        """
        Downloads the official Veracode Detailed XML Report for a build.
        Endpoint: GET /api/5.0/detailedreport.do?build_id=<build_id>
        Returns raw bytes (gzip-compressed XML) or None on failure.
        """
        try:
            url = self._xml_api_url("/api/5.0/detailedreport.do")
            resp = self.request(url, params={"build_id": build_id}, timeout=60)
            if resp.status_code == 200 and resp.content:
                return resp.content          # gzip or plain XML bytes
            logger.warning(f"detailedreport.do returned HTTP {resp.status_code} for build_id={build_id}")
        except Exception as e:
            logger.error(f"fetch_veracode_xml_report failed build_id={build_id}: {e}")
        return None

    def fetch_veracode_pdf_report(self, build_id: str) -> Optional[bytes]:
        """
        Downloads the official Veracode Detailed PDF Report for a build.
        Endpoint: GET /api/4.0/detailedreportpdf.do?build_id=<build_id>
        Returns raw PDF bytes or None on failure.
        """
        try:
            url = self._xml_api_url("/api/4.0/detailedreportpdf.do")
            resp = self.request(url, params={"build_id": build_id}, timeout=60)
            if resp.status_code == 200 and resp.content:
                # Confirm it is a PDF by checking magic bytes
                content = resp.content
                if content[:4] == b"%PDF" or b"%PDF" in content[:16]:
                    return content
                # Veracode returns XML error messages as text even on 200
                logger.warning(
                    f"detailedreportpdf.do returned non-PDF content for build_id={build_id}: "
                    f"{content[:120]}"
                )
            else:
                logger.warning(f"detailedreportpdf.do returned HTTP {resp.status_code} for build_id={build_id}")
        except Exception as e:
            logger.error(f"fetch_veracode_pdf_report failed build_id={build_id}: {e}")
        return None


veracode_client = VeracodeClient()

