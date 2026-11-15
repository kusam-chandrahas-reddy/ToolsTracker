"""
Vulnerability Metrics Engine for Veracode Sandbox Scans.
Calculates multidimensional metrics, cross-tabulations, severity, mitigation status, and scan type data.
"""
from typing import List, Dict, Any
from collections import defaultdict

SEVERITY_ORDER = ["Very High", "High", "Medium", "Low", "Very Low", "Informational"]
SEVERITY_NUM_MAP = {
    5: "Very High",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Very Low",
    0: "Informational"
}

MITIGATION_ORDER = [
    "Unmitigated",
    "Mitigation Proposed",
    "Mitigation Approved",
    "Mitigation Rejected",
    "Fixed / Resolved"
]

class MetricsEngine:
    @staticmethod
    def calculate_metrics(findings: List[Dict[str, Any]], sandboxes_status: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Produces comprehensive tabular metrics from normalized findings across one or multiple sandboxes.
        """
        total_flaws = len(findings)
        sast_findings = [f for f in findings if f.get("scan_type") == "SAST"]
        sca_findings = [f for f in findings if f.get("scan_type") == "SCA"]

        # KPI Metrics
        very_high_count = sum(1 for f in findings if f.get("severity") == 5)
        high_count = sum(1 for f in findings if f.get("severity") == 4)
        medium_count = sum(1 for f in findings if f.get("severity") == 3)
        low_count = sum(1 for f in findings if f.get("severity") in (1, 2))
        info_count = sum(1 for f in findings if f.get("severity") == 0)
        new_count = sum(1 for f in findings if f.get("is_new"))
        critical_high_count = very_high_count + high_count

        unmitigated_count = sum(1 for f in findings if f.get("mitigation_status") == "Unmitigated")
        mit_proposed_count = sum(1 for f in findings if f.get("mitigation_status") == "Mitigation Proposed")
        mit_approved_count = sum(1 for f in findings if f.get("mitigation_status") == "Mitigation Approved")
        mit_rejected_count = sum(1 for f in findings if f.get("mitigation_status") == "Mitigation Rejected")
        fixed_count = sum(1 for f in findings if f.get("mitigation_status") == "Fixed / Resolved")

        kpis = {
            "total_flaws": total_flaws,
            "critical_high": critical_high_count,
            "very_high": very_high_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "informational": info_count,
            "sast_count": len(sast_findings),
            "sca_count": len(sca_findings),
            "new_flaws": new_count,
            "unmitigated_count": unmitigated_count,
            "mit_proposed_count": mit_proposed_count,
            "mit_approved_count": mit_approved_count,
            "mit_rejected_count": mit_rejected_count,
            "fixed_count": fixed_count,
            "sandboxes_count": len(sandboxes_status) if sandboxes_status else 1
        }

        # 1. Primary Tabular Matrix: Scan Type x Severity x Mitigation Status Data
        severity_mitigation_matrix = MetricsEngine._generate_severity_mitigation_matrix(findings)

        # 2. High-level Severity Matrix: Scan Type vs Severity
        severity_matrix = MetricsEngine._generate_severity_matrix(findings)

        # 3. Mitigation Status Summary Table
        mitigation_table = MetricsEngine._generate_mitigation_table(findings)

        # 4. Multi-Sandbox Breakdown Table
        sandboxes_table = MetricsEngine._generate_sandboxes_table(findings, sandboxes_status or [])

        # 5. Top SAST CWE Categories Table
        sast_cwe_table = MetricsEngine._generate_sast_cwe_table(sast_findings)

        # 6. SCA Components & CVE Table
        sca_components_table = MetricsEngine._generate_sca_components_table(sca_findings)

        return {
            "kpis": kpis,
            "severity_mitigation_matrix": severity_mitigation_matrix,
            "severity_matrix": severity_matrix,
            "mitigation_table": mitigation_table,
            "sandboxes_table": sandboxes_table,
            "sast_cwe_table": sast_cwe_table,
            "sca_components_table": sca_components_table
        }

    @staticmethod
    def _generate_severity_mitigation_matrix(findings: List[Dict]) -> List[Dict]:
        """
        Generates granular tabular rows cross-referencing:
        Scan Type x Severity x Mitigation Status (Unmitigated, Proposed, Approved, Rejected, Fixed)
        """
        rows = []
        scan_types = [("SAST", "SAST (Static Analysis)"), ("SCA", "SCA (Software Composition)")]

        for st_code, st_label in scan_types:
            st_findings = [f for f in findings if f.get("scan_type") == st_code]
            if not st_findings and len(findings) > 0:
                continue

            for sev_num in [5, 4, 3, 2, 1, 0]:
                sev_label = SEVERITY_NUM_MAP[sev_num]
                subset = [f for f in st_findings if f.get("severity") == sev_num]
                
                # Only include rows that have flaws or keep full standard layout
                unmitigated = sum(1 for f in subset if f.get("mitigation_status") == "Unmitigated")
                proposed = sum(1 for f in subset if f.get("mitigation_status") == "Mitigation Proposed")
                approved = sum(1 for f in subset if f.get("mitigation_status") == "Mitigation Approved")
                rejected = sum(1 for f in subset if f.get("mitigation_status") == "Mitigation Rejected")
                fixed = sum(1 for f in subset if f.get("mitigation_status") == "Fixed / Resolved")
                total = len(subset)

                rows.append({
                    "scan_type": st_label,
                    "scan_type_code": st_code,
                    "severity_num": sev_num,
                    "severity_label": sev_label,
                    "total": total,
                    "unmitigated": unmitigated,
                    "mitigation_proposed": proposed,
                    "mitigation_approved": approved,
                    "mitigation_rejected": rejected,
                    "fixed_resolved": fixed,
                    "is_subtotal": False
                })

            # Subtotal row for scan type
            sub_unmit = sum(1 for f in st_findings if f.get("mitigation_status") == "Unmitigated")
            sub_prop = sum(1 for f in st_findings if f.get("mitigation_status") == "Mitigation Proposed")
            sub_appr = sum(1 for f in st_findings if f.get("mitigation_status") == "Mitigation Approved")
            sub_rej = sum(1 for f in st_findings if f.get("mitigation_status") == "Mitigation Rejected")
            sub_fix = sum(1 for f in st_findings if f.get("mitigation_status") == "Fixed / Resolved")

            rows.append({
                "scan_type": f"{st_label} - Subtotal",
                "scan_type_code": st_code,
                "severity_num": -1,
                "severity_label": "All Severities",
                "total": len(st_findings),
                "unmitigated": sub_unmit,
                "mitigation_proposed": sub_prop,
                "mitigation_approved": sub_appr,
                "mitigation_rejected": sub_rej,
                "fixed_resolved": sub_fix,
                "is_subtotal": True
            })

        # Grand Total Row
        gt_unmit = sum(1 for f in findings if f.get("mitigation_status") == "Unmitigated")
        gt_prop = sum(1 for f in findings if f.get("mitigation_status") == "Mitigation Proposed")
        gt_appr = sum(1 for f in findings if f.get("mitigation_status") == "Mitigation Approved")
        gt_rej = sum(1 for f in findings if f.get("mitigation_status") == "Mitigation Rejected")
        gt_fix = sum(1 for f in findings if f.get("mitigation_status") == "Fixed / Resolved")

        rows.append({
            "scan_type": "Grand Total (All Sandboxes & Scan Types)",
            "scan_type_code": "ALL",
            "severity_num": -1,
            "severity_label": "All Severities",
            "total": len(findings),
            "unmitigated": gt_unmit,
            "mitigation_proposed": gt_prop,
            "mitigation_approved": gt_appr,
            "mitigation_rejected": gt_rej,
            "fixed_resolved": gt_fix,
            "is_subtotal": True,
            "is_grand_total": True
        })

        return rows

    @staticmethod
    def _generate_severity_matrix(findings: List[Dict]) -> List[Dict]:
        """
        Generates tabular rows: SAST, SCA, and Total summary row.
        Includes Unmitigated and Mitigated totals.
        """
        def make_row(label: str, subset: List[Dict]) -> Dict:
            sev_counts = {sev: 0 for sev in SEVERITY_ORDER}
            open_count = 0
            new_count = 0
            unmitigated = 0
            mitigated = 0

            for f in subset:
                sev_label = f.get("severity_label", "Informational")
                if sev_label in sev_counts:
                    sev_counts[sev_label] += 1
                if f.get("status", "").upper() == "OPEN":
                    open_count += 1
                if f.get("is_new"):
                    new_count += 1
                if f.get("mitigation_status") == "Unmitigated":
                    unmitigated += 1
                else:
                    mitigated += 1

            return {
                "scan_type": label,
                "very_high": sev_counts["Very High"],
                "high": sev_counts["High"],
                "medium": sev_counts["Medium"],
                "low": sev_counts["Low"],
                "very_low": sev_counts["Very Low"],
                "informational": sev_counts["Informational"],
                "total": len(subset),
                "open": open_count,
                "unmitigated": unmitigated,
                "mitigated": mitigated,
                "new": new_count
            }

        sast_findings = [f for f in findings if f.get("scan_type") == "SAST"]
        sca_findings = [f for f in findings if f.get("scan_type") == "SCA"]

        return [
            make_row("SAST (Static Code Analysis)", sast_findings),
            make_row("SCA (Software Composition Analysis)", sca_findings),
            make_row("Total Sandbox Flaws", findings)
        ]

    @staticmethod
    def _generate_mitigation_table(findings: List[Dict]) -> List[Dict]:
        """
        Summarizes findings by Mitigation Status across SAST vs SCA.
        """
        status_map = {m: {"SAST": 0, "SCA": 0, "total": 0} for m in MITIGATION_ORDER}
        total_flaws = len(findings)

        for f in findings:
            ms = f.get("mitigation_status") or "Unmitigated"
            st = f.get("scan_type", "SAST")
            if ms not in status_map:
                status_map[ms] = {"SAST": 0, "SCA": 0, "total": 0}
            status_map[ms][st] += 1
            status_map[ms]["total"] += 1

        table = []
        for ms_label in MITIGATION_ORDER:
            counts = status_map.get(ms_label, {"SAST": 0, "SCA": 0, "total": 0})
            pct = round((counts["total"] / total_flaws * 100), 1) if total_flaws > 0 else 0.0
            table.append({
                "mitigation_status": ms_label,
                "sast": counts["SAST"],
                "sca": counts["SCA"],
                "total": counts["total"],
                "percentage": pct
            })

        return table

    @staticmethod
    def _generate_sandboxes_table(findings: List[Dict], sandboxes_status: List[Dict]) -> List[Dict]:
        """
        When multiple sandboxes are selected, generates a summary row per sandbox.
        """
        sb_map = defaultdict(lambda: {
            "name": "",
            "scan_status": "Results Ready",
            "last_scan_date": None,
            "total": 0,
            "crit_high": 0,
            "sast": 0,
            "sca": 0,
            "unmitigated": 0,
            "mitigated": 0
        })

        for s in sandboxes_status:
            guid = s.get("sandbox_guid")
            if guid:
                sb_map[guid]["name"] = s.get("sandbox_name") or s.get("name") or "Sandbox"
                sb_map[guid]["scan_status"] = s.get("scan_status") or "Results Ready"
                sb_map[guid]["last_scan_date"] = s.get("last_scan_date")

        for f in findings:
            guid = f.get("sandbox_guid") or "default"
            entry = sb_map[guid]
            if f.get("sandbox_name") and not entry["name"]:
                entry["name"] = f.get("sandbox_name")
            entry["total"] += 1
            if f.get("severity", 0) >= 4:
                entry["crit_high"] += 1
            if f.get("scan_type") == "SAST":
                entry["sast"] += 1
            else:
                entry["sca"] += 1
            if f.get("mitigation_status") == "Unmitigated":
                entry["unmitigated"] += 1
            else:
                entry["mitigated"] += 1

        table = []
        for guid, data in sb_map.items():
            table.append({
                "sandbox_guid": guid,
                "name": data["name"] or "Sandbox",
                "scan_status": data["scan_status"],
                "last_scan_date": data["last_scan_date"],
                "total": data["total"],
                "crit_high": data["crit_high"],
                "sast": data["sast"],
                "sca": data["sca"],
                "unmitigated": data["unmitigated"],
                "mitigated": data["mitigated"]
            })

        return sorted(table, key=lambda x: x["total"], reverse=True)

    @staticmethod
    def _generate_sast_cwe_table(sast_findings: List[Dict]) -> List[Dict]:
        """
        Groups SAST flaws by CWE ID and Category Name with mitigation breakdown.
        """
        cwe_groups = defaultdict(lambda: {
            "count": 0,
            "max_severity": 0,
            "cwe_name": "",
            "category": "",
            "unmitigated": 0,
            "mitigated": 0
        })
        total_sast = len(sast_findings)

        for f in sast_findings:
            cwe_id = f.get("cwe_id") or "CWE-Unknown"
            cwe_key = f"CWE-{cwe_id}" if isinstance(cwe_id, int) or not str(cwe_id).startswith("CWE") else str(cwe_id)
            cwe_groups[cwe_key]["count"] += 1
            sev = f.get("severity", 0)
            if sev > cwe_groups[cwe_key]["max_severity"]:
                cwe_groups[cwe_key]["max_severity"] = sev
            cwe_groups[cwe_key]["cwe_name"] = f.get("cwe_name") or f.get("category", "")
            cwe_groups[cwe_key]["category"] = f.get("category", "")
            if f.get("mitigation_status") == "Unmitigated":
                cwe_groups[cwe_key]["unmitigated"] += 1
            else:
                cwe_groups[cwe_key]["mitigated"] += 1

        table = []
        sorted_cwes = sorted(cwe_groups.items(), key=lambda item: (item[1]["count"], item[1]["max_severity"]), reverse=True)

        for rank, (cwe_key, data) in enumerate(sorted_cwes, start=1):
            pct = round((data["count"] / total_sast * 100), 1) if total_sast > 0 else 0
            sev_num = data["max_severity"]
            table.append({
                "rank": rank,
                "cwe_id": cwe_key,
                "category": data["category"],
                "cwe_name": data["cwe_name"],
                "count": data["count"],
                "unmitigated": data["unmitigated"],
                "mitigated": data["mitigated"],
                "max_severity": sev_num,
                "max_severity_label": SEVERITY_NUM_MAP.get(sev_num, "Low"),
                "percentage": pct
            })

        return table

    @staticmethod
    def _generate_sca_components_table(sca_findings: List[Dict]) -> List[Dict]:
        """
        Aggregates third-party components, CVE identifiers, CVSS scores, and mitigation state.
        """
        comp_groups = defaultdict(lambda: {
            "version": "",
            "cves": set(),
            "max_cvss": 0.0,
            "max_severity": 0,
            "flaw_count": 0,
            "unmitigated": 0,
            "remediation": ""
        })

        for f in sca_findings:
            comp_name = f.get("component_filename") or f.get("file_name") or "Unknown Component"
            entry = comp_groups[comp_name]
            entry["flaw_count"] += 1
            if f.get("version"):
                entry["version"] = f.get("version")
            if f.get("cve_id"):
                entry["cves"].add(f.get("cve_id"))
            cvss = f.get("cvss") or 0.0
            if cvss > entry["max_cvss"]:
                entry["max_cvss"] = cvss
            sev = f.get("severity", 0)
            if sev > entry["max_severity"]:
                entry["max_severity"] = sev
            if f.get("mitigation_status") == "Unmitigated":
                entry["unmitigated"] += 1
            if f.get("remediation_advice") and not entry["remediation"]:
                entry["remediation"] = f.get("remediation_advice")

        table = []
        sorted_comps = sorted(comp_groups.items(), key=lambda item: (item[1]["max_cvss"], item[1]["max_severity"]), reverse=True)

        for comp_name, data in sorted_comps:
            table.append({
                "component": comp_name,
                "version": data["version"] or "N/A",
                "cves": list(data["cves"]) if data["cves"] else ["N/A"],
                "max_cvss": data["max_cvss"],
                "max_severity": data["max_severity"],
                "max_severity_label": SEVERITY_NUM_MAP.get(data["max_severity"], "Low"),
                "flaw_count": data["flaw_count"],
                "unmitigated": data["unmitigated"],
                "remediation": data["remediation"] or "Update component to latest secure release"
            })

        return table

metrics_engine = MetricsEngine()
