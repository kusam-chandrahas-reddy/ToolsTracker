"""
Multi-Format Security Report Generator for Veracode Sandboxes.
Generates Excel (.xlsx), PDF (.pdf), and XML (.xml) reports across multiple applications & sandboxes.
Includes Application Name, Description, Mitigation Status, and First Found Date across all exports.
"""
import io
import datetime
from typing import List, Dict, Any, Union
import xml.etree.ElementTree as ET

import pandas as pd
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Adds running headers and page numbers to PDF."""
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
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header
        self.drawString(36, 580, "Veracode Platform — Multi-Application Sandbox Security Assessment (Policy Scans Excluded)")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 574, 756, 574)

        # Footer
        self.line(36, 36, 756, 36)
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(756, 24, page_str)
        self.drawString(36, 24, "CONFIDENTIAL — STRICTLY FOR AUTHORIZED INTERNAL SECURITY REMEDIATION")
        self.restoreState()


class ReportGenerator:

    @staticmethod
    def _normalize_apps_info(app_info: Union[Dict[str, Any], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        if isinstance(app_info, list):
            return app_info
        return [app_info] if app_info else [{"name": "Application", "guid": ""}]

    @staticmethod
    def generate_excel(
        app_info: Union[Dict[str, Any], List[Dict[str, Any]]],
        sandboxes_info: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        metrics: Dict[str, Any]
    ) -> io.BytesIO:
        """
        Builds a multi-tab Excel workbook (.xlsx) containing:
        - Executive Summary (with multiple applications)
        - Severity & Mitigation Matrix
        - All Reported Instances (with App Name, Description, Mitigation Status, First Found Date)
        - SAST Flaws
        - SCA Flaws
        """
        apps_list = ReportGenerator._normalize_apps_info(app_info)
        app_names_str = ", ".join(a.get("name", "N/A") for a in apps_list)

        wb = openpyxl.Workbook()
        wb.remove(wb.active)

        # Style definitions
        header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
        header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
        sub_fill = PatternFill(start_color="334155", end_color="334155", fill_type="solid")
        sub_font = Font(name="Calibri", size=10, bold=True, color="FFFFFF")
        border_thin = Border(
            left=Side(style='thin', color='E2E8F0'),
            right=Side(style='thin', color='E2E8F0'),
            top=Side(style='thin', color='E2E8F0'),
            bottom=Side(style='thin', color='E2E8F0')
        )

        # ---------------- SHEET 1: Executive Summary ----------------
        ws_exec = wb.create_sheet(title="Executive Summary")
        ws_exec.views.sheetView[0].showGridLines = True

        title_font = Font(name="Calibri", size=16, bold=True, color="0F172A")
        ws_exec["A1"] = "Veracode Multi-Application Sandbox Vulnerability & Metrics Report"
        ws_exec["A1"].font = title_font
        ws_exec["A2"] = f"Applications ({len(apps_list)}): {app_names_str}"
        ws_exec["A2"].font = Font(name="Calibri", size=11, italic=True, color="475569")
        ws_exec["A3"] = f"Report Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Policy Scans Excluded"
        ws_exec["A3"].font = Font(name="Calibri", size=9, color="64748B")

        # KPI Block
        kpis = metrics.get("kpis", {})
        ws_exec["A5"] = "High-Level KPI Overview"
        ws_exec["A5"].font = Font(name="Calibri", size=12, bold=True)

        kpi_rows = [
            ("Selected Applications Count", len(apps_list)),
            ("Selected Sandboxes Count", len(sandboxes_info)),
            ("Total Reported Flaws", kpis.get("total_flaws", len(findings))),
            ("Critical & High Flaws (Severity 4-5)", kpis.get("critical_high", 0)),
            ("SAST Flaws (Static Analysis)", kpis.get("sast_count", 0)),
            ("SCA Flaws (Third-Party Components)", kpis.get("sca_count", 0)),
            ("Unmitigated Flaws", kpis.get("unmitigated_count", 0)),
            ("Mitigations Proposed", kpis.get("mit_proposed_count", 0)),
            ("Mitigations Approved", kpis.get("mit_approved_count", 0)),
            ("Fixed / Resolved Flaws", kpis.get("fixed_count", 0))
        ]

        ws_exec["A6"] = "Metric"
        ws_exec["B6"] = "Value"
        ws_exec["A6"].fill = header_fill
        ws_exec["B6"].fill = header_fill
        ws_exec["A6"].font = header_font
        ws_exec["B6"].font = header_font

        for idx, (lbl, val) in enumerate(kpi_rows, start=7):
            ws_exec[f"A{idx}"] = lbl
            ws_exec[f"B{idx}"] = val
            ws_exec[f"A{idx}"].border = border_thin
            ws_exec[f"B{idx}"].border = border_thin
            ws_exec[f"B{idx}"].alignment = Alignment(horizontal="right")

        # Sandboxes Status Table
        start_sb_row = 19
        ws_exec[f"A{start_sb_row}"] = "Selected Sandboxes & Latest Scan Statuses"
        ws_exec[f"A{start_sb_row}"].font = Font(name="Calibri", size=12, bold=True)

        sb_headers = ["Application", "Sandbox Name", "Sandbox GUID", "Scan Status", "Build / Scan ID", "Version", "Last Scan Date"]
        for c_idx, h_text in enumerate(sb_headers, start=1):
            cell = ws_exec.cell(row=start_sb_row + 1, column=c_idx, value=h_text)
            cell.fill = header_fill
            cell.font = header_font

        for r_idx, sb in enumerate(sandboxes_info, start=start_sb_row + 2):
            app_name = sb.get("application_name") or (apps_list[0].get("name") if len(apps_list) == 1 else "Application")
            ws_exec.cell(row=r_idx, column=1, value=app_name)
            ws_exec.cell(row=r_idx, column=2, value=sb.get("sandbox_name") or sb.get("name") or "Sandbox")
            ws_exec.cell(row=r_idx, column=3, value=sb.get("sandbox_guid") or sb.get("guid"))
            ws_exec.cell(row=r_idx, column=4, value=sb.get("scan_status", "Results Ready"))
            ws_exec.cell(row=r_idx, column=5, value=sb.get("build_id", "N/A"))
            ws_exec.cell(row=r_idx, column=6, value=sb.get("version", "sandbox-latest"))
            ws_exec.cell(row=r_idx, column=7, value=sb.get("last_scan_date", "N/A"))
            for col in range(1, 8):
                ws_exec.cell(row=r_idx, column=col).border = border_thin

        # ---------------- SHEET 2: Severity & Mitigation Matrix ----------------
        ws_matrix = wb.create_sheet(title="Severity & Mitigation Matrix")
        ws_matrix.views.sheetView[0].showGridLines = True

        ws_matrix["A1"] = "Scan Type, Severity & Mitigation Status Cross-Tabulation"
        ws_matrix["A1"].font = title_font

        matrix_headers = [
            "Scan Type", "Severity", "Total Flaws",
            "Unmitigated", "Mitigation Proposed", "Mitigation Approved",
            "Mitigation Rejected", "Fixed / Resolved"
        ]
        for c_idx, h_text in enumerate(matrix_headers, start=1):
            cell = ws_matrix.cell(row=3, column=c_idx, value=h_text)
            cell.fill = header_fill
            cell.font = header_font

        matrix_rows = metrics.get("severity_mitigation_matrix", [])
        for r_idx, r in enumerate(matrix_rows, start=4):
            is_subtotal = r.get("is_subtotal", False)
            ws_matrix.cell(row=r_idx, column=1, value=r.get("scan_type"))
            ws_matrix.cell(row=r_idx, column=2, value=r.get("severity_label"))
            ws_matrix.cell(row=r_idx, column=3, value=r.get("total", 0))
            ws_matrix.cell(row=r_idx, column=4, value=r.get("unmitigated", 0))
            ws_matrix.cell(row=r_idx, column=5, value=r.get("mitigation_proposed", 0))
            ws_matrix.cell(row=r_idx, column=6, value=r.get("mitigation_approved", 0))
            ws_matrix.cell(row=r_idx, column=7, value=r.get("mitigation_rejected", 0))
            ws_matrix.cell(row=r_idx, column=8, value=r.get("fixed_resolved", 0))

            for col in range(1, 9):
                c = ws_matrix.cell(row=r_idx, column=col)
                c.border = border_thin
                if is_subtotal:
                    c.fill = sub_fill
                    c.font = sub_font
                if col >= 3:
                    c.alignment = Alignment(horizontal="right")

        # ---------------- SHEET 3: All Reported Instances ----------------
        ws_flaws = wb.create_sheet(title="All Reported Instances")
        ws_flaws.views.sheetView[0].showGridLines = True

        instance_headers = [
            "Application Name",
            "Sandbox Name",
            "Sandbox GUID",
            "Module",
            "Issue ID",
            "Scan Type",
            "Severity",
            "Severity Label",
            "Category / Title",
            "CWE ID",
            "CWE Name",
            "CVE ID",
            "CVSS",
            "Description",
            "Mitigation Status",
            "Resolution Status",
            "First Found Date",
            "Target Location (File / Component)",
            "Line Number",
            "Component Version",
            "Remediation Advice"
        ]

        for c_idx, h_text in enumerate(instance_headers, start=1):
            cell = ws_flaws.cell(row=1, column=c_idx, value=h_text)
            cell.fill = header_fill
            cell.font = header_font

        for r_idx, f in enumerate(findings, start=2):
            location = f.get("file_path") or f.get("component_filename") or f.get("file_name") or ""
            module_name = f.get("module") or f.get("component_filename") or f.get("file_name") or "N/A"
            ws_flaws.cell(row=r_idx, column=1, value=f.get("application_name") or app_names_str)
            ws_flaws.cell(row=r_idx, column=2, value=f.get("sandbox_name") or "Sandbox")
            ws_flaws.cell(row=r_idx, column=3, value=f.get("sandbox_guid") or "")
            ws_flaws.cell(row=r_idx, column=4, value=module_name)
            ws_flaws.cell(row=r_idx, column=5, value=f.get("issue_id"))
            ws_flaws.cell(row=r_idx, column=6, value=f.get("scan_type"))
            ws_flaws.cell(row=r_idx, column=7, value=f.get("severity"))
            ws_flaws.cell(row=r_idx, column=8, value=f.get("severity_label"))
            ws_flaws.cell(row=r_idx, column=9, value=f.get("category"))
            ws_flaws.cell(row=r_idx, column=10, value=f.get("cwe_id"))
            ws_flaws.cell(row=r_idx, column=11, value=f.get("cwe_name"))
            ws_flaws.cell(row=r_idx, column=12, value=f.get("cve_id"))
            ws_flaws.cell(row=r_idx, column=13, value=f.get("cvss"))
            ws_flaws.cell(row=r_idx, column=14, value=f.get("description", ""))
            ws_flaws.cell(row=r_idx, column=15, value=f.get("mitigation_status", "Unmitigated"))
            ws_flaws.cell(row=r_idx, column=16, value=f.get("resolution_status", "UNRESOLVED"))
            ws_flaws.cell(row=r_idx, column=17, value=f.get("first_found_date", ""))
            ws_flaws.cell(row=r_idx, column=18, value=location)
            ws_flaws.cell(row=r_idx, column=19, value=f.get("line_number") or "")
            ws_flaws.cell(row=r_idx, column=20, value=f.get("version") or "")
            ws_flaws.cell(row=r_idx, column=21, value=f.get("remediation_advice", ""))

            for col in range(1, 22):
                ws_flaws.cell(row=r_idx, column=col).border = border_thin

        # ---------------- SHEET 4 & 5: SAST and SCA Filtered Tabs ----------------
        sast_findings = [f for f in findings if f.get("scan_type") == "SAST"]
        sca_findings = [f for f in findings if f.get("scan_type") == "SCA"]

        def populate_sub_sheet(title, subset_findings):
            ws_sub = wb.create_sheet(title=title)
            ws_sub.views.sheetView[0].showGridLines = True
            for c_idx, h_text in enumerate(instance_headers, start=1):
                cell = ws_sub.cell(row=1, column=c_idx, value=h_text)
                cell.fill = header_fill
                cell.font = header_font
            for r_idx, f in enumerate(subset_findings, start=2):
                loc = f.get("file_path") or f.get("component_filename") or f.get("file_name") or ""
                mod = f.get("module") or f.get("component_filename") or f.get("file_name") or "N/A"
                ws_sub.cell(row=r_idx, column=1, value=f.get("application_name") or app_names_str)
                ws_sub.cell(row=r_idx, column=2, value=f.get("sandbox_name") or "Sandbox")
                ws_sub.cell(row=r_idx, column=3, value=f.get("sandbox_guid") or "")
                ws_sub.cell(row=r_idx, column=4, value=mod)
                ws_sub.cell(row=r_idx, column=5, value=f.get("issue_id"))
                ws_sub.cell(row=r_idx, column=6, value=f.get("scan_type"))
                ws_sub.cell(row=r_idx, column=7, value=f.get("severity"))
                ws_sub.cell(row=r_idx, column=8, value=f.get("severity_label"))
                ws_sub.cell(row=r_idx, column=9, value=f.get("category"))
                ws_sub.cell(row=r_idx, column=10, value=f.get("cwe_id"))
                ws_sub.cell(row=r_idx, column=11, value=f.get("cwe_name"))
                ws_sub.cell(row=r_idx, column=12, value=f.get("cve_id"))
                ws_sub.cell(row=r_idx, column=13, value=f.get("cvss"))
                ws_sub.cell(row=r_idx, column=14, value=f.get("description", ""))
                ws_sub.cell(row=r_idx, column=15, value=f.get("mitigation_status", "Unmitigated"))
                ws_sub.cell(row=r_idx, column=16, value=f.get("resolution_status", "UNRESOLVED"))
                ws_sub.cell(row=r_idx, column=17, value=f.get("first_found_date", ""))
                ws_sub.cell(row=r_idx, column=18, value=loc)
                ws_sub.cell(row=r_idx, column=19, value=f.get("line_number") or "")
                ws_sub.cell(row=r_idx, column=20, value=f.get("version") or "")
                ws_sub.cell(row=r_idx, column=21, value=f.get("remediation_advice", ""))
                for col in range(1, 22):
                    ws_sub.cell(row=r_idx, column=col).border = border_thin

        populate_sub_sheet("SAST Flaws Only", sast_findings)
        populate_sub_sheet("SCA Vulnerabilities Only", sca_findings)

        # Auto-adjust column widths
        for sheet in wb.worksheets:
            for col in sheet.columns:
                max_len = 0
                col_letter = get_column_letter(col[0].column)
                for cell in col:
                    if cell.value:
                        val_str = str(cell.value)
                        if len(val_str) > 60:
                            val_str = val_str[:60]
                        max_len = max(max_len, len(val_str))
                sheet.column_dimensions[col_letter].width = max(max_len + 3, 11)

        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
        return output

    @staticmethod
    def generate_pdf(
        app_info: Union[Dict[str, Any], List[Dict[str, Any]]],
        sandboxes_info: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        metrics: Dict[str, Any]
    ) -> io.BytesIO:
        """
        Builds a landscape PDF report using ReportLab across multiple applications & sandboxes.
        """
        apps_list = ReportGenerator._normalize_apps_info(app_info)
        app_names_str = ", ".join(a.get("name", "N/A") for a in apps_list)

        output = io.BytesIO()
        doc = SimpleDocTemplate(
            output,
            pagesize=landscape(letter),
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=46
        )

        styles = getSampleStyleSheet()
        normal = styles["Normal"]
        normal.fontSize = 8
        normal.leading = 10

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=15,
            leading=18,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold"
        )

        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=6
        )

        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=normal,
            fontName="Helvetica-Bold",
            textColor=colors.white,
            fontSize=7.5,
            leading=9
        )

        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=normal,
            fontName="Helvetica",
            fontSize=7,
            leading=9
        )

        kpis = metrics.get("kpis", {})
        story = []

        # Title
        story.append(Paragraph("Veracode Multi-Application Sandbox Security Report", title_style))
        story.append(Paragraph(
            f"<b>Applications ({len(apps_list)}):</b> {app_names_str} &nbsp;|&nbsp; "
            f"<b>Generated:</b> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp; "
            f"<b>Scope:</b> Isolated Developer Sandboxes (Policy Scans Excluded)",
            normal
        ))
        story.append(Spacer(1, 10))

        # Selected Sandboxes Summary Table
        story.append(Paragraph("Selected Sandboxes & Latest Scan Statuses", section_style))
        sb_table_data = [[
            Paragraph("Application", table_header_style),
            Paragraph("Sandbox Name", table_header_style),
            Paragraph("Scan Status", table_header_style),
            Paragraph("Build ID", table_header_style),
            Paragraph("Version", table_header_style),
            Paragraph("Last Scan Date", table_header_style)
        ]]

        for sb in sandboxes_info:
            app_n = sb.get("application_name") or (apps_list[0].get("name") if len(apps_list) == 1 else "Application")
            sb_table_data.append([
                Paragraph(str(app_n), table_cell_style),
                Paragraph(str(sb.get("sandbox_name") or sb.get("name") or "Sandbox"), table_cell_style),
                Paragraph(str(sb.get("scan_status", "Results Ready")), table_cell_style),
                Paragraph(str(sb.get("build_id", "N/A")), table_cell_style),
                Paragraph(str(sb.get("version", "sandbox-latest")), table_cell_style),
                Paragraph(str(sb.get("last_scan_date", "N/A")), table_cell_style)
            ])

        sb_table = Table(sb_table_data, colWidths=[150, 160, 110, 70, 110, 120])
        sb_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white])
        ]))
        story.append(sb_table)
        story.append(Spacer(1, 10))

        # KPI Summary Table
        story.append(Paragraph("Executive Vulnerability KPI Summary", section_style))
        kpi_table_data = [
            [
                Paragraph("Applications", table_header_style),
                Paragraph("Sandboxes", table_header_style),
                Paragraph("Total Flaws", table_header_style),
                Paragraph("Critical & High", table_header_style),
                Paragraph("SAST Flaws", table_header_style),
                Paragraph("SCA Flaws", table_header_style),
                Paragraph("Unmitigated", table_header_style),
                Paragraph("Mitigated / Fixed", table_header_style)
            ],
            [
                Paragraph(str(len(apps_list)), table_cell_style),
                Paragraph(str(len(sandboxes_info)), table_cell_style),
                Paragraph(str(kpis.get("total_flaws", len(findings))), table_cell_style),
                Paragraph(str(kpis.get("critical_high", 0)), table_cell_style),
                Paragraph(str(kpis.get("sast_count", 0)), table_cell_style),
                Paragraph(str(kpis.get("sca_count", 0)), table_cell_style),
                Paragraph(str(kpis.get("unmitigated_count", 0)), table_cell_style),
                Paragraph(str(kpis.get("mit_approved_count", 0) + kpis.get("fixed_count", 0)), table_cell_style)
            ]
        ]
        kpi_table = Table(kpi_table_data, colWidths=[90, 90, 90, 90, 90, 90, 90, 90])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#334155")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold')
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 12))

        # Severity & Mitigation Status by Scan Type Matrix
        story.append(Paragraph("Tabular Matrix: Scan Type x Severity x Mitigation Status Data", section_style))
        matrix_table_data = [[
            Paragraph("Scan Type", table_header_style),
            Paragraph("Severity", table_header_style),
            Paragraph("Total", table_header_style),
            Paragraph("Unmitigated", table_header_style),
            Paragraph("Proposed", table_header_style),
            Paragraph("Approved", table_header_style),
            Paragraph("Rejected", table_header_style),
            Paragraph("Fixed", table_header_style)
        ]]

        matrix_rows = metrics.get("severity_mitigation_matrix", [])
        for r in matrix_rows:
            is_sub = r.get("is_subtotal", False)
            f_style = ParagraphStyle("SubStyle", parent=table_cell_style, fontName="Helvetica-Bold") if is_sub else table_cell_style
            matrix_table_data.append([
                Paragraph(str(r.get("scan_type")), f_style),
                Paragraph(str(r.get("severity_label")), f_style),
                Paragraph(str(r.get("total", 0)), f_style),
                Paragraph(str(r.get("unmitigated", 0)), f_style),
                Paragraph(str(r.get("mitigation_proposed", 0)), f_style),
                Paragraph(str(r.get("mitigation_approved", 0)), f_style),
                Paragraph(str(r.get("mitigation_rejected", 0)), f_style),
                Paragraph(str(r.get("fixed_resolved", 0)), f_style)
            ])

        m_table = Table(matrix_table_data, colWidths=[200, 110, 60, 70, 70, 70, 70, 70])
        m_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ALIGN', (2, 0), (-1, -1), 'RIGHT')
        ]))
        story.append(m_table)
        story.append(Spacer(1, 14))

        # Page break before granular flaw register
        story.append(PageBreak())

        # Granular Vulnerability Register Table
        story.append(Paragraph("Sandbox Vulnerability Register (All Reported Instances)", section_style))
        
        flaw_table_data = [[
            Paragraph("App", table_header_style),
            Paragraph("Sandbox", table_header_style),
            Paragraph("Module", table_header_style),
            Paragraph("Type", table_header_style),
            Paragraph("Sev", table_header_style),
            Paragraph("Category / Title", table_header_style),
            Paragraph("Mitigation Status", table_header_style),
            Paragraph("First Found", table_header_style),
            Paragraph("Location", table_header_style),
            Paragraph("Description", table_header_style)
        ]]

        for f in findings:
            loc = f.get("file_name") or f.get("component_filename") or "N/A"
            if f.get("line_number"):
                loc += f":{f.get('line_number')}"
            
            desc = str(f.get("description", ""))
            if len(desc) > 80:
                desc = desc[:80] + "..."

            first_found = str(f.get("first_found_date") or "")
            if "T" in first_found:
                first_found = first_found.split("T")[0]

            mod_val = str(f.get("module") or f.get("component_filename") or f.get("file_name") or "N/A")
            if len(mod_val) > 20:
                mod_val = mod_val[:20] + "..."

            flaw_table_data.append([
                Paragraph(str(f.get("application_name") or "App")[:16], table_cell_style),
                Paragraph(str(f.get("sandbox_name") or "Sandbox")[:18], table_cell_style),
                Paragraph(mod_val, table_cell_style),
                Paragraph(str(f.get("scan_type")), table_cell_style),
                Paragraph(str(f.get("severity_label")), table_cell_style),
                Paragraph(str(f.get("category")), table_cell_style),
                Paragraph(str(f.get("mitigation_status", "Unmitigated")), table_cell_style),
                Paragraph(first_found or "N/A", table_cell_style),
                Paragraph(loc, table_cell_style),
                Paragraph(desc, table_cell_style)
            ])

        flaw_table = Table(flaw_table_data, colWidths=[70, 75, 75, 34, 48, 100, 75, 55, 80, 108])
        flaw_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white])
        ]))
        story.append(flaw_table)

        doc.build(story, canvasmaker=NumberedCanvas)
        output.seek(0)
        return output

    @staticmethod
    def generate_xml(
        app_info: Union[Dict[str, Any], List[Dict[str, Any]]],
        sandboxes_info: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        metrics: Dict[str, Any]
    ) -> io.BytesIO:
        """
        Builds a structured XML document containing multi-app and sandbox scan telemetry.
        """
        apps_list = ReportGenerator._normalize_apps_info(app_info)

        root = ET.Element("veracode_sandbox_report")
        root.set("version", "2.0")
        root.set("generated_at", datetime.datetime.utcnow().isoformat() + "Z")
        root.set("generator", "Veracode-Sandbox-Tracker")

        # Applications node
        apps_parent = ET.SubElement(root, "applications")
        for a in apps_list:
            app_el = ET.SubElement(apps_parent, "application")
            app_el.set("name", str(a.get("name", "Unknown")))
            app_el.set("guid", str(a.get("guid", "")))
            app_el.set("business_criticality", str(a.get("business_criticality", "Not Specified")))

        # Sandboxes node
        sb_parent = ET.SubElement(root, "sandboxes")
        for sb in sandboxes_info:
            sb_el = ET.SubElement(sb_parent, "sandbox")
            sb_el.set("name", str(sb.get("sandbox_name") or sb.get("name") or "Sandbox"))
            sb_el.set("guid", str(sb.get("sandbox_guid") or sb.get("guid") or ""))
            sb_el.set("application_name", str(sb.get("application_name", "")))
            sb_el.set("scan_status", str(sb.get("scan_status", "Results Ready")))
            sb_el.set("build_id", str(sb.get("build_id", "")))
            sb_el.set("version", str(sb.get("version", "")))
            sb_el.set("last_scan_date", str(sb.get("last_scan_date", "")))

        # Metrics node
        metrics_el = ET.SubElement(root, "metrics")
        kpis = metrics.get("kpis", {})
        for k, v in kpis.items():
            kpi_el = ET.SubElement(metrics_el, "kpi")
            kpi_el.set("name", k)
            kpi_el.set("value", str(v))

        # Severity & Mitigation Matrix node
        matrix_el = ET.SubElement(root, "severity_mitigation_matrix")
        for r in metrics.get("severity_mitigation_matrix", []):
            row_el = ET.SubElement(matrix_el, "row")
            row_el.set("scan_type", str(r.get("scan_type")))
            row_el.set("severity", str(r.get("severity_label")))
            row_el.set("total", str(r.get("total", 0)))
            row_el.set("unmitigated", str(r.get("unmitigated", 0)))
            row_el.set("mitigation_proposed", str(r.get("mitigation_proposed", 0)))
            row_el.set("mitigation_approved", str(r.get("mitigation_approved", 0)))
            row_el.set("mitigation_rejected", str(r.get("mitigation_rejected", 0)))
            row_el.set("fixed_resolved", str(r.get("fixed_resolved", 0)))

        # Findings node
        findings_el = ET.SubElement(root, "findings")
        findings_el.set("total_count", str(len(findings)))

        for f in findings:
            fel = ET.SubElement(findings_el, "finding")
            fel.set("issue_id", str(f.get("issue_id", "")))
            fel.set("application_name", str(f.get("application_name", "")))
            fel.set("application_guid", str(f.get("application_guid", "")))
            fel.set("sandbox_name", str(f.get("sandbox_name", "Sandbox")))
            fel.set("sandbox_guid", str(f.get("sandbox_guid", "")))
            fel.set("module", str(f.get("module") or f.get("component_filename") or f.get("file_name") or ""))
            fel.set("scan_type", str(f.get("scan_type", "")))
            fel.set("severity", str(f.get("severity", "")))
            fel.set("severity_label", str(f.get("severity_label", "")))
            fel.set("category", str(f.get("category", "")))
            fel.set("mitigation_status", str(f.get("mitigation_status", "Unmitigated")))
            fel.set("resolution_status", str(f.get("resolution_status", "UNRESOLVED")))
            fel.set("first_found_date", str(f.get("first_found_date") or ""))
            fel.set("status", str(f.get("status", "OPEN")))

            mod_el = ET.SubElement(fel, "module")
            mod_el.set("name", str(f.get("module") or f.get("component_filename") or f.get("file_name") or ""))

            cwe_el = ET.SubElement(fel, "cwe")
            cwe_el.set("id", str(f.get("cwe_id") or ""))
            cwe_el.set("name", str(f.get("cwe_name") or ""))

            cve_el = ET.SubElement(fel, "cve")
            cve_el.set("id", str(f.get("cve_id") or ""))
            cve_el.set("cvss", str(f.get("cvss") or ""))

            loc_el = ET.SubElement(fel, "location")
            loc_el.set("file_path", str(f.get("file_path") or ""))
            loc_el.set("file_name", str(f.get("file_name") or ""))
            loc_el.set("line_number", str(f.get("line_number") or ""))
            loc_el.set("component_filename", str(f.get("component_filename") or ""))
            loc_el.set("version", str(f.get("version") or ""))

            desc_el = ET.SubElement(fel, "description")
            desc_el.text = str(f.get("description", ""))

            rem_el = ET.SubElement(fel, "remediation_advice")
            rem_el.text = str(f.get("remediation_advice", ""))

        xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        return io.BytesIO(xml_bytes)

report_generator = ReportGenerator()
