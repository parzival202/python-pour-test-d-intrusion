"""
reporting/report_generator.py
Générateur de rapport HTML enrichi pour le projet.
Utilisation :
  from reporting.report_generator import ReportGenerator
  rg = ReportGenerator(session_id="S1")
  rg.generate_all(formats=["html", "pdf"])
"""

import json
from pathlib import Path
from datetime import datetime
import html
import os
import tempfile
from core.database import get_session_results
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

class ReportGenerator:
    """Classe ReportGenerator pour générer des rapports."""

    def __init__(self, session_id, results_dir="reports"):
        self.session_id = session_id
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.results = get_session_results(session_id)
        if not self.results:
            raise ValueError(f"No results found for session {session_id}")

    def generate_all(self, formats=["html"]):
        """Générer tous les rapports dans les formats spécifiés."""
        output_files = {}
        if "html" in formats:
            output_files["html"] = self.generate_html()
        if "json" in formats:
            output_files["json"] = self.generate_json()
        if "pdf" in formats:
            output_files["pdf"] = self.generate_pdf()
        return output_files

    def generate_json(self):
        """Générer un rapport JSON."""
        json_path = self.results_dir / self.session_id / "report.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        return str(json_path)

    def generate_html(self):
        """Générer un rapport HTML."""
        summary = generate_executive_summary(self.session_id, self.results)
        html_path = self.results_dir / self.session_id / "report.html"
        html_path.parent.mkdir(parents=True, exist_ok=True)

        actions_html = "".join(f"<li>{action}</li>" for action in summary['recommended_actions'])
        vuln_rows = "".join(f"<tr><td>{v.get('vuln_type')}</td><td>{v.get('severity')}</td><td>{v.get('target')}</td><td>{v.get('description')}</td></tr>" for v in summary['top_vulnerabilities'])

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Penetration Test Report - {self.session_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .vulnerabilities {{ margin-top: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Penetration Test Report - Session {self.session_id}</h1>
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Target:</strong> {summary['target']}</p>
                <p><strong>Status:</strong> {summary['status']}</p>
                <p><strong>Risk Level:</strong> {summary['risk_score']['level']} ({summary['risk_score']['percentage']}%)</p>
                <p><strong>Total Vulnerabilities:</strong> {summary['total_vulnerabilities']}</p>
                <h3>Recommended Actions</h3>
                <ul>
                    {actions_html}
                </ul>
            </div>
            <div class="vulnerabilities">
                <h2>Vulnerabilities</h2>
                <table>
                    <tr><th>Type</th><th>Severity</th><th>Target</th><th>Description</th></tr>
                    {vuln_rows}
                </table>
            </div>
        </body>
        </html>
        """

        html_path.write_text(html_content, encoding='utf-8')
        return str(html_path)

    def generate_pdf(self):
        """Générer un rapport PDF."""
        summary = generate_executive_summary(self.session_id, self.results)

        pdf_path = self.results_dir / self.session_id / "report.pdf"
        pdf_path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        title = Paragraph(f"Penetration Test Report - Session {self.session_id}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))

        story.append(Paragraph("Executive Summary", styles['Heading1']))
        story.append(Spacer(1, 6))

        summary_text = f"""
        Target: {summary['target']}<br/>
        Session Status: {summary['status']}<br/>
        Start Time: {summary['start_time']}<br/>
        End Time: {summary['end_time']}<br/>
        Total Scans: {summary['total_scans']}<br/>
        Total Vulnerabilities: {summary['total_vulnerabilities']}<br/>
        Risk Level: {summary['risk_score']['level']} ({summary['risk_score']['percentage']}%)<br/>
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Recommended Actions", styles['Heading2']))
        for action in summary['recommended_actions']:
            story.append(Paragraph(f"• {action}", styles['Normal']))
        story.append(Spacer(1, 12))

        if summary['top_vulnerabilities']:
            story.append(Paragraph("Top Vulnerabilities", styles['Heading2']))
            vuln_data = [["Type", "Severity", "Target", "Description"]]
            for vuln in summary['top_vulnerabilities']:
                vuln_data.append([
                    vuln.get('vuln_type', ''),
                    vuln.get('severity', ''),
                    vuln.get('target', ''),
                    vuln.get('description', '')[:50] + "..." if len(vuln.get('description', '')) > 50 else vuln.get('description', '')
                ])

            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)

        doc.build(story)
        return str(pdf_path)

def _load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return None

def generate_combined_report(network_json_path=None, web_json_path=None, out_html='report.html', out_dir=None):
    net = _load_json(network_json_path) if network_json_path else None
    web = _load_json(web_json_path) if web_json_path else None

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html_content = f"<html><body><h1>PenTest Report</h1><p>Generated: {now}</p></body></html>"

    if out_dir:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        outpath = Path(out_dir) / out_html
    else:
        outpath = Path(out_html)

    outpath.write_text(html_content, encoding='utf-8')
    return str(outpath)

def compute_risk_score(vulns):
    """
    Calculer le score de risque à partir de la liste des vulnérabilités.
    Retourne un dictionnaire avec score, pourcentage, niveau et comptes.
    """
    if not vulns:
        return {"score": 0, "percentage": 0, "level": "LOW", "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}

    severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    total_score = 0
    for vuln in vulns:
        sev = vuln.get("severity", "low").lower()
        if sev in counts:
            counts[sev] += 1
            total_score += severity_weights[sev]

    max_possible = len(vulns) * 4  # assuming max critical
    percentage = (total_score / max_possible * 100) if max_possible > 0 else 0

    if percentage >= 75:
        level = "CRITICAL"
    elif percentage >= 50:
        level = "HIGH"
    elif percentage >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": total_score, "percentage": round(percentage, 1), "level": level, "counts": counts}

def generate_executive_summary(session_id, results):
    """
    Générer un dictionnaire de résumé exécutif pour la session.
    """
    session = results.get("session", {})
    vulns = results.get("vulnerabilities", [])
    scans = results.get("scans", [])

    risk = compute_risk_score(vulns)

    # Top 5 vulnerabilities by severity
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.get("severity", "low").lower(), 0), reverse=True)
    top_vulns = sorted_vulns[:5]

    # Recommended actions based on risk level
    actions = []
    if risk["level"] == "CRITICAL":
        actions = ["Immediate patching required", "Isolate affected systems", "Conduct forensic analysis"]
    elif risk["level"] == "HIGH":
        actions = ["Prioritize patching critical vulnerabilities", "Implement monitoring", "Review access controls"]
    elif risk["level"] == "MEDIUM":
        actions = ["Schedule patching within 30 days", "Enhance security controls", "Conduct regular scans"]
    else:
        actions = ["Maintain current security posture", "Continue regular monitoring", "Update policies as needed"]

    return {
        "session_id": session_id,
        "target": session.get("target", "unknown"),
        "start_time": session.get("start_time", ""),
        "end_time": session.get("end_time", ""),
        "status": session.get("status", "unknown"),
        "total_scans": len(scans),
        "total_vulnerabilities": len(vulns),
        "risk_score": risk,
        "top_vulnerabilities": top_vulns,
        "recommended_actions": actions
    }

def generate_pdf(session_id, out_dir='reports'):
    """
    Générer un rapport PDF pour la session.
    """
    try:
        results = get_session_results(session_id)
        if not results:
            raise ValueError(f"No results found for session {session_id}")

        summary = generate_executive_summary(session_id, results)

        # Create output directory
        out_path = Path(out_dir) / session_id
        out_path.mkdir(parents=True, exist_ok=True)
        pdf_path = out_path / "report.pdf"

        # PDF setup
        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title = Paragraph(f"Penetration Test Report - Session {session_id}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        story.append(Spacer(1, 6))

        summary_text = f"""
        Target: {summary['target']}<br/>
        Session Status: {summary['status']}<br/>
        Start Time: {summary['start_time']}<br/>
        End Time: {summary['end_time']}<br/>
        Total Scans: {summary['total_scans']}<br/>
        Total Vulnerabilities: {summary['total_vulnerabilities']}<br/>
        Risk Level: {summary['risk_score']['level']} ({summary['risk_score']['percentage']}%)<br/>
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 12))

        # Recommended Actions
        story.append(Paragraph("Recommended Actions", styles['Heading2']))
        for action in summary['recommended_actions']:
            story.append(Paragraph(f"• {action}", styles['Normal']))
        story.append(Spacer(1, 12))

        # Top Vulnerabilities
        if summary['top_vulnerabilities']:
            story.append(Paragraph("Top Vulnerabilities", styles['Heading2']))
            vuln_data = [["Type", "Severity", "Target", "Description"]]
            for vuln in summary['top_vulnerabilities']:
                vuln_data.append([
                    vuln.get('vuln_type', ''),
                    vuln.get('severity', ''),
                    vuln.get('target', ''),
                    vuln.get('description', '')[:50] + "..." if len(vuln.get('description', '')) > 50 else vuln.get('description', '')
                ])

            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)

        # Build PDF
        doc.build(story)
        return str(pdf_path)

    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None

def generate(session_id, formats=["html"], out_dir="reports"):
    """
    Générer des rapports dans les formats spécifiés.
    """
    results = get_session_results(session_id)
    if not results:
        return {"error": f"No results for session {session_id}"}

    output_files = {}

    if "html" in formats:
        # Generate HTML report
        html_path = Path(out_dir) / session_id / "report.html"
        html_path.parent.mkdir(parents=True, exist_ok=True)

        # Build HTML content
        summary = generate_executive_summary(session_id, results)
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Penetration Test Report - {session_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .vulnerabilities {{ margin-top: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Penetration Test Report - Session {session_id}</h1>
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Target:</strong> {summary['target']}</p>
                <p><strong>Status:</strong> {summary['status']}</p>
                <p><strong>Risk Level:</strong> {summary['risk_score']['level']} ({summary['risk_score']['percentage']}%)</p>
                <p><strong>Total Vulnerabilities:</strong> {summary['total_vulnerabilities']}</p>
                <h3>Recommended Actions</h3>
                <ul>
                    {"".join(f"<li>{action}</li>" for action in summary['recommended_actions'])}
                </ul>
            </div>
            <div class="vulnerabilities">
                <h2>Vulnerabilities</h2>
                <table>
                    <tr><th>Type</th><th>Severity</th><th>Target</th><th>Description</th></tr>
                    {"".join(f"<tr><td>{v.get('vuln_type')}</td><td>{v.get('severity')}</td><td>{v.get('target')}</td><td>{v.get('description')}</td></tr>" for v in summary['top_vulnerabilities'])}
                </table>
            </div>
        </body>
        </html>
        """

        html_path.write_text(html_content, encoding='utf-8')
        output_files["html"] = str(html_path)

    if "json" in formats:
        json_path = Path(out_dir) / session_id / "report.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        output_files["json"] = str(json_path)

    if "pdf" in formats:
        pdf_path = generate_pdf(session_id, out_dir)
        if pdf_path:
            output_files["pdf"] = pdf_path

    return output_files
