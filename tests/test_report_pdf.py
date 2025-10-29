"""
tests/test_report_pdf.py
Tests pour la génération de rapports PDF.
"""
import pytest
from pathlib import Path
import tempfile
import shutil
from core.database import create_session, add_scan, add_vulnerability, close_session, ensure_schema
from reporting.report_generator import generate_pdf, compute_risk_score, generate_executive_summary

class TestReportPDF:
    def setup_method(self):
        """Configurer la base de données de test."""
        ensure_schema()
        import uuid
        self.session_id = f"test_session_pdf_{uuid.uuid4().hex[:8]}"
        self.target = "example.com"

        # Create test session
        create_session(self.session_id, self.target, {"test": True})

        # Add test scan
        scan_id = add_scan(self.session_id, "recon", self.target, {"hosts_found": 1})

        # Add test vulnerabilities
        add_vulnerability(self.session_id, {
            "type": "xss",
            "severity": "high",
            "target": "http://example.com/search",
            "description": "Reflected XSS in search parameter"
        }, scan_id)

        add_vulnerability(self.session_id, {
            "type": "sqli",
            "severity": "critical",
            "target": "http://example.com/login",
            "description": "SQL injection in login form"
        }, scan_id)

        close_session(self.session_id, "completed")

    def test_compute_risk_score(self):
        """Tester le calcul du score de risque."""
        vulns = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"}
        ]
        score = compute_risk_score(vulns)
        assert score["score"] == 10  # 4+3+2+1
        assert score["percentage"] == 62.5  # 10/16 * 100
        assert score["level"] == "HIGH"
        assert score["counts"]["critical"] == 1

    def test_generate_executive_summary(self):
        """Tester la génération du résumé exécutif."""
        from core.database import get_session_results
        results = get_session_results(self.session_id)
        summary = generate_executive_summary(self.session_id, results)

        assert summary["session_id"] == self.session_id
        assert summary["target"] == self.target
        assert summary["total_vulnerabilities"] == 2
        assert summary["risk_score"]["level"] == "CRITICAL"  # 1 critical + 1 high = score 7, 7/8=87.5% >=75 -> CRITICAL
        assert len(summary["top_vulnerabilities"]) == 2
        assert len(summary["recommended_actions"]) > 0

    def test_generate_pdf(self):
        """Tester la génération PDF."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = generate_pdf(self.session_id, tmpdir)
            assert pdf_path is not None
            assert Path(pdf_path).exists()
            assert Path(pdf_path).stat().st_size > 0  # Non-empty file

    def teardown_method(self):
        """Nettoyer les données de test."""
        # Note : Dans les vrais tests, vous pourriez vouloir nettoyer la base de données
        pass
