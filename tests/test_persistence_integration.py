import time
import uuid
from core import database


def test_persist_result_creates_rows():
    """Integration test: persist_result should insert scans, vulnerabilities and exploitations."""
    # Ensure schema is present
    database.ensure_schema()

    session_id = f"test_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    target = "127.0.0.1"
    cfg = {"test": True}

    # Create session
    db_sid = database.create_session(session_id, target, cfg)
    assert db_sid is not None

    # Build a result dict that contains a scan, vulnerabilities list and exploitations
    result = {
        "scan_type": "nmap",
        "target": target,
        "results": {
            "hosts_alive": [target],
            "meta": {"duration_s": 0.01}
        },
        "vulnerabilities": [
            {"type": "sqli", "severity": "HIGH", "target": target, "description": "test sqli"}
        ],
        "exploitations": [
            {"type": "sql_exploit", "success": False, "command": "echo test", "output": ""}
        ]
    }

    # Persist
    summary = database.persist_result(session_id, result)

    # Basic assertions on returned summary
    assert isinstance(summary, dict)
    assert len(summary.get('scans', [])) >= 1
    assert len(summary.get('vulnerabilities', [])) >= 1
    assert len(summary.get('exploitations', [])) >= 1

    # Verify via DB readers
    scans = database.get_scans_by_session(session_id)
    vulns = database.get_vulnerabilities_by_session(session_id)
    exploits = database.get_exploitations_by_session(session_id)

    assert any(s['target'] == target for s in scans)
    assert any(v['vuln_type'] == 'sqli' for v in vulns)
    assert len(exploits) >= 1
