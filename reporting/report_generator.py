"""
reporting/report_generator.py
Générateur de rapport HTML enrichi pour le projet.
Usage:
  from reporting.report_generator import generate_combined_report
  generate_combined_report(network_json_path='network_report.json',
                           web_json_path='web_report.json',
                           out_html='report.html')
"""

import json
from pathlib import Path
from datetime import datetime
import html

def _load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return None

def _format_table(rows, headers):
    th = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    trs = []
    for row in rows:
        tds = "".join(f"<td>{html.escape(str(row.get(h,'')))}</td>" for h in headers)
        trs.append(f"<tr>{tds}</tr>")
    return f"<table border='1' cellpadding='6' style='border-collapse:collapse'><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table>"

def _summary_from_network(net):
    if not net:
        return {"hosts_count": 0, "hosts": []}
    hosts = net.get("hosts_alive", []) or []
    hosts_info = net.get("hosts_info", {}) or {}
    hosts_summary = []
    for h in hosts:
        ports = hosts_info.get(h, {}).get("ports", {})
        open_ports = [str(p) for p, v in (ports.items() if isinstance(ports, dict) else []) if v]
        hosts_summary.append({"host": h, "open_ports": ", ".join(open_ports)})
    return {"hosts_count": len(hosts), "hosts": hosts_summary, "meta": net.get("meta", {})}

def _summary_from_web(web):
    if not web:
        return {"pages_scanned": 0, "forms_found": 0, "pages": []}
    pages = web.get("pages_scanned", 0)
    forms = web.get("forms_found", 0)
    return {"pages_scanned": pages, "forms_found": forms, "meta": web.get("duration_s", None)}

def generate_combined_report(network_json_path=None, web_json_path=None, out_html='report.html'):
    net = _load_json(network_json_path) if network_json_path and Path(network_json_path).exists() else None
    web = _load_json(web_json_path) if web_json_path and Path(web_json_path).exists() else None

    net_sum = _summary_from_network(net)
    web_sum = _summary_from_web(web)

    title = "Scan Report"
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html_parts = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'><title>{}</title>".format(html.escape(title)),
        "<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px} h1{color:#222} .card{border:1px solid #ddd;padding:12px;margin:8px 0;border-radius:6px} table{width:100%} th{background:#f4f4f4;text-align:left}</style>",
        "</head><body>",
        f"<h1>{html.escape(title)}</h1>",
        f"<p><strong>Generated:</strong> {now}</p>",
    ]

    # Executive summary
    html_parts.append("<div class='card'><h2>Executive summary</h2>")
    html_parts.append("<ul>")
    if net:
        html_parts.append(f"<li>Network targets: <strong>{html.escape(str(net.get('target','')))}</strong></li>")
        html_parts.append(f"<li>Hosts discovered: <strong>{net_sum['hosts_count']}</strong></li>")
    if web:
        html_parts.append(f"<li>Web target: <strong>{html.escape(str(web.get('target','')))}</strong></li>")
        html_parts.append(f"<li>Pages scanned: <strong>{web_sum['pages_scanned']}</strong></li>")
        html_parts.append(f"<li>Forms found: <strong>{web_sum['forms_found']}</strong></li>")
    html_parts.append("</ul></div>")

    # Network details
    html_parts.append("<div class='card'><h2>Network - details</h2>")
    if net and net_sum['hosts_count']>0:
        headers = ["host", "open_ports"]
        html_parts.append(_format_table(net_sum["hosts"], headers))
    else:
        html_parts.append("<p>No network data available.</p>")
    html_parts.append("</div>")

    # Web details
    html_parts.append("<div class='card'><h2>Web - details</h2>")
    if web:
        # show pages scanned and forms count
        html_parts.append(f"<p>Pages scanned: <strong>{web_sum['pages_scanned']}</strong></p>")
        html_parts.append(f"<p>Forms found: <strong>{web_sum['forms_found']}</strong></p>")
        # include small JSON dump
        html_parts.append("<h3>Raw web output (excerpt)</h3>")
        json_excerpt = html.escape(json.dumps(web, indent=2)[:4000])
        html_parts.append(f"<pre style='max-height:400px;overflow:auto;background:#f8f8f8;padding:8px'>{json_excerpt}</pre>")
    else:
        html_parts.append("<p>No web data available.</p>")
    html_parts.append("</div>")

    # meta / footer
    html_parts.append("<div class='card'><h2>Metadata</h2>")
    meta_rows = []
    if net and isinstance(net.get("_meta"), dict):
        meta_rows.append({"key":"network_session", "val": str(net.get("_meta"))})
    if web and isinstance(web.get("_meta"), dict):
        meta_rows.append({"key":"web_session", "val": str(web.get("_meta"))})
    meta_rows.append({"key":"report_generated_at", "val": now})
    html_parts.append(_format_table(meta_rows, ["key","val"]))
    html_parts.append("</div>")

    html_parts.append("<p>Notes: This report is generated for educational/demo purposes. Only test on authorized targets.</p>")
    html_parts.append("</body></html>")

    outpath = Path(out_html)
    outpath.write_text("\n".join(html_parts), encoding='utf-8')
    return str(outpath)
