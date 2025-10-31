"""
Quick scan driver used by the assistant to run a quick network + web probe for a single target.
Saves output to results/quick_scan_<target>_<timestamp>.json
"""
import json
import time
import sys
from pathlib import Path

# Ensure project root on sys.path so package imports work when running as script
proj_root = Path(__file__).resolve().parents[1]
if str(proj_root) not in sys.path:
    sys.path.insert(0, str(proj_root))

from modules.network.scanner import scan_target
from modules.web.scanner import scan_page

TARGET = 'http://192.168.111.128'
# derive IP for network scanner
ip = '192.168.111.128'

out = {
    'target': TARGET,
    'timestamp': time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()),
    'network': None,
    'web': None,
}

print(f"Starting quick scan for {TARGET}")
# run network scan (probe port 80)
net = scan_target(ip, threads=10, timeout=1.5, nmap_args=None, probe_port=80)
out['network'] = net

# if port 80 appears open on the host, scan web page
ports = net.get('hosts_info', {}).get(ip, {}).get('ports', {})
if ports and ports.get(80):
    print(f"Port 80 open on {ip}, scanning HTTP page")
    webres = scan_page(TARGET, timeout=5)
    out['web'] = webres
else:
    print(f"Port 80 not reported open for {ip} or host not found; attempting HTTP request anyway")
    try:
        webres = scan_page(TARGET, timeout=5)
        out['web'] = webres
    except Exception as e:
        out['web'] = {'error': str(e)}

# save results
p = Path('results')
p.mkdir(parents=True, exist_ok=True)
fn = p / f"quick_scan_{ip.replace('.','_')}_{out['timestamp']}.json"
fn.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf-8')
print(f"Saved results to {fn}")
print(json.dumps(out, indent=2, ensure_ascii=False))
