"""
modules/web/crawler.py
Simple web crawler + naive vulnerability checks (MVP).
This file does NOT reference any 'tp_sources' package.
It uses requests and BeautifulSoup if available, otherwise falls back gracefully.
"""

import importlib
import time
from urllib.parse import urljoin

# Prefer local helper modules if they exist at project root (by simple names),
# but do NOT require any 'tp_sources' package.
def _module_available(name):
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        # importlib.util may not be available in some edge envs; fallback:
        try:
            import pkgutil
            return pkgutil.find_loader(name) is not None
        except Exception:
            return False

# Try to detect optional helpers that might be present at project root
_HAS_REQUESTS_ADV = _module_available("requests_advanced")
_HAS_URL_HELPER = _module_available("url_checker")

# Always import the standard requests (it should be in requirements)
import requests
try:
    from bs4 import BeautifulSoup
    _BS_AVAILABLE = True
except Exception:
    _BS_AVAILABLE = False

DEFAULT_TIMEOUT = 5.0

def fetch(url, session=None, timeout=DEFAULT_TIMEOUT):
    s = session or requests.Session()
    try:
        r = s.get(url, timeout=timeout)
        return r
    except Exception:
        return None

def extract_links(html, base_url):
    if not _BS_AVAILABLE:
        return []
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        links.add(urljoin(base_url, a["href"]))
    return list(links)

def find_forms(html):
    if not _BS_AVAILABLE:
        return []
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        forms.append({
            "action": f.get("action"),
            "method": f.get("method", "get"),
            "inputs": [i.get("name") for i in f.find_all("input") if i.get("name")]
        })
    return forms

def detect_reflected_xss(url, session=None, timeout=DEFAULT_TIMEOUT):
    """
    Very naive reflected XSS check:
    - injects a tiny payload in parameter 'q' and sees if reflected.
    NOTE: This is a heuristic for educational purposes only.
    """
    payload = "<xsstest>"
    try:
        s = session or requests.Session()
        r = s.get(url, params={"q": payload}, timeout=timeout)
        return r is not None and payload in r.text
    except Exception:
        return False

def crawl(target, depth=1, session=None, max_pages=50):
    """
    Crawl starting from `target`. depth is number of link layers to follow.
    Returns a dict with summary: pages_scanned, forms_found, duration_s.
    """
    start = time.time()
    s = session or requests.Session()
    to_visit = [target]
    visited = set()
    pages = []
    forms_total = 0
    current_depth = depth
    # Simple breadth-limited crawl
    while to_visit and current_depth >= 0:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        r = fetch(url, s)
        if not r:
            continue
        pages.append({"url": url, "status": r.status_code})
        html = r.text
        forms = find_forms(html)
        forms_total += len(forms)
        # Naive XSS detection (educational)
        _ = detect_reflected_xss(url, session=s)
        # Enqueue new links (bounded by max_pages)
        links = extract_links(html, url)
        for l in links:
            if l not in visited and len(visited) + len(to_visit) < max_pages:
                to_visit.append(l)
        current_depth -= 1
    duration = time.time() - start
    return {"target": target, "pages_scanned": len(pages), "forms_found": forms_total, "duration_s": round(duration, 2)}
