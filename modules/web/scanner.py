"""
modules/web/scanner.py
Scanner heuristique de vulnérabilités web (MVP).
Vérifications sûres et non destructives :
 - detect_reflected_xss (amélioré)
 - detect_basic_sqli (injection de payload naïve)
 - detect_lfi (sondes de payload LFI communs)
 - scan_page(url, session) -> retourne un dictionnaire de découvertes

Notes :
 - Utiliser uniquement sur des cibles autorisées.
 - Utilise requests + BeautifulSoup (le crawler en dépend déjà).
"""
from typing import Dict, List
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import logging

logger = logging.getLogger(__name__)

# small payloads for testing (non-destructive)
_XSS_PAYLOADS = ['<xsstest>', '"><xsstest>', "'><xsstest>"]
_SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1 -- ", "\" OR \"1\"=\"1"]
_LFI_PAYLOADS = ["../../etc/passwd", "../../etc/passwd%00", "..\\..\\..\\..\\windows\\win.ini"]

DEFAULT_TIMEOUT = 5

def _find_forms(html: str) -> List[Dict]:
    """Trouver tous les formulaires dans le HTML."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        inputs = [i.get("name") for i in f.find_all(["input","textarea","select"]) if i.get("name")]
        forms.append({
            "action": f.get("action") or "",
            "method": (f.get("method") or "get").lower(),
            "inputs": inputs
        })
    return forms

def detect_reflected_xss(url: str, session: requests.Session = None, timeout:int=DEFAULT_TIMEOUT) -> Dict:
    """
    Détection XSS réfléchie améliorée avec test de paramètres complet et payloads améliorés.
    Retourne un résumé : {'url':..., 'payloads_tested':n, 'reflected': True/False, 'evidence':snippets}
    """
    s = session or requests.Session()
    findings = {"url": url, "payloads_tested": 0, "reflected": False, "evidence": []}

    # Enhanced XSS payloads
    xss_payloads = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert("xss")>',
        '"><script>alert("xss")</script>',
        "'><script>alert('xss')</script>",
        '<svg onload=alert("xss")>',
        '<iframe src=javascript:alert("xss")>',
        '<body onload=alert("xss")>',
        "' onmouseover=alert('xss') '",
        '<scr<script>ipt>alert("xss")</scr<script>ipt>'
    ]

    try:
        # Parse URL to get existing parameters
        parsed = urlparse(url)
        existing_params = {}
        if parsed.query:
            from urllib.parse import parse_qs
            existing_params = parse_qs(parsed.query)

        # Test each parameter with XSS payloads
        for param_name in existing_params.keys():
            for p in xss_payloads:
                findings["payloads_tested"] += 1
                test_params = existing_params.copy()
                test_params[param_name] = [p]

                try:
                    r = s.get(url, params=test_params, timeout=timeout)
                    if r is not None and p in r.text:
                        findings["reflected"] = True
                        findings["evidence"].append({
                            "type": "param",
                            "param": param_name,
                            "payload": p,
                            "snippet": r.text[:500]
                        })
                        return findings
                except Exception:
                    continue

        # Test with additional 'q' param if no existing params
        if not existing_params:
            for p in xss_payloads:
                findings["payloads_tested"] += 1
                try:
                    r = s.get(url, params={"q": p}, timeout=timeout)
                    if r is not None and p in r.text:
                        findings["reflected"] = True
                        findings["evidence"].append({
                            "type": "param",
                            "param": "q",
                            "payload": p,
                            "snippet": r.text[:500]
                        })
                        return findings
                except Exception:
                    continue

        # Test forms
        r = s.get(url, timeout=timeout)
        if not r:
            return findings
        forms = _find_forms(r.text)
        for form in forms:
            for p in xss_payloads:
                findings["payloads_tested"] += 1
                action = form["action"] or url
                if not action.startswith("http"):
                    action = urljoin(url, action)
                data = {name: p if i==0 else "test" for i,name in enumerate(form["inputs"])}
                try:
                    if form["method"] == "post":
                        rr = s.post(action, data=data, timeout=timeout)
                    else:
                        rr = s.get(action, params=data, timeout=timeout)
                    if rr is not None and p in rr.text:
                        findings["reflected"] = True
                        findings["evidence"].append({
                            "type": "form",
                            "payload": p,
                            "action": action,
                            "snippet": rr.text[:500]
                        })
                        return findings
                except Exception:
                    continue
    except Exception as e:
        logger.debug("detect_reflected_xss error: %s", e)
    return findings

def detect_basic_sqli(url: str, session: requests.Session = None, timeout:int=DEFAULT_TIMEOUT) -> Dict:
    """
    Détection SQLi naïve en injectant des payloads classiques et en cherchant des signatures d'erreur SQL
    ou un changement cohérent dans la longueur de réponse (très heuristique).
    Retourne un dictionnaire avec les découvertes, mais traiter comme heuristique uniquement.
    """
    s = session or requests.Session()
    errors_signatures = ["you have an error in your SQL syntax", "sql syntax", "mysql_fetch", "ORA-"]
    findings = {"url": url, "payloads_tested": 0, "likely_sqli": False, "evidence": []}
    try:
        # test GET param 'q'
        for p in _SQLI_PAYLOADS:
            findings["payloads_tested"] += 1
            try:
                r = s.get(url, params={"q": p}, timeout=timeout)
                text = r.text if r else ""
                if any(sig.lower() in text.lower() for sig in errors_signatures):
                    findings["likely_sqli"] = True
                    findings["evidence"].append({"payload":p, "snippet": text[:800]})
                    return findings
            except Exception:
                continue
        # forms
        r = s.get(url, timeout=timeout)
        if not r:
            return findings
        forms = _find_forms(r.text)
        for form in forms:
            for p in _SQLI_PAYLOADS:
                findings["payloads_tested"] += 1
                action = form["action"] or url
                if not action.startswith("http"):
                    action = urljoin(url, action)
                data = {name: p if i==0 else "test" for i,name in enumerate(form["inputs"])}
                try:
                    if form["method"] == "post":
                        rr = s.post(action, data=data, timeout=timeout)
                    else:
                        rr = s.get(action, params=data, timeout=timeout)
                    text = rr.text if rr else ""
                    if any(sig.lower() in text.lower() for sig in errors_signatures):
                        findings["likely_sqli"] = True
                        findings["evidence"].append({"payload":p,"action":action,"snippet":text[:800]})
                        return findings
                except Exception:
                    continue
    except Exception as e:
        logger.debug("detect_basic_sqli error: %s", e)
    return findings

def detect_lfi(url: str, session: requests.Session = None, timeout:int=DEFAULT_TIMEOUT) -> Dict:
    """
    Test LFI heuristique : ajouter des payloads LFI communs aux paramètres de requête connus ou aux formulaires.
    Non destructif : ne cherche que des indicateurs de contenu de fichier communs comme 'root:' ou des marqueurs 'Windows'.
    """
    s = session or requests.Session()
    indicators = ["root:x", "[boot loader]","[fonts]","Windows"]
    findings = {"url":url, "payloads_tested":0, "likely_lfi":False, "evidence":[]}
    try:
        # test basic param
        for p in _LFI_PAYLOADS:
            findings["payloads_tested"] += 1
            try:
                r = s.get(url, params={"file": p}, timeout=timeout)
                text = r.text if r else ""
                if any(ind in text for ind in indicators):
                    findings["likely_lfi"] = True
                    findings["evidence"].append({"payload":p,"snippet":text[:800]})
                    return findings
            except Exception:
                continue
        # forms
        r = s.get(url, timeout=timeout)
        if not r:
            return findings
        forms = _find_forms(r.text)
        for form in forms:
            for p in _LFI_PAYLOADS:
                findings["payloads_tested"] += 1
                action = form["action"] or url
                if not action.startswith("http"):
                    action = urljoin(url, action)
                data = {name: p if i==0 else "test" for i,name in enumerate(form["inputs"])}
                try:
                    if form["method"] == "post":
                        rr = s.post(action, data=data, timeout=timeout)
                    else:
                        rr = s.get(action, params=data, timeout=timeout)
                    text = rr.text if rr else ""
                    if any(ind in text for ind in indicators):
                        findings["likely_lfi"] = True
                        findings["evidence"].append({"payload":p,"action":action,"snippet":text[:800]})
                        return findings
                except Exception:
                    continue
    except Exception as e:
        logger.debug("detect_lfi error: %s", e)
    return findings

def scan_page(url: str, session: requests.Session = None, timeout:int=DEFAULT_TIMEOUT) -> Dict:
    """
    Exécuter les heuristiques sur une seule page et retourner les résultats agrégés.
    """
    s = session or requests.Session()
    res = {"url": url, "xss": None, "sqli": None, "lfi": None}
    try:
        res["xss"] = detect_reflected_xss(url, session=s, timeout=timeout)
        res["sqli"] = detect_basic_sqli(url, session=s, timeout=timeout)
        res["lfi"] = detect_lfi(url, session=s, timeout=timeout)
    except Exception as e:
        logger.debug("scan_page exception: %s", e)
    return res
