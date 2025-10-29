"""
modules/reconnaissance/passive.py
Comprehensive passive reconnaissance aggregator.
Combines OSINT, TLS certificate analysis, and metadata extraction.
Non-intrusive and safe for all targets.
"""

from . import osint
import ssl
import socket
from urllib.parse import urlparse
import json
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Import database functions
try:
    from core.database import add_scan, add_vulnerability
except ImportError:
    def add_scan(*args, **kwargs): return None
    def add_vulnerability(*args, **kwargs): return None

def tls_cert_info(host: str, port: int = 443, timeout: float = 3.0) -> Optional[Dict]:
    """
    Retrieve comprehensive TLS certificate information.
    Includes subject, issuer, validity dates, and SAN (Subject Alternative Names).
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # For passive recon, don't verify

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None

                # Extract certificate details
                subject = dict(x[0] for x in cert.get('subject', ()))
                issuer = dict(x[0] for x in cert.get('issuer', ()))

                # Get SAN (Subject Alternative Names)
                san = []
                try:
                    san_extension = cert.get('subjectAltName', [])
                    san = [name[1] for name in san_extension if len(name) > 1]
                except Exception:
                    pass

                return {
                    "subject": subject,
                    "issuer": issuer,
                    "version": cert.get('version'),
                    "serial_number": str(cert.get('serialNumber', '')),
                    "not_before": cert.get('notBefore'),
                    "not_after": cert.get('notAfter'),
                    "subject_alt_names": san,
                    "signature_algorithm": cert.get('signatureAlgorithm'),
                    "public_key_bits": len(cert.get('publicKey', {}).get('publicKey', b'')) * 8 if 'publicKey' in cert else None
                }
    except Exception as e:
        logger.debug("tls_cert_info error for %s:%d: %s", host, port, e)
        return None

def http_headers_info(url: str, timeout: float = 5.0) -> Optional[Dict]:
    """
    Extract HTTP headers and basic metadata from URL.
    Passive: only makes HEAD request to minimize impact.
    """
    try:
        import requests
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "url": response.url,  # Final URL after redirects
            "server": response.headers.get('Server'),
            "content_type": response.headers.get('Content-Type'),
            "content_length": response.headers.get('Content-Length'),
            "last_modified": response.headers.get('Last-Modified'),
            "etag": response.headers.get('ETag'),
            "powered_by": response.headers.get('X-Powered-By')
        }
    except Exception as e:
        logger.debug("http_headers_info error for %s: %s", url, e)
        return None

def passive_aggregate(target: str) -> Dict:
    """
    Comprehensive passive reconnaissance aggregation.
    Includes:
    - Basic host information
    - DNS enumeration (if domain)
    - WHOIS data
    - TLS certificate analysis
    - HTTP headers (if applicable)
    - Subdomain enumeration
    """
    agg = {
        "target": target,
        "timestamp": osint.time.time(),
        "recon_type": "passive"
    }

    try:
        # Basic host information
        agg["host_info"] = osint.basic_host_info(target)

        # Domain-specific reconnaissance
        if '.' in target and not target.replace('.', '').isdigit():
            # DNS enumeration
            agg["dns_enumeration"] = osint.dns_enumeration(target)

            # WHOIS lookup
            agg["whois"] = osint.whois_lookup(target)

            # Subdomain probing
            agg["subdomains"] = osint.probe_subdomains(target)

            # TLS certificate analysis (try common ports)
            tls_ports = [443, 8443, 993, 995]  # HTTPS, alternative HTTPS, IMAPS, POP3S
            tls_info = {}
            for port in tls_ports:
                cert = tls_cert_info(target, port)
                if cert:
                    tls_info[str(port)] = cert
                    break  # Stop at first successful cert
            agg["tls_certificates"] = tls_info

            # HTTP headers for web targets
            http_info = {}
            schemes = ['https://', 'http://']
            for scheme in schemes:
                url = f"{scheme}{target}"
                headers = http_headers_info(url)
                if headers:
                    http_info[scheme.rstrip('://')] = headers
                    break  # Stop at first successful response
            agg["http_headers"] = http_info

        else:
            # IP address - limited reconnaissance
            agg["dns_enumeration"] = None
            agg["whois"] = None
            agg["subdomains"] = []
            agg["tls_certificates"] = {}
            agg["http_headers"] = {}

    except Exception as e:
        logger.debug("passive_aggregate error for %s: %s", target, e)
        agg["error"] = str(e)

    return agg

def generate_passive_report(target: str, output_path: Optional[str] = None, session_id: Optional[str] = None) -> Dict:
    """
    Generate a comprehensive passive reconnaissance report.
    Optionally save to JSON file and database.
    """
    report = passive_aggregate(target)

    # Add summary statistics
    summary = {
        "total_subdomains_found": len(report.get("subdomains", [])),
        "dns_records_found": sum(len(records) for records in report.get("dns_enumeration", {}).values() if isinstance(records, list)),
        "tls_certs_found": len(report.get("tls_certificates", {})),
        "http_endpoints_found": len(report.get("http_headers", {}))
    }
    report["summary"] = summary

    # Save scan results to database if session_id provided
    if session_id:
        try:
            scan_id = add_scan(session_id, "passive_recon", target, report)
            logger.info("Saved passive recon scan with ID: %s", scan_id)

            # Check for potential vulnerabilities from recon data
            vulnerabilities = []

            # Check for expired or soon-to-expire certificates
            tls_certs = report.get("tls_certificates", {})
            for port, cert in tls_certs.items():
                if cert and 'not_after' in cert:
                    try:
                        import datetime
                        expiry_date = datetime.datetime.strptime(cert['not_after'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.datetime.now()).days
                        if days_until_expiry < 30:
                            vuln = {
                                "type": "certificate_expiry",
                                "severity": "medium" if days_until_expiry < 7 else "low",
                                "target": f"{target}:{port}",
                                "description": f"TLS certificate expires in {days_until_expiry} days",
                                "details": {
                                    "port": port,
                                    "expiry_date": cert['not_after'],
                                    "days_remaining": days_until_expiry
                                }
                            }
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        logger.debug("Error parsing certificate expiry: %s", e)

            # Save any found vulnerabilities
            for vuln in vulnerabilities:
                vuln_id = add_vulnerability(session_id, vuln, scan_id)
                logger.info("Saved vulnerability with ID: %s", vuln_id)

        except Exception as e:
            logger.error("Failed to save scan results to database: %s", e)

    # Save to file if requested
    if output_path:
        osint.save_json(output_path, report)

    return report
