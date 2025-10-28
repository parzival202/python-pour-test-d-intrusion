"""
modules/reconnaissance/passive.py
Lightweight passive reconnaissance aggregator.
Combines basic_host_info and optional whois/cert info into one summary.
Non-intrusive.
"""

from . import osint
import ssl, socket
from urllib.parse import urlparse
import json
import logging

logger = logging.getLogger(__name__)

def tls_cert_info(host: str, port: int = 443, timeout: float = 3.0):
    """
    Retrieve TLS certificate info (subject, issuer) if the host supports TLS.
    Non-blocking short timeout.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', ())) if cert else {}
                issuer = dict(x[0] for x in cert.get('issuer', ())) if cert else {}
                return {"subject": subject, "issuer": issuer}
    except Exception as e:
        logger.debug("tls_cert_info error: %s", e)
        return None

def passive_aggregate(target: str):
    """
    Aggregate:
     - basic host info (from osint.basic_host_info)
     - whois (if available)
     - tls cert (if available)
    Returns a dict.
    """
    agg = {}
    try:
        agg["host_info"] = osint.basic_host_info(target)
        who = osint.whois_lookup(target)
        agg["whois"] = who
        # try tls info if target looks like a hostname or ip
        host = target.split(":")[0]
        cert = tls_cert_info(host)
        agg["tls_cert"] = cert
    except Exception as e:
        logger.debug("passive_aggregate error: %s", e)
    return agg
