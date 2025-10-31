#!/usr/bin/env python3
"""
Point d'entrée amélioré pour le Penetration Testing Framework.

Utilisation (exemples) :
  python -m penetration_testing_framework.main recon --target example.com --osint
  python -m penetration_testing_framework.main network --target 10.0.0.0/24 --fast
  python -m penetration_testing_framework.main web --target https://example.com --crawl --scan
  python -m penetration_testing_framework.main report --session-id S1 --format html,json --outdir reports

Conception :
- sécurisé par défaut (les actions agressives nécessitent --force)
- fonction run(argv=None) exposée pour les tests programmatiques
- recherche les modules sous 'penetration_testing_framework.modules.*' puis 'modules.*'
"""
from __future__ import annotations
import argparse
import importlib
import json
import os
import sys
from datetime import datetime
from typing import Any, List, Optional
from datetime import datetime, timezone
from utils.file_utils import make_run_dir, save_json
from utils.json_utils import normalize_for_json
from core.logger import get_logger
import shlex

PACKAGE_PREFIX = "penetration_testing_framework"

# Importer les fonctions de base de données
try:
    from core.database import create_session, close_session, ensure_schema, persist_result
except ImportError:
    # Solution de secours si non disponible
    def create_session(*args, **kwargs): return None
    def close_session(*args, **kwargs): pass
    def ensure_schema(): pass
    persist_result = None

def try_import(module_path: str):
    """Essaie d'importer un module à partir du chemin donné."""
    try:
        return importlib.import_module(module_path)
    except Exception:
        return None

def load_config(path: Optional[str] = None) -> dict:
    """Charge la configuration à partir de fichiers ou utilise les valeurs par défaut."""
    cfg: dict = {}
    # essayer la configuration du package d'abord
    candidates = [
        f"{PACKAGE_PREFIX}.core.config",
        "core.config"
    ]
    for c in candidates:
        mod = try_import(c)
        if mod and hasattr(mod, "load_config"):
            try:
                return mod.load_config(path)
            except Exception:
                pass
    # solution de secours vers config.json local
    cand = path or os.path.join(os.getcwd(), "config.json")
    if os.path.exists(cand):
        try:
            with open(cand, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return cfg

def dispatch(module_candidates: List[str], func_name: str = "run", **kwargs) -> Any:
    """Essaie d'importer les modules candidats et appelle func_name(**kwargs) si présent."""
    # List of fallback function names to try when 'func_name' not present
    fallbacks = [func_name, 'scan_target', 'scan', 'scan_page', 'discover', 'discover_hosts', 'discover_and_list', 'run_all', 'main']
    for module_path in module_candidates:
        if not module_path:
            continue
        mod = try_import(module_path)
        if not mod:
            continue

        # try requested func_name first, then fallbacks
        import inspect
        for fname in fallbacks:
            if hasattr(mod, fname):
                func = getattr(mod, fname)
                try:
                    sig = None
                    try:
                        sig = inspect.signature(func)
                    except Exception:
                        sig = None

                    # If function accepts **kwargs, pass everything; otherwise filter to accepted params
                    filtered_kwargs = kwargs
                    if sig is not None:
                        params = sig.parameters
                        accepts_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
                        if not accepts_var_kw:
                            accepted = [p for p in params.keys() if p != 'self']
                            filtered_kwargs = {k: v for k, v in kwargs.items() if k in accepted}
                            # common mapping: if caller passed 'target' but function expects 'url' or 'ip' or 'host'
                            if 'target' in kwargs:
                                for alias in ('url', 'ip', 'host', 'address'):
                                    if alias in accepted and alias not in filtered_kwargs:
                                        filtered_kwargs[alias] = kwargs['target']
                                        break

                    return func(**filtered_kwargs)
                except TypeError:
                    # as a last resort, try calling with single dict arg if signature unknown
                    try:
                        return func(kwargs)
                    except Exception:
                        # give up on this callable and try the next fallback
                        break
                except Exception:
                    # propagate other exceptions to surface runtime errors from modules
                    raise
    return None

# ---- gestionnaires de commandes ----

def run_recon(args: argparse.Namespace, cfg: dict):
    """Exécute le module de reconnaissance en fonction des arguments."""
    session_id = cfg.get("session_id")
    if args.osint:
        candidates = [
            f"{PACKAGE_PREFIX}.modules.reconnaissance.osint",
            f"{PACKAGE_PREFIX}.modules.recon",
            "modules.reconnaissance.osint",
            "modules.recon",
        ]
        return dispatch(candidates, target=args.target, safe_mode=not args.force, session_id=session_id)
    # solution de secours passive
    candidates = [
        f"{PACKAGE_PREFIX}.modules.reconnaissance.passive",
        "modules.reconnaissance.passive"
    ]
    return dispatch(candidates, target=args.target, safe_mode=not args.force, session_id=session_id)

def run_network(args: argparse.Namespace, cfg: dict):
    """Exécute le module de scan réseau."""
    scan_type = "full" if args.full else ("fast" if args.fast else "default")
    ports = args.ports.split(",") if args.ports else None
    candidates = [
        f"{PACKAGE_PREFIX}.modules.network.scanner",
        "modules.network.scanner",
        "modules.network"
    ]
    results = dispatch(candidates, target=args.target, scan_type=scan_type, ports=ports, safe_mode=not args.force)
    if args.output and results is not None:
        # ensure JSON-serializable
        save_json(args.output, normalize_for_json(results))
    return results

def run_web(args: argparse.Namespace, cfg: dict):
    """Exécute les modules de crawling et de scan web si demandé."""
    results = {}
    # call crawler then scanner if requested
    if args.crawl:
        crawl_res = dispatch([f"{PACKAGE_PREFIX}.modules.web.crawler", "modules.web.crawler"],
                             target=args.target, depth=args.depth, safe_mode=not args.force)
        results['crawl'] = crawl_res
    if args.scan:
        scan_res = dispatch([f"{PACKAGE_PREFIX}.modules.web.scanner", "modules.web.scanner"],
                            target=args.target, safe_mode=not args.force)
        results['scan'] = scan_res
    if args.output and results:
        save_json(args.output, normalize_for_json(results))
    return results if results else True

def run_exploit(args: argparse.Namespace, cfg: dict):
    """Exécute le module d'exploitation spécifié."""
    module_name = args.module or "system.exploiter"
    candidates = [
        f"{PACKAGE_PREFIX}.modules.{module_name}",
        f"{PACKAGE_PREFIX}.modules.exploits.{args.module}" if args.module else "",
        f"modules.{module_name}"
    ]
    return dispatch(candidates, target=args.target, safe_mode=not args.force)

def run_report(args: argparse.Namespace, cfg: dict):
    """Génère un rapport basé sur l'ID de session."""
    rg = try_import(f"{PACKAGE_PREFIX}.reporting.report_generator") or try_import("reporting.report_generator") or try_import("reporting")
    if rg and hasattr(rg, "generate"):
        formats = args.format.split(",") if args.format else ["html"]
        return rg.generate(session_id=args.session_id, formats=formats, out_dir=args.outdir)
    print("[!] Report generator not found. Expected reporting.report_generator.generate()")
    return None

def run_config(args: argparse.Namespace, cfg: dict):
    """Gère l'affichage ou la modification de la configuration."""
    core_cfg = try_import(f"{PACKAGE_PREFIX}.core.config") or try_import("core.config")
    if args.show:
        print(json.dumps(cfg or {}, indent=2, ensure_ascii=False))
        if core_cfg and hasattr(core_cfg, "show"):
            try:
                core_cfg.show()
            except Exception:
                pass
        return cfg
    if args.set:
        # set expects KEY=VALUE entries
        cand = os.path.join(os.getcwd(), "config.json")
        for item in args.set:
            if "=" in item:
                k, v = item.split("=", 1)
                cfg[k] = v
        try:
            with open(cand, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            print("[*] Updated config written to", cand)
        except Exception as e:
            print("[!] Failed to write config:", e)
        return cfg
    return cfg

# ---- constructeur CLI ----

def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments pour l'interface en ligne de commande."""
    parser = argparse.ArgumentParser(prog="ptf", description="Penetration Testing Framework - CLI")
    # Global opt-out for persisting results into the DB
    parser.add_argument('--no-persist', action='store_true', help="Do not persist results to the database for this run")
    sub = parser.add_subparsers(dest="command", required=True)

    p_recon = sub.add_parser("recon", help="Modules de reconnaissance")
    p_recon.add_argument("--target", required=True)
    p_recon.add_argument("--osint", action="store_true")
    p_recon.add_argument("--output", help="Fichier ou répertoire de sortie pour les résultats (JSON)")
    p_recon.add_argument("--format", default="json", help="Format(s) de sortie, csv séparés (json,pdf)")
    p_recon.add_argument("--force", action="store_true")
    # allow placement of global flags after subcommand (user-friendly)
    p_recon.add_argument('--no-persist', action='store_true', help="Do not persist results to the database for this run")

    p_net = sub.add_parser("network", help="Scan réseau")
    p_net.add_argument("--target", required=True)
    p_net.add_argument("--ports", help="Comma separated ports (eg 22,80,443)")
    p_net.add_argument("--full", action="store_true", help="Full scan profile")
    p_net.add_argument("--fast", action="store_true", help="Fast scan profile")
    p_net.add_argument("--output", help="Fichier ou répertoire de sortie pour les résultats (JSON)")
    p_net.add_argument("--format", default="json", help="Format(s) de sortie, comma-separated (json,pdf)")
    p_net.add_argument("--force", action="store_true")
    p_net.add_argument('--no-persist', action='store_true', help="Do not persist results to the database for this run")

    p_web = sub.add_parser("web", help="Crawling et scan web")
    p_web.add_argument("--target", required=True)
    p_web.add_argument("--crawl", action="store_true")
    p_web.add_argument("--scan", action="store_true")
    p_web.add_argument("--depth", type=int, default=2)
    p_web.add_argument("--output", help="Fichier ou répertoire de sortie pour les résultats (JSON)")
    p_web.add_argument("--format", default="json", help="Format(s) de sortie, comma-separated (json,pdf)")
    p_web.add_argument("--force", action="store_true")
    p_web.add_argument('--no-persist', action='store_true', help="Do not persist results to the database for this run")

    p_exp = sub.add_parser("exploit", help="Exécuter un module d'exploitation (simulé)")
    p_exp.add_argument("--target", required=True)
    p_exp.add_argument("--module", help="Module name under modules/ to run (e.g., web_exploit)")
    p_exp.add_argument("--output", help="Fichier ou répertoire de sortie pour les résultats (JSON)")
    p_exp.add_argument("--format", default="json", help="Format(s) de sortie, comma-separated (json,pdf)")
    p_exp.add_argument("--force", action="store_true")
    p_exp.add_argument('--no-persist', action='store_true', help="Do not persist results to the database for this run")

    p_rep = sub.add_parser("report", help="Générer un rapport")
    p_rep.add_argument("--session-id", required=True)
    p_rep.add_argument("--format", default="html", help="Comma-separated formats (html,json,pdf)")
    p_rep.add_argument("--outdir", default="reports")
    p_rep.add_argument('--no-persist', action='store_true', help="Do not persist results to the database for this run")

    p_cfg = sub.add_parser("config", help="Afficher ou définir la configuration")
    p_cfg.add_argument("--show", action="store_true")
    p_cfg.add_argument("--set", nargs="*", help="Set key=value pairs", default=[])
    p_cfg.add_argument('--no-persist', action='store_true', help="Do not persist results to the database for this run")

    p_all = sub.add_parser("all", help="Exécuter le pipeline complet")
    p_all.add_argument("--target", required=True)
    p_all.add_argument("--quick", action="store_true")
    p_all.add_argument("--output", help="Répertoire de sortie pour les résultats agrégés")
    p_all.add_argument("--format", default="json", help="Format(s) de sortie pour 'all' (json,pdf)")
    p_all.add_argument("--force", action="store_true")
    p_all.add_argument('--no-persist', action='store_true', help="Do not persist results to the database for this run")

    return parser

def print_results(results: Any, command: str):
    """
    Imprime les résultats formatés sur la console en fonction du type de commande.
    """
    if not results:
        print("❌ No results to display")
        return

    print(f"\n{'='*60}")
    print(f"🔍 {command.upper()} RESULTS")
    print(f"{'='*60}\n")

    if command == "recon":
        print_recon_results(results)
    elif command == "network":
        print_network_results(results)
    elif command == "web":
        print_web_results(results)
    elif command == "exploit":
        print_exploit_results(results)
    elif command == "config":
        print_config_results(results)
    else:
        # Generic result display
        if isinstance(results, dict):
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            print(results)


def _write_json_output(results: Any, out_path: str):
    """Écrit les résultats en JSON dans out_path (fichier)."""
    try:
        from pathlib import Path
        p = Path(out_path)
        if p.is_dir():
            # choisir un nom de fichier par défaut
            p = p / "results.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"[*] Results written to {p}")
        return str(p)
    except Exception as e:
        print(f"[!] Failed to write JSON output: {e}")
        return None


def _try_generate_pdf_from_session(session_id: str, out_dir: str = "reports") -> Optional[str]:
    """Essaye de générer un PDF via le reporting generator si disponible et retourne le chemin."""
    rg = try_import(f"{PACKAGE_PREFIX}.reporting.report_generator") or try_import("reporting.report_generator") or try_import("reporting")
    if not rg:
        print("[!] Report generator not available for PDF generation")
        return None
    try:
        out = rg.generate(session_id=session_id, formats=["pdf"], out_dir=out_dir)
        if isinstance(out, dict) and out.get("pdf"):
            return out.get("pdf")
        # Some generators return path string
        return out
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")
        return None

def print_recon_results(results: Any):
    """Imprime les résultats de reconnaissance."""
    if isinstance(results, dict):
        if 'error' in results:
            print(f"❌ Error: {results['error']}")
            return

        if 'summary' in results:
            summary = results['summary']
            print("📊 SUMMARY:")
            print(f"   Subdomains found: {summary.get('total_subdomains_found', 0)}")
            print(f"   DNS records: {summary.get('dns_records_found', 0)}")
            print(f"   TLS certificates: {summary.get('tls_certs_found', 0)}")
            print(f"   HTTP endpoints: {summary.get('http_endpoints_found', 0)}")
            print()

        if 'host_info' in results and results['host_info']:
            print("🏠 HOST INFO:")
            print(f"   {results['host_info']}")
            print()

        if 'whois' in results and results['whois']:
            print("📋 WHOIS: Available")
            print()

        if 'subdomains' in results and results['subdomains']:
            print(f"🌐 SUBDOMAINS ({len(results['subdomains'])} found):")
            for subdomain in results['subdomains'][:10]:  # Show first 10
                print(f"   - {subdomain}")
            if len(results['subdomains']) > 10:
                print(f"   ... and {len(results['subdomains']) - 10} more")
            print()

        if 'dns_records' in results and results['dns_records']:
            print("🔍 DNS RECORDS:")
            for record_type, records in results['dns_records'].items():
                print(f"   {record_type}: {len(records)} records")
            print()

    else:
        print(f"✅ Reconnaissance completed: {results}")

def print_network_results(results: Any):
    """Imprime les résultats de scan réseau."""
    if isinstance(results, dict):
        if 'error' in results:
            print(f"❌ Error: {results['error']}")
            return

        hosts = results.get('hosts_alive', [])
        print(f"🖥️  ALIVE HOSTS: {len(hosts)}")
        for host in hosts[:10]:  # Show first 10
            print(f"   - {host}")
        if len(hosts) > 10:
            print(f"   ... and {len(hosts) - 10} more")
        print()

        if 'hosts_info' in results:
            print("📋 HOST DETAILS:")
            for ip, info in results['hosts_info'].items():
                ports = info.get('ports', {})
                open_ports = [p for p, is_open in ports.items() if is_open]
                print(f"   {ip}: {len(open_ports)} open ports {open_ports}")
            print()

        if 'meta' in results:
            meta = results['meta']
            print("⏱️  SCAN METADATA:")
            print(f"   Duration: {meta.get('duration_s', 0):.2f}s")
            print(f"   Threads: {meta.get('threads', 0)}")
            print(f"   Timeout: {meta.get('timeout', 0)}s")
            print()

        if 'nmap_raw' in results and results['nmap_raw']:
            print("🔍 NMAP RESULTS:")
            for ip, output in results['nmap_raw'].items():
                if output:
                    print(f"   {ip}: Scan completed")
                else:
                    print(f"   {ip}: No results")
            print()

    else:
        print(f"✅ Network scan completed: {results}")

def print_web_results(results: Any):
    """Imprime les résultats de scan web."""
    if isinstance(results, dict):
        if 'error' in results:
            print(f"❌ Error: {results['error']}")
            return

        if 'url' in results:
            print(f"🌐 TARGET: {results['url']}")
            print(f"   Status: {results.get('status', 'unknown')}")
            print()

        if 'forms' in results and results['forms']:
            print(f"📝 FORMS FOUND: {len(results['forms'])}")
            for i, form in enumerate(results['forms'][:3]):  # Show first 3
                print(f"   Form {i+1}: {form.get('action', 'N/A')} ({form.get('method', 'get')})")
            if len(results['forms']) > 3:
                print(f"   ... and {len(results['forms']) - 3} more forms")
            print()

        if 'vulnerabilities' in results:
            vulns = results['vulnerabilities']
            print("🔒 VULNERABILITY SCAN:")
            vuln_types = {
                'xss': ('💉 XSS', 'reflected'),
                'sqli': ('🗃️  SQLi', 'likely_sqli'),
                'lfi': ('📁 LFI', 'likely_lfi'),
                'rfi': ('📤 RFI', 'vulnerable'),
                'command_injection': ('⚡ CMD INJ', 'vulnerable')
            }

            total_vulns = 0
            for vuln_key, (emoji_name, vuln_field) in vuln_types.items():
                if vuln_key in vulns and vulns[vuln_key]:
                    vuln_data = vulns[vuln_key]
                    is_vuln = vuln_data.get(vuln_field, False)
                    status = "❌ VULNERABLE" if is_vuln else "✅ SAFE"
                    payloads = vuln_data.get('payloads_tested', 0)
                    print(f"   {emoji_name}: {status} ({payloads} payloads tested)")
                    if is_vuln:
                        total_vulns += 1
            print(f"\n   📊 TOTAL VULNERABILITIES: {total_vulns}")
            print()

        if 'summary' in results:
            summary = results['summary']
            print("📈 SCAN SUMMARY:")
            print(f"   Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            print(f"   Scan timestamp: {summary.get('scan_time', 'N/A')}")
            print()

    else:
        print(f"✅ Web scan completed: {results}")

def print_exploit_results(results: Any):
    """Imprime les résultats d'exploitation."""
    if isinstance(results, dict):
        if 'error' in results:
            print(f"❌ Error: {results['error']}")
            return

        if 'success' in results:
            status = "✅ SUCCESS" if results['success'] else "❌ FAILED"
            print(f"🎯 EXPLOIT RESULT: {status}")

        if 'details' in results:
            print(f"   Details: {results['details']}")

    else:
        print(f"✅ Exploit completed: {results}")

def print_config_results(results: Any):
    """Imprime les résultats de configuration."""
    if isinstance(results, dict):
        print("⚙️  CONFIGURATION:")
        for key, value in results.items():
            print(f"   {key}: {value}")
    else:
        print(f"✅ Config operation completed: {results}")

def run(argv: Optional[List[str]] = None):
    """Fonction principale pour exécuter le framework en fonction des arguments."""
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = load_config()
    cfg["session_id"] = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")  # Générer un ID de session unique basé sur l'heure UTC

    # Initialiser le schéma de base de données
    ensure_schema()

    # Set up RUN_DIR for logging
    run_dir = make_run_dir()
    os.environ["RUN_DIR"] = run_dir
    logger = get_logger()
    logger.info(f"Starting session {cfg['session_id']} in {run_dir}")

    # Créer une session dans la base de données pour cette exécution
    session_id = cfg["session_id"]
    create_session(session_id, args.target if hasattr(args, 'target') else 'unknown', cfg)

    results = None

    if args.command == "recon":
        results = run_recon(args, cfg)
    elif args.command == "network":
        results = run_network(args, cfg)
    elif args.command == "web":
        results = run_web(args, cfg)
    elif args.command == "exploit":
        results = run_exploit(args, cfg)
    elif args.command == "report":
        results = run_report(args, cfg)
    elif args.command == "config":
        results = run_config(args, cfg)
    elif args.command == "all":
        # orchestration conservatrice du pipeline
        print("🚀 Starting full penetration test pipeline...")
        # build a conservative namespace covering fields expected by individual subcommands
        a = argparse.Namespace(
            target=args.target,
            force=getattr(args, 'force', False),
            # recon
            osint=False,
            # network
            ports=None,
            full=False,
            fast=False,
            output=None,
            format=getattr(args, 'format', 'json'),
            # web
            crawl=True,
            scan=True,
            depth=2
        )

        recon_results = run_recon(a, cfg)
        network_results = run_network(a, cfg)
        web_results = run_web(a, cfg)
        exploit_results = run_exploit(argparse.Namespace(target=args.target, module=None, force=getattr(args, 'force', False)), cfg)
        # Persist intermediate results so report generator can read them
        try:
            compact = {"scans": [], "vulnerabilities": [], "exploitations": []}
            if network_results:
                compact['scans'].append({'scan_type': 'network', 'target': args.target, 'results': network_results})
            if web_results and isinstance(web_results, dict) and web_results.get('scan'):
                compact['scans'].append({'scan_type': 'web', 'target': args.target, 'results': web_results.get('scan')})
            try:
                persisted_tmp = persist_result(cfg['session_id'], normalize_for_json(compact)) if persist_result else None
            except Exception:
                persisted_tmp = None
        except Exception:
            persisted_tmp = None

        report_results = run_report(argparse.Namespace(session_id=cfg["session_id"], format="html,json", outdir="reports"), cfg)

        results = {
            "recon": recon_results,
            "network": network_results,
            "web": web_results,
            "exploit": exploit_results,
            "report": report_results,
            "session_id": cfg["session_id"]
        }

    # Imprimer les résultats s'il y en a
    if results is not None:
        # Persist results into DB when possible (skip if user requested --no-persist)
        logger_local = globals().get('logger') if 'logger' in globals() else None
        if not getattr(args, 'no_persist', False):
            if 'persist_result' in globals() and persist_result and session_id and results:
                try:
                    # For the 'all' pipeline, build a compact payload expected by persist_result
                    to_persist = None
                    if getattr(args, 'command', '') == 'all' or (hasattr(args, 'command') and args.command == 'all'):
                        to_persist = {"scans": [], "vulnerabilities": [], "exploitations": []}
                        # network
                        net = results.get('network') if isinstance(results, dict) else None
                        if net:
                            to_persist['scans'].append({
                                'scan_type': 'network',
                                'target': args.target,
                                'results': net
                            })
                        # web
                        web = results.get('web') if isinstance(results, dict) else None
                        if web and isinstance(web, dict):
                            # include crawl and scan if present
                            if web.get('scan'):
                                to_persist['scans'].append({
                                    'scan_type': 'web',
                                    'target': args.target,
                                    'results': web.get('scan')
                                })
                            if web.get('vulnerabilities') and isinstance(web.get('vulnerabilities'), list):
                                to_persist['vulnerabilities'].extend(web.get('vulnerabilities'))
                    else:
                        to_persist = results

                    # Normalize before persisting
                    try:
                        normalized_results = normalize_for_json(to_persist)
                    except Exception:
                        normalized_results = to_persist

                    persisted = persist_result(session_id, normalized_results)
                    if persisted:
                        if logger_local:
                            logger_local.info(f"[*] Persisted results summary: {persisted}")
                        else:
                            print(f"[*] Persisted results summary: {persisted}")
                except Exception as e:
                    if logger_local:
                        logger_local.exception("Failed to persist results")
                    else:
                        print(f"[!] Failed to persist results: {e}")
        else:
            if logger_local:
                logger_local.info("Persistence skipped ( --no-persist )")
            else:
                print("[i] Persistence skipped ( --no-persist )")
        # Enregistrer les résultats selon les options --format/--output si présentes
        # formats peut être spécifié sur chaque sous-commande
        formats = []
        out_target = None
        if hasattr(args, 'format') and args.format:
            formats = [f.strip().lower() for f in args.format.split(',') if f.strip()]
        if hasattr(args, 'outdir') and args.outdir:
            out_target = args.outdir
        if hasattr(args, 'output') and args.output:
            out_target = args.output

        # Si JSON demandé, écrire le résultat dict
        if isinstance(results, dict) and ('json' in formats or ('format' in dir(args) and not formats)):
            if out_target:
                # si out_target est un répertoire
                from pathlib import Path
                p = Path(out_target)
                if p.is_dir() or out_target.endswith(os.sep):
                    filename = f"{args.command}_{cfg.get('session_id','session')}.json"
                    fp = str(p / filename)
                else:
                    fp = out_target
                _write_json_output(results, fp)
            else:
                # pas d'out_target fourni -> afficher JSON sur stdout
                print(json.dumps(results, indent=2, ensure_ascii=False, default=str))

        # Si PDF demandé et on a un session_id, tenter via report generator
        if 'pdf' in formats:
            sid = cfg.get('session_id')
            if sid:
                out_dir = out_target if out_target else 'reports'
                pdf_path = _try_generate_pdf_from_session(sid, out_dir=out_dir)
                if pdf_path:
                    print(f"[*] PDF generated at: {pdf_path}")
                else:
                    print("[!] PDF generation requested but failed or not supported for ad-hoc results.")

        # Always print to console in formatted way as well
        print_results(results, args.command)

    # Fermer la session dans la base de données
    close_session(session_id, 'completed')

    return results

if __name__ == "__main__":
    # If the script is launched without arguments, provide an interactive CLI with examples.
    import sys

    def interactive_cli(parser: argparse.ArgumentParser):
        """Simple interactive prompt listing commands, descriptions and example usage."""
        # Small manual command catalogue and examples
        commands = {
            'recon': {
                'desc': 'Run reconnaissance (OSINT/DNS/subdomain discovery)',
                'example': 'recon --target example.com --osint'
            },
            'network': {
                'desc': 'Network scanning (ports/services)',
                'example': 'network --target 192.168.1.0/24 --ports 22,80,443 --full'
            },
            'web': {
                'desc': 'Web crawling and scanning (forms, XSS, SQLi)',
                'example': 'web --target https://example.com --crawl --scan --depth 3'
            },
            'exploit': {
                'desc': 'Run an exploitation module (simulated)',
                'example': 'exploit --target example.com --module system.exploiter'
            },
            'report': {
                'desc': 'Generate report from a session id',
                'example': 'report --session-id 20251030T121726Z --format html,pdf --outdir reports'
            },
            'config': {
                'desc': 'View or set configuration',
                'example': 'config --show'
            },
            'all': {
                'desc': 'Run full pipeline (recon, network, web, exploit, report)',
                'example': 'all --target example.com --format json'
            }
        }

        print("\nPenetration Testing Framework - Interactive CLI")
        print("Type a command line (examples below) or 'help', 'commands', 'exit'.\n")
        print("Available commands:")
        for name, info in commands.items():
            print(f"  {name:8} - {info['desc']}")
        print("\nExamples:")
        for name, info in commands.items():
            print(f"  $ python main.py {info['example']}")

        while True:
            try:
                line = input('\nptf> ').strip()
            except (EOFError, KeyboardInterrupt):
                print('\nExiting interactive CLI')
                break
            if not line:
                continue
            if line.lower() in ('exit', 'quit'):
                print('Goodbye')
                break
            if line.lower() in ('help', '?'):
                parser.print_help()
                continue
            if line.lower() in ('commands', 'list'):
                for name, info in commands.items():
                    print(f"  {name:8} - {info['desc']}  (example: {info['example']})")
                continue

            # Parse the provided line into argv tokens and dispatch
            try:
                tokens = shlex.split(line)
            except Exception as e:
                print(f"Could not parse input: {e}")
                continue
            if not tokens:
                continue
            # Run the command by calling run() with the token list
            try:
                run(tokens)
            except SystemExit:
                # argparse may call sys.exit(); ignore and continue
                continue
            except Exception as e:
                print(f"Error executing command: {e}")

    if len(sys.argv) == 1:
        parser = build_parser()
        interactive_cli(parser)
    else:
        run()
