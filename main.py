#!/usr/bin/env python3
"""Main entrypoint for the Penetration Testing Framework.
Defensive, modular, and safe-by-default.
"""
import argparse, importlib, json, os
from datetime import datetime

def try_import(module_path):
    try:
        return importlib.import_module(module_path)
    except Exception:
        return None

def load_config(path=None):
    cfg = {}
    core_cfg = try_import('core.config')
    if core_cfg and hasattr(core_cfg, 'load_config'):
        try:
            return core_cfg.load_config(path)
        except Exception:
            pass
    cand = path or 'config.json'
    if os.path.exists(cand):
        try:
            with open(cand, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return cfg

def dispatch_recon(args, cfg):
    mod = try_import('modules.reconnaissance.osint') or try_import('modules.recon')
    if mod and hasattr(mod, 'run'):
        print('[*] Recon module:', mod.__name__)
        mod.run(target=args.target, safe_mode=not args.force)
    else:
        print('[!] Recon module not found. Expected modules.reconnaissance.osint or modules.recon with run()')

def dispatch_network(args, cfg):
    mod = try_import('modules.network.scanner') or try_import('modules.network')
    if mod and hasattr(mod, 'run'):
        print('[*] Network module:', mod.__name__)
        mod.run(target=args.target, scan_type=args.scan, safe_mode=not args.force)
    else:
        print('[!] Network scanner module not found. Expected modules.network.scanner or modules.network with run()')

def dispatch_web(args, cfg):
    crawler = try_import('modules.web.crawler')
    scanner = try_import('modules.web.scanner')
    if args.crawl and crawler and hasattr(crawler, 'run'):
        print('[*] Web crawler:', crawler.__name__)
        crawler.run(target=args.target, depth=args.depth, safe_mode=not args.force)
    if args.scan and scanner and hasattr(scanner, 'run'):
        print('[*] Web scanner:', scanner.__name__)
        scanner.run(target=args.target, safe_mode=not args.force)
    if not ((args.crawl and crawler) or (args.scan and scanner)):
        print('[!] Web modules missing. Expected modules.web.crawler and/or modules.web.scanner with run()')

def dispatch_exploit(args, cfg):
    mod = None
    if args.module:
        candidates = [f'modules.web.{args.module}', f'modules.exploits.{args.module}', f'modules.{args.module}']
        for c in candidates:
            m = try_import(c)
            if m:
                mod = m
                break
    else:
        mod = try_import('modules.system.exploiter') or try_import('modules.exploit')

    if mod and hasattr(mod, 'run'):
        print('[*] Exploit module (simulated):', mod.__name__)
        mod.run(target=args.target, safe_mode=not args.force)
    else:
        print('[!] Exploit module not found. Provide --module NAME or add modules.system.exploiter with run()')

def dispatch_report(args, cfg):
    rg = try_import('reporting.report_generator') or try_import('reporting')
    if rg and hasattr(rg, 'generate'):
        formats = args.format.split(',') if args.format else ['html']
        print('[*] Generating report for session:', args.session_id, 'formats:', formats)
        rg.generate(session_id=args.session_id, formats=formats, out_dir=args.outdir)
    else:
        print('[!] Report generator not found. Expected reporting.report_generator with generate()')

def dispatch_config(args, cfg):
    print('[*] Current configuration (merged view):')
    print(json.dumps(cfg or {}, indent=2, ensure_ascii=False))
    core_cfg = try_import('core.config')
    if core_cfg and hasattr(core_cfg, 'show'):
        core_cfg.show()

def main():
    parser = argparse.ArgumentParser(prog='ptf', description='Penetration Testing Framework - entrypoint')
    sub = parser.add_subparsers(dest='command', required=True)

    p_recon = sub.add_parser('recon', help='Run reconnaissance modules (OSINT, passive)')
    p_recon.add_argument('--target', required=True, help='Target hostname or IP')
    p_recon.add_argument('--osint', action='store_true', help='Enable OSINT flows (if available)')
    p_recon.add_argument('--force', action='store_true', help='Force destructive operations (use with care)')

    p_net = sub.add_parser('network', help='Run network scanning modules')
    p_net.add_argument('--target', required=True, help='CIDR or IP range')
    p_net.add_argument('--scan', default='default', choices=['default','full','fast'], help='Scan profile')
    p_net.add_argument('--force', action='store_true', help='Allow aggressive scans')

    p_web = sub.add_parser('web', help='Run web crawling and scanning modules')
    p_web.add_argument('--target', required=True, help='Target URL or domain')
    p_web.add_argument('--crawl', action='store_true')
    p_web.add_argument('--scan', action='store_true')
    p_web.add_argument('--depth', type=int, default=2)
    p_web.add_argument('--force', action='store_true')

    p_exp = sub.add_parser('exploit', help='Run exploit module (simulated unless force)')
    p_exp.add_argument('--target', required=True)
    p_exp.add_argument('--module', help='Exploit module name to run')
    p_exp.add_argument('--force', action='store_true')

    p_rep = sub.add_parser('report', help='Generate report from session data')
    p_rep.add_argument('--session-id', required=True)
    p_rep.add_argument('--format', default='html', help='Comma-separated formats: html,json')
    p_rep.add_argument('--outdir', default='reports')

    p_cfg = sub.add_parser('config', help='Show or edit config (read-only by default)')

    p_all = sub.add_parser('all', help='Run full pipeline (recon->network->web->exploit->report)')
    p_all.add_argument('--target', required=True)
    p_all.add_argument('--quick', action='store_true')
    p_all.add_argument('--force', action='store_true')

    args = parser.parse_args()
    cfg = load_config()

    session_id = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    cfg['session_id'] = session_id

    if args.command == 'recon':
        dispatch_recon(args, cfg)
    elif args.command == 'network':
        dispatch_network(args, cfg)
    elif args.command == 'web':
        dispatch_web(args, cfg)
    elif args.command == 'exploit':
        dispatch_exploit(args, cfg)
    elif args.command == 'report':
        dispatch_report(args, cfg)
    elif args.command == 'config':
        dispatch_config(args, cfg)
    elif args.command == 'all':
        print('[*] Pipeline start - session:', session_id)
        class A: pass
        a = A(); a.target = args.target; a.force = args.force; a.crawl = True; a.scan = True; a.depth = 2
        dispatch_recon(a, cfg)
        dispatch_network(a, cfg)
        dispatch_web(a, cfg)
        dispatch_exploit(a, cfg)
        rep_args = argparse.Namespace(session_id=session_id, format='html,json', outdir='reports')
        dispatch_report(rep_args, cfg)
        print('[*] Pipeline finished.')
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
