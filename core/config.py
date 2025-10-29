"""
core/config.py
Hierarchical configuration loader supporting JSON, YAML, environment variables, and CLI overrides.

Priority (highest -> lowest):
  1. CLI overrides via --set key=value (handled by load_from_cli)
  2. Environment variables prefixed PEN_ (PEN_SCAN__THREADS=20 -> scan.threads)
  3. Config file (JSON or YAML) passed with --config
  4. HARD-CODED DEFAULTS
"""
import os
import json
import argparse
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

DEFAULT = {
    "scan": {"timeout": 2, "threads": 20, "rate_limit": 100},
    "logging": {"level": "INFO", "file": "pentest.log", "json_lines": False},
    "reporting": {"html_template": "report_template.html", "pdf_enabled": False},
    "recon": {"dns_timeout": 5, "subdomain_wordlist": ["www", "mail", "dev", "test", "beta"]},
    "web": {"crawl_depth": 2, "scan_timeout": 5},
    "exploit": {"safe_mode": True, "reverse_shell_port": 4444}
}

class Config:
    def __init__(self, config_path=None, cli_overrides=None):
        # start from defaults
        self._cfg = json.loads(json.dumps(DEFAULT))  # deep copy
        # load config file if provided
        if config_path:
            self._load_config_file(config_path)
        # environment overrides
        self._apply_env()
        # CLI overrides (dotted keys)
        if cli_overrides:
            for k, v in cli_overrides.items():
                self._set_by_dotted(k, v)

    def _load_config_file(self, path):
        """Load config from JSON or YAML file."""
        p = Path(path)
        if not p.exists():
            return
        try:
            if path.endswith('.yaml') or path.endswith('.yml'):
                if not HAS_YAML:
                    raise ImportError("PyYAML not installed")
                with open(path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
            else:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            self._merge(self._cfg, data)
        except Exception:
            # don't fail hard; keep defaults
            pass

    def _apply_env(self):
        # PEN_SCAN__THREADS -> scan.threads
        for k, v in os.environ.items():
            if not k.startswith('PEN_'):
                continue
            path = k[4:].lower().split('__')
            dotted = '.'.join(path)
            self._set_by_dotted(dotted, v)

    def _set_by_dotted(self, dotted, value):
        parts = dotted.split('.')
        node = self._cfg
        for p in parts[:-1]:
            if p not in node or not isinstance(node[p], dict):
                node[p] = {}
            node = node[p]
        node[parts[-1]] = self._smart_cast(value)

    def _smart_cast(self, v):
        # cast strings like "true", "10", "3.2" to types
        if isinstance(v, (int, float, dict, list, bool)):
            return v
        if not isinstance(v, str):
            return v
        lv = v.lower()
        if lv in ("true", "false"):
            return lv == "true"
        try:
            if "." in v:
                return float(v)
            return int(v)
        except Exception:
            return v

    def _merge(self, base, extra):
        for k, v in extra.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = v

    def get(self):
        return self._cfg

    def save_example(self, path="config.example.json"):
        """Save example config file."""
        Path(path).write_text(json.dumps(DEFAULT, indent=2), encoding='utf-8')


def load_from_cli(argv=None):
    """
    Parses --config and --set overrides from argv (or sys.argv if None)
    Returns the merged configuration dict.
    Supports JSON and YAML config files.
    Example of --set: --set scan.threads=40 --set logging.json_lines=true
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--config', help='Path to config JSON/YAML file', default=None)
    parser.add_argument('--set', action='append', help='Override config value K=V or key.path=val', default=[])
    args, _ = parser.parse_known_args(argv)
    overrides = {}
    for item in args.set or []:
        if '=' in item:
            k, v = item.split('=', 1)
        elif ':' in item:
            k, v = item.split(':', 1)
        else:
            continue
        overrides[k.strip()] = v.strip()
    cfg = Config(config_path=args.config, cli_overrides=overrides)
    return cfg.get()

# Create example config if run directly
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "example":
        Config().save_example()
        print("Created config.example.json")
    else:
        print(json.dumps(load_from_cli(), indent=2))
