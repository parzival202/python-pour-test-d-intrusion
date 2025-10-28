"""
core/config.py
Hierarchical configuration loader for the pentest framework.

Priority (highest -> lowest):
  1. CLI overrides via --set key=value (handled by load_from_cli)
  2. Environment variables prefixed PEN_ (PEN_SCAN__THREADS=20 -> scan.threads)
  3. Config JSON file passed with --config
  4. HARD-CODED DEFAULTS
"""
import os
import json
import argparse

DEFAULT = {
    "scan": {"timeout": 2, "threads": 20, "rate_limit": 100},
    "logging": {"level": "INFO", "file": "pentest.log", "json_lines": False},
    "reporting": {"html_template": "report_template.html"}
}

class Config:
    def __init__(self, config_path=None, cli_overrides=None):
        # start from defaults
        self._cfg = json.loads(json.dumps(DEFAULT))  # deep copy simple
        # load config file if provided
        if config_path:
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._merge(self._cfg, data)
            except Exception:
                # don't fail hard; keep defaults
                pass
        # environment overrides
        self._apply_env()
        # CLI overrides (dotted keys)
        if cli_overrides:
            for k, v in cli_overrides.items():
                self._set_by_dotted(k, v)

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


def load_from_cli(argv=None):
    """
    Parses --config and --set overrides from argv (or sys.argv if None)
    Returns the merged configuration dict.
    Example of --set: --set scan.threads=40 --set logging.json_lines=true
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--config', help='Path to config JSON file', default=None)
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

# quick test: python -c "from core.config import load_from_cli; print(load_from_cli(['--set','scan.threads=5']))"
if __name__ == "__main__":
    print(json.dumps(load_from_cli(), indent=2))
