"""
core/config.py
Chargeur de configuration hiérarchique prenant en charge JSON, YAML, les variables d'environnement et les remplacements CLI.

Priorité (la plus élevée -> la plus basse) :
  1. Remplacements CLI via --set key=value (géré par load_from_cli)
  2. Variables d'environnement préfixées PEN_ (PEN_SCAN__THREADS=20 -> scan.threads)
  3. Fichier de configuration (JSON ou YAML) passé avec --config
  4. VALEURS PAR DÉFAUT CODÉES EN DUR
"""
import os
import json
import argparse
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False  # Si PyYAML n'est pas installé, on ne peut pas charger les fichiers YAML

# Configuration par défaut pour le framework
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
        # commencer par les valeurs par défaut
        self._cfg = json.loads(json.dumps(DEFAULT))  # copie profonde
        # charger le fichier de configuration si fourni
        if config_path:
            self._load_config_file(config_path)
        # remplacements d'environnement
        self._apply_env()
        # remplacements CLI (clés pointillées)
        if cli_overrides:
            for k, v in cli_overrides.items():
                self._set_by_dotted(k, v)

    def _load_config_file(self, path):
        """Charge la configuration à partir d'un fichier JSON ou YAML."""
        p = Path(path)
        if not p.exists():
            return
        try:
            if path.endswith('.yaml') or path.endswith('.yml'):
                if not HAS_YAML:
                    raise ImportError("PyYAML n'est pas installé")
                with open(path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
            else:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            self._merge(self._cfg, data)
        except Exception:
            # ne pas échouer dur ; garder les valeurs par défaut
            pass

    def _apply_env(self):
        # PEN_SCAN__THREADS -> scan.threads
        for k, v in os.environ.items():
            if not k.startswith('PEN_'):
                continue
            path = k[4:].lower().split('__')
            dotted = '.'.join(path)
            self._set_by_dotted(dotted, v)  # Appliquer les variables d'environnement comme remplacements

    def _set_by_dotted(self, dotted, value):
        """Définit une valeur dans la configuration en utilisant une clé pointillée (ex: scan.threads)."""
        parts = dotted.split('.')
        node = self._cfg
        for p in parts[:-1]:
            if p not in node or not isinstance(node[p], dict):
                node[p] = {}
            node = node[p]
        node[parts[-1]] = self._smart_cast(value)

    def _smart_cast(self, v):
        """Convertit intelligemment les chaînes en types appropriés (bool, int, float)."""
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
        """Fusionne récursivement deux dictionnaires de configuration."""
        for k, v in extra.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = v

    def get(self):
        """Retourne la configuration actuelle."""
        return self._cfg

    def update(self, new_config: dict):
        """Met à jour la configuration avec de nouvelles valeurs."""
        self._merge(self._cfg, new_config)

    def save_example(self, path="config.example.json"):
        """Sauvegarde un fichier de configuration d'exemple."""
        Path(path).write_text(json.dumps(DEFAULT, indent=2), encoding='utf-8')


def load_from_cli(argv=None):
    """
    Analyse --config et --set remplacements depuis argv (ou sys.argv si None)
    Retourne le dictionnaire de configuration fusionné.
    Prend en charge les fichiers de configuration JSON et YAML.
    Exemple de --set : --set scan.threads=40 --set logging.json_lines=true
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--config', help='Chemin vers le fichier de configuration JSON/YAML', default=None)
    parser.add_argument('--set', action='append', help='Remplacer la valeur de configuration K=V ou key.path=val', default=[])
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

# Créer un exemple de configuration si exécuté directement
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "example":
        Config().save_example()
        print("Créé config.example.json")
    else:
        print(json.dumps(load_from_cli(), indent=2))
