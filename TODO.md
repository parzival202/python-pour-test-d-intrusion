# TODO.txt — Automated Patch Instructions (for BlackBox)

> All task descriptions are in English.
> Comments are in French (for understanding and tracking).

------------------------------------------------------------
- [ ] **Action 1 — Backup the project (CRITICAL)**
    # Sauvegarder l'état actuel du projet avant toute modification.
    git add -A && git commit -m "Backup before automated patches"

------------------------------------------------------------
- [ ] **Action 2 — Create / Update `utils/file_utils.py`**
    # Ajoute des fonctions utilitaires pour créer les dossiers horodatés et sauvegarder les fichiers JSON.
    Paste the following code inside `utils/file_utils.py`:

    ```python
    import json
    from pathlib import Path
    from datetime import datetime
    import os

    def save_json(path: str, data, pretty: bool = True):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        txt = json.dumps(data, indent=2, ensure_ascii=False) if pretty else json.dumps(data, ensure_ascii=False)
        p.write_text(txt, encoding='utf-8')
        return str(p.resolve())

    def load_json(path: str):
        p = Path(path)
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding='utf-8'))

    def make_run_dir(base_dir: str = "results", prefix: str = "run"):
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        run_dir = Path(base_dir) / f"{prefix}_{ts}"
        run_dir.mkdir(parents=True, exist_ok=True)
        return str(run_dir.resolve())
    ```

------------------------------------------------------------
- [ ] **Action 3 — Update `core/logger.py`**
    # Ajoute un système de logs vers la console et vers le dossier RUN_DIR si présent.
    Replace or create `core/logger.py` with this content:

    ```python
    import logging
    import os
    from logging.handlers import RotatingFileHandler

    def get_logger(name="ptf"):
        logger = logging.getLogger(name)
        if logger.handlers:
            return logger
        logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(ch)

        run_dir = os.environ.get("RUN_DIR", None)
        if run_dir:
            try:
                log_path = os.path.join(run_dir, "run.log")
                fh = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
                fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
                logger.addHandler(fh)
            except Exception:
                logger.debug("Could not add file handler.")
        return logger
    ```

------------------------------------------------------------
- [ ] **Action 4 — Update `reporting/report_generator.py`**
    # Permet de sauvegarder les rapports HTML dans le dossier horodaté spécifié (out_dir).
    Replace the function `generate_combined_report()` or the whole file with this simplified version.

    ```python
    import json
    from pathlib import Path
    from datetime import datetime
    import html

    def _load_json(path):
        try:
            return json.loads(Path(path).read_text(encoding='utf-8'))
        except Exception:
            return None

    def generate_combined_report(network_json_path=None, web_json_path=None, out_html='report.html', out_dir=None):
        net = _load_json(network_json_path) if network_json_path else None
        web = _load_json(web_json_path) if web_json_path else None

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        html_content = f"<html><body><h1>PenTest Report</h1><p>Generated: {now}</p></body></html>"

        if out_dir:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            outpath = Path(out_dir) / out_html
        else:
            outpath = Path(out_html)

        outpath.write_text(html_content, encoding='utf-8')
        return str(outpath)
    ```

------------------------------------------------------------
- [ ] **Action 5 — Update `main.py`**
    # Ajoute le support pour l’option --output et la création automatique du dossier RUN_DIR.
    Edit `main.py` and ensure the following snippets exist near the top:

    ```python
    import os
    from utils.file_utils import make_run_dir, save_json
    from core.logger import get_logger

    if not os.environ.get("RUN_DIR"):
        os.environ["RUN_DIR"] = make_run_dir(base_dir="results", prefix="run")

    logger = get_logger("ptf_main")
    ```

    And modify the `network` and `web` subcommands as follows:

    ```python
    parser_network.add_argument("--output", "-o", default=None, help="Output file path")
    parser_web.add_argument("--output", "-o", default=None, help="Output file path")

    def cmd_network(args):
        from modules.network.scanner import scan_target
        result = scan_target(args.target, threads=getattr(args, "threads", 20))
        outpath = args.output or os.path.join(os.environ.get("RUN_DIR","."), "network_report.json")
        save_json(outpath, result)
        logger.info(f"Network scan saved to {outpath}")

    def cmd_web(args):
        from modules.web.crawler import crawl
        result = crawl(args.target, depth=getattr(args, "depth", 1))
        outpath = args.output or os.path.join(os.environ.get("RUN_DIR","."), "web_report.json")
        save_json(outpath, result)
        logger.info(f"Web scan saved to {outpath}")
    ```

------------------------------------------------------------
- [ ] **Action 6 — Validate patches**
    # Vérifie que les commandes fonctionnent correctement après les modifications.
    Run the following in PowerShell or CMD:

    ```powershell
    python main.py network -h
    python main.py web -h
    python main.py network --target 127.0.0.1
    python main.py web --target http://127.0.0.1
    ```

------------------------------------------------------------
- [ ] **Action 7 — Generate report**
    # Teste la génération du rapport HTML final.
    ```bash
    python -c "from reporting.report_generator import generate_combined_report; print(generate_combined_report('results/latest/network_report.json', 'results/latest/web_report.json', 'final_report.html', out_dir='results/latest'))"
    ```

------------------------------------------------------------
- [ ] **Action 8 — Run tests and store outputs**
    # Exécute les tests et enregistre les résultats dans le dossier horodaté.
    ```bash
    export RUN_DIR=$(python -c "from utils.file_utils import make_run_dir; print(make_run_dir())")
    pytest -q --maxfail=1 --junitxml="$RUN_DIR/pytest_results.xml"
    ```

------------------------------------------------------------
- [ ] **Action 9 — Final verification**
    # Vérifie la structure finale et la présence des fichiers de sortie.
    ```bash
    tree results/
    ```

------------------------------------------------------------
- [ ] **Action 10 — Commit all changes**
    # Commit final une fois les vérifications terminées.
    git add -A && git commit -m "Implement output argument and result directory management"
