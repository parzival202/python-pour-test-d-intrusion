#!/usr/bin/env python3
"""
Script de lancement de l'interface graphique.

Ce script peut être utilisé pour lancer la GUI depuis la ligne de commande
ou comme point d'entrée alternatif.
"""

import sys
import os
from pathlib import Path

# Ajouter le répertoire parent au path pour les imports
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

def check_requirements():
    """Vérifie que les dépendances sont installées."""
    try:
        from PyQt5.QtCore import PYQT_VERSION_STR
        print(f"✓ PyQt5 version {PYQT_VERSION_STR} détecté")
    except ImportError:
        print("✗ PyQt5 non installé. Installez-le avec: pip install PyQt5")
        return False

    try:
        from core.config import Config
        from core.logger import get_logger
        print("✓ Modules du framework importés avec succès")
    except ImportError as e:
        print(f"✗ Erreur d'import du framework: {e}")
        return False

    return True

def main():
    """Fonction principale pour lancer la GUI."""
    print("🚀 Lancement de l'interface graphique PTF...")

    # Vérifications préalables
    if not check_requirements():
        print("❌ Vérifications échouées. Impossible de lancer la GUI.")
        sys.exit(1)

    # Vérification du mode safe
    if not os.environ.get('PTF_SAFE_MODE', 'true').lower() in ('true', '1', 'yes'):
        print("⚠️  AVERTISSEMENT: Mode safe désactivé.")
        print("   Utilisez uniquement sur des environnements autorisés!")
        response = input("   Continuer? (o/N): ")
        if response.lower() not in ('o', 'oui', 'yes', 'y'):
            print("Annulé.")
            sys.exit(0)

    # Import et lancement de l'application
    try:
        from gui.app import main as gui_main
        gui_main()
    except KeyboardInterrupt:
        print("\n👋 Arrêt demandé par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Erreur lors du lancement de la GUI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
