"""
Point d'entrée principal de l'interface graphique utilisateur.

Ce fichier initialise l'application PyQt5, configure le thème et lance
la fenêtre principale du Penetration Testing Framework.
"""

import sys
import os
from pathlib import Path

# Ajouter le répertoire parent au path pour les imports
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

try:
    from PyQt5.QtWidgets import QApplication, QMessageBox
    from PyQt5.QtCore import Qt, QTranslator, QLocale
    from PyQt5.QtGui import QIcon, QFont
except ImportError as e:
    print(f"Erreur d'import PyQt5: {e}")
    print("Veuillez installer PyQt5 avec: pip install PyQt5")
    sys.exit(1)

from core.config import Config
from core.logger import get_logger
from windows.main_window import MainWindow


class PTFApplication(QApplication):
    """Application principale PyQt5 pour le Penetration Testing Framework."""

    def __init__(self, argv):
        super().__init__(argv)

        # Configuration de l'application
        self.setApplicationName("Penetration Testing Framework")
        self.setApplicationVersion("1.0.0")
        self.setOrganizationName("PTF Team")

        # Configuration du thème et style
        self.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        self.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

        # Police par défaut
        font = QFont("Segoe UI", 9)
        self.setFont(font)

        # Chargement de la configuration
        self.config = Config()
        self.logger = get_logger("gui.app", self.config.get())

        # Chargement du style
        self.load_stylesheet()

        # Création de la fenêtre principale
        self.main_window = MainWindow(self.config, self.logger)
        self.main_window.show()

        self.logger.info("Application GUI démarrée")

    def load_stylesheet(self):
        """Charge la feuille de style principale."""
        style_path = current_dir / "styles" / "main.qss"
        if style_path.exists():
            try:
                with open(style_path, 'r', encoding='utf-8') as f:
                    stylesheet = f.read()
                self.setStyleSheet(stylesheet)
                self.logger.info("Feuille de style chargée")
            except Exception as e:
                self.logger.warning(f"Erreur lors du chargement du style: {e}")
        else:
            self.logger.info("Aucune feuille de style trouvée, utilisation du style par défaut")

    def show_error_dialog(self, title, message):
        """Affiche une boîte de dialogue d'erreur."""
        QMessageBox.critical(self.main_window, title, message)


def main():
    """Fonction principale pour lancer l'application GUI."""
    # Vérification de la version Python
    if sys.version_info < (3, 8):
        print("Erreur: Python 3.8 ou supérieur requis")
        sys.exit(1)

    # Vérification du mode safe
    if not os.environ.get('PTF_SAFE_MODE', 'true').lower() in ('true', '1', 'yes'):
        print("AVERTISSEMENT: Mode safe désactivé. Utilisez uniquement sur des environnements autorisés!")

    # Création et exécution de l'application
    app = PTFApplication(sys.argv)

    # Gestion des exceptions non capturées
    def exception_hook(exctype, value, traceback):
        app.logger.error(f"Exception non capturée: {exctype.__name__}: {value}")
        app.show_error_dialog("Erreur", f"Une erreur inattendue s'est produite:\n{exctype.__name__}: {value}")
        sys.__excepthook__(exctype, value, traceback)

    sys.excepthook = exception_hook

    # Boucle principale
    try:
        sys.exit(app.exec_())
    except KeyboardInterrupt:
        app.logger.info("Application interrompue par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        app.logger.error(f"Erreur lors de l'exécution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
