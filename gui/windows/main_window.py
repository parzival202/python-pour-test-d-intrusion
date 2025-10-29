"""
Fenêtre principale de l'interface graphique.

Cette fenêtre contient l'écran d'accueil avec les boutons rapides pour lancer
les différents types de scans, ainsi que les menus et barres d'outils.
"""

import sys
from pathlib import Path
from typing import Optional

try:
    from PyQt5.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QFrame, QSplitter, QTextEdit, QProgressBar, QStatusBar, QMessageBox,
        QMenuBar, QMenu, QAction, QGroupBox, QGridLayout, QScrollArea
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
    from PyQt5.QtGui import QFont, QIcon, QPixmap
except ImportError:
    print("PyQt5 non installé. Installez-le avec: pip install PyQt5")
    sys.exit(1)

from core.config import Config
from core.database import get_session_results, get_session
from components.session_manager import SessionManager
from components.logger_view import LoggerView
from windows.config_window import ConfigWindow


class ScanWorker(QThread):
    """Worker thread pour exécuter les scans sans bloquer l'UI."""

    progress_updated = pyqtSignal(int, str)  # pourcentage, message
    scan_finished = pyqtSignal(dict)  # résultats
    error_occurred = pyqtSignal(str)  # message d'erreur

    def __init__(self, scan_type: str, target: str, config: dict):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.config = config

    def run(self):
        """Exécute le scan dans le thread worker."""
        try:
            self.progress_updated.emit(10, f"Démarrage du scan {self.scan_type}...")

            # Simulation d'un scan (à remplacer par les vrais appels de modules)
            import time
            for i in range(11):
                time.sleep(0.5)
                self.progress_updated.emit(10 + i * 8, f"Scan {self.scan_type} en cours... {i*10}%")

            # Résultats simulés
            results = {
                "scan_type": self.scan_type,
                "target": self.target,
                "status": "completed",
                "findings": f"Résultats simulés pour {self.scan_type} sur {self.target}"
            }

            self.progress_updated.emit(100, "Scan terminé")
            self.scan_finished.emit(results)

        except Exception as e:
            self.error_occurred.emit(str(e))


class MainWindow(QMainWindow):
    """Fenêtre principale de l'application GUI."""

    def __init__(self, config: Config, logger):
        super().__init__()
        self.config = config
        self.logger = logger
        self.current_session = None
        self.scan_worker = None

        self.init_ui()
        self.setup_menus()
        self.setup_status_bar()

        self.logger.info("Fenêtre principale initialisée")

    def init_ui(self):
        """Initialise l'interface utilisateur."""
        self.setWindowTitle("Penetration Testing Framework - GUI")
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)

        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout principal
        main_layout = QVBoxLayout(central_widget)

        # En-tête avec logo et titre
        header_frame = self.create_header()
        main_layout.addWidget(header_frame)

        # Zone principale avec splitter
        splitter = QSplitter(Qt.Horizontal)

        # Panneau gauche : contrôles et boutons rapides
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)

        # Panneau droit : résultats et logs
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)

        splitter.setSizes([400, 800])
        main_layout.addWidget(splitter)

        # Barre de progression (cachée par défaut)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

    def create_header(self) -> QFrame:
        """Crée l'en-tête avec logo et titre."""
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel)
        frame.setStyleSheet("background-color: #f0f0f0; border-radius: 5px;")

        layout = QHBoxLayout(frame)

        # Logo (placeholder)
        logo_label = QLabel()
        logo_label.setFixedSize(64, 64)
        logo_label.setStyleSheet("background-color: #007acc; border-radius: 32px;")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_label.setText("🔒")  # Emoji comme logo temporaire
        layout.addWidget(logo_label)

        # Titre et description
        title_layout = QVBoxLayout()
        title = QLabel("Penetration Testing Framework")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title_layout.addWidget(title)

        subtitle = QLabel("Interface Graphique - Mode Éducatif/VM Uniquement")
        subtitle.setFont(QFont("Arial", 10))
        subtitle.setStyleSheet("color: #666;")
        title_layout.addWidget(subtitle)

        layout.addLayout(title_layout)
        layout.addStretch()

        # Statut du framework
        status_label = QLabel("Statut: Prêt")
        status_label.setStyleSheet("color: green; font-weight: bold;")
        layout.addWidget(status_label)

        return frame

    def create_left_panel(self) -> QWidget:
        """Crée le panneau gauche avec les contrôles."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Gestionnaire de sessions
        session_group = QGroupBox("Gestion des Sessions")
        session_layout = QVBoxLayout(session_group)

        self.session_manager = SessionManager(self.config, self.logger)
        self.session_manager.session_changed.connect(self.on_session_changed)
        session_layout.addWidget(self.session_manager)

        layout.addWidget(session_group)

        # Boutons rapides
        quick_actions_group = QGroupBox("Actions Rapides")
        quick_layout = QGridLayout(quick_actions_group)

        # Boutons pour différents types de scans
        buttons = [
            ("Scan Complet", "all", 0, 0),
            ("Reconnaissance", "recon", 0, 1),
            ("Réseau", "network", 1, 0),
            ("Web", "web", 1, 1),
            ("Rapport", "report", 2, 0),
        ]

        for text, scan_type, row, col in buttons:
            btn = QPushButton(text)
            btn.setMinimumHeight(40)
            btn.clicked.connect(lambda checked, st=scan_type: self.start_scan(st))
            quick_layout.addWidget(btn, row, col)

        layout.addWidget(quick_actions_group)

        # Configuration
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout(config_group)

        config_btn = QPushButton("Ouvrir Configuration")
        config_btn.clicked.connect(self.open_config_window)
        config_layout.addWidget(config_btn)

        layout.addWidget(config_group)

        layout.addStretch()

        return widget

    def create_right_panel(self) -> QWidget:
        """Crée le panneau droit avec les résultats."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Zone de résultats
        results_group = QGroupBox("Résultats et Logs")
        results_layout = QVBoxLayout(results_group)

        # Vue des logs
        self.logger_view = LoggerView(self.logger)
        results_layout.addWidget(self.logger_view)

        # Zone de résultats détaillés (scrollable)
        self.results_area = QScrollArea()
        self.results_area.setWidgetResizable(True)
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setPlainText("Aucun résultat pour le moment.\nLancez un scan pour voir les résultats ici.")
        self.results_area.setWidget(self.results_text)
        results_layout.addWidget(self.results_area)

        layout.addWidget(results_group)

        return widget

    def setup_menus(self):
        """Configure les menus de l'application."""
        menubar = self.menuBar()

        # Menu Fichier
        file_menu = menubar.addMenu("Fichier")

        new_session_action = QAction("Nouvelle Session", self)
        new_session_action.triggered.connect(self.new_session)
        file_menu.addAction(new_session_action)

        file_menu.addSeparator()

        exit_action = QAction("Quitter", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Menu Outils
        tools_menu = menubar.addMenu("Outils")

        config_action = QAction("Configuration", self)
        config_action.triggered.connect(self.open_config_window)
        tools_menu.addAction(config_action)

        # Menu Aide
        help_menu = menubar.addMenu("Aide")

        about_action = QAction("À propos", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def setup_status_bar(self):
        """Configure la barre de statut."""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Prêt")

        # Indicateur de session
        self.session_indicator = QLabel("Aucune session active")
        self.status_bar.addPermanentWidget(self.session_indicator)

    def start_scan(self, scan_type: str):
        """Démarre un scan du type spécifié."""
        if not self.current_session:
            QMessageBox.warning(self, "Aucune session", "Veuillez créer ou sélectionner une session d'abord.")
            return

        # Vérification de sécurité
        if scan_type in ["exploit", "all"]:
            reply = QMessageBox.question(
                self, "Confirmation requise",
                f"Le scan '{scan_type}' peut être destructif. Continuer?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                return

        # Désactiver les boutons pendant le scan
        self.set_scan_buttons_enabled(False)

        # Afficher la barre de progression
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        # Créer et démarrer le worker
        session_data = get_session(self.current_session)
        target = session_data.get("target", "unknown") if session_data else "unknown"

        self.scan_worker = ScanWorker(scan_type, target, self.config.get())
        self.scan_worker.progress_updated.connect(self.on_progress_updated)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)
        self.scan_worker.error_occurred.connect(self.on_scan_error)
        self.scan_worker.start()

        self.logger.info(f"Scan {scan_type} démarré pour session {self.current_session}")

    def set_scan_buttons_enabled(self, enabled: bool):
        """Active/désactive tous les boutons de scan."""
        # Cette méthode devrait parcourir tous les boutons et les activer/désactiver
        # Pour l'instant, on utilise une approche simplifiée
        for child in self.findChildren(QPushButton):
            if child.text() in ["Scan Complet", "Reconnaissance", "Réseau", "Web", "Rapport"]:
                child.setEnabled(enabled)

    def on_progress_updated(self, percentage: int, message: str):
        """Met à jour la barre de progression."""
        self.progress_bar.setValue(percentage)
        self.status_bar.showMessage(message)

    def on_scan_finished(self, results: dict):
        """Gère la fin d'un scan."""
        self.progress_bar.setVisible(False)
        self.set_scan_buttons_enabled(True)
        self.status_bar.showMessage("Scan terminé")

        # Afficher les résultats
        results_text = f"Scan {results.get('scan_type', 'unknown')} terminé\n"
        results_text += f"Target: {results.get('target', 'unknown')}\n"
        results_text += f"Status: {results.get('status', 'unknown')}\n"
        results_text += f"Findings: {results.get('findings', 'none')}\n"

        self.results_text.setPlainText(results_text)

        QMessageBox.information(self, "Scan terminé", f"Scan {results.get('scan_type')} terminé avec succès!")

    def on_scan_error(self, error_msg: str):
        """Gère les erreurs de scan."""
        self.progress_bar.setVisible(False)
        self.set_scan_buttons_enabled(True)
        self.status_bar.showMessage("Erreur lors du scan")

        QMessageBox.critical(self, "Erreur de scan", f"Une erreur s'est produite: {error_msg}")

    def on_session_changed(self, session_id: str):
        """Gère le changement de session."""
        self.current_session = session_id
        if session_id:
            self.session_indicator.setText(f"Session: {session_id}")
            self.status_bar.showMessage(f"Session {session_id} activée")
        else:
            self.session_indicator.setText("Aucune session active")
            self.status_bar.showMessage("Aucune session active")

    def new_session(self):
        """Crée une nouvelle session."""
        self.session_manager.create_new_session()

    def open_config_window(self):
        """Ouvre la fenêtre de configuration."""
        config_window = ConfigWindow(self.config, self)
        config_window.exec_()

    def show_about(self):
        """Affiche la boîte de dialogue À propos."""
        QMessageBox.about(
            self, "À propos",
            "Penetration Testing Framework GUI v1.0.0\n\n"
            "Interface graphique pour tests de pénétration.\n"
            "Utilisez uniquement sur des environnements autorisés!\n\n"
            "Mode éducatif/VM uniquement."
        )

    def closeEvent(self, event):
        """Gère la fermeture de la fenêtre."""
        if self.scan_worker and self.scan_worker.isRunning():
            reply = QMessageBox.question(
                self, "Scan en cours",
                "Un scan est en cours. Voulez-vous vraiment quitter?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return

        self.logger.info("Application fermée")
        event.accept()
