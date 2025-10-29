"""
Composant d'affichage des logs en temps réel.

Affiche les logs du framework avec filtrage par niveau (INFO/WARNING/ERROR).
Utilise le logger du framework pour recevoir les messages.
"""

import sys
from typing import Optional

try:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QTextEdit, QComboBox, QCheckBox, QGroupBox, QScrollBar
    )
    from PyQt5.QtCore import Qt, QTimer, pyqtSignal
    from PyQt5.QtGui import QTextCursor, QColor, QFont
except ImportError:
    print("PyQt5 non installé. Installez-le avec: pip install PyQt5")
    sys.exit(1)


class LoggerView(QWidget):
    """Composant pour afficher les logs en temps réel."""

    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.log_levels = ["ALL", "DEBUG", "INFO", "WARNING", "ERROR"]
        self.current_filter = "ALL"
        self.auto_scroll = True

        # Stocker les logs pour le filtrage
        self.all_logs = []
        self.filtered_logs = []

        self.init_ui()
        self.setup_logging_capture()

    def init_ui(self):
        """Initialise l'interface utilisateur."""
        layout = QVBoxLayout(self)

        # Contrôles
        controls_layout = QHBoxLayout()

        # Filtre de niveau
        controls_layout.addWidget(QLabel("Niveau:"))
        self.level_combo = QComboBox()
        self.level_combo.addItems(self.log_levels)
        self.level_combo.currentTextChanged.connect(self.on_filter_changed)
        controls_layout.addWidget(self.level_combo)

        # Auto-scroll
        self.auto_scroll_cb = QCheckBox("Auto-scroll")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.stateChanged.connect(self.on_auto_scroll_changed)
        controls_layout.addWidget(self.auto_scroll_cb)

        # Bouton clear
        clear_btn = QPushButton("Effacer")
        clear_btn.clicked.connect(self.clear_logs)
        controls_layout.addWidget(clear_btn)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Zone de logs
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setStyleSheet(
            "QTextEdit {"
            "    background-color: #1e1e1e;"
            "    color: #d4d4d4;"
            "    border: 1px solid #3e3e3e;"
            "    border-radius: 3px;"
            "}"
        )
        layout.addWidget(self.log_text)

    def setup_logging_capture(self):
        """Configure la capture des logs."""
        # Pour l'instant, on simule quelques logs
        # TODO: Intégrer avec le vrai système de logging
        self.add_log_entry("INFO", "LoggerView", "Composant de logs initialisé")
        self.add_log_entry("INFO", "GUI", "Interface graphique démarrée")

    def add_log_entry(self, level: str, logger_name: str, message: str):
        """Ajoute une entrée de log."""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'logger': logger_name,
            'message': message
        }

        self.all_logs.append(log_entry)
        self.apply_filter()

    def apply_filter(self):
        """Applique le filtre actuel aux logs."""
        if self.current_filter == "ALL":
            self.filtered_logs = self.all_logs
        else:
            self.filtered_logs = [
                log for log in self.all_logs
                if log['level'] == self.current_filter
            ]

        self.update_display()

    def update_display(self):
        """Met à jour l'affichage des logs."""
        self.log_text.clear()

        for log in self.filtered_logs:
            # Formater l'entrée
            formatted = f"[{log['timestamp']}] {log['level']:8} {log['logger']}: {log['message']}"

            # Couleur selon le niveau
            color = self.get_level_color(log['level'])

            # Insérer avec couleur
            cursor = self.log_text.textCursor()
            cursor.movePosition(QTextCursor.End)

            format = cursor.charFormat()
            format.setForeground(color)
            cursor.setCharFormat(format)

            cursor.insertText(formatted + "\n")

        # Auto-scroll si activé
        if self.auto_scroll:
            scrollbar = self.log_text.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def get_level_color(self, level: str) -> QColor:
        """Retourne la couleur pour un niveau de log."""
        colors = {
            "DEBUG": QColor("#888888"),
            "INFO": QColor("#ffffff"),
            "WARNING": QColor("#ffaa00"),
            "ERROR": QColor("#ff4444"),
            "CRITICAL": QColor("#ff0000")
        }
        return colors.get(level, QColor("#ffffff"))

    def on_filter_changed(self, level: str):
        """Gère le changement de filtre."""
        self.current_filter = level
        self.apply_filter()

    def on_auto_scroll_changed(self, state: int):
        """Gère le changement d'auto-scroll."""
        self.auto_scroll = state == Qt.Checked

    def clear_logs(self):
        """Efface tous les logs."""
        self.all_logs.clear()
        self.filtered_logs.clear()
        self.update_display()

    def add_demo_log(self):
        """Ajoute un log de démonstration (pour les tests)."""
        import random
        levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        messages = [
            "Scan réseau démarré",
            "Hôte 192.168.1.1 découvert",
            "Port 80 ouvert sur target",
            "Vérification des vulnérabilités XSS",
            "Rapport généré avec succès",
            "Session sauvegardée",
            "Erreur de connexion réseau",
            "Timeout lors du scan"
        ]

        level = random.choice(levels)
        message = random.choice(messages)

        self.add_log_entry(level, "DemoLogger", message)

    def log_message(self, level: str, message: str, logger_name: str = "GUI"):
        """Méthode publique pour ajouter un log."""
        self.add_log_entry(level, logger_name, message)
