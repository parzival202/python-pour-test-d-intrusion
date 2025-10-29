"""
Fenêtre de configuration de l'application.

Permet de modifier les paramètres du framework (threads, timeout, etc.)
et de sauvegarder la configuration.
"""

import sys
from typing import Optional

try:
    from PyQt5.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QLineEdit, QSpinBox, QCheckBox, QGroupBox, QFormLayout,
        QDialogButtonBox, QMessageBox, QComboBox, QTabWidget, QWidget
    )
    from PyQt5.QtCore import Qt
except ImportError:
    print("PyQt5 non installé. Installez-le avec: pip install PyQt5")
    sys.exit(1)

from core.config import Config


class ConfigWindow(QDialog):
    """Fenêtre de configuration de l'application."""

    def __init__(self, config: Config, parent=None):
        super().__init__(parent)
        self.config = config
        self.original_config = config.get().copy()

        self.init_ui()
        self.load_config()

    def init_ui(self):
        """Initialise l'interface utilisateur."""
        self.setWindowTitle("Configuration - Penetration Testing Framework")
        self.setModal(True)
        self.resize(600, 500)

        layout = QVBoxLayout(self)

        # Onglets pour organiser les paramètres
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Onglet Général
        general_tab = self.create_general_tab()
        self.tab_widget.addTab(general_tab, "Général")

        # Onglet Réseau
        network_tab = self.create_network_tab()
        self.tab_widget.addTab(network_tab, "Réseau")

        # Onglet Web
        web_tab = self.create_web_tab()
        self.tab_widget.addTab(web_tab, "Web")

        # Onglet Logging
        logging_tab = self.create_logging_tab()
        self.tab_widget.addTab(logging_tab, "Logging")

        # Boutons OK/Annuler
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.Apply,
            Qt.Horizontal, self
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.Apply).clicked.connect(self.apply_config)
        layout.addWidget(buttons)

    def create_general_tab(self) -> QWidget:
        """Crée l'onglet Général."""
        widget = QWidget()
        layout = QFormLayout(widget)

        # Mode safe
        self.safe_mode_cb = QCheckBox("Mode Safe (recommandé)")
        self.safe_mode_cb.setToolTip("Désactive les actions potentiellement destructives")
        layout.addRow(self.safe_mode_cb)

        # Nombre de threads
        self.threads_sb = QSpinBox()
        self.threads_sb.setRange(1, 50)
        self.threads_sb.setValue(4)
        layout.addRow("Threads simultanés:", self.threads_sb)

        # Timeout par défaut
        self.timeout_sb = QSpinBox()
        self.timeout_sb.setRange(1, 300)
        self.timeout_sb.setValue(30)
        self.timeout_sb.setSuffix(" secondes")
        layout.addRow("Timeout par défaut:", self.timeout_sb)

        # Répertoire de résultats
        self.results_dir_le = QLineEdit()
        self.results_dir_le.setText("results")
        layout.addRow("Répertoire résultats:", self.results_dir_le)

        return widget

    def create_network_tab(self) -> QWidget:
        """Crée l'onglet Réseau."""
        widget = QWidget()
        layout = QFormLayout(widget)

        # Ports par défaut
        self.default_ports_le = QLineEdit()
        self.default_ports_le.setText("22,80,443,3389")
        self.default_ports_le.setToolTip("Ports séparés par des virgules")
        layout.addRow("Ports par défaut:", self.default_ports_le)

        # Timeout réseau
        self.network_timeout_sb = QSpinBox()
        self.network_timeout_sb.setRange(1, 120)
        self.network_timeout_sb.setValue(10)
        self.network_timeout_sb.setSuffix(" secondes")
        layout.addRow("Timeout réseau:", self.network_timeout_sb)

        # Nombre de threads réseau
        self.network_threads_sb = QSpinBox()
        self.network_threads_sb.setRange(1, 100)
        self.network_threads_sb.setValue(10)
        layout.addRow("Threads réseau:", self.network_threads_sb)

        # Scan agressif
        self.aggressive_scan_cb = QCheckBox("Scan agressif")
        self.aggressive_scan_cb.setToolTip("Peut déclencher des alertes IDS/IPS")
        layout.addRow(self.aggressive_scan_cb)

        return widget

    def create_web_tab(self) -> QWidget:
        """Crée l'onglet Web."""
        widget = QWidget()
        layout = QFormLayout(widget)

        # User-Agent
        self.user_agent_le = QLineEdit()
        self.user_agent_le.setText("PTF/1.0 (Educational)")
        layout.addRow("User-Agent:", self.user_agent_le)

        # Timeout web
        self.web_timeout_sb = QSpinBox()
        self.web_timeout_sb.setRange(1, 120)
        self.web_timeout_sb.setValue(15)
        self.web_timeout_sb.setSuffix(" secondes")
        layout.addRow("Timeout web:", self.web_timeout_sb)

        # Profondeur de crawling
        self.crawl_depth_sb = QSpinBox()
        self.crawl_depth_sb.setRange(1, 10)
        self.crawl_depth_sb.setValue(2)
        layout.addRow("Profondeur crawling:", self.crawl_depth_sb)

        # Suivre les redirections
        self.follow_redirects_cb = QCheckBox("Suivre redirections")
        self.follow_redirects_cb.setChecked(True)
        layout.addRow(self.follow_redirects_cb)

        # Vérifier certificats SSL
        self.verify_ssl_cb = QCheckBox("Vérifier SSL")
        self.verify_ssl_cb.setChecked(False)
        self.verify_ssl_cb.setToolTip("Désactiver pour sites avec certificats invalides")
        layout.addRow(self.verify_ssl_cb)

        return widget

    def create_logging_tab(self) -> QWidget:
        """Crée l'onglet Logging."""
        widget = QWidget()
        layout = QFormLayout(widget)

        # Niveau de log
        self.log_level_cb = QComboBox()
        self.log_level_cb.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level_cb.setCurrentText("INFO")
        layout.addRow("Niveau de log:", self.log_level_cb)

        # Fichier de log
        self.log_file_le = QLineEdit()
        self.log_file_le.setText("ptf.log")
        layout.addRow("Fichier de log:", self.log_file_le)

        # Rotation des logs
        self.log_rotation_cb = QCheckBox("Rotation automatique")
        self.log_rotation_cb.setChecked(True)
        layout.addRow(self.log_rotation_cb)

        # Taille max des logs
        self.log_max_size_sb = QSpinBox()
        self.log_max_size_sb.setRange(1, 100)
        self.log_max_size_sb.setValue(10)
        self.log_max_size_sb.setSuffix(" Mo")
        layout.addRow("Taille max log:", self.log_max_size_sb)

        # Logs JSON
        self.json_logs_cb = QCheckBox("Format JSON")
        self.json_logs_cb.setToolTip("Format structuré pour analyse")
        layout.addRow(self.json_logs_cb)

        return widget

    def load_config(self):
        """Charge la configuration actuelle dans l'interface."""
        cfg = self.config.get()

        # Général
        self.safe_mode_cb.setChecked(cfg.get("safe_mode", True))
        self.threads_sb.setValue(cfg.get("threads", 4))
        self.timeout_sb.setValue(cfg.get("timeout", 30))
        self.results_dir_le.setText(cfg.get("results_dir", "results"))

        # Réseau
        network_cfg = cfg.get("network", {})
        self.default_ports_le.setText(",".join(map(str, network_cfg.get("default_ports", [22, 80, 443, 3389]))))
        self.network_timeout_sb.setValue(network_cfg.get("timeout", 10))
        self.network_threads_sb.setValue(network_cfg.get("threads", 10))
        self.aggressive_scan_cb.setChecked(network_cfg.get("aggressive", False))

        # Web
        web_cfg = cfg.get("web", {})
        self.user_agent_le.setText(web_cfg.get("user_agent", "PTF/1.0"))
        self.web_timeout_sb.setValue(web_cfg.get("timeout", 15))
        self.crawl_depth_sb.setValue(web_cfg.get("crawl_depth", 2))
        self.follow_redirects_cb.setChecked(web_cfg.get("follow_redirects", True))
        self.verify_ssl_cb.setChecked(web_cfg.get("verify_ssl", False))

        # Logging
        logging_cfg = cfg.get("logging", {})
        self.log_level_cb.setCurrentText(logging_cfg.get("level", "INFO"))
        self.log_file_le.setText(logging_cfg.get("file", "ptf.log"))
        self.log_rotation_cb.setChecked(logging_cfg.get("rotation", True))
        self.log_max_size_sb.setValue(logging_cfg.get("max_size_mb", 10))
        self.json_logs_cb.setChecked(logging_cfg.get("json_lines", False))

    def save_config(self) -> dict:
        """Sauvegarde la configuration depuis l'interface."""
        cfg = {}

        # Général
        cfg["safe_mode"] = self.safe_mode_cb.isChecked()
        cfg["threads"] = self.threads_sb.value()
        cfg["timeout"] = self.timeout_sb.value()
        cfg["results_dir"] = self.results_dir_le.text()

        # Réseau
        cfg["network"] = {
            "default_ports": [int(p.strip()) for p in self.default_ports_le.text().split(",") if p.strip()],
            "timeout": self.network_timeout_sb.value(),
            "threads": self.network_threads_sb.value(),
            "aggressive": self.aggressive_scan_cb.isChecked()
        }

        # Web
        cfg["web"] = {
            "user_agent": self.user_agent_le.text(),
            "timeout": self.web_timeout_sb.value(),
            "crawl_depth": self.crawl_depth_sb.value(),
            "follow_redirects": self.follow_redirects_cb.isChecked(),
            "verify_ssl": self.verify_ssl_cb.isChecked()
        }

        # Logging
        cfg["logging"] = {
            "level": self.log_level_cb.currentText(),
            "file": self.log_file_le.text(),
            "rotation": self.log_rotation_cb.isChecked(),
            "max_size_mb": self.log_max_size_sb.value(),
            "json_lines": self.json_logs_cb.isChecked()
        }

        return cfg

    def apply_config(self):
        """Applique la configuration sans fermer la fenêtre."""
        try:
            new_config = self.save_config()
            self.config.update(new_config)
            QMessageBox.information(self, "Configuration", "Configuration appliquée avec succès!")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'application: {e}")

    def accept(self):
        """Valide et ferme la fenêtre."""
        try:
            new_config = self.save_config()
            self.config.update(new_config)
            super().accept()
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde: {e}")

    def reject(self):
        """Annule et ferme la fenêtre."""
        # Restaurer la config originale
        self.config.update(self.original_config)
        super().reject()
