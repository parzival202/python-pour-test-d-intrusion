"""
Composant de gestion des sessions.

Permet de créer, afficher et fermer des sessions de test de pénétration.
Utilise la base de données pour persister les sessions.
"""

import sys
from typing import Optional

try:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QListWidget, QListWidgetItem, QInputDialog, QMessageBox,
        QGroupBox, QLineEdit, QComboBox
    )
    from PyQt5.QtCore import Qt, pyqtSignal
except ImportError:
    print("PyQt5 non installé. Installez-le avec: pip install PyQt5")
    sys.exit(1)

from core.config import Config
from core.database import create_session, get_session, close_session, get_connection


class SessionManager(QWidget):
    """Composant pour gérer les sessions de test."""

    # Signal émis quand la session change
    session_changed = pyqtSignal(str)  # session_id

    def __init__(self, config: Config, logger):
        super().__init__()
        self.config = config
        self.logger = logger
        self.current_session_id = None

        self.init_ui()
        self.load_sessions()

    def init_ui(self):
        """Initialise l'interface utilisateur."""
        layout = QVBoxLayout(self)

        # Titre
        title = QLabel("Sessions de Test")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)

        # Liste des sessions
        self.session_list = QListWidget()
        self.session_list.itemDoubleClicked.connect(self.on_session_selected)
        layout.addWidget(self.session_list)

        # Boutons d'action
        buttons_layout = QHBoxLayout()

        self.new_btn = QPushButton("Nouvelle")
        self.new_btn.clicked.connect(self.create_new_session)
        buttons_layout.addWidget(self.new_btn)

        self.close_btn = QPushButton("Fermer")
        self.close_btn.clicked.connect(self.close_current_session)
        self.close_btn.setEnabled(False)
        buttons_layout.addWidget(self.close_btn)

        layout.addLayout(buttons_layout)

        # Informations de session actuelle
        self.session_info = QLabel("Aucune session sélectionnée")
        self.session_info.setWordWrap(True)
        self.session_info.setStyleSheet("background-color: #f0f0f0; padding: 5px; border-radius: 3px;")
        layout.addWidget(self.session_info)

    def load_sessions(self):
        """Charge la liste des sessions depuis la base de données."""
        self.session_list.clear()

        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT session_id, target, status FROM sessions ORDER BY start_time DESC")
            rows = c.fetchall()
            conn.close()

            for row in rows:
                session_id, target, status = row
                item_text = f"{session_id} - {target} ({status})"
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, session_id)
                self.session_list.addItem(item)

        except Exception as e:
            self.logger.error(f"Erreur lors du chargement des sessions: {e}")
            # Fallback to empty list
            pass

    def create_new_session(self):
        """Crée une nouvelle session."""
        # Demander le target
        target, ok = QInputDialog.getText(
            self, "Nouvelle Session",
            "Entrez la cible (IP, domaine, réseau):"
        )

        if not ok or not target.strip():
            return

        target = target.strip()

        try:
            # Créer un ID de session unique avec timestamp
            import time
            timestamp = str(int(time.time()))
            session_id = f"session_{target.replace('.', '_')}_{timestamp}"

            # Créer la session dans la DB
            session_db_id = create_session(session_id, target, self.config.get())

            # Recharger la liste
            self.load_sessions()

            # Sélectionner la nouvelle session
            self.select_session(session_id)

            self.logger.info(f"Nouvelle session créée: {target}")

        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Impossible de créer la session: {e}")
            self.logger.error(f"Erreur création session: {e}")

    def select_session(self, session_id: str):
        """Sélectionne une session."""
        self.current_session_id = session_id
        self.session_changed.emit(session_id)

        # Mettre à jour l'info
        session_data = get_session(session_id)
        if session_data:
            info = f"Session: {session_id}\nCible: {session_data.get('target', 'unknown')}\nStatus: {session_data.get('status', 'unknown')}"
        else:
            info = f"Session: {session_id} (données non disponibles)"

        self.session_info.setText(info)
        self.close_btn.setEnabled(True)

        # Mettre en surbrillance dans la liste
        for i in range(self.session_list.count()):
            item = self.session_list.item(i)
            if item.data(Qt.UserRole) == session_id:
                item.setSelected(True)
                self.session_list.setCurrentItem(item)
                break

    def close_current_session(self):
        """Ferme la session actuelle."""
        if not self.current_session_id:
            return

        reply = QMessageBox.question(
            self, "Fermer la session",
            f"Voulez-vous fermer la session {self.current_session_id}?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                close_session(self.current_session_id, 'closed_by_user')
                self.load_sessions()
                self.current_session_id = None
                self.session_changed.emit("")
                self.session_info.setText("Aucune session sélectionnée")
                self.close_btn.setEnabled(False)
                self.logger.info(f"Session fermée: {self.current_session_id}")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Impossible de fermer la session: {e}")
                self.logger.error(f"Erreur fermeture session: {e}")

    def on_session_selected(self, item: QListWidgetItem):
        """Gère la sélection d'une session dans la liste."""
        session_id = item.data(Qt.UserRole)
        if session_id:
            self.select_session(session_id)

    def get_current_session(self) -> Optional[str]:
        """Retourne l'ID de la session actuelle."""
        return self.current_session_id
