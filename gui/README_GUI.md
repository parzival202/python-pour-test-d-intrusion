# Interface Graphique Utilisateur (GUI) - Penetration Testing Framework

## Objectif de l'IHM

L'interface graphique utilisateur (GUI) du Penetration Testing Framework vise à fournir une alternative conviviale à l'interface en ligne de commande (CLI) pour les utilisateurs moins familiers avec les outils en ligne de commande. Elle permet de :

- **Lancer des scans de sécurité** : Reconnaissance, réseau, web, exploitation (simulée)
- **Gérer les sessions** : Créer, afficher et fermer des sessions de test
- **Visualiser les résultats** : Afficher les vulnérabilités, scans et exploitations en temps réel
- **Générer des rapports** : Exporter les résultats en HTML, PDF ou JSON
- **Configurer le framework** : Modifier les paramètres (threads, timeout, etc.)
- **Surveiller les logs** : Afficher les logs en temps réel avec filtrage

L'interface est conçue pour être intuitive, sécurisée par défaut, et adaptée aux environnements éducatifs/VM uniquement.

## Architecture Choisie

### Technologie GUI : PyQt5

Nous avons choisi **PyQt5** pour les raisons suivantes :
- **Interface riche** : Widgets avancés, thèmes personnalisables, support des layouts complexes
- **Performance** : Basé sur Qt, optimisé pour les applications natives
- **Écosystème mature** : Large communauté, documentation abondante
- **Intégration Python** : Liaison native avec Python via PyQt5
- **Cross-platform** : Fonctionne sur Windows, Linux, macOS

**Alternative considérée** : Tkinter (inclus dans Python standard) était une option pour la simplicité, mais PyQt5 offre une meilleure expérience utilisateur pour une application complexe comme celle-ci.

### Structure de l'Architecture

```
gui/
├── app.py                 # Point d'entrée principal de l'application
├── __init__.py
├── assets/                # Ressources (icônes, images)
├── components/            # Composants réutilisables
│   ├── session_manager.py # Gestion des sessions
│   ├── logger_view.py     # Vue des logs
│   └── ...
├── windows/               # Fenêtres principales
│   ├── main_window.py     # Fenêtre principale
│   ├── config_window.py   # Fenêtre de configuration
│   └── ...
├── styles/                # Feuilles de style et thèmes
│   ├── main.qss           # Style principal
│   └── ...
└── plugins/               # Extensions futures (optionnel)
```

### Principes Architecturaux

- **Modularité** : Séparation claire entre composants, fenêtres et logique métier
- **Threading sécurisé** : Utilisation de QThread pour les opérations longues sans bloquer l'UI
- **Communication asynchrone** : Queue pour communiquer entre threads GUI et workers
- **Sécurité** : Mode "Safe Mode" activé par défaut, confirmations pour actions sensibles
- **Responsive** : Layouts adaptatifs pour différentes résolutions
- **Accessibilité** : Labels clairs, raccourcis clavier, support du thème sombre/clair

## Instructions d'Installation

### Prérequis

- Python 3.8+
- PyQt5 (inclus dans `requirements.txt`)

### Installation Automatique

1. Installer les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

2. Vérifier l'installation de PyQt5 :
   ```bash
   python -c "import PyQt5; print('PyQt5 version:', PyQt5.QtCore.PYQT_VERSION_STR)"
   ```

### Lancement de la GUI

#### Via script dédié
```bash
python gui/run_gui.py
```

#### Via module Python
```bash
python -m gui.app
```

#### Via entry point (si configuré)
```bash
ptf-gui
```

### Dépannage

- **Erreur d'import PyQt5** : `pip install PyQt5` ou vérifier la version Python (32/64 bits)
- **Problèmes d'affichage** : Sur Linux, installer `python3-pyqt5` via le gestionnaire de paquets
- **Performance lente** : Réduire le nombre de threads dans la configuration

## Fonctionnalités Clés

- Écran d'accueil avec boutons rapides
- Gestion des sessions avec base de données
- Vue temps réel des logs avec filtrage
- Panneau de configuration intégré
- Visualisation des résultats (sessions, scans, vulnérabilités)
- Génération de rapports PDF/HTML
- Mode démonstration pour tests
- Gestion d'erreurs conviviale
- Thème visuel cohérent

## Sécurité et Éthique

- **Mode Safe activé par défaut** : Désactive les actions potentiellement destructives
- **Confirmations obligatoires** : Pour scans longs, exploitations, modifications DB
- **Avertissement légal** : Rappel des règles d'éthique et d'autorisation
- **Limitation des payloads** : En mode safe, payloads simulés uniquement

## Développement et Tests

- Tests unitaires pour composants non-graphiques
- Tests d'intégration avec interface headless
- CI/CD avec linting et tests automatisés
- Documentation détaillée dans `docs/GUI_USER_GUIDE.md`

## Support et Contribution

Voir `gui/CONTRIBUTING_GUI.md` pour les conventions de code et processus de contribution.
