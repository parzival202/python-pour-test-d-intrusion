Contribution pédagogique
Les évolutions se font dans le cadre de la formation. Les suggestions sont
encouragées afin d’améliorer la compréhension et la qualité du projet.

📜 Licence
Usage académique uniquement — toute exploitation commerciale interdite.

# ✅ INSTALLATION.md


# Guide d'installation & d'utilisation

## ✅ 1) Prérequis système

- Python 3.10 ou supérieur
- Git installé
- Connexion Internet (pour installations de dépendances)
- Optionnel : environnement virtuel Python

---

## 📥 2) Télécharger ou cloner le projet


git clone https://github.com/USERNAME/penetration_testing_framework.git
cd penetration_testing_framework


Remplacer USERNAME par votre identifiant GitHub si publié.


⚙️ 3) Installation des dépendances
pip install -r requirements.txt


🚀 4) Lancer le framework
Exécution type sur une cible autorisée :
python main.py --target http://example.com --output output/

Exemple minimal :
python main.py --target 127.0.0.1

Les données collectées sont stockées dans la base interne.

📝 5) Génération d’un rapport
python main.py --report --session SESSION_ID

Les rapports HTML et/ou JSON sont générés dans :
output/reports/


🧪 6) Lancer les tests unitaires
pytest -v


ℹ️ Notes pédagogiques


Le framework est en évolution constante


Les étudiants peuvent ajouter leurs propres modules d’audit


Certaines fonctionnalités peuvent ne pas être totalement finalisées



🎓 Bon apprentissage et bonne exploration éthique de la cybersécurité !

✅ *INSTALLATION.md terminé* — tu peux copier/coller ✅


