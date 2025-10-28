# Penetration Testing Framework

## Présentation pédagogique

Ce framework est un *projet académique* conçu pour l’apprentissage des bases
du test d’intrusion et de l’analyse de sécurité réseau. Il offre une structure
organisée permettant d'exécuter plusieurs actions d’audit afin de collecter,
centraliser et analyser des informations relatives à une cible dans un
environnement *totalement autorisé et maîtrisé*.

Ce projet constitue un support d’évaluation universitaire et un outil
d’apprentissage pour les étudiants souhaitant se former au pentest.

---

## Objectifs pédagogiques

- Comprendre l’architecture d’un outil de pentest modulaire
- Améliorer la compréhension du fonctionnement d’un scanner réseau et web
- Manipuler une base de données appliquée à la cybersécurité
- Produire des rapports exploitables par un analyste SOC / Pentester
- Développer des modules d’audit personnalisés

---

## Architecture du projet

penetration_testing_framework/

core/ # Gestion centrale : base de données & configuration
modules/ # Modules d'audit (web, réseau…)
reporting/ # Génération des rapports JSON / HTML
tests/ # Tests unitaires Pytest
main.py # Point d’entrée du framework


Chaque composant est pensé pour être *améliorable et extensible* dans un
cadre pédagogique.

---

## Fonctionnalités existantes

| Fonction | Détails |
|---------|---------|
| Collecte d'informations | Requêtes HTTP, extraction de données… |
| OSINT basique | WHOIS, métadonnées web |
| Stockage sécurisé | Archivage des résultats dans une base interne |
| Reporting automatisé | Formats HTML et JSON |

---

## Avertissement légal

> **Toute utilisation doit être réalisée sur des systèmes que vous possédez ou
> pour lesquels vous disposez d’une autorisation écrite.**

L’usage de techniques d’intrusion en dehors d’un cadre légal constitue un
délit. L’auteur de ce projet décline toute responsabilité en cas de mauvaise
utilisation.

---

## Tests & Qualité

Les tests unitaires sont exécutables avec pytest et garantissent la stabilité
minimale du framework.

```bash
pytest -v