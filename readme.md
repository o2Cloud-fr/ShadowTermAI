# 🍯 SSH Honeypot avec IA et suivi des tentatives de téléchargement

**SSH Honeypot** est un honeypot SSH avancé qui simule un terminal interactif avec des réponses basées sur l'IA pour enregistrer les activités des attaquants. Il comprend une fonctionnalité spécifique pour surveiller et enregistrer les tentatives de téléchargement via `wget` et `curl`.

![Banner](https://o2cloud.fr/logo/o2Cloud.png)

## ✨ Fonctionnalités principales

- 🛡️ **Simulation d'un serveur SSH** - Authentification faible pour attirer les attaquants
- 💻 **Terminal interactif** - Répond aux commandes courantes de manière réaliste
- 📁 **Système de fichiers simulé** - Données sensibles factices pour leurrer les attaquants
- 📝 **Enregistrement détaillé** - Sessions et commandes entièrement loggées
- 📥 **Simulation de téléchargements** - Suivi des tentatives via `wget` et `curl`
- 🗄️ **Base de données MySQL** - Enregistrement des URLs ciblées
- ⚠️ **Système de score de risque** - Évaluation du danger potentiel d'une session
- 📊 **Rapports et statistiques** - Génération d'analyses sur les attaques

## 📋 Prérequis

- Node.js v14+ ou supérieur
- MySQL 5.7+ ou MariaDB 10.3+
- Modules NPM: `ssh2`, `winston`, `date-fns`, `sshpk`, `mysql2`

## 🚀 Installation

1. Clonez le dépôt sur votre serveur
```bash
git clone https://github.com/o2Cloud-fr/ShadowTermAI.git
cd ssh-honeypot-ia
```

2. Installez les dépendances NPM
```bash
npm install ssh2 winston date-fns sshpk mysql2
```

3. Créez la base de données MySQL
```bash
mysql -u root -p < honeypot_schema.sql
```

4. Générez une clé SSH pour le serveur
```bash
ssh-keygen -t rsa -f server.key ""
```

5. Configurez les paramètres dans le fichier principal
   - Modifiez les identifiants de connexion à la base de données
   - Ajustez les comptes utilisateurs du honeypot si nécessaire
   - Configurez l'adresse et le port d'écoute

## 📚 Utilisation

Le SSH Honeypot utilise Node.js avec des modules spécialisés pour créer un environnement de piégeage réaliste. L'application est structurée autour de :

- Un **serveur SSH simulé** qui accepte les connexions malveillantes
- Un **système de commandes interactif** pour maintenir l'illusion
- Un **moteur d'enregistrement** qui capture toutes les activités
- Une **base de données MySQL** pour analyser les patterns d'attaque

### Démarrage du honeypot

1. Lancez le honeypot
```bash
node ssh_honeypot.js
```

2. Le serveur SSH commencera à écouter sur le port configuré (par défaut 2222)

3. Les journaux seront écrits dans `honeypot.log` et les détails des sessions dans le répertoire `sessions/`

4. Les tentatives de téléchargement via `wget` et `curl` seront enregistrées dans la base de données MySQL

## 🗄️ Structure de la base de données

Le honeypot utilise plusieurs tables pour organiser les données collectées :

- **`sessions`** - Informations sur les sessions SSH établies
- **`commands`** - Commandes exécutées par les attaquants
- **`download_attempts`** - Détails des tentatives de téléchargement via wget/curl
- **`url_analysis`** - Analyse des URLs téléchargées
- **`statistics`** - Statistiques globales sur les attaques

## 🔍 Requêtes SQL utiles

### Afficher les tentatives de téléchargement récentes
```sql
SELECT ip_address, username, url, timestamp, risk_score
FROM download_attempts
ORDER BY timestamp DESC
LIMIT 20;
```

### Trouver les domaines les plus ciblés
```sql
SELECT
    SUBSTRING_INDEX(SUBSTRING_INDEX(url, '/', 3), '//', -1) as domain,
    COUNT(*) as count
FROM download_attempts
GROUP BY domain
ORDER BY count DESC;
```

### Afficher les sessions à haut risque
```sql
SELECT session_id, ip_address, username, risk_score, assessment
FROM sessions
WHERE risk_score > 50
ORDER BY risk_score DESC;
```

## 👨‍💻 Auteurs

- [@o2Cloud-fr](https://www.github.com/o2Cloud-fr/ShadowTermAI)

## 🔖 Badges

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-43853D?logo=node.js&logoColor=white)](https://github.com/o2Cloud-fr/ShadowTermAI)
[![MySQL](https://img.shields.io/badge/MySQL-4479A1?logo=mysql&logoColor=white)](https://github.com/o2Cloud-fr/ShadowTermAI)
[![SSH2](https://img.shields.io/badge/SSH2-Security-red)](https://github.com/o2Cloud-fr/ShadowTermAI)

## 🛡️ Sécurité

Ce honeypot est conçu pour être exposé aux attaquants potentiels, mais prenez les précautions suivantes :

- Exécutez-le dans un environnement isolé ou conteneurisé
- N'utilisez jamais de vrais mots de passe ou données sensibles
- Surveillez régulièrement les logs pour détecter toute compromission réelle
- Ne l'exécutez pas avec des privilèges root
- Utilisez un pare-feu pour contrôler l'accès

## ⚠️ Avertissement

L'utilisation de honeypots peut être légalement complexe dans certaines juridictions. Assurez-vous de comprendre les implications légales avant de déployer ce système sur un réseau public.

## 💬 Feedback

Si vous avez des commentaires ou des suggestions, n'hésitez pas à ouvrir une issue sur notre dépôt GitHub.

## 🔗 Liens

[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/remi-simier-2b30142a1/)
[![github](https://img.shields.io/badge/github-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/o2Cloud-fr/)

## 🛠️ Compétences

- Node.js
- MySQL/MariaDB
- SSH Protocol
- Security Analysis
- Honeypot Design
- Network Security

## 📝 Licence

[MIT License](https://opensource.org/licenses/MIT)

## 🗺️ Feuille de route

- Intégration de l'IA pour des réponses plus sophistiquées
- Support de protocoles additionnels (FTP, Telnet, HTTP)
- Interface web pour la visualisation des données
- Système d'alertes en temps réel
- Intégration avec des services de threat intelligence
- Module d'analyse comportementale des attaquants

## 🆘 Support

Pour obtenir de l'aide, ouvrez une issue sur notre dépôt GitHub ou contactez-nous par email : github@o2cloud.fr

## 💼 Utilisé par

Cette application est idéale pour :

- Les chercheurs en sécurité étudiant les techniques d'attaque
- Les administrateurs système souhaitant détecter les intrusions
- Les entreprises analysant les menaces sur leur infrastructure
- Les équipes de cybersécurité collectant des renseignements sur les menaces