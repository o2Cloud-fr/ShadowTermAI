# SSH Honeypot avec IA et suivi des tentatives de téléchargement

Ce projet est un honeypot SSH avancé qui simule un terminal interactif avec des réponses basées sur l'IA pour enregistrer les activités des attaquants. Il comprend une fonctionnalité spécifique pour surveiller et enregistrer les tentatives de téléchargement via `wget` et `curl`.

## Fonctionnalités principales

- Simulation d'un serveur SSH avec authentification faible pour attirer les attaquants
- Terminal interactif qui répond aux commandes courantes de manière réaliste
- Système de fichiers simulé avec des données sensibles factices
- Enregistrement détaillé des sessions et des commandes
- **Simulation de téléchargements réussis via `wget` et `curl`**
- **Enregistrement des URLs ciblées dans une base de données MySQL**
- Système de score de risque pour évaluer le danger potentiel d'une session
- Génération de rapports et statistiques sur les attaques

## Prérequis

- Node.js v14+ 
- MySQL 5.7+ ou MariaDB 10.3+
- Modules NPM: `ssh2`, `winston`, `date-fns`, `sshpk`, `mysql2`

## Installation

1. Clonez ce dépôt :
   ```
   git clone https://github.com/votre-nom/ssh-honeypot-ia.git
   cd ssh-honeypot-ia
   ```

2. Installez les dépendances :
   ```
   npm install ssh2 winston date-fns sshpk mysql2
   ```

3. Créez la base de données MySQL :
   ```
   mysql -u root -p < honeypot_db.sql
   ```

4. Générez une clé SSH pour le serveur :
   ```
   ssh-keygen -t rsa -f server.key -N ""
   ```

5. Configurez les paramètres dans le fichier principal :
   - Modifiez les identifiants de connexion à la base de données
   - Ajustez les comptes utilisateurs du honeypot si nécessaire
   - Configurez l'adresse et le port d'écoute

## Utilisation

1. Démarrez le honeypot :
   ```
   node ssh_honeypot_enhanced.js
   ```

2. Le serveur SSH commencera à écouter sur le port configuré (par défaut 2222)

3. Les journaux seront écrits dans `honeypot.log` et les détails des sessions dans le répertoire `sessions/`

4. Les tentatives de téléchargement via `wget` et `curl` seront enregistrées dans la base de données MySQL

## Structure de la base de données

- `sessions` : Informations sur les sessions SSH
- `commands` : Commandes exécutées par les attaquants
- `download_attempts` : Détails des tentatives de téléchargement via wget/curl
- `url_analysis` : Analyse des URLs téléchargées
- `statistics` : Statistiques globales sur les attaques

## Requêtes SQL utiles

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

## Sécurité

Ce honeypot est conçu pour être exposé aux attaquants potentiels, mais prenez les précautions suivantes :

- Exécutez-le dans un environnement isolé ou conteneurisé
- N'utilisez jamais de vrais mots de passe ou données sensibles
- Surveillez régulièrement les logs pour détecter toute compromission réelle
- Ne l'exécutez pas avec des privilèges root
- Utilisez un pare-feu pour contrôler l'accès

## Avertissement

L'utilisation de honeypots peut être légalement complexe dans certaines juridictions. Assurez-vous de comprendre les implications légales avant de déployer ce système sur un réseau public.

## Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.
